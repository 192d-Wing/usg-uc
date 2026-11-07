//! Shared management-plane authentication for the USG SBC.
//!
//! The SBC's management surface is served by several horizontally-scaled,
//! stateless pods (`sbc-api-server`, `sbc-provision-server`) behind nginx, so
//! per-process session tables don't work — a token minted by one replica must
//! validate on any other. This crate therefore issues **stateless,
//! HMAC-SHA-384-signed bearer tokens** (CNSA 2.0): any replica holding the
//! same signing key validates a token with no shared store.
//!
//! - Admin login verifies a username + password against an argon2id hash.
//! - Successful login mints a signed token carrying `{sub, iat, exp, aud}`.
//! - API keys (SHA-256 hashed) are supported for non-interactive clients.
//! - An axum middleware enforces deny-by-default on a route surface.
//!
//! Configuration is entirely environment-driven (12-factor / k8s Secrets):
//! see [`Authenticator::from_env`].
//!
//! ## NIST 800-53 Rev5 Controls
//! - **IA-2**: Identification and Authentication (Organizational Users)
//! - **IA-5**: Authenticator Management (argon2id at rest, signing-key floor)
//! - **AC-3**: Access Enforcement (deny-by-default middleware)
//! - **AC-12**: Session Termination (bounded token TTL)
//! - **SC-13**: Cryptographic Protection (HMAC-SHA-384)
//! - **SC-23**: Session Authenticity (`aud` / `iat` checks)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

type HmacSha384 = Hmac<Sha384>;

/// Default admin username when `SBC_ADMIN_USER` is unset.
const DEFAULT_ADMIN_USER: &str = "admin";
/// Default session token lifetime (seconds): 12 hours.
const DEFAULT_TOKEN_TTL_SECS: u64 = 12 * 60 * 60;

/// Minimum accepted signing-key length in bytes (256 bits).
///
/// NIST 800-53 Rev5: IA-5 (Authenticator Management) — SP 800-107r1 §5.3.4:
/// an HMAC key's security strength is bounded by its length; 32 bytes meets
/// the CNSA 2.0 192-bit level for HMAC-SHA-384.
pub const MIN_SIGNING_KEY_BYTES: usize = 32;
/// Recommended signing-key length in bytes (the SHA-384 output size).
pub const RECOMMENDED_SIGNING_KEY_BYTES: usize = 48;
/// Upper bound on `SBC_AUTH_TOKEN_TTL_SECS` (24 h).
///
/// NIST 800-53 Rev5: AC-12 (Session Termination).
pub const MAX_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;
/// Lower bound on `SBC_AUTH_TOKEN_TTL_SECS`.
pub const MIN_TOKEN_TTL_SECS: u64 = 60;
/// Allowed forward clock skew for a token's `iat` (seconds).
const MAX_IAT_SKEW_SECS: u64 = 60;
/// Audience bound into every management-plane token.
pub const TOKEN_AUDIENCE: &str = "sbc-api";
/// Token wire-format version prefix (v2 = HMAC-SHA-384; v1 SHA-256 tokens
/// are rejected outright).
const TOKEN_PREFIX: &str = "v2.";

/// Errors surfaced while configuring or using the authenticator.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No admin credential material was provided.
    #[error("no admin credentials configured: set SBC_ADMIN_PASSWORD_HASH or SBC_ADMIN_PASSWORD")]
    NoAdminCredentials,
    /// A configured value could not be parsed.
    #[error("invalid {var}: {reason}")]
    Invalid {
        /// The offending environment variable.
        var: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// argon2 hashing/verification failed.
    #[error("password hashing error: {0}")]
    Hashing(String),
}

/// Claims carried inside a signed token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (admin username or API-key identity).
    pub sub: String,
    /// Issued-at as a Unix timestamp (seconds).
    pub iat: u64,
    /// Expiry as a Unix timestamp (seconds).
    pub exp: u64,
    /// Audience; must equal [`TOKEN_AUDIENCE`].
    pub aud: String,
}

/// Mints and verifies stateless HMAC-SHA-384 bearer tokens.
///
/// Token wire format: `v2.<b64url(claims_json)>.<b64url(hmac)>` where the MAC
/// covers the `v2.<b64url(claims_json)>` prefix.
///
/// The key is zeroized when the last clone is dropped.
#[derive(Clone)]
pub struct TokenSigner {
    // NIST 800-53 Rev5: SC-12 (Cryptographic Key Management) — wiped on drop.
    key: Arc<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSigner")
            .field("key", &"<redacted>")
            .field("len", &self.key.len())
            .finish()
    }
}

impl TokenSigner {
    /// Creates a signer from raw key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Invalid`] if the key is shorter than
    /// [`MIN_SIGNING_KEY_BYTES`].
    pub fn new(key: Vec<u8>) -> Result<Self, AuthError> {
        let key = Zeroizing::new(key);
        // NIST 800-53 Rev5: IA-5 — fail closed on a weak signing key.
        if key.len() < MIN_SIGNING_KEY_BYTES {
            return Err(AuthError::Invalid {
                var: "SBC_AUTH_SIGNING_KEY",
                reason: format!(
                    "key is {} bytes; at least {MIN_SIGNING_KEY_BYTES} bytes required \
                     ({RECOMMENDED_SIGNING_KEY_BYTES} recommended)",
                    key.len()
                ),
            });
        }
        if key.len() < RECOMMENDED_SIGNING_KEY_BYTES {
            warn!(
                len = key.len(),
                "SBC_AUTH_SIGNING_KEY is shorter than the recommended \
                 {RECOMMENDED_SIGNING_KEY_BYTES} bytes for HMAC-SHA-384"
            );
        }
        Ok(Self { key: Arc::new(key) })
    }

    /// Mints a token for `subject` valid for `ttl_secs` seconds.
    #[must_use]
    pub fn mint(&self, subject: &str, ttl_secs: u64) -> String {
        let iat = now_secs();
        self.mint_claims(&Claims {
            sub: subject.to_string(),
            iat,
            exp: iat.saturating_add(ttl_secs),
            aud: TOKEN_AUDIENCE.to_string(),
        })
    }

    fn mint_claims(&self, claims: &Claims) -> String {
        // serde_json on a struct of owned String/u64 cannot fail.
        let json = serde_json::to_vec(claims).unwrap_or_default();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let signing_input = format!("{TOKEN_PREFIX}{b64}");
        let mac = self.sign(signing_input.as_bytes());
        let mac_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac);
        format!("{signing_input}.{mac_b64}")
    }

    /// Verifies a token's signature, audience, issue time and expiry,
    /// returning its claims.
    // POAM: POA&M-210 — tokens are stateless; there is no server-side
    // revocation, so logout does not invalidate an issued token. Mitigated by
    // the MAX_TOKEN_TTL_SECS cap and key rotation (invalidates all tokens).
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let (signing_input, mac_b64) = token.rsplit_once('.')?;
        let prefix = signing_input.strip_prefix(TOKEN_PREFIX)?;
        let presented = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mac_b64)
            .ok()?;
        let expected = self.sign(signing_input.as_bytes());
        // Constant-time comparison.
        if expected.ct_eq(&presented).unwrap_u8() != 1 {
            return None;
        }
        let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(prefix)
            .ok()?;
        let claims: Claims = serde_json::from_slice(&claims_json).ok()?;
        let now = now_secs();
        if claims.exp <= now {
            return None;
        }
        // NIST 800-53 Rev5: SC-23 (Session Authenticity) — bound audience,
        // reject future-dated tokens and forged over-long lifetimes.
        if claims.aud != TOKEN_AUDIENCE {
            return None;
        }
        if claims.iat > now.saturating_add(MAX_IAT_SKEW_SECS) {
            return None;
        }
        if claims.exp.saturating_sub(claims.iat) > MAX_TOKEN_TTL_SECS {
            return None;
        }
        Some(claims)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        // HMAC accepts keys of any length, so this never fails; return an
        // empty MAC (which never verifies) rather than panic.
        let Ok(mut mac) = HmacSha384::new_from_slice(&self.key) else {
            return Vec::new();
        };
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Parses a hex `SBC_AUTH_SIGNING_KEY` value into a signer (fail closed).
///
/// # Errors
///
/// Returns [`AuthError::Invalid`] if the value is empty, not hex, or decodes
/// to fewer than [`MIN_SIGNING_KEY_BYTES`] bytes.
pub fn parse_signing_key(hex_key: &str) -> Result<TokenSigner, AuthError> {
    let trimmed = hex_key.trim();
    if trimmed.is_empty() {
        return Err(AuthError::Invalid {
            var: "SBC_AUTH_SIGNING_KEY",
            reason: "set but empty".to_string(),
        });
    }
    let key = hex::decode(trimmed).map_err(|e| AuthError::Invalid {
        var: "SBC_AUTH_SIGNING_KEY",
        reason: e.to_string(),
    })?;
    TokenSigner::new(key)
}

/// Parses and bounds `SBC_AUTH_TOKEN_TTL_SECS`.
///
/// # Errors
///
/// Returns [`AuthError::Invalid`] if not an integer in
/// `MIN_TOKEN_TTL_SECS..=MAX_TOKEN_TTL_SECS`.
pub fn parse_token_ttl(value: &str) -> Result<u64, AuthError> {
    let ttl: u64 =
        value
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| AuthError::Invalid {
                var: "SBC_AUTH_TOKEN_TTL_SECS",
                reason: e.to_string(),
            })?;
    if !(MIN_TOKEN_TTL_SECS..=MAX_TOKEN_TTL_SECS).contains(&ttl) {
        return Err(AuthError::Invalid {
            var: "SBC_AUTH_TOKEN_TTL_SECS",
            reason: format!("{ttl} outside {MIN_TOKEN_TTL_SECS}..={MAX_TOKEN_TTL_SECS}"),
        });
    }
    Ok(ttl)
}

/// Admin username + argon2id password hash.
#[derive(Clone)]
struct AdminCredentials {
    username: String,
    password_hash: String,
}

impl AdminCredentials {
    /// Verifies a username/password against the stored hash (constant-ish
    /// time: the hash is computed even on username mismatch).
    fn verify(&self, username: &str, password: &str) -> bool {
        let parsed = match PasswordHash::new(&self.password_hash) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // Compare the username after the (slow) hash check so a wrong
        // username and a wrong password take comparable time.
        ok && username == self.username
    }
}

/// Hashes a plaintext password with argon2id (PHC string output).
///
/// # Errors
///
/// Returns [`AuthError::Hashing`] if hashing fails.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::Hashing(e.to_string()))
}

/// The management-plane authenticator: admin login + token + API keys.
///
/// Cheap to clone (`Arc` internals); share one instance as axum state.
#[derive(Clone)]
pub struct Authenticator {
    admin: AdminCredentials,
    signer: TokenSigner,
    api_key_hashes: Arc<Vec<String>>,
    token_ttl_secs: u64,
}

impl Authenticator {
    /// Builds the authenticator from the environment.
    ///
    /// - `SBC_ADMIN_USER` — admin username (default `admin`).
    /// - `SBC_ADMIN_PASSWORD_HASH` — argon2 PHC hash (preferred), **or**
    /// - `SBC_ADMIN_PASSWORD` — plaintext, hashed at startup (bootstrap).
    /// - `SBC_AUTH_SIGNING_KEY` — hex token-signing key shared across
    ///   replicas; at least 32 bytes decoded (48 recommended). Set-but-empty,
    ///   non-hex or short keys are rejected. If unset a random key is generated and a warning is
    ///   logged (single-replica only — tokens won't validate across pods).
    /// - `SBC_API_KEY_SHA256` — comma-separated SHA-256 hex digests of
    ///   accepted API keys (optional).
    /// - `SBC_AUTH_TOKEN_TTL_SECS` — token lifetime (default 43200; must be
    ///   within 60..=86400).
    ///
    /// # Errors
    ///
    /// Returns an error if no admin credentials are configured or a value
    /// fails to parse.
    pub fn from_env() -> Result<Self, AuthError> {
        let username =
            std::env::var("SBC_ADMIN_USER").unwrap_or_else(|_| DEFAULT_ADMIN_USER.to_string());

        let password_hash = if let Ok(h) = std::env::var("SBC_ADMIN_PASSWORD_HASH") {
            if h.trim().is_empty() {
                return Err(AuthError::Invalid {
                    var: "SBC_ADMIN_PASSWORD_HASH",
                    reason: "empty".to_string(),
                });
            }
            h
        } else if let Ok(p) = std::env::var("SBC_ADMIN_PASSWORD") {
            if p.is_empty() {
                return Err(AuthError::NoAdminCredentials);
            }
            info!(
                "Hashing SBC_ADMIN_PASSWORD at startup; prefer SBC_ADMIN_PASSWORD_HASH in production"
            );
            hash_password(&p)?
        } else {
            return Err(AuthError::NoAdminCredentials);
        };

        // NIST 800-53 Rev5: IA-5 / CM-6 — a key that is *set* must be valid;
        // empty, non-hex or short keys fail startup instead of silently
        // falling back to a random key.
        let signer = match std::env::var("SBC_AUTH_SIGNING_KEY") {
            Ok(hex_key) => parse_signing_key(&Zeroizing::new(hex_key))?,
            Err(_) => {
                warn!(
                    "SBC_AUTH_SIGNING_KEY not set — generating a random per-process key. \
                     Tokens will NOT validate across replicas; set a shared key (k8s Secret) \
                     for any multi-replica deployment."
                );
                TokenSigner::new(random_key())?
            }
        };

        let api_key_hashes: Vec<String> = std::env::var("SBC_API_KEY_SHA256")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let token_ttl_secs = match std::env::var("SBC_AUTH_TOKEN_TTL_SECS") {
            Ok(v) => parse_token_ttl(&v)?,
            Err(_) => DEFAULT_TOKEN_TTL_SECS,
        };

        Ok(Self {
            admin: AdminCredentials {
                username,
                password_hash,
            },
            signer,
            api_key_hashes: Arc::new(api_key_hashes),
            token_ttl_secs,
        })
    }

    /// Constructs an authenticator explicitly (tests / embedding).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Invalid`] if `signing_key` is shorter than
    /// [`MIN_SIGNING_KEY_BYTES`].
    pub fn new(
        admin_user: &str,
        admin_password_hash: &str,
        signing_key: Vec<u8>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            admin: AdminCredentials {
                username: admin_user.to_string(),
                password_hash: admin_password_hash.to_string(),
            },
            signer: TokenSigner::new(signing_key)?,
            api_key_hashes: Arc::new(Vec::new()),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        })
    }

    /// Verifies admin credentials and mints a session token on success.
    #[must_use]
    pub fn login(&self, username: &str, password: &str) -> Option<String> {
        if self.admin.verify(username, password) {
            Some(self.signer.mint(username, self.token_ttl_secs))
        } else {
            None
        }
    }

    /// Token lifetime in seconds (for clients / cookie Max-Age).
    #[must_use]
    pub const fn token_ttl_secs(&self) -> u64 {
        self.token_ttl_secs
    }

    /// Returns true if `credential` is a valid session token or API key.
    #[must_use]
    pub fn authorize(&self, credential: &str) -> bool {
        if self.signer.verify(credential).is_some() {
            return true;
        }
        if self.api_key_hashes.is_empty() {
            return false;
        }
        // POAM: POA&M-211 — API-key lookup digests are SHA-256
        // (SBC_API_KEY_SHA256); migrate to SHA-384 with dual-accept.
        let digest = hex::encode(Sha256::digest(credential.as_bytes()));
        self.api_key_hashes
            .iter()
            .any(|h| h.as_bytes().ct_eq(digest.as_bytes()).unwrap_u8() == 1)
    }
}

/// Extracts a credential from request headers: `Authorization: Bearer <t>`
/// first, then the `sbc_session` cookie.
#[must_use]
pub fn extract_credential(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION)
        && let Ok(s) = value.to_str()
        && let Some(t) = s.strip_prefix("Bearer ")
    {
        return Some(t.trim().to_string());
    }
    let cookies = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        if let Some(t) = pair.trim().strip_prefix("sbc_session=") {
            return Some(t.to_string());
        }
    }
    None
}

/// State for [`require_auth`]: the authenticator plus the exact paths that
/// bypass authentication (health probes, login, etc.).
#[derive(Clone)]
pub struct AuthLayer {
    /// Shared authenticator.
    pub authenticator: Arc<Authenticator>,
    /// Request paths exempt from authentication (exact match).
    pub public_paths: Arc<HashSet<String>>,
}

impl AuthLayer {
    /// Builds an auth layer exempting `public_paths`.
    #[must_use]
    pub fn new(authenticator: Arc<Authenticator>, public_paths: &[&str]) -> Self {
        Self {
            authenticator,
            public_paths: Arc::new(public_paths.iter().map(|s| (*s).to_string()).collect()),
        }
    }
}

/// Deny-by-default axum middleware. Requests to non-public paths must carry a
/// valid bearer token or API key.
///
/// ## NIST 800-53 Rev5: AC-3 (Access Enforcement)
pub async fn require_auth(
    axum::extract::State(layer): axum::extract::State<AuthLayer>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if layer.public_paths.contains(req.uri().path()) {
        return next.run(req).await;
    }
    let ok = extract_credential(req.headers()).is_some_and(|c| layer.authenticator.authorize(&c));
    if ok {
        return next.run(req).await;
    }
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_key() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; RECOMMENDED_SIGNING_KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth() -> Authenticator {
        let hash = hash_password("correct horse").expect("hash");
        Authenticator::new(
            "admin",
            &hash,
            b"shared-signing-key-32-bytes-long!".to_vec(),
        )
        .expect("auth")
    }

    #[test]
    fn login_and_token_roundtrip() {
        let auth = test_auth();
        assert!(auth.login("admin", "wrong").is_none());
        assert!(auth.login("nobody", "correct horse").is_none());
        let token = auth.login("admin", "correct horse").expect("login");
        assert!(auth.authorize(&token));
        assert!(!auth.authorize("garbage"));
        assert!(!auth.authorize("v1.aaaa.bbbb"));
        assert!(!auth.authorize("v2.aaaa.bbbb"));
    }

    #[test]
    fn token_validates_across_instances_with_same_key() {
        // Simulates two replicas sharing the signing key.
        let key = b"shared-signing-key-32-bytes-long!".to_vec();
        let hash = hash_password("pw").expect("hash");
        let a = Authenticator::new("admin", &hash, key.clone()).expect("a");
        let b = Authenticator::new("admin", &hash, key).expect("b");
        let token = a.login("admin", "pw").expect("login");
        assert!(
            b.authorize(&token),
            "replica B must accept replica A's token"
        );
    }

    #[test]
    fn token_rejected_with_different_key() {
        let hash = hash_password("pw").expect("hash");
        let a = Authenticator::new(
            "admin",
            &hash,
            b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        )
        .expect("a");
        let b = Authenticator::new(
            "admin",
            &hash,
            b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_vec(),
        )
        .expect("b");
        let token = a.login("admin", "pw").expect("login");
        assert!(!b.authorize(&token));
    }

    #[test]
    fn expired_token_rejected() {
        let signer = test_signer();
        let token = signer.mint("admin", 0); // exp = now, <= now → expired
        assert!(signer.verify(&token).is_none());
    }

    fn test_signer() -> TokenSigner {
        TokenSigner::new(vec![0x5a; RECOMMENDED_SIGNING_KEY_BYTES]).expect("signer")
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    #[test]
    fn short_signing_key_rejected() {
        assert!(TokenSigner::new(vec![1; MIN_SIGNING_KEY_BYTES - 1]).is_err());
        assert!(TokenSigner::new(vec![1; MIN_SIGNING_KEY_BYTES]).is_ok());
        assert!(TokenSigner::new(Vec::new()).is_err());
        let hash = hash_password("pw").expect("hash");
        assert!(Authenticator::new("admin", &hash, b"short".to_vec()).is_err());
    }

    #[test]
    fn parse_signing_key_rejects_empty_non_hex_and_short() {
        assert!(parse_signing_key("").is_err());
        assert!(parse_signing_key("   ").is_err());
        assert!(parse_signing_key(&"zz".repeat(48)).is_err());
        assert!(parse_signing_key(&"ab".repeat(31)).is_err());
        assert!(parse_signing_key(&"ab".repeat(32)).is_ok());
        assert!(parse_signing_key(&"ab".repeat(48)).is_ok());
    }

    #[test]
    fn short_key_error_does_not_leak_key() {
        let err = parse_signing_key("deadbeef").expect_err("short");
        assert!(!err.to_string().contains("deadbeef"));
    }

    #[test]
    fn ttl_bounds() {
        assert!(parse_token_ttl("59").is_err());
        assert_eq!(parse_token_ttl("60").ok(), Some(60));
        assert_eq!(parse_token_ttl("86400").ok(), Some(86_400));
        assert!(parse_token_ttl("86401").is_err());
        assert!(parse_token_ttl("abc").is_err());
        assert!(parse_token_ttl("-1").is_err());
    }

    #[test]
    fn v2_token_roundtrip_sha384() {
        let signer = test_signer();
        let token = signer.mint("admin", 300);
        assert!(token.starts_with("v2."));
        let (_, mac_b64) = token.rsplit_once('.').expect("mac");
        let mac = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mac_b64)
            .expect("b64");
        assert_eq!(mac.len(), 48, "HMAC-SHA-384 output");
        let claims = signer.verify(&token).expect("valid");
        assert_eq!(claims.sub, "admin");
        assert_eq!(claims.aud, TOKEN_AUDIENCE);
        assert_eq!(claims.exp - claims.iat, 300);
    }

    #[test]
    fn v1_token_rejected() {
        let key = vec![0x5a; RECOMMENDED_SIGNING_KEY_BYTES];
        let signer = TokenSigner::new(key.clone()).expect("signer");
        let claims = serde_json::json!({ "sub": "admin", "exp": now_secs() + 300 });
        let input = format!("v1.{}", b64(&serde_json::to_vec(&claims).expect("json")));
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("hmac");
        mac.update(input.as_bytes());
        let token = format!("{input}.{}", b64(&mac.finalize().into_bytes()));
        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn future_iat_rejected() {
        let signer = test_signer();
        let now = now_secs();
        let token = signer.mint_claims(&Claims {
            sub: "admin".into(),
            iat: now + 3600,
            exp: now + 7200,
            aud: TOKEN_AUDIENCE.into(),
        });
        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn excess_lifetime_rejected() {
        let signer = test_signer();
        let now = now_secs();
        let token = signer.mint_claims(&Claims {
            sub: "admin".into(),
            iat: now,
            exp: now + MAX_TOKEN_TTL_SECS + 1,
            aud: TOKEN_AUDIENCE.into(),
        });
        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn wrong_aud_rejected() {
        let signer = test_signer();
        let now = now_secs();
        let token = signer.mint_claims(&Claims {
            sub: "admin".into(),
            iat: now,
            exp: now + 300,
            aud: "other-service".into(),
        });
        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn signer_debug_redacts_key() {
        let signer = TokenSigner::new(b"super-secret-signing-key-material!!".to_vec()).expect("s");
        let dbg = format!("{signer:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn extract_credential_bearer_and_cookie() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc".parse().unwrap(),
        );
        assert_eq!(extract_credential(&h).as_deref(), Some("abc"));

        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "x=1; sbc_session=tok".parse().unwrap(),
        );
        assert_eq!(extract_credential(&h).as_deref(), Some("tok"));
    }

    #[test]
    fn iat_skew_and_lifetime_boundaries() {
        let signer = test_signer();
        let now = now_secs();
        let mk = |iat: u64, exp: u64| {
            signer.mint_claims(&Claims {
                sub: "admin".into(),
                iat,
                exp,
                aud: TOKEN_AUDIENCE.into(),
            })
        };
        // Lifetime exactly at the cap is accepted; one second over is not.
        assert!(signer.verify(&mk(now, now + MAX_TOKEN_TTL_SECS)).is_some());
        assert!(
            signer
                .verify(&mk(now, now + MAX_TOKEN_TTL_SECS + 1))
                .is_none()
        );
        // iat well inside the skew window is accepted; beyond it is rejected.
        assert!(signer.verify(&mk(now + 30, now + 600)).is_some());
        assert!(
            signer
                .verify(&mk(now + MAX_IAT_SKEW_SECS + 5, now + 600))
                .is_none()
        );
        // exp == now is expired (strict).
        assert!(signer.verify(&mk(now - 10, now)).is_none());
    }

    #[test]
    fn tampered_and_malformed_tokens_rejected() {
        let signer = test_signer();
        let token = signer.mint("admin", 300);
        let (input, mac) = token.rsplit_once('.').expect("mac");

        // Payload swapped for an attacker-chosen subject, original MAC kept.
        let forged_claims = b64(br#"{"sub":"root","iat":0,"exp":99999999999,"aud":"sbc-api"}"#);
        assert!(
            signer
                .verify(&format!("v2.{forged_claims}.{mac}"))
                .is_none()
        );
        // Single-character MAC flip.
        let mut bad_mac = mac.to_string();
        let last = bad_mac.pop().expect("char");
        bad_mac.push(if last == 'A' { 'B' } else { 'A' });
        assert!(signer.verify(&format!("{input}.{bad_mac}")).is_none());
        // Truncated MAC (SHA-256-length tag) and empty MAC.
        let short = b64(&[0u8; 32]);
        assert!(signer.verify(&format!("{input}.{short}")).is_none());
        assert!(signer.verify(&format!("{input}.")).is_none());
        // Structural garbage.
        for t in [
            "",
            ".",
            "v2.",
            "v2..",
            "v3.abc.def",
            "no-dots",
            "v2.!!!.@@@",
        ] {
            assert!(signer.verify(t).is_none(), "accepted {t:?}");
        }
        // Valid MAC over a non-JSON payload must still fail closed.
        let junk = format!("v2.{}", b64(b"not json"));
        let junk_mac = b64(&signer.sign(junk.as_bytes()));
        assert!(signer.verify(&format!("{junk}.{junk_mac}")).is_none());
    }

    #[test]
    fn parse_signing_key_odd_length_and_whitespace() {
        // Odd-length hex is rejected, not silently truncated.
        assert!(parse_signing_key(&format!("{}a", "ab".repeat(32))).is_err());
        // Surrounding whitespace (e.g. trailing newline from a Secret) is tolerated.
        assert!(parse_signing_key(&format!("{}\n", "ab".repeat(32))).is_ok());
        // Embedded whitespace is not hex.
        assert!(parse_signing_key(&format!("{} {}", "ab".repeat(16), "ab".repeat(16))).is_err());
    }

    #[test]
    fn ttl_parse_rejects_overflow_and_zero() {
        assert!(parse_token_ttl("0").is_err());
        assert!(parse_token_ttl("").is_err());
        assert!(parse_token_ttl("18446744073709551616").is_err());
        assert!(parse_token_ttl("3600s").is_err());
        assert_eq!(parse_token_ttl(" 3600 ").ok(), Some(3600));
    }
}
