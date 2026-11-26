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
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uc_crypto::hash::{SHA384_OUTPUT_LEN, hmac_sha384, sha384, verify_hmac_sha384};
use zeroize::Zeroizing;

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
        // NIST 800-53 Rev5: SC-13 — HMAC-SHA-384 in the FIPS module;
        // aws-lc compares the tag in constant time.
        if !verify_hmac_sha384(&self.key, signing_input.as_bytes(), &presented) {
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

    /// Audit id for a configured API-key digest: the first
    /// [`API_KEY_ID_HEX`] hex digits of HMAC-SHA-384(signing key,
    /// `"sbc-api-key-id:" || digest`). Keyed, so it cannot be computed from
    /// the key (or its digest) alone; stable for as long as the signing key.
    ///
    /// ## NIST 800-53 Rev5: AU-3, IA-5, SC-13
    fn api_key_id(&self, digest: &str) -> String {
        let mut input = Vec::with_capacity(API_KEY_ID_LABEL.len() + digest.len());
        input.extend_from_slice(API_KEY_ID_LABEL);
        input.extend_from_slice(digest.as_bytes());
        let mac = self.sign(&input);
        hex::encode(mac.get(..API_KEY_ID_HEX / 2).unwrap_or_default())
    }

    /// HMAC-SHA-384 over `data` (aws-lc FIPS module via uc-crypto).
    fn sign(&self, data: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
        hmac_sha384(&self.key, data)
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

/// Hex length of a SHA-384 digest.
const API_KEY_DIGEST_HEX_LEN: usize = 96;

/// Parses the accepted API-key digests.
///
/// `sha256` is the removed `SBC_API_KEY_SHA256` value: any non-blank value
/// fails startup so a key that would silently stop working is noticed.
/// `sha384` is `SBC_API_KEY_SHA384`: comma-separated lowercase-or-uppercase
/// hex SHA-384 digests; each must be exactly 96 hex characters.
///
/// ## NIST 800-53 Rev5: IA-5, SC-13, CM-6
fn parse_api_key_digests(
    sha256: Option<&str>,
    sha384: Option<&str>,
) -> Result<Vec<String>, AuthError> {
    if sha256.is_some_and(|v| !v.trim().is_empty()) {
        return Err(AuthError::Invalid {
            var: "SBC_API_KEY_SHA256",
            reason: "SHA-256 API-key digests are no longer accepted; set \
                     SBC_API_KEY_SHA384 to the SHA-384 hex digests instead"
                .to_string(),
        });
    }
    let Some(list) = sha384 else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (i, entry) in list.split(',').enumerate() {
        let h = entry.trim().to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        if h.len() != API_KEY_DIGEST_HEX_LEN || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AuthError::Invalid {
                var: "SBC_API_KEY_SHA384",
                reason: format!(
                    "entry {} is not a {API_KEY_DIGEST_HEX_LEN}-character hex SHA-384 digest",
                    i + 1
                ),
            });
        }
        out.push(h);
    }
    Ok(out)
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
    // POAM: POA&M-402 — argon2id runs outside the FIPS module (RustCrypto);
    // migrate to PBKDF2-HMAC-SHA-384 via uc-crypto with argon2 dual-accept.
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
// POAM: POA&M-402 (argon2id outside the FIPS module).
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
    /// - `SBC_API_KEY_SHA384` — comma-separated SHA-384 hex digests of
    ///   accepted API keys (optional). The former `SBC_API_KEY_SHA256` is
    ///   rejected at startup.
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

        let api_key_hashes = parse_api_key_digests(
            std::env::var("SBC_API_KEY_SHA256").ok().as_deref(),
            std::env::var("SBC_API_KEY_SHA384").ok().as_deref(),
        )?;

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
        self.identify(credential).is_some()
    }

    /// Identifies a valid session token or API key, for audit attribution.
    ///
    /// An API key is named by a keyed id derived from its configured digest
    /// and the signing key, never by the key or its digest.
    ///
    /// ## NIST 800-53 Rev5: IA-2, AU-3 (actor in audit records)
    #[must_use]
    pub fn identify(&self, credential: &str) -> Option<CredentialId> {
        if let Some(claims) = self.signer.verify(credential) {
            return Some(CredentialId::Session {
                subject: claims.sub,
            });
        }
        if self.api_key_hashes.is_empty() {
            return None;
        }
        // NIST 800-53 Rev5: IA-5, SC-13 — CNSA 2.0 SHA-384 lookup digest
        // (POA&M-211 closed). API keys are random 256-bit values
        // (docs/API-REFERENCE.md), so a fast digest is sufficient; a slow
        // password KDF per configured key per request would be a DoS lever.
        let digest = hex::encode(sha384(credential.as_bytes()));
        // Every configured digest is compared (no early exit).
        let mut matched: Option<&String> = None;
        for h in self.api_key_hashes.iter() {
            if uc_crypto::constant_time::eq(h.as_bytes(), digest.as_bytes()) {
                matched = Some(h);
            }
        }
        matched.map(|h| CredentialId::ApiKey {
            key_id: self.signer.api_key_id(h),
        })
    }

    /// True if `name` is the configured admin username (audit only: an
    /// unknown name is recorded as `unknown`, so a password typed into the
    /// username field is never stored).
    #[must_use]
    pub fn is_admin_user(&self, name: &str) -> bool {
        uc_crypto::constant_time::eq(self.admin.username.as_bytes(), name.as_bytes())
    }
}

/// Hex digits of the keyed API-key audit id (64 bits).
const API_KEY_ID_HEX: usize = 16;
/// Domain-separation label for the API-key audit id MAC (token MACs start
/// with `v2.`, so the two inputs never coincide).
const API_KEY_ID_LABEL: &[u8] = b"sbc-api-key-id:";

/// Who a valid credential belongs to ([`Authenticator::identify`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialId {
    /// A session token minted by [`Authenticator::login`].
    Session {
        /// The token's `sub` claim (the admin username).
        subject: String,
    },
    /// A configured API key.
    ApiKey {
        /// Keyed audit id (16 hex digits; see [`Authenticator::identify`]).
        key_id: String,
    },
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
        // v1 MACs were HMAC-SHA-256 (aws-lc-rs dev-dep; not in uc-crypto).
        let mac = aws_lc_rs::hmac::sign(
            &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key),
            input.as_bytes(),
        );
        let token = format!("{input}.{}", b64(mac.as_ref()));
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

    // ---- SR-40: credential identity for audit attribution ----------------

    /// `test_auth()` plus one accepted API key; returns (auth, key, digest).
    fn auth_with_api_key() -> (Authenticator, String, String) {
        let key = format!("qa-api-key-{}", std::process::id());
        let digest = hex::encode(sha384(key.as_bytes()));
        let auth = Authenticator {
            api_key_hashes: Arc::new(vec![digest.clone()]),
            ..test_auth()
        };
        (auth, key, digest)
    }

    #[test]
    fn identify_session_token_returns_subject() {
        let auth = test_auth();
        let token = auth.login("admin", "correct horse").expect("login");
        match auth.identify(&token) {
            Some(CredentialId::Session { subject }) => assert_eq!(subject, "admin"),
            other => panic!("expected a session credential, got {other:?}"),
        }
        assert!(auth.authorize(&token), "authorize delegates to identify");
    }

    /// SR-40 round 1 (SEC-006): the id is keyed by the signing key, so it
    /// cannot be derived from the key or its digest alone.
    #[test]
    fn identify_api_key_returns_keyed_id_not_key() {
        let (auth, key, digest) = auth_with_api_key();
        let id = |a: &Authenticator| match a.identify(&key) {
            Some(CredentialId::ApiKey { key_id }) => key_id,
            other => panic!("expected an API-key credential, got {other:?}"),
        };
        let key_id = id(&auth);
        assert_eq!(key_id.len(), 16);
        assert!(key_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!key_id.contains(&key), "the key itself is never the id");
        assert_ne!(key_id, digest[..16], "not the unkeyed digest prefix");
        assert_eq!(key_id, id(&auth), "stable for one signing key");
        let other_signer = Authenticator {
            signer: TokenSigner::new(b"another-signing-key-32-bytes-ok!!".to_vec()).expect("key"),
            ..auth.clone()
        };
        assert_ne!(key_id, id(&other_signer), "keyed by the signing key");
        assert!(auth.authorize(&key));
    }

    #[test]
    fn identify_rejects_unknown_credential() {
        let (auth, key, _) = auth_with_api_key();
        for cred in [
            "",
            "garbage",
            "v2.aaaa.bbbb",
            &format!("{key}x"),
            &test_signer().mint("admin", 0),
        ] {
            assert!(auth.identify(cred).is_none(), "{cred:?}");
            assert_eq!(auth.authorize(cred), auth.identify(cred).is_some());
        }
        // A token minted with another key does not identify.
        let other = Authenticator::new(
            "admin",
            &hash_password("correct horse").expect("hash"),
            b"another-signing-key-32-bytes-ok!!".to_vec(),
        )
        .expect("auth");
        let foreign = other.login("admin", "correct horse").expect("login");
        assert!(auth.identify(&foreign).is_none());
    }

    // ---- POA&M-211: SHA-384 API-key digests only -------------------------

    /// SHA-256 for building the rejected legacy digests (aws-lc-rs dev-dep;
    /// uc-auth no longer links `uc_crypto::interop::sha256`).
    fn test_sha256(data: &[u8]) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }

    #[test]
    fn api_key_sha256_digest_no_longer_identifies() {
        let key = format!("qa-api-key-{}", std::process::id());
        let auth = Authenticator {
            api_key_hashes: Arc::new(vec![hex::encode(test_sha256(key.as_bytes()))]),
            ..test_auth()
        };
        assert!(auth.identify(&key).is_none());
    }

    #[test]
    fn api_key_digest_parsing() {
        let d = hex::encode(sha384(b"k"));
        assert_eq!(parse_api_key_digests(None, None).ok(), Some(Vec::new()));
        assert_eq!(
            parse_api_key_digests(Some(" "), Some(&format!(" {}, ,", d.to_uppercase()))).ok(),
            Some(vec![d.clone()])
        );
        // The removed SHA-256 variable fails startup when set.
        let sha256 = hex::encode(test_sha256(b"k"));
        assert!(matches!(
            parse_api_key_digests(Some(&sha256), None),
            Err(AuthError::Invalid {
                var: "SBC_API_KEY_SHA256",
                ..
            })
        ));
        // A SHA-256 digest (64 hex) or non-hex value in the SHA-384 list fails.
        for bad in [sha256.as_str(), &"g".repeat(96), &format!("{d}0")] {
            assert!(
                matches!(
                    parse_api_key_digests(None, Some(bad)),
                    Err(AuthError::Invalid {
                        var: "SBC_API_KEY_SHA384",
                        ..
                    })
                ),
                "{} chars",
                bad.len()
            );
        }
    }

    #[test]
    fn is_admin_user_matches_only_configured_name() {
        let auth = test_auth();
        assert!(auth.is_admin_user("admin"));
        for name in ["", "Admin", "admin ", " admin", "admin\0", "root", "adm"] {
            assert!(!auth.is_admin_user(name), "{name:?}");
        }
    }

    // SR-16 golden vectors: MACs captured from the RustCrypto
    // implementation (cross-checked with openssl / Python hmac) so the
    // move to uc_crypto::hash::hmac_sha384 is proven byte-identical and
    // tokens minted before the upgrade keep verifying.

    /// v2 token for fixed claims under key `0x5a * 48`.
    const GOLDEN_V2_TOKEN: &str = "v2.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMzAwLCJhdWQiOiJzYmMtYXBpIn0.X_7kn_JCspkesoHaqn4aZjZGqj2ZxxN9k-TqDdlSfqL53NzgNx4sJGNEAlZQ8mPx";

    #[test]
    fn v2_token_golden_vector() {
        let signer = test_signer();
        let token = signer.mint_claims(&Claims {
            sub: "admin".to_string(),
            iat: 1_700_000_000,
            exp: 1_700_000_300,
            aud: TOKEN_AUDIENCE.to_string(),
        });
        assert_eq!(token, GOLDEN_V2_TOKEN);
        let (input, mac_b64) = GOLDEN_V2_TOKEN.rsplit_once('.').expect("mac");
        assert_eq!(b64(&signer.sign(input.as_bytes())), mac_b64);
        // Same signing input under a different key must not match.
        let other = TokenSigner::new(vec![0x5b; RECOMMENDED_SIGNING_KEY_BYTES]).expect("signer");
        assert_ne!(b64(&other.sign(input.as_bytes())), mac_b64);
    }

    #[test]
    fn hmac_sha384_rfc4231_test_case_6() {
        // RFC 4231 section 4.7: 131-byte key (above the 32-byte floor).
        let signer = TokenSigner::new(vec![0xaa; 131]).expect("signer");
        let mac = signer.sign(b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex::encode(mac),
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f\
             3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        );
    }
}
