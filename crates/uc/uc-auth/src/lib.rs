//! Shared management-plane authentication for the USG SBC.
//!
//! The SBC's management surface is served by several horizontally-scaled,
//! stateless pods (`sbc-api-server`, `sbc-provision-server`) behind nginx, so
//! per-process session tables don't work — a token minted by one replica must
//! validate on any other. This crate therefore issues **stateless,
//! HMAC-SHA256-signed bearer tokens**: any replica holding the same signing
//! key validates a token with no shared store.
//!
//! - Admin login verifies a username + password against an argon2id hash.
//! - Successful login mints a signed token carrying `{sub, exp}`.
//! - API keys (SHA-256 hashed) are supported for non-interactive clients.
//! - An axum middleware enforces deny-by-default on a route surface.
//!
//! Configuration is entirely environment-driven (12-factor / k8s Secrets):
//! see [`Authenticator::from_env`].
//!
//! ## NIST 800-53 Rev5 Controls
//! - **IA-2**: Identification and Authentication (Organizational Users)
//! - **IA-5**: Authenticator Management (argon2id at rest)
//! - **AC-3**: Access Enforcement (deny-by-default middleware)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Default admin username when `SBC_ADMIN_USER` is unset.
const DEFAULT_ADMIN_USER: &str = "admin";
/// Default session token lifetime (seconds): 12 hours.
const DEFAULT_TOKEN_TTL_SECS: u64 = 12 * 60 * 60;

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
    /// Expiry as a Unix timestamp (seconds).
    pub exp: u64,
}

/// Mints and verifies stateless HMAC-SHA256 bearer tokens.
///
/// Token wire format: `v1.<b64url(claims_json)>.<b64url(hmac)>` where the MAC
/// covers the `v1.<b64url(claims_json)>` prefix.
#[derive(Clone)]
pub struct TokenSigner {
    key: Arc<Vec<u8>>,
}

impl TokenSigner {
    /// Creates a signer from raw key bytes.
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self { key: Arc::new(key) }
    }

    /// Mints a token for `subject` valid for `ttl_secs` seconds.
    #[must_use]
    pub fn mint(&self, subject: &str, ttl_secs: u64) -> String {
        let exp = now_secs().saturating_add(ttl_secs);
        let claims = Claims {
            sub: subject.to_string(),
            exp,
        };
        // serde_json on a 2-field struct of owned String/u64 cannot fail.
        let json = serde_json::to_vec(&claims).unwrap_or_default();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let signing_input = format!("v1.{b64}");
        let mac = self.sign(signing_input.as_bytes());
        let mac_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac);
        format!("{signing_input}.{mac_b64}")
    }

    /// Verifies a token's signature and expiry, returning its claims.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let (signing_input, mac_b64) = token.rsplit_once('.')?;
        let prefix = signing_input.strip_prefix("v1.")?;
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
        if claims.exp <= now_secs() {
            return None;
        }
        Some(claims)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
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
    ///   replicas. If unset a random key is generated and a warning is
    ///   logged (single-replica only — tokens won't validate across pods).
    /// - `SBC_API_KEY_SHA256` — comma-separated SHA-256 hex digests of
    ///   accepted API keys (optional).
    /// - `SBC_AUTH_TOKEN_TTL_SECS` — token lifetime (default 43200).
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
            info!("Hashing SBC_ADMIN_PASSWORD at startup; prefer SBC_ADMIN_PASSWORD_HASH in production");
            hash_password(&p)?
        } else {
            return Err(AuthError::NoAdminCredentials);
        };

        let signer = match std::env::var("SBC_AUTH_SIGNING_KEY") {
            Ok(hex_key) if !hex_key.trim().is_empty() => {
                let key = hex::decode(hex_key.trim()).map_err(|e| AuthError::Invalid {
                    var: "SBC_AUTH_SIGNING_KEY",
                    reason: e.to_string(),
                })?;
                TokenSigner::new(key)
            }
            _ => {
                warn!(
                    "SBC_AUTH_SIGNING_KEY not set — generating a random per-process key. \
                     Tokens will NOT validate across replicas; set a shared key (k8s Secret) \
                     for any multi-replica deployment."
                );
                TokenSigner::new(random_key())
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
            Ok(v) => v.parse().map_err(|e: std::num::ParseIntError| AuthError::Invalid {
                var: "SBC_AUTH_TOKEN_TTL_SECS",
                reason: e.to_string(),
            })?,
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
    #[must_use]
    pub fn new(admin_user: &str, admin_password_hash: &str, signing_key: Vec<u8>) -> Self {
        Self {
            admin: AdminCredentials {
                username: admin_user.to_string(),
                password_hash: admin_password_hash.to_string(),
            },
            signer: TokenSigner::new(signing_key),
            api_key_hashes: Arc::new(Vec::new()),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        }
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
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        }
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
    let ok = extract_credential(req.headers())
        .is_some_and(|c| layer.authenticator.authorize(&c));
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
    let mut buf = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth() -> Authenticator {
        let hash = hash_password("correct horse").expect("hash");
        Authenticator::new("admin", &hash, b"shared-signing-key-32-bytes-long!".to_vec())
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
    }

    #[test]
    fn token_validates_across_instances_with_same_key() {
        // Simulates two replicas sharing the signing key.
        let key = b"shared-signing-key-32-bytes-long!".to_vec();
        let hash = hash_password("pw").expect("hash");
        let a = Authenticator::new("admin", &hash, key.clone());
        let b = Authenticator::new("admin", &hash, key);
        let token = a.login("admin", "pw").expect("login");
        assert!(b.authorize(&token), "replica B must accept replica A's token");
    }

    #[test]
    fn token_rejected_with_different_key() {
        let hash = hash_password("pw").expect("hash");
        let a = Authenticator::new("admin", &hash, b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec());
        let b = Authenticator::new("admin", &hash, b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_vec());
        let token = a.login("admin", "pw").expect("login");
        assert!(!b.authorize(&token));
    }

    #[test]
    fn expired_token_rejected() {
        let signer = TokenSigner::new(b"k".to_vec());
        let token = signer.mint("admin", 0); // exp = now, <= now → expired
        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn extract_credential_bearer_and_cookie() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(extract_credential(&h).as_deref(), Some("abc"));

        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::COOKIE, "x=1; sbc_session=tok".parse().unwrap());
        assert_eq!(extract_credential(&h).as_deref(), Some("tok"));
    }
}
