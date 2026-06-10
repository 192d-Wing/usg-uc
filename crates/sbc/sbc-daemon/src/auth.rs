//! Management-plane authentication.
//!
//! Every mutating REST and gRPC endpoint requires authentication. Two
//! credential types are supported:
//!
//! - **Admin login** (`POST /api/v1/auth/login`): username + password
//!   verified against an argon2id hash, yielding a session token delivered
//!   both as a JSON body (for `Authorization: Bearer` clients such as
//!   sbc-cli) and as an `HttpOnly; Secure; SameSite=Strict` cookie (for the
//!   dashboard).
//! - **API keys**: long-lived high-entropy keys for automation and gRPC
//!   clients, stored as SHA-256 hashes.
//!
//! Credentials persist in `admin_credentials.json` (mode 0600) next to the
//! TLS bootstrap material. On first start with no credential file, a random
//! admin password is generated and printed to the log **once**; set
//! `SBC_ADMIN_PASSWORD` to provision a known password non-interactively.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-2**: Identification and Authentication (Organizational Users)
//! - **IA-5**: Authenticator Management (argon2id at rest, 0600 perms)
//! - **AC-3**: Access Enforcement (deny-by-default middleware)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Session lifetime.
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Credential store file name (lives alongside the TLS bootstrap dir).
const CREDENTIALS_FILE: &str = "admin_credentials.json";

/// Persisted admin credentials.
#[derive(Debug, Serialize, Deserialize)]
struct StoredCredentials {
    /// Admin username.
    username: String,
    /// argon2id PHC-format password hash.
    password_hash: String,
    /// SHA-256 hex digests of API keys.
    #[serde(default)]
    api_key_hashes: Vec<String>,
}

/// Authentication mode for the management plane.
pub enum AuthMode {
    /// Authentication enforced (production path; always set by the runtime).
    Enforced(Box<AdminAuth>),
    /// Authentication disabled. Only used by unit tests that exercise
    /// handlers directly; the runtime never constructs this.
    Disabled,
}

/// Loaded admin credentials plus the in-memory session table.
pub struct AdminAuth {
    username: String,
    password_hash: String,
    api_key_hashes: Vec<String>,
    sessions: RwLock<HashMap<String, Instant>>,
}

/// Shared authentication state.
pub struct AuthState {
    /// Active mode.
    pub mode: AuthMode,
}

impl AuthState {
    /// Authentication disabled — for unit tests only.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            mode: AuthMode::Disabled,
        }
    }

    /// Enforced authentication backed by `auth`.
    #[must_use]
    pub fn enforced(auth: AdminAuth) -> Self {
        Self {
            mode: AuthMode::Enforced(Box::new(auth)),
        }
    }

    /// Validates a bearer/session token or API key.
    pub fn validate_token(&self, token: &str) -> bool {
        match &self.mode {
            AuthMode::Disabled => true,
            AuthMode::Enforced(auth) => auth.validate_token(token),
        }
    }

    /// Authorizes a request given its (possibly absent) credential.
    pub fn authorize(&self, token: Option<&str>) -> bool {
        match &self.mode {
            AuthMode::Disabled => true,
            AuthMode::Enforced(auth) => token.is_some_and(|t| auth.validate_token(t)),
        }
    }

    /// Attempts a username/password login, returning a session token.
    pub fn login(&self, username: &str, password: &str) -> Option<String> {
        match &self.mode {
            AuthMode::Disabled => Some("test-session".to_string()),
            AuthMode::Enforced(auth) => auth.login(username, password),
        }
    }

    /// Invalidates a session token.
    pub fn logout(&self, token: &str) {
        if let AuthMode::Enforced(auth) = &self.mode {
            auth.logout(token);
        }
    }
}

impl AdminAuth {
    /// Loads credentials from `dir`, bootstrapping on first start.
    ///
    /// Bootstrap order: `SBC_ADMIN_PASSWORD` env var if set, otherwise a
    /// generated random password printed to the log once.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential file cannot be read, parsed, or
    /// created.
    pub fn load_or_bootstrap(dir: &Path) -> Result<Self, String> {
        let env_password = std::env::var("SBC_ADMIN_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty());
        Self::load_or_bootstrap_with(dir, env_password)
    }

    /// Test helper: bootstraps credentials in `dir` with a known password.
    #[cfg(test)]
    pub fn load_or_bootstrap_for_test(dir: &Path, password: &str) -> Self {
        Self::load_or_bootstrap_with(dir, Some(password.to_string()))
            .expect("test bootstrap should succeed")
    }

    /// [`Self::load_or_bootstrap`] with an explicit bootstrap password
    /// (testable without env mutation).
    fn load_or_bootstrap_with(
        dir: &Path,
        bootstrap_password: Option<String>,
    ) -> Result<Self, String> {
        let path = dir.join(CREDENTIALS_FILE);

        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            let stored: StoredCredentials = serde_json::from_str(&data)
                .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
            info!(
                user = %stored.username,
                api_keys = stored.api_key_hashes.len(),
                path = %path.display(),
                "Loaded admin credentials"
            );
            return Ok(Self {
                username: stored.username,
                password_hash: stored.password_hash,
                api_key_hashes: stored.api_key_hashes,
                sessions: RwLock::new(HashMap::new()),
            });
        }

        // First start: bootstrap credentials.
        let (password, from_env) = match bootstrap_password {
            Some(p) => (p, true),
            None => (random_token(18), false),
        };

        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("password hashing failed: {e}"))?
            .to_string();

        let stored = StoredCredentials {
            username: "admin".to_string(),
            password_hash: password_hash.clone(),
            api_key_hashes: Vec::new(),
        };

        std::fs::create_dir_all(dir)
            .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| format!("failed to serialize credentials: {e}"))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
        restrict_permissions(&path);

        if from_env {
            info!(
                path = %path.display(),
                "Bootstrapped admin credentials from SBC_ADMIN_PASSWORD (user: admin)"
            );
        } else {
            // Intentionally printed once at first start so the operator can
            // log in; rotate via SBC_ADMIN_PASSWORD + deleting the file.
            warn!(
                path = %path.display(),
                "Generated initial admin credentials — user: admin  password: {password}  \
                 (shown only once; set SBC_ADMIN_PASSWORD to provision a known password)"
            );
        }

        Ok(Self {
            username: stored.username,
            password_hash: stored.password_hash,
            api_key_hashes: stored.api_key_hashes,
            sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Verifies a login and creates a session.
    fn login(&self, username: &str, password: &str) -> Option<String> {
        if username != self.username {
            // Hash anyway to keep timing comparable between unknown-user
            // and wrong-password failures.
            let _ = Argon2::default().verify_password(
                password.as_bytes(),
                &PasswordHash::new(&self.password_hash).ok()?,
            );
            return None;
        }

        let parsed = PasswordHash::new(&self.password_hash).ok()?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .ok()?;

        let token = random_token(32);
        if let Ok(mut sessions) = self.sessions.write() {
            let now = Instant::now();
            sessions.retain(|_, created| now.duration_since(*created) < SESSION_TTL);
            sessions.insert(token.clone(), now);
        }
        Some(token)
    }

    /// Validates a session token or API key.
    fn validate_token(&self, token: &str) -> bool {
        // Session token?
        if let Ok(sessions) = self.sessions.read() {
            if let Some(created) = sessions.get(token) {
                if created.elapsed() < SESSION_TTL {
                    return true;
                }
            }
        }

        // API key? Keys are high-entropy, so a fast hash comparison is
        // appropriate (argon2 here would add ~100ms to every request).
        if !self.api_key_hashes.is_empty() {
            let digest = hex::encode(Sha256::digest(token.as_bytes()));
            return self
                .api_key_hashes
                .iter()
                .any(|h| constant_time_eq(h.as_bytes(), digest.as_bytes()));
        }

        false
    }

    fn logout(&self, token: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.remove(token);
        }
    }
}

/// Extracts a credential from an HTTP request: `Authorization: Bearer`
/// header first, then the `sbc_session` cookie.
pub fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }

    let cookies = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(token) = pair.strip_prefix("sbc_session=") {
            return Some(token.to_string());
        }
    }
    None
}

/// Generates a URL-safe random token of `bytes` entropy bytes (hex-encoded).
fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Returns the directory used to persist admin credentials.
///
/// Mirrors the TLS bootstrap resolution: `SBC_STATE_DIR` env var, then
/// `/var/lib/sbc`, falling back to `$HOME/.local/state/sbc` when the
/// primary directory is not writable.
pub fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SBC_STATE_DIR") {
        return PathBuf::from(dir);
    }
    let primary = PathBuf::from("/var/lib/sbc");
    if is_writable_dir(&primary) {
        return primary;
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local").join("state").join("sbc");
    }
    primary
}

/// Checks whether `dir` exists (or can be created) and is writable.
fn is_writable_dir(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".sbc-write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Sets 0600 on the credential file (Unix).
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!(path = %path.display(), error = %e, "Failed to set permissions");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sbc-auth-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_bootstrap_login_and_session() {
        let dir = temp_dir("bootstrap");
        let auth = AdminAuth::load_or_bootstrap_with(
            &dir,
            Some("correct horse battery".to_string()),
        )
        .expect("bootstrap");

        assert!(auth.login("admin", "wrong").is_none());
        assert!(auth.login("nobody", "correct horse battery").is_none());

        let token = auth.login("admin", "correct horse battery").expect("login");
        assert!(auth.validate_token(&token));
        assert!(!auth.validate_token("bogus"));

        auth.logout(&token);
        assert!(!auth.validate_token(&token));

        // Reload from disk and verify the password still works.
        let reloaded = AdminAuth::load_or_bootstrap_with(&dir, None).expect("reload");
        assert!(reloaded.login("admin", "correct horse battery").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_extract_token() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc123".parse().expect("header"),
        );
        assert_eq!(extract_token(&headers).as_deref(), Some("abc123"));

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=1; sbc_session=tok456".parse().expect("header"),
        );
        assert_eq!(extract_token(&headers).as_deref(), Some("tok456"));

        assert_eq!(extract_token(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn test_credentials_file_permissions() {
        let dir = temp_dir("perms");
        // No bootstrap password: exercises the random-password path.
        let _auth = AdminAuth::load_or_bootstrap_with(&dir, None).expect("bootstrap");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CREDENTIALS_FILE))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
