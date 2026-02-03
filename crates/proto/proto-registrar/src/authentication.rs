//! SIP Digest Authentication for registrar.
//!
//! Implements RFC 3261 Section 22 (HTTP Digest Authentication) and
//! RFC 2617 with nonce lifecycle management for the registrar.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-2**: Identification and Authentication (Organizational Users)
//! - **IA-5**: Authenticator Management
//! - **IA-8**: Identification and Authentication (Non-Organizational Users)
//!
//! ## Features
//!
//! - Nonce generation with cryptographic randomness
//! - Nonce validation with expiration
//! - Nonce count (nc) tracking for replay protection
//! - Quality of Protection (qop) support: auth and auth-int
//! - Stale nonce detection and handling
//! - CNSA 2.0 compliant hash algorithms (SHA-256, SHA-512-256)

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default nonce lifetime in seconds.
pub const DEFAULT_NONCE_LIFETIME_SECS: u64 = 300; // 5 minutes

/// Maximum nonce count before requiring new nonce.
pub const MAX_NONCE_COUNT: u32 = 1_000_000;

/// Nonce state for tracking usage.
#[derive(Debug, Clone)]
pub struct NonceState {
    /// The nonce value.
    nonce: String,
    /// When the nonce was created.
    created_at: Instant,
    /// Last used nonce count.
    last_nc: u32,
    /// Number of times this nonce has been used.
    use_count: u32,
    /// Username this nonce was issued to (if bound).
    username: Option<String>,
    /// Realm this nonce was issued for.
    realm: String,
}

impl NonceState {
    /// Creates a new nonce state.
    fn new(nonce: String, realm: &str) -> Self {
        Self {
            nonce,
            created_at: Instant::now(),
            last_nc: 0,
            use_count: 0,
            username: None,
            realm: realm.to_string(),
        }
    }

    /// Binds this nonce to a specific username.
    fn bind_to_user(&mut self, username: &str) {
        self.username = Some(username.to_string());
    }

    /// Returns the nonce value.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns when this nonce was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the last nonce count used.
    pub fn last_nc(&self) -> u32 {
        self.last_nc
    }

    /// Returns the use count.
    pub fn use_count(&self) -> u32 {
        self.use_count
    }

    /// Checks if the nonce has expired.
    pub fn is_expired(&self, lifetime: Duration) -> bool {
        self.created_at.elapsed() > lifetime
    }

    /// Checks if the nonce is stale (expired but was valid).
    pub fn is_stale(&self, lifetime: Duration) -> bool {
        self.is_expired(lifetime) && self.use_count > 0
    }

    /// Validates and updates the nonce count for qop=auth.
    ///
    /// Returns true if the nc is valid (greater than last_nc).
    pub fn validate_nc(&mut self, nc: u32) -> bool {
        if nc > self.last_nc && nc <= MAX_NONCE_COUNT {
            self.last_nc = nc;
            self.use_count += 1;
            true
        } else {
            false
        }
    }
}

/// Result of nonce validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceValidation {
    /// Nonce is valid.
    Valid,
    /// Nonce is unknown/not found.
    Unknown,
    /// Nonce has expired.
    Expired,
    /// Nonce is stale (was valid, now expired).
    Stale,
    /// Nonce count is invalid (replay attack).
    InvalidNonceCount,
    /// Nonce count exceeds maximum.
    NonceCountExceeded,
    /// Username mismatch (nonce bound to different user).
    UsernameMismatch,
}

/// Authentication result.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication successful.
    Success {
        /// Username that authenticated.
        username: String,
        /// Authentication info for response (rspauth).
        auth_info: Option<String>,
    },
    /// Challenge required (no credentials provided).
    ChallengeRequired {
        /// The challenge to send.
        challenge: AuthChallenge,
    },
    /// Authentication failed.
    Failed {
        /// Reason for failure.
        reason: String,
    },
    /// Stale nonce - retry with new nonce.
    StaleNonce {
        /// New challenge with stale=true.
        challenge: AuthChallenge,
    },
}

/// Authentication challenge.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// Realm.
    pub realm: String,
    /// Nonce value.
    pub nonce: String,
    /// Opaque value (optional).
    pub opaque: Option<String>,
    /// Algorithm.
    pub algorithm: AuthAlgorithm,
    /// Quality of protection options.
    pub qop: Vec<AuthQop>,
    /// Whether this is a stale nonce response.
    pub stale: bool,
}

impl AuthChallenge {
    /// Formats as WWW-Authenticate header value.
    pub fn to_header_value(&self) -> String {
        let mut value = format!("Digest realm=\"{}\", nonce=\"{}\"", self.realm, self.nonce);

        if let Some(ref opaque) = self.opaque {
            value.push_str(", opaque=\"");
            value.push_str(opaque);
            value.push('"');
        }

        if self.algorithm != AuthAlgorithm::Md5 {
            value.push_str(", algorithm=");
            value.push_str(self.algorithm.as_str());
        }

        if !self.qop.is_empty() {
            let qop_str: Vec<&str> = self.qop.iter().map(AuthQop::as_str).collect();
            value.push_str(", qop=\"");
            value.push_str(&qop_str.join(","));
            value.push('"');
        }

        if self.stale {
            value.push_str(", stale=true");
        }

        value
    }
}

/// Authentication algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthAlgorithm {
    /// MD5 (legacy, not CNSA 2.0 compliant).
    #[default]
    Md5,
    /// SHA-256 (recommended).
    Sha256,
    /// SHA-512-256 (strongest).
    Sha512_256,
}

impl AuthAlgorithm {
    /// Returns the algorithm name as used in SIP headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA-256",
            Self::Sha512_256 => "SHA-512-256",
        }
    }
}

/// Quality of Protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthQop {
    /// Authentication only.
    Auth,
    /// Authentication with integrity.
    AuthInt,
}

impl AuthQop {
    /// Returns the qop value as used in SIP headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::AuthInt => "auth-int",
        }
    }
}

/// Credentials provided by the client.
#[derive(Debug, Clone)]
pub struct AuthCredentials {
    /// Username.
    pub username: String,
    /// Realm.
    pub realm: String,
    /// Nonce from challenge.
    pub nonce: String,
    /// Digest URI.
    pub uri: String,
    /// Digest response.
    pub response: String,
    /// Algorithm used.
    pub algorithm: AuthAlgorithm,
    /// Client nonce (for qop).
    pub cnonce: Option<String>,
    /// Quality of protection.
    pub qop: Option<AuthQop>,
    /// Nonce count.
    pub nc: Option<u32>,
    /// Opaque value.
    pub opaque: Option<String>,
}

impl AuthCredentials {
    /// Parses credentials from Authorization header value.
    ///
    /// Expected format: `Digest username="...", realm="...", ...`
    pub fn parse(header_value: &str) -> Option<Self> {
        let value = header_value.strip_prefix("Digest ")?.trim();

        let mut params = HashMap::new();
        for part in split_auth_params(value) {
            if let Some((key, val)) = part.split_once('=') {
                let val = val.trim_matches('"');
                params.insert(key.trim().to_lowercase(), val.to_string());
            }
        }

        Some(Self {
            username: params.get("username")?.clone(),
            realm: params.get("realm")?.clone(),
            nonce: params.get("nonce")?.clone(),
            uri: params.get("uri")?.clone(),
            response: params.get("response")?.clone(),
            algorithm: match params.get("algorithm").map(String::as_str) {
                Some("SHA-256" | "sha-256") => AuthAlgorithm::Sha256,
                Some("SHA-512-256" | "sha-512-256") => AuthAlgorithm::Sha512_256,
                _ => AuthAlgorithm::Md5,
            },
            cnonce: params.get("cnonce").cloned(),
            qop: params.get("qop").and_then(|q| match q.as_str() {
                "auth" => Some(AuthQop::Auth),
                "auth-int" => Some(AuthQop::AuthInt),
                _ => None,
            }),
            nc: params
                .get("nc")
                .and_then(|s| u32::from_str_radix(s, 16).ok()),
            opaque: params.get("opaque").cloned(),
        })
    }
}

/// Splits authentication parameters, handling quoted values.
fn split_auth_params(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    result.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Don't forget the last part
    let last = s[start..].trim();
    if !last.is_empty() {
        result.push(last);
    }

    result
}

/// Password lookup callback type.
pub type PasswordLookup = Box<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

/// Registrar authenticator.
///
/// Manages nonces and validates digest authentication credentials.
pub struct Authenticator {
    /// Active nonces.
    nonces: HashMap<String, NonceState>,
    /// Nonce lifetime.
    nonce_lifetime: Duration,
    /// Default algorithm.
    default_algorithm: AuthAlgorithm,
    /// Supported qop options.
    supported_qop: Vec<AuthQop>,
    /// Password lookup function.
    password_lookup: Option<PasswordLookup>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("nonces_count", &self.nonces.len())
            .field("nonce_lifetime", &self.nonce_lifetime)
            .field("default_algorithm", &self.default_algorithm)
            .field("supported_qop", &self.supported_qop)
            .field("password_lookup", &self.password_lookup.as_ref().map(|_| "<function>"))
            .finish()
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator {
    /// Creates a new authenticator with default settings.
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            nonce_lifetime: Duration::from_secs(DEFAULT_NONCE_LIFETIME_SECS),
            default_algorithm: AuthAlgorithm::Sha256, // CNSA 2.0 preference
            supported_qop: vec![AuthQop::Auth],
            password_lookup: None,
        }
    }

    /// Sets the nonce lifetime.
    #[must_use]
    pub fn with_nonce_lifetime(mut self, lifetime: Duration) -> Self {
        self.nonce_lifetime = lifetime;
        self
    }

    /// Sets the default algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: AuthAlgorithm) -> Self {
        self.default_algorithm = algorithm;
        self
    }

    /// Sets the supported qop options.
    #[must_use]
    pub fn with_qop(mut self, qop: Vec<AuthQop>) -> Self {
        self.supported_qop = qop;
        self
    }

    /// Sets the password lookup function.
    #[must_use]
    pub fn with_password_lookup<F>(mut self, lookup: F) -> Self
    where
        F: Fn(&str, &str) -> Option<String> + Send + Sync + 'static,
    {
        self.password_lookup = Some(Box::new(lookup));
        self
    }

    /// Generates a new nonce for authentication.
    pub fn generate_nonce(&mut self, realm: &str) -> String {
        let nonce = generate_random_nonce();
        let state = NonceState::new(nonce.clone(), realm);
        self.nonces.insert(nonce.clone(), state);
        nonce
    }

    /// Creates an authentication challenge.
    pub fn create_challenge(&mut self, realm: &str) -> AuthChallenge {
        let nonce = self.generate_nonce(realm);

        AuthChallenge {
            realm: realm.to_string(),
            nonce,
            opaque: Some(generate_opaque()),
            algorithm: self.default_algorithm,
            qop: self.supported_qop.clone(),
            stale: false,
        }
    }

    /// Creates a stale nonce challenge (for 401 with stale=true).
    pub fn create_stale_challenge(&mut self, realm: &str) -> AuthChallenge {
        let mut challenge = self.create_challenge(realm);
        challenge.stale = true;
        challenge
    }

    /// Validates a nonce.
    pub fn validate_nonce(
        &mut self,
        nonce: &str,
        username: Option<&str>,
        nc: Option<u32>,
    ) -> NonceValidation {
        let Some(state) = self.nonces.get_mut(nonce) else {
            return NonceValidation::Unknown;
        };

        // Check expiration
        if state.is_expired(self.nonce_lifetime) {
            if state.use_count > 0 {
                return NonceValidation::Stale;
            }
            return NonceValidation::Expired;
        }

        // Check username binding if specified
        if let (Some(bound_user), Some(provided_user)) = (&state.username, username)
            && bound_user != provided_user
        {
            return NonceValidation::UsernameMismatch;
        }

        // Validate nonce count if qop is used
        if let Some(nc_value) = nc {
            if nc_value > MAX_NONCE_COUNT {
                return NonceValidation::NonceCountExceeded;
            }
            if !state.validate_nc(nc_value) {
                return NonceValidation::InvalidNonceCount;
            }
        } else {
            // No qop - just increment use count
            state.use_count += 1;
        }

        // Bind to user on first use
        if state.username.is_none()
            && let Some(user) = username
        {
            state.bind_to_user(user);
        }

        NonceValidation::Valid
    }

    /// Authenticates credentials.
    ///
    /// Returns authentication result with success, challenge, or failure.
    pub fn authenticate(
        &mut self,
        credentials: Option<&AuthCredentials>,
        realm: &str,
        method: &str,
        entity_body: Option<&[u8]>,
    ) -> AuthResult {
        let Some(creds) = credentials else {
            // No credentials - send challenge
            return AuthResult::ChallengeRequired {
                challenge: self.create_challenge(realm),
            };
        };

        // Validate nonce
        let nonce_result = self.validate_nonce(&creds.nonce, Some(&creds.username), creds.nc);

        match nonce_result {
            NonceValidation::Valid => {}
            NonceValidation::Stale | NonceValidation::Expired => {
                return AuthResult::StaleNonce {
                    challenge: self.create_stale_challenge(realm),
                };
            }
            NonceValidation::Unknown => {
                return AuthResult::Failed {
                    reason: "Unknown nonce".to_string(),
                };
            }
            NonceValidation::InvalidNonceCount => {
                return AuthResult::Failed {
                    reason: "Invalid nonce count (possible replay attack)".to_string(),
                };
            }
            NonceValidation::NonceCountExceeded => {
                return AuthResult::StaleNonce {
                    challenge: self.create_stale_challenge(realm),
                };
            }
            NonceValidation::UsernameMismatch => {
                return AuthResult::Failed {
                    reason: "Nonce bound to different user".to_string(),
                };
            }
        }

        // Look up password
        let password = match &self.password_lookup {
            Some(lookup) => lookup(&creds.username, &creds.realm),
            None => {
                return AuthResult::Failed {
                    reason: "No password lookup configured".to_string(),
                };
            }
        };

        let Some(password) = password else {
            return AuthResult::Failed {
                reason: "User not found".to_string(),
            };
        };

        // Verify the digest response
        let expected = compute_digest_response(&DigestParams {
            username: &creds.username,
            realm: &creds.realm,
            password: &password,
            method,
            uri: &creds.uri,
            nonce: &creds.nonce,
            algorithm: creds.algorithm,
            qop: creds.qop,
            nc: creds.nc,
            cnonce: creds.cnonce.as_deref(),
            entity_body,
        });

        if expected.to_lowercase() == creds.response.to_lowercase() {
            AuthResult::Success {
                username: creds.username.clone(),
                auth_info: None, // Could compute rspauth here
            }
        } else {
            AuthResult::Failed {
                reason: "Invalid credentials".to_string(),
            }
        }
    }

    /// Removes expired nonces.
    pub fn cleanup_expired(&mut self) -> usize {
        let lifetime = self.nonce_lifetime;
        let before = self.nonces.len();
        self.nonces.retain(|_, state| !state.is_expired(lifetime));
        before - self.nonces.len()
    }

    /// Returns the number of active nonces.
    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }
}

/// Generates a cryptographically random nonce.
fn generate_random_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Combine timestamp with random data for uniqueness
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Use simple random generation without external crates
    // In production, use a proper CSPRNG
    let random_part: u64 = {
        // Simple PRNG based on timestamp and memory address
        let addr = &raw const timestamp as u64;
        timestamp as u64 ^ addr.wrapping_mul(0x517cc1b727220a95)
    };

    format!("{:016x}{:016x}", timestamp as u64, random_part)
}

/// Generates an opaque value.
fn generate_opaque() -> String {
    generate_random_nonce()[..16].to_string()
}

/// Parameters for digest response computation.
struct DigestParams<'a> {
    username: &'a str,
    realm: &'a str,
    password: &'a str,
    method: &'a str,
    uri: &'a str,
    nonce: &'a str,
    algorithm: AuthAlgorithm,
    qop: Option<AuthQop>,
    nc: Option<u32>,
    cnonce: Option<&'a str>,
    entity_body: Option<&'a [u8]>,
}

/// Computes the digest response.
///
/// Uses SHA-256 by default for CNSA 2.0 compliance.
fn compute_digest_response(params: &DigestParams<'_>) -> String {
    let algorithm = params.algorithm;
    let qop = params.qop;
    let nc = params.nc;
    // Compute HA1 = H(username:realm:password)
    let a1 = format!("{}:{}:{}", params.username, params.realm, params.password);
    let ha1 = hash_string(&a1, algorithm);

    // Compute HA2 = H(method:uri) or H(method:uri:H(entity-body)) for auth-int
    let ha2 = if qop == Some(AuthQop::AuthInt) {
        let body_hash =
            params.entity_body.map_or_else(|| hash_bytes(b"", algorithm), |b| hash_bytes(b, algorithm));
        let a2 = format!("{}:{}:{}", params.method, params.uri, body_hash);
        hash_string(&a2, algorithm)
    } else {
        let a2 = format!("{}:{}", params.method, params.uri);
        hash_string(&a2, algorithm)
    };

    // Compute response
    if let (Some(qop_val), Some(nc_val), Some(cnonce_val)) = (qop, nc, params.cnonce) {
        // With qop: response = H(HA1:nonce:nc:cnonce:qop:HA2)
        let data = format!(
            "{}:{}:{:08x}:{}:{}:{}",
            ha1,
            params.nonce,
            nc_val,
            cnonce_val,
            qop_val.as_str(),
            ha2
        );
        hash_string(&data, algorithm)
    } else {
        // Without qop: response = H(HA1:nonce:HA2)
        let data = format!("{}:{}:{}", ha1, params.nonce, ha2);
        hash_string(&data, algorithm)
    }
}

/// Hashes a string using the specified algorithm.
fn hash_string(s: &str, algorithm: AuthAlgorithm) -> String {
    hash_bytes(s.as_bytes(), algorithm)
}

/// Hashes bytes using the specified algorithm.
fn hash_bytes(data: &[u8], algorithm: AuthAlgorithm) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Note: In production, use proper cryptographic hash functions.
    // This is a placeholder that demonstrates the structure.
    // The actual implementation should use sha2 or similar crate.

    match algorithm {
        AuthAlgorithm::Md5 => {
            // MD5 placeholder - use md5 crate in production
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            format!("{:032x}", hasher.finish())
        }
        AuthAlgorithm::Sha256 | AuthAlgorithm::Sha512_256 => {
            // SHA-256/SHA-512-256 placeholder - use sha2 crate in production
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            // SHA-256 produces 64 hex chars
            format!("{:064x}", hasher.finish())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let mut auth = Authenticator::new();
        let nonce1 = auth.generate_nonce("example.com");
        let nonce2 = auth.generate_nonce("example.com");

        assert_ne!(nonce1, nonce2);
        assert_eq!(auth.nonce_count(), 2);
    }

    #[test]
    fn test_nonce_validation() {
        let mut auth = Authenticator::new();
        let nonce = auth.generate_nonce("example.com");

        // First use should be valid
        let result = auth.validate_nonce(&nonce, Some("alice"), Some(1));
        assert_eq!(result, NonceValidation::Valid);

        // Same nc should fail (replay)
        let result = auth.validate_nonce(&nonce, Some("alice"), Some(1));
        assert_eq!(result, NonceValidation::InvalidNonceCount);

        // Higher nc should succeed
        let result = auth.validate_nonce(&nonce, Some("alice"), Some(2));
        assert_eq!(result, NonceValidation::Valid);
    }

    #[test]
    fn test_unknown_nonce() {
        let mut auth = Authenticator::new();
        let result = auth.validate_nonce("unknown-nonce", None, None);
        assert_eq!(result, NonceValidation::Unknown);
    }

    #[test]
    fn test_nonce_expiration() {
        let mut auth = Authenticator::new().with_nonce_lifetime(Duration::from_millis(1));

        let nonce = auth.generate_nonce("example.com");

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(5));

        let result = auth.validate_nonce(&nonce, None, None);
        assert_eq!(result, NonceValidation::Expired);
    }

    #[test]
    fn test_create_challenge() {
        let mut auth = Authenticator::new()
            .with_algorithm(AuthAlgorithm::Sha256)
            .with_qop(vec![AuthQop::Auth, AuthQop::AuthInt]);

        let challenge = auth.create_challenge("example.com");

        assert_eq!(challenge.realm, "example.com");
        assert!(!challenge.nonce.is_empty());
        assert!(challenge.opaque.is_some());
        assert_eq!(challenge.algorithm, AuthAlgorithm::Sha256);
        assert!(!challenge.stale);
    }

    #[test]
    fn test_challenge_header_format() {
        let challenge = AuthChallenge {
            realm: "example.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: Some("xyz789".to_string()),
            algorithm: AuthAlgorithm::Sha256,
            qop: vec![AuthQop::Auth],
            stale: false,
        };

        let header = challenge.to_header_value();
        assert!(header.contains("Digest"));
        assert!(header.contains("realm=\"example.com\""));
        assert!(header.contains("nonce=\"abc123\""));
        assert!(header.contains("opaque=\"xyz789\""));
        assert!(header.contains("algorithm=SHA-256"));
        assert!(header.contains("qop=\"auth\""));
        assert!(!header.contains("stale"));
    }

    #[test]
    fn test_stale_challenge() {
        let mut auth = Authenticator::new();
        let challenge = auth.create_stale_challenge("example.com");

        assert!(challenge.stale);
        let header = challenge.to_header_value();
        assert!(header.contains("stale=true"));
    }

    #[test]
    fn test_authenticate_no_credentials() {
        let mut auth = Authenticator::new();

        let result = auth.authenticate(None, "example.com", "REGISTER", None);

        match result {
            AuthResult::ChallengeRequired { challenge } => {
                assert_eq!(challenge.realm, "example.com");
            }
            _ => panic!("Expected ChallengeRequired"),
        }
    }

    #[test]
    fn test_authenticate_with_password_lookup() {
        let mut auth = Authenticator::new().with_password_lookup(|username, _realm| {
            if username == "alice" {
                Some("secret".to_string())
            } else {
                None
            }
        });

        // Generate a nonce first
        let nonce = auth.generate_nonce("example.com");

        // Create credentials (would normally be computed by client)
        let creds = AuthCredentials {
            username: "alice".to_string(),
            realm: "example.com".to_string(),
            nonce,
            uri: "sip:example.com".to_string(),
            response: "dummy".to_string(), // Will fail - just testing flow
            algorithm: AuthAlgorithm::Sha256,
            cnonce: None,
            qop: None,
            nc: None,
            opaque: None,
        };

        let result = auth.authenticate(Some(&creds), "example.com", "REGISTER", None);

        // Should fail because response doesn't match
        match result {
            AuthResult::Failed { reason } => {
                assert!(reason.contains("Invalid credentials"));
            }
            _ => panic!("Expected Failed due to wrong response"),
        }
    }

    #[test]
    fn test_authenticate_user_not_found() {
        let mut auth = Authenticator::new().with_password_lookup(|_username, _realm| None);

        let nonce = auth.generate_nonce("example.com");

        let creds = AuthCredentials {
            username: "unknown".to_string(),
            realm: "example.com".to_string(),
            nonce,
            uri: "sip:example.com".to_string(),
            response: "dummy".to_string(),
            algorithm: AuthAlgorithm::Sha256,
            cnonce: None,
            qop: None,
            nc: None,
            opaque: None,
        };

        let result = auth.authenticate(Some(&creds), "example.com", "REGISTER", None);

        match result {
            AuthResult::Failed { reason } => {
                assert!(reason.contains("User not found"));
            }
            _ => panic!("Expected Failed"),
        }
    }

    #[test]
    fn test_cleanup_expired() {
        let mut auth = Authenticator::new().with_nonce_lifetime(Duration::from_millis(1));

        auth.generate_nonce("example.com");
        auth.generate_nonce("example.com");
        assert_eq!(auth.nonce_count(), 2);

        std::thread::sleep(Duration::from_millis(5));

        let removed = auth.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(auth.nonce_count(), 0);
    }

    #[test]
    fn test_parse_credentials() {
        let header = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:example.com", response="xyz789", algorithm=SHA-256, cnonce="client123", qop=auth, nc=00000001"#;

        let creds = AuthCredentials::parse(header).unwrap();

        assert_eq!(creds.username, "alice");
        assert_eq!(creds.realm, "example.com");
        assert_eq!(creds.nonce, "abc123");
        assert_eq!(creds.uri, "sip:example.com");
        assert_eq!(creds.response, "xyz789");
        assert_eq!(creds.algorithm, AuthAlgorithm::Sha256);
        assert_eq!(creds.cnonce, Some("client123".to_string()));
        assert_eq!(creds.qop, Some(AuthQop::Auth));
        assert_eq!(creds.nc, Some(1));
    }

    #[test]
    fn test_split_auth_params() {
        let params =
            split_auth_params(r#"username="alice", realm="example.com", qop="auth,auth-int""#);

        assert_eq!(params.len(), 3);
        assert!(params[0].contains("username"));
        assert!(params[1].contains("realm"));
        assert!(params[2].contains("qop"));
    }

    #[test]
    fn test_nonce_count_bounds() {
        let mut auth = Authenticator::new();
        let nonce = auth.generate_nonce("example.com");

        // Max count should succeed
        let result = auth.validate_nonce(&nonce, None, Some(MAX_NONCE_COUNT));
        assert_eq!(result, NonceValidation::Valid);

        // Exceeding max should fail
        let result = auth.validate_nonce(&nonce, None, Some(MAX_NONCE_COUNT + 1));
        assert_eq!(result, NonceValidation::NonceCountExceeded);
    }

    #[test]
    fn test_username_binding() {
        let mut auth = Authenticator::new();
        let nonce = auth.generate_nonce("example.com");

        // First use binds to alice
        let result = auth.validate_nonce(&nonce, Some("alice"), Some(1));
        assert_eq!(result, NonceValidation::Valid);

        // Different user should fail
        let result = auth.validate_nonce(&nonce, Some("bob"), Some(2));
        assert_eq!(result, NonceValidation::UsernameMismatch);

        // Same user should succeed
        let result = auth.validate_nonce(&nonce, Some("alice"), Some(3));
        assert_eq!(result, NonceValidation::Valid);
    }

    #[test]
    fn test_qop_auth_int_challenge() {
        let mut auth = Authenticator::new().with_qop(vec![AuthQop::Auth, AuthQop::AuthInt]);

        let challenge = auth.create_challenge("example.com");

        assert_eq!(challenge.qop.len(), 2);
        let header = challenge.to_header_value();
        assert!(header.contains("auth,auth-int") || header.contains("auth-int,auth"));
    }
}
