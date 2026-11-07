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
//! - SHA-256 / SHA-512-256 (RFC 7616) and legacy MD5
//!
//! ## Policy enforcement (POA&M-230)
//!
//! The server's configuration, not the client, decides every
//! security-relevant parameter. `authenticate` rejects a credential whose
//! `realm`, `algorithm` (RFC 7616 §3.7, no downgrade) or `qop` differs from
//! what was offered, whose `uri` does not match the Request-URI (RFC 7616
//! §3.4.6, RFC 3261 §19.1.4 comparison) or whose `opaque` does not echo the
//! challenge. nc is committed only after the response matched, so a party
//! without the password cannot burn a victim's nonce counts (RFC 7616
//! §3.4.5). NIST 800-53 Rev5: IA-2(8), IA-5(1).
//!
//! CNSA 2.0: SHA-256 and SHA-512/256 are not CNSA hashes; SIP digest stays
//! under the existing exception (POA&M-110) because RFC 7616 defines no
//! SHA-384.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Default nonce lifetime in seconds.
pub const DEFAULT_NONCE_LIFETIME_SECS: u64 = 300; // 5 minutes

/// Maximum nonce count before requiring new nonce.
pub const MAX_NONCE_COUNT: u32 = 1_000_000;

/// Default bound on outstanding nonces (NIST 800-53 Rev5: SC-5).
pub const DEFAULT_MAX_NONCES: usize = 65_536;

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
    /// Opaque value sent with this nonce (must be echoed).
    opaque: Option<String>,
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
            opaque: None,
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

        // POA&M-230: an unknown or unsupported (`-sess`) algorithm or qop
        // is malformed, never silently mapped to MD5 / "no qop"
        // (NIST 800-53 Rev5: SC-24 fail closed). Absent algorithm is MD5 per
        // RFC 7616 §3.3; the authenticator then rejects it unless MD5 is the
        // configured algorithm.
        let algorithm = match params.get("algorithm") {
            None => AuthAlgorithm::Md5,
            Some(a) if a.eq_ignore_ascii_case("MD5") => AuthAlgorithm::Md5,
            Some(a) if a.eq_ignore_ascii_case("SHA-256") => AuthAlgorithm::Sha256,
            Some(a) if a.eq_ignore_ascii_case("SHA-512-256") => AuthAlgorithm::Sha512_256,
            Some(_) => return None,
        };
        let qop = match params.get("qop") {
            None => None,
            Some(q) if q.eq_ignore_ascii_case("auth") => Some(AuthQop::Auth),
            Some(q) if q.eq_ignore_ascii_case("auth-int") => Some(AuthQop::AuthInt),
            Some(_) => return None,
        };
        let nc = match params.get("nc") {
            None => None,
            Some(s) => Some(u32::from_str_radix(s, 16).ok()?),
        };

        Some(Self {
            username: params.get("username")?.clone(),
            realm: params.get("realm")?.clone(),
            nonce: params.get("nonce")?.clone(),
            uri: params.get("uri")?.clone(),
            response: params.get("response")?.clone(),
            algorithm,
            cnonce: params.get("cnonce").cloned(),
            qop,
            nc,
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
    /// Nonces in issue order (oldest at the front). Every key in `nonces`
    /// appears exactly once here, so eviction and expiry sweeps pop from the
    /// front in amortised O(1) instead of scanning the map
    /// (NIST 800-53 Rev5: SC-5).
    order: VecDeque<String>,
    /// Nonce lifetime.
    nonce_lifetime: Duration,
    /// Default algorithm.
    default_algorithm: AuthAlgorithm,
    /// Supported qop options.
    supported_qop: Vec<AuthQop>,
    /// Password lookup function.
    password_lookup: Option<PasswordLookup>,
    /// Bound on outstanding nonces (SC-5).
    max_nonces: usize,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("nonces_count", &self.nonces.len())
            .field("order_len", &self.order.len())
            .field("nonce_lifetime", &self.nonce_lifetime)
            .field("default_algorithm", &self.default_algorithm)
            .field("supported_qop", &self.supported_qop)
            .field("max_nonces", &self.max_nonces)
            .field(
                "password_lookup",
                &self.password_lookup.as_ref().map(|_| "<function>"),
            )
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
            order: VecDeque::new(),
            nonce_lifetime: Duration::from_secs(DEFAULT_NONCE_LIFETIME_SECS),
            default_algorithm: AuthAlgorithm::Sha256, // CNSA 2.0 preference
            supported_qop: vec![AuthQop::Auth],
            password_lookup: None,
            max_nonces: DEFAULT_MAX_NONCES,
        }
    }

    /// Sets the bound on outstanding nonces (minimum 1).
    #[must_use]
    pub fn with_max_nonces(mut self, max: usize) -> Self {
        self.max_nonces = max.max(1);
        self
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
    ///
    /// NIST 800-53 Rev5: SC-5 - expired nonces at the front of the issue
    /// queue are dropped and, if still at the bound, the oldest outstanding
    /// nonce is evicted (its holder is simply re-challenged). Both steps pop
    /// from the front of `order`, so the insert path never scans the table.
    pub fn generate_nonce(&mut self, realm: &str) -> String {
        if self.nonces.len() >= self.max_nonces {
            self.cleanup_expired();
        }
        while self.nonces.len() >= self.max_nonces {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.nonces.remove(&oldest);
        }
        let nonce = generate_random_nonce();
        let state = NonceState::new(nonce.clone(), realm);
        if self.nonces.insert(nonce.clone(), state).is_none() {
            self.order.push_back(nonce.clone());
        }
        nonce
    }

    /// Creates an authentication challenge.
    pub fn create_challenge(&mut self, realm: &str) -> AuthChallenge {
        let nonce = self.generate_nonce(realm);
        let opaque = generate_opaque();
        if let Some(state) = self.nonces.get_mut(&nonce) {
            state.opaque = Some(opaque.clone());
        }

        AuthChallenge {
            realm: realm.to_string(),
            nonce,
            opaque: Some(opaque),
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

    /// Checks a nonce without changing any state: existence, expiry,
    /// username binding and that `nc` would be accepted.
    pub fn check_nonce(
        &self,
        nonce: &str,
        username: Option<&str>,
        nc: Option<u32>,
    ) -> NonceValidation {
        let Some(state) = self.nonces.get(nonce) else {
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

        // NIST 800-53 Rev5: IA-2(8) - without qop there is no nc, so a
        // nonce is single-use (legacy RFC 2069 mode, only reachable when an
        // operator configures an empty qop list).
        if nc.is_none() && state.use_count > 0 {
            return NonceValidation::InvalidNonceCount;
        }

        // RFC 7616 §3.4.5: nc strictly increasing per nonce.
        if let Some(nc_value) = nc {
            if nc_value > MAX_NONCE_COUNT {
                return NonceValidation::NonceCountExceeded;
            }
            if nc_value <= state.last_nc {
                return NonceValidation::InvalidNonceCount;
            }
        }

        NonceValidation::Valid
    }

    /// Records a successful use of `nonce`: advances nc and binds the nonce
    /// to `username` on first use. Call only after the response verified.
    pub fn commit_nc(&mut self, nonce: &str, username: Option<&str>, nc: Option<u32>) {
        let Some(state) = self.nonces.get_mut(nonce) else {
            return;
        };
        match nc {
            Some(nc_value) => {
                let _ = state.validate_nc(nc_value);
            }
            None => state.use_count += 1,
        }
        if state.username.is_none()
            && let Some(user) = username
        {
            state.bind_to_user(user);
        }
    }

    /// Validates a nonce and, if valid, commits it ([`Self::check_nonce`]
    /// followed by [`Self::commit_nc`]).
    pub fn validate_nonce(
        &mut self,
        nonce: &str,
        username: Option<&str>,
        nc: Option<u32>,
    ) -> NonceValidation {
        let result = self.check_nonce(nonce, username, nc);
        if result == NonceValidation::Valid {
            self.commit_nc(nonce, username, nc);
        }
        result
    }

    /// Checks the credential parameters against the server policy and
    /// returns the failure reason, if any.
    fn check_policy(
        &self,
        creds: &AuthCredentials,
        realm: &str,
        request_uri: Option<&str>,
    ) -> Option<&'static str> {
        if creds.realm != realm {
            return Some("Realm mismatch");
        }
        // RFC 7616 §3.7: the server's algorithm, never the client's.
        if creds.algorithm != self.default_algorithm {
            return Some("Algorithm mismatch");
        }
        match creds.qop {
            None if !self.supported_qop.is_empty() => return Some("qop required"),
            Some(q) if !self.supported_qop.contains(&q) => return Some("qop not offered"),
            Some(_) if creds.cnonce.as_deref().is_none_or(str::is_empty) || creds.nc.is_none() => {
                return Some("cnonce and nc required with qop");
            }
            _ => {}
        }
        // RFC 7616 §3.4.6 / RFC 3261 §22.4: digest-uri is the Request-URI,
        // compared with RFC 3261 §19.1.4 rules.
        //
        // POAM: when the caller does not supply the Request-URI (the
        // sbc-daemon REGISTER path does not yet set
        // `RegisterRequest::request_uri`) this check cannot run; tracked in
        // BACKLOG.md as the POA&M-230 caller follow-up.
        if let Some(ruri) = request_uri {
            let same = match (
                creds.uri.parse::<proto_sip::SipUri>(),
                ruri.parse::<proto_sip::SipUri>(),
            ) {
                (Ok(a), Ok(b)) => a.equivalent(&b),
                _ => false,
            };
            if !same {
                return Some("Digest uri does not match Request-URI");
            }
        }
        None
    }

    /// Authenticates credentials.
    ///
    /// `request_uri` is the Request-URI the credentials must be bound to;
    /// pass `None` only when it is genuinely unavailable (see the POAM note
    /// on the uri check).
    ///
    /// Returns authentication result with success, challenge, or failure.
    pub fn authenticate(
        &mut self,
        credentials: Option<&AuthCredentials>,
        realm: &str,
        method: &str,
        request_uri: Option<&str>,
        entity_body: Option<&[u8]>,
    ) -> AuthResult {
        let Some(creds) = credentials else {
            // No credentials - send challenge
            return AuthResult::ChallengeRequired {
                challenge: self.create_challenge(realm),
            };
        };

        if let Some(reason) = self.check_policy(creds, realm, request_uri) {
            return AuthResult::Failed {
                reason: reason.to_string(),
            };
        }

        // Validate nonce (no state change yet).
        let nonce_result = self.check_nonce(&creds.nonce, Some(&creds.username), creds.nc);

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

        // Opaque must echo the value sent with this nonce.
        let opaque_ok = self
            .nonces
            .get(&creds.nonce)
            .is_some_and(|st| st.opaque.is_none() || st.opaque == creds.opaque);
        if !opaque_ok {
            return AuthResult::Failed {
                reason: "Opaque mismatch".to_string(),
            };
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

        // Verify the digest response with the configured algorithm.
        let expected = compute_digest_response(&DigestParams {
            username: &creds.username,
            realm: &creds.realm,
            password: &password,
            method,
            uri: &creds.uri,
            nonce: &creds.nonce,
            algorithm: self.default_algorithm,
            qop: creds.qop,
            nc: creds.nc,
            cnonce: creds.cnonce.as_deref(),
            entity_body,
        });

        // Constant-time comparison of the hex digests.
        let presented = creds.response.to_lowercase();
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            expected.as_bytes(),
            presented.as_bytes(),
        )
        .is_ok()
        {
            // Commit nc only after the response matched (RFC 7616 §3.4.5).
            self.commit_nc(&creds.nonce, Some(&creds.username), creds.nc);
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
    ///
    /// Nonces are queued in issue order and share one lifetime, so the
    /// expired ones form a prefix of `order`; the sweep costs O(expired).
    pub fn cleanup_expired(&mut self) -> usize {
        let lifetime = self.nonce_lifetime;
        let mut removed = 0;
        while let Some(front) = self.order.front() {
            match self.nonces.get(front) {
                Some(state) if !state.is_expired(lifetime) => break,
                Some(_) => {
                    self.nonces.remove(front);
                    removed += 1;
                }
                None => {}
            }
            self.order.pop_front();
        }
        removed
    }

    /// Returns the number of active nonces.
    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }
}

/// Returns `n` CSPRNG bytes as lowercase hex.
fn random_hex(n: usize) -> String {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    use std::fmt::Write;

    let mut bytes = vec![0u8; n];
    // SystemRandom only fails if the OS entropy source is unavailable; a
    // nonce from a failed fill would be all zeros, so refuse instead.
    #[allow(clippy::expect_used)]
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system CSPRNG unavailable");
    bytes.iter().fold(String::with_capacity(n * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Generates a cryptographically random 128-bit nonce.
fn generate_random_nonce() -> String {
    random_hex(16)
}

/// Generates a random opaque value, independent of the nonce.
fn generate_opaque() -> String {
    random_hex(8)
}

/// Parameters for digest response computation.
pub(crate) struct DigestParams<'a> {
    pub(crate) username: &'a str,
    pub(crate) realm: &'a str,
    pub(crate) password: &'a str,
    pub(crate) method: &'a str,
    pub(crate) uri: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) algorithm: AuthAlgorithm,
    pub(crate) qop: Option<AuthQop>,
    pub(crate) nc: Option<u32>,
    pub(crate) cnonce: Option<&'a str>,
    pub(crate) entity_body: Option<&'a [u8]>,
}

/// Computes the digest response.
///
/// Uses SHA-256 by default for CNSA 2.0 compliance.
pub(crate) fn compute_digest_response(params: &DigestParams<'_>) -> String {
    let algorithm = params.algorithm;
    let qop = params.qop;
    let nc = params.nc;
    // Compute HA1 = H(username:realm:password)
    let a1 = format!("{}:{}:{}", params.username, params.realm, params.password);
    let ha1 = hash_string(&a1, algorithm);

    // Compute HA2 = H(method:uri) or H(method:uri:H(entity-body)) for auth-int
    let ha2 = if qop == Some(AuthQop::AuthInt) {
        let body_hash = params
            .entity_body
            .map_or_else(|| hash_bytes(b"", algorithm), |b| hash_bytes(b, algorithm));
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

/// Hashes bytes using the specified algorithm, returning lowercase hex.
fn hash_bytes(data: &[u8], algorithm: AuthAlgorithm) -> String {
    use std::fmt::Write;

    let to_hex = |bytes: &[u8]| {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    };

    match algorithm {
        AuthAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
        AuthAlgorithm::Sha256 => {
            to_hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref())
        }
        AuthAlgorithm::Sha512_256 => {
            to_hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512_256, data).as_ref())
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

    /// Nonces must come from a CSPRNG: consecutive values share no
    /// clock-derived prefix, and the opaque is not a slice of the nonce.
    #[test]
    fn nonce_is_not_clock_derived() {
        let a = generate_random_nonce();
        let b = generate_random_nonce();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        // The leading 64 bits must not be the wall clock in nanoseconds.
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let hour_ns = 3_600_000_000_000u64;
        let lead = u64::from_str_radix(&a[..16], 16).unwrap();
        assert!(
            lead.abs_diff(now_ns) > hour_ns,
            "nonce prefix is the clock: {a}"
        );
        let mut auth = Authenticator::new();
        let challenge = auth.create_challenge("example.com");
        let opaque = challenge.opaque.unwrap();
        assert!(!challenge.nonce.starts_with(&opaque));
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
        assert_ne!(challenge.nonce, "");
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

        let result = auth.authenticate(None, "example.com", "REGISTER", None, None);

        match result {
            AuthResult::ChallengeRequired { challenge } => {
                assert_eq!(challenge.realm, "example.com");
            }
            _ => panic!("Expected ChallengeRequired"),
        }
    }

    /// RFC 2617 §3.5 worked example (MD5, qop=auth).
    #[test]
    fn digest_response_matches_rfc2617_example() {
        let response = compute_digest_response(&DigestParams {
            username: "Mufasa",
            realm: "testrealm@host.com",
            password: "Circle Of Life",
            method: "GET",
            uri: "/dir/index.html",
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            algorithm: AuthAlgorithm::Md5,
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            cnonce: Some("0a4f113b"),
            entity_body: None,
        });
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    /// The SHA-2 variants must be the real hash functions (FIPS 180-4 "abc"
    /// vectors), not a placeholder.
    #[test]
    fn hash_bytes_uses_real_sha2() {
        assert_eq!(
            hash_bytes(b"abc", AuthAlgorithm::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_bytes(b"abc", AuthAlgorithm::Sha512_256),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
        assert_eq!(
            hash_bytes(b"abc", AuthAlgorithm::Md5),
            "900150983cd24fb0d6963f7d28e17f72"
        );
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
            cnonce: Some("c".to_string()),
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            opaque: None,
        };

        let result = auth.authenticate(Some(&creds), "example.com", "REGISTER", None, None);

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
            cnonce: Some("c".to_string()),
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            opaque: None,
        };

        let result = auth.authenticate(Some(&creds), "example.com", "REGISTER", None, None);

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

    /// Builds correct credentials for a fresh challenge.
    fn good_creds(auth: &mut Authenticator, alg: AuthAlgorithm, uri: &str) -> AuthCredentials {
        let challenge = auth.create_challenge("example.com");
        let response = compute_digest_response(&DigestParams {
            username: "alice",
            realm: "example.com",
            password: "secret",
            method: "REGISTER",
            uri,
            nonce: &challenge.nonce,
            algorithm: alg,
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            cnonce: Some("cn"),
            entity_body: None,
        });
        AuthCredentials {
            username: "alice".to_string(),
            realm: "example.com".to_string(),
            nonce: challenge.nonce,
            uri: uri.to_string(),
            response,
            algorithm: alg,
            cnonce: Some("cn".to_string()),
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            opaque: challenge.opaque,
        }
    }

    fn alice_auth() -> Authenticator {
        Authenticator::new().with_password_lookup(|u, _| (u == "alice").then(|| "secret".into()))
    }

    fn reason(r: AuthResult) -> String {
        match r {
            AuthResult::Failed { reason } => reason,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    const RURI: Option<&str> = Some("sip:example.com");

    #[test]
    fn realm_mismatch_rejected_before_response_check() {
        let mut auth = alice_auth();
        let creds = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        assert_eq!(
            reason(auth.authenticate(Some(&creds), "other.example.com", "REGISTER", RURI, None)),
            "Realm mismatch"
        );
        // The realm reject must not consume the nonce/nc: the same creds still work.
        assert!(matches!(
            auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None),
            AuthResult::Success { .. }
        ));
    }

    #[test]
    fn correct_credentials_succeed_once() {
        let mut auth = alice_auth();
        let creds = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        assert!(matches!(
            auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None),
            AuthResult::Success { .. }
        ));
        // Same nc again is a replay.
        assert!(
            reason(auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None))
                .contains("replay")
        );
    }

    /// A *correct* MD5 response is rejected when SHA-256 is configured.
    #[test]
    fn algorithm_downgrade_rejected() {
        let mut auth = alice_auth();
        let creds = good_creds(&mut auth, AuthAlgorithm::Md5, "sip:example.com");
        assert_eq!(
            reason(auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None)),
            "Algorithm mismatch"
        );
    }

    #[test]
    fn qop_mismatch_rejected() {
        let mut auth = alice_auth();
        let mut creds = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        creds.qop = Some(AuthQop::AuthInt);
        assert_eq!(
            reason(auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None)),
            "qop not offered"
        );
        creds.qop = None;
        assert_eq!(
            reason(auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None)),
            "qop required"
        );
    }

    #[test]
    fn uri_mismatch_rejected_equivalent_accepted() {
        let mut auth = alice_auth();
        let creds = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        assert_eq!(
            reason(auth.authenticate(
                Some(&creds),
                "example.com",
                "REGISTER",
                Some("sip:other.example.com"),
                None
            )),
            "Digest uri does not match Request-URI"
        );
        assert!(matches!(
            auth.authenticate(
                Some(&creds),
                "example.com",
                "REGISTER",
                Some("sip:EXAMPLE.com"),
                None
            ),
            AuthResult::Success { .. }
        ));
    }

    #[test]
    fn bad_response_does_not_consume_nc() {
        let mut auth = alice_auth();
        let good = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        let mut bad = good.clone();
        bad.response = "00".repeat(32);
        assert_eq!(
            reason(auth.authenticate(Some(&bad), "example.com", "REGISTER", RURI, None)),
            "Invalid credentials"
        );
        assert!(matches!(
            auth.authenticate(Some(&good), "example.com", "REGISTER", RURI, None),
            AuthResult::Success { .. }
        ));
    }

    #[test]
    fn opaque_must_echo() {
        let mut auth = alice_auth();
        let mut creds = good_creds(&mut auth, AuthAlgorithm::Sha256, "sip:example.com");
        creds.opaque = Some("forged".to_string());
        assert_eq!(
            reason(auth.authenticate(Some(&creds), "example.com", "REGISTER", RURI, None)),
            "Opaque mismatch"
        );
    }

    #[test]
    fn unknown_algorithm_or_qop_is_malformed() {
        let base = r#"Digest username="a", realm="r", nonce="n", uri="sip:r", response="x""#;
        assert!(AuthCredentials::parse(&format!("{base}, algorithm=SHA-1")).is_none());
        assert!(AuthCredentials::parse(&format!("{base}, algorithm=MD5-sess")).is_none());
        assert!(AuthCredentials::parse(&format!("{base}, qop=bogus")).is_none());
        assert!(AuthCredentials::parse(&format!("{base}, nc=zz")).is_none());
        let c = AuthCredentials::parse(&format!("{base}, algorithm=sha-512-256")).unwrap();
        assert_eq!(c.algorithm, AuthAlgorithm::Sha512_256);
    }

    #[test]
    fn nonce_table_is_bounded() {
        let mut auth = Authenticator::new().with_max_nonces(3);
        let first = auth.generate_nonce("r");
        std::thread::sleep(Duration::from_millis(2));
        for _ in 0..10 {
            auth.generate_nonce("r");
        }
        assert_eq!(auth.nonce_count(), 3);
        assert_eq!(
            auth.check_nonce(&first, None, None),
            NonceValidation::Unknown
        );
    }

    #[test]
    fn full_table_evicts_oldest_in_order_and_stays_bounded() {
        let mut auth = Authenticator::new().with_max_nonces(4);
        let issued: Vec<String> = (0..4).map(|_| auth.generate_nonce("r")).collect();
        // Each further nonce evicts exactly the oldest outstanding one.
        for (i, old) in issued.iter().enumerate() {
            auth.generate_nonce("r");
            assert_eq!(auth.check_nonce(old, None, None), NonceValidation::Unknown);
            for newer in &issued[i + 1..] {
                assert_eq!(auth.check_nonce(newer, None, None), NonceValidation::Valid);
            }
        }
        for _ in 0..10_000 {
            auth.generate_nonce("r");
        }
        assert_eq!(auth.nonce_count(), 4);
        assert_eq!(auth.order.len(), 4);
    }

    #[test]
    fn cleanup_expired_drains_queue() {
        let mut auth = Authenticator::new().with_nonce_lifetime(Duration::from_millis(1));
        for _ in 0..5 {
            auth.generate_nonce("r");
        }
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(auth.cleanup_expired(), 5);
        assert_eq!(auth.nonce_count(), 0);
        assert!(auth.order.is_empty());
    }

    #[test]
    fn nonce_without_qop_is_single_use() {
        let mut auth = Authenticator::new().with_qop(vec![]);
        let n = auth.generate_nonce("r");
        assert_eq!(
            auth.validate_nonce(&n, Some("u"), None),
            NonceValidation::Valid
        );
        assert_eq!(
            auth.validate_nonce(&n, Some("u"), None),
            NonceValidation::InvalidNonceCount
        );
    }

    /// RFC 7616 §3.9.1 SHA-256 vector (recomputed with Python hashlib).
    #[test]
    fn digest_response_matches_rfc7616_sha256_vector() {
        let response = compute_digest_response(&DigestParams {
            username: "Mufasa",
            realm: "http-auth@example.org",
            password: "Circle of Life",
            method: "GET",
            uri: "/dir/index.html",
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
            algorithm: AuthAlgorithm::Sha256,
            qop: Some(AuthQop::Auth),
            nc: Some(1),
            cnonce: Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"),
            entity_body: None,
        });
        assert_eq!(
            response,
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
    }
}
