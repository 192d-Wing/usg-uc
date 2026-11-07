//! SIP Digest Authentication per RFC 2617 and RFC 3261 Section 22.
//!
//! Provides parsing and generation of WWW-Authenticate, Authorization,
//! Proxy-Authenticate, and Proxy-Authorization headers.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::{SipError, SipResult};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

/// Digest authentication algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DigestAlgorithm {
    /// MD5 algorithm (legacy, not recommended).
    #[default]
    Md5,
    /// MD5-sess algorithm (legacy, not recommended).
    Md5Sess,
    /// SHA-256 algorithm.
    Sha256,
    /// SHA-256-sess algorithm.
    Sha256Sess,
    /// SHA-512-256 algorithm.
    Sha512_256,
    /// SHA-512-256-sess algorithm.
    Sha512_256Sess,
}

impl DigestAlgorithm {
    /// Returns the algorithm name for use in headers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
            Self::Sha512_256 => "SHA-512-256",
            Self::Sha512_256Sess => "SHA-512-256-sess",
        }
    }

    /// Returns true if this is a session-based algorithm.
    #[must_use]
    pub fn is_session(&self) -> bool {
        matches!(
            self,
            Self::Md5Sess | Self::Sha256Sess | Self::Sha512_256Sess
        )
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        match s.to_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "MD5-SESS" => Ok(Self::Md5Sess),
            "SHA-256" => Ok(Self::Sha256),
            "SHA-256-SESS" => Ok(Self::Sha256Sess),
            "SHA-512-256" => Ok(Self::Sha512_256),
            "SHA-512-256-SESS" => Ok(Self::Sha512_256Sess),
            _ => Err(SipError::InvalidHeader {
                name: "algorithm".to_string(),
                reason: format!("unknown digest algorithm: {s}"),
            }),
        }
    }
}

/// Quality of Protection options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qop {
    /// Authentication only.
    Auth,
    /// Authentication with integrity protection.
    AuthInt,
}

impl Qop {
    /// Returns the qop value string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::AuthInt => "auth-int",
        }
    }
}

impl fmt::Display for Qop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Qop {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        match s.to_lowercase().as_str() {
            "auth" => Ok(Self::Auth),
            "auth-int" => Ok(Self::AuthInt),
            _ => Err(SipError::InvalidHeader {
                name: "qop".to_string(),
                reason: format!("unknown qop value: {s}"),
            }),
        }
    }
}

/// Parsed `WWW-Authenticate` or `Proxy-Authenticate` challenge.
///
/// Format: `Digest realm="...", nonce="...", ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    /// Authentication realm.
    pub realm: String,
    /// Server nonce.
    pub nonce: String,
    /// Opaque value (optional).
    pub opaque: Option<String>,
    /// Algorithm (defaults to MD5).
    pub algorithm: DigestAlgorithm,
    /// Quality of protection options.
    pub qop: Vec<Qop>,
    /// Domain (optional).
    pub domain: Option<String>,
    /// Stale flag.
    pub stale: bool,
    /// Additional parameters.
    pub params: HashMap<String, String>,
}

impl DigestChallenge {
    /// Creates a new digest challenge.
    #[must_use]
    pub fn new(realm: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            nonce: nonce.into(),
            opaque: None,
            algorithm: DigestAlgorithm::default(),
            qop: Vec::new(),
            domain: None,
            stale: false,
            params: HashMap::new(),
        }
    }

    /// Sets the algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the opaque value.
    #[must_use]
    pub fn with_opaque(mut self, opaque: impl Into<String>) -> Self {
        self.opaque = Some(opaque.into());
        self
    }

    /// Adds a qop option.
    #[must_use]
    pub fn with_qop(mut self, qop: Qop) -> Self {
        if !self.qop.contains(&qop) {
            self.qop.push(qop);
        }
        self
    }

    /// Sets the stale flag.
    #[must_use]
    pub fn with_stale(mut self, stale: bool) -> Self {
        self.stale = stale;
        self
    }

    /// Sets the domain.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
}

impl fmt::Display for DigestChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest realm=\"{}\", nonce=\"{}\"",
            self.realm, self.nonce
        )?;

        // RFC 7616 §3.3: always name the algorithm, including MD5, so the
        // client never has to infer it.
        write!(f, ", algorithm={}", self.algorithm)?;

        if let Some(ref opaque) = self.opaque {
            write!(f, ", opaque=\"{opaque}\"")?;
        }

        if !self.qop.is_empty() {
            let qop_str: Vec<&str> = self.qop.iter().map(Qop::as_str).collect();
            write!(f, ", qop=\"{}\"", qop_str.join(","))?;
        }

        if let Some(ref domain) = self.domain {
            write!(f, ", domain=\"{domain}\"")?;
        }

        if self.stale {
            write!(f, ", stale=true")?;
        }

        for (name, value) in &self.params {
            write!(f, ", {name}=\"{value}\"")?;
        }

        Ok(())
    }
}

/// Extracts a required parameter from parsed auth parameters.
fn get_required_param(
    params: &HashMap<String, String>,
    name: &str,
    header: &str,
) -> SipResult<String> {
    params
        .get(name)
        .cloned()
        .ok_or_else(|| SipError::InvalidHeader {
            name: header.to_string(),
            reason: format!("missing {name}"),
        })
}

/// Filters out known parameters and returns extra parameters.
fn filter_extra_params(params: HashMap<String, String>, known: &[&str]) -> HashMap<String, String> {
    params
        .into_iter()
        .filter(|(k, _)| !known.iter().any(|&known_key| k == known_key))
        .collect()
}

impl FromStr for DigestChallenge {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        let s = s.trim();
        // NIST 800-53 Rev5: SI-10 - untrusted input, real error (was debug_assert).
        if s.is_empty() {
            return Err(SipError::InvalidHeader {
                name: "WWW-Authenticate".to_string(),
                reason: "empty challenge".to_string(),
            });
        }
        let params_str = s
            .strip_prefix("Digest ")
            .or_else(|| s.strip_prefix("digest "))
            .unwrap_or(s);

        let params = parse_auth_params(params_str)?;

        let realm = get_required_param(&params, "realm", "WWW-Authenticate")?;
        let nonce = get_required_param(&params, "nonce", "WWW-Authenticate")?;

        let algorithm = params
            .get("algorithm")
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or_default();

        let qop: Vec<Qop> = params
            .get("qop")
            .map(|s| s.split(',').filter_map(|q| q.trim().parse().ok()).collect())
            .unwrap_or_default();

        let extra_params = filter_extra_params(
            params.clone(),
            &[
                "realm",
                "nonce",
                "algorithm",
                "opaque",
                "domain",
                "stale",
                "qop",
            ],
        );

        Ok(Self {
            realm,
            nonce,
            opaque: params.get("opaque").cloned(),
            algorithm,
            qop,
            domain: params.get("domain").cloned(),
            stale: params
                .get("stale")
                .is_some_and(|s| s.eq_ignore_ascii_case("true")),
            params: extra_params,
        })
    }
}

/// Parsed Authorization or `Proxy-Authorization` credentials.
///
/// Format: `Digest username="...", realm="...", nonce="...", uri="...", response="..."`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestCredentials {
    /// Username.
    pub username: String,
    /// Authentication realm.
    pub realm: String,
    /// Server nonce.
    pub nonce: String,
    /// Digest URI.
    pub uri: String,
    /// Response hash.
    pub response: String,
    /// Algorithm used.
    pub algorithm: DigestAlgorithm,
    /// Client nonce (required if qop is set).
    pub cnonce: Option<String>,
    /// Quality of protection used.
    pub qop: Option<Qop>,
    /// Nonce count (required if qop is set).
    pub nc: Option<u32>,
    /// Opaque value (if provided in challenge).
    pub opaque: Option<String>,
    /// Additional parameters.
    pub params: HashMap<String, String>,
}

impl DigestCredentials {
    /// Creates new digest credentials.
    #[must_use]
    pub fn new(
        username: impl Into<String>,
        realm: impl Into<String>,
        nonce: impl Into<String>,
        uri: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            realm: realm.into(),
            nonce: nonce.into(),
            uri: uri.into(),
            response: response.into(),
            algorithm: DigestAlgorithm::default(),
            cnonce: None,
            qop: None,
            nc: None,
            opaque: None,
            params: HashMap::new(),
        }
    }

    /// Sets the algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets qop-related fields.
    #[must_use]
    pub fn with_qop(mut self, qop: Qop, cnonce: impl Into<String>, nc: u32) -> Self {
        self.qop = Some(qop);
        self.cnonce = Some(cnonce.into());
        self.nc = Some(nc);
        self
    }

    /// Sets the opaque value.
    #[must_use]
    pub fn with_opaque(mut self, opaque: impl Into<String>) -> Self {
        self.opaque = Some(opaque.into());
        self
    }
}

impl fmt::Display for DigestCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
            self.username, self.realm, self.nonce, self.uri, self.response
        )?;

        if self.algorithm != DigestAlgorithm::Md5 {
            write!(f, ", algorithm={}", self.algorithm)?;
        }

        if let Some(ref opaque) = self.opaque {
            write!(f, ", opaque=\"{opaque}\"")?;
        }

        if let Some(qop) = self.qop {
            write!(f, ", qop={qop}")?;

            if let Some(ref cnonce) = self.cnonce {
                write!(f, ", cnonce=\"{cnonce}\"")?;
            }

            if let Some(nc) = self.nc {
                write!(f, ", nc={nc:08x}")?;
            }
        }

        for (name, value) in &self.params {
            write!(f, ", {name}=\"{value}\"")?;
        }

        Ok(())
    }
}

impl FromStr for DigestCredentials {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        let s = s.trim();
        // NIST 800-53 Rev5: SI-10 - untrusted input, real error (was debug_assert).
        if s.is_empty() {
            return Err(SipError::InvalidHeader {
                name: "Authorization".to_string(),
                reason: "empty credentials".to_string(),
            });
        }
        let params_str = s
            .strip_prefix("Digest ")
            .or_else(|| s.strip_prefix("digest "))
            .unwrap_or(s);

        let params = parse_auth_params(params_str)?;

        let username = get_required_param(&params, "username", "Authorization")?;
        let realm = get_required_param(&params, "realm", "Authorization")?;
        let nonce = get_required_param(&params, "nonce", "Authorization")?;
        let uri = get_required_param(&params, "uri", "Authorization")?;
        let response = get_required_param(&params, "response", "Authorization")?;

        let algorithm = params
            .get("algorithm")
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or_default();

        let extra_params = filter_extra_params(
            params.clone(),
            &[
                "username",
                "realm",
                "nonce",
                "uri",
                "response",
                "algorithm",
                "opaque",
                "cnonce",
                "qop",
                "nc",
            ],
        );

        Ok(Self {
            username,
            realm,
            nonce,
            uri,
            response,
            algorithm,
            cnonce: params.get("cnonce").cloned(),
            qop: params.get("qop").map(|s| s.parse()).transpose()?,
            nc: params
                .get("nc")
                .and_then(|s| u32::from_str_radix(s, 16).ok()),
            opaque: params.get("opaque").cloned(),
            params: extra_params,
        })
    }
}

/// Parses authentication parameters from a header value.
///
/// Handles quoted and unquoted values.
///
/// # Loop Bounds (Power of 10 Rule 2)
///
/// - Outer loop bounded by number of commas in input
/// - Inner quote scanning bounded by parameter length
fn parse_auth_params(s: &str) -> SipResult<HashMap<String, String>> {
    let mut params = HashMap::new();

    // Simple state machine for parsing
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    // Power of 10 Rule 2: Loop bounded by chars.len()
    while i < chars.len() {
        let c = chars[i];

        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' && in_quotes {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ',' && !in_quotes {
            // End of parameter
            if let Some((name, value)) = parse_single_param(&current) {
                params.insert(name, value);
                // NIST 800-53 Rev5: SC-5 - bound auth-params.
                if params.len() > crate::MAX_PARAMS {
                    return Err(SipError::LimitExceeded {
                        what: "auth parameters",
                        limit: crate::MAX_PARAMS,
                    });
                }
            }
            current.clear();
        } else {
            current.push(c);
        }

        i += 1;
    }

    // Handle last parameter
    if !current.is_empty()
        && let Some((name, value)) = parse_single_param(&current)
    {
        params.insert(name, value);
    }

    Ok(params)
}

/// Parses a single `name=value` or `name="value"` parameter.
fn parse_single_param(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let (name, value) = s.split_once('=')?;
    let name = name.trim().to_lowercase();
    let value = value.trim().trim_matches('"').to_string();
    Some((name, value))
}

/// Trait for computing digest authentication hashes.
///
/// This trait abstracts the hash algorithm, allowing the protocol library
/// to remain independent of specific crypto implementations.
///
/// Implementations must use:
/// - MD5 for `DigestAlgorithm::Md5` and `Md5Sess`
/// - SHA-256 for `DigestAlgorithm::Sha256` and `Sha256Sess`
/// - SHA-512/256 for `DigestAlgorithm::Sha512_256` and `Sha512_256Sess`
///
/// RFC 7616 §3.4.1: the hash is selected by the `algorithm` parameter. The
/// digest functions refuse a hasher whose [`DigestHasher::handles`] returns
/// false for the algorithm in use, so an MD5 hasher can never answer or verify
/// a SHA-256 challenge (POA&M-230; NIST 800-53 Rev5: SC-13, SC-24 fail closed).
pub trait DigestHasher {
    /// Computes the hash of the input and returns it as a lowercase hex string.
    fn hash(&self, input: &[u8]) -> String;

    /// Returns true if this hasher implements the hash function named by
    /// `algorithm` (session and non-session variants share one hash).
    ///
    /// There is deliberately no default: an implementor must state which
    /// algorithms it computes, or every digest computation fails closed.
    fn handles(&self, algorithm: DigestAlgorithm) -> bool;
}

/// Lowercase hex encoding of a digest output.
#[cfg(feature = "digest-auth")]
fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// MD5 hasher for digest authentication (legacy compatibility).
///
/// WARNING: MD5 is cryptographically weak. Only use for
/// interoperability with systems that don't support SHA-256.
#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Md5DigestHasher;

#[cfg(feature = "digest-auth")]
impl DigestHasher for Md5DigestHasher {
    fn hash(&self, input: &[u8]) -> String {
        format!("{:x}", md5::compute(input))
    }

    fn handles(&self, algorithm: DigestAlgorithm) -> bool {
        matches!(algorithm, DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess)
    }
}

/// SHA-256 hasher for digest authentication (RFC 7616 §3.2).
///
/// NIST 800-53 Rev5: SC-13 (Cryptographic Protection) - computed by
/// aws-lc-rs (the FIPS 140-3 validated module only when the build enables
/// the `aws-lc-rs/fips` feature, e.g. via the workspace `fips` feature). Not a CNSA 2.0 hash; SIP digest stays under the
/// existing CNSA exception (POA&M-110) because RFC 7616 defines no SHA-384.
#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256DigestHasher;

#[cfg(feature = "digest-auth")]
impl DigestHasher for Sha256DigestHasher {
    fn hash(&self, input: &[u8]) -> String {
        to_hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input).as_ref())
    }

    fn handles(&self, algorithm: DigestAlgorithm) -> bool {
        matches!(
            algorithm,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess
        )
    }
}

/// SHA-512/256 hasher for digest authentication (RFC 7616 §3.2).
///
/// This is the FIPS 180-4 SHA-512/256 function (its own initial hash
/// values), not SHA-512 truncated to 256 bits.
#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha512_256DigestHasher;

#[cfg(feature = "digest-auth")]
impl DigestHasher for Sha512_256DigestHasher {
    fn hash(&self, input: &[u8]) -> String {
        to_hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512_256, input).as_ref())
    }

    fn handles(&self, algorithm: DigestAlgorithm) -> bool {
        matches!(
            algorithm,
            DigestAlgorithm::Sha512_256 | DigestAlgorithm::Sha512_256Sess
        )
    }
}

/// Hasher selected from the `algorithm` of a challenge or policy.
///
/// Enum dispatch (no boxing). Use [`AlgorithmHasher::for_algorithm`] with the
/// challenge's algorithm on the UAC side and with the configured policy
/// algorithm on the server side.
#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmHasher {
    /// MD5 / MD5-sess.
    Md5,
    /// SHA-256 / SHA-256-sess.
    Sha256,
    /// SHA-512-256 / SHA-512-256-sess.
    Sha512_256,
}

#[cfg(feature = "digest-auth")]
impl AlgorithmHasher {
    /// Returns the hasher that implements `algorithm`.
    #[must_use]
    pub fn for_algorithm(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => Self::Md5,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => Self::Sha256,
            DigestAlgorithm::Sha512_256 | DigestAlgorithm::Sha512_256Sess => Self::Sha512_256,
        }
    }
}

#[cfg(feature = "digest-auth")]
impl DigestHasher for AlgorithmHasher {
    fn hash(&self, input: &[u8]) -> String {
        match self {
            Self::Md5 => Md5DigestHasher.hash(input),
            Self::Sha256 => Sha256DigestHasher.hash(input),
            Self::Sha512_256 => Sha512_256DigestHasher.hash(input),
        }
    }

    fn handles(&self, algorithm: DigestAlgorithm) -> bool {
        Self::for_algorithm(algorithm) == *self
    }
}

/// Rejects a hasher that does not implement `algorithm` (fail closed).
fn ensure_hasher(hasher: &impl DigestHasher, algorithm: DigestAlgorithm) -> SipResult<()> {
    if hasher.handles(algorithm) {
        Ok(())
    } else {
        Err(SipError::InvalidHeader {
            name: "algorithm".to_string(),
            reason: format!("hasher does not implement digest algorithm {algorithm}"),
        })
    }
}

/// Generates a client nonce for digest authentication.
///
/// Uses cryptographic randomness to prevent prediction and replay attacks.
#[cfg(feature = "digest-auth")]
#[must_use]
/// Generates a random cnonce (client nonce) for digest authentication.
///
/// # Panics
///
/// Panics if the CSPRNG fails (via `getrandom`), which is unrecoverable.
#[allow(clippy::expect_used)]
pub fn generate_cnonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom failed");
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Computes HA1 for digest authentication per RFC 2617 Section 3.2.2.1.
///
/// For non-session algorithms: `HA1 = H(username:realm:password)`
/// For session algorithms: `HA1 = H(H(username:realm:password):nonce:cnonce)`
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `username` - The user's username
/// * `realm` - The authentication realm
/// * `password` - The user's password
/// * `algorithm` - The digest algorithm being used
/// * `nonce` - Server nonce (required for session algorithms)
/// * `cnonce` - Client nonce (required for session algorithms)
///
/// # Errors
///
/// Returns an error if `hasher` does not implement `algorithm`, or if a
/// session algorithm is used without `nonce`/`cnonce`.
pub fn compute_ha1(
    hasher: &impl DigestHasher,
    username: &str,
    realm: &str,
    password: &str,
    algorithm: DigestAlgorithm,
    nonce: Option<&str>,
    cnonce: Option<&str>,
) -> SipResult<String> {
    // RFC 7616 §3.4.2: A1 is hashed with the negotiated algorithm.
    ensure_hasher(hasher, algorithm)?;
    let mut a1 = String::with_capacity(username.len() + realm.len() + password.len() + 2);

    let _ = write!(a1, "{username}:{realm}:{password}");
    let ha1_base = hasher.hash(a1.as_bytes());

    if algorithm.is_session() {
        let nonce = nonce.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "nonce required for session algorithm".to_string(),
        })?;
        let cnonce = cnonce.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "cnonce required for session algorithm".to_string(),
        })?;
        let mut a1_sess = String::with_capacity(ha1_base.len() + nonce.len() + cnonce.len() + 2);
        let _ = write!(a1_sess, "{ha1_base}:{nonce}:{cnonce}");
        Ok(hasher.hash(a1_sess.as_bytes()))
    } else {
        Ok(ha1_base)
    }
}

/// Computes HA2 for digest authentication per RFC 2617 Section 3.2.2.2.
///
/// For qop=auth or no qop: `HA2 = H(method:digest-uri)`
/// For qop=auth-int: `HA2 = H(method:digest-uri:H(entity-body))`
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `method` - The SIP method (e.g., "INVITE", "REGISTER")
/// * `uri` - The digest URI
/// * `qop` - Quality of protection option
/// * `entity_body` - The message body (required for auth-int)
///
/// # Errors
///
/// Returns an error if HA2 computation fails.
pub fn compute_ha2(
    hasher: &impl DigestHasher,
    method: &str,
    uri: &str,
    qop: Option<Qop>,
    entity_body: Option<&[u8]>,
) -> SipResult<String> {
    let a2 = if qop == Some(Qop::AuthInt) {
        let body = entity_body.unwrap_or(&[]);
        let body_hash = hasher.hash(body);
        let mut s = String::with_capacity(method.len() + uri.len() + body_hash.len() + 2);

        let _ = write!(s, "{method}:{uri}:{body_hash}");
        s
    } else {
        let mut s = String::with_capacity(method.len() + uri.len() + 1);

        let _ = write!(s, "{method}:{uri}");
        s
    };

    Ok(hasher.hash(a2.as_bytes()))
}

/// Computes the digest response per RFC 2617 Section 3.2.2.
///
/// Without qop: `response = H(HA1:nonce:HA2)`
/// With qop: `response = H(HA1:nonce:nc:cnonce:qop:HA2)`
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `ha1` - Pre-computed HA1 value
/// * `nonce` - Server nonce
/// * `nc` - Nonce count (required if qop is set)
/// * `cnonce` - Client nonce (required if qop is set)
/// * `qop` - Quality of protection option
/// * `ha2` - Pre-computed HA2 value
///
/// # Errors
///
/// Returns an error if response computation fails.
pub fn compute_response(
    hasher: &impl DigestHasher,
    ha1: &str,
    nonce: &str,
    nc: Option<u32>,
    cnonce: Option<&str>,
    qop: Option<Qop>,
    ha2: &str,
) -> SipResult<String> {
    let response_str = if let Some(qop) = qop {
        let nc = nc.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "nc required when qop is set".to_string(),
        })?;
        let cnonce = cnonce.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "cnonce required when qop is set".to_string(),
        })?;
        let qop_str = qop.as_str();
        let mut s = String::with_capacity(
            ha1.len() + nonce.len() + 8 + cnonce.len() + qop_str.len() + ha2.len() + 5,
        );

        let _ = write!(s, "{ha1}:{nonce}:{nc:08x}:{cnonce}:{qop_str}:{ha2}");
        s
    } else {
        let mut s = String::with_capacity(ha1.len() + nonce.len() + ha2.len() + 2);

        let _ = write!(s, "{ha1}:{nonce}:{ha2}");
        s
    };

    Ok(hasher.hash(response_str.as_bytes()))
}

/// Computes a complete digest authentication response.
///
/// This is a convenience function that combines `compute_ha1`, `compute_ha2`,
/// and `compute_response`.
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `username` - The user's username
/// * `realm` - The authentication realm
/// * `password` - The user's password
/// * `method` - The SIP method
/// * `uri` - The digest URI
/// * `nonce` - Server nonce
/// * `algorithm` - Digest algorithm
/// * `qop` - Quality of protection option
/// * `nc` - Nonce count
/// * `cnonce` - Client nonce
/// * `entity_body` - Message body (for auth-int)
///
/// # Errors
///
/// Returns an error if digest response computation fails.
#[allow(clippy::too_many_arguments)]
pub fn compute_digest_response(
    hasher: &impl DigestHasher,
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    algorithm: DigestAlgorithm,
    qop: Option<Qop>,
    nc: Option<u32>,
    cnonce: Option<&str>,
    entity_body: Option<&[u8]>,
) -> SipResult<String> {
    let ha1 = compute_ha1(
        hasher,
        username,
        realm,
        password,
        algorithm,
        Some(nonce),
        cnonce,
    )?;

    let ha2 = compute_ha2(hasher, method, uri, qop, entity_body)?;

    compute_response(hasher, &ha1, nonce, nc, cnonce, qop, &ha2)
}

/// Verifies digest credentials against a known password.
///
/// Low-level response check only: it trusts the credential's `algorithm`,
/// `qop`, `uri`, `nonce` and `nc`. Server-side authentication must use
/// [`crate::digest_verifier::DigestVerifier`] (feature `digest-auth`), which
/// enforces the configured algorithm/qop, the Request-URI binding, nonce
/// validity and nc replay (RFC 7616 §3.4.5, §3.4.6, §3.7).
///
/// The hasher must implement `credentials.algorithm`; otherwise this returns
/// `Err` instead of comparing a digest computed with the wrong hash.
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `credentials` - The credentials to verify
/// * `password` - The user's known password
/// * `method` - The SIP method of the request
/// * `entity_body` - The message body (for auth-int verification)
///
/// # Errors
///
/// Returns an error if credential verification fails.
pub fn verify_credentials(
    hasher: &impl DigestHasher,
    credentials: &DigestCredentials,
    password: &str,
    method: &str,
    entity_body: Option<&[u8]>,
) -> SipResult<bool> {
    let expected = compute_digest_response(
        hasher,
        &credentials.username,
        &credentials.realm,
        password,
        method,
        &credentials.uri,
        &credentials.nonce,
        credentials.algorithm,
        credentials.qop,
        credentials.nc,
        credentials.cnonce.as_deref(),
        entity_body,
    )?;

    // Constant-time comparison to prevent timing attacks
    Ok(constant_time_eq(&expected, &credentials.response))
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Creates `DigestCredentials` for a given challenge.
///
/// # Arguments
///
/// * `hasher` - The hash function implementation
/// * `challenge` - The digest challenge from the server
/// * `username` - The user's username
/// * `password` - The user's password
/// * `method` - The SIP method
/// * `uri` - The digest URI
/// * `cnonce` - Client nonce (required if qop is used)
/// * `nc` - Nonce count (required if qop is used)
/// * `entity_body` - Message body (for auth-int)
///
/// # Errors
///
/// Returns an error if credential creation fails.
#[allow(clippy::too_many_arguments)]
pub fn create_credentials(
    hasher: &impl DigestHasher,
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: Option<&str>,
    nc: Option<u32>,
    entity_body: Option<&[u8]>,
) -> SipResult<DigestCredentials> {
    // Select qop from challenge (prefer auth over auth-int if both available)
    let qop = if challenge.qop.contains(&Qop::Auth) {
        Some(Qop::Auth)
    } else if challenge.qop.contains(&Qop::AuthInt) {
        Some(Qop::AuthInt)
    } else {
        None
    };

    let response = compute_digest_response(
        hasher,
        username,
        &challenge.realm,
        password,
        method,
        uri,
        &challenge.nonce,
        challenge.algorithm,
        qop,
        nc,
        cnonce,
        entity_body,
    )?;

    let mut creds =
        DigestCredentials::new(username, &challenge.realm, &challenge.nonce, uri, response)
            .with_algorithm(challenge.algorithm);

    if let Some(ref opaque) = challenge.opaque {
        creds = creds.with_opaque(opaque);
    }

    if let Some(qop) = qop {
        let cnonce = cnonce.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "cnonce required when qop is used".to_string(),
        })?;
        let nc = nc.ok_or_else(|| SipError::InvalidHeader {
            name: "Authorization".to_string(),
            reason: "nc required when qop is used".to_string(),
        })?;
        creds = creds.with_qop(qop, cnonce, nc);
    }

    Ok(creds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unreadable_literal)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_challenge_parse() {
        let challenge = r#"Digest realm="example.com", nonce="abc123", qop="auth""#;
        let parsed: DigestChallenge = challenge.parse().unwrap();

        assert_eq!(parsed.realm, "example.com");
        assert_eq!(parsed.nonce, "abc123");
        assert_eq!(parsed.qop, vec![Qop::Auth]);
        assert_eq!(parsed.algorithm, DigestAlgorithm::Md5);
    }

    #[test]
    fn test_digest_challenge_display() {
        let challenge = DigestChallenge::new("example.com", "abc123")
            .with_qop(Qop::Auth)
            .with_opaque("opaque_value");

        let s = challenge.to_string();
        assert!(s.contains("realm=\"example.com\""));
        assert!(s.contains("nonce=\"abc123\""));
        assert!(s.contains("qop=\"auth\""));
        assert!(s.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn test_digest_challenge_with_algorithm() {
        let challenge = r#"Digest realm="test", nonce="xyz", algorithm=SHA-256"#;
        let parsed: DigestChallenge = challenge.parse().unwrap();

        assert_eq!(parsed.algorithm, DigestAlgorithm::Sha256);
    }

    #[test]
    fn test_digest_credentials_parse() {
        let creds = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="deadbeef""#;
        let parsed: DigestCredentials = creds.parse().unwrap();

        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.realm, "example.com");
        assert_eq!(parsed.nonce, "abc123");
        assert_eq!(parsed.uri, "sip:bob@example.com");
        assert_eq!(parsed.response, "deadbeef");
    }

    #[test]
    fn test_digest_credentials_display() {
        let creds = DigestCredentials::new(
            "alice",
            "example.com",
            "abc123",
            "sip:bob@example.com",
            "deadbeef",
        )
        .with_qop(Qop::Auth, "client_nonce", 1);

        let s = creds.to_string();
        assert!(s.contains("username=\"alice\""));
        assert!(s.contains("qop=auth"));
        assert!(s.contains("cnonce=\"client_nonce\""));
        assert!(s.contains("nc=00000001"));
    }

    #[test]
    fn test_digest_credentials_with_qop() {
        let creds = r#"Digest username="bob", realm="test", nonce="xyz", uri="sip:alice@test", response="aabbcc", qop=auth, cnonce="client", nc=00000001"#;
        let parsed: DigestCredentials = creds.parse().unwrap();

        assert_eq!(parsed.qop, Some(Qop::Auth));
        assert_eq!(parsed.cnonce, Some("client".to_string()));
        assert_eq!(parsed.nc, Some(1));
    }

    #[test]
    fn test_algorithm_roundtrip() {
        for alg in [
            DigestAlgorithm::Md5,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha512_256,
        ] {
            let s = alg.to_string();
            let parsed: DigestAlgorithm = s.parse().unwrap();
            assert_eq!(alg, parsed);
        }
    }

    #[test]
    fn test_stale_flag() {
        let challenge = r#"Digest realm="test", nonce="xyz", stale=true"#;
        let parsed: DigestChallenge = challenge.parse().unwrap();
        assert!(parsed.stale);
    }

    /// Mock hasher for testing - uses a deterministic hash function
    /// that produces different outputs for different inputs.
    struct MockHasher;

    impl DigestHasher for MockHasher {
        fn hash(&self, input: &[u8]) -> String {
            // Simple but deterministic mock hash for testing
            // Uses FNV-1a like algorithm to ensure different inputs produce different outputs
            let mut hash: u64 = 0xcbf29ce484222325;
            for byte in input {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x100000001b3);
            }
            // Use all 128 bits (two 64-bit values) to match MD5 output length
            let hash2 = hash.wrapping_mul(0x517cc1b727220a95);
            format!("{hash:016x}{hash2:016x}")
        }

        fn handles(&self, _algorithm: DigestAlgorithm) -> bool {
            true
        }
    }

    #[test]
    fn test_compute_ha1_basic() {
        let hasher = MockHasher;
        let ha1 = compute_ha1(
            &hasher,
            "alice",
            "example.com",
            "secret",
            DigestAlgorithm::Md5,
            None,
            None,
        )
        .unwrap();

        // HA1 should be consistent
        let ha1_again = compute_ha1(
            &hasher,
            "alice",
            "example.com",
            "secret",
            DigestAlgorithm::Md5,
            None,
            None,
        )
        .unwrap();

        assert_eq!(ha1, ha1_again);
    }

    #[test]
    fn test_compute_ha2_auth() {
        let hasher = MockHasher;
        let ha2 = compute_ha2(
            &hasher,
            "INVITE",
            "sip:bob@example.com",
            Some(Qop::Auth),
            None,
        )
        .unwrap();

        assert_ne!(ha2, "");
    }

    #[test]
    fn test_compute_ha2_auth_int() {
        let hasher = MockHasher;
        let body = b"test body content";
        let ha2 = compute_ha2(
            &hasher,
            "INVITE",
            "sip:bob@example.com",
            Some(Qop::AuthInt),
            Some(body),
        )
        .unwrap();

        // Different body should produce different HA2
        let ha2_different = compute_ha2(
            &hasher,
            "INVITE",
            "sip:bob@example.com",
            Some(Qop::AuthInt),
            Some(b"different body"),
        )
        .unwrap();

        assert_ne!(ha2, ha2_different);
    }

    #[test]
    fn test_compute_response_without_qop() {
        let hasher = MockHasher;
        let response = compute_response(
            &hasher,
            "ha1value",
            "servernonce",
            None,
            None,
            None,
            "ha2value",
        )
        .unwrap();

        assert_ne!(response, "");
    }

    #[test]
    fn test_compute_response_with_qop() {
        let hasher = MockHasher;
        let response = compute_response(
            &hasher,
            "ha1value",
            "servernonce",
            Some(1),
            Some("clientnonce"),
            Some(Qop::Auth),
            "ha2value",
        )
        .unwrap();

        assert_ne!(response, "");
    }

    #[test]
    fn test_compute_response_requires_nc_with_qop() {
        let hasher = MockHasher;
        let result = compute_response(
            &hasher,
            "ha1value",
            "servernonce",
            None, // Missing nc
            Some("clientnonce"),
            Some(Qop::Auth),
            "ha2value",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_create_credentials() {
        let hasher = MockHasher;
        let challenge = DigestChallenge::new("example.com", "servernonce123")
            .with_qop(Qop::Auth)
            .with_algorithm(DigestAlgorithm::Sha256);

        let creds = create_credentials(
            &hasher,
            &challenge,
            "alice",
            "password",
            "REGISTER",
            "sip:example.com",
            Some("clientnonce"),
            Some(1),
            None,
        )
        .unwrap();

        assert_eq!(creds.username, "alice");
        assert_eq!(creds.realm, "example.com");
        assert_eq!(creds.nonce, "servernonce123");
        assert_eq!(creds.qop, Some(Qop::Auth));
        assert_eq!(creds.algorithm, DigestAlgorithm::Sha256);
        assert_ne!(creds.response, "");
    }

    #[test]
    fn test_verify_credentials() {
        let hasher = MockHasher;

        // Create credentials
        let challenge = DigestChallenge::new("test.com", "nonce123");
        let creds = create_credentials(
            &hasher,
            &challenge,
            "user",
            "pass",
            "REGISTER",
            "sip:test.com",
            None,
            None,
            None,
        )
        .unwrap();

        // Verify with correct password
        let valid = verify_credentials(&hasher, &creds, "pass", "REGISTER", None).unwrap();
        assert!(valid);

        // Verify with wrong password
        let invalid = verify_credentials(&hasher, &creds, "wrongpass", "REGISTER", None).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("test", "test"));
        assert!(!constant_time_eq("test", "Test"));
        assert!(!constant_time_eq("test", "testing"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn auth_untrusted_input_errors_in_release() {
        assert!("".parse::<DigestChallenge>().is_err());
        assert!("  ".parse::<DigestCredentials>().is_err());
        let many = (0..=crate::MAX_PARAMS + 1).fold(String::new(), |mut acc, i| {
            let _ = write!(acc, "p{i}=v,");
            acc
        });
        assert!(
            format!("Digest realm=\"r\", nonce=\"n\", {many}")
                .parse::<DigestChallenge>()
                .is_err()
        );
    }

    // RFC 7616 §3.9.1 inputs. Expected values were recomputed independently
    // with Python hashlib (md5 / sha256 / sha512_256), not copied from text.
    #[cfg(feature = "digest-auth")]
    mod rfc7616 {
        use super::*;

        const USER: &str = "Mufasa";
        const REALM: &str = "http-auth@example.org";
        const PASS: &str = "Circle of Life";
        const URI: &str = "/dir/index.html";
        const NONCE: &str = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
        const CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

        fn response(alg: DigestAlgorithm) -> String {
            compute_digest_response(
                &AlgorithmHasher::for_algorithm(alg),
                USER,
                REALM,
                PASS,
                "GET",
                URI,
                NONCE,
                alg,
                Some(Qop::Auth),
                Some(1),
                Some(CNONCE),
                None,
            )
            .unwrap()
        }

        #[test]
        fn md5_vector() {
            assert_eq!(
                response(DigestAlgorithm::Md5),
                "8ca523f5e9506fed4657c9700eebdbec"
            );
        }

        #[test]
        fn sha256_vector() {
            assert_eq!(
                response(DigestAlgorithm::Sha256),
                "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
            );
        }

        #[test]
        fn sha512_256_response() {
            assert_eq!(
                response(DigestAlgorithm::Sha512_256),
                "430d05014cecc49cab6fbe03176d41a1da86cbfe24a16580e22aaad928d960d0"
            );
        }

        #[test]
        fn session_variants() {
            assert_eq!(
                response(DigestAlgorithm::Md5Sess),
                "e783283f46242139c486a698fec7211d"
            );
            assert_eq!(
                response(DigestAlgorithm::Sha256Sess),
                "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7"
            );
            assert_eq!(
                response(DigestAlgorithm::Sha512_256Sess),
                "3f2a34f923c38b0fb26dce2fdfc2ce326c23cecf86fbb1444f3e51fbbc2cb92e"
            );
        }

        /// FIPS 180-4 "abc" vector; SHA-512/256 is not truncated SHA-512.
        #[test]
        fn sha512_256_is_not_truncated_sha512() {
            let h = Sha512_256DigestHasher.hash(b"abc");
            assert_eq!(
                h,
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
            );
            assert_ne!(
                h,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            );
        }

        #[test]
        fn algorithm_hasher_dispatch() {
            for (alg, hasher) in [
                (DigestAlgorithm::Md5, AlgorithmHasher::Md5),
                (DigestAlgorithm::Md5Sess, AlgorithmHasher::Md5),
                (DigestAlgorithm::Sha256, AlgorithmHasher::Sha256),
                (DigestAlgorithm::Sha256Sess, AlgorithmHasher::Sha256),
                (DigestAlgorithm::Sha512_256, AlgorithmHasher::Sha512_256),
                (DigestAlgorithm::Sha512_256Sess, AlgorithmHasher::Sha512_256),
            ] {
                assert_eq!(AlgorithmHasher::for_algorithm(alg), hasher);
                assert!(hasher.handles(alg));
            }
            assert!(!AlgorithmHasher::Md5.handles(DigestAlgorithm::Sha256));
            assert!(!Sha256DigestHasher.handles(DigestAlgorithm::Md5));
        }

        /// POA&M-230 regression: an MD5 hasher must not answer a SHA-256
        /// challenge with an MD5 digest.
        #[test]
        fn md5_hasher_with_sha256_challenge_fails_closed() {
            let challenge = DigestChallenge::new(REALM, NONCE)
                .with_algorithm(DigestAlgorithm::Sha256)
                .with_qop(Qop::Auth);
            let result = create_credentials(
                &Md5DigestHasher,
                &challenge,
                USER,
                PASS,
                "GET",
                URI,
                Some(CNONCE),
                Some(1),
                None,
            );
            assert!(result.is_err());
            let creds = DigestCredentials::new(USER, REALM, NONCE, URI, "00")
                .with_algorithm(DigestAlgorithm::Sha256);
            assert!(verify_credentials(&Md5DigestHasher, &creds, PASS, "GET", None).is_err());
        }
    }
}
