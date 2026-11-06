//! Structured SIP header parameter types per RFC 3261.
//!
//! Provides structured parsing for complex headers like Via, From, To, and `CSeq`.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::MAX_PARAMS;
use crate::error::{SipError, SipResult};
use crate::header::is_token_byte;
use crate::method::Method;
use crate::uri::SipUri;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// RFC 3261 Section 8.1.1.7 magic cookie prefix for Via branch parameter.
pub const VIA_BRANCH_MAGIC_COOKIE: &str = "z9hG4bK";

/// Parsed Via header per RFC 3261 Section 20.42.
///
/// Format: `SIP/2.0/transport sent-by;params`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaHeader {
    /// Protocol name (always "SIP").
    pub protocol: String,
    /// Protocol version (always "2.0").
    pub version: String,
    /// Transport (UDP, TCP, TLS, SCTP, WS, WSS).
    pub transport: String,
    /// Sent-by host.
    pub host: String,
    /// Sent-by port (optional).
    pub port: Option<u16>,
    /// Branch parameter (transaction ID).
    pub branch: Option<String>,
    /// Received parameter (actual source IP).
    pub received: Option<String>,
    /// Rport parameter (actual source port).
    /// `Some(Some(port))` = `;rport=PORT` (server response),
    /// `Some(None)` = `;rport` (client request per RFC 3581),
    /// `None` = not present.
    pub rport: Option<Option<u16>>,
    /// TTL parameter (time-to-live for multicast).
    pub ttl: Option<u8>,
    /// Maddr parameter (multicast address).
    pub maddr: Option<String>,
    /// Additional parameters.
    pub params: HashMap<String, Option<String>>,
}

impl ViaHeader {
    /// Creates a new Via header with the given transport and host.
    #[must_use]
    pub fn new(transport: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            protocol: "SIP".to_string(),
            version: "2.0".to_string(),
            transport: transport.into(),
            host: host.into(),
            port: None,
            branch: None,
            received: None,
            rport: None,
            ttl: None,
            maddr: None,
            params: HashMap::new(),
        }
    }

    /// Sets the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the branch parameter.
    #[must_use]
    pub fn with_branch(mut self, branch: impl Into<String>) -> Self {
        self.branch = Some(branch.into());
        self
    }

    /// Requests rport processing per RFC 3581 (adds empty `;rport` parameter).
    ///
    /// Used in outgoing requests to ask the server to include the source port
    /// in the Via response, enabling NAT traversal.
    #[must_use]
    pub fn with_rport(mut self) -> Self {
        self.rport = Some(None);
        self
    }

    /// Generates a valid RFC 3261 branch parameter with magic cookie.
    ///
    /// Uses cryptographic randomness to prevent prediction and replay attacks.
    #[must_use]
    /// Generates a random branch parameter with RFC 3261 magic cookie prefix.
    ///
    /// # Panics
    ///
    /// Panics if the CSPRNG fails (via `getrandom`), which is unrecoverable.
    #[allow(clippy::expect_used)]
    pub fn generate_branch() -> String {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let hex: String = bytes.iter().fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        format!("{VIA_BRANCH_MAGIC_COOKIE}{hex}")
    }

    /// Returns true if the branch parameter has the RFC 3261 magic cookie.
    #[must_use]
    pub fn has_rfc3261_branch(&self) -> bool {
        self.branch
            .as_ref()
            .is_some_and(|b| b.starts_with(VIA_BRANCH_MAGIC_COOKIE))
    }

    /// Returns the sent-by as "host:port" string.
    #[must_use]
    pub fn sent_by(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }

    /// Returns the protocol/version/transport string.
    #[must_use]
    pub fn protocol_string(&self) -> String {
        format!("{}/{}/{}", self.protocol, self.version, self.transport)
    }
}

impl fmt::Display for ViaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{} ", self.protocol, self.version, self.transport)?;
        write!(f, "{}", self.host)?;

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        if let Some(ref branch) = self.branch {
            write!(f, ";branch={branch}")?;
        }

        if let Some(ref received) = self.received {
            write!(f, ";received={received}")?;
        }

        match self.rport {
            Some(Some(rport)) => write!(f, ";rport={rport}")?,
            Some(None) => write!(f, ";rport")?,
            None => {}
        }

        if let Some(ttl) = self.ttl {
            write!(f, ";ttl={ttl}")?;
        }

        if let Some(ref maddr) = self.maddr {
            write!(f, ";maddr={maddr}")?;
        }

        for (name, value) in &self.params {
            write!(f, ";{name}")?;
            if let Some(v) = value {
                write!(f, "={v}")?;
            }
        }

        Ok(())
    }
}

impl FromStr for ViaHeader {
    type Err = SipError;

    /// Parses a single Via field value (one `via-parm`).
    ///
    /// RFC 3261 §20.42 / §25.1: LWS is allowed around `/` (SLASH), `;`
    /// (SEMI), `=` (EQUAL) and `:` (COLON) and between sent-protocol and
    /// sent-by (RFC 4475 §3.1.1.1). A combined value (`a, b`) is rejected
    /// here; use [`crate::Headers::via_all_parsed`] to split it.
    ///
    /// NIST 800-53 Rev5: SI-10 (input validation), SC-5 (parameter cap).
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - Parameter loop bounded by [`MAX_PARAMS`]
    fn from_str(s: &str) -> SipResult<Self> {
        let s = trim_lws(s);
        if s.is_empty() {
            return Err(via_err("empty value"));
        }
        // Exactly one list element; counted without allocating.
        let mut elems = crate::list::split_list(s);
        match (elems.next(), elems.next()) {
            (Some(Ok(_)), None) => {}
            (Some(Err(_)) | None, _) | (_, Some(Err(_))) => {
                return Err(via_err("multiple or malformed Via values"));
            }
            (_, Some(Ok(_))) => return Err(via_err("multiple Via values in one field")),
        }

        // sent-protocol = protocol-name SLASH protocol-version SLASH transport
        let (protocol_str, rest) = s
            .split_once('/')
            .ok_or_else(|| via_err("invalid protocol format"))?;
        let (version_str, rest) = rest
            .split_once('/')
            .ok_or_else(|| via_err("invalid protocol format"))?;
        let protocol_str = trim_lws(protocol_str);
        let version_str = trim_lws(version_str);
        let rest = trim_lws_start(rest);
        let transport_end = rest
            .bytes()
            .position(|b| !is_token_byte(b))
            .unwrap_or(rest.len());
        let (transport_str, rest) = rest.split_at(transport_end);
        if !is_token(protocol_str) || !is_token(version_str) || transport_str.is_empty() {
            return Err(via_err("invalid protocol format"));
        }
        if !rest.starts_with([' ', '\t']) {
            return Err(via_err("missing sent-by"));
        }

        let protocol = protocol_str.to_string();
        let version = version_str.to_string();
        let transport = transport_str.to_uppercase();

        // Split sent-by from params (no Vec allocation)
        let (sent_by, params_str) = match rest.split_once(';') {
            Some((sb, ps)) => (trim_lws(sb), Some(ps)),
            None => (trim_lws(rest), None),
        };

        // Parse host [COLON port]
        let (host, port) = match sent_by.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(':') => match trim_lws(p).parse() {
                Ok(port) => (trim_lws(h).to_string(), Some(port)),
                Err(_) => (sent_by.to_string(), None),
            },
            _ => (sent_by.to_string(), None),
        };
        if host.is_empty() || host.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(via_err("invalid sent-by"));
        }

        let p = parse_via_params(params_str)?;

        Ok(Self {
            protocol,
            version,
            transport,
            host,
            port,
            branch: p.branch,
            received: p.received,
            rport: p.rport_present.then_some(p.rport),
            ttl: p.ttl,
            maddr: p.maddr,
            params: p.params,
        })
    }
}

/// Parsed Via parameters.
#[derive(Default)]
struct ViaParams {
    branch: Option<String>,
    received: Option<String>,
    /// `;rport` present (with or without a value).
    rport_present: bool,
    rport: Option<u16>,
    ttl: Option<u8>,
    maddr: Option<String>,
    params: HashMap<String, Option<String>>,
}

/// Parses `*( SEMI via-params )` (RFC 3261 §20.42), LWS-tolerant.
///
/// NIST 800-53 Rev5: SC-5 - at most [`MAX_PARAMS`] parameters.
fn parse_via_params(params_str: Option<&str>) -> SipResult<ViaParams> {
    let mut p = ViaParams::default();
    let mut count = 0usize;

    for param in params_str.into_iter().flat_map(|ps| ps.split(';')) {
        let (raw_name, raw_value) = match param.split_once('=') {
            Some((n, v)) => (trim_lws(n), Some(trim_lws(v))),
            None => (trim_lws(param), None::<&str>),
        };
        if raw_name.is_empty() && raw_value.is_none() {
            continue;
        }
        count += 1;
        if count > MAX_PARAMS {
            return Err(SipError::LimitExceeded {
                what: "Via parameters",
                limit: MAX_PARAMS,
            });
        }
        if !is_token(raw_name) {
            return Err(via_err("parameter name is not a token"));
        }

        if raw_name.eq_ignore_ascii_case("branch") {
            // RFC 3261 §20.42: via-branch = "branch" EQUAL token
            match raw_value {
                Some(v) if !v.is_empty() => p.branch = Some(v.to_string()),
                _ => return Err(via_err("empty branch parameter")),
            }
        } else if raw_name.eq_ignore_ascii_case("received") {
            p.received = raw_value.map(String::from);
        } else if raw_name.eq_ignore_ascii_case("rport") {
            p.rport_present = true;
            p.rport = raw_value.and_then(|v| v.parse().ok());
        } else if raw_name.eq_ignore_ascii_case("ttl") {
            p.ttl = raw_value.and_then(|v| v.parse().ok());
        } else if raw_name.eq_ignore_ascii_case("maddr") {
            p.maddr = raw_value.map(String::from);
        } else {
            // Only allocate for unknown params
            p.params
                .insert(raw_name.to_lowercase(), raw_value.map(String::from));
        }
    }

    Ok(p)
}

/// Builds a Via parse error.
fn via_err(reason: &str) -> SipError {
    SipError::InvalidHeader {
        name: "Via".to_string(),
        reason: reason.to_string(),
    }
}

/// Trims SP / HTAB (RFC 3261 §25.1 LWS after unfolding).
fn trim_lws(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Trims leading SP / HTAB.
fn trim_lws_start(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Returns true if `s` is a non-empty `token` (RFC 3261 §25.1).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

/// Parsed From/To header per RFC 3261 Section 20.20/20.39.
///
/// Format: `"Display Name" <sip:user@host>;tag=xxx`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    /// Display name (optional).
    pub display_name: Option<String>,
    /// SIP URI.
    pub uri: SipUri,
    /// Tag parameter (dialog identification).
    pub tag: Option<String>,
    /// Additional parameters.
    pub params: HashMap<String, Option<String>>,
}

impl NameAddr {
    /// Creates a new name-addr from a URI.
    #[must_use]
    pub fn new(uri: SipUri) -> Self {
        Self {
            display_name: None,
            uri,
            tag: None,
            params: HashMap::new(),
        }
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the tag parameter.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Generates a random tag for From/To headers.
    ///
    /// Uses cryptographic randomness to prevent prediction and call hijacking.
    #[must_use]
    /// Generates a random tag parameter.
    ///
    /// # Panics
    ///
    /// Panics if the CSPRNG fails (via `getrandom`), which is unrecoverable.
    #[allow(clippy::expect_used)]
    pub fn generate_tag() -> String {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        bytes.iter().fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.display_name {
            // Quote display name if it contains special characters
            if name.contains(' ') || name.contains('"') || name.contains('<') {
                write!(f, "\"{}\" ", name.replace('"', "\\\""))?;
            } else {
                write!(f, "{name} ")?;
            }
        }

        write!(f, "<{}>", self.uri)?;

        if let Some(ref tag) = self.tag {
            write!(f, ";tag={tag}")?;
        }

        for (name, value) in &self.params {
            write!(f, ";{name}")?;
            if let Some(v) = value {
                write!(f, "={v}")?;
            }
        }

        Ok(())
    }
}

/// Parses a quoted display name from a name-addr string.
fn parse_quoted_display_name(s: &str) -> SipResult<(String, &str)> {
    // Scan for the closing quote using byte offsets. The delimiters ('"' and
    // '\\') are ASCII so byte-level scanning is safe for UTF-8 strings.
    let bytes = s.as_bytes();
    let mut pos = 1;
    while pos < bytes.len() {
        if bytes[pos] == b'"' && (pos == 0 || bytes[pos - 1] != b'\\') {
            break;
        }
        pos += 1;
    }

    if pos >= bytes.len() {
        return Err(SipError::InvalidHeader {
            name: "From/To".to_string(),
            reason: "unclosed display name quote".to_string(),
        });
    }

    let name = s[1..pos].replace("\\\"", "\"");
    Ok((name, &s[pos + 1..]))
}

/// Extracts display name and remaining string from a name-addr.
fn extract_display_name(s: &str) -> SipResult<(Option<String>, &str)> {
    if s.starts_with('"') {
        let (name, rest) = parse_quoted_display_name(s)?;
        Ok((Some(name), rest))
    } else if let Some(pos) = s.find('<') {
        let name = s[..pos].trim();
        if name.is_empty() {
            Ok((None, &s[pos..]))
        } else {
            Ok((Some(name.to_string()), &s[pos..]))
        }
    } else {
        Ok((None, s))
    }
}

/// Extracts the URI string and parameters string from the remaining input.
fn extract_uri_and_params(rest: &str) -> SipResult<(&str, &str)> {
    if rest.starts_with('<') {
        let end = rest.find('>').ok_or_else(|| SipError::InvalidHeader {
            name: "From/To".to_string(),
            reason: "unclosed angle bracket".to_string(),
        })?;
        Ok((&rest[1..end], &rest[end + 1..]))
    } else if let Some(pos) = rest.find(';') {
        Ok((&rest[..pos], &rest[pos..]))
    } else {
        Ok((rest, ""))
    }
}

/// Parsed name-addr parameters: tag and the remaining params.
type NameAddrParams = (Option<String>, HashMap<String, Option<String>>);

/// Parses name-addr parameters into tag and other params.
///
/// NIST 800-53 Rev5: SC-5 - at most [`MAX_PARAMS`] parameters.
fn parse_nameaddr_params(params_str: &str) -> SipResult<NameAddrParams> {
    let mut tag = None;
    let mut params = HashMap::new();

    for (i, param) in params_str
        .split(';')
        .filter(|p| !trim_lws(p).is_empty())
        .enumerate()
    {
        if i >= MAX_PARAMS {
            return Err(SipError::LimitExceeded {
                what: "name-addr parameters",
                limit: MAX_PARAMS,
            });
        }
        let (raw_name, raw_value) = if let Some((n, v)) = param.split_once('=') {
            (n.trim(), Some(v.trim()))
        } else {
            (param.trim(), None::<&str>)
        };

        if raw_name.eq_ignore_ascii_case("tag") {
            tag = raw_value.map(String::from);
        } else {
            // Only allocate for unknown params
            params.insert(raw_name.to_lowercase(), raw_value.map(String::from));
        }
    }

    Ok((tag, params))
}

impl FromStr for NameAddr {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        let s = s.trim();
        // NIST 800-53 Rev5: SI-10 - untrusted input, real error (was debug_assert).
        if s.is_empty() {
            return Err(SipError::InvalidHeader {
                name: "From/To".to_string(),
                reason: "empty name-addr".to_string(),
            });
        }

        let (display_name, rest) = extract_display_name(s)?;
        let rest = rest.trim();
        let (uri_str, params_str) = extract_uri_and_params(rest)?;
        let uri: SipUri = uri_str.parse()?;
        let (tag, params) = parse_nameaddr_params(params_str)?;

        Ok(Self {
            display_name,
            uri,
            tag,
            params,
        })
    }
}

/// Parsed `CSeq` header per RFC 3261 Section 20.16.
///
/// Format: `sequence-number method`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeqHeader {
    /// Sequence number (0 to 2^31-1 per RFC 3261).
    pub sequence: u32,
    /// Request method.
    pub method: Method,
}

impl CSeqHeader {
    /// Creates a new `CSeq` header.
    #[must_use]
    pub fn new(sequence: u32, method: Method) -> Self {
        Self { sequence, method }
    }
}

impl fmt::Display for CSeqHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.sequence, self.method)
    }
}

impl FromStr for CSeqHeader {
    type Err = SipError;

    /// Parses a `CSeq` header string.
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - `split_whitespace()` bounded by input length
    fn from_str(s: &str) -> SipResult<Self> {
        // NIST 800-53 Rev5: SI-10 - untrusted input, real error (was debug_assert).
        if s.trim().is_empty() {
            return Err(SipError::InvalidHeader {
                name: "CSeq".to_string(),
                reason: "empty value".to_string(),
            });
        }

        // Split into sequence and method (no Vec allocation)
        let (seq_str, method_str) =
            s.trim()
                .split_once(char::is_whitespace)
                .ok_or_else(|| SipError::InvalidHeader {
                    name: "CSeq".to_string(),
                    reason: "expected 'sequence method'".to_string(),
                })?;

        let method_str = method_str.trim_start();
        if !is_token(method_str) {
            return Err(SipError::InvalidHeader {
                name: "CSeq".to_string(),
                reason: "method is not a token".to_string(),
            });
        }

        // RFC 3261 §25.1: CSeq = 1*DIGIT LWS Method (no sign).
        if seq_str.len() > 10 || !seq_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SipError::InvalidHeader {
                name: "CSeq".to_string(),
                reason: "invalid sequence number".to_string(),
            });
        }
        let sequence: u32 = seq_str.parse().map_err(|_| SipError::InvalidHeader {
            name: "CSeq".to_string(),
            reason: "invalid sequence number".to_string(),
        })?;

        // RFC 3261 §8.1.1.5: sequence number MUST be less than 2^31.
        // NIST 800-53 Rev5: SI-10 - enforced in release builds (was debug_assert).
        if sequence > 0x7FFF_FFFF {
            return Err(SipError::InvalidHeader {
                name: "CSeq".to_string(),
                reason: "sequence number must be < 2^31".to_string(),
            });
        }

        // Method parsing is infallible - unknown methods become Extension variants
        let method: Method = method_str
            .parse()
            .unwrap_or_else(|e: std::convert::Infallible| match e {});

        Ok(Self { sequence, method })
    }
}

/// Parsed Max-Forwards header per RFC 3261 Section 20.22.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxForwardsHeader {
    /// Hop count value (0-255).
    pub value: u8,
}

impl MaxForwardsHeader {
    /// Default Max-Forwards value per RFC 3261.
    pub const DEFAULT: u8 = 70;

    /// Creates a new Max-Forwards header.
    #[must_use]
    pub fn new(value: u8) -> Self {
        Self { value }
    }

    /// Returns true if no more forwarding is allowed.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Decrements the value, returning None if already zero.
    #[must_use]
    pub fn decrement(&self) -> Option<Self> {
        self.value.checked_sub(1).map(|v| Self { value: v })
    }
}

impl Default for MaxForwardsHeader {
    fn default() -> Self {
        Self {
            value: Self::DEFAULT,
        }
    }
}

impl fmt::Display for MaxForwardsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl FromStr for MaxForwardsHeader {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        let value: u8 = s.trim().parse().map_err(|_| SipError::InvalidHeader {
            name: "Max-Forwards".to_string(),
            reason: "invalid value (must be 0-255)".to_string(),
        })?;
        Ok(Self { value })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_via_parse() {
        let via: ViaHeader = "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776"
            .parse()
            .unwrap();
        assert_eq!(via.protocol, "SIP");
        assert_eq!(via.version, "2.0");
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "pc33.example.com");
        assert_eq!(via.branch, Some("z9hG4bK776".to_string()));
        assert!(via.has_rfc3261_branch());
    }

    #[test]
    fn test_via_with_port() {
        let via: ViaHeader = "SIP/2.0/TCP 192.168.1.1:5060;branch=z9hG4bKtest"
            .parse()
            .unwrap();
        assert_eq!(via.host, "192.168.1.1");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.transport, "TCP");
    }

    #[test]
    fn test_via_display() {
        let via = ViaHeader::new("UDP", "example.com")
            .with_port(5060)
            .with_branch("z9hG4bKtest");
        let s = via.to_string();
        assert!(s.contains("SIP/2.0/UDP"));
        assert!(s.contains("example.com:5060"));
        assert!(s.contains("branch=z9hG4bKtest"));
    }

    #[test]
    fn test_via_branch_magic_cookie() {
        let branch = ViaHeader::generate_branch();
        assert!(branch.starts_with(VIA_BRANCH_MAGIC_COOKIE));
    }

    #[test]
    fn test_name_addr_simple() {
        let addr: NameAddr = "<sip:alice@example.com>".parse().unwrap();
        assert_eq!(addr.display_name, None);
        assert_eq!(addr.uri.user, Some("alice".to_string()));
        assert_eq!(addr.uri.host, "example.com");
    }

    #[test]
    fn test_name_addr_with_display_name() {
        let addr: NameAddr = "\"Alice Smith\" <sip:alice@example.com>;tag=1234"
            .parse()
            .unwrap();
        assert_eq!(addr.display_name, Some("Alice Smith".to_string()));
        assert_eq!(addr.tag, Some("1234".to_string()));
    }

    #[test]
    fn test_name_addr_display_name_no_quotes() {
        let addr: NameAddr = "Alice <sip:alice@example.com>".parse().unwrap();
        assert_eq!(addr.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn test_name_addr_display() {
        let addr = NameAddr::new(SipUri::new("example.com").with_user("alice"))
            .with_display_name("Alice Smith")
            .with_tag("abc123");
        let s = addr.to_string();
        assert!(s.contains("\"Alice Smith\""));
        assert!(s.contains("<sip:alice@example.com>"));
        assert!(s.contains("tag=abc123"));
    }

    #[test]
    fn test_cseq_parse() {
        let cseq: CSeqHeader = "1 INVITE".parse().unwrap();
        assert_eq!(cseq.sequence, 1);
        assert_eq!(cseq.method, Method::Invite);
    }

    #[test]
    fn test_cseq_display() {
        let cseq = CSeqHeader::new(42, Method::Register);
        assert_eq!(cseq.to_string(), "42 REGISTER");
    }

    #[test]
    fn test_max_forwards_parse() {
        let mf: MaxForwardsHeader = "70".parse().unwrap();
        assert_eq!(mf.value, 70);
        assert!(!mf.is_zero());
    }

    #[test]
    fn test_max_forwards_decrement() {
        let mf = MaxForwardsHeader::new(2);
        let mf = mf.decrement().unwrap();
        assert_eq!(mf.value, 1);
        let mf = mf.decrement().unwrap();
        assert_eq!(mf.value, 0);
        assert!(mf.is_zero());
        assert!(mf.decrement().is_none());
    }

    #[test]
    fn via_lws_tolerant() {
        let via: ViaHeader = "SIP / 2.0 / UDP host.example.com ; branch = z9hG4bK1"
            .parse()
            .unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "host.example.com");
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK1"));
        let via: ViaHeader = "SIP/2.0/TCP h.example.com : 5070;rport".parse().unwrap();
        assert_eq!(via.port, Some(5070));
    }

    #[test]
    fn via_rejects_bad_input() {
        assert!("".parse::<ViaHeader>().is_err());
        assert!("SIP/2.0/UDP h;branch=".parse::<ViaHeader>().is_err());
        assert!("SIP/2.0/UDP h;branch".parse::<ViaHeader>().is_err());
        assert!("SIP/2.0/UDPh".parse::<ViaHeader>().is_err());
        assert!("SIP/2.0/UDP a, SIP/2.0/UDP b".parse::<ViaHeader>().is_err());
        let many = (0..=crate::MAX_PARAMS).fold(String::new(), |mut acc, i| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!(";p{i}"));
            acc
        });
        assert!(format!("SIP/2.0/UDP h{many}").parse::<ViaHeader>().is_err());
    }

    #[test]
    fn cseq_errors_in_release() {
        assert!("".parse::<CSeqHeader>().is_err());
        assert!("2147483648 INVITE".parse::<CSeqHeader>().is_err());
        assert!("2147483647 INVITE".parse::<CSeqHeader>().is_ok());
        assert!("+1 INVITE".parse::<CSeqHeader>().is_err());
        assert!("1 IN VITE".parse::<CSeqHeader>().is_err());
    }

    #[test]
    fn name_addr_errors_in_release() {
        assert!("".parse::<NameAddr>().is_err());
        assert!("   ".parse::<NameAddr>().is_err());
        let many = (0..=crate::MAX_PARAMS).fold(String::new(), |mut acc, i| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!(";p{i}"));
            acc
        });
        assert!(format!("<sip:a@b>{many}").parse::<NameAddr>().is_err());
    }
}
