//! Structured SIP header parameter types per RFC 3261.
//!
//! Provides structured parsing for complex headers like Via, From, To, and `CSeq`.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::{SipError, SipResult};
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
    #[must_use]
    pub fn generate_branch() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{VIA_BRANCH_MAGIC_COOKIE}{timestamp:x}")
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

    /// Parses a Via header string.
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - `splitn(2, ' ')` produces at most 2 elements
    /// - `split('/')` bounded by input length
    /// - Parameter parsing bounded by input length
    fn from_str(s: &str) -> SipResult<Self> {
        // Power of 10 Rule 5: Assert precondition
        debug_assert!(!s.is_empty(), "empty Via header string");

        // Split into protocol part and rest (no Vec allocation)
        let (proto_part, rest) = s.split_once(' ').ok_or_else(|| SipError::InvalidHeader {
            name: "Via".to_string(),
            reason: "missing sent-by".to_string(),
        })?;

        // Parse SIP/2.0/transport via chained split_once (no Vec allocation)
        let (protocol_str, remainder) =
            proto_part
                .split_once('/')
                .ok_or_else(|| SipError::InvalidHeader {
                    name: "Via".to_string(),
                    reason: "invalid protocol format".to_string(),
                })?;
        let (version_str, transport_str) =
            remainder
                .split_once('/')
                .ok_or_else(|| SipError::InvalidHeader {
                    name: "Via".to_string(),
                    reason: "invalid protocol format".to_string(),
                })?;

        let protocol = protocol_str.to_string();
        let version = version_str.to_string();
        let transport = transport_str.to_uppercase();

        // Split sent-by from params (no Vec allocation)
        let (sent_by, params_str) = if let Some((sb, ps)) = rest.split_once(';') {
            (sb, Some(ps))
        } else {
            (rest, None)
        };

        // Parse host:port
        let (host, port) = if let Some((h, p)) = sent_by.rsplit_once(':') {
            if let Ok(port) = p.parse() {
                (h.to_string(), Some(port))
            } else {
                (sent_by.to_string(), None)
            }
        } else {
            (sent_by.to_string(), None)
        };

        // Parse parameters
        let mut branch = None;
        let mut received = None;
        let mut rport = None;
        let mut ttl = None;
        let mut maddr = None;
        let mut params = HashMap::new();

        for param in params_str.into_iter().flat_map(|ps| ps.split(';')) {
            // Split name=value without allocating; only allocate for the
            // matched field or for unknown params that go into the HashMap.
            let (raw_name, raw_value) = if let Some((n, v)) = param.split_once('=') {
                (n.trim(), Some(v.trim()))
            } else {
                (param.trim(), None::<&str>)
            };

            if raw_name.eq_ignore_ascii_case("branch") {
                branch = raw_value.map(String::from);
            } else if raw_name.eq_ignore_ascii_case("received") {
                received = raw_value.map(String::from);
            } else if raw_name.eq_ignore_ascii_case("rport") {
                rport = Some(raw_value.and_then(|v| v.parse().ok()));
            } else if raw_name.eq_ignore_ascii_case("ttl") {
                ttl = raw_value.and_then(|v| v.parse().ok());
            } else if raw_name.eq_ignore_ascii_case("maddr") {
                maddr = raw_value.map(String::from);
            } else {
                // Only allocate for unknown params
                params.insert(raw_name.to_lowercase(), raw_value.map(String::from));
            }
        }

        Ok(Self {
            protocol,
            version,
            transport,
            host,
            port,
            branch,
            received,
            rport,
            ttl,
            maddr,
            params,
        })
    }
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
    #[must_use]
    pub fn generate_tag() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:x}", timestamp & 0xFFFF_FFFF_FFFF)
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

/// Parses name-addr parameters into tag and other params.
fn parse_nameaddr_params(params_str: &str) -> (Option<String>, HashMap<String, Option<String>>) {
    let mut tag = None;
    let mut params = HashMap::new();

    for param in params_str.split(';').filter(|p| !p.is_empty()) {
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

    (tag, params)
}

impl FromStr for NameAddr {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        let s = s.trim();
        debug_assert!(!s.is_empty(), "empty name-addr string");

        let (display_name, rest) = extract_display_name(s)?;
        let rest = rest.trim();
        let (uri_str, params_str) = extract_uri_and_params(rest)?;
        let uri: SipUri = uri_str.parse()?;
        let (tag, params) = parse_nameaddr_params(params_str);

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
        // Power of 10 Rule 5: Assert precondition
        debug_assert!(!s.is_empty(), "empty CSeq header string");

        // Split into sequence and method (no Vec allocation)
        let (seq_str, method_str) =
            s.trim()
                .split_once(char::is_whitespace)
                .ok_or_else(|| SipError::InvalidHeader {
                    name: "CSeq".to_string(),
                    reason: "expected 'sequence method'".to_string(),
                })?;

        let method_str = method_str.trim_start();

        let sequence: u32 = seq_str.parse().map_err(|_| SipError::InvalidHeader {
            name: "CSeq".to_string(),
            reason: "invalid sequence number".to_string(),
        })?;

        // Power of 10 Rule 5: Assert sequence range (RFC 3261: 0 to 2^31-1)
        debug_assert!(
            sequence <= 0x7FFF_FFFF,
            "CSeq sequence exceeds RFC 3261 max"
        );

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
}
