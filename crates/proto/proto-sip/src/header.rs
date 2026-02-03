//! SIP headers per RFC 3261.
//!
//! This module provides header name constants, header parsing, and header
//! collection management for SIP messages per RFC 3261 Section 20.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::{SipError, SipResult};
use crate::header_params::{CSeqHeader, MaxForwardsHeader, NameAddr, ViaHeader};
use std::fmt;
use std::str::FromStr;

/// Common SIP header names per RFC 3261 Section 20 and extensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeaderName {
    // Request routing (RFC 3261 Section 20)
    /// Via header (Section 20.42).
    Via,
    /// Route header (Section 20.34).
    Route,
    /// Record-Route header (Section 20.30).
    RecordRoute,
    /// Max-Forwards header (Section 20.22).
    MaxForwards,
    /// Path header (RFC 3327).
    Path,

    // Transaction identification (RFC 3261 Section 20)
    /// Call-ID header (Section 20.8).
    CallId,
    /// `CSeq` header (Section 20.16).
    CSeq,
    /// From header (Section 20.20).
    From,
    /// To header (Section 20.39).
    To,

    // Message body (RFC 3261 Section 20)
    /// Content-Type header (Section 20.15).
    ContentType,
    /// Content-Length header (Section 20.14).
    ContentLength,
    /// Content-Encoding header (Section 20.12).
    ContentEncoding,
    /// Content-Disposition header (Section 20.11).
    ContentDisposition,
    /// Content-Language header (Section 20.13).
    ContentLanguage,

    // Session/dialog (RFC 3261 Section 20)
    /// Contact header (Section 20.10).
    Contact,
    /// Expires header (Section 20.19).
    Expires,
    /// Min-Expires header (Section 20.23).
    MinExpires,

    // Authentication (RFC 3261 Section 20)
    /// WWW-Authenticate header (Section 20.44).
    WwwAuthenticate,
    /// Authorization header (Section 20.7).
    Authorization,
    /// Proxy-Authenticate header (Section 20.27).
    ProxyAuthenticate,
    /// Proxy-Authorization header (Section 20.28).
    ProxyAuthorization,

    // Features (RFC 3261 Section 20)
    /// Allow header (Section 20.5).
    Allow,
    /// Supported header (Section 20.37).
    Supported,
    /// Require header (Section 20.32).
    Require,
    /// Proxy-Require header (Section 20.29).
    ProxyRequire,
    /// Unsupported header (Section 20.40).
    Unsupported,

    // Information (RFC 3261 Section 20)
    /// Accept header (Section 20.1).
    Accept,
    /// Accept-Encoding header (Section 20.2).
    AcceptEncoding,
    /// Accept-Language header (Section 20.3).
    AcceptLanguage,
    /// Alert-Info header (Section 20.4).
    AlertInfo,
    /// Call-Info header (Section 20.9).
    CallInfo,
    /// Date header (Section 20.17).
    Date,
    /// Error-Info header (Section 20.18).
    ErrorInfo,
    /// In-Reply-To header (Section 20.21).
    InReplyTo,
    /// MIME-Version header (Section 20.24).
    MimeVersion,
    /// Organization header (Section 20.25).
    Organization,
    /// Priority header (Section 20.26).
    Priority,
    /// Reply-To header (Section 20.31).
    ReplyTo,
    /// Retry-After header (Section 20.33).
    RetryAfter,
    /// Server header (Section 20.35).
    Server,
    /// Subject header (Section 20.36).
    Subject,
    /// Timestamp header (Section 20.38).
    Timestamp,
    /// User-Agent header (Section 20.41).
    UserAgent,
    /// Warning header (Section 20.43).
    Warning,

    // Event framework (RFC 6665)
    /// Event header.
    Event,
    /// Subscription-State header.
    SubscriptionState,
    /// Allow-Events header.
    AllowEvents,

    // Session timers (RFC 4028)
    /// Session-Expires header.
    SessionExpires,
    /// Min-SE header.
    MinSe,

    // STIR/SHAKEN (RFC 8224)
    /// Identity header.
    Identity,

    // P-headers (RFC 3325, RFC 3455)
    /// P-Asserted-Identity header.
    PAssertedIdentity,
    /// P-Preferred-Identity header.
    PPreferredIdentity,

    // Reason header (RFC 3326)
    /// Reason header.
    Reason,

    // Refer (RFC 3515)
    /// Refer-To header.
    ReferTo,
    /// Referred-By header.
    ReferredBy,

    // Replaces (RFC 3891)
    /// Replaces header.
    Replaces,

    // Custom/extension header.
    /// Custom header.
    Custom(String),
}

impl HeaderName {
    /// Returns the canonical header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Via => "Via",
            Self::Route => "Route",
            Self::RecordRoute => "Record-Route",
            Self::MaxForwards => "Max-Forwards",
            Self::Path => "Path",
            Self::CallId => "Call-ID",
            Self::CSeq => "CSeq",
            Self::From => "From",
            Self::To => "To",
            Self::ContentType => "Content-Type",
            Self::ContentLength => "Content-Length",
            Self::ContentEncoding => "Content-Encoding",
            Self::ContentDisposition => "Content-Disposition",
            Self::ContentLanguage => "Content-Language",
            Self::Contact => "Contact",
            Self::Expires => "Expires",
            Self::MinExpires => "Min-Expires",
            Self::WwwAuthenticate => "WWW-Authenticate",
            Self::Authorization => "Authorization",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::ProxyAuthorization => "Proxy-Authorization",
            Self::Allow => "Allow",
            Self::Supported => "Supported",
            Self::Require => "Require",
            Self::ProxyRequire => "Proxy-Require",
            Self::Unsupported => "Unsupported",
            Self::Accept => "Accept",
            Self::AcceptEncoding => "Accept-Encoding",
            Self::AcceptLanguage => "Accept-Language",
            Self::AlertInfo => "Alert-Info",
            Self::CallInfo => "Call-Info",
            Self::Date => "Date",
            Self::ErrorInfo => "Error-Info",
            Self::InReplyTo => "In-Reply-To",
            Self::MimeVersion => "MIME-Version",
            Self::Organization => "Organization",
            Self::Priority => "Priority",
            Self::ReplyTo => "Reply-To",
            Self::RetryAfter => "Retry-After",
            Self::Server => "Server",
            Self::Subject => "Subject",
            Self::Timestamp => "Timestamp",
            Self::UserAgent => "User-Agent",
            Self::Warning => "Warning",
            Self::Event => "Event",
            Self::SubscriptionState => "Subscription-State",
            Self::AllowEvents => "Allow-Events",
            Self::SessionExpires => "Session-Expires",
            Self::MinSe => "Min-SE",
            Self::Identity => "Identity",
            Self::PAssertedIdentity => "P-Asserted-Identity",
            Self::PPreferredIdentity => "P-Preferred-Identity",
            Self::Reason => "Reason",
            Self::ReferTo => "Refer-To",
            Self::ReferredBy => "Referred-By",
            Self::Replaces => "Replaces",
            Self::Custom(name) => name,
        }
    }

    /// Returns the compact form if available (RFC 3261 Section 7.3.3).
    #[must_use]
    pub fn compact_form(&self) -> Option<char> {
        match self {
            Self::Via => Some('v'),
            Self::From => Some('f'),
            Self::To => Some('t'),
            Self::CallId => Some('i'),
            Self::Contact => Some('m'),
            Self::ContentType => Some('c'),
            Self::ContentLength => Some('l'),
            Self::Supported => Some('k'),
            Self::Subject => Some('s'),
            Self::ReferTo => Some('r'),
            Self::AllowEvents => Some('u'),
            Self::Event => Some('o'),
            _ => None,
        }
    }

    /// Returns true if this header may appear multiple times in a message.
    #[must_use]
    pub fn allows_multiple(&self) -> bool {
        matches!(
            self,
            Self::Via
                | Self::Route
                | Self::RecordRoute
                | Self::Path
                | Self::Contact
                | Self::Accept
                | Self::AcceptEncoding
                | Self::AcceptLanguage
                | Self::Allow
                | Self::Supported
                | Self::Require
                | Self::ProxyRequire
                | Self::Unsupported
                | Self::Warning
                | Self::AllowEvents
        )
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HeaderName {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        // Handle compact forms (RFC 3261 Section 7.3.3)
        if s.len() == 1 {
            match s.chars().next() {
                Some('v' | 'V') => return Ok(Self::Via),
                Some('f' | 'F') => return Ok(Self::From),
                Some('t' | 'T') => return Ok(Self::To),
                Some('i' | 'I') => return Ok(Self::CallId),
                Some('m' | 'M') => return Ok(Self::Contact),
                Some('c' | 'C') => return Ok(Self::ContentType),
                Some('l' | 'L') => return Ok(Self::ContentLength),
                Some('k' | 'K') => return Ok(Self::Supported),
                Some('s' | 'S') => return Ok(Self::Subject),
                Some('r' | 'R') => return Ok(Self::ReferTo),
                Some('u' | 'U') => return Ok(Self::AllowEvents),
                Some('o' | 'O') => return Ok(Self::Event),
                _ => {}
            }
        }

        // Case-insensitive comparison
        match s.to_lowercase().as_str() {
            "via" => Ok(Self::Via),
            "route" => Ok(Self::Route),
            "record-route" => Ok(Self::RecordRoute),
            "max-forwards" => Ok(Self::MaxForwards),
            "path" => Ok(Self::Path),
            "call-id" => Ok(Self::CallId),
            "cseq" => Ok(Self::CSeq),
            "from" => Ok(Self::From),
            "to" => Ok(Self::To),
            "content-type" => Ok(Self::ContentType),
            "content-length" => Ok(Self::ContentLength),
            "content-encoding" => Ok(Self::ContentEncoding),
            "content-disposition" => Ok(Self::ContentDisposition),
            "content-language" => Ok(Self::ContentLanguage),
            "contact" => Ok(Self::Contact),
            "expires" => Ok(Self::Expires),
            "min-expires" => Ok(Self::MinExpires),
            "www-authenticate" => Ok(Self::WwwAuthenticate),
            "authorization" => Ok(Self::Authorization),
            "proxy-authenticate" => Ok(Self::ProxyAuthenticate),
            "proxy-authorization" => Ok(Self::ProxyAuthorization),
            "allow" => Ok(Self::Allow),
            "supported" => Ok(Self::Supported),
            "require" => Ok(Self::Require),
            "proxy-require" => Ok(Self::ProxyRequire),
            "unsupported" => Ok(Self::Unsupported),
            "accept" => Ok(Self::Accept),
            "accept-encoding" => Ok(Self::AcceptEncoding),
            "accept-language" => Ok(Self::AcceptLanguage),
            "alert-info" => Ok(Self::AlertInfo),
            "call-info" => Ok(Self::CallInfo),
            "date" => Ok(Self::Date),
            "error-info" => Ok(Self::ErrorInfo),
            "in-reply-to" => Ok(Self::InReplyTo),
            "mime-version" => Ok(Self::MimeVersion),
            "organization" => Ok(Self::Organization),
            "priority" => Ok(Self::Priority),
            "reply-to" => Ok(Self::ReplyTo),
            "retry-after" => Ok(Self::RetryAfter),
            "server" => Ok(Self::Server),
            "subject" => Ok(Self::Subject),
            "timestamp" => Ok(Self::Timestamp),
            "user-agent" => Ok(Self::UserAgent),
            "warning" => Ok(Self::Warning),
            "event" => Ok(Self::Event),
            "subscription-state" => Ok(Self::SubscriptionState),
            "allow-events" => Ok(Self::AllowEvents),
            "session-expires" => Ok(Self::SessionExpires),
            "min-se" => Ok(Self::MinSe),
            "identity" => Ok(Self::Identity),
            "p-asserted-identity" => Ok(Self::PAssertedIdentity),
            "p-preferred-identity" => Ok(Self::PPreferredIdentity),
            "reason" => Ok(Self::Reason),
            "refer-to" => Ok(Self::ReferTo),
            "referred-by" => Ok(Self::ReferredBy),
            "replaces" => Ok(Self::Replaces),
            _ => Ok(Self::Custom(s.to_string())),
        }
    }
}

/// A single SIP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Header name.
    pub name: HeaderName,
    /// Header value.
    pub value: String,
}

impl Header {
    /// Creates a new header.
    #[must_use]
    pub fn new(name: HeaderName, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    /// Parses a header from a line.
    ///
    /// Format: `Header-Name: value`
    ///
    /// # Errors
    ///
    /// Returns an error if the header line is malformed (missing colon separator).
    pub fn parse(line: &str) -> SipResult<Self> {
        // Power of 10 Rule 5: Assert precondition
        debug_assert!(!line.is_empty(), "empty header line");

        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| SipError::InvalidHeader {
                name: "unknown".to_string(),
                reason: "missing colon separator".to_string(),
            })?;

        let name: HeaderName = name.trim().parse()?;
        let value = value.trim().to_string();

        // Power of 10 Rule 5: Assert post-condition
        debug_assert!(!name.as_str().is_empty(), "header name cannot be empty");

        Ok(Self { name, value })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

/// Collection of SIP headers with structured parsing support.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    headers: Vec<Header>,
}

impl Headers {
    /// Creates an empty headers collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a header.
    pub fn add(&mut self, header: Header) {
        self.headers.push(header);
    }

    /// Sets a header (replaces existing).
    pub fn set(&mut self, name: HeaderName, value: impl Into<String>) {
        self.remove(&name);
        self.add(Header::new(name, value));
    }

    /// Gets the first header with the given name.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&Header> {
        self.headers.iter().find(|h| &h.name == name)
    }

    /// Gets all headers with the given name.
    #[must_use]
    pub fn get_all(&self, name: &HeaderName) -> Vec<&Header> {
        self.headers.iter().filter(|h| &h.name == name).collect()
    }

    /// Gets the first header value with the given name.
    #[must_use]
    pub fn get_value(&self, name: &HeaderName) -> Option<&str> {
        self.get(name).map(|h| h.value.as_str())
    }

    /// Removes all headers with the given name.
    pub fn remove(&mut self, name: &HeaderName) {
        self.headers.retain(|h| &h.name != name);
    }

    /// Returns true if the header exists.
    #[must_use]
    pub fn contains(&self, name: &HeaderName) -> bool {
        self.headers.iter().any(|h| &h.name == name)
    }

    /// Returns the number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns true if there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Returns an iterator over the headers.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.headers.iter()
    }

    // ==================== Structured Header Access ====================

    /// Returns the Content-Length if present.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.get_value(&HeaderName::ContentLength)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the Call-ID if present.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.get_value(&HeaderName::CallId)
    }

    /// Returns the `CSeq` value as a raw string if present.
    #[must_use]
    pub fn cseq(&self) -> Option<&str> {
        self.get_value(&HeaderName::CSeq)
    }

    /// Returns the `CSeq` as a structured type.
    #[must_use]
    pub fn cseq_parsed(&self) -> Option<CSeqHeader> {
        self.get_value(&HeaderName::CSeq)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the first Via header as a structured type.
    #[must_use]
    pub fn via_parsed(&self) -> Option<ViaHeader> {
        self.get_value(&HeaderName::Via)
            .and_then(|v| v.parse().ok())
    }

    /// Returns all Via headers as structured types.
    #[must_use]
    pub fn via_all_parsed(&self) -> Vec<ViaHeader> {
        self.get_all(&HeaderName::Via)
            .iter()
            .filter_map(|h| h.value.parse().ok())
            .collect()
    }

    /// Returns the From header as a structured type.
    #[must_use]
    pub fn from_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::From)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the To header as a structured type.
    #[must_use]
    pub fn to_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::To).and_then(|v| v.parse().ok())
    }

    /// Returns the Max-Forwards header as a structured type.
    #[must_use]
    pub fn max_forwards(&self) -> Option<MaxForwardsHeader> {
        self.get_value(&HeaderName::MaxForwards)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the Expires header value if present.
    #[must_use]
    pub fn expires(&self) -> Option<u32> {
        self.get_value(&HeaderName::Expires)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the Contact header as a structured type.
    #[must_use]
    pub fn contact_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::Contact)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the From header tag parameter.
    #[must_use]
    pub fn from_tag(&self) -> Option<String> {
        self.from_parsed().and_then(|n| n.tag)
    }

    /// Returns the To header tag parameter.
    #[must_use]
    pub fn to_tag(&self) -> Option<String> {
        self.to_parsed().and_then(|n| n.tag)
    }

    /// Returns the Via branch parameter from the topmost Via header.
    #[must_use]
    pub fn via_branch(&self) -> Option<String> {
        self.via_parsed().and_then(|v| v.branch)
    }

    // ==================== Route Header Access ====================

    /// Returns all Route header values.
    #[must_use]
    pub fn route_values(&self) -> Vec<String> {
        self.get_all(&HeaderName::Route)
            .iter()
            .map(|h| h.value.clone())
            .collect()
    }

    /// Returns all Record-Route header values.
    #[must_use]
    pub fn record_route_values(&self) -> Vec<String> {
        self.get_all(&HeaderName::RecordRoute)
            .iter()
            .map(|h| h.value.clone())
            .collect()
    }

    /// Adds a Route header.
    pub fn add_route(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::Route, value));
    }

    /// Adds a Record-Route header.
    pub fn add_record_route(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::RecordRoute, value));
    }

    /// Prepends a Route header (at the beginning of Route headers).
    pub fn prepend_route(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Route header or insert at beginning
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::Route);
        let header = Header::new(HeaderName::Route, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    /// Prepends a Record-Route header (for proxy insertion).
    pub fn prepend_record_route(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Record-Route header or insert after Via
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::RecordRoute)
            .or_else(|| {
                // Insert after last Via header
                self.headers
                    .iter()
                    .rposition(|h| h.name == HeaderName::Via)
                    .map(|i| i + 1)
            });
        let header = Header::new(HeaderName::RecordRoute, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    // ==================== Path Header Access (RFC 3327) ====================

    /// Returns all Path header values.
    ///
    /// Per RFC 3327, Path headers are used by proxies to record the route
    /// that a REGISTER request traversed. The registrar stores this path
    /// for later routing of requests to the registered contact.
    #[must_use]
    pub fn path_values(&self) -> Vec<String> {
        self.get_all(&HeaderName::Path)
            .iter()
            .map(|h| h.value.clone())
            .collect()
    }

    /// Adds a Path header.
    pub fn add_path(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::Path, value));
    }

    /// Prepends a Path header (for edge proxy insertion per RFC 3327).
    ///
    /// Per RFC 3327 Section 4.1, proxies MUST insert their URI at the
    /// beginning of the Path header list.
    pub fn prepend_path(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Path header or insert after Via
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::Path)
            .or_else(|| {
                // Insert after last Via header
                self.headers
                    .iter()
                    .rposition(|h| h.name == HeaderName::Via)
                    .map(|i| i + 1)
            });
        let header = Header::new(HeaderName::Path, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    // ==================== Mandatory Header Validation ====================

    /// Validates that all mandatory RFC 3261 headers are present for a request.
    ///
    /// RFC 3261 Section 8.1.1 requires: Via, To, From, Call-ID, `CSeq`, Max-Forwards
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - Iterates exactly 6 times (fixed required header count)
    ///
    /// # Errors
    ///
    /// Returns [`SipError::MissingHeader`] if any required header is absent.
    pub fn validate_request_headers(&self) -> SipResult<()> {
        // Power of 10 Rule 2: Fixed-size array ensures bounded iteration
        const REQUIRED_COUNT: usize = 6;
        let required = [
            HeaderName::Via,
            HeaderName::To,
            HeaderName::From,
            HeaderName::CallId,
            HeaderName::CSeq,
            HeaderName::MaxForwards,
        ];

        // Power of 10 Rule 5: Assert array size matches constant
        debug_assert_eq!(
            required.len(),
            REQUIRED_COUNT,
            "required headers count mismatch"
        );

        // Loop bound: exactly REQUIRED_COUNT iterations
        for name in &required {
            if !self.contains(name) {
                return Err(SipError::MissingHeader {
                    name: name.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates that all mandatory RFC 3261 headers are present for a response.
    ///
    /// RFC 3261 Section 8.1.1 requires: Via, To, From, Call-ID, `CSeq`
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - Iterates exactly 5 times (fixed required header count)
    ///
    /// # Errors
    ///
    /// Returns [`SipError::MissingHeader`] if any required header is absent.
    pub fn validate_response_headers(&self) -> SipResult<()> {
        // Power of 10 Rule 2: Fixed-size array ensures bounded iteration
        const REQUIRED_COUNT: usize = 5;
        let required = [
            HeaderName::Via,
            HeaderName::To,
            HeaderName::From,
            HeaderName::CallId,
            HeaderName::CSeq,
        ];

        // Power of 10 Rule 5: Assert array size matches constant
        debug_assert_eq!(
            required.len(),
            REQUIRED_COUNT,
            "required headers count mismatch"
        );

        // Loop bound: exactly REQUIRED_COUNT iterations
        for name in &required {
            if !self.contains(name) {
                return Err(SipError::MissingHeader {
                    name: name.to_string(),
                });
            }
        }

        Ok(())
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for header in &self.headers {
            writeln!(f, "{header}")?;
        }
        Ok(())
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.headers.into_iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.headers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::Method;

    #[test]
    fn test_header_name_from_str() {
        assert_eq!("Via".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("via".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("VIA".parse::<HeaderName>().unwrap(), HeaderName::Via);
    }

    #[test]
    fn test_header_name_compact() {
        assert_eq!("v".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("f".parse::<HeaderName>().unwrap(), HeaderName::From);
        assert_eq!("t".parse::<HeaderName>().unwrap(), HeaderName::To);
        assert_eq!("i".parse::<HeaderName>().unwrap(), HeaderName::CallId);
        assert_eq!("s".parse::<HeaderName>().unwrap(), HeaderName::Subject);
        assert_eq!("o".parse::<HeaderName>().unwrap(), HeaderName::Event);
    }

    #[test]
    fn test_header_parse() {
        let header = Header::parse("Via: SIP/2.0/UDP example.com").unwrap();
        assert_eq!(header.name, HeaderName::Via);
        assert_eq!(header.value, "SIP/2.0/UDP example.com");
    }

    #[test]
    fn test_headers_collection() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add(Header::new(HeaderName::CallId, "abc123"));
        headers.add(Header::new(HeaderName::ContentLength, "0"));

        assert_eq!(headers.len(), 3);
        assert_eq!(headers.call_id(), Some("abc123"));
        assert_eq!(headers.content_length(), Some(0));
    }

    #[test]
    fn test_headers_multi() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "first"));
        headers.add(Header::new(HeaderName::Via, "second"));

        let via_headers = headers.get_all(&HeaderName::Via);
        assert_eq!(via_headers.len(), 2);
    }

    #[test]
    fn test_header_display() {
        let header = Header::new(HeaderName::CallId, "abc123@host");
        assert_eq!(format!("{header}"), "Call-ID: abc123@host");
    }

    #[test]
    fn test_structured_via() {
        let mut headers = Headers::new();
        headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776",
        ));

        let via = headers.via_parsed().unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "pc33.example.com");
        assert_eq!(via.branch, Some("z9hG4bK776".to_string()));
    }

    #[test]
    fn test_structured_from_to() {
        let mut headers = Headers::new();
        headers.add(Header::new(
            HeaderName::From,
            "\"Alice\" <sip:alice@example.com>;tag=1234",
        ));
        headers.add(Header::new(HeaderName::To, "<sip:bob@example.com>"));

        let from = headers.from_parsed().unwrap();
        assert_eq!(from.display_name, Some("Alice".to_string()));
        assert_eq!(from.tag, Some("1234".to_string()));
        assert_eq!(headers.from_tag(), Some("1234".to_string()));

        let to = headers.to_parsed().unwrap();
        assert!(to.tag.is_none());
        assert!(headers.to_tag().is_none());
    }

    #[test]
    fn test_structured_cseq() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::CSeq, "1 INVITE"));

        let cseq = headers.cseq_parsed().unwrap();
        assert_eq!(cseq.sequence, 1);
        assert_eq!(cseq.method, Method::Invite);
    }

    #[test]
    fn test_structured_max_forwards() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::MaxForwards, "70"));

        let mf = headers.max_forwards().unwrap();
        assert_eq!(mf.value, 70);
    }

    #[test]
    fn test_validate_request_headers() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add(Header::new(HeaderName::To, "<sip:bob@example.com>"));
        headers.add(Header::new(HeaderName::From, "<sip:alice@example.com>"));
        headers.add(Header::new(HeaderName::CallId, "abc123"));
        headers.add(Header::new(HeaderName::CSeq, "1 INVITE"));
        headers.add(Header::new(HeaderName::MaxForwards, "70"));

        assert!(headers.validate_request_headers().is_ok());
    }

    #[test]
    fn test_validate_request_headers_missing() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        // Missing other required headers

        let result = headers.validate_request_headers();
        assert!(matches!(result, Err(SipError::MissingHeader { .. })));
    }

    #[test]
    fn test_new_headers() {
        assert_eq!(
            "User-Agent".parse::<HeaderName>().unwrap(),
            HeaderName::UserAgent
        );
        assert_eq!("Server".parse::<HeaderName>().unwrap(), HeaderName::Server);
        assert_eq!(
            "Priority".parse::<HeaderName>().unwrap(),
            HeaderName::Priority
        );
        assert_eq!("Reason".parse::<HeaderName>().unwrap(), HeaderName::Reason);
    }

    #[test]
    fn test_path_header() {
        // RFC 3327 Path header support
        assert_eq!("Path".parse::<HeaderName>().unwrap(), HeaderName::Path);
        assert_eq!("path".parse::<HeaderName>().unwrap(), HeaderName::Path);
        assert_eq!(HeaderName::Path.as_str(), "Path");
        assert!(HeaderName::Path.allows_multiple());
    }

    #[test]
    fn test_path_header_methods() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));

        // Add Path headers
        headers.add_path("<sip:edge.example.com;lr>");
        headers.add_path("<sip:proxy.example.com;lr>");

        let paths = headers.path_values();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "<sip:edge.example.com;lr>");
        assert_eq!(paths[1], "<sip:proxy.example.com;lr>");
    }

    #[test]
    fn test_prepend_path() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add_path("<sip:proxy.example.com;lr>");

        // Prepend should insert at the beginning
        headers.prepend_path("<sip:edge.example.com;lr>");

        let paths = headers.path_values();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "<sip:edge.example.com;lr>");
        assert_eq!(paths[1], "<sip:proxy.example.com;lr>");
    }
}
