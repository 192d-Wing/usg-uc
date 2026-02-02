//! SIP headers per RFC 3261.

use crate::error::{SipError, SipResult};
use std::fmt;
use std::str::FromStr;

/// Common SIP header names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeaderName {
    // Request routing
    /// Via header.
    Via,
    /// Route header.
    Route,
    /// Record-Route header.
    RecordRoute,
    /// Max-Forwards header.
    MaxForwards,

    // Transaction identification
    /// Call-ID header.
    CallId,
    /// CSeq header.
    CSeq,
    /// Branch parameter in Via.
    From,
    /// To header.
    To,

    // Message body
    /// Content-Type header.
    ContentType,
    /// Content-Length header.
    ContentLength,
    /// Content-Encoding header.
    ContentEncoding,

    // Session/dialog
    /// Contact header.
    Contact,
    /// Expires header.
    Expires,

    // Authentication
    /// WWW-Authenticate header.
    WwwAuthenticate,
    /// Authorization header.
    Authorization,
    /// Proxy-Authenticate header.
    ProxyAuthenticate,
    /// Proxy-Authorization header.
    ProxyAuthorization,

    // Features
    /// Allow header.
    Allow,
    /// Supported header.
    Supported,
    /// Require header.
    Require,
    /// Proxy-Require header.
    ProxyRequire,
    /// Unsupported header.
    Unsupported,

    // Event framework
    /// Event header.
    Event,
    /// Subscription-State header.
    SubscriptionState,

    // STIR/SHAKEN
    /// Identity header.
    Identity,

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
            Self::CallId => "Call-ID",
            Self::CSeq => "CSeq",
            Self::From => "From",
            Self::To => "To",
            Self::ContentType => "Content-Type",
            Self::ContentLength => "Content-Length",
            Self::ContentEncoding => "Content-Encoding",
            Self::Contact => "Contact",
            Self::Expires => "Expires",
            Self::WwwAuthenticate => "WWW-Authenticate",
            Self::Authorization => "Authorization",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::ProxyAuthorization => "Proxy-Authorization",
            Self::Allow => "Allow",
            Self::Supported => "Supported",
            Self::Require => "Require",
            Self::ProxyRequire => "Proxy-Require",
            Self::Unsupported => "Unsupported",
            Self::Event => "Event",
            Self::SubscriptionState => "Subscription-State",
            Self::Identity => "Identity",
            Self::Custom(name) => name,
        }
    }

    /// Returns the compact form if available.
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
            _ => None,
        }
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
        // Handle compact forms
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
                _ => {}
            }
        }

        // Case-insensitive comparison
        match s.to_lowercase().as_str() {
            "via" => Ok(Self::Via),
            "route" => Ok(Self::Route),
            "record-route" => Ok(Self::RecordRoute),
            "max-forwards" => Ok(Self::MaxForwards),
            "call-id" => Ok(Self::CallId),
            "cseq" => Ok(Self::CSeq),
            "from" => Ok(Self::From),
            "to" => Ok(Self::To),
            "content-type" => Ok(Self::ContentType),
            "content-length" => Ok(Self::ContentLength),
            "content-encoding" => Ok(Self::ContentEncoding),
            "contact" => Ok(Self::Contact),
            "expires" => Ok(Self::Expires),
            "www-authenticate" => Ok(Self::WwwAuthenticate),
            "authorization" => Ok(Self::Authorization),
            "proxy-authenticate" => Ok(Self::ProxyAuthenticate),
            "proxy-authorization" => Ok(Self::ProxyAuthorization),
            "allow" => Ok(Self::Allow),
            "supported" => Ok(Self::Supported),
            "require" => Ok(Self::Require),
            "proxy-require" => Ok(Self::ProxyRequire),
            "unsupported" => Ok(Self::Unsupported),
            "event" => Ok(Self::Event),
            "subscription-state" => Ok(Self::SubscriptionState),
            "identity" => Ok(Self::Identity),
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
    pub fn parse(line: &str) -> SipResult<Self> {
        let (name, value) = line.split_once(':').ok_or_else(|| SipError::InvalidHeader {
            name: "unknown".to_string(),
            reason: "missing colon separator".to_string(),
        })?;

        let name: HeaderName = name.trim().parse()?;
        let value = value.trim().to_string();

        Ok(Self { name, value })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

/// Collection of SIP headers.
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

    /// Returns the CSeq if present.
    #[must_use]
    pub fn cseq(&self) -> Option<&str> {
        self.get_value(&HeaderName::CSeq)
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
}
