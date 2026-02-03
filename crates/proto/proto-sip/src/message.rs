//! SIP message types per RFC 3261.

use crate::error::{SipError, SipResult};
use crate::header::{Header, Headers};
use crate::method::Method;
use crate::response::StatusCode;
use crate::uri::SipUri;
use crate::{MAX_MESSAGE_SIZE, SIP_VERSION};
use bytes::Bytes;
use std::fmt;
use std::str::FromStr;

/// A SIP message (request or response).
#[derive(Debug, Clone)]
pub enum SipMessage {
    /// SIP request.
    Request(SipRequest),
    /// SIP response.
    Response(SipResponse),
}

impl SipMessage {
    /// Parses a SIP message from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> SipResult<Self> {
        // Power of 10 Rule 5: Assert preconditions
        debug_assert!(!data.is_empty(), "empty data passed to parse");

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(SipError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_MESSAGE_SIZE,
            });
        }

        let text = std::str::from_utf8(data).map_err(|e| SipError::ParseError {
            reason: format!("invalid UTF-8: {e}"),
        })?;

        // Power of 10 Rule 5: Assert post-parse invariant
        debug_assert!(!text.is_empty(), "UTF-8 conversion produced empty string");

        text.parse()
    }

    /// Returns true if this is a request.
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Returns true if this is a response.
    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Returns the headers.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        match self {
            Self::Request(req) => &req.headers,
            Self::Response(resp) => &resp.headers,
        }
    }

    /// Returns mutable headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        match self {
            Self::Request(req) => &mut req.headers,
            Self::Response(resp) => &mut resp.headers,
        }
    }

    /// Returns the body.
    #[must_use]
    pub fn body(&self) -> Option<&Bytes> {
        match self {
            Self::Request(req) => req.body.as_ref(),
            Self::Response(resp) => resp.body.as_ref(),
        }
    }

    /// Returns the Call-ID.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.headers().call_id()
    }

    /// Returns the `CSeq`.
    #[must_use]
    pub fn cseq(&self) -> Option<&str> {
        self.headers().cseq()
    }

    /// Encodes the message to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

impl fmt::Display for SipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(req) => write!(f, "{req}"),
            Self::Response(resp) => write!(f, "{resp}"),
        }
    }
}

impl FromStr for SipMessage {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        // Find the first line
        let (first_line, rest) = s
            .split_once("\r\n")
            .or_else(|| s.split_once('\n'))
            .ok_or_else(|| SipError::ParseError {
                reason: "no first line".to_string(),
            })?;

        // Determine if request or response
        if first_line.starts_with("SIP/") {
            // Response: SIP/2.0 200 OK
            SipResponse::parse_with_rest(first_line, rest).map(Self::Response)
        } else {
            // Request: INVITE sip:user@host SIP/2.0
            SipRequest::parse_with_rest(first_line, rest).map(Self::Request)
        }
    }
}

/// A SIP request.
#[derive(Debug, Clone)]
pub struct SipRequest {
    /// Request method.
    pub method: Method,
    /// Request-URI.
    pub uri: SipUri,
    /// Headers.
    pub headers: Headers,
    /// Message body (optional).
    pub body: Option<Bytes>,
}

impl SipRequest {
    /// Creates a new SIP request.
    #[must_use]
    pub fn new(method: Method, uri: SipUri) -> Self {
        Self {
            method,
            uri,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Sets the message body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds a header.
    pub fn add_header(&mut self, header: Header) {
        self.headers.add(header);
    }

    /// Parses request from first line and rest of message.
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - `split_whitespace()` is bounded by input length
    /// - Header parsing loops bounded by message size
    fn parse_with_rest(first_line: &str, rest: &str) -> SipResult<Self> {
        // Power of 10 Rule 5: Assert preconditions
        debug_assert!(!first_line.is_empty(), "empty first line");

        // Parse: METHOD uri SIP/2.0
        // Loop bound: split_whitespace iterates at most first_line.len() times
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SipError::ParseError {
                reason: format!("invalid request line: {first_line}"),
            });
        }

        // Power of 10 Rule 5: Assert parts count
        debug_assert_eq!(parts.len(), 3, "request line must have exactly 3 parts");

        // Method parsing is infallible - unknown methods become Extension variants
        let method: Method = parts[0]
            .parse()
            .unwrap_or_else(|e: std::convert::Infallible| match e {});
        let uri: SipUri = parts[1].parse()?;

        if parts[2] != SIP_VERSION {
            return Err(SipError::ParseError {
                reason: format!("unsupported SIP version: {}", parts[2]),
            });
        }

        let (headers, body) = parse_headers_and_body(rest)?;

        // Power of 10 Rule 5: Assert post-conditions
        debug_assert!(!method.as_str().is_empty(), "method cannot be empty");

        Ok(Self {
            method,
            uri,
            headers,
            body,
        })
    }
}

impl fmt::Display for SipRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Request line
        writeln!(f, "{} {} {}\r", self.method, self.uri, SIP_VERSION)?;

        // Headers
        for header in self.headers.iter() {
            writeln!(f, "{header}\r")?;
        }

        // Blank line
        write!(f, "\r\n")?;

        // Body
        if let Some(ref body) = self.body {
            if let Ok(text) = std::str::from_utf8(body) {
                write!(f, "{text}")?;
            }
        }

        Ok(())
    }
}

/// A SIP response.
#[derive(Debug, Clone)]
pub struct SipResponse {
    /// Status code.
    pub status: StatusCode,
    /// Reason phrase (optional override).
    pub reason: Option<String>,
    /// Headers.
    pub headers: Headers,
    /// Message body (optional).
    pub body: Option<Bytes>,
}

impl SipResponse {
    /// Creates a new SIP response.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Sets a custom reason phrase.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the message body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds a header.
    pub fn add_header(&mut self, header: Header) {
        self.headers.add(header);
    }

    /// Returns the reason phrase.
    #[must_use]
    pub fn reason_phrase(&self) -> &str {
        self.reason
            .as_deref()
            .unwrap_or_else(|| self.status.reason_phrase())
    }

    /// Parses response from first line and rest of message.
    fn parse_with_rest(first_line: &str, rest: &str) -> SipResult<Self> {
        // Parse: SIP/2.0 200 OK
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(SipError::ParseError {
                reason: format!("invalid status line: {first_line}"),
            });
        }

        if parts[0] != SIP_VERSION {
            return Err(SipError::ParseError {
                reason: format!("unsupported SIP version: {}", parts[0]),
            });
        }

        let code: u16 = parts[1].parse().map_err(|_| SipError::ParseError {
            reason: format!("invalid status code: {}", parts[1]),
        })?;

        let status = StatusCode::new(code)?;
        let reason = parts.get(2).map(ToString::to_string);

        let (headers, body) = parse_headers_and_body(rest)?;

        Ok(Self {
            status,
            reason,
            headers,
            body,
        })
    }
}

impl fmt::Display for SipResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Status line
        writeln!(
            f,
            "{} {} {}\r",
            SIP_VERSION,
            self.status.code(),
            self.reason_phrase()
        )?;

        // Headers
        for header in self.headers.iter() {
            writeln!(f, "{header}\r")?;
        }

        // Blank line
        write!(f, "\r\n")?;

        // Body
        if let Some(ref body) = self.body {
            if let Ok(text) = std::str::from_utf8(body) {
                write!(f, "{text}")?;
            }
        }

        Ok(())
    }
}

/// Parses headers and body from message rest.
///
/// # Loop Bounds (Power of 10 Rule 2)
///
/// - `header_section.lines()` is bounded by input string length
/// - Maximum iterations: `header_section.len()` (one per character worst case)
fn parse_headers_and_body(rest: &str) -> SipResult<(Headers, Option<Bytes>)> {
    let mut headers = Headers::new();

    // Split headers from body (double CRLF)
    let (header_section, body_section) = if let Some(pos) = rest.find("\r\n\r\n") {
        (&rest[..pos], Some(&rest[pos + 4..]))
    } else if let Some(pos) = rest.find("\n\n") {
        (&rest[..pos], Some(&rest[pos + 2..]))
    } else {
        (rest, None)
    };

    // Parse headers
    // Power of 10 Rule 2: Loop bounded by header_section.lines() count
    let mut current_header: Option<String> = None;

    for line in header_section.lines() {
        if line.is_empty() {
            break;
        }

        // Handle header folding (continuation lines start with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref mut h) = current_header {
                h.push(' ');
                h.push_str(line.trim());
            }
        } else {
            // Finish previous header
            if let Some(h) = current_header.take() {
                headers.add(Header::parse(&h)?);
            }
            current_header = Some(line.to_string());
        }
    }

    // Finish last header
    if let Some(h) = current_header {
        headers.add(Header::parse(&h)?);
    }

    // Parse body
    let body = body_section
        .filter(|b| !b.is_empty())
        .map(|b| Bytes::from(b.to_string()));

    // Validate Content-Length if present
    if let Some(expected) = headers.content_length() {
        let actual = body.as_ref().map_or(0, Bytes::len);
        // Power of 10 Rule 5: Assert content length invariant
        debug_assert!(
            expected <= crate::MAX_MESSAGE_SIZE,
            "Content-Length exceeds max message size"
        );
        if expected != actual {
            return Err(SipError::ContentLengthMismatch {
                header: expected,
                actual,
            });
        }
    }

    Ok((headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HeaderName;

    #[test]
    fn test_parse_invite_request() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP pc33.example.com\r\n\
                   Call-ID: abc123@pc33.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

        let parsed: SipMessage = msg.parse().unwrap();
        assert!(parsed.is_request());

        if let SipMessage::Request(req) = parsed {
            assert_eq!(req.method, Method::Invite);
            assert_eq!(req.uri.host, "example.com");
            assert_eq!(req.headers.call_id(), Some("abc123@pc33.example.com"));
        }
    }

    #[test]
    fn test_parse_response() {
        let msg = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP example.com\r\n\
                   Call-ID: abc123\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

        let parsed: SipMessage = msg.parse().unwrap();
        assert!(parsed.is_response());

        if let SipMessage::Response(resp) = parsed {
            assert_eq!(resp.status, StatusCode::OK);
        }
    }

    #[test]
    fn test_create_request() {
        let uri = SipUri::new("example.com").with_user("alice");
        let mut req = SipRequest::new(Method::Invite, uri);
        req.add_header(Header::new(HeaderName::CallId, "test123"));
        req.add_header(Header::new(HeaderName::CSeq, "1 INVITE"));

        let msg = req.to_string();
        assert!(msg.starts_with("INVITE sip:alice@example.com SIP/2.0"));
        assert!(msg.contains("Call-ID: test123"));
    }

    #[test]
    fn test_create_response() {
        let resp = SipResponse::new(StatusCode::OK);
        let msg = resp.to_string();
        assert!(msg.starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn test_roundtrip() {
        let original = "INVITE sip:alice@example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP pc33.example.com\r\n\
                        Call-ID: abc123\r\n\
                        CSeq: 1 INVITE\r\n\
                        Content-Length: 0\r\n\
                        \r\n";

        let parsed: SipMessage = original.parse().unwrap();
        let reparsed: SipMessage = parsed.to_string().parse().unwrap();

        assert_eq!(parsed.call_id(), reparsed.call_id());
    }

    #[test]
    fn test_message_with_body() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Content-Length: 4\r\n\
                   \r\n\
                   test";

        let parsed: SipMessage = msg.parse().unwrap();
        assert_eq!(parsed.body().map(|b| b.as_ref()), Some(b"test".as_slice()));
    }

    #[test]
    fn test_content_length_mismatch() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Content-Length: 10\r\n\
                   \r\n\
                   test";

        let result: SipResult<SipMessage> = msg.parse();
        assert!(matches!(result, Err(SipError::ContentLengthMismatch { .. })));
    }
}
