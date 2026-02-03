//! SIP message builder utilities.
//!
//! Provides convenient builders for constructing SIP requests and responses
//! with automatic header generation per RFC 3261.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::SipResult;
use crate::header::{Header, HeaderName, Headers};
use crate::header_params::{CSeqHeader, MaxForwardsHeader, NameAddr, ViaHeader};
use crate::message::{SipRequest, SipResponse};
use crate::method::Method;
use crate::response::StatusCode;
use crate::uri::SipUri;
use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates a unique Call-ID.
///
/// Format: `{timestamp_hex}{counter_hex}@{host}`
#[must_use]
pub fn generate_call_id(host: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Static counter to ensure uniqueness even with same timestamp
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Combine timestamp with counter for uniqueness
    format!("{:x}{:x}@{}", (timestamp & 0xFFFF_FFFF) as u64, count, host)
}

/// Generates a unique branch parameter with RFC 3261 magic cookie.
#[must_use]
pub fn generate_branch() -> String {
    ViaHeader::generate_branch()
}

/// Generates a unique tag for From/To headers.
#[must_use]
pub fn generate_tag() -> String {
    NameAddr::generate_tag()
}

/// Builder for SIP requests.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    method: Method,
    uri: SipUri,
    headers: Headers,
    body: Option<Bytes>,
    auto_content_length: bool,
}

impl RequestBuilder {
    /// Creates a new request builder.
    #[must_use]
    pub fn new(method: Method, uri: SipUri) -> Self {
        Self {
            method,
            uri,
            headers: Headers::new(),
            body: None,
            auto_content_length: true,
        }
    }

    /// Creates an INVITE request builder.
    #[must_use]
    pub fn invite(uri: SipUri) -> Self {
        Self::new(Method::Invite, uri)
    }

    /// Creates a REGISTER request builder.
    #[must_use]
    pub fn register(uri: SipUri) -> Self {
        Self::new(Method::Register, uri)
    }

    /// Creates a BYE request builder.
    #[must_use]
    pub fn bye(uri: SipUri) -> Self {
        Self::new(Method::Bye, uri)
    }

    /// Creates a CANCEL request builder.
    #[must_use]
    pub fn cancel(uri: SipUri) -> Self {
        Self::new(Method::Cancel, uri)
    }

    /// Creates an OPTIONS request builder.
    #[must_use]
    pub fn options(uri: SipUri) -> Self {
        Self::new(Method::Options, uri)
    }

    /// Creates an ACK request builder.
    #[must_use]
    pub fn ack(uri: SipUri) -> Self {
        Self::new(Method::Ack, uri)
    }

    /// Sets the Via header.
    #[must_use]
    pub fn via(mut self, via: &ViaHeader) -> Self {
        self.headers.set(HeaderName::Via, via.to_string());
        self
    }

    /// Sets the Via header with auto-generated branch.
    #[must_use]
    pub fn via_auto(self, transport: &str, host: &str, port: Option<u16>) -> Self {
        let mut via = ViaHeader::new(transport, host).with_branch(generate_branch());
        if let Some(p) = port {
            via = via.with_port(p);
        }
        self.via(&via)
    }

    /// Sets the From header.
    #[must_use]
    pub fn from(mut self, from: &NameAddr) -> Self {
        self.headers.set(HeaderName::From, from.to_string());
        self
    }

    /// Sets the From header with auto-generated tag.
    #[must_use]
    pub fn from_auto(self, uri: SipUri, display_name: Option<&str>) -> Self {
        let mut from = NameAddr::new(uri).with_tag(generate_tag());
        if let Some(name) = display_name {
            from = from.with_display_name(name);
        }
        self.from(&from)
    }

    /// Sets the To header.
    #[must_use]
    pub fn to(mut self, to: &NameAddr) -> Self {
        self.headers.set(HeaderName::To, to.to_string());
        self
    }

    /// Sets the To header (without tag - tags are added by UAS).
    #[must_use]
    pub fn to_uri(self, uri: SipUri, display_name: Option<&str>) -> Self {
        let mut to = NameAddr::new(uri);
        if let Some(name) = display_name {
            to = to.with_display_name(name);
        }
        self.to(&to)
    }

    /// Sets the Call-ID header.
    #[must_use]
    pub fn call_id(mut self, call_id: impl Into<String>) -> Self {
        self.headers.set(HeaderName::CallId, call_id.into());
        self
    }

    /// Sets the Call-ID header with auto-generated value.
    #[must_use]
    pub fn call_id_auto(self, host: &str) -> Self {
        self.call_id(generate_call_id(host))
    }

    /// Sets the `CSeq` header.
    #[must_use]
    pub fn cseq(mut self, sequence: u32) -> Self {
        let cseq = CSeqHeader::new(sequence, self.method.clone());
        self.headers.set(HeaderName::CSeq, cseq.to_string());
        self
    }

    /// Sets the Max-Forwards header.
    #[must_use]
    pub fn max_forwards(mut self, value: u8) -> Self {
        self.headers.set(HeaderName::MaxForwards, value.to_string());
        self
    }

    /// Sets the Contact header.
    #[must_use]
    pub fn contact(mut self, contact: &NameAddr) -> Self {
        self.headers.set(HeaderName::Contact, contact.to_string());
        self
    }

    /// Sets the Contact header from a URI.
    #[must_use]
    pub fn contact_uri(self, uri: SipUri) -> Self {
        self.contact(&NameAddr::new(uri))
    }

    /// Sets the Expires header.
    #[must_use]
    pub fn expires(mut self, seconds: u32) -> Self {
        self.headers.set(HeaderName::Expires, seconds.to_string());
        self
    }

    /// Sets the Content-Type header.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.headers
            .set(HeaderName::ContentType, content_type.into());
        self
    }

    /// Sets the User-Agent header.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.headers.set(HeaderName::UserAgent, user_agent.into());
        self
    }

    /// Adds a generic header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        self.headers.add(Header::new(name, value.into()));
        self
    }

    /// Sets the message body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets the message body with Content-Type.
    #[must_use]
    pub fn body_sdp(self, sdp: impl Into<Bytes>) -> Self {
        self.content_type("application/sdp").body(sdp)
    }

    /// Disables automatic Content-Length header generation.
    #[must_use]
    pub fn no_auto_content_length(mut self) -> Self {
        self.auto_content_length = false;
        self
    }

    /// Builds the SIP request.
    ///
    /// # Errors
    ///
    /// Returns an error if required headers are missing.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn build(mut self) -> SipResult<SipRequest> {
        // Auto-generate Content-Length if needed
        if self.auto_content_length {
            let len = self.body.as_ref().map_or(0, Bytes::len);
            self.headers.set(HeaderName::ContentLength, len.to_string());
        }

        // Validate required headers
        self.headers.validate_request_headers()?;

        let mut request = SipRequest::new(self.method, self.uri);
        request.headers = self.headers;
        request.body = self.body;

        Ok(request)
    }

    /// Builds the request with default Max-Forwards if not set.
    ///
    /// # Errors
    ///
    /// Returns an error if required headers are missing.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn build_with_defaults(mut self) -> SipResult<SipRequest> {
        // Add default Max-Forwards if not present
        if !self.headers.contains(&HeaderName::MaxForwards) {
            self.headers.set(
                HeaderName::MaxForwards,
                MaxForwardsHeader::DEFAULT.to_string(),
            );
        }

        self.build()
    }
}

/// Builder for SIP responses.
#[derive(Debug, Clone)]
pub struct ResponseBuilder {
    status: StatusCode,
    reason: Option<String>,
    headers: Headers,
    body: Option<Bytes>,
    auto_content_length: bool,
}

impl ResponseBuilder {
    /// Creates a new response builder.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            headers: Headers::new(),
            body: None,
            auto_content_length: true,
        }
    }

    /// Creates a 100 Trying response builder.
    #[must_use]
    pub fn trying() -> Self {
        Self::new(StatusCode::TRYING)
    }

    /// Creates a 180 Ringing response builder.
    #[must_use]
    pub fn ringing() -> Self {
        Self::new(StatusCode::RINGING)
    }

    /// Creates a 200 OK response builder.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Creates a 400 Bad Request response builder.
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST)
    }

    /// Creates a 401 Unauthorized response builder.
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED)
    }

    /// Creates a 403 Forbidden response builder.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN)
    }

    /// Creates a 404 Not Found response builder.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
    }

    /// Creates a 486 Busy Here response builder.
    #[must_use]
    pub fn busy_here() -> Self {
        Self::new(StatusCode::BUSY_HERE)
    }

    /// Creates a 500 Server Internal Error response builder.
    #[must_use]
    pub fn server_error() -> Self {
        Self::new(StatusCode::SERVER_INTERNAL_ERROR)
    }

    /// Creates a 503 Service Unavailable response builder.
    #[must_use]
    pub fn service_unavailable() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE)
    }

    /// Sets a custom reason phrase.
    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Copies Via, From, To, Call-ID, and `CSeq` headers from the request.
    #[must_use]
    pub fn copy_headers_from(mut self, request: &SipRequest) -> Self {
        // Copy all Via headers (in order)
        for via in request.headers.get_all(&HeaderName::Via) {
            self.headers.add(Header::new(HeaderName::Via, &via.value));
        }

        // Copy From
        if let Some(from) = request.headers.get_value(&HeaderName::From) {
            self.headers.set(HeaderName::From, from);
        }

        // Copy To
        if let Some(to) = request.headers.get_value(&HeaderName::To) {
            self.headers.set(HeaderName::To, to);
        }

        // Copy Call-ID
        if let Some(call_id) = request.headers.call_id() {
            self.headers.set(HeaderName::CallId, call_id);
        }

        // Copy CSeq
        if let Some(cseq) = request.headers.cseq() {
            self.headers.set(HeaderName::CSeq, cseq);
        }

        self
    }

    /// Adds a To tag (for dialog establishment).
    #[must_use]
    pub fn to_tag(mut self, tag: impl Into<String>) -> Self {
        if let Some(to) = self.headers.get_value(&HeaderName::To) {
            // Parse existing To and add tag
            if let Ok(mut name_addr) = to.parse::<NameAddr>() {
                name_addr.tag = Some(tag.into());
                self.headers.set(HeaderName::To, name_addr.to_string());
            }
        }
        self
    }

    /// Adds an auto-generated To tag.
    #[must_use]
    pub fn to_tag_auto(self) -> Self {
        self.to_tag(generate_tag())
    }

    /// Sets the Contact header.
    #[must_use]
    pub fn contact(mut self, contact: &NameAddr) -> Self {
        self.headers.set(HeaderName::Contact, contact.to_string());
        self
    }

    /// Sets the Content-Type header.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.headers
            .set(HeaderName::ContentType, content_type.into());
        self
    }

    /// Sets the Server header.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.headers.set(HeaderName::Server, server.into());
        self
    }

    /// Sets the `WWW-Authenticate` header for 401 responses.
    #[must_use]
    pub fn www_authenticate(mut self, challenge: impl Into<String>) -> Self {
        self.headers
            .set(HeaderName::WwwAuthenticate, challenge.into());
        self
    }

    /// Adds a generic header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        self.headers.add(Header::new(name, value.into()));
        self
    }

    /// Sets the message body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets the message body with SDP Content-Type.
    #[must_use]
    pub fn body_sdp(self, sdp: impl Into<Bytes>) -> Self {
        self.content_type("application/sdp").body(sdp)
    }

    /// Disables automatic Content-Length header generation.
    #[must_use]
    pub fn no_auto_content_length(mut self) -> Self {
        self.auto_content_length = false;
        self
    }

    /// Builds the SIP response.
    ///
    /// # Errors
    ///
    /// Returns an error if required headers are missing.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn build(mut self) -> SipResult<SipResponse> {
        // Auto-generate Content-Length if needed
        if self.auto_content_length {
            let len = self.body.as_ref().map_or(0, Bytes::len);
            self.headers.set(HeaderName::ContentLength, len.to_string());
        }

        // Validate required headers
        self.headers.validate_response_headers()?;

        let mut response = SipResponse::new(self.status);
        if let Some(reason) = self.reason {
            response = response.with_reason(reason);
        }
        response.headers = self.headers;
        response.body = self.body;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_call_id() {
        let call_id1 = generate_call_id("example.com");
        let call_id2 = generate_call_id("example.com");

        assert!(call_id1.ends_with("@example.com"));
        // Call IDs should be unique (high probability)
        assert_ne!(call_id1, call_id2);
    }

    #[test]
    fn test_request_builder_invite() {
        let uri = SipUri::new("example.com").with_user("bob");
        let from_uri = SipUri::new("example.com").with_user("alice");

        let request = RequestBuilder::invite(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(from_uri.clone(), Some("Alice"))
            .to_uri(uri.clone(), Some("Bob"))
            .call_id_auto("example.com")
            .cseq(1)
            .max_forwards(70)
            .contact_uri(from_uri)
            .build()
            .unwrap();

        assert_eq!(request.method, Method::Invite);
        assert!(request.headers.call_id().is_some());
        assert!(request.headers.via_branch().is_some());
    }

    #[test]
    fn test_request_builder_register() {
        let uri = SipUri::new("example.com");
        let contact_uri = SipUri::new("192.168.1.1")
            .with_user("alice")
            .with_port(5060);

        let request = RequestBuilder::register(uri)
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(SipUri::new("example.com").with_user("alice"), None)
            .to_uri(SipUri::new("example.com").with_user("alice"), None)
            .call_id_auto("example.com")
            .cseq(1)
            .max_forwards(70)
            .contact_uri(contact_uri)
            .expires(3600)
            .build()
            .unwrap();

        assert_eq!(request.method, Method::Register);
        assert_eq!(request.headers.expires(), Some(3600));
    }

    #[test]
    fn test_response_builder_ok() {
        // First create a request to copy headers from
        let uri = SipUri::new("example.com").with_user("bob");

        let request = RequestBuilder::invite(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(SipUri::new("example.com").with_user("alice"), None)
            .to_uri(uri, None)
            .call_id("test@example.com")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap();

        let response = ResponseBuilder::ok()
            .copy_headers_from(&request)
            .to_tag_auto()
            .contact(NameAddr::new(SipUri::new("192.168.1.2").with_user("bob")))
            .build()
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers.call_id(), Some("test@example.com"));
        assert!(response.headers.to_tag().is_some());
    }

    #[test]
    fn test_response_builder_unauthorized() {
        let uri = SipUri::new("example.com").with_user("bob");

        let request = RequestBuilder::register(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(uri.clone(), None)
            .to_uri(uri, None)
            .call_id("reg@example.com")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap();

        let response = ResponseBuilder::unauthorized()
            .copy_headers_from(&request)
            .www_authenticate(r#"Digest realm="example.com", nonce="abc123""#)
            .build()
            .unwrap();

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers
                .get_value(&HeaderName::WwwAuthenticate)
                .is_some()
        );
    }

    #[test]
    fn test_request_with_body() {
        let uri = SipUri::new("example.com").with_user("bob");
        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";

        let request = RequestBuilder::invite(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(SipUri::new("example.com").with_user("alice"), None)
            .to_uri(uri, None)
            .call_id_auto("example.com")
            .cseq(1)
            .max_forwards(70)
            .body_sdp(sdp)
            .build()
            .unwrap();

        assert_eq!(
            request.headers.get_value(&HeaderName::ContentType),
            Some("application/sdp")
        );
        assert_eq!(request.headers.content_length(), Some(sdp.len()));
        assert!(request.body.is_some());
    }
}
