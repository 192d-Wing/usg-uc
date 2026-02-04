//! RFC 3261 §11: Querying for Capabilities (OPTIONS)
//!
//! This module provides server-side processing for OPTIONS requests per RFC 3261 Section 11.
//! OPTIONS allows a UAC to query the capabilities of a UAS or proxy without affecting state.
//!
//! # RFC 3261 Section 11 Requirements
//!
//! - **§11.1**: Construction of OPTIONS requests (handled by builder.rs)
//! - **§11.2**: Processing of OPTIONS requests and response generation
//!
//! The response to OPTIONS MUST include:
//! - Allow: lists supported methods
//! - Accept: lists acceptable Content-Types (if body is accepted)
//! - Accept-Encoding: lists acceptable content encodings
//! - Accept-Language: lists acceptable languages
//! - Supported: lists supported extensions (option tags)
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::builder::ResponseBuilder;
use crate::error::SipResult;
use crate::header::HeaderName;
use crate::message::{SipRequest, SipResponse};
use crate::method::Method;

/// Default supported methods for a basic SIP UA per RFC 3261.
pub const DEFAULT_SUPPORTED_METHODS: &[Method] = &[
    Method::Invite,
    Method::Ack,
    Method::Cancel,
    Method::Bye,
    Method::Options,
    Method::Register,
];

/// Default supported content types for SDP-based sessions.
pub const DEFAULT_ACCEPT_TYPES: &[&str] = &["application/sdp"];

/// Default supported encodings.
pub const DEFAULT_ACCEPT_ENCODINGS: &[&str] = &["identity"];

/// Default supported languages.
pub const DEFAULT_ACCEPT_LANGUAGES: &[&str] = &["en"];

/// Capabilities that can be advertised in OPTIONS responses.
///
/// Per RFC 3261 §11.2, an OPTIONS response indicates the capabilities
/// of the UAS without affecting dialog or session state.
#[derive(Debug, Clone)]
pub struct OptionsCapabilities {
    /// Supported SIP methods (Allow header).
    pub methods: Vec<Method>,

    /// Supported SIP extensions/option tags (Supported header).
    pub extensions: Vec<String>,

    /// Acceptable Content-Types (Accept header).
    pub accept_types: Vec<String>,

    /// Acceptable content encodings (Accept-Encoding header).
    pub accept_encodings: Vec<String>,

    /// Acceptable languages (Accept-Language header).
    pub accept_languages: Vec<String>,

    /// Server identification string (Server header).
    pub server: Option<String>,
}

impl Default for OptionsCapabilities {
    fn default() -> Self {
        Self {
            methods: DEFAULT_SUPPORTED_METHODS.to_vec(),
            extensions: Vec::new(),
            accept_types: DEFAULT_ACCEPT_TYPES.iter().map(|s| (*s).to_string()).collect(),
            accept_encodings: DEFAULT_ACCEPT_ENCODINGS.iter().map(|s| (*s).to_string()).collect(),
            accept_languages: DEFAULT_ACCEPT_LANGUAGES.iter().map(|s| (*s).to_string()).collect(),
            server: None,
        }
    }
}

impl OptionsCapabilities {
    /// Creates a new capabilities configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates capabilities with the specified methods.
    #[must_use]
    pub fn with_methods(mut self, methods: Vec<Method>) -> Self {
        self.methods = methods;
        self
    }

    /// Adds a supported method.
    #[must_use]
    pub fn add_method(mut self, method: Method) -> Self {
        if !self.methods.contains(&method) {
            self.methods.push(method);
        }
        self
    }

    /// Creates capabilities with the specified extensions.
    #[must_use]
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Adds a supported extension (option tag).
    #[must_use]
    pub fn add_extension(mut self, extension: impl Into<String>) -> Self {
        let ext = extension.into();
        if !self.extensions.contains(&ext) {
            self.extensions.push(ext);
        }
        self
    }

    /// Creates capabilities with the specified accept types.
    #[must_use]
    pub fn with_accept_types(mut self, types: Vec<String>) -> Self {
        self.accept_types = types;
        self
    }

    /// Adds an acceptable Content-Type.
    #[must_use]
    pub fn add_accept_type(mut self, content_type: impl Into<String>) -> Self {
        let ct = content_type.into();
        if !self.accept_types.contains(&ct) {
            self.accept_types.push(ct);
        }
        self
    }

    /// Creates capabilities with the specified accept encodings.
    #[must_use]
    pub fn with_accept_encodings(mut self, encodings: Vec<String>) -> Self {
        self.accept_encodings = encodings;
        self
    }

    /// Creates capabilities with the specified accept languages.
    #[must_use]
    pub fn with_accept_languages(mut self, languages: Vec<String>) -> Self {
        self.accept_languages = languages;
        self
    }

    /// Sets the server identification string.
    #[must_use]
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Formats the Allow header value.
    #[must_use]
    pub fn allow_header_value(&self) -> String {
        self.methods
            .iter()
            .map(Method::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Formats the Supported header value.
    #[must_use]
    pub fn supported_header_value(&self) -> Option<String> {
        if self.extensions.is_empty() {
            None
        } else {
            Some(self.extensions.join(", "))
        }
    }

    /// Formats the Accept header value.
    #[must_use]
    pub fn accept_header_value(&self) -> Option<String> {
        if self.accept_types.is_empty() {
            None
        } else {
            Some(self.accept_types.join(", "))
        }
    }

    /// Formats the Accept-Encoding header value.
    #[must_use]
    pub fn accept_encoding_header_value(&self) -> Option<String> {
        if self.accept_encodings.is_empty() {
            None
        } else {
            Some(self.accept_encodings.join(", "))
        }
    }

    /// Formats the Accept-Language header value.
    #[must_use]
    pub fn accept_language_header_value(&self) -> Option<String> {
        if self.accept_languages.is_empty() {
            None
        } else {
            Some(self.accept_languages.join(", "))
        }
    }
}

/// Creates a 200 OK response to an OPTIONS request per RFC 3261 §11.2.
///
/// This function constructs a proper OPTIONS response that advertises
/// the capabilities of the UA as specified in the `capabilities` parameter.
///
/// # RFC 3261 §11.2 Compliance
///
/// The response includes:
/// - Via, From, To, Call-ID, `CSeq` copied from request
/// - Allow header listing supported methods
/// - Accept header listing acceptable Content-Types
/// - Accept-Encoding header listing acceptable encodings
/// - Accept-Language header listing acceptable languages
/// - Supported header listing supported extensions (if any)
/// - Server header (if configured)
///
/// # Errors
///
/// Returns an error if required headers are missing from the request
/// or if response construction fails.
pub fn create_options_response(
    request: &SipRequest,
    capabilities: &OptionsCapabilities,
) -> SipResult<SipResponse> {
    // Power of 10 Rule 5: Assert precondition
    debug_assert_eq!(
        request.method,
        Method::Options,
        "create_options_response called with non-OPTIONS request"
    );

    let mut builder = ResponseBuilder::ok().copy_headers_from(request);

    // RFC 3261 §11.2: MUST include Allow header
    builder = builder.header(HeaderName::Allow, capabilities.allow_header_value());

    // RFC 3261 §11.2: Include Accept if body types are supported
    if let Some(accept) = capabilities.accept_header_value() {
        builder = builder.header(HeaderName::Accept, accept);
    }

    // RFC 3261 §11.2: Include Accept-Encoding
    if let Some(encoding) = capabilities.accept_encoding_header_value() {
        builder = builder.header(HeaderName::AcceptEncoding, encoding);
    }

    // RFC 3261 §11.2: Include Accept-Language
    if let Some(language) = capabilities.accept_language_header_value() {
        builder = builder.header(HeaderName::AcceptLanguage, language);
    }

    // RFC 3261 §11.2: Include Supported if extensions are available
    if let Some(supported) = capabilities.supported_header_value() {
        builder = builder.header(HeaderName::Supported, supported);
    }

    // Include Server header if configured
    if let Some(ref server) = capabilities.server {
        builder = builder.server(server);
    }

    builder.build()
}

/// Creates a 200 OK response to an OPTIONS request with default capabilities.
///
/// This is a convenience function that uses `OptionsCapabilities::default()`.
///
/// # Errors
///
/// Returns an error if required headers are missing from the request.
pub fn create_options_response_default(request: &SipRequest) -> SipResult<SipResponse> {
    create_options_response(request, &OptionsCapabilities::default())
}

/// Processes an OPTIONS request and returns the appropriate response.
///
/// This is the main entry point for handling incoming OPTIONS requests.
/// It validates the request and constructs the response per RFC 3261 §11.2.
///
/// # Arguments
///
/// * `request` - The incoming OPTIONS request
/// * `capabilities` - The capabilities to advertise
///
/// # Returns
///
/// Returns a 200 OK response with capability headers on success.
/// Returns a 400 Bad Request if the request is malformed.
///
/// # Errors
///
/// Returns an error if response construction fails.
pub fn process_options_request(
    request: &SipRequest,
    capabilities: &OptionsCapabilities,
) -> SipResult<SipResponse> {
    // Validate this is actually an OPTIONS request
    if request.method != Method::Options {
        return ResponseBuilder::bad_request()
            .copy_headers_from(request)
            .reason("Expected OPTIONS request")
            .build();
    }

    create_options_response(request, capabilities)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::builder::RequestBuilder;
    use crate::uri::SipUri;

    fn create_test_options_request() -> SipRequest {
        let uri = SipUri::new("example.com").with_user("bob");
        RequestBuilder::options(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(SipUri::new("example.com").with_user("alice"), None)
            .to_uri(uri, None)
            .call_id("options-test@example.com")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap()
    }

    #[test]
    fn test_options_capabilities_default() {
        let caps = OptionsCapabilities::default();

        assert!(!caps.methods.is_empty());
        assert!(caps.methods.contains(&Method::Invite));
        assert!(caps.methods.contains(&Method::Options));
        assert!(caps.accept_types.contains(&"application/sdp".to_string()));
    }

    #[test]
    fn test_options_capabilities_builder() {
        let caps = OptionsCapabilities::new()
            .add_method(Method::Subscribe)
            .add_method(Method::Notify)
            .add_extension("100rel")
            .add_extension("timer")
            .add_accept_type("application/pidf+xml")
            .with_server("USG-SIP/1.0");

        assert!(caps.methods.contains(&Method::Subscribe));
        assert!(caps.methods.contains(&Method::Notify));
        assert!(caps.extensions.contains(&"100rel".to_string()));
        assert!(caps.extensions.contains(&"timer".to_string()));
        assert!(caps.accept_types.contains(&"application/pidf+xml".to_string()));
        assert_eq!(caps.server, Some("USG-SIP/1.0".to_string()));
    }

    #[test]
    fn test_allow_header_value() {
        let caps = OptionsCapabilities::new()
            .with_methods(vec![Method::Invite, Method::Bye, Method::Options]);

        assert_eq!(caps.allow_header_value(), "INVITE, BYE, OPTIONS");
    }

    #[test]
    fn test_supported_header_value() {
        let caps = OptionsCapabilities::new()
            .add_extension("100rel")
            .add_extension("timer");

        assert_eq!(caps.supported_header_value(), Some("100rel, timer".to_string()));

        let empty_caps = OptionsCapabilities::new().with_extensions(vec![]);
        assert_eq!(empty_caps.supported_header_value(), None);
    }

    #[test]
    fn test_create_options_response() {
        let request = create_test_options_request();
        let caps = OptionsCapabilities::new()
            .add_extension("100rel")
            .with_server("Test-Server/1.0");

        let response = create_options_response(&request, &caps).unwrap();

        assert_eq!(response.status, crate::response::StatusCode::OK);
        assert!(response.headers.get_value(&HeaderName::Allow).is_some());
        assert!(response.headers.get_value(&HeaderName::Accept).is_some());
        assert!(response.headers.get_value(&HeaderName::AcceptEncoding).is_some());
        assert!(response.headers.get_value(&HeaderName::AcceptLanguage).is_some());
        assert!(response.headers.get_value(&HeaderName::Supported).is_some());
        assert!(response.headers.get_value(&HeaderName::Server).is_some());

        // Verify headers copied from request
        assert_eq!(response.headers.call_id(), Some("options-test@example.com"));
    }

    #[test]
    fn test_create_options_response_default() {
        let request = create_test_options_request();
        let response = create_options_response_default(&request).unwrap();

        assert_eq!(response.status, crate::response::StatusCode::OK);
        assert!(response.headers.get_value(&HeaderName::Allow).is_some());

        // Check Allow contains default methods
        let allow = response.headers.get_value(&HeaderName::Allow).unwrap();
        assert!(allow.contains("INVITE"));
        assert!(allow.contains("OPTIONS"));
        assert!(allow.contains("BYE"));
    }

    #[test]
    fn test_process_options_request() {
        let request = create_test_options_request();
        let caps = OptionsCapabilities::default();

        let response = process_options_request(&request, &caps).unwrap();
        assert_eq!(response.status, crate::response::StatusCode::OK);
    }

    #[test]
    fn test_process_non_options_request() {
        // Create an INVITE request instead of OPTIONS
        let uri = SipUri::new("example.com").with_user("bob");
        let request = RequestBuilder::invite(uri.clone())
            .via_auto("UDP", "192.168.1.1", Some(5060))
            .from_auto(SipUri::new("example.com").with_user("alice"), None)
            .to_uri(uri, None)
            .call_id("invite-test@example.com")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap();

        let caps = OptionsCapabilities::default();
        let response = process_options_request(&request, &caps).unwrap();

        // Should return 400 Bad Request for non-OPTIONS
        assert_eq!(response.status, crate::response::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_no_duplicate_methods() {
        let caps = OptionsCapabilities::new()
            .add_method(Method::Invite)
            .add_method(Method::Invite); // Duplicate

        let invite_count = caps.methods.iter().filter(|m| **m == Method::Invite).count();
        assert_eq!(invite_count, 1, "Should not add duplicate methods");
    }

    #[test]
    fn test_no_duplicate_extensions() {
        let caps = OptionsCapabilities::new()
            .add_extension("100rel")
            .add_extension("100rel"); // Duplicate

        let count = caps.extensions.iter().filter(|e| *e == "100rel").count();
        assert_eq!(count, 1, "Should not add duplicate extensions");
    }

    #[test]
    fn test_constants() {
        assert!(!DEFAULT_SUPPORTED_METHODS.is_empty());
        assert!(DEFAULT_SUPPORTED_METHODS.contains(&Method::Options));
        assert!(!DEFAULT_ACCEPT_TYPES.is_empty());
        assert!(!DEFAULT_ACCEPT_ENCODINGS.is_empty());
        assert!(!DEFAULT_ACCEPT_LANGUAGES.is_empty());
    }
}
