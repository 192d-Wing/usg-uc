//! SIP stack integration layer.
//!
//! This module coordinates all SIP components into a working call flow:
//! - Message parsing via `proto-sip`
//! - Transaction handling via `sbc-transaction`
//! - Dialog management via `sbc-dialog`
//! - B2BUA call control via `sbc-b2bua`
//! - Registration handling via `sbc-registrar`
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - SIP events are logged
//! - **IA-2**: Identification and Authentication - REGISTER handling
//! - **SC-8**: Transmission Confidentiality and Integrity

use bytes::Bytes;
use proto_b2bua::{Call, CallId};
use proto_dialog::{Dialog, DialogId};
#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
use proto_registrar::{
    AuthenticatedRegistrar, ContactInfo, LocationService, RegisterRequest, RegistrarConfig,
    RegistrarMode,
};
use proto_sip::{Header, HeaderName, Method, SipMessage, StatusCode};
use proto_transaction::{
    ClientInviteTransaction, ClientNonInviteTransaction, ServerInviteTransaction,
    ServerNonInviteTransaction, TransactionKey,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uc_types::address::SbcSocketAddr;

/// SIP stack for processing SIP messages.
pub struct SipStack {
    /// Transaction store.
    transactions: RwLock<TransactionStore>,
    /// Dialog store.
    dialogs: RwLock<DialogStore>,
    /// Call store (B2BUA).
    calls: RwLock<CallStore>,
    /// Authenticated registrar for REGISTER handling with digest auth.
    registrar: RwLock<AuthenticatedRegistrar>,
    /// Location service for routing (in-memory, shared with registrar).
    location_service: Arc<RwLock<LocationService>>,
    /// Async location service for routing (storage-backed, when cluster enabled).
    #[cfg(feature = "cluster")]
    async_location_service: Option<Arc<AsyncLocationService>>,
    /// Stack configuration.
    config: SipStackConfig,
    /// Registration statistics.
    registrations_active: AtomicU64,
    registrations_total: AtomicU64,
}

/// SIP stack configuration.
#[derive(Debug, Clone)]
pub struct SipStackConfig {
    /// Instance name for Via headers.
    pub instance_name: String,
    /// Local SIP domain.
    pub domain: String,
    /// Registrar mode.
    pub registrar_mode: RegistrarMode,
    /// Enable B2BUA mode.
    pub b2bua_enabled: bool,
    /// Authentication realm for digest auth.
    pub auth_realm: String,
    /// Whether authentication is required for REGISTER.
    pub require_auth: bool,
    /// Static credentials: username → password (for standalone deployment).
    pub auth_credentials: HashMap<String, String>,
}

impl Default for SipStackConfig {
    fn default() -> Self {
        Self {
            instance_name: "sbc-01".to_string(),
            domain: "sbc.local".to_string(),
            registrar_mode: RegistrarMode::B2bua,
            b2bua_enabled: true,
            auth_realm: "sbc.local".to_string(),
            require_auth: false,
            auth_credentials: HashMap::new(),
        }
    }
}

/// Store for active transactions.
#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct TransactionStore {
    /// Server INVITE transactions.
    server_invite: HashMap<TransactionKey, ServerInviteState>,
    /// Server non-INVITE transactions.
    server_non_invite: HashMap<TransactionKey, ServerNonInviteState>,
    /// Client INVITE transactions.
    client_invite: HashMap<TransactionKey, ClientInviteState>,
    /// Client non-INVITE transactions.
    client_non_invite: HashMap<TransactionKey, ClientNonInviteState>,
}

/// State for server INVITE transaction.
struct ServerInviteState {
    transaction: ServerInviteTransaction,
    source: SbcSocketAddr,
}

/// State for server non-INVITE transaction.
struct ServerNonInviteState {
    transaction: ServerNonInviteTransaction,
    source: SbcSocketAddr,
}

/// State for client INVITE transaction.
struct ClientInviteState {
    transaction: ClientInviteTransaction,
    destination: SbcSocketAddr,
}

/// State for client non-INVITE transaction.
struct ClientNonInviteState {
    transaction: ClientNonInviteTransaction,
    destination: SbcSocketAddr,
}

/// Store for active dialogs.
#[derive(Default)]
struct DialogStore {
    /// Dialogs indexed by dialog ID.
    dialogs: HashMap<DialogId, Dialog>,
}

/// Store for active calls (B2BUA).
#[derive(Default)]
struct CallStore {
    /// Calls indexed by call ID.
    calls: HashMap<CallId, Call>,
}

/// Result of processing a SIP message.
#[derive(Debug)]
pub enum ProcessResult {
    /// Message was processed, send response.
    Response {
        /// Response message.
        message: SipMessage,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Forward request to another destination.
    Forward {
        /// Request message.
        message: SipMessage,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Multiple actions (e.g., 100 Trying + forward INVITE, or BYE + 200 OK).
    Multiple(Vec<ProcessResult>),
    /// No action required (e.g., ACK for 2xx).
    NoAction,
    /// Error processing message.
    Error {
        /// Error description.
        reason: String,
    },
}

impl SipStack {
    /// Creates a new SIP stack.
    pub fn new(config: SipStackConfig) -> Self {
        let location_service = Arc::new(RwLock::new(LocationService::new()));

        let registrar_config = RegistrarConfig {
            mode: config.registrar_mode,
            realm: config.auth_realm.clone(),
            require_auth: config.require_auth,
            ..RegistrarConfig::default()
        };

        // Build authenticated registrar with password lookup from config
        let credentials = config.auth_credentials.clone();
        let registrar =
            AuthenticatedRegistrar::new(registrar_config).with_password_lookup(move |user, _| {
                credentials.get(user).cloned()
            });

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            location_service,
            #[cfg(feature = "cluster")]
            async_location_service: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            config,
        }
    }

    /// Creates a new SIP stack with a storage-backed async location service.
    #[cfg(feature = "cluster")]
    pub fn new_with_location_service(
        config: SipStackConfig,
        async_location_service: Arc<AsyncLocationService>,
    ) -> Self {
        let location_service = Arc::new(RwLock::new(LocationService::new()));

        let registrar_config = RegistrarConfig {
            mode: config.registrar_mode,
            realm: config.auth_realm.clone(),
            require_auth: config.require_auth,
            ..RegistrarConfig::default()
        };

        let credentials = config.auth_credentials.clone();
        let registrar =
            AuthenticatedRegistrar::new(registrar_config).with_password_lookup(move |user, _| {
                credentials.get(user).cloned()
            });

        info!("SIP stack initialized with storage-backed location service");

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            location_service,
            async_location_service: Some(async_location_service),
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            config,
        }
    }

    /// Returns whether the stack has a storage-backed location service.
    #[cfg(feature = "cluster")]
    pub fn has_async_location_service(&self) -> bool {
        self.async_location_service.is_some()
    }

    /// Processes an incoming SIP message.
    pub async fn process_message(&self, data: &Bytes, source: SbcSocketAddr) -> ProcessResult {
        // Parse the SIP message
        let message = match SipMessage::parse(data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!(error = %e, "Failed to parse SIP message");
                return ProcessResult::Error {
                    reason: format!("Parse error: {e}"),
                };
            }
        };

        debug!(
            message_type = if message.is_request() {
                "request"
            } else {
                "response"
            },
            source = %source,
            "Processing SIP message"
        );

        match message {
            SipMessage::Request(_) => self.process_request(message, source).await,
            SipMessage::Response(_) => self.process_response(message, source).await,
        }
    }

    /// Processes a SIP request.
    async fn process_request(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let method = req.method.clone();
        let call_id = req.headers.call_id().map(String::from);

        info!(
            method = %method,
            call_id = call_id.as_deref().unwrap_or("none"),
            source = %source,
            "Received SIP request"
        );

        match method {
            Method::Register => self.handle_register(message, source).await,
            Method::Invite => self.handle_invite(message, source).await,
            Method::Ack => self.handle_ack(message).await,
            Method::Bye => self.handle_bye(message, source).await,
            Method::Cancel => self.handle_cancel(message, source).await,
            Method::Options => self.handle_options(message, source).await,
            _ => self.handle_other_request(message, source).await,
        }
    }

    /// Processes a SIP response.
    async fn process_response(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Response(ref resp) = message else {
            return ProcessResult::Error {
                reason: "Expected response".to_string(),
            };
        };

        info!(
            status = resp.status.code(),
            reason = resp.reason_phrase(),
            source = %source,
            "Received SIP response"
        );

        // Match to client transaction and process
        // In B2BUA mode, may need to create response for other leg
        self.match_response_to_transaction().await
    }

    /// Handles REGISTER request.
    ///
    /// Processes registration through `AuthenticatedRegistrar` which handles:
    /// - Digest authentication challenge/response (RFC 3261 §22)
    /// - Binding storage in `LocationService`
    /// - Expiration enforcement (min/max/default)
    /// - Wildcard removal (Contact: *)
    async fn handle_register(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing REGISTER");

        // Parse AOR from To header
        let aor = match req.headers.get_value(&HeaderName::To) {
            Some(to) => extract_uri_from_header(&to),
            None => {
                return ProcessResult::Response {
                    message: SipMessage::Response(create_response_from_request(
                        req,
                        StatusCode::BAD_REQUEST,
                    )),
                    destination: source,
                };
            }
        };

        // Parse Contact headers into ContactInfo list
        let contacts = parse_contacts_from_request(req);

        // Parse Expires header
        let expires: Option<u32> = req
            .headers
            .get_value(&HeaderName::Expires)
            .and_then(|v| v.parse().ok());

        // Parse Call-ID and CSeq
        let call_id = req
            .headers
            .call_id()
            .unwrap_or("unknown")
            .to_string();
        let cseq: u32 = req
            .headers
            .cseq()
            .and_then(|c| c.split_whitespace().next()?.parse().ok())
            .unwrap_or(1);

        // Build RegisterRequest
        let register_req = RegisterRequest::new(&aor)
            .with_contacts(contacts)
            .with_call_id(&call_id)
            .with_cseq(cseq);
        let register_req = if let Some(exp) = expires {
            RegisterRequest { expires: Some(exp), ..register_req }
        } else {
            register_req
        };
        let register_req = if let Some(auth) = req.headers.get_value(&HeaderName::Authorization) {
            register_req.with_authorization(auth)
        } else {
            register_req
        };
        let register_req = RegisterRequest {
            source_address: Some(source.to_string()),
            ..register_req
        };

        // Process through AuthenticatedRegistrar
        let reg_response = {
            let mut registrar = self.registrar.write().await;
            match registrar.process_register(&register_req) {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(error = %e, aor = %aor, "Registration processing failed");
                    return ProcessResult::Response {
                        message: SipMessage::Response(create_response_from_request(
                            req,
                            StatusCode::SERVER_INTERNAL_ERROR,
                        )),
                        destination: source,
                    };
                }
            }
        };

        // Build SIP response from RegisterResponse
        let status = StatusCode::new(reg_response.status_code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR);
        let mut response = create_response_from_request(req, status);

        match reg_response.status_code {
            200 => {
                // Add Contact headers for all current bindings
                for contact_str in reg_response.format_contacts() {
                    response.add_header(Header::new(HeaderName::Contact, contact_str));
                }

                // Sync bindings to shared location service for routing
                let binding_count = reg_response.contacts.len();
                {
                    let mut loc = self.location_service.write().await;
                    // Remove existing bindings for this AOR and re-add current ones
                    let _ = loc.remove_all_bindings(&aor);
                    for binding in &reg_response.contacts {
                        let new_binding = proto_registrar::Binding::new(
                            &aor,
                            binding.contact_uri(),
                            &call_id,
                            cseq,
                        );
                        let _ = loc.add_binding(new_binding);
                    }
                }

                self.registrations_total.fetch_add(1, Ordering::Relaxed);
                // Update active count based on location service
                self.registrations_active.store(
                    {
                        let loc = self.location_service.read().await;
                        loc.total_bindings() as u64
                    },
                    Ordering::Relaxed,
                );

                info!(
                    aor = %aor,
                    bindings = binding_count,
                    "Registration successful"
                );
            }
            401 => {
                // Add WWW-Authenticate challenge header
                if let Some(ref www_auth) = reg_response.www_authenticate {
                    response.add_header(Header::new(
                        HeaderName::WwwAuthenticate,
                        www_auth.as_str(),
                    ));
                }
                debug!(aor = %aor, "Registration challenged (401)");
            }
            423 => {
                // Add Min-Expires header
                if let Some(min_exp) = reg_response.min_expires {
                    response.add_header(Header::new(
                        HeaderName::Custom("Min-Expires".to_string()),
                        min_exp.to_string(),
                    ));
                }
                debug!(aor = %aor, "Registration interval too brief (423)");
            }
            _ => {
                warn!(
                    aor = %aor,
                    status = reg_response.status_code,
                    reason = %reg_response.reason,
                    "Registration failed"
                );
            }
        }

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles INVITE request.
    async fn handle_invite(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let call_id = req.headers.call_id().map(String::from);
        debug!(
            uri = %req.uri,
            call_id = call_id.as_deref().unwrap_or("none"),
            "Processing INVITE"
        );

        // Create 100 Trying response
        let trying = create_response_from_request(req, StatusCode::TRYING);

        info!(
            uri = %req.uri,
            call_id = call_id.as_deref().unwrap_or("none"),
            "Call initiated, sent 100 Trying"
        );

        // In a full implementation, would:
        // 1. Create server transaction
        // 2. Look up destination via location service or routing
        // 3. Create B2BUA call legs
        // 4. Forward INVITE to B-leg

        ProcessResult::Response {
            message: SipMessage::Response(trying),
            destination: source,
        }
    }

    /// Handles ACK request.
    async fn handle_ack(&self, message: SipMessage) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing ACK");

        // ACK for 2xx completes dialog establishment
        // ACK for non-2xx is absorbed by transaction layer
        ProcessResult::NoAction
    }

    /// Handles BYE request.
    async fn handle_bye(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let call_id = req.headers.call_id().map(String::from);
        debug!(
            call_id = call_id.as_deref().unwrap_or("none"),
            "Processing BYE"
        );

        // Create 200 OK response
        let response = create_response_from_request(req, StatusCode::OK);

        info!(
            call_id = call_id.as_deref().unwrap_or("none"),
            "Call terminated"
        );

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles CANCEL request.
    async fn handle_cancel(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing CANCEL");

        // Create 200 OK for the CANCEL
        let response = create_response_from_request(req, StatusCode::OK);

        // Would also need to send 487 Request Terminated for the INVITE

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles OPTIONS request (keepalive/capability query).
    async fn handle_options(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing OPTIONS");

        // Create 200 OK with capabilities
        let mut response = create_response_from_request(req, StatusCode::OK);

        // Add Allow header with supported methods
        response.add_header(Header::new(
            HeaderName::Allow,
            "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER",
        ));

        // Add Accept header as custom
        response.add_header(Header::new(
            HeaderName::Custom("Accept".to_string()),
            "application/sdp",
        ));

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles other requests.
    async fn handle_other_request(
        &self,
        message: SipMessage,
        source: SbcSocketAddr,
    ) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        warn!(method = %req.method, "Unsupported method");

        // Create 405 Method Not Allowed
        let mut response = create_response_from_request(req, StatusCode::METHOD_NOT_ALLOWED);
        response.add_header(Header::new(
            HeaderName::Allow,
            "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER",
        ));

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Matches a response to its client transaction.
    async fn match_response_to_transaction(&self) -> ProcessResult {
        // In B2BUA mode, would forward response to appropriate leg
        // For now, just log it
        debug!("Response matched to transaction");
        ProcessResult::NoAction
    }

    /// Returns the number of active dialogs.
    pub async fn dialog_count(&self) -> usize {
        self.dialogs.read().await.dialogs.len()
    }

    /// Returns the number of active calls.
    pub async fn call_count(&self) -> usize {
        self.calls.read().await.calls.len()
    }
}

/// Creates a response from a request, copying required headers.
fn create_response_from_request(
    req: &proto_sip::message::SipRequest,
    status: StatusCode,
) -> proto_sip::message::SipResponse {
    let mut response = proto_sip::message::SipResponse::new(status);

    // Copy Via headers
    if let Some(via) = req.headers.get_value(&HeaderName::Via) {
        response.add_header(Header::new(HeaderName::Via, via));
    }

    // Copy From header
    if let Some(from) = req.headers.get_value(&HeaderName::From) {
        response.add_header(Header::new(HeaderName::From, from));
    }

    // Copy To header (add tag if not present for non-100 responses)
    if let Some(to) = req.headers.get_value(&HeaderName::To) {
        let to_value = if status.code() != 100 && !to.contains("tag=") {
            format!("{};tag={}", to, generate_tag())
        } else {
            to.to_string()
        };
        response.add_header(Header::new(HeaderName::To, to_value));
    }

    // Copy Call-ID
    if let Some(call_id) = req.headers.call_id() {
        response.add_header(Header::new(HeaderName::CallId, call_id));
    }

    // Copy CSeq
    if let Some(cseq) = req.headers.cseq() {
        response.add_header(Header::new(HeaderName::CSeq, cseq));
    }

    // Add Content-Length: 0
    response.add_header(Header::new(HeaderName::ContentLength, "0"));

    response
}

/// Generates a random tag for From/To headers.
fn generate_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", timestamp & 0xFFFF_FFFF)
}

/// Extracts a SIP URI from a From/To header value.
///
/// Handles formats like:
/// - `<sip:alice@example.com>`
/// - `"Alice" <sip:alice@example.com>;tag=1234`
/// - `sip:alice@example.com`
fn extract_uri_from_header(header_value: &str) -> String {
    if let Some(start) = header_value.find('<') {
        if let Some(end) = header_value.find('>') {
            return header_value[start + 1..end].to_string();
        }
    }
    // No angle brackets — take the value before any parameters
    header_value
        .split(';')
        .next()
        .unwrap_or(header_value)
        .trim()
        .to_string()
}

/// Parses Contact headers from a SIP request into `ContactInfo` list.
fn parse_contacts_from_request(req: &proto_sip::message::SipRequest) -> Vec<ContactInfo> {
    let mut contacts = Vec::new();

    // Get all Contact header values
    let contact_values: Vec<String> = req
        .headers
        .get_all(&HeaderName::Contact)
        .map(|h| h.value.clone())
        .collect();

    for contact_val in &contact_values {
        // Handle wildcard
        if contact_val.trim() == "*" {
            contacts.push(ContactInfo::new("*"));
            continue;
        }

        // Parse each contact (may be comma-separated)
        for part in contact_val.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let uri = extract_uri_from_header(part);
            let mut info = ContactInfo::new(&uri);

            // Parse expires parameter
            if let Some(exp_str) = extract_param(part, "expires") {
                info.expires = exp_str.parse().ok();
            }

            // Parse q parameter
            if let Some(q_str) = extract_param(part, "q") {
                info.q_value = q_str.parse().ok();
            }

            // Parse +sip.instance parameter (RFC 5626)
            if let Some(instance) = extract_param(part, "+sip.instance") {
                info.instance_id = Some(instance.trim_matches('"').to_string());
            }

            // Parse reg-id parameter (RFC 5626)
            if let Some(reg_id_str) = extract_param(part, "reg-id") {
                info.reg_id = reg_id_str.parse().ok();
            }

            contacts.push(info);
        }
    }

    contacts
}

/// Extracts a parameter value from a SIP header value string.
///
/// Looks for `name=value` patterns after the URI portion.
fn extract_param<'a>(header_value: &'a str, name: &str) -> Option<&'a str> {
    // Find the parameter after the URI (after '>')
    let params_start = header_value.find('>').map_or(0, |p| p + 1);
    let params = &header_value[params_start..];

    for part in params.split(';') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim();
            if key.eq_ignore_ascii_case(name) {
                return Some(part[eq_pos + 1..].trim());
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sip_stack_creation() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        assert_eq!(stack.dialog_count().await, 0);
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn test_process_options() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        let options = b"OPTIONS sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:sbc.local>\r\n\
            Call-ID: test123@example.com\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(options), source)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                assert!(message.is_response());
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status, StatusCode::OK);
                }
            }
            _ => panic!("Expected response"),
        }
    }

    #[tokio::test]
    async fn test_process_register() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:alice@example.com>\r\n\
            Call-ID: reg123@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                assert!(message.is_response());
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status, StatusCode::OK);
                }
            }
            _ => panic!("Expected response"),
        }

        // Verify binding was stored in location service
        let loc = stack.location_service.read().await;
        assert!(
            loc.has_bindings("sip:alice@example.com"),
            "Location service should have binding for alice"
        );
        let bindings = loc.lookup("sip:alice@example.com");
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].contact_uri(),
            "sip:alice@client.example.com:5060"
        );
    }

    #[tokio::test]
    async fn test_register_with_auth() {
        let mut config = SipStackConfig::default();
        config.require_auth = true;
        config.auth_realm = "example.com".to_string();
        config
            .auth_credentials
            .insert("alice".to_string(), "password123".to_string());

        let stack = SipStack::new(config);

        // First REGISTER without credentials → should get 401
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:alice@example.com>\r\n\
            Call-ID: reg123@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                if let SipMessage::Response(resp) = message {
                    assert_eq!(
                        resp.status.code(),
                        401,
                        "Should get 401 Unauthorized without credentials"
                    );
                    // Should have WWW-Authenticate header
                    let www_auth = resp.headers.get_value(&HeaderName::WwwAuthenticate);
                    assert!(
                        www_auth.is_some(),
                        "401 response should include WWW-Authenticate"
                    );
                }
            }
            _ => panic!("Expected response"),
        }

        // Verify no binding stored
        let loc = stack.location_service.read().await;
        assert!(
            !loc.has_bindings("sip:alice@example.com"),
            "Should NOT have binding after 401"
        );
    }

    #[tokio::test]
    async fn test_process_invite() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        let invite = b"INVITE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call123@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), source)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                assert!(message.is_response());
                if let SipMessage::Response(resp) = message {
                    // Should get 100 Trying
                    assert_eq!(resp.status, StatusCode::TRYING);
                }
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn test_generate_tag() {
        let tag1 = generate_tag();
        let tag2 = generate_tag();

        assert!(!tag1.is_empty());
        assert!(!tag2.is_empty());
        // Tags should be formatted as hex
        assert!(tag1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(tag2.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
