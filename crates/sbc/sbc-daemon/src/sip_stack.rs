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
use proto_b2bua::{B2buaMode, Call, CallConfig, CallId, MediaAddress, SdpRewriter, extract_media_address};
use proto_dialog::{Dialog, DialogId};
#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
use proto_registrar::{
    AuthenticatedRegistrar, ContactInfo, LocationService, RegisterRequest, RegistrarConfig,
    RegistrarMode,
};
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id};
use proto_sip::uri::SipUri;
use proto_sip::{Header, HeaderName, Method, SipMessage, StatusCode};
use proto_transaction::{
    ClientInviteTransaction, ClientNonInviteTransaction, ServerInviteTransaction,
    ServerNonInviteTransaction, TransactionKey, TransportType,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
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
    /// Call correlation: maps A-leg/B-leg SIP Call-IDs to internal CallIds.
    call_correlation: RwLock<CallCorrelation>,
    /// SDP rewriter for media anchoring.
    sdp_rewriter: SdpRewriter,
    /// Media pipeline for RTP relay (optional, set after construction).
    media_pipeline: Option<Arc<crate::media_pipeline::MediaPipeline>>,
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

/// Correlates A-leg and B-leg SIP Call-IDs with internal B2BUA CallIds.
#[derive(Default)]
struct CallCorrelation {
    /// Maps A-leg SIP Call-ID → internal CallId.
    a_leg: HashMap<String, CallId>,
    /// Maps B-leg SIP Call-ID → internal CallId.
    b_leg: HashMap<String, CallId>,
    /// Maps internal CallId → call addressing info.
    addresses: HashMap<CallId, CallAddresses>,
}

/// Addressing info for both legs of a B2BUA call.
struct CallAddresses {
    /// A-leg source address (where to send responses).
    a_leg_source: SbcSocketAddr,
    /// B-leg destination address (where to forward requests).
    b_leg_destination: SbcSocketAddr,
    /// A-leg SIP Call-ID.
    a_leg_sip_call_id: String,
    /// B-leg SIP Call-ID.
    b_leg_sip_call_id: String,
    /// SBC's local SIP address for Via/Contact headers.
    local_addr: String,
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
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
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
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            config,
        }
    }

    /// Sets the media pipeline for RTP relay.
    pub fn set_media_pipeline(&mut self, pipeline: Arc<crate::media_pipeline::MediaPipeline>) {
        self.media_pipeline = Some(pipeline);
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
    ///
    /// In B2BUA mode, matches the response to the B-leg client transaction,
    /// then forwards an appropriate response to the A-leg.
    async fn process_response(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Response(ref resp) = message else {
            return ProcessResult::Error {
                reason: "Expected response".to_string(),
            };
        };

        let status_code = resp.status.code();
        let sip_call_id = resp
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(
            status = status_code,
            call_id = %sip_call_id,
            source = %source,
            "Received SIP response"
        );

        // Look up the B-leg Call-ID in correlation map
        let corr = self.call_correlation.read().await;
        let internal_id = match corr.b_leg.get(&sip_call_id) {
            Some(id) => id.clone(),
            None => {
                debug!(call_id = %sip_call_id, "Response for unknown B-leg Call-ID, ignoring");
                return ProcessResult::NoAction;
            }
        };

        let addrs = match corr.addresses.get(&internal_id) {
            Some(a) => CallAddresses {
                a_leg_source: a.a_leg_source,
                b_leg_destination: a.b_leg_destination,
                a_leg_sip_call_id: a.a_leg_sip_call_id.clone(),
                b_leg_sip_call_id: a.b_leg_sip_call_id.clone(),
                local_addr: a.local_addr.clone(),
            },
            None => {
                warn!(call_id = %sip_call_id, "No addresses for call");
                return ProcessResult::NoAction;
            }
        };
        drop(corr);

        // Handle based on status code class
        if status_code == 100 {
            // 100 Trying — absorb, do not forward to A-leg (RFC 3261 §16.7)
            debug!("Absorbing 100 Trying from B-leg");
            return ProcessResult::NoAction;
        }

        if (101..200).contains(&status_code) {
            // 1xx provisional (180 Ringing, 183 Session Progress)
            return self
                .handle_provisional_response(resp, &internal_id, &addrs)
                .await;
        }

        if (200..300).contains(&status_code) {
            // 2xx success (200 OK)
            return self
                .handle_success_response(resp, &internal_id, &addrs)
                .await;
        }

        // 4xx/5xx/6xx error — forward to A-leg, cleanup
        self.handle_error_response(resp, status_code, &internal_id, &addrs)
            .await
    }

    /// Handles 1xx provisional response from B-leg (180 Ringing, 183 Session Progress).
    async fn handle_provisional_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        let status_code = resp.status.code();

        // Update call state
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.receive_provisional(status_code);
            }
        }

        // Build provisional response for A-leg with A-leg's Call-ID
        let mut a_response = proto_sip::message::SipResponse::new(resp.status);

        // Copy Via from A-leg (original request's Via, not B-leg's)
        // For now, copy from B-leg response and trust the headers
        copy_response_headers(resp, &mut a_response);

        // Replace Call-ID with A-leg's
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // If 183 with SDP, rewrite SDP for A-leg
        if status_code == 183 {
            if let Some(ref body) = resp.body {
                let sdp_str = String::from_utf8_lossy(body);
                let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
                let local_media = MediaAddress::new(local_ip, 20_002);
                let result = self
                    .sdp_rewriter
                    .rewrite_answer_for_a_leg(&sdp_str, &local_media);
                a_response.body = Some(Bytes::from(result.rewritten));
                a_response
                    .headers
                    .set(HeaderName::ContentType, "application/sdp");
            }
        }

        info!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Forwarding provisional response to A-leg"
        );

        ProcessResult::Response {
            message: SipMessage::Response(a_response),
            destination: addrs.a_leg_source,
        }
    }

    /// Handles 200 OK from B-leg: activate call, rewrite SDP, send ACK to B-leg.
    async fn handle_success_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        // Activate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.activate();
            }
        }

        // Extract B-leg's RTP address from SDP
        if let Some(ref body) = resp.body {
            let sdp_str = String::from_utf8_lossy(body);
            if let Some(_remote_media) = extract_media_address(&sdp_str) {
                // Phase 4 will use this to set_remote_address on MediaPipeline
                debug!(
                    call_id = %addrs.a_leg_sip_call_id,
                    "B-leg RTP address extracted from SDP"
                );
            }
        }

        // Build 200 OK for A-leg with rewritten SDP
        let mut a_response = proto_sip::message::SipResponse::new(StatusCode::OK);
        copy_response_headers(resp, &mut a_response);
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // Rewrite SDP for A-leg
        if let Some(ref body) = resp.body {
            let sdp_str = String::from_utf8_lossy(body);
            let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
            let local_media = MediaAddress::new(local_ip, 20_002);
            let result = self
                .sdp_rewriter
                .rewrite_answer_for_a_leg(&sdp_str, &local_media);
            a_response.body = Some(Bytes::from(result.rewritten));
            a_response
                .headers
                .set(HeaderName::ContentType, "application/sdp");
            // Update Content-Length
            if let Some(ref body) = a_response.body {
                a_response
                    .headers
                    .set(HeaderName::ContentLength, &body.len().to_string());
            }
        }

        // Build ACK for B-leg
        let b_leg_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut ack_request = proto_sip::message::SipRequest::new(Method::Ack, b_leg_uri);
        ack_request.headers.set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        ack_request.headers.set(HeaderName::CSeq, "1 ACK");
        let _local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
        let branch = generate_branch();
        ack_request.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        ack_request.headers.set(HeaderName::ContentLength, "0");

        info!(
            call_id = %addrs.a_leg_sip_call_id,
            "Call connected: 200 OK → A-leg, ACK → B-leg"
        );

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(a_response),
                destination: addrs.a_leg_source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(ack_request),
                destination: addrs.b_leg_destination,
            },
        ])
    }

    /// Handles 4xx/5xx/6xx error response from B-leg.
    async fn handle_error_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        status_code: u16,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        // Fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.fail(status_code, resp.reason_phrase());
            }
        }

        // Build error response for A-leg
        let mut a_response = proto_sip::message::SipResponse::new(resp.status);
        copy_response_headers(resp, &mut a_response);
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // Cleanup call state
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(internal_id);
        }

        warn!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Call failed, forwarding error to A-leg"
        );

        ProcessResult::Response {
            message: SipMessage::Response(a_response),
            destination: addrs.a_leg_source,
        }
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
    ///
    /// B2BUA call flow:
    /// 1. Send 100 Trying to A-leg
    /// 2. Look up destination in LocationService (registered users) or resolve directly
    /// 3. Create B2BUA Call with A-leg/B-leg config
    /// 4. Rewrite SDP with SBC's address for media anchoring
    /// 5. Build B-leg INVITE with new headers
    /// 6. Return Multiple(100 Trying + Forward B-leg INVITE)
    async fn handle_invite(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let a_leg_call_id = req
            .headers
            .call_id()
            .unwrap_or("unknown")
            .to_string();

        debug!(uri = %req.uri, call_id = %a_leg_call_id, "Processing INVITE");

        // 1. Build 100 Trying for A-leg
        let trying = create_response_from_request(req, StatusCode::TRYING);

        // 2. Extract destination from Request-URI
        let dest_user = req.uri.user.as_deref().unwrap_or("").to_string();
        let dest_host = req.uri.host.clone();
        let dest_aor = format!("sip:{}@{}", dest_user, dest_host);

        // 3. Look up destination: first check location service, then try direct
        let b_leg_destination = {
            let loc = self.location_service.read().await;
            let bindings = loc.lookup(&dest_aor);
            if let Some(binding) = bindings.first() {
                // Registered user — resolve contact URI to address
                let contact = binding.contact_uri().to_string();
                resolve_sip_uri_to_addr(&contact)
            } else {
                // Not registered — try resolving Request-URI directly
                resolve_sip_uri_to_addr(&req.uri.to_string())
            }
        };

        let b_leg_destination = match b_leg_destination {
            Some(addr) => addr,
            None => {
                warn!(dest = %dest_aor, "Cannot resolve destination");
                let not_found =
                    create_response_from_request(req, StatusCode::NOT_FOUND);
                return ProcessResult::Response {
                    message: SipMessage::Response(not_found),
                    destination: source,
                };
            }
        };

        // 4. Create B2BUA call
        let internal_call_id = CallId::generate();
        let a_leg_from = req
            .headers
            .get_value(&HeaderName::From)
            .map(|f| extract_uri_from_header(&f))
            .unwrap_or_default();

        let call_config = CallConfig::new(
            format!("sip:{}@{}", self.config.instance_name, self.config.domain),
            a_leg_from,
            format!("sip:{}@{}", self.config.instance_name, self.config.domain),
            dest_aor.clone(),
        )
        .with_call_id(internal_call_id.clone());

        let mut call = Call::new(call_config);
        if let Err(e) = call.receive() {
            error!(error = %e, "Failed to transition call to Received");
        }
        if let Err(e) = call.start_routing() {
            error!(error = %e, "Failed to transition call to Routing");
        }

        // 5. Determine SBC's local address for SDP rewriting
        let local_ip = source.ip().to_string(); // Use the address we received on
        let local_sip_addr = format!("{}:{}", local_ip, source.port());

        // 6. Rewrite SDP for B-leg (replace A-leg's address with SBC's)
        let b_leg_sdp = if let Some(ref body) = req.body {
            let sdp_str = String::from_utf8_lossy(body);
            // For now, use a placeholder port — Phase 4 will allocate real RTP ports
            let local_media = MediaAddress::new(&local_ip, 20_000);
            let result = self
                .sdp_rewriter
                .rewrite_offer_for_b_leg(&sdp_str, &local_media);
            Some(result.rewritten)
        } else {
            None
        };

        // 7. Build B-leg INVITE
        let b_leg_sip_call_id = generate_call_id(&self.config.domain);
        let b_leg_branch = generate_branch();

        let mut b_leg_uri = SipUri::new(&dest_host).with_user(&dest_user);
        if let Some(port) = req.uri.port {
            b_leg_uri.port = Some(port);
        }

        let mut builder = RequestBuilder::invite(b_leg_uri)
            .via_auto("UDP", &local_ip, Some(source.port()))
            .from_auto(
                SipUri::new(&self.config.domain).with_user(&self.config.instance_name),
                None,
            )
            .to_uri(
                SipUri::new(&dest_host).with_user(&dest_user),
                None,
            )
            .call_id(&b_leg_sip_call_id)
            .cseq(1)
            .max_forwards(70)
            .contact_uri(
                SipUri::new(&local_ip).with_port(source.port()),
            );

        if let Some(ref sdp) = b_leg_sdp {
            builder = builder.body_sdp(sdp.as_bytes().to_vec());
        }

        let b_leg_request = match builder.build_with_defaults() {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build B-leg INVITE");
                let server_err = create_response_from_request(
                    req,
                    StatusCode::SERVER_INTERNAL_ERROR,
                );
                return ProcessResult::Response {
                    message: SipMessage::Response(server_err),
                    destination: source,
                };
            }
        };

        // 8. Store call state and correlation
        {
            let mut calls = self.calls.write().await;
            calls.calls.insert(internal_call_id.clone(), call);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.insert(a_leg_call_id.clone(), internal_call_id.clone());
            corr.b_leg.insert(b_leg_sip_call_id.clone(), internal_call_id.clone());
            corr.addresses.insert(
                internal_call_id.clone(),
                CallAddresses {
                    a_leg_source: source,
                    b_leg_destination,
                    a_leg_sip_call_id: a_leg_call_id.clone(),
                    b_leg_sip_call_id: b_leg_sip_call_id.clone(),
                    local_addr: local_sip_addr,
                },
            );
        }

        // 9. Create transactions
        {
            let a_branch = req
                .headers
                .get_value(&HeaderName::Via)
                .and_then(|v| extract_param(&v, "branch").map(String::from))
                .unwrap_or_else(generate_branch);

            let mut txns = self.transactions.write().await;
            let server_key = TransactionKey::server(&a_branch, "INVITE");
            txns.server_invite.insert(
                server_key,
                ServerInviteState {
                    transaction: ServerInviteTransaction::new(
                        TransactionKey::server(&a_branch, "INVITE"),
                        TransportType::Unreliable,
                    ),
                    source,
                },
            );

            let client_key = TransactionKey::client(&b_leg_branch, "INVITE");
            txns.client_invite.insert(
                client_key,
                ClientInviteState {
                    transaction: ClientInviteTransaction::new(
                        TransactionKey::client(&b_leg_branch, "INVITE"),
                        TransportType::Unreliable,
                    ),
                    destination: b_leg_destination,
                },
            );
        }

        info!(
            call_id = %a_leg_call_id,
            b_leg_call_id = %b_leg_sip_call_id,
            destination = %b_leg_destination,
            "INVITE routed: A-leg → SBC → B-leg"
        );

        // 10. Return 100 Trying to A-leg + forward INVITE to B-leg
        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(trying),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_leg_request),
                destination: b_leg_destination,
            },
        ])
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
    ///
    /// B2BUA BYE flow:
    /// 1. Look up Call-ID → find internal call (could be A-leg or B-leg)
    /// 2. Send 200 OK to BYE sender
    /// 3. Build BYE for the other leg
    /// 4. Stop media relay and clean up call state
    async fn handle_bye(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let sip_call_id = req
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(call_id = %sip_call_id, "Processing BYE");

        // Look up the call — could be from A-leg or B-leg
        let corr = self.call_correlation.read().await;
        let (internal_id, is_from_a_leg) =
            if let Some(id) = corr.a_leg.get(&sip_call_id) {
                (id.clone(), true)
            } else if let Some(id) = corr.b_leg.get(&sip_call_id) {
                (id.clone(), false)
            } else {
                // Unknown call — just respond 200 OK
                debug!(call_id = %sip_call_id, "BYE for unknown call");
                let response = create_response_from_request(req, StatusCode::OK);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            };

        let addrs = match corr.addresses.get(&internal_id) {
            Some(a) => CallAddresses {
                a_leg_source: a.a_leg_source,
                b_leg_destination: a.b_leg_destination,
                a_leg_sip_call_id: a.a_leg_sip_call_id.clone(),
                b_leg_sip_call_id: a.b_leg_sip_call_id.clone(),
                local_addr: a.local_addr.clone(),
            },
            None => {
                let response = create_response_from_request(req, StatusCode::OK);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            }
        };
        drop(corr);

        // Terminate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(&internal_id) {
                let _ = call.start_termination();
            }
        }

        // Stop media relay
        if let Some(ref pipeline) = self.media_pipeline {
            let call_id_str = internal_id.to_string();
            let _ = pipeline.stop_relay(&call_id_str).await;
            let _ = pipeline.remove_session(&call_id_str).await;
        }

        // Build 200 OK for BYE sender
        let ok_response = create_response_from_request(req, StatusCode::OK);

        // Build BYE for the other leg
        let (other_call_id, other_dest) = if is_from_a_leg {
            (&addrs.b_leg_sip_call_id, addrs.b_leg_destination)
        } else {
            (&addrs.a_leg_sip_call_id, addrs.a_leg_source)
        };

        let other_uri = SipUri::new(other_dest.ip().to_string())
            .with_port(other_dest.port());
        let mut bye_request = proto_sip::message::SipRequest::new(Method::Bye, other_uri);
        bye_request.headers.set(HeaderName::CallId, other_call_id);
        bye_request.headers.set(HeaderName::CSeq, "2 BYE");
        let branch = generate_branch();
        bye_request.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        bye_request.headers.set(HeaderName::ContentLength, "0");

        // Clean up call state
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(&internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(&internal_id);
        }

        info!(
            call_id = %sip_call_id,
            from_a_leg = is_from_a_leg,
            "Call terminated via BYE"
        );

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(ok_response),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(bye_request),
                destination: other_dest,
            },
        ])
    }

    /// Handles CANCEL request.
    ///
    /// B2BUA CANCEL flow:
    /// 1. Match CANCEL to pending A-leg INVITE
    /// 2. Send 200 OK for CANCEL to sender
    /// 3. Send 487 Request Terminated for the original INVITE
    /// 4. Send CANCEL to B-leg (if pending)
    /// 5. Clean up call state
    async fn handle_cancel(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let sip_call_id = req
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(call_id = %sip_call_id, "Processing CANCEL");

        // Look up the call via A-leg Call-ID
        let corr = self.call_correlation.read().await;
        let internal_id = match corr.a_leg.get(&sip_call_id) {
            Some(id) => id.clone(),
            None => {
                // Unknown call — just respond 200 OK for the CANCEL
                let response = create_response_from_request(req, StatusCode::OK);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            }
        };

        let addrs = match corr.addresses.get(&internal_id) {
            Some(a) => CallAddresses {
                a_leg_source: a.a_leg_source,
                b_leg_destination: a.b_leg_destination,
                a_leg_sip_call_id: a.a_leg_sip_call_id.clone(),
                b_leg_sip_call_id: a.b_leg_sip_call_id.clone(),
                local_addr: a.local_addr.clone(),
            },
            None => {
                let response = create_response_from_request(req, StatusCode::OK);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            }
        };
        drop(corr);

        // Fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(&internal_id) {
                let _ = call.fail(487, "Request Terminated");
            }
        }

        // Stop media if started
        if let Some(ref pipeline) = self.media_pipeline {
            let call_id_str = internal_id.to_string();
            let _ = pipeline.stop_relay(&call_id_str).await;
            let _ = pipeline.remove_session(&call_id_str).await;
        }

        // 200 OK for CANCEL
        let cancel_ok = create_response_from_request(req, StatusCode::OK);

        // 487 Request Terminated for the original INVITE
        let mut terminated = proto_sip::message::SipResponse::new(
            StatusCode::new(487).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
        );
        // Copy headers from CANCEL (same Via/From/To/Call-ID as original INVITE)
        if let Some(via) = req.headers.get_value(&HeaderName::Via) {
            terminated.headers.add(Header::new(HeaderName::Via, via));
        }
        if let Some(from) = req.headers.get_value(&HeaderName::From) {
            terminated.headers.set(HeaderName::From, from);
        }
        if let Some(to) = req.headers.get_value(&HeaderName::To) {
            let to_with_tag = if to.contains("tag=") {
                to.to_string()
            } else {
                format!("{};tag={}", to, generate_tag())
            };
            terminated.headers.set(HeaderName::To, to_with_tag);
        }
        terminated.headers.set(HeaderName::CallId, &sip_call_id);
        terminated.headers.set(HeaderName::CSeq, "1 INVITE");
        terminated.headers.set(HeaderName::ContentLength, "0");

        // CANCEL to B-leg
        let b_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut b_cancel = proto_sip::message::SipRequest::new(Method::Cancel, b_uri);
        b_cancel.headers.set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        b_cancel.headers.set(HeaderName::CSeq, "1 CANCEL");
        let branch = generate_branch();
        b_cancel.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        b_cancel.headers.set(HeaderName::ContentLength, "0");

        // Clean up
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(&internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(&internal_id);
        }

        info!(call_id = %sip_call_id, "Call cancelled");

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(cancel_ok),
                destination: source,
            },
            ProcessResult::Response {
                message: SipMessage::Response(terminated),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_cancel),
                destination: addrs.b_leg_destination,
            },
        ])
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

/// Copies common headers from a B-leg response for forwarding to A-leg.
///
/// Copies Via, From, To, CSeq, and Content-Length.
/// Call-ID should be replaced by the caller with the A-leg's Call-ID.
fn copy_response_headers(
    from: &proto_sip::message::SipResponse,
    to: &mut proto_sip::message::SipResponse,
) {
    // Copy Via (will be the A-leg's Via from the original INVITE)
    for via in from.headers.get_all(&HeaderName::Via) {
        to.headers.add(Header::new(HeaderName::Via, &via.value));
    }
    if let Some(from_val) = from.headers.get_value(&HeaderName::From) {
        to.headers.set(HeaderName::From, from_val);
    }
    if let Some(to_val) = from.headers.get_value(&HeaderName::To) {
        to.headers.set(HeaderName::To, to_val);
    }
    if let Some(cseq) = from.headers.cseq() {
        to.headers.set(HeaderName::CSeq, cseq);
    }
    to.headers.set(HeaderName::ContentLength, "0");
}

/// Resolves a SIP URI string to a socket address.
///
/// Parses the host and port from URIs like `sip:user@host:port` or `sip:host`.
/// Defaults to port 5060 if not specified.
fn resolve_sip_uri_to_addr(uri: &str) -> Option<SbcSocketAddr> {
    // Strip sip: or sips: prefix
    let without_scheme = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);

    // Strip user@ if present
    let host_part = if let Some(at_pos) = without_scheme.find('@') {
        &without_scheme[at_pos + 1..]
    } else {
        without_scheme
    };

    // Strip parameters (;transport=udp etc.)
    let host_part = host_part.split(';').next().unwrap_or(host_part);

    // Parse host:port
    let (host, port) = if let Some(colon_pos) = host_part.rfind(':') {
        let port_str = &host_part[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (&host_part[..colon_pos], port)
        } else {
            (host_part, 5060)
        }
    } else {
        (host_part, 5060)
    };

    // Parse IP address
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return Some(SbcSocketAddr::new_v4(ipv4, port));
    }
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return Some(SbcSocketAddr::new_v6(ipv6, port));
    }

    // For hostnames, try DNS resolution (synchronous for now)
    use std::net::ToSocketAddrs;
    let addr_str = format!("{host}:{port}");
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(SbcSocketAddr::from(addr));
        }
    }

    None
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
    async fn test_invite_unresolvable_destination() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // INVITE to unresolvable host → should get 404
        let invite = b"INVITE sip:bob@nonexistent.invalid SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:bob@nonexistent.invalid>\r\n\
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
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status.code(), 404, "Unresolvable destination should return 404");
                }
            }
            _ => panic!("Expected 404 response"),
        }
    }

    #[tokio::test]
    async fn test_invite_to_registered_user() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // First, register bob at 127.0.0.1:5060
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776\r\n\
            From: <sip:bob@sbc.local>;tag=reg1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: reg-bob@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source)
            .await;
        // Verify registration succeeded
        if let ProcessResult::Response { message, .. } = &result {
            if let SipMessage::Response(resp) = message {
                assert_eq!(resp.status, StatusCode::OK, "Registration should succeed");
            }
        }

        // Now INVITE bob — should route via location service
        let invite = b"INVITE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK999\r\n\
            From: <sip:alice@example.com>;tag=inv1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-bob@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@192.168.1.100:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let alice_source = SbcSocketAddr::new_v4(
            std::net::Ipv4Addr::new(192, 168, 1, 100),
            5060,
        );
        let result = stack
            .process_message(&Bytes::from_static(invite), alice_source)
            .await;

        // Should get Multiple(100 Trying + Forward INVITE)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 2, "Should have 2 results: Trying + Forward");

                // First: 100 Trying to A-leg
                if let ProcessResult::Response { message, destination } = &results[0] {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status, StatusCode::TRYING);
                    }
                    assert_eq!(*destination, alice_source);
                } else {
                    panic!("First result should be Response (100 Trying)");
                }

                // Second: Forward INVITE to B-leg (bob at 127.0.0.1:5060)
                if let ProcessResult::Forward { message, destination } = &results[1] {
                    assert!(message.is_request(), "Forward should be a request");
                    assert_eq!(
                        destination.ip(),
                        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
                        "B-leg should go to bob's registered address"
                    );
                } else {
                    panic!("Second result should be Forward (B-leg INVITE)");
                }

                // Verify call state was created
                assert_eq!(stack.call_count().await, 1);
            }
            other => panic!("Expected Multiple, got: {other:?}"),
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
