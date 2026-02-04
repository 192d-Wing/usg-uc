//! Call manager for coordinating call lifecycle.
//!
//! Provides high-level call management including:
//! - Making and receiving calls
//! - Call state tracking
//! - Media session coordination
//! - Call history integration

use crate::audio_session::{AudioSession, AudioSessionConfig, AudioSessionEvent};
use crate::contact_manager::ContactManager;
use crate::{AppError, AppResult};
use chrono::Utc;
use client_audio::PipelineStats;
use client_sip_ua::{CallAgent, CallEvent, MediaSession, MediaSessionEvent, MediaSessionState};
use client_types::audio::CodecPreference;
use client_types::{
    CallDirection, CallEndReason, CallHistoryEntry, CallInfo, CallState, DtmfDigit, SipAccount,
};
use proto_ice::IceConfig;
use proto_sip::header::HeaderName;
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::response::StatusCode;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

/// Information about an incoming call that hasn't been answered yet.
#[derive(Debug, Clone)]
pub struct IncomingCallInfo {
    /// Internal call ID.
    pub call_id: String,
    /// SIP Call-ID header value.
    pub sip_call_id: String,
    /// Remote party SIP URI.
    pub remote_uri: String,
    /// Remote party display name.
    pub remote_display_name: Option<String>,
    /// Source address of the INVITE.
    pub source_addr: SocketAddr,
    /// The original INVITE request (for building responses).
    pub invite_request: SipRequest,
    /// Our local tag for the dialog.
    pub local_tag: String,
}

/// Call manager coordinates calls between SIP UA and media sessions.
pub struct CallManager {
    /// SIP call agent.
    call_agent: CallAgent,
    /// Call agent event receiver.
    call_event_rx: mpsc::Receiver<CallEvent>,
    /// Active media sessions by call ID.
    media_sessions: HashMap<String, MediaSession>,
    /// Active audio sessions by call ID.
    audio_sessions: HashMap<String, AudioSession>,
    /// Incoming calls awaiting answer/reject.
    incoming_calls: HashMap<String, IncomingCallInfo>,
    /// Local address for media.
    local_media_addr: SocketAddr,
    /// ICE configuration.
    ice_config: IceConfig,
    /// DTLS certificate chain (from smart card or file).
    dtls_cert_chain: Vec<Vec<u8>>,
    /// DTLS private key.
    dtls_private_key: Vec<u8>,
    /// Event sender for application events.
    app_event_tx: mpsc::Sender<CallManagerEvent>,
    /// Audio event sender.
    audio_event_tx: mpsc::Sender<AudioSessionEvent>,
    /// Contact manager for call history (optional).
    contact_manager: Option<Arc<RwLock<ContactManager>>>,
    /// Current SIP account.
    account: Option<SipAccount>,
    /// Preferred codec for calls.
    preferred_codec: CodecPreference,
    /// Currently focused call ID (the one with active audio).
    focused_call_id: Option<String>,
    /// All active call IDs (including held calls).
    active_calls: Vec<String>,
    /// Maximum concurrent calls allowed (call waiting limit).
    max_concurrent_calls: usize,
    /// Whether muted.
    is_muted: bool,
    /// Music on Hold file path (optional).
    moh_file_path: Option<String>,
    /// Negotiated codec per call (from SDP answer).
    negotiated_codecs: HashMap<String, CodecPreference>,
}

/// Events emitted by the call manager.
#[derive(Debug, Clone)]
pub enum CallManagerEvent {
    /// Call state changed.
    CallStateChanged {
        /// Call ID.
        call_id: String,
        /// New state.
        state: CallState,
        /// Call info.
        info: CallInfo,
    },
    /// Incoming call (ring!).
    IncomingCall {
        /// Call ID.
        call_id: String,
        /// Remote party URI.
        remote_uri: String,
        /// Remote party display name.
        remote_display_name: Option<String>,
    },
    /// Call connected, media ready.
    CallConnected {
        /// Call ID.
        call_id: String,
        /// Local media address.
        local_addr: SocketAddr,
        /// Remote media address.
        remote_addr: SocketAddr,
    },
    /// Call ended.
    CallEnded {
        /// Call ID.
        call_id: String,
        /// End reason.
        reason: CallEndReason,
        /// Call duration in seconds (if connected).
        duration_secs: Option<u64>,
    },
    /// Media session state changed.
    MediaStateChanged {
        /// Call ID.
        call_id: String,
        /// New media state.
        state: MediaSessionState,
    },
    /// Error occurred.
    Error {
        /// Call ID (if applicable).
        call_id: Option<String>,
        /// Error message.
        message: String,
    },
    /// Response needs to be sent (for incoming calls).
    SendResponse {
        /// The SIP response to send.
        response: SipResponse,
        /// Destination address.
        destination: SocketAddr,
    },
}

impl CallManager {
    /// Creates a new call manager.
    ///
    /// # Arguments
    /// * `local_sip_addr` - Local address for SIP signaling
    /// * `local_media_addr` - Local address for RTP media
    /// * `app_event_tx` - Channel for application events
    pub fn new(
        local_sip_addr: SocketAddr,
        local_media_addr: SocketAddr,
        app_event_tx: mpsc::Sender<CallManagerEvent>,
    ) -> Self {
        // Create internal channel for call agent events
        let (call_event_tx, call_event_rx) = mpsc::channel(64);

        // Create internal channel for audio session events
        let (audio_event_tx, _audio_event_rx) = mpsc::channel(64);

        let call_agent = CallAgent::new(
            local_sip_addr,
            String::new(), // Will be set when account is configured
            String::new(),
            call_event_tx,
        );

        Self {
            call_agent,
            call_event_rx,
            media_sessions: HashMap::new(),
            audio_sessions: HashMap::new(),
            incoming_calls: HashMap::new(),
            local_media_addr,
            ice_config: IceConfig::default(),
            dtls_cert_chain: Vec::new(),
            dtls_private_key: Vec::new(),
            app_event_tx,
            audio_event_tx,
            contact_manager: None,
            account: None,
            preferred_codec: CodecPreference::G711Ulaw,
            focused_call_id: None,
            active_calls: Vec::new(),
            max_concurrent_calls: 2, // Support call waiting with 2 calls
            is_muted: false,
            moh_file_path: None,
            negotiated_codecs: HashMap::new(),
        }
    }

    /// Configures the call manager with a SIP account.
    pub fn configure_account(&mut self, account: &SipAccount) {
        self.account = Some(account.clone());
        info!(account_id = %account.id, "Call manager configured with account");
    }

    /// Sets the ICE configuration.
    pub fn set_ice_config(&mut self, config: IceConfig) {
        self.ice_config = config;
    }

    /// Sets the DTLS credentials.
    pub fn set_dtls_credentials(&mut self, cert_chain: Vec<Vec<u8>>, private_key: Vec<u8>) {
        self.dtls_cert_chain = cert_chain;
        self.dtls_private_key = private_key;
        info!("DTLS credentials configured");
    }

    /// Sets the preferred codec for calls.
    pub fn set_preferred_codec(&mut self, codec: CodecPreference) {
        self.preferred_codec = codec;
        info!(codec = ?codec, "Preferred codec set");
    }

    /// Sets the Music on Hold file path.
    ///
    /// The file should be a WAV file that will be played to the remote party
    /// when a call is placed on hold.
    pub fn set_moh_file_path(&mut self, path: Option<String>) {
        self.moh_file_path = path.clone();
        if let Some(ref p) = path {
            info!(path = %p, "MOH file path set");
        } else {
            info!("MOH file path cleared");
        }
    }

    /// Returns the currently configured MOH file path.
    pub fn moh_file_path(&self) -> Option<&str> {
        self.moh_file_path.as_deref()
    }

    /// Returns the preferred codec.
    pub fn preferred_codec(&self) -> CodecPreference {
        self.preferred_codec
    }

    /// Sets the contact manager for call history.
    pub fn set_contact_manager(&mut self, manager: Arc<RwLock<ContactManager>>) {
        self.contact_manager = Some(manager);
    }

    /// Makes an outbound call.
    ///
    /// # Arguments
    /// * `remote_uri` - SIP URI to call (e.g., "sips:bob@example.com")
    ///
    /// # Returns
    /// Call ID on success.
    pub async fn make_call(&mut self, remote_uri: &str) -> AppResult<String> {
        // Check concurrent call limit
        if self.active_calls.len() >= self.max_concurrent_calls {
            return Err(AppError::Sip(format!(
                "Maximum concurrent calls ({}) reached",
                self.max_concurrent_calls
            )));
        }

        // If there's a focused call that's connected, put it on hold first (call waiting)
        if let Some(ref focused_id) = self.focused_call_id.clone() {
            let state = self.call_agent.get_state(&focused_id);
            if state == Some(CallState::Connected) {
                info!(call_id = %focused_id, "Auto-holding current call for new outbound call");
                self.hold_call_by_id(&focused_id).await?;
            }
        }

        // Verify we have an account configured
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        info!(remote_uri = %remote_uri, "Making outbound call");

        // Create media session channel
        let (media_tx, _media_rx) = mpsc::channel(32);

        // Create media session for this call
        let media_session = MediaSession::new(
            self.local_media_addr,
            true, // outbound = controlling
            self.ice_config.clone(),
            self.dtls_cert_chain.clone(),
            self.dtls_private_key.clone(),
            media_tx,
        );

        // Generate SDP offer from media session
        let sdp_offer = self.generate_sdp_offer(&media_session, account)?;

        // Make the call via SIP UA
        let call_id = self
            .call_agent
            .make_call(remote_uri, &sdp_offer)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Store media session and track the call
        self.media_sessions.insert(call_id.clone(), media_session);
        self.active_calls.push(call_id.clone());
        self.focused_call_id = Some(call_id.clone());

        // Notify application
        let info = CallInfo {
            id: call_id.clone(),
            state: CallState::Dialing,
            direction: CallDirection::Outbound,
            remote_uri: remote_uri.to_string(),
            remote_display_name: None,
            start_time: Utc::now(),
            connect_time: None,
            is_muted: false,
            is_on_hold: false,
            failure_reason: None,
        };

        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.clone(),
                state: CallState::Dialing,
                info,
            })
            .await;

        Ok(call_id)
    }

    /// Hangs up the currently focused call.
    pub async fn hangup(&mut self) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        self.hangup_call(&call_id).await
    }

    /// Hangs up a specific call.
    pub async fn hangup_call(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Hanging up call");

        // Get call info before hangup
        let call_info = self.call_agent.get_call_info(call_id);

        // Send hangup via SIP UA
        self.call_agent
            .hangup(call_id)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Close media session
        if let Some(mut session) = self.media_sessions.remove(call_id) {
            let _ = session.close().await;
        }

        // Clean up negotiated codec
        self.negotiated_codecs.remove(call_id);

        // Record in call history
        if let Some(info) = call_info {
            self.record_call_history(&info, CallEndReason::LocalHangup)
                .await;
        }

        // Remove from active calls list
        self.active_calls.retain(|id| id != call_id);

        // Clear focused call if it was the one we hung up
        if self.focused_call_id.as_ref() == Some(&call_id.to_string()) {
            // If there are other calls, focus the first one
            self.focused_call_id = self.active_calls.first().cloned();
        }

        // Notify application
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallEnded {
                call_id: call_id.to_string(),
                reason: CallEndReason::LocalHangup,
                duration_secs: None,
            })
            .await;

        Ok(())
    }

    /// Handles a call event from the SIP UA.
    pub async fn handle_call_event(&mut self, event: CallEvent) -> AppResult<()> {
        match event {
            CallEvent::StateChanged {
                call_id,
                state,
                info,
            } => {
                self.handle_state_changed(&call_id, state, info).await?;
            }
            CallEvent::SdpAnswerReceived { call_id, sdp } => {
                self.handle_sdp_answer(&call_id, &sdp).await?;
            }
            CallEvent::SendRequest { .. } => {
                // Transport layer handles this via poll_call_events()
            }
            CallEvent::SendResponse { .. } => {
                // Transport layer handles this via poll_call_events()
            }
            CallEvent::SdpOfferReceived { call_id, sdp } => {
                self.handle_sdp_offer(&call_id, &sdp).await?;
            }
        }

        Ok(())
    }

    /// Polls for pending call events.
    ///
    /// Returns events that need to be processed. `SendRequest` and `SendResponse`
    /// events should be forwarded to the SIP transport layer.
    pub fn poll_call_events(&mut self) -> Vec<CallEvent> {
        std::iter::from_fn(|| self.call_event_rx.try_recv().ok()).collect()
    }

    /// Routes an incoming SIP response to the appropriate call.
    ///
    /// This should be called when the transport layer receives a SIP response
    /// for a call (INVITE 1xx/2xx/3xx-6xx, BYE 200, CANCEL 200, etc.).
    pub async fn handle_sip_response(&mut self, response: &SipResponse) -> AppResult<()> {
        // Extract Call-ID from response to find the matching call
        let sip_call_id = match response.headers.get_value(&HeaderName::CallId) {
            Some(id) => id.to_string(),
            None => {
                warn!("Received response without Call-ID header");
                return Ok(());
            }
        };

        // Find the call session with this SIP Call-ID
        if let Some(call_id) = self.find_call_by_sip_id(&sip_call_id) {
            debug!(
                call_id = %call_id,
                sip_call_id = %sip_call_id,
                status = response.status.code(),
                "Routing response to call agent"
            );
            self.call_agent
                .handle_response(response, &call_id)
                .await
                .map_err(|e| AppError::Sip(e.to_string()))?;
        } else {
            debug!(sip_call_id = %sip_call_id, "No matching call found for response");
        }

        Ok(())
    }

    /// Routes an incoming SIP request (e.g., INVITE) to the call manager.
    ///
    /// This handles incoming calls and in-dialog requests.
    pub async fn handle_sip_request(&mut self, request: &SipRequest) -> AppResult<()> {
        let method = request.method.as_str();
        debug!(method = %method, "Received incoming SIP request");

        match method {
            "INVITE" => {
                // Incoming call
                self.handle_incoming_invite(request).await?;
            }
            "BYE" => {
                // Remote party hanging up
                self.handle_incoming_bye(request).await?;
            }
            "CANCEL" => {
                // Remote party cancelling
                self.handle_incoming_cancel(request).await?;
            }
            "ACK" => {
                // Acknowledgement (normally handled by transaction layer)
                debug!("Received ACK");
            }
            _ => {
                debug!(method = %method, "Ignoring unsupported request method");
            }
        }

        Ok(())
    }

    /// Finds a call by its SIP Call-ID.
    fn find_call_by_sip_id(&self, sip_call_id: &str) -> Option<String> {
        self.call_agent.find_call_by_sip_id(sip_call_id)
    }

    /// Handles an incoming INVITE request.
    ///
    /// This method requires the source address of the INVITE to be known
    /// for sending responses. Use `handle_incoming_invite_from` instead.
    async fn handle_incoming_invite(&mut self, request: &SipRequest) -> AppResult<()> {
        // Default to localhost if source not known (shouldn't happen in real usage)
        let default_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap_or_else(|_| {
            // Fallback that won't panic
            SocketAddr::from(([127, 0, 0, 1], 5060))
        });
        self.handle_incoming_invite_from(request, default_addr)
            .await
    }

    /// Handles an incoming INVITE request from a known source.
    ///
    /// This is the preferred method as it includes the source address
    /// needed for sending responses.
    pub async fn handle_incoming_invite_from(
        &mut self,
        request: &SipRequest,
        source: SocketAddr,
    ) -> AppResult<()> {
        use crate::sip_transport::{build_response_from_request, generate_tag};

        info!(source = %source, "Received incoming INVITE");

        // Check if we've reached the concurrent call limit
        if self.active_calls.len() >= self.max_concurrent_calls {
            info!(
                current = self.active_calls.len(),
                max = self.max_concurrent_calls,
                "At max concurrent calls, rejecting incoming with 486 Busy Here"
            );
            // Send 486 Busy Here
            let response = build_response_from_request(request, StatusCode::BUSY_HERE, None);
            let _ = self
                .app_event_tx
                .send(CallManagerEvent::SendResponse {
                    response,
                    destination: source,
                })
                .await;
            return Ok(());
        }

        // If we have an active call, this is a call waiting scenario
        if !self.active_calls.is_empty() {
            info!(
                existing_calls = self.active_calls.len(),
                "Incoming call during active call (call waiting)"
            );
        }

        // Extract caller info from From header
        let from_value = request
            .headers
            .get_value(&HeaderName::From)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Parse display name and URI from From header
        let (remote_display_name, remote_uri) = parse_from_header(&from_value);

        // Extract SIP Call-ID
        let sip_call_id = request
            .headers
            .get_value(&HeaderName::CallId)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("unknown-{}", generate_tag()));

        // Generate a unique internal call ID
        let call_id = format!("incoming-{}", generate_tag());

        // Generate our local tag for the dialog
        let local_tag = generate_tag();

        // Store the incoming call info
        let incoming_info = IncomingCallInfo {
            call_id: call_id.clone(),
            sip_call_id: sip_call_id.clone(),
            remote_uri: remote_uri.clone(),
            remote_display_name: remote_display_name.clone(),
            source_addr: source,
            invite_request: request.clone(),
            local_tag: local_tag.clone(),
        };
        self.incoming_calls.insert(call_id.clone(), incoming_info);

        // Send 100 Trying immediately (per RFC 3261 §8.2.6)
        let trying_response = build_response_from_request(request, StatusCode::TRYING, None);
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: trying_response,
                destination: source,
            })
            .await;

        // Send 180 Ringing
        let ringing_response =
            build_response_from_request(request, StatusCode::RINGING, Some(&local_tag));
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ringing_response,
                destination: source,
            })
            .await;

        // Notify the application about the incoming call
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::IncomingCall {
                call_id,
                remote_uri,
                remote_display_name,
            })
            .await;

        Ok(())
    }

    /// Accepts an incoming call.
    ///
    /// Sends a 200 OK response with SDP answer and transitions to Connected state.
    pub async fn accept_incoming_call(&mut self, call_id: &str) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        let incoming = self
            .incoming_calls
            .remove(call_id)
            .ok_or_else(|| AppError::Sip(format!("No incoming call with ID: {call_id}")))?;

        info!(call_id = %call_id, remote = %incoming.remote_uri, "Accepting incoming call");

        // Verify we have an account configured
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?
            .clone();

        // Create media session for this call
        let (media_tx, _media_rx) = mpsc::channel(32);
        let media_session = MediaSession::new(
            self.local_media_addr,
            false, // incoming = controlled
            self.ice_config.clone(),
            self.dtls_cert_chain.clone(),
            self.dtls_private_key.clone(),
            media_tx,
        );

        // Generate SDP answer
        let sdp_answer = self.generate_sdp_offer(&media_session, &account)?;

        // Build 200 OK with SDP body
        let mut ok_response = build_response_from_request(
            &incoming.invite_request,
            StatusCode::OK,
            Some(&incoming.local_tag),
        );

        // Add Contact header - extract user from SIP URI
        let username =
            extract_username_from_sip_uri(&account.sip_uri).unwrap_or_else(|| account.id.clone());
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::Contact,
            format!("<sip:{username}@{}>", self.local_media_addr.ip()),
        ));

        // Add Content-Type and body
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::ContentType,
            "application/sdp",
        ));

        // Update Content-Length
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::ContentLength,
            sdp_answer.len().to_string(),
        ));

        ok_response = ok_response.with_body(sdp_answer);

        // Send 200 OK
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ok_response,
                destination: incoming.source_addr,
            })
            .await;

        // If there's an existing focused call, put it on hold first
        if let Some(ref focused_id) = self.focused_call_id.clone() {
            let state = self.call_agent.get_state(&focused_id);
            if state == Some(CallState::Connected) {
                info!(call_id = %focused_id, "Auto-holding current call for incoming call");
                self.hold_call_by_id(&focused_id).await?;
            }
        }

        // Store media session and track the call
        self.media_sessions
            .insert(call_id.to_string(), media_session);
        self.active_calls.push(call_id.to_string());
        self.focused_call_id = Some(call_id.to_string());

        // Notify application of state change
        let info = CallInfo {
            id: call_id.to_string(),
            state: CallState::Connected,
            direction: CallDirection::Inbound,
            remote_uri: incoming.remote_uri,
            remote_display_name: incoming.remote_display_name,
            start_time: Utc::now(),
            connect_time: Some(Utc::now()),
            is_muted: false,
            is_on_hold: false,
            failure_reason: None,
        };

        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.to_string(),
                state: CallState::Connected,
                info,
            })
            .await;

        Ok(())
    }

    /// Rejects an incoming call.
    ///
    /// Sends a 486 Busy Here (or 603 Decline) response.
    pub async fn reject_incoming_call(&mut self, call_id: &str, decline: bool) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        let incoming = self
            .incoming_calls
            .remove(call_id)
            .ok_or_else(|| AppError::Sip(format!("No incoming call with ID: {call_id}")))?;

        let status = if decline {
            StatusCode::DECLINE
        } else {
            StatusCode::BUSY_HERE
        };

        info!(
            call_id = %call_id,
            remote = %incoming.remote_uri,
            status = status.code(),
            "Rejecting incoming call"
        );

        // Build rejection response
        let response = build_response_from_request(
            &incoming.invite_request,
            status,
            Some(&incoming.local_tag),
        );

        // Send the rejection
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response,
                destination: incoming.source_addr,
            })
            .await;

        // Notify application
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallEnded {
                call_id: call_id.to_string(),
                reason: CallEndReason::LocalReject,
                duration_secs: None,
            })
            .await;

        Ok(())
    }

    /// Returns information about pending incoming calls.
    pub fn incoming_calls(&self) -> Vec<&IncomingCallInfo> {
        self.incoming_calls.values().collect()
    }

    /// Checks if there's a pending incoming call.
    pub fn has_incoming_call(&self) -> bool {
        !self.incoming_calls.is_empty()
    }

    /// Handles an incoming BYE request.
    async fn handle_incoming_bye(&mut self, request: &SipRequest) -> AppResult<()> {
        let sip_call_id = match request.headers.get_value(&HeaderName::CallId) {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };

        if let Some(call_id) = self.find_call_by_sip_id(&sip_call_id) {
            info!(call_id = %call_id, "Remote party sent BYE");
            // Mark the call as terminated - the remote party hung up
            self.handle_state_changed(&call_id, CallState::Terminated, None)
                .await?;
        }

        Ok(())
    }

    /// Handles an incoming CANCEL request.
    async fn handle_incoming_cancel(&mut self, request: &SipRequest) -> AppResult<()> {
        let sip_call_id = match request.headers.get_value(&HeaderName::CallId) {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };

        if let Some(call_id) = self.find_call_by_sip_id(&sip_call_id) {
            info!(call_id = %call_id, "Remote party sent CANCEL");
            // Mark the call as terminated - the remote party cancelled
            self.handle_state_changed(&call_id, CallState::Terminated, None)
                .await?;
        }

        Ok(())
    }

    /// Handles a media session event.
    pub async fn handle_media_event(
        &mut self,
        call_id: &str,
        event: MediaSessionEvent,
    ) -> AppResult<()> {
        match event {
            MediaSessionEvent::StateChanged { state } => {
                debug!(call_id = %call_id, state = ?state, "Media session state changed");

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::MediaStateChanged {
                        call_id: call_id.to_string(),
                        state,
                    })
                    .await;
            }
            MediaSessionEvent::Ready {
                local_addr,
                remote_addr,
            } => {
                info!(
                    call_id = %call_id,
                    local = %local_addr,
                    remote = %remote_addr,
                    "Media session ready"
                );

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::CallConnected {
                        call_id: call_id.to_string(),
                        local_addr,
                        remote_addr,
                    })
                    .await;
            }
            MediaSessionEvent::Failed { reason } => {
                error!(call_id = %call_id, reason = %reason, "Media session failed");

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::Error {
                        call_id: Some(call_id.to_string()),
                        message: reason,
                    })
                    .await;
            }
            MediaSessionEvent::LocalCandidate { .. }
            | MediaSessionEvent::LocalCredentials { .. }
            | MediaSessionEvent::LocalFingerprint { .. } => {
                // These are handled during SDP generation
            }
        }

        Ok(())
    }

    /// Toggles mute state.
    pub fn toggle_mute(&mut self) -> bool {
        self.is_muted = !self.is_muted;

        // Update audio session mute state for focused call
        if let Some(call_id) = &self.focused_call_id {
            if let Some(session) = self.audio_sessions.get(call_id) {
                session.set_muted(self.is_muted);
            }
        }

        info!(muted = self.is_muted, "Mute toggled");
        self.is_muted
    }

    /// Returns whether currently muted.
    pub fn is_muted(&self) -> bool {
        self.is_muted
    }

    /// Sends a DTMF digit on the focused call.
    ///
    /// Uses RFC 4733 telephone-event for out-of-band DTMF signaling.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send (0-9, *, #, A-D)
    /// * `duration_ms` - Duration of the tone in milliseconds (typical: 100ms)
    pub async fn send_dtmf(&self, digit: DtmfDigit, duration_ms: u32) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?;

        let session = self
            .audio_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Audio("No audio session for call".to_string()))?;

        info!(digit = %digit, duration_ms = duration_ms, "Sending DTMF");
        session.send_dtmf(digit, duration_ms).await
    }

    /// Transfers the focused call to another party (blind transfer).
    ///
    /// Sends a REFER request per RFC 3515 to transfer the call to the
    /// specified target URI. The remote party will initiate a new call
    /// to the transfer target.
    ///
    /// # Arguments
    /// * `transfer_target` - SIP URI of the transfer destination (e.g., "sips:bob@example.com")
    ///
    /// # Returns
    /// Ok(()) if the REFER was sent successfully. The actual transfer result
    /// will be reported asynchronously via call state changes.
    pub async fn transfer_call(&mut self, transfer_target: &str) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        self.transfer_call_by_id(&call_id, transfer_target).await
    }

    /// Transfers a specific call to another party (blind transfer).
    ///
    /// # Arguments
    /// * `call_id` - The call to transfer
    /// * `transfer_target` - SIP URI of the transfer destination
    pub async fn transfer_call_by_id(
        &mut self,
        call_id: &str,
        transfer_target: &str,
    ) -> AppResult<()> {
        info!(
            call_id = %call_id,
            transfer_target = %transfer_target,
            "Initiating call transfer"
        );

        // Send REFER via call agent
        self.call_agent
            .transfer_call(call_id, transfer_target)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        Ok(())
    }

    /// Switches the input (microphone) device for the active call.
    ///
    /// This allows changing the microphone mid-call without disconnecting.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new input device, or None for default
    pub async fn switch_input_device(&self, device_name: Option<String>) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?;

        let session = self
            .audio_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Audio("No audio session for call".to_string()))?;

        info!(device = ?device_name, "Switching input device");
        session.switch_input_device(device_name).await
    }

    /// Switches the output (speaker) device for the active call.
    ///
    /// This allows changing the speaker mid-call without disconnecting.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new output device, or None for default
    pub async fn switch_output_device(&self, device_name: Option<String>) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?;

        let session = self
            .audio_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Audio("No audio session for call".to_string()))?;

        info!(device = ?device_name, "Switching output device");
        session.switch_output_device(device_name).await
    }

    /// Returns the current input device name for the active call.
    pub async fn current_input_device(&self) -> Option<String> {
        let call_id = self.focused_call_id.as_ref()?;
        let session = self.audio_sessions.get(call_id)?;
        session.input_device_name().await
    }

    /// Returns the current output device name for the active call.
    pub async fn current_output_device(&self) -> Option<String> {
        let call_id = self.focused_call_id.as_ref()?;
        let session = self.audio_sessions.get(call_id)?;
        session.output_device_name().await
    }

    /// Puts the focused call on hold.
    ///
    /// Sends a re-INVITE with `a=sendonly` direction to put media on hold.
    pub async fn hold_call(&mut self) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        self.hold_call_by_id(&call_id).await
    }

    /// Puts a specific call on hold by ID.
    pub async fn hold_call_by_id(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Putting call on hold");

        // Generate hold SDP with sendonly direction
        let hold_sdp = self.generate_hold_sdp(call_id)?;

        // Send re-INVITE via call agent
        self.call_agent
            .hold_call(call_id, &hold_sdp)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Activate MOH for this call's audio session
        if let Some(audio_session) = self.audio_sessions.get(call_id) {
            // Enable MOH (will send MOH audio instead of microphone)
            audio_session.set_moh_active(true).await;
            debug!(call_id = %call_id, "MOH activated for held call");
        }

        Ok(())
    }

    /// Resumes the focused held call.
    ///
    /// Sends a re-INVITE with `a=sendrecv` direction to restore bidirectional media.
    pub async fn resume_call(&mut self) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        self.resume_call_by_id(&call_id).await
    }

    /// Resumes a specific held call by ID.
    pub async fn resume_call_by_id(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Resuming call");

        // Generate resume SDP with sendrecv direction
        let resume_sdp = self.generate_resume_sdp(call_id)?;

        // Send re-INVITE via call agent
        self.call_agent
            .resume_call(call_id, &resume_sdp)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Resume audio session and deactivate MOH
        if let Some(audio_session) = self.audio_sessions.get(call_id) {
            // Deactivate MOH (return to normal microphone capture)
            audio_session.set_moh_active(false).await;
            audio_session.set_muted(self.is_muted);
            debug!(call_id = %call_id, "MOH deactivated for resumed call");
        }

        Ok(())
    }

    /// Toggles hold state for the focused call.
    ///
    /// If the call is connected, puts it on hold.
    /// If the call is on hold, resumes it.
    pub async fn toggle_hold(&mut self) -> AppResult<bool> {
        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        let state = self
            .call_agent
            .get_state(&call_id)
            .ok_or_else(|| AppError::Sip("Call not found".to_string()))?;

        match state {
            CallState::Connected => {
                self.hold_call().await?;
                Ok(true) // Now on hold
            }
            CallState::OnHold => {
                self.resume_call().await?;
                Ok(false) // No longer on hold
            }
            _ => Err(AppError::Sip(format!(
                "Cannot toggle hold in state {:?}",
                state
            ))),
        }
    }

    /// Returns the focused call ID.
    pub fn active_call_id(&self) -> Option<&str> {
        self.focused_call_id.as_deref()
    }

    /// Returns info for the focused call.
    pub fn active_call_info(&self) -> Option<CallInfo> {
        self.focused_call_id
            .as_ref()
            .and_then(|id| self.call_agent.get_call_info(id))
    }

    /// Returns all active call IDs (including held calls).
    pub fn all_call_ids(&self) -> &[String] {
        &self.active_calls
    }

    /// Returns info for all active calls.
    pub fn all_call_info(&self) -> Vec<CallInfo> {
        self.active_calls
            .iter()
            .filter_map(|id| self.call_agent.get_call_info(id))
            .collect()
    }

    /// Returns the state of a specific call.
    pub fn get_call_state(&self, call_id: &str) -> Option<CallState> {
        self.call_agent.get_state(call_id)
    }

    /// Returns info for a specific call.
    pub fn get_call_info(&self, call_id: &str) -> Option<CallInfo> {
        self.call_agent.get_call_info(call_id)
    }

    /// Returns the media session for a call.
    pub fn get_media_session(&self, call_id: &str) -> Option<&MediaSession> {
        self.media_sessions.get(call_id)
    }

    /// Returns mutable reference to media session for a call.
    pub fn get_media_session_mut(&mut self, call_id: &str) -> Option<&mut MediaSession> {
        self.media_sessions.get_mut(call_id)
    }

    /// Returns the audio session for a call.
    pub fn get_audio_session(&self, call_id: &str) -> Option<&AudioSession> {
        self.audio_sessions.get(call_id)
    }

    /// Returns audio pipeline statistics for the focused call.
    pub async fn audio_stats(&self) -> Option<PipelineStats> {
        if let Some(call_id) = &self.focused_call_id {
            if let Some(session) = self.audio_sessions.get(call_id) {
                return Some(session.stats().await);
            }
        }
        None
    }

    /// Switches focus to a different call.
    ///
    /// If there's a currently focused call that's connected, it will be put on hold.
    /// The target call will be resumed if it's on hold.
    pub async fn switch_to_call(&mut self, call_id: &str) -> AppResult<()> {
        // Verify target call exists
        if !self.active_calls.contains(&call_id.to_string()) {
            return Err(AppError::Sip(format!("Call not found: {}", call_id)));
        }

        // Put current focused call on hold if it's connected
        if let Some(ref current) = self.focused_call_id.clone() {
            if current != call_id {
                let state = self.call_agent.get_state(&current);
                if state == Some(CallState::Connected) {
                    self.hold_call_by_id(&current).await?;
                }
            }
        }

        // Resume target call if it's on hold
        let state = self.call_agent.get_state(call_id);
        if state == Some(CallState::OnHold) {
            self.resume_call_by_id(call_id).await?;
        }

        self.focused_call_id = Some(call_id.to_string());
        info!(call_id = %call_id, "Switched focus to call");
        Ok(())
    }

    /// Starts the audio session for a connected call.
    async fn start_audio_session(
        &mut self,
        call_id: &str,
        remote_addr: SocketAddr,
    ) -> AppResult<()> {
        info!(call_id = %call_id, remote = %remote_addr, "Starting audio session");

        // Create audio session
        let mut audio_session = AudioSession::new(self.audio_event_tx.clone());

        // Use the negotiated codec from SDP answer if available, otherwise fall back to preferred
        let codec = self
            .negotiated_codecs
            .get(call_id)
            .copied()
            .unwrap_or(self.preferred_codec);

        info!(call_id = %call_id, codec = ?codec, "Using codec for audio session");

        // Configure audio
        let config = AudioSessionConfig {
            local_port: 0,
            remote_addr,
            codec,
            jitter_buffer_ms: 60,
            // SRTP keys will be obtained from media session in production
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: self.moh_file_path.clone(),
        };

        // Start the audio session
        match audio_session.start(config).await {
            Ok(port) => {
                info!(call_id = %call_id, port = port, "Audio session started");
                self.audio_sessions
                    .insert(call_id.to_string(), audio_session);
                Ok(())
            }
            Err(e) => {
                error!(call_id = %call_id, error = %e, "Failed to start audio session");
                Err(e)
            }
        }
    }

    /// Stops the audio session for a call.
    async fn stop_audio_session(&mut self, call_id: &str) -> AppResult<()> {
        if let Some(mut session) = self.audio_sessions.remove(call_id) {
            info!(call_id = %call_id, "Stopping audio session");
            session.stop().await?;
        }
        Ok(())
    }

    // --- Private methods ---

    async fn handle_state_changed(
        &mut self,
        call_id: &str,
        state: CallState,
        info: Option<CallInfo>,
    ) -> AppResult<()> {
        debug!(call_id = %call_id, state = ?state, "Call state changed");

        let call_info = info.unwrap_or_else(|| {
            self.call_agent
                .get_call_info(call_id)
                .unwrap_or_else(|| CallInfo {
                    id: call_id.to_string(),
                    state,
                    direction: CallDirection::Outbound,
                    remote_uri: String::new(),
                    remote_display_name: None,
                    start_time: Utc::now(),
                    connect_time: None,
                    is_muted: self.is_muted,
                    is_on_hold: false,
                    failure_reason: None,
                })
        });

        match state {
            CallState::Connected => {
                // Start media session establishment (ICE + DTLS)
                if let Some(session) = self.media_sessions.get_mut(call_id) {
                    if let Err(e) = session.establish(None).await {
                        warn!(call_id = %call_id, error = %e, "Failed to establish media");
                    }
                }

                // Start audio session when call connects
                // Get remote address from media session after ICE completes
                let remote_addr = self.media_sessions.get(call_id).and_then(|session| {
                    if session.is_ready() {
                        session.remote_addr()
                    } else {
                        warn!(
                            call_id = %call_id,
                            "Media session not ready, using local address as fallback"
                        );
                        Some(self.local_media_addr)
                    }
                });

                if let Some(addr) = remote_addr {
                    info!(call_id = %call_id, remote_addr = %addr, "Starting audio session");
                    if let Err(e) = self.start_audio_session(call_id, addr).await {
                        warn!(call_id = %call_id, error = %e, "Failed to start audio");
                    }
                }
            }
            CallState::Terminated => {
                // Stop audio session first
                if let Err(e) = self.stop_audio_session(call_id).await {
                    warn!(call_id = %call_id, error = %e, "Failed to stop audio session");
                }

                // Clean up media session
                if let Some(mut session) = self.media_sessions.remove(call_id) {
                    let _ = session.close().await;
                }

                // Clean up negotiated codec
                self.negotiated_codecs.remove(call_id);

                // Record in call history
                let end_reason = call_info
                    .failure_reason
                    .as_ref()
                    .map(|_| CallEndReason::Failed)
                    .unwrap_or(CallEndReason::RemoteHangup);

                self.record_call_history(&call_info, end_reason).await;

                // Remove from active calls list
                self.active_calls.retain(|id| id != call_id);

                // Clear focused call if it was this one
                if self.focused_call_id.as_ref() == Some(&call_id.to_string()) {
                    // Focus another call if available
                    self.focused_call_id = self.active_calls.first().cloned();
                }
            }
            _ => {}
        }

        // Notify application
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.to_string(),
                state,
                info: call_info,
            })
            .await;

        Ok(())
    }

    async fn handle_sdp_answer(&mut self, call_id: &str, sdp: &str) -> AppResult<()> {
        debug!(call_id = %call_id, "Received SDP answer");

        // Parse the negotiated codec from the SDP answer
        if let Some(codec) = parse_codec_from_sdp(sdp) {
            info!(call_id = %call_id, codec = ?codec, "Negotiated codec from SDP answer");
            self.negotiated_codecs.insert(call_id.to_string(), codec);
        } else {
            debug!(call_id = %call_id, "No codec found in SDP answer, will use preferred codec");
        }

        // Parse SDP and configure media session
        if let Some(session) = self.media_sessions.get_mut(call_id) {
            // Extract ICE credentials from SDP
            if let Some(creds) = parse_ice_credentials_from_sdp(sdp) {
                session.set_remote_ice_credentials(creds);
            }

            // Extract ICE candidates from SDP
            for line in sdp.lines() {
                if line.starts_with("a=candidate:") {
                    if let Err(e) = session.add_remote_ice_candidate(line) {
                        warn!(error = %e, "Failed to add remote ICE candidate");
                    }
                }
            }

            // Start media session
            if let Err(e) = session.start().await {
                error!(call_id = %call_id, error = %e, "Failed to start media session");
            }
        }

        Ok(())
    }

    async fn handle_sdp_offer(&mut self, call_id: &str, sdp: &str) -> AppResult<()> {
        debug!(call_id = %call_id, "Received SDP offer");

        // For incoming calls, we'd create a media session here
        // and generate an answer
        let _ = (call_id, sdp);

        Ok(())
    }

    fn generate_sdp_offer(
        &self,
        session: &MediaSession,
        account: &SipAccount,
    ) -> AppResult<String> {
        let creds = session.local_ice_credentials();
        let fingerprint = session.local_dtls_fingerprint();
        let ssrc = session.local_ssrc();

        // Generate basic SDP offer
        // In production, this would use proto-sdp properly
        let sdp = format!(
            "v=0\r\n\
             o=- {session_id} {session_version} IN IP4 {ip}\r\n\
             s=USG SIP Client\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:sha-384 {fingerprint}\r\n\
             a=setup:actpass\r\n\
             a=mid:audio\r\n\
             a=sendrecv\r\n\
             a=rtcp-mux\r\n\
             a=ssrc:{ssrc} cname:{cname}\r\n",
            session_id = session_id(),
            session_version = 1,
            ip = self.local_media_addr.ip(),
            port = self.local_media_addr.port(),
            ufrag = creds.ufrag,
            pwd = creds.pwd,
            fingerprint = fingerprint,
            ssrc = ssrc,
            cname = account.id,
        );

        Ok(sdp)
    }

    /// Generates SDP for putting a call on hold (sendonly direction).
    fn generate_hold_sdp(&self, call_id: &str) -> AppResult<String> {
        self.generate_sdp_with_direction(call_id, "sendonly")
    }

    /// Generates SDP for resuming a call (sendrecv direction).
    fn generate_resume_sdp(&self, call_id: &str) -> AppResult<String> {
        self.generate_sdp_with_direction(call_id, "sendrecv")
    }

    /// Generates SDP with the specified media direction.
    fn generate_sdp_with_direction(&self, call_id: &str, direction: &str) -> AppResult<String> {
        let session = self
            .media_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Sip("No media session for call".to_string()))?;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        let creds = session.local_ice_credentials();
        let fingerprint = session.local_dtls_fingerprint();
        let ssrc = session.local_ssrc();

        // Generate SDP with specified direction
        let sdp = format!(
            "v=0\r\n\
             o=- {session_id} {session_version} IN IP4 {ip}\r\n\
             s=USG SIP Client\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:sha-384 {fingerprint}\r\n\
             a=setup:actpass\r\n\
             a=mid:audio\r\n\
             a={direction}\r\n\
             a=rtcp-mux\r\n\
             a=ssrc:{ssrc} cname:{cname}\r\n",
            session_id = session_id(),
            session_version = 2, // Increment version for re-INVITE
            ip = self.local_media_addr.ip(),
            port = self.local_media_addr.port(),
            ufrag = creds.ufrag,
            pwd = creds.pwd,
            fingerprint = fingerprint,
            direction = direction,
            ssrc = ssrc,
            cname = account.id,
        );

        Ok(sdp)
    }

    async fn record_call_history(&self, info: &CallInfo, end_reason: CallEndReason) {
        if let Some(manager) = &self.contact_manager {
            let entry = CallHistoryEntry::from_call_info(info, end_reason);
            let mut guard = manager.write().await;
            guard.add_call_history(entry);
            if let Err(e) = guard.save_if_dirty() {
                warn!(error = %e, "Failed to save call history");
            }
        }
    }
}

/// Extracts the username from a SIP URI.
///
/// Handles formats like:
/// - `sip:user@host`
/// - `sips:user@host`
/// - `<sip:user@host>`
///
/// Returns None if the URI doesn't contain a username.
fn extract_username_from_sip_uri(uri: &str) -> Option<String> {
    // Strip angle brackets if present
    let uri = uri.trim().trim_start_matches('<').trim_end_matches('>');

    // Strip sip: or sips: prefix
    let uri = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);

    // Find the @ symbol - username is before it
    if let Some(at_pos) = uri.find('@') {
        let username = &uri[..at_pos];
        if !username.is_empty() {
            return Some(username.to_string());
        }
    }

    None
}

/// Parses a From header value to extract display name and URI.
///
/// From header format: `"Display Name" <sip:user@host>` or `<sip:user@host>`
///
/// Returns (display_name, uri) where display_name is None if not present.
fn parse_from_header(from_value: &str) -> (Option<String>, String) {
    let trimmed = from_value.trim();

    // Check for display name in quotes
    if let Some(quote_end) = trimmed.strip_prefix('"').and_then(|s| s.find('"')) {
        let display_name = trimmed[1..quote_end + 1].to_string();
        let rest = &trimmed[quote_end + 2..];

        // Extract URI from angle brackets
        if let (Some(start), Some(end)) = (rest.find('<'), rest.find('>')) {
            let uri = rest[start + 1..end].to_string();
            return (Some(display_name), uri);
        }
    }

    // Check for URI in angle brackets without display name
    if let (Some(start), Some(end)) = (trimmed.find('<'), trimmed.find('>')) {
        // Check if there's a display name before the <
        let before = trimmed[..start].trim();
        let display_name = if before.is_empty() {
            None
        } else {
            Some(before.to_string())
        };
        let uri = trimmed[start + 1..end].to_string();
        return (display_name, uri);
    }

    // No angle brackets, use the whole thing as URI (minus tag)
    let uri = trimmed
        .split(';')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string();
    (None, uri)
}

/// Parses ICE credentials from SDP.
fn parse_ice_credentials_from_sdp(sdp: &str) -> Option<proto_ice::IceCredentials> {
    let mut ufrag = None;
    let mut pwd = None;

    for line in sdp.lines() {
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            pwd = Some(value.trim().to_string());
        }
    }

    match (ufrag, pwd) {
        (Some(ufrag), Some(pwd)) => Some(proto_ice::IceCredentials { ufrag, pwd }),
        _ => None,
    }
}

/// Parses the negotiated codec from an SDP answer.
///
/// Looks at the first payload type in the m=audio line, then finds the
/// corresponding rtpmap to determine the codec name.
///
/// # Arguments
/// * `sdp` - The SDP answer string
///
/// # Returns
/// The negotiated codec preference, or None if not found
fn parse_codec_from_sdp(sdp: &str) -> Option<CodecPreference> {
    let mut first_payload_type: Option<u8> = None;
    let mut rtpmaps: Vec<(u8, String)> = Vec::new();

    for line in sdp.lines() {
        // Find the m=audio line and get the first payload type
        if line.starts_with("m=audio") {
            // Format: m=audio <port> <proto> <fmt> <fmt> ...
            // e.g., "m=audio 49170 RTP/AVP 0 8 96"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // First format is at index 3
                if let Ok(pt) = parts[3].parse::<u8>() {
                    first_payload_type = Some(pt);
                }
            }
        }

        // Collect all rtpmap attributes
        // Format: a=rtpmap:<payload type> <encoding name>/<clock rate>[/<parameters>]
        // e.g., "a=rtpmap:0 PCMU/8000"
        if let Some(rtpmap) = line.strip_prefix("a=rtpmap:") {
            let parts: Vec<&str> = rtpmap.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pt) = parts[0].parse::<u8>() {
                    // Get the encoding name (before the /)
                    let codec_name = parts[1].split('/').next().unwrap_or("");
                    rtpmaps.push((pt, codec_name.to_string()));
                }
            }
        }
    }

    // Find the codec name for the first payload type
    let pt = first_payload_type?;

    // Check well-known static payload types first
    match pt {
        0 => return Some(CodecPreference::G711Ulaw),
        8 => return Some(CodecPreference::G711Alaw),
        9 => return Some(CodecPreference::G722),
        _ => {}
    }

    // Look up in rtpmap for dynamic payload types
    for (rtpmap_pt, codec_name) in rtpmaps {
        if rtpmap_pt == pt {
            let name_lower = codec_name.to_lowercase();
            if name_lower == "pcmu" {
                return Some(CodecPreference::G711Ulaw);
            } else if name_lower == "pcma" {
                return Some(CodecPreference::G711Alaw);
            } else if name_lower == "g722" {
                return Some(CodecPreference::G722);
            } else if name_lower == "opus" {
                return Some(CodecPreference::Opus);
            }
        }
    }

    None
}

/// Generates a unique session ID for SDP.
fn session_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_call_manager_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let manager = CallManager::new(sip_addr, media_addr, tx);

        assert!(manager.active_call_id().is_none());
        assert!(!manager.is_muted());
    }

    #[tokio::test]
    async fn test_make_call_without_account() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager.make_call("sips:bob@example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_hangup_without_active_call() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager.hangup().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_toggle_mute() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        assert!(!manager.is_muted());
        assert!(manager.toggle_mute());
        assert!(manager.is_muted());
        assert!(!manager.toggle_mute());
        assert!(!manager.is_muted());
    }

    #[test]
    fn test_parse_ice_credentials() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 0.0.0.0\r\n\
                   s=-\r\n\
                   c=IN IP4 0.0.0.0\r\n\
                   t=0 0\r\n\
                   m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                   a=ice-ufrag:testufrag\r\n\
                   a=ice-pwd:testpassword\r\n";

        let creds = parse_ice_credentials_from_sdp(sdp).unwrap();
        assert_eq!(creds.ufrag, "testufrag");
        assert_eq!(creds.pwd, "testpassword");
    }

    #[test]
    fn test_parse_ice_credentials_missing() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n";
        assert!(parse_ice_credentials_from_sdp(sdp).is_none());
    }

    #[test]
    fn test_extract_username_from_sip_uri() {
        // Standard SIP URI
        assert_eq!(
            extract_username_from_sip_uri("sip:alice@example.com"),
            Some("alice".to_string())
        );

        // SIPS URI
        assert_eq!(
            extract_username_from_sip_uri("sips:bob@secure.example.com"),
            Some("bob".to_string())
        );

        // With angle brackets
        assert_eq!(
            extract_username_from_sip_uri("<sip:carol@example.com>"),
            Some("carol".to_string())
        );

        // No username (host only)
        assert_eq!(extract_username_from_sip_uri("sip:example.com"), None);

        // Empty string
        assert_eq!(extract_username_from_sip_uri(""), None);
    }

    #[test]
    fn test_parse_from_header_with_display_name() {
        let (display, uri) = parse_from_header("\"Alice Smith\" <sip:alice@example.com>;tag=123");
        assert_eq!(display, Some("Alice Smith".to_string()));
        assert_eq!(uri, "sip:alice@example.com");
    }

    #[test]
    fn test_parse_from_header_no_display_name() {
        let (display, uri) = parse_from_header("<sip:bob@example.com>;tag=456");
        assert_eq!(display, None);
        assert_eq!(uri, "sip:bob@example.com");
    }

    #[test]
    fn test_parse_from_header_plain_uri() {
        let (display, uri) = parse_from_header("sip:charlie@example.com;tag=789");
        assert_eq!(display, None);
        assert_eq!(uri, "sip:charlie@example.com");
    }

    #[test]
    fn test_parse_from_header_unquoted_display_name() {
        let (display, uri) = parse_from_header("Dave <sip:dave@example.com>");
        assert_eq!(display, Some("Dave".to_string()));
        assert_eq!(uri, "sip:dave@example.com");
    }

    #[tokio::test]
    async fn test_incoming_call_tracking() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let manager = CallManager::new(sip_addr, media_addr, tx);

        // Initially no incoming calls
        assert!(!manager.has_incoming_call());
        assert!(manager.incoming_calls().is_empty());
    }

    #[test]
    fn test_parse_codec_from_sdp_pcmu() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8 96\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:96 opus/48000/2\r\n";

        let codec = parse_codec_from_sdp(sdp).unwrap();
        assert!(matches!(codec, CodecPreference::G711Ulaw));
    }

    #[test]
    fn test_parse_codec_from_sdp_pcma() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 8 0 96\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:96 opus/48000/2\r\n";

        let codec = parse_codec_from_sdp(sdp).unwrap();
        assert!(matches!(codec, CodecPreference::G711Alaw));
    }

    #[test]
    fn test_parse_codec_from_sdp_opus() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 111 0 8\r\n\
                   a=rtpmap:111 opus/48000/2\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";

        let codec = parse_codec_from_sdp(sdp).unwrap();
        assert!(matches!(codec, CodecPreference::Opus));
    }

    #[test]
    fn test_parse_codec_from_sdp_g722() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 9 0 8\r\n\
                   a=rtpmap:9 G722/8000\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";

        let codec = parse_codec_from_sdp(sdp).unwrap();
        assert!(matches!(codec, CodecPreference::G722));
    }

    #[test]
    fn test_parse_codec_from_sdp_no_audio() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n";

        assert!(parse_codec_from_sdp(sdp).is_none());
    }
}
