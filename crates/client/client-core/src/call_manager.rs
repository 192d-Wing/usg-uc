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
use client_sip_ua::{
    CallAgent, CallEvent, MediaSession, MediaSessionEvent, MediaSessionState, ReferStatus,
};
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

/// SIP dialog identifiers for an active call, used for re-INVITE detection.
struct ActiveCallDialog {
    sip_call_id: String,
    local_tag: String,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
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
    /// DTMF volume level for RFC 4733 packets (0-63, default 10).
    dtmf_volume: u8,
    /// Inter-digit pause in milliseconds (default 100).
    dtmf_inter_digit_pause_ms: u32,
    /// Negotiated codec per call (from SDP answer).
    negotiated_codecs: HashMap<String, CodecPreference>,
    /// Negotiated telephone-event payload type per call (None = not supported).
    telephone_event_pt: HashMap<String, Option<u8>>,
    /// Negotiated RFC 2198 redundancy payload type per call (None = not supported).
    redundancy_pt: HashMap<String, Option<u8>>,
    /// Negotiated RTP header extension IDs per call (from SDP `a=extmap`).
    negotiated_extension_ids: HashMap<String, Vec<(u8, String)>>,
    /// Effective local media address per call (what was advertised in SDP).
    effective_media_addrs: HashMap<String, SocketAddr>,
    /// SIP dialog identifiers for active calls (for re-INVITE detection).
    active_call_dialogs: HashMap<String, ActiveCallDialog>,
    /// SDP session ID per call (RFC 8866 - must remain constant for session).
    sdp_session_ids: HashMap<String, u64>,
    /// SDP session version per call (RFC 8866 - increments on modifications).
    sdp_session_versions: HashMap<String, u64>,
    /// Selected input device name (persists across calls).
    selected_input_device: Option<String>,
    /// Selected output device name (persists across calls).
    selected_output_device: Option<String>,
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
    /// Incoming call cancelled by remote party before answer.
    IncomingCallCancelled {
        /// Call ID.
        call_id: String,
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
    /// Transfer progress update (RFC 3515 REFER NOTIFY).
    TransferProgress {
        /// Call ID being transferred.
        call_id: String,
        /// Transfer target URI.
        target_uri: String,
        /// SIP status code (100=Trying, 180=Ringing, 200=Success, etc.).
        status_code: u16,
        /// Whether the transfer succeeded.
        is_success: bool,
        /// Whether this is the final status.
        is_final: bool,
    },
    /// DTMF digit received via SIP INFO.
    DtmfReceived {
        /// Call ID.
        call_id: String,
        /// DTMF digit (0-9, *, #, A-D).
        digit: char,
        /// Duration in RFC 4733 timestamp units (typically 8000 Hz clock).
        duration: u16,
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
            dtmf_volume: 10,
            dtmf_inter_digit_pause_ms: 100,
            negotiated_codecs: HashMap::new(),
            telephone_event_pt: HashMap::new(),
            redundancy_pt: HashMap::new(),
            negotiated_extension_ids: HashMap::new(),
            effective_media_addrs: HashMap::new(),
            active_call_dialogs: HashMap::new(),
            sdp_session_ids: HashMap::new(),
            sdp_session_versions: HashMap::new(),
            selected_input_device: None,
            selected_output_device: None,
        }
    }

    /// Configures the call manager with a SIP account.
    pub fn configure_account(&mut self, account: &SipAccount) {
        // Map transport preference to Via header transport string
        let transport_str = match account.transport {
            client_types::TransportPreference::Udp => "UDP",
            client_types::TransportPreference::Tcp => "TCP",
            client_types::TransportPreference::TlsOnly => "TLS",
        };

        // Configure call agent with account's AOR, display name, caller ID, and transport
        self.call_agent.configure(
            account.sip_uri.clone(),
            account.display_name.clone(),
            account.caller_id.clone(),
            transport_str,
            #[cfg(feature = "digest-auth")]
            account.digest_credentials.clone(),
        );
        self.account = Some(account.clone());
        info!(
            account_id = %account.id,
            caller_id = ?account.caller_id,
            transport = %transport_str,
            "Call manager configured with account"
        );
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
        self.moh_file_path = path;
        if let Some(ref p) = self.moh_file_path {
            info!(path = %p, "MOH file path set");
        } else {
            info!("MOH file path cleared");
        }
    }

    /// Returns the currently configured MOH file path.
    pub fn moh_file_path(&self) -> Option<&str> {
        self.moh_file_path.as_deref()
    }

    /// Sets the DTMF volume level (0-63, where 0 is loudest).
    pub fn set_dtmf_volume(&mut self, volume: u8) {
        self.dtmf_volume = volume.min(63);
        info!(volume = self.dtmf_volume, "DTMF volume set");
    }

    /// Sets the inter-digit pause between consecutive DTMF digits.
    pub fn set_dtmf_inter_digit_pause_ms(&mut self, pause_ms: u32) {
        self.dtmf_inter_digit_pause_ms = pause_ms;
        info!(pause_ms, "DTMF inter-digit pause set");
    }

    /// Returns the preferred codec.
    pub const fn preferred_codec(&self) -> CodecPreference {
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
            let max = self.max_concurrent_calls;
            return Err(AppError::Sip(format!(
                "Maximum concurrent calls ({max}) reached"
            )));
        }

        // If there's a focused call that's connected, put it on hold first (call waiting)
        if let Some(ref focused_id) = self.focused_call_id.clone() {
            let state = self.call_agent.get_state(focused_id);
            if state == Some(CallState::Connected) {
                info!(call_id = %focused_id, "Auto-holding current call for new outbound call");
                self.hold_call_by_id(focused_id).await?;
            }
        }

        // Verify we have an account configured
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        // If the URI doesn't contain a domain (@), append the account's domain
        let full_remote_uri = if remote_uri.contains('@') {
            remote_uri.to_string()
        } else {
            // Extract scheme and user part
            let (scheme, user_part) = remote_uri.strip_prefix("sips:").map_or_else(
                || {
                    remote_uri
                        .strip_prefix("sip:")
                        .map_or(("sip", remote_uri), |rest| ("sip", rest))
                },
                |rest| ("sips", rest),
            );

            // Get domain from account
            let domain = account.domain().unwrap_or("localhost");
            format!("{scheme}:{user_part}@{domain}")
        };

        info!(remote_uri = %full_remote_uri, "Making outbound call");

        // Get the effective local media address (this creates and binds a UDP socket)
        // We must use this SAME address for SDP and for the audio session
        let effective_media_addr = self.get_effective_media_addr()?;

        // Create media session channel
        let (media_tx, _media_rx) = mpsc::channel(32);

        // Create media session for this call using the effective address
        let media_session = MediaSession::new(
            effective_media_addr,
            true, // outbound = controlling
            self.ice_config.clone(),
            self.dtls_cert_chain.clone(),
            self.dtls_private_key.clone(),
            media_tx,
        );

        // Generate session ID for this call (version starts at 1)
        let sdp_session_id = session_id();
        let sdp_session_version = 1;

        // Generate SDP offer using the same effective address
        let sdp_offer = self.generate_sdp_offer_with_addr(
            &media_session,
            account,
            effective_media_addr,
            sdp_session_id,
            sdp_session_version,
        );

        // Make the call via SIP UA
        let call_id = self
            .call_agent
            .make_call(&full_remote_uri, &sdp_offer)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Store the effective media address for this call (used when starting audio session)
        self.effective_media_addrs
            .insert(call_id.clone(), effective_media_addr);

        // Store SDP session ID and version for this call
        self.sdp_session_ids.insert(call_id.clone(), sdp_session_id);
        self.sdp_session_versions
            .insert(call_id.clone(), sdp_session_version);

        // Track SIP dialog identifiers for re-INVITE detection.
        // remote_addr is unknown until a response arrives; use unspecified placeholder.
        if let (Some(sip_call_id), Some(local_tag)) = (
            self.call_agent.get_sip_call_id(&call_id),
            self.call_agent.get_local_tag(&call_id),
        ) {
            self.active_call_dialogs.insert(
                call_id.clone(),
                ActiveCallDialog {
                    sip_call_id,
                    local_tag,
                    remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                },
            );
        }

        // Store media session and track the call
        self.media_sessions.insert(call_id.clone(), media_session);
        self.active_calls.push(call_id.clone());
        self.focused_call_id = Some(call_id.clone());

        // Notify application
        let info = CallInfo {
            id: call_id.clone(),
            state: CallState::Dialing,
            direction: CallDirection::Outbound,
            remote_uri: full_remote_uri,
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
        info!(
            focused_call_id = ?self.focused_call_id,
            active_calls = ?self.active_calls,
            "hangup() called"
        );

        let call_id = self
            .focused_call_id
            .as_ref()
            .ok_or_else(|| {
                error!(
                    "hangup() failed: No focused call. active_calls: {:?}",
                    self.active_calls
                );
                AppError::Sip("No active call".to_string())
            })?
            .clone();

        self.hangup_call(&call_id).await
    }

    /// Hangs up a specific call.
    pub async fn hangup_call(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "hangup_call() called");

        // Get call info before hangup
        let call_info = self.call_agent.get_call_info(call_id);
        debug!(call_id = %call_id, call_info = ?call_info, "Call info before hangup");

        // Send hangup via SIP UA
        self.call_agent
            .hangup(call_id)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Close media session
        if let Some(mut session) = self.media_sessions.remove(call_id) {
            let _ = session.close().await;
        }

        // Clean up negotiated codec and dialog tracking
        self.negotiated_codecs.remove(call_id);
        self.active_call_dialogs.remove(call_id);

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
            CallEvent::SendRequest { .. } | CallEvent::SendResponse { .. } => {
                // Transport layer handles this via poll_call_events()
            }
            CallEvent::SdpOfferReceived { call_id, sdp } => {
                Self::handle_sdp_offer(&call_id, &sdp);
            }
            CallEvent::TransferProgress {
                call_id,
                target_uri,
                status,
                is_final,
            } => {
                self.handle_transfer_progress(&call_id, &target_uri, status, is_final)
                    .await?;
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
        let Some(id) = response.headers.get_value(&HeaderName::CallId) else {
            warn!("Received response without Call-ID header");
            return Ok(());
        };
        let sip_call_id = id.to_string();

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
    /// Note: For BYE requests, use `handle_sip_request_from` to send 200 OK response.
    pub async fn handle_sip_request(&mut self, request: &SipRequest) -> AppResult<()> {
        // Default to localhost if source not known
        let default_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 5060));
        self.handle_sip_request_from(request, default_addr).await
    }

    /// Routes an incoming SIP request with source address for response routing.
    ///
    /// This handles incoming calls and in-dialog requests (INVITE, BYE, CANCEL, etc.).
    pub async fn handle_sip_request_from(
        &mut self,
        request: &SipRequest,
        source: SocketAddr,
    ) -> AppResult<()> {
        let method = request.method.as_str();
        debug!(method = %method, source = %source, "Received incoming SIP request");

        match method {
            "INVITE" => {
                // Check if this is a mid-dialog re-INVITE by matching Call-ID + To-tag
                let sip_call_id = request
                    .headers
                    .get_value(&HeaderName::CallId)
                    .map(std::string::ToString::to_string);
                let to_tag = request.headers.to_tag();

                let reinvite_match = sip_call_id
                    .as_ref()
                    .and_then(|id| self.find_active_call_by_sip_call_id(id))
                    .and_then(|(call_id, dialog)| {
                        // A re-INVITE has a To-tag matching our local_tag for the dialog.
                        // Initial INVITEs have no To-tag.
                        if to_tag.as_ref().is_some_and(|t| t == &dialog.local_tag) {
                            Some((call_id, dialog.local_tag.clone()))
                        } else {
                            None
                        }
                    });

                if let Some((call_id, local_tag)) = reinvite_match {
                    self.handle_incoming_reinvite(request, source, &call_id, &local_tag)
                        .await?;
                } else {
                    self.handle_incoming_invite_from(request, source).await?;
                }
            }
            "BYE" => {
                // Remote party hanging up
                self.handle_incoming_bye(request, source).await?;
            }
            "CANCEL" => {
                // Remote party cancelling
                self.handle_incoming_cancel(request, source).await?;
            }
            "ACK" => {
                // Acknowledgement (normally handled by transaction layer)
                debug!("Received ACK");
            }
            "INFO" => {
                // In-dialog INFO (e.g. SIP INFO DTMF relay)
                self.handle_incoming_info(request, source).await?;
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

    /// Finds a pending incoming call by its SIP Call-ID.
    fn find_incoming_call_by_sip_id(&self, sip_call_id: &str) -> Option<String> {
        self.incoming_calls
            .iter()
            .find(|(_, info)| info.sip_call_id == sip_call_id)
            .map(|(_, info)| info.call_id.clone())
    }

    /// Finds an active call by its SIP Call-ID in the dialog tracking map.
    ///
    /// Returns `(app_call_id, dialog)` if found.
    fn find_active_call_by_sip_call_id(
        &self,
        sip_call_id: &str,
    ) -> Option<(String, &ActiveCallDialog)> {
        self.active_call_dialogs
            .iter()
            .find(|(_, d)| d.sip_call_id == sip_call_id)
            .map(|(id, d)| (id.clone(), d))
    }

    /// Handles an incoming mid-dialog re-INVITE (e.g. session timer refresh, hold).
    ///
    /// Unlike an initial INVITE, a re-INVITE targets an existing dialog identified
    /// by matching SIP Call-ID + To-tag. We respond 200 OK with SDP answer rather
    /// than ringing the phone.
    #[allow(clippy::too_many_lines)]
    async fn handle_incoming_reinvite(
        &mut self,
        request: &SipRequest,
        source: SocketAddr,
        call_id: &str,
        local_tag: &str,
    ) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        info!(
            call_id = %call_id,
            source = %source,
            "Received incoming re-INVITE for active call"
        );

        // Glare check: if we have a pending outbound INVITE transaction on this
        // call (e.g. our own hold/resume re-INVITE), respond 491 Request Pending.
        if self.call_agent.has_pending_invite_transaction(call_id) {
            warn!(call_id = %call_id, "Glare detected — pending INVITE transaction, responding 491");
            let response = build_response_from_request(
                request,
                StatusCode::REQUEST_PENDING,
                Some(local_tag),
            );
            let _ = self
                .app_event_tx
                .send(CallManagerEvent::SendResponse {
                    response,
                    destination: source,
                })
                .await;
            return Ok(());
        }

        // Parse remote SDP from body
        let remote_sdp = request
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");

        // Parse media direction from remote SDP
        let remote_direction = parse_media_direction(remote_sdp);

        // Track whether we need to restart audio (codec or remote addr changed)
        let mut audio_restart_needed = false;

        // Re-negotiate codec if SDP is present
        if !remote_sdp.is_empty() {
            if let Some(codec) = negotiate_codec_from_sdp_offer(remote_sdp, self.preferred_codec) {
                let previous_codec = self.negotiated_codecs.get(call_id).copied();
                info!(call_id = %call_id, codec = ?codec, "Re-negotiated codec from re-INVITE SDP");
                self.negotiated_codecs.insert(call_id.to_string(), codec);

                // Flag audio restart if codec actually changed
                if let Some(prev) = previous_codec
                    && prev != codec
                    && self.audio_sessions.contains_key(call_id)
                {
                    info!(
                        call_id = %call_id,
                        from = ?prev,
                        to = ?codec,
                        "Codec changed in re-INVITE"
                    );
                    audio_restart_needed = true;
                }
            }

            // Update DTMF and redundancy PTs
            let dtmf_pt = parse_telephone_event_pt(remote_sdp);
            self.telephone_event_pt.insert(call_id.to_string(), dtmf_pt);
            let red_pt = parse_redundancy_pt(remote_sdp);
            self.redundancy_pt.insert(call_id.to_string(), red_pt);
            let ext_ids = parse_extmap_attributes(remote_sdp);
            self.negotiated_extension_ids
                .insert(call_id.to_string(), ext_ids);

            // Update remote media address if changed
            if let Some(new_remote_addr) = parse_remote_media_addr_from_sdp(remote_sdp)
                && let Some(session) = self.media_sessions.get_mut(call_id)
            {
                let old_addr = session.remote_addr();
                if old_addr != Some(new_remote_addr) {
                    info!(
                        call_id = %call_id,
                        old = ?old_addr,
                        new = %new_remote_addr,
                        "Remote media address changed in re-INVITE"
                    );
                    session.set_remote_addr(new_remote_addr);
                    // Must restart audio to pick up the new destination
                    if self.audio_sessions.contains_key(call_id) {
                        audio_restart_needed = true;
                    }
                }
            }
        }

        // Restart audio session if codec or remote address changed
        if audio_restart_needed {
            info!(call_id = %call_id, "Restarting audio session for re-INVITE parameter change");
            let _ = self.stop_audio_session(call_id).await;
            if let Some(addr) = self
                .media_sessions
                .get(call_id)
                .and_then(MediaSession::remote_addr)
            {
                let _ = self.start_audio_session(call_id, addr).await;
            }
        }

        // Compute reciprocal direction for our SDP answer
        let our_direction = match remote_direction {
            "sendonly" => "recvonly",
            "recvonly" => "sendonly",
            "inactive" => "inactive",
            _ => "sendrecv",
        };

        // Log hold/resume events
        match remote_direction {
            "sendonly" | "inactive" => {
                info!(call_id = %call_id, direction = %remote_direction, "Remote party placed call on hold");
            }
            "sendrecv" => {
                debug!(call_id = %call_id, "Re-INVITE with sendrecv (session refresh or resume)");
            }
            _ => {}
        }

        // Generate SDP answer with reciprocal direction
        let sdp_answer = self.generate_sdp_with_direction(call_id, our_direction)?;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        // Build 200 OK with SDP body
        let mut ok_response =
            build_response_from_request(request, StatusCode::OK, Some(local_tag));

        // Add Contact header with routable IP (not 0.0.0.0)
        let effective_addr = self.get_effective_media_addr()?;
        let username =
            extract_username_from_sip_uri(&account.sip_uri).unwrap_or_else(|| account.id.clone());
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::Contact,
            format!("<sip:{username}@{ip}>", ip = effective_addr.ip()),
        ));

        // Echo Session-Expires from request (RFC 4028 §7.2) so the session
        // timer is properly refreshed. Without this, the B2BUA (BulkVS) may
        // consider the refresh failed and stall media for up to Timer C (3 min).
        if let Some(se) = request
            .headers
            .get_value(&HeaderName::SessionExpires)
        {
            let se_value = se.to_string();
            info!(call_id = %call_id, session_expires = %se_value, "Echoing Session-Expires in 200 OK");
            ok_response.add_header(proto_sip::header::Header::new(
                HeaderName::SessionExpires,
                se_value,
            ));
            // Indicate timer extension support
            ok_response.add_header(proto_sip::header::Header::new(
                HeaderName::Supported,
                "timer",
            ));
        }
        // Echo Min-SE if present (RFC 4028 §5)
        if let Some(min_se) = request.headers.get_value(&HeaderName::MinSe) {
            ok_response.add_header(proto_sip::header::Header::new(
                HeaderName::MinSe,
                min_se.to_string(),
            ));
        }

        // Add Content-Type and body (use set() to replace the Content-Length: 0
        // that build_response_from_request() added)
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::ContentType,
            "application/sdp",
        ));
        ok_response.headers.set(
            proto_sip::header::HeaderName::ContentLength,
            sdp_answer.len().to_string(),
        );
        ok_response = ok_response.with_body(sdp_answer);

        // Send 200 OK
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ok_response,
                destination: source,
            })
            .await;

        info!(call_id = %call_id, "Sent 200 OK for re-INVITE");
        Ok(())
    }

    /// Handles an incoming INVITE request.
    ///
    /// This method requires the source address of the INVITE to be known
    /// for sending responses. Use `handle_incoming_invite_from` instead.
    #[allow(dead_code)]
    pub async fn handle_incoming_invite(&mut self, request: &SipRequest) -> AppResult<()> {
        // Default to localhost if source not known (shouldn't happen in real usage)
        let default_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 5060));
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
            .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);

        // Parse display name and URI from From header
        let (remote_display_name, remote_uri) = parse_from_header(&from_value);

        // Extract SIP Call-ID
        let sip_call_id = request.headers.get_value(&HeaderName::CallId).map_or_else(
            || format!("unknown-{}", generate_tag()),
            std::string::ToString::to_string,
        );

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
    #[allow(clippy::too_many_lines)]
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

        // Parse the remote's SDP offer from the INVITE body to negotiate
        // codec, DTMF PT, and redundancy PT.
        if let Some(remote_sdp) = incoming
            .invite_request
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
        {
            // Negotiate best codec from intersection of offer and our capabilities
            if let Some(codec) = negotiate_codec_from_sdp_offer(remote_sdp, self.preferred_codec) {
                info!(call_id = %call_id, codec = ?codec, "Negotiated codec from incoming SDP offer");
                self.negotiated_codecs.insert(call_id.to_string(), codec);
            }
            // Parse DTMF telephone-event PT from remote offer
            let dtmf_pt = parse_telephone_event_pt(remote_sdp);
            self.telephone_event_pt.insert(call_id.to_string(), dtmf_pt);
            if let Some(pt) = dtmf_pt {
                info!(call_id = %call_id, pt = pt, "Remote offer supports telephone-event PT={pt}");
            }
            // Parse RFC 2198 redundancy PT from remote offer
            let red_pt = parse_redundancy_pt(remote_sdp);
            self.redundancy_pt.insert(call_id.to_string(), red_pt);
            if let Some(pt) = red_pt {
                info!(call_id = %call_id, pt = pt, "Remote offer supports redundancy PT={pt}");
            }
            // Parse RTP header extensions from remote offer (RFC 5285)
            let ext_ids = parse_extmap_attributes(remote_sdp);
            if !ext_ids.is_empty() {
                info!(call_id = %call_id, count = ext_ids.len(), "Remote offer supports RTP extensions");
            }
            self.negotiated_extension_ids
                .insert(call_id.to_string(), ext_ids);
        }

        // Discover and store the effective media address for this inbound call
        let effective_media_addr = self.get_effective_media_addr()?;
        self.effective_media_addrs
            .insert(call_id.to_string(), effective_media_addr);

        // Generate SDP answer using the stored address
        let sdp_session_id = self.get_or_create_sdp_session_id(call_id);
        let sdp_session_version = self.get_sdp_session_version(call_id);
        let sdp_answer = self.generate_sdp_offer_with_addr(
            &media_session,
            &account,
            effective_media_addr,
            sdp_session_id,
            sdp_session_version,
        );

        // Build 200 OK with SDP body
        let mut ok_response = build_response_from_request(
            &incoming.invite_request,
            StatusCode::OK,
            Some(&incoming.local_tag),
        );

        // Add Contact header with routable IP (not 0.0.0.0)
        let effective_addr = self.get_effective_media_addr()?;
        let username =
            extract_username_from_sip_uri(&account.sip_uri).unwrap_or_else(|| account.id.clone());
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::Contact,
            format!("<sip:{username}@{ip}>", ip = effective_addr.ip()),
        ));

        // Add Content-Type and body (use set() to replace the Content-Length: 0
        // that build_response_from_request() added)
        ok_response.add_header(proto_sip::header::Header::new(
            proto_sip::header::HeaderName::ContentType,
            "application/sdp",
        ));

        ok_response.headers.set(
            proto_sip::header::HeaderName::ContentLength,
            sdp_answer.len().to_string(),
        );

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
            let state = self.call_agent.get_state(focused_id);
            if state == Some(CallState::Connected) {
                info!(call_id = %focused_id, "Auto-holding current call for incoming call");
                self.hold_call_by_id(focused_id).await?;
            }
        }

        // Store media session and track the call
        self.media_sessions
            .insert(call_id.to_string(), media_session);
        self.active_calls.push(call_id.to_string());
        self.focused_call_id = Some(call_id.to_string());

        // Track SIP dialog identifiers for re-INVITE detection
        let sip_call_id = incoming.sip_call_id.clone();
        let local_tag = incoming.local_tag.clone();
        let remote_tag = incoming.invite_request.headers.from_tag();
        let remote_uri_str = incoming.remote_uri.clone();
        let remote_display = incoming.remote_display_name.clone();
        let source_addr = incoming.source_addr;
        let remote_sdp_str = incoming
            .invite_request
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(String::from);

        self.active_call_dialogs.insert(
            call_id.to_string(),
            ActiveCallDialog {
                sip_call_id: sip_call_id.clone(),
                local_tag: local_tag.clone(),
                remote_addr: source_addr,
            },
        );

        // Register the inbound call in the call agent so hangup (BYE) works.
        // For BYE routing, use the Contact header from the INVITE if available,
        // otherwise fall back to the source address.
        let bye_target = incoming
            .invite_request
            .headers
            .get_value(&proto_sip::header::HeaderName::Contact)
            .and_then(|c| {
                // Extract URI from Contact: <sip:...>
                let s = c.to_string();
                let start = s.find('<').map(|i| i + 1).unwrap_or(0);
                let end = s.find('>').unwrap_or(s.len());
                Some(s[start..end].to_string())
            })
            .unwrap_or_else(|| format!("sip:{}:{}", source_addr.ip(), source_addr.port()));

        self.call_agent.register_inbound_call(
            call_id,
            &sip_call_id,
            &local_tag,
            remote_tag.as_deref(),
            &bye_target,
            remote_display.as_deref(),
            remote_sdp_str.as_deref(),
        );

        // Start audio session using remote media address from INVITE SDP
        if let Some(ref sdp) = remote_sdp_str {
            if let Some(remote_media_addr) = parse_remote_media_addr_from_sdp(sdp) {
                info!(
                    call_id = %call_id,
                    remote_media = %remote_media_addr,
                    "Starting audio for accepted incoming call"
                );
                if let Err(e) = self.start_audio_session(call_id, remote_media_addr).await {
                    error!(call_id = %call_id, error = %e, "Failed to start audio for incoming call");
                }
            } else {
                warn!(call_id = %call_id, "No remote media address in incoming SDP");
            }
        } else {
            warn!(call_id = %call_id, "No SDP body in incoming INVITE");
        }

        // Notify application of state change
        let info = CallInfo {
            id: call_id.to_string(),
            state: CallState::Connected,
            direction: CallDirection::Inbound,
            remote_uri: remote_uri_str,
            remote_display_name: remote_display,
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
    ///
    /// Sends a 200 OK response and terminates the call.
    async fn handle_incoming_bye(
        &mut self,
        request: &SipRequest,
        source: SocketAddr,
    ) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        let Some(id) = request.headers.get_value(&HeaderName::CallId) else {
            warn!("Received BYE without Call-ID header");
            return Ok(());
        };
        let sip_call_id = id.to_string();

        // Always send 200 OK response for BYE
        let ok_response = build_response_from_request(request, StatusCode::OK, None);
        info!(destination = %source, "Queueing 200 OK response for BYE");
        if let Err(e) = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ok_response,
                destination: source,
            })
            .await
        {
            error!(error = %e, "Failed to queue 200 OK response for BYE");
        }

        if let Some(call_id) = self
            .find_call_by_sip_id(&sip_call_id)
            .or_else(|| self.find_active_call_by_sip_call_id(&sip_call_id).map(|(id, _)| id))
        {
            info!(call_id = %call_id, sip_call_id = %sip_call_id, "Remote party sent BYE, terminating call");
            // Mark the call as terminated - the remote party hung up
            self.handle_state_changed(&call_id, CallState::Terminated, None)
                .await?;
        } else {
            warn!(sip_call_id = %sip_call_id, "Received BYE for unknown call");
        }

        Ok(())
    }

    /// Handles an incoming CANCEL request.
    ///
    /// Sends a 200 OK response and terminates the call.
    async fn handle_incoming_cancel(
        &mut self,
        request: &SipRequest,
        source: SocketAddr,
    ) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        let Some(id) = request.headers.get_value(&HeaderName::CallId) else {
            warn!("Received CANCEL without Call-ID header");
            return Ok(());
        };
        let sip_call_id = id.to_string();

        // Always send 200 OK response for CANCEL
        let ok_response = build_response_from_request(request, StatusCode::OK, None);
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ok_response,
                destination: source,
            })
            .await;

        if let Some(call_id) = self
            .find_call_by_sip_id(&sip_call_id)
            .or_else(|| self.find_active_call_by_sip_call_id(&sip_call_id).map(|(id, _)| id))
        {
            info!(call_id = %call_id, sip_call_id = %sip_call_id, "Remote party sent CANCEL, terminating call");
            // Mark the call as terminated - the remote party cancelled
            self.handle_state_changed(&call_id, CallState::Terminated, None)
                .await?;
        } else if let Some(call_id) = self.find_incoming_call_by_sip_id(&sip_call_id) {
            info!(call_id = %call_id, sip_call_id = %sip_call_id, "Remote party cancelled incoming call before answer");
            // Remove from pending incoming calls
            self.incoming_calls.remove(&call_id);
            // Notify the application so the UI can dismiss the incoming call modal
            let _ = self
                .app_event_tx
                .send(CallManagerEvent::IncomingCallCancelled { call_id })
                .await;
        } else {
            warn!(sip_call_id = %sip_call_id, "Received CANCEL for unknown call");
        }

        Ok(())
    }

    /// Handles an incoming SIP INFO request.
    ///
    /// Parses `application/dtmf-relay` bodies and emits a `DtmfReceived` event.
    /// Always responds with 200 OK to the sender.
    async fn handle_incoming_info(
        &self,
        request: &SipRequest,
        source: SocketAddr,
    ) -> AppResult<()> {
        use crate::sip_transport::build_response_from_request;

        // Always send 200 OK for INFO
        let ok_response = build_response_from_request(request, StatusCode::OK, None);
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::SendResponse {
                response: ok_response,
                destination: source,
            })
            .await;

        // Check Content-Type for dtmf-relay
        let content_type = request
            .headers
            .get_value(&HeaderName::ContentType)
            .unwrap_or_default();
        if !content_type.contains("dtmf-relay") && !content_type.contains("dtmf") {
            debug!(content_type = %content_type, "INFO request is not DTMF relay, ignoring body");
            return Ok(());
        }

        // Parse Signal= and Duration= from body
        let body_str = request
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");

        let Some((digit, duration)) = parse_dtmf_relay_body(body_str) else {
            warn!("INFO dtmf-relay body missing Signal= field");
            return Ok(());
        };

        // Find the call
        let sip_call_id = request
            .headers
            .get_value(&HeaderName::CallId)
            .unwrap_or_default()
            .to_string();
        let call_id = self
            .find_call_by_sip_id(&sip_call_id)
            .unwrap_or_else(|| sip_call_id.clone());

        info!(call_id = %call_id, digit = %digit, duration = duration, "Received DTMF via SIP INFO");

        let _ = self
            .app_event_tx
            .send(CallManagerEvent::DtmfReceived {
                call_id,
                digit,
                duration,
            })
            .await;

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
        if let Some(call_id) = &self.focused_call_id
            && let Some(session) = self.audio_sessions.get(call_id)
        {
            session.set_muted(self.is_muted);
        }

        info!(muted = self.is_muted, "Mute toggled");
        self.is_muted
    }

    /// Returns whether currently muted.
    pub const fn is_muted(&self) -> bool {
        self.is_muted
    }

    /// Sends a DTMF digit on the focused call.
    ///
    /// Uses RFC 4733 telephone-event when negotiated. Falls back to SIP INFO
    /// (`application/dtmf-relay`) plus in-band audio tones when telephone-event
    /// is not available.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send (0-9, *, #, A-D)
    /// * `duration_ms` - Duration of the tone in milliseconds (typical: 100ms)
    pub async fn send_dtmf(&mut self, digit: DtmfDigit, duration_ms: u32) -> AppResult<()> {
        let call_id = self
            .focused_call_id
            .clone()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?;

        // Check if remote party supports RFC 4733 telephone-event
        let dtmf_pt = self.telephone_event_pt.get(&call_id).copied().flatten();
        let use_rfc2833 = dtmf_pt.is_some();

        if use_rfc2833 {
            // RFC 4733 path via audio pipeline
            let session = self
                .audio_sessions
                .get(&call_id)
                .ok_or_else(|| AppError::Audio("No audio session for call".to_string()))?;
            info!(digit = %digit, duration_ms = duration_ms, method = "RFC4733", "Sending DTMF");
            session.send_dtmf(digit, duration_ms, true)
        } else {
            // SIP INFO fallback + in-band audio
            info!(digit = %digit, duration_ms = duration_ms, method = "SIP-INFO+in-band", "Sending DTMF");

            // Send SIP INFO for reliable signaling
            if let Err(e) = self
                .call_agent
                .send_info_dtmf(&call_id, digit, duration_ms)
                .await
            {
                warn!(error = %e, "SIP INFO DTMF failed, relying on in-band only");
            }

            // Also send in-band tones as belt-and-suspenders
            if let Some(session) = self.audio_sessions.get(&call_id) {
                session.send_dtmf(digit, duration_ms, false)?;
            }
            Ok(())
        }
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
    pub fn switch_input_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        info!(device = ?device_name, "Switching input device");

        // Also update the active session if one exists
        if let Some(session) = self
            .focused_call_id
            .as_ref()
            .and_then(|id| self.audio_sessions.get_mut(id))
        {
            session.switch_input_device(device_name.clone())?;
        }

        // Always persist the preference for future calls
        self.selected_input_device = device_name;

        Ok(())
    }

    /// Switches the output (speaker) device for the active call.
    ///
    /// This allows changing the speaker mid-call without disconnecting.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new output device, or None for default
    pub fn switch_output_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        info!(device = ?device_name, "Switching output device");

        // Also update the active session if one exists
        if let Some(session) = self
            .focused_call_id
            .as_ref()
            .and_then(|id| self.audio_sessions.get_mut(id))
        {
            session.switch_output_device(device_name.clone())?;
        }

        // Always persist the preference for future calls
        self.selected_output_device = device_name;

        Ok(())
    }

    /// Returns the current input device name (from active call or stored preference).
    pub fn current_input_device(&self) -> Option<String> {
        // Try active session first, fall back to stored preference
        self.focused_call_id
            .as_ref()
            .and_then(|id| self.audio_sessions.get(id))
            .and_then(|session| session.input_device_name())
            .map(String::from)
            .or_else(|| self.selected_input_device.clone())
    }

    /// Returns the current output device name (from active call or stored preference).
    pub fn current_output_device(&self) -> Option<String> {
        // Try active session first, fall back to stored preference
        self.focused_call_id
            .as_ref()
            .and_then(|id| self.audio_sessions.get(id))
            .and_then(|session| session.output_device_name())
            .map(String::from)
            .or_else(|| self.selected_output_device.clone())
    }

    /// Sets the preferred devices without switching any active session.
    ///
    /// Used at startup to restore saved preferences from settings.
    pub fn set_preferred_devices(&mut self, input: Option<String>, output: Option<String>) {
        self.selected_input_device = input;
        self.selected_output_device = output;
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
            audio_session.set_moh_active(true);
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
            audio_session.set_moh_active(false);
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
                "Cannot toggle hold in state {state:?}"
            ))),
        }
    }

    /// Changes the codec for an active call via SIP re-INVITE.
    ///
    /// Sends a re-INVITE with SDP offering only the requested codec.
    /// When the remote accepts, the audio session is automatically
    /// restarted with the new codec (handled in `handle_sdp_answer`).
    pub async fn change_codec(
        &mut self,
        call_id: &str,
        new_codec: CodecPreference,
    ) -> AppResult<()> {
        // Verify call exists and is connected
        let current_state = self
            .call_agent
            .get_state(call_id)
            .ok_or_else(|| AppError::Sip("Call not found".to_string()))?;

        if current_state != CallState::Connected {
            return Err(AppError::Sip(format!(
                "Cannot change codec in state {current_state:?}"
            )));
        }

        // Check if codec is actually different
        let current_codec = self
            .negotiated_codecs
            .get(call_id)
            .copied()
            .unwrap_or(self.preferred_codec);

        if current_codec == new_codec {
            info!(call_id = %call_id, codec = ?new_codec, "Codec unchanged, skipping re-INVITE");
            return Ok(());
        }

        info!(
            call_id = %call_id,
            from = ?current_codec,
            to = ?new_codec,
            "Changing codec via re-INVITE"
        );

        // Generate SDP with the target codec as the only offered codec
        let sdp = self.generate_sdp_for_codec_change(call_id, new_codec)?;

        // Send re-INVITE via call agent
        self.call_agent
            .send_media_update(call_id, &sdp)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        Ok(())
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
    pub fn audio_stats(&self) -> Option<PipelineStats> {
        let call_id = self.focused_call_id.as_ref()?;
        self.audio_sessions.get(call_id).map(AudioSession::stats)
    }

    /// Switches focus to a different call.
    ///
    /// If there's a currently focused call that's connected, it will be put on hold.
    /// The target call will be resumed if it's on hold.
    pub async fn switch_to_call(&mut self, call_id: &str) -> AppResult<()> {
        // Verify target call exists
        if !self.active_calls.contains(&call_id.to_string()) {
            return Err(AppError::Sip(format!("Call not found: {call_id}")));
        }

        // Put current focused call on hold if it's connected
        if let Some(ref current) = self.focused_call_id.clone()
            && current != call_id
        {
            let state = self.call_agent.get_state(current);
            if state == Some(CallState::Connected) {
                self.hold_call_by_id(current).await?;
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

        // Create audio session and apply stored device preferences
        let mut audio_session = AudioSession::new(self.audio_event_tx.clone());

        if let Some(ref name) = self.selected_input_device {
            let _ = audio_session.switch_input_device(Some(name.clone()));
        }
        if let Some(ref name) = self.selected_output_device {
            let _ = audio_session.switch_output_device(Some(name.clone()));
        }

        // Use the negotiated codec from SDP answer if available, otherwise fall back to preferred
        let codec = self
            .negotiated_codecs
            .get(call_id)
            .copied()
            .unwrap_or(self.preferred_codec);

        info!(call_id = %call_id, codec = ?codec, "Using codec for audio session");

        // Get the local port that was advertised in the SDP offer
        // This ensures we bind to the same port the remote will send RTP to
        let local_port = self
            .effective_media_addrs
            .get(call_id)
            .map_or(0, std::net::SocketAddr::port);

        info!(call_id = %call_id, local_port = local_port, "Using local port from SDP");

        // Configure audio
        // Get negotiated DTMF payload type for this call
        let dtmf_payload_type = self.telephone_event_pt.get(call_id).copied().flatten();

        let redundancy_pt = self.redundancy_pt.get(call_id).copied().flatten();

        let extension_ids = self
            .negotiated_extension_ids
            .get(call_id)
            .cloned()
            .unwrap_or_default();

        let config = AudioSessionConfig {
            local_port,
            remote_addr,
            codec,
            jitter_buffer_ms: 40,
            // SRTP keys will be obtained from media session in production
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: self.moh_file_path.clone(),
            dtmf_payload_type,
            dtmf_volume: self.dtmf_volume,
            dtmf_inter_digit_pause_ms: self.dtmf_inter_digit_pause_ms,
            redundancy_pt,
            extension_ids,
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
        info!(call_id = %call_id, state = ?state, "Call state changed");

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
                info!(call_id = %call_id, "Processing Connected state");

                // If audio session already exists (e.g. resume from hold),
                // skip starting a new one — the existing pipeline is still running.
                if self.audio_sessions.contains_key(call_id) {
                    info!(call_id = %call_id, "Audio session already active, skipping start");
                } else {
                    // Start media session establishment (ICE + DTLS) — only
                    // for TLS transport. Plain RTP calls (UDP/TCP) don't use
                    // ICE and establish() would always fail with "No ICE candidates".
                    let use_ice = self.account.as_ref().is_some_and(|a| {
                        matches!(a.transport, client_types::TransportPreference::TlsOnly)
                    });
                    if use_ice {
                        if let Some(session) = self.media_sessions.get_mut(call_id) {
                            info!(call_id = %call_id, "Found media session, attempting to establish");
                            if let Err(e) = session.establish(None).await {
                                warn!(call_id = %call_id, error = %e, "Failed to establish media");
                            }
                        } else {
                            warn!(call_id = %call_id, "No media session found for call");
                        }
                    } else {
                        debug!(call_id = %call_id, "Skipping ICE/DTLS for plain RTP call");
                    }

                    // Start audio session when call connects
                    // Get remote address from media session - either from ICE or from SDP parsing
                    let remote_addr = self.media_sessions.get(call_id).and_then(|session| {
                        // For non-ICE calls, remote_addr is set from SDP c=/m= lines
                        // For ICE calls, it's set after ICE connectivity check completes
                        let addr = session.remote_addr();
                        if addr.is_none() {
                            warn!(
                                call_id = %call_id,
                                "No remote media address available"
                            );
                        }
                        addr
                    });

                    if let Some(addr) = remote_addr {
                        info!(call_id = %call_id, remote_addr = %addr, "Starting audio session");
                        if let Err(e) = self.start_audio_session(call_id, addr).await {
                            warn!(call_id = %call_id, error = %e, "Failed to start audio");
                        }
                    } else {
                        error!(call_id = %call_id, "Cannot start audio: no remote address");
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

                // Clean up negotiated codec, effective media address, and dialog tracking
                self.negotiated_codecs.remove(call_id);
                self.effective_media_addrs.remove(call_id);
                self.active_call_dialogs.remove(call_id);

                // Record in call history
                let end_reason = call_info
                    .failure_reason
                    .as_ref()
                    .map_or(CallEndReason::RemoteHangup, |_| CallEndReason::Failed);

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
        info!(call_id = %call_id, state = ?state, "Queueing CallStateChanged event");
        if let Err(e) = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.to_string(),
                state,
                info: call_info,
            })
            .await
        {
            error!(error = %e, "Failed to queue CallStateChanged event");
        }

        Ok(())
    }

    async fn handle_sdp_answer(&mut self, call_id: &str, sdp: &str) -> AppResult<()> {
        debug!(call_id = %call_id, "Received SDP answer");

        // Remember the previous codec to detect mid-call codec changes
        let previous_codec = self.negotiated_codecs.get(call_id).copied();

        // Parse the negotiated codec from the SDP answer
        if let Some(codec) = parse_codec_from_sdp(sdp) {
            // Validate codec is in our offer (RFC 3264 Section 6.1)
            let account = self
                .account
                .as_ref()
                .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

            if !self.is_codec_offered(codec, account) {
                return Err(AppError::Sip(format!(
                    "Remote party selected codec {codec:?} which was not in our offer"
                )));
            }

            info!(call_id = %call_id, codec = ?codec, "Negotiated codec from SDP answer");
            self.negotiated_codecs.insert(call_id.to_string(), codec);

            // Detect mid-call codec change: if the codec changed and we have a
            // running audio session, stop it so handle_state_changed(Connected)
            // will restart it with the new codec.
            if let Some(prev) = previous_codec
                && prev != codec
                && self.audio_sessions.contains_key(call_id)
            {
                info!(
                    call_id = %call_id,
                    from = ?prev,
                    to = ?codec,
                    "Codec changed via re-INVITE, restarting audio session"
                );
                if let Err(e) = self.stop_audio_session(call_id).await {
                    warn!(call_id = %call_id, error = %e, "Failed to stop audio session for codec change");
                }
            }
        } else {
            debug!(call_id = %call_id, "No codec found in SDP answer, will use preferred codec");
        }

        // Check if telephone-event was negotiated for DTMF support
        let dtmf_pt = parse_telephone_event_pt(sdp);
        self.telephone_event_pt.insert(call_id.to_string(), dtmf_pt);

        if let Some(pt) = dtmf_pt {
            info!(call_id = %call_id, pt = pt, "Remote supports RFC 2833/4733 telephone-event PT={pt}");
        } else {
            warn!(call_id = %call_id, "Remote does NOT support RFC 2833/4733 telephone-event");
        }

        // Check if RFC 2198 redundancy was negotiated
        let red_pt = parse_redundancy_pt(sdp);
        self.redundancy_pt.insert(call_id.to_string(), red_pt);
        if let Some(pt) = red_pt {
            info!(call_id = %call_id, pt = pt, "Remote supports RFC 2198 redundancy PT={pt}");
        }

        // Parse negotiated RTP header extensions (RFC 5285)
        let ext_ids = parse_extmap_attributes(sdp);
        if !ext_ids.is_empty() {
            info!(
                call_id = %call_id,
                count = ext_ids.len(),
                "Negotiated RTP header extensions"
            );
            for (id, uri) in &ext_ids {
                debug!(call_id = %call_id, id = id, uri = %uri, "Extension negotiated");
            }
        }
        self.negotiated_extension_ids
            .insert(call_id.to_string(), ext_ids);

        // Parse remote media address from SDP (c= and m= lines)
        // This is used for non-ICE calls where the remote specifies its address directly
        let remote_media_addr = parse_remote_media_addr_from_sdp(sdp);
        if let Some(addr) = remote_media_addr {
            info!(call_id = %call_id, remote_addr = %addr, "Parsed remote media address from SDP");
        }

        // Parse SDP and configure media session
        if let Some(session) = self.media_sessions.get_mut(call_id) {
            // Set the remote media address for non-ICE calls
            // This ensures we have a valid address even if ICE doesn't complete
            if let Some(addr) = remote_media_addr {
                session.set_remote_addr(addr);
            }

            // Extract ICE credentials from SDP (if present, this is a secure call)
            let ice_creds = parse_ice_credentials_from_sdp(sdp);
            let has_ice = ice_creds.is_some();

            if let Some(creds) = ice_creds {
                session.set_remote_ice_credentials(creds);

                // Extract ICE candidates from SDP
                for line in sdp.lines() {
                    if line.starts_with("a=candidate:")
                        && let Err(e) = session.add_remote_ice_candidate(line)
                    {
                        warn!(error = %e, "Failed to add remote ICE candidate");
                    }
                }

                // Start media session only for ICE/DTLS calls
                // For plain RTP calls, the AudioPipeline handles everything
                if let Err(e) = session.start().await {
                    error!(call_id = %call_id, error = %e, "Failed to start media session");
                }
            } else {
                debug!(call_id = %call_id, "Plain RTP call - skipping ICE/DTLS media session start");
            }

            // Log whether this is a secure or plain RTP call
            info!(call_id = %call_id, has_ice = has_ice, "SDP answer processed");
        }

        Ok(())
    }

    fn handle_sdp_offer(call_id: &str, sdp: &str) {
        debug!(call_id = %call_id, "Received SDP offer");

        // For incoming calls, we'd create a media session here
        // and generate an answer
        let _ = (call_id, sdp);
    }

    /// Handles transfer progress updates from REFER NOTIFYs (RFC 3515).
    async fn handle_transfer_progress(
        &self,
        call_id: &str,
        target_uri: &str,
        status: ReferStatus,
        is_final: bool,
    ) -> AppResult<()> {
        info!(
            call_id = %call_id,
            target = %target_uri,
            status = ?status,
            is_final = is_final,
            "Transfer progress update"
        );

        // Forward to application event handler
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::TransferProgress {
                call_id: call_id.to_string(),
                target_uri: target_uri.to_string(),
                status_code: status.status_code(),
                is_success: status == ReferStatus::Success,
                is_final,
            })
            .await;

        Ok(())
    }

    /// Validates that a codec was included in our SDP offer.
    /// Per RFC 3264 Section 6.1, the answer must only contain codecs from the offer.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    fn is_codec_offered(&self, codec: CodecPreference, account: &SipAccount) -> bool {
        // Check if we're using TLS/secure transport (determines which codecs we offer)
        let use_srtp = matches!(
            account.transport,
            client_types::TransportPreference::TlsOnly
        );

        if use_srtp {
            // SRTP offers: Opus (111), G.722 (9), PCMU (0), PCMA (8)
            matches!(
                codec,
                CodecPreference::Opus
                    | CodecPreference::G722
                    | CodecPreference::G711Ulaw
                    | CodecPreference::G711Alaw
            )
        } else {
            // Plain RTP offers: G.722 (9), PCMU (0), PCMA (8)
            matches!(
                codec,
                CodecPreference::G722 | CodecPreference::G711Ulaw | CodecPreference::G711Alaw
            )
        }
    }

    /// Gets the SDP session ID for a call, creating one if it doesn't exist.
    /// Per RFC 8866, the session ID must remain constant for the duration of the session.
    fn get_or_create_sdp_session_id(&mut self, call_id: &str) -> u64 {
        if let Some(&id) = self.sdp_session_ids.get(call_id) {
            id
        } else {
            let id = session_id();
            self.sdp_session_ids.insert(call_id.to_string(), id);
            // Initialize version to 1
            self.sdp_session_versions.insert(call_id.to_string(), 1);
            id
        }
    }

    /// Gets the current SDP session version for a call.
    /// Returns 1 if the call doesn't have a version yet.
    fn get_sdp_session_version(&self, call_id: &str) -> u64 {
        self.sdp_session_versions.get(call_id).copied().unwrap_or(1)
    }

    /// Increments the SDP session version for a call (used on re-INVITE).
    /// Per RFC 8866, the version must increment each time the SDP is modified.
    fn increment_sdp_session_version(&mut self, call_id: &str) {
        let version = self.sdp_session_versions.get(call_id).copied().unwrap_or(1);
        self.sdp_session_versions
            .insert(call_id.to_string(), version + 1);
    }

    #[allow(dead_code)]
    fn generate_sdp_offer(
        &mut self,
        call_id: &str,
        session: &MediaSession,
        account: &SipAccount,
    ) -> AppResult<String> {
        let effective_media_addr = self.get_effective_media_addr()?;
        let sdp_session_id = self.get_or_create_sdp_session_id(call_id);
        let sdp_session_version = self.get_sdp_session_version(call_id);
        Ok(self.generate_sdp_offer_with_addr(
            session,
            account,
            effective_media_addr,
            sdp_session_id,
            sdp_session_version,
        ))
    }

    #[allow(clippy::unused_self)]
    fn generate_sdp_offer_with_addr(
        &self,
        session: &MediaSession,
        account: &SipAccount,
        effective_media_addr: SocketAddr,
        sdp_session_id: u64,
        sdp_session_version: u64,
    ) -> String {
        let ssrc = session.local_ssrc();

        // Check if we're using TLS/secure transport
        let use_srtp = matches!(
            account.transport,
            client_types::TransportPreference::TlsOnly
        );

        // Generate SDP based on transport security
        if use_srtp {
            // Secure RTP with ICE and DTLS fingerprint
            let creds = session.local_ice_credentials();
            let fingerprint = session.local_dtls_fingerprint();

            let addr_type = sdp_addr_type(&effective_media_addr);
            format!(
                "v=0\r\n\
                 o=- {session_id} {session_version} IN {addr_type} {ip}\r\n\
                 s=USG SIP Client\r\n\
                 c=IN {addr_type} {ip}\r\n\
                 b=AS:100\r\n\
                 t=0 0\r\n\
                 m=audio {port} UDP/TLS/RTP/SAVPF 111 9 0 8 13 101 121\r\n\
                 a=rtpmap:111 opus/48000/2\r\n\
                 a=fmtp:111 minptime=20;useinbandfec=1;stereo=1\r\n\
                 a=rtpmap:9 G722/8000\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=rtpmap:13 CN/8000\r\n\
                 a=rtpmap:101 telephone-event/8000\r\n\
                 a=fmtp:101 0-16\r\n\
                 a=rtpmap:121 red/8000\r\n\
                 a=fmtp:121 0/0\r\n\
                 a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
                 a=ptime:20\r\n\
                 a=maxptime:120\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:sha-384 {fingerprint}\r\n\
                 a=setup:actpass\r\n\
                 a=mid:audio\r\n\
                 a=sendrecv\r\n\
                 a=rtcp-mux\r\n\
                 a=ssrc:{ssrc} cname:{cname}\r\n",
                session_id = sdp_session_id,
                session_version = sdp_session_version,
                addr_type = addr_type,
                ip = effective_media_addr.ip(),
                port = effective_media_addr.port(),
                ufrag = creds.ufrag,
                pwd = creds.pwd,
                fingerprint = fingerprint,
                ssrc = ssrc,
                cname = account.id,
            )
        } else {
            // Plain RTP (no SRTP, no ICE, no DTLS)
            let addr_type = sdp_addr_type(&effective_media_addr);
            format!(
                "v=0\r\n\
                 o=- {session_id} {session_version} IN {addr_type} {ip}\r\n\
                 s=USG SIP Client\r\n\
                 c=IN {addr_type} {ip}\r\n\
                 b=AS:80\r\n\
                 t=0 0\r\n\
                 m=audio {port} RTP/AVP 9 0 8 13 101 121\r\n\
                 a=rtpmap:9 G722/8000\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=rtpmap:13 CN/8000\r\n\
                 a=rtpmap:101 telephone-event/8000\r\n\
                 a=fmtp:101 0-16\r\n\
                 a=rtpmap:121 red/8000\r\n\
                 a=fmtp:121 0/0\r\n\
                 a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
                 a=ptime:20\r\n\
                 a=maxptime:120\r\n\
                 a=sendrecv\r\n\
                 a=ssrc:{ssrc} cname:{cname}\r\n",
                session_id = sdp_session_id,
                session_version = sdp_session_version,
                addr_type = addr_type,
                ip = effective_media_addr.ip(),
                port = effective_media_addr.port(),
                ssrc = ssrc,
                cname = account.id,
            )
        }
    }

    /// Gets the effective media address, discovering the local IP if needed.
    ///
    /// If `local_media_addr` is unspecified (0.0.0.0), discovers the actual
    /// local IP by creating a UDP socket. Also assigns an ephemeral port if
    /// the configured port is 0.
    fn get_effective_media_addr(&self) -> AppResult<SocketAddr> {
        if !self.local_media_addr.ip().is_unspecified() && self.local_media_addr.port() != 0 {
            return Ok(self.local_media_addr);
        }

        // Create a UDP socket to discover local IP and get an ephemeral port
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| AppError::Sip(format!("Failed to bind UDP socket: {e}")))?;

        // Connect to a public address to discover our local IP
        // Using Google's DNS as a well-known routable address
        socket
            .connect("8.8.8.8:53")
            .map_err(|e| AppError::Sip(format!("Failed to discover local IP: {e}")))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| AppError::Sip(format!("Failed to get local address: {e}")))?;

        info!(
            configured = %self.local_media_addr,
            effective = %local_addr,
            "Discovered effective media address"
        );

        Ok(local_addr)
    }

    /// Generates SDP for putting a call on hold (sendonly direction).
    fn generate_hold_sdp(&mut self, call_id: &str) -> AppResult<String> {
        self.generate_sdp_with_direction(call_id, "sendonly")
    }

    /// Generates SDP for resuming a call (sendrecv direction).
    fn generate_resume_sdp(&mut self, call_id: &str) -> AppResult<String> {
        self.generate_sdp_with_direction(call_id, "sendrecv")
    }

    /// Generates SDP for a codec change re-INVITE.
    ///
    /// Offers only the target codec (plus telephone-event and redundancy)
    /// to force the remote party to use the requested codec.
    fn generate_sdp_for_codec_change(
        &mut self,
        call_id: &str,
        codec: CodecPreference,
    ) -> AppResult<String> {
        let sdp_session_id = self.get_or_create_sdp_session_id(call_id);
        self.increment_sdp_session_version(call_id);
        let sdp_session_version = self.get_sdp_session_version(call_id);

        let session = self
            .media_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Sip("No media session for call".to_string()))?;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        let ssrc = session.local_ssrc();

        // Use the effective media addr already advertised for this call
        let effective_media_addr = self
            .effective_media_addrs
            .get(call_id)
            .copied()
            .ok_or_else(|| AppError::Sip("No effective media address for call".to_string()))?;

        let use_srtp = matches!(
            account.transport,
            client_types::TransportPreference::TlsOnly
        );

        let addr_type = sdp_addr_type(&effective_media_addr);

        // Build codec-specific m= line and rtpmap attributes
        let (codec_pts, codec_rtpmap, codec_fmtp) = match codec {
            CodecPreference::Opus => (
                "111",
                "a=rtpmap:111 opus/48000/2\r\n",
                "a=fmtp:111 minptime=20;useinbandfec=1;stereo=1\r\n",
            ),
            CodecPreference::G722 => ("9", "a=rtpmap:9 G722/8000\r\n", ""),
            CodecPreference::G711Ulaw => ("0", "a=rtpmap:0 PCMU/8000\r\n", ""),
            CodecPreference::G711Alaw => ("8", "a=rtpmap:8 PCMA/8000\r\n", ""),
        };

        let profile = if use_srtp {
            "UDP/TLS/RTP/SAVPF"
        } else {
            "RTP/AVP"
        };

        // Build m= line: codec PT + CN(13) + telephone-event(101) + red(121)
        let m_line = format!(
            "m=audio {port} {profile} {codec_pts} 13 101 121\r\n",
            port = effective_media_addr.port(),
        );

        let mut sdp = format!(
            "v=0\r\n\
             o=- {session_id} {session_version} IN {addr_type} {ip}\r\n\
             s=USG SIP Client\r\n\
             c=IN {addr_type} {ip}\r\n\
             b=AS:80\r\n\
             t=0 0\r\n\
             {m_line}\
             {codec_rtpmap}\
             {codec_fmtp}\
             a=rtpmap:13 CN/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n\
             a=fmtp:101 0-16\r\n\
             a=rtpmap:121 red/8000\r\n\
             a=fmtp:121 0/0\r\n\
             a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
             a=ptime:20\r\n\
             a=maxptime:120\r\n",
            session_id = sdp_session_id,
            session_version = sdp_session_version,
            addr_type = addr_type,
            ip = effective_media_addr.ip(),
        );

        // Add ICE/DTLS attributes for secure calls
        if use_srtp {
            use std::fmt::Write as _;
            let creds = session.local_ice_credentials();
            let fingerprint = session.local_dtls_fingerprint();
            let _ = write!(
                sdp,
                "a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:sha-384 {fingerprint}\r\n\
                 a=setup:actpass\r\n\
                 a=mid:audio\r\n\
                 a=rtcp-mux\r\n",
                ufrag = creds.ufrag,
                pwd = creds.pwd,
            );
        }

        sdp.push_str("a=sendrecv\r\n");
        {
            use std::fmt::Write as _;
            let _ = write!(sdp, "a=ssrc:{ssrc} cname:{cname}\r\n", cname = account.id);
        }

        Ok(sdp)
    }

    /// Generates SDP with the specified media direction.
    fn generate_sdp_with_direction(&mut self, call_id: &str, direction: &str) -> AppResult<String> {
        // Get session ID and increment version for re-INVITE (RFC 8866 Section 5.2)
        // MUST do this before borrowing session to avoid borrow checker issues
        let sdp_session_id = self.get_or_create_sdp_session_id(call_id);
        self.increment_sdp_session_version(call_id);
        let sdp_session_version = self.get_sdp_session_version(call_id);

        let session = self
            .media_sessions
            .get(call_id)
            .ok_or_else(|| AppError::Sip("No media session for call".to_string()))?;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        let ssrc = session.local_ssrc();

        // Prefer the stored media address (from initial SDP) so re-INVITEs
        // and hold/resume advertise the same port as the active RTP session.
        let effective_media_addr = self
            .effective_media_addrs
            .get(call_id)
            .copied()
            .map_or_else(|| self.get_effective_media_addr(), Ok)?;

        // Check if we're using TLS/secure transport
        let use_srtp = matches!(
            account.transport,
            client_types::TransportPreference::TlsOnly
        );

        // Generate SDP based on transport security
        let addr_type = sdp_addr_type(&effective_media_addr);
        let sdp = if use_srtp {
            // Secure RTP with ICE and DTLS fingerprint
            let creds = session.local_ice_credentials();
            let fingerprint = session.local_dtls_fingerprint();

            format!(
                "v=0\r\n\
                 o=- {session_id} {session_version} IN {addr_type} {ip}\r\n\
                 s=USG SIP Client\r\n\
                 c=IN {addr_type} {ip}\r\n\
                 b=AS:100\r\n\
                 t=0 0\r\n\
                 m=audio {port} UDP/TLS/RTP/SAVPF 111 9 0 8 13 101 121\r\n\
                 a=rtpmap:111 opus/48000/2\r\n\
                 a=fmtp:111 minptime=20;useinbandfec=1;stereo=1\r\n\
                 a=rtpmap:9 G722/8000\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=rtpmap:13 CN/8000\r\n\
                 a=rtpmap:101 telephone-event/8000\r\n\
                 a=fmtp:101 0-16\r\n\
                 a=rtpmap:121 red/8000\r\n\
                 a=fmtp:121 0/0\r\n\
                 a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
                 a=ptime:20\r\n\
                 a=maxptime:120\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:sha-384 {fingerprint}\r\n\
                 a=setup:actpass\r\n\
                 a=mid:audio\r\n\
                 a={direction}\r\n\
                 a=rtcp-mux\r\n\
                 a=ssrc:{ssrc} cname:{cname}\r\n",
                session_id = sdp_session_id,
                session_version = sdp_session_version,
                addr_type = addr_type,
                ip = effective_media_addr.ip(),
                port = effective_media_addr.port(),
                ufrag = creds.ufrag,
                pwd = creds.pwd,
                fingerprint = fingerprint,
                direction = direction,
                ssrc = ssrc,
                cname = account.id,
            )
        } else {
            // Plain RTP (no SRTP, no ICE, no DTLS)
            format!(
                "v=0\r\n\
                 o=- {session_id} {session_version} IN {addr_type} {ip}\r\n\
                 s=USG SIP Client\r\n\
                 c=IN {addr_type} {ip}\r\n\
                 b=AS:80\r\n\
                 t=0 0\r\n\
                 m=audio {port} RTP/AVP 9 0 8 13 101 121\r\n\
                 a=rtpmap:9 G722/8000\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=rtpmap:13 CN/8000\r\n\
                 a=rtpmap:101 telephone-event/8000\r\n\
                 a=fmtp:101 0-16\r\n\
                 a=rtpmap:121 red/8000\r\n\
                 a=fmtp:121 0/0\r\n\
                 a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
                 a=ptime:20\r\n\
                 a=maxptime:120\r\n\
                 a={direction}\r\n\
                 a=ssrc:{ssrc} cname:{cname}\r\n",
                session_id = sdp_session_id,
                session_version = sdp_session_version,
                addr_type = addr_type,
                ip = effective_media_addr.ip(),
                port = effective_media_addr.port(),
                direction = direction,
                ssrc = ssrc,
                cname = account.id,
            )
        };

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
/// Returns (`display_name`, uri) where `display_name` is None if not present.
fn parse_from_header(from_value: &str) -> (Option<String>, String) {
    let trimmed = from_value.trim();

    // Check for display name in quotes
    if let Some(quote_end) = trimmed.strip_prefix('"').and_then(|s| s.find('"')) {
        let display_name = trimmed[1..=quote_end].to_string();
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

/// Parses the telephone-event payload type from an SDP body.
///
/// Looks for `a=rtpmap:<N> telephone-event/8000` and verifies the payload
/// type is also listed in the `m=audio` line. Returns the dynamic PT number
/// (commonly 101, but can be any value 96-127).
///
/// # Arguments
/// * `sdp` - The SDP answer or offer string
///
/// # Returns
/// `Some(pt)` if telephone-event is supported, `None` otherwise
fn parse_telephone_event_pt(sdp: &str) -> Option<u8> {
    // First, find a=rtpmap:<N> telephone-event and extract the PT
    let mut candidate_pt: Option<u8> = None;
    let mut media_line_pts = String::new();

    for line in sdp.lines() {
        // Capture the m=audio line for cross-checking
        if line.starts_with("m=audio") {
            media_line_pts = line.to_string();
        }

        // Look for: a=rtpmap:<N> telephone-event/8000
        if let Some(rest) = line.strip_prefix("a=rtpmap:")
            && rest.contains("telephone-event")
        {
            // Extract PT number from "101 telephone-event/8000"
            if let Some(pt_str) = rest.split_whitespace().next()
                && let Ok(pt) = pt_str.parse::<u8>()
            {
                candidate_pt = Some(pt);
            }
        }
    }

    // Cross-check: the PT must also appear in the m=audio line
    let pt = candidate_pt?;
    let pt_token = format!(" {pt}");
    if media_line_pts.contains(&pt_token) {
        Some(pt)
    } else {
        None
    }
}

/// Parses the RFC 2198 redundancy payload type from an SDP body.
///
/// Looks for `a=rtpmap:<N> red/8000` (or `red/<clock>`) and verifies the
/// payload type is also listed in the `m=audio` line. Returns the dynamic
/// PT number (commonly 121, but can be any value 96-127).
fn parse_redundancy_pt(sdp: &str) -> Option<u8> {
    let mut candidate_pt: Option<u8> = None;
    let mut media_line_pts = String::new();

    for line in sdp.lines() {
        if line.starts_with("m=audio") {
            media_line_pts = line.to_string();
        }

        // Look for: a=rtpmap:<N> red/<clock>
        if let Some(rest) = line.strip_prefix("a=rtpmap:")
            && (rest.trim().contains("red/") || rest.trim().contains("RED/"))
        {
            let rest = rest.trim();
            if let Some(pt_str) = rest.split_whitespace().next()
                && let Ok(pt) = pt_str.parse::<u8>()
            {
                candidate_pt = Some(pt);
            }
        }
    }

    // Cross-check: the PT must also appear in the m=audio line
    let pt = candidate_pt?;
    let pt_token = format!(" {pt}");
    if media_line_pts.contains(&pt_token) {
        Some(pt)
    } else {
        None
    }
}

/// Parses `a=extmap` attributes from an SDP body.
///
/// Returns a list of `(id, uri)` pairs for negotiated RTP header extensions.
/// Only includes extensions we support (currently: ssrc-audio-level).
///
/// Format: `a=extmap:<id>[/<direction>] <URI> [<extensionattributes>]`
fn parse_extmap_attributes(sdp: &str) -> Vec<(u8, String)> {
    /// Extension URIs we support.
    const SUPPORTED_URIS: &[&str] = &["urn:ietf:params:rtp-hdrext:ssrc-audio-level"];

    let mut extensions = Vec::new();

    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("a=extmap:") {
            let rest = rest.trim();
            // Split into id_part and URI (+ optional attrs)
            if let Some((id_part, uri_part)) = rest.split_once(' ') {
                // Parse ID (strip optional direction suffix like "1/sendrecv")
                let id_str = id_part.split('/').next().unwrap_or(id_part);
                if let Ok(id) = id_str.parse::<u8>() {
                    // Extract just the URI (first token of the rest)
                    let uri = uri_part.split_whitespace().next().unwrap_or(uri_part);
                    // Only include extensions we support
                    if SUPPORTED_URIS.contains(&uri) {
                        extensions.push((id, uri.to_string()));
                    }
                }
            }
        }
    }

    extensions
}

/// Parses a `application/dtmf-relay` body from a SIP INFO request.
///
/// Expected format:
/// ```text
/// Signal=5
/// Duration=160
/// ```
///
/// Returns `(digit, duration)` on success, or `None` if the body lacks a `Signal=` field.
fn parse_dtmf_relay_body(body: &str) -> Option<(char, u16)> {
    let mut digit: Option<char> = None;
    let mut duration: u16 = 160; // default ~20ms at 8kHz

    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("Signal=")
            .or_else(|| line.strip_prefix("signal="))
        {
            let rest = rest.trim();
            if let Some(ch) = rest.chars().next() {
                digit = Some(ch);
            }
        } else if let Some(rest) = line
            .strip_prefix("Duration=")
            .or_else(|| line.strip_prefix("duration="))
        {
            let rest = rest.trim();
            if let Ok(d) = rest.parse::<u16>() {
                duration = d;
            }
        }
    }

    digit.map(|d| (d, duration))
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
            if parts.len() >= 2
                && let Ok(pt) = parts[0].parse::<u8>()
            {
                // Get the encoding name (before the /)
                let codec_name = parts[1].split('/').next().unwrap_or("");
                rtpmaps.push((pt, codec_name.to_string()));
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

/// Parses all offered codecs from an SDP body and selects the best match.
///
/// Unlike `parse_codec_from_sdp` (which takes just the first PT), this
/// function builds the full list of offered codecs, then picks the one
/// that best matches our local preference order:
///   1. Our preferred codec (if offered)
///   2. Remaining codecs in *our* preference order
///
/// This implements RFC 3264 §6.1 answerer behaviour: the answerer selects
/// the best codec from the intersection of offered and supported codecs.
fn negotiate_codec_from_sdp_offer(
    sdp: &str,
    preferred: CodecPreference,
) -> Option<CodecPreference> {
    let mut payload_types: Vec<u8> = Vec::new();
    let mut rtpmaps: Vec<(u8, String)> = Vec::new();

    for line in sdp.lines() {
        if line.starts_with("m=audio") {
            // Parse all payload types from the m= line
            let parts: Vec<&str> = line.split_whitespace().collect();
            for pt_str in parts.iter().skip(3) {
                if let Ok(pt) = pt_str.parse::<u8>() {
                    payload_types.push(pt);
                }
            }
        }
        if let Some(rtpmap) = line.strip_prefix("a=rtpmap:") {
            let parts: Vec<&str> = rtpmap.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(pt) = parts[0].parse::<u8>()
            {
                let codec_name = parts[1].split('/').next().unwrap_or("");
                rtpmaps.push((pt, codec_name.to_string()));
            }
        }
    }

    // Resolve each offered PT to a CodecPreference
    let mut offered_codecs: Vec<CodecPreference> = Vec::new();
    for pt in &payload_types {
        let codec = match *pt {
            0 => Some(CodecPreference::G711Ulaw),
            8 => Some(CodecPreference::G711Alaw),
            9 => Some(CodecPreference::G722),
            _ => {
                // Look up dynamic PT in rtpmaps
                rtpmaps
                    .iter()
                    .find(|(rpt, _)| rpt == pt)
                    .and_then(|(_, name)| {
                        let lower = name.to_lowercase();
                        if lower == "pcmu" {
                            Some(CodecPreference::G711Ulaw)
                        } else if lower == "pcma" {
                            Some(CodecPreference::G711Alaw)
                        } else if lower == "g722" {
                            Some(CodecPreference::G722)
                        } else if lower == "opus" {
                            Some(CodecPreference::Opus)
                        } else {
                            None
                        }
                    })
            }
        };
        if let Some(c) = codec
            && !offered_codecs.contains(&c)
        {
            offered_codecs.push(c);
        }
    }

    if offered_codecs.is_empty() {
        return None;
    }

    // Prefer our preferred codec if the remote offers it
    if offered_codecs.contains(&preferred) {
        return Some(preferred);
    }

    // Fall back to our preference order
    let our_order = [
        CodecPreference::Opus,
        CodecPreference::G722,
        CodecPreference::G711Ulaw,
        CodecPreference::G711Alaw,
    ];
    for candidate in &our_order {
        if offered_codecs.contains(candidate) {
            return Some(*candidate);
        }
    }

    None
}

/// Parses the remote media address from an SDP answer.
///
/// Extracts the connection address from the c= line and the port from the m=audio line.
/// This is used for non-ICE calls where the remote endpoint specifies its
/// media address directly in the SDP.
///
/// # Arguments
/// * `sdp` - The SDP answer string
///
/// # Returns
/// The remote media socket address, or None if not found or invalid
fn parse_remote_media_addr_from_sdp(sdp: &str) -> Option<SocketAddr> {
    let mut connection_ip: Option<std::net::IpAddr> = None;
    let mut audio_port: Option<u16> = None;

    for line in sdp.lines() {
        // Parse connection line: c=IN IP4 <address> or c=IN IP6 <address>
        if line.starts_with("c=IN IP4 ") {
            let addr_str = line.strip_prefix("c=IN IP4 ")?.trim();
            connection_ip = addr_str.parse().ok();
        } else if line.starts_with("c=IN IP6 ") {
            let addr_str = line.strip_prefix("c=IN IP6 ")?.trim();
            connection_ip = addr_str.parse().ok();
        }
        // Parse media line: m=audio <port> <proto> <fmt>...
        else if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                audio_port = parts[1].parse().ok();
            }
        }
    }

    match (connection_ip, audio_port) {
        (Some(ip), Some(port)) if port > 0 => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// Extracts the media direction attribute from SDP.
///
/// Looks for `a=sendrecv`, `a=sendonly`, `a=recvonly`, or `a=inactive`.
/// Defaults to `"sendrecv"` per RFC 3264 Section 5 if no direction attribute is present.
fn parse_media_direction(sdp: &str) -> &'static str {
    for line in sdp.lines() {
        let trimmed = line.trim();
        match trimmed {
            "a=sendonly" => return "sendonly",
            "a=recvonly" => return "recvonly",
            "a=sendrecv" => return "sendrecv",
            "a=inactive" => return "inactive",
            _ => {}
        }
    }
    "sendrecv"
}

/// Generates a unique session ID for SDP per RFC 8866 Section 5.2.
///
/// Uses NTP timestamp format for better uniqueness:
/// - High 32 bits: seconds since Jan 1, 1970 (UNIX epoch)
/// - Low 32 bits: fractional seconds (nanoseconds scaled to 2^32)
///
/// This provides much better collision resistance than millisecond timestamps.
#[allow(clippy::cast_possible_truncation)]
fn session_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    // Convert nanoseconds to NTP fractional format (scaled to 2^32)
    // nanos is 0..1_000_000_000, we want 0..4_294_967_296
    let frac = ((u64::from(nanos) * 0x1_0000_0000) / 1_000_000_000) as u32;

    // Combine: high 32 bits = seconds, low 32 bits = fractional
    (secs << 32) | u64::from(frac)
}

/// Returns SDP address type string for a socket address (RFC 8866 Section 5.7).
///
/// Returns `"IP4"` for IPv4 addresses or `"IP6"` for IPv6 addresses.
const fn sdp_addr_type(addr: &SocketAddr) -> &'static str {
    if addr.is_ipv4() { "IP4" } else { "IP6" }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
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

    #[test]
    fn test_parse_remote_media_addr_from_sdp_ipv4() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.100\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.100\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";

        let addr = parse_remote_media_addr_from_sdp(sdp).unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 49170);
    }

    #[test]
    fn test_parse_remote_media_addr_from_sdp_different_port() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 10.0.0.1\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 5060 RTP/AVP 0\r\n";

        let addr = parse_remote_media_addr_from_sdp(sdp).unwrap();
        assert_eq!(addr.ip().to_string(), "10.0.0.1");
        assert_eq!(addr.port(), 5060);
    }

    #[test]
    fn test_parse_remote_media_addr_from_sdp_no_connection() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.100\r\n\
                   s=-\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        assert!(parse_remote_media_addr_from_sdp(sdp).is_none());
    }

    #[test]
    fn test_parse_remote_media_addr_from_sdp_no_audio() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.100\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.100\r\n\
                   t=0 0\r\n";

        assert!(parse_remote_media_addr_from_sdp(sdp).is_none());
    }

    #[test]
    fn test_parse_remote_media_addr_from_sdp_zero_port() {
        // Port 0 means media is declined
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.100\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.100\r\n\
                   t=0 0\r\n\
                   m=audio 0 RTP/AVP 0\r\n";

        assert!(parse_remote_media_addr_from_sdp(sdp).is_none());
    }

    #[test]
    fn test_parse_telephone_event_pt_standard() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8 101\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:101 telephone-event/8000\r\n\
                   a=fmtp:101 0-16\r\n";

        assert_eq!(parse_telephone_event_pt(sdp), Some(101));
    }

    #[test]
    fn test_parse_telephone_event_pt_non_standard() {
        // Some providers use PT=96 or PT=100
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 96\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:96 telephone-event/8000\r\n";

        assert_eq!(parse_telephone_event_pt(sdp), Some(96));
    }

    #[test]
    fn test_parse_telephone_event_pt_missing() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";

        assert_eq!(parse_telephone_event_pt(sdp), None);
    }

    #[test]
    fn test_parse_telephone_event_pt_rtpmap_but_not_in_media_line() {
        // rtpmap present but PT not in m= line
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.168.1.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.168.1.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:101 telephone-event/8000\r\n";

        assert_eq!(parse_telephone_event_pt(sdp), None);
    }

    #[test]
    fn test_parse_dtmf_relay_body_standard() {
        let body = "Signal=5\r\nDuration=800\r\n";
        let (digit, duration) = parse_dtmf_relay_body(body).unwrap();
        assert_eq!(digit, '5');
        assert_eq!(duration, 800);
    }

    #[test]
    fn test_parse_dtmf_relay_body_lowercase() {
        let body = "signal=*\r\nduration=160\r\n";
        let (digit, duration) = parse_dtmf_relay_body(body).unwrap();
        assert_eq!(digit, '*');
        assert_eq!(duration, 160);
    }

    #[test]
    fn test_parse_dtmf_relay_body_missing_signal() {
        let body = "Duration=800\r\n";
        assert!(parse_dtmf_relay_body(body).is_none());
    }

    #[test]
    fn test_parse_dtmf_relay_body_signal_only() {
        // Duration defaults to 160 when missing
        let body = "Signal=#\r\n";
        let (digit, duration) = parse_dtmf_relay_body(body).unwrap();
        assert_eq!(digit, '#');
        assert_eq!(duration, 160);
    }

    // ── RFC 2198 redundancy PT parsing ──────────────────────────────

    #[test]
    fn test_parse_redundancy_pt_standard() {
        let sdp = "\
v=0\r\n\
o=- 1234 5678 IN IP4 10.0.0.1\r\n\
s=-\r\n\
c=IN IP4 10.0.0.1\r\n\
m=audio 10000 RTP/AVP 0 121 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:121 red/8000\r\n\
a=fmtp:121 0/0\r\n\
a=rtpmap:101 telephone-event/8000\r\n";
        assert_eq!(parse_redundancy_pt(sdp), Some(121));
    }

    #[test]
    fn test_parse_redundancy_pt_different_pt() {
        let sdp = "\
m=audio 5000 RTP/AVP 0 96 101\r\n\
a=rtpmap:96 red/8000\r\n\
a=fmtp:96 0/0\r\n";
        assert_eq!(parse_redundancy_pt(sdp), Some(96));
    }

    #[test]
    fn test_parse_redundancy_pt_case_insensitive() {
        let sdp = "\
m=audio 5000 RTP/AVP 0 121\r\n\
a=rtpmap:121 RED/8000\r\n";
        assert_eq!(parse_redundancy_pt(sdp), Some(121));
    }

    #[test]
    fn test_parse_redundancy_pt_not_in_m_line() {
        // rtpmap present but PT not listed in m= line → None
        let sdp = "\
m=audio 5000 RTP/AVP 0 101\r\n\
a=rtpmap:121 red/8000\r\n";
        assert_eq!(parse_redundancy_pt(sdp), None);
    }

    #[test]
    fn test_parse_redundancy_pt_absent() {
        let sdp = "\
m=audio 5000 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n";
        assert_eq!(parse_redundancy_pt(sdp), None);
    }

    // ── SDP offer codec negotiation ─────────────────────────────

    #[test]
    fn test_negotiate_preferred_codec_offered() {
        // Remote offers PCMU and PCMA, we prefer PCMU → pick PCMU
        let sdp = "\
m=audio 5000 RTP/AVP 8 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::G711Ulaw),
            Some(CodecPreference::G711Ulaw)
        );
    }

    #[test]
    fn test_negotiate_preferred_not_offered_fallback() {
        // Remote offers only PCMA and PCMU, we prefer Opus → fallback to G722? No, G711Ulaw
        let sdp = "\
m=audio 5000 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::Opus),
            Some(CodecPreference::G711Ulaw) // highest in our preference order that's offered
        );
    }

    #[test]
    fn test_negotiate_opus_from_dynamic_pt() {
        // Remote offers Opus as dynamic PT 111
        let sdp = "\
m=audio 5000 RTP/AVP 111 0 8\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::G711Ulaw),
            Some(CodecPreference::G711Ulaw) // we prefer PCMU and it's offered
        );
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::Opus),
            Some(CodecPreference::Opus) // we prefer Opus and it's offered
        );
    }

    #[test]
    fn test_negotiate_g722_preferred() {
        let sdp = "\
m=audio 5000 RTP/AVP 9 0\r\n\
a=rtpmap:9 G722/8000\r\n\
a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::G722),
            Some(CodecPreference::G722)
        );
    }

    #[test]
    fn test_negotiate_no_supported_codecs() {
        // Remote offers only an unknown codec
        let sdp = "\
m=audio 5000 RTP/AVP 96\r\n\
a=rtpmap:96 speex/16000\r\n";
        assert_eq!(
            negotiate_codec_from_sdp_offer(sdp, CodecPreference::G711Ulaw),
            None
        );
    }

    #[test]
    fn test_negotiate_empty_sdp() {
        assert_eq!(
            negotiate_codec_from_sdp_offer("", CodecPreference::G711Ulaw),
            None
        );
    }

    #[tokio::test]
    async fn test_is_codec_offered_plain_rtp_includes_g722() {
        // Plain RTP offers G.722 (9), PCMU (0), PCMA (8) in SDP
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();
        let manager = CallManager::new(sip_addr, media_addr, tx);

        let mut account = SipAccount::default();
        account.transport = client_types::TransportPreference::Udp;

        assert!(manager.is_codec_offered(CodecPreference::G722, &account));
        assert!(manager.is_codec_offered(CodecPreference::G711Ulaw, &account));
        assert!(manager.is_codec_offered(CodecPreference::G711Alaw, &account));
        // Opus not offered on plain RTP
        assert!(!manager.is_codec_offered(CodecPreference::Opus, &account));
    }

    #[tokio::test]
    async fn test_is_codec_offered_srtp_includes_all() {
        // SRTP offers Opus (111), G.722 (9), PCMU (0), PCMA (8)
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();
        let manager = CallManager::new(sip_addr, media_addr, tx);

        let account = SipAccount::default(); // TlsOnly by default

        assert!(manager.is_codec_offered(CodecPreference::Opus, &account));
        assert!(manager.is_codec_offered(CodecPreference::G722, &account));
        assert!(manager.is_codec_offered(CodecPreference::G711Ulaw, &account));
        assert!(manager.is_codec_offered(CodecPreference::G711Alaw, &account));
    }

    #[test]
    fn test_codec_change_detected_in_sdp_answer() {
        // Verify parse_codec_from_sdp correctly identifies different codecs
        // This tests the codec detection that drives audio session restart
        let sdp_g711 = "\
m=audio 5000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(
            parse_codec_from_sdp(sdp_g711),
            Some(CodecPreference::G711Ulaw)
        );

        let sdp_g722 = "\
m=audio 5000 RTP/AVP 9\r\n\
a=rtpmap:9 G722/8000\r\n";
        assert_eq!(parse_codec_from_sdp(sdp_g722), Some(CodecPreference::G722));

        let sdp_alaw = "\
m=audio 5000 RTP/AVP 8\r\n\
a=rtpmap:8 PCMA/8000\r\n";
        assert_eq!(
            parse_codec_from_sdp(sdp_alaw),
            Some(CodecPreference::G711Alaw)
        );

        // Codecs are distinct — change detection works
        assert_ne!(
            parse_codec_from_sdp(sdp_g711),
            parse_codec_from_sdp(sdp_g722)
        );
    }

    // ── RFC 5285 extmap parsing tests ─────────────────────────────

    #[test]
    fn test_parse_extmap_audio_level() {
        let sdp = "\
v=0\r\n\
o=- 1234 1 IN IP4 10.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
a=sendrecv\r\n";

        let exts = parse_extmap_attributes(sdp);
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].0, 1);
        assert_eq!(exts[0].1, "urn:ietf:params:rtp-hdrext:ssrc-audio-level");
    }

    #[test]
    fn test_parse_extmap_with_direction() {
        let sdp = "\
m=audio 5004 RTP/AVP 0\r\n\
a=extmap:2/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n";

        let exts = parse_extmap_attributes(sdp);
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].0, 2);
    }

    #[test]
    fn test_parse_extmap_unsupported_ignored() {
        let sdp = "\
m=audio 5004 RTP/AVP 0\r\n\
a=extmap:3 urn:ietf:params:rtp-hdrext:toffset\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n";

        let exts = parse_extmap_attributes(sdp);
        // toffset is not in our supported list
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].0, 1);
    }

    #[test]
    fn test_parse_extmap_none() {
        let sdp = "\
m=audio 5004 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";

        let exts = parse_extmap_attributes(sdp);
        assert!(exts.is_empty());
    }
}
