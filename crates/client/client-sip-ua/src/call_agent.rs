//! SIP Call Agent.
//!
//! Handles call control including INVITE, BYE, CANCEL transactions.
//! Uses mutual TLS with smart card certificates for authentication.

use crate::{SipUaError, SipUaResult};
use chrono::Utc;
use client_types::{CallDirection, CallFailureReason, CallInfo, CallState, DtmfDigit};
use proto_dialog::Dialog;
use proto_dialog::refer::{ReferRequest, ReferStatus};
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id, generate_tag};
use proto_sip::header::HeaderName;
use proto_sip::header_params::{NameAddr, ViaHeader};
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::uri::SipUri;
use proto_transaction::client::{ClientInviteTransaction, ClientNonInviteTransaction};
use proto_transaction::{TransactionKey, TransportType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// User agent string for SIP messages.
const USER_AGENT: &str = "USG-SIP-Client/0.1.0";

/// Call agent handles outbound and inbound calls.
pub struct CallAgent {
    /// Active calls by call ID.
    calls: HashMap<String, CallSession>,
    /// Event sender for call state changes.
    event_tx: mpsc::Sender<CallEvent>,
    /// Local address for Via/Contact headers.
    local_addr: SocketAddr,
    /// Our SIP URI (address of record).
    aor: String,
    /// Display name for From header.
    display_name: String,
    /// Transport type for SIP signaling (UDP, TCP, or TLS).
    transport_type: String,
}

/// State for a single call session.
struct CallSession {
    /// Unique call ID for application tracking.
    id: String,
    /// SIP Call-ID header value.
    sip_call_id: String,
    /// Current call state.
    state: CallState,
    /// SIP dialog (once established).
    #[allow(dead_code)]
    dialog: Option<Dialog>,
    /// Active INVITE transaction (if any).
    invite_transaction: Option<ClientInviteTransaction>,
    /// Active non-INVITE transaction (if any, e.g., BYE, CANCEL).
    #[allow(dead_code)]
    non_invite_transaction: Option<ClientNonInviteTransaction>,
    /// From tag.
    from_tag: String,
    /// To tag (from remote).
    to_tag: Option<String>,
    /// `CSeq` number.
    cseq: u32,
    /// Remote party URI.
    remote_uri: String,
    /// Remote party display name.
    remote_display_name: Option<String>,
    /// Whether this is an outbound call.
    is_outbound: bool,
    /// Local SDP offer (if sent).
    #[allow(dead_code)]
    local_sdp: Option<String>,
    /// Remote SDP answer/offer (if received).
    remote_sdp: Option<String>,
    /// Call start time (when call was initiated).
    start_time: chrono::DateTime<Utc>,
    /// Call connect time (when Connected).
    connected_at: Option<Instant>,
    /// Last branch parameter.
    last_branch: Option<String>,
    /// Failure reason if the call failed.
    failure_reason: Option<CallFailureReason>,
    /// Active REFER request for call transfer (RFC 3515).
    refer_request: Option<ReferRequest>,
    /// Transfer target URI when transfer is in progress.
    transfer_target: Option<String>,
}

/// Events emitted by the call agent.
#[derive(Debug, Clone)]
pub enum CallEvent {
    /// Call state changed.
    StateChanged {
        /// Call ID.
        call_id: String,
        /// New state.
        state: CallState,
        /// Call info (if available).
        info: Option<CallInfo>,
    },
    /// Need to send a SIP request.
    SendRequest {
        /// The SIP request to send.
        request: SipRequest,
        /// Destination address.
        destination: SocketAddr,
    },
    /// Need to send a SIP response.
    #[allow(dead_code)]
    SendResponse {
        /// The SIP response to send.
        response: SipResponse,
        /// Destination address.
        destination: SocketAddr,
    },
    /// SDP offer received, need to provide answer.
    #[allow(dead_code)]
    SdpOfferReceived {
        /// Call ID.
        call_id: String,
        /// SDP offer content.
        sdp: String,
    },
    /// SDP answer received, can start media.
    SdpAnswerReceived {
        /// Call ID.
        call_id: String,
        /// SDP answer content.
        sdp: String,
    },
    /// Transfer progress update (RFC 3515 REFER NOTIFY).
    TransferProgress {
        /// Call ID being transferred.
        call_id: String,
        /// Transfer target URI.
        target_uri: String,
        /// Transfer status (Trying, Ringing, Success, Failed).
        status: ReferStatus,
        /// Whether this is the final status.
        is_final: bool,
    },
}

impl CallAgent {
    /// Creates a new call agent.
    pub fn new(
        local_addr: SocketAddr,
        aor: String,
        display_name: String,
        event_tx: mpsc::Sender<CallEvent>,
    ) -> Self {
        Self {
            calls: HashMap::new(),
            event_tx,
            local_addr,
            aor,
            display_name,
            transport_type: "TLS".to_string(), // Default to TLS, updated by configure()
        }
    }

    /// Configures the agent with account information.
    ///
    /// # Arguments
    /// * `aor` - Address of Record (SIP URI for the account)
    /// * `display_name` - Display name for From header
    /// * `caller_id` - Optional Caller ID to use instead of the AOR user part
    /// * `transport` - Transport type string ("UDP", "TCP", or "TLS")
    pub fn configure(
        &mut self,
        aor: String,
        display_name: String,
        caller_id: Option<String>,
        transport: &str,
    ) {
        // If caller_id is provided, replace the user part of the AOR
        self.aor = if let Some(cid) = caller_id {
            // Parse the AOR and replace the user part
            if let Some(at_pos) = aor.find('@') {
                let scheme_end = aor.find(':').map_or(0, |p| p + 1);
                format!("{}{cid}{}", &aor[..scheme_end], &aor[at_pos..])
            } else {
                aor
            }
        } else {
            aor
        };
        self.display_name = display_name;
        self.transport_type = transport.to_uppercase();
        info!(
            aor = %self.aor,
            display_name = %self.display_name,
            transport = %self.transport_type,
            "Call agent configured"
        );
    }

    /// Makes an outbound call.
    ///
    /// Returns the call ID for tracking.
    pub async fn make_call(&mut self, remote_uri: &str, sdp_offer: &str) -> SipUaResult<String> {
        // Verify agent is configured
        if self.aor.is_empty() {
            return Err(SipUaError::ConfigError(
                "Call agent not configured with account (empty AOR)".to_string(),
            ));
        }

        let call_id = Uuid::new_v4().to_string();

        info!(
            call_id = %call_id,
            remote_uri = %remote_uri,
            aor = %self.aor,
            display_name = %self.display_name,
            "Initiating outbound call"
        );

        // Parse destination address from URI (includes DNS resolution)
        let destination = Self::parse_destination(remote_uri).await?;

        // Get the local IP address that can reach the destination
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;
        debug!(
            destination = %destination,
            local_addr = %effective_local_addr,
            "Determined local address for call"
        );

        let sip_call_id = generate_call_id(&effective_local_addr.ip().to_string());

        // Create call session
        let from_tag = generate_tag();
        let branch = generate_branch();

        let mut session = CallSession {
            id: call_id.clone(),
            sip_call_id: sip_call_id.clone(),
            state: CallState::Idle,
            dialog: None,
            invite_transaction: None,
            non_invite_transaction: None,
            from_tag: from_tag.clone(),
            to_tag: None,
            cseq: 1,
            remote_uri: remote_uri.to_string(),
            remote_display_name: None,
            is_outbound: true,
            local_sdp: Some(sdp_offer.to_string()),
            remote_sdp: None,
            start_time: Utc::now(),
            connected_at: None,
            last_branch: Some(branch.clone()),
            failure_reason: None,
            refer_request: None,
            transfer_target: None,
        };

        // Build request before storing session
        let request = Self::build_invite_request_static(
            remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            1,
            &from_tag,
            &branch,
            sdp_offer,
            &self.transport_type,
        )?;

        // Create INVITE transaction
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction = ClientInviteTransaction::new(tx_key, TransportType::Reliable);
        session.invite_transaction = Some(transaction);
        session.state = CallState::Dialing;

        self.calls.insert(call_id.clone(), session);

        // Send state change notification
        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.clone(),
                state: CallState::Dialing,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        // Send request
        info!(
            call_id = %call_id,
            destination = %destination,
            method = "INVITE",
            "Queuing SendRequest event for INVITE"
        );
        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        info!(call_id = %call_id, "SendRequest event queued successfully");
        Ok(call_id)
    }

    /// Hangs up an active call.
    pub async fn hangup(&mut self, call_id: &str) -> SipUaResult<()> {
        debug!(
            call_id = %call_id,
            known_calls = ?self.calls.keys().collect::<Vec<_>>(),
            "CallAgent::hangup() looking up call"
        );

        let state = self
            .calls
            .get(call_id)
            .ok_or_else(|| {
                error!(
                    call_id = %call_id,
                    known_calls = ?self.calls.keys().collect::<Vec<_>>(),
                    "CallAgent::hangup() - Call not found in calls map"
                );
                SipUaError::InvalidState("Call not found".to_string())
            })?
            .state;

        info!(call_id = %call_id, state = ?state, "CallAgent::hangup() - hanging up call");

        match state {
            CallState::Dialing | CallState::Ringing | CallState::EarlyMedia => {
                // Send CANCEL for pending INVITE
                self.send_cancel(call_id).await
            }
            CallState::Connected | CallState::OnHold | CallState::Transferring => {
                // Send BYE
                self.send_bye(call_id).await
            }
            CallState::Terminated | CallState::Idle => {
                // Already ended
                Ok(())
            }
            _ => Err(SipUaError::InvalidState(format!(
                "Cannot hangup in state {state:?}"
            ))),
        }
    }

    /// Puts a call on hold by sending a re-INVITE with hold SDP.
    ///
    /// The hold SDP uses `a=sendonly` direction to indicate we're putting the call on hold.
    /// This stops sending media but continues receiving.
    pub async fn hold_call(&mut self, call_id: &str, hold_sdp: &str) -> SipUaResult<()> {
        let session = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        if session.state != CallState::Connected {
            return Err(SipUaError::InvalidState(format!(
                "Cannot hold call in state {:?}",
                session.state
            )));
        }

        info!(call_id = %call_id, "Putting call on hold");

        self.send_reinvite(call_id, hold_sdp, true).await
    }

    /// Resumes a held call by sending a re-INVITE with normal SDP.
    ///
    /// The resume SDP uses `a=sendrecv` direction to restore bidirectional media.
    pub async fn resume_call(&mut self, call_id: &str, resume_sdp: &str) -> SipUaResult<()> {
        let session = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        if session.state != CallState::OnHold {
            return Err(SipUaError::InvalidState(format!(
                "Cannot resume call in state {:?}",
                session.state
            )));
        }

        info!(call_id = %call_id, "Resuming held call");

        self.send_reinvite(call_id, resume_sdp, false).await
    }

    /// Sends a re-INVITE to update the media session (e.g., codec change).
    ///
    /// Unlike hold/resume, this does not change hold state. The call remains
    /// Connected and the SDP offer contains the desired media parameters.
    /// Used for mid-call codec renegotiation per RFC 3261 Section 14.
    pub async fn send_media_update(&mut self, call_id: &str, sdp: &str) -> SipUaResult<()> {
        let session = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        if session.state != CallState::Connected {
            return Err(SipUaError::InvalidState(format!(
                "Cannot update media in state {:?}",
                session.state
            )));
        }

        info!(call_id = %call_id, "Sending media update re-INVITE");

        self.send_reinvite(call_id, sdp, false).await
    }

    /// Transfers a call to another party (blind transfer).
    ///
    /// Sends a REFER request per RFC 3515 to transfer the call to the
    /// specified target URI. The remote party will initiate a new call
    /// to the transfer target.
    ///
    /// # Arguments
    /// * `call_id` - The call to transfer
    /// * `transfer_target` - SIP URI of the transfer destination (e.g., "sips:bob@example.com")
    ///
    /// # Returns
    /// Ok(()) if the REFER was sent successfully. The actual transfer result
    /// will be reported via NOTIFY messages (handled asynchronously).
    pub async fn transfer_call(&mut self, call_id: &str, transfer_target: &str) -> SipUaResult<()> {
        let session = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        // Can only transfer connected or held calls
        if session.state != CallState::Connected && session.state != CallState::OnHold {
            return Err(SipUaError::InvalidState(format!(
                "Cannot transfer call in state {:?}",
                session.state
            )));
        }

        info!(
            call_id = %call_id,
            transfer_target = %transfer_target,
            "Initiating blind transfer"
        );

        self.send_refer(call_id, transfer_target).await
    }

    /// Sends a REFER request to transfer the call.
    async fn send_refer(&mut self, call_id: &str, transfer_target: &str) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cseq += 1;

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;

        // Build REFER request
        let request = Self::build_refer_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            transfer_target,
            &self.transport_type,
        )?;

        // Create non-INVITE transaction for REFER
        let branch = generate_branch();
        let tx_key = TransactionKey::client(&branch, "REFER");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);

        // Create ReferRequest to track the implicit subscription (RFC 3515)
        let refer_request = ReferRequest::new(transfer_target).with_referred_by(self.aor.clone());

        if let Some(session) = self.calls.get_mut(call_id) {
            session.non_invite_transaction = Some(transaction);
            session.state = CallState::Transferring;
            session.refer_request = Some(refer_request);
            session.transfer_target = Some(transfer_target.to_string());
        }

        // Send request
        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        // Notify state change
        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Transferring,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Sends a re-INVITE with new SDP.
    ///
    /// Used for hold/resume and other mid-call SDP renegotiation.
    async fn send_reinvite(&mut self, call_id: &str, sdp: &str, is_hold: bool) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cseq += 1;
            session.local_sdp = Some(sdp.to_string());

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;
        let branch = generate_branch();

        // Build re-INVITE request
        let request = Self::build_reinvite_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &branch,
            sdp,
            &self.transport_type,
        )?;

        // Create INVITE transaction for re-INVITE
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction = ClientInviteTransaction::new(tx_key, TransportType::Reliable);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.invite_transaction = Some(transaction);
            session.last_branch = Some(branch);
        }

        // Send request
        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        // Transition state based on hold/resume
        let new_state = if is_hold {
            CallState::OnHold
        } else {
            CallState::Connected
        };

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = new_state;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: new_state,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Handles a received SIP response.
    pub async fn handle_response(
        &mut self,
        response: &SipResponse,
        call_id: &str,
    ) -> SipUaResult<()> {
        let status_code = response.status.code();
        let current_state = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?
            .state;

        debug!(
            call_id = %call_id,
            status_code = status_code,
            state = ?current_state,
            "Received call response"
        );

        // Update transaction state
        if let Some(session) = self.calls.get_mut(call_id)
            && let Some(ref mut tx) = session.invite_transaction
        {
            let _ = tx.receive_response(status_code);
        }

        match status_code {
            100 => {
                // Trying - no state change needed
                debug!(call_id = %call_id, "Call is trying");
            }
            180 | 183 => {
                self.handle_provisional_response(call_id, status_code, response)
                    .await?;
            }
            200 => {
                self.handle_success_response(call_id, response).await?;
            }
            code if (300..400).contains(&code) => {
                self.handle_redirect_response(call_id, code).await?;
            }
            401 | 407 => {
                self.handle_auth_challenge(call_id, status_code, response)
                    .await?;
            }
            480 => {
                self.handle_unavailable_response(call_id, response).await?;
            }
            486 | 600 => {
                self.handle_busy_response(call_id, status_code, response)
                    .await?;
            }
            487 => {
                self.handle_cancelled_response(call_id, response).await?;
            }
            code if (400..700).contains(&code) => {
                self.handle_failure_response(call_id, code, response)
                    .await?;
            }
            _ => {
                debug!(
                    call_id = %call_id,
                    status_code = status_code,
                    "Received unexpected response"
                );
            }
        }

        Ok(())
    }

    /// Handles an incoming NOTIFY request for REFER subscriptions (RFC 3515).
    ///
    /// This processes the sipfrag body to determine transfer progress and emits
    /// appropriate events. Returns the 200 OK response to send back.
    pub async fn handle_notify(&mut self, request: &SipRequest) -> SipUaResult<SipResponse> {
        // Extract Call-ID to find the right session
        let sip_call_id = request
            .headers
            .get_value(&HeaderName::CallId)
            .ok_or_else(|| SipUaError::InvalidState("Missing Call-ID header".to_string()))?
            .to_string();

        // Find the call session by SIP Call-ID
        let call_id = self.find_call_by_sip_id(&sip_call_id).ok_or_else(|| {
            SipUaError::InvalidState(format!("No call found for Call-ID: {sip_call_id}"))
        })?;

        // Verify this is a REFER notification (Event: refer)
        let event_header = request.headers.get_value(&HeaderName::Event).unwrap_or("");

        if !event_header.starts_with("refer") {
            warn!(
                call_id = %call_id,
                event = %event_header,
                "Received NOTIFY for non-refer event, ignoring"
            );
            return Ok(Self::build_200_ok_for_notify(request));
        }

        // Parse Subscription-State header
        let sub_state_header = request.headers.get_value(&HeaderName::SubscriptionState);

        let is_final = sub_state_header.is_some_and(|s| s.starts_with("terminated"));

        // Parse sipfrag body to get transfer status
        let status = request.body.as_ref().map_or_else(
            || {
                warn!(call_id = %call_id, "NOTIFY without sipfrag body");
                None
            },
            |body| {
                let body_str = String::from_utf8_lossy(body);
                Self::parse_sipfrag(&body_str)
            },
        );

        // Get transfer target and update refer request state
        let transfer_target = {
            let session = self
                .calls
                .get_mut(&call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            // Update ReferRequest with status if available
            if let (Some(refer_req), Some(st)) = (&mut session.refer_request, status) {
                refer_req.update_status(st);
            }

            session.transfer_target.clone().unwrap_or_default()
        };

        // Emit transfer progress event
        if let Some(status) = status {
            info!(
                call_id = %call_id,
                status = ?status,
                is_final = is_final,
                target = %transfer_target,
                "Transfer progress update"
            );

            self.event_tx
                .send(CallEvent::TransferProgress {
                    call_id: call_id.clone(),
                    target_uri: transfer_target,
                    status,
                    is_final,
                })
                .await
                .map_err(|e| SipUaError::TransportError(e.to_string()))?;

            // If transfer succeeded, we can end the original call
            if status == ReferStatus::Success {
                info!(call_id = %call_id, "Transfer completed successfully, terminating original call");
                if let Some(session) = self.calls.get_mut(&call_id) {
                    session.state = CallState::Terminated;
                    session.refer_request = None;
                    session.transfer_target = None;
                }

                self.event_tx
                    .send(CallEvent::StateChanged {
                        call_id: call_id.clone(),
                        state: CallState::Terminated,
                        info: None,
                    })
                    .await
                    .map_err(|e| SipUaError::TransportError(e.to_string()))?;
            } else if status == ReferStatus::Failed {
                info!(call_id = %call_id, "Transfer failed, reverting to connected state");
                if let Some(session) = self.calls.get_mut(&call_id) {
                    session.state = CallState::Connected;
                    session.refer_request = None;
                    session.transfer_target = None;
                }

                self.event_tx
                    .send(CallEvent::StateChanged {
                        call_id: call_id.clone(),
                        state: CallState::Connected,
                        info: None,
                    })
                    .await
                    .map_err(|e| SipUaError::TransportError(e.to_string()))?;
            }
        }

        // Build 200 OK response
        Ok(Self::build_200_ok_for_notify(request))
    }

    /// Parses a sipfrag body to extract the SIP status code.
    ///
    /// Sipfrag format: "SIP/2.0 <status-code> <reason-phrase>"
    fn parse_sipfrag(body: &str) -> Option<ReferStatus> {
        let body = body.trim();

        // Must start with SIP version
        if !body.starts_with("SIP/2.0 ") {
            debug!("Invalid sipfrag: doesn't start with SIP/2.0");
            return None;
        }

        // Extract status code (characters after "SIP/2.0 ")
        let remainder = &body[8..];
        let status_str = remainder.split_whitespace().next()?;
        let status_code: u16 = status_str.parse().ok()?;

        Some(ReferStatus::from_status_code(status_code))
    }

    /// Builds a 200 OK response for a NOTIFY request.
    fn build_200_ok_for_notify(request: &SipRequest) -> SipResponse {
        use proto_sip::header::Header;
        use proto_sip::response::StatusCode;

        let mut response = SipResponse::new(StatusCode::OK);

        // Copy Via headers (all, in order) - RFC 3261 section 8.2.6.1
        for via in request.headers.get_all(&HeaderName::Via) {
            response.add_header(Header::new(HeaderName::Via, &via.value));
        }

        // Copy From header unchanged
        if let Some(from) = request.headers.get_value(&HeaderName::From) {
            response.add_header(Header::new(HeaderName::From, from));
        }

        // Copy To header unchanged
        if let Some(to) = request.headers.get_value(&HeaderName::To) {
            response.add_header(Header::new(HeaderName::To, to));
        }

        // Copy Call-ID header unchanged
        if let Some(call_id) = request.headers.get_value(&HeaderName::CallId) {
            response.add_header(Header::new(HeaderName::CallId, call_id));
        }

        // Copy CSeq header unchanged
        if let Some(cseq) = request.headers.get_value(&HeaderName::CSeq) {
            response.add_header(Header::new(HeaderName::CSeq, cseq));
        }

        // Add User-Agent and Content-Length
        response.add_header(Header::new(HeaderName::UserAgent, USER_AGENT));
        response.add_header(Header::new(HeaderName::ContentLength, "0"));

        response
    }

    async fn handle_provisional_response(
        &mut self,
        call_id: &str,
        status_code: u16,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let session = self
            .calls
            .get_mut(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        if session.state == CallState::Dialing {
            let new_state = if status_code == 183 {
                CallState::EarlyMedia
            } else {
                CallState::Ringing
            };
            session.state = new_state;

            self.event_tx
                .send(CallEvent::StateChanged {
                    call_id: call_id.to_string(),
                    state: new_state,
                    info: None,
                })
                .await
                .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        }

        // Extract early SDP if present (183)
        if status_code == 183
            && let Some(body) = &response.body
        {
            let sdp = String::from_utf8_lossy(body).to_string();
            if let Some(session) = self.calls.get_mut(call_id) {
                session.remote_sdp = Some(sdp.clone());
            }
            let _ = self
                .event_tx
                .send(CallEvent::SdpAnswerReceived {
                    call_id: call_id.to_string(),
                    sdp,
                })
                .await;
        }

        // Extract To tag if present
        if let Some(session) = self.calls.get_mut(call_id)
            && session.to_tag.is_none()
        {
            session.to_tag = Self::extract_to_tag(response);
        }

        Ok(())
    }

    async fn handle_success_response(
        &mut self,
        call_id: &str,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        // Extract data needed for ACK
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, current_state) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            // 200 OK for a BYE (call is Terminating) — just confirm termination
            if session.state == CallState::Terminating {
                info!(call_id = %call_id, "BYE confirmed (200 OK), call terminated");
                session.state = CallState::Terminated;
                let _ = self
                    .event_tx
                    .send(CallEvent::StateChanged {
                        call_id: call_id.to_string(),
                        state: CallState::Terminated,
                        info: None,
                    })
                    .await;
                return Ok(());
            }

            // For a hold re-INVITE 200 OK, preserve the OnHold state.
            // Only transition to Connected for the initial INVITE or resume.
            if session.state != CallState::OnHold {
                session.state = CallState::Connected;
                session.connected_at = Some(Instant::now());
            }
            session.invite_transaction = None;

            if session.to_tag.is_none() {
                session.to_tag = Self::extract_to_tag(response);
            }

            if let Some(body) = &response.body {
                let sdp = String::from_utf8_lossy(body).to_string();
                session.remote_sdp = Some(sdp.clone());
                let _ = self
                    .event_tx
                    .send(CallEvent::SdpAnswerReceived {
                        call_id: call_id.to_string(),
                        sdp,
                    })
                    .await;
            }

            let current_state = session.state;
            info!(call_id = %call_id, state = ?current_state, "INVITE 200 OK processed");

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
                current_state,
            )
        };

        // Send ACK
        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;
        let ack_request = Self::build_ack_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &self.transport_type,
        )?;

        self.event_tx
            .send(CallEvent::SendRequest {
                request: ack_request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: current_state,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    async fn handle_redirect_response(&mut self, call_id: &str, code: u16) -> SipUaResult<()> {
        warn!(
            call_id = %call_id,
            status_code = code,
            "Call redirected, not supported"
        );

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Rejected {
                status_code: code,
                reason: "Redirect not supported".to_string(),
            });
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    async fn handle_auth_challenge(
        &mut self,
        call_id: &str,
        status_code: u16,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        error!(
            call_id = %call_id,
            status_code = status_code,
            "Server requested digest auth, mTLS-only supported"
        );

        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::AuthenticationFailed);
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await
    }

    async fn handle_unavailable_response(
        &mut self,
        call_id: &str,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Rejected {
                status_code: 480,
                reason: "Temporarily unavailable".to_string(),
            });
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await
    }

    async fn handle_busy_response(
        &mut self,
        call_id: &str,
        status_code: u16,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Rejected {
                status_code,
                reason: "Busy".to_string(),
            });
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await
    }

    async fn handle_cancelled_response(
        &mut self,
        call_id: &str,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Cancelled);
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await
    }

    async fn handle_failure_response(
        &mut self,
        call_id: &str,
        code: u16,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        error!(
            call_id = %call_id,
            status_code = code,
            "Call failed"
        );

        let reason = response
            .reason
            .clone()
            .unwrap_or_else(|| "Unknown error".to_string());

        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Rejected {
                status_code: code,
                reason,
            });
            session.invite_transaction = None;
        }

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminated,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await
    }

    fn extract_session_data_for_ack(
        &self,
        call_id: &str,
    ) -> SipUaResult<(String, String, u32, String, Option<String>)> {
        let session = self
            .calls
            .get(call_id)
            .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

        Ok((
            session.remote_uri.clone(),
            session.sip_call_id.clone(),
            session.cseq,
            session.from_tag.clone(),
            session.to_tag.clone(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_ack_for_failure(
        &self,
        _call_id: &str,
        remote_uri: &str,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        _response: &SipResponse,
    ) -> SipUaResult<()> {
        let destination = Self::parse_destination(remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;
        let ack_request = Self::build_ack_request_static(
            remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            sip_call_id,
            cseq,
            from_tag,
            to_tag,
            &self.transport_type,
        )?;

        self.event_tx
            .send(CallEvent::SendRequest {
                request: ack_request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Gets call information.
    pub fn get_call_info(&self, call_id: &str) -> Option<CallInfo> {
        self.calls.get(call_id).map(|session| {
            let connect_time = session.connected_at.map(|_| Utc::now());
            CallInfo {
                id: session.id.clone(),
                state: session.state,
                direction: if session.is_outbound {
                    CallDirection::Outbound
                } else {
                    CallDirection::Inbound
                },
                remote_uri: session.remote_uri.clone(),
                remote_display_name: session.remote_display_name.clone(),
                start_time: session.start_time,
                connect_time,
                is_muted: false,
                is_on_hold: session.state == CallState::OnHold,
                failure_reason: session.failure_reason.clone(),
            }
        })
    }

    /// Gets call state.
    pub fn get_state(&self, call_id: &str) -> Option<CallState> {
        self.calls.get(call_id).map(|s| s.state)
    }

    /// Finds a call by its SIP Call-ID header value.
    ///
    /// Returns the application call ID if found.
    pub fn find_call_by_sip_id(&self, sip_call_id: &str) -> Option<String> {
        self.calls
            .iter()
            .find(|(_, session)| session.sip_call_id == sip_call_id)
            .map(|(_, session)| session.id.clone())
    }

    /// Sends a CANCEL request for a pending INVITE.
    async fn send_cancel(&mut self, call_id: &str) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, branch) = {
            let session = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
                session.last_branch.clone().unwrap_or_else(generate_branch),
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;

        // Build CANCEL request
        let request = Self::build_cancel_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &branch,
            &self.transport_type,
        )?;

        // Create non-INVITE transaction
        let new_branch = generate_branch();
        let tx_key = TransactionKey::client(&new_branch, "CANCEL");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.non_invite_transaction = Some(transaction);
        }

        // Send request
        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Sends a BYE request to end a connected call.
    async fn send_bye(&mut self, call_id: &str) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cseq += 1;
            session.state = CallState::Terminating;

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;

        // Build BYE request
        let request = Self::build_bye_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &self.transport_type,
        )?;

        // Create non-INVITE transaction
        let branch = generate_branch();
        let tx_key = TransactionKey::client(&branch, "BYE");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.non_invite_transaction = Some(transaction);
        }

        // Send request
        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        self.event_tx
            .send(CallEvent::StateChanged {
                call_id: call_id.to_string(),
                state: CallState::Terminating,
                info: None,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Sends a DTMF digit via SIP INFO (RFC 6086 fallback).
    ///
    /// Used when telephone-event is not negotiated in SDP. Sends an INFO
    /// request with `Content-Type: application/dtmf-relay` body.
    pub async fn send_info_dtmf(
        &mut self,
        call_id: &str,
        digit: DtmfDigit,
        duration_ms: u32,
    ) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            // Must be in connected state for in-dialog INFO
            if session.state != CallState::Connected {
                return Err(SipUaError::InvalidState(
                    "Cannot send INFO DTMF in non-connected state".to_string(),
                ));
            }

            session.cseq += 1;

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;

        let request = Self::build_info_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &self.transport_type,
            digit,
            duration_ms,
        )?;

        self.event_tx
            .send(CallEvent::SendRequest {
                request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        info!(call_id = %call_id, digit = %digit, "Sent SIP INFO DTMF");
        Ok(())
    }

    /// Builds a SIP INFO request for DTMF relay.
    #[allow(clippy::too_many_arguments)]
    fn build_info_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        transport_type: &str,
        digit: DtmfDigit,
        duration_ms: u32,
    ) -> SipUaResult<SipRequest> {
        use proto_sip::method::Method;

        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let branch = generate_branch();

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        // Duration in RTP timestamp units (8 samples/ms at 8kHz)
        let rtp_duration = duration_ms * 8;
        let body = format!("Signal={}\r\nDuration={rtp_duration}", digit.to_char());

        let request = RequestBuilder::new(Method::Info, remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .content_type("application/dtmf-relay")
            .body(body)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds an INVITE request (static version to avoid borrow issues).
    #[allow(clippy::too_many_arguments)]
    fn build_invite_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        branch: &str,
        sdp_offer: &str,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch.to_string());

        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let to = NameAddr::new(remote_uri.clone());

        // Only add transport param for non-UDP (UDP is the default)
        let mut contact_uri = SipUri::new(local_addr.ip().to_string()).with_port(local_addr.port());
        if transport_type != "UDP" {
            contact_uri = contact_uri.with_param("transport", Some(transport_type.to_lowercase()));
        }
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        let contact = NameAddr::new(contact_uri);

        let request = RequestBuilder::invite(remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .contact(&contact)
            .user_agent(USER_AGENT)
            .content_type("application/sdp")
            .body(bytes::Bytes::from(sdp_offer.as_bytes().to_vec()))
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a CANCEL request (static version).
    #[allow(clippy::too_many_arguments)]
    fn build_cancel_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        branch: &str,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch.to_string());

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let request = RequestBuilder::cancel(remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a BYE request (static version).
    #[allow(clippy::too_many_arguments)]
    fn build_bye_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let branch = generate_branch();

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let request = RequestBuilder::bye(remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds an ACK request (static version).
    #[allow(clippy::too_many_arguments)]
    fn build_ack_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let branch = generate_branch();

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let request = RequestBuilder::ack(remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a re-INVITE request for mid-call SDP renegotiation (hold/resume).
    #[allow(clippy::too_many_arguments)]
    fn build_reinvite_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        branch: &str,
        sdp: &str,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch.to_string());

        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        // Contact header for in-dialog request
        let mut contact_uri = SipUri::new(local_addr.ip().to_string()).with_port(local_addr.port());
        if transport_type != "UDP" {
            contact_uri = contact_uri.with_param("transport", Some(transport_type.to_lowercase()));
        }
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        let contact = NameAddr::new(contact_uri);

        let request = RequestBuilder::invite(remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .contact(&contact)
            .user_agent(USER_AGENT)
            .content_type("application/sdp")
            .body(bytes::Bytes::from(sdp.as_bytes().to_vec()))
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a REFER request for call transfer (RFC 3515).
    #[allow(clippy::too_many_arguments)]
    fn build_refer_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        transfer_target: &str,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        use proto_sip::method::Method;

        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let branch = generate_branch();

        let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        // Contact header for in-dialog request
        let mut contact_uri = SipUri::new(local_addr.ip().to_string()).with_port(local_addr.port());
        if transport_type != "UDP" {
            contact_uri = contact_uri.with_param("transport", Some(transport_type.to_lowercase()));
        }
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        let contact = NameAddr::new(contact_uri);

        // Build REFER request with Refer-To header
        let request = RequestBuilder::new(Method::Refer, remote_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70)
            .contact(&contact)
            .user_agent(USER_AGENT)
            .header(HeaderName::ReferTo, transfer_target)
            .header(HeaderName::ReferredBy, aor)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Parses a SIP URI to get destination address, performing DNS resolution if needed.
    async fn parse_destination(uri: &str) -> SipUaResult<SocketAddr> {
        debug!(uri = %uri, "parse_destination: parsing SIP URI");

        let sip_uri: SipUri = uri.parse().map_err(|e| {
            error!(uri = %uri, error = %e, "parse_destination: failed to parse SIP URI");
            SipUaError::ConfigError(format!("Invalid URI: {e}"))
        })?;

        let host = &sip_uri.host;
        // Use transport-appropriate default port: UDP/TCP = 5060, TLS = 5061
        let port = sip_uri.port.unwrap_or(5060);

        debug!(host = %host, port = port, "parse_destination: extracted host and port");

        // Try to parse host as IP address first
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            debug!(addr = %addr, "parse_destination: host is already an IP address");
            return Ok(addr);
        }

        // DNS resolution for hostnames
        debug!(host = %host, "parse_destination: performing DNS resolution");
        let lookup_host = format!("{host}:{port}");
        let mut addrs = tokio::net::lookup_host(&lookup_host).await.map_err(|e| {
            error!(host = %host, error = %e, "parse_destination: DNS resolution failed");
            SipUaError::ConfigError(format!("DNS resolution failed for {host}: {e}"))
        })?;

        let result = addrs.next().ok_or_else(|| {
            error!(host = %host, "parse_destination: no addresses found");
            SipUaError::ConfigError(format!("No addresses found for {host}"))
        })?;

        debug!(
            host = %host,
            resolved = %result,
            "parse_destination: DNS resolution returned address"
        );

        info!(
            uri = %uri,
            resolved = %result,
            "parse_destination: resolved destination address"
        );

        Ok(result)
    }

    /// Gets the local address to use for reaching a destination.
    ///
    /// If the configured `local_addr` is unspecified (0.0.0.0), this function
    /// determines the appropriate local IP by creating a UDP socket connected
    /// to the destination. This ensures the Via/Contact headers contain a
    /// routable IP address.
    #[allow(clippy::unused_async)]
    async fn get_local_addr_for_destination(
        destination: SocketAddr,
        configured_addr: SocketAddr,
    ) -> SipUaResult<SocketAddr> {
        // If we already have a specific IP configured, use it
        if !configured_addr.ip().is_unspecified() {
            debug!(
                configured = %configured_addr,
                "Using configured local address"
            );
            return Ok(configured_addr);
        }

        // Create a UDP socket and "connect" to the destination to discover our local IP
        debug!(
            destination = %destination,
            "Discovering local IP for destination"
        );

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            error!(error = %e, "Failed to bind socket for local IP discovery");
            SipUaError::TransportError(format!("Failed to bind UDP socket: {e}"))
        })?;

        socket.connect(destination).map_err(|e| {
            error!(error = %e, destination = %destination, "Failed to connect socket for local IP discovery");
            SipUaError::TransportError(format!("Failed to connect to destination: {e}"))
        })?;

        let local_addr = socket.local_addr().map_err(|e| {
            error!(error = %e, "Failed to get local address from socket");
            SipUaError::TransportError(format!("Failed to get local address: {e}"))
        })?;

        info!(
            destination = %destination,
            local_addr = %local_addr,
            "Discovered local IP for destination"
        );

        Ok(local_addr)
    }

    /// Extracts To tag from response.
    fn extract_to_tag(response: &SipResponse) -> Option<String> {
        response.headers.get(&HeaderName::To).and_then(|h| {
            let value = &h.value;
            value.find("tag=").map(|pos| {
                let start = pos + 4;
                let end = value[start..]
                    .find(|c: char| c == ';' || c == '>' || c.is_whitespace())
                    .map_or(value.len(), |i| start + i);
                value[start..end].to_string()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_call_agent_new() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let agent = CallAgent::new(
            local_addr,
            "sips:alice@example.com".to_string(),
            "Alice".to_string(),
            tx,
        );

        assert!(agent.calls.is_empty());
    }

    #[tokio::test]
    async fn test_parse_destination() {
        let addr = CallAgent::parse_destination("sips:bob@192.168.1.1:5061")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5061);
    }

    #[tokio::test]
    async fn test_parse_destination_default_port() {
        let addr = CallAgent::parse_destination("sips:bob@192.168.1.1")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        // Default port for non-TLS is now 5060 (not 5061)
        assert_eq!(addr.port(), 5060);
    }

    #[tokio::test]
    async fn test_make_call() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sips:alice@192.168.1.100".to_string(),
            "Alice".to_string(),
            tx,
        );

        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.100\r\n";
        let call_id = agent
            .make_call("sips:bob@192.168.1.1:5061", sdp)
            .await
            .unwrap();

        // Should receive state change
        let event = rx.recv().await.unwrap();
        assert!(matches!(
            event,
            CallEvent::StateChanged {
                state: CallState::Dialing,
                ..
            }
        ));

        // Should receive send request
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, CallEvent::SendRequest { .. }));

        // State should be Dialing
        assert_eq!(agent.get_state(&call_id), Some(CallState::Dialing));
    }

    #[tokio::test]
    async fn test_get_call_info_unknown() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let agent = CallAgent::new(
            local_addr,
            "sips:alice@example.com".to_string(),
            "Alice".to_string(),
            tx,
        );

        assert!(agent.get_call_info("unknown").is_none());
    }
}
