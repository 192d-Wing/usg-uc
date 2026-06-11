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
    /// Digest auth credentials for INVITE challenges (`BulkVS` etc.).
    #[cfg(feature = "digest-auth")]
    digest_credentials: Option<client_types::DigestAuthCredentials>,
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
    /// Exact Via header value of the last INVITE actually sent (including a
    /// digest-auth resend). RFC 3261 §9.1 requires the CANCEL's single Via
    /// to match the INVITE's, host AND port, and §17.1.1.3 requires the same
    /// for the ACK to a non-2xx final response. The Via sent-by port comes
    /// from a per-request ephemeral discovery socket, so it cannot be
    /// re-derived later — it must be stored verbatim.
    last_via: Option<String>,
    /// True while a CANCEL for the pending INVITE is outstanding (the
    /// INVITE's own final response has not arrived yet). If a 200 OK to the
    /// INVITE wins the race — RFC 3261 §15: the callee answered just as we
    /// cancelled — the UAC MUST ACK the 200 and immediately send a BYE for
    /// the now-established dialog instead of surfacing Connected.
    cancel_pending: bool,
    /// Failure reason if the call failed.
    failure_reason: Option<CallFailureReason>,
    /// Active REFER request for call transfer (RFC 3515).
    refer_request: Option<ReferRequest>,
    /// Transfer target URI when transfer is in progress.
    transfer_target: Option<String>,
    /// Nonce count for digest auth retries on this call's INVITE.
    #[cfg(feature = "digest-auth")]
    nonce_count: u32,
    /// Last digest challenge received for this call.
    #[cfg(feature = "digest-auth")]
    last_challenge: Option<proto_sip::auth::DigestChallenge>,
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
            #[cfg(feature = "digest-auth")]
            digest_credentials: None,
        }
    }

    /// Configures the agent with account information.
    ///
    /// # Arguments
    /// * `aor` - Address of Record (SIP URI for the account)
    /// * `display_name` - Display name for From header
    /// * `caller_id` - Optional Caller ID to use instead of the AOR user part
    /// * `transport` - Transport type string ("UDP", "TCP", or "TLS")
    /// * `digest_credentials` - Optional digest auth credentials for INVITE challenges
    pub fn configure(
        &mut self,
        aor: String,
        display_name: String,
        caller_id: Option<String>,
        transport: &str,
        #[cfg(feature = "digest-auth")] digest_credentials: Option<
            client_types::DigestAuthCredentials,
        >,
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
        #[cfg(feature = "digest-auth")]
        {
            self.digest_credentials = digest_credentials;
        }
        info!(
            aor = %self.aor,
            display_name = %self.display_name,
            transport = %self.transport_type,
            "Call agent configured"
        );
    }

    /// Registers an accepted inbound call in the call agent's calls map.
    ///
    /// This allows hangup (BYE) and other in-dialog operations to work for
    /// inbound calls the same way they work for outbound calls.
    #[allow(clippy::too_many_arguments)]
    pub fn register_inbound_call(
        &mut self,
        call_id: &str,
        sip_call_id: &str,
        local_tag: &str,
        remote_tag: Option<&str>,
        remote_uri: &str,
        remote_display_name: Option<&str>,
        remote_sdp: Option<&str>,
    ) {
        let session = CallSession {
            id: call_id.to_string(),
            sip_call_id: sip_call_id.to_string(),
            state: CallState::Connected,
            dialog: None,
            invite_transaction: None,
            non_invite_transaction: None,
            from_tag: local_tag.to_string(),
            to_tag: remote_tag.map(String::from),
            cseq: 1,
            remote_uri: remote_uri.to_string(),
            remote_display_name: remote_display_name.map(String::from),
            is_outbound: false,
            local_sdp: None,
            remote_sdp: remote_sdp.map(String::from),
            start_time: Utc::now(),
            connected_at: Some(Instant::now()),
            last_branch: None,
            last_via: None,
            cancel_pending: false,
            failure_reason: None,
            refer_request: None,
            transfer_target: None,
            #[cfg(feature = "digest-auth")]
            nonce_count: 0,
            #[cfg(feature = "digest-auth")]
            last_challenge: None,
        };
        info!(
            call_id = %call_id,
            sip_call_id = %sip_call_id,
            "Registered inbound call in call agent"
        );
        self.calls.insert(call_id.to_string(), session);
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
        let from_tag = generate_tag();
        let branch = generate_branch();

        // Build request first (borrows strings), then move them into session
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

        // Snapshot the exact Via we are sending; CANCEL/ACK must reuse it
        // verbatim (RFC 3261 §9.1 / §17.1.1.3).
        let invite_via = request
            .headers
            .get_value(&HeaderName::Via)
            .map(String::from);

        // Create INVITE transaction
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction = ClientInviteTransaction::new(tx_key, TransportType::Reliable);

        let session = CallSession {
            id: call_id.clone(),
            sip_call_id,
            state: CallState::Dialing,
            dialog: None,
            invite_transaction: Some(transaction),
            non_invite_transaction: None,
            from_tag,
            to_tag: None,
            cseq: 1,
            remote_uri: remote_uri.to_string(),
            remote_display_name: None,
            is_outbound: true,
            local_sdp: Some(sdp_offer.to_string()),
            remote_sdp: None,
            start_time: Utc::now(),
            connected_at: None,
            last_branch: Some(branch),
            last_via: invite_via,
            cancel_pending: false,
            failure_reason: None,
            refer_request: None,
            transfer_target: None,
            #[cfg(feature = "digest-auth")]
            nonce_count: 0,
            #[cfg(feature = "digest-auth")]
            last_challenge: None,
        };

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

        // Snapshot the exact Via for a potential CANCEL (RFC 3261 §9.1)
        let reinvite_via = request
            .headers
            .get_value(&HeaderName::Via)
            .map(String::from);

        // Create INVITE transaction for re-INVITE
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction = ClientInviteTransaction::new(tx_key, TransportType::Reliable);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.invite_transaction = Some(transaction);
            session.last_branch = Some(branch);
            session.last_via = reinvite_via;
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

        // Skip responses for already-terminated calls. Retransmitted 401s
        // and late responses arrive after we've moved on; processing them
        // would re-trigger state changes or duplicate ACKs.
        if current_state == CallState::Terminated {
            debug!(
                call_id = %call_id,
                status_code = status_code,
                "Ignoring response for terminated call"
            );
            return Ok(());
        }

        // Responses are routed here by Call-ID alone, so a response to the
        // CANCEL transaction (CSeq method CANCEL, RFC 3261 §17.1.3) also
        // lands here. It never decides the call's fate by itself: a 200
        // only confirms the CANCEL was received (§9.1) and a 481 means the
        // INVITE already completed — in both cases the INVITE's own final
        // response (487, or a 2xx that won the race) arrives separately.
        if Self::cseq_method(response).as_deref() == Some("CANCEL") {
            debug!(
                call_id = %call_id,
                status_code = status_code,
                "Response to CANCEL transaction; awaiting INVITE final response"
            );
            return Ok(());
        }

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
        // RFC 3261 §15 race: the INVITE's 200 OK beat our CANCEL — the
        // callee answered just as we hung up. The dialog IS established at
        // the UAS, so it must be ACKed and immediately torn down with a
        // BYE; it must never surface as Connected.
        let invite_200_after_cancel = Self::cseq_method(response).as_deref() == Some("INVITE")
            && self.calls.get(call_id).is_some_and(|s| s.cancel_pending);
        if invite_200_after_cancel {
            return self.handle_invite_200_after_cancel(call_id, response).await;
        }

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

        // Send ACK (for a 2xx: a new transaction with a fresh Via/branch)
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
            None,
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

    /// Handles a 200 OK to the INVITE that arrived after we sent CANCEL.
    ///
    /// RFC 3261 §15 / §9.1: if the UAS answers despite the CANCEL (glare),
    /// the UAC MUST ACK the 2xx (§13.2.2.4: new transaction, fresh branch,
    /// To-tag from the 200) and then immediately send a BYE to terminate
    /// the dialog the 200 established. The call never reports Connected to
    /// the app layer (no `SdpAnswerReceived`, no audio) — it goes straight
    /// Terminating → Terminated when the BYE is confirmed.
    ///
    /// Live evidence (`BulkVS`): hangup during `EarlyMedia` → CANCEL sent →
    /// 80ms later 200 OK to the INVITE; without this path the call object
    /// flashed Connected and died with reason Cancelled but NO BYE went
    /// out, leaving the carrier holding an established leg until timeout.
    async fn handle_invite_200_after_cancel(
        &mut self,
        call_id: &str,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cancel_pending = false;
            session.invite_transaction = None;

            // The ACK and BYE belong to the dialog the 200 established, so
            // they must carry the 200's To-tag (RFC 3261 §13.2.2.4), not a
            // tag learned from an earlier provisional response.
            if let Some(tag) = Self::extract_to_tag(response) {
                session.to_tag = Some(tag);
            }

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
            )
        };

        info!(
            call_id = %call_id,
            "INVITE 200 OK won the race against CANCEL; sending ACK then BYE (RFC 3261 §15)"
        );

        // ACK the 2xx: a new transaction with a fresh Via/branch (§13.2.2.4).
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
            None,
        )?;

        self.event_tx
            .send(CallEvent::SendRequest {
                request: ack_request,
                destination,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        // Tear the established dialog down. `send_bye` increments the CSeq,
        // keeps the call Terminating, and the BYE's 200 OK moves it to
        // Terminated via the normal path.
        self.send_bye(call_id).await
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

    #[allow(clippy::too_many_lines)]
    async fn handle_auth_challenge(
        &mut self,
        call_id: &str,
        status_code: u16,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        // Try digest auth if feature is enabled and credentials are available
        #[cfg(feature = "digest-auth")]
        {
            if let Some(ref creds) = self.digest_credentials {
                use proto_sip::auth::{Md5DigestHasher, create_credentials, generate_cnonce};

                let header_name = if status_code == 401 {
                    HeaderName::WwwAuthenticate
                } else {
                    HeaderName::ProxyAuthenticate
                };

                if let Some(challenge_header) = response.headers.get(&header_name)
                    && let Ok(challenge) = challenge_header
                        .value
                        .parse::<proto_sip::auth::DigestChallenge>()
                {
                    // Skip retransmitted 401s — if the nonce matches the last
                    // challenge we already processed, this is a retransmit from
                    // the server for a previous INVITE we already ACK'd.
                    #[cfg(feature = "digest-auth")]
                    {
                        let is_retransmit = self
                            .calls
                            .get(call_id)
                            .and_then(|s| s.last_challenge.as_ref())
                            .is_some_and(|last| last.nonce == challenge.nonce);

                        if is_retransmit {
                            debug!(
                                call_id = %call_id,
                                "Ignoring retransmitted 401 (same nonce), already sent auth'd INVITE"
                            );
                            return Ok(());
                        }
                    }

                    // ACK the challenged INVITE (RFC 3261 §22.2)
                    let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
                        self.extract_session_data_for_ack(call_id)?;

                    self.send_ack_for_failure(
                        call_id,
                        &remote_uri,
                        &sip_call_id,
                        cseq,
                        &from_tag,
                        to_tag.as_deref(),
                        response,
                    )
                    .await?;

                    let session = self
                        .calls
                        .get_mut(call_id)
                        .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

                    // Only retry once — BulkVS flow is: INVITE → 401 → auth'd INVITE → 200 OK.
                    // A second genuine 401 (different nonce) means credentials are wrong.
                    if session.nonce_count < 1 {
                        info!(
                            call_id = %call_id,
                            realm = %challenge.realm,
                            nonce_count = session.nonce_count,
                            "INVITE 401 challenge, retrying with digest credentials"
                        );

                        session.last_challenge = Some(challenge.clone());
                        session.nonce_count += 1;
                        session.cseq += 1;
                        let new_cseq = session.cseq;

                        // Re-derive effective local address for the new request
                        let destination = Self::parse_destination(&remote_uri).await?;
                        let effective_local_addr =
                            Self::get_local_addr_for_destination(destination, self.local_addr)
                                .await?;

                        // Rebuild the INVITE with a new branch (new transaction)
                        let new_branch = generate_branch();
                        let sdp_offer = self
                            .calls
                            .get(call_id)
                            .and_then(|s| s.local_sdp.clone())
                            .unwrap_or_default();

                        let mut request = Self::build_invite_request_static(
                            &remote_uri,
                            &self.aor,
                            &self.display_name,
                            effective_local_addr,
                            &sip_call_id,
                            new_cseq,
                            &from_tag,
                            &new_branch,
                            &sdp_offer,
                            &self.transport_type,
                        )?;

                        // Compute and add Authorization header
                        let hasher = Md5DigestHasher;
                        let cnonce = generate_cnonce();

                        // Use the Request-URI for the digest URI
                        let digest_uri = remote_uri.clone();

                        let auth_creds = create_credentials(
                            &hasher,
                            &challenge,
                            &creds.username,
                            &creds.password,
                            "INVITE",
                            &digest_uri,
                            Some(&cnonce),
                            Some(1_u32),
                            None,
                        )
                        .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

                        // Use Authorization for 401, Proxy-Authorization for 407
                        let auth_header = if status_code == 401 {
                            HeaderName::Authorization
                        } else {
                            HeaderName::ProxyAuthorization
                        };
                        request.headers.set(auth_header, auth_creds.to_string());

                        // Snapshot the exact Via of this authenticated INVITE —
                        // it is the LAST INVITE actually sent, so a later
                        // CANCEL/ACK must copy this Via, not the original's
                        // (RFC 3261 §9.1 / §17.1.1.3).
                        let new_via = request
                            .headers
                            .get_value(&HeaderName::Via)
                            .map(String::from);

                        // Create new INVITE transaction
                        let tx_key = TransactionKey::client(&new_branch, "INVITE");
                        let transaction =
                            ClientInviteTransaction::new(tx_key, TransportType::Reliable);

                        if let Some(session) = self.calls.get_mut(call_id) {
                            session.invite_transaction = Some(transaction);
                            session.last_branch = Some(new_branch);
                            session.last_via = new_via;
                        }

                        // Send the authenticated INVITE
                        info!(call_id = %call_id, "Sending authenticated INVITE");
                        self.event_tx
                            .send(CallEvent::SendRequest {
                                request,
                                destination,
                            })
                            .await
                            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

                        return Ok(());
                    }
                    warn!(call_id = %call_id, "INVITE digest auth failed (credentials rejected by server)");
                }
            }
        }

        // Fall through: no digest credentials, feature disabled, or auth failed.
        // ACK the 401 before terminating.
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag) =
            self.extract_session_data_for_ack(call_id)?;

        self.send_ack_for_failure(
            call_id,
            &remote_uri,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            response,
        )
        .await?;

        error!(
            call_id = %call_id,
            status_code = status_code,
            "INVITE auth challenge failed — no digest credentials available"
        );

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

        Ok(())
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
        call_id: &str,
        remote_uri: &str,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let destination = Self::parse_destination(remote_uri).await?;
        let effective_local_addr =
            Self::get_local_addr_for_destination(destination, self.local_addr).await?;

        // RFC 3261 §17.1.1.3: the ACK for a non-2xx final response must
        // carry the INVITE's Via verbatim (same branch, same sent-by
        // host:port) so it matches the INVITE transaction.
        let invite_via = self.calls.get(call_id).and_then(|s| s.last_via.clone());

        // §17.1.1.3 also requires the ACK's To header to equal the To of
        // the response being acknowledged (including any to-tag the server
        // added), not the INVITE's tag-less To.
        let response_to_tag = Self::extract_to_tag(response);
        let ack_to_tag = response_to_tag.as_deref().or(to_tag);

        let ack_request = Self::build_ack_request_static(
            remote_uri,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            sip_call_id,
            cseq,
            from_tag,
            ack_to_tag,
            &self.transport_type,
            invite_via.as_deref(),
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

    /// Returns the SIP Call-ID for a given application call ID.
    pub fn get_sip_call_id(&self, call_id: &str) -> Option<String> {
        self.calls.get(call_id).map(|s| s.sip_call_id.clone())
    }

    /// Returns the local From-tag for a given application call ID.
    pub fn get_local_tag(&self, call_id: &str) -> Option<String> {
        self.calls.get(call_id).map(|s| s.from_tag.clone())
    }

    /// Returns true if the call has a pending outbound INVITE transaction.
    pub fn has_pending_invite_transaction(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|s| s.invite_transaction.is_some())
    }

    /// Sends a CANCEL request for a pending INVITE.
    ///
    /// Per RFC 3261 §9.1, the CANCEL must be identical to the INVITE it
    /// cancels in Request-URI, Call-ID, To, From (including tags), and `CSeq`
    /// number (with method CANCEL), and must carry a single Via IDENTICAL to
    /// the INVITE's — same branch AND same sent-by host:port. The To header
    /// must NOT include a remote tag learned from a provisional response —
    /// the original INVITE had none. Live evidence: a fresh branch, or the
    /// same branch with a different sent-by port (each request used to
    /// snapshot a fresh ephemeral discovery-socket port), makes `BulkVS`
    /// reply 481 "Call/Transaction Does Not Exist" and the far end keeps
    /// ringing. The stored `last_via` is therefore copied verbatim.
    async fn send_cancel(&mut self, call_id: &str) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, branch, invite_via) = {
            let session = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                // CSeq number must equal the INVITE's CSeq (method CANCEL).
                session.cseq,
                session.from_tag.clone(),
                // Reuse the INVITE's Via branch — never generate a new one.
                session.last_branch.clone().ok_or_else(|| {
                    SipUaError::InvalidState(
                        "No pending INVITE branch to CANCEL (RFC 3261 §9.1)".to_string(),
                    )
                })?,
                // Reuse the INVITE's exact Via line (host AND port).
                session.last_via.clone().ok_or_else(|| {
                    SipUaError::InvalidState(
                        "No pending INVITE Via to CANCEL (RFC 3261 §9.1)".to_string(),
                    )
                })?,
            )
        };

        let destination = Self::parse_destination(&remote_uri).await?;

        // Build CANCEL request (same Via line and CSeq number as the INVITE)
        let request = Self::build_cancel_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            &sip_call_id,
            cseq,
            &from_tag,
            &invite_via,
        )?;

        // The CANCEL client transaction reuses the INVITE's branch so that
        // responses to the CANCEL (200/481) match this transaction.
        let tx_key = TransactionKey::client(&branch, "CANCEL");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.non_invite_transaction = Some(transaction);
            // The call is ending. Track the outstanding CANCEL so that a
            // 200 OK to the INVITE that wins the race (RFC 3261 §15: the
            // callee answered just as we cancelled) is ACKed and torn down
            // with a BYE instead of surfacing Connected to the app.
            session.cancel_pending = true;
            session.state = CallState::Terminating;
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
            .with_branch(branch)
            .with_rport();

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
            .with_branch(branch.to_string())
            .with_rport();

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
    ///
    /// Per RFC 3261 §9.1 the caller must pass the INVITE's complete Via
    /// header value (`invite_via`) — same branch AND same sent-by host:port
    /// — and the INVITE's `CSeq` number. The Via is copied verbatim rather
    /// than rebuilt, because the sent-by port is otherwise re-derived from a
    /// fresh ephemeral socket and would differ from the INVITE's. The To
    /// header deliberately carries no tag: the INVITE being cancelled was
    /// sent without one, and a CANCEL must match it.
    #[allow(clippy::too_many_arguments)]
    fn build_cancel_request_static(
        remote_uri_str: &str,
        aor: &str,
        display_name: &str,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        invite_via: &str,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        // No to-tag: must match the original INVITE's To header exactly.
        let to = NameAddr::new(remote_uri.clone());

        let request = RequestBuilder::cancel(remote_uri)
            // The INVITE's Via, verbatim (RFC 3261 §9.1).
            .header(HeaderName::Via, invite_via)
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
            .with_branch(branch)
            .with_rport();

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
    ///
    /// `invite_via` selects which transaction this ACK belongs to:
    /// - `Some(via)`: ACK for a non-2xx final response. RFC 3261 §17.1.1.3
    ///   requires the ACK to carry the INVITE's Via verbatim (same branch
    ///   and same sent-by host:port) so it matches the INVITE transaction.
    /// - `None`: ACK for a 2xx response. That ACK is a new transaction
    ///   (RFC 3261 §13.2.2.4), so a fresh Via with a new branch is built
    ///   from `local_addr`.
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
        invite_via: Option<&str>,
    ) -> SipUaResult<SipRequest> {
        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri.clone());
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let mut builder = RequestBuilder::ack(remote_uri);
        builder = if let Some(via_value) = invite_via {
            // Non-2xx ACK: the INVITE's Via, verbatim (RFC 3261 §17.1.1.3).
            builder.header(HeaderName::Via, via_value)
        } else {
            // 2xx ACK: new transaction, fresh branch (RFC 3261 §13.2.2.4).
            let via = ViaHeader::new(transport_type, local_addr.ip().to_string())
                .with_port(local_addr.port())
                .with_branch(generate_branch())
                .with_rport();
            builder.via(&via)
        };

        let request = builder
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
            .with_branch(branch.to_string())
            .with_rport();

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
            .with_branch(branch)
            .with_rport();

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
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_host)
            .await
            .map_err(|e| {
                error!(host = %host, error = %e, "parse_destination: DNS resolution failed");
                SipUaError::ConfigError(format!("DNS resolution failed for {host}: {e}"))
            })?
            .collect();

        // Prefer IPv6 (AAAA) over IPv4 (A) to match socket address family
        let result = addrs
            .iter()
            .find(|a| a.is_ipv6())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| {
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

    /// Extracts the method from a response's `CSeq` header (RFC 3261
    /// §8.1.3.3): responses are routed to a call by Call-ID alone, so the
    /// `CSeq` method is what tells an INVITE 200 apart from a CANCEL or
    /// BYE 200 on the same call.
    fn cseq_method(response: &SipResponse) -> Option<String> {
        response
            .headers
            .get_value(&HeaderName::CSeq)
            .and_then(|v| v.split_whitespace().nth(1))
            .map(str::to_ascii_uppercase)
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

    /// Extracts the branch parameter from a Via header value.
    fn via_branch(request: &SipRequest) -> String {
        let via = request.headers.get_value(&HeaderName::Via).unwrap();
        let start = via.find("branch=").unwrap() + "branch=".len();
        via[start..].split(';').next().unwrap().to_string()
    }

    fn sent_request(event: CallEvent) -> SipRequest {
        match event {
            CallEvent::SendRequest { request, .. } => request,
            other => panic!("expected SendRequest, got {other:?}"),
        }
    }

    /// RFC 3261 §9.1: a CANCEL must reuse the INVITE's Via branch and `CSeq`
    /// number (with method CANCEL), carry a Via line IDENTICAL to the
    /// INVITE's (host AND port), and must not include a To-tag the INVITE
    /// didn't have. Live evidence: a fresh branch — or the same branch with
    /// a different Via sent-by port (each request used to snapshot a fresh
    /// ephemeral discovery-socket port) — makes `BulkVS` reply 481
    /// "Call/Transaction Does Not Exist" and the far phone keeps ringing.
    ///
    /// The agent is deliberately configured with an unspecified local
    /// address (0.0.0.0:0) so each request goes through per-request
    /// ephemeral-port discovery — the exact condition that produced the
    /// differing Via ports on the wire.
    #[tokio::test]
    async fn test_cancel_reuses_invite_branch_and_cseq() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sips:alice@192.168.1.100".to_string(),
            "Alice".to_string(),
            tx,
        );

        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.100\r\n";
        let call_id = agent
            .make_call("sips:bob@127.0.0.1:5061", sdp)
            .await
            .unwrap();

        // Drain StateChanged, then capture the INVITE
        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());

        // Simulate a 180 Ringing that delivered a remote To-tag; the CANCEL
        // must NOT echo it (the INVITE was sent without one).
        let session = agent.calls.get_mut(&call_id).unwrap();
        session.state = CallState::Ringing;
        session.to_tag = Some("remote-tag-from-180".to_string());

        agent.send_cancel(&call_id).await.unwrap();
        let cancel = sent_request(rx.recv().await.unwrap());

        assert_eq!(cancel.method.to_string(), "CANCEL");

        // Same Via branch as the INVITE (RFC 3261 §9.1)
        assert_eq!(via_branch(&cancel), via_branch(&invite));

        // The FULL Via line must match verbatim — host AND port. A matching
        // branch with a different sent-by port still fails transaction
        // matching at the server (live wire: 58707 vs 60827 → 481).
        assert_eq!(
            cancel.headers.get_value(&HeaderName::Via).unwrap(),
            invite.headers.get_value(&HeaderName::Via).unwrap(),
            "CANCEL must copy the INVITE's exact Via line (RFC 3261 §9.1)"
        );

        // Same CSeq number, method CANCEL
        let invite_cseq = invite.headers.get_value(&HeaderName::CSeq).unwrap();
        let cancel_cseq = cancel.headers.get_value(&HeaderName::CSeq).unwrap();
        let invite_cseq_num = invite_cseq.split_whitespace().next().unwrap();
        let mut cancel_cseq_parts = cancel_cseq.split_whitespace();
        assert_eq!(cancel_cseq_parts.next().unwrap(), invite_cseq_num);
        assert_eq!(cancel_cseq_parts.next().unwrap(), "CANCEL");

        // Identical Request-URI, Call-ID, and From (including tag)
        assert_eq!(cancel.uri.to_string(), invite.uri.to_string());
        assert_eq!(
            cancel.headers.get_value(&HeaderName::CallId),
            invite.headers.get_value(&HeaderName::CallId)
        );
        assert_eq!(
            cancel.headers.get_value(&HeaderName::From),
            invite.headers.get_value(&HeaderName::From)
        );

        // To must match the INVITE's To: no remote tag from the 180
        let cancel_to = cancel.headers.get_value(&HeaderName::To).unwrap();
        assert!(
            !cancel_to.contains("tag="),
            "CANCEL To header must not carry a to-tag the INVITE didn't have: {cancel_to}"
        );
        assert_eq!(
            cancel_to,
            invite.headers.get_value(&HeaderName::To).unwrap()
        );
    }

    /// RFC 3261 §15 / §9.1 race: the UAC sends CANCEL for a pending INVITE
    /// but a 200 OK to the INVITE arrives anyway (the callee answered just
    /// as we cancelled). The UAC MUST ACK the 200 (§13.2.2.4: To-tag from
    /// the 200) and then immediately send a BYE for the now-established
    /// dialog — and must never surface Connected to the app.
    ///
    /// Live evidence (`BulkVS`): hangup during `EarlyMedia` → CANCEL sent →
    /// 80ms later "INVITE 200 OK processed ... state=Connected" → the call
    /// went Terminated with reason Cancelled but NO BYE was sent, leaving
    /// the carrier holding an established leg until it timed out.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_ack_and_bye_when_200_ok_wins_race_against_cancel() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(32);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );

        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n";
        let call_id = agent
            .make_call("sip:bob@127.0.0.1:5061", sdp)
            .await
            .unwrap();

        // Drain StateChanged(Dialing), then capture the INVITE
        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());
        let sip_call_id = invite
            .headers
            .get_value(&HeaderName::CallId)
            .unwrap()
            .to_string();

        // Simulate a 180 Ringing carrying a provisional To-tag
        let mut ringing = SipResponse::new(StatusCode::RINGING);
        ringing
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-from-180");
        ringing.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ringing, &call_id).await.unwrap();
        let _ = rx.recv().await.unwrap(); // StateChanged(Ringing)
        assert_eq!(agent.get_state(&call_id), Some(CallState::Ringing));

        // Hang up while ringing: a CANCEL goes out for the pending INVITE
        agent.hangup(&call_id).await.unwrap();
        let cancel = sent_request(rx.recv().await.unwrap());
        assert_eq!(cancel.method.to_string(), "CANCEL");
        let _ = rx.recv().await.unwrap(); // StateChanged(Terminating)
        assert_eq!(agent.get_state(&call_id), Some(CallState::Terminating));

        // The 200 OK to the CANCEL only confirms the CANCEL was received
        // (§9.1) — it must not decide the call's fate.
        let mut cancel_ok = SipResponse::new(StatusCode::OK);
        cancel_ok.headers.set(HeaderName::CSeq, "1 CANCEL");
        agent.handle_response(&cancel_ok, &call_id).await.unwrap();
        assert_eq!(agent.get_state(&call_id), Some(CallState::Terminating));

        // Glare: the callee answered just as we cancelled — the 200 OK to
        // the INVITE wins the race (live wire: 80ms after the CANCEL).
        let mut invite_ok = SipResponse::new(StatusCode::OK);
        invite_ok
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-from-200");
        invite_ok.headers.set(HeaderName::CSeq, "1 INVITE");
        invite_ok.body = Some(bytes::Bytes::from_static(
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
        ));
        agent.handle_response(&invite_ok, &call_id).await.unwrap();

        // Drain everything the glare produced
        let mut requests = Vec::new();
        let mut saw_connected = false;
        let mut saw_sdp_answer = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                CallEvent::SendRequest { request, .. } => requests.push(request),
                CallEvent::StateChanged { state, .. } => {
                    saw_connected |= state == CallState::Connected;
                }
                CallEvent::SdpAnswerReceived { .. } => saw_sdp_answer = true,
                _ => {}
            }
        }

        // The UAC MUST ACK the 200 and then immediately BYE (RFC 3261 §15)
        assert_eq!(
            requests.len(),
            2,
            "expected exactly ACK then BYE, got {requests:#?}"
        );
        let ack = &requests[0];
        let bye = &requests[1];

        assert_eq!(ack.method.to_string(), "ACK");
        assert_eq!(
            ack.headers.get_value(&HeaderName::CallId).unwrap(),
            sip_call_id,
            "ACK must belong to the INVITE's dialog (Call-ID)"
        );
        assert!(
            ack.headers
                .get_value(&HeaderName::To)
                .unwrap()
                .contains("tag=tag-from-200"),
            "2xx ACK must carry the 200's To-tag (RFC 3261 §13.2.2.4)"
        );
        assert_eq!(ack.headers.get_value(&HeaderName::CSeq).unwrap(), "1 ACK");

        assert_eq!(bye.method.to_string(), "BYE");
        assert_eq!(
            bye.headers.get_value(&HeaderName::CallId).unwrap(),
            sip_call_id,
            "BYE must belong to the INVITE's dialog (Call-ID)"
        );
        assert!(
            bye.headers
                .get_value(&HeaderName::To)
                .unwrap()
                .contains("tag=tag-from-200"),
            "BYE must target the dialog the 200 OK established (To-tag)"
        );
        assert_eq!(bye.headers.get_value(&HeaderName::CSeq).unwrap(), "2 BYE");

        // The call never reported Connected and never started audio
        assert!(
            !saw_connected,
            "call must not surface Connected after hangup (CANCEL pending)"
        );
        assert!(
            !saw_sdp_answer,
            "must not deliver an SDP answer (audio start) for a cancelled call"
        );
        assert_eq!(agent.get_state(&call_id), Some(CallState::Terminating));

        // The BYE's 200 OK completes the teardown
        let mut bye_ok = SipResponse::new(StatusCode::OK);
        bye_ok.headers.set(HeaderName::CSeq, "2 BYE");
        agent.handle_response(&bye_ok, &call_id).await.unwrap();
        assert_eq!(agent.get_state(&call_id), Some(CallState::Terminated));
    }

    /// `BulkVS` flow: INVITE (`CSeq` 1) → 401 → ACK → auth'd INVITE (`CSeq` 2).
    /// The auth'd INVITE is the LAST one actually sent, so a CANCEL must
    /// copy ITS exact Via line (RFC 3261 §9.1), and the ACK to the 401 must
    /// copy the FIRST INVITE's exact Via line (RFC 3261 §17.1.1.3) along
    /// with the 401's To-tag.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_cancel_via_matches_authed_invite_after_401_resend() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );
        agent.configure(
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            None,
            "UDP",
            Some(client_types::DigestAuthCredentials::new("alice", "secret")),
        );

        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n";
        let call_id = agent
            .make_call("sip:bob@127.0.0.1:5061", sdp)
            .await
            .unwrap();

        // Drain StateChanged, then capture the first INVITE (CSeq 1)
        let _ = rx.recv().await.unwrap();
        let invite1 = sent_request(rx.recv().await.unwrap());
        let invite1_via = invite1.headers.get_value(&HeaderName::Via).unwrap();

        // Simulate the provider's 401 challenge (with a server To-tag)
        let mut challenge = SipResponse::new(StatusCode::UNAUTHORIZED);
        challenge
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=srv-401-tag");
        challenge.headers.set(
            HeaderName::WwwAuthenticate,
            "Digest realm=\"bulkvs\", nonce=\"abc123\"",
        );
        agent.handle_response(&challenge, &call_id).await.unwrap();

        // ACK for the 401: must copy INVITE 1's exact Via line (§17.1.1.3)
        // and echo the 401's To-tag, with the INVITE's CSeq number.
        let ack = sent_request(rx.recv().await.unwrap());
        assert_eq!(ack.method.to_string(), "ACK");
        assert_eq!(
            ack.headers.get_value(&HeaderName::Via).unwrap(),
            invite1_via,
            "ACK for non-2xx must copy the INVITE's exact Via line (RFC 3261 §17.1.1.3)"
        );
        assert!(
            ack.headers
                .get_value(&HeaderName::To)
                .unwrap()
                .contains("tag=srv-401-tag"),
            "ACK To must equal the To of the response being acknowledged"
        );
        assert_eq!(ack.headers.get_value(&HeaderName::CSeq).unwrap(), "1 ACK");

        // Authenticated INVITE resend (CSeq 2) — the LAST INVITE sent.
        let invite2 = sent_request(rx.recv().await.unwrap());
        assert_eq!(invite2.method.to_string(), "INVITE");
        let invite2_via = invite2.headers.get_value(&HeaderName::Via).unwrap();
        assert_eq!(
            invite2.headers.get_value(&HeaderName::CSeq).unwrap(),
            "2 INVITE"
        );

        // CANCEL must copy the auth'd INVITE's exact Via line and CSeq number.
        agent.send_cancel(&call_id).await.unwrap();
        let cancel = sent_request(rx.recv().await.unwrap());
        assert_eq!(cancel.method.to_string(), "CANCEL");
        assert_eq!(
            cancel.headers.get_value(&HeaderName::Via).unwrap(),
            invite2_via,
            "CANCEL must copy the last-sent INVITE's exact Via line (RFC 3261 §9.1)"
        );
        assert_eq!(
            cancel.headers.get_value(&HeaderName::CSeq).unwrap(),
            "2 CANCEL"
        );
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
