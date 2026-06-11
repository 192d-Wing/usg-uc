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
use proto_sip::uri::{SipUri, UriScheme};
use proto_transaction::client::{ClientInviteTransaction, ClientNonInviteTransaction};
use proto_transaction::{TransactionKey, TransportType};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uc_dns::{SipResolver, TransportPreference};
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
    /// RFC 3263 resolver (NAPTR/SRV/A) for SIP URI destinations. Created
    /// lazily on first use because the underlying DNS resolver needs a
    /// running tokio runtime.
    resolver: OnceLock<SipResolver>,
    /// Our public address as seen by the peer, learned from `received`/
    /// `rport` on the top Via of responses (RFC 3581). When set, it is
    /// used as the advertised address (Via sent-by, Contact) of
    /// subsequently built requests on the call paths.
    public_addr: Option<SocketAddr>,
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
    /// Dialog route set, stored in the order Route headers are emitted on
    /// in-dialog requests. For this UAC that is the REVERSED Record-Route
    /// order of the dialog-establishing response (RFC 3261 §12.1.2).
    /// Entries are full name-addr values (e.g. `<sip:proxy;lr>`).
    route_set: Vec<String>,
    /// Remote target: the URI from the Contact header of the
    /// dialog-establishing response, refreshed by re-INVITE 2xx responses
    /// (RFC 3261 §12.2.1.1). It is the Request-URI of in-dialog requests.
    remote_target: Option<String>,
    /// Last branch parameter.
    last_branch: Option<String>,
    /// Max-Forwards of the last INVITE actually sent. RFC 3261 §9.1
    /// requires the CANCEL to carry the same Max-Forwards as the request
    /// it cancels, and §17.1.1.3 requires the same for the ACK to a
    /// non-2xx final response — neither may reset it to 70.
    last_max_forwards: Option<u8>,
    /// SDP and hold-flag of the last re-INVITE sent, kept for the one-shot
    /// 491 glare retry (RFC 3261 §14.1).
    last_reinvite: Option<(String, bool)>,
    /// Number of consecutive 491 responses to the current re-INVITE.
    reinvite_glare_attempts: u8,
    /// Pending re-INVITE retry scheduled after a 491 (RFC 3261 §14.1).
    reinvite_retry: Option<ReinviteRetry>,
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
    /// The ACK sent in answer to an INVITE's 2xx, stored verbatim so a
    /// retransmitted 2xx (our ACK was lost) is answered with the identical
    /// ACK instead of being dropped or reprocessed (RFC 6026 §2).
    last_ack: Option<StoredAck>,
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

/// A scheduled re-INVITE retry after 491 glare (RFC 3261 §14.1).
struct ReinviteRetry {
    /// When the retry fires.
    at: Instant,
    /// The SDP of the re-INVITE to retry.
    sdp: String,
    /// Whether the re-INVITE was a hold.
    is_hold: bool,
}

/// Request routing for an in-dialog request (RFC 3261 §12.2.1.1):
/// where the Request-URI points, which Route headers to carry, and which
/// hop the request is physically sent to.
struct DialogTarget {
    /// The Request-URI (the remote target, or the first strict route).
    request_uri: String,
    /// Route header values, in emission order.
    routes: Vec<String>,
    /// URI whose resolved address the request is sent to (first route,
    /// or the remote target when the route set is empty).
    next_hop: String,
}

/// The ACK sent for an INVITE's 2xx response, kept so a retransmitted 2xx
/// can be answered with a byte-identical ACK (RFC 6026 §2).
struct StoredAck {
    /// `CSeq` number of the INVITE whose 2xx this ACK acknowledges.
    cseq: u32,
    /// The ACK request exactly as first sent.
    request: SipRequest,
    /// Destination the ACK was sent to.
    destination: SocketAddr,
}

/// Which pending client transaction owns an incoming response
/// (RFC 3261 §17.1.3: matched by top Via branch + `CSeq` method).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseTxMatch {
    /// The pending INVITE transaction.
    Invite,
    /// The pending non-INVITE transaction (BYE, CANCEL, REFER, ...).
    NonInvite,
    /// No pending client transaction matches.
    Unmatched,
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
            resolver: OnceLock::new(),
            public_addr: None,
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
    ///
    /// `record_routes` are the raw Record-Route header values of the
    /// incoming INVITE, in received order. For a UAS the dialog route set
    /// is that order, NOT reversed (RFC 3261 §12.1.1).
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
        record_routes: &[String],
    ) {
        let route_set: Vec<String> = record_routes
            .iter()
            .flat_map(|v| Self::split_header_list(v))
            .collect();
        if !route_set.is_empty() {
            info!(
                call_id = %call_id,
                route_set = ?route_set,
                "Captured dialog route set from incoming INVITE Record-Route (RFC 3261 §12.1.1)"
            );
        }
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
            route_set,
            remote_target: Some(remote_uri.to_string()),
            last_branch: None,
            last_max_forwards: None,
            last_reinvite: None,
            reinvite_glare_attempts: 0,
            reinvite_retry: None,
            last_via: None,
            cancel_pending: false,
            last_ack: None,
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
    #[allow(clippy::too_many_lines)]
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
        let destination = self.parse_destination(remote_uri).await?;

        // Get the local IP address that can reach the destination
        let effective_local_addr = self.effective_local_addr(destination).await?;
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

        // Snapshot the INVITE's Max-Forwards; CANCEL and the ACK to a
        // non-2xx final response must reuse it (RFC 3261 §9.1 / §17.1.1.3).
        let invite_max_forwards = Self::request_max_forwards(&request);

        // Create INVITE transaction
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction =
            ClientInviteTransaction::new(tx_key, TransportType::Reliable).with_cseq(1);

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
            route_set: Vec::new(),
            remote_target: None,
            last_branch: Some(branch),
            last_max_forwards: invite_max_forwards,
            last_reinvite: None,
            reinvite_glare_attempts: 0,
            reinvite_retry: None,
            last_via: invite_via,
            cancel_pending: false,
            last_ack: None,
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

        self.reset_glare_attempts(call_id);
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

        self.reset_glare_attempts(call_id);
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

        self.reset_glare_attempts(call_id);
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
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, target) = {
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
                Self::dialog_target(session),
            )
        };

        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;

        // The transaction key must carry the branch actually sent on the
        // wire so responses match it (RFC 3261 §17.1.3).
        let branch = generate_branch();

        // Build REFER request
        let request = Self::build_refer_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &branch,
            transfer_target,
            &self.transport_type,
        )?;

        // Create non-INVITE transaction for REFER
        let tx_key = TransactionKey::client(&branch, "REFER");
        let transaction =
            ClientNonInviteTransaction::new(tx_key, TransportType::Reliable).with_cseq(cseq);

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
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, target) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cseq += 1;
            session.local_sdp = Some(sdp.to_string());
            // Keep the offer around for a one-shot 491 glare retry
            // (RFC 3261 §14.1).
            session.last_reinvite = Some((sdp.to_string(), is_hold));

            (
                session.remote_uri.clone(),
                session.sip_call_id.clone(),
                session.cseq,
                session.from_tag.clone(),
                session.to_tag.clone(),
                Self::dialog_target(session),
            )
        };

        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;
        let branch = generate_branch();

        // Build re-INVITE request
        let request = Self::build_reinvite_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
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
        let reinvite_max_forwards = Self::request_max_forwards(&request);

        // Create INVITE transaction for re-INVITE
        let tx_key = TransactionKey::client(&branch, "INVITE");
        let transaction =
            ClientInviteTransaction::new(tx_key, TransportType::Reliable).with_cseq(cseq);

        if let Some(session) = self.calls.get_mut(call_id) {
            session.invite_transaction = Some(transaction);
            session.last_branch = Some(branch);
            session.last_via = reinvite_via;
            session.last_max_forwards = reinvite_max_forwards;
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
    ///
    /// The response was routed to this call by Call-ID alone; before any
    /// call state is mutated it is matched to the owning client transaction
    /// by top Via branch + `CSeq` method (RFC 3261 §17.1.3), and its `CSeq`
    /// number is validated against the pending request's (RFC 3261
    /// §12.2.1.1). Retransmitted responses are absorbed by the transaction
    /// (RFC 3261 §17.1.2.2). Responses matching no transaction are dropped,
    /// except a retransmitted 2xx to an already-ACKed INVITE, which
    /// re-sends the identical ACK (RFC 6026 §2).
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

        // RFC 3581: learn our NAT public address from received/rport on
        // the top Via before anything else — even absorbed retransmissions
        // carry valid transport-layer information.
        self.update_public_addr_from_via(response);

        // Transaction-layer gate: only responses that belong to a pending
        // transaction (and are not retransmissions) reach the handlers.
        if !self.gate_response_to_transaction(response, call_id).await? {
            return Ok(());
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
            491 => {
                self.handle_request_pending_response(call_id, response)
                    .await?;
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

        // RFC 3261 §12.1: ANY provisional response with a To-tag (180
        // included, not just 183) establishes an early dialog — capture the
        // tag, the Record-Route route set, and the remote target. Once set,
        // a DIFFERING tag on a later 1xx (a forked early dialog) is ignored
        // with a warning; only a 2xx may finalize a different tag.
        if let Some(session) = self.calls.get_mut(call_id)
            && let Some(tag) = Self::extract_to_tag(response)
        {
            match &session.to_tag {
                None => {
                    session.to_tag = Some(tag);
                    Self::capture_route_set(session, response);
                    Self::capture_remote_target(session, response);
                }
                Some(existing) if *existing != tag => {
                    warn!(
                        call_id = %call_id,
                        existing_tag = %existing,
                        new_tag = %tag,
                        "Ignoring differing To-tag on later 1xx (forked early dialog); \
                         only a 2xx may finalize a different tag (RFC 3261 §12.1)"
                    );
                }
                Some(_) => {}
            }
        }

        // Extract early SDP if present (183). RFC 3264 §6: ignore an early
        // answer whose codecs do not intersect our offer — starting media
        // on it would produce one-way or no audio.
        if status_code == 183
            && let Some(body) = &response.body
        {
            let sdp = String::from_utf8_lossy(body).to_string();
            let offer = self.calls.get(call_id).and_then(|s| s.local_sdp.clone());
            if offer.is_some_and(|o| !Self::sdp_codecs_intersect(&o, &sdp)) {
                warn!(
                    call_id = %call_id,
                    "Ignoring early SDP (183): answer codecs do not intersect our offer (RFC 3264 §6)"
                );
            } else {
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
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
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
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, current_state, target) = {
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

            // RFC 3261 §12.1.2: the dialog-establishing 2xx fixes the route
            // set from its Record-Route headers (reversed for this UAC). A
            // re-INVITE 2xx never modifies the route set, but its Contact
            // DOES refresh the remote target (§12.2.1.1).
            if session.connected_at.is_none() {
                Self::capture_route_set(session, response);
            }
            Self::capture_remote_target(session, response);

            // For a hold re-INVITE 200 OK, preserve the OnHold state.
            // Only transition to Connected for the initial INVITE or resume.
            if session.state != CallState::OnHold {
                session.state = CallState::Connected;
                session.connected_at = Some(Instant::now());
            }
            session.invite_transaction = None;
            // A 2xx ends any 491 glare backoff for the re-INVITE.
            session.reinvite_glare_attempts = 0;
            session.reinvite_retry = None;

            // RFC 3261 §12.1: the 2xx finalizes the dialog's To-tag. A tag
            // differing from one learned on a 1xx means a different fork
            // answered — adopt the 2xx's tag (it identifies the confirmed
            // dialog the ACK must address).
            if let Some(tag) = Self::extract_to_tag(response) {
                if session
                    .to_tag
                    .as_deref()
                    .is_some_and(|existing| existing != tag)
                {
                    warn!(
                        call_id = %call_id,
                        provisional_tag = ?session.to_tag,
                        final_tag = %tag,
                        "2xx finalizes dialog with a To-tag differing from the provisional's \
                         (forking); adopting the 2xx tag (RFC 3261 §12.1)"
                    );
                }
                session.to_tag = Some(tag);
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
                Self::dialog_target(session),
            )
        };

        // Send ACK (for a 2xx: a new transaction with a fresh Via/branch),
        // routed through the dialog's route set to the remote target
        // (RFC 3261 §13.2.2.4 / §12.2.1.1).
        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;
        let ack_request = Self::build_ack_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &self.transport_type,
            None,
            70,
        )?;

        // Keep the ACK verbatim: a retransmitted 200 (our ACK was lost)
        // must be answered with the identical ACK (RFC 6026 §2).
        if let Some(session) = self.calls.get_mut(call_id) {
            session.last_ack = Some(StoredAck {
                cseq,
                request: ack_request.clone(),
                destination,
            });
        }

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
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, target) = {
            let session = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipUaError::InvalidState("Call not found".to_string()))?;

            session.cancel_pending = false;
            session.invite_transaction = None;

            // The 200 established a dialog: capture its route set and
            // remote target so the ACK and the tear-down BYE traverse any
            // Record-Routing proxies (RFC 3261 §12.1.2).
            if session.connected_at.is_none() {
                Self::capture_route_set(session, response);
            }
            Self::capture_remote_target(session, response);

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
                Self::dialog_target(session),
            )
        };

        info!(
            call_id = %call_id,
            "INVITE 200 OK won the race against CANCEL; sending ACK then BYE (RFC 3261 §15)"
        );

        // ACK the 2xx: a new transaction with a fresh Via/branch (§13.2.2.4).
        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;
        let ack_request = Self::build_ack_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            &sip_call_id,
            cseq,
            &from_tag,
            to_tag.as_deref(),
            &self.transport_type,
            None,
            70,
        )?;

        // Keep the ACK verbatim for retransmitted 200s (RFC 6026 §2).
        if let Some(session) = self.calls.get_mut(call_id) {
            session.last_ack = Some(StoredAck {
                cseq,
                request: ack_request.clone(),
                destination,
            });
        }

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
                        let destination = self.parse_destination(&remote_uri).await?;
                        let effective_local_addr = self.effective_local_addr(destination).await?;

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
                        let new_max_forwards = Self::request_max_forwards(&request);

                        // Create new INVITE transaction
                        let tx_key = TransactionKey::client(&new_branch, "INVITE");
                        let transaction =
                            ClientInviteTransaction::new(tx_key, TransportType::Reliable)
                                .with_cseq(new_cseq);

                        if let Some(session) = self.calls.get_mut(call_id) {
                            session.invite_transaction = Some(transaction);
                            session.last_branch = Some(new_branch);
                            session.last_via = new_via;
                            session.last_max_forwards = new_max_forwards;
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

        // RFC 3261 §21.5.2: surface Retry-After so the app can back off
        // instead of immediately redialing a busy/declined destination.
        let reason = Self::retry_after_secs(response).map_or_else(
            || "Busy".to_string(),
            |secs| format!("Busy (Retry-After: {secs}s)"),
        );

        if let Some(session) = self.calls.get_mut(call_id) {
            session.state = CallState::Terminated;
            session.failure_reason = Some(CallFailureReason::Rejected {
                status_code,
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

        let mut reason = response
            .reason
            .clone()
            .unwrap_or_else(|| "Unknown error".to_string());

        // RFC 3261 §21.5.2: surface Retry-After (503 Service Unavailable
        // etc.) so the app can back off instead of hammering the server.
        if let Some(secs) = Self::retry_after_secs(response) {
            reason = format!("{reason} (Retry-After: {secs}s)");
        }

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

    /// Handles a 491 Request Pending (RFC 3261 §14.1 glare).
    ///
    /// For a re-INVITE on an established dialog the 491 means our offer
    /// collided with one from the peer: ACK the 491, keep the call alive,
    /// and retry the re-INVITE ONCE after a 2–4 s backoff (as the
    /// Call-ID owner; the retry fires from `process_timers`). A 491 to the
    /// initial INVITE is handled as an ordinary call failure.
    async fn handle_request_pending_response(
        &mut self,
        call_id: &str,
        response: &SipResponse,
    ) -> SipUaResult<()> {
        let is_reinvite = self
            .calls
            .get(call_id)
            .is_some_and(|s| s.connected_at.is_some());
        if !is_reinvite {
            return self.handle_failure_response(call_id, 491, response).await;
        }

        // ACK the non-2xx final response (RFC 3261 §17.1.1.3).
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
        session.invite_transaction = None;
        session.reinvite_glare_attempts = session.reinvite_glare_attempts.saturating_add(1);

        if session.reinvite_glare_attempts > 1 {
            warn!(
                call_id = %call_id,
                "re-INVITE rejected with 491 again after backoff; giving up (RFC 3261 §14.1)"
            );
            session.last_reinvite = None;
            return Ok(());
        }

        if let Some((sdp, is_hold)) = session.last_reinvite.clone() {
            let delay_ms = Self::glare_retry_delay_ms();
            session.reinvite_retry = Some(ReinviteRetry {
                at: Instant::now() + Duration::from_millis(delay_ms),
                sdp,
                is_hold,
            });
            info!(
                call_id = %call_id,
                delay_ms = delay_ms,
                "491 glare on re-INVITE; retrying once after backoff (RFC 3261 §14.1)"
            );
        }
        Ok(())
    }

    /// Returns a 2–4 s backoff for the 491 glare retry (RFC 3261 §14.1).
    fn glare_retry_delay_ms() -> u64 {
        // Cheap jitter without a rand dependency: sub-millisecond clock
        // noise is more than random enough for collision avoidance.
        let nanos = u64::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos()),
        );
        2000 + (nanos % 2001)
    }

    /// Drives the agent's time-based behavior (currently the 491 glare
    /// retry, RFC 3261 §14.1). Call periodically from the app event pump.
    pub async fn process_timers(&mut self) -> SipUaResult<()> {
        let now = Instant::now();
        let due: Vec<(String, String, bool)> = self
            .calls
            .values_mut()
            .filter_map(|session| {
                if session
                    .reinvite_retry
                    .as_ref()
                    .is_some_and(|retry| retry.at <= now)
                {
                    session
                        .reinvite_retry
                        .take()
                        .map(|retry| (session.id.clone(), retry.sdp, retry.is_hold))
                } else {
                    None
                }
            })
            .collect();

        for (call_id, sdp, is_hold) in due {
            if matches!(
                self.get_state(&call_id),
                Some(CallState::Connected | CallState::OnHold)
            ) {
                info!(
                    call_id = %call_id,
                    "Retrying re-INVITE after 491 glare backoff (RFC 3261 §14.1)"
                );
                self.send_reinvite(&call_id, &sdp, is_hold).await?;
            }
        }
        Ok(())
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
        // RFC 3261 §17.1.1.3: the ACK must carry the same Request-URI and
        // Route headers as the INVITE it acknowledges. The initial INVITE
        // was sent to the remote URI with no routes; a re-INVITE on an
        // established dialog used the dialog's remote target + route set.
        let target = self.calls.get(call_id).map_or_else(
            || DialogTarget {
                request_uri: remote_uri.to_string(),
                routes: Vec::new(),
                next_hop: remote_uri.to_string(),
            },
            |session| {
                if session.connected_at.is_some() {
                    Self::dialog_target(session)
                } else {
                    DialogTarget {
                        request_uri: session.remote_uri.clone(),
                        routes: Vec::new(),
                        next_hop: session.remote_uri.clone(),
                    }
                }
            },
        );

        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;

        // RFC 3261 §17.1.1.3: the ACK for a non-2xx final response must
        // carry the INVITE's Via verbatim (same branch, same sent-by
        // host:port) so it matches the INVITE transaction — and the
        // INVITE's Max-Forwards (§9.1 family), not a reset 70.
        let (invite_via, invite_max_forwards) = self
            .calls
            .get(call_id)
            .map_or((None, None), |s| (s.last_via.clone(), s.last_max_forwards));

        // §17.1.1.3 also requires the ACK's To header to equal the To of
        // the response being acknowledged (including any to-tag the server
        // added), not the INVITE's tag-less To.
        let response_to_tag = Self::extract_to_tag(response);
        let ack_to_tag = response_to_tag.as_deref().or(to_tag);

        let ack_request = Self::build_ack_request_static(
            &target.request_uri,
            remote_uri,
            &target.routes,
            &self.aor,
            &self.display_name,
            effective_local_addr,
            sip_call_id,
            cseq,
            from_tag,
            ack_to_tag,
            &self.transport_type,
            invite_via.as_deref(),
            invite_max_forwards.unwrap_or(70),
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
        let (remote_uri, sip_call_id, cseq, from_tag, branch, invite_via, invite_max_forwards) = {
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
                // Reuse the INVITE's Max-Forwards (RFC 3261 §9.1).
                session.last_max_forwards.unwrap_or(70),
            )
        };

        let destination = self.parse_destination(&remote_uri).await?;

        // Build CANCEL request (same Via line, CSeq number, and
        // Max-Forwards as the INVITE)
        let request = Self::build_cancel_request_static(
            &remote_uri,
            &self.aor,
            &self.display_name,
            &sip_call_id,
            cseq,
            &from_tag,
            &invite_via,
            invite_max_forwards,
        )?;

        // The CANCEL client transaction reuses the INVITE's branch so that
        // responses to the CANCEL (200/481) match this transaction.
        let tx_key = TransactionKey::client(&branch, "CANCEL");
        let transaction =
            ClientNonInviteTransaction::new(tx_key, TransportType::Reliable).with_cseq(cseq);

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
    ///
    /// The BYE is an in-dialog request: its Request-URI is the dialog's
    /// remote target (the peer's Contact) and it carries the dialog's
    /// route set so Record-Routing proxies stay on the path
    /// (RFC 3261 §12.2.1.1).
    async fn send_bye(&mut self, call_id: &str) -> SipUaResult<()> {
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, target) = {
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
                Self::dialog_target(session),
            )
        };

        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;

        // The transaction key must carry the branch actually sent on the
        // wire so the BYE's 200 matches it (RFC 3261 §17.1.3).
        let branch = generate_branch();

        // Build BYE request
        let request = Self::build_bye_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
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
        let tx_key = TransactionKey::client(&branch, "BYE");
        let transaction =
            ClientNonInviteTransaction::new(tx_key, TransportType::Reliable).with_cseq(cseq);

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
        let (remote_uri, sip_call_id, cseq, from_tag, to_tag, target) = {
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
                Self::dialog_target(session),
            )
        };

        let destination = self.parse_destination(&target.next_hop).await?;
        let effective_local_addr = self.effective_local_addr(destination).await?;

        let request = Self::build_info_request_static(
            &target.request_uri,
            &remote_uri,
            &target.routes,
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
    ///
    /// `request_uri_str` is the dialog's remote target and `routes` its
    /// route set (RFC 3261 §12.2.1.1); `remote_uri_str` is the dialog's
    /// remote URI used in the To header.
    #[allow(clippy::too_many_arguments)]
    fn build_info_request_static(
        request_uri_str: &str,
        remote_uri_str: &str,
        routes: &[String],
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

        let request_uri: SipUri = request_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid request URI: {e}")))?;

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

        let mut to = NameAddr::new(remote_uri);
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        // Duration in RTP timestamp units (8 samples/ms at 8kHz)
        let rtp_duration = duration_ms * 8;
        let body = format!("Signal={}\r\nDuration={rtp_duration}", digit.to_char());

        let mut builder = RequestBuilder::new(Method::Info, request_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70);
        for route in routes {
            builder = builder.header(HeaderName::Route, route);
        }
        let request = builder
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
        max_forwards: u8,
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
            // The INVITE's Max-Forwards, not a reset 70 (RFC 3261 §9.1).
            .max_forwards(max_forwards)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a BYE request (static version).
    ///
    /// `branch` is the Via branch the caller registered in the transaction
    /// key, so responses match the transaction (RFC 3261 §17.1.3).
    /// `request_uri_str` is the dialog's remote target and `routes` its
    /// route set (RFC 3261 §12.2.1.1); `remote_uri_str` is the dialog's
    /// remote URI used in the To header.
    #[allow(clippy::too_many_arguments)]
    fn build_bye_request_static(
        request_uri_str: &str,
        remote_uri_str: &str,
        routes: &[String],
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
        let request_uri: SipUri = request_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid request URI: {e}")))?;

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

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri);
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let mut builder = RequestBuilder::bye(request_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70);
        for route in routes {
            builder = builder.header(HeaderName::Route, route);
        }
        let request = builder
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds an ACK request (static version).
    ///
    /// `invite_via` selects which transaction this ACK belongs to:
    /// - `Some(via)`: ACK for a non-2xx final response. RFC 3261 §17.1.1.3
    ///   requires the ACK to carry the INVITE's Via verbatim (same branch
    ///   and same sent-by host:port) so it matches the INVITE transaction,
    ///   and the INVITE's `max_forwards` rather than a reset 70.
    /// - `None`: ACK for a 2xx response. That ACK is a new transaction
    ///   (RFC 3261 §13.2.2.4), so a fresh Via with a new branch is built
    ///   from `local_addr`.
    ///
    /// `request_uri_str` and `routes` carry the same Request-URI and Route
    /// set as the INVITE being acknowledged (RFC 3261 §17.1.1.3 /
    /// §12.2.1.1); `remote_uri_str` is the dialog's remote URI for the To
    /// header.
    #[allow(clippy::too_many_arguments)]
    fn build_ack_request_static(
        request_uri_str: &str,
        remote_uri_str: &str,
        routes: &[String],
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        transport_type: &str,
        invite_via: Option<&str>,
        max_forwards: u8,
    ) -> SipUaResult<SipRequest> {
        let request_uri: SipUri = request_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid request URI: {e}")))?;

        let remote_uri: SipUri = remote_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid remote URI: {e}")))?;

        let aor_uri: SipUri = aor
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid AOR: {e}")))?;

        let from = NameAddr::new(aor_uri)
            .with_display_name(display_name)
            .with_tag(from_tag.to_string());

        let mut to = NameAddr::new(remote_uri);
        if let Some(tag) = to_tag {
            to = to.with_tag(tag.to_string());
        }

        let mut builder = RequestBuilder::ack(request_uri);
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
        for route in routes {
            builder = builder.header(HeaderName::Route, route);
        }

        let request = builder
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(max_forwards)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a re-INVITE request for mid-call SDP renegotiation (hold/resume).
    ///
    /// `request_uri_str` is the dialog's remote target and `routes` its
    /// route set (RFC 3261 §12.2.1.1); `remote_uri_str` is the dialog's
    /// remote URI used in the To header.
    #[allow(clippy::too_many_arguments)]
    fn build_reinvite_request_static(
        request_uri_str: &str,
        remote_uri_str: &str,
        routes: &[String],
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
        let request_uri: SipUri = request_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid request URI: {e}")))?;

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

        let mut to = NameAddr::new(remote_uri);
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

        let mut builder = RequestBuilder::invite(request_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70);
        for route in routes {
            builder = builder.header(HeaderName::Route, route);
        }
        let request = builder
            .contact(&contact)
            .user_agent(USER_AGENT)
            .content_type("application/sdp")
            .body(bytes::Bytes::from(sdp.as_bytes().to_vec()))
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Builds a REFER request for call transfer (RFC 3515).
    ///
    /// `branch` is the Via branch the caller registered in the transaction
    /// key, so responses match the transaction (RFC 3261 §17.1.3).
    /// `request_uri_str` is the dialog's remote target and `routes` its
    /// route set (RFC 3261 §12.2.1.1); `remote_uri_str` is the dialog's
    /// remote URI used in the To header.
    #[allow(clippy::too_many_arguments)]
    fn build_refer_request_static(
        request_uri_str: &str,
        remote_uri_str: &str,
        routes: &[String],
        aor: &str,
        display_name: &str,
        local_addr: SocketAddr,
        sip_call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: Option<&str>,
        branch: &str,
        transfer_target: &str,
        transport_type: &str,
    ) -> SipUaResult<SipRequest> {
        use proto_sip::method::Method;

        let request_uri: SipUri = request_uri_str
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid request URI: {e}")))?;

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

        let mut to = NameAddr::new(remote_uri);
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
        let mut builder = RequestBuilder::new(Method::Refer, request_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(sip_call_id)
            .cseq(cseq)
            .max_forwards(70);
        for route in routes {
            builder = builder.header(HeaderName::Route, route);
        }
        let request = builder
            .contact(&contact)
            .user_agent(USER_AGENT)
            .header(HeaderName::ReferTo, transfer_target)
            .header(HeaderName::ReferredBy, aor)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
    }

    /// Parses a SIP URI to get a destination address, performing RFC 3263
    /// resolution (NAPTR → SRV → A/AAAA) when needed.
    ///
    /// Per RFC 3263 §4: a numeric IP host or an explicit port skips the
    /// NAPTR/SRV steps. The SRV service is derived from the transport
    /// (`_sip._udp` for UDP, `_sips._tcp` for TLS): the URI's `transport`
    /// parameter wins, then a `sips` scheme forces TLS, then the agent's
    /// configured transport applies. If RFC 3263 resolution fails (e.g.
    /// the DNS resolver is unreachable), falls back to a plain system
    /// A/AAAA lookup as before.
    async fn parse_destination(&self, uri: &str) -> SipUaResult<SocketAddr> {
        debug!(uri = %uri, "parse_destination: parsing SIP URI");

        let sip_uri: SipUri = uri.parse().map_err(|e| {
            error!(uri = %uri, error = %e, "parse_destination: failed to parse SIP URI");
            SipUaError::ConfigError(format!("Invalid URI: {e}"))
        })?;

        // Transport selection (RFC 3263 §4.1): URI transport param, else
        // sips scheme ⇒ TLS, else the agent's configured transport.
        let transport = sip_uri.transport().map_or_else(
            || {
                if sip_uri.scheme == UriScheme::Sips {
                    "TLS".to_string()
                } else {
                    self.transport_type.clone()
                }
            },
            str::to_ascii_uppercase,
        );
        let preference = match transport.as_str() {
            "TCP" => TransportPreference::Tcp,
            "TLS" => TransportPreference::Tls,
            _ => TransportPreference::Udp,
        };

        let resolver = self.resolver.get_or_init(SipResolver::with_defaults);
        match resolver
            .resolve(&sip_uri.host, sip_uri.port, preference)
            .await
        {
            Ok(targets) => {
                // Targets arrive sorted by SRV priority/weight; among the
                // best priority, prefer IPv6 to match the socket family.
                let best_priority = targets.first().map(|t| t.priority);
                let result = targets
                    .iter()
                    .filter(|t| Some(t.priority) == best_priority)
                    .find(|t| t.address.is_ipv6())
                    .or_else(|| targets.first())
                    .map(|t| t.address)
                    .ok_or_else(|| {
                        SipUaError::ConfigError(format!("No addresses found for {}", sip_uri.host))
                    })?;
                info!(
                    uri = %uri,
                    resolved = %result,
                    transport = %transport,
                    "parse_destination: resolved destination address (RFC 3263)"
                );
                Ok(result)
            }
            Err(e) => {
                warn!(
                    host = %sip_uri.host,
                    error = %e,
                    "parse_destination: RFC 3263 resolution failed; falling back to system A/AAAA lookup"
                );
                Self::lookup_host_fallback(&sip_uri, &transport).await
            }
        }
    }

    /// Plain system A/AAAA lookup used when RFC 3263 resolution fails.
    async fn lookup_host_fallback(sip_uri: &SipUri, transport: &str) -> SipUaResult<SocketAddr> {
        let host = &sip_uri.host;
        let default_port = if transport == "TLS" { 5061 } else { 5060 };
        let port = sip_uri.port.unwrap_or(default_port);

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&format!("{host}:{port}"))
            .await
            .map_err(|e| {
                error!(host = %host, error = %e, "parse_destination: DNS resolution failed");
                SipUaError::ConfigError(format!("DNS resolution failed for {host}: {e}"))
            })?
            .collect();

        // Prefer IPv6 (AAAA) over IPv4 (A) to match socket address family
        addrs
            .iter()
            .find(|a| a.is_ipv6())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| {
                error!(host = %host, "parse_destination: no addresses found");
                SipUaError::ConfigError(format!("No addresses found for {host}"))
            })
    }

    /// Returns the local address to advertise (Via sent-by, Contact) for a
    /// request toward `destination`: the NAT public address learned via
    /// RFC 3581 `received`/`rport` when known, otherwise the locally
    /// discovered interface address.
    async fn effective_local_addr(&self, destination: SocketAddr) -> SipUaResult<SocketAddr> {
        if let Some(public) = self.public_addr {
            debug!(
                public = %public,
                "Using NAT public address from RFC 3581 received/rport for advertised headers"
            );
            return Ok(public);
        }
        Self::get_local_addr_for_destination(destination, self.local_addr).await
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

    /// Transaction-layer gate run before any call state is mutated.
    ///
    /// Matches the response to the owning client transaction (RFC 3261
    /// §17.1.3), lets the transaction absorb retransmissions (§17.1.2.2),
    /// and consumes responses that must not reach the dialog handlers
    /// (CANCEL-transaction responses, 2xx completions of other non-INVITE
    /// transactions, unmatched responses).
    ///
    /// Returns true if the response must be passed to the dialog/call
    /// handlers; false if it was consumed here.
    async fn gate_response_to_transaction(
        &mut self,
        response: &SipResponse,
        call_id: &str,
    ) -> SipUaResult<bool> {
        let status_code = response.status.code();
        let response_branch = Self::response_top_via_branch(response);
        let response_cseq = Self::response_cseq(response);

        // RFC 3261 §17.1.3: match the response to the client transaction
        // whose request carried the same top Via branch and CSeq method —
        // Call-ID only located the call, not the transaction.
        let tx_match = self
            .calls
            .get(call_id)
            .map_or(ResponseTxMatch::Unmatched, |session| {
                Self::match_response_transaction(
                    session,
                    response_branch.as_deref(),
                    response_cseq.as_ref(),
                )
            });

        match tx_match {
            ResponseTxMatch::Invite => {
                // RFC 3261 §17.1.1: let the transaction absorb retransmitted
                // responses (e.g. a duplicate 180) so they cannot re-drive
                // the call state machine or re-emit state changes.
                let accepted = self
                    .calls
                    .get_mut(call_id)
                    .and_then(|s| s.invite_transaction.as_mut())
                    .is_some_and(|tx| tx.receive_response(status_code).unwrap_or(false));
                if !accepted {
                    debug!(
                        call_id = %call_id,
                        status_code = status_code,
                        "Absorbed retransmitted response (INVITE transaction, RFC 3261 §17.1.1)"
                    );
                    return Ok(false);
                }
                Ok(true)
            }
            ResponseTxMatch::NonInvite => {
                let accepted = self
                    .calls
                    .get_mut(call_id)
                    .and_then(|s| s.non_invite_transaction.as_mut())
                    .is_some_and(|tx| tx.receive_response(status_code).unwrap_or(false));
                if !accepted {
                    debug!(
                        call_id = %call_id,
                        status_code = status_code,
                        "Absorbed retransmitted response (non-INVITE transaction, RFC 3261 §17.1.2.2)"
                    );
                    return Ok(false);
                }

                match response_cseq.as_ref().map(|(_, m)| m.as_str()) {
                    // A response to the CANCEL transaction never decides the
                    // call's fate by itself: a 200 only confirms the CANCEL
                    // was received (§9.1) and a 481 means the INVITE already
                    // completed — in both cases the INVITE's own final
                    // response (487, or a 2xx that won the race) arrives
                    // separately.
                    Some("CANCEL") => {
                        debug!(
                            call_id = %call_id,
                            status_code = status_code,
                            "Response to CANCEL transaction; awaiting INVITE final response"
                        );
                        Ok(false)
                    }
                    // A BYE response drives teardown via the normal dispatch.
                    Some("BYE") => Ok(true),
                    // A 2xx to any other non-INVITE request (REFER, ...)
                    // just completes that transaction. It must not reach the
                    // INVITE/dialog handlers — a late 200 must never confirm
                    // the wrong request (RFC 3261 §12.2.1.1); REFER progress
                    // arrives via NOTIFY (RFC 3515).
                    _ => {
                        if (200..300).contains(&status_code) {
                            debug!(
                                call_id = %call_id,
                                status_code = status_code,
                                cseq = ?response_cseq,
                                "Non-INVITE transaction completed"
                            );
                            return Ok(false);
                        }
                        Ok(true)
                    }
                }
            }
            ResponseTxMatch::Unmatched => {
                self.handle_unmatched_response(
                    call_id,
                    status_code,
                    response_branch.as_deref(),
                    response_cseq.as_ref(),
                )
                .await?;
                Ok(false)
            }
        }
    }

    /// Identifies which pending client transaction owns a response.
    ///
    /// RFC 3261 §17.1.3: a response matches the client transaction whose
    /// request carried the same top Via branch and `CSeq` method. The
    /// `CSeq` number is additionally validated against the pending
    /// request's (RFC 3261 §12.2.1.1) so a late 2xx cannot confirm the
    /// wrong request. A response with no Via branch is tolerated (matched
    /// by `CSeq` method + number alone); a response with no `CSeq` matches
    /// nothing.
    fn match_response_transaction(
        session: &CallSession,
        branch: Option<&str>,
        cseq: Option<&(u32, String)>,
    ) -> ResponseTxMatch {
        let Some((seq, method)) = cseq else {
            return ResponseTxMatch::Unmatched;
        };

        let key_matches = |key: &TransactionKey, tx_cseq: Option<u32>| {
            key.method == *method
                && branch.is_none_or(|b| b == key.branch)
                && tx_cseq.is_none_or(|c| c == *seq)
        };

        if let Some(tx) = &session.invite_transaction
            && key_matches(tx.key(), tx.cseq())
        {
            return ResponseTxMatch::Invite;
        }
        if let Some(tx) = &session.non_invite_transaction
            && key_matches(tx.key(), tx.cseq())
        {
            return ResponseTxMatch::NonInvite;
        }
        ResponseTxMatch::Unmatched
    }

    /// Handles a response that matches no pending client transaction.
    ///
    /// RFC 6026 §2: a retransmitted 2xx to an INVITE we already acknowledged
    /// means our ACK was lost — re-send the identical ACK rather than
    /// dropping or reprocessing the response. Anything else is dropped with
    /// a log (RFC 3261 §17.1.3): acting on it would let late or stray
    /// responses (a BYE 200, a CANCEL 481) corrupt the state of newer
    /// transactions on the same call.
    async fn handle_unmatched_response(
        &self,
        call_id: &str,
        status_code: u16,
        branch: Option<&str>,
        cseq: Option<&(u32, String)>,
    ) -> SipUaResult<()> {
        if (200..300).contains(&status_code)
            && let Some((seq, method)) = cseq
            && method == "INVITE"
        {
            let stored = self
                .calls
                .get(call_id)
                .and_then(|s| s.last_ack.as_ref())
                .filter(|ack| ack.cseq == *seq)
                .map(|ack| (ack.request.clone(), ack.destination));

            if let Some((request, destination)) = stored {
                info!(
                    call_id = %call_id,
                    cseq = seq,
                    "Retransmitted 2xx to INVITE; re-sending identical ACK (RFC 6026 §2)"
                );
                self.event_tx
                    .send(CallEvent::SendRequest {
                        request,
                        destination,
                    })
                    .await
                    .map_err(|e| SipUaError::TransportError(e.to_string()))?;
                return Ok(());
            }
        }

        warn!(
            call_id = %call_id,
            status_code = status_code,
            branch = ?branch,
            cseq = ?cseq,
            "Dropping response that matches no pending client transaction (RFC 3261 §17.1.3)"
        );
        Ok(())
    }

    /// Extracts the branch parameter from a response's top Via header
    /// (RFC 3261 §17.1.3).
    fn response_top_via_branch(response: &SipResponse) -> Option<String> {
        let via = response.headers.get_value(&HeaderName::Via)?;
        let start = via.find("branch=")? + "branch=".len();
        let rest = &via[start..];
        let end = rest.find([';', ',', ' ', '\t']).map_or(rest.len(), |i| i);
        Some(rest[..end].to_string())
    }

    /// Parses a response's `CSeq` header into (sequence number, method).
    fn response_cseq(response: &SipResponse) -> Option<(u32, String)> {
        let value = response.headers.get_value(&HeaderName::CSeq)?;
        let mut parts = value.split_whitespace();
        let seq = parts.next()?.parse().ok()?;
        let method = parts.next()?.to_ascii_uppercase();
        Some((seq, method))
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

    /// Resets the 491 glare attempt counter for a call (a fresh
    /// user-initiated re-INVITE starts a new glare budget).
    fn reset_glare_attempts(&mut self, call_id: &str) {
        if let Some(session) = self.calls.get_mut(call_id) {
            session.reinvite_glare_attempts = 0;
        }
    }

    /// Computes the Request-URI, Route headers, and next hop for an
    /// in-dialog request (RFC 3261 §12.2.1.1).
    ///
    /// - Empty route set: Request-URI = remote target, no Route headers,
    ///   send to the remote target.
    /// - First route is a loose router (`;lr`): Request-URI = remote
    ///   target, Route headers = the route set verbatim, send to the
    ///   first route.
    /// - First route is a strict router (no `;lr`): Request-URI = first
    ///   route's URI, Route headers = remaining routes plus the remote
    ///   target as the last Route, send to the first route.
    fn dialog_target(session: &CallSession) -> DialogTarget {
        let remote_target = session
            .remote_target
            .clone()
            .unwrap_or_else(|| session.remote_uri.clone());

        let Some(first_route) = session.route_set.first() else {
            return DialogTarget {
                request_uri: remote_target.clone(),
                routes: Vec::new(),
                next_hop: remote_target,
            };
        };

        let first_uri = Self::name_addr_uri(first_route);
        if first_uri.contains(";lr") {
            DialogTarget {
                request_uri: remote_target,
                routes: session.route_set.clone(),
                next_hop: first_uri,
            }
        } else {
            // Strict-routing fallback (RFC 3261 §12.2.1.1): the request
            // is aimed AT the first route; the remote target goes last.
            let mut routes: Vec<String> = session.route_set[1..].to_vec();
            routes.push(format!("<{remote_target}>"));
            DialogTarget {
                request_uri: first_uri.clone(),
                routes,
                next_hop: first_uri,
            }
        }
    }

    /// Captures the dialog route set from a dialog-establishing response's
    /// Record-Route headers, REVERSED for this UAC (RFC 3261 §12.1.2).
    fn capture_route_set(session: &mut CallSession, response: &SipResponse) {
        let mut routes: Vec<String> = response
            .headers
            .get_all(&HeaderName::RecordRoute)
            .flat_map(|h| Self::split_header_list(&h.value))
            .collect();
        if routes.is_empty() {
            return;
        }
        routes.reverse();
        info!(
            call_id = %session.id,
            route_set = ?routes,
            "Captured dialog route set from Record-Route (RFC 3261 §12.1.2)"
        );
        session.route_set = routes;
    }

    /// Captures or refreshes the dialog's remote target from a response's
    /// Contact header (RFC 3261 §12.1.2 / §12.2.1.1).
    fn capture_remote_target(session: &mut CallSession, response: &SipResponse) {
        let Some(contact) = response.headers.get_value(&HeaderName::Contact) else {
            return;
        };
        let uri = Self::name_addr_uri(contact);
        if uri.is_empty() || session.remote_target.as_deref() == Some(uri.as_str()) {
            return;
        }
        info!(
            call_id = %session.id,
            remote_target = %uri,
            "Captured dialog remote target from Contact (RFC 3261 §12.1.2)"
        );
        session.remote_target = Some(uri);
    }

    /// Extracts the URI from a name-addr or addr-spec header value
    /// (`"Name" <sip:uri;params>` → `sip:uri;params`).
    fn name_addr_uri(value: &str) -> String {
        if let Some(start) = value.find('<')
            && let Some(len) = value[start + 1..].find('>')
        {
            return value[start + 1..start + 1 + len].to_string();
        }
        // addr-spec form: strip header params after the first top-level ';'
        // is NOT safe (URI params share the syntax), so take it verbatim.
        value.trim().to_string()
    }

    /// Splits a comma-separated header value into its elements, ignoring
    /// commas inside `<...>` (Record-Route can carry several entries in
    /// one header line).
    fn split_header_list(value: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut depth = 0_u32;
        let mut start = 0_usize;
        for (i, c) in value.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    let part = value[start..i].trim();
                    if !part.is_empty() {
                        out.push(part.to_string());
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }
        let last = value[start..].trim();
        if !last.is_empty() {
            out.push(last.to_string());
        }
        out
    }

    /// Parses a request's Max-Forwards header value.
    fn request_max_forwards(request: &SipRequest) -> Option<u8> {
        request
            .headers
            .get_value(&HeaderName::MaxForwards)
            .and_then(|v| v.trim().parse().ok())
    }

    /// Parses a response's Retry-After header (RFC 3261 §20.33): leading
    /// integer seconds, optionally followed by a comment or parameters.
    fn retry_after_secs(response: &SipResponse) -> Option<u32> {
        let value = response.headers.get_value(&HeaderName::RetryAfter)?;
        let digits: String = value
            .trim()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// RFC 3581: learns our NAT public address from `received`/`rport` on
    /// the top Via of a response. When it differs from the address we
    /// advertised, it becomes the address used in the Via/Contact of
    /// subsequently built requests on the call paths.
    fn update_public_addr_from_via(&mut self, response: &SipResponse) {
        let Some(via) = response.headers.get_value(&HeaderName::Via) else {
            return;
        };

        let received = Self::via_param(via, "received").and_then(|v| v.parse::<IpAddr>().ok());
        let rport = Self::via_param(via, "rport").and_then(|v| v.parse::<u16>().ok());
        if received.is_none() && rport.is_none() {
            return;
        }

        // The sent-by we advertised (the server echoes our Via verbatim,
        // adding received/rport): "SIP/2.0/UDP host:port;params".
        let sent_by = via
            .split_whitespace()
            .nth(1)
            .map_or("", |s| s.split(';').next().unwrap_or(s));
        let (adv_host, adv_port) = sent_by
            .rsplit_once(':')
            .map_or((sent_by, None), |(h, p)| (h, p.parse::<u16>().ok()));
        let advertised_ip = adv_host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
        let advertised_port = adv_port.unwrap_or(5060);

        let Some(public_ip) = received.or(advertised_ip) else {
            return;
        };
        let public = SocketAddr::new(public_ip, rport.unwrap_or(advertised_port));

        let advertised = advertised_ip.map(|ip| SocketAddr::new(ip, advertised_port));
        if advertised == Some(public) || self.public_addr == Some(public) {
            return;
        }

        info!(
            advertised = ?advertised,
            public = %public,
            "Discovered NAT public address from Via received/rport (RFC 3581); \
             using it for subsequently built requests"
        );
        self.public_addr = Some(public);
    }

    /// Extracts a parameter value from a Via header value.
    fn via_param(via: &str, name: &str) -> Option<String> {
        via.split(';').skip(1).find_map(|param| {
            let (key, value) = param.trim().split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    /// Returns the audio codec names of an SDP's first `m=audio` line,
    /// lowercase, resolved through `a=rtpmap` (with the RFC 3551 static
    /// payload-type table as fallback). `telephone-event` is excluded.
    fn sdp_audio_codecs(sdp: &str) -> Vec<String> {
        let mut payload_types: Vec<&str> = Vec::new();
        let mut rtpmap: HashMap<&str, String> = HashMap::new();

        for line in sdp.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("m=audio ") {
                if payload_types.is_empty() {
                    // "m=audio <port> <proto> <pt> <pt> ..."
                    payload_types = rest.split_whitespace().skip(2).collect();
                }
            } else if let Some(rest) = line.strip_prefix("a=rtpmap:") {
                // "<pt> <encoding>/<clock>[/<channels>]"
                let mut parts = rest.split_whitespace();
                if let (Some(pt), Some(encoding)) = (parts.next(), parts.next())
                    && let Some(name) = encoding.split('/').next()
                {
                    rtpmap.insert(pt, name.to_ascii_lowercase());
                }
            }
        }

        payload_types
            .iter()
            .filter_map(|pt| {
                rtpmap
                    .get(pt)
                    .cloned()
                    .or_else(|| Self::static_payload_name(pt))
            })
            .filter(|name| name != "telephone-event")
            .collect()
    }

    /// RFC 3551 static audio payload-type names (subset in use here).
    fn static_payload_name(pt: &str) -> Option<String> {
        let name = match pt {
            "0" => "pcmu",
            "3" => "gsm",
            "4" => "g723",
            "8" => "pcma",
            "9" => "g722",
            "18" => "g729",
            _ => return None,
        };
        Some(name.to_string())
    }

    /// RFC 3264 §6: returns true when the answer's audio codecs intersect
    /// the offer's. When either side cannot be parsed, returns true (do
    /// not block on what we cannot validate).
    fn sdp_codecs_intersect(offer: &str, answer: &str) -> bool {
        let offered = Self::sdp_audio_codecs(offer);
        let answered = Self::sdp_audio_codecs(answer);
        if offered.is_empty() || answered.is_empty() {
            return true;
        }
        answered.iter().any(|codec| offered.contains(codec))
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

    fn test_agent() -> CallAgent {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        CallAgent::new(
            local_addr,
            "sips:alice@example.com".to_string(),
            "Alice".to_string(),
            tx,
        )
    }

    #[tokio::test]
    async fn test_parse_destination() {
        let agent = test_agent();
        let addr = agent
            .parse_destination("sips:bob@192.168.1.1:5061")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5061);
    }

    #[tokio::test]
    async fn test_parse_destination_default_port() {
        let agent = test_agent();
        // RFC 3263: a sips URI without a port defaults to TLS port 5061.
        let addr = agent
            .parse_destination("sips:bob@192.168.1.1")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5061);

        // A plain sip URI without a port resolves with the agent's
        // transport; the test agent defaults to TLS ⇒ 5061. With UDP
        // configured it is 5060.
        let mut udp_agent = test_agent();
        udp_agent.configure(
            "sip:alice@example.com".to_string(),
            "Alice".to_string(),
            None,
            "UDP",
            #[cfg(feature = "digest-auth")]
            None,
        );
        let addr = udp_agent
            .parse_destination("sip:bob@192.168.1.1")
            .await
            .unwrap();
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

        // Same Max-Forwards as the INVITE — not a reset 70 (RFC 3261 §9.1)
        assert_eq!(
            cancel.headers.get_value(&HeaderName::MaxForwards),
            invite.headers.get_value(&HeaderName::MaxForwards),
            "CANCEL must reuse the INVITE's Max-Forwards (RFC 3261 §9.1)"
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
        challenge.headers.set(HeaderName::CSeq, "1 INVITE");
        challenge
            .headers
            .set(HeaderName::Via, invite1_via.to_string());
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
        assert_eq!(
            ack.headers.get_value(&HeaderName::MaxForwards),
            invite1.headers.get_value(&HeaderName::MaxForwards),
            "non-2xx ACK must reuse the INVITE's Max-Forwards (RFC 3261 §17.1.1.3)"
        );

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

    /// RFC 3261 §17.1.1 / §17.1.2.2: a retransmitted 180 within the INVITE
    /// transaction must be absorbed — it must not re-emit a state change or
    /// otherwise re-drive the call state machine.
    #[tokio::test]
    async fn test_duplicate_180_absorbed() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(10);
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

        // Drain StateChanged(Dialing), capture the INVITE for its Via
        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());
        let invite_via = invite
            .headers
            .get_value(&HeaderName::Via)
            .unwrap()
            .to_string();

        let mut ringing = SipResponse::new(StatusCode::RINGING);
        ringing.headers.set(HeaderName::Via, invite_via);
        ringing
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-180");
        ringing.headers.set(HeaderName::CSeq, "1 INVITE");

        agent.handle_response(&ringing, &call_id).await.unwrap();
        let event = rx.recv().await.unwrap();
        assert!(matches!(
            event,
            CallEvent::StateChanged {
                state: CallState::Ringing,
                ..
            }
        ));
        assert_eq!(agent.get_state(&call_id), Some(CallState::Ringing));

        // Retransmitted 180: absorbed by the transaction, no second event
        agent.handle_response(&ringing, &call_id).await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "retransmitted 180 must not emit any event"
        );
        assert_eq!(agent.get_state(&call_id), Some(CallState::Ringing));
    }

    /// RFC 3261 §17.1.3 / §12.2.1.1: a late 200 to an old BYE (stale
    /// branch, stale `CSeq`) must not touch a newer INVITE transaction on
    /// the same Call-ID — it matches no pending transaction and is dropped.
    #[tokio::test]
    async fn test_late_bye_200_does_not_touch_newer_invite_transaction() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(16);
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

        // Drain StateChanged(Dialing), capture the INVITE
        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());
        let invite_via = invite
            .headers
            .get_value(&HeaderName::Via)
            .unwrap()
            .to_string();

        // Connect the call: 200 OK to the INVITE (matched by branch + CSeq)
        let mut ok = SipResponse::new(StatusCode::OK);
        ok.headers.set(HeaderName::Via, invite_via);
        ok.headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        ok.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ok, &call_id).await.unwrap();
        while rx.try_recv().is_ok() {} // drain ACK + StateChanged(Connected)
        assert_eq!(agent.get_state(&call_id), Some(CallState::Connected));

        // Send a hold re-INVITE: a NEWER INVITE transaction is now pending
        agent
            .hold_call(&call_id, "v=0\r\na=sendonly\r\n")
            .await
            .unwrap();
        while rx.try_recv().is_ok() {} // drain re-INVITE + StateChanged(OnHold)
        assert!(agent.has_pending_invite_transaction(&call_id));
        assert_eq!(agent.get_state(&call_id), Some(CallState::OnHold));

        // A late 200 to some old BYE arrives (stale branch, stale CSeq).
        // It must be dropped: no events, no state change, the pending
        // re-INVITE transaction untouched.
        let mut late_bye_ok = SipResponse::new(StatusCode::OK);
        late_bye_ok.headers.set(
            HeaderName::Via,
            "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKstale",
        );
        late_bye_ok.headers.set(HeaderName::CSeq, "9 BYE");
        agent.handle_response(&late_bye_ok, &call_id).await.unwrap();

        assert!(
            rx.try_recv().is_err(),
            "late BYE 200 must not emit any event"
        );
        assert_eq!(agent.get_state(&call_id), Some(CallState::OnHold));
        assert!(
            agent.has_pending_invite_transaction(&call_id),
            "the newer INVITE transaction must be untouched"
        );
    }

    /// RFC 6026 §2: a retransmitted 200 OK to the INVITE (the first ACK was
    /// lost) must be answered with the identical ACK — not reprocessed
    /// (which would re-emit state changes) and not dropped (which would
    /// leave the UAS retransmitting until Timer H fires).
    #[tokio::test]
    async fn test_retransmitted_invite_200_resends_identical_ack() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(16);
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

        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());
        let invite_via = invite
            .headers
            .get_value(&HeaderName::Via)
            .unwrap()
            .to_string();

        let mut ok = SipResponse::new(StatusCode::OK);
        ok.headers.set(HeaderName::Via, invite_via);
        ok.headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        ok.headers.set(HeaderName::CSeq, "1 INVITE");
        ok.body = Some(bytes::Bytes::from_static(
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
        ));
        agent.handle_response(&ok, &call_id).await.unwrap();

        // Drain the first 200's processing and capture the original ACK
        let mut ack1 = None;
        let mut saw_connected = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                CallEvent::SendRequest { request, .. } => ack1 = Some(request),
                CallEvent::StateChanged { state, .. } => {
                    saw_connected |= state == CallState::Connected;
                }
                _ => {}
            }
        }
        let ack1 = ack1.unwrap();
        assert_eq!(ack1.method.to_string(), "ACK");
        assert!(saw_connected);

        // The 200 is retransmitted (our ACK was lost): the agent must
        // re-send the IDENTICAL ACK and nothing else.
        agent.handle_response(&ok, &call_id).await.unwrap();
        let ack2 = sent_request(rx.recv().await.unwrap());
        assert_eq!(ack2.method.to_string(), "ACK");
        assert_eq!(
            ack2.headers.get_value(&HeaderName::Via),
            ack1.headers.get_value(&HeaderName::Via),
            "re-sent ACK must reuse the original ACK's Via (same branch)"
        );
        assert_eq!(
            ack2.headers.get_value(&HeaderName::CSeq),
            ack1.headers.get_value(&HeaderName::CSeq)
        );
        assert_eq!(
            ack2.headers.get_value(&HeaderName::To),
            ack1.headers.get_value(&HeaderName::To)
        );
        assert_eq!(
            ack2.headers.get_value(&HeaderName::CallId),
            ack1.headers.get_value(&HeaderName::CallId)
        );

        assert!(
            rx.try_recv().is_err(),
            "a retransmitted 200 must not re-emit state changes or SDP events"
        );
        assert_eq!(agent.get_state(&call_id), Some(CallState::Connected));
    }

    /// Drives an outbound call to Connected; returns (`call_id`, INVITE,
    /// drained requests from the 200 processing).
    async fn connect_call(
        agent: &mut CallAgent,
        rx: &mut mpsc::Receiver<CallEvent>,
        ok_response: &mut SipResponse,
    ) -> (String, SipRequest) {
        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\nm=audio 49170 RTP/AVP 0 8\r\n";
        let call_id = agent
            .make_call("sip:bob@127.0.0.1:5061", sdp)
            .await
            .unwrap();
        let _ = rx.recv().await.unwrap(); // StateChanged(Dialing)
        let invite = sent_request(rx.recv().await.unwrap());

        ok_response.headers.set(HeaderName::CSeq, "1 INVITE");
        if ok_response.headers.get_value(&HeaderName::To).is_none() {
            ok_response
                .headers
                .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        }
        agent.handle_response(ok_response, &call_id).await.unwrap();
        (call_id, invite)
    }

    /// RFC 3261 §12.1.2 / §12.2.1.1: the dialog-establishing 200 carries
    /// Record-Route and Contact; the in-dialog BYE must set its
    /// Request-URI to the remote target (the 200's Contact URI), carry the
    /// Route set REVERSED, keep the dialog's remote URI in To, and be sent
    /// to the resolved address of the first Route.
    #[tokio::test]
    async fn test_in_dialog_bye_uses_route_set_and_remote_target() {
        use proto_sip::header::Header;
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(32);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );

        let mut ok = SipResponse::new(StatusCode::OK);
        // Two Record-Routing proxies (topmost first, as received).
        ok.add_header(Header::new(
            HeaderName::RecordRoute,
            "<sip:127.0.0.1:5080;lr>",
        ));
        ok.add_header(Header::new(
            HeaderName::RecordRoute,
            "<sip:127.0.0.2:5081;lr>",
        ));
        ok.headers
            .set(HeaderName::Contact, "<sip:bob-contact@127.0.0.1:5070>");

        let (call_id, _invite) = connect_call(&mut agent, &mut rx, &mut ok).await;

        // Drain the ACK and StateChanged(Connected); the ACK must already
        // be routed through the route set toward the remote target.
        let mut ack = None;
        while let Ok(event) = rx.try_recv() {
            if let CallEvent::SendRequest {
                request,
                destination,
            } = event
            {
                ack = Some((request, destination));
            }
        }
        let (ack, ack_dest) = ack.unwrap();
        assert_eq!(ack.method.to_string(), "ACK");
        assert_eq!(ack.uri.to_string(), "sip:bob-contact@127.0.0.1:5070");
        assert_eq!(
            ack_dest,
            "127.0.0.2:5081".parse::<SocketAddr>().unwrap(),
            "in-dialog request must be sent to the first Route (reversed Record-Route)"
        );

        // Hang up: the BYE is the in-dialog request under test.
        agent.hangup(&call_id).await.unwrap();
        let (bye, bye_dest) = match rx.recv().await.unwrap() {
            CallEvent::SendRequest {
                request,
                destination,
            } => (request, destination),
            other => panic!("expected SendRequest, got {other:?}"),
        };

        assert_eq!(bye.method.to_string(), "BYE");
        assert_eq!(
            bye.uri.to_string(),
            "sip:bob-contact@127.0.0.1:5070",
            "BYE Request-URI must be the remote target (the 200's Contact)"
        );

        let routes: Vec<&str> = bye
            .headers
            .get_all(&HeaderName::Route)
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            routes,
            vec!["<sip:127.0.0.2:5081;lr>", "<sip:127.0.0.1:5080;lr>"],
            "BYE must carry the Record-Route set reversed (RFC 3261 §12.1.2)"
        );

        // To still names the dialog's remote URI (not the Contact).
        let to = bye.headers.get_value(&HeaderName::To).unwrap();
        assert!(to.contains("sip:bob@127.0.0.1:5061"), "To was: {to}");
        assert!(to.contains("tag=tag-200"));

        assert_eq!(
            bye_dest,
            "127.0.0.2:5081".parse::<SocketAddr>().unwrap(),
            "BYE must be sent to the first Route's address"
        );
    }

    /// RFC 3261 §12.2.1.1 strict-routing fallback: when the first route
    /// lacks `;lr`, the Request-URI becomes the first route's URI and the
    /// remote target moves to the last Route header.
    #[tokio::test]
    async fn test_in_dialog_bye_strict_route_fallback() {
        use proto_sip::header::Header;
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(32);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );

        let mut ok = SipResponse::new(StatusCode::OK);
        // A single strict (no ;lr) Record-Route proxy.
        ok.add_header(Header::new(HeaderName::RecordRoute, "<sip:127.0.0.1:5080>"));
        ok.headers
            .set(HeaderName::Contact, "<sip:bob-contact@127.0.0.1:5070>");

        let (call_id, _invite) = connect_call(&mut agent, &mut rx, &mut ok).await;
        while rx.try_recv().is_ok() {}

        agent.hangup(&call_id).await.unwrap();
        let bye = sent_request(rx.recv().await.unwrap());

        assert_eq!(
            bye.uri.to_string(),
            "sip:127.0.0.1:5080",
            "strict routing: Request-URI must be the first route's URI"
        );
        let routes: Vec<&str> = bye
            .headers
            .get_all(&HeaderName::Route)
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            routes,
            vec!["<sip:bob-contact@127.0.0.1:5070>"],
            "strict routing: remote target must become the last Route"
        );
    }

    /// RFC 3261 §12.1: the To-tag must be captured from ANY first tagged
    /// provisional — 180 included — a later 1xx with a DIFFERENT tag is
    /// ignored, and only a 2xx may finalize a different tag (forking).
    #[tokio::test]
    async fn test_to_tag_captured_from_180_and_forking_rules() {
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
        while rx.try_recv().is_ok() {}

        // 180 with a tag: captured (previously only the 183 path stored it)
        let mut ringing = SipResponse::new(StatusCode::RINGING);
        ringing
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-from-180");
        ringing.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ringing, &call_id).await.unwrap();
        assert_eq!(
            agent.calls.get(&call_id).unwrap().to_tag.as_deref(),
            Some("tag-from-180"),
            "To-tag must be captured from the 180 (RFC 3261 §12.1)"
        );

        // A later 183 with a DIFFERENT tag (fork): ignored
        let mut progress = SipResponse::new(StatusCode::SESSION_PROGRESS);
        progress
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=other-fork");
        progress.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&progress, &call_id).await.unwrap();
        assert_eq!(
            agent.calls.get(&call_id).unwrap().to_tag.as_deref(),
            Some("tag-from-180"),
            "a differing To-tag on a later 1xx must be ignored"
        );

        // The 2xx MAY finalize a different tag (the answering fork)
        let mut ok = SipResponse::new(StatusCode::OK);
        ok.headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=final-tag");
        ok.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ok, &call_id).await.unwrap();
        assert_eq!(
            agent.calls.get(&call_id).unwrap().to_tag.as_deref(),
            Some("final-tag"),
            "the 2xx finalizes the dialog's To-tag (forking)"
        );

        // And the ACK addresses the confirmed dialog (final tag)
        let mut ack = None;
        while let Ok(event) = rx.try_recv() {
            if let CallEvent::SendRequest { request, .. } = event {
                ack = Some(request);
            }
        }
        let ack = ack.unwrap();
        assert_eq!(ack.method.to_string(), "ACK");
        assert!(
            ack.headers
                .get_value(&HeaderName::To)
                .unwrap()
                .contains("tag=final-tag")
        );
    }

    /// RFC 3581: `received`/`rport` on the top Via of a response reveal
    /// our NAT public address; subsequently built requests must advertise
    /// it in their Via.
    #[tokio::test]
    async fn test_received_rport_updates_effective_address() {
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
        let _ = rx.recv().await.unwrap();
        let invite = sent_request(rx.recv().await.unwrap());
        let invite_via = invite.headers.get_value(&HeaderName::Via).unwrap();

        // The server echoes our Via, filling received + rport (RFC 3581)
        let mut ok = SipResponse::new(StatusCode::OK);
        ok.headers.set(
            HeaderName::Via,
            format!("{invite_via};received=203.0.113.5;rport=12345"),
        );
        ok.headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        ok.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ok, &call_id).await.unwrap();
        while rx.try_recv().is_ok() {}

        assert_eq!(
            agent.public_addr,
            Some("203.0.113.5:12345".parse().unwrap()),
            "received/rport must be stored as the effective public address"
        );

        // The next built request (BYE) advertises the public address
        agent.hangup(&call_id).await.unwrap();
        let bye = sent_request(rx.recv().await.unwrap());
        let bye_via = bye.headers.get_value(&HeaderName::Via).unwrap();
        assert!(
            bye_via.contains("203.0.113.5:12345"),
            "BYE Via must carry the RFC 3581 public address, was: {bye_via}"
        );
    }

    /// RFC 3264 §6 hardening: an early (183) SDP answer whose codecs do
    /// not intersect our offer must be logged and ignored — no
    /// `SdpAnswerReceived` (no audio start) for an unusable answer.
    #[tokio::test]
    async fn test_early_sdp_codec_mismatch_ignored() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(32);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );

        // Offer PCMU/PCMA (0, 8)
        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\nm=audio 49170 RTP/AVP 0 8\r\n";
        let call_id = agent
            .make_call("sip:bob@127.0.0.1:5061", sdp)
            .await
            .unwrap();
        while rx.try_recv().is_ok() {}

        // 183 answering with G729 only (18): no intersection
        let mut progress = SipResponse::new(StatusCode::SESSION_PROGRESS);
        progress
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-183");
        progress.headers.set(HeaderName::CSeq, "1 INVITE");
        progress.body = Some(bytes::Bytes::from_static(
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 18\r\n",
        ));
        agent.handle_response(&progress, &call_id).await.unwrap();

        let mut saw_sdp_answer = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, CallEvent::SdpAnswerReceived { .. }) {
                saw_sdp_answer = true;
            }
        }
        assert!(
            !saw_sdp_answer,
            "mismatched early SDP must not be surfaced (RFC 3264 §6)"
        );
        assert!(
            agent.calls.get(&call_id).unwrap().remote_sdp.is_none(),
            "mismatched early SDP must not be stored"
        );

        // Interleave a 180 so the next 183 is not absorbed as a
        // same-status retransmission by the INVITE transaction.
        let mut ringing = SipResponse::new(StatusCode::RINGING);
        ringing
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-183");
        ringing.headers.set(HeaderName::CSeq, "1 INVITE");
        agent.handle_response(&ringing, &call_id).await.unwrap();
        while rx.try_recv().is_ok() {}

        // A compatible 183 (PCMU + telephone-event) IS surfaced
        let mut progress2 = SipResponse::new(StatusCode::SESSION_PROGRESS);
        progress2
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-183");
        progress2.headers.set(HeaderName::CSeq, "1 INVITE");
        progress2.body = Some(bytes::Bytes::from_static(
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n",
        ));
        agent.handle_response(&progress2, &call_id).await.unwrap();
        let mut saw_sdp_answer = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, CallEvent::SdpAnswerReceived { .. }) {
                saw_sdp_answer = true;
            }
        }
        assert!(saw_sdp_answer, "compatible early SDP must be surfaced");
    }

    /// RFC 3261 §14.1: a 491 to a re-INVITE (glare) must not kill the
    /// call; the re-INVITE is `ACK`ed and retried once after the glare
    /// backoff via `process_timers`.
    #[tokio::test]
    async fn test_491_glare_reinvite_acked_and_retried_once() {
        use proto_sip::response::StatusCode;

        let (tx, mut rx) = mpsc::channel(32);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut agent = CallAgent::new(
            local_addr,
            "sip:alice@127.0.0.1".to_string(),
            "Alice".to_string(),
            tx,
        );

        let mut ok = SipResponse::new(StatusCode::OK);
        let (call_id, _invite) = connect_call(&mut agent, &mut rx, &mut ok).await;
        while rx.try_recv().is_ok() {}

        // Hold: re-INVITE (CSeq 2) goes out
        agent
            .hold_call(&call_id, "v=0\r\na=sendonly\r\n")
            .await
            .unwrap();
        let reinvite = sent_request(rx.recv().await.unwrap());
        assert_eq!(
            reinvite.headers.get_value(&HeaderName::CSeq).unwrap(),
            "2 INVITE"
        );
        while rx.try_recv().is_ok() {}

        // Glare: 491 Request Pending
        let mut pending = SipResponse::new(StatusCode::REQUEST_PENDING);
        pending
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        pending.headers.set(HeaderName::CSeq, "2 INVITE");
        agent.handle_response(&pending, &call_id).await.unwrap();

        // The 491 must be ACKed, the call must stay alive, a retry queued
        let ack = sent_request(rx.recv().await.unwrap());
        assert_eq!(ack.method.to_string(), "ACK");
        assert_eq!(ack.headers.get_value(&HeaderName::CSeq).unwrap(), "2 ACK");
        assert_ne!(agent.get_state(&call_id), Some(CallState::Terminated));
        assert!(agent.calls.get(&call_id).unwrap().reinvite_retry.is_some());

        // Fire the timer early and pump: the re-INVITE is retried (CSeq 3)
        if let Some(session) = agent.calls.get_mut(&call_id)
            && let Some(retry) = session.reinvite_retry.as_mut()
        {
            retry.at = Instant::now();
        }
        agent.process_timers().await.unwrap();
        let retry_invite = sent_request(rx.recv().await.unwrap());
        assert_eq!(retry_invite.method.to_string(), "INVITE");
        assert_eq!(
            retry_invite.headers.get_value(&HeaderName::CSeq).unwrap(),
            "3 INVITE"
        );
        while rx.try_recv().is_ok() {}

        // A second 491 exhausts the one-shot retry: ACKed, no new retry
        let mut pending2 = SipResponse::new(StatusCode::REQUEST_PENDING);
        pending2
            .headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-200");
        pending2.headers.set(HeaderName::CSeq, "3 INVITE");
        agent.handle_response(&pending2, &call_id).await.unwrap();
        let ack2 = sent_request(rx.recv().await.unwrap());
        assert_eq!(ack2.method.to_string(), "ACK");
        assert!(
            agent.calls.get(&call_id).unwrap().reinvite_retry.is_none(),
            "only ONE glare retry is scheduled (RFC 3261 §14.1)"
        );
    }

    /// RFC 3261 §21.5.2: Retry-After on a 486 is surfaced in the failure
    /// reason so the app can back off instead of redialing immediately.
    #[tokio::test]
    async fn test_retry_after_surfaced_on_busy() {
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
        while rx.try_recv().is_ok() {}

        let mut busy = SipResponse::new(StatusCode::BUSY_HERE);
        busy.headers
            .set(HeaderName::To, "<sip:bob@127.0.0.1:5061>;tag=tag-486");
        busy.headers.set(HeaderName::CSeq, "1 INVITE");
        busy.headers.set(HeaderName::RetryAfter, "120");
        agent.handle_response(&busy, &call_id).await.unwrap();

        let info = agent.get_call_info(&call_id).unwrap();
        let reason = info.failure_reason.unwrap().to_string();
        assert!(
            reason.contains("Retry-After: 120s"),
            "failure reason must surface Retry-After, was: {reason}"
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
