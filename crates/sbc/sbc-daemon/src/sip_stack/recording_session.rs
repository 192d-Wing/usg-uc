//! SIPREC recording session glue for the SIP stack (RFC 7866 SRC).
//!
//! The stack-side half of [`crate::recording`]: it owns the locking, the
//! media-controller calls and the transaction hooks, and leaves every
//! decision and message layout to that module.
//!
//! Sequence: trigger, offer check and slot at INVITE
//! ([`SipStack::recording_admit`]); recordability, fork preparation and the
//! RS INVITE at answer ([`SipStack::recording_on_answer`]); answer
//! validation, ACK and fork activation on the SRS 2xx
//! ([`SipStack::handle_rs_response`]); BYE to the SRS when the call ends
//! ([`SipStack::recording_call_ended`]).
//!
//! Failure policy (`recording.on_failure`), by the moment of the failure:
//!
//! - at INVITE (no slot, an offer that cannot be recorded): the INVITE is
//!   refused before the B-leg is dialled;
//! - at the callee's 2xx (the answer makes the call unrecordable, the fork
//!   cannot be prepared): the 2xx is not relayed, the caller gets a final
//!   error and the callee ACK + BYE;
//! - after the 2xx was relayed ([`SipStack::recording_failure`]): BYE to
//!   both legs, the caller's held until its ACK (RFC 3261 §15).
//!
//! Lock order (unchanged): `transactions` -> `call_correlation` -> leaf locks
//! (`rs_deadlines`, `rs_wind_down`, `released_invites`). No media
//! controller call and no `.await` on another lock is made while
//! `call_correlation` is held. A state transition of the RS leg is decided
//! by whoever changes it under the `call_correlation` write lock, so each
//! start / stop / failure happens exactly once.
//!
//! ## NIST 800-53 Rev5: AU-14, AU-5, AU-12, SC-5, SC-8, SC-12, SC-23, SC-24,
//! SI-10
//!
//! ## RFC 7866 §6.1.1, §7; RFC 3261 §9.1, §13.2.2.4, §13.3.1.4, §15, §17.1.1
// POAM: POA&M-301 - the RS starts at the call's 200 OK: early media is not
// recorded.

use super::{
    CallAddresses, LegHiding, ProcessResult, ReleasedInvite, SipStack, audit,
    create_response_from_request, extract_param, host_port, is_sdp_content_type, is_sip_token,
    lock_leaf, sanitize_remote_target,
};
use crate::flow::Flow;
use crate::recording::{
    AnswerClaim, AnsweredCall, CallRecording, MAX_RS_ROUTES, OfferedCall, RS_ALLOW,
    RecordingCounters, RecordingLeg, RecordingSettings, RecordingSlot, RsState, Trigger,
};
use proto_b2bua::CallId;
use proto_sip::header_params::CSeqHeader;
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::{HeaderName, Method, SipMessage, StatusCode};
use proto_transaction::TransactionKey;
use std::net::{IpAddr, SocketAddr};
use std::sync::Weak;
use std::time::Instant;
use tracing::{debug, info, warn};
use uc_audit::event::{
    RecordingFailAction, RecordingFailReason, RecordingRelay, RecordingStopReason,
    TerminationReason,
};
use uc_types::address::{SbcSocketAddr, TransportType as AddrTransport};

/// A pending RS INVITE's deadline (`recording.rs_invite_timeout_ms`).
pub(super) struct RsDeadline {
    at: Instant,
    call: CallId,
    rs_call_id: String,
    /// Dead once the call stopped being recorded; used only to prune.
    slot: Weak<RecordingSlot>,
}

/// RS BYE / CANCEL handed to the recorder's send lane per timer tick: a
/// quarter of the lane, so a mass teardown (shutdown, trunk loss) cannot
/// overrun it and lose the requests (TLS has no retransmission).
///
/// ## NIST 800-53 Rev5: SC-5
pub(super) const RS_WIND_DOWN_PER_TICK: usize = crate::flows::LANE_DEPTH / 4;

/// What recording decided at the callee's 2xx.
pub(super) enum AnswerRecording {
    /// Relay the 2xx; then send these (the RS INVITE, or nothing).
    Proceed(Vec<ProcessResult>),
    /// The call cannot be recorded and the policy refuses it: the 2xx is
    /// not relayed.
    Refuse(RecordingFailReason),
}

/// Final response for a call refused because it cannot be recorded: 488
/// with a `Warning` when the session description is the cause (RFC 3261
/// §21.4.26, §20.43), else 503 (§21.5.4).
pub(super) fn refusal_response(
    reason: RecordingFailReason,
    host: &str,
) -> (StatusCode, Option<String>) {
    match reason {
        RecordingFailReason::MediaNotRecordable | RecordingFailReason::RemoteMediaUnsupported => (
            StatusCode::NOT_ACCEPTABLE_HERE,
            Some(format!("399 {host} \"Session cannot be recorded\"")),
        ),
        _ => (StatusCode::SERVICE_UNAVAILABLE, None),
    }
}

/// What is left to do toward the SRS when a recording ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LegEnd {
    /// Nothing: the RS INVITE transaction is over (final response, failed
    /// send, Timer B) or the SRS ended the dialog itself.
    Done,
    /// End the dialog: BYE when established; for a pending INVITE, CANCEL
    /// (after a provisional) and ACK + BYE for a 2xx that still arrives.
    WindDown,
}

impl SipStack {
    /// Enables SIPREC recording with the resolved `[recording]` settings.
    ///
    /// ## NIST 800-53 Rev5: CM-6
    pub fn set_recording(&mut self, settings: RecordingSettings) {
        self.recording = Some(settings);
    }

    /// Recording counters (metrics endpoint).
    pub const fn recording_counters(&self) -> &RecordingCounters {
        &self.recording_counters
    }

    /// Whether recording is enabled on this stack.
    pub const fn recording_enabled(&self) -> bool {
        self.recording.is_some()
    }

    /// INVITE time: evaluates the trigger, checks what the offer alone
    /// decides and takes a `max_sessions` slot.
    ///
    /// `Err(reason)`: the call matched and cannot be recorded (no slot, or
    /// an offer [`crate::recording::offer_recordable`] rules out) and the
    /// policy refuses it; the caller answers with [`refusal_response`]
    /// before the B-leg is dialled. Under `continue`, or for an emergency
    /// call, such a call proceeds unrecorded and is audited here.
    ///
    /// `image`: a direct T.38 call. `may_terminate`: the relay may
    /// terminate DTLS-SRTP for this call.
    ///
    /// ## NIST 800-53 Rev5: AU-14, SC-5, AU-5, AU-12, SC-24; 47 CFR 9.16;
    /// RFC 3261 §15
    pub(super) fn recording_admit(
        &self,
        internal_id: &CallId,
        trigger: &Trigger<'_>,
        emergency: bool,
        offer: Option<&[u8]>,
        image: bool,
        may_terminate: bool,
    ) -> Result<CallRecording, RecordingFailReason> {
        let Some(s) = &self.recording else {
            return Ok(CallRecording::default());
        };
        if !s.matches(trigger) {
            return Ok(CallRecording::default());
        }
        let mut plan = CallRecording {
            matched: true,
            emergency,
            ..CallRecording::default()
        };
        // RFC 7866 §7.1.3: an opted-out call needs no slot. Whether the
        // opt-out is honoured is the operator's policy (PT-5).
        if s.honour_recordpref && crate::recording::opted_out(offer) {
            plan.opt_out_offer = true;
            return Ok(plan);
        }
        let offer_text = offer.map(String::from_utf8_lossy);
        let recordable = crate::recording::offer_recordable(&OfferedCall {
            offer_sdp: offer_text.as_deref(),
            image,
            anchored: self.media_pipeline.is_some(),
            may_terminate,
        });
        if !recordable {
            let reason = RecordingFailReason::MediaNotRecordable;
            self.admit_failure(s, internal_id, &mut plan, reason)?;
            return Ok(plan);
        }
        if let Some(slot) = self.recording_counters.try_reserve(s.max_sessions) {
            plan.slot = Some(slot);
            return Ok(plan);
        }
        warn!(
            call_id = %internal_id,
            max_sessions = s.max_sessions,
            "No recording session slot for a call matching the recording trigger"
        );
        self.admit_failure(
            s,
            internal_id,
            &mut plan,
            RecordingFailReason::NoSessionSlot,
        )?;
        Ok(plan)
    }

    /// INVITE time, after the media session was requested: a call that is
    /// to be recorded but got no relay (the media session could not be
    /// created) cannot be recorded. Same contract as
    /// [`Self::recording_admit`].
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-24
    pub(super) fn recording_admit_unanchored(
        &self,
        internal_id: &CallId,
        plan: &mut CallRecording,
    ) -> Result<(), RecordingFailReason> {
        let Some(s) = &self.recording else {
            return Ok(());
        };
        if plan.slot.is_none() {
            return Ok(());
        }
        self.admit_failure(
            s,
            internal_id,
            plan,
            RecordingFailReason::MediaNotRecordable,
        )
    }

    /// A matched call that cannot be recorded, found at INVITE: releases the
    /// slot, counts and audits `recording_failed`, and either refuses the
    /// call (`Err`) or tags it for the CDR and lets it proceed unrecorded.
    fn admit_failure(
        &self,
        s: &RecordingSettings,
        internal_id: &CallId,
        plan: &mut CallRecording,
        reason: RecordingFailReason,
    ) -> Result<(), RecordingFailReason> {
        plan.slot = None;
        let action = s.action(plan.emergency);
        self.recording_counters.note_failed(reason, action);
        audit(crate::recording::audit_failed(
            &internal_id.to_string(),
            None,
            reason,
            action,
            None,
        ));
        warn!(
            call_id = %internal_id,
            reason = reason.as_str(),
            ?action,
            "Call matching the recording trigger cannot be recorded"
        );
        if action == RecordingFailAction::CallRejected {
            return Err(reason);
        }
        plan.tag = Some(crate::recording::failure_tag(reason, false));
        Ok(())
    }

    /// Whether `addr` is one of the SBC's own sockets: one of its addresses
    /// (any address of a local interface as learned at startup, a zone's
    /// media, signaling or external address, the fork's own address, or the
    /// configured domain when that is an address literal) with a port in
    /// the SBC's RTP range or one of its SIP listener ports. The interface
    /// list covers an unzoned relay, which binds the wildcard address; the
    /// configured addresses cover those no interface carries (NAT).
    /// The recorder's media must never be sent there: an SRS answer naming
    /// a relay port could latch another call's relay, one naming a listener
    /// would aim the fork at the SIP stack.
    ///
    /// ## NIST 800-53 Rev5: SC-7 (Boundary Protection), SI-10
    fn is_own_socket(&self, s: &RecordingSettings, addr: SocketAddr) -> bool {
        let port = addr.port();
        let c = &self.config;
        if !s.media_ports.contains(&port)
            && ![c.udp_port, c.tcp_port, c.tls_port, c.ws_port].contains(&port)
        {
            return false;
        }
        let ip = addr.ip().to_canonical();
        // Sorted at startup; no syscall on the signaling task.
        if s.local_addrs.binary_search(&ip).is_ok() {
            return true;
        }
        if s.local_media_ip == Some(ip) || self.recording_media_ip(s) == Some(ip) {
            return true;
        }
        if crate::recording::bare_host(&c.domain)
            .parse::<IpAddr>()
            .is_ok_and(|own| own == ip)
        {
            return true;
        }
        self.zone_registry.as_ref().is_some_and(|reg| {
            reg.zone_names().iter().any(|zone| {
                [
                    reg.media_ip(zone),
                    reg.signaling_ip(zone),
                    reg.external_ip(zone),
                ]
                .contains(&Some(ip))
            })
        })
    }

    /// The fork's bind address and the address advertised in the RS SDP:
    /// the `srs_zone` media address, else the SBC's source address toward
    /// the SRS (resolved at startup).
    fn recording_media_ip(&self, s: &RecordingSettings) -> Option<IpAddr> {
        s.srs_zone
            .as_deref()
            .zip(self.zone_registry.as_ref())
            .and_then(|(zone, reg)| reg.media_ip(zone))
            .or(s.local_media_ip)
    }

    /// SBC sent-by (`host:port`) of the recorder flow: the TLS listener
    /// port, and the `srs_zone` signaling address or the internal B-leg
    /// rule (RFC 3261 §18.1.1).
    fn recording_sent_by(&self, s: &RecordingSettings) -> String {
        let port = self.signaling_port(AddrTransport::Tls);
        let zone_host = s
            .srs_zone
            .as_deref()
            .zip(self.zone_registry.as_ref())
            .and_then(|(zone, reg)| reg.external_ip(zone).or_else(|| reg.signaling_ip(zone)))
            .map(|ip| ip.to_string());
        let host = zone_host
            .unwrap_or_else(|| self.b_leg_signaling_addr(None, false, AddrTransport::Tls).0);
        host_port(&host, port)
    }

    /// Claims the callee's 2xx of a matched call for recording, under the
    /// correlation write lock. `false`: another copy of the 2xx already
    /// holds the claim (a duplicate handled concurrently), so this one is a
    /// retransmission and must neither start nor fail the recording.
    ///
    /// ## NIST 800-53 Rev5: SC-24, SC-5; RFC 3261 §13.2.2.4
    pub(super) async fn recording_claim_answer(&self, internal_id: &CallId) -> bool {
        let mut corr = self.call_correlation.write().await;
        corr.addresses.get_mut(internal_id).is_some_and(|a| {
            let first = a.recording.answer == AnswerClaim::Unclaimed && !a.b_leg_answered;
            a.recording.answer = AnswerClaim::Claimed;
            first
        })
    }

    /// Answer time, before the callee's 2xx is relayed: decides
    /// recordability, prepares the fork and builds the RS INVITE.
    ///
    /// [`AnswerRecording::Proceed`]: relay the 2xx; the results (the RS
    /// INVITE on the recorder flow, or nothing) go on the wire after the
    /// caller's 200 and the callee's ACK. [`AnswerRecording::Refuse`]: the
    /// call cannot be recorded under `on_failure = reject`; the failure is
    /// already audited, counted and tagged, and the caller of this function
    /// refuses the call instead of relaying the 2xx (RFC 3261 §15: no BYE
    /// toward a caller that has not ACKed).
    ///
    /// `addrs` is the call's record as it was before the answer; the trigger
    /// facts in it were fixed at INVITE.
    ///
    /// ## NIST 800-53 Rev5: AU-14, AU-5, SC-12, SC-24; RFC 7866 §6.1.1
    pub(super) async fn recording_on_answer(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        answer: Option<&[u8]>,
        terminated: bool,
    ) -> AnswerRecording {
        let nothing = || AnswerRecording::Proceed(Vec::new());
        let Some(s) = &self.recording else {
            return nothing();
        };
        let plan = &addrs.recording;
        if !plan.matched || plan.tag.is_some() || plan.leg.is_some() {
            return nothing();
        }
        let session = internal_id.to_string();

        // RFC 7866 §7.1.3 / PT-5: a participant's opt-out, when honoured,
        // is a skip, not a failure.
        if s.honour_recordpref && (plan.opt_out_offer || crate::recording::opted_out(answer)) {
            {
                let mut corr = self.call_correlation.write().await;
                let Some(a) = corr.addresses.get_mut(internal_id) else {
                    return nothing();
                };
                if a.recording.tag.is_some() {
                    return nothing();
                }
                a.recording.tag = Some(uc_cdr::RecordingTag::OptOut);
                a.recording.slot = None;
            }
            self.recording_counters.note_skipped();
            audit(crate::recording::audit_skipped(&session));
            info!(call_id = %session, "Recording skipped: participant opted out (recordpref)");
            return nothing();
        }

        let offer_text = addrs.b_leg_last_sdp.as_deref().map(String::from_utf8_lossy);
        let answer_text = answer.map(String::from_utf8_lossy);
        let pipeline = self
            .media_pipeline
            .as_ref()
            .filter(|_| addrs.media_a_leg_port.is_some());
        let classified = crate::recording::classify(&AnsweredCall {
            offer_sdp: offer_text.as_deref(),
            answer_sdp: answer_text.as_deref(),
            terminated,
            image: addrs.initial_offer_kind == crate::t38::CallMediaKind::Image,
            anchored: pipeline.is_some(),
        });
        let (codecs, pipeline) = match (classified, pipeline) {
            (Ok(c), Some(p)) => (c, p),
            (Err(reason), _) => return self.answer_failure(internal_id, reason).await,
            (Ok(_), None) => {
                return self
                    .answer_failure(internal_id, RecordingFailReason::MediaNotRecordable)
                    .await;
            }
        };
        let fork_setup = RecordingFailReason::ForkSetup;
        let (Ok((keys, material)), Some(media_ip)) = (
            crate::recording::generate_keys(),
            self.recording_media_ip(s),
        ) else {
            return self.answer_failure(internal_id, fork_setup).await;
        };
        // The keys move into the pipeline; the daemon keeps none (SC-12).
        let fork_ports = match pipeline
            .prepare_recording_fork(&session, material, Some(media_ip))
            .await
        {
            Ok(p) => p,
            Err(e) => {
                let reason = unsupported_or(&e, fork_setup);
                warn!(call_id = %session, error = %e, "Recording fork could not be prepared");
                return self.answer_failure(internal_id, reason).await;
            }
        };
        let relay = if terminated {
            RecordingRelay::DtlsTerminated
        } else {
            RecordingRelay::Opaque
        };
        let built = (|| {
            let sdp_session =
                u64::from_be_bytes(uc_crypto::random::generate_random::<8>().map_err(|_| ())?) >> 1;
            let sdp = crate::recording::build_rs_sdp(
                media_ip,
                [fork_ports.a_leg_port, fork_ports.b_leg_port],
                &codecs,
                sdp_session,
            )?;
            let meta =
                crate::recording::build_metadata(&session, &addrs.a_leg_from, &addrs.a_leg_to);
            let parts = uc_siprec::build_rs_offer(&sdp, &meta, &keys).map_err(|_| ())?;
            let session_id = crate::recording::session_id_from_body(&parts.body).ok_or(())?;
            let (invite, leg) = crate::recording::build_rs_invite(
                s,
                &self.config.domain,
                &self.recording_sent_by(s),
                parts,
                relay,
                codecs.offered_formats(),
            )?;
            Ok::<_, ()>((invite, leg, session_id))
        })();
        // SDES keys are zeroized here; the copies live in the pipeline's
        // SRTP contexts and in the INVITE body (wiped when it is dropped).
        drop(keys);
        let Ok((invite, leg, session_id)) = built else {
            let _ = pipeline.stop_recording_fork(&session).await;
            warn!(call_id = %session, "Recording session INVITE could not be built");
            return self.answer_failure(internal_id, fork_setup).await;
        };

        // Commit: the leg exists from here on, and only if the call is still
        // up and nothing else decided its recording meanwhile.
        let slot = {
            let mut corr = self.call_correlation.write().await;
            let committed = corr.addresses.get_mut(internal_id).and_then(|a| {
                if a.recording.tag.is_some() || a.recording.leg.is_some() {
                    return None;
                }
                a.recording.leg = Some(leg.clone());
                a.recording.session_id = Some(session_id);
                Some(a.recording.slot.as_ref().map(std::sync::Arc::downgrade))
            });
            if committed.is_some() {
                corr.rs_leg.insert(leg.call_id.clone(), internal_id.clone());
            }
            committed
        };
        let Some(slot) = slot else {
            let _ = pipeline.stop_recording_fork(&session).await;
            return nothing();
        };
        self.push_rs_deadline(RsDeadline {
            at: leg.invited_at + s.invite_timeout,
            call: internal_id.clone(),
            rs_call_id: leg.call_id,
            slot: slot.unwrap_or_default(),
        });
        info!(call_id = %session, srs = %s.srs_addr, "Recording session INVITE to the SRS");
        AnswerRecording::Proceed(vec![ProcessResult::Forward {
            message: SipMessage::Request(invite),
            destination: s.srs_addr,
            flow: s.flow.clone().into(),
        }])
    }

    /// A recording failure found while the callee's 2xx is being handled
    /// (nothing was relayed to the caller yet): bookkeeping as for any
    /// failure, and under `reject` the call is refused, not torn down.
    async fn answer_failure(
        &self,
        internal_id: &CallId,
        reason: RecordingFailReason,
    ) -> AnswerRecording {
        match self
            .recording_fail(internal_id, reason, None, LegEnd::Done)
            .await
        {
            Some(RecordingFailAction::CallRejected) => AnswerRecording::Refuse(reason),
            _ => AnswerRecording::Proceed(Vec::new()),
        }
    }

    /// Queues an RS INVITE deadline. The queue is bounded by the slot
    /// count: when it passes twice `max_sessions`, entries of calls that
    /// stopped being recorded are dropped (SC-5).
    fn push_rs_deadline(&self, deadline: RsDeadline) {
        let cap = self
            .recording
            .as_ref()
            .map_or(16, |s| s.max_sessions.saturating_mul(2).saturating_add(16));
        let mut q = lock_leaf(&self.rs_deadlines);
        if q.len() >= cap {
            q.retain(|d| d.slot.strong_count() > 0);
        }
        q.push_back(deadline);
    }

    /// Timer tick: hands queued RS BYE / CANCEL to the recorder flow (at
    /// most [`RS_WIND_DOWN_PER_TICK`]), and fails RS INVITEs past
    /// `recording.rs_invite_timeout_ms` with no final response as
    /// `srs_timeout`. Returns the wire output (already topology-hidden;
    /// the caller tracks it).
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-5
    pub(super) async fn recording_poll(&self) -> Vec<ProcessResult> {
        let Some(s) = &self.recording else {
            return Vec::new();
        };
        let mut out: Vec<ProcessResult> = {
            let mut q = lock_leaf(&self.rs_wind_down);
            let n = q.len().min(RS_WIND_DOWN_PER_TICK);
            q.drain(..n)
                .map(|request| ProcessResult::Forward {
                    message: SipMessage::Request(request),
                    destination: s.srs_addr,
                    flow: s.flow.clone().into(),
                })
                .collect()
        };
        let now = Instant::now();
        let due: Vec<RsDeadline> = {
            let mut q = lock_leaf(&self.rs_deadlines);
            let mut due = Vec::new();
            while q.front().is_some_and(|d| d.at <= now) {
                due.extend(q.pop_front());
            }
            due
        };
        for d in due {
            let snapshot = {
                let corr = self.call_correlation.read().await;
                corr.addresses.get(&d.call).and_then(|a| {
                    a.recording
                        .leg
                        .as_ref()
                        .is_some_and(|l| l.state == RsState::Inviting && l.call_id == d.rs_call_id)
                        .then(|| LegHiding::of(a))
                })
            };
            let Some(snapshot) = snapshot else {
                continue;
            };
            let mut failed = self
                .recording_failure(
                    &d.call,
                    RecordingFailReason::SrsTimeout,
                    None,
                    LegEnd::WindDown,
                )
                .await;
            for r in &mut failed {
                self.apply_egress_topology(r, None, std::slice::from_ref(&snapshot))
                    .await;
            }
            out.extend(failed);
        }
        out
    }

    /// Shutdown: the next RS BYE / CANCEL from the wind-down queue (at most
    /// [`RS_WIND_DOWN_PER_TICK`]) for the server's final flush. The timer
    /// loop that normally paces them is gone by then, so no client
    /// transaction is opened: the recorder flow is TLS (no retransmission)
    /// and nothing is left to process the 200.
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-5
    pub(crate) fn recording_shutdown_batch(&self) -> Vec<ProcessResult> {
        let Some(s) = &self.recording else {
            return Vec::new();
        };
        let mut q = lock_leaf(&self.rs_wind_down);
        let n = q.len().min(RS_WIND_DOWN_PER_TICK);
        q.drain(..n)
            .map(|request| ProcessResult::Forward {
                message: SipMessage::Request(request),
                destination: s.srs_addr,
                flow: s.flow.clone().into(),
            })
            .collect()
    }

    /// Shutdown: gives up on the RS BYE / CANCEL still queued. Each is
    /// counted in `sbc_recording_rs_bye_dropped_total` and the total is
    /// logged once (the SRS ends those sessions on its own RTP inactivity
    /// timeout). Returns the number dropped.
    ///
    /// ## NIST 800-53 Rev5: AU-5
    pub(crate) fn recording_shutdown_abandon(&self) -> usize {
        let left = {
            let mut q = lock_leaf(&self.rs_wind_down);
            let n = q.len();
            q.clear();
            n
        };
        for _ in 0..left {
            self.recording_counters.note_rs_bye_dropped();
        }
        if left > 0 {
            warn!(
                dropped = left,
                "Recording session BYE/CANCEL not sent before shutdown"
            );
        }
        left
    }

    /// Queues an SBC-originated RS BYE / CANCEL on the recording wind-down
    /// queue. The timer loop opens its client transaction and sends it on
    /// the recorder flow, [`RS_WIND_DOWN_PER_TICK`] per tick, so a burst of
    /// ending recordings is paced to what the recorder's send lane carries.
    ///
    /// The queue is bounded by `max_sessions` (each recording ends with at
    /// most one such request). A full queue drops the request (counted in
    /// `sbc_recording_rs_bye_dropped_total`): the SRS then ends the session
    /// on its own RTP inactivity timeout.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    fn rs_queue(&self, s: &RecordingSettings, request: SipRequest) {
        let cap = s.max_sessions.saturating_add(RS_WIND_DOWN_PER_TICK);
        let queued = {
            let mut q = lock_leaf(&self.rs_wind_down);
            let room = q.len() < cap;
            if room {
                q.push_back(request);
            }
            room
        };
        if !queued {
            self.recording_counters.note_rs_bye_dropped();
            warn!("Recording session BYE/CANCEL dropped (wind-down queue full)");
        }
    }

    /// Ends the RS dialog toward the SRS. Established: BYE (RFC 3261 §15).
    /// Still inviting: the attempt is remembered so a 2xx that crosses gets
    /// ACK + BYE (§13.2.2.4), and a CANCEL is sent once a provisional was
    /// seen (§9.1).
    fn rs_wind_down(&self, s: &RecordingSettings, leg: &RecordingLeg) {
        match leg.state {
            RsState::Established => self.rs_queue(s, crate::recording::build_rs_bye(leg, &s.flow)),
            RsState::Inviting => {
                let now = Instant::now();
                lock_leaf(&self.released_invites).insert(
                    ReleasedInvite {
                        call_id: leg.call_id.clone(),
                        branch: leg.branch.clone(),
                        destination: s.srs_addr,
                        flow: s.flow.clone(),
                        hidden: false,
                        sent_by: leg.sent_by.clone(),
                        from: leg.from.clone(),
                        to: leg.to.clone(),
                        request_uri: s.srs_uri.clone(),
                        invite_cseq: 1,
                        released_at: now,
                        answered_tags: Vec::new(),
                    },
                    now,
                );
                if leg.provisional_seen {
                    self.rs_queue(s, crate::recording::build_rs_cancel(s, leg));
                }
            }
        }
    }

    /// Recording failure after the callee's 2xx was relayed to the caller
    /// (RS send failure, SRS reject / timeout / bad answer / BYE, a media
    /// change): the bookkeeping of [`Self::recording_fail`], then
    /// `recording.on_failure`:
    ///
    /// - emergency call: always continues unrecorded (47 CFR 9.16);
    /// - `reject`: BYE both legs, CDR release cause `recording_failure`.
    ///   The caller's BYE is held until its ACK for the 2xx arrived, or the
    ///   2xx retransmission gave up after 64*T1 (RFC 3261 §15: a UAS must
    ///   not send a BYE on a confirmed dialog before it received the ACK;
    ///   §13.3.1.4);
    /// - `continue`: the call stays up, unrecorded.
    ///
    /// Returns the BYEs that go out now under `reject` (not yet
    /// topology-hidden), else nothing. A second failure for the same call
    /// is a no-op.
    ///
    /// ## NIST 800-53 Rev5: AU-5, AU-12, SC-24, SC-5
    pub(super) async fn recording_failure(
        &self,
        internal_id: &CallId,
        reason: RecordingFailReason,
        sip_status: Option<u16>,
        end: LegEnd,
    ) -> Vec<ProcessResult> {
        if self
            .recording_fail(internal_id, reason, sip_status, end)
            .await
            != Some(RecordingFailAction::CallRejected)
        {
            return Vec::new();
        }
        self.terminate_call(
            &internal_id.to_string(),
            crate::cdr::CdrEnd::recording_failure(),
            TerminationReason::PolicyTerminated,
            "recording failed (recording.on_failure = reject)",
            true,
        )
        .await
        .0
    }

    /// The one recording failure bookkeeping path: releases the slot, drops
    /// the fork (its keys are zeroized with it), audits `recording_failed`,
    /// counts the reason, sets the CDR tag and ends the RS dialog as `end`
    /// says. Returns the action `recording.on_failure` takes for the call,
    /// for the caller to carry out; `None` when the call is gone or its
    /// recording already has a final outcome (exactly once).
    ///
    /// ## NIST 800-53 Rev5: AU-5, AU-12, SC-24, SC-5
    async fn recording_fail(
        &self,
        internal_id: &CallId,
        reason: RecordingFailReason,
        sip_status: Option<u16>,
        end: LegEnd,
    ) -> Option<RecordingFailAction> {
        let s = self.recording.as_ref()?;
        let session = internal_id.to_string();
        let (leg, session_id, emergency) = {
            let mut corr = self.call_correlation.write().await;
            let a = corr.addresses.get_mut(internal_id)?;
            // Exactly once: an outcome without a leg is already final.
            if !a.recording.matched || (a.recording.leg.is_none() && a.recording.tag.is_some()) {
                return None;
            }
            let leg = a.recording.leg.take();
            let was_active = leg.as_ref().is_some_and(|l| l.active_since.is_some());
            a.recording.slot = None;
            a.recording.tag = Some(crate::recording::failure_tag(reason, was_active));
            let session_id = a.recording.session_id.clone();
            let emergency = a.recording.emergency;
            if let Some(l) = &leg {
                corr.rs_leg.remove(&l.call_id);
            }
            (leg, session_id, emergency)
        };
        let action = s.action(emergency);
        self.recording_counters.note_failed(reason, action);
        if let Some(active_since) = leg.as_ref().and_then(|l| l.active_since) {
            // The recording covered part of the call: close it on the trail.
            self.recording_counters.note_stopped();
            audit(crate::recording::audit_stopped(
                &session,
                session_id.as_deref().unwrap_or_default(),
                crate::recording::stop_reason_for(reason),
                Some(active_since),
            ));
        }
        audit(crate::recording::audit_failed(
            &session,
            session_id.as_deref(),
            reason,
            action,
            sip_status,
        ));
        warn!(
            call_id = %session,
            reason = reason.as_str(),
            ?action,
            sip_status,
            "Recording failed"
        );
        if let Some(leg) = &leg
            && end == LegEnd::WindDown
        {
            self.rs_wind_down(s, leg);
        }
        if let Some(pipeline) = &self.media_pipeline {
            let _ = pipeline.stop_recording_fork(&session).await;
        }
        Some(action)
    }

    /// The first send of an RS INVITE failed (TLS connect, handshake or
    /// certificate failure, write error, full lane). `None` when the INVITE
    /// is not a recording session INVITE. There is no failover: one SRS.
    ///
    /// Returned results are hidden and tracked, like `on_invite_sent`'s.
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-8
    pub(super) async fn recording_invite_send_failed(
        &self,
        req: &SipRequest,
        branch: &str,
        tls_handshake_failed: bool,
    ) -> Option<Vec<ProcessResult>> {
        self.recording.as_ref()?;
        let rs_call_id = req.headers.call_id()?;
        let (internal_id, snapshot) = {
            let corr = self.call_correlation.read().await;
            let id = corr.rs_leg.get(rs_call_id)?.clone();
            let snapshot = corr.addresses.get(&id).and_then(|a| {
                a.recording
                    .leg
                    .as_ref()
                    .is_some_and(|l| l.state == RsState::Inviting && l.branch == branch)
                    .then(|| LegHiding::of(a))
            });
            (id, snapshot)
        };
        let Some(snapshot) = snapshot else {
            return Some(Vec::new());
        };
        // Stop Timer B on the dead attempt.
        self.transactions
            .write()
            .await
            .client_invite
            .remove(&TransactionKey::client(branch, Method::Invite.to_string()));
        let reason = if tls_handshake_failed {
            RecordingFailReason::SrsTls
        } else {
            RecordingFailReason::SrsUnreachable
        };
        let mut out = self
            .recording_failure(&internal_id, reason, None, LegEnd::Done)
            .await;
        for r in &mut out {
            self.apply_egress_topology(r, None, std::slice::from_ref(&snapshot))
                .await;
        }
        for r in &out {
            self.track_result(r).await;
        }
        Some(out)
    }

    /// Whether a response must be dropped before the transaction layer sees
    /// it: its Call-ID is a live recording session's and it did not arrive
    /// over TLS from the SRS address. The RS is signalled on the verified
    /// recorder TLS flow only, so anything else is forged; letting it reach
    /// the client transaction would complete that transaction and make the
    /// genuine answer look like a retransmission.
    ///
    /// No lock for a Call-ID that is not a recording session's, or while no
    /// recording slot is held.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-23 (Session Authenticity), SI-10
    pub(super) async fn rs_response_refused(
        &self,
        sip_call_id: &str,
        source: SbcSocketAddr,
        transport: AddrTransport,
    ) -> bool {
        let Some(s) = &self.recording else {
            return false;
        };
        if !crate::recording::is_rs_call_id(sip_call_id)
            || self.recording_counters.slots_held() == 0
            || (transport == AddrTransport::Tls && source.ip() == s.srs_addr.ip())
        {
            return false;
        }
        self.call_correlation
            .read()
            .await
            .rs_leg
            .contains_key(sip_call_id)
    }

    /// A response in a recording session dialog. The transaction layer has
    /// already matched it to an INVITE this SBC sent (and built the ACK for
    /// a non-2xx final, `ack_action`). Only a response that arrived over
    /// TLS from the SRS address is acted on.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-23, SI-10; RFC 3261 §13.2.2.4
    pub(super) async fn handle_rs_response(
        &self,
        resp: &SipResponse,
        (source, transport): (SbcSocketAddr, AddrTransport),
        internal_id: &CallId,
        branch: &str,
        cseq: &CSeqHeader,
        ack_action: Option<ProcessResult>,
    ) -> ProcessResult {
        let absorbed = |ack: Option<ProcessResult>| ack.unwrap_or(ProcessResult::NoAction);
        let Some(s) = &self.recording else {
            return absorbed(ack_action);
        };
        let leg = {
            let corr = self.call_correlation.read().await;
            corr.addresses
                .get(internal_id)
                .and_then(|a| a.recording.leg.clone())
        };
        let Some(leg) = leg else {
            return absorbed(ack_action);
        };
        // Only the INVITE this leg sent, answered from the SRS address on
        // the recorder's transport (TLS).
        if cseq.method != Method::Invite
            || cseq.sequence != 1
            || leg.branch != branch
            || source.ip() != s.srs_addr.ip()
            || transport != AddrTransport::Tls
        {
            debug!(call_id = %internal_id, "Response does not match the recording session INVITE");
            return absorbed(ack_action);
        }
        let status = resp.status.code();
        if status < 200 {
            // RFC 3261 §9.1: a CANCEL may be sent from now on.
            if !leg.provisional_seen {
                let mut corr = self.call_correlation.write().await;
                if let Some(l) = corr
                    .addresses
                    .get_mut(internal_id)
                    .and_then(|a| a.recording.leg.as_mut())
                {
                    l.provisional_seen = true;
                }
            }
            return ProcessResult::NoAction;
        }
        if status >= 300 {
            if leg.state != RsState::Inviting {
                return absorbed(ack_action);
            }
            let mut out: Vec<ProcessResult> = ack_action.into_iter().collect();
            out.extend(
                self.recording_failure(
                    internal_id,
                    crate::recording::reason_for_status(status),
                    Some(status),
                    LegEnd::Done,
                )
                .await,
            );
            return ProcessResult::Multiple(out);
        }
        self.handle_rs_2xx(resp, internal_id, s, &leg).await
    }

    /// The SRS answered 2xx: validate the answer, ACK, activate the fork.
    /// An unusable answer is still ACKed, then the dialog is ended with a
    /// BYE and the failure policy applies.
    ///
    /// ## NIST 800-53 Rev5: SI-10, AU-12; RFC 3261 §13.2.2.4, RFC 7866 §7.2
    async fn handle_rs_2xx(
        &self,
        resp: &SipResponse,
        internal_id: &CallId,
        s: &RecordingSettings,
        leg: &RecordingLeg,
    ) -> ProcessResult {
        let forward = |request: SipRequest| ProcessResult::Forward {
            message: SipMessage::Request(request),
            destination: s.srs_addr,
            flow: s.flow.clone().into(),
        };
        // A retransmitted 2xx (our ACK was lost): re-ACK only; the fork is
        // not activated twice.
        if leg.state == RsState::Established {
            return forward(crate::recording::build_rs_ack(leg, &s.flow));
        }
        let status = resp.status.code();
        let bad_answer = RecordingFailReason::SrsBadAnswer;
        // A 2xx without a valid To tag is malformed; nothing to ACK.
        let Some(tag) = resp
            .headers
            .get_value(&HeaderName::To)
            .and_then(|t| extract_param(t, "tag"))
            .filter(|t| is_sip_token(t))
            .map(str::to_string)
        else {
            return ProcessResult::Multiple(
                self.recording_failure(internal_id, bad_answer, Some(status), LegEnd::WindDown)
                    .await,
            );
        };
        let contact = resp
            .headers
            .get_value(&HeaderName::Contact)
            .and_then(sanitize_remote_target);
        let routes = rs_route_set(resp);
        let is_sdp = resp
            .headers
            .get_value(&HeaderName::ContentType)
            .is_some_and(is_sdp_content_type);
        // Nothing of the answer is logged: it carries the SRS's SDES key.
        let media =
            crate::recording::validate_rs_answer(resp, is_sdp, &leg.offered_formats, |addr| {
                self.is_own_socket(s, addr)
            });

        // Claim the transition under the write lock: Inviting -> Established.
        let claimed = {
            let mut corr = self.call_correlation.write().await;
            corr.addresses.get_mut(internal_id).and_then(|a| {
                let answered_at = a.established_at;
                let image = a.media_kind == crate::t38::CallMediaKind::Image;
                let l = a
                    .recording
                    .leg
                    .as_mut()
                    .filter(|l| l.state == RsState::Inviting && l.branch == leg.branch)?;
                l.remote_tag = Some(tag);
                l.remote_target = crate::recording::remote_target(contact, s);
                l.routes = routes;
                l.state = RsState::Established;
                Some((l.clone(), answered_at, image))
            })
        };
        let Some((established, answered_at, image)) = claimed else {
            return ProcessResult::NoAction;
        };
        let session = internal_id.to_string();
        let mut out = vec![forward(crate::recording::build_rs_ack(
            &established,
            &s.flow,
        ))];
        let failure = match media {
            Err(()) => Some(bad_answer),
            // The call switched to T.38 while the RS was being set up.
            Ok(_) if image => Some(RecordingFailReason::MediaNotRecordable),
            Ok(remotes) => match &self.media_pipeline {
                None => Some(RecordingFailReason::MediaNotRecordable),
                // An activation error tears the fork down completely
                // (keys dropped, ports released); it is not retried.
                Some(pipeline) => pipeline
                    .activate_recording_fork(&session, remotes)
                    .await
                    .err()
                    .map(|e| {
                        warn!(call_id = %session, error = %e, "Recording fork could not be activated");
                        unsupported_or(&e, RecordingFailReason::ForkSetup)
                    }),
            },
        };
        if let Some(reason) = failure {
            let sip_status = (reason == bad_answer).then_some(status);
            out.extend(
                self.recording_failure(internal_id, reason, sip_status, LegEnd::WindDown)
                    .await,
            );
            return ProcessResult::Multiple(out);
        }
        // Media is being forked. If the call ended meanwhile, its teardown
        // already wound the RS down and nothing is audited as started.
        let started = {
            let mut corr = self.call_correlation.write().await;
            corr.addresses.get_mut(internal_id).and_then(|a| {
                let l = a
                    .recording
                    .leg
                    .as_mut()
                    .filter(|l| l.call_id == established.call_id)?;
                l.active_since = Some(Instant::now());
                let l = l.clone();
                a.recording.tag = Some(uc_cdr::RecordingTag::Recorded);
                Some((l, a.recording.session_id.clone()))
            })
        };
        if let Some((l, session_id)) = started {
            self.recording_counters.note_started();
            audit(crate::recording::audit_started(
                &session,
                session_id.as_deref().unwrap_or_default(),
                &l,
                answered_at,
            ));
            info!(call_id = %session, "Recording session active");
        }
        ProcessResult::Multiple(out)
    }

    /// A request whose Call-ID is a live recording session's. `None`: not an
    /// RS request (or an ACK / CANCEL, left to the transaction handlers).
    ///
    /// Accepted only from the SRS address, over TLS, with the dialog's
    /// tags; anything else is 481. BYE ends the recording and goes through
    /// the failure policy; OPTIONS is answered with `Allow`; a re-INVITE
    /// gets 488 with a `Warning` (RFC 3261 §14.2); UPDATE and every other
    /// method get 405 with `Allow` (§21.4.6).
    ///
    /// The call table is not locked for a request whose Call-ID is not a
    /// recording session's (every REGISTER, OPTIONS and call-leg request),
    /// or while no recording slot is held.
    ///
    /// ## NIST 800-53 Rev5: SC-23, SC-7, AC-4, SI-10; RFC 3261 §12.2.2, §15
    // POAM: POA&M-308 - SRS-initiated re-INVITE (pause, resume, metadata
    // request) is refused with 488; UPDATE is not supported (405).
    pub(super) async fn handle_rs_request(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        transport: AddrTransport,
    ) -> Option<ProcessResult> {
        let s = self.recording.as_ref()?;
        if matches!(req.method, Method::Ack | Method::Cancel) {
            return None;
        }
        let rs_call_id = req.headers.call_id()?;
        if !crate::recording::is_rs_call_id(rs_call_id) || self.recording_counters.slots_held() == 0
        {
            return None;
        }
        let (internal_id, leg) = {
            let corr = self.call_correlation.read().await;
            let id = corr.rs_leg.get(rs_call_id)?.clone();
            let leg = corr
                .addresses
                .get(&id)
                .and_then(|a| a.recording.leg.clone());
            (id, leg)
        };
        let respond_with = |status: StatusCode, header: Option<(HeaderName, String)>| {
            let mut r = create_response_from_request(req, status);
            if let Some((name, value)) = header {
                r.headers.set(name, value);
            }
            ProcessResult::Response {
                message: SipMessage::Response(r),
                destination: source,
                flow: Flow::Reply,
            }
        };
        let respond = |status: StatusCode| respond_with(status, None);
        let allow = || Some((HeaderName::Allow, RS_ALLOW.to_string()));
        let in_dialog = leg.as_ref().is_some_and(|l| {
            transport == AddrTransport::Tls
                && source.ip() == s.srs_addr.ip()
                && l.state == RsState::Established
                && l.remote_tag.is_some()
                && req.headers.from_tag() == l.remote_tag
                && req.headers.to_tag().as_deref() == extract_param(&l.from, "tag")
        });
        if !in_dialog {
            warn!(
                method = %req.method,
                source = %source,
                "Request for a recording session from outside its dialog, 481"
            );
            return Some(respond(StatusCode::CALL_DOES_NOT_EXIST));
        }
        Some(match req.method {
            Method::Bye => {
                info!(call_id = %internal_id, "SRS ended the recording session (BYE)");
                let mut out = vec![respond(StatusCode::OK)];
                out.extend(
                    self.recording_failure(
                        &internal_id,
                        RecordingFailReason::SrsBye,
                        None,
                        LegEnd::Done,
                    )
                    .await,
                );
                ProcessResult::Multiple(out)
            }
            Method::Options => respond_with(StatusCode::OK, allow()),
            // RFC 3261 §14.2, §20.43: the session is not changed.
            Method::Invite => respond_with(
                StatusCode::NOT_ACCEPTABLE_HERE,
                Some((
                    HeaderName::Warning,
                    format!(
                        "399 {} \"Recording session cannot be modified\"",
                        self.config.domain
                    ),
                )),
            ),
            _ => respond_with(StatusCode::METHOD_NOT_ALLOWED, allow()),
        })
    }

    /// Hiding snapshots for a message whose Call-ID is a recording
    /// session's: the RS dialog itself (never hidden) and the recorded
    /// call's own decision (for the BYEs a recording failure may add).
    /// Returns the snapshots and how many are set, without a heap `Vec`.
    ///
    /// No lock for a Call-ID that is not a recording session's, or while no
    /// recording slot is held.
    pub(super) async fn recording_hiding(&self, sip_call_id: &str) -> ([LegHiding; 2], usize) {
        let none = || (<[LegHiding; 2]>::default(), 0);
        if self.recording.is_none()
            || !crate::recording::is_rs_call_id(sip_call_id)
            || self.recording_counters.slots_held() == 0
        {
            return none();
        }
        let corr = self.call_correlation.read().await;
        let Some(id) = corr.rs_leg.get(sip_call_id) else {
            return none();
        };
        let rs = LegHiding {
            a_call_id: String::new(),
            b_call_id: sip_call_id.to_string(),
            a_hidden: false,
            b_hidden: false,
        };
        match corr.addresses.get(id).map(LegHiding::of) {
            Some(call) => ([rs, call], 2),
            None => ([rs, LegHiding::default()], 1),
        }
    }

    /// Whether a switch to T.38 must be refused because the call is being
    /// recorded: under `on_failure = reject` the recording must not be lost
    /// to a media change. Emergency calls and `continue` allow the switch.
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-24
    pub(super) fn recording_refuses_switch(&self, addrs: &CallAddresses) -> bool {
        self.recording.as_ref().is_some_and(|s| {
            addrs.recording.in_progress()
                && s.action(addrs.recording.emergency) == RecordingFailAction::CallRejected
        })
    }

    /// A relayed re-INVITE / UPDATE of a recorded call was answered 2xx. If
    /// the re-negotiated media is no longer readable (cleartext RTP became
    /// SDES passthrough) the recording fails as `media_not_recordable`
    /// through the policy: forking ciphertext would leave a useless
    /// recording behind a CDR that says `recorded`.
    ///
    /// ## NIST 800-53 Rev5: AU-14, AU-5, SC-24
    pub(super) async fn recording_media_changed(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        answer: Option<&[u8]>,
    ) -> Vec<ProcessResult> {
        if self.recording.is_none() || !addrs.recording.in_progress() {
            return Vec::new();
        }
        let terminated = addrs.media_terminated == crate::t38::RelaySecurity::DtlsTerminated;
        if crate::recording::still_recordable(answer, terminated) {
            return Vec::new();
        }
        self.recording_failure(
            internal_id,
            RecordingFailReason::MediaNotRecordable,
            None,
            LegEnd::WindDown,
        )
        .await
    }

    /// A recorded call switched to T.38 (allowed under `continue` or for an
    /// emergency call): the recording ends. An active recording is audited
    /// `recording_stopped` (`media_not_recordable`) and the CDR says
    /// `partial`; an RS still being set up fails as `media_not_recordable`.
    ///
    /// ## NIST 800-53 Rev5: AU-12, AU-14
    // POAM: POA&M-305 - the RS is ended rather than updated; a later switch
    // back to audio is not recorded.
    pub(super) async fn recording_media_switched(&self, session_key: &str) -> Vec<ProcessResult> {
        let Some(s) = &self.recording else {
            return Vec::new();
        };
        let internal_id = CallId::from(session_key);
        let stopped = {
            let mut corr = self.call_correlation.write().await;
            let taken = corr.addresses.get_mut(&internal_id).and_then(|a| {
                a.recording
                    .leg
                    .as_ref()
                    .is_some_and(|l| l.active_since.is_some())
                    .then(|| {
                        a.recording.slot = None;
                        a.recording.tag = Some(uc_cdr::RecordingTag::Partial);
                        (a.recording.leg.take(), a.recording.session_id.clone())
                    })
            });
            if let Some((Some(l), _)) = &taken {
                corr.rs_leg.remove(&l.call_id);
            }
            taken
        };
        let Some((Some(leg), session_id)) = stopped else {
            // Not active yet (or not recorded at all): the failure path
            // handles a pending RS and is a no-op otherwise.
            return self
                .recording_failure(
                    &internal_id,
                    RecordingFailReason::MediaNotRecordable,
                    None,
                    LegEnd::WindDown,
                )
                .await;
        };
        self.recording_counters.note_stopped();
        audit(crate::recording::audit_stopped(
            session_key,
            session_id.as_deref().unwrap_or_default(),
            RecordingStopReason::MediaNotRecordable,
            leg.active_since,
        ));
        info!(call_id = %session_key, "Recording stopped: call switched to T.38");
        self.rs_wind_down(s, &leg);
        if let Some(pipeline) = &self.media_pipeline {
            let _ = pipeline.stop_recording_fork(session_key).await;
        }
        Vec::new()
    }

    /// End of call (the exactly-once removal in `finish_call_record`): ends
    /// the RS dialog, releases the slot, audits, and writes the CDR
    /// `recording` / `recording_session_id` fields. The fork itself dies
    /// with the media session (`stop_relay` / `remove_session`).
    ///
    /// A recording that was active is `recorded`. A call that ended while
    /// its RS INVITE was still pending, or between the SRS 2xx and fork
    /// activation, is `failed`, audited `recording_failed` with reason
    /// `call_ended_during_setup` and action `call_already_ended`: the SRS
    /// did not fail and the policy had no call left to act on, so neither
    /// `srs_timeout` nor `continued_unrecorded` would be true. An answered,
    /// matched call with no outcome yet is `not_recordable`, audited
    /// `recording_failed` (`media_not_recordable`, `call_already_ended`);
    /// with an honoured opt-out in its offer it is `opt_out`, audited
    /// `recording_skipped`.
    ///
    /// ## NIST 800-53 Rev5: AU-12, AU-3, SC-5
    // POAM: POA&M-300 - `recorded` means the fork was active when the call
    // ended; no per-session forked / dropped packet count backs it, so a
    // session that forwarded no packet is not downgraded to `partial`.
    pub(super) fn recording_call_ended(
        &self,
        internal_id: &CallId,
        removed: &mut CallAddresses,
        end: &crate::cdr::CdrEnd,
    ) {
        if !removed.recording.matched {
            return;
        }
        let session = internal_id.to_string();
        let rec = &mut removed.recording;
        if let (Some(s), Some(leg)) = (&self.recording, rec.leg.take()) {
            let session_id = rec.session_id.as_deref();
            if leg.active_since.is_some() {
                self.recording_counters.note_stopped();
                audit(crate::recording::audit_stopped(
                    &session,
                    session_id.unwrap_or_default(),
                    crate::recording::stop_reason(end.cause == uc_cdr::ReleaseCause::Shutdown),
                    leg.active_since,
                ));
                rec.tag = Some(uc_cdr::RecordingTag::Recorded);
            } else {
                let reason = RecordingFailReason::CallEndedDuringSetup;
                let action = RecordingFailAction::CallAlreadyEnded;
                self.recording_counters.note_failed(reason, action);
                audit(crate::recording::audit_failed(
                    &session, session_id, reason, action, None,
                ));
                rec.tag = Some(uc_cdr::RecordingTag::Failed);
            }
            self.rs_wind_down(s, &leg);
        } else if rec.tag.is_none() && removed.b_leg_answered && rec.opt_out_offer {
            // An honoured opt-out in the offer whose answer never reached
            // the recording decision (a direct T.38 call with an unusable
            // answer): a skip, as it would have been at the answer (PT-5).
            self.recording_counters.note_skipped();
            audit(crate::recording::audit_skipped(&session));
            rec.tag = Some(uc_cdr::RecordingTag::OptOut);
        } else if rec.tag.is_none() && removed.b_leg_answered {
            // No answer-time decision was recorded for this matched call.
            // The CDR tag has its audit record and count like every other
            // not-recorded outcome (NIST 800-53 Rev5: AU-12, AU-14).
            let reason = RecordingFailReason::MediaNotRecordable;
            let action = RecordingFailAction::CallAlreadyEnded;
            self.recording_counters.note_failed(reason, action);
            audit(crate::recording::audit_failed(
                &session,
                rec.session_id.as_deref(),
                reason,
                action,
                None,
            ));
            rec.tag = Some(uc_cdr::RecordingTag::NotRecordable);
        }
        rec.slot = None;
        removed.cdr.recording = rec.tag;
        removed.cdr.recording_session_id.clone_from(&rec.session_id);
    }
}

/// `remote_media_unsupported` for a controller without the fork (a remote
/// media node), else `fallback`.
fn unsupported_or(
    e: &sbc_media_core::media_pipeline::MediaPipelineError,
    fallback: RecordingFailReason,
) -> RecordingFailReason {
    if matches!(
        e,
        sbc_media_core::media_pipeline::MediaPipelineError::RecordingUnsupported
    ) {
        RecordingFailReason::RemoteMediaUnsupported
    } else {
        fallback
    }
}

/// The RS route set: the 2xx Record-Route in reverse (RFC 3261 §12.1.2),
/// bounded. A malformed or oversized list gives no route set. Carried for
/// the far end only; RS requests always go to the pinned SRS address.
fn rs_route_set(resp: &SipResponse) -> Vec<String> {
    let mut routes: Vec<String> = Vec::new();
    for rr in resp.headers.get_all(&HeaderName::RecordRoute) {
        match proto_sip::split_list_bounded(&rr.value, MAX_RS_ROUTES) {
            Ok(v) if routes.len() + v.len() <= MAX_RS_ROUTES => {
                routes.extend(v.into_iter().map(str::to_string));
            }
            _ => return Vec::new(),
        }
    }
    routes.reverse();
    routes
}
