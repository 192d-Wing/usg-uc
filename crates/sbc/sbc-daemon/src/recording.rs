//! SIPREC Session Recording Client policy for the B2BUA (`[recording]`).
//!
//! Pure decisions and builders used by `sip_stack` (same split as `t38`):
//! which calls match the recording trigger, whether a call's media can be
//! recorded, the recording session (RS) INVITE / ACK / BYE / CANCEL toward
//! the recorder (SRS), validation of the SRS answer, the per-call recording
//! state, the `max_sessions` slot, counters and audit records. The stack
//! glue (locks, timers, media controller calls) is in
//! `sip_stack/recording_session.rs`.
//!
//! No header value of an RS request is taken from a received message. The
//! only call-derived data are the two participants' AOR and display name,
//! which reach the SRS through the escaping RFC 7865 serializer, and the
//! negotiated payload formats of the call's offer and answer.
//!
//! ## NIST 800-53 Rev5
//!
//! - **AU-14 / AU-14(1)**: session content capture for calls whose media
//!   the SBC can read, from the SRS answer on (gaps: the POAM notes below)
//! - **AU-2 / AU-3 / AU-12**: `recording_started|stopped|failed|skipped`
//! - **AU-5 / SC-24**: failure policy, fail closed by default
//! - **SC-5**: `recording.max_sessions` slot, bounded state
//! - **SC-8 / SC-12 / SC-13**: RS only on the verified recorder TLS flow;
//!   per-stream CSPRNG SDES keys, `AEAD_AES_256_GCM`, never logged
//! - **SI-10**: SRS answer validation, bounded body, metadata sanitising
//!
//! ## RFC
//!
//! - RFC 7866 §6.1.1 (SRC-initiated RS, `Require: siprec`, `+sip.src`),
//!   §7.1.1 (RS SDP), §7.1.3 (`recordpref`), §9.1 (metadata), §12 (security)
//! - RFC 7865 §6 (metadata model)
//! - RFC 3261 §8.1.1, §9.1, §12.1.2, §13.2.2.4, §15, §17.1.1
//! - RFC 4568 §5, §6 (SDES), RFC 7714 (AES-256-GCM)
// POAM: POA&M-300 - no RS liveness check (session timer / OPTIONS ping); a
// recorder that dies silently mid-call is not detected.
// POAM: POA&M-300 - the CDR `recorded` tag and `recording_stopped` carry no
// per-session forked / dropped packet counts (process-wide counters only).
// POAM: POA&M-301 - no RTCP toward the SRS (RFC 7866 §8.1.1, §8.1.5.1: the
// RS carries RTP only); SDES / DTLS passthrough calls and calls on remote
// media nodes are not recordable.
// POAM: POA&M-301 - early media (before the call's 200 OK) is not recorded:
// the RS INVITE is sent when the call is answered.
// POAM: POA&M-303 - no in-band recording indication to participants (no
// `a=record`, RFC 7866 §7.1.2).
// POAM: POA&M-305 - no metadata update on re-INVITE, hold or T.38 switch.
// POAM: POA&M-307 - RS state is node-local (not replicated).
// POAM: POA&M-308 - SRS-initiated re-INVITE / UPDATE are refused (488).

use crate::flow::LegFlow;
use bytes::Bytes;
use proto_b2bua::{StreamKind, StreamPreference, select_anchored_stream};
use proto_sdp::{Attribute, AttributeName, SessionDescription, TransportProtocol};
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::uri::{SipUri, UriScheme};
use proto_sip::{Header, HeaderName, Method};
use sbc_config::schema::{RecordingConfig, RecordingFailureAction, RecordprefPolicy};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uc_audit::event::{
    RecordingFailAction, RecordingFailReason, RecordingFailed, RecordingRelay, RecordingSkipReason,
    RecordingSkipped, RecordingStarted, RecordingStopReason, RecordingStopped,
};
use uc_siprec::{MediaStream, Participant, RecordingMetadata, RsInviteParts, SdesKey};
use uc_types::address::SbcSocketAddr;

/// Streams of a recording session: the caller's sent media (label `1`) and
/// the callee's (label `2`).
pub const RS_STREAMS: usize = 2;

/// Largest SRS answer body examined (SC-5, SI-10). An `application/sdp`
/// answer with two audio m-lines is a few hundred bytes.
pub const MAX_RS_ANSWER_BYTES: usize = 16 * 1024;

/// Payload formats copied from the call's SDP into one RS m-line.
const MAX_RS_FORMATS: usize = 32;
/// Methods the SBC accepts inside a recording session dialog (RFC 3261
/// §20.5): the `Allow` of the RS INVITE, of the OPTIONS 200 and of a 405.
pub const RS_ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS";
/// `a=rtpmap` / `a=fmtp` / `a=ptime` lines copied per RS m-line.
const MAX_RS_CODEC_ATTRS: usize = 64;
/// Longest codec attribute value copied.
const MAX_RS_CODEC_ATTR_LEN: usize = 256;
/// Longest participant AOR / display name sent in the metadata. Longer
/// values are truncated (not refused) so an oversized From cannot be used to
/// make recording fail.
const MAX_PARTICIPANT_FIELD: usize = 256;
/// Record-Route entries kept as the RS route set (RFC 3261 §12.1.2).
pub const MAX_RS_ROUTES: usize = 16;
/// Prefix of every recording session Call-ID the SBC generates. It lets
/// the per-message paths tell "cannot be a recording session message"
/// without taking the call-table lock ([`is_rs_call_id`]); it carries no
/// authority (the RS dialog table decides) and no call data.
const RS_CALL_ID_PREFIX: &str = "rs-";
/// AOR recorded for a participant whose From / To carried no usable URI.
const ANONYMOUS_AOR: &str = "sip:anonymous@anonymous.invalid";

/// Resolved `[recording]` settings, built once at startup (the section is
/// restart-required on reload).
///
/// ## NIST 800-53 Rev5: CM-6, SC-8, SC-23
#[derive(Debug, Clone)]
pub struct RecordingSettings {
    /// The configured recorder URI (`sips:` only). Request-URI and To of the
    /// RS INVITE.
    pub srs_uri: SipUri,
    /// The recorder's address, resolved once at startup and pinned: every RS
    /// request goes here, whatever the SRS puts in Contact / Record-Route.
    pub srs_addr: SbcSocketAddr,
    /// The recorder TLS flow (dial-on-demand, SRS CA and name verified).
    pub flow: LegFlow,
    /// Record every call.
    pub record_all: bool,
    /// Record calls with either leg on one of these trunk groups.
    pub trunk_groups: Vec<String>,
    /// Record calls with either leg in one of these zones.
    pub zones: Vec<String>,
    /// Concurrent recording sessions on this node.
    pub max_sessions: usize,
    /// RS INVITE final-response timeout.
    pub invite_timeout: Duration,
    /// What happens to the call when recording fails.
    pub on_failure: RecordingFailureAction,
    /// Honour a participant's `a=recordpref` opt-out.
    pub honour_recordpref: bool,
    /// Zone whose media address the fork binds to and advertises.
    pub srs_zone: Option<String>,
    /// The SBC's source address toward the SRS, used in the RS SDP when no
    /// zone media address applies.
    pub local_media_ip: Option<IpAddr>,
    /// The SBC's own RTP port range (`media.rtp_port_min..=rtp_port_max`).
    /// An SRS answer that names one of the SBC's addresses with a port in
    /// this range (a relay or fork socket) is refused. Every port until the
    /// daemon sets the real range, so an unset range fails closed.
    pub media_ports: std::ops::RangeInclusive<u16>,
    /// Every address assigned to a local interface, sorted, learned once at
    /// startup (`sbc_config::interface::local_addresses`). An unzoned relay
    /// binds the wildcard address, so each of these reaches the SBC's
    /// sockets whether or not the configuration names it.
    // POAM: POA&M-301 - an address added to an interface after startup is
    // not in this list until the daemon restarts.
    pub local_addrs: Vec<IpAddr>,
}

impl RecordingSettings {
    /// Builds the settings from a validated `[recording]` section, the
    /// resolved recorder address and the SBC's source address toward it.
    ///
    /// # Errors
    ///
    /// A message for the startup log when the URI is missing, not `sips:`,
    /// or the TLS name is unusable. `sbc-config` validation rejects all of
    /// these first; this is the daemon's own fail-closed check.
    pub fn from_config(
        rec: &RecordingConfig,
        srs_addr: SbcSocketAddr,
        local_media_ip: Option<IpAddr>,
    ) -> Result<Self, String> {
        let srs_uri = parse_srs_uri(rec.srs_uri.as_deref())?;
        let tls_name: Arc<str> = Arc::from(
            rec.srs_tls_server_name
                .as_deref()
                .unwrap_or_else(|| bare_host(&srs_uri.host)),
        );
        if tls_name.is_empty() {
            return Err("recording: empty SRS TLS server name".to_string());
        }
        Ok(Self {
            srs_uri,
            srs_addr,
            flow: LegFlow::recorder(&tls_name),
            record_all: rec.record_all,
            trunk_groups: rec.trunk_groups.clone(),
            zones: rec.zones.clone(),
            max_sessions: usize::try_from(rec.max_sessions).unwrap_or(usize::MAX),
            invite_timeout: Duration::from_millis(u64::from(rec.rs_invite_timeout_ms)),
            on_failure: rec.on_failure,
            honour_recordpref: rec.recordpref_never == RecordprefPolicy::Honour,
            srs_zone: rec.srs_zone.clone(),
            local_media_ip,
            media_ports: 0..=u16::MAX,
            local_addrs: Vec::new(),
        })
    }

    /// Whether a call matches the recording trigger: `record_all`, or either
    /// leg on a listed trunk group or in a listed zone. The egress leg is
    /// every trunk the call may leave on: the route's first trunk and each
    /// failover target, so a failover can never move a call onto a listed
    /// group without it having gone through the recording policy.
    ///
    /// ## NIST 800-53 Rev5: AU-14, SC-24
    pub fn matches(&self, t: &Trigger<'_>) -> bool {
        self.record_all
            || [t.ingress_trunk_group, t.egress_trunk_group]
                .into_iter()
                .flatten()
                .chain(t.failover_targets.iter().map(|(group, _)| group.as_str()))
                .any(|g| self.trunk_groups.iter().any(|x| x == g))
            || [t.ingress_zone, t.egress_zone]
                .into_iter()
                .flatten()
                .any(|z| self.zones.iter().any(|x| x == z))
    }

    /// The action the failure policy takes for a call. Emergency calls are
    /// never torn down for a recording failure (47 CFR 9.16).
    pub const fn action(&self, emergency: bool) -> RecordingFailAction {
        if emergency {
            RecordingFailAction::EmergencyContinued
        } else {
            match self.on_failure {
                RecordingFailureAction::Reject => RecordingFailAction::CallRejected,
                RecordingFailureAction::Continue => RecordingFailAction::ContinuedUnrecorded,
            }
        }
    }
}

/// Parses `recording.srs_uri`: `sips:` only, no `transport` / `maddr`.
///
/// # Errors
///
/// A message naming the rule the URI breaks.
///
/// ## NIST 800-53 Rev5: SC-8; RFC 5630 §3.2
pub fn parse_srs_uri(uri: Option<&str>) -> Result<SipUri, String> {
    let raw = uri.ok_or_else(|| "recording.srs_uri is not set".to_string())?;
    let parsed: SipUri = raw
        .parse()
        .map_err(|_| "recording.srs_uri is not a SIP URI".to_string())?;
    if parsed.scheme != UriScheme::Sips {
        return Err("recording.srs_uri must be a sips: URI".to_string());
    }
    if parsed.host.is_empty() || parsed.maddr().is_some() || parsed.transport().is_some() {
        return Err("recording.srs_uri must name a host and carry no maddr/transport".to_string());
    }
    Ok(parsed)
}

/// Whether a SIP Call-ID can be a recording session's (see
/// [`RS_CALL_ID_PREFIX`]). `false` is definitive; `true` still needs the
/// RS dialog table.
pub fn is_rs_call_id(call_id: &str) -> bool {
    call_id.starts_with(RS_CALL_ID_PREFIX)
}

/// A URI host without IPv6 brackets.
pub fn bare_host(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// What the trigger is evaluated against (both legs of the call).
#[derive(Debug, Clone, Copy, Default)]
pub struct Trigger<'a> {
    /// Trunk group the INVITE arrived from.
    pub ingress_trunk_group: Option<&'a str>,
    /// Trunk group the call is routed to.
    pub egress_trunk_group: Option<&'a str>,
    /// Zone the INVITE arrived on.
    pub ingress_zone: Option<&'a str>,
    /// Zone the callee is reached through (the same for every trunk of
    /// the route).
    pub egress_zone: Option<&'a str>,
    /// `(trunk group, trunk)` of each failover target of the route.
    pub failover_targets: &'a [(String, String)],
}

/// One held `recording.max_sessions` slot; released on drop, so every path
/// that drops the call's recording state frees it without per-path code.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[derive(Debug)]
pub struct RecordingSlot(Arc<AtomicUsize>);

impl Drop for RecordingSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// Recording counters, exported as gauges by the metrics endpoint (fixed
/// names, no labels).
///
/// ## NIST 800-53 Rev5: SI-4 (System Monitoring), AU-5
#[derive(Debug, Default)]
pub struct RecordingCounters {
    /// Slots held (`sbc_recording_sessions_active`).
    slots: Arc<AtomicUsize>,
    started: AtomicU64,
    stopped: AtomicU64,
    skipped: AtomicU64,
    calls_rejected: AtomicU64,
    failed: [AtomicU64; RecordingFailReason::ALL.len()],
    rs_bye_dropped: AtomicU64,
}

/// Gauge: recording session slots held.
pub const METRIC_SESSIONS_ACTIVE: &str = "sbc_recording_sessions_active";
/// Counter: recording sessions started.
pub const METRIC_STARTED: &str = "sbc_recording_started_total";
/// Counter: recording sessions stopped after having been active.
pub const METRIC_STOPPED: &str = "sbc_recording_stopped_total";
/// Counter: matched calls not recorded because a participant opted out.
pub const METRIC_SKIPPED: &str = "sbc_recording_skipped_total";
/// Counter: calls refused or torn down by `recording.on_failure = reject`.
pub const METRIC_CALLS_REJECTED: &str = "sbc_recording_calls_rejected_total";
/// Counter: RS BYE / CANCEL / ACK the SBC dropped (wind-down queue or
/// recorder send lane full).
pub const METRIC_RS_BYE_DROPPED: &str = "sbc_recording_rs_bye_dropped_total";
/// Counter: RTP packets sent to the recorder.
pub const METRIC_FORK_PACKETS: &str = "sbc_recording_fork_packets_total";
/// Counter: RTP packets that should have been forked and were not.
pub const METRIC_FORK_DROPPED: &str = "sbc_recording_fork_dropped_total";
/// Counters per failure reason, in [`RecordingFailReason::ALL`] order.
pub const METRIC_FAILED: [&str; RecordingFailReason::ALL.len()] = [
    "sbc_recording_failed_no_session_slot_total",
    "sbc_recording_failed_media_not_recordable_total",
    "sbc_recording_failed_fork_setup_total",
    "sbc_recording_failed_srs_unreachable_total",
    "sbc_recording_failed_srs_tls_total",
    "sbc_recording_failed_srs_rejected_total",
    "sbc_recording_failed_srs_not_acceptable_488_total",
    "sbc_recording_failed_srs_timeout_total",
    "sbc_recording_failed_srs_bad_answer_total",
    "sbc_recording_failed_srs_bye_total",
    "sbc_recording_failed_remote_media_unsupported_total",
    "sbc_recording_failed_call_ended_during_setup_total",
];
/// Help text for the recording metrics.
pub const METRIC_HELP: &str = "SIPREC recording sessions (RFC 7866 SRC): slots held, sessions \
                               started / stopped / skipped, failures by reason, calls rejected by \
                               the failure policy and RTP packets forked to the recorder";

/// Every recording metric name (registration order).
pub fn metric_names() -> impl Iterator<Item = &'static str> {
    [
        METRIC_SESSIONS_ACTIVE,
        METRIC_STARTED,
        METRIC_STOPPED,
        METRIC_SKIPPED,
        METRIC_CALLS_REJECTED,
        METRIC_RS_BYE_DROPPED,
        METRIC_FORK_PACKETS,
        METRIC_FORK_DROPPED,
    ]
    .into_iter()
    .chain(METRIC_FAILED)
}

fn reason_index(reason: RecordingFailReason) -> Option<usize> {
    RecordingFailReason::ALL.iter().position(|r| *r == reason)
}

impl RecordingCounters {
    /// Reserves one slot if fewer than `ceiling` are held. The check and
    /// the increment are one CAS, so concurrent INVITEs cannot overshoot.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_reserve(&self, ceiling: usize) -> Option<Arc<RecordingSlot>> {
        self.slots
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                (cur < ceiling).then_some(cur + 1)
            })
            .ok()
            .map(|_| Arc::new(RecordingSlot(Arc::clone(&self.slots))))
    }

    /// Slots currently held.
    pub fn slots_held(&self) -> usize {
        self.slots.load(Ordering::Acquire)
    }

    /// A recording session became active.
    pub fn note_started(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }

    /// An active recording session ended.
    pub fn note_stopped(&self) {
        self.stopped.fetch_add(1, Ordering::Relaxed);
    }

    /// A matched call was skipped (participant opt-out).
    pub fn note_skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// A recording failure, and what the policy did with the call.
    pub fn note_failed(&self, reason: RecordingFailReason, action: RecordingFailAction) {
        if let Some(c) = reason_index(reason).and_then(|i| self.failed.get(i)) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if action == RecordingFailAction::CallRejected {
            self.calls_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An RS BYE / CANCEL / ACK was dropped: the wind-down queue or the
    /// recorder's send lane was full (the SRS falls back to its own RTP
    /// inactivity timeout).
    pub fn note_rs_bye_dropped(&self) {
        self.rs_bye_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Failures counted for `reason`.
    pub fn failed(&self, reason: RecordingFailReason) -> u64 {
        reason_index(reason)
            .and_then(|i| self.failed.get(i))
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Calls refused or torn down by the failure policy.
    pub fn calls_rejected(&self) -> u64 {
        self.calls_rejected.load(Ordering::Relaxed)
    }

    /// `(name, value)` for every recording metric.
    pub fn metric_values(&self) -> Vec<(&'static str, u64)> {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut out = vec![
            (
                METRIC_SESSIONS_ACTIVE,
                u64::try_from(self.slots_held()).unwrap_or(u64::MAX),
            ),
            (METRIC_STARTED, load(&self.started)),
            (METRIC_STOPPED, load(&self.stopped)),
            (METRIC_SKIPPED, load(&self.skipped)),
            (METRIC_CALLS_REJECTED, load(&self.calls_rejected)),
            (METRIC_RS_BYE_DROPPED, load(&self.rs_bye_dropped)),
            (
                METRIC_FORK_PACKETS,
                sbc_media_core::media_pipeline::recording_fork_packets(),
            ),
            (
                METRIC_FORK_DROPPED,
                sbc_media_core::media_pipeline::recording_fork_dropped(),
            ),
        ];
        out.extend(
            METRIC_FAILED
                .iter()
                .copied()
                .zip(self.failed.iter().map(load)),
        );
        out
    }
}

/// State of the SBC's dialog with the recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsState {
    /// The RS INVITE is out; no final response yet.
    Inviting,
    /// The SRS answered 2xx with a valid answer (dialog confirmed).
    Established,
}

/// The recording session leg of a call: the SBC's UAC dialog with the SRS.
/// SBC-chosen values only, except `remote_tag`, `remote_target` and `routes`,
/// which are validated values from the SRS 2xx. Holds no key material.
///
/// ## RFC 3261 §12.1.2 (UAC dialog state)
#[derive(Debug, Clone)]
pub struct RecordingLeg {
    /// RS Call-ID (random; never derived from the call's Call-IDs).
    pub call_id: String,
    /// From with the SBC's tag.
    pub from: String,
    /// To without a tag.
    pub to: String,
    /// The SRS's tag, once it answered.
    pub remote_tag: Option<String>,
    /// Top Via branch of the RS INVITE.
    pub branch: String,
    /// Request-URI of in-dialog requests (the 2xx Contact when it is a
    /// usable `sips:` URI, else the configured SRS URI).
    pub remote_target: SipUri,
    /// Route set from the 2xx Record-Route, reversed. Carried for the far
    /// end only: the request still goes to the pinned SRS address.
    pub routes: Vec<String>,
    /// SBC sent-by of the recorder flow (Via / Contact).
    pub sent_by: String,
    /// Dialog state.
    pub state: RsState,
    /// A provisional response was seen, so a CANCEL may be sent (§9.1).
    pub provisional_seen: bool,
    /// When the RS INVITE was built.
    pub invited_at: Instant,
    /// When the fork started copying media to the SRS.
    pub active_since: Option<Instant>,
    /// Next CSeq of the SBC's requests in the RS dialog (the INVITE used 1).
    pub next_cseq: u32,
    /// Relay mode feeding the fork.
    pub relay: RecordingRelay,
    /// Payload formats offered on each RS m-line; the SRS answer must
    /// accept all of them (RFC 3264 §6.1).
    pub offered_formats: Arc<[Vec<String>; RS_STREAMS]>,
}

/// Per-call recording state, inside the call's correlation record. It is
/// cloned with the record, so it holds no keys: SDES keys go straight from
/// the generator to the media pipeline and the RS INVITE body.
///
/// ## NIST 800-53 Rev5: SC-12 (keys not in cloned state), SC-5
#[derive(Debug, Clone, Default)]
pub struct CallRecording {
    /// The call matched the recording trigger.
    pub matched: bool,
    /// Emergency call: never torn down for a recording failure.
    pub emergency: bool,
    /// The caller's offer carried a `recordpref` opt-out.
    pub opt_out_offer: bool,
    /// Whether the callee's 2xx is being (or was) handled.
    pub answer: AnswerClaim,
    /// The `max_sessions` slot. Released when the last clone drops; the live
    /// record's copy is cleared as soon as the call stops being recorded.
    pub slot: Option<Arc<RecordingSlot>>,
    /// The RS dialog, while one exists.
    pub leg: Option<RecordingLeg>,
    /// Recording outcome so far (CDR `recording`).
    pub tag: Option<uc_cdr::RecordingTag>,
    /// RFC 7865 session identifier sent to the SRS, as a UUID.
    pub session_id: Option<String>,
}

/// Whether a copy of the callee's 2xx has claimed the call's answer for
/// recording. A second copy handled while the first is still in progress
/// is a retransmission and must not start, or fail, the recording again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnswerClaim {
    /// No 2xx seen yet.
    #[default]
    Unclaimed,
    /// A 2xx is being, or was, handled.
    Claimed,
}

impl CallRecording {
    /// The call is being recorded or the RS is being set up.
    pub const fn in_progress(&self) -> bool {
        self.leg.is_some()
    }
}

/// CDR tag for a recording that failed for `reason`. `was_active`: media
/// was already being forked (the recording covers part of the call).
pub const fn failure_tag(reason: RecordingFailReason, was_active: bool) -> uc_cdr::RecordingTag {
    if was_active {
        return uc_cdr::RecordingTag::Partial;
    }
    match reason {
        RecordingFailReason::NoSessionSlot
        | RecordingFailReason::MediaNotRecordable
        | RecordingFailReason::RemoteMediaUnsupported => uc_cdr::RecordingTag::NotRecordable,
        RecordingFailReason::ForkSetup
        | RecordingFailReason::SrsUnreachable
        | RecordingFailReason::SrsTls
        | RecordingFailReason::SrsRejected
        | RecordingFailReason::SrsNotAcceptable488
        | RecordingFailReason::SrsTimeout
        | RecordingFailReason::SrsBadAnswer
        | RecordingFailReason::SrsBye
        | RecordingFailReason::CallEndedDuringSetup => uc_cdr::RecordingTag::Failed,
    }
}

/// Failure reason for a non-2xx final response to the RS INVITE. 488 is
/// named separately: it is what an AES-128-only recorder answers to the
/// `AEAD_AES_256_GCM`-only offer.
pub const fn reason_for_status(status: u16) -> RecordingFailReason {
    if status == 488 {
        RecordingFailReason::SrsNotAcceptable488
    } else {
        RecordingFailReason::SrsRejected
    }
}

// ----------------------------------------------------------------------
// Audit records (enum fields and SBC-generated identifiers only).
// ----------------------------------------------------------------------

/// `recording_started`.
pub fn audit_started(
    session: &str,
    recording_session_id: &str,
    leg: &RecordingLeg,
    answered: Option<Instant>,
) -> uc_audit::AuditEvent {
    let now = Instant::now();
    uc_audit::AuditEvent::RecordingStarted(RecordingStarted {
        call_id: session.to_string(),
        recording_session_id: recording_session_id.to_string(),
        start_offset_ms: millis(now.saturating_duration_since(answered.unwrap_or(leg.invited_at))),
        relay: leg.relay,
    })
}

/// `recording_stopped`.
pub fn audit_stopped(
    session: &str,
    recording_session_id: &str,
    reason: RecordingStopReason,
    active_since: Option<Instant>,
) -> uc_audit::AuditEvent {
    uc_audit::AuditEvent::RecordingStopped(RecordingStopped {
        call_id: session.to_string(),
        recording_session_id: recording_session_id.to_string(),
        reason,
        duration_ms: active_since.map_or(0, |t| millis(t.elapsed())),
    })
}

/// `recording_failed`.
pub fn audit_failed(
    session: &str,
    recording_session_id: Option<&str>,
    reason: RecordingFailReason,
    action: RecordingFailAction,
    sip_status: Option<u16>,
) -> uc_audit::AuditEvent {
    uc_audit::AuditEvent::RecordingFailed(RecordingFailed {
        call_id: session.to_string(),
        recording_session_id: recording_session_id.map(str::to_string),
        reason,
        action,
        sip_status,
    })
}

/// `recording_skipped` (participant opt-out).
pub fn audit_skipped(session: &str) -> uc_audit::AuditEvent {
    uc_audit::AuditEvent::RecordingSkipped(RecordingSkipped {
        call_id: session.to_string(),
        reason: RecordingSkipReason::ParticipantOptOut,
    })
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

// ----------------------------------------------------------------------
// Recordability (decided at answer).
// ----------------------------------------------------------------------

/// The payload formats of one RS m-line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodecSet {
    /// RTP payload type numbers, as SDP format tokens.
    pub formats: Vec<String>,
    /// `a=rtpmap` / `a=fmtp` / `a=ptime` / `a=maxptime` for those formats.
    pub attributes: Vec<Attribute>,
}

/// The formats of the two RS streams of a recordable call.
///
/// The SBC relays RTP unchanged, so each direction carries the payload type
/// numbers its receiver asked for (RFC 3264 §5.1, §6.1): the caller sends
/// with the numbers of the callee's answer, the callee with the numbers of
/// the offer it was sent. The two can differ for the same codec.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsCodecs {
    /// Stream `1`, the caller's sent media: the answer's formats.
    pub caller: CodecSet,
    /// Stream `2`, the callee's sent media: the formats of the offer the
    /// SBC sent to the callee, for the codecs the answer accepted.
    pub callee: CodecSet,
}

impl RsCodecs {
    /// The format list of each RS m-line, in stream order.
    pub fn offered_formats(&self) -> [Vec<String>; RS_STREAMS] {
        [self.caller.formats.clone(), self.callee.formats.clone()]
    }
}

/// Facts about the answered call that decide whether it can be recorded.
#[derive(Debug, Clone, Copy)]
pub struct AnsweredCall<'a> {
    /// The offer the SBC sent to the callee (keeps the caller's m-line
    /// protocol).
    pub offer_sdp: Option<&'a str>,
    /// The callee's answer.
    pub answer_sdp: Option<&'a str>,
    /// The relay terminates DTLS-SRTP on both legs (the SBC holds
    /// plaintext).
    pub terminated: bool,
    /// The call is a direct T.38 call (image stream anchored).
    pub image: bool,
    /// The in-process media relay anchors the call.
    pub anchored: bool,
}

/// What the INVITE alone says about a call (before the B-leg is dialled).
#[derive(Debug, Clone, Copy)]
pub struct OfferedCall<'a> {
    /// The caller's offer; `None` for an INVITE without SDP (late offer).
    pub offer_sdp: Option<&'a str>,
    /// A direct T.38 call (image-only offer).
    pub image: bool,
    /// An in-process media relay exists to anchor the call.
    pub anchored: bool,
    /// The relay may terminate DTLS-SRTP for this call (termination is
    /// configured and the offer carries a DTLS fingerprint); whether it
    /// does is known only at the answer.
    pub may_terminate: bool,
}

const fn is_cleartext_rtp(proto: TransportProtocol) -> bool {
    matches!(
        proto,
        TransportProtocol::RtpAvp | TransportProtocol::RtpAvpf
    )
}

fn has_key_attribute(sdp: &SessionDescription, index: usize) -> bool {
    let keyed = |a: &Attribute| match &a.name {
        AttributeName::Fingerprint => true,
        AttributeName::Custom(n) => n.eq_ignore_ascii_case("crypto"),
        _ => false,
    };
    sdp.attributes.iter().any(keyed)
        || sdp
            .media
            .get(index)
            .is_some_and(|m| m.attributes.iter().any(keyed))
}

/// Whether an SDP announces ZRTP (`a=zrtp-hash`, RFC 6189 §8) at session or
/// media level. ZRTP keys SRTP in the media path on a plain `RTP/AVP`
/// m-line, so the SBC would relay, and fork, ciphertext it cannot read.
/// Raw-text scan: it does not depend on the body parsing as SDP.
///
/// Payload-level encryption that is not announced in SDP (ZRTP without the
/// hash attribute, proprietary schemes) cannot be detected.
///
/// ## NIST 800-53 Rev5: SC-24 (fail closed), AU-14
pub fn announces_zrtp(sdp: &str) -> bool {
    const NAME: &str = "a=zrtp-hash";
    sdp.lines().any(|line| {
        let line = line.trim();
        line.get(..NAME.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(NAME))
            && matches!(line.as_bytes().get(NAME.len()), None | Some(b':'))
    })
}

/// Whether the INVITE already shows that the call cannot be recorded,
/// whatever the callee answers: no SDP offer, a direct T.38 call, no
/// in-process relay, an offer that announces ZRTP, or an anchored audio
/// m-line that is not `RTP/AVP` / `RTP/AVPF` on a relay that will not
/// terminate DTLS-SRTP. Such a call is refused under `on_failure = reject`
/// before the B-leg is dialled, so it is never connected and then cut
/// (RFC 3261 §15: a UAS must not BYE before it got the ACK).
///
/// `true` means "not ruled out yet": [`classify`] decides at the answer.
///
/// ## NIST 800-53 Rev5: SC-24 (fail closed), AU-5
pub fn offer_recordable(call: &OfferedCall<'_>) -> bool {
    if call.image || !call.anchored {
        return false;
    }
    let Some(offer) = call.offer_sdp.filter(|o| !o.trim().is_empty()) else {
        return false;
    };
    if announces_zrtp(offer) {
        return false;
    }
    select_anchored_stream(offer, StreamPreference::Audio).is_some_and(|stream| {
        stream.kind == StreamKind::Audio && (call.may_terminate || is_cleartext_rtp(stream.proto))
    })
}

/// RFC 3551 §6 table 4: the static audio payload types, for an m-line that
/// lists one without an `a=rtpmap`.
const fn static_codec(pt: u8) -> Option<(&'static str, u32)> {
    Some(match pt {
        0 => ("pcmu", 8000),
        3 => ("gsm", 8000),
        4 => ("g723", 8000),
        5 => ("dvi4", 8000),
        6 => ("dvi4", 16_000),
        7 => ("lpc", 8000),
        8 => ("pcma", 8000),
        9 => ("g722", 8000),
        10 | 11 => ("l16", 44_100),
        12 => ("qcelp", 8000),
        13 => ("cn", 8000),
        14 => ("mpa", 90_000),
        15 => ("g728", 8000),
        16 => ("dvi4", 11_025),
        17 => ("dvi4", 22_050),
        18 => ("g729", 8000),
        _ => return None,
    })
}

/// Encoding name (lower case) and clock rate of payload type `pt` on an
/// m-line: its `a=rtpmap` (RFC 8866 §6.6), else the static assignment.
/// `None` for a dynamic type without an rtpmap.
fn codec_identity(media: &proto_sdp::MediaDescription, pt: &str) -> Option<(String, u32)> {
    let mapped = media
        .attributes
        .iter()
        .filter(|a| a.name == AttributeName::Rtpmap)
        .filter_map(|a| a.value.as_deref())
        .find_map(|v| {
            let mut fields = v.split_ascii_whitespace();
            if fields.next() != Some(pt) {
                return None;
            }
            let mut encoding = fields.next()?.split('/');
            let name = encoding.next().filter(|n| !n.is_empty())?;
            let rate = encoding.next()?.parse::<u32>().ok()?;
            Some((name.to_ascii_lowercase(), rate))
        });
    mapped.or_else(|| {
        let (name, rate) = static_codec(pt.parse().ok()?)?;
        Some((name.to_string(), rate))
    })
}

/// The RTP payload types of an m-line (RFC 3551: 0..=127), de-duplicated
/// and bounded, that `keep` accepts.
fn payload_formats(
    media: &proto_sdp::MediaDescription,
    keep: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut formats: Vec<String> = Vec::new();
    for f in &media.formats {
        if f.parse::<u8>().is_ok_and(|pt| pt <= 127)
            && !formats.contains(f)
            && formats.len() < MAX_RS_FORMATS
            && keep(f)
        {
            formats.push(f.clone());
        }
    }
    formats
}

fn codec_set(media: &proto_sdp::MediaDescription, formats: Vec<String>) -> CodecSet {
    let attributes = media
        .attributes
        .iter()
        .filter(|a| codec_attribute_for(a, &formats))
        .take(MAX_RS_CODEC_ATTRS)
        .cloned()
        .collect();
    CodecSet {
        formats,
        attributes,
    }
}

/// Decides whether the answered call's media can be recorded and, if so,
/// which formats each RS stream carries.
///
/// Recordable: the relay anchors an audio stream, and the SBC can read it:
/// either the relay terminates DTLS-SRTP, or the anchored m-line is
/// `RTP/AVP` / `RTP/AVPF` in both the offer and the answer with no keying
/// attribute in the answer (an `a=crypto` on `RTP/AVP` is opportunistic
/// SRTP the SBC passes through and cannot read). Neither SDP may announce
/// ZRTP ([`announces_zrtp`]).
///
/// Stream `1` (the caller's sent media) gets the answer's payload types;
/// stream `2` (the callee's) gets the payload types of the offer the SBC
/// sent to the callee, for the codecs the answer accepted, matched by
/// encoding name and clock rate (RFC 3264 §6.1; see [`RsCodecs`]).
///
/// # Errors
///
/// [`RecordingFailReason::MediaNotRecordable`] otherwise. The media
/// pipeline cannot tell cleartext RTP from passthrough SRTP, so this check
/// is the only guard against forking ciphertext.
///
/// ## NIST 800-53 Rev5: SC-24 (fail closed), SI-10
// POAM: POA&M-301 - SDES / DTLS passthrough legs are not recordable.
pub fn classify(call: &AnsweredCall<'_>) -> Result<RsCodecs, RecordingFailReason> {
    const NOT: RecordingFailReason = RecordingFailReason::MediaNotRecordable;
    if call.image || !call.anchored {
        return Err(NOT);
    }
    let answer_text = call.answer_sdp.ok_or(NOT)?;
    let offer_text = call.offer_sdp.ok_or(NOT)?;
    if announces_zrtp(answer_text) || announces_zrtp(offer_text) {
        return Err(NOT);
    }
    let answer = select_anchored_stream(answer_text, StreamPreference::Audio).ok_or(NOT)?;
    if answer.kind != StreamKind::Audio || answer.port == 0 {
        return Err(NOT);
    }
    let parsed: SessionDescription = answer_text.parse().map_err(|_| NOT)?;
    if !call.terminated {
        let offer = select_anchored_stream(offer_text, StreamPreference::Audio).ok_or(NOT)?;
        if !is_cleartext_rtp(offer.proto)
            || !is_cleartext_rtp(answer.proto)
            || has_key_attribute(&parsed, answer.index)
        {
            return Err(NOT);
        }
    }
    let media = parsed.media.get(answer.index).ok_or(NOT)?;
    // RFC 3264 §6: the answer's m-lines pair with the offer's by position.
    let offered: SessionDescription = offer_text.parse().map_err(|_| NOT)?;
    let offered_media = offered
        .media
        .get(answer.index)
        .filter(|m| m.media_type == proto_sdp::MediaType::Audio)
        .ok_or(NOT)?;

    let answer_formats = payload_formats(media, |_| true);
    let accepted: Vec<(String, u32)> = answer_formats
        .iter()
        .filter_map(|pt| codec_identity(media, pt))
        .collect();
    // A dynamic type the offer did not map is matched by its number.
    let offer_formats = payload_formats(offered_media, |pt| {
        codec_identity(offered_media, pt).map_or_else(
            || answer_formats.iter().any(|f| f == pt),
            |id| accepted.contains(&id),
        )
    });
    if answer_formats.is_empty() || offer_formats.is_empty() {
        return Err(NOT);
    }
    Ok(RsCodecs {
        caller: codec_set(media, answer_formats),
        callee: codec_set(offered_media, offer_formats),
    })
}

/// Whether a recorded call's media is still readable after a mid-call
/// session change (the 2xx answer to a relayed re-INVITE / UPDATE).
///
/// A call that was cleartext RTP at answer can be re-negotiated to SDES
/// SRTP, which the SBC passes through and cannot read: forking it would
/// send the recorder ciphertext while the CDR says `recorded`. Every active
/// audio m-line of the answer must still be `RTP/AVP` / `RTP/AVPF` without
/// a keying attribute, unless the relay terminates DTLS-SRTP, and the
/// answer must not announce ZRTP. No body means no session change; a body
/// that does not parse is not trusted. Image m-lines are the T.38 switch's
/// business.
///
/// ## NIST 800-53 Rev5: SC-24 (fail closed), AU-14
// POAM: POA&M-301 - SDES / DTLS passthrough legs are not recordable.
pub fn still_recordable(answer_sdp: Option<&[u8]>, terminated: bool) -> bool {
    let Some(body) = answer_sdp.filter(|b| !b.is_empty()) else {
        return true;
    };
    let text = std::str::from_utf8(body).ok();
    if text.is_some_and(announces_zrtp) {
        return false;
    }
    if terminated {
        return true;
    }
    let Some(sdp) = text.and_then(|t| t.parse::<SessionDescription>().ok()) else {
        return false;
    };
    sdp.media
        .iter()
        .enumerate()
        .filter(|(_, m)| m.media_type == proto_sdp::MediaType::Audio && m.port != 0)
        .all(|(i, m)| is_cleartext_rtp(m.protocol) && !has_key_attribute(&sdp, i))
}

/// A codec attribute safe to copy into the RS offer: bounded, free of
/// control characters, and (for `rtpmap` / `fmtp`) naming a copied format.
fn codec_attribute_for(a: &Attribute, formats: &[String]) -> bool {
    let Some(value) = a.value.as_deref() else {
        return false;
    };
    if value.len() > MAX_RS_CODEC_ATTR_LEN || value.chars().any(char::is_control) {
        return false;
    }
    match a.name {
        AttributeName::Rtpmap | AttributeName::Fmtp => value
            .split_whitespace()
            .next()
            .is_some_and(|pt| formats.iter().any(|f| f == pt)),
        AttributeName::Ptime | AttributeName::Maxptime => {
            value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty()
        }
        _ => false,
    }
}

// ----------------------------------------------------------------------
// RS offer.
// ----------------------------------------------------------------------

/// Two fresh SDES keys and the same material for the media pipeline, in
/// stream order (caller's sent media first).
///
/// # Errors
///
/// `()` when the CSPRNG or key construction fails (fail closed).
///
/// ## NIST 800-53 Rev5: SC-12, SC-13 (one CSPRNG key per stream)
pub fn generate_keys() -> Result<
    (
        [SdesKey; RS_STREAMS],
        [proto_srtp::SrtpKeyMaterial; RS_STREAMS],
    ),
    (),
> {
    let material = |k: &SdesKey| {
        proto_srtp::SrtpKeyMaterial::new(
            proto_srtp::SrtpProfile::AeadAes256Gcm,
            k.master_key().to_vec(),
            k.master_salt().to_vec(),
        )
        .map_err(|_| ())
    };
    let a = SdesKey::generate().map_err(|_| ())?;
    let b = SdesKey::generate().map_err(|_| ())?;
    let pipeline = [material(&a)?, material(&b)?];
    Ok(([a, b], pipeline))
}

/// The RS SDP offer skeleton: two audio m-lines on the fork ports, each
/// with the formats its stream carries. `build_rs_offer` adds `RTP/SAVP`, `a=sendonly`,
/// `a=rtcp-mux`, `a=label` and `a=crypto`.
///
/// # Errors
///
/// `()` when the SBC-built skeleton does not parse (never expected).
///
/// ## RFC 7866 §7.1.1; RFC 8866 §5
pub fn build_rs_sdp(
    media_ip: IpAddr,
    ports: [u16; RS_STREAMS],
    codecs: &RsCodecs,
    session_id: u64,
) -> Result<SessionDescription, ()> {
    let family = if media_ip.is_ipv4() { "IP4" } else { "IP6" };
    let [a_port, b_port] = ports;
    let skeleton = format!(
        "v=0\r\no=- {session_id} 1 IN {family} {media_ip}\r\ns=-\r\n\
         c=IN {family} {media_ip}\r\nt=0 0\r\n\
         m=audio {a_port} RTP/SAVP 0\r\nm=audio {b_port} RTP/SAVP 0\r\n"
    );
    let mut sdp: SessionDescription = skeleton.parse().map_err(|_| ())?;
    for (m, set) in sdp.media.iter_mut().zip([&codecs.caller, &codecs.callee]) {
        m.formats.clone_from(&set.formats);
        m.attributes.extend(set.attributes.iter().cloned());
    }
    Ok(sdp)
}

/// Splits a From / To header value into the AOR and display name recorded
/// for a participant. Both are attacker-controlled: control characters are
/// dropped and long values truncated here, and the RFC 7865 serializer
/// escapes them. URI parameters, headers and a password are not recorded.
///
/// ## NIST 800-53 Rev5: SI-10, SI-15
pub fn participant_identity(header_value: &str) -> (String, Option<String>) {
    let v = header_value.trim();
    let (name, uri) = match (v.find('<'), v.rfind('>')) {
        (Some(open), Some(close)) if open < close => (
            v.get(..open).unwrap_or(""),
            v.get(open + 1..close).unwrap_or(""),
        ),
        _ => ("", v.split(';').next().unwrap_or("")),
    };
    let uri = uri.split([';', '?']).next().unwrap_or("").trim();
    // `sip:user:password@host`: drop the password.
    let aor = match uri.rsplit_once('@') {
        Some((userinfo, host)) => {
            let mut parts = userinfo.splitn(3, ':');
            match (parts.next(), parts.next()) {
                (Some(scheme), Some(user)) => format!("{scheme}:{user}@{host}"),
                _ => uri.to_string(),
            }
        }
        None => uri.to_string(),
    };
    let aor = clean_field(&aor);
    let name = clean_field(name.trim().trim_matches('"'));
    (
        if aor.is_empty() {
            ANONYMOUS_AOR.to_string()
        } else {
            aor
        },
        (!name.is_empty()).then_some(name),
    )
}

fn clean_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_PARTICIPANT_FIELD));
    for c in s.chars() {
        if c.is_control() || matches!(c, '\u{FFFE}' | '\u{FFFF}') {
            continue;
        }
        if out.len() + c.len_utf8() > MAX_PARTICIPANT_FIELD {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// RFC 7865 metadata for a two-party call: one session, the caller and the
/// callee, and the two streams (`1` the caller's sent media, `2` the
/// callee's).
///
/// ## RFC 7865 §6; RFC 7866 §9.1
pub fn build_metadata(session: &str, caller_from: &str, callee_to: &str) -> RecordingMetadata {
    let mut meta = RecordingMetadata::new(session);
    for (id, header, label) in [("caller", caller_from, "1"), ("callee", callee_to, "2")] {
        let (aor, name) = participant_identity(header);
        let mut p = Participant::new(id, aor);
        if let Some(name) = name {
            p = p.with_display_name(name);
        }
        meta.add_participant(p);
        meta.add_stream(MediaStream::audio(label).with_participant(id));
    }
    meta
}

/// Reads the RFC 7865 `<session session_id="...">` value out of an RS
/// INVITE body built by `uc_siprec::build_rs_offer` and renders it as a
/// UUID (RFC 7865 §6.10: the identifiers are base64-encoded 128-bit UUIDs).
/// This is the identifier the SRS stores with the recording; the CDR and
/// the audit trail carry the same value.
///
/// `None` when the body does not hold exactly one 128-bit identifier there
/// (the caller fails the recording closed).
pub fn session_id_from_body(body: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"<session session_id=\"";
    let start = body.windows(MARK.len()).position(|w| w == MARK)? + MARK.len();
    let rest = body.get(start..)?;
    let end = rest.iter().position(|b| *b == b'"')?;
    let bytes = base64_decode_16(rest.get(..end)?)?;
    let hex = |range: std::ops::Range<usize>| -> Option<String> {
        use std::fmt::Write as _;
        let mut s = String::new();
        for b in bytes.get(range)? {
            let _ = write!(s, "{b:02x}");
        }
        Some(s)
    };
    Some(format!(
        "{}-{}-{}-{}-{}",
        hex(0..4)?,
        hex(4..6)?,
        hex(6..8)?,
        hex(8..10)?,
        hex(10..16)?
    ))
}

/// Decodes standard base64 (RFC 4648 §4, padding optional) that encodes
/// exactly 16 octets.
fn base64_decode_16(input: &[u8]) -> Option<[u8; 16]> {
    let input = match input {
        [head @ .., b'=', b'='] => head,
        other => other,
    };
    if input.len() != 22 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0usize;
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((acc >> bits) & 0xFF).ok()?;
            if let Some(slot) = out.get_mut(n) {
                *slot = byte;
            }
            n += 1;
        }
    }
    (n == 16).then_some(out)
}

// ----------------------------------------------------------------------
// RS requests. Every header value is SBC-chosen.
// ----------------------------------------------------------------------

/// Owner of the RS INVITE body inside a [`Bytes`]: the buffer (it carries
/// the SDES `inline:` keys) is wiped when the last reference to the body is
/// dropped, i.e. when the client transaction that keeps the INVITE is
/// pruned.
///
/// ## NIST 800-53 Rev5: SC-12, SI-12
struct KeyedBody(zeroize::Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for KeyedBody {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

fn random_hex<const N: usize>() -> Result<String, ()> {
    use std::fmt::Write as _;
    let bytes: [u8; N] = uc_crypto::random::generate_random().map_err(|_| ())?;
    let mut s = String::with_capacity(N * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

/// A URI host form of `host` (IPv6 literals bracketed).
fn uri_host(host: &str) -> String {
    let bare = bare_host(host);
    if bare.contains(':') {
        format!("[{bare}]")
    } else {
        bare.to_string()
    }
}

fn base_request(
    method: Method,
    uri: SipUri,
    leg: &RecordingLeg,
    flow: &LegFlow,
    branch: &str,
) -> SipRequest {
    let mut r = SipRequest::new(method, uri);
    r.headers.add(Header::new(
        HeaderName::Via,
        crate::flow::via_for(flow, &leg.sent_by, branch),
    ));
    r.headers.set(HeaderName::MaxForwards, "70");
    r.headers.set(HeaderName::From, &leg.from);
    r.headers.set(HeaderName::CallId, &leg.call_id);
    r
}

fn to_with_tag(leg: &RecordingLeg) -> String {
    leg.remote_tag
        .as_deref()
        .map_or_else(|| leg.to.clone(), |t| format!("{};tag={t}", leg.to))
}

/// Builds the RS INVITE and the leg state for it.
///
/// Request-URI and To are the configured SRS URI; Call-ID (with the fixed
/// `rs-` prefix), From tag and branch are random; Contact carries `+sip.src` and `Require` carries
/// `siprec` (RFC 7866 §6.1.1); `Allow` lists what the SBC accepts in the
/// dialog (RFC 3261 §13.2.1). The body (RS SDP offer with SDES keys plus
/// RFC 7865 metadata) is moved, not copied, into the request.
/// `offered_formats` is kept on the leg to check the SRS answer against.
///
/// # Errors
///
/// `()` when the CSPRNG fails.
///
/// ## RFC 3261 §8.1.1; RFC 7866 §6.1.1, §9.1; NIST 800-53 Rev5: SC-8, SC-12
pub fn build_rs_invite(
    settings: &RecordingSettings,
    domain: &str,
    sent_by: &str,
    parts: RsInviteParts,
    relay: RecordingRelay,
    offered_formats: [Vec<String>; RS_STREAMS],
) -> Result<(SipRequest, RecordingLeg), ()> {
    let host = uri_host(domain);
    let leg = RecordingLeg {
        call_id: format!("{RS_CALL_ID_PREFIX}{}@{host}", random_hex::<16>()?),
        from: format!("<sips:{host}>;tag={}", random_hex::<8>()?),
        to: format!("<{}>", settings.srs_uri),
        remote_tag: None,
        branch: proto_sip::builder::generate_branch(),
        remote_target: settings.srs_uri.clone(),
        routes: Vec::new(),
        sent_by: sent_by.to_string(),
        state: RsState::Inviting,
        provisional_seen: false,
        invited_at: Instant::now(),
        active_since: None,
        next_cseq: 2,
        relay,
        offered_formats: Arc::new(offered_formats),
    };
    let mut inv = base_request(
        Method::Invite,
        settings.srs_uri.clone(),
        &leg,
        &settings.flow,
        &leg.branch,
    );
    inv.headers.set(HeaderName::To, &leg.to);
    inv.headers.set(HeaderName::CSeq, "1 INVITE");
    inv.headers.set(
        HeaderName::Contact,
        parts.headers.contact_value(&format!("sips:{sent_by}")),
    );
    inv.headers
        .set(HeaderName::Require, parts.headers.require());
    inv.headers.set(HeaderName::Allow, RS_ALLOW);
    inv.headers
        .set(HeaderName::ContentType, parts.content_type.as_str());
    inv.headers
        .set(HeaderName::ContentLength, parts.body.len().to_string());
    inv.body = Some(Bytes::from_owner(KeyedBody(parts.body)));
    Ok((inv, leg))
}

fn in_dialog(method: Method, cseq: u32, leg: &RecordingLeg, flow: &LegFlow) -> SipRequest {
    let name = method.to_string();
    let mut r = base_request(
        method,
        leg.remote_target.clone(),
        leg,
        flow,
        &proto_sip::builder::generate_branch(),
    );
    r.headers.set(HeaderName::To, to_with_tag(leg));
    r.headers.set(HeaderName::CSeq, format!("{cseq} {name}"));
    for route in &leg.routes {
        r.headers.add(Header::new(HeaderName::Route, route));
    }
    r.headers.set(HeaderName::ContentLength, "0");
    r
}

/// ACK for the RS INVITE's 2xx (RFC 3261 §13.2.2.4: its own transaction,
/// the INVITE's CSeq number). Rebuilt for every 2xx retransmission.
pub fn build_rs_ack(leg: &RecordingLeg, flow: &LegFlow) -> SipRequest {
    in_dialog(Method::Ack, 1, leg, flow)
}

/// BYE ending the RS dialog (RFC 3261 §15), with the leg's next CSeq.
pub fn build_rs_bye(leg: &RecordingLeg, flow: &LegFlow) -> SipRequest {
    in_dialog(Method::Bye, leg.next_cseq, leg, flow)
}

/// CANCEL for a pending RS INVITE (RFC 3261 §9.1: same Request-URI,
/// Call-ID, From, To, CSeq number and top Via as the INVITE).
pub fn build_rs_cancel(settings: &RecordingSettings, leg: &RecordingLeg) -> SipRequest {
    let mut r = base_request(
        Method::Cancel,
        settings.srs_uri.clone(),
        leg,
        &settings.flow,
        &leg.branch,
    );
    r.headers.set(HeaderName::To, &leg.to);
    r.headers.set(HeaderName::CSeq, "1 CANCEL");
    r.headers.set(HeaderName::ContentLength, "0");
    r
}

/// The remote target for in-dialog RS requests (RFC 3261 §12.1.2): the 2xx
/// Contact (already sanitized by the caller). A `sip:` Contact is upgraded
/// to `sips:` keeping its user, host and port (the dialog was set up with a
/// `sips:` Request-URI over TLS, RFC 5630 §3.1.3; a `transport` parameter
/// is dropped, RFC 5630 §3.2). No Contact: the configured SRS URI.
///
/// Deliberate deviation from RFC 3261 §12.2.1.1: only the Request-URI comes
/// from the Contact. Every RS request is sent to the pinned SRS address on
/// the recorder flow, so an SRS answer cannot redirect SBC traffic.
///
/// ## NIST 800-53 Rev5: SC-8, SC-23
pub fn remote_target(contact: Option<SipUri>, settings: &RecordingSettings) -> SipUri {
    let Some(mut uri) = contact else {
        return settings.srs_uri.clone();
    };
    uri.scheme = UriScheme::Sips;
    uri.password = None;
    uri.headers.clear();
    uri.params
        .retain(|(name, _)| !name.eq_ignore_ascii_case("transport"));
    uri
}

/// Validates the SRS 2xx answer and returns the two media addresses, in
/// stream order. The body is size-capped before it is parsed; it must be
/// `application/sdp`, UTF-8, and pass `uc_siprec::parse_rs_answer` (same
/// m-line count, `RTP/SAVP`, one `AEAD_AES_256_GCM` crypto with tag 1,
/// `recvonly`, a unicast address). On top of that:
///
/// - each m-line must accept every payload format the RS offer listed for
///   it and add none (RFC 3264 §6.1). The fork copies the call's payload
///   types unchanged, so a format the SRS left out would arrive anyway and
///   be undecodable behind a `recorded` CDR;
/// - no media address may be one of the SBC's own sockets (`is_own`: an
///   SBC address with a port the SBC itself uses): the fork must not be
///   pointed back at the SBC's relay or signaling ports. A recorder on the
///   SBC's host, on ports of its own, is allowed.
///
/// # Errors
///
/// `()` for any defect: the caller reports `srs_bad_answer`. Nothing from
/// the answer is logged (it carries the SRS's SDES key).
///
/// ## NIST 800-53 Rev5: SI-10, SC-5, SC-7; RFC 4568 §5.1.2, RFC 7866 §7.2
// POAM: POA&M-301 - the media address may be a host other than the SRS
// signaling peer (a separate media server): it is only required to be
// unicast, non-loopback and not the SBC itself, so an authenticated SRS can
// point the encrypted fork at a third host.
pub fn validate_rs_answer(
    resp: &SipResponse,
    is_sdp: bool,
    offered_formats: &[Vec<String>; RS_STREAMS],
    is_own: impl Fn(SocketAddr) -> bool,
) -> Result<[SocketAddr; RS_STREAMS], ()> {
    let body = resp.body.as_ref().filter(|b| !b.is_empty()).ok_or(())?;
    if !is_sdp || body.len() > MAX_RS_ANSWER_BYTES {
        return Err(());
    }
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    let sdp: SessionDescription = text.parse().map_err(|_| ())?;
    let streams = uc_siprec::parse_rs_answer(&sdp, RS_STREAMS).map_err(|_| ())?;
    for (m, offered) in sdp.media.iter().zip(offered_formats) {
        let same_set = m.formats.iter().all(|f| offered.contains(f))
            && offered.iter().all(|f| m.formats.contains(f));
        if !same_set {
            return Err(());
        }
    }
    let [a, b] = streams.as_slice() else {
        return Err(());
    };
    let own = |addr: SocketAddr| {
        // An IPv4-mapped IPv6 literal reaches the IPv4 address.
        let v4 = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        is_own(addr) || v4.is_some_and(|ip| is_own(SocketAddr::new(ip, addr.port())))
    };
    if own(a.addr) || own(b.addr) {
        return Err(());
    }
    Ok([a.addr, b.addr])
}

/// Whether an SDP body carries a participant's `recordpref` opt-out for
/// the recorded audio stream (RFC 7866 §7.1.3 `off`, and the non-standard
/// alias `never`; a media-level value overrides the session-level one).
pub fn opted_out(sdp: Option<&[u8]>) -> bool {
    sdp.is_some_and(|b| uc_siprec::has_recordpref_never(&String::from_utf8_lossy(b)))
}

/// Stop reason audited when an active recording ends through the failure
/// path for `reason`.
pub const fn stop_reason_for(reason: RecordingFailReason) -> RecordingStopReason {
    match reason {
        RecordingFailReason::MediaNotRecordable => RecordingStopReason::MediaNotRecordable,
        RecordingFailReason::CallEndedDuringSetup => RecordingStopReason::CallEnded,
        _ => RecordingStopReason::SrsBye,
    }
}

/// Stop reason for a recording that ends with its call.
pub const fn stop_reason(shutdown: bool) -> RecordingStopReason {
    if shutdown {
        RecordingStopReason::Shutdown
    } else {
        RecordingStopReason::CallEnded
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
        m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\n\
        a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n";
    const ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
        m=audio 5000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n\
        a=fmtp:101 0-16\r\na=ptime:20\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n";

    pub fn settings(on_failure: RecordingFailureAction) -> RecordingSettings {
        let rec = RecordingConfig {
            enabled: true,
            notice_acknowledged: true,
            srs_uri: Some("sips:srs.example.test:5061".to_string()),
            srs_tls_ca_file: Some("/unused".to_string()),
            record_all: true,
            on_failure,
            ..RecordingConfig::default()
        };
        RecordingSettings::from_config(
            &rec,
            SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 0, 2, 50), 5061),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
        )
        .unwrap()
    }

    fn call<'a>(offer: &'a str, answer: &'a str) -> AnsweredCall<'a> {
        AnsweredCall {
            offer_sdp: Some(offer),
            answer_sdp: Some(answer),
            terminated: false,
            image: false,
            anchored: true,
        }
    }

    #[test]
    fn settings_require_a_sips_uri_and_default_the_tls_name() {
        let s = settings(RecordingFailureAction::Reject);
        assert_eq!(s.flow.dial.as_deref(), Some("srs.example.test"));
        assert!(s.flow.recorder);
        assert_eq!(s.flow.transport, uc_types::address::TransportType::Tls);
        assert_eq!(s.invite_timeout, Duration::from_millis(5000));
        assert!(
            !s.honour_recordpref,
            "a participant opt-out is honoured only by explicit choice"
        );
        for bad in [
            None,
            Some("sip:srs.example.test"),
            Some("sips:srs.example.test;transport=tcp"),
            Some("sips:srs.example.test;maddr=192.0.2.1"),
            Some("tel:+15551230000"),
            Some("not a uri"),
        ] {
            assert!(parse_srs_uri(bad).is_err(), "{bad:?}");
        }
        let mut rec = RecordingConfig {
            srs_uri: Some("sips:[2001:db8::5]:5071".to_string()),
            srs_tls_server_name: Some("rec.example.test".to_string()),
            ..RecordingConfig::default()
        };
        let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5071);
        let s = RecordingSettings::from_config(&rec, addr, None).unwrap();
        assert_eq!(s.flow.dial.as_deref(), Some("rec.example.test"));
        rec.srs_tls_server_name = None;
        let s = RecordingSettings::from_config(&rec, addr, None).unwrap();
        assert_eq!(s.flow.dial.as_deref(), Some("2001:db8::5"), "no brackets");
    }

    #[test]
    fn trigger_matches_either_leg() {
        let mut s = settings(RecordingFailureAction::Reject);
        assert!(s.matches(&Trigger::default()), "record_all");
        s.record_all = false;
        assert!(!s.matches(&Trigger::default()));
        s.trunk_groups = vec!["carrier".to_string()];
        s.zones = vec!["dmz".to_string()];
        let t = |itg, etg, iz, ez| Trigger {
            ingress_trunk_group: itg,
            egress_trunk_group: etg,
            ingress_zone: iz,
            egress_zone: ez,
            failover_targets: &[],
        };
        assert!(s.matches(&t(Some("carrier"), None, None, None)));
        assert!(s.matches(&t(None, Some("carrier"), None, None)));
        assert!(s.matches(&t(None, None, Some("dmz"), None)));
        assert!(s.matches(&t(None, None, None, Some("dmz"))));
        assert!(!s.matches(&t(Some("other"), Some("x"), Some("lan"), Some("lan"))));
    }

    // SEC-001 (AU-14): a trunk-group trigger matches when any trunk the
    // call may fail over to is in a listed group, not only the first one.
    #[test]
    fn trigger_matches_a_failover_target_group() {
        let mut s = settings(RecordingFailureAction::Reject);
        s.record_all = false;
        s.trunk_groups = vec!["carrier-b".to_string()];
        let pair = |g: &str, t: &str| (g.to_string(), t.to_string());
        let on_b = [pair("carrier-a", "a2"), pair("carrier-b", "b1")];
        let on_a = [pair("carrier-a", "a2")];
        let t = |failover_targets| Trigger {
            egress_trunk_group: Some("carrier-a"),
            failover_targets,
            ..Trigger::default()
        };
        assert!(s.matches(&t(&on_b)), "second failover target is listed");
        assert!(!s.matches(&t(&on_a)));
        assert!(!s.matches(&t(&[])));
        // The trunk id is not a group name.
        assert!(!s.matches(&t(&[pair("carrier-a", "carrier-b")])));
    }

    // AU-5 / 47 CFR 9.16: emergency calls are never torn down.
    #[test]
    fn policy_action_exempts_emergency_calls() {
        let reject = settings(RecordingFailureAction::Reject);
        assert_eq!(reject.action(false), RecordingFailAction::CallRejected);
        assert_eq!(reject.action(true), RecordingFailAction::EmergencyContinued);
        let cont = settings(RecordingFailureAction::Continue);
        assert_eq!(cont.action(false), RecordingFailAction::ContinuedUnrecorded);
        assert_eq!(cont.action(true), RecordingFailAction::EmergencyContinued);
    }

    // SC-5: the slot count never passes the ceiling and drops release it.
    #[test]
    fn slots_are_bounded_and_released_on_drop() {
        let c = RecordingCounters::default();
        let a = c.try_reserve(2).unwrap();
        let b = c.try_reserve(2).unwrap();
        assert!(c.try_reserve(2).is_none());
        assert_eq!(c.slots_held(), 2);
        let a2 = Arc::clone(&a);
        drop(a);
        assert_eq!(c.slots_held(), 2, "a clone still holds the slot");
        drop(a2);
        assert_eq!(c.slots_held(), 1);
        drop(b);
        assert_eq!(c.slots_held(), 0);
        assert!(c.try_reserve(1).is_some());
    }

    #[test]
    fn metric_names_follow_the_audit_reason_tokens() {
        for (reason, name) in RecordingFailReason::ALL.into_iter().zip(METRIC_FAILED) {
            assert_eq!(
                name,
                format!("sbc_recording_failed_{}_total", reason.as_str())
            );
        }
        let c = RecordingCounters::default();
        c.note_failed(
            RecordingFailReason::SrsNotAcceptable488,
            RecordingFailAction::CallRejected,
        );
        c.note_failed(
            RecordingFailReason::SrsTimeout,
            RecordingFailAction::ContinuedUnrecorded,
        );
        c.note_started();
        c.note_stopped();
        c.note_skipped();
        c.note_rs_bye_dropped();
        let _slot = c.try_reserve(4);
        let values: std::collections::HashMap<_, _> = c.metric_values().into_iter().collect();
        assert_eq!(values.len(), metric_names().count(), "no duplicate names");
        for name in metric_names() {
            assert!(values.contains_key(name), "{name}");
        }
        assert_eq!(values[METRIC_SESSIONS_ACTIVE], 1);
        assert_eq!(values[METRIC_STARTED], 1);
        assert_eq!(values[METRIC_STOPPED], 1);
        assert_eq!(values[METRIC_SKIPPED], 1);
        assert_eq!(values[METRIC_CALLS_REJECTED], 1);
        assert_eq!(values[METRIC_RS_BYE_DROPPED], 1);
        assert_eq!(
            values["sbc_recording_failed_srs_not_acceptable_488_total"],
            1
        );
        assert_eq!(values["sbc_recording_failed_srs_timeout_total"], 1);
        assert_eq!(c.failed(RecordingFailReason::SrsBye), 0);
    }

    #[test]
    fn failure_tags_and_status_reasons() {
        use uc_cdr::RecordingTag as T;
        assert_eq!(
            failure_tag(RecordingFailReason::NoSessionSlot, false),
            T::NotRecordable
        );
        assert_eq!(
            failure_tag(RecordingFailReason::MediaNotRecordable, false),
            T::NotRecordable
        );
        assert_eq!(
            failure_tag(RecordingFailReason::SrsTimeout, false),
            T::Failed
        );
        assert_eq!(failure_tag(RecordingFailReason::SrsBye, true), T::Partial);
        assert_eq!(
            reason_for_status(488),
            RecordingFailReason::SrsNotAcceptable488
        );
        assert_eq!(reason_for_status(503), RecordingFailReason::SrsRejected);
    }

    #[test]
    fn classify_copies_the_answer_formats() {
        let codecs = classify(&call(OFFER, ANSWER)).unwrap().caller;
        assert_eq!(codecs.formats, vec!["0", "101"]);
        let values: Vec<_> = codecs
            .attributes
            .iter()
            .map(|a| format!("{}:{}", a.name.as_str(), a.value.as_deref().unwrap()))
            .collect();
        assert_eq!(
            values,
            vec![
                "rtpmap:0 PCMU/8000",
                "rtpmap:101 telephone-event/8000",
                "fmtp:101 0-16",
                "ptime:20"
            ],
            "the rtpmap of a format the answer did not select is not copied"
        );
    }

    // POA&M-301 / SC-24: media the SBC cannot read is never forked.
    #[test]
    fn classify_refuses_unreadable_media() {
        let not = Err(RecordingFailReason::MediaNotRecordable);
        let savp = ANSWER.replace("RTP/AVP", "RTP/SAVP");
        assert_eq!(classify(&call(OFFER, &savp)), not, "SDES answer");
        let savp_offer = OFFER.replace("RTP/AVP", "RTP/SAVP");
        assert_eq!(classify(&call(&savp_offer, ANSWER)), not, "SDES offer");
        let dtls = ANSWER.replace("RTP/AVP", "UDP/TLS/RTP/SAVP");
        assert_eq!(classify(&call(OFFER, &dtls)), not, "DTLS passthrough");
        let osrtp = format!(
            "{ANSWER}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n"
        );
        assert_eq!(classify(&call(OFFER, &osrtp)), not, "opportunistic SRTP");
        let fingerprint = ANSWER.replace("t=0 0\r\n", "t=0 0\r\na=fingerprint:sha-384 AA:BB\r\n");
        assert_eq!(
            classify(&call(OFFER, &fingerprint)),
            not,
            "session fingerprint"
        );
        let declined = ANSWER.replace("m=audio 5000", "m=audio 0");
        assert_eq!(classify(&call(OFFER, &declined)), not, "declined stream");
        let image = "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
            m=image 5100 udptl t38\r\n";
        assert_eq!(classify(&call(OFFER, image)), not, "image answer");
        assert_eq!(classify(&call(OFFER, "garbage")), not);
        assert_eq!(
            classify(&AnsweredCall {
                answer_sdp: None,
                ..call(OFFER, ANSWER)
            }),
            not,
            "no answer body"
        );
        assert_eq!(
            classify(&AnsweredCall {
                offer_sdp: None,
                ..call(OFFER, ANSWER)
            }),
            not,
            "no offer to compare"
        );
        assert_eq!(
            classify(&AnsweredCall {
                image: true,
                ..call(OFFER, ANSWER)
            }),
            not,
            "direct T.38 call"
        );
        assert_eq!(
            classify(&AnsweredCall {
                anchored: false,
                ..call(OFFER, ANSWER)
            }),
            not,
            "no in-process relay"
        );
        let no_pt = ANSWER.replace("RTP/AVP 0 101", "RTP/AVP opus x");
        assert_eq!(classify(&call(OFFER, &no_pt)), not, "no numeric format");
    }

    // A mid-call re-negotiation to SRTP passthrough ends recordability;
    // hold and a disabled audio stream do not.
    #[test]
    fn still_recordable_follows_the_renegotiated_media() {
        assert!(still_recordable(None, false), "no body: no change");
        assert!(still_recordable(Some(b""), false));
        assert!(still_recordable(Some(ANSWER.as_bytes()), false));
        let hold = ANSWER.replace("a=sendrecv", "a=inactive");
        assert!(still_recordable(Some(hold.as_bytes()), false), "hold");
        let off = ANSWER.replace("m=audio 5000", "m=audio 0");
        assert!(
            still_recordable(Some(off.as_bytes()), false),
            "audio declined"
        );
        let savp = ANSWER.replace("RTP/AVP", "RTP/SAVP");
        assert!(!still_recordable(Some(savp.as_bytes()), false), "SDES");
        assert!(
            still_recordable(Some(savp.as_bytes()), true),
            "terminated relay"
        );
        let osrtp = format!("{ANSWER}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n");
        assert!(!still_recordable(Some(osrtp.as_bytes()), false), "OSRTP");
        assert!(!still_recordable(Some(b"garbage"), false), "unparseable");
        assert!(!still_recordable(Some(&[0xff, 0xfe]), false), "not UTF-8");
        assert_eq!(
            stop_reason_for(RecordingFailReason::MediaNotRecordable),
            RecordingStopReason::MediaNotRecordable
        );
        assert_eq!(
            stop_reason_for(RecordingFailReason::SrsBye),
            RecordingStopReason::SrsBye
        );
    }

    // A DTLS-terminated relay holds plaintext: the SAVP m-line is fine.
    #[test]
    fn classify_accepts_a_terminated_relay() {
        let dtls = ANSWER.replace("RTP/AVP", "UDP/TLS/RTP/SAVP");
        let c = AnsweredCall {
            terminated: true,
            ..call(OFFER, &dtls)
        };
        assert_eq!(classify(&c).unwrap().caller.formats, vec!["0", "101"]);
    }

    // RFC-002 (RFC 3264 §5.1, §6.1; RFC 3550 §5.1): the callee sends with
    // the payload types of the offer it received, the caller with those of
    // the answer. The reviewer's case: offer 96/101, answer 111/110.
    #[test]
    fn classify_labels_each_stream_with_the_payload_types_it_carries() {
        let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
            m=audio 4000 RTP/AVP 96 101 8 97\r\na=rtpmap:96 opus/48000/2\r\n\
            a=fmtp:96 useinbandfec=1\r\na=rtpmap:101 telephone-event/48000\r\n\
            a=fmtp:101 0-15\r\na=rtpmap:97 telephone-event/8000\r\n";
        let answer = "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
            m=audio 5000 RTP/AVP 111 110\r\na=rtpmap:111 OPUS/48000/2\r\n\
            a=fmtp:111 stereo=0\r\na=rtpmap:110 telephone-event/48000\r\na=fmtp:110 0-16\r\n";
        let codecs = classify(&call(offer, answer)).unwrap();
        let values = |set: &CodecSet| -> Vec<String> {
            set.attributes
                .iter()
                .map(|a| format!("{}:{}", a.name.as_str(), a.value.as_deref().unwrap()))
                .collect()
        };
        assert_eq!(codecs.caller.formats, vec!["111", "110"]);
        assert_eq!(
            values(&codecs.caller),
            vec![
                "rtpmap:111 OPUS/48000/2",
                "fmtp:111 stereo=0",
                "rtpmap:110 telephone-event/48000",
                "fmtp:110 0-16",
            ]
        );
        // Stream 2: the offer's numbers and parameters, for the accepted
        // codecs only (PCMA and the 8 kHz telephone-event were not).
        assert_eq!(codecs.callee.formats, vec!["96", "101"]);
        assert_eq!(
            values(&codecs.callee),
            vec![
                "rtpmap:96 opus/48000/2",
                "fmtp:96 useinbandfec=1",
                "rtpmap:101 telephone-event/48000",
                "fmtp:101 0-15",
            ]
        );
        assert_eq!(
            codecs.offered_formats(),
            [
                vec!["111".to_string(), "110".to_string()],
                vec!["96".to_string(), "101".to_string()]
            ]
        );
        let sdp = build_rs_sdp("192.0.2.9".parse().unwrap(), [30_000, 30_002], &codecs, 1)
            .unwrap()
            .to_string();
        assert!(sdp.contains("m=audio 30000 RTP/SAVP 111 110"), "{sdp}");
        assert!(sdp.contains("m=audio 30002 RTP/SAVP 96 101"), "{sdp}");

        // A static type without an rtpmap on one side still pairs up.
        let bare = "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
            m=audio 5000 RTP/AVP 8\r\n";
        let codecs = classify(&call(offer, bare)).unwrap();
        assert_eq!(codecs.callee.formats, vec!["8"]);
        // No codec in common with the offer: nothing the callee could send.
        let alien = bare.replace("RTP/AVP 8", "RTP/AVP 9");
        assert_eq!(
            classify(&call(offer, &alien)),
            Err(RecordingFailReason::MediaNotRecordable)
        );
    }

    // SEC-006: ZRTP keys SRTP in the media path on an RTP/AVP m-line.
    #[test]
    fn zrtp_is_not_recordable() {
        let hash =
            "a=zrtp-hash:1.10 fe30efd02423cb054e50efd0248742ac7a52c8f91bc2df881ae642c371ba46df\r\n";
        let offer = format!("{OFFER}{hash}");
        let answer = format!("{ANSWER}{hash}");
        let not = Err(RecordingFailReason::MediaNotRecordable);
        assert_eq!(classify(&call(&offer, ANSWER)), not, "offer");
        assert_eq!(classify(&call(OFFER, &answer)), not, "answer");
        let terminated = AnsweredCall {
            terminated: true,
            ..call(OFFER, &answer)
        };
        assert_eq!(classify(&terminated), not, "also on a terminated relay");
        assert!(announces_zrtp("v=0\r\nA=ZRTP-HASH:1.10 00\r\n"));
        assert!(announces_zrtp(
            &OFFER.replace("s=-\r\n", &format!("s=-\r\n{hash}"))
        ));
        assert!(!announces_zrtp(OFFER));
        assert!(!announces_zrtp(
            "v=0\r\na=zrtp-hashes:1\r\ni=a=zrtp-hash:1\r\n"
        ));
        assert!(!still_recordable(Some(answer.as_bytes()), false));
        assert!(!still_recordable(Some(answer.as_bytes()), true));
        let offered = |offer_sdp| OfferedCall {
            offer_sdp,
            image: false,
            anchored: true,
            may_terminate: false,
        };
        assert!(!offer_recordable(&offered(Some(&offer))));
        assert!(offer_recordable(&offered(Some(OFFER))));
    }

    // RFC-001 (a): what the INVITE alone rules out.
    #[test]
    fn offer_recordable_rules_out_what_no_answer_can_fix() {
        let base = OfferedCall {
            offer_sdp: Some(OFFER),
            image: false,
            anchored: true,
            may_terminate: false,
        };
        assert!(offer_recordable(&base));
        assert!(!offer_recordable(&OfferedCall {
            offer_sdp: None,
            ..base
        }));
        assert!(!offer_recordable(&OfferedCall {
            offer_sdp: Some("  "),
            ..base
        }));
        assert!(!offer_recordable(&OfferedCall {
            offer_sdp: Some("garbage"),
            ..base
        }));
        assert!(!offer_recordable(&OfferedCall {
            image: true,
            ..base
        }));
        assert!(!offer_recordable(&OfferedCall {
            anchored: false,
            ..base
        }));
        let savp = OFFER.replace("RTP/AVP", "RTP/SAVP");
        let dtls = OFFER.replace("RTP/AVP", "UDP/TLS/RTP/SAVP");
        for srtp in [&savp, &dtls] {
            let c = OfferedCall {
                offer_sdp: Some(srtp),
                ..base
            };
            assert!(!offer_recordable(&c), "passthrough SRTP");
            assert!(
                offer_recordable(&OfferedCall {
                    may_terminate: true,
                    ..c
                }),
                "the answer decides when the relay may terminate"
            );
        }
        // Opportunistic SRTP on RTP/AVP: the answer decides.
        let osrtp = format!("{OFFER}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:x\r\n");
        assert!(offer_recordable(&OfferedCall {
            offer_sdp: Some(&osrtp),
            ..base
        }));
    }

    // SI-10: hostile codec attributes are not copied into the RS offer.
    #[test]
    fn classify_drops_hostile_codec_attributes() {
        let long = "x".repeat(MAX_RS_CODEC_ATTR_LEN + 1);
        let answer = format!(
            "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
             m=audio 5000 RTP/AVP 0 0 200 8\r\na=rtpmap:0 PCMU/8000\r\na=fmtp:0 {long}\r\n\
             a=rtpmap:8 PCMA/8000\ra=crypto:1 x inline:y\r\na=ptime:abc\r\na=label:evil\r\n\
             a=rtpmap:9 G722/8000\r\n"
        );
        let codecs = classify(&call(OFFER, &answer)).unwrap().caller;
        assert_eq!(codecs.formats, vec!["0", "8"], "deduplicated, PT <= 127");
        let values: Vec<_> = codecs
            .attributes
            .iter()
            .map(|a| a.value.clone().unwrap())
            .collect();
        assert_eq!(values, vec!["0 PCMU/8000"]);
    }

    #[test]
    fn rs_sdp_carries_ports_family_and_formats() {
        let codecs = classify(&call(OFFER, ANSWER)).unwrap();
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let sdp = build_rs_sdp(ip, [30_000, 30_002], &codecs, 77).unwrap();
        let text = sdp.to_string();
        assert!(text.contains("o=- 77 1 IN IP4 192.0.2.9"), "{text}");
        assert!(text.contains("c=IN IP4 192.0.2.9"), "{text}");
        assert!(text.contains("m=audio 30000 RTP/SAVP 0 101"), "{text}");
        assert!(text.contains("m=audio 30002 RTP/SAVP 0 101"), "{text}");
        assert_eq!(text.matches("a=rtpmap:101 telephone-event/8000").count(), 2);
        let v6: IpAddr = "2001:db8::9".parse().unwrap();
        let text = build_rs_sdp(v6, [30_000, 30_002], &codecs, 1)
            .unwrap()
            .to_string();
        assert!(text.contains("c=IN IP6 2001:db8::9"), "{text}");
    }

    // SI-10 / SI-15: participant fields are bounded and cleaned; an
    // oversized or hostile From cannot make the metadata build fail.
    #[test]
    fn participant_identity_is_bounded_and_cleaned() {
        assert_eq!(
            participant_identity("\"Alice A\" <sip:alice@example.com;user=phone?x=y>;tag=1"),
            (
                "sip:alice@example.com".to_string(),
                Some("Alice A".to_string())
            )
        );
        assert_eq!(
            participant_identity("sip:bob@example.com;tag=9"),
            ("sip:bob@example.com".to_string(), None)
        );
        assert_eq!(
            participant_identity("<sips:carol:secret@example.com>").0,
            "sips:carol@example.com",
            "password not recorded"
        );
        assert_eq!(participant_identity("").0, ANONYMOUS_AOR);
        assert_eq!(participant_identity("<>").0, ANONYMOUS_AOR);
        let hostile = format!(
            "\"{}\u{1}\u{0}<x>\" <sip:{}@h>",
            "n".repeat(5000),
            "u".repeat(5000)
        );
        let (aor, name) = participant_identity(&hostile);
        assert!(aor.len() <= MAX_PARTICIPANT_FIELD);
        assert!(
            name.is_none_or(
                |n| n.len() <= MAX_PARTICIPANT_FIELD && !n.chars().any(char::is_control)
            )
        );
        let multibyte = format!("\"{}\" <sip:a@b>", "é".repeat(400));
        let (_, name) = participant_identity(&multibyte);
        assert!(
            name.unwrap().len() <= MAX_PARTICIPANT_FIELD,
            "char boundary"
        );
    }

    fn offer_parts(from: &str, to: &str) -> RsInviteParts {
        let codecs = classify(&call(OFFER, ANSWER)).unwrap();
        let sdp = build_rs_sdp("192.0.2.9".parse().unwrap(), [30_000, 30_002], &codecs, 5).unwrap();
        let (keys, _) = generate_keys().unwrap();
        uc_siprec::build_rs_offer(&sdp, &build_metadata("sess-1", from, to), &keys).unwrap()
    }

    #[test]
    fn metadata_survives_hostile_identities_and_yields_a_uuid() {
        let hostile = format!(
            "\"<script>&\u{7}{}\" <sip:a\"'<>&@example.com>;tag=1",
            "x".repeat(4000)
        );
        let parts = offer_parts(&hostile, "<sip:bob@example.com>");
        let body = String::from_utf8(parts.body.to_vec()).unwrap();
        assert!(!body.contains("<script>"), "escaped by the serializer");
        assert!(body.contains("<label>1</label>") && body.contains("<label>2</label>"));
        let id = session_id_from_body(&parts.body).unwrap();
        assert_eq!(id.len(), 36);
        let groups: Vec<_> = id.split('-').map(str::len).collect();
        assert_eq!(groups, vec![8, 4, 4, 4, 12]);
        assert!(id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // RFC-013 (RFC 7865 §6.10, RFC 9562 §5.4): a version 4 UUID.
        assert_eq!(id.as_bytes().get(14), Some(&b'4'), "version nibble");
        assert!(
            matches!(id.as_bytes().get(19), Some(b'8' | b'9' | b'a' | b'b')),
            "variant bits"
        );
        assert_ne!(
            session_id_from_body(&offer_parts("<sip:a@b>", "<sip:c@d>").body),
            Some(id),
            "fresh per recording session"
        );
    }

    #[test]
    fn session_id_extraction_fails_closed() {
        assert_eq!(session_id_from_body(b""), None);
        assert_eq!(session_id_from_body(b"<session session_id=\""), None);
        assert_eq!(session_id_from_body(b"<session session_id=\"abc\">"), None);
        assert_eq!(
            session_id_from_body(b"<session session_id=\"!!!!!!!!!!!!!!!!!!!!!!==\">"),
            None
        );
        // 16 zero octets.
        assert_eq!(
            session_id_from_body(b"<session session_id=\"AAAAAAAAAAAAAAAAAAAAAA==\">").as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(
            base64_decode_16(b"AAECAwQFBgcICQoLDA0ODw=="),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert_eq!(
            base64_decode_16(b"AAECAwQFBgcICQoLDA0ODw"),
            base64_decode_16(b"AAECAwQFBgcICQoLDA0ODw==")
        );
    }

    fn header<'a>(r: &'a SipRequest, name: &HeaderName) -> &'a str {
        r.headers.get_value(name).unwrap()
    }

    // RFC 7866 §6.1.1, §9.1 (POA&M-300 acceptance): the RS INVITE.
    #[test]
    fn rs_invite_carries_siprec_headers_metadata_and_srtp_offer() {
        let s = settings(RecordingFailureAction::Reject);
        let parts = offer_parts(
            "\"Alice\" <sip:alice@example.com>;tag=1",
            "<sip:bob@sbc.local>",
        );
        let (inv, leg) = build_rs_invite(
            &s,
            "sbc.example.test",
            "192.0.2.9:5061",
            parts,
            RecordingRelay::Opaque,
            offered(),
        )
        .unwrap();
        assert_eq!(inv.method, Method::Invite);
        assert_eq!(inv.uri.to_string(), "sips:srs.example.test:5061");
        assert_eq!(
            header(&inv, &HeaderName::To),
            "<sips:srs.example.test:5061>"
        );
        assert!(header(&inv, &HeaderName::From).starts_with("<sips:sbc.example.test>;tag="));
        assert_eq!(header(&inv, &HeaderName::CSeq), "1 INVITE");
        assert_eq!(header(&inv, &HeaderName::MaxForwards), "70");
        assert_eq!(header(&inv, &HeaderName::Require), "siprec");
        assert_eq!(
            header(&inv, &HeaderName::Contact),
            "<sips:192.0.2.9:5061>;+sip.src"
        );
        let via = header(&inv, &HeaderName::Via);
        assert!(
            via.starts_with("SIP/2.0/TLS 192.0.2.9:5061;branch=z9hG4bK"),
            "{via}"
        );
        assert!(!via.contains("rport"));
        assert_eq!(
            inv.headers.via_branch().as_deref(),
            Some(leg.branch.as_str())
        );
        let ct = header(&inv, &HeaderName::ContentType);
        let boundary = ct.strip_prefix("multipart/mixed;boundary=").unwrap();
        let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
        assert_eq!(
            header(&inv, &HeaderName::ContentLength),
            body.len().to_string()
        );
        assert_eq!(body.matches(&format!("--{boundary}")).count(), 3);
        assert!(body.contains("Content-Type: application/rs-metadata+xml"));
        assert!(body.contains("Content-Disposition: recording-session"));
        assert!(body.contains("aor=\"sip:alice@example.com\""));
        assert!(body.contains("<name>Alice</name>"));
        assert_eq!(body.matches("m=audio ").count(), 2);
        assert_eq!(body.matches("RTP/SAVP").count(), 2);
        assert_eq!(body.matches("a=sendonly").count(), 2);
        assert_eq!(body.matches("a=rtcp-mux").count(), 2);
        assert_eq!(
            body.matches("a=crypto:1 AEAD_AES_256_GCM inline:").count(),
            2
        );
        assert!(body.contains("a=label:1") && body.contains("a=label:2"));
        // Random, SBC-owned identifiers.
        let call_id = inv.headers.call_id().unwrap();
        assert_eq!(call_id, leg.call_id);
        assert!(call_id.ends_with("@sbc.example.test") && call_id.len() > 40);
        assert_eq!(leg.state, RsState::Inviting);
        assert_eq!(leg.next_cseq, 2);
        // The wire form parses.
        let wire = proto_sip::SipMessage::Request(inv).to_bytes();
        assert!(proto_sip::SipMessage::parse(&wire).is_ok());
    }

    fn established_leg() -> (RecordingSettings, RecordingLeg) {
        let s = settings(RecordingFailureAction::Reject);
        let (_, mut leg) = build_rs_invite(
            &s,
            "sbc.example.test",
            "192.0.2.9:5061",
            offer_parts("<sip:a@b>", "<sip:c@d>"),
            RecordingRelay::Opaque,
            offered(),
        )
        .unwrap();
        leg.remote_tag = Some("srstag".to_string());
        leg.state = RsState::Established;
        leg.routes = vec!["<sips:edge.example.test;lr>".to_string()];
        (s, leg)
    }

    // RFC 3261 §13.2.2.4, §15, §9.1: dialog identifiers of ACK, BYE, CANCEL.
    #[test]
    fn rs_ack_bye_and_cancel_are_dialog_correct() {
        let (s, leg) = established_leg();
        let ack = build_rs_ack(&leg, &s.flow);
        assert_eq!(ack.method, Method::Ack);
        assert_eq!(header(&ack, &HeaderName::CSeq), "1 ACK");
        assert_eq!(
            header(&ack, &HeaderName::To),
            "<sips:srs.example.test:5061>;tag=srstag"
        );
        assert_eq!(header(&ack, &HeaderName::From), leg.from);
        assert_eq!(ack.headers.call_id(), Some(leg.call_id.as_str()));
        assert_ne!(
            ack.headers.via_branch().as_deref(),
            Some(leg.branch.as_str()),
            "the 2xx ACK is its own transaction"
        );
        assert_eq!(
            header(&ack, &HeaderName::Route),
            "<sips:edge.example.test;lr>"
        );
        assert!(ack.body.is_none());

        let bye = build_rs_bye(&leg, &s.flow);
        assert_eq!(bye.method, Method::Bye);
        assert_eq!(header(&bye, &HeaderName::CSeq), "2 BYE");
        assert_eq!(
            header(&bye, &HeaderName::To),
            "<sips:srs.example.test:5061>;tag=srstag"
        );
        assert_eq!(bye.headers.call_id(), Some(leg.call_id.as_str()));
        assert!(header(&bye, &HeaderName::Via).starts_with("SIP/2.0/TLS 192.0.2.9:5061"));

        let cancel = build_rs_cancel(&s, &leg);
        assert_eq!(cancel.method, Method::Cancel);
        assert_eq!(cancel.uri, s.srs_uri);
        assert_eq!(header(&cancel, &HeaderName::CSeq), "1 CANCEL");
        assert_eq!(header(&cancel, &HeaderName::To), leg.to, "no To tag");
        assert_eq!(
            cancel.headers.via_branch().as_deref(),
            Some(leg.branch.as_str()),
            "same top Via as the INVITE"
        );
    }

    // RFC-006 (RFC 3261 §12.1.2, RFC 5630 §3.1.3): the Contact is the
    // remote target; a `sip:` one is upgraded, never used as it is.
    #[test]
    fn remote_target_is_the_contact_upgraded_to_sips() {
        let s = settings(RecordingFailureAction::Reject);
        let sips: SipUri = "sips:rec@198.51.100.7:5061".parse().unwrap();
        assert_eq!(remote_target(Some(sips.clone()), &s), sips);
        let sip: SipUri = "sip:rec@198.51.100.7:5070;transport=tcp;lr"
            .parse()
            .unwrap();
        let upgraded = remote_target(Some(sip), &s);
        assert_eq!(upgraded.scheme, UriScheme::Sips, "no downgrade");
        assert_eq!(upgraded.user.as_deref(), Some("rec"));
        assert_eq!(upgraded.host, "198.51.100.7");
        assert_eq!(upgraded.port, Some(5070));
        assert!(upgraded.transport().is_none(), "{upgraded}");
        assert_eq!(remote_target(None, &s), s.srs_uri);
    }

    fn offered() -> [Vec<String>; RS_STREAMS] {
        [vec!["0".to_string()], vec!["0".to_string()]]
    }

    fn check(resp: &SipResponse, is_sdp: bool) -> Result<[SocketAddr; RS_STREAMS], ()> {
        validate_rs_answer(resp, is_sdp, &offered(), |_| false)
    }

    /// 44 zero octets in base64: a syntactically valid key || salt, not a secret.
    const KEY: &str = "inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn answer(body: Option<String>) -> SipResponse {
        let mut r = SipResponse::new(proto_sip::StatusCode::OK);
        r.body = body.map(Bytes::from);
        r
    }

    fn good_answer() -> String {
        format!(
            "v=0\r\no=- 9 9 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n\
             m=audio 40000 RTP/SAVP 0\r\na=recvonly\r\na=crypto:1 AEAD_AES_256_GCM {KEY}\r\n\
             m=audio 40002 RTP/SAVP 0\r\na=recvonly\r\na=crypto:1 AEAD_AES_256_GCM {KEY}\r\n"
        )
    }

    #[test]
    fn rs_answer_yields_the_two_media_addresses_in_order() {
        let got = check(&answer(Some(good_answer())), true).unwrap();
        assert_eq!(got[0], "198.51.100.7:40000".parse().unwrap());
        assert_eq!(got[1], "198.51.100.7:40002".parse().unwrap());
    }

    // SI-10: every defect of the SRS answer is refused, never a panic.
    #[test]
    fn rs_answer_defects_are_refused() {
        let good = good_answer();
        assert!(check(&answer(None), true).is_err(), "no body");
        assert!(check(&answer(Some(String::new())), true).is_err());
        assert!(
            check(&answer(Some(good.clone())), false).is_err(),
            "not application/sdp"
        );
        let oversized = format!("{good}{}", "a=x:y\r\n".repeat(MAX_RS_ANSWER_BYTES / 7 + 1));
        assert!(oversized.len() > MAX_RS_ANSWER_BYTES);
        assert!(check(&answer(Some(oversized)), true).is_err());
        let mut binary = answer(None);
        binary.body = Some(Bytes::from_static(&[0xff, 0xfe, 0x00, 0x80]));
        assert!(check(&binary, true).is_err(), "not UTF-8");
        for (what, bad) in [
            (
                "one stream",
                good.split("m=audio 40002").next().unwrap().to_string(),
            ),
            ("port 0", good.replace("m=audio 40002", "m=audio 0")),
            ("RTP/AVP", good.replace("RTP/SAVP", "RTP/AVP")),
            (
                "AES-128",
                good.replace("AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"),
            ),
            ("sendrecv", good.replace("a=recvonly", "a=sendrecv")),
            ("loopback", good.replace("198.51.100.7", "127.0.0.1")),
            ("unspecified", good.replace("198.51.100.7", "0.0.0.0")),
            ("multicast", good.replace("198.51.100.7", "224.0.0.5")),
            ("garbage", "not sdp at all".to_string()),
        ] {
            assert!(check(&answer(Some(bad)), true).is_err(), "{what}");
        }
    }

    // RFC-002 (RFC 3264 §6.1): the SRS must accept every offered format of
    // each stream; a subset (or an extra format) is a bad answer.
    #[test]
    fn rs_answer_must_accept_every_offered_format() {
        let good = good_answer();
        let two = [
            vec!["0".to_string(), "101".to_string()],
            vec!["96".to_string(), "101".to_string()],
        ];
        let full = good
            .replace("m=audio 40000 RTP/SAVP 0", "m=audio 40000 RTP/SAVP 101 0")
            .replace("m=audio 40002 RTP/SAVP 0", "m=audio 40002 RTP/SAVP 96 101");
        let none = |_| false;
        assert!(validate_rs_answer(&answer(Some(full.clone())), true, &two, none).is_ok());
        assert!(
            validate_rs_answer(&answer(Some(good)), true, &two, none).is_err(),
            "subset"
        );
        let swapped = full.replace("RTP/SAVP 96 101", "RTP/SAVP 0 101");
        assert!(
            validate_rs_answer(&answer(Some(swapped)), true, &two, none).is_err(),
            "the other stream's formats"
        );
        let extra = full.replace("RTP/SAVP 96 101", "RTP/SAVP 96 101 8");
        assert!(
            validate_rs_answer(&answer(Some(extra)), true, &two, none).is_err(),
            "a format that was not offered"
        );
    }

    // SEC-005 (SC-7): the fork is never pointed at one of the SBC's own
    // addresses, in either stream, IPv4-mapped or not.
    #[test]
    fn rs_answer_with_an_sbc_address_is_refused() {
        let own: IpAddr = "198.51.100.7".parse().unwrap();
        let is_own =
            |addr: SocketAddr| addr.ip() == own && (40_000..=40_100).contains(&addr.port());
        let good = good_answer();
        assert!(validate_rs_answer(&answer(Some(good.clone())), true, &offered(), is_own).is_err());
        let second_only = good.replace(
            "m=audio 40002 RTP/SAVP 0\r\n",
            "m=audio 40002 RTP/SAVP 0\r\nc=IN IP4 198.51.100.7\r\n",
        );
        let second_only = second_only.replacen("c=IN IP4 198.51.100.7", "c=IN IP4 198.51.100.8", 1);
        assert!(
            validate_rs_answer(&answer(Some(second_only)), true, &offered(), is_own).is_err(),
            "second stream"
        );
        let mapped = good.replace("IN IP4 198.51.100.7", "IN IP6 ::ffff:198.51.100.7");
        assert!(
            validate_rs_answer(&answer(Some(mapped)), true, &offered(), is_own).is_err(),
            "IPv4-mapped"
        );
        let other = good.replace("198.51.100.7", "198.51.100.8");
        assert!(validate_rs_answer(&answer(Some(other)), true, &offered(), is_own).is_ok());
        // A recorder on the SBC's host, on ports the SBC does not use.
        let colocated = good
            .replace("m=audio 40000", "m=audio 50000")
            .replace("m=audio 40002", "m=audio 50002");
        assert!(validate_rs_answer(&answer(Some(colocated)), true, &offered(), is_own).is_ok());
    }

    #[test]
    fn opt_out_matches_off_and_legacy_never() {
        assert!(opted_out(Some(b"v=0\r\na=recordpref:off\r\n")));
        assert!(opted_out(Some(
            b"v=0\r\nm=audio 1 RTP/AVP 0\r\na=recordpref:never\r\n"
        )));
        assert!(!opted_out(Some(b"v=0\r\na=recordpref:on\r\n")));
        assert!(!opted_out(Some(b"v=0\r\na=recordpref:pause\r\n")));
        assert!(!opted_out(None));
    }

    // SC-12 / SI-12: nothing that holds or describes keys prints them.
    #[test]
    fn debug_output_holds_no_key_material() {
        let (keys, material) = generate_keys().unwrap();
        let b64_prefix = {
            let parts = uc_siprec::build_rs_offer(
                &build_rs_sdp(
                    "192.0.2.9".parse().unwrap(),
                    [30_000, 30_002],
                    &classify(&call(OFFER, ANSWER)).unwrap(),
                    5,
                )
                .unwrap(),
                &build_metadata("s", "<sip:a@b>", "<sip:c@d>"),
                &keys,
            )
            .unwrap();
            let body = String::from_utf8(parts.body.to_vec()).unwrap();
            let at = body.find("inline:").unwrap() + "inline:".len();
            let key = body[at..at + 24].to_string();
            let dbg = format!("{parts:?}");
            assert!(!dbg.contains(&key), "RsInviteParts Debug");
            key
        };
        assert!(!format!("{keys:?}").contains(&b64_prefix));
        let (s, leg) = established_leg();
        let state = CallRecording {
            matched: true,
            leg: Some(leg),
            session_id: Some("id".to_string()),
            ..CallRecording::default()
        };
        let dbg = format!("{state:?} {s:?}");
        assert!(!dbg.contains("inline:") && !dbg.contains(&b64_prefix));
        // The pipeline's key type has no Debug at all; it only moves.
        drop(material);
    }

    #[test]
    fn audit_records_use_internal_identifiers() {
        let (_, mut leg) = established_leg();
        leg.active_since = Some(Instant::now());
        let started = audit_started("sess-1", "uuid-1", &leg, Some(Instant::now()));
        let json = serde_json::to_string(&started).unwrap();
        assert!(json.contains("\"call_id\":\"sess-1\""), "{json}");
        assert!(
            json.contains("\"recording_session_id\":\"uuid-1\""),
            "{json}"
        );
        assert!(json.contains("\"relay\":\"opaque\""), "{json}");
        assert!(
            !json.contains(&leg.call_id),
            "the RS Call-ID is not audited"
        );
        let failed = audit_failed(
            "sess-1",
            None,
            RecordingFailReason::NoSessionSlot,
            RecordingFailAction::EmergencyContinued,
            None,
        );
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"reason\":\"no_session_slot\""), "{json}");
        assert!(
            json.contains("\"action\":\"emergency_continued\""),
            "{json}"
        );
        let stopped = audit_stopped("sess-1", "uuid-1", stop_reason(true), None);
        let json = serde_json::to_string(&stopped).unwrap();
        assert!(json.contains("\"reason\":\"shutdown\""), "{json}");
        assert!(json.contains("\"duration_ms\":0"), "{json}");
        assert!(
            serde_json::to_string(&audit_skipped("sess-1"))
                .unwrap()
                .contains("participant_opt_out")
        );
    }
}
