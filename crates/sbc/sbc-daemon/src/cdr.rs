//! Call Detail Record emission for the SIP stack.
//!
//! The SIP stack keeps one [`CdrDraft`] inside each call's correlation
//! record and fills it as facts become known (admission, routing, each
//! failover, 18x/2xx, teardown cause). `finish_call_record` removes the
//! record exactly once across all racing teardown paths and hands the draft
//! to [`CdrContext::emit_call`], so every stored call produces exactly one
//! CDR. INVITEs refused before a call is stored go through
//! [`CdrContext::emit_rejected`].
//!
//! Emission never blocks: the record is built after the correlation lock is
//! released and pushed onto the `uc-cdr` bounded queue with `try_send`.
//! Formatting, hashing and I/O run on the `uc-cdr-writer` thread.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2 / AU-12**: Call attempts and completions are generated events;
//!   `cdr.record_unanswered` is the organisation-defined event set
//! - **AU-3 / AU-3(1)**: What, when, where, source, outcome and identity
//! - **AU-5 / AU-5(4)**: Drop counting, health, audit events, optional
//!   `reject_new_calls`
//! - **AU-9(2) / SC-8**: Off-host copy over TLS 1.3 (RFC 5425)
//! - **SC-5**: Bounded draft, queue, ring and field lengths

use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sbc_config::schema::{
    CdrConfig, CdrFormatConfig, CdrOnFailure, CdrPiiMode, CdrRecordUnanswered,
};
use tracing::{info, warn};
use uc_cdr::{
    CallRecord, CdrEmitter, CdrEmitterConfig, CdrFormat, CdrHealth, CdrObserver, CdrReload,
    CdrSink, Direction, Disposition, FileSinkConfig, HmacKey, PiiPolicy, ReleaseCause, ReleaseSide,
    SyslogConnector, SyslogSink, SyslogSinkConfig, Transport, TrunkAttempt, TrunkOutcome,
};
use uc_types::address::{SbcSocketAddr, TransportType};

/// How long the runtime waits for queued CDRs at shutdown (plan §5).
pub const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Syslog collector DNS resolution timeout.
const SYSLOG_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Syslog collector TCP connect timeout.
const SYSLOG_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Syslog collector read/write timeout. Bounds how long a stalled collector
/// holds the syslog sink thread; the file writer never waits on it.
const SYSLOG_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest SDP scanned for codec/SRTP facts.
const MAX_SDP_SCAN: usize = 16 * 1024;

/// Epoch milliseconds (UTC) now.
///
/// ## NIST 800-53 Rev5: AU-8 (Time Stamps)
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Maps the A-leg transport to the CDR schema. SCTP has no schema value in
/// v1 and is recorded as `tcp` (both are reliable, connection-oriented).
// POAM: CDR schema v1 has no `sctp` transport value; SCTP A-legs are
// recorded as `tcp`.
pub const fn transport_of(t: TransportType) -> Transport {
    match t {
        TransportType::Udp => Transport::Udp,
        TransportType::Tcp | TransportType::Sctp => Transport::Tcp,
        TransportType::Tls => Transport::Tls,
        TransportType::WebSocket => Transport::Ws,
        TransportType::WebSocketSecure => Transport::Wss,
    }
}

/// The user part of a SIP/SIPS/TEL URI (`sip:alice@host;x` -> `alice`). Falls
/// back to the whole URI when there is no user part. Never panics on
/// malformed input; the result is length-capped by `CallRecord::sanitize`.
pub fn uri_user(uri: &str) -> &str {
    let rest = uri
        .strip_prefix("sips:")
        .or_else(|| uri.strip_prefix("sip:"))
        .or_else(|| uri.strip_prefix("tel:"))
        .unwrap_or(uri);
    let end = rest.find(['@', ';', '?', '>']).unwrap_or(rest.len());
    rest.get(..end).filter(|u| !u.is_empty()).unwrap_or(rest)
}

/// Splits `value` on `sep` outside RFC 3261 §25.1 quoted-strings (with
/// `\` quoted-pairs), so `text="a, Q.850;cause=1"` stays one element.
fn split_unquoted(value: &str, sep: u8) -> impl Iterator<Item = &str> {
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut i = 0;
    let mut in_quotes = false;
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        while let Some(&b) = bytes.get(i) {
            if in_quotes {
                match b {
                    b'\\' => i += 1,
                    b'"' => in_quotes = false,
                    _ => {}
                }
            } else if b == b'"' {
                in_quotes = true;
            } else if b == sep {
                let part = value.get(start..i);
                i += 1;
                start = i;
                return part;
            }
            i += 1;
        }
        done = true;
        value.get(start..)
    })
}

/// Q.850 cause from a Reason header value (`Q.850;cause=16;text="..."`).
///
/// RFC 3326 §2: the protocol token is case-insensitive; the cause is a
/// decimal integer (Q.850 assigns 1..=127). Commas and semicolons inside
/// quoted reason-text are not separators. Malformed values yield `None`.
pub fn q850_from_reason(value: &str) -> Option<u8> {
    for reason in split_unquoted(value, b',') {
        let mut parts = split_unquoted(reason, b';');
        let Some(proto) = parts.next() else { continue };
        if !proto.trim().eq_ignore_ascii_case("Q.850") {
            continue;
        }
        for p in parts {
            if let Some((k, v)) = p.split_once('=')
                && k.trim().eq_ignore_ascii_case("cause")
            {
                return v
                    .trim()
                    .parse::<u8>()
                    .ok()
                    .filter(|c| (1..=127).contains(c));
            }
        }
    }
    None
}

// POAM: RFC-5 a=rtpmap/a=crypto are not scoped to the chosen m-section and
// encoding names keep the received case; RFC-7 the static payload table
// covers PT 0/8/9/18 only (RFC 3551 Table 4 has more).
/// Codec and SRTP suite from an answer SDP: the first payload of the first
/// accepted `m=audio` line (RFC 3264 §6: port 0 means the stream was
/// rejected), named through `a=rtpmap` or the static RFC 3551 table.
/// Bounded scan; malformed SDP yields `None`.
pub fn media_facts(sdp: &[u8]) -> (Option<String>, Option<String>) {
    let sdp = sdp.get(..sdp.len().min(MAX_SDP_SCAN)).unwrap_or_default();
    let text = String::from_utf8_lossy(sdp);
    let mut pt: Option<&str> = None;
    let mut dtls = false;
    let mut codec = None;
    let mut srtp = None;
    for line in text.lines() {
        let line = line.trim_end();
        if pt.is_none()
            && let Some(m) = line.strip_prefix("m=audio ")
        {
            let mut f = m.split_ascii_whitespace();
            let port = f.next().unwrap_or("0");
            // `port` may carry a `/count` suffix (RFC 8866 §5.14).
            if port.split('/').next() == Some("0") {
                continue;
            }
            let proto = f.next().unwrap_or("");
            dtls = proto.contains("TLS");
            pt = f.next();
        } else if let Some(map) = line.strip_prefix("a=rtpmap:")
            && let Some((num, enc)) = map.split_once(' ')
            && Some(num) == pt
            && codec.is_none()
        {
            codec = enc.split('/').next().map(str::to_string);
        } else if let Some(c) = line.strip_prefix("a=crypto:")
            && srtp.is_none()
        {
            srtp = c.split_ascii_whitespace().nth(1).map(str::to_string);
        }
    }
    if codec.is_none() {
        codec = pt.and_then(|p| match p {
            "0" => Some("PCMU".to_string()),
            "8" => Some("PCMA".to_string()),
            "9" => Some("G722".to_string()),
            "18" => Some("G729".to_string()),
            _ => None,
        });
    }
    if srtp.is_none() && dtls {
        srtp = Some("DTLS-SRTP".to_string());
    }
    (codec, srtp)
}

/// CDR facts accumulated over a stored call's life. Lives inside the call's
/// correlation record and is updated under the existing `call_correlation`
/// write lock; it is bounded (`trunks_tried`/`b_call_ids` are capped at
/// `uc_cdr::record::MAX_ATTEMPTS`, strings at emit).
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), SC-5
#[derive(Debug, Clone, Default)]
pub struct CdrDraft {
    /// Epoch ms the INVITE was received.
    pub setup_ms: u64,
    /// First 18x.
    pub ring_ms: Option<u64>,
    /// 2xx from the B-leg.
    pub answer_ms: Option<u64>,
    /// A-leg Call-ID.
    pub a_call_id: String,
    /// One per B-leg attempt.
    pub b_call_ids: Vec<String>,
    /// Internal call id.
    pub internal_call_id: String,
    /// Direction.
    pub direction: Direction,
    /// From user as received.
    pub caller: String,
    /// R-URI user as received.
    pub callee_dialed: String,
    /// Callee after translation (when it differs).
    pub callee_translated: Option<String>,
    /// Caller as sent on the B-leg (when it differs).
    pub caller_translated: Option<String>,
    /// A-leg source.
    pub source_ip: String,
    /// A-leg source port.
    pub source_port: u16,
    /// A-leg transport.
    pub transport: Transport,
    /// Receiving zone.
    pub ingress_zone: Option<String>,
    /// Egress zone.
    pub egress_zone: Option<String>,
    /// Trunk group of the route.
    pub trunk_group: Option<String>,
    /// Current trunk (the attempt in flight).
    pub current_trunk: Option<String>,
    /// Finished attempts (failed over).
    pub trunks_tried: Vec<TrunkAttempt>,
    /// Failovers performed.
    pub failover_count: u32,
    /// Media anchored on the SBC relay.
    pub media_anchored: bool,
    /// Media node advertised by the pipeline (standalone media pool).
    pub media_node: Option<String>,
    /// Negotiated codec.
    pub codec: Option<String>,
    /// SRTP suite.
    pub srtp: Option<String>,
    /// Emergency call.
    pub emergency: bool,
    /// Attestation the B-leg INVITE was signed with.
    pub stir_attestation: Option<uc_cdr::Attestation>,
    /// Inbound verification outcome.
    pub stir_verstat: Option<uc_cdr::Verstat>,
    /// Inbound verification failure reason token.
    pub stir_verify_reason: Option<String>,
    /// Attestation of the verified inbound PASSporT.
    pub stir_inbound_attestation: Option<uc_cdr::Attestation>,
    /// Host of the inbound `x5u`.
    pub stir_x5u_host: Option<String>,
    /// Media kinds used, set-like and bounded (schema v3, POA&M-294).
    pub media_kinds: Vec<uc_cdr::MediaKindTag>,
}

impl CdrDraft {
    /// Records the end of the current trunk attempt and the start of the
    /// next (failover). Bounded by `MAX_ATTEMPTS`.
    pub fn record_failover(&mut self, outcome: TrunkOutcome, next_trunk: &str, b_call_id: &str) {
        if let Some(t) = self.current_trunk.take()
            && self.trunks_tried.len() < uc_cdr::record::MAX_ATTEMPTS
        {
            self.trunks_tried.push(TrunkAttempt {
                trunk_id: t,
                status: outcome,
                at_ms: now_ms(),
            });
        }
        self.current_trunk = Some(next_trunk.to_string());
        if self.b_call_ids.len() < uc_cdr::record::MAX_ATTEMPTS {
            self.b_call_ids.push(b_call_id.to_string());
        }
        self.failover_count = self.failover_count.saturating_add(1);
    }

    /// Notes a media kind the call used (answer or accepted switchover).
    /// Set-like, ordered by first use, at most `uc_cdr::MAX_MEDIA_KINDS`.
    pub fn note_media_kind(&mut self, kind: uc_cdr::MediaKindTag) {
        uc_cdr::note_media_kind(&mut self.media_kinds, kind);
    }

    /// Records the first 18x.
    pub fn record_ringing(&mut self) {
        if self.ring_ms.is_none() {
            self.ring_ms = Some(now_ms());
        }
    }

    /// Records the 2xx and the negotiated media from the answer SDP.
    pub fn record_answer(&mut self, answer_sdp: Option<&[u8]>) {
        if self.answer_ms.is_none() {
            self.answer_ms = Some(now_ms());
        }
        if let Some(sdp) = answer_sdp {
            let (codec, srtp) = media_facts(sdp);
            self.codec = codec;
            self.srtp = srtp;
        }
    }

    /// Builds the record. The last attempt's outcome comes from `end`.
    fn into_record(self, end: &CdrEnd) -> CallRecord {
        let answered = self.answer_ms.is_some();
        let mut trunks_tried = self.trunks_tried;
        if let Some(t) = &self.current_trunk
            && trunks_tried.len() < uc_cdr::record::MAX_ATTEMPTS
        {
            let status = if answered {
                TrunkOutcome::Status(200)
            } else {
                end.attempt.unwrap_or(TrunkOutcome::Status(end.status))
            };
            trunks_tried.push(TrunkAttempt {
                trunk_id: t.clone(),
                status,
                at_ms: now_ms(),
            });
        }
        let mut r = CallRecord {
            a_call_id: self.a_call_id,
            b_call_ids: self.b_call_ids,
            internal_call_id: self.internal_call_id,
            direction: self.direction,
            caller: self.caller,
            callee_dialed: self.callee_dialed,
            callee_translated: self.callee_translated,
            caller_translated: self.caller_translated,
            source_ip: self.source_ip,
            source_port: self.source_port,
            transport: self.transport,
            ingress_zone: self.ingress_zone,
            egress_zone: self.egress_zone,
            trunk_group: self.trunk_group,
            trunks_tried,
            final_trunk: self.current_trunk,
            failover_count: self.failover_count,
            setup_ms: self.setup_ms,
            ring_ms: self.ring_ms,
            answer_ms: self.answer_ms,
            end_ms: now_ms(),
            disposition: end.disposition,
            final_sip_status: if answered { 200 } else { end.status },
            release_side: end.side,
            release_cause: end.cause,
            q850_cause: end.q850,
            media_node: self.media_node,
            media_anchored: self.media_anchored,
            codec: self.codec,
            srtp: self.srtp,
            emergency: self.emergency,
            stir_attestation: self.stir_attestation,
            stir_verstat: self.stir_verstat,
            stir_verify_reason: self.stir_verify_reason,
            stir_inbound_attestation: self.stir_inbound_attestation,
            stir_x5u_host: self.stir_x5u_host,
            media_kinds: self.media_kinds,
            ..CallRecord::default()
        };
        r.compute_durations();
        r
    }
}

/// How a stored call ended. Built by the teardown path that removed the
/// call record; only the first (winning) path's `CdrEnd` is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdrEnd {
    /// Outcome. Overridden to `answered` for normal clearing of an answered call.
    pub disposition: Disposition,
    /// Cause.
    pub cause: ReleaseCause,
    /// Releasing side.
    pub side: ReleaseSide,
    /// Final status sent to the A-leg when unanswered.
    pub status: u16,
    /// Outcome of the last trunk attempt when not a plain status.
    pub attempt: Option<TrunkOutcome>,
    /// RFC 3326 Q.850 cause, if a Reason header carried one.
    pub q850: Option<u8>,
    /// The final status is a 401/407 challenge (skipped unless
    /// `cdr.record_auth_challenges`).
    pub auth_challenge: bool,
}

impl CdrEnd {
    const fn new(
        disposition: Disposition,
        cause: ReleaseCause,
        side: ReleaseSide,
        status: u16,
    ) -> Self {
        Self {
            disposition,
            cause,
            side,
            status,
            attempt: None,
            q850: None,
            auth_challenge: false,
        }
    }

    /// BYE from either leg. An early-dialog BYE from the caller is a cancel.
    ///
    /// RFC 3261 §15: the side that sent the BYE released the call.
    pub const fn bye(from_caller: bool, answered: bool) -> Self {
        let side = if from_caller {
            ReleaseSide::Caller
        } else {
            ReleaseSide::Callee
        };
        if answered {
            Self::new(Disposition::Answered, ReleaseCause::Normal, side, 200)
        } else {
            Self::new(Disposition::Cancelled, ReleaseCause::Cancel, side, 487)
        }
    }

    /// CANCEL before answer (RFC 3261 §9: the INVITE gets a 487).
    pub const fn cancel() -> Self {
        Self::new(
            Disposition::Cancelled,
            ReleaseCause::Cancel,
            ReleaseSide::Caller,
            487,
        )
    }

    /// Final error response from the trunk/callee, relayed to the caller.
    pub const fn trunk_final(status: u16) -> Self {
        let disposition = match status {
            486 | 600 => Disposition::Busy,
            408 | 480 => Disposition::NoAnswer,
            _ => Disposition::Failed,
        };
        let mut e = Self::new(
            disposition,
            ReleaseCause::TrunkError,
            ReleaseSide::Callee,
            status,
        );
        e.auth_challenge = matches!(status, 401 | 407);
        e
    }

    /// Timer B fired on the last trunk (RFC 3261 §17.1.1.2: 408 to the caller).
    pub const fn timer_b() -> Self {
        let mut e = Self::new(
            Disposition::NoAnswer,
            ReleaseCause::TimerB,
            ReleaseSide::Sbc,
            408,
        );
        e.attempt = Some(TrunkOutcome::Timeout);
        e
    }

    /// The INVITE could not be sent to the last trunk (RFC 3261 §8.1.3.1: 503).
    pub const fn transport_error() -> Self {
        let mut e = Self::new(
            Disposition::Failed,
            ReleaseCause::TransportError,
            ReleaseSide::Sbc,
            503,
        );
        e.attempt = Some(TrunkOutcome::TransportError);
        e
    }

    /// The media path failed after answer.
    pub const fn media_failure() -> Self {
        Self::new(
            Disposition::MediaFailure,
            ReleaseCause::MediaFailure,
            ReleaseSide::Sbc,
            500,
        )
    }

    /// The SBC released the dialog because a leg went away (2xx never ACKed,
    /// relayed re-INVITE timed out or got 481).
    pub const fn dialog_lost(answered: bool, status: u16) -> Self {
        Self::new(
            if answered {
                Disposition::Answered
            } else {
                Disposition::Failed
            },
            ReleaseCause::TransportError,
            ReleaseSide::Sbc,
            status,
        )
    }

    /// Calls still up when the daemon shuts down.
    pub const fn shutdown(answered: bool) -> Self {
        Self::new(
            if answered {
                Disposition::Answered
            } else {
                Disposition::Failed
            },
            ReleaseCause::Shutdown,
            ReleaseSide::Sbc,
            503,
        )
    }

    /// Adds the Q.850 cause from a Reason header (RFC 3326).
    #[must_use]
    pub fn with_reason(self, reason: Option<&str>) -> Self {
        self.with_reasons(reason)
    }

    /// Adds the Q.850 cause from every Reason header field (RFC 3326 §2: a
    /// message may carry one per protocol, e.g. `SIP` then `Q.850`). The
    /// first Q.850 cause found wins.
    #[must_use]
    pub fn with_reasons<'a>(mut self, values: impl IntoIterator<Item = &'a str>) -> Self {
        self.q850 = values.into_iter().find_map(q850_from_reason);
        self
    }
}

/// An INVITE refused before a call was stored.
#[derive(Debug, Clone, Copy)]
pub struct Rejection<'a> {
    /// A-leg Call-ID.
    pub a_call_id: &'a str,
    /// From URI (or header) as received.
    pub from: &'a str,
    /// R-URI user as received.
    pub callee: &'a str,
    /// Source.
    pub source: SbcSocketAddr,
    /// Transport.
    pub transport: TransportType,
    /// Receiving zone.
    pub zone: Option<&'a str>,
    /// Emergency number.
    pub emergency: bool,
    /// Status sent.
    pub status: u16,
    /// Cause.
    pub cause: ReleaseCause,
}

/// Call-IDs remembered for reject-CDR de-duplication (SC-5 bound).
const RECENT_REJECTS_CAPACITY: usize = 8192;
/// How long a rejected Call-ID is remembered: 64*T1, the longest an
/// RFC 3261 §17.1.1 client keeps retransmitting an INVITE.
const RECENT_REJECTS_TTL: Duration = Duration::from_secs(32);

/// Recently rejected INVITE Call-IDs, so a retransmitted INVITE that is
/// rejected again does not write a second CDR. Bounded FIFO with a TTL;
/// `HashSet` uses the randomly keyed `RandomState` (attacker-chosen keys).
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[derive(Default)]
struct RecentRejects {
    set: std::collections::HashSet<String>,
    order: std::collections::VecDeque<(String, std::time::Instant)>,
}

impl RecentRejects {
    /// Records `call_id`; `false` when it was rejected recently.
    fn first_seen(&mut self, call_id: &str, now: std::time::Instant) -> bool {
        while let Some((id, at)) = self.order.front() {
            if now.duration_since(*at) < RECENT_REJECTS_TTL
                && self.order.len() < RECENT_REJECTS_CAPACITY
            {
                break;
            }
            self.set.remove(id);
            self.order.pop_front();
        }
        let key: String = call_id
            .chars()
            .take(uc_cdr::record::MAX_FIELD_LEN)
            .collect();
        if self.set.contains(&key) {
            return false;
        }
        self.set.insert(key.clone());
        self.order.push_back((key, now));
        true
    }
}

/// Daemon-side CDR state: the emitter plus the emission policy.
pub struct CdrContext {
    emitter: Arc<CdrEmitter>,
    record_unanswered: AtomicU8,
    record_auth_challenges: bool,
    on_failure: CdrOnFailure,
    recent_rejects: std::sync::Mutex<RecentRejects>,
}

impl std::fmt::Debug for CdrContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdrContext")
            .field("emitter", &self.emitter)
            .field("on_failure", &self.on_failure)
            .finish_non_exhaustive()
    }
}

const fn unanswered_code(p: CdrRecordUnanswered) -> u8 {
    match p {
        CdrRecordUnanswered::All => 0,
        CdrRecordUnanswered::Routed => 1,
        CdrRecordUnanswered::None => 2,
    }
}

impl CdrContext {
    /// Wraps a started emitter.
    pub fn new(emitter: Arc<CdrEmitter>, config: &CdrConfig) -> Self {
        Self {
            emitter,
            record_unanswered: AtomicU8::new(unanswered_code(config.record_unanswered)),
            record_auth_challenges: config.record_auth_challenges,
            on_failure: config.on_failure,
            recent_rejects: std::sync::Mutex::new(RecentRejects::default()),
        }
    }

    /// The emitter (ring, stats, health, flush).
    pub fn emitter(&self) -> &Arc<CdrEmitter> {
        &self.emitter
    }

    /// Hot-reloads the event-set policy (plan §3.4).
    pub fn set_record_unanswered(&self, p: CdrRecordUnanswered) {
        self.record_unanswered
            .store(unanswered_code(p), Ordering::Relaxed);
    }

    /// `cdr.on_failure = "reject_new_calls"` and the pipeline is unhealthy:
    /// new non-emergency INVITEs are refused (the caller checks emergency).
    ///
    /// ## NIST 800-53 Rev5: AU-5(4) (Shutdown on Failure, organisation-defined)
    pub fn rejecting_new_calls(&self) -> bool {
        self.on_failure == CdrOnFailure::RejectNewCalls
            && self.emitter.health() == CdrHealth::Unhealthy
    }

    /// Emits the CDR for a stored call that just ended.
    ///
    /// ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
    pub fn emit_call(&self, draft: CdrDraft, end: &CdrEnd) {
        let answered = draft.answer_ms.is_some();
        if end.auth_challenge && !answered && !self.record_auth_challenges {
            return;
        }
        // Stored calls were routed, so only `none` filters them.
        if !answered && self.record_unanswered.load(Ordering::Relaxed) == 2 {
            return;
        }
        let mut end = *end;
        if answered && end.disposition != Disposition::MediaFailure {
            end.disposition = Disposition::Answered;
        }
        self.emitter.emit(draft.into_record(&end));
    }

    /// Emits the CDR for an INVITE refused before a call was stored
    /// (policy, draining, no route). Honours `cdr.record_unanswered`: only
    /// `all` records these. A Call-ID rejected in the last 32 s is not
    /// recorded again (INVITE retransmissions).
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-12
    pub fn emit_rejected(&self, r: &Rejection<'_>) {
        if self.record_unanswered.load(Ordering::Relaxed) != 0 {
            return;
        }
        // One CDR per rejected INVITE, not per retransmission. The lock is
        // held for one bounded set operation, never across an await.
        if !self
            .recent_rejects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first_seen(r.a_call_id, std::time::Instant::now())
        {
            return;
        }
        let now = now_ms();
        let mut rec = CallRecord {
            a_call_id: r.a_call_id.to_string(),
            caller: uri_user(r.from).to_string(),
            callee_dialed: r.callee.to_string(),
            source_ip: r.source.ip().to_string(),
            source_port: r.source.port(),
            transport: transport_of(r.transport),
            ingress_zone: r.zone.map(str::to_string),
            setup_ms: now,
            end_ms: now,
            disposition: Disposition::Rejected,
            final_sip_status: r.status,
            release_side: ReleaseSide::Sbc,
            release_cause: r.cause,
            emergency: r.emergency,
            ..CallRecord::default()
        };
        rec.compute_durations();
        self.emitter.emit(rec);
    }
}

/// Bridges `uc-cdr` writer notifications to `uc-audit` (AU-5, AU-9).
#[derive(Debug, Default)]
pub struct AuditObserver;

impl CdrObserver for AuditObserver {
    fn on_rotated(&self, file: &Path, sha384_hex: &str) {
        uc_audit::log_event(uc_audit::AuditEvent::CdrFileRotated(
            uc_audit::event::CdrFileRotated {
                file: file.display().to_string(),
                sha384: sha384_hex.to_string(),
            },
        ));
    }

    fn on_write_error(&self, error: &io::Error) {
        uc_audit::log_event(uc_audit::AuditEvent::CdrSinkFailure(
            uc_audit::event::CdrSinkFailure {
                reason: "write_error".to_string(),
                detail: error.to_string(),
            },
        ));
    }

    fn on_drop(&self, dropped_total: u64, writer_dead: bool) {
        // Runs on the emitting task: uc-audit's log_event is a non-blocking
        // queue push.
        uc_audit::log_event(uc_audit::AuditEvent::CdrSinkFailure(
            uc_audit::event::CdrSinkFailure {
                reason: if writer_dead {
                    "writer_dead"
                } else {
                    "queue_full"
                }
                .to_string(),
                detail: format!("{dropped_total} CDRs dropped"),
            },
        ));
    }
}

// POAM: NIST-06 (IA-3) no client certificate is presented, so the collector
// cannot authenticate the SBC; add optional client identity (security.tls
// cert/key) for mutually authenticated RFC 5425.
/// RFC 5425 TLS connector for the CDR syslog sink: TLS 1.3 only, CNSA 2.0
/// suite and groups (`TLS_AES_256_GCM_SHA384`, ML-KEM-1024 or P-384, via
/// `uc_transport::tls::create_client_config` / `cnsa_provider`), with
/// connect and I/O timeouts. The SBC presents no client certificate (see
/// the POA&M note above).
///
/// ## NIST 800-53 Rev5: SC-8, SC-13, AU-9(2)
pub struct TlsSyslogConnector {
    host: String,
    port: u16,
    config: Arc<rustls::ClientConfig>,
    resolver: CollectorResolver,
}

impl std::fmt::Debug for TlsSyslogConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSyslogConnector")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Splits a validated `tls://host:port` target.
fn parse_tls_target(target: &str) -> Option<(String, u16)> {
    let rest = target.strip_prefix("tls://")?;
    let (host, port) = rest.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then(|| (host.to_string(), port))
}

impl TlsSyslogConnector {
    /// Builds the connector from `cdr.syslog` (CA from `cdr.syslog.ca_path`,
    /// else `security.tls_ca_path`).
    pub fn new(target: &str, ca_path: &Path) -> Result<Self, String> {
        let (host, port) = parse_tls_target(target)
            .ok_or_else(|| format!("invalid cdr.syslog.target {target:?}"))?;
        let roots = uc_transport::tls::load_root_store(ca_path)
            .map_err(|e| format!("cdr.syslog CA {}: {e}", ca_path.display()))?;
        let config = uc_transport::tls::create_client_config(roots)
            .map_err(|e| format!("cdr.syslog TLS config: {e}"))?;
        Ok(Self {
            host,
            port,
            config: Arc::new(config),
            resolver: CollectorResolver::system(),
        })
    }
}

/// Blocking name lookup used by [`CollectorResolver`] (a seam for tests).
type LookupFn = dyn Fn(&str, u16) -> io::Result<Option<SocketAddr>> + Send + Sync;

/// Pending lookup result channel.
type LookupRx = std::sync::mpsc::Receiver<io::Result<Option<SocketAddr>>>;

/// Resolves the collector name on a helper thread with a timeout
/// (`getaddrinfo` has no timeout of its own).
///
/// At most one lookup thread is in flight: when a lookup times out its
/// receiver is kept and the next call waits on the same thread instead of
/// spawning another, so a resolver that never answers costs one thread,
/// not one per reconnect. The last good address is cached and used while
/// the resolver is failing or hung. A literal IP never spawns.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), AU-9(2)
struct CollectorResolver {
    lookup: Arc<LookupFn>,
    pending: Option<LookupRx>,
    cached: Option<SocketAddr>,
}

impl CollectorResolver {
    fn system() -> Self {
        Self::with_lookup(Arc::new(|host: &str, port: u16| {
            (host, port).to_socket_addrs().map(|mut a| a.next())
        }))
    }

    fn with_lookup(lookup: Arc<LookupFn>) -> Self {
        Self {
            lookup,
            pending: None,
            cached: None,
        }
    }

    fn resolve(&mut self, host: &str, port: u16, timeout: Duration) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let rx = if let Some(rx) = self.pending.take() {
            rx
        } else {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let name = host.to_string();
            let lookup = Arc::clone(&self.lookup);
            std::thread::Builder::new()
                .name("uc-cdr-syslog-dns".to_string())
                .spawn(move || {
                    let _ = tx.send(lookup(&name, port));
                })?;
            rx
        };
        let fresh = match rx.recv_timeout(timeout) {
            Ok(Ok(Some(addr))) => Ok(addr),
            Ok(Ok(None)) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "collector did not resolve",
            )),
            Ok(Err(e)) => Err(e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Keep waiting on this thread next time; never spawn a second.
                self.pending = Some(rx);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "collector DNS resolution timed out",
                ))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "collector DNS lookup thread exited without a result",
            )),
        };
        match fresh {
            Ok(addr) => {
                self.cached = Some(addr);
                Ok(addr)
            }
            Err(e) => self.cached.ok_or(e),
        }
    }
}

impl SyslogConnector for TlsSyslogConnector {
    fn connect(&mut self) -> io::Result<Box<dyn Write + Send>> {
        let addr = self
            .resolver
            .resolve(&self.host, self.port, SYSLOG_RESOLVE_TIMEOUT)?;
        let tcp = TcpStream::connect_timeout(&addr, SYSLOG_CONNECT_TIMEOUT)?;
        tcp.set_read_timeout(Some(SYSLOG_IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(SYSLOG_IO_TIMEOUT))?;
        tcp.set_nodelay(true)?;
        let name = rustls_pki_types::ServerName::try_from(self.host.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let conn = rustls::ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(io::Error::other)?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        // Complete the handshake now so a bad certificate fails the connect,
        // not the first record (bounded by the socket timeouts).
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(Box::new(stream))
    }
}

/// Node id for CDRs: `cdr.node_id`, else the instance name if it is a valid
/// node id, else the hostname, else `"sbc"`.
fn resolve_node_id(config: &CdrConfig, instance_name: &str) -> String {
    if let Some(id) = config.node_id.as_ref().filter(|s| !s.is_empty()) {
        return id.clone();
    }
    if uc_cdr::sink::valid_node_id(instance_name) {
        return instance_name.to_string();
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| uc_cdr::sink::valid_node_id(h))
        .unwrap_or_else(|| "sbc".to_string())
}

/// PII policy from config (loads the HMAC key for `hash`).
///
/// ## NIST 800-53 Rev5: SI-12, SC-12
fn pii_policy(config: &CdrConfig) -> Result<PiiPolicy, String> {
    Ok(match config.pii {
        CdrPiiMode::Full => PiiPolicy::Full,
        CdrPiiMode::MaskCaller => PiiPolicy::MaskCaller,
        CdrPiiMode::Hash => {
            let path = config
                .pii_hash_key_file
                .as_deref()
                .ok_or("cdr.pii = \"hash\" requires cdr.pii_hash_key_file")?;
            PiiPolicy::Hash(
                HmacKey::load(path)
                    .map_err(|e| format!("cdr.pii_hash_key_file {}: {e}", path.display()))?,
            )
        }
    })
}

/// Starts the CDR pipeline from `[cdr]`. `Ok(None)` when `cdr.enabled` is
/// false. Fails (and the daemon refuses to start) when the directory is
/// not writable: CDR generation is an AU-12 requirement, so the error names
/// the directory and the keys that control it.
///
/// ## NIST 800-53 Rev5: AU-5 (fail closed at startup), AU-12
pub fn start_from_config(
    config: &CdrConfig,
    instance_name: &str,
    security_ca_path: Option<&Path>,
) -> Result<Option<Arc<CdrContext>>, String> {
    if !config.enabled {
        info!("CDRs disabled by configuration (cdr.enabled = false)");
        return Ok(None);
    }
    let node_id = resolve_node_id(config, instance_name);
    let rotate_interval = config
        .rotate_interval_secs()
        .ok_or_else(|| format!("invalid cdr.rotate_interval {:?}", config.rotate_interval))?;
    let file = FileSinkConfig {
        directory: config.directory.clone(),
        format: match config.format {
            CdrFormatConfig::Jsonl => CdrFormat::Jsonl,
            CdrFormatConfig::Csv => CdrFormat::Csv,
        },
        rotate_size_bytes: u64::from(config.rotate_size_mb) * 1024 * 1024,
        rotate_interval: (rotate_interval > 0).then(|| Duration::from_secs(rotate_interval)),
        retention_files: config.retention_files,
        retention_days: config.retention_days,
        fsync_interval: Duration::from_millis(u64::from(config.fsync_interval_ms)),
    };
    let mut sinks: Vec<Box<dyn CdrSink>> = Vec::new();
    if config.syslog.enabled {
        let ca = config
            .syslog
            .ca_path
            .as_deref()
            .or(security_ca_path)
            .ok_or("cdr.syslog.enabled needs cdr.syslog.ca_path or security.tls_ca_path")?;
        let connector = TlsSyslogConnector::new(&config.syslog.target, ca)?;
        sinks.push(Box::new(SyslogSink::new(
            &SyslogSinkConfig {
                hostname: node_id.clone(),
                app_name: "usg-sbc".to_string(),
                facility: config.syslog.facility,
            },
            Box::new(connector),
        )));
    }
    let emitter_cfg = CdrEmitterConfig {
        node_id: node_id.clone(),
        queue_capacity: config.queue_capacity,
        ring_capacity: config.ring_capacity,
        hash_chain: config.hash_chain,
        pii: pii_policy(config)?,
        file: Some(file),
    };
    let emitter =
        CdrEmitter::start(emitter_cfg, sinks, Some(Arc::new(AuditObserver))).map_err(|e| {
            format!(
                "cannot start CDR writer in {}: {e}. Create the directory writable by the \
                 daemon user, point cdr.directory at a writable path, or set \
                 cdr.enabled = false",
                config.directory.display()
            )
        })?;
    info!(
        node_id = %node_id,
        directory = %config.directory.display(),
        "CDR pipeline started"
    );
    Ok(Some(Arc::new(CdrContext::new(emitter, config))))
}

/// Applies the hot-reloadable `[cdr]` keys; warns about keys that need a
/// restart.
pub fn reload(ctx: &CdrContext, old: &CdrConfig, new: &CdrConfig) {
    ctx.set_record_unanswered(new.record_unanswered);
    let mut r = CdrReload::default();
    if old.retention_files != new.retention_files || old.retention_days != new.retention_days {
        r.retention = Some((new.retention_files, new.retention_days));
    }
    if old.pii != new.pii || old.pii_hash_key_file != new.pii_hash_key_file {
        match pii_policy(new) {
            Ok(p) => r.pii = Some(p),
            Err(e) => warn!(error = %e, "CDR PII policy not reloaded"),
        }
    }
    if (r.pii.is_some() || r.retention.is_some()) && !ctx.emitter.reload(r) {
        warn!("CDR reload not applied (writer queue full or writer stopped)");
    }
    let restart_only = old.enabled != new.enabled
        || old.directory != new.directory
        || old.format != new.format
        || old.syslog != new.syslog
        || old.queue_capacity != new.queue_capacity
        || old.ring_capacity != new.ring_capacity
        || old.hash_chain != new.hash_chain
        || old.on_failure != new.on_failure
        || old.record_auth_challenges != new.record_auth_challenges;
    if restart_only {
        warn!(
            "[cdr] sink/policy changes other than record_unanswered, pii and retention need a restart"
        );
    }
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "config-reload".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Reloaded,
            description: "[cdr] settings reloaded".to_string(),
        },
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// POA&M-294: an audio call that switched to T.38 and back records both
    /// kinds once, in first-use order (schema v3 `media_kinds`).
    #[test]
    fn draft_media_kinds_audio_image_audio() {
        use crate::t38::CallMediaKind;
        let mut d = CdrDraft::default();
        for k in [
            CallMediaKind::Audio,
            CallMediaKind::Image,
            CallMediaKind::Audio,
        ] {
            d.note_media_kind(k.cdr());
        }
        let r = d.into_record(&CdrEnd::bye(true, true));
        assert_eq!(
            r.media_kinds,
            vec![uc_cdr::MediaKindTag::Audio, uc_cdr::MediaKindTag::Image]
        );
    }

    #[test]
    fn uri_user_handles_forms() {
        assert_eq!(uri_user("sip:alice@example.com"), "alice");
        assert_eq!(uri_user("sips:+1555@h;user=phone"), "+1555");
        assert_eq!(uri_user("tel:+1555;phone-context=x"), "+1555");
        assert_eq!(uri_user("sip:host.only"), "host.only");
        assert_eq!(uri_user(""), "");
    }

    #[test]
    fn q850_parses_rfc3326_reason() {
        assert_eq!(q850_from_reason("Q.850;cause=16;text=\"x\""), Some(16));
        assert_eq!(
            q850_from_reason("SIP;cause=200, q.850 ; cause = 17"),
            Some(17)
        );
        assert_eq!(q850_from_reason("Q.850;cause=999"), None);
        assert_eq!(q850_from_reason("Q.850;cause=abc"), None);
        assert_eq!(q850_from_reason("garbage"), None);
        assert_eq!(q850_from_reason("Q.850;cause=0"), None, "0 is unassigned");
        // RFC-2: separators inside quoted reason-text are not split on.
        assert_eq!(
            q850_from_reason("SIP;cause=480;text=\"x, Q.850;cause=1\""),
            None
        );
        assert_eq!(
            q850_from_reason("SIP;cause=480;text=\"busy, \\\"later\\\"\", Q.850;cause=17"),
            Some(17)
        );
        assert_eq!(
            q850_from_reason("Q.850;text=\"a;cause=9\";cause=16"),
            Some(16)
        );
    }

    #[test]
    fn q850_from_separate_reason_headers() {
        // RFC-1: the Q.850 value is in the second Reason header field.
        let end = CdrEnd::cancel().with_reasons(["SIP;cause=200;text=\"x\"", "Q.850;cause=16"]);
        assert_eq!(end.q850, Some(16));
        let end = CdrEnd::cancel().with_reasons(std::iter::empty());
        assert_eq!(end.q850, None);
    }

    #[test]
    fn media_facts_skips_rejected_audio_stream() {
        // RFC-3: port 0 = rejected (RFC 3264 §6); use the accepted stream.
        let sdp = b"v=0\r\nm=audio 0 RTP/AVP 18\r\nm=audio 4002 RTP/AVP 8\r\n";
        assert_eq!(media_facts(sdp).0.as_deref(), Some("PCMA"));
        assert_eq!(media_facts(b"m=audio 0 RTP/AVP 0\r\n").0, None);
    }

    #[test]
    fn media_facts_reads_codec_and_srtp() {
        let sdp = b"v=0\r\nm=audio 4000 RTP/SAVP 8 0\r\na=rtpmap:8 PCMA/8000\r\n\
            a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:xyz\r\n";
        assert_eq!(
            media_facts(sdp),
            (Some("PCMA".into()), Some("AES_256_CM_HMAC_SHA1_80".into()))
        );
        let dtls = b"m=audio 4000 UDP/TLS/RTP/SAVP 0\r\n";
        assert_eq!(
            media_facts(dtls),
            (Some("PCMU".into()), Some("DTLS-SRTP".into()))
        );
        assert_eq!(media_facts(b"\xff\x00garbage"), (None, None));
    }

    /// Starts a one-connection TLS collector on 127.0.0.1 with `provider`,
    /// returning its port, the CA PEM file, and the server thread (which
    /// yields whether the handshake completed).
    #[allow(clippy::unwrap_used)]
    fn tls_collector(
        provider: rustls::crypto::CryptoProvider,
    ) -> (u16, tempfile::NamedTempFile, std::thread::JoinHandle<bool>) {
        let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&key, &ca, &ca_key)
            .unwrap();
        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca.pem().as_bytes()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(server)).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut tcp).is_err() {
                    return false;
                }
            }
            true
        });
        (port, ca_file, handle)
    }

    /// POA&M-26: the RFC 5425 connector completes a handshake with a CNSA
    /// 2.0 collector and refuses one offering only AES-128 / X25519.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn syslog_tls_is_cnsa_only() {
        use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
        let (port, ca, server) = tls_collector(uc_transport::tls::cnsa_provider());
        let mut c = TlsSyslogConnector::new(&format!("tls://127.0.0.1:{port}"), ca.path()).unwrap();
        assert!(c.connect().is_ok());
        assert!(server.join().unwrap());

        let weak = rustls::crypto::CryptoProvider {
            cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
            kx_groups: vec![kx_group::X25519],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let (port, ca, server) = tls_collector(weak);
        let mut c = TlsSyslogConnector::new(&format!("tls://127.0.0.1:{port}"), ca.path()).unwrap();
        assert!(c.connect().is_err());
        assert!(!server.join().unwrap());
    }

    #[test]
    fn tls_target_parses() {
        assert_eq!(
            parse_tls_target("tls://collector:6514"),
            Some(("collector".into(), 6514))
        );
        assert_eq!(
            parse_tls_target("tls://[2001:db8::1]:6514"),
            Some(("2001:db8::1".into(), 6514))
        );
        assert_eq!(parse_tls_target("udp://c:1"), None);
        assert_eq!(parse_tls_target("tls://c:0"), None);
    }

    #[test]
    fn unwritable_directory_error_names_directory_and_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x")?;
        let cfg = CdrConfig {
            directory: blocker.join("cdr"),
            ..CdrConfig::default()
        };
        let Err(err) = start_from_config(&cfg, "sbc1", None) else {
            return Err("an unwritable directory must fail startup".into());
        };
        assert!(
            err.contains(&blocker.join("cdr").display().to_string()),
            "{err}"
        );
        assert!(err.contains("cdr.enabled"), "{err}");
        assert!(err.contains("cdr.directory"), "{err}");
        Ok(())
    }

    #[test]
    fn observer_raises_audit_events() {
        let capture = uc_audit::capture::start();
        let o = AuditObserver;
        o.on_rotated(Path::new("/var/lib/usg-sbc/cdr/x.jsonl"), "ab");
        o.on_write_error(&io::Error::other("disk full"));
        o.on_drop(3, false);
        o.on_drop(4, true);
        let ev = capture.events();
        assert!(ev.iter().any(|e| matches!(e,
            uc_audit::AuditEvent::CdrFileRotated(r) if r.sha384 == "ab")));
        let reasons: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CdrSinkFailure(f) => Some(f.reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, ["write_error", "queue_full", "writer_dead"]);
    }

    #[test]
    fn disabled_starts_nothing() {
        let cfg = CdrConfig {
            enabled: false,
            ..CdrConfig::default()
        };
        assert!(matches!(start_from_config(&cfg, "sbc1", None), Ok(None)));
    }

    /// A resolver that never answers costs one helper thread, not one per
    /// reconnect; the pending lookup is reused.
    #[test]
    fn hung_resolver_keeps_one_lookup_in_flight() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let hold_rx = Arc::new(std::sync::Mutex::new(hold_rx));
        let c = Arc::clone(&calls);
        let mut r = CollectorResolver::with_lookup(Arc::new(move |_: &str, _: u16| {
            c.fetch_add(1, Ordering::SeqCst);
            // Never returns while the test holds `hold_tx`.
            let _ = hold_rx.lock().map(|rx| rx.recv());
            Ok(None)
        }));
        for _ in 0..5 {
            let e = r
                .resolve("collector.example", 6514, Duration::from_millis(20))
                .err()
                .map(|e| e.kind());
            assert_eq!(e, Some(io::ErrorKind::TimedOut));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(hold_tx);
    }

    /// The last good address is used while the resolver fails or hangs, and
    /// a literal IP never spawns a lookup.
    #[test]
    fn resolver_falls_back_to_last_good_address() -> io::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let good = SocketAddr::from(([192, 0, 2, 10], 6514));
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let mut r = CollectorResolver::with_lookup(Arc::new(move |_: &str, _: u16| {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Some(SocketAddr::from(([192, 0, 2, 10], 6514))))
            } else {
                Err(io::Error::other("SERVFAIL"))
            }
        }));
        let t = Duration::from_secs(5);
        assert_eq!(r.resolve("collector.example", 6514, t)?, good);
        assert_eq!(r.resolve("collector.example", 6514, t)?, good);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            r.resolve("198.51.100.7", 6514, t)?,
            SocketAddr::from(([198, 51, 100, 7], 6514))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }
}
