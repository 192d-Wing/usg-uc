//! Rate-limited audit of signaling rejections an attacker can drive at
//! line rate: digest REGISTER failures (POA&M-236), in-dialog 481/503
//! rejections (POA&M-252), RFC 3261 §16.4 route-preprocessing failures and
//! loop detection.
//!
//! Each class reuses [`uc_sti::aggregate::FailureAggregator`]: the first
//! failure per (source IP, reason) per window is audited at once, later
//! ones are counted and reported on the next emission for that key or by
//! [`SignalingAudit::flush`] once the window closes, so a burst that stops is
//! still fully accounted for (`;count=<n>` on the policy / failure reason).
//! Aggregation is per node; a SIEM sums the per-node counts.
//!
//! The key tables are bounded (`uc_sti::aggregate::MAX_KEYS` each); an event
//! dropped because a table was full is counted in [`SignalingAudit::dropped`]
//! and reported once per flush as an `AuditRecordsDropped` record.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-4, AU-5, AU-12, SC-5

use proto_sip::HeaderName;
use proto_sip::digest_verifier::DigestReject;
use proto_sip::message::SipRequest;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uc_sti::aggregate::{FailureAggregator, Seen};
use uc_types::address::SbcSocketAddr;

/// Separator of the context fields remembered for a flushed event. Every
/// field passes through [`audit_field`], which strips control characters
/// (U+001F included), so the separator cannot be forged into a field
/// whatever the parser lets through.
const CTX_SEP: char = '\u{1f}';

/// Byte cap of each attacker-supplied string (AOR, From URI, Request-URI,
/// method) kept in an aggregator slot or written to an audit record. Keeps
/// the per-key memory of the bounded tables small (SC-5).
pub const MAX_AUDIT_FIELD_BYTES: usize = 256;

/// Sanitizes an attacker-supplied value for audit storage: drops control
/// characters and truncates to [`MAX_AUDIT_FIELD_BYTES`] on a char boundary.
///
/// ## NIST 800-53 Rev5: AU-3, AU-9, SC-5
fn audit_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_AUDIT_FIELD_BYTES));
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_AUDIT_FIELD_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// In-dialog / signaling rejection policies (bounded label set, also the
/// `policy` of the `AuthorizationDecision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InDialogPolicy {
    /// No dialog matches the Call-ID (RFC 3261 §12.2.2, 481).
    UnknownDialog,
    /// The Call-ID matches but the tags do not (forged/guessed, 481).
    FromTagMismatch,
    /// PRACK RAck names no relayed reliable 1xx (RFC 3262 §7.2, 481).
    RackMismatch,
    /// PRACK received from the callee leg (481).
    PrackFromCallee,
    /// Per-call relay cap reached (503, SC-5).
    PendingRelayCap,
    /// Per-call relay cap reached under the write lock (503, SC-5).
    PendingRelayCapRace,
}

impl InDialogPolicy {
    /// Every policy, for metric export.
    pub const ALL: [Self; 6] = [
        Self::UnknownDialog,
        Self::FromTagMismatch,
        Self::RackMismatch,
        Self::PrackFromCallee,
        Self::PendingRelayCap,
        Self::PendingRelayCapRace,
    ];

    /// Stable policy string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownDialog => "in-dialog:unknown-dialog",
            Self::FromTagMismatch => "in-dialog:from-tag-mismatch",
            Self::RackMismatch => "in-dialog:rack-mismatch",
            Self::PrackFromCallee => "in-dialog:prack-from-callee",
            Self::PendingRelayCap => "in-dialog:pending-relay-cap",
            Self::PendingRelayCapRace => "in-dialog:pending-relay-cap-race",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Number of digest outcomes counted (`ok`, `stale`, ten reject codes,
/// `aor_mismatch`, `throttled`).
const DIGEST_OUTCOMES: usize = 14;

/// Digest outcome labels (`sbc_digest_verify_total{outcome}`).
pub const DIGEST_OUTCOME_LABELS: [&str; DIGEST_OUTCOMES] = [
    "ok",
    "stale",
    "realm_mismatch",
    "algorithm_mismatch",
    "qop_mismatch",
    "missing_qop_params",
    "uri_mismatch",
    "unknown_nonce",
    "nonce_replay",
    "opaque_mismatch",
    "bad_response",
    "malformed",
    "aor_mismatch",
    "throttled",
];

/// Gauge names, one per digest outcome (order of [`DIGEST_OUTCOME_LABELS`]).
pub const DIGEST_METRIC_NAMES: [&str; DIGEST_OUTCOMES] = [
    "sbc_digest_verify_ok_total",
    "sbc_digest_verify_stale_total",
    "sbc_digest_verify_realm_mismatch_total",
    "sbc_digest_verify_algorithm_mismatch_total",
    "sbc_digest_verify_qop_mismatch_total",
    "sbc_digest_verify_missing_qop_params_total",
    "sbc_digest_verify_uri_mismatch_total",
    "sbc_digest_verify_unknown_nonce_total",
    "sbc_digest_verify_nonce_replay_total",
    "sbc_digest_verify_opaque_mismatch_total",
    "sbc_digest_verify_bad_response_total",
    "sbc_digest_verify_malformed_total",
    "sbc_digest_verify_aor_mismatch_total",
    "sbc_digest_verify_throttled_total",
];

/// Gauge names, one per in-dialog policy (order of [`InDialogPolicy::ALL`]).
pub const IN_DIALOG_METRIC_NAMES: [&str; 6] = [
    "sbc_in_dialog_rejects_unknown_dialog_total",
    "sbc_in_dialog_rejects_from_tag_mismatch_total",
    "sbc_in_dialog_rejects_rack_mismatch_total",
    "sbc_in_dialog_rejects_prack_from_callee_total",
    "sbc_in_dialog_rejects_pending_relay_cap_total",
    "sbc_in_dialog_rejects_pending_relay_cap_race_total",
];

/// Audit `failure_reason` of a digest failure backoff window opening.
pub const THROTTLE_TRIPPED_REASON: &str = "digest:throttle_tripped";

/// Gauge: signaling audit events dropped because a table was full.
pub const METRIC_DROPPED: &str = "sbc_signaling_audit_dropped_total";

/// Help text for every signaling-audit gauge.
pub const METRIC_HELP: &str =
    "Signaling rejections (digest REGISTER outcomes, in-dialog 481/503) and audit drops";

/// A digest REGISTER outcome that is not a missing-credentials challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestOutcome {
    /// Authenticated.
    Ok,
    /// Valid digest on an expired/exhausted nonce (RFC 7616 §3.3).
    Stale,
    /// Rejected by the verifier.
    Reject(DigestReject),
    /// The digest username is not the AOR user (registration hijack).
    AorMismatch,
    /// Refused inside a per-username failure backoff window (AC-7). On the
    /// wire it is a `bad_response`.
    Throttled,
}

impl DigestOutcome {
    /// Metric label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Stale => "stale",
            Self::Reject(r) => r.as_str(),
            Self::AorMismatch => "aor_mismatch",
            Self::Throttled => "throttled",
        }
    }

    /// Audit `failure_reason` stem (`digest:<reason>`).
    #[must_use]
    pub fn audit_reason(self) -> &'static str {
        match self {
            Self::Ok => "digest:ok",
            Self::Stale => "digest:stale",
            Self::AorMismatch => "digest:aor_mismatch",
            Self::Throttled => "digest:throttled",
            Self::Reject(r) => match r {
                DigestReject::RealmMismatch => "digest:realm_mismatch",
                DigestReject::AlgorithmMismatch => "digest:algorithm_mismatch",
                DigestReject::QopMismatch => "digest:qop_mismatch",
                DigestReject::MissingQopParams => "digest:missing_qop_params",
                DigestReject::UriMismatch => "digest:uri_mismatch",
                DigestReject::UnknownNonce => "digest:unknown_nonce",
                DigestReject::NonceReplay => "digest:nonce_replay",
                DigestReject::OpaqueMismatch => "digest:opaque_mismatch",
                DigestReject::BadResponse => "digest:bad_response",
                DigestReject::Malformed => "digest:malformed",
            },
        }
    }

    fn index(self) -> usize {
        DIGEST_OUTCOME_LABELS
            .iter()
            .position(|l| *l == self.label())
            .unwrap_or(DIGEST_OUTCOMES - 1)
    }
}

/// Rate-limited signaling audit (see the module docs).
pub struct SignalingAudit {
    /// Digest REGISTER failures, keyed (source IP, reason).
    auth: FailureAggregator,
    /// In-dialog, route-preprocess and loop rejections, keyed (source IP,
    /// policy).
    in_dialog: FailureAggregator,
    /// Total of `dropped()` already reported by a flush (AU-5).
    dropped_reported: AtomicU64,
    /// `sbc_digest_verify_total{outcome}`.
    digest_outcomes: [AtomicU64; DIGEST_OUTCOMES],
    /// `sbc_in_dialog_rejects_total{policy}`.
    in_dialog_rejects: [AtomicU64; InDialogPolicy::ALL.len()],
}

impl std::fmt::Debug for SignalingAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalingAudit")
            .field("window", &self.auth.window())
            .finish_non_exhaustive()
    }
}

/// `policy` with `;count=<n>` appended when more than one failure is
/// carried.
fn with_count(stem: &str, count: u64) -> String {
    if count > 1 {
        format!("{stem};count={count}")
    } else {
        stem.to_owned()
    }
}

impl SignalingAudit {
    /// Creates the aggregators with the given window
    /// (`rate_limit.audit_interval_secs`).
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            auth: FailureAggregator::new(window),
            in_dialog: FailureAggregator::new(window),
            dropped_reported: AtomicU64::new(0),
            digest_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            in_dialog_rejects: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// The aggregation window.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.auth.window()
    }

    /// Audit events dropped because an aggregation table was full (metric
    /// `sbc_signaling_audit_dropped_total`).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.auth.dropped().saturating_add(self.in_dialog.dropped())
    }

    /// Every exported counter as `(gauge name, help, value)`. The uc-metrics
    /// gauges are refreshed through `&self`, which cannot set labels, so each
    /// bounded label value is its own gauge:
    /// `sbc_digest_verify_<outcome>_total` (14),
    /// `sbc_in_dialog_rejects_<policy>_total` (6) and
    /// `sbc_signaling_audit_dropped_total`.
    ///
    /// ## NIST 800-53 Rev5: SI-4, AU-5
    pub fn metric_values(&self) -> Vec<(&'static str, u64)> {
        let mut out: Vec<(&'static str, u64)> = DIGEST_METRIC_NAMES
            .iter()
            .zip(&self.digest_outcomes)
            .map(|(n, c)| (*n, c.load(Ordering::Relaxed)))
            .collect();
        out.extend(
            IN_DIALOG_METRIC_NAMES
                .iter()
                .zip(&self.in_dialog_rejects)
                .map(|(n, c)| (*n, c.load(Ordering::Relaxed))),
        );
        out.push((METRIC_DROPPED, self.dropped()));
        out
    }

    /// `(outcome, count)` pairs for `sbc_digest_verify_total`.
    pub fn digest_outcome_counts(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        DIGEST_OUTCOME_LABELS
            .iter()
            .zip(&self.digest_outcomes)
            .map(|(l, c)| (*l, c.load(Ordering::Relaxed)))
    }

    /// `(policy, count)` pairs for `sbc_in_dialog_rejects_total`.
    pub fn in_dialog_reject_counts(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        InDialogPolicy::ALL
            .iter()
            .zip(&self.in_dialog_rejects)
            .map(|(p, c)| (p.as_str(), c.load(Ordering::Relaxed)))
    }

    /// Counts a digest outcome; a non-`Ok` outcome is audited as a failed
    /// `AuthenticationAttempt` (rate limited per source IP and reason).
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3, IA-2; RFC 7616 §3.3
    pub fn digest(&self, aor: &str, source: SbcSocketAddr, outcome: DigestOutcome, now: Instant) {
        if let Some(c) = self.digest_outcomes.get(outcome.index()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if outcome == DigestOutcome::Ok {
            return;
        }
        self.auth_failure(aor, source, outcome.audit_reason(), now);
    }

    /// Audits the opening of a per-username digest failure backoff window
    /// (`digest:throttle_tripped`) as a failed `AuthenticationAttempt`,
    /// rate limited per source IP like every other digest failure.
    ///
    /// ## NIST 800-53 Rev5: AC-7, AU-2, AU-3
    pub fn digest_throttle_tripped(&self, aor: &str, source: SbcSocketAddr, now: Instant) {
        self.auth_failure(aor, source, THROTTLE_TRIPPED_REASON, now);
    }

    /// One failed digest `AuthenticationAttempt`, aggregated per (source
    /// IP, reason).
    fn auth_failure(&self, aor: &str, source: SbcSocketAddr, reason: &'static str, now: Instant) {
        let ip = source.ip();
        let key = ip.to_string();
        let aor = audit_field(aor);
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &aor,
        };
        if let Some(count) = self.auth.record_seen(&key, reason, now, seen) {
            emit_auth_failure(&aor, ip, reason, count);
        }
    }

    /// Audits an in-dialog rejection as a denied `AuthorizationDecision`
    /// (rate limited per source IP and policy).
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3, SI-4; RFC 3261 §12.2.2
    pub fn in_dialog_reject(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        policy: InDialogPolicy,
        now: Instant,
    ) {
        if let Some(c) = self.in_dialog_rejects.get(policy.index()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.signaling_reject(req, source, policy.as_str(), now);
    }

    /// Audits a rejected request under a `'static` policy (route
    /// preprocessing, loop detection, in-dialog), rate limited per source
    /// IP and policy.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12
    pub fn signaling_reject(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        policy: &'static str,
        now: Instant,
    ) {
        let ip = source.ip();
        let key = ip.to_string();
        let subject = audit_field(&subject_of(req, source));
        let resource = audit_field(&req.uri.to_string());
        let action = audit_field(req.method.as_str());
        let ctx = format!("{action}{CTX_SEP}{subject}{CTX_SEP}{resource}");
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &ctx,
        };
        if let Some(count) = self.in_dialog.record_seen(&key, policy, now, seen) {
            emit_denied(subject, resource, action, policy, count, Some(ip));
        }
    }

    /// Emits one event per key whose window closed with suppressed
    /// failures, and one `AuditRecordsDropped` for events lost to a full
    /// table since the previous flush (AU-5).
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-5, SC-5
    pub fn flush(&self, now: Instant) {
        let total = self.dropped();
        let delta = total.saturating_sub(self.dropped_reported.swap(total, Ordering::Relaxed));
        if delta > 0 {
            tracing::warn!(
                dropped = delta,
                total,
                "signaling audit events dropped (aggregation table full)"
            );
            // POAM: POA&M-236 (residual) - uc-audit has no
            // aggregation-overflow drop reason, so aggregator-table overflow
            // is reported as QueueFull (the table is a bounded queue of
            // pending records); a dedicated AuditDropReason variant needs a
            // uc-audit schema change outside this crate.
            uc_audit::log_event(uc_audit::AuditEvent::AuditRecordsDropped(
                uc_audit::event::AuditRecordsDropped {
                    count: delta,
                    total,
                    reason: uc_audit::event::AuditDropReason::QueueFull,
                },
            ));
        }
        for p in self.auth.flush(now) {
            if let Some(ip) = p.last_source_ip {
                emit_auth_failure(&p.last_call_id_hash, ip, p.reason, p.count);
            }
        }
        for p in self.in_dialog.flush(now) {
            let mut parts = p.last_call_id_hash.splitn(3, CTX_SEP);
            let action = parts.next().unwrap_or_default().to_owned();
            let subject = parts.next().unwrap_or_default().to_owned();
            let resource = parts.next().unwrap_or_default().to_owned();
            emit_denied(
                subject,
                resource,
                action,
                p.reason,
                p.count,
                p.last_source_ip,
            );
        }
    }

    /// Spawns the periodic flush (once per window) until shutdown.
    pub fn spawn_flush(
        self: &Arc<Self>,
        shutdown: crate::shutdown::ShutdownSignal,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(this.window());
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => this.flush(Instant::now()),
                    () = shutdown.wait_for_shutdown() => {
                        this.flush(Instant::now());
                        break;
                    }
                }
            }
        })
    }
}

/// Subject of an `AuthorizationDecision`: the From URI, else the source.
fn subject_of(req: &SipRequest, source: SbcSocketAddr) -> String {
    req.headers.get_value(&HeaderName::From).map_or_else(
        || source.to_string(),
        crate::sip_stack::extract_uri_from_header,
    )
}

fn emit_auth_failure(identity: &str, ip: std::net::IpAddr, reason: &str, count: u64) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthenticationAttempt(
        uc_audit::event::AuthenticationAttempt {
            identity: identity.to_owned(),
            source_ip: ip,
            success: false,
            failure_reason: Some(with_count(reason, count)),
            method: uc_audit::event::AuthMethod::Digest,
        },
    ));
}

fn emit_denied(
    identity: String,
    resource: String,
    action: String,
    policy: &str,
    count: u64,
    source_ip: Option<std::net::IpAddr>,
) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity,
            resource,
            action,
            granted: false,
            policy: with_count(policy, count),
            source_ip,
        },
    ));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use uc_audit::AuditEvent;

    fn req(call_id: &str) -> SipRequest {
        let raw = format!(
            "MESSAGE sip:bob@192.0.2.10 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.7;branch=z9hG4bK-1\r\n\
             From: <sip:alice@example.com>;tag=a\r\n\
             To: <sip:bob@example.com>;tag=b\r\n\
             Call-ID: {call_id}\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"
        );
        match proto_sip::SipMessage::parse(raw.as_bytes()) {
            Ok(proto_sip::SipMessage::Request(r)) => r,
            other => panic!("parse: {other:?}"),
        }
    }

    fn src(last: u8) -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, last), 5060)
    }

    fn denied(events: &[AuditEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) if !d.granted => Some(d.policy.clone()),
                _ => None,
            })
            .collect()
    }

    fn auth_failures(events: &[AuditEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuthenticationAttempt(a) if !a.success => a.failure_reason.clone(),
                _ => None,
            })
            .collect()
    }

    /// Plan test 37: a burst from one source is one event, then one flushed
    /// event carrying the suppressed count.
    #[test]
    fn in_dialog_burst_is_aggregated_then_flushed() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let r = req("x@test");
        for _ in 0..100 {
            a.in_dialog_reject(&r, src(1), InDialogPolicy::UnknownDialog, t0);
        }
        assert_eq!(denied(&cap.events()), vec!["in-dialog:unknown-dialog"]);
        a.flush(t0 + Duration::from_secs(61));
        assert_eq!(
            denied(&cap.events()),
            vec![
                "in-dialog:unknown-dialog",
                "in-dialog:unknown-dialog;count=99"
            ]
        );
        let counts: Vec<_> = a.in_dialog_reject_counts().collect();
        assert_eq!(counts[0], ("in-dialog:unknown-dialog", 100));
        // The flushed record keeps the subject and resource (AU-3).
        let flushed = cap
            .events()
            .into_iter()
            .rev()
            .find_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .unwrap();
        assert_eq!(flushed.action, "MESSAGE");
        assert_eq!(flushed.identity, "sip:alice@example.com");
        assert_eq!(flushed.resource, "sip:bob@192.0.2.10");
    }

    /// Plan test 7: 50 digest failures from one IP → one event and a
    /// flushed `count=49`; a second IP gets its own event.
    #[test]
    fn digest_failures_rate_limited_per_source() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let bad = DigestOutcome::Reject(DigestReject::BadResponse);
        for _ in 0..50 {
            a.digest("sip:alice@example.com", src(1), bad, t0);
        }
        a.digest("sip:alice@example.com", src(2), bad, t0);
        assert_eq!(
            auth_failures(&cap.events()),
            vec!["digest:bad_response", "digest:bad_response"]
        );
        a.flush(t0 + Duration::from_secs(61));
        assert_eq!(
            auth_failures(&cap.events()),
            vec![
                "digest:bad_response",
                "digest:bad_response",
                "digest:bad_response;count=49"
            ]
        );
        // `ok` is counted but never audited as a failure.
        a.digest("sip:alice@example.com", src(1), DigestOutcome::Ok, t0);
        let ok = a.digest_outcome_counts().find(|(l, _)| *l == "ok").unwrap();
        assert_eq!(ok.1, 1);
        let br = a
            .digest_outcome_counts()
            .find(|(l, _)| *l == "bad_response")
            .unwrap();
        assert_eq!(br.1, 51);
    }

    /// Plan test 38: a full key table drops (counts) events and the flush
    /// reports the delta once as `AuditRecordsDropped`.
    #[test]
    fn full_table_counts_drops_and_flush_reports_them() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let r = req("y@test");
        for i in 0..=uc_sti::aggregate::MAX_KEYS {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000_u32 + u32::try_from(i).unwrap());
            a.in_dialog_reject(
                &r,
                SbcSocketAddr::new_v4(ip, 5060),
                InDialogPolicy::FromTagMismatch,
                t0,
            );
        }
        assert_eq!(a.dropped(), 1);
        a.flush(t0 + Duration::from_millis(10));
        let drops: Vec<u64> = cap
            .events()
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuditRecordsDropped(d) => Some(d.count),
                _ => None,
            })
            .collect();
        assert_eq!(drops, vec![1]);
        // Reported once: a second flush with no new drops is silent.
        a.flush(t0 + Duration::from_millis(20));
        let n = cap
            .events()
            .iter()
            .filter(|e| matches!(e, AuditEvent::AuditRecordsDropped(_)))
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn digest_labels_cover_every_outcome() {
        for r in [
            DigestReject::RealmMismatch,
            DigestReject::AlgorithmMismatch,
            DigestReject::QopMismatch,
            DigestReject::MissingQopParams,
            DigestReject::UriMismatch,
            DigestReject::UnknownNonce,
            DigestReject::NonceReplay,
            DigestReject::OpaqueMismatch,
            DigestReject::BadResponse,
            DigestReject::Malformed,
        ] {
            let o = DigestOutcome::Reject(r);
            assert_eq!(DIGEST_OUTCOME_LABELS[o.index()], r.as_str());
            assert_eq!(o.audit_reason(), format!("digest:{}", r.as_str()));
        }
        assert_eq!(
            DIGEST_OUTCOME_LABELS[DigestOutcome::AorMismatch.index()],
            "aor_mismatch"
        );
        assert_eq!(
            DIGEST_OUTCOME_LABELS[DigestOutcome::Throttled.index()],
            "throttled"
        );
        assert_eq!(
            DIGEST_METRIC_NAMES[DigestOutcome::Throttled.index()],
            "sbc_digest_verify_throttled_total"
        );
        assert_eq!(DigestOutcome::Throttled.audit_reason(), "digest:throttled");
    }

    /// QA: keys are (source IP, policy). Distinct policies from one IP are
    /// each audited once; a flush before the window closes, or for a key
    /// with nothing suppressed, emits nothing.
    #[test]
    fn qa_distinct_policies_and_quiet_flush() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let r = req("z@test");
        a.in_dialog_reject(&r, src(9), InDialogPolicy::UnknownDialog, t0);
        a.in_dialog_reject(&r, src(9), InDialogPolicy::RackMismatch, t0);
        a.signaling_reject(&r, src(9), "loop-detected", t0);
        a.in_dialog_reject(&r, src(9), InDialogPolicy::RackMismatch, t0);
        assert_eq!(
            denied(&cap.events()),
            vec![
                "in-dialog:unknown-dialog",
                "in-dialog:rack-mismatch",
                "loop-detected"
            ]
        );
        a.flush(t0 + Duration::from_secs(1));
        assert_eq!(denied(&cap.events()).len(), 3, "window still open");
        a.flush(t0 + Duration::from_secs(61));
        assert_eq!(
            denied(&cap.events()),
            vec![
                "in-dialog:unknown-dialog",
                "in-dialog:rack-mismatch",
                "loop-detected",
                "in-dialog:rack-mismatch"
            ],
            "only the key with a suppressed event is flushed"
        );
        assert!(
            !cap.events()
                .iter()
                .any(|e| matches!(e, AuditEvent::AuditRecordsDropped(_)))
        );
        let counts: Vec<_> = a.in_dialog_reject_counts().collect();
        assert!(counts.contains(&("in-dialog:rack-mismatch", 2)));
        assert!(counts.contains(&("in-dialog:unknown-dialog", 1)));
    }

    /// QA: stale and AOR-mismatch outcomes are audited as failures with
    /// their own reasons and counters.
    #[test]
    fn qa_stale_and_aor_mismatch_audited() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        a.digest("sip:a@example.com", src(3), DigestOutcome::Stale, t0);
        a.digest("sip:a@example.com", src(3), DigestOutcome::AorMismatch, t0);
        assert_eq!(
            auth_failures(&cap.events()),
            vec!["digest:stale", "digest:aor_mismatch"]
        );
        for l in ["stale", "aor_mismatch"] {
            assert_eq!(
                a.digest_outcome_counts().find(|(x, _)| *x == l).unwrap().1,
                1
            );
        }
        let ev = cap
            .events()
            .into_iter()
            .find_map(|e| match e {
                AuditEvent::AuthenticationAttempt(x) => Some(x),
                _ => None,
            })
            .unwrap();
        assert_eq!(ev.source_ip, src(3).ip());
        assert_eq!(ev.identity, "sip:a@example.com");
    }

    /// SEC-1/SEC-4/SEC-5: attacker-supplied strings are stripped of control
    /// characters (U+001F included) and capped before they are retained or
    /// audited, and a forged separator cannot shift fields on flush.
    #[test]
    fn audit_field_caps_and_strips_control_chars() {
        let long = "a".repeat(5000);
        assert_eq!(audit_field(&long).len(), MAX_AUDIT_FIELD_BYTES);
        // Multi-byte chars are cut on a char boundary.
        let wide = "\u{00e9}".repeat(200);
        let cut = audit_field(&wide);
        assert!(cut.len() <= MAX_AUDIT_FIELD_BYTES);
        assert_eq!(cut.chars().count(), MAX_AUDIT_FIELD_BYTES / 2);
        assert_eq!(audit_field("a\u{1f}b\r\n\u{0}c\u{7f}"), "abc");
    }

    #[test]
    fn retained_and_flushed_context_is_bounded_and_unforgeable() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let bad = DigestOutcome::Reject(DigestReject::BadResponse);
        let huge_aor = format!("sip:{}\u{1f}x@example.com", "u".repeat(4000));
        for _ in 0..3 {
            a.digest(&huge_aor, src(9), bad, t0);
        }
        // Forged separators in the subject and an oversized resource.
        let mut r = req("y@test");
        r.headers.set(
            HeaderName::From,
            "<sip:ev\u{1f}il\u{1f}x@example.com>;tag=a",
        );
        for _ in 0..3 {
            a.signaling_reject(&r, src(9), "route:test", t0);
        }
        a.flush(t0 + Duration::from_secs(61));
        let events = cap.events();
        for e in &events {
            match e {
                AuditEvent::AuthenticationAttempt(x) => {
                    assert!(x.identity.len() <= MAX_AUDIT_FIELD_BYTES);
                    assert!(!x.identity.contains('\u{1f}'));
                }
                AuditEvent::AuthorizationDecision(d) => {
                    assert_eq!(d.action, "MESSAGE");
                    assert_eq!(d.identity, "sip:evilx@example.com");
                    assert_eq!(d.resource, "sip:bob@192.0.2.10");
                }
                _ => {}
            }
        }
        assert_eq!(denied(&events).len(), 2);
        assert_eq!(auth_failures(&events).len(), 2);
    }
}
