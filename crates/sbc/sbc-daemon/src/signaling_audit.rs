//! Rate-limited audit of signaling rejections an attacker can drive at
//! line rate: digest REGISTER failures (POA&M-236), in-dialog 481/503
//! rejections (POA&M-252), RFC 3261 §16.4 route-preprocessing failures and
//! loop detection, and rejects of unauthenticated senders (source admission,
//! bearer REGISTER failures).
//!
//! Each class reuses [`uc_sti::aggregate::FailureAggregator`]: the first
//! failure per (source IP, reason) per window is audited at once, later
//! ones are counted and reported on the next emission for that key or by
//! [`SignalingAudit::flush`] once the window closes, so a burst that stops is
//! still fully accounted for (`;count=<n>` on the policy / failure reason).
//! Aggregation is per node; a SIEM sums the per-node counts.
//!
//! Source-admission rejects and bearer REGISTER failures each have their
//! own table keyed by (source prefix, policy): IPv4 /24, IPv6 /64, so
//! rotating or spoofed sources inside one prefix share a key and a flood of
//! one class cannot evict another class's keys. An aggregated record of
//! these classes carries `;prefix=<key>`; its `source_ip` is the last
//! (possibly spoofed) sample.
//!
//! Each class also has an emit budget ([`EMIT_BUDGET_PER_WINDOW`] records
//! per window, immediate and flushed together). Events beyond it are
//! folded into one `<class>:over-budget;count=<n>;keys=<k>;top=...`
//! summary per flush naming the highest folded keys. Of each budget,
//! [`FLUSH_RESERVE_PER_WINDOW`] is kept for the flush, which writes pending
//! counts highest first, so a sustained source keeps its own record after a
//! one-shot flood of new keys. The five classes (digest, in-dialog and
//! signalling, source admission, bearer, bearer `Forbidden` with subject)
//! therefore write at most 5 x (256 + 1) = 1285 records per window.
//!
//! Worst case: at 0.9 to 1.4 KiB per record (fields at their caps) and the
//! default 60 s window that is 68 to 106 MiB/h, so these classes alone turn
//! over the default audit capacity ((16 + 1) x 64 MiB = 1.06 GiB,
//! `overwrite_oldest`) in about 10 to 16 h; at the minimum 1 s window in
//! about 10 to 16 min. Post-admission INVITE denials and the legacy
//! registrar path are audited per request outside this bound (POA&M-431).
//! Other audit events add to this; off-box shipping (AU-4(1)) is the
//! evidence path.
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

/// Byte cap of the Call-ID inside an in-dialog reject record's resource.
pub const MAX_AUDIT_CALL_ID_BYTES: usize = 64;

/// `s` with every byte outside `[A-Za-z0-9-._~@:!+*'()]` written as `%XX`
/// (pure ASCII output).
fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len().min(MAX_AUDIT_FIELD_BYTES));
    for b in s.bytes() {
        if out.len() >= MAX_AUDIT_FIELD_BYTES {
            break;
        }
        if b.is_ascii_alphanumeric() || b"-._~@:!+*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `s` truncated to at most `max` bytes on a char boundary.
fn capped(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// Sanitizes an attacker-supplied value for audit storage: drops control
/// characters and truncates to [`MAX_AUDIT_FIELD_BYTES`] on a char boundary.
///
/// ## NIST 800-53 Rev5: AU-3, AU-9, SC-5
pub fn audit_field(s: &str) -> String {
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
    /// The To tag is missing or is not a local tag of the dialog
    /// (RFC 3261 §12.2.2, 481).
    ToTagMismatch,
    /// The tags name the dialog but the request did not come from the
    /// leg's peer (403).
    ForeignSource,
    /// An ACK for a pending 2xx does not match its dialog, CSeq or peer
    /// (RFC 3261 §13.2.2.4; absorbed, no response).
    AckMismatch,
    /// A CANCEL matches no INVITE transaction or call (RFC 3261 §9.2, 481).
    CancelNoMatch,
}

impl InDialogPolicy {
    /// Every policy, for metric export.
    pub const ALL: [Self; 10] = [
        Self::UnknownDialog,
        Self::FromTagMismatch,
        Self::RackMismatch,
        Self::PrackFromCallee,
        Self::PendingRelayCap,
        Self::PendingRelayCapRace,
        Self::ToTagMismatch,
        Self::ForeignSource,
        Self::AckMismatch,
        Self::CancelNoMatch,
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
            Self::ToTagMismatch => "in-dialog:to-tag-mismatch",
            Self::ForeignSource => "in-dialog:foreign-source",
            Self::AckMismatch => "in-dialog:ack-mismatch",
            Self::CancelNoMatch => "in-dialog:cancel-no-match",
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
pub const IN_DIALOG_METRIC_NAMES: [&str; InDialogPolicy::ALL.len()] = [
    "sbc_in_dialog_rejects_unknown_dialog_total",
    "sbc_in_dialog_rejects_from_tag_mismatch_total",
    "sbc_in_dialog_rejects_rack_mismatch_total",
    "sbc_in_dialog_rejects_prack_from_callee_total",
    "sbc_in_dialog_rejects_pending_relay_cap_total",
    "sbc_in_dialog_rejects_pending_relay_cap_race_total",
    "sbc_in_dialog_rejects_to_tag_mismatch_total",
    "sbc_in_dialog_rejects_foreign_source_total",
    "sbc_in_dialog_rejects_ack_mismatch_total",
    "sbc_in_dialog_rejects_cancel_no_match_total",
];

/// Audit `failure_reason` of a digest failure backoff window opening.
pub const THROTTLE_TRIPPED_REASON: &str = "digest:throttle_tripped";

/// Gauge: signaling audit events dropped because a table was full.
pub const METRIC_DROPPED: &str = "sbc_signaling_audit_dropped_total";

/// Gauge: INVITEs refused by source admission (403).
pub const METRIC_SOURCE_ADMISSION_REJECTS: &str = "sbc_source_admission_rejects_total";

/// Gauge: bearer (RFC 8898) REGISTER authentication failures.
pub const METRIC_BEARER_REGISTER_FAILURES: &str = "sbc_bearer_register_failures_total";

/// Gauge names of the unauthenticated-reject counters.
pub const UNAUTH_METRIC_NAMES: [&str; 2] = [
    METRIC_SOURCE_ADMISSION_REJECTS,
    METRIC_BEARER_REGISTER_FAILURES,
];

/// Policy of an audited source-admission reject (same as before
/// aggregation, so SIEM rules keep matching).
pub const SOURCE_ADMISSION_POLICY: &str = "source-admission";

/// Audit `failure_reason` stems of bearer REGISTER failures: the RFC 6750
/// §3.1 error code, or `forbidden` for a valid token that may not register
/// the AOR.
const BEARER_REASONS: [&str; 5] = [
    "bearer:invalid_request",
    "bearer:invalid_token",
    "bearer:insufficient_scope",
    "bearer:forbidden",
    "bearer:other",
];

/// Static `failure_reason` for a bearer failure label (anything that is
/// not an RFC 6750 code or `forbidden` is `bearer:other`).
fn bearer_reason(label: &str) -> &'static str {
    match label {
        "invalid_request" => BEARER_REASONS[0],
        "invalid_token" => BEARER_REASONS[1],
        "insufficient_scope" => BEARER_REASONS[2],
        "forbidden" => BEARER_REASONS[3],
        _ => BEARER_REASONS[4],
    }
}

/// Aggregation key of an unauthenticated sender: its IPv4 /24 or IPv6 /64
/// (an IPv4-mapped IPv6 address counts as IPv4).
// POAM: POA&M-431 -- accepted risk: distinct sources inside one prefix
// share a record (the last exact IP is kept), and an IPv6 sender spread over
// more than MAX_KEYS /64s overflows the table into counted drops.
fn prefix_key(ip: std::net::IpAddr) -> String {
    use std::net::IpAddr;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

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

/// Records one class (digest, in-dialog/signaling, source admission,
/// bearer) may write per window, immediate and flushed together. Beyond it
/// the class's events are folded into one over-budget summary per flush
/// (count and number of keys), so the audit volume a flood can drive is
/// bounded independently of the number of keys (SC-5, AU-4).
pub const EMIT_BUDGET_PER_WINDOW: u64 = 256;

/// Part of each class budget only the flush may use: suppressed counts of
/// sustained sources are written even after a one-shot flood of new keys
/// used up the immediate share.
pub const FLUSH_RESERVE_PER_WINDOW: u64 = 64;

/// Immediate (first-per-key) records per class per window.
const IMMEDIATE_BUDGET: u64 = EMIT_BUDGET_PER_WINDOW - FLUSH_RESERVE_PER_WINDOW;

/// Pending keys taken per class per flush: the whole table, so the
/// highest counts are always considered first.
const FLUSH_MAX_PER_CLASS: usize = uc_sti::aggregate::MAX_KEYS;

/// Folded keys named in an over-budget summary (highest counts).
const SUMMARY_TOP: usize = 4;

/// Bytes of each key and identity in a summary's top list.
const SUMMARY_FIELD_BYTES: usize = 64;

/// Gauge: signaling audit events folded into over-budget summaries.
pub const METRIC_OVER_BUDGET: &str = "sbc_signaling_audit_over_budget_total";

/// Audit `failure_reason` of a bearer `Forbidden` (valid token, foreign
/// AOR) that names the authenticated subject.
const BEARER_FORBIDDEN: &str = "bearer:forbidden";

/// Aggregation classes, each with its own table and budget.
#[derive(Debug, Clone, Copy)]
enum Class {
    Auth = 0,
    InDialog = 1,
    Source = 2,
    Bearer = 3,
    /// Bearer `Forbidden` with an authenticated subject: own table and
    /// budget, so unauthenticated junk cannot fold a verified subject away.
    BearerSubject = 4,
}

impl Class {
    const COUNT: usize = 5;
    const ALL: [Self; Self::COUNT] = [
        Self::Auth,
        Self::InDialog,
        Self::Source,
        Self::Bearer,
        Self::BearerSubject,
    ];

    /// Stem of the class's over-budget summary.
    const fn over_budget_label(self) -> &'static str {
        match self {
            Self::Auth => "digest:over-budget",
            Self::InDialog => "signaling:over-budget",
            Self::Source => "source-admission:over-budget",
            Self::Bearer => "bearer:over-budget",
            Self::BearerSubject => "bearer:forbidden:over-budget",
        }
    }
}

/// The highest-count keys folded into a summary: `(key, identity, count)`.
type TopKeys = Vec<(String, String, u64)>;

/// A folded event, for the summary's top list.
struct Folded<'a> {
    count: u64,
    ip: Option<std::net::IpAddr>,
    key: &'a str,
    identity: &'a str,
}

/// Per-class emit budget for the current window. The counters are atomics;
/// the summary lock is taken only once over budget.
#[derive(Debug, Default)]
struct Budget {
    emitted: AtomicU64,
    over_count: AtomicU64,
    over_keys: AtomicU64,
    over_total: AtomicU64,
    /// Sample source IP and the [`SUMMARY_TOP`] highest folded keys.
    summary: std::sync::Mutex<(Option<std::net::IpAddr>, TopKeys)>,
}

impl Budget {
    /// Whether an event may be written with `limit` records per window
    /// ([`IMMEDIATE_BUDGET`] for first-per-key events, the full budget for
    /// flushed counts); if not, it is folded into the over-budget summary.
    fn admit(&self, limit: u64, ev: &Folded<'_>) -> bool {
        if self
            .emitted
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < limit).then_some(n + 1)
            })
            .is_ok()
        {
            return true;
        }
        self.over_count.fetch_add(ev.count, Ordering::Relaxed);
        self.over_keys.fetch_add(1, Ordering::Relaxed);
        self.over_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.summary.lock() {
            if ev.ip.is_some() {
                g.0 = ev.ip;
            }
            let top = &mut g.1;
            let min = top.iter().map(|t| t.2).min().unwrap_or(0);
            if top.len() < SUMMARY_TOP || ev.count > min {
                if top.len() >= SUMMARY_TOP
                    && let Some(i) = top.iter().position(|t| t.2 == min)
                {
                    top.swap_remove(i);
                }
                let field = |v: &str| capped(&percent_encode(v), SUMMARY_FIELD_BYTES).to_owned();
                top.push((field(ev.key), field(ev.identity), ev.count));
            }
        }
        false
    }

    /// Takes the folded `(count, keys, sample ip, top keys)`, if any.
    fn take_over(&self) -> Option<(u64, u64, Option<std::net::IpAddr>, TopKeys)> {
        let count = self.over_count.swap(0, Ordering::Relaxed);
        let keys = self.over_keys.swap(0, Ordering::Relaxed);
        let (ip, mut top) = self
            .summary
            .lock()
            .map_or_default(|mut g| std::mem::take(&mut *g));
        top.sort_unstable_by_key(|t| std::cmp::Reverse(t.2));
        (count > 0).then_some((count, keys, ip, top))
    }
}

/// Lets one log line through per second (lock-free), for the per-request
/// warnings on aggregated reject paths; reports how many were suppressed.
///
/// ## NIST 800-53 Rev5: SC-5, AU-4 (the operational log is bounded too)
#[derive(Debug, Default)]
pub struct LogThrottle {
    /// Milliseconds since the process epoch of the last line, plus one.
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl LogThrottle {
    /// A throttle that allows the first line.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(suppressed since the last line)` when a line may be logged.
    pub fn allow(&self) -> Option<u64> {
        static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let now = u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let last = self.last_ms.load(Ordering::Relaxed);
        if (last == 0 || now.saturating_sub(last) >= 1000)
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Throttle of the per-INVITE source-admission warning.
pub static SOURCE_ADMISSION_LOG: LogThrottle = LogThrottle::new();
/// Throttle of the per-REGISTER bearer `Forbidden` warning.
pub static BEARER_FORBIDDEN_LOG: LogThrottle = LogThrottle::new();

/// Rate-limited signaling audit (see the module docs).
pub struct SignalingAudit {
    /// Digest REGISTER failures, keyed (source IP, reason).
    auth: FailureAggregator,
    /// In-dialog, route-preprocess and loop rejections, keyed (source IP,
    /// policy).
    in_dialog: FailureAggregator,
    /// Source-admission rejects, keyed (source prefix, policy).
    unauth: FailureAggregator,
    /// Bearer REGISTER failures, keyed (source prefix, reason), or
    /// (source prefix, subject) for `Forbidden`. Its own table, so a
    /// spoofed INVITE flood cannot crowd out bearer failures.
    bearer: FailureAggregator,
    /// Bearer `Forbidden` with a subject, keyed (source prefix, subject).
    bearer_subject: FailureAggregator,
    /// Emit budgets, indexed by [`Class`].
    budgets: [Budget; Class::COUNT],
    /// `sbc_source_admission_rejects_total`.
    source_admission_rejects: AtomicU64,
    /// `sbc_bearer_register_failures_total`.
    bearer_failures: AtomicU64,
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

/// [`with_count`], plus `;prefix=<key>` on an aggregated record of a
/// prefix-keyed class: `source_ip` is then only the last (possibly
/// spoofed) sample, the prefix is the attribution.
fn with_count_prefix(stem: &str, count: u64, prefix: &str) -> String {
    if count > 1 {
        format!("{stem};count={count};prefix={prefix}")
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
            unauth: FailureAggregator::new(window),
            bearer: FailureAggregator::new(window),
            bearer_subject: FailureAggregator::new(window),
            budgets: std::array::from_fn(|_| Budget::default()),
            source_admission_rejects: AtomicU64::new(0),
            bearer_failures: AtomicU64::new(0),
            dropped_reported: AtomicU64::new(0),
            digest_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            in_dialog_rejects: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn budget(&self, class: Class) -> &Budget {
        // Indexed by the enum discriminant; COUNT entries.
        &self.budgets[class as usize]
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
        self.auth
            .dropped()
            .saturating_add(self.in_dialog.dropped())
            .saturating_add(self.unauth.dropped())
            .saturating_add(self.bearer.dropped())
            .saturating_add(self.bearer_subject.dropped())
    }

    /// Events folded into over-budget summaries (metric
    /// `sbc_signaling_audit_over_budget_total`).
    #[must_use]
    pub fn over_budget(&self) -> u64 {
        self.budgets
            .iter()
            .map(|b| b.over_total.load(Ordering::Relaxed))
            .sum()
    }

    /// Every exported counter as `(gauge name, help, value)`. The uc-metrics
    /// gauges are refreshed through `&self`, which cannot set labels, so each
    /// bounded label value is its own gauge:
    /// `sbc_digest_verify_<outcome>_total` (14),
    /// `sbc_in_dialog_rejects_<policy>_total` (10),
    /// `sbc_source_admission_rejects_total`,
    /// `sbc_bearer_register_failures_total`,
    /// `sbc_signaling_audit_over_budget_total` and
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
        out.push((
            METRIC_SOURCE_ADMISSION_REJECTS,
            self.source_admission_rejects.load(Ordering::Relaxed),
        ));
        out.push((
            METRIC_BEARER_REGISTER_FAILURES,
            self.bearer_failures.load(Ordering::Relaxed),
        ));
        out.push((METRIC_OVER_BUDGET, self.over_budget()));
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
        if let Some(count) = self.auth.record_seen(&key, reason, now, seen)
            && self.immediate(Class::Auth, count, ip, &key, &aor)
        {
            emit_auth_failure(&aor, ip, reason, count);
        }
    }

    /// Audits an in-dialog rejection as a denied `AuthorizationDecision`
    /// (rate limited per source IP and policy). The record's resource is the
    /// Request-URI followed by the request's Call-ID (capped at
    /// [`MAX_AUDIT_CALL_ID_BYTES`]) and source port, so the rejected request
    /// can be tied to its call and flow (AU-3) without a schema change.
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
        // Percent-encoded, so a Call-ID cannot imitate the record's own
        // `key=value` fields (it may contain spaces and `=`).
        let call_id = percent_encode(req.headers.call_id().unwrap_or(""));
        let call_id = capped(&call_id, MAX_AUDIT_CALL_ID_BYTES);
        let ruri = req.uri.to_string();
        let ruri = capped(
            &ruri,
            MAX_AUDIT_FIELD_BYTES.saturating_sub(MAX_AUDIT_CALL_ID_BYTES + 32),
        );
        let resource = audit_field(&format!(
            "{ruri} call-id={call_id} src-port={}",
            source.port()
        ));
        self.reject_with_resource(req, source, policy.as_str(), now, resource);
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
        self.reject_with_resource(req, source, policy, now, audit_field(&req.uri.to_string()));
    }

    /// [`Self::signaling_reject`] with a caller-built (sanitized) resource.
    fn reject_with_resource(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        policy: &'static str,
        now: Instant,
        resource: String,
    ) {
        let ip = source.ip();
        let key = ip.to_string();
        let subject = audit_field(&subject_of(req, source));
        let action = audit_field(req.method.as_str());
        let ctx = format!("{action}{CTX_SEP}{subject}{CTX_SEP}{resource}");
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &ctx,
        };
        if let Some(count) = self.in_dialog.record_seen(&key, policy, now, seen)
            && self.immediate(Class::InDialog, count, ip, &key, &subject)
        {
            emit_denied(
                subject,
                resource,
                action,
                policy.to_owned(),
                count,
                Some(ip),
            );
        }
    }

    /// Audits an INVITE refused by source admission (403) as a denied
    /// `AuthorizationDecision` (policy `source-admission`, identity the From
    /// URI, resource the Request-URI, both capped by [`audit_field`]),
    /// rate limited per (source prefix, policy). An aggregated record adds
    /// `;prefix=<key>`.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, SC-5; RFC 3261 §21.4.4
    pub fn source_admission_reject(&self, req: &SipRequest, source: SbcSocketAddr, now: Instant) {
        self.source_admission_rejects
            .fetch_add(1, Ordering::Relaxed);
        let ip = source.ip();
        let key = prefix_key(ip);
        let subject = audit_field(&subject_of(req, source));
        let resource = audit_field(&req.uri.to_string());
        let action = audit_field(req.method.as_str());
        let ctx = format!("{action}{CTX_SEP}{subject}{CTX_SEP}{resource}");
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &ctx,
        };
        if let Some(count) = self
            .unauth
            .record_seen(&key, SOURCE_ADMISSION_POLICY, now, seen)
            && self.immediate(Class::Source, count, ip, &key, &subject)
        {
            emit_denied(
                subject,
                resource,
                action,
                with_count_prefix(SOURCE_ADMISSION_POLICY, count, &key),
                1,
                Some(ip),
            );
        }
    }

    /// Audits a failed bearer REGISTER as a failed `AuthenticationAttempt`
    /// (method `Jwt`, `failure_reason` `bearer:<reason>`), rate limited per
    /// (source prefix, reason). `reason` is the RFC 6750 §3.1 error code
    /// (`BearerError::as_param`) or `forbidden`; no token or verifier detail
    /// reaches the record. A `Forbidden` with a known subject goes through
    /// [`Self::bearer_forbidden`] instead.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, SC-5; RFC 6750 §3.1, RFC 8898 §3
    pub fn bearer_failure(
        &self,
        aor: &str,
        source: SbcSocketAddr,
        reason: &'static str,
        now: Instant,
    ) {
        self.bearer_failures.fetch_add(1, Ordering::Relaxed);
        let ip = source.ip();
        let key = prefix_key(ip);
        let reason = bearer_reason(reason);
        let aor = audit_field(aor);
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &aor,
        };
        if let Some(count) = self.bearer.record_seen(&key, reason, now, seen)
            && self.immediate(Class::Bearer, count, ip, &key, &aor)
        {
            emit_bearer_failure(&aor, ip, &with_count_prefix(reason, count, &key));
        }
    }

    /// Audits a bearer `Forbidden` (the token verified, but its subject may
    /// not register the AOR): identity is the authenticated subject `dn`,
    /// `failure_reason` is `bearer:forbidden;aor=<percent-encoded AOR>`.
    /// Keyed by (source prefix, subject), so one subject's attempts from one
    /// prefix aggregate and distinct subjects stay attributable.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-3 (subject of the event), AU-12, SC-5; RFC 8898 §3
    pub fn bearer_forbidden(&self, dn: &str, aor: &str, source: SbcSocketAddr, now: Instant) {
        self.bearer_failures.fetch_add(1, Ordering::Relaxed);
        let ip = source.ip();
        let dn = audit_field(dn);
        let aor = percent_encode(aor);
        let key = format!("{}|{dn}", prefix_key(ip));
        let ctx = format!("{dn}{CTX_SEP}{aor}");
        let seen = Seen {
            source_ip: Some(ip),
            call_id_hash: &ctx,
        };
        if let Some(count) = self
            .bearer_subject
            .record_seen(&key, BEARER_FORBIDDEN, now, seen)
            && self.immediate(Class::BearerSubject, count, ip, &key, &dn)
        {
            let prefix = key.split('|').next().unwrap_or_default();
            let stem = format!("{BEARER_FORBIDDEN};aor={aor}");
            emit_bearer_failure(&dn, ip, &with_count_prefix(&stem, count, prefix));
        }
    }

    /// Admits a first-per-key event within the immediate share.
    fn immediate(
        &self,
        class: Class,
        count: u64,
        ip: std::net::IpAddr,
        key: &str,
        identity: &str,
    ) -> bool {
        self.budget(class).admit(
            IMMEDIATE_BUDGET,
            &Folded {
                count,
                ip: Some(ip),
                key,
                identity,
            },
        )
    }

    /// Admits a flushed count within the full budget.
    fn flushed(&self, class: Class, p: &uc_sti::aggregate::Pending, identity: &str) -> bool {
        self.budget(class).admit(
            EMIT_BUDGET_PER_WINDOW,
            &Folded {
                count: p.count,
                ip: p.last_source_ip,
                key: &p.trunk,
                identity,
            },
        )
    }

    /// Pending counts of `agg`, highest first, so the most active sources
    /// get the flush budget.
    fn pending_by_count(agg: &FailureAggregator, now: Instant) -> Vec<uc_sti::aggregate::Pending> {
        let mut v = agg.flush_at_most(now, FLUSH_MAX_PER_CLASS);
        v.sort_unstable_by_key(|p| std::cmp::Reverse(p.count));
        v
    }

    /// Writes and resets the over-budget summary of `class`: total count,
    /// number of keys, and the highest folded `key/identity/count`
    /// (percent-encoded, at most [`SUMMARY_TOP`]).
    fn emit_over_budget(&self, class: Class) {
        let Some((count, keys, ip, top)) = self.budget(class).take_over() else {
            return;
        };
        let top = top
            .iter()
            .map(|(k, i, n)| format!("{k}/{i}/{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let label = format!(
            "{};count={count};keys={keys};top={top}",
            class.over_budget_label()
        );
        tracing::warn!(
            class = class.over_budget_label(),
            count,
            keys,
            "signaling audit emit budget exceeded; events folded into one summary record"
        );
        match class {
            Class::Auth | Class::Bearer | Class::BearerSubject => {
                let method = if matches!(class, Class::Bearer | Class::BearerSubject) {
                    uc_audit::event::AuthMethod::Jwt
                } else {
                    uc_audit::event::AuthMethod::Digest
                };
                uc_audit::log_event(uc_audit::AuditEvent::AuthenticationAttempt(
                    uc_audit::event::AuthenticationAttempt {
                        identity: "*".to_owned(),
                        source_ip: ip
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        success: false,
                        failure_reason: Some(label),
                        method,
                    },
                ));
            }
            Class::InDialog | Class::Source => {
                emit_denied("*".to_owned(), "*".to_owned(), "*".to_owned(), label, 1, ip);
            }
        }
    }

    /// Emits one event per key whose window closed with suppressed
    /// failures (at most [`FLUSH_MAX_PER_CLASS`] keys per class, within the
    /// class's emit budget), each class's over-budget summary, and one
    /// `AuditRecordsDropped` for events lost to a full table since the
    /// previous flush (AU-5).
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
        // Flushed counts, highest first, use what is left of this window's
        // budget (at least the flush reserve); then the summary of what was
        // folded, then a new window.
        for p in Self::pending_by_count(&self.auth, now) {
            if let Some(ip) = p.last_source_ip
                && self.flushed(Class::Auth, &p, &p.last_call_id_hash)
            {
                emit_auth_failure(&p.last_call_id_hash, ip, p.reason, p.count);
            }
        }
        for p in Self::pending_by_count(&self.in_dialog, now) {
            let mut parts = p.last_call_id_hash.splitn(3, CTX_SEP);
            let action = parts.next().unwrap_or_default().to_owned();
            let subject = parts.next().unwrap_or_default().to_owned();
            let resource = parts.next().unwrap_or_default().to_owned();
            if self.flushed(Class::InDialog, &p, &subject) {
                emit_denied(
                    subject,
                    resource,
                    action,
                    p.reason.to_owned(),
                    p.count,
                    p.last_source_ip,
                );
            }
        }
        for p in Self::pending_by_count(&self.unauth, now) {
            let mut parts = p.last_call_id_hash.splitn(3, CTX_SEP);
            let action = parts.next().unwrap_or_default().to_owned();
            let subject = parts.next().unwrap_or_default().to_owned();
            let resource = parts.next().unwrap_or_default().to_owned();
            if self.flushed(Class::Source, &p, &subject) {
                emit_denied(
                    subject,
                    resource,
                    action,
                    with_count_prefix(p.reason, p.count, &p.trunk),
                    1,
                    p.last_source_ip,
                );
            }
        }
        for p in Self::pending_by_count(&self.bearer, now) {
            let Some(ip) = p.last_source_ip else { continue };
            if self.flushed(Class::Bearer, &p, &p.last_call_id_hash) {
                emit_bearer_failure(
                    &p.last_call_id_hash,
                    ip,
                    &with_count_prefix(p.reason, p.count, &p.trunk),
                );
            }
        }
        for p in Self::pending_by_count(&self.bearer_subject, now) {
            let Some(ip) = p.last_source_ip else { continue };
            // Context is the subject, then the encoded AOR.
            let (dn, aor) = p
                .last_call_id_hash
                .split_once(CTX_SEP)
                .unwrap_or((p.last_call_id_hash.as_str(), ""));
            if self.flushed(Class::BearerSubject, &p, dn) {
                let prefix = p.trunk.split('|').next().unwrap_or_default();
                let stem = format!("{};aor={aor}", p.reason);
                emit_bearer_failure(dn, ip, &with_count_prefix(&stem, p.count, prefix));
            }
        }
        for class in Class::ALL {
            self.emit_over_budget(class);
            self.budget(class).emitted.store(0, Ordering::Relaxed);
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

fn emit_bearer_failure(identity: &str, ip: std::net::IpAddr, failure_reason: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthenticationAttempt(
        uc_audit::event::AuthenticationAttempt {
            identity: identity.to_owned(),
            source_ip: ip,
            success: false,
            failure_reason: Some(failure_reason.to_owned()),
            method: uc_audit::event::AuthMethod::Jwt,
        },
    ));
}

fn emit_denied(
    identity: String,
    resource: String,
    action: String,
    policy: String,
    count: u64,
    source_ip: Option<std::net::IpAddr>,
) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity,
            resource,
            action,
            granted: false,
            policy: if count > 1 {
                with_count(&policy, count)
            } else {
                policy
            },
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
        assert_eq!(
            flushed.resource,
            "sip:bob@192.0.2.10 call-id=x@test src-port=5060"
        );
    }

    /// NIST-04: the in-dialog reject record names the Call-ID (capped) and
    /// the source port, and stays within the field cap.
    #[test]
    fn in_dialog_reject_record_carries_bounded_call_id_and_port() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let long = format!("{}@test", "c".repeat(4000));
        a.in_dialog_reject(
            &req(&long),
            src(2),
            InDialogPolicy::ForeignSource,
            Instant::now(),
        );
        let d = cap
            .events()
            .into_iter()
            .find_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .unwrap();
        assert!(d.resource.len() <= MAX_AUDIT_FIELD_BYTES, "{}", d.resource);
        let cid = d
            .resource
            .split("call-id=")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .unwrap();
        assert_eq!(cid.len(), MAX_AUDIT_CALL_ID_BYTES);
        assert!(d.resource.ends_with("src-port=5060"), "{}", d.resource);
    }

    /// SEC-12: a Call-ID with spaces and `=` cannot forge the port field.
    #[test]
    fn in_dialog_reject_call_id_cannot_forge_fields() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        a.in_dialog_reject(
            &req("x src-port=1 y"),
            src(3),
            InDialogPolicy::ForeignSource,
            Instant::now(),
        );
        let d = cap
            .events()
            .into_iter()
            .find_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            d.resource,
            "sip:bob@192.0.2.10 call-id=x%20src-port%3D1%20y src-port=5060"
        );
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

    // ── SR-42a (QA-first): unauthenticated rejects (source admission,
    // bearer REGISTER) aggregated per (source prefix, policy) in their own
    // table. NIST 800-53 Rev5: AU-3, AU-4, AU-5, SC-5 ──

    fn invite(from_user: &str, ruri_user: &str) -> SipRequest {
        let raw = format!(
            "INVITE sip:{ruri_user}@192.0.2.10 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.7;branch=z9hG4bK-1\r\n\
             From: <sip:{from_user}@example.com>;tag=a\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: inv@test\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        );
        match proto_sip::SipMessage::parse(raw.as_bytes()) {
            Ok(proto_sip::SipMessage::Request(r)) => r,
            other => panic!("parse: {other:?}"),
        }
    }

    fn authz(events: &[AuditEvent]) -> Vec<uc_audit::event::AuthorizationDecision> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d.clone()),
                _ => None,
            })
            .collect()
    }

    fn auth_attempts(events: &[AuditEvent]) -> Vec<uc_audit::event::AuthenticationAttempt> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuthenticationAttempt(a) => Some(a.clone()),
                _ => None,
            })
            .collect()
    }

    fn v6(s: &str) -> SbcSocketAddr {
        SbcSocketAddr::from(std::net::SocketAddr::new(s.parse().unwrap(), 5060))
    }

    fn metric(a: &SignalingAudit, name: &str) -> u64 {
        a.metric_values()
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no metric {name}"))
            .1
    }

    /// Plan 8: 100 INVITEs from 100 rotating sources inside one /24 are one
    /// `AuthorizationDecision` (same record shape as before: policy
    /// `source-admission`, action INVITE, From / R-URI), then one flushed
    /// record with `;count=99` carrying the last exact source IP. Another
    /// /24 is its own key.
    #[test]
    fn source_admission_flood_from_rotating_ips_in_one_prefix_is_one_event_then_flushed_count() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let r = invite("mallory", "911");
        for last in 1..=100u8 {
            a.source_admission_reject(&r, src(last), t0);
        }
        let first = authz(&cap.events());
        assert_eq!(first.len(), 1, "{first:?}");
        let d = &first[0];
        assert_eq!(d.policy, "source-admission");
        assert_eq!(d.action, "INVITE");
        assert!(!d.granted);
        assert_eq!(d.identity, "sip:mallory@example.com");
        assert_eq!(d.resource, "sip:911@192.0.2.10");
        assert_eq!(d.source_ip, Some(src(1).ip()));

        let other = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 101, 1), 5060);
        a.source_admission_reject(&r, other, t0);
        assert_eq!(authz(&cap.events()).len(), 2, "another /24 is another key");

        a.flush(t0 + Duration::from_secs(61));
        let all = authz(&cap.events());
        assert_eq!(all.len(), 3, "{all:?}");
        assert_eq!(
            all[2].policy,
            "source-admission;count=99;prefix=198.51.100.0/24"
        );
        assert_eq!(
            all[2].source_ip,
            Some(src(100).ip()),
            "last exact IP is kept"
        );
        assert_eq!(all[2].identity, "sip:mallory@example.com");
        assert_eq!(all[2].resource, "sip:911@192.0.2.10");
        assert_eq!(metric(&a, "sbc_source_admission_rejects_total"), 101);
    }

    /// Plan 8: IPv6 sources aggregate by /64.
    #[test]
    fn source_admission_v6_keys_by_64() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let r = invite("mallory", "bob");
        for s in [
            "2001:db8:0:1::1",
            "2001:db8:0:1:ffff:ffff:ffff:fffe",
            "2001:db8:0:1:1234::9",
        ] {
            a.source_admission_reject(&r, v6(s), t0);
        }
        assert_eq!(authz(&cap.events()).len(), 1, "one /64 is one key");
        a.source_admission_reject(&r, v6("2001:db8:0:2::1"), t0);
        assert_eq!(authz(&cap.events()).len(), 2, "next /64 is another key");
        a.flush(t0 + Duration::from_secs(61));
        let all = authz(&cap.events());
        let flushed: Vec<_> = all[2..].iter().map(|d| d.policy.as_str()).collect();
        assert_eq!(
            flushed,
            ["source-admission;count=2;prefix=2001:db8:0:1::/64"]
        );
        assert_eq!(all[2].source_ip, Some(v6("2001:db8:0:1:1234::9").ip()));
    }

    /// Plan 8: From and Request-URI at the parser's size limits (and with
    /// control characters) are capped at MAX_AUDIT_FIELD_BYTES and
    /// stripped, in the immediate and the flushed record.
    #[test]
    fn source_admission_fields_capped_and_control_stripped() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let mut r = invite("x", &"u".repeat(4000));
        r.headers.set(
            HeaderName::From,
            format!("<sip:{}\u{1f}\r\n@example.com>;tag=a", "f".repeat(7900)),
        );
        for last in 1..=3u8 {
            a.source_admission_reject(&r, src(last), t0);
        }
        a.flush(t0 + Duration::from_secs(61));
        let all = authz(&cap.events());
        assert_eq!(all.len(), 2);
        for d in &all {
            assert!(
                d.identity.len() <= MAX_AUDIT_FIELD_BYTES,
                "{}",
                d.identity.len()
            );
            assert!(
                d.resource.len() <= MAX_AUDIT_FIELD_BYTES,
                "{}",
                d.resource.len()
            );
            assert!(
                !d.identity.chars().any(char::is_control),
                "{:?}",
                d.identity
            );
            assert!(d.identity.starts_with("sip:fff"));
            assert!(d.resource.starts_with("sip:uuu"));
            assert!(d.policy.len() <= 64);
        }
    }

    /// Plan 8: bearer REGISTER failures are `AuthenticationAttempt`s with
    /// method Jwt and the static RFC 6750 label (`bearer:<error>` or
    /// `bearer:forbidden`), aggregated per (source prefix, label).
    #[test]
    fn bearer_failure_reasons_static_and_aggregated() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let aor = "sip:alice@example.com";
        for _ in 0..20 {
            a.bearer_failure(aor, src(1), "invalid_token", t0);
        }
        // Same /24, other host: the same key.
        a.bearer_failure(aor, src(2), "invalid_token", t0);
        for reason in ["invalid_request", "insufficient_scope", "forbidden"] {
            a.bearer_failure(aor, src(1), reason, t0);
        }
        let first = auth_attempts(&cap.events());
        let reasons: Vec<_> = first
            .iter()
            .map(|e| e.failure_reason.clone().unwrap())
            .collect();
        assert_eq!(
            reasons,
            [
                "bearer:invalid_token",
                "bearer:invalid_request",
                "bearer:insufficient_scope",
                "bearer:forbidden"
            ]
        );
        for e in &first {
            assert!(!e.success);
            assert_eq!(e.method, uc_audit::event::AuthMethod::Jwt);
            assert_eq!(e.identity, aor);
        }
        a.flush(t0 + Duration::from_secs(61));
        let all = auth_attempts(&cap.events());
        assert_eq!(all.len(), 5);
        assert_eq!(
            all[4].failure_reason.as_deref(),
            Some("bearer:invalid_token;count=20;prefix=198.51.100.0/24")
        );
        assert_eq!(all[4].source_ip, src(2).ip());
        assert_eq!(metric(&a, "sbc_bearer_register_failures_total"), 24);
        // Bearer failures are not digest outcomes.
        assert!(a.digest_outcome_counts().all(|(_, n)| n == 0));
    }

    /// Plan 8: a bearer `Forbidden` is audited with the static label only;
    /// the AOR is capped and control-stripped; nothing else from the
    /// request or token reaches the record.
    #[test]
    fn bearer_forbidden_detail_not_in_audit() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let aor = format!("sip:{}\u{1f}\r\n@example.com", "a".repeat(600));
        a.bearer_failure(&aor, src(5), "forbidden", Instant::now());
        let e = auth_attempts(&cap.events());
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].failure_reason.as_deref(), Some("bearer:forbidden"));
        assert!(e[0].identity.len() <= MAX_AUDIT_FIELD_BYTES);
        assert!(!e[0].identity.chars().any(char::is_control));
        let json = serde_json::to_string(&cap.events()[0]).unwrap();
        assert!(!json.contains("dn"), "{json}");
    }

    /// Plan 8: the unauthenticated-reject table is separate: filling it
    /// (counted drops) neither evicts nor blocks digest and in-dialog keys.
    #[test]
    fn unauth_table_full_does_not_evict_digest_or_in_dialog_keys() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let bad = DigestOutcome::Reject(DigestReject::BadResponse);
        let aor = "sip:alice@example.com";
        let msg = req("k@test");
        a.digest(aor, src(1), bad, t0);
        a.in_dialog_reject(&msg, src(1), InDialogPolicy::UnknownDialog, t0);

        let inv = invite("m", "bob");
        let over = 10usize;
        for i in 0..uc_sti::aggregate::MAX_KEYS + over {
            let ip = std::net::Ipv4Addr::from(0x0b00_0000_u32 + (u32::try_from(i).unwrap() << 8));
            a.source_admission_reject(&inv, SbcSocketAddr::new_v4(ip, 5060), t0);
        }
        assert_eq!(a.dropped(), over as u64);

        // Existing keys still aggregate (suppressed, not re-emitted) ...
        a.digest(aor, src(1), bad, t0);
        a.in_dialog_reject(&msg, src(1), InDialogPolicy::UnknownDialog, t0);
        // ... and new digest / in-dialog sources still get a record.
        a.digest(aor, src(7), bad, t0);
        a.in_dialog_reject(&msg, src(7), InDialogPolicy::UnknownDialog, t0);
        let ev = cap.events();
        assert_eq!(
            auth_failures(&ev),
            ["digest:bad_response", "digest:bad_response"]
        );
        let in_dialog: Vec<_> = denied(&ev)
            .into_iter()
            .filter(|p| p.starts_with("in-dialog"))
            .collect();
        assert_eq!(
            in_dialog,
            ["in-dialog:unknown-dialog", "in-dialog:unknown-dialog"]
        );

        a.flush(t0 + Duration::from_secs(61));
        let ev = cap.events();
        assert_eq!(auth_failures(&ev).len(), 3, "src(1) digest key flushed");
        let drops: Vec<u64> = ev
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuditRecordsDropped(d) => Some(d.count),
                _ => None,
            })
            .collect();
        assert_eq!(drops, [over as u64]);
    }

    /// Plan 8: `/metrics` exports the two unauth counters, and the unauth
    /// table's drops are part of `sbc_signaling_audit_dropped_total`.
    #[test]
    fn metric_values_include_unauth_counters() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let _cap = uc_audit::capture::start();
        let t0 = Instant::now();
        assert_eq!(metric(&a, "sbc_source_admission_rejects_total"), 0);
        assert_eq!(metric(&a, "sbc_bearer_register_failures_total"), 0);
        let inv = invite("m", "bob");
        for last in 1..=3u8 {
            a.source_admission_reject(&inv, src(last), t0);
        }
        a.bearer_failure("sip:a@example.com", src(1), "invalid_token", t0);
        a.bearer_failure("sip:a@example.com", src(1), "forbidden", t0);
        assert_eq!(metric(&a, "sbc_source_admission_rejects_total"), 3);
        assert_eq!(metric(&a, "sbc_bearer_register_failures_total"), 2);

        let b = SignalingAudit::new(Duration::from_secs(60));
        for i in 0..=uc_sti::aggregate::MAX_KEYS {
            let ip = std::net::Ipv4Addr::from(0x0c00_0000_u32 + (u32::try_from(i).unwrap() << 8));
            b.source_admission_reject(&inv, SbcSocketAddr::new_v4(ip, 5060), t0);
        }
        assert_eq!(b.dropped(), 1);
        assert_eq!(metric(&b, METRIC_DROPPED), 1);
        // Names are unique (one gauge each).
        let names: Vec<_> = a.metric_values().into_iter().map(|(n, _)| n).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), names.len());
    }

    // ── SR-42 round 1 ──

    /// SEC-001: beyond EMIT_BUDGET_PER_WINDOW records a class folds its
    /// events into one over-budget summary per flush; counts are kept.
    /// NIST 800-53 Rev5: SC-5, AU-4
    #[test]
    fn emit_budget_folds_excess_into_one_summary() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let inv = invite("m", "bob");
        let n = 300u32;
        for i in 0..n {
            let ip = std::net::Ipv4Addr::from(0x0d00_0000_u32 + (i << 8));
            a.source_admission_reject(&inv, SbcSocketAddr::new_v4(ip, 5060), t0);
        }
        let first = authz(&cap.events());
        assert_eq!(first.len() as u64, IMMEDIATE_BUDGET, "flush reserve kept");
        a.flush(t0 + Duration::from_secs(61));
        let all = authz(&cap.events());
        let summary: Vec<_> = all
            .iter()
            .filter(|d| d.policy.starts_with("source-admission:over-budget"))
            .collect();
        assert_eq!(summary.len(), 1, "{all:?}");
        let over = u64::from(n) - IMMEDIATE_BUDGET;
        assert!(
            summary[0].policy.starts_with(&format!(
                "source-admission:over-budget;count={over};keys={over};top="
            )),
            "{}",
            summary[0].policy
        );
        assert_eq!(summary[0].identity, "*");
        assert!(summary[0].source_ip.is_some());
        assert_eq!(metric(&a, METRIC_OVER_BUDGET), over);
        // Other classes are not affected by this class's budget.
        a.digest(
            "sip:a@x",
            src(1),
            DigestOutcome::Reject(DigestReject::BadResponse),
            t0,
        );
        assert_eq!(auth_failures(&cap.events()).len(), 1);
    }

    /// SEC-002: a source-admission flood that fills its table does not
    /// block bearer failure records (own table).
    #[test]
    fn bearer_table_is_separate_from_source_admission() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let inv = invite("m", "bob");
        for i in 0..=uc_sti::aggregate::MAX_KEYS {
            let ip = std::net::Ipv4Addr::from(0x0e00_0000_u32 + (u32::try_from(i).unwrap() << 8));
            a.source_admission_reject(&inv, SbcSocketAddr::new_v4(ip, 5060), t0);
        }
        assert_eq!(a.dropped(), 1);
        a.bearer_failure("sip:a@example.com", src(9), "invalid_token", t0);
        let b = auth_attempts(&cap.events());
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].failure_reason.as_deref(), Some("bearer:invalid_token"));
    }

    /// SEC-003: a bearer Forbidden names the authenticated subject, with the
    /// AOR percent-encoded in the reason; aggregated per (prefix, subject).
    /// NIST 800-53 Rev5: AU-3
    #[test]
    fn bearer_forbidden_records_subject_per_prefix_and_dn() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        for _ in 0..5 {
            a.bearer_forbidden("alice", "sip:bob;x=1@example.com", src(1), t0);
        }
        a.bearer_forbidden("carol\u{1f}\r\n", "sip:bob@example.com", src(2), t0);
        let e = auth_attempts(&cap.events());
        assert_eq!(e.len(), 2, "{e:?}");
        assert_eq!(e[0].identity, "alice");
        assert_eq!(
            e[0].failure_reason.as_deref(),
            Some("bearer:forbidden;aor=sip:bob%3Bx%3D1@example.com")
        );
        assert_eq!(e[0].method, uc_audit::event::AuthMethod::Jwt);
        assert_eq!(e[1].identity, "carol");
        a.flush(t0 + Duration::from_secs(61));
        let e = auth_attempts(&cap.events());
        assert_eq!(e.len(), 3);
        assert_eq!(e[2].identity, "alice");
        assert_eq!(
            e[2].failure_reason.as_deref(),
            Some("bearer:forbidden;aor=sip:bob%3Bx%3D1@example.com;count=4;prefix=198.51.100.0/24")
        );
    }

    /// NIST-012: the throttle lets one line through per second and counts
    /// the rest.
    #[test]
    fn log_throttle_allows_one_line_per_second() {
        let t = LogThrottle::new();
        assert_eq!(t.allow(), Some(0));
        assert_eq!(t.allow(), None);
        assert_eq!(t.allow(), None);
    }

    /// SEC-013 (round 2): a one-shot flood of spoofed sources uses up the
    /// immediate share, but a sustained real source still gets its own
    /// record, with its identity and count, from the flush reserve (pending
    /// counts are flushed highest first). The summary names the top keys.
    /// NIST 800-53 Rev5: AU-3, SC-5
    #[test]
    fn sustained_source_survives_one_shot_flood_with_identity() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        let bad = DigestOutcome::Reject(DigestReject::BadResponse);
        for i in 0..2_000u32 {
            let ip = std::net::Ipv4Addr::from(0x0f00_0000_u32 + i);
            a.digest("sip:junk@x", SbcSocketAddr::new_v4(ip, 5060), bad, t0);
        }
        let real = src(77);
        for _ in 0..50 {
            a.digest("sip:alice@example.com", real, bad, t0);
        }
        a.flush(t0 + Duration::from_secs(61));
        let ev = auth_attempts(&cap.events());
        let mine: Vec<_> = ev
            .iter()
            .filter(|e| e.identity == "sip:alice@example.com")
            .collect();
        assert_eq!(mine.len(), 1, "{mine:?}");
        assert_eq!(mine[0].source_ip, real.ip());
        assert_eq!(
            mine[0].failure_reason.as_deref(),
            Some("digest:bad_response;count=49")
        );
        let summary: Vec<_> = ev
            .iter()
            .filter_map(|e| e.failure_reason.as_deref())
            .filter(|r| r.starts_with("digest:over-budget"))
            .collect();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains(";top="), "{}", summary[0]);
        let total: usize = ev.len();
        assert!(total as u64 <= EMIT_BUDGET_PER_WINDOW + 1, "{total}");
    }

    /// SEC-013 (round 2): Forbidden-with-subject has its own table and
    /// budget: unauthenticated bearer junk cannot fold a verified subject.
    #[test]
    fn bearer_subject_class_is_separate() {
        let a = SignalingAudit::new(Duration::from_secs(60));
        let cap = uc_audit::capture::start();
        let t0 = Instant::now();
        for i in 0..1_000u32 {
            let ip = std::net::Ipv4Addr::from(0x1000_0000_u32 + (i << 8));
            a.bearer_failure(
                "sip:x@y",
                SbcSocketAddr::new_v4(ip, 5060),
                "invalid_token",
                t0,
            );
        }
        a.bearer_forbidden("alice", "sip:bob@example.com", src(3), t0);
        let e = auth_attempts(&cap.events());
        assert!(e.iter().any(|x| x.identity == "alice"), "subject folded");
    }
}
