//! Management-plane audit records shared by sbc-api-server and
//! central-config-api.
//!
//! - Every privileged write emits one `ConfigurationChange` whose `admin`
//!   is the canonical actor id and whose `description` is a fixed
//!   `key=value` grammar:
//!   `entity=<e> id=<id> op=<op> outcome=<ok|failed> [reason=<r>]
//!   [site=<s>] [<detail>=<v> ...] [iss=<iss>] [user=<display>] [src=<ip>]`.
//! - Login successes are recorded per event; auth failures are rate limited
//!   per (client IP, reason) by a bounded [`FailureAggregator`], so an
//!   unauthenticated client cannot flood the audit log.
//!
//! Variable fields are sanitised ([`audit_field`]) and whitespace in them is
//! replaced, so a caller-supplied id, path or name cannot add or repeat a
//! key.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5, AC-7, SI-10, SC-5

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::StatusCode;
use uc_audit::aggregate::{FailureAggregator, Seen};
use uc_audit::event::{
    AuditDropReason, AuditRecordsDropped, AuthMethod, AuthenticationAttempt, ConfigChangeType,
    ConfigurationChange,
};
use uc_audit::{AuditEvent, log_event};

/// Longest variable field kept in a record, in bytes.
pub const MAX_FIELD_BYTES: usize = 128;
/// Longest actor id kept, in bytes: the audit `admin` field and the
/// `<actor>` of a store's `updated_by = 'local:<actor>'` share this cap.
pub const MAX_ACTOR_BYTES: usize = 250;
/// Auth-failure aggregation window per (client IP, reason).
pub const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// How often callers should run [`flush_auth_failures`]. Shorter than the
/// window, so a closed window's count is reported within 5 s; each run is
/// still capped at [`MAX_FLUSH_RECORDS`].
pub const AUTH_FAILURE_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// First emissions per second across every aggregated class (burst of one
/// second's worth). Past it a first emission is suppressed and counted in
/// [`budget_suppressed`], never queued.
pub const MAX_FIRST_EMISSIONS_PER_SEC: u64 = 256;
/// Detail keys whose value is an actor id: capped at [`MAX_ACTOR_BYTES`]
/// instead of [`MAX_FIELD_BYTES`].
const ACTOR_DETAIL_KEYS: [&str; 1] = ["claimed_origin_actor"];

/// Who made a management-plane request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// Canonical actor id: `oidc:<sub>@<iss>`, `admin:<subject>`,
    /// `apikey:<id>` or `site:<sub>`. Recorded as the event's `admin`.
    pub id: String,
    /// Token issuer, when the credential has one.
    pub issuer: Option<String>,
    /// Display name (e.g. `preferred_username`); informational only.
    pub display: Option<String>,
    /// Resolved client IP.
    pub source_ip: Option<IpAddr>,
}

/// The operation a write performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// New entity.
    Create,
    /// Existing entity changed (or upsert).
    Update,
    /// Entity removed.
    Delete,
    /// A named action (reboot, terminate, `tls_reload`, register, ...).
    Action(&'static str),
}

impl Op {
    /// The `op=` token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Action(a) => a,
        }
    }
}

/// How a write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Applied.
    Ok,
    /// Not applied, with a fixed reason token (`invalid`, `not_found`,
    /// `conflict`, `storage`, `daemon_unavailable`, `rejected`,
    /// `forbidden`).
    Failed(&'static str),
}

impl Outcome {
    /// Maps a response status: 2xx is `Ok`, anything else a failure with a
    /// reason derived from the status class.
    #[must_use]
    pub fn from_status(status: StatusCode) -> Self {
        if status.is_success() {
            return Self::Ok;
        }
        Self::Failed(match status {
            StatusCode::BAD_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE => "invalid",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "forbidden",
            StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => "daemon_unavailable",
            StatusCode::METHOD_NOT_ALLOWED => "rejected",
            s if s.is_server_error() => "storage",
            _ => "rejected",
        })
    }
}

/// Strips control characters (C0, DEL, C1) and caps the result at
/// [`MAX_FIELD_BYTES`] on a char boundary.
///
/// ## NIST 800-53 Rev5: SI-10 (no log injection through audit fields)
#[must_use]
pub fn audit_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_FIELD_BYTES));
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_FIELD_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// [`audit_field`] for an actor id, capped at [`MAX_ACTOR_BYTES`].
#[must_use]
pub fn actor_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_ACTOR_BYTES));
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_ACTOR_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// [`audit_field`] with whitespace replaced by `_`, so the value stays one
/// token of the description grammar. Empty values become `-`.
fn token(s: &str) -> String {
    let v: String = audit_field(s)
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    if v.is_empty() { "-".to_string() } else { v }
}

/// [`token`] for an actor id: [`actor_field`] (250 B cap), whitespace
/// replaced.
fn actor_token(s: &str) -> String {
    let v: String = actor_field(s)
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    if v.is_empty() { "-".to_string() } else { v }
}

/// Emits one `ConfigurationChange` for a management-plane write.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5
// POAM: POA&M-427 (AU-3) entity, id, op, outcome and issuer are key=value
// text in `description`, not structured fields; SIEM parsing is needed.
pub fn config_change(
    actor: &Actor,
    entity: &'static str,
    id: &str,
    op: Op,
    outcome: Outcome,
    site: Option<&str>,
) {
    emit_change(actor, entity, id, op, outcome, site, &[]);
}

/// [`config_change`] with extra `key=value` detail appended after the
/// fixed fields (e.g. `kind=partitions`, `table=phones`). Keys are fixed
/// tokens chosen by the caller; values are sanitised.
pub fn config_change_detail(
    actor: &Actor,
    entity: &'static str,
    id: &str,
    op: Op,
    outcome: Outcome,
    site: Option<&str>,
    detail: &[(&'static str, &str)],
) {
    emit_change(actor, entity, id, op, outcome, site, detail);
}

/// Router backstop record for a write no handler audited:
/// `entity=route id=<route> op=<METHOD> outcome=<..> status=<code>`.
/// `route` is the matched route template, not the raw path.
///
/// ## NIST 800-53 Rev5: AU-2, AU-12, CM-3
pub fn route_write(actor: &Actor, route: &str, method: &'static str, status: StatusCode) {
    let code = status.as_u16().to_string();
    emit_change(
        actor,
        "route",
        route,
        Op::Action(method),
        Outcome::from_status(status),
        None,
        &[("status", &code)],
    );
}

fn emit_change(
    actor: &Actor,
    entity: &'static str,
    id: &str,
    op: Op,
    outcome: Outcome,
    site: Option<&str>,
    detail: &[(&'static str, &str)],
) {
    let mut d = format!(
        "entity={} id={} op={} outcome=",
        token(entity),
        token(id),
        token(op.as_str())
    );
    match outcome {
        Outcome::Ok => d.push_str("ok"),
        Outcome::Failed(r) => {
            let _ = write!(d, "failed reason={}", token(r));
        }
    }
    if let Some(s) = site {
        let _ = write!(d, " site={}", token(s));
    }
    for (k, v) in detail {
        let v = if ACTOR_DETAIL_KEYS.contains(k) {
            actor_token(v)
        } else {
            token(v)
        };
        let _ = write!(d, " {}={v}", token(k));
    }
    if let Some(i) = &actor.issuer {
        let _ = write!(d, " iss={}", token(i));
    }
    if let Some(u) = &actor.display {
        let _ = write!(d, " user={}", token(u));
    }
    if let Some(ip) = actor.source_ip {
        let _ = write!(d, " src={ip}");
    }
    log_event(AuditEvent::ConfigurationChange(ConfigurationChange {
        admin: actor_field(&actor.id),
        change_type: ConfigChangeType::Modified,
        description: d,
    }));
}

fn auth_event(identity: &str, ip: IpAddr, method: AuthMethod, failure: Option<String>) {
    log_event(AuditEvent::AuthenticationAttempt(AuthenticationAttempt {
        identity: audit_field(identity),
        source_ip: ip,
        success: failure.is_none(),
        failure_reason: failure,
        method,
    }));
}

/// Records a successful management-plane authentication (not aggregated).
///
/// ## NIST 800-53 Rev5: AC-7, IA-2, AU-2
pub fn auth_success(identity: &str, ip: IpAddr, method: AuthMethod) {
    auth_event(identity, ip, method, None);
}

/// The credential type of a rejected bearer or cookie, without trusting it:
/// a cookie or a `v2.` token is a session token, three dot-separated
/// segments a JWT, anything else an API key.
#[must_use]
pub fn credential_method(credential: &str, from_cookie: bool) -> AuthMethod {
    if from_cookie || credential.starts_with("v2.") {
        AuthMethod::Session
    } else if credential.split('.').count() == 3 {
        AuthMethod::Jwt
    } else {
        AuthMethod::ApiKey
    }
}

/// Most aggregated records one [`flush_auth_failures`] call emits; the rest
/// stay pending for the next call, so a flush cannot fill the audit queue.
pub const MAX_FLUSH_RECORDS: usize = 256;

/// Separate bounded key tables, so cheap noise in one class (bad bearers,
/// busy refusals, malformed bodies) cannot evict the keys of another
/// (wrong passwords, lockouts).
#[derive(Clone, Copy)]
enum Class {
    /// `invalid_credentials` (bounded upstream by the login guard).
    Credentials,
    /// `rate_limited` (lockout 429).
    Lockout,
    /// `busy`, `invalid_format`.
    LoginNoise,
    /// Token rejects: `invalid_token`, `insufficient_scope`, `wrong_site`.
    Token,
    /// Unauthenticated writes refused before authorization.
    Body,
}

/// Flush order: the most security-relevant classes first.
const CLASSES: [Class; 5] = [
    Class::Credentials,
    Class::Lockout,
    Class::LoginNoise,
    Class::Token,
    Class::Body,
];

const fn class_of(reason: &str) -> Class {
    match reason.as_bytes() {
        b"invalid_credentials" => Class::Credentials,
        b"rate_limited" => Class::Lockout,
        b"busy" | b"invalid_format" => Class::LoginNoise,
        _ => Class::Token,
    }
}

/// One aggregator per class, created on first use.
static TABLES: [LazyLock<FailureAggregator>; 5] =
    [const { LazyLock::new(|| FailureAggregator::new(AUTH_FAILURE_WINDOW)) }; 5];
/// Aggregator drops plus budget suppressions already reported by
/// [`flush_auth_failures`].
static DROPS_REPORTED: AtomicU64 = AtomicU64::new(0);

/// Process-wide limit on first emissions (GCRA token bucket, lock-free):
/// `tat_ns` is the theoretical arrival time, in ns since [`EPOCH`], of the
/// next conforming emission.
///
/// ## NIST 800-53 Rev5: AU-4, AU-5, SC-5
struct EmitBudget {
    tat_ns: AtomicU64,
    suppressed: AtomicU64,
}

impl EmitBudget {
    const INTERVAL_NS: u64 = 1_000_000_000 / MAX_FIRST_EMISSIONS_PER_SEC;
    /// One second of tolerance: a burst of `MAX_FIRST_EMISSIONS_PER_SEC`.
    const BURST_NS: u64 = 1_000_000_000;

    const fn new() -> Self {
        Self {
            tat_ns: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Takes one emission at `now_ns`; `false` (and counted) past the
    /// budget.
    fn try_take(&self, now_ns: u64) -> bool {
        let mut cur = self.tat_ns.load(Ordering::Relaxed);
        loop {
            let tat = cur.max(now_ns);
            // GCRA: conforming while at most a burst minus one interval ahead.
            if tat - now_ns > Self::BURST_NS - Self::INTERVAL_NS {
                self.suppressed.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            let next = tat.saturating_add(Self::INTERVAL_NS);
            match self
                .tat_ns
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }
}

static BUDGET: EmitBudget = EmitBudget::new();
/// Time origin of [`BUDGET`].
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Whether a first emission at `now` fits the process-wide budget.
fn first_emission_allowed(now: Instant) -> bool {
    let ns = now.saturating_duration_since(*EPOCH).as_nanos();
    BUDGET.try_take(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// First emissions suppressed by the process-wide budget so far (metric;
/// reported with the table drops by [`flush_auth_failures`]).
#[must_use]
pub fn budget_suppressed() -> u64 {
    BUDGET.suppressed.load(Ordering::Relaxed)
}

fn table(c: Class) -> &'static FailureAggregator {
    &TABLES[c as usize]
}

/// A small stack string, so a suppressed failure allocates nothing.
struct StackStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackStr<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Appends whole chars while they fit; returns `false` once full.
    fn push(&mut self, c: char) -> bool {
        let mut tmp = [0u8; 4];
        let enc = c.encode_utf8(&mut tmp).as_bytes();
        let Some(dst) = self.buf.get_mut(self.len..self.len + enc.len()) else {
            return false;
        };
        dst.copy_from_slice(enc);
        self.len += enc.len();
        true
    }

    fn as_str(&self) -> &str {
        self.buf
            .get(..self.len)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or_default()
    }
}

impl<const N: usize> std::fmt::Write for StackStr<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        for c in s.chars() {
            if !self.push(c) {
                return Err(std::fmt::Error);
            }
        }
        Ok(())
    }
}

/// Aggregation key: the client bucket (IPv6 /64, unmapped IPv4).
fn bucket(ip: IpAddr) -> StackStr<48> {
    let mut k = StackStr::new();
    let _ = write!(k, "{}", crate::bucket_key(ip));
    k
}

/// `<method>|<sanitised identity>`, carried on the slot so a flushed record
/// still names the latest failure's method and identity.
fn context(method: AuthMethod, identity: &str) -> StackStr<{ MAX_FIELD_BYTES + 8 }> {
    let mut c = StackStr::new();
    let _ = write!(c, "{}|", method_token(method));
    for ch in identity.chars().filter(|ch| !ch.is_control()) {
        if c.len + ch.len_utf8() > MAX_FIELD_BYTES + 2 || !c.push(ch) {
            break;
        }
    }
    c
}

const fn method_token(m: AuthMethod) -> &'static str {
    match m {
        AuthMethod::Digest => "d",
        AuthMethod::TlsCertificate => "t",
        AuthMethod::ApiKey => "k",
        AuthMethod::Jwt => "j",
        AuthMethod::Password => "p",
        AuthMethod::Session => "s",
    }
}

fn method_from_token(t: &str) -> AuthMethod {
    match t {
        "d" => AuthMethod::Digest,
        "t" => AuthMethod::TlsCertificate,
        "k" => AuthMethod::ApiKey,
        "p" => AuthMethod::Password,
        "s" => AuthMethod::Session,
        _ => AuthMethod::Jwt,
    }
}

/// Records a failed management-plane authentication.
///
/// The first failure per (client bucket, reason) per window is emitted at
/// once with the full client IP; later ones are counted and carried as
/// `"<reason> count=<n>"` on the next emission or by
/// [`flush_auth_failures`]. Reasons: `invalid_credentials`, `rate_limited`,
/// `busy`, `invalid_format`, `invalid_token`, `insufficient_scope`,
/// `wrong_site`. Emissions past [`MAX_FIRST_EMISSIONS_PER_SEC`] are
/// suppressed and counted.
///
/// ## NIST 800-53 Rev5: AC-7, AU-2, AU-4, SC-5
pub fn auth_failure(identity: &str, ip: IpAddr, method: AuthMethod, reason: &'static str) {
    let key = bucket(ip);
    let ctx = context(method, identity);
    let seen = Seen {
        source_ip: Some(ip),
        call_id_hash: ctx.as_str(),
    };
    let now = Instant::now();
    let Some(n) = table(class_of(reason)).record_seen(key.as_str(), reason, now, seen) else {
        return;
    };
    if !first_emission_allowed(now) {
        return;
    }
    if n == 1 {
        auth_event(identity, ip, method, Some(reason.to_string()));
    } else {
        auth_event(identity, ip, method, Some(format!("{reason} count={n}")));
    }
}

/// Actor of a write refused before authorization.
const UNAUTHENTICATED: &str = "unauthenticated";

/// Records a write refused before authorization (malformed or oversize
/// body).
///
/// One `ConfigurationChange` with actor `unauthenticated` and reason
/// `invalid`, aggregated per client bucket like an auth failure, so an
/// unauthenticated client cannot flood the log.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, SC-5
pub fn rejected_write(
    ip: IpAddr,
    entity: &'static str,
    op: Op,
    site: Option<&str>,
    status: StatusCode,
) {
    let key = bucket(ip);
    let seen = Seen {
        source_ip: Some(ip),
        call_id_hash: entity,
    };
    let now = Instant::now();
    let Some(n) = table(Class::Body).record_seen(key.as_str(), "invalid_body", now, seen) else {
        return;
    };
    if !first_emission_allowed(now) {
        return;
    }
    let actor = Actor {
        id: UNAUTHENTICATED.to_string(),
        issuer: None,
        display: None,
        source_ip: Some(ip),
    };
    let code = status.as_u16().to_string();
    let count = n.to_string();
    let mut detail: Vec<(&'static str, &str)> = vec![("status", &code)];
    if n > 1 {
        detail.push(("count", &count));
    }
    emit_change(
        &actor,
        entity,
        "-",
        op,
        Outcome::Failed("invalid"),
        site,
        &detail,
    );
}

/// Minimum share of one flush's [`MAX_FLUSH_RECORDS`] per class.
const FLUSH_SHARE: usize = MAX_FLUSH_RECORDS / CLASSES.len();

/// Emits the suppressed counts whose window has closed by `now`, at most
/// [`MAX_FLUSH_RECORDS`] per call (the rest stay pending).
///
/// Each class first gets [`FLUSH_SHARE`] records, so a backlog in one
/// class cannot starve another; the unused remainder then goes to the
/// classes still pending, most security-relevant first.
///
/// Also emits one `AuditRecordsDropped` with the number of records not
/// written since the previous flush: failures dropped because a key table
/// was full, plus first emissions over [`MAX_FIRST_EMISSIONS_PER_SEC`]. Run
/// every [`AUTH_FAILURE_FLUSH_INTERVAL`].
///
/// ## NIST 800-53 Rev5: AU-5, SC-5
// POAM: POA&M-438 (AU-5) both drop causes share `AuditDropReason::Aggregated`; a distinct
// reason for the budget needs a uc-audit event change.
pub fn flush_auth_failures(now: Instant) {
    let mut left = MAX_FLUSH_RECORDS;
    for class in CLASSES {
        let pending = table(class).flush_at_most(now, FLUSH_SHARE.min(left));
        left -= pending.len().min(left);
        emit_flushed(class, pending);
    }
    for class in CLASSES {
        if left == 0 {
            break;
        }
        let pending = table(class).flush_at_most(now, left);
        left -= pending.len().min(left);
        emit_flushed(class, pending);
    }
    let table_drops: u64 = CLASSES.iter().map(|c| table(*c).dropped()).sum();
    let total = table_drops.saturating_add(budget_suppressed());
    let prev = DROPS_REPORTED.swap(total, Ordering::Relaxed);
    if total > prev {
        log_event(AuditEvent::AuditRecordsDropped(AuditRecordsDropped {
            count: total - prev,
            total,
            reason: AuditDropReason::Aggregated,
        }));
    }
}

/// One record per flushed key of `class`.
fn emit_flushed(class: Class, pending: Vec<uc_audit::aggregate::Pending>) {
    for p in pending {
        let ip = p
            .last_source_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        if matches!(class, Class::Body) {
            flushed_rejected_writes(ip, &p.last_call_id_hash, p.count);
            continue;
        }
        let (m, identity) = p
            .last_call_id_hash
            .split_once('|')
            .unwrap_or(("j", "unknown"));
        auth_event(
            identity,
            ip,
            method_from_token(m),
            Some(format!("{} count={}", p.reason, p.count)),
        );
    }
}

/// The suppressed tail of [`rejected_write`] records for one client bucket.
fn flushed_rejected_writes(ip: IpAddr, last_entity: &str, count: u64) {
    let actor = Actor {
        id: UNAUTHENTICATED.to_string(),
        issuer: None,
        display: None,
        source_ip: Some(ip),
    };
    let count = count.to_string();
    emit_change(
        &actor,
        "rejected_write",
        "-",
        Op::Action("write"),
        Outcome::Failed("invalid"),
        None,
        &[("last_entity", last_entity), ("count", &count)],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_from_status_classes() {
        assert_eq!(Outcome::from_status(StatusCode::CREATED), Outcome::Ok);
        assert_eq!(
            Outcome::from_status(StatusCode::NOT_FOUND),
            Outcome::Failed("not_found")
        );
        assert_eq!(
            Outcome::from_status(StatusCode::SERVICE_UNAVAILABLE),
            Outcome::Failed("daemon_unavailable")
        );
        assert_eq!(
            Outcome::from_status(StatusCode::INTERNAL_SERVER_ERROR),
            Outcome::Failed("storage")
        );
    }

    #[test]
    fn credential_method_classifies_without_trusting() {
        assert_eq!(credential_method("anything", true), AuthMethod::Session);
        assert_eq!(credential_method("v2.a.b", false), AuthMethod::Session);
        assert_eq!(credential_method("a.b.c", false), AuthMethod::Jwt);
        assert_eq!(credential_method("not-a-token", false), AuthMethod::ApiKey);
    }

    #[test]
    fn keys_and_context_fit_stack_buffers() {
        let ip: IpAddr = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bucket(ip).as_str(), "2001:db8:ffff:ffff::");
        let mapped: IpAddr = "::ffff:192.0.2.9"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bucket(mapped).as_str(), "192.0.2.9");
        let long = "\u{e9}".repeat(200);
        let c = context(AuthMethod::Password, &long);
        assert!(c.as_str().starts_with("p|"));
        assert!(c.as_str().len() <= MAX_FIELD_BYTES + 2);
        assert_eq!(context(AuthMethod::Jwt, "a\r\nb").as_str(), "j|ab");
    }

    /// SR-40 round 2 (SEC-008): a burst of one second's budget, then one
    /// per interval; refusals are counted.
    #[test]
    fn emit_budget_bursts_then_refills() {
        let b = EmitBudget::new();
        let t0 = 5_000_000_000;
        let burst = (0..1000).filter(|_| b.try_take(t0)).count();
        assert_eq!(
            u64::try_from(burst).unwrap_or(0),
            MAX_FIRST_EMISSIONS_PER_SEC
        );
        assert_eq!(
            b.suppressed.load(Ordering::Relaxed),
            1000 - MAX_FIRST_EMISSIONS_PER_SEC
        );
        assert!(!b.try_take(t0 + EmitBudget::INTERVAL_NS / 2));
        assert!(b.try_take(t0 + EmitBudget::INTERVAL_NS));
        assert!(!b.try_take(t0 + EmitBudget::INTERVAL_NS));
        let later = t0 + 10 * EmitBudget::BURST_NS;
        let refilled = (0..1000).filter(|_| b.try_take(later)).count();
        assert_eq!(
            u64::try_from(refilled).unwrap_or(0),
            MAX_FIRST_EMISSIONS_PER_SEC
        );
    }

    /// SR-40 round 2 (SEC-010): an actor-valued detail keeps 250 bytes.
    #[test]
    fn actor_detail_uses_actor_cap() {
        assert_eq!(actor_token(&"a".repeat(400)).len(), MAX_ACTOR_BYTES);
        assert_eq!(token(&"a".repeat(400)).len(), MAX_FIELD_BYTES);
        assert_eq!(actor_token("local:a b\r\n"), "local:a_b");
    }

    #[test]
    fn actor_cap_is_shared() {
        assert_eq!(actor_field(&"x".repeat(400)).len(), MAX_ACTOR_BYTES);
    }

    #[test]
    fn method_token_round_trips() {
        for m in [
            AuthMethod::Digest,
            AuthMethod::TlsCertificate,
            AuthMethod::ApiKey,
            AuthMethod::Jwt,
            AuthMethod::Password,
            AuthMethod::Session,
        ] {
            assert_eq!(method_from_token(method_token(m)), m);
        }
    }
}
