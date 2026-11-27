//! CRL revocation checking on the daemon's TLS paths (SR-29, POA&M-401
//! phase (a); `docs/TLS-REVOCATION-DESIGN.md`).
//!
//! | Role | Path | CRL key |
//! |---|---|---|
//! | `sip_tls` | SIP-TLS listener, mTLS client certificates (V1) | `security.tls_crl_path` |
//! | `trunk_tls` | trunk egress TLS and mTLS (V2, V3; one shared verifier) | `security.trunk_tls_crl_path` |
//! | `srs_tls` | SIPREC recorder TLS (V4) | `recording.srs_tls_crl_file` |
//! | `cdr_syslog` | CDR syslog, RFC 5425 (V5) | `cdr.syslog.crl_path` |
//!
//! The policy is `[security.revocation]` for every role (D6);
//! `client_unknown` applies to `sip_tls`, `server_unknown` to the rest.
//! CRLs are loaded once at startup ([`load`]); a new CRL needs a restart
//! (D5). A CRL already past `nextUpdate` at startup does not stop the
//! daemon: it is logged and audited, and with `expired_crl = "reject"`
//! (D1) every handshake that needs it fails, so that path fails closed.
//!
//! Each rejected handshake increments
//! `tls_revocation_rejections_total{role,reason}`; the audit record
//! `TlsPeerCertificateRejected` is aggregated per (role, reason) over
//! [`AUDIT_WINDOW`] so a peer retrying a revoked certificate cannot flood
//! the audit trail.
//!
//! With no CRL configured nothing here runs and every TLS path behaves as
//! before.
//!
//! ## NIST 800-53 Rev5: IA-5(2), IA-3, SC-17, SC-23, AU-2, AU-3, AU-4, SI-4

use sbc_config::schema::{
    ExpiredCrlPolicy, RevocationCheckDepth, RevocationConfig, RevocationUnknown,
};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use uc_audit::aggregate::{FailureAggregator, Seen};
use uc_transport::RevocationFailure;
use uc_transport::revocation::{
    CheckDepth, CrlSet, ExpiredCrl, Revocation, RevocationPolicy, UnknownStatus,
};

/// CRL sets above this size are logged as a warning at load: the CRL
/// signature is checked on every full handshake, linear in its size
/// (SC-5).
pub const LARGE_CRL_BYTES: usize = 8 * 1024 * 1024;

/// Aggregation window of `TlsPeerCertificateRejected`.
pub const AUDIT_WINDOW: Duration = Duration::from_secs(60);

/// Rejections by role and reason (gauge mirroring a monotonic counter).
pub const METRIC_REJECTIONS: &str = "tls_revocation_rejections_total";
/// 1 when the role has CRLs loaded.
pub const METRIC_ENABLED: &str = "tls_revocation_enabled";
/// Seconds until the role's earliest CRL `nextUpdate` (negative once
/// passed; 0 when the role has no CRL or the CRL has no `nextUpdate`).
pub const METRIC_NEXT_UPDATE: &str = "tls_crl_next_update_seconds";

/// A TLS path with its own CRL set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// SIP-TLS listener, mTLS client certificates (V1).
    SipTls,
    /// Trunk egress TLS and mTLS (V2, V3).
    TrunkTls,
    /// SIPREC recorder (V4).
    SrsTls,
    /// CDR syslog collector (V5).
    CdrSyslog,
}

impl Role {
    /// Every role, in metric order.
    pub const ALL: [Self; 4] = [Self::SipTls, Self::TrunkTls, Self::SrsTls, Self::CdrSyslog];

    /// Stable token for logs, audit and metric labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SipTls => "sip_tls",
            Self::TrunkTls => "trunk_tls",
            Self::SrsTls => "srs_tls",
            Self::CdrSyslog => "cdr_syslog",
        }
    }

    const fn idx(self) -> usize {
        match self {
            Self::SipTls => 0,
            Self::TrunkTls => 1,
            Self::SrsTls => 2,
            Self::CdrSyslog => 3,
        }
    }
}

const fn reason_idx(r: RevocationFailure) -> usize {
    match r {
        RevocationFailure::Revoked => 0,
        RevocationFailure::UnknownStatus => 1,
        RevocationFailure::CrlExpired => 2,
        RevocationFailure::CrlInvalid => 3,
    }
}

/// `i64::MIN`: no `nextUpdate` known for the role.
const NO_NEXT_UPDATE: i64 = i64::MIN;

struct State {
    rejections: [[AtomicU64; 4]; 4],
    enabled: [AtomicBool; 4],
    next_update: [AtomicI64; 4],
}

static STATE: State = State {
    rejections: [const { [const { AtomicU64::new(0) }; 4] }; 4],
    enabled: [const { AtomicBool::new(false) }; 4],
    next_update: [const { AtomicI64::new(NO_NEXT_UPDATE) }; 4],
};

static AGGREGATOR: LazyLock<FailureAggregator> =
    LazyLock::new(|| FailureAggregator::new(AUDIT_WINDOW));

/// The rustls policy of `role` from `[security.revocation]`.
#[must_use]
pub const fn policy_for(role: Role, cfg: RevocationConfig) -> RevocationPolicy {
    let unknown = match role {
        Role::SipTls => cfg.client_unknown,
        Role::TrunkTls | Role::SrsTls | Role::CdrSyslog => cfg.server_unknown,
    };
    RevocationPolicy {
        depth: match cfg.check_depth {
            RevocationCheckDepth::Chain => CheckDepth::Chain,
            RevocationCheckDepth::EndEntity => CheckDepth::EndEntity,
        },
        unknown: match unknown {
            RevocationUnknown::Deny => UnknownStatus::Deny,
            RevocationUnknown::Allow => UnknownStatus::Allow,
        },
        expired: match cfg.expired_crl {
            ExpiredCrlPolicy::Reject => ExpiredCrl::Reject,
            ExpiredCrlPolicy::Ignore => ExpiredCrl::Ignore,
        },
    }
}

fn policy_token(p: RevocationPolicy) -> String {
    format!(
        "{},{},{}",
        match p.depth {
            CheckDepth::Chain => "chain",
            CheckDepth::EndEntity => "end_entity",
        },
        match p.unknown {
            UnknownStatus::Deny => "deny",
            UnknownStatus::Allow => "allow",
        },
        match p.expired {
            ExpiredCrl::Reject => "reject",
            ExpiredCrl::Ignore => "ignore",
        },
    )
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Loads `role`'s CRLs from `path` with the `[security.revocation]`
/// policy, records the role as enabled, logs and audits the load
/// (`TlsRevocationListLoaded`).
///
/// A CRL past `nextUpdate` is not a load error (D1): it is logged at error
/// level (`expired_crl = "reject"`: the handshakes that need it fail) or
/// warning level (`"ignore"`).
///
/// # Errors
///
/// The CRL path cannot be loaded ([`CrlSet::load`]); the caller fails the
/// TLS path the same way it does for a bad CA bundle.
pub fn load(role: Role, path: &Path, cfg: RevocationConfig) -> Result<Revocation, String> {
    let set = CrlSet::load(path).map_err(|e| e.to_string())?;
    let policy = policy_for(role, cfg);
    let now = unix_now();
    let expired = set.expired_at(now).count();
    let next_update = set.earliest_next_update();
    STATE.enabled[role.idx()].store(true, Ordering::Relaxed);
    STATE.next_update[role.idx()].store(next_update.unwrap_or(NO_NEXT_UPDATE), Ordering::Relaxed);
    if set.der_bytes() > LARGE_CRL_BYTES {
        warn!(
            role = role.as_str(),
            path = %path.display(),
            bytes = set.der_bytes(),
            "CRL set is larger than 8 MiB: every TLS handshake on this path verifies it \
             (about 1 ms per MB); keep CRLs small where peers drive handshakes"
        );
    }
    if expired > 0 {
        match policy.expired {
            ExpiredCrl::Reject => error!(
                role = role.as_str(),
                path = %path.display(),
                expired,
                "CRL past nextUpdate: TLS handshakes that need it are refused until a \
                 fresh CRL is installed and the SBC is restarted"
            ),
            ExpiredCrl::Ignore => warn!(
                role = role.as_str(),
                path = %path.display(),
                expired,
                "CRL past nextUpdate is used anyway (security.revocation.expired_crl = \"ignore\")"
            ),
        }
    }
    info!(
        role = role.as_str(),
        path = %path.display(),
        crls = set.len(),
        revoked_entries = set.entries(),
        next_update = ?next_update,
        policy = %policy_token(policy),
        "TLS CRLs loaded (revocation checking on)"
    );
    uc_audit::log_event(uc_audit::AuditEvent::TlsRevocationListLoaded(
        uc_audit::event::TlsRevocationListLoaded {
            role: role.as_str().to_string(),
            path: path.display().to_string(),
            crl_count: set.len() as u64,
            revoked_entries: set.entries() as u64,
            next_update,
            expired_count: expired as u64,
            policy: policy_token(policy),
        },
    ));
    Ok(Revocation {
        crls: Arc::new(set),
        policy,
    })
}

/// [`load`] for an optional path: `Ok(None)` when no CRL is configured.
///
/// # Errors
///
/// As [`load`].
pub fn load_opt(
    role: Role,
    path: Option<&Path>,
    cfg: RevocationConfig,
) -> Result<Option<Revocation>, String> {
    path.map(|p| load(role, p, cfg)).transpose()
}

fn emit(role: &str, reason: &str, peer: Option<IpAddr>, count: u64) {
    warn!(
        role,
        reason,
        peer = ?peer,
        count,
        "TLS peer certificate rejected by the revocation check"
    );
    uc_audit::log_event(uc_audit::AuditEvent::TlsPeerCertificateRejected(
        uc_audit::event::TlsPeerCertificateRejected {
            role: role.to_string(),
            reason: reason.to_string(),
            peer,
            count,
        },
    ));
}

/// Counts one rejected handshake and audits it (aggregated per role and
/// reason over [`AUDIT_WINDOW`]).
pub fn note_rejection(role: Role, reason: RevocationFailure, peer: Option<IpAddr>) {
    STATE.rejections[role.idx()][reason_idx(reason)].fetch_add(1, Ordering::Relaxed);
    audit_rejection(&AGGREGATOR, role, reason, peer, Instant::now());
}

/// Audits one rejection through `agg` at `now`: emitted at once for the
/// first one of a (role, reason) window, counted otherwise.
fn audit_rejection(
    agg: &FailureAggregator,
    role: Role,
    reason: RevocationFailure,
    peer: Option<IpAddr>,
    now: Instant,
) {
    let seen = Seen {
        source_ip: peer,
        call_id_hash: "",
    };
    if let Some(count) = agg.record_seen(role.as_str(), reason.as_str(), now, seen) {
        emit(role.as_str(), reason.as_str(), peer, count);
    }
}

fn flush_from(agg: &FailureAggregator, now: Instant) {
    for p in agg.flush(now) {
        emit(&p.trunk, p.reason, p.last_source_ip, p.count);
    }
}

/// [`note_rejection`] when `err` is a revocation failure. Returns whether
/// it was one.
pub fn note_transport_error(
    role: Role,
    err: &uc_transport::TransportError,
    peer: Option<IpAddr>,
) -> bool {
    if let uc_transport::TransportError::TlsPeerCertificateRejected { reason, .. } = err {
        note_rejection(role, *reason, peer);
        true
    } else {
        false
    }
}

/// [`note_rejection`] for an `io::Error` wrapping a rustls error (the
/// blocking CDR syslog connector). Returns whether it was one.
pub fn note_io_error(role: Role, err: &std::io::Error, peer: Option<IpAddr>) -> bool {
    uc_transport::revocation::classify_io(err).is_some_and(|reason| {
        note_rejection(role, reason, peer);
        true
    })
}

/// Emits the suppressed counts of every (role, reason) whose window has
/// closed by `now`.
pub fn flush(now: Instant) {
    flush_from(&AGGREGATOR, now);
}

/// Spawns the periodic flush (once per window) until shutdown.
pub fn spawn_flush(shutdown: crate::shutdown::ShutdownSignal) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUDIT_WINDOW);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => flush(Instant::now()),
                () = shutdown.wait_for_shutdown() => {
                    flush(Instant::now());
                    break;
                }
            }
        }
    })
}

/// Rejections so far for (`role`, `reason`).
#[must_use]
pub fn rejections(role: Role, reason: RevocationFailure) -> u64 {
    STATE.rejections[role.idx()][reason_idx(reason)].load(Ordering::Relaxed)
}

/// Whether `role` has CRLs loaded.
#[must_use]
pub fn enabled(role: Role) -> bool {
    STATE.enabled[role.idx()].load(Ordering::Relaxed)
}

/// Registers the labelled gauges with every series created (bounded:
/// 4 roles x 4 reasons), so [`refresh_metrics`] can update them through a
/// shared reference.
///
/// ## NIST 800-53 Rev5: SI-4, SC-5 (bounded series)
pub fn register_metrics(metrics: &mut uc_metrics::MetricRegistry) {
    let rej = metrics.register_gauge_with_labels(
        METRIC_REJECTIONS,
        "TLS handshakes refused by the CRL revocation check, by role and reason",
        vec!["role".to_string(), "reason".to_string()],
    );
    for role in Role::ALL {
        for reason in RevocationFailure::ALL {
            rej.set_with_labels(&[role.as_str(), reason.as_str()], 0);
        }
    }
    let en = metrics.register_gauge_with_labels(
        METRIC_ENABLED,
        "1 when CRL revocation checking is on for the TLS role",
        vec!["role".to_string()],
    );
    for role in Role::ALL {
        en.set_with_labels(&[role.as_str()], 0);
    }
    let next = metrics.register_gauge_with_labels(
        METRIC_NEXT_UPDATE,
        "Seconds until the earliest CRL nextUpdate of the TLS role (negative once passed; \
         0 without a CRL)",
        vec!["role".to_string()],
    );
    for role in Role::ALL {
        next.set_with_labels(&[role.as_str()], 0);
    }
}

/// Copies the current counts into the gauges registered by
/// [`register_metrics`].
pub fn refresh_metrics(metrics: &uc_metrics::MetricRegistry) {
    let as_gauge = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    if let Some(g) = metrics.gauge(METRIC_REJECTIONS) {
        for role in Role::ALL {
            for reason in RevocationFailure::ALL {
                g.set_existing_with_labels(
                    &[role.as_str(), reason.as_str()],
                    as_gauge(rejections(role, reason)),
                );
            }
        }
    }
    if let Some(g) = metrics.gauge(METRIC_ENABLED) {
        for role in Role::ALL {
            g.set_existing_with_labels(&[role.as_str()], i64::from(enabled(role)));
        }
    }
    if let Some(g) = metrics.gauge(METRIC_NEXT_UPDATE) {
        let now = unix_now();
        for role in Role::ALL {
            let next = STATE.next_update[role.idx()].load(Ordering::Relaxed);
            let v = if next == NO_NEXT_UPDATE {
                0
            } else {
                next.saturating_sub(now)
            };
            g.set_existing_with_labels(&[role.as_str()], v);
        }
    }
}

/// Logs the configuration warnings of `[security.revocation]` that are not
/// errors: unknown client status allowed with mutual TLS on.
pub fn warn_on_config(sec: &sbc_config::schema::SecurityConfig) {
    if sec.require_mtls
        && sec.tls_crl_path.is_some()
        && sec.revocation.client_unknown == RevocationUnknown::Allow
    {
        warn!(
            "security.revocation.client_unknown = \"allow\": client certificates no CRL \
             covers are accepted on the SIP-TLS listener"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::field_reassign_with_default
)]
pub mod tests;
