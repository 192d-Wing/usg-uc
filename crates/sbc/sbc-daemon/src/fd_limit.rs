//! File-descriptor budget at startup (SR-57).
//!
//! Every accepted stream connection, egress connection, RTP socket and
//! listener holds a file descriptor. Before the server starts, the soft
//! `RLIMIT_NOFILE` is raised to the hard limit; if the configured connection
//! caps still do not fit, `transport.max_connections_total` (and the
//! per-listener and per-source caps with it) is clamped so accept, RTP binds
//! and DNS keep fds. The daemon refuses to start when fewer than
//! [`MIN_CONNECTIONS`] signaling connections would fit.
//!
//! A clamp is logged at `error!` and audited as a `ConfigurationChange`
//! (`Modified`); a refusal is audited as `SystemShutdown{graceful:false}`.
//!
//! ## NIST 800-53 Rev5: SC-5, SC-6, CM-6, AU-12

use crate::api_server::MAX_API_TLS_CONNECTIONS;
use crate::flows::DEFAULT_MAX_EGRESS_CONNECTIONS;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use sbc_config::SbcConfig;
use tracing::{error, info, warn};

/// Fds kept back for DNS, logs, the API and gRPC listeners and CDR files.
/// REST HTTPS connections are counted separately
/// ([`MAX_API_TLS_CONNECTIONS`]).
// POAM: POA&M-212 - the plain-HTTP REST listener has no connection cap, so
// its connections are outside this budget and can take fds from it.
const HEADROOM_FDS: u64 = 512;

/// Fewest signaling connections the daemon starts with. A floor for
/// starting at all, not a reservation within the pool.
pub const MIN_CONNECTIONS: u32 = 64;

/// First soft-limit target tried when the hard limit is not accepted as a
/// soft value (macOS reports `RLIM_INFINITY` but caps the soft limit at
/// `kern.maxfilesperproc`). Halved until `setrlimit` succeeds.
const FALLBACK_SOFT_START: u64 = 1 << 20;

/// Startup fd plan computed by [`plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdPlan {
    /// New soft `RLIMIT_NOFILE`, when below the hard limit.
    pub raise_soft_to: Option<u64>,
    /// New `transport.max_connections_total`, when the caps do not fit.
    pub clamp_total: Option<u32>,
    /// Fewer than [`MIN_CONNECTIONS`] connections fit: do not start.
    pub refuse: bool,
    /// Fd limit the plan was computed against.
    pub limit: u64,
    /// Fds the unclamped configuration needs ([`required_fds`]).
    pub required: u64,
}

/// SIP listener sockets (UDP, TCP, TLS, WS, WSS).
fn sip_listeners(config: &SbcConfig) -> u64 {
    let t = &config.transport;
    [
        t.udp_listen.len(),
        t.tcp_listen.len(),
        t.tls_listen.len(),
        t.ws_listen.len(),
        t.wss_listen.len(),
    ]
    .iter()
    .map(|&n| n as u64)
    .sum()
}

/// Fds the configuration needs: every stream connection, the egress pool,
/// one RTP socket per port when media is in-process, the SIP listeners, the
/// REST HTTPS connection cap and fixed headroom.
pub fn required_fds(config: &SbcConfig, local_media: bool) -> u64 {
    let media = if local_media {
        u64::from(config.media.rtp_port_max)
            .saturating_sub(u64::from(config.media.rtp_port_min))
            .saturating_add(1)
    } else {
        0
    };
    u64::from(config.transport.max_connections_total)
        .saturating_add(DEFAULT_MAX_EGRESS_CONNECTIONS as u64)
        .saturating_add(media)
        .saturating_add(sip_listeners(config))
        .saturating_add(MAX_API_TLS_CONNECTIONS as u64)
        .saturating_add(HEADROOM_FDS)
}

/// Plans the soft-limit raise and any cap clamp for `soft`/`hard`
/// `RLIMIT_NOFILE`. Pure.
pub fn plan(soft: u64, hard: u64, config: &SbcConfig, local_media: bool) -> FdPlan {
    let required = required_fds(config, local_media);
    let total = config.transport.max_connections_total;
    let mut p = FdPlan {
        raise_soft_to: (soft < hard).then_some(hard),
        clamp_total: None,
        refuse: false,
        limit: hard,
        required,
    };
    if required <= hard {
        return p;
    }
    let overhead = required - u64::from(total);
    let fit = hard.saturating_sub(overhead);
    if fit < u64::from(MIN_CONNECTIONS) {
        p.refuse = true;
    } else {
        // fit < total here, so it fits in u32.
        p.clamp_total = Some(u32::try_from(fit).unwrap_or(total));
    }
    p
}

/// Applies the cap part of `plan` to `config`: clamps
/// `max_connections_total`, and the per-listener and per-source caps to it,
/// logging at `error!` and auditing the change.
///
/// A refusal is audited as `SystemShutdown{graceful:false}`; the caller
/// flushes the audit queue before exiting.
///
/// # Errors
/// The plan refuses to start (fewer than [`MIN_CONNECTIONS`] fit).
pub fn apply_plan(config: &mut SbcConfig, plan: &FdPlan) -> Result<(), String> {
    if plan.refuse {
        let reason = format!(
            "RLIMIT_NOFILE {} leaves fewer than {MIN_CONNECTIONS} file descriptors for \
             signaling connections (configuration needs {}); raise the fd limit, narrow \
             media.rtp_port_min..rtp_port_max or lower transport.max_connections_total",
            plan.limit, plan.required
        );
        // NIST 800-53 Rev5: AU-2, AU-12 - the daemon stops before serving.
        uc_audit::log_event(uc_audit::AuditEvent::SystemShutdown(
            uc_audit::event::SystemShutdown {
                reason: format!("fd_limit: {reason}"),
                graceful: false,
            },
        ));
        return Err(reason);
    }
    let Some(total) = plan.clamp_total else {
        return Ok(());
    };
    let t = &mut config.transport;
    let (old_total, old_listener, old_source) = (
        t.max_connections_total,
        t.max_connections_per_listener,
        t.max_connections_per_source,
    );
    t.max_connections_total = total;
    t.max_connections_per_listener = old_listener.min(total);
    // Keep the validated per-source <= per-listener invariant.
    t.max_connections_per_source = old_source.min(t.max_connections_per_listener);
    let description = format!(
        "[transport] clamped to RLIMIT_NOFILE {limit} (configuration needs {required}): \
         max_connections_total {old_total} -> {total}, \
         max_connections_per_listener {old_listener} -> {listener}, \
         max_connections_per_source {old_source} -> {source}",
        limit = plan.limit,
        required = plan.required,
        listener = t.max_connections_per_listener,
        source = t.max_connections_per_source,
    );
    error!(
        limit = plan.limit,
        required = plan.required,
        max_connections_total = total,
        max_connections_per_listener = t.max_connections_per_listener,
        max_connections_per_source = t.max_connections_per_source,
        "File descriptor limit below the configured connection caps; caps clamped"
    );
    // NIST 800-53 Rev5: CM-6, AU-12 - the effective configuration differs
    // from the file.
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "startup".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Modified,
            description,
        },
    ));
    Ok(())
}

/// Finds the highest soft limit in `soft..=target` that `set` accepts.
/// Tries `target` first, then halves from [`FALLBACK_SOFT_START`] while the
/// candidate is above `soft`, then binary-searches between the last
/// accepted value (`soft` when none was) and the last refused value.
/// Returns the last accepted value (`soft` when none was).
fn search_soft(soft: u64, target: u64, mut set: impl FnMut(u64) -> bool) -> u64 {
    if set(target) {
        return target;
    }
    let mut refused = target;
    // `soft` is in effect already; refused calls leave the limit unchanged,
    // so the last accepted value (`lo`) is the one in effect.
    let mut lo = soft;
    let mut candidate = FALLBACK_SOFT_START.min(target / 2);
    while candidate > soft {
        if set(candidate) {
            lo = candidate;
            break;
        }
        refused = candidate;
        candidate /= 2;
    }
    let mut hi = refused;
    while hi.saturating_sub(lo) > 1 {
        let mid = lo + (hi - lo) / 2;
        if set(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Sets the soft `RLIMIT_NOFILE` to `target`, falling back to the highest
/// smaller value the kernel accepts. Returns the soft limit in effect
/// afterwards, as read back with `getrlimit`.
fn raise_soft(soft: u64, hard: u64, target: u64) -> u64 {
    let set = search_soft(soft, target, |v| {
        setrlimit(Resource::RLIMIT_NOFILE, v, hard).is_ok()
    });
    // The kernel may round or cap the value; trust what it reports.
    let effective = getrlimit(Resource::RLIMIT_NOFILE).map_or(set, |(s, _)| s);
    if effective <= soft {
        warn!(soft, hard, "Could not raise the soft RLIMIT_NOFILE");
    }
    effective
}

/// Raises the soft `RLIMIT_NOFILE` and fits the connection caps to the fd
/// limit. Runs once, before the server is built.
///
/// # Errors
/// `getrlimit` fails, or fewer than [`MIN_CONNECTIONS`] connections fit.
pub fn apply(config: &mut SbcConfig, local_media: bool) -> Result<(), String> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|e| format!("getrlimit(RLIMIT_NOFILE) failed: {e}"))?;
    let wanted = plan(soft, hard, config, local_media);
    let effective = wanted
        .raise_soft_to
        .map_or(soft, |target| raise_soft(soft, hard, target));
    let p = if effective == wanted.limit {
        wanted
    } else {
        plan(effective, effective, config, local_media)
    };
    if effective != soft {
        info!(
            from = soft,
            to = effective,
            hard,
            "Raised soft RLIMIT_NOFILE"
        );
    }
    apply_plan(config, &p)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flows::DEFAULT_MAX_EGRESS_CONNECTIONS;
    use sbc_config::SbcConfig;

    /// Fds kept back for DNS, logs, the API and gRPC listeners, CDR files.
    const HEADROOM: u64 = 512;
    /// REST HTTPS connection cap (`api_server::MAX_API_TLS_CONNECTIONS`).
    const API_TLS: u64 = 256;
    /// Refuse to start below this many signaling connections.
    const FLOOR: u32 = 64;

    fn sip_listeners(c: &SbcConfig) -> u64 {
        let t = &c.transport;
        (t.udp_listen.len()
            + t.tcp_listen.len()
            + t.tls_listen.len()
            + t.ws_listen.len()
            + t.wss_listen.len()) as u64
    }

    fn media_ports(c: &SbcConfig) -> u64 {
        u64::from(c.media.rtp_port_max) - u64::from(c.media.rtp_port_min) + 1
    }

    /// Everything `required_fds` counts except `max_connections_total`.
    fn overhead(c: &SbcConfig, local_media: bool) -> u64 {
        DEFAULT_MAX_EGRESS_CONNECTIONS as u64
            + if local_media { media_ports(c) } else { 0 }
            + sip_listeners(c)
            + API_TLS
            + HEADROOM
    }

    // ---- required_fds ----

    #[test]
    fn required_fds_counts_conns_egress_media_and_headroom() {
        let c = SbcConfig::default();
        // Defaults: 20000 connections, 1024 egress, RTP 16384..=32768,
        // udp + tcp + tls listeners, 256 REST HTTPS connections, 512
        // headroom.
        assert_eq!(c.transport.max_connections_total, 20_000);
        assert_eq!(sip_listeners(&c), 3);
        assert_eq!(media_ports(&c), 16_385);
        assert_eq!(MAX_API_TLS_CONNECTIONS as u64, API_TLS);
        assert_eq!(
            required_fds(&c, true),
            20_000 + 1024 + 16_385 + 3 + 256 + 512
        );
        assert_eq!(required_fds(&c, true), 38_180);
    }

    #[test]
    fn required_fds_remote_media_has_no_rtp_ports() {
        let c = SbcConfig::default();
        assert_eq!(required_fds(&c, false), 20_000 + 1024 + 3 + 256 + 512);
    }

    #[test]
    fn required_fds_tracks_listeners_media_range_and_total() {
        let mut c = SbcConfig::default();
        let base = required_fds(&c, true);
        c.transport
            .ws_listen
            .push("127.0.0.1:5066".parse().unwrap());
        assert_eq!(required_fds(&c, true), base + 1, "one more listener");
        c.media.rtp_port_min = 20_000;
        c.media.rtp_port_max = 20_099;
        assert_eq!(
            required_fds(&c, true),
            u64::from(c.transport.max_connections_total) + overhead(&c, true)
        );
        assert_eq!(overhead(&c, true), 1024 + 100 + 4 + 256 + 512);
        c.transport.max_connections_total = 500;
        assert_eq!(required_fds(&c, false), 500 + 1024 + 4 + 256 + 512);
    }

    // ---- plan (pure) ----

    #[test]
    fn plan_raises_soft_to_hard() {
        let c = SbcConfig::default();
        let p = plan(1024, 1_048_576, &c, true);
        assert_eq!(p.raise_soft_to, Some(1_048_576));
        assert_eq!(p.clamp_total, None);
        assert!(!p.refuse);
    }

    #[test]
    fn plan_does_not_raise_when_soft_is_hard() {
        let c = SbcConfig::default();
        let p = plan(1_048_576, 1_048_576, &c, true);
        assert_eq!(p.raise_soft_to, None);
        assert_eq!(p.clamp_total, None);
        assert!(!p.refuse);
    }

    #[test]
    fn plan_unlimited_hard_never_clamps() {
        // RLIM_INFINITY is u64::MAX on Linux and macOS; no overflow, no clamp.
        let c = SbcConfig::default();
        let p = plan(1024, u64::MAX, &c, true);
        assert_eq!(p.clamp_total, None);
        assert!(!p.refuse);
    }

    #[test]
    fn plan_exact_fit_does_not_clamp() {
        let c = SbcConfig::default();
        let hard = required_fds(&c, true);
        let p = plan(hard, hard, &c, true);
        assert_eq!(p.clamp_total, None);
        assert!(!p.refuse);
        let p = plan(hard - 1, hard - 1, &c, true);
        assert_eq!(p.clamp_total, Some(c.transport.max_connections_total - 1));
    }

    #[test]
    fn plan_clamps_total_when_hard_too_low() {
        let c = SbcConfig::default();
        let required = required_fds(&c, false);
        let total = u64::from(c.transport.max_connections_total);
        let p = plan(1024, 8192, &c, false);
        let want = 8192 - (required - total);
        assert_eq!(want, 6397);
        assert_eq!(p.clamp_total, Some(u32::try_from(want).unwrap()));
        assert_eq!(p.raise_soft_to, Some(8192));
        assert!(!p.refuse);
    }

    #[test]
    fn plan_refuses_below_floor() {
        let c = SbcConfig::default();
        // Local media alone (16385 RTP ports) exceeds 2048 fds.
        let p = plan(1024, 2048, &c, true);
        assert!(p.refuse);
    }

    #[test]
    fn plan_floor_boundary_is_64_connections() {
        let c = SbcConfig::default();
        let over = overhead(&c, false);
        let p = plan(over + u64::from(FLOOR), over + u64::from(FLOOR), &c, false);
        assert_eq!(p.clamp_total, Some(FLOOR));
        assert!(!p.refuse, "exactly 64 connections still starts");
        let p = plan(
            over + u64::from(FLOOR) - 1,
            over + u64::from(FLOOR) - 1,
            &c,
            false,
        );
        assert!(p.refuse, "63 connections refuses to start");
    }

    // ---- apply_plan: clamp both caps, error! + audit ----

    #[test]
    fn apply_plan_clamps_both_caps_and_audits() {
        let mut c = SbcConfig::default();
        let p = plan(1024, 8192, &c, false);
        let capture = uc_audit::capture::start();
        apply_plan(&mut c, &p).unwrap();
        assert_eq!(c.transport.max_connections_total, 6397);
        assert!(
            c.transport.max_connections_per_listener <= c.transport.max_connections_total,
            "per-listener cap {} must not exceed the clamped total {}",
            c.transport.max_connections_per_listener,
            c.transport.max_connections_total
        );
        assert!(
            capture.events().iter().any(|e| matches!(
                e,
                uc_audit::AuditEvent::ConfigurationChange(cc)
                    if cc.change_type == uc_audit::event::ConfigChangeType::Modified
                        && cc.description.contains("max_connections_total")
                        && cc.description.contains("6397")
            )),
            "clamp must emit ConfigurationChange{{Modified}} naming the key and value"
        );
    }

    #[test]
    fn apply_plan_keeps_smaller_per_listener_cap() {
        let mut c = SbcConfig::default();
        c.transport.max_connections_per_listener = 5000;
        let p = plan(1024, 8192, &c, false);
        apply_plan(&mut c, &p).unwrap();
        assert_eq!(c.transport.max_connections_total, 6397);
        assert_eq!(c.transport.max_connections_per_listener, 5000);
    }

    #[test]
    fn apply_plan_without_clamp_changes_nothing_and_does_not_audit() {
        let mut c = SbcConfig::default();
        let before = c.clone();
        let p = plan(1024, 1_048_576, &c, true);
        let capture = uc_audit::capture::start();
        apply_plan(&mut c, &p).unwrap();
        assert_eq!(c, before);
        assert!(
            !capture
                .events()
                .iter()
                .any(|e| matches!(e, uc_audit::AuditEvent::ConfigurationChange(_))),
            "no clamp, no configuration-change record"
        );
    }

    #[test]
    fn apply_plan_refusal_is_an_error() {
        let mut c = SbcConfig::default();
        let p = plan(1024, 2048, &c, true);
        assert!(p.refuse);
        let err = apply_plan(&mut c, &p).unwrap_err();
        assert!(
            err.contains("RLIMIT_NOFILE") || err.contains("file descriptor"),
            "refusal names the fd limit: {err}"
        );
    }

    #[test]
    fn apply_plan_refusal_is_audited_as_ungraceful_shutdown() {
        let mut c = SbcConfig::default();
        let p = plan(1024, 2048, &c, true);
        let capture = uc_audit::capture::start();
        let err = apply_plan(&mut c, &p).unwrap_err();
        let want = format!("fd_limit: {err}");
        assert!(
            capture.events().iter().any(|e| matches!(
                e,
                uc_audit::AuditEvent::SystemShutdown(s)
                    if !s.graceful && s.reason == want
            )),
            "refusal must emit an ungraceful SystemShutdown naming fd_limit"
        );
    }

    // ---- search_soft: fallback when the hard limit is refused ----

    /// A kernel that accepts soft values up to `cap` and records the last
    /// accepted one (refused calls leave it unchanged).
    fn fake_kernel(cap: u64, current: &mut u64) -> impl FnMut(u64) -> bool + '_ {
        move |v| {
            if v <= cap {
                *current = v;
                true
            } else {
                false
            }
        }
    }

    #[test]
    fn search_soft_takes_target_when_accepted() {
        let mut cur = 256;
        assert_eq!(
            search_soft(256, 65_536, fake_kernel(u64::MAX, &mut cur)),
            65_536
        );
        assert_eq!(cur, 65_536);
    }

    #[test]
    fn search_soft_finds_the_exact_kernel_cap_above_a_power_of_two() {
        // macOS: hard RLIM_INFINITY, soft capped at kern.maxfilesperproc.
        for cap in [10_240, 24_576, 61_440, 1_048_575, (1 << 20) + 7] {
            let mut cur = 256;
            let got = search_soft(256, u64::MAX, fake_kernel(cap, &mut cur));
            assert_eq!(got, cap, "kernel cap {cap}");
            assert_eq!(cur, cap, "value in effect is the one returned");
        }
    }

    #[test]
    fn search_soft_keeps_soft_when_nothing_above_it_is_accepted() {
        let mut cur = 4096;
        assert_eq!(
            search_soft(4096, u64::MAX, fake_kernel(4096, &mut cur)),
            4096
        );
        assert_eq!(cur, 4096);
    }

    // SEC-R1-3: the first halved candidate is already at or below soft; the
    // search still finds the kernel cap between soft and the refused target.
    #[test]
    fn search_soft_searches_between_soft_and_refused_target() {
        let mut cur = 4096;
        assert_eq!(search_soft(4096, 6000, fake_kernel(5000, &mut cur)), 5000);
        assert_eq!(cur, 5000, "value in effect is the one returned");
    }

    // ---- apply: real getrlimit/setrlimit ----

    // Raising only (never lowering) keeps this safe alongside parallel tests.
    #[cfg(unix)]
    #[test]
    fn apply_raises_soft_limit() {
        use nix::sys::resource::{Resource, getrlimit};
        let (soft_before, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        let mut c = SbcConfig::default();
        // A small total so the clamp floor cannot trip on a low-limit host.
        c.transport.max_connections_total = 100;
        c.transport.max_connections_per_listener = 100;
        apply(&mut c, false).unwrap();
        let (soft_after, hard_after) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert_eq!(hard_after, hard, "hard limit is never changed");
        assert!(soft_after >= soft_before, "soft limit is never lowered");
        #[cfg(target_os = "linux")]
        assert_eq!(soft_after, hard, "soft raised to hard");
    }
}
