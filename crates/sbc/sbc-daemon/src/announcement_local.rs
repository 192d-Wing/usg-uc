//! Limits on in-process announcement playback (no pod configured, or the
//! fallback when the pod is unreachable), matching the pod's defaults: a
//! global cap of concurrent plays, a per-destination-IP cap, a bound on one
//! play's duration and the same destination policy. Without them the
//! fallback would send announcement RTP with none of these.
//!
//! `SBC_ANNOUNCEMENT_ALLOWED_DEST_CIDRS` (comma-separated CIDRs, at most 256)
//! restricts destinations to the media networks, as the pod's
//! `SBC_ANN_ALLOWED_DEST_CIDRS`; empty or unset = no CIDR restriction. The
//! special address classes and port 0 are always refused; there is no
//! loopback lab flag here.
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, SI-10; SC-7(5) when the allow-list is set

use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use sbc_announcement::limits::{LimitRefusal, PlayGuard, PlayLimits};
use sbc_announcement::{
    AnnouncementServer, AnnouncementType, DestinationPolicy, DestinationRefusal,
    parse_allowed_cidrs,
};
use tokio::net::UdpSocket;

/// Concurrent in-process plays (the pod's default `SBC_ANN_MAX_PLAYS`).
pub const MAX_LOCAL_PLAYS: usize = 128;

/// Concurrent in-process plays to one destination IP (the pod's default
/// `SBC_ANN_MAX_PLAYS_PER_DEST`).
pub const MAX_LOCAL_PLAYS_PER_DEST: usize = 32;

/// Longest in-process play (the pod's default `SBC_ANN_MAX_PLAY_SECS`).
pub const MAX_LOCAL_PLAY: Duration = Duration::from_secs(30);

/// Env var holding the in-process destination allow-list.
pub const ALLOWED_DEST_CIDRS_ENV: &str = "SBC_ANNOUNCEMENT_ALLOWED_DEST_CIDRS";

static LIMITS: LazyLock<PlayLimits> =
    LazyLock::new(|| PlayLimits::new(MAX_LOCAL_PLAYS, MAX_LOCAL_PLAYS_PER_DEST));

static POLICY: OnceLock<DestinationPolicy> = OnceLock::new();

/// Parses `SBC_ANNOUNCEMENT_ALLOWED_DEST_CIDRS` from `lookup`.
///
/// # Errors
/// A message naming the variable and the bad entry.
pub fn policy_from(lookup: impl Fn(&str) -> Option<String>) -> Result<DestinationPolicy, String> {
    Ok(DestinationPolicy {
        allow_loopback: false,
        allowed: parse_allowed_cidrs(
            ALLOWED_DEST_CIDRS_ENV,
            lookup(ALLOWED_DEST_CIDRS_ENV).as_deref(),
        )?,
    })
}

/// Startup: parses the allow-list from the process environment (`main`
/// exits 2 on `Err`) and keeps it.
///
/// # Errors
/// As [`policy_from`].
pub fn init_local_policy() -> Result<(), String> {
    let policy = policy_from(|k: &str| std::env::var(k).ok())?;
    // A second call keeps the first (identical) value.
    let _ = POLICY.set(policy);
    Ok(())
}

/// Checks an announcement RTP destination taken from the caller's SDP.
///
/// # Errors
/// The refused class.
pub fn check_destination(dest: SocketAddr) -> Result<(), DestinationRefusal> {
    POLICY.get_or_init(DestinationPolicy::default).check(dest)
}

/// One in-process play slot toward `dest` (the unspecified address when
/// the caller's SDP had no usable destination), released when the guard
/// drops.
///
/// # Errors
/// The full cap ([`MAX_LOCAL_PLAYS`] or [`MAX_LOCAL_PLAYS_PER_DEST`]); the
/// caller answers 503 instead of playing.
pub fn try_local_slot(dest: Option<IpAddr>) -> Result<PlayGuard, LimitRefusal> {
    LIMITS.try_acquire(dest.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))
}

/// Plays `announcement` in-process, stopped at [`MAX_LOCAL_PLAY`].
///
/// # Errors
/// As `AnnouncementServer::play_on_socket`, or the time bound.
pub async fn play_bounded(
    announcement: AnnouncementType,
    socket: UdpSocket,
    dest: SocketAddr,
    ssrc: u32,
) -> Result<u64, String> {
    play_within(MAX_LOCAL_PLAY, announcement, socket, dest, ssrc).await
}

async fn play_within(
    limit: Duration,
    announcement: AnnouncementType,
    socket: UdpSocket,
    dest: SocketAddr,
    ssrc: u32,
) -> Result<u64, String> {
    tokio::time::timeout(
        limit,
        AnnouncementServer::play_on_socket(announcement, socket, dest, ssrc),
    )
    .await
    .unwrap_or_else(|_| Err("announcement exceeded the maximum play time".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parses_and_refuses_bad_entries() {
        let p = policy_from(|_| None);
        assert!(p.is_ok_and(|p| p.allowed.is_empty() && !p.allow_loopback));
        let p = policy_from(|_| Some("10.0.0.0/8".to_string()));
        assert!(p.is_ok_and(|p| p.allowed.len() == 1));
        let p = policy_from(|_| Some("nope".to_string()));
        assert!(p.is_err_and(|e| e.contains(ALLOWED_DEST_CIDRS_ENV)));
    }

    #[test]
    fn destination_classes_refused_without_list() {
        let bad = |s: &str| s.parse::<SocketAddr>().map(check_destination);
        for d in [
            "127.0.0.1:4000",
            "0.0.0.0:4000",
            "224.0.0.1:4000",
            "255.255.255.255:4000",
            "203.0.113.5:0",
            "[64:ff9b::7f00:1]:4000",
        ] {
            assert!(matches!(bad(d), Ok(Err(_))), "{d}");
        }
        assert!(matches!(bad("203.0.113.5:4000"), Ok(Ok(()))));
    }

    /// The local limits use the pod's defaults (the cap logic itself is
    /// tested in `sbc_announcement::limits` / the pod's limits tests).
    #[test]
    fn local_defaults_match_pod() {
        assert_eq!(
            (MAX_LOCAL_PLAYS, MAX_LOCAL_PLAYS_PER_DEST, MAX_LOCAL_PLAY),
            (128, 32, Duration::from_secs(30))
        );
        // One slot toward a documentation address is admitted and released.
        let ip: IpAddr = [192, 0, 2, 77].into();
        let g = try_local_slot(Some(ip));
        assert!(g.is_ok());
        assert_eq!(LIMITS.active_for(ip), 1);
        drop(g);
        assert_eq!(LIMITS.active_for(ip), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn play_is_time_bounded() {
        let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
            return;
        };
        let dest: SocketAddr = ([127, 0, 0, 1], 9).into();
        // Silence is 2 s; a 100 ms bound stops it.
        let r = play_within(
            Duration::from_millis(100),
            AnnouncementType::Silence,
            socket,
            dest,
            1,
        )
        .await;
        assert!(r.is_err_and(|e| e.contains("maximum play time")));
    }
}
