//! Admission of SDP media addresses as relay targets (SR-19).
//!
//! An SDP `c=`/`m=` address becomes the address the relay sends to on that
//! leg. Without a constraint a caller that controls both ends of a call can
//! make the SBC send datagrams from its own addresses to any host and port,
//! including hosts inside the boundary that trust the SBC.
//!
//! Rules, per leg:
//! - every leg: refuse loopback, link-local, multicast and unspecified
//!   addresses, and any address the SBC owns (zone signalling, media and
//!   external addresses, this call's media addresses);
//! - a trunk leg (operator-configured peer) is otherwise trusted;
//! - any other leg (registered or unauthenticated source):
//!   - refuse ports below 1024;
//!   - refuse a configured trunk host address (a peer that trusts the SBC);
//!   - when its signalling peer is outside the internal networks, refuse an
//!     internal address: media stays in the leg's own zone.
//!
//! Pure: the caller supplies the facts (locks and lookups live in the stack).
//!
//! ## NIST 800-53 Rev5: SC-7 (Boundary Protection), AC-4 (Information Flow
//! Enforcement)

// POAM: POA&M-481 - one internal/external split, not per-zone networks; an
// internal non-trunk leg may still name other internal hosts (ports >= 1024).

use std::net::IpAddr;
use uc_types::address::SbcSocketAddr;

/// Lowest port an untrusted leg may name as its media port.
pub(super) const MIN_UNTRUSTED_MEDIA_PORT: u16 = 1024;

/// The signalling peer of the leg whose SDP names the address.
#[derive(Debug, Clone, Copy)]
pub(super) struct MediaLeg {
    /// The leg's signalling peer (A-leg source, B-leg destination).
    pub peer: IpAddr,
    /// The leg faces a configured trunk.
    pub trunk: bool,
}

/// Why an SDP media address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MediaTargetRefusal {
    /// Not an IP literal (hostnames are not resolved).
    NotIp,
    /// Loopback, link-local, multicast or unspecified.
    Disallowed,
    /// An address of the SBC itself.
    SbcOwned,
    /// A port below [`MIN_UNTRUSTED_MEDIA_PORT`] on an untrusted leg.
    PrivilegedPort,
    /// A configured trunk host named by an untrusted leg.
    TrunkHost,
    /// An internal address named by a leg whose peer is external.
    CrossZone,
}

impl MediaTargetRefusal {
    /// Short label for logs.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::NotIp => "not-ip",
            Self::Disallowed => "disallowed",
            Self::SbcOwned => "sbc-owned",
            Self::PrivilegedPort => "privileged-port",
            Self::TrunkHost => "trunk-host",
            Self::CrossZone => "cross-zone",
        }
    }
}

/// Lookups the policy needs, supplied by the stack.
pub(super) trait MediaTargetFacts {
    /// `ip` is inside `topology_hiding.internal_networks` (or the built-in
    /// private ranges when hiding is off).
    fn is_internal(&self, ip: IpAddr) -> bool;
    /// `ip` is an address of the SBC.
    fn is_sbc_owned(&self, ip: IpAddr) -> bool;
    /// `ip` is a configured trunk host.
    fn is_trunk_host(&self, ip: IpAddr) -> bool;
}

/// Applies the SR-19 rules to an SDP media address on `leg`.
pub(super) fn admit_media_target(
    address: &str,
    port: u16,
    leg: MediaLeg,
    facts: &impl MediaTargetFacts,
) -> Result<SbcSocketAddr, MediaTargetRefusal> {
    let ip: IpAddr = address
        .parse::<IpAddr>()
        .map_err(|_| MediaTargetRefusal::NotIp)?
        .to_canonical();
    if sbc_announcement::is_disallowed_media_ip(ip) || ip.is_unspecified() {
        return Err(MediaTargetRefusal::Disallowed);
    }
    if facts.is_sbc_owned(ip) {
        return Err(MediaTargetRefusal::SbcOwned);
    }
    if !leg.trunk {
        if port < MIN_UNTRUSTED_MEDIA_PORT {
            return Err(MediaTargetRefusal::PrivilegedPort);
        }
        if facts.is_trunk_host(ip) {
            return Err(MediaTargetRefusal::TrunkHost);
        }
        if facts.is_internal(ip) && !facts.is_internal(leg.peer.to_canonical()) {
            return Err(MediaTargetRefusal::CrossZone);
        }
    }
    Ok(SbcSocketAddr::from(std::net::SocketAddr::new(ip, port)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Facts;
    impl MediaTargetFacts for Facts {
        fn is_internal(&self, ip: IpAddr) -> bool {
            matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 10)
        }
        fn is_sbc_owned(&self, ip: IpAddr) -> bool {
            ip == "203.0.113.1".parse::<IpAddr>().unwrap()
                || ip == "10.0.0.1".parse::<IpAddr>().unwrap()
        }
        fn is_trunk_host(&self, ip: IpAddr) -> bool {
            ip == "10.20.0.5".parse::<IpAddr>().unwrap()
        }
    }

    fn leg(peer: &str, trunk: bool) -> MediaLeg {
        MediaLeg {
            peer: peer.parse().unwrap(),
            trunk,
        }
    }

    fn admit(addr: &str, port: u16, l: MediaLeg) -> Result<SbcSocketAddr, MediaTargetRefusal> {
        admit_media_target(addr, port, l, &Facts)
    }

    #[test]
    fn external_leg_cannot_target_internal_networks() {
        let ext = leg("198.51.100.7", false);
        assert_eq!(
            admit("10.20.0.9", 40000, ext),
            Err(MediaTargetRefusal::CrossZone)
        );
        assert_eq!(
            admit("::ffff:10.20.0.9", 40000, ext),
            Err(MediaTargetRefusal::CrossZone)
        );
        assert!(admit("198.51.100.7", 40000, ext).is_ok());
        assert!(admit("192.0.2.44", 40000, ext).is_ok());
    }

    #[test]
    fn internal_leg_keeps_internal_media() {
        assert!(admit("10.30.1.2", 40000, leg("10.30.1.2", false)).is_ok());
    }

    #[test]
    fn untrusted_leg_refuses_privileged_ports_and_trunk_hosts() {
        let int = leg("10.30.1.2", false);
        for port in [0, 53, 161, 1023] {
            assert_eq!(
                admit("10.30.1.2", port, int),
                Err(MediaTargetRefusal::PrivilegedPort)
            );
        }
        assert!(admit("10.30.1.2", 1024, int).is_ok());
        assert_eq!(
            admit("10.20.0.5", 5060, int),
            Err(MediaTargetRefusal::TrunkHost)
        );
    }

    #[test]
    fn every_leg_refuses_sbc_and_local_addresses() {
        for l in [leg("198.51.100.7", false), leg("10.20.0.5", true)] {
            for a in ["203.0.113.1", "10.0.0.1", "::ffff:10.0.0.1"] {
                assert_eq!(admit(a, 40000, l), Err(MediaTargetRefusal::SbcOwned));
            }
            for a in [
                "127.0.0.1",
                "0.0.0.0",
                "224.0.0.1",
                "169.254.1.1",
                "fe80::1",
                "::",
            ] {
                assert_eq!(admit(a, 40000, l), Err(MediaTargetRefusal::Disallowed));
            }
            assert_eq!(
                admit("media.example.com", 40000, l),
                Err(MediaTargetRefusal::NotIp)
            );
        }
    }

    #[test]
    fn trunk_leg_is_trusted_for_zone_and_port() {
        let trunk = leg("10.20.0.5", true);
        assert!(admit("10.20.0.6", 1000, trunk).is_ok());
        assert!(admit("10.20.0.5", 40000, trunk).is_ok());
        let ext_trunk = leg("198.51.100.20", true);
        assert!(admit("10.40.0.1", 40000, ext_trunk).is_ok());
    }
}
