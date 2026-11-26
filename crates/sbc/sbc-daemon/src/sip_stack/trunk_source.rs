//! Inbound trunk identification by arrival flow (SR-04).
//!
//! A request comes from a configured trunk when its canonical source IP is a
//! trunk's host and it arrived over the trunk's configured `protocol` or a
//! stronger transport (a transport floor, as for in-dialog requests): an
//! exact (IP, transport) entry wins; otherwise a `udp` trunk also matches
//! TCP and TLS arrival (RFC 3261 §18.1.1: a request too large for UDP MUST
//! go over TCP), and a `tcp` trunk also matches TLS. A `tls` trunk matches
//! TLS only, and UDP never matches a TCP/TLS trunk: a UDP datagram from a
//! TLS trunk's address is not that trunk (no RFC 3325 trust, no per-user
//! limiter exemption, no STIR `source_trunk`, no trunk CSS). The source port
//! is not part of the key (carriers send from ephemeral ports).
//!
//! Pure: no locks, no I/O. Canonicalisation (`::ffff:a.b.c.d` → `a.b.c.d`)
//! happens only in [`TrunkSourceKey::new`], on insert and lookup alike.
//!
//! ## NIST 800-53 Rev5: AC-3, AC-4, SC-7, CM-3

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::warn;
use uc_routing::TrunkProtocol;
use uc_types::address::TransportType as AddrTransport;

/// The value of an inbound trunk entry: (trunk group, CSS).
pub type InboundTrunk = (String, Option<String>);

/// Transports a trunk can be configured with (`VALID_TRUNK_PROTOCOLS`).
const TRUNK_TRANSPORTS: [AddrTransport; 3] =
    [AddrTransport::Udp, AddrTransport::Tcp, AddrTransport::Tls];

/// Key of [`InboundTrunkMap`]: canonical source IP and the trunk's
/// configured transport (UDP, TCP or TLS only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrunkSourceKey {
    ip: IpAddr,
    transport: AddrTransport,
}

impl TrunkSourceKey {
    /// Builds a key; `None` for a transport no trunk can use (WS, WSS,
    /// SCTP), so such ingress never matches a trunk.
    #[must_use]
    pub fn new(ip: IpAddr, transport: AddrTransport) -> Option<Self> {
        matches!(
            transport,
            AddrTransport::Udp | AddrTransport::Tcp | AddrTransport::Tls
        )
        .then(|| Self {
            ip: ip.to_canonical(),
            transport,
        })
    }

    /// Canonical source IP.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The trunk's configured transport.
    #[must_use]
    pub const fn transport(&self) -> AddrTransport {
        self.transport
    }
}

/// (canonical source IP, configured trunk transport) → (trunk group, CSS),
/// looked up from the arrival transport through [`Self::resolve`]'s
/// transport floor. An address may be a UDP trunk of one group and a TLS
/// trunk of another.
/// std `HashMap` (keyed `SipHash`); filled from configuration and the
/// trunk-sync API only, so bounded by the configuration (SC-5).
///
/// POAM: POA&M-397 trunk identity is the source IP and transport:
/// TLS trunks are not bound to a peer certificate and UDP trunks are not
/// matched on source port, so a datagram spoofed from a UDP trunk's address
/// is treated as that trunk.
#[derive(Debug, Default)]
pub struct InboundTrunkMap {
    by_source: HashMap<TrunkSourceKey, InboundTrunk>,
}

impl InboundTrunkMap {
    /// The trunk entry a request from `ip` arriving over `transport` belongs
    /// to, with the key it matched (the trunk's configured transport): the
    /// exact entry first, then weaker configured transports (see the module
    /// docs). At most three probes.
    ///
    /// ## NIST 800-53 Rev5: AC-3, SC-7
    #[must_use]
    pub fn resolve(
        &self,
        ip: IpAddr,
        transport: AddrTransport,
    ) -> Option<(TrunkSourceKey, &InboundTrunk)> {
        floor_candidates(transport).iter().find_map(|t| {
            let key = TrunkSourceKey::new(ip, *t)?;
            self.by_source.get(&key).map(|trunk| (key, trunk))
        })
    }

    /// The trunk a request from `ip` over `transport` belongs to, if any
    /// ([`Self::resolve`] without the key).
    #[must_use]
    pub fn get(&self, ip: IpAddr, transport: AddrTransport) -> Option<&InboundTrunk> {
        self.resolve(ip, transport).map(|(_, trunk)| trunk)
    }

    /// Whether a request from `ip` over `transport` is from a trunk.
    #[must_use]
    pub fn contains(&self, ip: IpAddr, transport: AddrTransport) -> bool {
        self.get(ip, transport).is_some()
    }

    /// Whether `ip` is a trunk over any transport. Destination-side use only
    /// (topology hiding toward a trunk host): never for source admission.
    #[must_use]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        TRUNK_TRANSPORTS.iter().any(|t| self.has_key(ip, *t))
    }

    /// A configured transport other than `other_than` that `ip` is a trunk
    /// over (deny path log hint only).
    #[must_use]
    pub fn configured_transport(
        &self,
        ip: IpAddr,
        other_than: AddrTransport,
    ) -> Option<AddrTransport> {
        TRUNK_TRANSPORTS
            .into_iter()
            .find(|t| *t != other_than && self.has_key(ip, *t))
    }

    /// Whether the exact key (`ip`, configured `transport`) exists.
    fn has_key(&self, ip: IpAddr, transport: AddrTransport) -> bool {
        TrunkSourceKey::new(ip, transport).is_some_and(|k| self.by_source.contains_key(&k))
    }

    /// Replaces the entries of trunk group `group` with `sources` and `css`.
    /// A source already mapped to another group moves to `group` (warning).
    ///
    /// NIST 800-53 Rev5: AC-3, AC-4, CM-3
    pub fn replace_group(
        &mut self,
        group: &str,
        css: Option<&str>,
        sources: &HashSet<TrunkSourceKey>,
    ) {
        self.remove_group(group);
        for key in sources {
            if let Some((previous, _)) = self
                .by_source
                .insert(*key, (group.to_string(), css.map(String::from)))
            {
                // Only another group's entry can remain after the removal.
                warn!(
                    trunk_group = group,
                    previous_trunk_group = %previous,
                    transport = %key.transport(),
                    "Trunk host address moved from another trunk group"
                );
            }
        }
    }

    /// Every source IP with an entry over any transport, sorted and
    /// deduplicated (the per-source rate limiters' trusted set).
    ///
    /// NIST 800-53 Rev5: SC-5
    #[must_use]
    pub fn source_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self.by_source.keys().map(TrunkSourceKey::ip).collect();
        ips.sort_unstable();
        ips.dedup();
        ips
    }

    /// Drops every entry of trunk group `group`.
    pub fn remove_group(&mut self, group: &str) {
        self.by_source.retain(|_, (g, _)| g != group);
    }
}

/// Configured trunk transports that admit a request arriving over
/// `arrival`, strongest first: the transport floor of the module docs.
const fn floor_candidates(arrival: AddrTransport) -> &'static [AddrTransport] {
    match arrival {
        AddrTransport::Udp => &[AddrTransport::Udp],
        AddrTransport::Tcp => &[AddrTransport::Tcp, AddrTransport::Udp],
        AddrTransport::Tls => &[AddrTransport::Tls, AddrTransport::Tcp, AddrTransport::Udp],
        AddrTransport::WebSocket | AddrTransport::WebSocketSecure | AddrTransport::Sctp => &[],
    }
}

/// Source key of a config-file trunk at `ip` with `protocol` (see
/// [`trunk_protocol_from_config`]).
#[must_use]
pub fn config_trunk_key(ip: IpAddr, protocol: &str) -> Option<TrunkSourceKey> {
    TrunkSourceKey::new(
        ip,
        trunk_protocol_transport(trunk_protocol_from_config(protocol)),
    )
}

/// Router protocol of a config-file trunk `protocol` string. Validation
/// (`VALID_TRUNK_PROTOCOLS`) has already rejected anything else; an
/// unknown value maps to UDP as the router always did.
#[must_use]
pub fn trunk_protocol_from_config(s: &str) -> TrunkProtocol {
    match s {
        "tcp" => TrunkProtocol::Tcp,
        "tls" => TrunkProtocol::Tls,
        _ => TrunkProtocol::Udp,
    }
}

/// The arrival transport a trunk configured with `p` sends on.
#[must_use]
pub const fn trunk_protocol_transport(p: TrunkProtocol) -> AddrTransport {
    match p {
        TrunkProtocol::Udp => AddrTransport::Udp,
        TrunkProtocol::Tcp => AddrTransport::Tcp,
        TrunkProtocol::Tls => AddrTransport::Tls,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ALL: [AddrTransport; 6] = [
        AddrTransport::Udp,
        AddrTransport::Tcp,
        AddrTransport::Tls,
        AddrTransport::WebSocket,
        AddrTransport::WebSocketSecure,
        AddrTransport::Sctp,
    ];

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn key(ip: IpAddr, t: AddrTransport) -> TrunkSourceKey {
        TrunkSourceKey::new(ip, t).expect("trunk transport")
    }

    fn set(keys: &[TrunkSourceKey]) -> HashSet<TrunkSourceKey> {
        keys.iter().copied().collect()
    }

    #[test]
    fn new_canonicalises_mapped_v4() {
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
        let k = key(mapped, AddrTransport::Tls);
        assert_eq!(k.ip(), v4(203, 0, 113, 9));
        assert_eq!(k.transport(), AddrTransport::Tls);
        assert_eq!(k, key(v4(203, 0, 113, 9), AddrTransport::Tls));
    }

    #[test]
    fn non_trunk_transports_have_no_key() {
        for t in [
            AddrTransport::WebSocket,
            AddrTransport::WebSocketSecure,
            AddrTransport::Sctp,
        ] {
            assert!(TrunkSourceKey::new(v4(203, 0, 113, 9), t).is_none(), "{t}");
        }
        let mut m = InboundTrunkMap::default();
        m.replace_group(
            "g",
            None,
            &set(&[key(v4(203, 0, 113, 9), AddrTransport::Tls)]),
        );
        assert!(!m.contains(v4(203, 0, 113, 9), AddrTransport::WebSocketSecure));
    }

    #[test]
    fn replace_group_replaces_only_that_group_and_moves_keys() {
        let ip = v4(203, 0, 113, 9);
        let other = v4(203, 0, 113, 10);
        let mut m = InboundTrunkMap::default();
        m.replace_group("a", Some("css-a"), &set(&[key(ip, AddrTransport::Udp)]));
        m.replace_group("b", None, &set(&[key(other, AddrTransport::Tls)]));
        // Replacing "a" leaves "b" alone.
        m.replace_group("a", Some("css-a2"), &set(&[key(ip, AddrTransport::Tcp)]));
        assert_eq!(m.get(ip, AddrTransport::Udp), None);
        assert_eq!(
            m.get(ip, AddrTransport::Tcp),
            Some(&("a".to_string(), Some("css-a2".to_string())))
        );
        assert_eq!(
            m.get(other, AddrTransport::Tls),
            Some(&("b".to_string(), None))
        );
        // "b" takes a's key: it moves.
        m.replace_group(
            "b",
            None,
            &set(&[key(other, AddrTransport::Tls), key(ip, AddrTransport::Tcp)]),
        );
        assert_eq!(
            m.get(ip, AddrTransport::Tcp),
            Some(&("b".to_string(), None))
        );
    }

    #[test]
    fn same_ip_two_transports_two_groups() {
        let ip = v4(203, 0, 113, 9);
        let mut m = InboundTrunkMap::default();
        m.replace_group("a", None, &set(&[key(ip, AddrTransport::Udp)]));
        m.replace_group("b", None, &set(&[key(ip, AddrTransport::Tls)]));
        assert_eq!(
            m.get(ip, AddrTransport::Udp).map(|(g, _)| g.as_str()),
            Some("a")
        );
        assert_eq!(
            m.get(ip, AddrTransport::Tls).map(|(g, _)| g.as_str()),
            Some("b")
        );
        // TCP has no exact entry: the UDP trunk admits it (floor), and the
        // resolved key is the UDP trunk's.
        assert_eq!(
            m.resolve(ip, AddrTransport::Tcp)
                .map(|(k, (g, _))| (k.transport(), g.as_str())),
            Some((AddrTransport::Udp, "a"))
        );
    }

    /// RFC 3261 §18.1.1 floor: udp admits TCP/TLS, tcp admits TLS, tls only
    /// TLS; an exact entry wins over a weaker one; WS/WSS/SCTP never match.
    #[test]
    fn transport_floor() {
        let ip = v4(203, 0, 113, 9);
        let resolved = |m: &InboundTrunkMap, t| m.resolve(ip, t).map(|(k, _)| k.transport());
        let mut m = InboundTrunkMap::default();
        m.replace_group("g", None, &set(&[key(ip, AddrTransport::Udp)]));
        for t in [AddrTransport::Udp, AddrTransport::Tcp, AddrTransport::Tls] {
            assert_eq!(resolved(&m, t), Some(AddrTransport::Udp), "{t}");
        }
        for t in [
            AddrTransport::WebSocket,
            AddrTransport::WebSocketSecure,
            AddrTransport::Sctp,
        ] {
            assert_eq!(resolved(&m, t), None, "{t}");
        }
        m.replace_group("g", None, &set(&[key(ip, AddrTransport::Tcp)]));
        assert_eq!(resolved(&m, AddrTransport::Udp), None);
        assert_eq!(resolved(&m, AddrTransport::Tcp), Some(AddrTransport::Tcp));
        assert_eq!(resolved(&m, AddrTransport::Tls), Some(AddrTransport::Tcp));
        m.replace_group("g", None, &set(&[key(ip, AddrTransport::Tls)]));
        assert_eq!(resolved(&m, AddrTransport::Udp), None);
        assert_eq!(resolved(&m, AddrTransport::Tcp), None);
        assert_eq!(resolved(&m, AddrTransport::Tls), Some(AddrTransport::Tls));
        // Exact wins: a udp trunk and a tls trunk on one host.
        m.replace_group(
            "g",
            None,
            &set(&[key(ip, AddrTransport::Udp), key(ip, AddrTransport::Tls)]),
        );
        assert_eq!(resolved(&m, AddrTransport::Tls), Some(AddrTransport::Tls));
        assert_eq!(resolved(&m, AddrTransport::Tcp), Some(AddrTransport::Udp));
        assert_eq!(resolved(&m, AddrTransport::Udp), Some(AddrTransport::Udp));
    }

    // NIST 800-53 Rev5: SC-5 - the limiters' trusted set is per IP: an
    // address that is a trunk over two transports appears once.
    #[test]
    fn source_ips_dedups_across_transports() {
        let mut m = InboundTrunkMap::default();
        let a = v4(203, 0, 113, 1);
        let b = v4(203, 0, 113, 2);
        m.replace_group(
            "g1",
            None,
            &set(&[key(b, AddrTransport::Udp), key(a, AddrTransport::Tls)]),
        );
        m.replace_group("g2", None, &set(&[key(a, AddrTransport::Udp)]));
        assert_eq!(m.source_ips(), vec![a, b]);
        m.remove_group("g1");
        m.remove_group("g2");
        assert!(m.source_ips().is_empty());
    }

    #[test]
    fn remove_group_drops_its_keys() {
        let ip = v4(203, 0, 113, 9);
        let mut m = InboundTrunkMap::default();
        m.replace_group(
            "a",
            None,
            &set(&[key(ip, AddrTransport::Udp), key(ip, AddrTransport::Tls)]),
        );
        m.replace_group(
            "b",
            None,
            &set(&[key(v4(203, 0, 113, 10), AddrTransport::Udp)]),
        );
        m.remove_group("a");
        assert!(!m.contains_ip(ip));
        assert!(m.contains(v4(203, 0, 113, 10), AddrTransport::Udp));
    }

    #[test]
    fn contains_ip_any_trunk_transport() {
        let ip = v4(10, 0, 0, 9);
        let mut m = InboundTrunkMap::default();
        assert!(!m.contains_ip(ip));
        m.replace_group("a", None, &set(&[key(ip, AddrTransport::Tls)]));
        assert!(m.contains_ip(ip));
        assert!(m.contains_ip(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 9).to_ipv6_mapped())));
        assert!(!m.contains(ip, AddrTransport::Udp));
    }

    #[test]
    fn configured_transport_names_another_transport() {
        let ip = v4(203, 0, 113, 9);
        let mut m = InboundTrunkMap::default();
        m.replace_group("a", None, &set(&[key(ip, AddrTransport::Tls)]));
        assert_eq!(
            m.configured_transport(ip, AddrTransport::Udp),
            Some(AddrTransport::Tls)
        );
        assert_eq!(m.configured_transport(ip, AddrTransport::Tls), None);
        assert_eq!(
            m.configured_transport(v4(203, 0, 113, 10), AddrTransport::Udp),
            None
        );
    }

    /// Table test: for every (address form, trunk transport), insert then
    /// `get` round-trips, a stronger arrival transport matches (floor) and
    /// every weaker or non-trunk transport misses.
    #[test]
    fn round_trip_floor_only() {
        let ips = [
            v4(198, 51, 100, 1),
            IpAddr::V6(Ipv4Addr::new(198, 51, 100, 2).to_ipv6_mapped()),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        for ip in ips {
            for t in TRUNK_TRANSPORTS {
                let mut m = InboundTrunkMap::default();
                m.replace_group("g", None, &set(&[key(ip, t)]));
                assert!(m.contains(ip, t), "{ip} {t}");
                assert!(m.contains(ip.to_canonical(), t), "{ip} {t} canonical");
                for other in ALL.into_iter().filter(|o| *o != t) {
                    let want = floor_candidates(other).contains(&t);
                    assert_eq!(m.get(ip, other).is_some(), want, "{ip} {t} vs {other}");
                }
            }
        }
    }

    #[test]
    fn protocol_mapping() {
        assert_eq!(trunk_protocol_from_config("tls"), TrunkProtocol::Tls);
        assert_eq!(trunk_protocol_from_config("tcp"), TrunkProtocol::Tcp);
        assert_eq!(trunk_protocol_from_config("udp"), TrunkProtocol::Udp);
        assert_eq!(trunk_protocol_from_config("bogus"), TrunkProtocol::Udp);
        assert_eq!(
            trunk_protocol_transport(TrunkProtocol::Tls),
            AddrTransport::Tls
        );
        assert_eq!(
            trunk_protocol_transport(TrunkProtocol::Tcp),
            AddrTransport::Tcp
        );
        assert_eq!(
            trunk_protocol_transport(TrunkProtocol::Udp),
            AddrTransport::Udp
        );
    }
}
