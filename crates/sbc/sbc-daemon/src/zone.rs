//! Zone registry and external IP monitoring.
//!
//! Provides the runtime zone registry that maps zone names to resolved
//! IP addresses, and the external IP monitor for STUN-based NAT discovery.
//!
//! STUN answers are unauthenticated, so the monitor only queries the
//! operator-pinned server (`stun:<ip>:<port>`, no default, no DNS), lets
//! the first answer set the address, and does not let a later different
//! answer replace it unless `transport.stun_accept_external_ip_change` is
//! set (then only after two agreeing refreshes). Refused and applied
//! changes are logged and audited.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (zone isolation, advertised address)
//! - **SI-4**: System Monitoring (external IP changes)
//! - **AU-2**: refused and applied changes are audited

use proto_stun::client::StunClient;
use sbc_config::interface::ResolvedZone;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Immutable (at startup) registry of resolved zones.
/// External IPs may be updated at runtime via STUN or Via received=.
#[derive(Debug)]
pub struct ResolvedZoneRegistry {
    /// Zone data, keyed by zone name.
    zones: HashMap<String, ZoneEntry>,
}

/// A single zone entry with resolved IPs.
#[derive(Debug)]
struct ZoneEntry {
    /// Signaling interface IP (for SIP transports).
    signaling_ip: IpAddr,
    /// Media interface IP (for RTP/SRTP ports).
    media_ip: IpAddr,
    /// External IP — may be updated at runtime.
    external_ip: RwLock<Option<IpAddr>>,
    /// Raw external_ip config source (for STUN re-resolution).
    external_ip_source: Option<String>,
}

/// Public view of a zone's resolved addresses.
#[derive(Debug, Clone)]
pub struct ZoneAddresses {
    /// Zone name.
    pub name: String,
    /// Signaling interface IP.
    pub signaling_ip: IpAddr,
    /// Media interface IP.
    pub media_ip: IpAddr,
    /// External IP (if configured).
    pub external_ip: Option<IpAddr>,
}

impl ResolvedZoneRegistry {
    /// Creates a new registry from resolved zones.
    pub fn from_resolved(zones: Vec<ResolvedZone>) -> Self {
        let mut map = HashMap::with_capacity(zones.len());
        for z in zones {
            map.insert(
                z.name.clone(),
                ZoneEntry {
                    signaling_ip: z.signaling_ip,
                    media_ip: z.media_ip,
                    external_ip: RwLock::new(z.external_ip),
                    external_ip_source: z.external_ip_source,
                },
            );
        }
        Self { zones: map }
    }

    /// Returns the addresses for a zone, or `None` if not found.
    pub async fn get(&self, name: &str) -> Option<ZoneAddresses> {
        let entry = self.zones.get(name)?;
        let external_ip = *entry.external_ip.read().await;
        Some(ZoneAddresses {
            name: name.to_string(),
            signaling_ip: entry.signaling_ip,
            media_ip: entry.media_ip,
            external_ip,
        })
    }

    /// Returns the signaling IP for a zone (synchronous, no external_ip).
    pub fn signaling_ip(&self, name: &str) -> Option<IpAddr> {
        self.zones.get(name).map(|e| e.signaling_ip)
    }

    /// Returns the media IP for a zone (synchronous).
    pub fn media_ip(&self, name: &str) -> Option<IpAddr> {
        self.zones.get(name).map(|e| e.media_ip)
    }

    /// Returns all unique signaling IPs (for creating SIP listeners).
    pub fn unique_signaling_addrs(&self) -> Vec<(IpAddr, String)> {
        let mut seen = HashMap::new();
        for (name, entry) in &self.zones {
            seen.entry(entry.signaling_ip)
                .or_insert_with(|| name.clone());
        }
        seen.into_iter().collect()
    }

    /// Returns all zone names.
    pub fn zone_names(&self) -> Vec<String> {
        self.zones.keys().cloned().collect()
    }

    /// Returns the external IP for a zone (synchronous, best-effort via try_read).
    pub fn external_ip(&self, name: &str) -> Option<IpAddr> {
        self.zones
            .get(name)
            .and_then(|e| e.external_ip.try_read().ok().and_then(|v| *v))
    }

    /// Looks up which zone owns a given signaling IP. Falls back to the first
    /// configured zone when there is no exact match — this is the L3 single-IP
    /// case where the pod has one Cilium-assigned IP and every zone shares it.
    /// Per-call zone is then derived downstream via trunk-peer matching and
    /// dial-plan routing rather than by which local IP the packet hit.
    pub fn zone_for_signaling_ip(&self, ip: IpAddr) -> Option<String> {
        for (name, entry) in &self.zones {
            if entry.signaling_ip == ip {
                return Some(name.clone());
            }
        }
        self.zones.keys().next().cloned()
    }

    /// Returns the name of the first carrier/external-facing zone — one with an
    /// external IP source configured (a literal external IP or a `stun` source).
    /// Used to pick the media interface advertised to trunks on outbound
    /// (untrusted) legs. `None` if no zone is external-facing (single-side
    /// deployment), in which case the caller falls back to the ingress zone.
    ///
    /// With multiple external-facing zones the choice is unspecified (HashMap
    /// order); production carrier deployments configure exactly one.
    pub fn external_facing_zone(&self) -> Option<String> {
        self.zones
            .iter()
            .find(|(_, e)| e.external_ip_source.is_some())
            .map(|(name, _)| name.clone())
    }

    /// Sets the external IP for a zone unconditionally (tests only; the
    /// STUN monitor goes through [`Self::apply_stun_answer`]).
    #[cfg(test)]
    pub async fn update_external_ip(&self, zone_name: &str, ip: IpAddr) {
        if let Some(entry) = self.zones.get(zone_name) {
            let mut ext = entry.external_ip.write().await;
            let old = *ext;
            *ext = Some(ip);
            if old != Some(ip) {
                info!(
                    zone = zone_name,
                    old = ?old,
                    new = %ip,
                    "External IP updated"
                );
            }
        }
    }

    /// Applies one STUN answer for a zone (SR-33).
    ///
    /// - No address yet: the answer sets it.
    /// - Same address: nothing changes.
    /// - Different address with `accept_change = false`: refused; logged
    ///   and audited once per distinct answer.
    /// - Different address with `accept_change = true`: applied only when
    ///   the previous refresh returned the same new address; logged and
    ///   audited.
    ///
    /// `pending` carries the last differing answer between refreshes.
    ///
    /// ## NIST 800-53 Rev5: SC-7, SI-4, AU-2
    // POAM: POA&M-502 (STUN answers are unauthenticated; the first one is trusted).
    pub async fn apply_stun_answer(
        &self,
        zone_name: &str,
        answer: IpAddr,
        accept_change: bool,
        pending: &mut Option<IpAddr>,
    ) -> StunDecision {
        let Some(entry) = self.zones.get(zone_name) else {
            return StunDecision::Unchanged;
        };
        let mut ext = entry.external_ip.write().await;
        let Some(current) = *ext else {
            *ext = Some(answer);
            *pending = None;
            info!(zone = zone_name, external_ip = %answer, "External IP set from STUN");
            return StunDecision::Set;
        };
        if current == answer {
            *pending = None;
            return StunDecision::Unchanged;
        }
        let repeated = *pending == Some(answer);
        *pending = Some(answer);
        if !accept_change {
            if !repeated {
                warn!(
                    zone = zone_name,
                    current = %current,
                    answer = %answer,
                    "STUN answer differs from the zone's external IP; not applied \
                     (transport.stun_accept_external_ip_change = false)"
                );
                audit_external_ip(zone_name, current, answer, "refused");
            }
            return StunDecision::Refused;
        }
        if !repeated {
            warn!(
                zone = zone_name,
                current = %current,
                answer = %answer,
                "STUN answer differs from the zone's external IP; applying if the next refresh agrees"
            );
            return StunDecision::Pending;
        }
        *ext = Some(answer);
        *pending = None;
        warn!(
            zone = zone_name,
            old = %current,
            new = %answer,
            "External IP changed from STUN (confirmed by two refreshes)"
        );
        audit_external_ip(zone_name, current, answer, "applied");
        StunDecision::Changed
    }

    /// Zones whose external IP comes from STUN, with their pinned server.
    /// A source that is not `stun:<ip>:<port>` is skipped with a warning
    /// (config validation already rejects it).
    fn stun_zones(&self) -> Vec<(String, SocketAddr)> {
        self.zones
            .iter()
            .filter_map(|(name, entry)| {
                let src = entry.external_ip_source.as_deref()?;
                if !src.starts_with("stun") {
                    return None;
                }
                let server = parse_stun_server(src);
                if server.is_none() {
                    warn!(zone = %name, source = src, "STUN external_ip needs stun:<ip>:<port>; skipped");
                }
                server.map(|s| (name.clone(), s))
            })
            .collect()
    }

    /// Returns true if the registry has any zones.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

/// What [`ResolvedZoneRegistry::apply_stun_answer`] did with an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunDecision {
    /// First answer; the zone had no external IP.
    Set,
    /// Same address as before.
    Unchanged,
    /// A different address, not applied by policy.
    Refused,
    /// A different address, waiting for the next refresh to agree.
    Pending,
    /// A different address, confirmed and applied.
    Changed,
}

/// Audits a refused or applied STUN external-IP change.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, SI-4
fn audit_external_ip(zone: &str, current: IpAddr, answer: IpAddr, outcome: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "stun-monitor".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Modified,
            description: format!(
                "zone external_ip change {outcome}: zone={zone} current={current} stun_answer={answer}"
            ),
        },
    ));
}

/// Monitors and periodically refreshes STUN-based external IPs.
pub struct ExternalIpMonitor {
    registry: Arc<ResolvedZoneRegistry>,
    interval: Duration,
    accept_change: bool,
}

impl ExternalIpMonitor {
    /// Creates a new monitor. `accept_change` is
    /// `transport.stun_accept_external_ip_change`.
    pub fn new(
        registry: Arc<ResolvedZoneRegistry>,
        interval_secs: u64,
        accept_change: bool,
    ) -> Self {
        Self {
            registry,
            interval: Duration::from_secs(interval_secs),
            accept_change,
        }
    }

    /// Starts the periodic STUN refresh loop. Returns the join handle.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let stun_zones = self.registry.stun_zones();
            if stun_zones.is_empty() {
                return;
            }

            info!(
                zones = ?stun_zones.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
                interval_secs = self.interval.as_secs(),
                accept_change = self.accept_change,
                "Starting external IP monitor (STUN)"
            );

            let mut pending: HashMap<String, Option<IpAddr>> = HashMap::new();
            let mut ticker = tokio::time::interval(self.interval);
            loop {
                // The first tick fires immediately (initial resolution).
                ticker.tick().await;
                for (zone_name, server) in &stun_zones {
                    let bind_ip = self
                        .registry
                        .signaling_ip(zone_name)
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    match discover(*server, bind_ip).await {
                        Ok(ip) => {
                            let slot = pending.entry(zone_name.clone()).or_default();
                            self.registry
                                .apply_stun_answer(zone_name, ip, self.accept_change, slot)
                                .await;
                        }
                        Err(e) => {
                            warn!(zone = zone_name, error = %e, stun_server = %server, "STUN refresh failed");
                        }
                    }
                }
            }
        })
    }
}

/// One STUN Binding to the pinned server; returns the mapped IP.
async fn discover(server: SocketAddr, bind_ip: IpAddr) -> Result<IpAddr, String> {
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .map_err(|e| format!("Bind failed: {e}"))?;
    let client = StunClient::new(Arc::new(socket), server);
    let srflx = client
        .discover_srflx()
        .await
        .map_err(|e| format!("STUN discovery failed: {e}"))?;
    Ok(srflx.ip())
}

/// Parses `stun:<ip>:<port>`. There is no default server and no host-name
/// form (SR-33): a name would be re-resolved on every refresh.
fn parse_stun_server(src: &str) -> Option<SocketAddr> {
    src.strip_prefix("stun:")?
        .parse::<SocketAddr>()
        .ok()
        .filter(|a| a.port() != 0 && !a.ip().is_unspecified())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_test_zones() -> Vec<ResolvedZone> {
        vec![
            ResolvedZone {
                name: "internal".to_string(),
                signaling_ip: "10.0.1.10".parse().unwrap(),
                media_ip: "10.0.1.10".parse().unwrap(),
                external_ip: None,
                external_ip_source: None,
            },
            ResolvedZone {
                name: "external".to_string(),
                signaling_ip: "10.0.2.10".parse().unwrap(),
                media_ip: "10.0.3.10".parse().unwrap(),
                external_ip: Some("203.0.113.10".parse().unwrap()),
                external_ip_source: Some("203.0.113.10".to_string()),
            },
        ]
    }

    #[tokio::test]
    async fn test_registry_get() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        let z = reg.get("internal").await.unwrap();
        assert_eq!(z.signaling_ip, "10.0.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(z.media_ip, "10.0.1.10".parse::<IpAddr>().unwrap());
        assert!(z.external_ip.is_none());

        let z = reg.get("external").await.unwrap();
        assert_eq!(z.external_ip, Some("203.0.113.10".parse().unwrap()));

        assert!(reg.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_update_external_ip() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        reg.update_external_ip("internal", "1.2.3.4".parse().unwrap())
            .await;
        let z = reg.get("internal").await.unwrap();
        assert_eq!(z.external_ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_unique_signaling_addrs() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        let addrs = reg.unique_signaling_addrs();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_zone_for_signaling_ip() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        assert_eq!(
            reg.zone_for_signaling_ip("10.0.1.10".parse().unwrap()),
            Some("internal".to_string())
        );
        assert_eq!(
            reg.zone_for_signaling_ip("10.0.2.10".parse().unwrap()),
            Some("external".to_string())
        );
        // Unmatched IP falls back to the first zone (L3 single-IP case where
        // the pod's Cilium-assigned IP doesn't equal any configured zone IP).
        let fallback = reg.zone_for_signaling_ip("99.99.99.99".parse().unwrap());
        assert!(
            fallback.is_some(),
            "unmatched IP should fall back, not return None"
        );
    }

    #[test]
    fn test_external_facing_zone() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        // "external" has external_ip_source set; "internal" does not.
        assert_eq!(reg.external_facing_zone(), Some("external".to_string()));

        // No external-facing zone → None (single-side deployment).
        let internal_only = ResolvedZoneRegistry::from_resolved(vec![ResolvedZone {
            name: "internal".to_string(),
            signaling_ip: "10.0.1.10".parse().unwrap(),
            media_ip: "10.0.1.10".parse().unwrap(),
            external_ip: None,
            external_ip_source: None,
        }]);
        assert_eq!(internal_only.external_facing_zone(), None);
    }

    #[test]
    fn test_parse_stun_server() {
        assert_eq!(parse_stun_server("stun"), None);
        assert_eq!(parse_stun_server("stun:stun.example.com:3478"), None);
        assert_eq!(parse_stun_server("stun:192.0.2.1:0"), None);
        assert_eq!(
            parse_stun_server("stun:192.0.2.1:3478"),
            Some("192.0.2.1:3478".parse().unwrap())
        );
        assert_eq!(
            parse_stun_server("stun:[2001:db8::1]:3478"),
            Some("[2001:db8::1]:3478".parse().unwrap())
        );
    }

    fn stun_registry() -> ResolvedZoneRegistry {
        ResolvedZoneRegistry::from_resolved(vec![ResolvedZone {
            name: "ext".to_string(),
            signaling_ip: "10.0.1.1".parse().unwrap(),
            media_ip: "10.0.1.1".parse().unwrap(),
            external_ip: None,
            external_ip_source: Some("stun:192.0.2.1:3478".to_string()),
        }])
    }

    /// SR-33: with the default policy the first answer sets the address
    /// and a later different answer never replaces it.
    #[tokio::test]
    async fn stun_answer_cannot_change_the_address_by_default() {
        let reg = stun_registry();
        let mut pending = None;
        let a: IpAddr = "203.0.113.10".parse().unwrap();
        let b: IpAddr = "198.51.100.66".parse().unwrap();
        assert_eq!(
            reg.apply_stun_answer("ext", a, false, &mut pending).await,
            StunDecision::Set
        );
        assert_eq!(
            reg.apply_stun_answer("ext", a, false, &mut pending).await,
            StunDecision::Unchanged
        );
        for _ in 0..3 {
            assert_eq!(
                reg.apply_stun_answer("ext", b, false, &mut pending).await,
                StunDecision::Refused
            );
        }
        assert_eq!(reg.external_ip("ext"), Some(a));
    }

    /// With `stun_accept_external_ip_change = true` a change needs two
    /// agreeing refreshes; an alternating answer never lands.
    #[tokio::test]
    async fn stun_change_needs_two_agreeing_refreshes_when_allowed() {
        let reg = stun_registry();
        let mut pending = None;
        let a: IpAddr = "203.0.113.10".parse().unwrap();
        let b: IpAddr = "198.51.100.66".parse().unwrap();
        let c: IpAddr = "198.51.100.77".parse().unwrap();
        reg.apply_stun_answer("ext", a, true, &mut pending).await;
        assert_eq!(
            reg.apply_stun_answer("ext", b, true, &mut pending).await,
            StunDecision::Pending
        );
        assert_eq!(
            reg.apply_stun_answer("ext", c, true, &mut pending).await,
            StunDecision::Pending
        );
        assert_eq!(
            reg.apply_stun_answer("ext", a, true, &mut pending).await,
            StunDecision::Unchanged
        );
        assert_eq!(
            reg.apply_stun_answer("ext", b, true, &mut pending).await,
            StunDecision::Pending
        );
        assert_eq!(reg.external_ip("ext"), Some(a));
        assert_eq!(
            reg.apply_stun_answer("ext", b, true, &mut pending).await,
            StunDecision::Changed
        );
        assert_eq!(reg.external_ip("ext"), Some(b));
    }

    /// A configured literal external IP is never touched by STUN: the zone
    /// is not a STUN zone at all.
    #[test]
    fn configured_external_ip_is_not_a_stun_zone() {
        let reg = ResolvedZoneRegistry::from_resolved(make_test_zones());
        assert_eq!(reg.stun_zones(), Vec::new());
    }

    #[test]
    fn test_stun_zones() {
        let zones = vec![
            ResolvedZone {
                name: "ext".to_string(),
                signaling_ip: "10.0.1.1".parse().unwrap(),
                media_ip: "10.0.1.1".parse().unwrap(),
                external_ip: None,
                external_ip_source: Some("stun:192.0.2.1:3478".to_string()),
            },
            ResolvedZone {
                name: "int".to_string(),
                signaling_ip: "10.0.2.1".parse().unwrap(),
                media_ip: "10.0.2.1".parse().unwrap(),
                external_ip: None,
                external_ip_source: None,
            },
        ];
        let reg = ResolvedZoneRegistry::from_resolved(zones);
        let stun = reg.stun_zones();
        assert_eq!(stun.len(), 1);
        assert_eq!(stun[0].0, "ext");
    }
}
