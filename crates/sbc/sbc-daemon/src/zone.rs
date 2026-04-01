//! Zone registry and external IP monitoring.
//!
//! Provides the runtime zone registry that maps zone names to resolved
//! IP addresses, and the external IP monitor for STUN-based NAT discovery
//! and Via received= parameter updates.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (zone isolation)
//! - **SI-4**: System Monitoring (external IP changes)

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
        let external_ip = entry.external_ip.read().await.clone();
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
        seen.into_iter().map(|(ip, name)| (ip, name)).collect()
    }

    /// Returns all zone names.
    pub fn zone_names(&self) -> Vec<String> {
        self.zones.keys().cloned().collect()
    }

    /// Looks up which zone owns a given signaling IP.
    pub fn zone_for_signaling_ip(&self, ip: IpAddr) -> Option<String> {
        for (name, entry) in &self.zones {
            if entry.signaling_ip == ip {
                return Some(name.clone());
            }
        }
        None
    }

    /// Updates the external IP for a zone (called from STUN or Via received=).
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

    /// Returns zones that need STUN resolution (external_ip_source starts with "stun").
    fn stun_zones(&self) -> Vec<(String, String)> {
        self.zones
            .iter()
            .filter_map(|(name, entry)| {
                entry.external_ip_source.as_ref().and_then(|src| {
                    if src.starts_with("stun") {
                        Some((name.clone(), src.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Returns true if the registry has any zones.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

/// Default STUN server for NAT discovery.
const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

/// Monitors and periodically refreshes STUN-based external IPs.
pub struct ExternalIpMonitor {
    registry: Arc<ResolvedZoneRegistry>,
    interval: Duration,
}

impl ExternalIpMonitor {
    /// Creates a new monitor.
    pub fn new(registry: Arc<ResolvedZoneRegistry>, interval_secs: u64) -> Self {
        Self {
            registry,
            interval: Duration::from_secs(interval_secs),
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
                "Starting external IP monitor (STUN)"
            );

            // Initial resolution
            for (zone_name, stun_src) in &stun_zones {
                let bind_ip = self
                    .registry
                    .signaling_ip(zone_name)
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                if let Err(e) = self.resolve_stun(zone_name, stun_src, bind_ip).await {
                    warn!(zone = zone_name, error = %e, "Initial STUN resolution failed");
                }
            }

            // Periodic refresh
            let mut ticker = tokio::time::interval(self.interval);
            ticker.tick().await; // skip immediate first tick (already did initial)
            loop {
                ticker.tick().await;
                for (zone_name, stun_src) in &stun_zones {
                    let bind_ip = self
                        .registry
                        .signaling_ip(zone_name)
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    if let Err(e) = self.resolve_stun(zone_name, stun_src, bind_ip).await {
                        warn!(zone = zone_name, error = %e, "STUN refresh failed");
                    }
                }
            }
        })
    }

    /// Performs a single STUN resolution for a zone.
    async fn resolve_stun(
        &self,
        zone_name: &str,
        stun_src: &str,
        bind_ip: IpAddr,
    ) -> Result<(), String> {
        let stun_server = parse_stun_server(stun_src);

        let server_addr: SocketAddr = stun_server
            .parse()
            .or_else(|_| {
                use std::net::ToSocketAddrs;
                stun_server
                    .to_socket_addrs()
                    .map_err(|e| e.to_string())?
                    .next()
                    .ok_or_else(|| "DNS resolution failed".to_string())
            })
            .map_err(|e| format!("Cannot resolve STUN server {stun_server}: {e}"))?;

        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|e| format!("Bind failed: {e}"))?;

        let client = StunClient::new(Arc::new(socket), server_addr);
        let srflx = client
            .discover_srflx()
            .await
            .map_err(|e| format!("STUN discovery failed: {e}"))?;

        info!(
            zone = zone_name,
            external_ip = %srflx.ip(),
            stun_server = stun_server,
            "STUN discovery complete"
        );

        self.registry
            .update_external_ip(zone_name, srflx.ip())
            .await;
        Ok(())
    }
}

/// Parses a STUN source string. Supports:
/// - `"stun"` → default server
/// - `"stun:host:port"` → custom server
fn parse_stun_server(src: &str) -> String {
    if src == "stun" {
        DEFAULT_STUN_SERVER.to_string()
    } else if let Some(server) = src.strip_prefix("stun:") {
        server.to_string()
    } else {
        DEFAULT_STUN_SERVER.to_string()
    }
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
        assert!(reg.zone_for_signaling_ip("99.99.99.99".parse().unwrap()).is_none());
    }

    #[test]
    fn test_parse_stun_server() {
        assert_eq!(parse_stun_server("stun"), "stun.l.google.com:19302");
        assert_eq!(
            parse_stun_server("stun:stun.example.com:3478"),
            "stun.example.com:3478"
        );
    }

    #[test]
    fn test_stun_zones() {
        let zones = vec![
            ResolvedZone {
                name: "ext".to_string(),
                signaling_ip: "10.0.1.1".parse().unwrap(),
                media_ip: "10.0.1.1".parse().unwrap(),
                external_ip: None,
                external_ip_source: Some("stun".to_string()),
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
