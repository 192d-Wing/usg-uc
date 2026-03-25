//! DNS-based service discovery.
//!
//! This module provides DNS-based peer discovery using SRV and A/AAAA records.
//! It integrates with the uc-dns crate for actual DNS resolution.

use crate::config::{DiscoveryMethod, DnsConfig};
use crate::error::{DiscoveryError, DiscoveryResult};
use crate::{DiscoveredPeer, DiscoveryProvider, PeerMetadata};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, trace, warn};
use uc_dns::cache::DnsCache;
use uc_dns::hickory::HickoryDnsResolver;

/// DNS-based discovery provider.
///
/// Supports two discovery modes:
/// - **SRV records**: Discovers peers via DNS SRV records, which include
///   priority, weight, port, and target hostname information.
/// - **A/AAAA records**: Discovers peers via simple DNS A/AAAA record lookups,
///   using a configured default port.
pub struct DnsDiscovery {
    /// DNS resolver for actual lookups.
    resolver: HickoryDnsResolver,
    /// Configuration.
    config: DnsConfig,
    /// Discovery method (SRV or A records).
    method: DiscoveryMethod,
}

impl DnsDiscovery {
    /// Creates a new DNS discovery provider.
    ///
    /// # Errors
    /// Returns an error if the DNS resolver cannot be initialized.
    pub fn new(config: DnsConfig, method: DiscoveryMethod) -> DiscoveryResult<Self> {
        debug!(
            domain = %config.domain,
            method = %method,
            "Creating DNS discovery provider"
        );

        let cache = Arc::new(DnsCache::default());
        let resolver =
            HickoryDnsResolver::new(cache).map_err(|e| DiscoveryError::DnsResolutionFailed {
                name: "resolver_init".to_string(),
                reason: format!("Failed to create DNS resolver: {e}"),
            })?;

        Ok(Self {
            resolver,
            config,
            method,
        })
    }

    /// Discovers peers using SRV records.
    async fn discover_srv(&self) -> DiscoveryResult<Vec<DiscoveredPeer>> {
        let srv_name = format!("_sbc._tcp.{}", self.config.domain);
        debug!(name = %srv_name, "Looking up SRV records");

        let records = self
            .resolver
            .lookup_srv_with_addresses(&srv_name)
            .await
            .map_err(|e| DiscoveryError::DnsResolutionFailed {
                name: srv_name.clone(),
                reason: e.to_string(),
            })?;

        let mut peers = Vec::with_capacity(records.len());

        for record in records {
            trace!(
                target = %record.target,
                priority = record.priority,
                weight = record.weight,
                port = record.port,
                "Found SRV record"
            );

            // Get resolved addresses from the SRV record
            if record.addresses.is_empty() {
                warn!(target = %record.target, "SRV target has no resolved addresses");
                continue;
            }

            for addr in &record.addresses {
                let socket_addr = SocketAddr::new(*addr, record.port);
                let peer = DiscoveredPeer::new(socket_addr)
                    .with_priority(record.priority)
                    .with_weight(record.weight)
                    .with_metadata(
                        PeerMetadata::new()
                            .with_label("dns_target", &record.target)
                            .with_label("discovery_method", "dns_srv"),
                    );
                peers.push(peer);
            }
        }

        debug!(count = peers.len(), "Discovered peers via SRV records");
        Ok(peers)
    }

    /// Discovers peers using A/AAAA records.
    async fn discover_a(&self) -> DiscoveryResult<Vec<DiscoveredPeer>> {
        debug!(domain = %self.config.domain, "Looking up A/AAAA records");

        let addresses = self
            .resolver
            .lookup_addresses(&self.config.domain)
            .await
            .map_err(|e| DiscoveryError::DnsResolutionFailed {
                name: self.config.domain.clone(),
                reason: e.to_string(),
            })?;

        let peers: Vec<DiscoveredPeer> = addresses
            .into_iter()
            .map(|addr| {
                let socket_addr = SocketAddr::new(addr, self.config.default_port);
                DiscoveredPeer::new(socket_addr).with_metadata(
                    PeerMetadata::new()
                        .with_label("dns_domain", &self.config.domain)
                        .with_label("discovery_method", "dns_a"),
                )
            })
            .collect();

        debug!(count = peers.len(), "Discovered peers via A/AAAA records");
        Ok(peers)
    }
}

impl DiscoveryProvider for DnsDiscovery {
    fn discover(
        &self,
    ) -> Pin<Box<dyn Future<Output = DiscoveryResult<Vec<DiscoveredPeer>>> + Send + '_>> {
        Box::pin(async move {
            match self.method {
                DiscoveryMethod::DnsSrv => self.discover_srv().await,
                DiscoveryMethod::DnsA => self.discover_a().await,
                _ => Err(DiscoveryError::ConfigError {
                    reason: format!("Invalid discovery method for DNS provider: {}", self.method),
                }),
            }
        })
    }

    fn method_name(&self) -> &'static str {
        match self.method {
            DiscoveryMethod::DnsSrv => "dns_srv",
            DiscoveryMethod::DnsA => "dns_a",
            _ => "dns",
        }
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            // Try to resolve a well-known domain to verify DNS is working
            match self.resolver.lookup_addresses("localhost").await {
                Ok(_) => true,
                Err(e) => {
                    warn!(error = %e, "DNS health check failed");
                    false
                }
            }
        })
    }
}

impl std::fmt::Debug for DnsDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsDiscovery")
            .field("domain", &self.config.domain)
            .field("method", &self.method)
            .field("default_port", &self.config.default_port)
            .finish()
    }
}

/// Sorts discovered peers by priority and weight.
///
/// Lower priority values are preferred. Within the same priority,
/// higher weight values are preferred.
pub fn sort_peers(peers: &mut [DiscoveredPeer]) {
    peers.sort_by(|a, b| {
        // First sort by priority (lower is better)
        match a.priority.cmp(&b.priority) {
            std::cmp::Ordering::Equal => {
                // Then by weight (higher is better)
                b.weight.cmp(&a.weight)
            }
            other => other,
        }
    });
}

/// Selects a peer using weighted random selection within a priority group.
///
/// This implements RFC 2782 weight-based selection for SRV records.
#[must_use]
pub fn select_weighted_peer(peers: &[DiscoveredPeer]) -> Option<&DiscoveredPeer> {
    use std::time::{SystemTime, UNIX_EPOCH};

    if peers.is_empty() {
        return None;
    }

    // Group by priority
    let min_priority = peers.iter().map(|p| p.priority).min().unwrap_or(0);
    let same_priority: Vec<&DiscoveredPeer> = peers
        .iter()
        .filter(|p| p.priority == min_priority)
        .collect();

    if same_priority.len() == 1 {
        return Some(same_priority[0]);
    }

    // Calculate total weight
    let total_weight: u32 = same_priority.iter().map(|p| u32::from(p.weight)).sum();
    if total_weight == 0 {
        // If all weights are 0, pick randomly
        let random = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as usize)
            .unwrap_or(0);
        return Some(same_priority[random % same_priority.len()]);
    }

    // Weighted random selection
    let random = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_nanos() % u128::from(total_weight)) as u32)
        .unwrap_or(0);

    let mut cumulative = 0u32;
    for peer in &same_priority {
        cumulative += u32::from(peer.weight);
        if random < cumulative {
            return Some(peer);
        }
    }

    // Fallback to first peer
    Some(same_priority[0])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_peers_by_priority() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let mut peers = vec![
            DiscoveredPeer::new(addr).with_priority(20).with_weight(100),
            DiscoveredPeer::new(addr).with_priority(10).with_weight(50),
            DiscoveredPeer::new(addr).with_priority(10).with_weight(100),
        ];

        sort_peers(&mut peers);

        assert_eq!(peers[0].priority, 10);
        assert_eq!(peers[0].weight, 100); // Higher weight first within same priority
        assert_eq!(peers[1].priority, 10);
        assert_eq!(peers[1].weight, 50);
        assert_eq!(peers[2].priority, 20);
    }

    #[test]
    fn test_select_weighted_peer_single() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let peers = vec![DiscoveredPeer::new(addr).with_priority(10).with_weight(100)];

        let selected = select_weighted_peer(&peers);
        assert!(selected.is_some());
    }

    #[test]
    fn test_select_weighted_peer_empty() {
        let peers: Vec<DiscoveredPeer> = vec![];
        let selected = select_weighted_peer(&peers);
        assert!(selected.is_none());
    }

    #[test]
    fn test_select_weighted_peer_zero_weights() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let peers = vec![
            DiscoveredPeer::new(addr).with_priority(10).with_weight(0),
            DiscoveredPeer::new(addr).with_priority(10).with_weight(0),
        ];

        let selected = select_weighted_peer(&peers);
        assert!(selected.is_some());
    }

    // Integration tests require DNS resolution
    // Run with: cargo test --features dns -- --ignored

    #[tokio::test]
    #[ignore = "requires network and DNS"]
    async fn test_dns_a_discovery() {
        let config = DnsConfig {
            domain: "localhost".to_string(),
            default_port: 5070,
            ..Default::default()
        };

        let discovery = DnsDiscovery::new(config, DiscoveryMethod::DnsA).unwrap();
        let peers = discovery.discover().await;

        // localhost should resolve
        assert!(peers.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires network and DNS"]
    async fn test_dns_health_check() {
        let config = DnsConfig::default();
        let discovery = DnsDiscovery::new(config, DiscoveryMethod::DnsA).unwrap();

        assert!(discovery.health_check().await);
    }
}
