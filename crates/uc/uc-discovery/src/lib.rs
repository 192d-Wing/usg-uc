//! # Service Discovery for USG SBC Clustering
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::unused_async)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::collapsible_if)]
//!
//! This crate provides service discovery mechanisms for the USG Session Border Controller
//! clustering layer, enabling:
//!
//! - **Static Discovery**: Pre-configured peer list
//! - **DNS Discovery**: SRV and A record-based discovery
//! - **Kubernetes Discovery**: Native K8s service discovery
//! - **Gossip Protocol**: SWIM-style failure detection
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (network discovery)
//! - **CP-7**: Alternate Processing Site
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Discovery Manager                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │   Static    │     DNS       │  Kubernetes  │    Gossip     │
//! │   List      │   SRV/A       │   Endpoints  │   Protocol    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use uc_discovery::{DiscoveryConfig, DiscoveryManager, DiscoveryMethod};
//!
//! let config = DiscoveryConfig::builder()
//!     .method(DiscoveryMethod::Static)
//!     .static_peers(vec!["node1:5070".parse()?, "node2:5070".parse()?])
//!     .build();
//!
//! let manager = DiscoveryManager::new(config);
//! let peers = manager.discover().await?;
//! ```

pub mod config;
pub mod error;
pub mod gossip;
pub mod static_list;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(feature = "kubernetes")]
pub mod kubernetes;

pub use config::{
    DiscoveryConfig, DiscoveryMethod, DnsConfig, GossipConfig, KubernetesConfig, KubernetesPort,
};
pub use error::{DiscoveryError, DiscoveryResult};
pub use gossip::{GossipProtocol, MemberStatus};
pub use static_list::StaticDiscovery;

#[cfg(feature = "dns")]
pub use dns::DnsDiscovery;

#[cfg(feature = "kubernetes")]
pub use kubernetes::KubernetesDiscovery;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use uc_cluster::NodeId;

/// Discovered peer information.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Node ID if known.
    pub node_id: Option<NodeId>,
    /// Control plane address.
    pub address: SocketAddr,
    /// Priority for selection (lower is higher priority).
    pub priority: u16,
    /// Weight for load balancing.
    pub weight: u16,
    /// Optional metadata.
    pub metadata: Option<PeerMetadata>,
}

impl DiscoveredPeer {
    /// Creates a new discovered peer with default priority and weight.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            node_id: None,
            address,
            priority: 0,
            weight: 100,
            metadata: None,
        }
    }

    /// Creates a new discovered peer with a known node ID.
    #[must_use]
    pub fn with_node_id(address: SocketAddr, node_id: NodeId) -> Self {
        Self {
            node_id: Some(node_id),
            address,
            priority: 0,
            weight: 100,
            metadata: None,
        }
    }

    /// Sets the priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the weight.
    #[must_use]
    pub const fn with_weight(mut self, weight: u16) -> Self {
        self.weight = weight;
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: PeerMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Additional peer metadata.
#[derive(Debug, Clone, Default)]
pub struct PeerMetadata {
    /// Geographic region.
    pub region: Option<String>,
    /// Availability zone.
    pub zone: Option<String>,
    /// Custom labels.
    pub labels: std::collections::HashMap<String, String>,
}

impl PeerMetadata {
    /// Creates new empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the region.
    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Sets the zone.
    #[must_use]
    pub fn with_zone(mut self, zone: impl Into<String>) -> Self {
        self.zone = Some(zone.into());
        self
    }

    /// Adds a label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Discovery provider trait.
pub trait DiscoveryProvider: Send + Sync + 'static {
    /// Discovers available peers.
    fn discover(
        &self,
    ) -> Pin<Box<dyn Future<Output = DiscoveryResult<Vec<DiscoveredPeer>>> + Send + '_>>;

    /// Returns the discovery method name.
    fn method_name(&self) -> &'static str;

    /// Checks if the discovery provider is healthy.
    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

/// Discovery manager that coordinates multiple discovery providers.
pub struct DiscoveryManager {
    /// Primary discovery provider.
    provider: Box<dyn DiscoveryProvider>,
    /// Configuration.
    config: DiscoveryConfig,
}

impl DiscoveryManager {
    /// Creates a new discovery manager with the given configuration.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid.
    pub fn new(config: DiscoveryConfig) -> DiscoveryResult<Self> {
        let provider: Box<dyn DiscoveryProvider> = match config.method {
            DiscoveryMethod::Static => Box::new(StaticDiscovery::new(config.static_peers.clone())),
            #[cfg(feature = "dns")]
            DiscoveryMethod::DnsSrv | DiscoveryMethod::DnsA => {
                let dns_config = config
                    .dns
                    .clone()
                    .ok_or_else(|| DiscoveryError::ConfigError {
                        reason: "DNS discovery requires dns configuration".to_string(),
                    })?;
                Box::new(DnsDiscovery::new(dns_config, config.method)?)
            }
            #[cfg(not(feature = "dns"))]
            DiscoveryMethod::DnsSrv | DiscoveryMethod::DnsA => {
                return Err(DiscoveryError::ConfigError {
                    reason: "DNS discovery requires the 'dns' feature".to_string(),
                });
            }
            #[cfg(feature = "kubernetes")]
            DiscoveryMethod::Kubernetes => {
                let k8s_config =
                    config
                        .kubernetes
                        .clone()
                        .ok_or_else(|| DiscoveryError::ConfigError {
                            reason: "Kubernetes discovery requires kubernetes configuration"
                                .to_string(),
                        })?;
                Box::new(KubernetesDiscovery::new(k8s_config)?)
            }
            #[cfg(not(feature = "kubernetes"))]
            DiscoveryMethod::Kubernetes => {
                return Err(DiscoveryError::ConfigError {
                    reason: "Kubernetes discovery requires the 'kubernetes' feature".to_string(),
                });
            }
        };

        Ok(Self { provider, config })
    }

    /// Discovers available peers.
    ///
    /// # Errors
    /// Returns an error if discovery fails.
    pub async fn discover(&self) -> DiscoveryResult<Vec<DiscoveredPeer>> {
        self.provider.discover().await
    }

    /// Returns the configured discovery method.
    #[must_use]
    pub fn method(&self) -> DiscoveryMethod {
        self.config.method
    }

    /// Returns the discovery method name.
    #[must_use]
    pub fn method_name(&self) -> &'static str {
        self.provider.method_name()
    }

    /// Performs a health check on the discovery provider.
    pub async fn health_check(&self) -> bool {
        self.provider.health_check().await
    }
}

impl std::fmt::Debug for DiscoveryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryManager")
            .field("method", &self.method_name())
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_peer_creation() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let peer = DiscoveredPeer::new(addr);

        assert_eq!(peer.address, addr);
        assert!(peer.node_id.is_none());
        assert_eq!(peer.priority, 0);
        assert_eq!(peer.weight, 100);
    }

    #[test]
    fn test_discovered_peer_with_node_id() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let peer = DiscoveredPeer::with_node_id(addr, NodeId::new("node-01"));

        assert_eq!(peer.node_id.as_ref().unwrap().as_str(), "node-01");
    }

    #[test]
    fn test_peer_metadata() {
        let metadata = PeerMetadata::new()
            .with_region("us-east-1")
            .with_zone("us-east-1a")
            .with_label("env", "prod");

        assert_eq!(metadata.region.as_deref(), Some("us-east-1"));
        assert_eq!(metadata.zone.as_deref(), Some("us-east-1a"));
        assert_eq!(metadata.labels.get("env"), Some(&"prod".to_string()));
    }
}
