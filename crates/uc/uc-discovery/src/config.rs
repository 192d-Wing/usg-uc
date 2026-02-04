//! Discovery configuration types.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    /// Discovery method to use.
    pub method: DiscoveryMethod,
    /// Refresh interval in milliseconds.
    pub refresh_interval_ms: u64,
    /// Static peer list (for static discovery).
    #[serde(default)]
    pub static_peers: Vec<SocketAddr>,
    /// DNS configuration (for DNS discovery).
    pub dns: Option<DnsConfig>,
    /// Kubernetes configuration (for K8s discovery).
    pub kubernetes: Option<KubernetesConfig>,
    /// Gossip configuration.
    pub gossip: GossipConfig,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: DiscoveryMethod::Static,
            refresh_interval_ms: 30000,
            static_peers: Vec::new(),
            dns: None,
            kubernetes: None,
            gossip: GossipConfig::default(),
        }
    }
}

impl DiscoveryConfig {
    /// Creates a new discovery configuration builder.
    #[must_use]
    pub fn builder() -> DiscoveryConfigBuilder {
        DiscoveryConfigBuilder::default()
    }

    /// Returns the refresh interval as a Duration.
    #[must_use]
    pub const fn refresh_interval(&self) -> Duration {
        Duration::from_millis(self.refresh_interval_ms)
    }
}

/// Builder for discovery configuration.
#[derive(Debug, Default)]
pub struct DiscoveryConfigBuilder {
    config: DiscoveryConfig,
}

impl DiscoveryConfigBuilder {
    /// Sets the discovery method.
    #[must_use]
    pub const fn method(mut self, method: DiscoveryMethod) -> Self {
        self.config.method = method;
        self
    }

    /// Sets the refresh interval in milliseconds.
    #[must_use]
    pub const fn refresh_interval_ms(mut self, interval_ms: u64) -> Self {
        self.config.refresh_interval_ms = interval_ms;
        self
    }

    /// Sets the static peer list.
    #[must_use]
    pub fn static_peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.config.static_peers = peers;
        self
    }

    /// Adds a static peer.
    #[must_use]
    pub fn add_static_peer(mut self, peer: SocketAddr) -> Self {
        self.config.static_peers.push(peer);
        self
    }

    /// Sets the DNS configuration.
    #[must_use]
    pub fn dns(mut self, dns: DnsConfig) -> Self {
        self.config.dns = Some(dns);
        self
    }

    /// Sets the Kubernetes configuration.
    #[must_use]
    pub fn kubernetes(mut self, kubernetes: KubernetesConfig) -> Self {
        self.config.kubernetes = Some(kubernetes);
        self
    }

    /// Sets the gossip configuration.
    #[must_use]
    pub fn gossip(mut self, gossip: GossipConfig) -> Self {
        self.config.gossip = gossip;
        self
    }

    /// Builds the discovery configuration.
    #[must_use]
    pub fn build(self) -> DiscoveryConfig {
        self.config
    }
}

/// Discovery method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    /// Static peer list.
    #[default]
    Static,
    /// DNS SRV records.
    DnsSrv,
    /// DNS A/AAAA records.
    DnsA,
    /// Kubernetes service discovery.
    Kubernetes,
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "static"),
            Self::DnsSrv => write!(f, "dns_srv"),
            Self::DnsA => write!(f, "dns_a"),
            Self::Kubernetes => write!(f, "kubernetes"),
        }
    }
}

/// DNS discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// DNS domain name to query.
    pub domain: String,
    /// DNS servers to use (empty means system default).
    #[serde(default)]
    pub servers: Vec<SocketAddr>,
    /// Port to use when discovering via A records.
    pub default_port: u16,
    /// DNS query timeout in milliseconds.
    pub timeout_ms: u64,
    /// DNS query retry attempts.
    pub retry_attempts: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            domain: "sbc.local".to_string(),
            servers: Vec::new(),
            default_port: 5070,
            timeout_ms: 5000,
            retry_attempts: 3,
        }
    }
}

impl DnsConfig {
    /// Returns the query timeout as a Duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Kubernetes discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KubernetesConfig {
    /// Namespace to search in (empty means current namespace).
    pub namespace: String,
    /// Service name to look up.
    pub service_name: String,
    /// Port name or number to use.
    pub port: KubernetesPort,
    /// Label selector for filtering endpoints.
    #[serde(default)]
    pub label_selector: Option<String>,
    /// Whether to use in-cluster config.
    pub in_cluster: bool,
    /// Path to kubeconfig (if not using in-cluster).
    pub kubeconfig_path: Option<String>,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            namespace: String::new(),
            service_name: "sbc".to_string(),
            port: KubernetesPort::Named("control".to_string()),
            label_selector: None,
            in_cluster: true,
            kubeconfig_path: None,
        }
    }
}

/// Kubernetes port specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KubernetesPort {
    /// Named port.
    Named(String),
    /// Numeric port.
    Number(u16),
}

impl Default for KubernetesPort {
    fn default() -> Self {
        Self::Named("control".to_string())
    }
}

/// Gossip protocol configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GossipConfig {
    /// Enable gossip protocol.
    pub enabled: bool,
    /// Gossip interval in milliseconds.
    pub interval_ms: u64,
    /// Number of nodes to gossip with per interval.
    pub fanout: usize,
    /// Suspicion multiplier for failure detection.
    pub suspicion_multiplier: u32,
    /// Probe interval in milliseconds.
    pub probe_interval_ms: u64,
    /// Probe timeout in milliseconds.
    pub probe_timeout_ms: u64,
    /// Indirect probes count.
    pub indirect_probes: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 200,
            fanout: 3,
            suspicion_multiplier: 4,
            probe_interval_ms: 1000,
            probe_timeout_ms: 500,
            indirect_probes: 3,
        }
    }
}

impl GossipConfig {
    /// Returns the gossip interval as a Duration.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms)
    }

    /// Returns the probe interval as a Duration.
    #[must_use]
    pub const fn probe_interval(&self) -> Duration {
        Duration::from_millis(self.probe_interval_ms)
    }

    /// Returns the probe timeout as a Duration.
    #[must_use]
    pub const fn probe_timeout(&self) -> Duration {
        Duration::from_millis(self.probe_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.method, DiscoveryMethod::Static);
        assert_eq!(config.refresh_interval_ms, 30000);
        assert!(config.static_peers.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let config = DiscoveryConfig::builder()
            .method(DiscoveryMethod::Static)
            .add_static_peer(addr)
            .refresh_interval_ms(10000)
            .build();

        assert_eq!(config.method, DiscoveryMethod::Static);
        assert_eq!(config.static_peers.len(), 1);
        assert_eq!(config.refresh_interval_ms, 10000);
    }

    #[test]
    fn test_discovery_method_display() {
        assert_eq!(format!("{}", DiscoveryMethod::Static), "static");
        assert_eq!(format!("{}", DiscoveryMethod::DnsSrv), "dns_srv");
        assert_eq!(format!("{}", DiscoveryMethod::DnsA), "dns_a");
        assert_eq!(format!("{}", DiscoveryMethod::Kubernetes), "kubernetes");
    }

    #[test]
    fn test_dns_config_timeout() {
        let config = DnsConfig::default();
        assert_eq!(config.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_gossip_config_durations() {
        let config = GossipConfig::default();
        assert_eq!(config.interval(), Duration::from_millis(200));
        assert_eq!(config.probe_interval(), Duration::from_secs(1));
        assert_eq!(config.probe_timeout(), Duration::from_millis(500));
    }
}
