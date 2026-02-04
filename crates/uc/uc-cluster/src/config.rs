//! Cluster configuration types.

use crate::node::{NodeId, NodeRole};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Cluster configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterConfig {
    /// Enable clustering.
    pub enabled: bool,
    /// Unique cluster identifier.
    pub cluster_id: String,
    /// This node's unique identifier.
    pub node_id: Option<String>,
    /// Node role (primary, secondary, witness).
    pub role: NodeRole,
    /// Geographic region for geo-aware routing.
    pub region: String,
    /// Availability zone within region.
    pub zone: String,
    /// Control plane bind address.
    pub control_bind: SocketAddr,
    /// Heartbeat configuration.
    pub heartbeat: HeartbeatConfig,
    /// Failover configuration.
    pub failover: FailoverConfig,
    /// Replication configuration.
    pub replication: ReplicationConfig,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cluster_id: "sbc-cluster".to_string(),
            node_id: None,
            role: NodeRole::Primary,
            region: "default".to_string(),
            zone: "zone-a".to_string(),
            control_bind: "[::]:5070".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 5070)
            }),
            heartbeat: HeartbeatConfig::default(),
            failover: FailoverConfig::default(),
            replication: ReplicationConfig::default(),
        }
    }
}

impl ClusterConfig {
    /// Creates a new cluster configuration builder.
    #[must_use]
    pub fn builder() -> ClusterConfigBuilder {
        ClusterConfigBuilder::default()
    }

    /// Returns the effective node ID, generating one if not specified.
    #[must_use]
    pub fn effective_node_id(&self) -> NodeId {
        self.node_id
            .clone()
            .map(NodeId::new)
            .unwrap_or_else(|| NodeId::new(generate_node_id()))
    }
}

/// Generates a unique node ID based on process ID and timestamp.
fn generate_node_id() -> String {
    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("node-{pid}-{timestamp}")
}

/// Builder for cluster configuration.
#[derive(Debug, Default)]
pub struct ClusterConfigBuilder {
    config: ClusterConfig,
}

impl ClusterConfigBuilder {
    /// Sets the cluster ID.
    #[must_use]
    pub fn cluster_id(mut self, id: impl Into<String>) -> Self {
        self.config.cluster_id = id.into();
        self
    }

    /// Sets the node ID.
    #[must_use]
    pub fn node_id(mut self, id: impl Into<String>) -> Self {
        self.config.node_id = Some(id.into());
        self
    }

    /// Sets the node role.
    #[must_use]
    pub const fn role(mut self, role: NodeRole) -> Self {
        self.config.role = role;
        self
    }

    /// Sets the region.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.config.region = region.into();
        self
    }

    /// Sets the zone.
    #[must_use]
    pub fn zone(mut self, zone: impl Into<String>) -> Self {
        self.config.zone = zone.into();
        self
    }

    /// Sets the control plane bind address.
    #[must_use]
    pub const fn control_bind(mut self, addr: SocketAddr) -> Self {
        self.config.control_bind = addr;
        self
    }

    /// Sets the heartbeat configuration.
    #[must_use]
    pub fn heartbeat(mut self, heartbeat: HeartbeatConfig) -> Self {
        self.config.heartbeat = heartbeat;
        self
    }

    /// Sets the failover configuration.
    #[must_use]
    pub fn failover(mut self, failover: FailoverConfig) -> Self {
        self.config.failover = failover;
        self
    }

    /// Sets the replication configuration.
    #[must_use]
    pub fn replication(mut self, replication: ReplicationConfig) -> Self {
        self.config.replication = replication;
        self
    }

    /// Enables clustering.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Builds the cluster configuration.
    #[must_use]
    pub fn build(self) -> ClusterConfig {
        self.config
    }
}

/// Heartbeat configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in milliseconds.
    pub interval_ms: u64,
    /// Number of missed heartbeats before marking node as suspect.
    pub suspect_threshold: u32,
    /// Number of missed heartbeats before marking node as dead.
    pub dead_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            suspect_threshold: 3,
            dead_threshold: 5,
        }
    }
}

impl HeartbeatConfig {
    /// Returns the heartbeat interval as a Duration.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms)
    }

    /// Returns the duration before a node is considered suspect.
    #[must_use]
    pub const fn suspect_timeout(&self) -> Duration {
        Duration::from_millis(self.interval_ms * self.suspect_threshold as u64)
    }

    /// Returns the duration before a node is considered dead.
    #[must_use]
    pub const fn dead_timeout(&self) -> Duration {
        Duration::from_millis(self.interval_ms * self.dead_threshold as u64)
    }
}

/// Failover configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FailoverConfig {
    /// Time before declaring a node dead (milliseconds).
    pub failure_detection_timeout_ms: u64,
    /// Grace period for draining before takeover (milliseconds).
    pub drain_timeout_ms: u64,
    /// Maximum time for state sync during takeover (milliseconds).
    pub sync_timeout_ms: u64,
    /// Strategy for failover target selection.
    pub strategy: FailoverStrategy,
    /// Automatic failover enabled.
    pub auto_failover: bool,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            failure_detection_timeout_ms: 5000,
            drain_timeout_ms: 30000,
            sync_timeout_ms: 10000,
            strategy: FailoverStrategy::PreferSameZone,
            auto_failover: true,
        }
    }
}

impl FailoverConfig {
    /// Returns the failure detection timeout as a Duration.
    #[must_use]
    pub const fn failure_detection_timeout(&self) -> Duration {
        Duration::from_millis(self.failure_detection_timeout_ms)
    }

    /// Returns the drain timeout as a Duration.
    #[must_use]
    pub const fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms)
    }

    /// Returns the sync timeout as a Duration.
    #[must_use]
    pub const fn sync_timeout(&self) -> Duration {
        Duration::from_millis(self.sync_timeout_ms)
    }
}

/// Strategy for selecting failover target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailoverStrategy {
    /// Prefer nodes in the same zone.
    #[default]
    PreferSameZone,
    /// Prefer nodes in the same region.
    PreferSameRegion,
    /// Prefer node with fewest active calls.
    LeastLoaded,
    /// Explicit priority list (based on node IDs).
    Priority,
}

/// Replication configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationConfig {
    /// Replication mode.
    pub mode: ReplicationMode,
    /// Batch size for replication.
    pub batch_size: usize,
    /// Replication interval in milliseconds.
    pub replication_interval_ms: u64,
    /// Snapshot interval in seconds.
    pub snapshot_interval_secs: u64,
    /// Maximum lag before triggering catch-up sync (milliseconds).
    pub max_lag_ms: u64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            mode: ReplicationMode::SemiSynchronous,
            batch_size: 100,
            replication_interval_ms: 100,
            snapshot_interval_secs: 300,
            max_lag_ms: 5000,
        }
    }
}

impl ReplicationConfig {
    /// Returns the replication interval as a Duration.
    #[must_use]
    pub const fn replication_interval(&self) -> Duration {
        Duration::from_millis(self.replication_interval_ms)
    }

    /// Returns the snapshot interval as a Duration.
    #[must_use]
    pub const fn snapshot_interval(&self) -> Duration {
        Duration::from_secs(self.snapshot_interval_secs)
    }

    /// Returns the max lag as a Duration.
    #[must_use]
    pub const fn max_lag(&self) -> Duration {
        Duration::from_millis(self.max_lag_ms)
    }
}

/// Replication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    /// Synchronous - wait for N nodes to acknowledge.
    Synchronous {
        /// Minimum acknowledgments required.
        min_acks: usize,
    },
    /// Asynchronous - fire and forget.
    Asynchronous,
    /// Semi-synchronous - ack from at least one peer.
    #[default]
    SemiSynchronous,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClusterConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.cluster_id, "sbc-cluster");
        assert!(config.node_id.is_none());
        assert_eq!(config.role, NodeRole::Primary);
    }

    #[test]
    fn test_config_builder() {
        let config = ClusterConfig::builder()
            .cluster_id("test-cluster")
            .node_id("node-01")
            .role(NodeRole::Secondary)
            .region("us-west-2")
            .zone("us-west-2a")
            .enabled(true)
            .build();

        assert!(config.enabled);
        assert_eq!(config.cluster_id, "test-cluster");
        assert_eq!(config.node_id, Some("node-01".to_string()));
        assert_eq!(config.role, NodeRole::Secondary);
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.zone, "us-west-2a");
    }

    #[test]
    fn test_heartbeat_timeouts() {
        let config = HeartbeatConfig {
            interval_ms: 1000,
            suspect_threshold: 3,
            dead_threshold: 5,
        };

        assert_eq!(config.suspect_timeout(), Duration::from_secs(3));
        assert_eq!(config.dead_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_effective_node_id() {
        let config = ClusterConfig::builder().node_id("explicit-node").build();
        assert_eq!(config.effective_node_id().as_str(), "explicit-node");

        let config_no_id = ClusterConfig::default();
        let generated_id = config_no_id.effective_node_id();
        assert!(!generated_id.as_str().is_empty());
        assert!(generated_id.as_str().starts_with("node-"));
    }

    #[test]
    fn test_failover_config_durations() {
        let config = FailoverConfig::default();
        assert_eq!(config.failure_detection_timeout(), Duration::from_secs(5));
        assert_eq!(config.drain_timeout(), Duration::from_secs(30));
        assert_eq!(config.sync_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_replication_config_durations() {
        let config = ReplicationConfig::default();
        assert_eq!(config.replication_interval(), Duration::from_millis(100));
        assert_eq!(config.snapshot_interval(), Duration::from_secs(300));
        assert_eq!(config.max_lag(), Duration::from_secs(5));
    }
}
