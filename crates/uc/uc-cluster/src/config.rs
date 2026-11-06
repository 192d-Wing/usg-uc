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
    /// Cluster semantics of the per-node admission caps.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), CP-2(2) (Capacity Planning)
    pub admission: ClusterAdmissionConfig,
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
            admission: ClusterAdmissionConfig::default(),
        }
    }
}

/// How configured admission caps (`max_calls`, `max_registrations`, trunk
/// `max_calls`) apply across a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionSplit {
    /// Every node enforces the full configured cap (an N-node cluster
    /// admits up to N x cap). Backward-compatible default.
    #[default]
    PerNode,
    /// Every node enforces `cap / expected_nodes` (rounded down, at least
    /// 1), so the cluster total never exceeds the configured cap.
    Divide,
}

/// Most nodes `cluster.admission.expected_nodes` may name.
pub const MAX_EXPECTED_NODES: u32 = 64;

/// Static cluster-wide admission split (POA&M-1 phase 1).
///
/// The share is computed once at config load from `expected_nodes`, not
/// from live membership, so a partition cannot raise it (fails closed).
///
/// ## NIST 800-53 Rev5: SC-5, SC-24 (Fail in Known State), CM-6
// POAM: POA&M-80 — phase 2 of POA&M-1 (lease borrowing over uc-storage so survivors can
// use a dead node's share) is not implemented; a node's share is static and
// operators must update `expected_nodes` when the cluster is resized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// CM-6: a misspelled key must not silently fall back to `expected_nodes = 1`.
#[serde(default, deny_unknown_fields)]
pub struct ClusterAdmissionConfig {
    /// Whether caps are per node or divided across `expected_nodes`.
    pub split: AdmissionSplit,
    /// Number of nodes the caps are divided across (1..=64).
    pub expected_nodes: u32,
}

impl Default for ClusterAdmissionConfig {
    fn default() -> Self {
        Self {
            split: AdmissionSplit::PerNode,
            expected_nodes: 1,
        }
    }
}

impl ClusterAdmissionConfig {
    /// Divisor applied to divided caps on this node (1 under `per_node`).
    #[must_use]
    pub const fn divisor(&self) -> u32 {
        match self.split {
            AdmissionSplit::PerNode => 1,
            AdmissionSplit::Divide => {
                if self.expected_nodes == 0 {
                    1
                } else {
                    self.expected_nodes
                }
            }
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
        assert_ne!(generated_id.as_str(), "");
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
        assert_eq!(config.snapshot_interval(), Duration::from_mins(5));
        assert_eq!(config.max_lag(), Duration::from_secs(5));
    }

    #[test]
    fn qa_admission_divisor() {
        let mut a = ClusterAdmissionConfig::default();
        assert_eq!(a.split, AdmissionSplit::PerNode);
        assert_eq!(a.expected_nodes, 1);
        assert_eq!(a.divisor(), 1);
        a.expected_nodes = 5;
        assert_eq!(a.divisor(), 1, "per_node ignores expected_nodes");
        a.split = AdmissionSplit::Divide;
        assert_eq!(a.divisor(), 5);
        a.expected_nodes = 0;
        assert_eq!(a.divisor(), 1, "0 never divides by zero");
        a.expected_nodes = MAX_EXPECTED_NODES;
        assert_eq!(a.divisor(), 64);
    }

    #[test]
    fn qa_admission_serde_default_and_names() {
        let c: ClusterConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c.admission, ClusterAdmissionConfig::default());
        let a: ClusterAdmissionConfig =
            serde_json::from_str(r#"{"split":"divide","expected_nodes":3}"#).unwrap();
        assert_eq!(a.split, AdmissionSplit::Divide);
        assert_eq!(a.divisor(), 3);
        assert_eq!(
            serde_json::to_string(&AdmissionSplit::PerNode).unwrap(),
            r#""per_node""#
        );
        assert!(serde_json::from_str::<ClusterAdmissionConfig>(r#"{"split":"Divide"}"#).is_err());
        // NIST-001: typo in a key is rejected, not ignored.
        assert!(
            serde_json::from_str::<ClusterAdmissionConfig>(
                r#"{"split":"divide","expected_node":3}"#
            )
            .is_err()
        );
    }
}
