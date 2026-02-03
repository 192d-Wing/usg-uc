//! Cluster membership management.

use crate::config::{ClusterConfig, FailoverStrategy};
use crate::error::{ClusterError, ClusterResult};
use crate::health::{HealthChecker, HealthStatus, Heartbeat};
use crate::node::{ClusterNode, NodeEndpoints, NodeId, NodeState, NodeSummary};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Quorum calculation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumPolicy {
    /// Simple majority (N/2 + 1).
    Majority,
    /// All nodes required.
    All,
    /// Specific count required.
    Count(usize),
    /// Weighted by role.
    Weighted {
        /// Weight for primary nodes.
        primary_weight: u32,
        /// Weight for secondary nodes.
        secondary_weight: u32,
        /// Weight for witness nodes.
        witness_weight: u32,
    },
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self::Majority
    }
}

impl QuorumPolicy {
    /// Checks if quorum is satisfied.
    #[must_use]
    pub fn has_quorum(&self, active: usize, total: usize) -> bool {
        if total == 0 {
            return false;
        }

        match self {
            Self::Majority => active > total / 2,
            Self::All => active == total,
            Self::Count(n) => active >= *n,
            Self::Weighted { .. } => {
                // For weighted, use majority as fallback
                active > total / 2
            }
        }
    }

    /// Returns the minimum number of nodes required for quorum.
    #[must_use]
    pub fn minimum_for_quorum(&self, total: usize) -> usize {
        match self {
            Self::Majority => total / 2 + 1,
            Self::All => total,
            Self::Count(n) => *n,
            Self::Weighted { .. } => total / 2 + 1,
        }
    }
}

/// Cluster membership state for a single node.
struct MemberState {
    node: ClusterNode,
    health_checker: HealthChecker,
}

/// Manages cluster membership.
pub struct ClusterMembership {
    /// Local node configuration.
    config: ClusterConfig,
    /// Local node ID.
    local_node_id: NodeId,
    /// Known cluster members.
    members: RwLock<HashMap<NodeId, MemberState>>,
    /// Current cluster view version.
    view_version: AtomicU64,
    /// Quorum policy.
    quorum_policy: QuorumPolicy,
}

impl ClusterMembership {
    /// Creates a new cluster membership manager.
    #[must_use]
    pub fn new(config: ClusterConfig) -> Self {
        let local_node_id = config.effective_node_id();

        Self {
            config,
            local_node_id,
            members: RwLock::new(HashMap::new()),
            view_version: AtomicU64::new(0),
            quorum_policy: QuorumPolicy::default(),
        }
    }

    /// Returns the local node ID.
    #[must_use]
    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    /// Returns the current view version.
    #[must_use]
    pub fn view_version(&self) -> u64 {
        self.view_version.load(Ordering::SeqCst)
    }

    /// Sets the quorum policy.
    pub fn set_quorum_policy(&mut self, policy: QuorumPolicy) {
        self.quorum_policy = policy;
    }

    /// Adds a node to the cluster membership.
    ///
    /// # Errors
    /// Returns an error if the node already exists.
    pub async fn add_node(&self, node: ClusterNode) -> ClusterResult<()> {
        let mut members = self.members.write().await;

        if members.contains_key(&node.id) {
            return Err(ClusterError::NodeAlreadyExists {
                node_id: node.id.to_string(),
            });
        }

        info!(node_id = %node.id, role = %node.role, "Adding node to cluster");

        let health_checker = HealthChecker::new(self.config.heartbeat.clone());
        members.insert(
            node.id.clone(),
            MemberState {
                node,
                health_checker,
            },
        );

        self.increment_view_version();
        Ok(())
    }

    /// Removes a node from the cluster membership.
    ///
    /// # Errors
    /// Returns an error if the node is not found.
    pub async fn remove_node(&self, node_id: &NodeId) -> ClusterResult<ClusterNode> {
        let mut members = self.members.write().await;

        let state = members
            .remove(node_id)
            .ok_or_else(|| ClusterError::NodeNotFound {
                node_id: node_id.to_string(),
            })?;

        info!(node_id = %node_id, "Removed node from cluster");
        self.increment_view_version();

        Ok(state.node)
    }

    /// Returns a node by ID.
    pub async fn get_node(&self, node_id: &NodeId) -> Option<NodeSummary> {
        let members = self.members.read().await;
        members
            .get(node_id)
            .map(|state| NodeSummary::from(&state.node))
    }

    /// Returns all active members.
    pub async fn active_members(&self) -> Vec<NodeSummary> {
        let members = self.members.read().await;
        members
            .values()
            .filter(|state| state.node.state.can_vote())
            .map(|state| NodeSummary::from(&state.node))
            .collect()
    }

    /// Returns all members.
    pub async fn all_members(&self) -> Vec<NodeSummary> {
        let members = self.members.read().await;
        members
            .values()
            .map(|state| NodeSummary::from(&state.node))
            .collect()
    }

    /// Returns the number of members.
    pub async fn member_count(&self) -> usize {
        self.members.read().await.len()
    }

    /// Checks if quorum is maintained.
    pub async fn has_quorum(&self) -> bool {
        let members = self.members.read().await;
        let active = members
            .values()
            .filter(|state| state.health_checker.status().is_available())
            .count();
        let total = members.len();

        self.quorum_policy.has_quorum(active, total)
    }

    /// Returns quorum status.
    pub async fn quorum_status(&self) -> QuorumStatus {
        let members = self.members.read().await;
        let active = members
            .values()
            .filter(|state| state.health_checker.status().is_available())
            .count();
        let total = members.len();

        QuorumStatus {
            has_quorum: self.quorum_policy.has_quorum(active, total),
            active_voters: active,
            total_voters: total,
            required: self.quorum_policy.minimum_for_quorum(total),
        }
    }

    /// Handles a heartbeat from a peer.
    pub async fn handle_heartbeat(&self, heartbeat: Heartbeat) -> ClusterResult<()> {
        let mut members = self.members.write().await;

        if let Some(state) = members.get_mut(&heartbeat.node_id) {
            state.health_checker.record_heartbeat(heartbeat.sequence);
            state.node.state = heartbeat.state;
            state.node.health_score = heartbeat.health_score;
            state.node.active_calls = heartbeat.active_calls;
            state.node.active_registrations = heartbeat.active_registrations;
            state.node.touch_heartbeat();

            debug!(
                node_id = %heartbeat.node_id,
                sequence = heartbeat.sequence,
                state = %heartbeat.state,
                "Processed heartbeat"
            );
        } else {
            debug!(
                node_id = %heartbeat.node_id,
                "Received heartbeat from unknown node"
            );
        }

        Ok(())
    }

    /// Checks for failed nodes based on heartbeat timeouts.
    pub async fn check_failures(&self) -> Vec<NodeId> {
        let members = self.members.read().await;
        let mut failed = Vec::new();

        for (node_id, state) in members.iter() {
            if state.health_checker.status() == HealthStatus::Dead {
                warn!(node_id = %node_id, "Node detected as failed");
                failed.push(node_id.clone());
            }
        }

        failed
    }

    /// Marks a node as failed.
    pub async fn mark_failed(&self, node_id: &NodeId) -> ClusterResult<()> {
        let mut members = self.members.write().await;

        let state = members
            .get_mut(node_id)
            .ok_or_else(|| ClusterError::NodeNotFound {
                node_id: node_id.to_string(),
            })?;

        state.node.set_state(NodeState::Unhealthy);
        self.increment_view_version();

        warn!(node_id = %node_id, "Marked node as failed");
        Ok(())
    }

    /// Selects the best failover target based on the configured strategy.
    pub async fn select_failover_target(&self, local_node: &ClusterNode) -> Option<NodeId> {
        let members = self.members.read().await;

        let candidates: Vec<_> = members
            .values()
            .filter(|state| {
                state.node.id != self.local_node_id
                    && state.node.state.is_healthy()
                    && state.health_checker.status().is_available()
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        match self.config.failover.strategy {
            FailoverStrategy::PreferSameZone => {
                // Prefer same zone, then same region, then any
                candidates
                    .iter()
                    .filter(|s| s.node.is_same_zone(local_node))
                    .min_by_key(|s| s.node.active_calls)
                    .or_else(|| {
                        candidates
                            .iter()
                            .filter(|s| s.node.is_same_region(local_node))
                            .min_by_key(|s| s.node.active_calls)
                    })
                    .or_else(|| candidates.iter().min_by_key(|s| s.node.active_calls))
                    .map(|s| s.node.id.clone())
            }
            FailoverStrategy::PreferSameRegion => candidates
                .iter()
                .filter(|s| s.node.is_same_region(local_node))
                .min_by_key(|s| s.node.active_calls)
                .or_else(|| candidates.iter().min_by_key(|s| s.node.active_calls))
                .map(|s| s.node.id.clone()),
            FailoverStrategy::LeastLoaded => candidates
                .iter()
                .min_by_key(|s| s.node.active_calls)
                .map(|s| s.node.id.clone()),
            FailoverStrategy::Priority => {
                // Use alphabetical order as priority
                candidates
                    .iter()
                    .min_by(|a, b| a.node.id.as_str().cmp(b.node.id.as_str()))
                    .map(|s| s.node.id.clone())
            }
        }
    }

    /// Increments the view version.
    fn increment_view_version(&self) {
        self.view_version.fetch_add(1, Ordering::SeqCst);
    }
}

/// Quorum status information.
#[derive(Debug, Clone)]
pub struct QuorumStatus {
    /// Whether quorum is satisfied.
    pub has_quorum: bool,
    /// Number of active voting members.
    pub active_voters: usize,
    /// Total number of voting members.
    pub total_voters: usize,
    /// Minimum required for quorum.
    pub required: usize,
}

/// Creates a local cluster node from configuration.
#[must_use]
pub fn create_local_node(config: &ClusterConfig, endpoints: NodeEndpoints) -> ClusterNode {
    ClusterNode::new(
        config.effective_node_id(),
        config.role,
        config.region.clone(),
        config.zone.clone(),
        endpoints,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::node::NodeRole;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use uc_types::SbcSocketAddr;

    fn create_test_config() -> ClusterConfig {
        ClusterConfig::builder()
            .cluster_id("test-cluster")
            .node_id("local-node")
            .region("us-east-1")
            .zone("us-east-1a")
            .build()
    }

    fn create_test_endpoints() -> NodeEndpoints {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
        NodeEndpoints::new(
            SbcSocketAddr::from(addr),
            addr,
            addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        )
    }

    #[test]
    fn test_quorum_policy_majority() {
        let policy = QuorumPolicy::Majority;
        assert!(policy.has_quorum(2, 3));
        assert!(policy.has_quorum(3, 5));
        assert!(!policy.has_quorum(1, 3));
        assert!(!policy.has_quorum(2, 5));
    }

    #[test]
    fn test_quorum_policy_all() {
        let policy = QuorumPolicy::All;
        assert!(policy.has_quorum(3, 3));
        assert!(!policy.has_quorum(2, 3));
    }

    #[test]
    fn test_quorum_policy_count() {
        let policy = QuorumPolicy::Count(2);
        assert!(policy.has_quorum(2, 5));
        assert!(policy.has_quorum(3, 5));
        assert!(!policy.has_quorum(1, 5));
    }

    #[tokio::test]
    async fn test_membership_add_remove_node() {
        let config = create_test_config();
        let membership = ClusterMembership::new(config);

        let node = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node).await.unwrap();
        assert_eq!(membership.member_count().await, 1);

        let removed = membership
            .remove_node(&NodeId::new("node-01"))
            .await
            .unwrap();
        assert_eq!(removed.id.as_str(), "node-01");
        assert_eq!(membership.member_count().await, 0);
    }

    #[tokio::test]
    async fn test_membership_duplicate_node() {
        let config = create_test_config();
        let membership = ClusterMembership::new(config);

        let node1 = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        let node2 = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1b".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node1).await.unwrap();
        let result = membership.add_node(node2).await;
        assert!(matches!(
            result,
            Err(ClusterError::NodeAlreadyExists { .. })
        ));
    }

    #[tokio::test]
    async fn test_membership_view_version() {
        let config = create_test_config();
        let membership = ClusterMembership::new(config);

        let initial_version = membership.view_version();

        let node = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node).await.unwrap();
        assert!(membership.view_version() > initial_version);
    }
}
