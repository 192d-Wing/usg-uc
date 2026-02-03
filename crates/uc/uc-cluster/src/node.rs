//! Cluster node types and state management.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::time::Instant;
use uc_types::SbcSocketAddr;

/// Unique identifier for a cluster node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Creates a new node ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the node ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Role of a node in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Primary node - actively handles traffic.
    #[default]
    Primary,
    /// Secondary node - standby, ready to take over.
    Secondary,
    /// Witness node - participates in quorum but doesn't handle traffic.
    Witness,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => write!(f, "primary"),
            Self::Secondary => write!(f, "secondary"),
            Self::Witness => write!(f, "witness"),
        }
    }
}

/// State of a node in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeState {
    /// Node is starting up.
    #[default]
    Starting,
    /// Node is syncing state from peers.
    Syncing,
    /// Node is ready and healthy but not yet active.
    Ready,
    /// Node is actively handling traffic.
    Active,
    /// Node is draining connections for graceful handoff.
    Draining,
    /// Node is unhealthy and should not receive traffic.
    Unhealthy,
    /// Node is shutting down.
    ShuttingDown,
}

impl NodeState {
    /// Returns true if the node can handle traffic.
    #[must_use]
    pub const fn can_handle_traffic(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns true if the node is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Ready | Self::Active | Self::Draining)
    }

    /// Returns true if the node can participate in quorum.
    #[must_use]
    pub const fn can_vote(&self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Active | Self::Draining | Self::Syncing
        )
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Syncing => write!(f, "syncing"),
            Self::Ready => write!(f, "ready"),
            Self::Active => write!(f, "active"),
            Self::Draining => write!(f, "draining"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

/// Network endpoints for a cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEndpoints {
    /// SIP signaling endpoint.
    pub sip: SbcSocketAddr,
    /// Cluster control plane endpoint.
    pub control: SocketAddr,
    /// State sync endpoint.
    pub sync: SocketAddr,
    /// API endpoint.
    pub api: SocketAddr,
}

impl NodeEndpoints {
    /// Creates new node endpoints.
    #[must_use]
    pub const fn new(
        sip: SbcSocketAddr,
        control: SocketAddr,
        sync: SocketAddr,
        api: SocketAddr,
    ) -> Self {
        Self {
            sip,
            control,
            sync,
            api,
        }
    }
}

/// Represents a node in the cluster.
#[derive(Debug)]
pub struct ClusterNode {
    /// Unique node identifier.
    pub id: NodeId,
    /// Node role in the cluster.
    pub role: NodeRole,
    /// Current node state.
    pub state: NodeState,
    /// Geographic region.
    pub region: String,
    /// Availability zone within region.
    pub zone: String,
    /// Network endpoints.
    pub endpoints: NodeEndpoints,
    /// Last heartbeat received.
    pub last_heartbeat: Instant,
    /// Health score (0.0 to 1.0).
    pub health_score: f64,
    /// Number of active calls.
    pub active_calls: u32,
    /// Number of active registrations.
    pub active_registrations: u32,
    /// Node generation (incremented on restart).
    pub generation: u64,
}

impl ClusterNode {
    /// Creates a new cluster node.
    #[must_use]
    pub fn new(
        id: NodeId,
        role: NodeRole,
        region: String,
        zone: String,
        endpoints: NodeEndpoints,
    ) -> Self {
        Self {
            id,
            role,
            state: NodeState::Starting,
            region,
            zone,
            endpoints,
            last_heartbeat: Instant::now(),
            health_score: 1.0,
            active_calls: 0,
            active_registrations: 0,
            generation: 1,
        }
    }

    /// Updates the node state.
    pub fn set_state(&mut self, state: NodeState) {
        self.state = state;
    }

    /// Updates the health score.
    pub fn set_health_score(&mut self, score: f64) {
        self.health_score = score.clamp(0.0, 1.0);
    }

    /// Updates the last heartbeat time.
    pub fn touch_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Returns the time since the last heartbeat.
    #[must_use]
    pub fn time_since_heartbeat(&self) -> std::time::Duration {
        self.last_heartbeat.elapsed()
    }

    /// Returns true if the node is in the same zone.
    #[must_use]
    pub fn is_same_zone(&self, other: &Self) -> bool {
        self.region == other.region && self.zone == other.zone
    }

    /// Returns true if the node is in the same region.
    #[must_use]
    pub fn is_same_region(&self, other: &Self) -> bool {
        self.region == other.region
    }
}

/// Summary information about a cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    /// Node ID.
    pub node_id: String,
    /// Node role.
    pub role: NodeRole,
    /// Node state.
    pub state: NodeState,
    /// Geographic region.
    pub region: String,
    /// Availability zone.
    pub zone: String,
    /// Health score.
    pub health_score: f64,
    /// Active calls.
    pub active_calls: u32,
    /// Active registrations.
    pub active_registrations: u32,
    /// Milliseconds since last heartbeat.
    pub ms_since_heartbeat: u64,
}

impl From<&ClusterNode> for NodeSummary {
    fn from(node: &ClusterNode) -> Self {
        Self {
            node_id: node.id.to_string(),
            role: node.role,
            state: node.state,
            region: node.region.clone(),
            zone: node.zone.clone(),
            health_score: node.health_score,
            active_calls: node.active_calls,
            active_registrations: node.active_registrations,
            ms_since_heartbeat: node.time_since_heartbeat().as_millis() as u64,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

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
    fn test_node_id() {
        let id = NodeId::new("node-01");
        assert_eq!(id.as_str(), "node-01");
        assert_eq!(id.to_string(), "node-01");
    }

    #[test]
    fn test_node_role_display() {
        assert_eq!(NodeRole::Primary.to_string(), "primary");
        assert_eq!(NodeRole::Secondary.to_string(), "secondary");
        assert_eq!(NodeRole::Witness.to_string(), "witness");
    }

    #[test]
    fn test_node_state_methods() {
        assert!(NodeState::Active.can_handle_traffic());
        assert!(!NodeState::Ready.can_handle_traffic());
        assert!(!NodeState::Draining.can_handle_traffic());

        assert!(NodeState::Active.is_healthy());
        assert!(NodeState::Ready.is_healthy());
        assert!(NodeState::Draining.is_healthy());
        assert!(!NodeState::Unhealthy.is_healthy());

        assert!(NodeState::Active.can_vote());
        assert!(NodeState::Ready.can_vote());
        assert!(NodeState::Syncing.can_vote());
        assert!(!NodeState::Starting.can_vote());
        assert!(!NodeState::ShuttingDown.can_vote());
    }

    #[test]
    fn test_cluster_node_creation() {
        let endpoints = create_test_endpoints();
        let node = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Primary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            endpoints,
        );

        assert_eq!(node.id.as_str(), "node-01");
        assert_eq!(node.role, NodeRole::Primary);
        assert_eq!(node.state, NodeState::Starting);
        assert_eq!(node.region, "us-east-1");
        assert_eq!(node.zone, "us-east-1a");
        assert!((node.health_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cluster_node_state_updates() {
        let endpoints = create_test_endpoints();
        let mut node = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Primary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            endpoints,
        );

        node.set_state(NodeState::Active);
        assert_eq!(node.state, NodeState::Active);

        node.set_health_score(0.8);
        assert!((node.health_score - 0.8).abs() < f64::EPSILON);

        // Test clamping
        node.set_health_score(1.5);
        assert!((node.health_score - 1.0).abs() < f64::EPSILON);

        node.set_health_score(-0.5);
        assert!(node.health_score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_node_zone_comparison() {
        let endpoints = create_test_endpoints();
        let node1 = ClusterNode::new(
            NodeId::new("node-01"),
            NodeRole::Primary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            endpoints.clone(),
        );
        let node2 = ClusterNode::new(
            NodeId::new("node-02"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            endpoints.clone(),
        );
        let node3 = ClusterNode::new(
            NodeId::new("node-03"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1b".to_string(),
            endpoints,
        );

        assert!(node1.is_same_zone(&node2));
        assert!(!node1.is_same_zone(&node3));
        assert!(node1.is_same_region(&node2));
        assert!(node1.is_same_region(&node3));
    }
}
