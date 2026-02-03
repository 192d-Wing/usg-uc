//! SWIM-style gossip protocol for failure detection.
//!
//! Implements a gossip-based protocol for:
//! - Membership dissemination
//! - Failure detection
//! - State synchronization

use crate::config::GossipConfig;
use crate::error::DiscoveryResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uc_cluster::NodeId;

pub use crate::config::GossipConfig as Config;

/// Status of a cluster member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    /// Member is alive and responding.
    Alive,
    /// Member is suspected of being down.
    Suspect,
    /// Member is confirmed dead.
    Dead,
    /// Member has left the cluster gracefully.
    Left,
}

impl std::fmt::Display for MemberStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alive => write!(f, "alive"),
            Self::Suspect => write!(f, "suspect"),
            Self::Dead => write!(f, "dead"),
            Self::Left => write!(f, "left"),
        }
    }
}

/// Information about a cluster member.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    /// Node ID.
    pub node_id: NodeId,
    /// Network address.
    pub address: SocketAddr,
    /// Current status.
    pub status: MemberStatus,
    /// Incarnation number (increases on status changes).
    pub incarnation: u64,
    /// When this info was last updated.
    pub last_updated: Instant,
}

impl MemberInfo {
    /// Creates new member info.
    #[must_use]
    pub fn new(node_id: NodeId, address: SocketAddr) -> Self {
        Self {
            node_id,
            address,
            status: MemberStatus::Alive,
            incarnation: 0,
            last_updated: Instant::now(),
        }
    }

    /// Checks if the member is available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self.status, MemberStatus::Alive | MemberStatus::Suspect)
    }
}

/// Gossip message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Ping message for probing.
    Ping {
        /// Sequence number.
        sequence: u64,
        /// Sender node ID.
        from: String,
    },
    /// Ping acknowledgement.
    PingAck {
        /// Sequence number being acknowledged.
        sequence: u64,
        /// Sender node ID.
        from: String,
    },
    /// Indirect ping request.
    PingReq {
        /// Sequence number.
        sequence: u64,
        /// Original sender.
        from: String,
        /// Target to ping.
        target: SocketAddr,
    },
    /// Member update broadcast.
    MemberUpdate {
        /// Node ID.
        node_id: String,
        /// New status.
        status: MemberStatus,
        /// Incarnation number.
        incarnation: u64,
    },
    /// Join request.
    Join {
        /// Joining node ID.
        node_id: String,
        /// Joining node address.
        address: SocketAddr,
    },
    /// Leave notification.
    Leave {
        /// Leaving node ID.
        node_id: String,
    },
}

/// SWIM-style gossip protocol implementation.
pub struct GossipProtocol {
    /// Local node ID.
    local_node_id: NodeId,
    /// Local address.
    local_address: SocketAddr,
    /// Configuration.
    config: GossipConfig,
    /// Known members.
    members: RwLock<HashMap<NodeId, MemberInfo>>,
    /// Sequence counter for probes.
    sequence: AtomicU64,
    /// Local incarnation number.
    incarnation: AtomicU64,
}

impl GossipProtocol {
    /// Creates a new gossip protocol instance.
    #[must_use]
    pub fn new(local_node_id: NodeId, local_address: SocketAddr, config: GossipConfig) -> Self {
        info!(
            node_id = %local_node_id,
            address = %local_address,
            "Initializing gossip protocol"
        );

        Self {
            local_node_id,
            local_address,
            config,
            members: RwLock::new(HashMap::new()),
            sequence: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
        }
    }

    /// Returns the local node ID.
    #[must_use]
    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Adds a member to the membership list.
    pub async fn add_member(&self, node_id: NodeId, address: SocketAddr) {
        let mut members = self.members.write().await;
        let member = MemberInfo::new(node_id.clone(), address);
        members.insert(node_id.clone(), member);
        info!(node_id = %node_id, address = %address, "Added member to gossip");
    }

    /// Removes a member from the membership list.
    pub async fn remove_member(&self, node_id: &NodeId) -> Option<MemberInfo> {
        let mut members = self.members.write().await;
        let removed = members.remove(node_id);
        if removed.is_some() {
            info!(node_id = %node_id, "Removed member from gossip");
        }
        removed
    }

    /// Returns all known members.
    pub async fn members(&self) -> Vec<MemberInfo> {
        self.members.read().await.values().cloned().collect()
    }

    /// Returns members with a specific status.
    pub async fn members_with_status(&self, status: MemberStatus) -> Vec<MemberInfo> {
        self.members
            .read()
            .await
            .values()
            .filter(|m| m.status == status)
            .cloned()
            .collect()
    }

    /// Returns available members (alive or suspect).
    pub async fn available_members(&self) -> Vec<MemberInfo> {
        self.members
            .read()
            .await
            .values()
            .filter(|m| m.is_available())
            .cloned()
            .collect()
    }

    /// Handles an incoming gossip message.
    pub async fn handle_message(
        &self,
        message: GossipMessage,
    ) -> DiscoveryResult<Option<GossipMessage>> {
        match message {
            GossipMessage::Ping { sequence, from } => {
                debug!(sequence, from = %from, "Received ping");
                Ok(Some(GossipMessage::PingAck {
                    sequence,
                    from: self.local_node_id.to_string(),
                }))
            }
            GossipMessage::PingAck { sequence, from } => {
                debug!(sequence, from = %from, "Received ping ack");
                // Mark the member as alive
                self.update_member_status(&NodeId::new(&from), MemberStatus::Alive)
                    .await;
                Ok(None)
            }
            GossipMessage::PingReq {
                sequence,
                from,
                target,
            } => {
                debug!(sequence, from = %from, target = %target, "Received ping-req");
                // Forward ping to target and relay response
                Ok(None) // Response handling would be done asynchronously
            }
            GossipMessage::MemberUpdate {
                node_id,
                status,
                incarnation,
            } => {
                self.handle_member_update(&NodeId::new(&node_id), status, incarnation)
                    .await;
                Ok(None)
            }
            GossipMessage::Join { node_id, address } => {
                info!(node_id = %node_id, address = %address, "Member joining");
                self.add_member(NodeId::new(&node_id), address).await;
                Ok(None)
            }
            GossipMessage::Leave { node_id } => {
                info!(node_id = %node_id, "Member leaving");
                self.update_member_status(&NodeId::new(&node_id), MemberStatus::Left)
                    .await;
                Ok(None)
            }
        }
    }

    /// Creates a ping message.
    #[must_use]
    pub fn create_ping(&self) -> GossipMessage {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        GossipMessage::Ping {
            sequence,
            from: self.local_node_id.to_string(),
        }
    }

    /// Creates a join message.
    #[must_use]
    pub fn create_join(&self) -> GossipMessage {
        GossipMessage::Join {
            node_id: self.local_node_id.to_string(),
            address: self.local_address,
        }
    }

    /// Creates a leave message.
    #[must_use]
    pub fn create_leave(&self) -> GossipMessage {
        GossipMessage::Leave {
            node_id: self.local_node_id.to_string(),
        }
    }

    /// Selects random members for gossiping.
    pub async fn select_gossip_targets(&self) -> Vec<MemberInfo> {
        use std::collections::HashSet;

        let members = self.members.read().await;
        let available: Vec<_> = members
            .values()
            .filter(|m| m.is_available())
            .cloned()
            .collect();

        if available.len() <= self.config.fanout {
            return available;
        }

        // Select random subset
        let mut selected = HashSet::new();
        let mut result = Vec::with_capacity(self.config.fanout);

        while result.len() < self.config.fanout && selected.len() < available.len() {
            let idx = (self.sequence.fetch_add(1, Ordering::Relaxed) as usize) % available.len();
            if selected.insert(idx) {
                result.push(available[idx].clone());
            }
        }

        result
    }

    /// Updates a member's status.
    async fn update_member_status(&self, node_id: &NodeId, status: MemberStatus) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            if member.status != status {
                debug!(
                    node_id = %node_id,
                    old_status = %member.status,
                    new_status = %status,
                    "Member status changed"
                );
                member.status = status;
                member.last_updated = Instant::now();
            }
        }
    }

    /// Handles a member update message.
    async fn handle_member_update(&self, node_id: &NodeId, status: MemberStatus, incarnation: u64) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            // Only apply update if incarnation is higher
            if incarnation > member.incarnation {
                member.status = status;
                member.incarnation = incarnation;
                member.last_updated = Instant::now();
                debug!(
                    node_id = %node_id,
                    status = %status,
                    incarnation = incarnation,
                    "Applied member update"
                );
            }
        } else {
            warn!(
                node_id = %node_id,
                "Received update for unknown member"
            );
        }
    }

    /// Marks a member as suspect.
    pub async fn suspect_member(&self, node_id: &NodeId) {
        self.update_member_status(node_id, MemberStatus::Suspect)
            .await;
    }

    /// Marks a member as dead.
    pub async fn mark_dead(&self, node_id: &NodeId) {
        self.update_member_status(node_id, MemberStatus::Dead).await;
    }

    /// Increments local incarnation and returns new value.
    pub fn increment_incarnation(&self) -> u64 {
        self.incarnation.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl std::fmt::Debug for GossipProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipProtocol")
            .field("local_node_id", &self.local_node_id)
            .field("local_address", &self.local_address)
            .field("config", &self.config)
            .field("members", &"<locked>")
            .field("sequence", &self.sequence.load(Ordering::Relaxed))
            .field("incarnation", &self.incarnation.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_gossip() -> GossipProtocol {
        GossipProtocol::new(
            NodeId::new("test-node"),
            "[::1]:5070".parse().unwrap(),
            GossipConfig::default(),
        )
    }

    #[test]
    fn test_member_status_display() {
        assert_eq!(format!("{}", MemberStatus::Alive), "alive");
        assert_eq!(format!("{}", MemberStatus::Suspect), "suspect");
        assert_eq!(format!("{}", MemberStatus::Dead), "dead");
        assert_eq!(format!("{}", MemberStatus::Left), "left");
    }

    #[test]
    fn test_member_info_availability() {
        let mut member = MemberInfo::new(NodeId::new("node"), "[::1]:5070".parse().unwrap());

        assert!(member.is_available());

        member.status = MemberStatus::Suspect;
        assert!(member.is_available());

        member.status = MemberStatus::Dead;
        assert!(!member.is_available());

        member.status = MemberStatus::Left;
        assert!(!member.is_available());
    }

    #[tokio::test]
    async fn test_add_remove_member() {
        let gossip = create_test_gossip();
        let node_id = NodeId::new("peer-01");
        let addr: SocketAddr = "[::1]:5071".parse().unwrap();

        gossip.add_member(node_id.clone(), addr).await;
        let members = gossip.members().await;
        assert_eq!(members.len(), 1);

        let removed = gossip.remove_member(&node_id).await;
        assert!(removed.is_some());

        let members = gossip.members().await;
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn test_handle_ping() {
        let gossip = create_test_gossip();
        let ping = GossipMessage::Ping {
            sequence: 1,
            from: "sender".to_string(),
        };

        let response = gossip.handle_message(ping).await.unwrap();
        assert!(matches!(response, Some(GossipMessage::PingAck { .. })));
    }

    #[test]
    fn test_create_messages() {
        let gossip = create_test_gossip();

        let ping = gossip.create_ping();
        assert!(matches!(ping, GossipMessage::Ping { .. }));

        let join = gossip.create_join();
        assert!(matches!(join, GossipMessage::Join { .. }));

        let leave = gossip.create_leave();
        assert!(matches!(leave, GossipMessage::Leave { .. }));
    }

    #[tokio::test]
    async fn test_suspect_and_dead() {
        let gossip = create_test_gossip();
        let node_id = NodeId::new("peer-01");

        gossip
            .add_member(node_id.clone(), "[::1]:5071".parse().unwrap())
            .await;

        gossip.suspect_member(&node_id).await;
        let members = gossip.members_with_status(MemberStatus::Suspect).await;
        assert_eq!(members.len(), 1);

        gossip.mark_dead(&node_id).await;
        let members = gossip.members_with_status(MemberStatus::Dead).await;
        assert_eq!(members.len(), 1);
    }
}
