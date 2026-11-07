//! State replicator implementation.

use crate::config::StateSyncConfig;
use crate::error::{StateSyncError, StateSyncResult};
use crate::protocol::{ReplicationMessage, ReplicationPayload};
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uc_cluster::{AuthError, AuthenticatedEnvelope, NodeId, PeerAuthenticator};

/// Trait for types that can be replicated.
pub trait Replicable: Send + Sync + 'static {
    /// Converts the state to a replication payload.
    fn to_payload(&self) -> ReplicationPayload;

    /// Applies a replication payload.
    fn apply_payload(&mut self, payload: &ReplicationPayload) -> StateSyncResult<()>;

    /// Returns the state type name.
    fn state_type() -> &'static str;
}

/// Pending replication operation.
#[derive(Debug)]
struct PendingOperation {
    /// Sequence number.
    sequence: u64,
    /// Payload.
    payload: ReplicationPayload,
    /// Target nodes.
    targets: Vec<NodeId>,
    /// Nodes that have acknowledged.
    acknowledged: Vec<NodeId>,
    /// When the operation was created.
    created_at: std::time::Instant,
}

impl PendingOperation {
    /// Creates a new pending operation.
    fn new(sequence: u64, payload: ReplicationPayload, targets: Vec<NodeId>) -> Self {
        Self {
            sequence,
            payload,
            targets,
            acknowledged: Vec::new(),
            created_at: std::time::Instant::now(),
        }
    }

    /// Records an acknowledgment.
    fn acknowledge(&mut self, node_id: &NodeId) -> bool {
        if !self.acknowledged.contains(node_id) {
            self.acknowledged.push(node_id.clone());
        }
        self.is_fully_acknowledged()
    }

    /// Checks if all targets have acknowledged.
    fn is_fully_acknowledged(&self) -> bool {
        self.targets.iter().all(|t| self.acknowledged.contains(t))
    }

    /// Returns the acknowledgment count.
    fn ack_count(&self) -> usize {
        self.acknowledged.len()
    }
}

/// State replicator for distributed state synchronization.
pub struct StateReplicator {
    /// Local node ID.
    local_node_id: NodeId,
    /// Configuration.
    config: StateSyncConfig,
    /// Current sequence number.
    sequence: AtomicU64,
    /// Current state version.
    version: AtomicU64,
    /// Pending operations.
    pending: RwLock<VecDeque<PendingOperation>>,
    /// Whether the replicator is running.
    running: AtomicBool,
    /// Sync lag in milliseconds.
    sync_lag_ms: AtomicU64,
}

impl StateReplicator {
    /// Creates a new state replicator.
    #[must_use]
    pub fn new(local_node_id: NodeId, config: StateSyncConfig) -> Self {
        info!(
            node_id = %local_node_id,
            mode = %config.mode,
            "Creating state replicator"
        );

        Self {
            local_node_id,
            config,
            sequence: AtomicU64::new(0),
            version: AtomicU64::new(0),
            pending: RwLock::new(VecDeque::new()),
            running: AtomicBool::new(false),
            sync_lag_ms: AtomicU64::new(0),
        }
    }

    /// Returns the local node ID.
    #[must_use]
    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    /// Returns the current sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    /// Returns the current state version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Returns the current sync lag in milliseconds.
    #[must_use]
    pub fn sync_lag_ms(&self) -> u64 {
        self.sync_lag_ms.load(Ordering::SeqCst)
    }

    /// Returns the number of pending operations.
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Checks if the replicator is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Starts the replicator.
    pub fn start(&self) {
        self.running.store(true, Ordering::Release);
        info!("State replicator started");
    }

    /// Stops the replicator.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        info!("State replicator stopped");
    }

    /// Replicates a payload to peers.
    pub async fn replicate(
        &self,
        payload: ReplicationPayload,
        targets: Vec<NodeId>,
    ) -> StateSyncResult<u64> {
        if !self.is_running() {
            return Err(StateSyncError::NotSynchronized);
        }

        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Check pending operations limit
        {
            let pending = self.pending.read().await;
            if pending.len() >= self.config.max_pending_ops {
                warn!(
                    pending = pending.len(),
                    max = self.config.max_pending_ops,
                    "Backpressure: too many pending operations"
                );
                return Err(StateSyncError::ReplicationFailed {
                    reason: "Too many pending operations".to_string(),
                });
            }
        }

        let operation = PendingOperation::new(sequence, payload, targets);

        {
            let mut pending = self.pending.write().await;
            pending.push_back(operation);
        }

        debug!(sequence, "Created replication operation");

        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(sequence)
    }

    /// Handles an acknowledgment from a peer.
    pub async fn handle_ack(&self, sequence: u64, node_id: &NodeId, success: bool) -> bool {
        if !success {
            warn!(sequence, node_id = %node_id, "Received failed ack");
            return false;
        }

        let mut pending = self.pending.write().await;

        if let Some(op) = pending.iter_mut().find(|op| op.sequence == sequence) {
            let complete = op.acknowledge(node_id);
            debug!(
                sequence,
                node_id = %node_id,
                ack_count = op.ack_count(),
                complete,
                "Processed ack"
            );
            complete
        } else {
            debug!(sequence, "Ack for unknown sequence");
            false
        }
    }

    /// Removes completed operations from the pending queue.
    pub async fn cleanup_completed(&self) -> usize {
        let mut pending = self.pending.write().await;
        let before = pending.len();

        pending.retain(|op| !op.is_fully_acknowledged());

        let removed = before - pending.len();
        if removed > 0 {
            debug!(removed, "Cleaned up completed operations");
        }
        removed
    }

    /// Removes timed out operations.
    pub async fn cleanup_timeout(&self, timeout: Duration) -> usize {
        let mut pending = self.pending.write().await;
        let before = pending.len();

        pending.retain(|op| op.created_at.elapsed() < timeout);

        let removed = before - pending.len();
        if removed > 0 {
            warn!(removed, "Removed timed out operations");
        }
        removed
    }

    /// Creates a replication message for the given payload.
    #[must_use]
    pub fn create_message(&self, sequence: u64, payload: ReplicationPayload) -> ReplicationMessage {
        ReplicationMessage::replicate(sequence, &self.local_node_id, payload)
    }

    /// Creates a sync heartbeat message.
    #[must_use]
    pub async fn create_heartbeat(&self) -> ReplicationMessage {
        let pending_ops = self.pending.read().await.len() as u64;
        ReplicationMessage::sync_heartbeat(
            &self.local_node_id,
            self.version(),
            pending_ops,
            self.sync_lag_ms(),
        )
    }

    /// Seals an outbound replication message for a peer.
    ///
    /// NIST 800-53 Rev5: IA-3, SC-8(1), SC-13 (HMAC-SHA-384).
    /// Library-only (no transport; POA&M-231).
    ///
    /// # Errors
    /// Returns an error if serialization fails or the message is too large.
    pub fn seal_message(
        &self,
        auth: &PeerAuthenticator,
        message: &ReplicationMessage,
    ) -> StateSyncResult<AuthenticatedEnvelope> {
        let bytes =
            serde_json::to_vec(message).map_err(|e| StateSyncError::SerializationError {
                reason: e.to_string(),
            })?;
        auth.seal(Bytes::from(bytes))
            .map_err(|e| StateSyncError::SerializationError {
                reason: e.to_string(),
            })
    }

    /// Verifies and decodes an inbound replication message.
    ///
    /// This is the only supported inbound path: the envelope must pass
    /// HMAC-SHA-384, timestamp, sequence and generation checks, and any
    /// node identity inside the message must equal the authenticated sender.
    /// Callers must take the peer identity for [`Self::handle_ack`] from the
    /// returned message, never from unauthenticated input.
    ///
    /// NIST 800-53 Rev5: IA-3 (peer authentication), SC-23 (anti-replay),
    /// SI-10 (input validation). Library-only (no transport; POA&M-231).
    ///
    /// # Errors
    /// Returns [`StateSyncError::AuthenticationFailed`] or
    /// [`StateSyncError::DeserializationError`]; nothing is applied.
    pub fn open_message(
        &self,
        auth: &PeerAuthenticator,
        envelope: &AuthenticatedEnvelope,
    ) -> StateSyncResult<ReplicationMessage> {
        auth.verify(envelope)?;
        let message: ReplicationMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                StateSyncError::DeserializationError {
                    reason: e.to_string(),
                }
            })?;
        if message
            .claimed_sender()
            .is_some_and(|claimed| claimed != envelope.sender.as_str())
        {
            return Err(AuthError::SenderMismatch.into());
        }
        Ok(message)
    }

    /// Updates the sync lag.
    pub fn update_lag(&self, lag_ms: u64) {
        self.sync_lag_ms.store(lag_ms, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for StateReplicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateReplicator")
            .field("local_node_id", &self.local_node_id)
            .field("config", &self.config)
            .field("sequence", &self.sequence())
            .field("version", &self.version())
            .field("running", &self.is_running())
            .field("sync_lag_ms", &self.sync_lag_ms())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn create_test_replicator() -> StateReplicator {
        StateReplicator::new(NodeId::new("local"), StateSyncConfig::default())
    }

    #[tokio::test]
    async fn test_replicator_creation() {
        let replicator = create_test_replicator();

        assert_eq!(replicator.sequence(), 0);
        assert_eq!(replicator.version(), 0);
        assert!(!replicator.is_running());
    }

    #[tokio::test]
    async fn test_start_stop() {
        let replicator = create_test_replicator();

        replicator.start();
        assert!(replicator.is_running());

        replicator.stop();
        assert!(!replicator.is_running());
    }

    #[tokio::test]
    async fn test_replicate_not_running() {
        let replicator = create_test_replicator();

        let result = replicator
            .replicate(
                ReplicationPayload::Set {
                    key: "test".to_string(),
                    value: Bytes::from("value"),
                    ttl_ms: None,
                },
                vec![NodeId::new("peer1")],
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_replicate_success() {
        let replicator = create_test_replicator();
        replicator.start();

        let seq = replicator
            .replicate(
                ReplicationPayload::Set {
                    key: "test".to_string(),
                    value: Bytes::from("value"),
                    ttl_ms: None,
                },
                vec![NodeId::new("peer1")],
            )
            .await
            .unwrap();

        assert_eq!(seq, 0);
        assert_eq!(replicator.pending_count().await, 1);
        assert_eq!(replicator.version(), 1);
    }

    #[tokio::test]
    async fn test_handle_ack() {
        let replicator = create_test_replicator();
        replicator.start();

        let seq = replicator
            .replicate(
                ReplicationPayload::Set {
                    key: "test".to_string(),
                    value: Bytes::from("value"),
                    ttl_ms: None,
                },
                vec![NodeId::new("peer1")],
            )
            .await
            .unwrap();

        let complete = replicator
            .handle_ack(seq, &NodeId::new("peer1"), true)
            .await;
        assert!(complete);
    }

    #[tokio::test]
    async fn test_cleanup_completed() {
        let replicator = create_test_replicator();
        replicator.start();

        let seq = replicator
            .replicate(
                ReplicationPayload::Delete {
                    key: "test".to_string(),
                },
                vec![NodeId::new("peer1")],
            )
            .await
            .unwrap();

        replicator
            .handle_ack(seq, &NodeId::new("peer1"), true)
            .await;

        let removed = replicator.cleanup_completed().await;
        assert_eq!(removed, 1);
        assert_eq!(replicator.pending_count().await, 0);
    }

    fn auth(local: &str, peer: &str) -> PeerAuthenticator {
        let key =
            uc_cluster::ClusterAuthKey::new(vec![0x33; uc_cluster::auth::MIN_KEY_LEN]).unwrap();
        PeerAuthenticator::new(key, 1, NodeId::new(local), 1, [NodeId::new(peer)]).unwrap()
    }

    #[test]
    fn authenticated_message_round_trip() {
        let sender = StateReplicator::new(NodeId::new("peer"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let (a_peer, a_local) = (auth("peer", "local"), auth("local", "peer"));
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("peer"));
        let env = sender.seal_message(&a_peer, &msg).unwrap();
        let opened = receiver.open_message(&a_local, &env).unwrap();
        assert_eq!(opened.claimed_sender(), Some("peer"));
        // Replay is rejected.
        assert!(matches!(
            receiver.open_message(&a_local, &env),
            Err(StateSyncError::AuthenticationFailed(AuthError::Replayed))
        ));
    }

    #[test]
    fn tampered_message_rejected() {
        let sender = StateReplicator::new(NodeId::new("peer"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let (a_peer, a_local) = (auth("peer", "local"), auth("local", "peer"));
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("peer"));
        let mut env = sender.seal_message(&a_peer, &msg).unwrap();
        env.payload = Bytes::from(
            serde_json::to_vec(&ReplicationMessage::ack_success(4, &NodeId::new("peer"))).unwrap(),
        );
        assert!(matches!(
            receiver.open_message(&a_local, &env),
            Err(StateSyncError::AuthenticationFailed(AuthError::BadTag))
        ));
    }

    #[test]
    fn spoofed_inner_identity_rejected() {
        let sender = StateReplicator::new(NodeId::new("peer"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let (a_peer, a_local) = (auth("peer", "local"), auth("local", "peer"));
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("someone-else"));
        let env = sender.seal_message(&a_peer, &msg).unwrap();
        assert!(matches!(
            receiver.open_message(&a_local, &env),
            Err(StateSyncError::AuthenticationFailed(
                AuthError::SenderMismatch
            ))
        ));
    }

    #[test]
    fn unknown_peer_rejected() {
        let sender = StateReplicator::new(NodeId::new("intruder"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("intruder"));
        let env = sender
            .seal_message(&auth("intruder", "local"), &msg)
            .unwrap();
        assert!(matches!(
            receiver.open_message(&auth("local", "peer"), &env),
            Err(StateSyncError::AuthenticationFailed(
                AuthError::UnknownSender
            ))
        ));
    }

    #[test]
    fn wrong_key_message_rejected() {
        let sender = StateReplicator::new(NodeId::new("peer"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let other_key =
            uc_cluster::ClusterAuthKey::new(vec![0x44; uc_cluster::auth::MIN_KEY_LEN]).unwrap();
        let a_peer =
            PeerAuthenticator::new(other_key, 1, NodeId::new("peer"), 1, [NodeId::new("local")])
                .unwrap();
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("peer"));
        let env = sender.seal_message(&a_peer, &msg).unwrap();
        assert!(matches!(
            receiver.open_message(&auth("local", "peer"), &env),
            Err(StateSyncError::AuthenticationFailed(AuthError::BadTag))
        ));
    }

    #[test]
    fn generation_rollback_rejected() {
        let sender = StateReplicator::new(NodeId::new("peer"), StateSyncConfig::default());
        let receiver = create_test_replicator();
        let a_local = auth("local", "peer");
        let key =
            || uc_cluster::ClusterAuthKey::new(vec![0x33; uc_cluster::auth::MIN_KEY_LEN]).unwrap();
        let gen5 = PeerAuthenticator::new(key(), 1, NodeId::new("peer"), 5, [NodeId::new("local")])
            .unwrap();
        let gen4 = PeerAuthenticator::new(key(), 1, NodeId::new("peer"), 4, [NodeId::new("local")])
            .unwrap();
        let msg = ReplicationMessage::ack_success(3, &NodeId::new("peer"));
        let env5 = sender.seal_message(&gen5, &msg).unwrap();
        assert!(receiver.open_message(&a_local, &env5).is_ok());
        let env4 = sender.seal_message(&gen4, &msg).unwrap();
        assert!(matches!(
            receiver.open_message(&a_local, &env4),
            Err(StateSyncError::AuthenticationFailed(
                AuthError::StaleGeneration
            ))
        ));
    }

    #[test]
    fn authenticated_garbage_payload_rejected() {
        let receiver = create_test_replicator();
        let env = auth("peer", "local")
            .seal(Bytes::from_static(b"{not json"))
            .unwrap();
        assert!(matches!(
            receiver.open_message(&auth("local", "peer"), &env),
            Err(StateSyncError::DeserializationError { .. })
        ));
    }
}
