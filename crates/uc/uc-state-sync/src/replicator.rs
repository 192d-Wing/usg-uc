//! State replicator implementation.

use crate::config::StateSyncConfig;
use crate::error::{StateSyncError, StateSyncResult};
use crate::protocol::{ReplicationMessage, ReplicationPayload};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uc_cluster::NodeId;

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
    use bytes::Bytes;

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
}
