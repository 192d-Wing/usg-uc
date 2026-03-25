//! Replication protocol messages.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uc_cluster::NodeId;

/// Replication message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessage {
    /// Request to replicate state.
    ReplicateRequest {
        /// Sequence number.
        sequence: u64,
        /// Source node.
        source: String,
        /// Payload to replicate.
        payload: ReplicationPayload,
    },

    /// Acknowledgment of replication.
    ReplicateAck {
        /// Sequence number being acknowledged.
        sequence: u64,
        /// Acknowledging node.
        node_id: String,
        /// Success status.
        success: bool,
        /// Error message if failed.
        error: Option<String>,
    },

    /// Request a snapshot.
    SnapshotRequest {
        /// Requesting node.
        node_id: String,
        /// Last known version.
        last_version: u64,
    },

    /// Snapshot response.
    SnapshotResponse {
        /// Version of the snapshot.
        version: u64,
        /// Total chunks.
        total_chunks: u32,
        /// Current chunk index.
        chunk_index: u32,
        /// Chunk data.
        data: Bytes,
        /// Whether this is the last chunk.
        is_last: bool,
    },

    /// Snapshot acknowledgment.
    SnapshotAck {
        /// Node ID.
        node_id: String,
        /// Chunk index acknowledged.
        chunk_index: u32,
        /// Success status.
        success: bool,
    },

    /// Heartbeat with sync status.
    SyncHeartbeat {
        /// Source node.
        node_id: String,
        /// Current version.
        version: u64,
        /// Pending operations count.
        pending_ops: u64,
        /// Sync lag in milliseconds.
        lag_ms: u64,
    },
}

impl ReplicationMessage {
    /// Creates a new replicate request.
    #[must_use]
    pub fn replicate(sequence: u64, source: &NodeId, payload: ReplicationPayload) -> Self {
        Self::ReplicateRequest {
            sequence,
            source: source.to_string(),
            payload,
        }
    }

    /// Creates a successful acknowledgment.
    #[must_use]
    pub fn ack_success(sequence: u64, node_id: &NodeId) -> Self {
        Self::ReplicateAck {
            sequence,
            node_id: node_id.to_string(),
            success: true,
            error: None,
        }
    }

    /// Creates a failed acknowledgment.
    #[must_use]
    pub fn ack_failure(sequence: u64, node_id: &NodeId, error: impl Into<String>) -> Self {
        Self::ReplicateAck {
            sequence,
            node_id: node_id.to_string(),
            success: false,
            error: Some(error.into()),
        }
    }

    /// Creates a snapshot request.
    #[must_use]
    pub fn snapshot_request(node_id: &NodeId, last_version: u64) -> Self {
        Self::SnapshotRequest {
            node_id: node_id.to_string(),
            last_version,
        }
    }

    /// Creates a sync heartbeat.
    #[must_use]
    pub fn sync_heartbeat(node_id: &NodeId, version: u64, pending_ops: u64, lag_ms: u64) -> Self {
        Self::SyncHeartbeat {
            node_id: node_id.to_string(),
            version,
            pending_ops,
            lag_ms,
        }
    }
}

/// Replication payload types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationPayload {
    /// Key-value set operation.
    Set {
        /// Key.
        key: String,
        /// Value.
        value: Bytes,
        /// TTL in milliseconds (optional).
        ttl_ms: Option<u64>,
    },

    /// Key deletion.
    Delete {
        /// Key to delete.
        key: String,
    },

    /// Batch of operations.
    Batch {
        /// Operations in the batch.
        operations: Vec<ReplicationPayload>,
    },

    /// Counter increment.
    Increment {
        /// Key.
        key: String,
        /// Delta.
        delta: i64,
    },

    /// CRDT update.
    CrdtUpdate {
        /// Key.
        key: String,
        /// CRDT type.
        crdt_type: CrdtType,
        /// Serialized CRDT state.
        state: Bytes,
    },

    /// Registration update.
    RegistrationUpdate {
        /// Address of Record.
        aor: String,
        /// Contact URI.
        contact: String,
        /// Expiry time (Unix timestamp).
        expires_at: i64,
        /// Whether this is a removal.
        is_removal: bool,
    },

    /// Call state update.
    CallStateUpdate {
        /// Call ID.
        call_id: String,
        /// Serialized call state.
        state: Bytes,
        /// Whether the call has ended.
        ended: bool,
    },
}

/// CRDT type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrdtType {
    /// Grow-only counter.
    GCounter,
    /// Positive-negative counter.
    PNCounter,
    /// Last-writer-wins register.
    LWWRegister,
}

impl std::fmt::Display for CrdtType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GCounter => write!(f, "g_counter"),
            Self::PNCounter => write!(f, "pn_counter"),
            Self::LWWRegister => write!(f, "lww_register"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replicate_message() {
        let node_id = NodeId::new("node1");
        let payload = ReplicationPayload::Set {
            key: "test".to_string(),
            value: Bytes::from("value"),
            ttl_ms: None,
        };

        let msg = ReplicationMessage::replicate(1, &node_id, payload);
        assert!(matches!(
            msg,
            ReplicationMessage::ReplicateRequest { sequence: 1, .. }
        ));
    }

    #[test]
    fn test_ack_messages() {
        let node_id = NodeId::new("node1");

        let success = ReplicationMessage::ack_success(1, &node_id);
        assert!(matches!(
            success,
            ReplicationMessage::ReplicateAck { success: true, .. }
        ));

        let failure = ReplicationMessage::ack_failure(1, &node_id, "error");
        assert!(matches!(
            failure,
            ReplicationMessage::ReplicateAck { success: false, .. }
        ));
    }

    #[test]
    fn test_crdt_type_display() {
        assert_eq!(format!("{}", CrdtType::GCounter), "g_counter");
        assert_eq!(format!("{}", CrdtType::PNCounter), "pn_counter");
        assert_eq!(format!("{}", CrdtType::LWWRegister), "lww_register");
    }

    #[allow(clippy::panic)]
    #[test]
    fn test_batch_payload() {
        let batch = ReplicationPayload::Batch {
            operations: vec![
                ReplicationPayload::Set {
                    key: "key1".to_string(),
                    value: Bytes::from("value1"),
                    ttl_ms: None,
                },
                ReplicationPayload::Delete {
                    key: "key2".to_string(),
                },
            ],
        };

        if let ReplicationPayload::Batch { operations } = batch {
            assert_eq!(operations.len(), 2);
        } else {
            panic!("Expected Batch payload");
        }
    }
}
