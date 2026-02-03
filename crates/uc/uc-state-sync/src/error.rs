//! Error types for the state sync module.

use thiserror::Error;

/// Result type alias for state sync operations.
pub type StateSyncResult<T> = Result<T, StateSyncError>;

/// Errors that can occur during state synchronization.
#[derive(Debug, Error)]
pub enum StateSyncError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// Replication failed.
    #[error("replication failed: {reason}")]
    ReplicationFailed {
        /// Reason for the replication failure.
        reason: String,
    },

    /// Snapshot creation failed.
    #[error("snapshot creation failed: {reason}")]
    SnapshotCreationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Snapshot application failed.
    #[error("snapshot application failed: {reason}")]
    SnapshotApplicationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Node not found.
    #[error("node not found: {node_id}")]
    NodeNotFound {
        /// The node ID that was not found.
        node_id: String,
    },

    /// Connection failed.
    #[error("connection to peer failed: {reason}")]
    ConnectionFailed {
        /// Reason for the connection failure.
        reason: String,
    },

    /// Serialization error.
    #[error("serialization error: {reason}")]
    SerializationError {
        /// Reason for the serialization error.
        reason: String,
    },

    /// Deserialization error.
    #[error("deserialization error: {reason}")]
    DeserializationError {
        /// Reason for the deserialization error.
        reason: String,
    },

    /// Operation timeout.
    #[error("operation timed out after {duration_ms}ms")]
    Timeout {
        /// Duration in milliseconds.
        duration_ms: u64,
    },

    /// Storage error.
    #[error("storage error: {reason}")]
    StorageError {
        /// Reason for the storage error.
        reason: String,
    },

    /// Version conflict.
    #[error("version conflict: expected {expected}, got {actual}")]
    VersionConflict {
        /// Expected version.
        expected: u64,
        /// Actual version.
        actual: u64,
    },

    /// Sync in progress.
    #[error("sync already in progress")]
    SyncInProgress,

    /// Not synchronized.
    #[error("node not synchronized")]
    NotSynchronized,
}

impl From<serde_json::Error> for StateSyncError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError {
            reason: err.to_string(),
        }
    }
}
