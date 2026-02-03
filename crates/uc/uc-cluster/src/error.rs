//! Error types for the cluster module.

use std::net::SocketAddr;
use thiserror::Error;

/// Result type alias for cluster operations.
pub type ClusterResult<T> = Result<T, ClusterError>;

/// Errors that can occur during cluster operations.
#[derive(Debug, Error)]
pub enum ClusterError {
    /// Node not found in cluster.
    #[error("node not found: {node_id}")]
    NodeNotFound {
        /// The node ID that was not found.
        node_id: String,
    },

    /// Quorum not available.
    #[error("quorum not available: {active} of {required} nodes active")]
    QuorumNotAvailable {
        /// Number of active nodes.
        active: usize,
        /// Number of nodes required for quorum.
        required: usize,
    },

    /// Failover in progress.
    #[error("failover already in progress")]
    FailoverInProgress,

    /// Failover failed.
    #[error("failover failed: {reason}")]
    FailoverFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Connection failed.
    #[error("connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Address that failed to connect.
        address: SocketAddr,
        /// Reason for failure.
        reason: String,
    },

    /// Heartbeat timeout.
    #[error("heartbeat timeout for node {node_id}")]
    HeartbeatTimeout {
        /// Node that timed out.
        node_id: String,
    },

    /// Invalid state transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted target state.
        to: String,
    },

    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// Serialization error.
    #[error("serialization error: {reason}")]
    SerializationError {
        /// Reason for the serialization error.
        reason: String,
    },

    /// Network error.
    #[error("network error: {reason}")]
    NetworkError {
        /// Reason for the network error.
        reason: String,
    },

    /// State sync error.
    #[error("state sync error: {reason}")]
    StateSyncError {
        /// Reason for the state sync error.
        reason: String,
    },

    /// Node already exists.
    #[error("node already exists: {node_id}")]
    NodeAlreadyExists {
        /// The node ID that already exists.
        node_id: String,
    },

    /// Cluster not initialized.
    #[error("cluster not initialized")]
    NotInitialized,

    /// Operation timed out.
    #[error("operation timed out after {duration_ms}ms")]
    Timeout {
        /// Duration in milliseconds before timeout.
        duration_ms: u64,
    },
}
