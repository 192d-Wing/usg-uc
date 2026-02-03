//! Error types for the discovery module.

use std::net::SocketAddr;
use thiserror::Error;

/// Result type alias for discovery operations.
pub type DiscoveryResult<T> = Result<T, DiscoveryError>;

/// Errors that can occur during discovery operations.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// DNS resolution failed.
    #[error("DNS resolution failed for {name}: {reason}")]
    DnsResolutionFailed {
        /// Name being resolved.
        name: String,
        /// Reason for failure.
        reason: String,
    },

    /// Connection to peer failed.
    #[error("connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Address that failed.
        address: SocketAddr,
        /// Reason for failure.
        reason: String,
    },

    /// Kubernetes API error.
    #[error("Kubernetes API error: {reason}")]
    KubernetesError {
        /// Reason for the error.
        reason: String,
    },

    /// No peers found.
    #[error("no peers found")]
    NoPeersFound,

    /// Discovery timeout.
    #[error("discovery timeout after {duration_ms}ms")]
    Timeout {
        /// Duration in milliseconds.
        duration_ms: u64,
    },

    /// Gossip protocol error.
    #[error("gossip protocol error: {reason}")]
    GossipError {
        /// Reason for the error.
        reason: String,
    },

    /// Network error.
    #[error("network error: {reason}")]
    NetworkError {
        /// Reason for the error.
        reason: String,
    },

    /// Parse error.
    #[error("parse error: {reason}")]
    ParseError {
        /// Reason for the error.
        reason: String,
    },
}
