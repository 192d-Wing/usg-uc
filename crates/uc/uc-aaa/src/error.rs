//! Error types for the AAA module.

use std::net::SocketAddr;
use thiserror::Error;

/// Result type alias for AAA operations.
pub type AaaResult<T> = Result<T, AaaError>;

/// Errors that can occur during AAA operations.
#[derive(Debug, Error)]
pub enum AaaError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// Authentication failed.
    #[error("authentication failed: {reason}")]
    AuthenticationFailed {
        /// Reason for the authentication failure.
        reason: String,
    },

    /// Authorization failed.
    #[error("authorization failed: {reason}")]
    AuthorizationFailed {
        /// Reason for the authorization failure.
        reason: String,
    },

    /// Connection to AAA server failed.
    #[error("connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Server address.
        address: SocketAddr,
        /// Reason for the failure.
        reason: String,
    },

    /// Request timeout.
    #[error("request timed out after {duration_ms}ms")]
    Timeout {
        /// Duration in milliseconds.
        duration_ms: u64,
    },

    /// Invalid response from server.
    #[error("invalid response: {reason}")]
    InvalidResponse {
        /// Reason for the error.
        reason: String,
    },

    /// RADIUS protocol error.
    #[error("RADIUS error: {reason}")]
    RadiusError {
        /// Reason for the error.
        reason: String,
    },

    /// Diameter protocol error.
    #[error("Diameter error: {reason}")]
    DiameterError {
        /// Reason for the error.
        reason: String,
    },

    /// No servers available.
    #[error("no AAA servers available")]
    NoServersAvailable,

    /// Server rejected request.
    #[error("server rejected request: {reason}")]
    Rejected {
        /// Reason for rejection.
        reason: String,
    },

    /// IO error.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the error.
        reason: String,
    },
}

impl From<std::io::Error> for AaaError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            reason: err.to_string(),
        }
    }
}
