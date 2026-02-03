//! Error types for the SNMP module.

use std::net::SocketAddr;
use thiserror::Error;

/// Result type alias for SNMP operations.
pub type SnmpResult<T> = Result<T, SnmpError>;

/// Errors that can occur during SNMP operations.
#[derive(Debug, Error)]
pub enum SnmpError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the error.
        reason: String,
    },

    /// Send failed.
    #[error("failed to send trap to {address}: {reason}")]
    SendFailed {
        /// Target address.
        address: SocketAddr,
        /// Reason for failure.
        reason: String,
    },

    /// IO error.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the error.
        reason: String,
    },

    /// Encoding error.
    #[error("encoding error: {reason}")]
    EncodingError {
        /// Reason for the error.
        reason: String,
    },
}

impl From<std::io::Error> for SnmpError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            reason: err.to_string(),
        }
    }
}
