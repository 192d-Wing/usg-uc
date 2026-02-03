//! Error types for the syslog module.

use std::net::SocketAddr;
use thiserror::Error;

/// Result type alias for syslog operations.
pub type SyslogResult<T> = Result<T, SyslogError>;

/// Errors that can occur during syslog operations.
#[derive(Debug, Error)]
pub enum SyslogError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the error.
        reason: String,
    },

    /// Connection failed.
    #[error("connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Target address.
        address: SocketAddr,
        /// Reason for failure.
        reason: String,
    },

    /// Send failed.
    #[error("failed to send message: {reason}")]
    SendFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Format error.
    #[error("message format error: {reason}")]
    FormatError {
        /// Reason for the error.
        reason: String,
    },

    /// IO error.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the error.
        reason: String,
    },
}

impl From<std::io::Error> for SyslogError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            reason: err.to_string(),
        }
    }
}
