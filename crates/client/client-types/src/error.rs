//! Error types for the soft client.

use thiserror::Error;

/// Result type for client operations.
pub type ClientResult<T> = Result<T, ClientError>;

/// Client error types.
#[derive(Debug, Error)]
pub enum ClientError {
    /// SIP protocol error.
    #[error("SIP error: {0}")]
    Sip(String),

    /// Registration failed.
    #[error("Registration failed: {reason}")]
    RegistrationFailed {
        /// Failure reason.
        reason: String,
    },

    /// Call failed.
    #[error("Call failed: {reason}")]
    CallFailed {
        /// Failure reason.
        reason: String,
    },

    /// Authentication failed.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Network error.
    #[error("Network error: {0}")]
    Network(String),

    /// Audio error.
    #[error("Audio error: {0}")]
    Audio(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Credential storage error.
    #[error("Credential error: {0}")]
    Credential(String),

    /// Invalid state for operation.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
