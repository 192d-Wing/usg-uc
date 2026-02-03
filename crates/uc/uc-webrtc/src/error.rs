//! WebRTC error types.

use thiserror::Error;

/// WebRTC error type.
#[derive(Debug, Error)]
pub enum WebRtcError {
    /// Session not found.
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// Session identifier.
        session_id: String,
    },

    /// Session already exists.
    #[error("session already exists: {session_id}")]
    SessionExists {
        /// Session identifier.
        session_id: String,
    },

    /// Invalid session state.
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// SDP parsing error.
    #[error("SDP error: {reason}")]
    SdpError {
        /// Error reason.
        reason: String,
    },

    /// ICE error.
    #[error("ICE error: {reason}")]
    IceError {
        /// Error reason.
        reason: String,
    },

    /// DTLS error.
    #[error("DTLS error: {reason}")]
    DtlsError {
        /// Error reason.
        reason: String,
    },

    /// Media error.
    #[error("media error: {reason}")]
    MediaError {
        /// Error reason.
        reason: String,
    },

    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Error reason.
        reason: String,
    },

    /// Timeout error.
    #[error("timeout: {operation}")]
    Timeout {
        /// Operation that timed out.
        operation: String,
    },

    /// Internal error.
    #[error("internal error: {reason}")]
    Internal {
        /// Error reason.
        reason: String,
    },
}

/// Result type for WebRTC operations.
pub type WebRtcResult<T> = Result<T, WebRtcError>;
