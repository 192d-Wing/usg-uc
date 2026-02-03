//! SIPREC error types.

use thiserror::Error;

/// SIPREC-specific errors.
#[derive(Debug, Error)]
pub enum SiprecError {
    /// Recording server not configured.
    #[error("no recording server configured")]
    NoRecordingServer,

    /// Recording server unreachable.
    #[error("recording server unreachable: {address}")]
    ServerUnreachable {
        /// Server address.
        address: String,
    },

    /// Recording session setup failed.
    #[error("recording session setup failed: {reason}")]
    SessionSetupFailed {
        /// Failure reason.
        reason: String,
    },

    /// Recording session already exists.
    #[error("recording session already exists for call: {call_id}")]
    SessionExists {
        /// Call ID.
        call_id: String,
    },

    /// Recording session not found.
    #[error("recording session not found: {session_id}")]
    SessionNotFound {
        /// Session ID.
        session_id: String,
    },

    /// Invalid session state for operation.
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// Metadata generation error.
    #[error("metadata generation failed: {reason}")]
    MetadataError {
        /// Error reason.
        reason: String,
    },

    /// Media forking error.
    #[error("media forking failed: {reason}")]
    ForkingError {
        /// Error reason.
        reason: String,
    },

    /// SDP negotiation error.
    #[error("SDP negotiation failed: {reason}")]
    SdpError {
        /// Error reason.
        reason: String,
    },

    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Error reason.
        reason: String,
    },

    /// SIP protocol error.
    #[error("SIP error: {0}")]
    SipError(#[from] proto_sip::SipError),

    /// SDP error.
    #[error("SDP error: {0}")]
    SdpParseError(#[from] proto_sdp::SdpError),
}

/// Result type for SIPREC operations.
pub type SiprecResult<T> = Result<T, SiprecError>;
