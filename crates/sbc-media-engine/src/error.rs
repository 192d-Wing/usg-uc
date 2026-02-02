//! Media engine error types.

use thiserror::Error;

/// Result type for media engine operations.
pub type MediaResult<T> = Result<T, MediaError>;

/// Media engine errors.
#[derive(Debug, Error)]
pub enum MediaError {
    /// Session creation failed.
    #[error("session creation failed: {reason}")]
    SessionCreationFailed {
        /// Error description.
        reason: String,
    },

    /// Session not found.
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// Session ID.
        session_id: String,
    },

    /// Stream not found.
    #[error("stream not found: {stream_id}")]
    StreamNotFound {
        /// Stream ID.
        stream_id: u32,
    },

    /// Invalid state transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted state.
        to: String,
    },

    /// Codec negotiation failed.
    #[error("codec negotiation failed: {reason}")]
    CodecNegotiationFailed {
        /// Error description.
        reason: String,
    },

    /// Transcoding not supported.
    #[error("transcoding not supported: {from_codec} to {to_codec}")]
    TranscodingNotSupported {
        /// Source codec.
        from_codec: String,
        /// Target codec.
        to_codec: String,
    },

    /// Resource exhausted.
    #[error("resource exhausted: {resource}")]
    ResourceExhausted {
        /// Resource name.
        resource: String,
    },

    /// RTP error.
    #[error("RTP error: {0}")]
    Rtp(#[from] sbc_rtp::RtpError),

    /// SRTP error.
    #[error("SRTP error: {0}")]
    Srtp(#[from] sbc_srtp::SrtpError),

    /// Codec error.
    #[error("codec error: {0}")]
    Codec(#[from] sbc_codecs::CodecError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Timeout.
    #[error("operation timed out")]
    Timeout,

    /// Session closed.
    #[error("session closed")]
    SessionClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MediaError::SessionNotFound {
            session_id: "test-123".to_string(),
        };
        assert!(err.to_string().contains("test-123"));
    }
}
