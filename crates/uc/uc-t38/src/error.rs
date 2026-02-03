//! Error types for T.38 fax relay.

use thiserror::Error;

/// T.38 error types.
#[derive(Debug, Error)]
pub enum T38Error {
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

    /// Invalid IFP packet.
    #[error("invalid IFP packet: {reason}")]
    InvalidIfpPacket {
        /// Error reason.
        reason: String,
    },

    /// Invalid UDPTL packet.
    #[error("invalid UDPTL packet: {reason}")]
    InvalidUdptlPacket {
        /// Error reason.
        reason: String,
    },

    /// Transport error.
    #[error("transport error: {reason}")]
    TransportError {
        /// Error reason.
        reason: String,
    },

    /// Timeout error.
    #[error("timeout: {operation}")]
    Timeout {
        /// Operation that timed out.
        operation: String,
    },

    /// Fax negotiation failed.
    #[error("fax negotiation failed: {reason}")]
    NegotiationFailed {
        /// Error reason.
        reason: String,
    },

    /// Unsupported feature.
    #[error("unsupported feature: {feature}")]
    Unsupported {
        /// Unsupported feature name.
        feature: String,
    },

    /// I/O error.
    #[error("I/O error: {reason}")]
    Io {
        /// Error reason.
        reason: String,
    },
}

/// Result type for T.38 operations.
pub type T38Result<T> = Result<T, T38Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = T38Error::SessionNotFound {
            session_id: "test-123".to_string(),
        };
        assert!(err.to_string().contains("test-123"));
    }

    #[test]
    fn test_invalid_ifp_packet() {
        let err = T38Error::InvalidIfpPacket {
            reason: "bad header".to_string(),
        };
        assert!(err.to_string().contains("bad header"));
    }
}
