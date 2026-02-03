//! ICE error types.

use thiserror::Error;

/// Result type for ICE operations.
pub type IceResult<T> = Result<T, IceError>;

/// ICE errors.
#[derive(Debug, Error)]
pub enum IceError {
    /// Gathering failed.
    #[error("candidate gathering failed: {reason}")]
    GatheringFailed {
        /// Error description.
        reason: String,
    },

    /// No candidates available.
    #[error("no candidates available")]
    NoCandidates,

    /// Connectivity check failed.
    #[error("connectivity check failed: {reason}")]
    CheckFailed {
        /// Error description.
        reason: String,
    },

    /// All candidate pairs failed.
    #[error("all candidate pairs failed connectivity checks")]
    AllPairsFailed,

    /// ICE timeout.
    #[error("ICE negotiation timed out")]
    Timeout,

    /// Invalid candidate.
    #[error("invalid candidate: {reason}")]
    InvalidCandidate {
        /// Error description.
        reason: String,
    },

    /// Invalid state transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted state.
        to: String,
    },

    /// Role conflict.
    #[error("ICE role conflict detected")]
    RoleConflict,

    /// STUN error.
    #[error("STUN error: {0}")]
    Stun(#[from] proto_stun::StunError),

    /// TURN error.
    #[error("TURN error: {0}")]
    Turn(#[from] proto_turn::TurnError),

    /// Network error.
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    /// Network error with reason.
    #[error("network error: {reason}")]
    NetworkError {
        /// Error description.
        reason: String,
    },

    /// Missing required attribute.
    #[error("missing required attribute: {attribute}")]
    MissingAttribute {
        /// Attribute name.
        attribute: String,
    },

    /// Parse error.
    #[error("parse error: {reason}")]
    ParseError {
        /// Error description.
        reason: String,
    },

    /// Protocol error.
    #[error("protocol error: {reason}")]
    ProtocolError {
        /// Error description.
        reason: String,
    },
}

/// ICE disconnection reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Normal disconnect by local party.
    LocalClose,
    /// Remote party closed.
    RemoteClose,
    /// Connection timeout.
    Timeout,
    /// Network failure.
    NetworkFailure,
    /// ICE restart requested.
    IceRestart,
}

impl std::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalClose => write!(f, "local close"),
            Self::RemoteClose => write!(f, "remote close"),
            Self::Timeout => write!(f, "timeout"),
            Self::NetworkFailure => write!(f, "network failure"),
            Self::IceRestart => write!(f, "ICE restart"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disconnect_reasons() {
        assert_eq!(DisconnectReason::LocalClose.to_string(), "local close");
        assert_eq!(DisconnectReason::Timeout.to_string(), "timeout");
    }
}
