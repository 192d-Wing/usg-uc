//! B2BUA error types.

use std::fmt;

/// B2BUA result type.
pub type B2buaResult<T> = Result<T, B2buaError>;

/// B2BUA errors.
#[derive(Debug)]
pub enum B2buaError {
    /// Invalid state transition.
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Target state.
        to: String,
    },
    /// Call not found.
    CallNotFound {
        /// Call ID.
        call_id: String,
    },
    /// Leg not found.
    LegNotFound {
        /// Leg ID.
        leg_id: String,
    },
    /// Invalid leg operation.
    InvalidLegOperation {
        /// Reason.
        reason: String,
    },
    /// Call already exists.
    CallAlreadyExists {
        /// Call ID.
        call_id: String,
    },
    /// Max calls exceeded.
    MaxCallsExceeded {
        /// Maximum calls allowed.
        max: usize,
    },
    /// Dialog error.
    DialogError {
        /// Error message.
        message: String,
    },
    /// Media error.
    MediaError {
        /// Error message.
        message: String,
    },
    /// Codec negotiation failed.
    CodecNegotiationFailed {
        /// Reason.
        reason: String,
    },
    /// Timeout.
    Timeout {
        /// Operation that timed out.
        operation: String,
    },
}

impl fmt::Display for B2buaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {from} to {to}")
            }
            Self::CallNotFound { call_id } => {
                write!(f, "Call not found: {call_id}")
            }
            Self::LegNotFound { leg_id } => {
                write!(f, "Leg not found: {leg_id}")
            }
            Self::InvalidLegOperation { reason } => {
                write!(f, "Invalid leg operation: {reason}")
            }
            Self::CallAlreadyExists { call_id } => {
                write!(f, "Call already exists: {call_id}")
            }
            Self::MaxCallsExceeded { max } => {
                write!(f, "Maximum calls exceeded: {max}")
            }
            Self::DialogError { message } => {
                write!(f, "Dialog error: {message}")
            }
            Self::MediaError { message } => {
                write!(f, "Media error: {message}")
            }
            Self::CodecNegotiationFailed { reason } => {
                write!(f, "Codec negotiation failed: {reason}")
            }
            Self::Timeout { operation } => {
                write!(f, "Timeout: {operation}")
            }
        }
    }
}

impl std::error::Error for B2buaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = B2buaError::InvalidStateTransition {
            from: "Early".to_string(),
            to: "Terminated".to_string(),
        };
        assert!(error.to_string().contains("Early"));
        assert!(error.to_string().contains("Terminated"));
    }

    #[test]
    fn test_call_not_found() {
        let error = B2buaError::CallNotFound {
            call_id: "call-123".to_string(),
        };
        assert!(error.to_string().contains("call-123"));
    }
}
