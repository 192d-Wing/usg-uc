//! Transaction error types.

use thiserror::Error;

/// Result type for transaction operations.
pub type TransactionResult<T> = Result<T, TransactionError>;

/// Transaction errors.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// Invalid state transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted state.
        to: String,
    },

    /// Transaction timeout.
    #[error("transaction timeout: {timer}")]
    Timeout {
        /// Timer that expired.
        timer: String,
    },

    /// Transaction terminated.
    #[error("transaction terminated")]
    Terminated,

    /// Transport error.
    #[error("transport error: {reason}")]
    TransportError {
        /// Error description.
        reason: String,
    },

    /// Invalid response.
    #[error("invalid response: {reason}")]
    InvalidResponse {
        /// Error description.
        reason: String,
    },

    /// Invalid request.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// Error description.
        reason: String,
    },

    /// Transaction not found.
    #[error("transaction not found: {key}")]
    NotFound {
        /// Transaction key.
        key: String,
    },

    /// SIP error.
    #[error("SIP error: {0}")]
    Sip(#[from] sbc_sip::SipError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TransactionError::Timeout {
            timer: "Timer B".to_string(),
        };
        assert!(err.to_string().contains("Timer B"));
    }
}
