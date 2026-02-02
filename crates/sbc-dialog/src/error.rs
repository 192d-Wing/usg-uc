//! Dialog error types.

use thiserror::Error;

/// Result type for dialog operations.
pub type DialogResult<T> = Result<T, DialogError>;

/// Dialog errors.
#[derive(Debug, Error)]
pub enum DialogError {
    /// Invalid state transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted state.
        to: String,
    },

    /// Dialog not found.
    #[error("dialog not found: {dialog_id}")]
    NotFound {
        /// Dialog ID.
        dialog_id: String,
    },

    /// Dialog already exists.
    #[error("dialog already exists: {dialog_id}")]
    AlreadyExists {
        /// Dialog ID.
        dialog_id: String,
    },

    /// Dialog terminated.
    #[error("dialog has been terminated")]
    Terminated,

    /// Invalid CSeq.
    #[error("invalid CSeq: expected {expected}, got {actual}")]
    InvalidCSeq {
        /// Expected CSeq.
        expected: u32,
        /// Actual CSeq.
        actual: u32,
    },

    /// Session timer expired.
    #[error("session timer expired")]
    SessionExpired,

    /// Invalid session timer.
    #[error("invalid session timer: {reason}")]
    InvalidSessionTimer {
        /// Error description.
        reason: String,
    },

    /// Missing required header.
    #[error("missing required header: {header}")]
    MissingHeader {
        /// Header name.
        header: String,
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
        let err = DialogError::InvalidCSeq {
            expected: 100,
            actual: 99,
        };
        assert!(err.to_string().contains("100"));
    }
}
