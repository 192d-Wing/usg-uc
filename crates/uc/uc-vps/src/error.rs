//! VPS error types.

use thiserror::Error;

/// Result alias for VPS operations.
pub type VpsResult<T> = Result<T, VpsError>;

/// VPS errors.
#[derive(Debug, Error)]
pub enum VpsError {
    /// The configuration is invalid.
    #[error("invalid VPS configuration: {reason}")]
    InvalidConfig {
        /// Why the configuration was rejected.
        reason: String,
    },

    /// An underlying policy engine error.
    #[error("policy error: {0}")]
    Policy(#[from] uc_policy::PolicyError),
}

impl VpsError {
    /// Creates an invalid-configuration error.
    pub fn invalid_config(reason: impl Into<String>) -> Self {
        Self::InvalidConfig {
            reason: reason.into(),
        }
    }
}
