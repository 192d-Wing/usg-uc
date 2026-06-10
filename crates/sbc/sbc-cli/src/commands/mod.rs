//! CLI command implementations.

pub mod calls;
pub mod config;
pub mod health;
pub mod login;
pub mod metrics;
pub mod status;

use crate::api::ApiError;

/// Command execution error.
#[derive(Debug)]
pub struct CommandError {
    /// Error message.
    pub message: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CommandError {}

impl CommandError {
    /// Creates a new command error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<ApiError> for CommandError {
    fn from(err: ApiError) -> Self {
        Self::new(err.message)
    }
}

/// Result type for command execution.
pub type CommandResult = Result<(), CommandError>;
