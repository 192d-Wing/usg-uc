//! Configuration error types.

use thiserror::Error;

/// Result type for configuration operations.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Configuration error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read configuration file.
    #[error("failed to read config file '{path}': {reason}")]
    FileRead {
        /// Path to the file.
        path: String,
        /// Error description.
        reason: String,
    },

    /// Failed to parse configuration.
    #[error("failed to parse config: {reason}")]
    Parse {
        /// Parse error description.
        reason: String,
    },

    /// Configuration validation failed.
    #[error("config validation failed: {message}")]
    Validation {
        /// Validation error message.
        message: String,
    },

    /// CNSA 2.0 compliance violation in configuration.
    #[error("CNSA 2.0 violation in config: {message}")]
    CnsaViolation {
        /// Description of the violation.
        message: String,
    },

    /// Network interface not found.
    #[error("network interface '{name}' not found")]
    InterfaceNotFound {
        /// Interface name that was not found.
        name: String,
    },

    /// Network interface has no IPv4 address.
    #[error("network interface '{name}' has no IPv4 address")]
    InterfaceNoAddress {
        /// Interface name.
        name: String,
    },
}
