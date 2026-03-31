//! Error types for phone management operations.

use std::fmt;

/// Errors that can occur during phone management operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PhoneMgmtError {
    /// The requested phone was not found.
    PhoneNotFound,
    /// A phone with the given MAC address already exists.
    PhoneAlreadyExists,
    /// The provided MAC address is not valid.
    InvalidMacAddress,
    /// The provided model string is not recognized.
    InvalidModel(String),
    /// Failed to generate provisioning configuration.
    ConfigGenerationFailed(String),
    /// The requested firmware was not found.
    FirmwareNotFound,
    /// An error occurred in the storage backend.
    StorageError(String),
}

impl fmt::Display for PhoneMgmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PhoneNotFound => write!(f, "phone not found"),
            Self::PhoneAlreadyExists => write!(f, "phone already exists"),
            Self::InvalidMacAddress => write!(f, "invalid MAC address"),
            Self::InvalidModel(m) => write!(f, "invalid phone model: {m}"),
            Self::ConfigGenerationFailed(msg) => {
                write!(f, "config generation failed: {msg}")
            }
            Self::FirmwareNotFound => write!(f, "firmware not found"),
            Self::StorageError(msg) => write!(f, "storage error: {msg}"),
        }
    }
}
