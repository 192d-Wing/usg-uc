//! Error types for the config store.

use thiserror::Error;

/// Result alias for config-store operations.
pub type ConfigStoreResult<T> = Result<T, ConfigStoreError>;

/// Errors that can be raised by any config-store backend.
#[derive(Debug, Error)]
pub enum ConfigStoreError {
    /// Connecting to or running schema migrations against the database failed.
    #[error("storage backend error: {0}")]
    Storage(String),

    /// The entity referenced by the request was not present.
    #[error("not found")]
    NotFound,

    /// Mapping a row or JSON value to the typed model failed. Usually means
    /// the on-disk JSON (during migration) is malformed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// File I/O failed (only raised by the JSON migration helper).
    #[error("io error: {0}")]
    Io(String),
}

impl From<sqlx::Error> for ConfigStoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<serde_json::Error> for ConfigStoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for ConfigStoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
