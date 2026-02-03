//! Error types for the storage module.

use thiserror::Error;

/// Result type alias for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// Connection failed.
    #[error("connection failed: {reason}")]
    ConnectionFailed {
        /// Reason for the connection failure.
        reason: String,
    },

    /// Key not found.
    #[error("key not found: {key}")]
    KeyNotFound {
        /// The key that was not found.
        key: String,
    },

    /// Serialization error.
    #[error("serialization error: {reason}")]
    SerializationError {
        /// Reason for the serialization error.
        reason: String,
    },

    /// Deserialization error.
    #[error("deserialization error: {reason}")]
    DeserializationError {
        /// Reason for the deserialization error.
        reason: String,
    },

    /// Operation timeout.
    #[error("operation timed out after {duration_ms}ms")]
    Timeout {
        /// Duration in milliseconds.
        duration_ms: u64,
    },

    /// Redis error.
    #[error("Redis error: {reason}")]
    RedisError {
        /// Reason for the Redis error.
        reason: String,
    },

    /// PostgreSQL error.
    #[error("PostgreSQL error: {reason}")]
    PostgresError {
        /// Reason for the PostgreSQL error.
        reason: String,
    },

    /// Pool exhausted.
    #[error("connection pool exhausted")]
    PoolExhausted,

    /// Transaction error.
    #[error("transaction error: {reason}")]
    TransactionError {
        /// Reason for the transaction error.
        reason: String,
    },

    /// Migration error.
    #[error("migration error: {reason}")]
    MigrationError {
        /// Reason for the migration error.
        reason: String,
    },

    /// IO error.
    #[error("IO error: {reason}")]
    IoError {
        /// Reason for the IO error.
        reason: String,
    },
}

#[cfg(feature = "redis")]
impl From<redis::RedisError> for StorageError {
    fn from(err: redis::RedisError) -> Self {
        Self::RedisError {
            reason: err.to_string(),
        }
    }
}

#[cfg(feature = "postgres")]
impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        Self::PostgresError {
            reason: err.to_string(),
        }
    }
}
