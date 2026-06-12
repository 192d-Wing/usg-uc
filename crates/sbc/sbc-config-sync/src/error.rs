//! Error type for the sync agent.

use thiserror::Error;

/// Result alias for sync-agent operations.
pub type SyncResult<T> = Result<T, SyncError>;

/// Failures during a reconcile cycle.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Talking to the central config API failed (network, TLS, non-2xx).
    #[error("central API: {0}")]
    Central(String),

    /// The local site database rejected a query or the apply transaction.
    #[error("local database: {0}")]
    Local(String),

    /// A payload from central couldn't be decoded into the expected shape
    /// (e.g. a phone payload missing `mac_address`).
    #[error("malformed payload for {table}/{row_id}: {reason}")]
    Payload {
        /// The table the row belongs to.
        table: String,
        /// The row id.
        row_id: String,
        /// What was wrong.
        reason: String,
    },
}

impl From<sqlx::Error> for SyncError {
    fn from(err: sqlx::Error) -> Self {
        Self::Local(err.to_string())
    }
}

impl From<reqwest::Error> for SyncError {
    fn from(err: reqwest::Error) -> Self {
        Self::Central(err.to_string())
    }
}
