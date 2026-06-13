//! Error types for the central config store.

use thiserror::Error;

/// Result alias for central-config-store operations.
pub type CentralResult<T> = Result<T, CentralError>;

/// Errors raised by the central config store.
#[derive(Debug, Error)]
pub enum CentralError {
    /// Connecting to, migrating, or querying the database failed.
    #[error("storage backend error: {0}")]
    Storage(String),

    /// The named site has no row in the `sites` registry. Writes bump
    /// that row's epoch, so an unknown site can't be written to.
    #[error("unknown site: {0}")]
    UnknownSite(String),

    /// A DID is already owned by a different site. Fleet-wide DID
    /// uniqueness is a hard invariant (a number routes to exactly one
    /// base), enforced via `did_registry`.
    #[error("DID {did} is already assigned to site {owner}")]
    DidConflict {
        /// The DID that collided.
        did: String,
        /// The site that already owns it.
        owner: String,
    },

    /// A within-site uniqueness constraint was violated (e.g. two live
    /// phones sharing a MAC).
    #[error("uniqueness conflict: {0}")]
    Conflict(String),

    /// The requested entity was not present.
    #[error("not found")]
    NotFound,

    /// Encoding/decoding a JSON payload failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A `site_code` failed the canonical-form check before it could reach
    /// the database CHECK constraint.
    #[error("invalid site code: {0}")]
    InvalidSiteCode(String),
}

impl From<sqlx::Error> for CentralError {
    fn from(err: sqlx::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for CentralError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<serde_json::Error> for CentralError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
