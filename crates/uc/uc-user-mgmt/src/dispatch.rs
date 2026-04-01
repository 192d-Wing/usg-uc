//! Backend-agnostic dispatch for [`UserStore`] implementations.
//!
//! The [`UserStore`] trait uses RPITIT (return-position `impl Trait` in traits),
//! which makes it non-object-safe. This enum provides static dispatch across
//! backends without requiring `dyn` trait objects.

use crate::model::{User, UserFilter};
use crate::store::{Result, UserStore};

/// Dispatches [`UserStore`] calls to the configured backend.
///
/// Variants are conditionally compiled based on enabled features.
pub enum DynUserStore {
    /// SQLite backend (default, for dev/single-node).
    #[cfg(feature = "sqlite")]
    Sqlite(crate::sqlite::SqliteUserStore),

    /// PostgreSQL backend (for production HA deployments).
    #[cfg(feature = "postgres")]
    Postgres(crate::postgres::PostgresUserStore),
}

/// Generates a match arm for each enabled backend variant.
macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.$method($($arg),*).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(s) => s.$method($($arg),*).await,
        }
    };
}

impl UserStore for DynUserStore {
    async fn create_user(&self, user: User) -> Result<User> {
        dispatch!(self, create_user, user)
    }

    async fn get_user(&self, id: &str) -> Result<User> {
        dispatch!(self, get_user, id)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<User> {
        dispatch!(self, get_user_by_username, username)
    }

    async fn get_user_by_certificate_dn(&self, dn: &str) -> Result<User> {
        dispatch!(self, get_user_by_certificate_dn, dn)
    }

    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>> {
        dispatch!(self, list_users, filter)
    }

    async fn update_user(&self, user: User) -> Result<User> {
        dispatch!(self, update_user, user)
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        dispatch!(self, delete_user, id)
    }

    async fn authenticate_digest(
        &self,
        username: &str,
        realm: &str,
    ) -> Result<Option<String>> {
        dispatch!(self, authenticate_digest, username, realm)
    }

    async fn authenticate_certificate(
        &self,
        dn: &str,
        san: &str,
    ) -> Result<Option<User>> {
        dispatch!(self, authenticate_certificate, dn, san)
    }

    async fn count_users(&self) -> Result<usize> {
        dispatch!(self, count_users)
    }
}
