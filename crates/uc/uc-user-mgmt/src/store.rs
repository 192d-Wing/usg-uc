//! Trait definition for user storage backends.

use crate::error::UserMgmtError;
use crate::model::{User, UserFilter};

/// Result type for user management operations.
pub type Result<T> = std::result::Result<T, UserMgmtError>;

/// Async trait for user storage backends.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait UserStore: Send + Sync {
    /// Create a new user account.
    fn create_user(
        &self,
        user: User,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    /// Retrieve a user by their unique ID.
    fn get_user(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    /// Retrieve a user by their username.
    fn get_user_by_username(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    /// Retrieve a user by their X.509 certificate Distinguished Name.
    fn get_user_by_certificate_dn(
        &self,
        dn: &str,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    /// List users matching the given filter criteria.
    fn list_users(
        &self,
        filter: &UserFilter,
    ) -> impl std::future::Future<Output = Result<Vec<User>>> + Send;

    /// Update an existing user account.
    fn update_user(
        &self,
        user: User,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    /// Delete a user account by ID.
    fn delete_user(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Look up the HA1 digest hash for SIP digest authentication.
    ///
    /// Returns `Some(ha1)` if the user exists and has digest credentials,
    /// `None` otherwise.
    fn authenticate_digest(
        &self,
        username: &str,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;

    /// Authenticate a user by X.509 certificate identity.
    ///
    /// Returns the matching `User` if a user with the given DN and SAN exists.
    fn authenticate_certificate(
        &self,
        dn: &str,
        san: &str,
    ) -> impl std::future::Future<Output = Result<Option<User>>> + Send;

    /// Return the total number of users in the store.
    fn count_users(
        &self,
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
}
