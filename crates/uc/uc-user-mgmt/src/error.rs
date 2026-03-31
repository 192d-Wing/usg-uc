//! Error types for user management operations.

use std::fmt;

/// Errors that can occur during user management operations.
#[derive(Debug)]
pub enum UserMgmtError {
    /// The requested user was not found.
    UserNotFound,
    /// A user with the given username or ID already exists.
    UserAlreadyExists,
    /// The provided credentials are invalid.
    InvalidCredentials,
    /// Certificate validation failed.
    CertificateValidationFailed(String),
    /// An error occurred in the storage backend.
    StorageError(String),
    /// An error occurred communicating with the LDAP server.
    LdapError(String),
}

impl fmt::Display for UserMgmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "user not found"),
            Self::UserAlreadyExists => write!(f, "user already exists"),
            Self::InvalidCredentials => write!(f, "invalid credentials"),
            Self::CertificateValidationFailed(msg) => {
                write!(f, "certificate validation failed: {msg}")
            }
            Self::StorageError(msg) => write!(f, "storage error: {msg}"),
            Self::LdapError(msg) => write!(f, "LDAP error: {msg}"),
        }
    }
}

impl std::error::Error for UserMgmtError {}
