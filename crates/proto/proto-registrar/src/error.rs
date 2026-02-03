//! Registrar error types.

use std::fmt;

/// Registrar result type.
pub type RegistrarResult<T> = Result<T, RegistrarError>;

/// Registrar errors.
#[derive(Debug)]
pub enum RegistrarError {
    /// AOR not found.
    AorNotFound {
        /// Address of record.
        aor: String,
    },
    /// Binding not found.
    BindingNotFound {
        /// Contact URI.
        contact: String,
    },
    /// Too many contacts for AOR.
    TooManyContacts {
        /// Maximum allowed.
        max: usize,
    },
    /// Invalid expires value.
    InvalidExpires {
        /// Requested value.
        requested: u32,
        /// Minimum allowed.
        min: u32,
    },
    /// Registration expired.
    RegistrationExpired {
        /// Contact URI.
        contact: String,
    },
    /// Invalid contact URI.
    InvalidContact {
        /// Contact string.
        contact: String,
        /// Reason.
        reason: String,
    },
    /// Authorization required.
    AuthRequired {
        /// Realm.
        realm: String,
    },
    /// Authorization failed.
    AuthFailed {
        /// Reason.
        reason: String,
    },
    /// Registration not allowed.
    NotAllowed {
        /// Reason.
        reason: String,
    },
    /// Internal error.
    Internal {
        /// Error message.
        message: String,
    },
}

impl fmt::Display for RegistrarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AorNotFound { aor } => {
                write!(f, "AOR not found: {aor}")
            }
            Self::BindingNotFound { contact } => {
                write!(f, "Binding not found: {contact}")
            }
            Self::TooManyContacts { max } => {
                write!(f, "Too many contacts (max {max})")
            }
            Self::InvalidExpires { requested, min } => {
                write!(f, "Invalid expires value {requested} (minimum {min})")
            }
            Self::RegistrationExpired { contact } => {
                write!(f, "Registration expired: {contact}")
            }
            Self::InvalidContact { contact, reason } => {
                write!(f, "Invalid contact {contact}: {reason}")
            }
            Self::AuthRequired { realm } => {
                write!(f, "Authorization required for realm: {realm}")
            }
            Self::AuthFailed { reason } => {
                write!(f, "Authorization failed: {reason}")
            }
            Self::NotAllowed { reason } => {
                write!(f, "Registration not allowed: {reason}")
            }
            Self::Internal { message } => {
                write!(f, "Internal error: {message}")
            }
        }
    }
}

impl std::error::Error for RegistrarError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = RegistrarError::AorNotFound {
            aor: "sip:alice@example.com".to_string(),
        };
        assert!(error.to_string().contains("alice@example.com"));
    }

    #[test]
    fn test_invalid_expires() {
        let error = RegistrarError::InvalidExpires {
            requested: 30,
            min: 60,
        };
        assert!(error.to_string().contains("30"));
        assert!(error.to_string().contains("60"));
    }
}
