//! ACL error types.

use std::fmt;

/// ACL result type.
pub type AclResult<T> = Result<T, AclError>;

/// ACL errors.
#[derive(Debug)]
pub enum AclError {
    /// Invalid network specification.
    InvalidNetwork {
        /// Network string.
        network: String,
        /// Reason.
        reason: String,
    },
    /// Invalid IP address.
    InvalidIpAddress {
        /// Address string.
        address: String,
    },
    /// Invalid CIDR prefix.
    InvalidPrefix {
        /// Prefix value.
        prefix: u8,
        /// Maximum for address family.
        max: u8,
    },
    /// Rule not found.
    RuleNotFound {
        /// Rule ID.
        rule_id: String,
    },
    /// Maximum rules exceeded.
    MaxRulesExceeded {
        /// Maximum.
        max: usize,
    },
    /// Invalid rule configuration.
    InvalidRule {
        /// Reason.
        reason: String,
    },
    /// Duplicate rule.
    DuplicateRule {
        /// Rule ID.
        rule_id: String,
    },
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNetwork { network, reason } => {
                write!(f, "Invalid network '{}': {}", network, reason)
            }
            Self::InvalidIpAddress { address } => {
                write!(f, "Invalid IP address: {}", address)
            }
            Self::InvalidPrefix { prefix, max } => {
                write!(f, "Invalid prefix /{} (max {})", prefix, max)
            }
            Self::RuleNotFound { rule_id } => {
                write!(f, "Rule not found: {}", rule_id)
            }
            Self::MaxRulesExceeded { max } => {
                write!(f, "Maximum rules exceeded: {}", max)
            }
            Self::InvalidRule { reason } => {
                write!(f, "Invalid rule: {}", reason)
            }
            Self::DuplicateRule { rule_id } => {
                write!(f, "Duplicate rule: {}", rule_id)
            }
        }
    }
}

impl std::error::Error for AclError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = AclError::InvalidNetwork {
            network: "192.168.1.0/33".to_string(),
            reason: "prefix too large".to_string(),
        };
        assert!(error.to_string().contains("192.168.1.0/33"));
    }

    #[test]
    fn test_invalid_prefix() {
        let error = AclError::InvalidPrefix {
            prefix: 33,
            max: 32,
        };
        assert!(error.to_string().contains("33"));
        assert!(error.to_string().contains("32"));
    }
}
