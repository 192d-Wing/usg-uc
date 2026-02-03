//! Policy error types.

use std::fmt;

/// Policy result type.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Policy errors.
#[derive(Debug)]
pub enum PolicyError {
    /// Rule not found.
    RuleNotFound {
        /// Rule ID.
        rule_id: String,
    },
    /// Rule set not found.
    RuleSetNotFound {
        /// Rule set name.
        name: String,
    },
    /// Rule set already exists.
    RuleSetExists {
        /// Rule set name.
        name: String,
    },
    /// Too many rules.
    TooManyRules {
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Invalid condition.
    InvalidCondition {
        /// Reason.
        reason: String,
    },
    /// Invalid action.
    InvalidAction {
        /// Reason.
        reason: String,
    },
    /// Policy evaluation failed.
    EvaluationFailed {
        /// Reason.
        reason: String,
    },
    /// Duplicate rule.
    DuplicateRule {
        /// Rule ID.
        rule_id: String,
    },
    /// Invalid configuration.
    InvalidConfig {
        /// Reason.
        reason: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleNotFound { rule_id } => {
                write!(f, "Rule not found: {rule_id}")
            }
            Self::RuleSetNotFound { name } => {
                write!(f, "Rule set not found: {name}")
            }
            Self::RuleSetExists { name } => {
                write!(f, "Rule set already exists: {name}")
            }
            Self::TooManyRules { count, max } => {
                write!(f, "Too many rules: {count} (max {max})")
            }
            Self::InvalidCondition { reason } => {
                write!(f, "Invalid condition: {reason}")
            }
            Self::InvalidAction { reason } => {
                write!(f, "Invalid action: {reason}")
            }
            Self::EvaluationFailed { reason } => {
                write!(f, "Policy evaluation failed: {reason}")
            }
            Self::DuplicateRule { rule_id } => {
                write!(f, "Duplicate rule: {rule_id}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "Invalid configuration: {reason}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = PolicyError::RuleNotFound {
            rule_id: "rule-1".to_string(),
        };
        assert!(error.to_string().contains("rule-1"));
    }
}
