//! Routing error types.

use std::fmt;

/// Routing result type.
pub type RoutingResult<T> = Result<T, RoutingError>;

/// Routing errors.
#[derive(Debug)]
pub enum RoutingError {
    /// No route found.
    NoRoute {
        /// Destination that couldn't be routed.
        destination: String,
    },
    /// All trunks failed.
    AllTrunksFailed {
        /// Number of trunks tried.
        trunks_tried: usize,
    },
    /// Trunk not found.
    TrunkNotFound {
        /// Trunk ID.
        trunk_id: String,
    },
    /// Trunk group not found.
    TrunkGroupNotFound {
        /// Trunk group ID.
        group_id: String,
    },
    /// Dial plan not found.
    DialPlanNotFound {
        /// Dial plan ID.
        plan_id: String,
    },
    /// Invalid dial pattern.
    InvalidPattern {
        /// Pattern.
        pattern: String,
        /// Reason.
        reason: String,
    },
    /// Route blocked by policy.
    Blocked {
        /// Reason.
        reason: String,
    },
    /// Configuration error.
    ConfigError {
        /// Reason.
        reason: String,
    },
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute { destination } => {
                write!(f, "No route found for: {destination}")
            }
            Self::AllTrunksFailed { trunks_tried } => {
                write!(f, "All {trunks_tried} trunks failed")
            }
            Self::TrunkNotFound { trunk_id } => {
                write!(f, "Trunk not found: {trunk_id}")
            }
            Self::TrunkGroupNotFound { group_id } => {
                write!(f, "Trunk group not found: {group_id}")
            }
            Self::DialPlanNotFound { plan_id } => {
                write!(f, "Dial plan not found: {plan_id}")
            }
            Self::InvalidPattern { pattern, reason } => {
                write!(f, "Invalid pattern '{pattern}': {reason}")
            }
            Self::Blocked { reason } => {
                write!(f, "Route blocked: {reason}")
            }
            Self::ConfigError { reason } => {
                write!(f, "Configuration error: {reason}")
            }
        }
    }
}

impl std::error::Error for RoutingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_route_display() {
        let error = RoutingError::NoRoute {
            destination: "+15551234567".to_string(),
        };
        assert!(error.to_string().contains("+15551234567"));
    }

    #[test]
    fn test_all_trunks_failed_display() {
        let error = RoutingError::AllTrunksFailed { trunks_tried: 3 };
        assert!(error.to_string().contains('3'));
    }
}
