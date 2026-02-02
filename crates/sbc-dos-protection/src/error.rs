//! DoS protection error types.

use std::fmt;

/// DoS protection result type.
pub type DosResult<T> = Result<T, DosError>;

/// DoS protection errors.
#[derive(Debug)]
pub enum DosError {
    /// Rate limit exceeded.
    RateLimitExceeded {
        /// Source identifier.
        source: String,
        /// Current rate.
        current_rate: u32,
        /// Limit.
        limit: u32,
    },
    /// Source is blocked.
    Blocked {
        /// Source identifier.
        source: String,
        /// Seconds until unblock.
        remaining_secs: u64,
    },
    /// Invalid configuration.
    InvalidConfig {
        /// Reason.
        reason: String,
    },
    /// Tracker error.
    TrackerError {
        /// Message.
        message: String,
    },
}

impl fmt::Display for DosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimitExceeded {
                source,
                current_rate,
                limit,
            } => {
                write!(
                    f,
                    "Rate limit exceeded for {}: {} > {}",
                    source, current_rate, limit
                )
            }
            Self::Blocked {
                source,
                remaining_secs,
            } => {
                write!(f, "Source {} blocked for {} more seconds", source, remaining_secs)
            }
            Self::InvalidConfig { reason } => {
                write!(f, "Invalid configuration: {}", reason)
            }
            Self::TrackerError { message } => {
                write!(f, "Tracker error: {}", message)
            }
        }
    }
}

impl std::error::Error for DosError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_exceeded_display() {
        let error = DosError::RateLimitExceeded {
            source: "192.168.1.100".to_string(),
            current_rate: 150,
            limit: 100,
        };
        assert!(error.to_string().contains("150"));
        assert!(error.to_string().contains("100"));
    }

    #[test]
    fn test_blocked_display() {
        let error = DosError::Blocked {
            source: "10.0.0.1".to_string(),
            remaining_secs: 30,
        };
        assert!(error.to_string().contains("30"));
    }
}
