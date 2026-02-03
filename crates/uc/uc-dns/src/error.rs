//! Error types for DNS operations.

use thiserror::Error;

/// DNS error types.
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS resolution failed.
    #[error("DNS resolution failed for {domain}: {reason}")]
    ResolutionFailed {
        /// Domain that failed to resolve.
        domain: String,
        /// Error reason.
        reason: String,
    },

    /// No records found.
    #[error("no DNS records found for {domain}")]
    NoRecords {
        /// Domain with no records.
        domain: String,
    },

    /// Invalid domain name.
    #[error("invalid domain name: {domain}")]
    InvalidDomain {
        /// The invalid domain.
        domain: String,
    },

    /// Invalid NAPTR record.
    #[error("invalid NAPTR record: {reason}")]
    InvalidNaptr {
        /// Error reason.
        reason: String,
    },

    /// Invalid SRV record.
    #[error("invalid SRV record: {reason}")]
    InvalidSrv {
        /// Error reason.
        reason: String,
    },

    /// Invalid ENUM query.
    #[error("invalid ENUM query for {number}: {reason}")]
    InvalidEnum {
        /// E.164 number.
        number: String,
        /// Error reason.
        reason: String,
    },

    /// ENUM number not found.
    #[error("ENUM number not found: {number}")]
    EnumNotFound {
        /// E.164 number.
        number: String,
    },

    /// Unsupported transport.
    #[error("unsupported transport: {transport}")]
    UnsupportedTransport {
        /// Transport name.
        transport: String,
    },

    /// Timeout error.
    #[error("DNS query timeout for {domain}")]
    Timeout {
        /// Domain that timed out.
        domain: String,
    },

    /// Cache error.
    #[error("cache error: {reason}")]
    CacheError {
        /// Error reason.
        reason: String,
    },

    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Error reason.
        reason: String,
    },
}

/// Result type for DNS operations.
pub type DnsResult<T> = Result<T, DnsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DnsError::ResolutionFailed {
            domain: "example.com".to_string(),
            reason: "server not responding".to_string(),
        };
        assert!(err.to_string().contains("example.com"));
    }

    #[test]
    fn test_no_records() {
        let err = DnsError::NoRecords {
            domain: "missing.example.com".to_string(),
        };
        assert!(err.to_string().contains("no DNS records"));
    }
}
