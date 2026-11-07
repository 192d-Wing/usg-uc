//! uc-sti error types.
//!
//! ## NIST 800-53 Rev5: SI-11 (Error Handling)

use proto_stir_shaken::FailureReason;
use thiserror::Error;

/// Why a certificate could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FetchError {
    /// The `x5u` URL is refused by policy (scheme, port, userinfo, host
    /// allow-list, or an address that fails the SSRF guard).
    #[error("x5u refused by policy: {0}")]
    Policy(&'static str),
    /// DNS, TCP, TLS or HTTP failure.
    #[error("certificate fetch failed: {0}")]
    Transport(&'static str),
    /// Non-200 response.
    #[error("certificate fetch HTTP status {0}")]
    Status(u16),
    /// Response body over `max_cert_bytes`.
    #[error("certificate response too large")]
    TooLarge,
    /// Deadline exceeded.
    #[error("certificate fetch timed out")]
    Timeout,
    /// Concurrency limit reached.
    #[error("certificate fetch concurrency limit reached")]
    Busy,
    /// Fetched certificate did not validate (chain, profile, expiry).
    #[error("certificate untrusted: {0}")]
    Untrusted(&'static str),
}

impl FetchError {
    /// Maps to the verification failure reason (and so the SIP code).
    #[must_use]
    pub const fn reason(&self) -> FailureReason {
        match self {
            Self::Policy(_) => FailureReason::BadInfo,
            Self::Timeout => FailureReason::CertFetchTimeout,
            Self::Busy => FailureReason::CertFetchBusy,
            Self::Untrusted(_) => FailureReason::CertUntrusted,
            Self::Transport(_) | Self::Status(_) | Self::TooLarge => FailureReason::CertFetchFailed,
        }
    }

    /// Bounded metric label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Policy(_) => "policy",
            Self::Transport(_) => "transport",
            Self::Status(_) => "status",
            Self::TooLarge => "too-large",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::Untrusted(_) => "untrusted",
        }
    }
}

/// Signing key / certificate load failures.
#[derive(Debug, Error)]
pub enum KeyLoadError {
    /// File could not be opened/read.
    #[error("{what}: {source}")]
    Io {
        /// Which file.
        what: &'static str,
        /// Cause.
        source: std::io::Error,
    },
    /// File permissions/ownership/type refused.
    #[error("{0}")]
    Permissions(String),
    /// Key or certificate content invalid.
    #[error("{0}")]
    Invalid(&'static str),
}
