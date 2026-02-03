//! Health check endpoints and liveness probes.
//!
//! This crate provides health check functionality for Kubernetes
//! liveness and readiness probes, and system diagnostics.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SI-6**: Security Function Verification
//! - **CA-7**: Continuous Monitoring
//!
//! ## Features
//!
//! - Liveness probe support
//! - Readiness probe support
//! - Component health checks
//! - Aggregated health status

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::use_self)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

pub mod check;
pub mod checker;
pub mod status;

pub use check::{HealthCheck, HealthCheckResult};
pub use checker::{HealthChecker, HealthCheckerConfig};
pub use status::{ComponentStatus, HealthStatus, SystemHealth};

/// Default health check timeout in milliseconds.
pub const DEFAULT_CHECK_TIMEOUT_MS: u64 = 5000;

/// Default interval between health checks in seconds.
pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const _: () = {
            assert!(DEFAULT_CHECK_TIMEOUT_MS > 0);
            assert!(DEFAULT_CHECK_INTERVAL_SECS > 0);
        };
    }
}
