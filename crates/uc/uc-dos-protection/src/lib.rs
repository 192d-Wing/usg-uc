//! Denial of service detection and mitigation.
//!
//! This crate provides rate limiting, traffic analysis, and DoS attack
//! detection mechanisms to protect the SBC infrastructure.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial of Service Protection
//! - **SI-4**: System Monitoring
//!
//! ## Features
//!
//! - Token bucket rate limiting
//! - Per-IP request tracking
//! - Sliding window rate limiting
//! - Automatic throttling and blocking
//! - Configurable thresholds and actions

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Clippy style preferences for protocol implementation code
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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

pub mod error;
pub mod limiter;
pub mod tracker;

pub use error::{DosError, DosResult};
pub use limiter::{RateLimitAction, RateLimiter, RateLimiterConfig};
pub use tracker::{RequestTracker, SourceStats};

/// Default rate limit (requests per second).
pub const DEFAULT_RPS: u32 = 100;

/// Default burst size.
pub const DEFAULT_BURST: u32 = 200;

/// Default block duration in seconds.
pub const DEFAULT_BLOCK_DURATION_SECS: u64 = 60;

/// Default tracking window in seconds.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const _: () = {
            assert!(DEFAULT_RPS > 0);
            assert!(DEFAULT_BURST >= DEFAULT_RPS);
        };
    }
}
