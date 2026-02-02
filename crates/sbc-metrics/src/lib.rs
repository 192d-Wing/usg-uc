//! Prometheus metrics collection and export.
//!
//! This crate provides metrics instrumentation for monitoring SBC
//! performance, call statistics, and system health.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-6**: Audit Record Review, Analysis, and Reporting
//! - **CA-7**: Continuous Monitoring
//! - **SI-4**: System Monitoring
//!
//! ## Features
//!
//! - Counter, gauge, and histogram metrics
//! - Prometheus text format export
//! - Label support
//! - Metric registry

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

pub mod counter;
pub mod gauge;
pub mod histogram;
pub mod registry;

pub use counter::Counter;
pub use gauge::Gauge;
pub use histogram::Histogram;
pub use registry::{MetricRegistry, MetricType, SbcMetrics};

/// Default histogram buckets for latency (in milliseconds).
pub const DEFAULT_LATENCY_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];

/// Default histogram buckets for call duration (in seconds).
pub const DEFAULT_DURATION_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_buckets() {
        assert!(!DEFAULT_LATENCY_BUCKETS.is_empty());
        // Should be in ascending order
        for i in 1..DEFAULT_LATENCY_BUCKETS.len() {
            assert!(DEFAULT_LATENCY_BUCKETS[i] > DEFAULT_LATENCY_BUCKETS[i - 1]);
        }
    }

    #[test]
    fn test_duration_buckets() {
        assert!(!DEFAULT_DURATION_BUCKETS.is_empty());
        for i in 1..DEFAULT_DURATION_BUCKETS.len() {
            assert!(DEFAULT_DURATION_BUCKETS[i] > DEFAULT_DURATION_BUCKETS[i - 1]);
        }
    }
}
