//! Integration tests for the USG Unified Communications SBC.
//!
//! This crate contains integration tests that verify the interaction
//! between multiple SBC components.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CA-8**: Penetration Testing
//! - **SA-11**: Developer Testing and Evaluation

#![forbid(unsafe_code)]
#![allow(clippy::missing_docs_in_private_items)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::doc_markdown,
        clippy::uninlined_format_args,
        clippy::similar_names,
        clippy::unreadable_literal,
        clippy::float_cmp,
        clippy::bool_assert_comparison,
    )
)]

#[cfg(test)]
mod config_tests;

#[cfg(test)]
mod health_tests;

#[cfg(test)]
mod metrics_tests;

#[cfg(test)]
mod policy_tests;

#[cfg(all(test, feature = "cluster"))]
mod cluster_tests;

#[cfg(all(test, feature = "grpc"))]
mod grpc_tests;
