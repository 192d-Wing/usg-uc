//! Policy engine for call admission and control.
//!
//! This crate implements policy-based decision making for call routing,
//! admission control, and SIP message manipulation.
//!
//! ## Features
//!
//! - Call admission control (CAC)
//! - SIP header manipulation policies
//! - Time-based routing rules
//! - Codec preference policies
//! - Trunk/route selection

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

pub mod action;
pub mod condition;
pub mod engine;
pub mod error;
pub mod rule;

pub use action::{PolicyAction, HeaderAction};
pub use condition::{Condition, ConditionMatch};
pub use engine::{PolicyEngine, PolicyDecision};
pub use error::{PolicyError, PolicyResult};
pub use rule::{PolicyRule, RuleSet};

/// Default policy priority.
pub const DEFAULT_PRIORITY: u32 = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_priority() {
        assert!(DEFAULT_PRIORITY > 0);
    }
}
