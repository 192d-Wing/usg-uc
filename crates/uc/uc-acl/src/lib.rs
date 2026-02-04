//! Access control lists and IP filtering.
//!
//! This crate provides access control functionality including IP allowlists,
//! denylists, and network-based filtering for SBC security.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-3**: Access Enforcement
//! - **AC-4**: Information Flow Enforcement
//! - **SC-7**: Boundary Protection
//!
//! ## Features
//!
//! - IP address and CIDR network filtering
//! - Domain-based access control
//! - SIP URI filtering
//! - Time-based rules
//! - Configurable actions (allow, deny, rate-limit)

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
pub mod filter;
pub mod network;
pub mod rule;

pub use error::{AclError, AclResult};
pub use filter::{AclFilter, FilterAction, FilterResult};
pub use network::{IpNetwork, NetworkMatch};
pub use rule::{AclRule, RuleMatch, RulePriority};

/// Default rule priority.
pub const DEFAULT_PRIORITY: u32 = 1000;

/// Maximum rules per ACL.
pub const MAX_RULES: usize = 10000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const _: () = {
            assert!(DEFAULT_PRIORITY > 0);
            assert!(MAX_RULES > 0);
        };
    }
}
