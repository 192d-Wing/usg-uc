//! Call routing and least-cost routing engine.
//!
//! This crate provides call routing logic including dial plan processing,
//! carrier selection, and failover handling.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-4**: Information Flow Enforcement
//! - **CP-10**: System Recovery and Reconstitution (failover)
//!
//! ## Features
//!
//! - Dial plan pattern matching
//! - Number translation/manipulation
//! - Trunk/carrier selection
//! - Least-cost routing (LCR)
//! - Failover and load balancing

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

pub mod dialplan;
pub mod error;
pub mod router;
pub mod trunk;

pub use dialplan::{
    DestinationType, DialPlan, DialPlanEntry, DialPlanResult, DialPattern, Direction,
    NumberTransform,
};
pub use error::{RoutingError, RoutingResult};
pub use router::{Router, RouterConfig, RoutingDecision};
pub use trunk::{SelectionStrategy, Trunk, TrunkConfig, TrunkGroup, TrunkProtocol, TrunkState};

/// Default routing priority.
pub const DEFAULT_PRIORITY: u32 = 100;

/// Default trunk weight for load balancing.
pub const DEFAULT_WEIGHT: u32 = 100;

/// Default failover timeout in milliseconds.
pub const DEFAULT_FAILOVER_TIMEOUT_MS: u64 = 5000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const _: () = {
            assert!(DEFAULT_PRIORITY > 0);
            assert!(DEFAULT_WEIGHT > 0);
            assert!(DEFAULT_FAILOVER_TIMEOUT_MS > 0);
        };
    }
}
