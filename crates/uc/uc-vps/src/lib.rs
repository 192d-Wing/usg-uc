//! Voice Protection System (VPS) for the SBC.
//!
//! Implements the inline call-screening layer of a DoD-style Voice
//! Protection System: dynamic blocklists, call-level (not packet-level)
//! TDoS rate limiting, per-callee concurrency caps, STIR/SHAKEN
//! screening, and declarative call-policy rules. The engine composes
//! `uc-policy` (rule evaluation) and `uc-dos-protection` (token-bucket
//! limiting) behind a single transport-agnostic entry point.
//!
//! See `docs/VPS-ARCHITECTURE.md` for the full design and phasing.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-3**: Access Enforcement
//! - **AC-4**: Information Flow Enforcement
//! - **SC-5**: Denial of Service Protection
//! - **SI-4**: System Monitoring
//!
//! ## Evaluation order (`VpsEngine::screen_call`)
//!
//! 1. Dynamic blocklist (source IP, caller prefix)
//! 2. Per-source call-attempt rate limit (escalates to timed block)
//! 3. Per-callee concurrency cap
//! 4. STIR/SHAKEN screening (inbound trunk calls)
//! 5. Declarative policy rules (first match in priority order)
//! 6. Configured default action

#![forbid(unsafe_code)]
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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

pub mod blocklist;
pub mod call_limiter;
pub mod config;
pub mod context;
pub mod engine;
pub mod error;
pub mod verdict;

pub use blocklist::Blocklist;
pub use call_limiter::{CallLimiter, CallLimiterConfig};
pub use config::{
    AttestationLevel, ScreeningMode, StirShakenScreeningConfig, TdosConfig, VpsConfig,
    VpsDefaultAction, VpsRuleAction, VpsRuleConfig,
};
pub use context::{CallAttempt, CallDirection, StirShakenStatus, uri_user};
pub use engine::{VpsEngine, VpsStats};
pub use error::{VpsError, VpsResult};
pub use verdict::{VerdictSource, VpsAction, VpsVerdict};

/// Default SIP status code for policy denials.
pub const DEFAULT_DENY_STATUS: u16 = 403;

/// SIP status code for failed STIR/SHAKEN verification (RFC 8224 §6.2.2).
pub const STIR_SHAKEN_FAILED_STATUS: u16 = 438;

/// SIP status code for rate-limit rejections.
pub const RATE_LIMIT_STATUS: u16 = 503;

/// SIP status code for per-callee concurrency-cap rejections.
pub const CONCURRENCY_CAP_STATUS: u16 = 486;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_constants() {
        assert_eq!(DEFAULT_DENY_STATUS, 403);
        assert_eq!(STIR_SHAKEN_FAILED_STATUS, 438);
    }
}
