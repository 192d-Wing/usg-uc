//! Audit aggregation for STIR failures. The aggregator lives in
//! [`uc_audit::aggregate`] so non-STIR callers can share it; this module
//! re-exports it for existing `uc_sti::aggregate` users.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-4 (Audit Log Storage Capacity), AU-5, SC-5

pub use uc_audit::aggregate::*;
