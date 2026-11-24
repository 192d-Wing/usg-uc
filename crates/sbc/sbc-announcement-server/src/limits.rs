//! Play concurrency caps (`SBC_ANN_MAX_PLAYS`, `SBC_ANN_MAX_PLAYS_PER_DEST`):
//! the shared implementation in `sbc_announcement::limits`, also used by the
//! daemon's in-process playback.
//!
//! ## NIST 800-53 Rev5: SC-5

#[cfg(test)]
pub use sbc_announcement::limits::LimitRefusal;
pub use sbc_announcement::limits::PlayLimits;
