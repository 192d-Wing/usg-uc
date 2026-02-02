//! Call Detail Records generation and storage.
//!
//! This crate handles CDR creation, formatting, and export for billing,
//! compliance, and analytics purposes.
//!
//! ## Features
//!
//! - CDR record generation
//! - Multiple output formats (JSON, CSV)
//! - Field mapping and customization
//! - Buffered writing for performance

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

pub mod error;
pub mod format;
pub mod record;
pub mod writer;

pub use error::{CdrError, CdrResult};
pub use format::{CdrFormat, CsvFormatter, JsonFormatter};
pub use record::{CallRecord, CallStatus, DisconnectCause};
pub use writer::{CdrWriter, CdrWriterConfig};

/// Default buffer size for CDR writing.
pub const DEFAULT_BUFFER_SIZE: usize = 1000;

/// Default flush interval in seconds.
pub const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(DEFAULT_BUFFER_SIZE > 0);
        assert!(DEFAULT_FLUSH_INTERVAL_SECS > 0);
    }
}
