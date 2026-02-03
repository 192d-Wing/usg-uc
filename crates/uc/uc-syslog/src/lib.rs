//! # Syslog Forwarding for USG SBC
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::format_collect)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::assigning_clones)]
//!
//! This crate provides RFC 5424 compliant syslog forwarding for the USG Session Border Controller.
//!
//! ## Features
//!
//! - RFC 5424 message formatting
//! - UDP and TCP transport
//! - Structured data support
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-4**: Audit Log Storage Capacity
//! - **AU-6**: Audit Record Review, Analysis, and Reporting
//! - **AU-9**: Protection of Audit Information

pub mod config;
pub mod error;
pub mod formatter;
pub mod forwarder;

pub use config::SyslogConfig;
pub use error::{SyslogError, SyslogResult};
pub use formatter::{Facility, Severity, SyslogMessage};
pub use forwarder::SyslogForwarder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = SyslogConfig::default();
    }
}
