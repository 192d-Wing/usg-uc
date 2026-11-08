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
//! - UDP (RFC 5426), TCP (RFC 6587) and TLS (RFC 5425) transport
//! - Structured data support
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! Library-only: sbc-daemon does not yet wire the TLS transport
//! (POA&M-245).
//!
//! - **AU-9 / SC-8**: only with `transport = tls` (CNSA 2.0 provider,
//!   collector certificate and name verified). UDP and TCP give no
//!   protection in transit.
//! - **AU-4 / AU-6**: off-box forwarding supports central storage and
//!   review; this crate does not buffer, so records sent while the
//!   collector is unreachable are lost (the caller sees the error).

pub mod config;
pub mod error;
pub mod formatter;
pub mod forwarder;

pub use config::{SyslogConfig, SyslogTlsConfig, SyslogTransport};
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
