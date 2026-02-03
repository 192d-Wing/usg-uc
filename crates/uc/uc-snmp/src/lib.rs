//! # SNMP Trap Generation for USG SBC
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unnecessary_wraps)]
//!
//! This crate provides SNMP trap generation for monitoring the USG Session Border Controller.
//!
//! ## Features
//!
//! - SNMPv2c trap generation
//! - Custom MIB definitions for SBC metrics
//! - Configurable trap destinations
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-6**: Audit Record Review, Analysis, and Reporting
//! - **SI-4**: System Monitoring

pub mod config;
pub mod error;
pub mod trap;

pub use config::SnmpConfig;
pub use error::{SnmpError, SnmpResult};
pub use trap::{SnmpTrap, TrapSender, TrapType};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = SnmpConfig::default();
    }
}
