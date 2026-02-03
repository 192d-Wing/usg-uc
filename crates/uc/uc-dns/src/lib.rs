//! # DNS Integration for SIP Routing
//!
//! This crate provides DNS-based service discovery for SIP, implementing:
//!
//! - **RFC 3263**: SIP DNS procedures (SRV, NAPTR, A/AAAA)
//! - **RFC 6116**: ENUM (E.164 to URI mapping)
//! - **DNS Caching**: TTL-aware caching for performance
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-20**: Secure Name/Address Resolution Service
//! - **SC-21**: Secure Name/Address Resolution Service (Authoritative Source)
//! - **SC-22**: Architecture and Provisioning for Name/Address Resolution Service
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    DNS Resolution Layer                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  SIP Resolver  │  ENUM Lookup  │  DNS Cache  │  Transport   │
//! │  (RFC 3263)    │  (RFC 6116)   │  (TTL)      │  Selection   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_name_repetitions)]

pub mod cache;
pub mod config;
pub mod r#enum;
pub mod error;
pub mod naptr;
pub mod resolver;
pub mod srv;

#[cfg(feature = "resolver")]
pub mod hickory;

pub use cache::{CachedRecord, DnsCache};
pub use config::DnsConfig;
pub use r#enum::{EnumResolver, EnumResult};
pub use error::{DnsError, DnsResult};
pub use naptr::{NaptrRecord, NaptrService};
pub use resolver::{SipResolver, SipTarget, TransportPreference};
pub use srv::{SrvRecord, SrvResolver};

#[cfg(feature = "resolver")]
pub use hickory::HickoryDnsResolver;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = DnsConfig::default();
    }
}
