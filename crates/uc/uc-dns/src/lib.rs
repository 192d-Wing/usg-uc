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
//! - **CM-7**: the resolver uses the host system DNS configuration, never
//!   hickory's public-resolver defaults (`SipResolver::new`).
//! - **SC-20 / SC-21 / SC-22**: NOT implemented. Responses are not
//!   DNSSEC-validated and no DoT/DoH is used (POA&M-172).
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
