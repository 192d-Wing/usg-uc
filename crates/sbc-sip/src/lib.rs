//! SIP protocol message parsing and generation.
//!
//! This crate handles Session Initiation Protocol (SIP) message parsing,
//! validation, and construction for VoIP signaling.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP: Session Initiation Protocol
//! - **RFC 3263**: SIP: Locating SIP Servers
//! - **RFC 3264**: An Offer/Answer Model with SDP
//! - **RFC 4566**: SDP: Session Description Protocol
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **IA-2**: Identification and Authentication

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod header;
pub mod message;
pub mod method;
pub mod response;
pub mod uri;

pub use error::{SipError, SipResult};
pub use header::{Header, HeaderName, Headers};
pub use message::SipMessage;
pub use method::Method;
pub use response::StatusCode;
pub use uri::SipUri;

/// Maximum SIP message size per RFC 3261.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Default SIP port (UDP/TCP).
pub const DEFAULT_SIP_PORT: u16 = 5060;

/// Default SIP TLS port.
pub const DEFAULT_SIPS_PORT: u16 = 5061;

/// SIP protocol version.
pub const SIP_VERSION: &str = "SIP/2.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_SIP_PORT, 5060);
        assert_eq!(DEFAULT_SIPS_PORT, 5061);
        assert_eq!(SIP_VERSION, "SIP/2.0");
    }
}
