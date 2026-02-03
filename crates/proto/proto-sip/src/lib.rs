//! SIP protocol message parsing and generation.
//!
//! This crate handles Session Initiation Protocol (SIP) message parsing,
//! validation, and construction for `VoIP` signaling.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP: Session Initiation Protocol (message layer)
//! - **RFC 2617**: HTTP Authentication (Digest authentication)
//! - **RFC 3263**: SIP: Locating SIP Servers
//! - **RFC 3264**: An Offer/Answer Model with SDP
//! - **RFC 4566**: SDP: Session Description Protocol
//! - **RFC 7118**: WebSocket Transport for SIP
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **IA-2**: Identification and Authentication

//! ## Safety-Critical Code Compliance
//!
//! This crate follows NASA's "Power of 10" rules for safety-critical code:
//!
//! - **Rule 1**: No goto, recursion - enforced by Rust design
//! - **Rule 2**: Fixed loop bounds - all loops iterate over bounded collections
//! - **Rule 3**: No dynamic allocation after init - N/A (Rust manages allocation safely)
//! - **Rule 4**: Function length - functions kept concise
//! - **Rule 5**: Assertions - debug assertions validate invariants
//! - **Rule 6**: Minimal scope - data scoped to smallest necessary level
//! - **Rule 7**: Return checking - enforced via `Result` types
//! - **Rule 8**: Limited preprocessor - Rust has no C-style preprocessor
//! - **Rule 9**: Pointer restrictions - `#![forbid(unsafe_code)]` enforced
//! - **Rule 10**: All warnings enabled - `#![deny(warnings)]` enforced

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod auth;
pub mod builder;
pub mod error;
pub mod header;
pub mod header_params;
pub mod manipulation;
pub mod message;
pub mod method;
pub mod proxy;
pub mod redirect;
pub mod response;
pub mod routing;
pub mod topology;
pub mod transport;
pub mod uri;

pub use auth::{
    DigestAlgorithm, DigestChallenge, DigestCredentials, DigestHasher, Qop,
    compute_digest_response, compute_ha1, compute_ha2, compute_response, create_credentials,
    verify_credentials,
};
pub use builder::{
    RequestBuilder, ResponseBuilder, generate_branch, generate_call_id, generate_tag,
};
pub use error::{SipError, SipResult};
pub use header::{Header, HeaderName, Headers};
pub use header_params::{
    CSeqHeader, MaxForwardsHeader, NameAddr, VIA_BRANCH_MAGIC_COOKIE, ViaHeader,
};
pub use message::{SipMessage, SipRequest, SipResponse};
pub use method::Method;
pub use redirect::{
    DEFAULT_MAX_REDIRECT_DEPTH, RedirectContact, RedirectHandler, RedirectHeaders, RedirectResult,
    parse_redirect_response,
};
pub use response::StatusCode;
pub use routing::{
    RouteEntry, RouteSet, compute_request_target, create_record_route,
    process_record_route_for_uac, process_record_route_for_uas,
};
pub use topology::{TopologyHider, TopologyHidingConfig, TopologyHidingMode};
pub use transport::Transport;
pub use uri::{SipUri, UriScheme};

// RFC 3261 §16.6 Proxy forwarding
pub use proxy::{
    ForkingMode, ForwardingTarget, ProxyContext, ProxyValidation, RequestForwarder,
    ResponseProcessor, create_loop_detected_response, create_too_many_hops_response,
    create_trying_response,
};

// Header Manipulation Engine (Enterprise SBC feature)
pub use manipulation::{
    HeaderManipulator, ManipulationAction, ManipulationCondition, ManipulationContext,
    ManipulationDirection, ManipulationPolicy, ManipulationPresets, ManipulationRule, MessageType,
};

/// Maximum SIP message size per RFC 3261.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Default SIP port (UDP/TCP).
pub const DEFAULT_SIP_PORT: u16 = 5060;

/// Default SIP TLS port.
pub const DEFAULT_SIPS_PORT: u16 = 5061;

/// SIP protocol version.
pub const SIP_VERSION: &str = "SIP/2.0";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_SIP_PORT, 5060);
        assert_eq!(DEFAULT_SIPS_PORT, 5061);
        assert_eq!(SIP_VERSION, "SIP/2.0");
    }
}
