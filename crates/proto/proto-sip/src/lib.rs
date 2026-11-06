//! SIP protocol message parsing and generation.
//!
//! This crate handles Session Initiation Protocol (SIP) message parsing,
//! validation, and construction for `VoIP` signaling.
//!
//! ## RFC 3261 Compliance
//!
//! Message layer coverage (see `PROTO_RFC_COMPLIANCE.md` and
//! `docs/RFC_COMPLIANCE_GAPS.md` for known gaps, e.g. the §25 URI grammar):
//!
//! - **§7**: SIP Messages - Complete message parsing and generation
//! - **§8**: General User Agent Behavior - Request/response construction
//! - **§10**: Registrations - REGISTER method and Contact handling
//! - **§11**: Querying for Capabilities - OPTIONS request/response processing
//! - **§19**: SIP Uniform Resource Indicators - URI parsing (partial §25 grammar)
//! - **§20**: Header Fields - All 44 standard headers implemented
//! - **§22**: Usage of HTTP Authentication - Digest auth (MD5, SHA-256, SHA-512-256)
//!
//! ## Additional RFC Compliance
//!
//! - **RFC 2617**: HTTP Authentication (Digest authentication)
//! - **RFC 3263**: SIP: Locating SIP Servers
//! - **RFC 3264**: An Offer/Answer Model with SDP
//! - **RFC 4566**: SDP: Session Description Protocol
//! - **RFC 7118**: WebSocket Transport for SIP
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (bodies serialized verbatim)
//! - **SI-10**: Information Input Validation (strict byte-based parser)
//! - **SC-5**: Denial-of-Service Protection (`MAX_*` parser limits)
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
//! - **Rule 10**: Lints enforced - `clippy::all` denied workspace-wide, plus
//!   `missing_docs` and the `unwrap`/`expect`/`panic` restriction lints denied
//!   in this crate. (`pedantic`/`nursery` are warn-level; see workspace lints.)

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod auth;
pub mod builder;
pub mod error;
pub mod header;
pub mod header_params;
pub mod list;
pub mod manipulation;
pub mod message;
pub mod method;
pub mod options;
pub mod proxy;
pub mod redirect;
pub mod response;
pub mod routing;
pub mod topology;
pub mod transport;
pub mod uri;

#[cfg(feature = "digest-auth")]
pub use auth::Md5DigestHasher;
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
pub use list::{ListSplit, split_list, split_list_bounded};
pub use message::{Framing, SipMessage, SipRequest, SipResponse};
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

// RFC 3261 §11 OPTIONS capability querying
pub use options::{
    DEFAULT_ACCEPT_ENCODINGS, DEFAULT_ACCEPT_LANGUAGES, DEFAULT_ACCEPT_TYPES,
    DEFAULT_SUPPORTED_METHODS, OptionsCapabilities, create_options_response,
    create_options_response_default, process_options_request,
};

/// Maximum SIP message size per RFC 3261.
pub const MAX_MESSAGE_SIZE: usize = 65535;

// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection) - per-message
// parser limits bound CPU and memory spent on any single message.

/// Maximum number of header fields in one message (folded lines count once).
pub const MAX_HEADERS: usize = 256;

/// Maximum length of one unfolded header field (name + value).
pub const MAX_HEADER_LEN: usize = 8192;

/// Maximum length of the start line (Request-Line / Status-Line).
pub const MAX_START_LINE_LEN: usize = 8192;

/// Maximum length of a URI string.
pub const MAX_URI_LEN: usize = 4096;

/// Maximum parameters per URI / Via / name-addr parameter list.
pub const MAX_PARAMS: usize = 64;

/// Maximum list elements per header field after comma splitting.
pub const MAX_LIST_ELEMENTS: usize = 64;

/// Maximum leading CRLF pairs skipped before the start line
/// (RFC 3261 §7.5; RFC 5626 §3.5.1 keep-alives).
pub const MAX_LEADING_CRLF: usize = 32;

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
