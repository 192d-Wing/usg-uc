//! # SBC Transport
//!
//! Transport layer abstraction for the USG Session Border Controller.
//!
//! This crate provides unified transport abstractions for:
//! - UDP (connectionless, unreliable)
//! - TCP (connection-oriented, reliable)
//! - TLS (encrypted TCP)
//! - WebSocket (HTTP upgrade based)
//! - SCTP (multi-homed, multi-stream - RFC 4168)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-23**: Session Authenticity
//!
//! ## IPv6-First Design
//!
//! All transports prefer IPv6 per project requirements. IPv4 is supported
//! but IPv6 should be used where possible.
//!
//! ## CNSA 2.0 Compliance
//!
//! TLS is configured with CNSA 2.0 compliant cipher suites only:
//! - TLS 1.3 with `TLS_AES_256_GCM_SHA384`
//! - P-384 ECDHE key exchange
//! - P-384 ECDSA certificates

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod listener;
pub mod qos;
pub mod udp;

#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "tls")]
pub mod cert_reload;

#[cfg(feature = "websocket")]
pub mod websocket;

#[cfg(feature = "sctp")]
#[allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::unused_async,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal,
    clippy::struct_excessive_bools,
    clippy::clone_on_copy,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::derive_partial_eq_without_eq,
    clippy::unnecessary_wraps,
    clippy::bool_to_int_with_if,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    clippy::uninlined_format_args,
    clippy::derivable_impls
)]
pub mod sctp;

pub use error::{TransportError, TransportResult};
pub use listener::TransportListener;
pub use qos::{
    DscpValue, QosConfig, QosPolicyManager, TrafficType, TrunkQosPolicy, apply_dscp,
    apply_qos_config,
};
pub use uc_types::address::{SbcSocketAddr, TransportType};

use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;

/// Maximum SIP message size per RFC 3261.
///
/// UDP messages are limited to 1300 bytes for MTU safety,
/// but TCP/TLS can handle larger messages.
pub const MAX_UDP_MESSAGE_SIZE: usize = 1300;

/// Maximum message size for stream transports (TCP/TLS/WS).
pub const MAX_STREAM_MESSAGE_SIZE: usize = 65535;

/// Received message with source information.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The message payload.
    pub data: Bytes,
    /// Source address of the message.
    pub source: SbcSocketAddr,
    /// Transport type the message arrived on.
    pub transport: TransportType,
}

/// Transport trait for sending and receiving SIP messages.
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
pub trait Transport: Send + Sync {
    /// Sends data to the specified destination.
    ///
    /// ## Errors
    ///
    /// Returns an error if the send operation fails.
    fn send<'a>(
        &'a self,
        data: &'a [u8],
        dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>>;

    /// Receives the next message.
    ///
    /// This is a blocking call that waits for the next message.
    ///
    /// ## Errors
    ///
    /// Returns an error if the receive operation fails.
    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>>;

    /// Returns the local address this transport is bound to.
    fn local_addr(&self) -> &SbcSocketAddr;

    /// Returns the transport type.
    fn transport_type(&self) -> TransportType;

    /// Returns true if this transport provides encryption.
    fn is_secure(&self) -> bool {
        self.transport_type().is_secure()
    }

    /// Closes the transport.
    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>>;
}

/// Connection-oriented transport for stream protocols (TCP, TLS, WebSocket).
///
/// ## NIST 800-53 Rev5: SC-23 (Session Authenticity)
pub trait StreamTransport: Transport {
    /// Returns the remote peer address.
    fn peer_addr(&self) -> &SbcSocketAddr;

    /// Returns true if the connection is still open.
    fn is_connected(&self) -> bool;
}
