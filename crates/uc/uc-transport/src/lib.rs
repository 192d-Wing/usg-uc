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

// Use deny instead of forbid to allow platform-specific unsafe code with #[allow(unsafe_code)]
#![deny(unsafe_code)]
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

/// Returns `addr` with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)
/// rewritten to plain IPv4; any other address is returned unchanged.
///
/// Dual-stack (`[::]`) sockets report IPv4 peers in mapped form. Applying
/// this once at ingress lets consumers (source blocklists, trunk-peer
/// matching, Via `received=`) compare against plain-IPv4 configuration.
///
/// NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 (one canonical form for peer addresses)
#[must_use]
pub(crate) const fn canonical_peer(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Reads one chunk of at most [`STREAM_READ_CHUNK`] bytes from a TCP or TLS
/// stream into `buf` and splits it off as the returned `Bytes`.
///
/// Reads straight into the chunk buffer. The previous chunk was split off
/// and, once the caller drops it, `reserve` reclaims the same allocation;
/// `limit` keeps one read to one chunk.
///
/// ## Errors
///
/// `ReceiveFailed` on an I/O error; `ConnectionClosed` on EOF.
///
/// ## NIST 800-53 Rev5: SC-5 (one bounded chunk per read)
#[cfg(any(feature = "tcp", feature = "tls"))]
pub(crate) async fn read_stream_chunk<R>(
    stream: &mut R,
    buf: &mut bytes::BytesMut,
) -> TransportResult<Bytes>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use bytes::BufMut;
    use tokio::io::AsyncReadExt;

    buf.reserve(STREAM_READ_CHUNK);
    let n = stream
        .read_buf(&mut (&mut *buf).limit(STREAM_READ_CHUNK))
        .await
        .map_err(|e| TransportError::ReceiveFailed {
            reason: e.to_string(),
        })?;
    if n == 0 {
        return Err(TransportError::ConnectionClosed);
    }
    Ok(buf.split().freeze())
}

/// Reports that a dual-stack test cannot run on this host. Skips (returns)
/// normally; panics instead when `UC_REQUIRE_DUAL_STACK=1`, so a CI job
/// that sets it cannot pass the canonical-peer tests by skipping them.
#[cfg(test)]
pub(crate) fn skip_dual_stack(reason: &str) {
    assert!(
        std::env::var("UC_REQUIRE_DUAL_STACK").as_deref() != Ok("1"),
        "UC_REQUIRE_DUAL_STACK=1 but dual-stack test cannot run: {reason}"
    );
    eprintln!("skipping: {reason}");
}

/// Maximum SIP message size per RFC 3261.
///
/// UDP messages are limited to 1300 bytes for MTU safety,
/// but TCP/TLS can handle larger messages.
pub const MAX_UDP_MESSAGE_SIZE: usize = 1300;

/// UDP receive buffer size.
///
/// RFC 3261 §18.1.1 only caps what we SEND over UDP (the 1300-byte MTU
/// guard above); receivers must accept datagrams up to the 65,535-byte
/// UDP maximum. Peers legitimately exceed 1300 — an RFC 8898 Bearer
/// REGISTER carries a ~1.5 KB JWT — and `recv_from` into a smaller buffer
/// silently truncates the datagram, mangling the request.
pub const MAX_UDP_RECV_SIZE: usize = 65535;

/// Maximum message size for stream transports (TCP/TLS/WS).
pub const MAX_STREAM_MESSAGE_SIZE: usize = 65535;

/// Bytes read per `recv` on a TCP or TLS stream.
///
/// This is also the resident size of each connection's read buffer. Framing
/// above the transport accumulates chunks up to [`MAX_STREAM_MESSAGE_SIZE`];
/// the transport itself keeps one chunk per connection. The buffer is reused
/// only once the caller has dropped the previous chunk (see
/// [`Transport::recv`]).
///
/// ## NIST 800-53 Rev5: SC-5, SC-6
// POAM: POA&M-452 - no node-wide budget on buffered bytes; each connection
// may still hold one message (up to MAX_STREAM_MESSAGE_SIZE) in its framer,
// and a WebSocket connection up to about 2 x 64 KiB in tungstenite after a
// maximum-size message, bounded only by the connection caps.
pub const STREAM_READ_CHUNK: usize = 4096;

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
    /// Stream transports (TCP, TLS) return a view into one reused chunk
    /// buffer of [`STREAM_READ_CHUNK`] bytes. Copy or drop the returned
    /// `data` before the next `recv`: while it is alive the buffer cannot be
    /// reclaimed and each read allocates a new one.
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

    /// Returns true once [`Transport::close`] has been called. A reader
    /// parked in `recv` does not wake on close; it polls this to stop.
    fn is_closed(&self) -> bool {
        false
    }

    /// Control frames (e.g. WebSocket ping/pong) received since the last
    /// call. Transports without control frames return 0.
    // POAM: POA&M-458: not yet consumed by the daemon reader.
    fn take_control_frames(&self) -> u64 {
        0
    }
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
