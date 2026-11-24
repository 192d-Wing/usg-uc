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

/// Returns true when an `accept()` error is a process- or system-wide
/// resource exhaustion (EMFILE, ENFILE, ENOBUFS, ENOMEM, or
/// [`std::io::ErrorKind::OutOfMemory`]).
///
/// Only these call for an accept-loop back-off: accepting again at once
/// would fail the same way. Any other accept error concerns one pending
/// connection (for example ECONNABORTED or EPROTO) and the loop should
/// continue immediately.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[must_use]
pub fn is_accept_resource_exhaustion(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::OutOfMemory {
        return true;
    }
    let Some(code) = err.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        matches!(
            Errno::from_raw(code),
            Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM
        )
    }
    #[cfg(windows)]
    {
        // WSAEMFILE, WSAENOBUFS.
        matches!(code, 10024 | 10055)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Returns true when an `accept()` error concerns one pending connection.
///
/// For example the peer aborted or reset, a protocol or network error on
/// that connection, a firewall refusal, an interrupted or would-block call.
/// Such errors say nothing about the listener: the accept loop continues
/// at once and they never count toward a persistent-error back-off.
/// Listener-level errors (EBADF, EINVAL, ENOTSOCK, EOPNOTSUPP, EFAULT) and
/// unknown errors return false.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[must_use]
pub fn is_accept_per_connection_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        err.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
    ) {
        return true;
    }
    let Some(code) = err.raw_os_error() else {
        return false;
    };
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        // accept(2): errors the kernel reports for the connection being
        // accepted, not for the listening socket.
        matches!(
            Errno::from_raw(code),
            Errno::ECONNABORTED
                | Errno::ECONNRESET
                | Errno::EPROTO
                | Errno::EPERM
                | Errno::EINTR
                | Errno::EAGAIN
                | Errno::ETIMEDOUT
                | Errno::ENETDOWN
                | Errno::ENETUNREACH
                | Errno::EHOSTDOWN
                | Errno::EHOSTUNREACH
                | Errno::ENOPROTOOPT
        )
    }
    #[cfg(windows)]
    {
        // WSAECONNABORTED, WSAECONNRESET, WSAEINTR, WSAEWOULDBLOCK,
        // WSAENETDOWN, WSAETIMEDOUT.
        matches!(code, 10053 | 10054 | 10004 | 10035 | 10050 | 10060)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Maps a listener `accept()` error to [`TransportError::AcceptFailed`],
/// keeping the resource-exhaustion and per-connection classes.
#[cfg(any(feature = "tcp", feature = "tls", feature = "websocket"))]
pub(crate) fn accept_error(err: &std::io::Error) -> TransportError {
    let resource_exhausted = is_accept_resource_exhaustion(err);
    TransportError::AcceptFailed {
        reason: err.to_string(),
        resource_exhausted,
        per_connection: !resource_exhausted && is_accept_per_connection_error(err),
    }
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

    /// Returns true once [`Transport::close`] has been called. A reader
    /// parked in `recv` does not wake on close; it polls this to stop.
    fn is_closed(&self) -> bool {
        false
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

/// SR-22 tests for the accept-error classifier
/// (`is_accept_resource_exhaustion`, `is_accept_per_connection_error`).
#[cfg(all(test, unix))]
mod sr22_accept_classifier_tests {
    use super::{is_accept_per_connection_error, is_accept_resource_exhaustion};
    use nix::errno::Errno;
    use std::io::Error;

    // NIST 800-53 Rev5: SC-5
    // Only process- or system-wide resource errors back off; a failure tied
    // to one connection lets the accept loop continue at once.
    #[test]
    fn accept_error_classification() {
        for errno in [Errno::EMFILE, Errno::ENFILE, Errno::ENOBUFS, Errno::ENOMEM] {
            let err = Error::from_raw_os_error(errno as i32);
            assert!(
                is_accept_resource_exhaustion(&err),
                "{errno:?} must back off"
            );
        }
        for errno in [
            Errno::ECONNABORTED,
            Errno::ENOTCONN,
            Errno::EPROTO,
            Errno::EPERM,
            Errno::ECONNRESET,
            Errno::EINTR,
            Errno::EAGAIN,
            Errno::EINVAL,
        ] {
            let err = Error::from_raw_os_error(errno as i32);
            assert!(
                !is_accept_resource_exhaustion(&err),
                "{errno:?} must not back off"
            );
        }
        assert!(is_accept_resource_exhaustion(&Error::from(
            std::io::ErrorKind::OutOfMemory
        )));
        assert!(!is_accept_resource_exhaustion(&Error::other("custom")));
    }

    // NIST 800-53 Rev5: SC-5
    // SEC-009: only errors about the pending connection are per-connection;
    // listener-level and unknown errors count toward the persistent-error
    // back-off.
    #[test]
    fn accept_error_per_connection_classification() {
        for errno in [
            Errno::ECONNABORTED,
            Errno::ECONNRESET,
            Errno::EPROTO,
            Errno::EPERM,
            Errno::EINTR,
            Errno::EAGAIN,
            Errno::ETIMEDOUT,
            Errno::ENETUNREACH,
            Errno::EHOSTUNREACH,
        ] {
            let err = Error::from_raw_os_error(errno as i32);
            assert!(
                is_accept_per_connection_error(&err),
                "{errno:?} is per-connection"
            );
        }
        for errno in [
            Errno::EBADF,
            Errno::EINVAL,
            Errno::ENOTSOCK,
            Errno::EOPNOTSUPP,
            Errno::EFAULT,
            Errno::EMFILE,
        ] {
            let err = Error::from_raw_os_error(errno as i32);
            assert!(
                !is_accept_per_connection_error(&err),
                "{errno:?} is listener-level"
            );
        }
        assert!(!is_accept_per_connection_error(&Error::other("custom")));
    }

    // SEC-009: the mapped error carries both classes.
    #[cfg(feature = "tcp")]
    #[test]
    fn accept_error_maps_classes() {
        let per_conn = super::accept_error(&Error::from_raw_os_error(Errno::ECONNABORTED as i32));
        assert!(per_conn.is_per_connection_accept_error());
        assert!(!per_conn.is_resource_exhausted());
        let listener = super::accept_error(&Error::from_raw_os_error(Errno::EBADF as i32));
        assert!(!listener.is_per_connection_accept_error());
        assert!(!listener.is_resource_exhausted());
        let exhausted = super::accept_error(&Error::from_raw_os_error(Errno::EMFILE as i32));
        assert!(!exhausted.is_per_connection_accept_error());
        assert!(exhausted.is_resource_exhausted());
    }
}
