//! SCTP protocol implementation (RFC 9260).
//!
//! This module provides a pure Rust, async-first implementation of the
//! Stream Control Transmission Protocol for SIP signaling (RFC 4168).
//!
//! ## Features
//!
//! - Full RFC 9260 compliance
//! - UDP encapsulation for NAT traversal (RFC 6951)
//! - Multi-homing with automatic failover
//! - Multi-stream support (stream 0 reserved for SIP signaling)
//! - Ordered and unordered delivery modes
//! - Congestion control per RFC 9260 Section 7
//! - SCTP-AUTH for authenticated chunks (RFC 4895)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality (DTLS-SCTP)
//! - **SC-12**: SCTP-AUTH with SHA-384 HMAC
//! - **SC-13**: AES-256-GCM for cookie encryption
//! - **SC-23**: Association state tracking

pub mod association;
pub mod chunk;
pub mod congestion;
pub mod connected;
pub mod cookie;
pub mod listener;
pub mod packet;
pub mod path;
pub mod state;
pub mod stream;
pub mod timer;
pub mod udp_encap;

pub use association::{AssociationConfig, AssociationHandle, AssociationInner};
pub use chunk::{
    AbortChunk, AuthChunk, Chunk, ChunkType, CookieAckChunk, CookieEchoChunk, CwrChunk, DataChunk,
    EcneChunk, ErrorCause, ErrorChunk, GapAckBlock, HeartbeatAckChunk, HeartbeatChunk, HmacId,
    InitAckChunk, InitChunk, InitParam, PadChunk, SackChunk, ShutdownAckChunk, ShutdownChunk,
    ShutdownCompleteChunk, UnknownChunk, UnknownChunkAction,
};
pub use congestion::CongestionController;
pub use connected::{ConnectedSctpAssociation, ConnectedSctpConfig};
pub use cookie::{CookieData, CookieError, CookieGenerator, DEFAULT_COOKIE_LIFETIME};
pub use listener::{SctpListener, SctpListenerConfig};
pub use packet::{HEADER_SIZE, MAX_PACKET_SIZE, SctpPacket};
pub use path::{Path, PathId, PathManager, PathState};
pub use state::{AssociationState, StateAction, StateEvent, StateMachine};
pub use stream::{Stream, StreamError, StreamManager};
pub use timer::{RtoCalculator, Timer, TimerManager, TimerType};
pub use udp_encap::{
    EncapsulatedPacket, SCTP_UDP_PORT, UDP_HEADER_SIZE, UdpEncapConfig, UdpEncapError, UdpHeader,
    decapsulate, encapsulate,
};

use crate::error::{TransportError, TransportResult};
use crate::{MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, StreamTransport, Transport};
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use tracing::{debug, info};
use uc_types::address::{SbcSocketAddr, TransportType};

// =============================================================================
// SCTP Configuration
// =============================================================================

/// SCTP configuration.
#[derive(Debug, Clone)]
pub struct SctpConfig {
    /// Number of outbound streams.
    pub outbound_streams: u16,
    /// Maximum inbound streams.
    pub max_inbound_streams: u16,
    /// Maximum number of retransmissions.
    pub max_retransmissions: u16,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u32,
    /// RTO initial value in milliseconds.
    pub rto_initial_ms: u32,
    /// RTO minimum in milliseconds.
    pub rto_min_ms: u32,
    /// RTO maximum in milliseconds.
    pub rto_max_ms: u32,
    /// Maximum burst size.
    pub max_burst: u32,
    /// Path MTU.
    pub path_mtu: u16,
    /// Enable ordered delivery.
    pub ordered_delivery: bool,
    /// Local addresses for multi-homing.
    pub local_addresses: Vec<SocketAddr>,
    /// Advertised receiver window credit.
    pub a_rwnd: u32,
}

impl Default for SctpConfig {
    fn default() -> Self {
        Self {
            outbound_streams: 10,
            max_inbound_streams: 10,
            max_retransmissions: 10,
            heartbeat_interval_ms: 30_000,
            rto_initial_ms: 3000,
            rto_min_ms: 1000,
            rto_max_ms: 60_000,
            max_burst: 4,
            path_mtu: 1280,
            ordered_delivery: true,
            local_addresses: Vec::new(),
            a_rwnd: 65535,
        }
    }
}

// =============================================================================
// Stream Identifier
// =============================================================================

/// SCTP stream identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u16);

impl StreamId {
    /// SIP signaling stream (stream 0).
    pub const SIP_SIGNALING: Self = Self(0);

    /// Creates a new stream ID.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
}

// =============================================================================
// SCTP Association (Deprecated Stub)
// =============================================================================

/// SCTP association for SIP transport.
///
/// # Deprecated
///
/// This is a stub implementation without real network I/O.
/// Use [`ConnectedSctpAssociation`] instead for production use.
///
/// ```rust,ignore
/// use uc_transport::sctp::{ConnectedSctpAssociation, ConnectedSctpConfig};
///
/// let config = ConnectedSctpConfig::default();
/// let mut assoc = ConnectedSctpAssociation::new(local_addr, peer_addr, config).await?;
/// assoc.connect().await?;
/// ```
#[deprecated(
    since = "0.2.0",
    note = "Use ConnectedSctpAssociation for real network I/O"
)]
#[allow(deprecated)]
pub struct SctpAssociation {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Primary remote address.
    peer_addr: SbcSocketAddr,
    /// All remote addresses (multi-homing).
    peer_addresses: Vec<SocketAddr>,
    /// Configuration.
    config: SctpConfig,
    /// State machine.
    state_machine: StateMachine,
    /// Connected flag.
    connected: AtomicBool,
    /// Next stream sequence number.
    next_stream_seq: AtomicU16,
    /// Local verification tag.
    local_verification_tag: u32,
    /// Peer verification tag.
    peer_verification_tag: u32,
    /// Local initial TSN.
    local_tsn: u32,
}

#[allow(deprecated)]
impl SctpAssociation {
    /// Creates a new SCTP association (client mode).
    #[must_use]
    pub fn new(local_addr: SbcSocketAddr, peer_addr: SbcSocketAddr, config: SctpConfig) -> Self {
        // Generate random verification tag and initial TSN
        let local_verification_tag = rand_verification_tag();
        let local_tsn = rand_initial_tsn();

        Self {
            local_addr,
            peer_addr: peer_addr.clone(),
            peer_addresses: vec![peer_addr.into()],
            config,
            state_machine: StateMachine::new(),
            connected: AtomicBool::new(false),
            next_stream_seq: AtomicU16::new(0),
            local_verification_tag,
            peer_verification_tag: 0,
            local_tsn,
        }
    }

    /// Initiates the SCTP association.
    ///
    /// This sends an INIT chunk and transitions through the 4-way handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if association setup fails.
    pub async fn connect(&mut self) -> TransportResult<()> {
        // Process the Associate event to start the handshake
        let actions = self.state_machine.process_event(StateEvent::Associate);

        info!(
            local = %self.local_addr,
            peer = %self.peer_addr,
            actions = ?actions,
            "SCTP association initiating"
        );

        // TODO: Actually send INIT and process responses
        // For now, simulate successful connection
        self.state_machine.process_event(StateEvent::ReceiveInitAck);
        self.state_machine
            .process_event(StateEvent::ReceiveCookieAck);

        self.connected.store(true, Ordering::Relaxed);

        Ok(())
    }

    /// Returns the association state.
    #[must_use]
    pub fn state(&self) -> AssociationState {
        self.state_machine.state()
    }

    /// Returns the primary path address.
    #[must_use]
    pub fn primary_path(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    /// Returns all peer addresses.
    #[must_use]
    pub fn peer_addresses(&self) -> &[SocketAddr] {
        &self.peer_addresses
    }

    /// Adds a peer address for multi-homing.
    pub fn add_peer_address(&mut self, addr: SocketAddr) {
        if !self.peer_addresses.contains(&addr) {
            self.peer_addresses.push(addr);
            debug!(addr = %addr, "Added SCTP peer address");
        }
    }

    /// Sets the primary path.
    pub fn set_primary_path(&mut self, addr: SocketAddr) {
        self.peer_addr = SbcSocketAddr::from(addr);
        debug!(addr = %addr, "Set SCTP primary path");
    }

    /// Returns the next stream ID for sending.
    #[must_use]
    pub fn next_stream(&self) -> StreamId {
        let seq = self.next_stream_seq.fetch_add(1, Ordering::Relaxed);
        StreamId(seq % self.config.outbound_streams)
    }

    /// Returns the local verification tag.
    #[must_use]
    pub const fn local_verification_tag(&self) -> u32 {
        self.local_verification_tag
    }

    /// Returns the peer verification tag.
    #[must_use]
    pub const fn peer_verification_tag(&self) -> u32 {
        self.peer_verification_tag
    }

    /// Sends data on a specific stream.
    ///
    /// # Errors
    ///
    /// Returns an error if not connected or send fails.
    pub async fn send_on_stream(
        &self,
        stream: StreamId,
        data: &[u8],
        ordered: bool,
    ) -> TransportResult<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }

        // Create DATA chunk
        let _data_chunk = DataChunk::new(
            self.local_tsn,
            stream.0,
            0, // SSN - should be tracked per stream
            0, // PPID
            Bytes::copy_from_slice(data),
        )
        .with_unordered(!ordered);

        // TODO: Actually encode and send the packet
        debug!(
            stream = stream.0,
            len = data.len(),
            ordered = ordered,
            "SCTP send on stream"
        );

        Ok(())
    }

    /// Receives data from any stream.
    ///
    /// # Errors
    ///
    /// Returns an error if not connected or receive fails.
    pub async fn recv_from_stream(&self) -> TransportResult<(StreamId, Bytes)> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }

        // TODO: Actually receive from UDP socket and decode
        // For now, just wait indefinitely (pending)
        std::future::pending().await
    }

    /// Gracefully shuts down the association.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&mut self) -> TransportResult<()> {
        let actions = self.state_machine.process_event(StateEvent::Shutdown);

        info!(
            peer = %self.peer_addr,
            actions = ?actions,
            "SCTP association shutdown initiated"
        );

        // Simulate all data acked and shutdown completion
        self.state_machine.process_event(StateEvent::AllDataAcked);
        self.state_machine
            .process_event(StateEvent::ReceiveShutdownAck);

        self.connected.store(false, Ordering::Relaxed);

        Ok(())
    }

    /// Aborts the association immediately.
    pub fn abort(&mut self) {
        let actions = self.state_machine.process_event(StateEvent::Abort);
        self.connected.store(false, Ordering::Relaxed);

        info!(
            peer = %self.peer_addr,
            actions = ?actions,
            "SCTP association aborted"
        );
    }
}

#[allow(deprecated)]
impl Transport for SctpAssociation {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
        _dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if data.len() > MAX_STREAM_MESSAGE_SIZE {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_STREAM_MESSAGE_SIZE,
                });
            }

            // Use stream 0 for SIP signaling by default
            self.send_on_stream(StreamId::SIP_SIGNALING, data, self.config.ordered_delivery)
                .await
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            let (_stream, data) = self.recv_from_stream().await?;

            Ok(ReceivedMessage {
                data,
                source: self.peer_addr.clone(),
                transport: TransportType::Sctp,
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Sctp
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        })
    }
}

#[allow(deprecated)]
impl StreamTransport for SctpAssociation {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

#[allow(deprecated)]
impl std::fmt::Debug for SctpAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctpAssociation")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("state", &self.state())
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .field("outbound_streams", &self.config.outbound_streams)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a cryptographically secure random verification tag.
///
/// Uses the `rand` crate with OS-provided entropy.
fn rand_verification_tag() -> u32 {
    use rand::RngCore;
    rand::rng().next_u32()
}

/// Generates a cryptographically secure random initial TSN.
///
/// Uses the `rand` crate with OS-provided entropy.
fn rand_initial_tsn() -> u32 {
    use rand::RngCore;
    rand::rng().next_u32()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(deprecated, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_config_default() {
        let config = SctpConfig::default();
        assert_eq!(config.outbound_streams, 10);
        assert_eq!(config.max_inbound_streams, 10);
        assert!(config.ordered_delivery);
        assert_eq!(config.a_rwnd, 65535);
    }

    #[test]
    fn test_stream_id() {
        assert_eq!(StreamId::SIP_SIGNALING.0, 0);
        assert_eq!(StreamId::new(5).0, 5);
    }

    #[test]
    fn test_sctp_association_creation() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let assoc = SctpAssociation::new(local, peer.clone(), config);

        assert_eq!(assoc.state(), AssociationState::Closed);
        assert_eq!(assoc.primary_path(), &peer);
        assert!(!assoc.is_connected());
        assert_ne!(assoc.local_verification_tag(), 0);
    }

    #[tokio::test]
    async fn test_sctp_association_connect() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = SctpAssociation::new(local, peer, config);
        assoc.connect().await.unwrap();

        assert_eq!(assoc.state(), AssociationState::Established);
        assert!(assoc.is_connected());
    }

    #[test]
    fn test_sctp_multi_homing() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = SctpAssociation::new(local, peer, config);

        let secondary: SocketAddr = "192.168.1.1:5061".parse().unwrap();
        assoc.add_peer_address(secondary);

        assert_eq!(assoc.peer_addresses().len(), 2);
    }

    #[tokio::test]
    async fn test_sctp_association_shutdown() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = SctpAssociation::new(local, peer, config);
        assoc.connect().await.unwrap();

        assoc.shutdown().await.unwrap();

        assert_eq!(assoc.state(), AssociationState::Closed);
        assert!(!assoc.is_connected());
    }

    #[test]
    fn test_sctp_association_abort() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = SctpAssociation::new(local, peer, config);
        // Manually set connected for this test
        assoc.connected.store(true, Ordering::Relaxed);

        assoc.abort();

        assert_eq!(assoc.state(), AssociationState::Closed);
        assert!(!assoc.is_connected());
    }
}
