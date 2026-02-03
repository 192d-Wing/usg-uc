//! SCTP transport for SIP (RFC 4168).
//!
//! This module provides SCTP (Stream Control Transmission Protocol) transport
//! for SIP messages, enabling multi-homed and multi-stream communication.
//!
//! ## RFC 4168 Compliance
//!
//! - Multi-homing for network redundancy
//! - Multiple streams for head-of-line blocking avoidance
//! - Ordered and unordered delivery modes
//! - Heartbeat for path monitoring
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (with DTLS-SCTP)
//! - **SC-23**: Session Authenticity
//!
//! ## Implementation Status
//!
//! This is currently a stub implementation. Full SCTP support requires
//! kernel-level SCTP or a userspace SCTP implementation (e.g., usrsctp).

use crate::error::{TransportError, TransportResult};
use crate::{ReceivedMessage, StreamTransport, Transport, MAX_STREAM_MESSAGE_SIZE};
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use tracing::{debug, info};
use uc_types::address::{SbcSocketAddr, TransportType};

/// SCTP association state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    /// Association not established.
    Closed,
    /// INIT sent, waiting for INIT-ACK.
    CookieWait,
    /// COOKIE-ECHO sent, waiting for COOKIE-ACK.
    CookieEchoed,
    /// Association established.
    Established,
    /// Shutdown initiated.
    ShutdownPending,
    /// SHUTDOWN sent.
    ShutdownSent,
    /// SHUTDOWN-ACK sent.
    ShutdownAckSent,
}

impl std::fmt::Display for SctpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::CookieWait => write!(f, "cookie-wait"),
            Self::CookieEchoed => write!(f, "cookie-echoed"),
            Self::Established => write!(f, "established"),
            Self::ShutdownPending => write!(f, "shutdown-pending"),
            Self::ShutdownSent => write!(f, "shutdown-sent"),
            Self::ShutdownAckSent => write!(f, "shutdown-ack-sent"),
        }
    }
}

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
        }
    }
}

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

/// SCTP association for SIP transport.
///
/// Represents an SCTP association with multi-homing and multi-stream support.
pub struct SctpAssociation {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Primary remote address.
    peer_addr: SbcSocketAddr,
    /// All remote addresses (multi-homing).
    peer_addresses: Vec<SocketAddr>,
    /// Configuration.
    config: SctpConfig,
    /// Association state.
    state: SctpState,
    /// Connected flag.
    connected: AtomicBool,
    /// Next stream sequence number.
    next_stream_seq: AtomicU16,
}

impl SctpAssociation {
    /// Creates a new SCTP association (client mode).
    ///
    /// # Note
    ///
    /// This is a stub implementation. Actual SCTP support requires
    /// platform-specific SCTP libraries.
    #[must_use]
    pub fn new(
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        config: SctpConfig,
    ) -> Self {
        Self {
            local_addr,
            peer_addr: peer_addr.clone(),
            peer_addresses: vec![peer_addr.into()],
            config,
            state: SctpState::Closed,
            connected: AtomicBool::new(false),
            next_stream_seq: AtomicU16::new(0),
        }
    }

    /// Initiates the SCTP association.
    ///
    /// # Errors
    ///
    /// Returns an error if association setup fails.
    pub async fn connect(&mut self) -> TransportResult<()> {
        // Stub: In real implementation, would send INIT chunk
        info!(
            local = %self.local_addr,
            peer = %self.peer_addr,
            "SCTP association connect (stub)"
        );

        self.state = SctpState::Established;
        self.connected.store(true, Ordering::Relaxed);

        Ok(())
    }

    /// Returns the association state.
    #[must_use]
    pub fn state(&self) -> SctpState {
        self.state
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

    /// Sends data on a specific stream.
    ///
    /// # Errors
    ///
    /// Returns an error if not connected or send fails.
    pub async fn send_on_stream(
        &self,
        _stream: StreamId,
        _data: &[u8],
        _ordered: bool,
    ) -> TransportResult<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }

        // Stub: In real implementation, would send DATA chunk
        debug!(
            stream = _stream.0,
            len = _data.len(),
            ordered = _ordered,
            "SCTP send on stream (stub)"
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

        // Stub: In real implementation, would receive DATA chunk
        // For now, just wait indefinitely (pending)
        std::future::pending().await
    }

    /// Gracefully shuts down the association.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&mut self) -> TransportResult<()> {
        self.state = SctpState::ShutdownPending;
        self.connected.store(false, Ordering::Relaxed);

        // Stub: In real implementation, would send SHUTDOWN chunk
        info!(peer = %self.peer_addr, "SCTP association shutdown (stub)");

        self.state = SctpState::Closed;
        Ok(())
    }

    /// Aborts the association immediately.
    pub fn abort(&mut self) {
        self.state = SctpState::Closed;
        self.connected.store(false, Ordering::Relaxed);
        info!(peer = %self.peer_addr, "SCTP association aborted");
    }
}

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
            // Can't mutate self in this context, just mark as disconnected
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        })
    }
}

impl StreamTransport for SctpAssociation {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SctpAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctpAssociation")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("state", &self.state)
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .field("outbound_streams", &self.config.outbound_streams)
            .finish_non_exhaustive()
    }
}

/// SCTP listener for accepting incoming associations.
///
/// # Note
///
/// This is a stub implementation.
pub struct SctpListener {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Configuration.
    config: SctpConfig,
}

impl SctpListener {
    /// Creates a new SCTP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    pub async fn bind(addr: &SbcSocketAddr, config: SctpConfig) -> TransportResult<Self> {
        info!(addr = %addr, "SCTP listener bind (stub)");

        Ok(Self {
            local_addr: addr.clone(),
            config,
        })
    }

    /// Accepts the next SCTP association.
    ///
    /// # Errors
    ///
    /// Returns an error if accept fails.
    pub async fn accept(&self) -> TransportResult<SctpAssociation> {
        // Stub: In real implementation, would wait for INIT from peer
        // For now, just wait indefinitely
        std::future::pending().await
    }

    /// Returns the local address.
    #[must_use]
    pub fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }
}

impl std::fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctpListener")
            .field("local_addr", &self.local_addr)
            .field("outbound_streams", &self.config.outbound_streams)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_state_display() {
        assert_eq!(SctpState::Closed.to_string(), "closed");
        assert_eq!(SctpState::Established.to_string(), "established");
    }

    #[test]
    fn test_sctp_config_default() {
        let config = SctpConfig::default();
        assert_eq!(config.outbound_streams, 10);
        assert_eq!(config.max_inbound_streams, 10);
        assert!(config.ordered_delivery);
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

        assert_eq!(assoc.state(), SctpState::Closed);
        assert_eq!(assoc.primary_path(), &peer);
        assert!(!assoc.is_connected());
    }

    #[tokio::test]
    async fn test_sctp_association_connect() {
        let config = SctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:5060".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = SctpAssociation::new(local, peer, config);
        assoc.connect().await.unwrap();

        assert_eq!(assoc.state(), SctpState::Established);
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
}
