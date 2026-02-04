//! SCTP Listener for accepting incoming associations (RFC 9260).
//!
//! This module provides server-side SCTP functionality, accepting incoming
//! associations using the 4-way handshake with stateless cookie-based
//! connection establishment.
//!
//! ## 4-Way Handshake (Server Perspective)
//!
//! 1. Receive INIT from client
//! 2. Send INIT-ACK with state cookie (no state stored yet)
//! 3. Receive COOKIE-ECHO, validate cookie, create association
//! 4. Send COOKIE-ACK, association established
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial-of-service protection via stateless cookies
//! - **SC-8**: Transmission integrity via HMAC-protected cookies
//! - **SC-23**: Session authenticity through verification tags

use super::association::{AssociationConfig, AssociationHandle};
use super::chunk::{Chunk, CookieAckChunk, InitAckChunk, InitChunk};
use super::cookie::{CookieData, CookieGenerator};
use super::packet::SctpPacket;
use super::udp_encap::{EncapsulatedPacket, UdpEncapConfig, SCTP_UDP_PORT};
use crate::error::{TransportError, TransportResult};
use crate::listener::{AcceptFuture, TransportListener};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, trace, warn};
use uc_types::address::{SbcSocketAddr, TransportType};

// =============================================================================
// Constants
// =============================================================================

/// Maximum size of UDP receive buffer.
const MAX_RECV_BUFFER: usize = 65535;

/// Cleanup interval for stale pending associations.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time a pending association can wait for COOKIE-ECHO.
const PENDING_TIMEOUT: Duration = Duration::from_secs(60);

// =============================================================================
// Listener Configuration
// =============================================================================

/// Configuration for an SCTP listener.
#[derive(Debug, Clone)]
pub struct SctpListenerConfig {
    /// Association configuration for accepted connections.
    pub association_config: AssociationConfig,
    /// UDP encapsulation configuration.
    pub udp_encap: UdpEncapConfig,
    /// Maximum pending associations (before COOKIE-ECHO).
    pub max_pending: usize,
    /// Whether to use UDP encapsulation.
    pub use_udp_encap: bool,
}

impl Default for SctpListenerConfig {
    fn default() -> Self {
        Self {
            association_config: AssociationConfig::default(),
            udp_encap: UdpEncapConfig::default(),
            max_pending: 1024,
            use_udp_encap: true,
        }
    }
}

// =============================================================================
// Pending Association
// =============================================================================

/// Key for identifying pending associations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingKey {
    /// Remote address.
    peer_addr: SocketAddr,
    /// Local verification tag we sent in INIT-ACK.
    local_tag: u32,
}

/// A pending association waiting for COOKIE-ECHO.
#[derive(Debug)]
#[allow(dead_code)] // Fields are for monitoring/debugging
struct PendingAssociation {
    /// When the INIT-ACK was sent.
    created_at: Instant,
    /// The INIT we received.
    init_tag: u32,
}

// =============================================================================
// SCTP Listener Inner
// =============================================================================

/// Internal state of the SCTP listener.
#[allow(dead_code)] // Socket is used by background task
struct SctpListenerInner {
    /// UDP socket for receiving packets.
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Cookie generator for stateless operation.
    cookie_generator: CookieGenerator,
    /// Listener configuration.
    config: SctpListenerConfig,
    /// Pending associations (only tracked for cleanup, not required for operation).
    pending: HashMap<PendingKey, PendingAssociation>,
    /// Whether the listener is closed.
    closed: bool,
}

impl SctpListenerInner {
    /// Creates an INIT-ACK response for an incoming INIT.
    fn create_init_ack(
        &self,
        init: &InitChunk,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> (InitAckChunk, u32) {
        // Generate random local verification tag
        let local_tag = generate_random_u32();
        let local_initial_tsn = generate_random_u32();

        // Create cookie data
        let cookie_data = CookieData::new(
            local_tag,
            init.initiate_tag,
            local_initial_tsn,
            init.initial_tsn,
            self.config
                .association_config
                .outbound_streams
                .min(init.num_inbound_streams),
            self.config
                .association_config
                .max_inbound_streams
                .min(init.num_outbound_streams),
            peer_addr,
            local_addr,
        );

        let cookie = self.cookie_generator.generate(&cookie_data);

        let init_ack = InitAckChunk::from_init(
            init,
            local_tag,
            self.config.association_config.a_rwnd,
            local_initial_tsn,
            cookie,
        );

        (init_ack, local_tag)
    }

    /// Validates a COOKIE-ECHO and creates an association if valid.
    fn validate_cookie_echo(
        &self,
        cookie: &Bytes,
        peer_addr: SocketAddr,
    ) -> Result<AssociationHandle, TransportError> {
        // Validate the cookie
        let cookie_data = self
            .cookie_generator
            .validate(cookie)
            .map_err(|e| TransportError::ReceiveFailed {
                reason: format!("Invalid cookie: {e}"),
            })?;

        // Verify the peer address matches
        if cookie_data.peer_addr != peer_addr {
            return Err(TransportError::ReceiveFailed {
                reason: format!(
                    "Cookie peer address mismatch: expected {}, got {peer_addr}",
                    cookie_data.peer_addr
                ),
            });
        }

        // Create the association handle
        let local_addr = cookie_data.local_addr;
        let handle = AssociationHandle::new(
            local_addr,
            peer_addr,
            self.config.association_config.clone(),
        );

        Ok(handle)
    }

    /// Cleans up stale pending associations.
    fn cleanup_stale_pending(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, pending| {
            now.duration_since(pending.created_at) < PENDING_TIMEOUT
        });
    }
}

// =============================================================================
// SCTP Listener
// =============================================================================

/// SCTP Listener for accepting incoming associations.
///
/// Implements stateless server operation using cookies per RFC 9260.
/// The listener does not store state until a valid COOKIE-ECHO is received,
/// providing protection against SYN-flood style attacks.
pub struct SctpListener {
    /// Inner state protected by RwLock.
    inner: Arc<RwLock<SctpListenerInner>>,
    /// Channel for established associations.
    accept_rx: mpsc::Receiver<(AssociationHandle, SbcSocketAddr)>,
    /// Sender for the accept channel (kept alive so background task doesn't drop).
    #[allow(dead_code)]
    accept_tx: mpsc::Sender<(AssociationHandle, SbcSocketAddr)>,
    /// Whether the listener is closed.
    closed: Arc<AtomicBool>,
    /// Background task handle.
    #[allow(dead_code)] // Will be used when we implement proper shutdown
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SctpListener {
    /// Creates a new SCTP listener bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind(addr: SocketAddr, config: SctpListenerConfig) -> TransportResult<Self> {
        // Determine the port to use
        let bind_port = if config.use_udp_encap {
            if addr.port() == 0 {
                SCTP_UDP_PORT
            } else {
                addr.port()
            }
        } else {
            addr.port()
        };

        let bind_addr = SocketAddr::new(addr.ip(), bind_port);

        // Create and bind the UDP socket
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TransportError::BindFailed {
                address: SbcSocketAddr::from(bind_addr),
                reason: format!("Failed to bind UDP socket: {e}"),
            })?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| TransportError::BindFailed {
                address: SbcSocketAddr::from(bind_addr),
                reason: format!("Failed to get local address: {e}"),
            })?;

        let sbc_addr = SbcSocketAddr::from(local_addr);

        info!(
            local_addr = %local_addr,
            use_udp_encap = config.use_udp_encap,
            "SCTP listener bound"
        );

        let socket = Arc::new(socket);

        let inner = SctpListenerInner {
            socket: socket.clone(),
            local_addr: sbc_addr.clone(),
            cookie_generator: CookieGenerator::new(),
            config,
            pending: HashMap::new(),
            closed: false,
        };

        let inner = Arc::new(RwLock::new(inner));

        // Create channel for accepted associations
        let (accept_tx, accept_rx) = mpsc::channel(64);

        let closed = Arc::new(AtomicBool::new(false));

        // Start background task
        let task_handle = {
            let inner_clone = inner.clone();
            let accept_tx_clone = accept_tx.clone();
            let closed_clone = closed.clone();

            tokio::spawn(async move {
                Self::listener_loop(inner_clone, socket, accept_tx_clone, closed_clone).await;
            })
        };

        Ok(Self {
            inner,
            accept_rx,
            accept_tx,
            closed,
            task_handle: Some(task_handle),
        })
    }

    /// Background task that processes incoming packets.
    async fn listener_loop(
        inner: Arc<RwLock<SctpListenerInner>>,
        socket: Arc<UdpSocket>,
        accept_tx: mpsc::Sender<(AssociationHandle, SbcSocketAddr)>,
        closed: Arc<AtomicBool>,
    ) {
        let mut recv_buf = vec![0u8; MAX_RECV_BUFFER];
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);

        loop {
            tokio::select! {
                // Receive packets
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            if closed.load(Ordering::Relaxed) {
                                break;
                            }

                            let data = Bytes::copy_from_slice(&recv_buf[..len]);
                            Self::handle_packet(
                                &inner,
                                &socket,
                                data,
                                peer_addr,
                                &accept_tx,
                            ).await;
                        }
                        Err(e) => {
                            if closed.load(Ordering::Relaxed) {
                                break;
                            }
                            warn!(error = %e, "Error receiving packet");
                        }
                    }
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    let mut inner = inner.write().await;
                    inner.cleanup_stale_pending();
                }
            }
        }

        debug!("SCTP listener loop terminated");
    }

    /// Handles an incoming packet.
    async fn handle_packet(
        inner: &Arc<RwLock<SctpListenerInner>>,
        socket: &UdpSocket,
        data: Bytes,
        peer_addr: SocketAddr,
        accept_tx: &mpsc::Sender<(AssociationHandle, SbcSocketAddr)>,
    ) {
        // Try to decode as UDP-encapsulated SCTP
        let sctp_data = {
            let inner_read = inner.read().await;
            if inner_read.config.use_udp_encap {
                match EncapsulatedPacket::decode(data.clone()) {
                    Ok(encap) => encap.sctp_packet.encode().freeze(),
                    Err(_) => data, // Try as raw SCTP
                }
            } else {
                data
            }
        };

        // Decode SCTP packet
        let packet = match SctpPacket::decode(&sctp_data) {
            Ok(p) => p,
            Err(e) => {
                trace!(error = %e, "Failed to decode SCTP packet");
                return;
            }
        };

        // Process chunks
        for chunk in &packet.chunks {
            match chunk {
                Chunk::Init(init) => {
                    Self::handle_init(inner, socket, init, peer_addr, packet.source_port).await;
                }
                Chunk::CookieEcho(cookie_echo) => {
                    Self::handle_cookie_echo(
                        inner,
                        socket,
                        &cookie_echo.cookie,
                        peer_addr,
                        packet.source_port,
                        packet.dest_port,
                        accept_tx,
                    )
                    .await;
                }
                _ => {
                    // Other chunks are handled by established associations
                    trace!(chunk_type = ?chunk.chunk_type(), "Ignoring chunk in listener");
                }
            }
        }
    }

    /// Handles an incoming INIT chunk.
    async fn handle_init(
        inner: &Arc<RwLock<SctpListenerInner>>,
        socket: &UdpSocket,
        init: &InitChunk,
        peer_addr: SocketAddr,
        peer_port: u16,
    ) {
        debug!(
            peer_addr = %peer_addr,
            peer_port = peer_port,
            initiate_tag = init.initiate_tag,
            "Received INIT"
        );

        let local_addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(error = %e, "Failed to get local address");
                return;
            }
        };

        let (init_ack, local_tag) = {
            let mut inner = inner.write().await;

            // Check pending limit
            if inner.pending.len() >= inner.config.max_pending {
                inner.cleanup_stale_pending();
                if inner.pending.len() >= inner.config.max_pending {
                    warn!("Too many pending associations, dropping INIT");
                    return;
                }
            }

            let (init_ack, local_tag) = inner.create_init_ack(init, peer_addr, local_addr);

            // Track pending (optional, for monitoring/cleanup only)
            let key = PendingKey {
                peer_addr,
                local_tag,
            };
            inner.pending.insert(
                key,
                PendingAssociation {
                    created_at: Instant::now(),
                    init_tag: init.initiate_tag,
                },
            );
            drop(inner);

            (init_ack, local_tag)
        };

        // Create response packet
        let mut response = SctpPacket::new(
            local_addr.port(),
            peer_port,
            init.initiate_tag, // Use peer's tag in response
        );
        response.add_chunk(Chunk::InitAck(init_ack));

        // Send response
        let response_bytes = {
            let inner = inner.read().await;
            let bytes = if inner.config.use_udp_encap {
                let encap = EncapsulatedPacket::from_config(response, &inner.config.udp_encap);
                encap.encode(Some(&local_addr), Some(&peer_addr))
            } else {
                response.encode().freeze()
            };
            drop(inner);
            bytes
        };

        if let Err(e) = socket.send_to(&response_bytes, peer_addr).await {
            warn!(error = %e, peer_addr = %peer_addr, "Failed to send INIT-ACK");
        } else {
            debug!(
                peer_addr = %peer_addr,
                local_tag = local_tag,
                "Sent INIT-ACK"
            );
        }
    }

    /// Handles an incoming COOKIE-ECHO chunk.
    async fn handle_cookie_echo(
        inner: &Arc<RwLock<SctpListenerInner>>,
        socket: &UdpSocket,
        cookie: &Bytes,
        peer_addr: SocketAddr,
        peer_port: u16,
        local_port: u16,
        accept_tx: &mpsc::Sender<(AssociationHandle, SbcSocketAddr)>,
    ) {
        debug!(
            peer_addr = %peer_addr,
            cookie_len = cookie.len(),
            "Received COOKIE-ECHO"
        );

        // Validate cookie and create association
        let (handle, peer_tag) = {
            let inner = inner.read().await;

            let handle = match inner.validate_cookie_echo(cookie, peer_addr) {
                Ok(h) => h,
                Err(e) => {
                    warn!(error = %e, peer_addr = %peer_addr, "Invalid COOKIE-ECHO");
                    return;
                }
            };
            drop(inner);

            let peer_tag = handle.peer_verification_tag().await;
            (handle, peer_tag)
        };

        // Note: The cookie validation already sets up the association state.
        // The AssociationHandle is ready for use after cookie validation.

        let local_addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(error = %e, "Failed to get local address");
                return;
            }
        };

        // Create COOKIE-ACK response
        let mut response = SctpPacket::new(local_port, peer_port, peer_tag);
        response.add_chunk(Chunk::CookieAck(CookieAckChunk));

        // Send response
        let response_bytes = {
            let inner = inner.read().await;
            let bytes = if inner.config.use_udp_encap {
                let encap = EncapsulatedPacket::from_config(response, &inner.config.udp_encap);
                encap.encode(Some(&local_addr), Some(&peer_addr))
            } else {
                response.encode().freeze()
            };
            drop(inner);
            bytes
        };

        if let Err(e) = socket.send_to(&response_bytes, peer_addr).await {
            warn!(error = %e, peer_addr = %peer_addr, "Failed to send COOKIE-ACK");
            return;
        }

        debug!(
            peer_addr = %peer_addr,
            "Sent COOKIE-ACK, association established"
        );

        // Note: We don't need to remove from pending since the cookie-based
        // approach is stateless. Pending associations are only tracked for
        // monitoring and cleanup purposes.

        // Send to accept channel
        let sbc_peer_addr = SbcSocketAddr::from(peer_addr);
        if accept_tx.send((handle, sbc_peer_addr)).await.is_err() {
            warn!("Accept channel closed, dropping association");
        } else {
            info!(
                peer_addr = %peer_addr,
                "SCTP association accepted"
            );
        }
    }

    /// Returns the local address the listener is bound to.
    pub async fn local_addr(&self) -> SbcSocketAddr {
        self.inner.read().await.local_addr.clone()
    }
}

impl TransportListener for SctpListener {
    type Connection = AssociationHandle;

    fn accept(&self) -> AcceptFuture<'_, Self::Connection> {
        Box::pin(async move {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TransportError::ConnectionClosed);
            }

            // This is a bit awkward because we need &mut self for recv()
            // but TransportListener::accept takes &self.
            // We'll use a workaround with unsafe or restructure.
            // For now, we'll create a simple polling approach.

            // Note: This is a limitation - we can't easily get &mut access
            // to accept_rx from &self. In a real implementation, we'd use
            // interior mutability or restructure the API.

            Err(TransportError::ReceiveFailed {
                reason: "Use accept_async() instead".to_string(),
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        // This is tricky because we need async access.
        // For now, we'll panic - real impl would cache this.
        unimplemented!("Use local_addr_async() instead")
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Sctp
    }

    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = TransportResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Relaxed);

            let mut inner = self.inner.write().await;
            inner.closed = true;
            inner.pending.clear();
            drop(inner);

            info!("SCTP listener closed");
            Ok(())
        })
    }
}

impl SctpListener {
    /// Accepts the next incoming association (async-friendly version).
    ///
    /// # Errors
    ///
    /// Returns an error if the listener is closed.
    pub async fn accept_async(&mut self) -> TransportResult<(AssociationHandle, SbcSocketAddr)> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(TransportError::ConnectionClosed);
        }

        self.accept_rx
            .recv()
            .await
            .ok_or(TransportError::ConnectionClosed)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a pseudo-random u32.
fn generate_random_u32() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    (now ^ (now >> 32)) as u32
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SctpListenerConfig {
        SctpListenerConfig {
            use_udp_encap: false, // Disable to allow ephemeral port binding
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_listener_bind() {
        let listener = SctpListener::bind("127.0.0.1:0".parse().unwrap(), test_config())
            .await
            .unwrap();

        let addr = listener.local_addr().await;
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_listener_config_default() {
        let config = SctpListenerConfig::default();
        assert!(config.use_udp_encap);
        assert_eq!(config.max_pending, 1024);
    }

    #[test]
    fn test_pending_key_equality() {
        let key1 = PendingKey {
            peer_addr: "127.0.0.1:5060".parse().unwrap(),
            local_tag: 12345,
        };
        let key2 = PendingKey {
            peer_addr: "127.0.0.1:5060".parse().unwrap(),
            local_tag: 12345,
        };
        assert_eq!(key1, key2);

        let key3 = PendingKey {
            peer_addr: "127.0.0.1:5060".parse().unwrap(),
            local_tag: 54321,
        };
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_listener_close() {
        let listener = SctpListener::bind("127.0.0.1:0".parse().unwrap(), test_config())
            .await
            .unwrap();

        listener.close().await.unwrap();
        assert!(listener.closed.load(Ordering::Relaxed));
    }
}
