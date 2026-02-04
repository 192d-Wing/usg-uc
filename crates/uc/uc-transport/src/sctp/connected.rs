//! Connected SCTP association with real socket I/O.
//!
//! This module provides `ConnectedSctpAssociation`, which wraps an
//! `AssociationHandle` with a UDP socket for actual network communication.

use super::StreamId;
use super::association::{AssociationConfig, AssociationHandle};
use super::chunk::{AbortChunk, Chunk, ShutdownChunk};
use super::packet::{MAX_PACKET_SIZE, SctpPacket};
use super::state::{AssociationState, StateAction};
use super::udp_encap::UdpEncapConfig;
use crate::error::{TransportError, TransportResult};
use crate::{MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, StreamTransport, Transport};
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};
use uc_types::address::{SbcSocketAddr, TransportType};

/// SCTP association with real socket I/O.
///
/// This struct wraps `AssociationHandle` and provides actual network
/// communication via UDP sockets (SCTP-over-UDP per RFC 6951).
pub struct ConnectedSctpAssociation {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Primary remote address.
    peer_addr: SbcSocketAddr,
    /// Association handle for internal state.
    handle: AssociationHandle,
    /// UDP socket for SCTP-over-UDP transport.
    socket: Arc<UdpSocket>,
    /// Channel for received messages.
    recv_rx: mpsc::Receiver<(u16, Bytes)>,
    /// Shutdown signal sender.
    #[allow(dead_code)]
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Connected flag.
    connected: AtomicBool,
    /// Background I/O task handle.
    #[allow(dead_code)]
    io_task: Option<tokio::task::JoinHandle<()>>,
    /// Whether UDP encapsulation is enabled (RFC 6951).
    use_udp_encapsulation: bool,
    /// UDP encapsulation configuration.
    udp_encap_config: UdpEncapConfig,
}

/// Configuration for connected SCTP association.
#[derive(Debug, Clone)]
pub struct ConnectedSctpConfig {
    /// Number of outbound streams.
    pub outbound_streams: u16,
    /// Maximum inbound streams.
    pub max_inbound_streams: u16,
    /// Maximum number of retransmissions.
    pub max_retransmissions: u16,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u32,
    /// Path MTU.
    pub path_mtu: u16,
    /// Enable ordered delivery.
    pub ordered_delivery: bool,
    /// Advertised receiver window credit.
    pub a_rwnd: u32,
    /// Enable UDP encapsulation per RFC 6951.
    ///
    /// When enabled, SCTP packets are wrapped in a UDP header for NAT traversal.
    /// The encapsulation adds 8 bytes of overhead per packet.
    pub use_udp_encapsulation: bool,
    /// UDP encapsulation configuration (ports).
    ///
    /// Only used when `use_udp_encapsulation` is true.
    pub udp_encap_config: UdpEncapConfig,
}

impl Default for ConnectedSctpConfig {
    fn default() -> Self {
        Self {
            outbound_streams: 10,
            max_inbound_streams: 10,
            max_retransmissions: 10,
            heartbeat_interval_ms: 30_000,
            path_mtu: 1280,
            ordered_delivery: true,
            a_rwnd: 65535,
            use_udp_encapsulation: false,
            udp_encap_config: UdpEncapConfig::default(),
        }
    }
}

impl ConnectedSctpConfig {
    /// Creates a configuration with UDP encapsulation enabled.
    ///
    /// This is useful for deployments behind NAT devices that don't
    /// understand native SCTP.
    #[must_use]
    pub fn with_udp_encapsulation(mut self) -> Self {
        self.use_udp_encapsulation = true;
        self
    }

    /// Sets the UDP encapsulation ports.
    #[must_use]
    pub fn with_udp_encap_ports(mut self, local_port: u16, remote_port: u16) -> Self {
        self.use_udp_encapsulation = true;
        self.udp_encap_config = UdpEncapConfig::new(local_port, remote_port);
        self
    }
}

impl ConnectedSctpAssociation {
    /// Creates a new connected SCTP association (client mode).
    ///
    /// This binds a UDP socket and creates the association handle.
    /// Call `connect()` to initiate the 4-way handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if socket binding fails.
    pub async fn new(
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        config: ConnectedSctpConfig,
    ) -> TransportResult<Self> {
        // Bind UDP socket
        let local_socket: SocketAddr = local_addr.clone().into();
        let socket =
            UdpSocket::bind(local_socket)
                .await
                .map_err(|e| TransportError::BindFailed {
                    reason: e.to_string(),
                    address: local_addr.clone(),
                })?;

        // Get actual local address (in case port 0 was used)
        let actual_local: SocketAddr =
            socket
                .local_addr()
                .map_err(|e| TransportError::BindFailed {
                    reason: e.to_string(),
                    address: local_addr.clone(),
                })?;

        let actual_local_sbc = SbcSocketAddr::from(actual_local);

        // Store encapsulation settings
        let use_udp_encapsulation = config.use_udp_encapsulation;
        let udp_encap_config = config.udp_encap_config.clone();

        // Create association config
        let assoc_config = AssociationConfig {
            outbound_streams: config.outbound_streams,
            max_inbound_streams: config.max_inbound_streams,
            a_rwnd: config.a_rwnd,
            max_retransmissions: config.max_retransmissions.into(),
            max_init_retransmissions: config.max_retransmissions.into(),
            cookie_lifetime: std::time::Duration::from_secs(60),
            heartbeat_interval: std::time::Duration::from_millis(
                config.heartbeat_interval_ms.into(),
            ),
            path_mtu: config.path_mtu.into(),
            ordered_delivery: config.ordered_delivery,
            udp_encap: udp_encap_config.clone(),
        };

        // Create association handle
        let peer_socket: SocketAddr = peer_addr.clone().into();
        let handle = AssociationHandle::new(actual_local, peer_socket, assoc_config);

        // Create message channel for received data
        let (recv_tx, recv_rx) = mpsc::channel(1024);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let socket = Arc::new(socket);

        // Start background I/O task
        let io_task = {
            let socket = socket.clone();
            let handle = handle.clone();
            let peer_addr = peer_socket;
            let encap_config = udp_encap_config.clone();
            tokio::spawn(async move {
                io_loop(
                    socket,
                    handle,
                    peer_addr,
                    recv_tx,
                    shutdown_rx,
                    use_udp_encapsulation,
                    encap_config,
                )
                .await;
            })
        };

        info!(
            local = %actual_local_sbc,
            peer = %peer_addr,
            udp_encap = use_udp_encapsulation,
            "Connected SCTP association created"
        );

        Ok(Self {
            local_addr: actual_local_sbc,
            peer_addr,
            handle,
            socket,
            recv_rx,
            shutdown_tx: Some(shutdown_tx),
            connected: AtomicBool::new(false),
            io_task: Some(io_task),
            use_udp_encapsulation,
            udp_encap_config,
        })
    }

    /// Creates a connected SCTP association from an existing handle.
    ///
    /// Used by `SctpListener` when accepting new connections.
    #[allow(dead_code)]
    pub(crate) fn from_handle(
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        handle: AssociationHandle,
        socket: Arc<UdpSocket>,
        recv_rx: mpsc::Receiver<(u16, Bytes)>,
        use_udp_encapsulation: bool,
        udp_encap_config: UdpEncapConfig,
    ) -> Self {
        Self {
            local_addr,
            peer_addr,
            handle,
            socket,
            recv_rx,
            shutdown_tx: None,
            connected: AtomicBool::new(true),
            io_task: None,
            use_udp_encapsulation,
            udp_encap_config,
        }
    }

    /// Returns whether UDP encapsulation is enabled.
    #[must_use]
    pub fn is_udp_encapsulated(&self) -> bool {
        self.use_udp_encapsulation
    }

    /// Encodes an SCTP packet, optionally with UDP encapsulation.
    fn encode_packet(&self, packet: &SctpPacket) -> Bytes {
        if self.use_udp_encapsulation {
            use super::udp_encap::EncapsulatedPacket;
            let encap = EncapsulatedPacket::from_config(packet.clone(), &self.udp_encap_config);
            let local_addr: SocketAddr = self.local_addr.clone().into();
            let peer_addr: SocketAddr = self.peer_addr.clone().into();
            encap.encode(Some(&local_addr), Some(&peer_addr))
        } else {
            packet.encode().freeze()
        }
    }

    /// Decodes a received buffer, handling optional UDP encapsulation.
    fn decode_packet(&self, buf: &[u8]) -> Result<SctpPacket, TransportError> {
        if self.use_udp_encapsulation {
            use super::udp_encap::decapsulate;
            let encap =
                decapsulate(Bytes::copy_from_slice(buf)).map_err(|e| TransportError::Io {
                    reason: format!("UDP decapsulation failed: {e}"),
                })?;
            Ok(encap.sctp_packet)
        } else {
            SctpPacket::decode(&Bytes::copy_from_slice(buf)).map_err(|e| TransportError::Io {
                reason: format!("Failed to decode SCTP packet: {e}"),
            })
        }
    }

    /// Initiates the SCTP association.
    ///
    /// This sends an INIT chunk and performs the 4-way handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if association setup fails.
    pub async fn connect(&mut self) -> TransportResult<()> {
        info!(
            local = %self.local_addr,
            peer = %self.peer_addr,
            udp_encap = self.use_udp_encapsulation,
            "SCTP association initiating 4-way handshake"
        );

        // Create and send INIT packet
        let init_packet = self.handle.create_init_packet().await;
        let init_bytes = self.encode_packet(&init_packet);

        let peer_socket: SocketAddr = self.peer_addr.clone().into();
        self.socket
            .send_to(&init_bytes, peer_socket)
            .await
            .map_err(|e| TransportError::SendFailed {
                address: self.peer_addr.clone(),
                reason: e.to_string(),
            })?;

        debug!(peer = %self.peer_addr, "Sent INIT chunk");

        // Wait for INIT-ACK with timeout
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let timeout = std::time::Duration::from_secs(5);

        let (len, from) = tokio::time::timeout(timeout, self.socket.recv_from(&mut buf))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ReceiveFailed {
                reason: e.to_string(),
            })?;

        debug!(from = %from, len = len, "Received response");

        // Decode and process INIT-ACK (with optional decapsulation)
        let packet = self.decode_packet(&buf[..len])?;

        let response_chunks =
            self.handle
                .process_packet(&packet)
                .await
                .map_err(|e| TransportError::Io {
                    reason: format!("Failed to process INIT-ACK: {e}"),
                })?;

        // Should have COOKIE-ECHO to send
        if response_chunks.is_empty() {
            return Err(TransportError::Io {
                reason: "No COOKIE-ECHO generated from INIT-ACK".to_string(),
            });
        }

        // Send COOKIE-ECHO
        let verification_tag = self.handle.peer_verification_tag().await;
        let mut cookie_echo_packet = SctpPacket::new(
            self.local_addr.port(),
            self.peer_addr.port(),
            verification_tag,
        );
        for chunk in response_chunks {
            cookie_echo_packet.add_chunk(chunk);
        }

        let cookie_echo_bytes = self.encode_packet(&cookie_echo_packet);
        self.socket
            .send_to(&cookie_echo_bytes, peer_socket)
            .await
            .map_err(|e| TransportError::SendFailed {
                address: self.peer_addr.clone(),
                reason: e.to_string(),
            })?;

        debug!(peer = %self.peer_addr, "Sent COOKIE-ECHO chunk");

        // Wait for COOKIE-ACK
        let (len, _from) = tokio::time::timeout(timeout, self.socket.recv_from(&mut buf))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ReceiveFailed {
                reason: e.to_string(),
            })?;

        // Decode with optional decapsulation
        let packet = self.decode_packet(&buf[..len])?;

        self.handle
            .process_packet(&packet)
            .await
            .map_err(|e| TransportError::Io {
                reason: format!("Failed to process COOKIE-ACK: {e}"),
            })?;

        // Verify we're established
        if !self.handle.is_established().await {
            return Err(TransportError::Io {
                reason: "Failed to establish association".to_string(),
            });
        }

        self.connected.store(true, Ordering::Relaxed);

        info!(
            local = %self.local_addr,
            peer = %self.peer_addr,
            "SCTP association established"
        );

        Ok(())
    }

    /// Returns the association state.
    pub async fn state(&self) -> AssociationState {
        self.handle.state().await
    }

    /// Returns the primary path address.
    #[must_use]
    pub fn primary_path(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    /// Returns the local verification tag.
    pub async fn local_verification_tag(&self) -> u32 {
        self.handle.local_verification_tag().await
    }

    /// Returns the peer verification tag.
    pub async fn peer_verification_tag(&self) -> u32 {
        self.handle.peer_verification_tag().await
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

        // Queue data through association handle
        self.handle
            .send(stream.0, Bytes::copy_from_slice(data), ordered)
            .await
            .map_err(|e| TransportError::SendFailed {
                address: self.peer_addr.clone(),
                reason: e,
            })?;

        // Get pending data and send it
        let pending_chunks = self.handle.get_pending_data().await;
        if !pending_chunks.is_empty() {
            let verification_tag = self.handle.peer_verification_tag().await;
            let mut packet = SctpPacket::new(
                self.local_addr.port(),
                self.peer_addr.port(),
                verification_tag,
            );

            for chunk in pending_chunks {
                packet.add_chunk(Chunk::Data(chunk));
            }

            let bytes = packet.encode();
            let peer_socket: SocketAddr = self.peer_addr.clone().into();
            self.socket
                .send_to(&bytes, peer_socket)
                .await
                .map_err(|e| TransportError::SendFailed {
                    address: self.peer_addr.clone(),
                    reason: e.to_string(),
                })?;
        }

        debug!(
            stream = stream.0,
            len = data.len(),
            ordered = ordered,
            "SCTP sent on stream"
        );

        Ok(())
    }

    /// Receives data from any stream.
    ///
    /// # Errors
    ///
    /// Returns an error if not connected or receive fails.
    pub async fn recv_from_stream(&mut self) -> TransportResult<(StreamId, Bytes)> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }

        // Try to receive from channel (populated by I/O task)
        match self.recv_rx.recv().await {
            Some((stream_id, data)) => Ok((StreamId(stream_id), data)),
            None => Err(TransportError::ConnectionClosed),
        }
    }

    /// Gracefully shuts down the association.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&mut self) -> TransportResult<()> {
        info!(
            peer = %self.peer_addr,
            "SCTP association shutdown initiated"
        );

        let actions = self.handle.shutdown().await;

        // Send SHUTDOWN chunk if needed
        for action in actions {
            if action == StateAction::SendShutdown {
                let verification_tag = self.handle.peer_verification_tag().await;
                let mut packet = SctpPacket::new(
                    self.local_addr.port(),
                    self.peer_addr.port(),
                    verification_tag,
                );
                packet.add_chunk(Chunk::Shutdown(ShutdownChunk::new(0)));

                let bytes = packet.encode();
                let peer_socket: SocketAddr = self.peer_addr.clone().into();
                let _ = self.socket.send_to(&bytes, peer_socket).await;
            }
        }

        self.connected.store(false, Ordering::Relaxed);

        // Signal shutdown to I/O task
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        Ok(())
    }

    /// Aborts the association immediately.
    pub async fn abort(&mut self) {
        let actions = self.handle.abort().await;

        // Send ABORT chunk if needed
        for action in actions {
            if action == StateAction::SendAbort {
                let verification_tag = self.handle.peer_verification_tag().await;
                let mut packet = SctpPacket::new(
                    self.local_addr.port(),
                    self.peer_addr.port(),
                    verification_tag,
                );
                packet.add_chunk(Chunk::Abort(AbortChunk::new()));

                let bytes = packet.encode();
                let peer_socket: SocketAddr = self.peer_addr.clone().into();
                let _ = self.socket.send_to(&bytes, peer_socket).await;
            }
        }

        self.connected.store(false, Ordering::Relaxed);

        info!(
            peer = %self.peer_addr,
            "SCTP association aborted"
        );

        // Signal shutdown to I/O task
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Transport for ConnectedSctpAssociation {
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
            self.send_on_stream(StreamId::SIP_SIGNALING, data, true)
                .await
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            loop {
                // Try to get a message from the handle
                if let Some((stream_id, data)) = self.handle.recv().await {
                    trace!(
                        stream = stream_id,
                        len = data.len(),
                        "Received SCTP message"
                    );
                    return Ok(ReceivedMessage {
                        data,
                        source: self.peer_addr.clone(),
                        transport: TransportType::Sctp,
                    });
                }

                // Yield to allow other tasks to run
                tokio::task::yield_now().await;
            }
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

impl StreamTransport for ConnectedSctpAssociation {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for ConnectedSctpAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedSctpAssociation")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Background I/O Task
// =============================================================================

/// Timer check interval (100ms).
const TIMER_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Background I/O loop for handling socket operations.
#[allow(clippy::too_many_arguments)]
async fn io_loop(
    socket: Arc<UdpSocket>,
    handle: AssociationHandle,
    peer_addr: SocketAddr,
    recv_tx: mpsc::Sender<(u16, Bytes)>,
    mut shutdown_rx: oneshot::Receiver<()>,
    use_udp_encapsulation: bool,
    udp_encap_config: UdpEncapConfig,
) {
    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    // Create timer interval for periodic checks
    let mut timer_interval = tokio::time::interval(TIMER_CHECK_INTERVAL);
    timer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Get local address for encapsulation
    let local_addr = socket.local_addr().ok();

    loop {
        tokio::select! {
            biased;

            // Check for shutdown signal
            _ = &mut shutdown_rx => {
                debug!("SCTP I/O loop shutting down");
                break;
            }

            // Periodic timer check for retransmissions and heartbeats
            _ = timer_interval.tick() => {
                // Check for T3-rtx expiration and handle retransmissions
                let retransmit_chunks = handle.check_retransmissions().await;
                if !retransmit_chunks.is_empty() {
                    trace!(count = retransmit_chunks.len(), "Retransmitting DATA chunks");
                    if let Err(e) = send_data_chunks(
                        &socket, &handle, peer_addr, &retransmit_chunks,
                        use_udp_encapsulation, &udp_encap_config, local_addr.as_ref(),
                    ).await {
                        warn!(error = %e, "Failed to send retransmit chunks");
                    }
                }

                // Check for fast retransmit chunks
                let fast_rtx_chunks = handle.get_fast_retransmit_chunks().await;
                if !fast_rtx_chunks.is_empty() {
                    trace!(count = fast_rtx_chunks.len(), "Fast retransmitting DATA chunks");
                    if let Err(e) = send_data_chunks(
                        &socket, &handle, peer_addr, &fast_rtx_chunks,
                        use_udp_encapsulation, &udp_encap_config, local_addr.as_ref(),
                    ).await {
                        warn!(error = %e, "Failed to send fast retransmit chunks");
                    }
                }

                // Check for heartbeat timer expiration (RFC 9260 §8.3)
                let expired_timers = handle.check_timers().await;
                for timer_type in expired_timers {
                    if timer_type == super::timer::TimerType::Heartbeat {
                        // Get all paths that need heartbeats
                        let heartbeat_targets = handle.get_heartbeat_targets().await;

                        if heartbeat_targets.is_empty() {
                            // No paths need heartbeats yet, just restart timer
                            handle.restart_heartbeat_timer().await;
                        } else {
                            // Send heartbeat to each path that needs one
                            for (path_id, target_addr) in heartbeat_targets {
                                trace!(target = %target_addr, path = %path_id, "Sending HEARTBEAT");
                                if let Err(e) = send_heartbeat_to_path(
                                    &socket, &handle, target_addr, path_id,
                                    use_udp_encapsulation, &udp_encap_config, local_addr.as_ref(),
                                ).await {
                                    warn!(error = %e, target = %target_addr, "Failed to send heartbeat");
                                } else {
                                    // Mark this path as having sent a heartbeat
                                    handle.mark_heartbeat_sent(path_id).await;
                                }
                            }
                            // Restart heartbeat timer
                            handle.restart_heartbeat_timer().await;
                        }
                    }
                }
            }

            // Receive packets from the network
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, from)) => {
                        if from != peer_addr {
                            trace!(from = %from, expected = %peer_addr, "Ignoring packet from unexpected source");
                            continue;
                        }

                        trace!(len = len, from = %from, "Received SCTP packet");

                        // Decode packet (with optional decapsulation)
                        let decode_result = if use_udp_encapsulation {
                            use super::udp_encap::decapsulate;
                            decapsulate(Bytes::copy_from_slice(&buf[..len]))
                                .map(|encap| encap.sctp_packet)
                                .map_err(|e| e.to_string())
                        } else {
                            SctpPacket::decode(&Bytes::copy_from_slice(&buf[..len]))
                                .map_err(|e| e.to_string())
                        };

                        match decode_result {
                            Ok(packet) => {
                                // Process through handle
                                match handle.process_packet(&packet).await {
                                    Ok(response_chunks) => {
                                        // Send any response chunks
                                        if !response_chunks.is_empty() {
                                            let vtag = handle.peer_verification_tag().await;
                                            let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
                                            let mut response_packet = SctpPacket::new(
                                                local_port,
                                                peer_addr.port(),
                                                vtag,
                                            );
                                            for chunk in response_chunks {
                                                response_packet.add_chunk(chunk);
                                            }

                                            let response_bytes = encode_packet_with_encap(
                                                &response_packet,
                                                use_udp_encapsulation,
                                                &udp_encap_config,
                                                local_addr.as_ref(),
                                                &peer_addr,
                                            );
                                            if let Err(e) = socket.send_to(&response_bytes, peer_addr).await {
                                                warn!(error = %e, "Failed to send response packet");
                                            }
                                        }

                                        // Check for received data to forward
                                        while let Some((stream_id, data)) = handle.recv().await {
                                            if recv_tx.send((stream_id, data)).await.is_err() {
                                                debug!("Receiver dropped, stopping I/O loop");
                                                return;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Failed to process SCTP packet");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to decode SCTP packet");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Socket recv error");
                    }
                }
            }
        }
    }
}

/// Encodes an SCTP packet with optional UDP encapsulation.
fn encode_packet_with_encap(
    packet: &SctpPacket,
    use_udp_encapsulation: bool,
    udp_encap_config: &UdpEncapConfig,
    local_addr: Option<&SocketAddr>,
    peer_addr: &SocketAddr,
) -> Bytes {
    if use_udp_encapsulation {
        use super::udp_encap::EncapsulatedPacket;
        let encap = EncapsulatedPacket::from_config(packet.clone(), udp_encap_config);
        encap.encode(local_addr, Some(peer_addr))
    } else {
        packet.encode().freeze()
    }
}

/// Sends DATA chunks in a packet.
#[allow(clippy::too_many_arguments)]
async fn send_data_chunks(
    socket: &UdpSocket,
    handle: &AssociationHandle,
    peer_addr: SocketAddr,
    chunks: &[super::chunk::DataChunk],
    use_udp_encapsulation: bool,
    udp_encap_config: &UdpEncapConfig,
    local_addr: Option<&SocketAddr>,
) -> Result<(), std::io::Error> {
    if chunks.is_empty() {
        return Ok(());
    }

    let vtag = handle.peer_verification_tag().await;
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut packet = SctpPacket::new(local_port, peer_addr.port(), vtag);

    for chunk in chunks {
        packet.add_chunk(Chunk::Data(chunk.clone()));
    }

    let bytes = encode_packet_with_encap(
        &packet,
        use_udp_encapsulation,
        udp_encap_config,
        local_addr,
        &peer_addr,
    );
    socket.send_to(&bytes, peer_addr).await?;

    // Track sent chunks for retransmission
    handle.track_sent_chunks(chunks).await;

    Ok(())
}

/// Sends a HEARTBEAT chunk to the primary peer address.
#[allow(dead_code)] // Keep for backwards compatibility, prefer send_heartbeat_to_path
async fn send_heartbeat(
    socket: &UdpSocket,
    handle: &AssociationHandle,
    peer_addr: SocketAddr,
    use_udp_encapsulation: bool,
    udp_encap_config: &UdpEncapConfig,
    local_addr: Option<&SocketAddr>,
) -> Result<(), std::io::Error> {
    use super::chunk::HeartbeatChunk;

    let vtag = handle.peer_verification_tag().await;
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut packet = SctpPacket::new(local_port, peer_addr.port(), vtag);

    // Create heartbeat with timestamp for RTT calculation
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let hb_info = Bytes::from(now.to_be_bytes().to_vec());
    let heartbeat = HeartbeatChunk::new(hb_info);

    packet.add_chunk(Chunk::Heartbeat(heartbeat));

    let bytes = encode_packet_with_encap(
        &packet,
        use_udp_encapsulation,
        udp_encap_config,
        local_addr,
        &peer_addr,
    );
    socket.send_to(&bytes, peer_addr).await?;

    Ok(())
}

/// Sends a HEARTBEAT chunk to a specific path (RFC 9260 §8.3).
///
/// Per RFC 9260 §8.3, heartbeats should be sent to each destination
/// transport address at the heartbeat interval. The heartbeat info
/// contains path identification for proper HEARTBEAT-ACK routing.
async fn send_heartbeat_to_path(
    socket: &UdpSocket,
    handle: &AssociationHandle,
    target_addr: SocketAddr,
    path_id: super::path::PathId,
    use_udp_encapsulation: bool,
    udp_encap_config: &UdpEncapConfig,
    local_addr: Option<&SocketAddr>,
) -> Result<(), std::io::Error> {
    let vtag = handle.peer_verification_tag().await;
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut packet = SctpPacket::new(local_port, target_addr.port(), vtag);

    // Create heartbeat with path info for proper routing of HEARTBEAT-ACK
    let heartbeat = handle.create_heartbeat_for_path(path_id).await;

    packet.add_chunk(Chunk::Heartbeat(heartbeat));

    let bytes = encode_packet_with_encap(
        &packet,
        use_udp_encapsulation,
        udp_encap_config,
        local_addr,
        &target_addr,
    );
    socket.send_to(&bytes, target_addr).await?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connected_association_creation() {
        let config = ConnectedSctpConfig::default();
        // Use port 0 to let the OS assign an available port
        let local = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let assoc = ConnectedSctpAssociation::new(local, peer.clone(), config)
            .await
            .unwrap();

        assert_eq!(assoc.state().await, AssociationState::Closed);
        assert_eq!(assoc.primary_path(), &peer);
        assert!(!assoc.is_connected());
        assert_ne!(assoc.local_verification_tag().await, 0);
        assert!(!assoc.is_udp_encapsulated());
    }

    #[tokio::test]
    async fn test_connected_association_with_udp_encapsulation() {
        let config = ConnectedSctpConfig::default().with_udp_encapsulation();
        let local = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let assoc = ConnectedSctpAssociation::new(local, peer.clone(), config)
            .await
            .unwrap();

        assert!(assoc.is_udp_encapsulated());
        assert_eq!(assoc.primary_path(), &peer);
    }

    #[tokio::test]
    async fn test_connected_association_with_custom_encap_ports() {
        let config = ConnectedSctpConfig::default().with_udp_encap_ports(12345, 54321);
        let local = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let assoc = ConnectedSctpAssociation::new(local, peer, config)
            .await
            .unwrap();

        assert!(assoc.is_udp_encapsulated());
        assert_eq!(assoc.udp_encap_config.local_port, 12345);
        assert_eq!(assoc.udp_encap_config.remote_port, 54321);
    }

    #[tokio::test]
    async fn test_connected_association_shutdown() {
        let config = ConnectedSctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = ConnectedSctpAssociation::new(local, peer, config)
            .await
            .unwrap();

        // Manually set connected for shutdown test
        assoc.connected.store(true, Ordering::Relaxed);

        assoc.shutdown().await.unwrap();

        assert!(!assoc.is_connected());
    }

    #[tokio::test]
    async fn test_connected_association_abort() {
        let config = ConnectedSctpConfig::default();
        let local = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let peer = SbcSocketAddr::from("127.0.0.1:5061".parse::<SocketAddr>().unwrap());

        let mut assoc = ConnectedSctpAssociation::new(local, peer, config)
            .await
            .unwrap();

        // Manually set connected for this test
        assoc.connected.store(true, Ordering::Relaxed);

        assoc.abort().await;

        assert!(!assoc.is_connected());
    }

    #[test]
    fn test_config_defaults() {
        let config = ConnectedSctpConfig::default();
        assert_eq!(config.outbound_streams, 10);
        assert_eq!(config.max_inbound_streams, 10);
        assert!(!config.use_udp_encapsulation);
        assert_eq!(
            config.udp_encap_config.local_port,
            super::super::udp_encap::SCTP_UDP_PORT
        );
    }

    #[test]
    fn test_encode_packet_with_encap() {
        use super::super::chunk::{Chunk, DataChunk};

        let mut packet = SctpPacket::new(5060, 5061, 0x12345678);
        packet.add_chunk(Chunk::Data(DataChunk::new(
            1,
            0,
            0,
            0,
            Bytes::from_static(b"test"),
        )));

        let config = UdpEncapConfig::default();
        let local_addr: SocketAddr = "192.168.1.1:9899".parse().unwrap();
        let peer_addr: SocketAddr = "192.168.1.2:9899".parse().unwrap();

        // Without encapsulation
        let bytes_raw =
            encode_packet_with_encap(&packet, false, &config, Some(&local_addr), &peer_addr);

        // With encapsulation (should be larger due to UDP header)
        let bytes_encap =
            encode_packet_with_encap(&packet, true, &config, Some(&local_addr), &peer_addr);

        // Encapsulated packet should be 8 bytes larger (UDP header)
        assert_eq!(bytes_encap.len(), bytes_raw.len() + 8);
    }

    #[test]
    fn test_encode_decode_roundtrip_without_encap() {
        use super::super::chunk::{Chunk, DataChunk};

        let mut packet = SctpPacket::new(5060, 5061, 0x12345678);
        packet.add_chunk(Chunk::Data(DataChunk::new(
            1,
            0,
            0,
            0,
            Bytes::from_static(b"hello"),
        )));

        let config = UdpEncapConfig::default();
        let peer_addr: SocketAddr = "192.168.1.2:9899".parse().unwrap();

        let encoded = encode_packet_with_encap(&packet, false, &config, None, &peer_addr);

        // Decode without encapsulation
        let decoded = SctpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.source_port, 5060);
        assert_eq!(decoded.dest_port, 5061);
        assert_eq!(decoded.verification_tag, 0x12345678);
    }

    #[test]
    fn test_encode_decode_roundtrip_with_encap() {
        use super::super::chunk::{Chunk, DataChunk};
        use super::super::udp_encap::decapsulate;

        let mut packet = SctpPacket::new(5060, 5061, 0x12345678);
        packet.add_chunk(Chunk::Data(DataChunk::new(
            1,
            0,
            0,
            0,
            Bytes::from_static(b"hello"),
        )));

        let config = UdpEncapConfig::default();
        let local_addr: SocketAddr = "192.168.1.1:9899".parse().unwrap();
        let peer_addr: SocketAddr = "192.168.1.2:9899".parse().unwrap();

        let encoded =
            encode_packet_with_encap(&packet, true, &config, Some(&local_addr), &peer_addr);

        // Decode with decapsulation
        let encap = decapsulate(encoded).unwrap();
        assert_eq!(encap.udp_header.source_port, config.local_port);
        assert_eq!(encap.udp_header.dest_port, config.remote_port);
        assert_eq!(encap.sctp_packet.source_port, 5060);
        assert_eq!(encap.sctp_packet.dest_port, 5061);
        assert_eq!(encap.sctp_packet.verification_tag, 0x12345678);
    }
}
