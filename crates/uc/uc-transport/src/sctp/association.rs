//! SCTP association implementation (RFC 9260).
//!
//! This module provides the core SCTP association that integrates:
//! - State machine for connection lifecycle
//! - Stream management for multi-streaming
//! - Congestion control and reliability
//! - Path management for multi-homing
//! - Timer management for retransmissions
//! - UDP encapsulation for NAT traversal

use super::chunk::{
    Chunk, CookieAckChunk, CookieEchoChunk, DataChunk, HeartbeatAckChunk, HeartbeatChunk,
    InitAckChunk, InitChunk, InitParam, SackChunk, ShutdownAckChunk, ShutdownChunk,
    ShutdownCompleteChunk,
};
use super::cookie::{CookieData, CookieGenerator};
use super::packet::SctpPacket;
use super::path::{PathId, PathManager};
use super::state::{AssociationState, StateAction, StateEvent, StateMachine};
use super::stream::StreamManager;
use super::timer::TimerManager;
use super::udp_encap::UdpEncapConfig;
use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of retransmissions before aborting.
pub const MAX_RETRANSMISSIONS: u32 = 10;

/// Maximum number of INIT retransmissions.
pub const MAX_INIT_RETRANSMISSIONS: u32 = 8;

/// Default receiver window size.
pub const DEFAULT_RWND: u32 = 65535;

/// Default number of streams.
pub const DEFAULT_STREAMS: u16 = 10;

// =============================================================================
// Association Configuration
// =============================================================================

/// Configuration for an SCTP association.
#[derive(Debug, Clone)]
pub struct AssociationConfig {
    /// Number of outbound streams.
    pub outbound_streams: u16,
    /// Maximum number of inbound streams.
    pub max_inbound_streams: u16,
    /// Advertised receiver window.
    pub a_rwnd: u32,
    /// Maximum retransmissions.
    pub max_retransmissions: u32,
    /// Maximum INIT retransmissions.
    pub max_init_retransmissions: u32,
    /// Cookie lifetime.
    pub cookie_lifetime: Duration,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Path MTU.
    pub path_mtu: u32,
    /// Whether to use ordered delivery by default.
    pub ordered_delivery: bool,
    /// UDP encapsulation configuration.
    pub udp_encap: UdpEncapConfig,
}

impl Default for AssociationConfig {
    fn default() -> Self {
        Self {
            outbound_streams: DEFAULT_STREAMS,
            max_inbound_streams: DEFAULT_STREAMS,
            a_rwnd: DEFAULT_RWND,
            max_retransmissions: MAX_RETRANSMISSIONS,
            max_init_retransmissions: MAX_INIT_RETRANSMISSIONS,
            cookie_lifetime: super::cookie::DEFAULT_COOKIE_LIFETIME,
            heartbeat_interval: Duration::from_secs(30),
            path_mtu: 1280,
            ordered_delivery: true,
            udp_encap: UdpEncapConfig::default(),
        }
    }
}

// =============================================================================
// Retransmission Entry
// =============================================================================

/// Entry in the retransmission queue.
#[derive(Debug)]
#[allow(dead_code)] // Fields will be used by retransmission logic
struct RetransmitEntry {
    /// The data chunk to retransmit.
    chunk: DataChunk,
    /// When the chunk was first sent.
    first_sent: Instant,
    /// When the chunk was last sent.
    last_sent: Instant,
    /// Number of retransmissions.
    retransmit_count: u32,
    /// Path the chunk was sent on.
    path_id: PathId,
}

// =============================================================================
// Association Inner
// =============================================================================

/// Internal state of an SCTP association.
#[derive(Debug)]
pub struct AssociationInner {
    // Identity
    /// Local verification tag.
    local_verification_tag: u32,
    /// Peer verification tag.
    peer_verification_tag: u32,
    /// Local initial TSN.
    local_initial_tsn: u32,
    /// Peer initial TSN.
    peer_initial_tsn: u32,

    // TSN tracking
    /// Next TSN to send.
    next_tsn: u32,
    /// Last TSN acknowledged by peer (cumulative).
    last_acked_tsn: u32,
    /// Peer's cumulative TSN (what we've acknowledged).
    peer_cumulative_tsn: u32,

    // Windows
    /// Local receiver window (our advertised window).
    local_rwnd: u32,
    /// Peer's advertised receiver window.
    peer_rwnd: u32,

    // Components
    /// State machine.
    state_machine: StateMachine,
    /// Stream manager.
    streams: StreamManager,
    /// Path manager.
    paths: PathManager,
    /// Timer manager.
    #[allow(dead_code)] // Will be used by retransmission and heartbeat logic
    timers: TimerManager,
    /// Cookie generator.
    cookie_generator: CookieGenerator,

    // Buffers
    /// Send queue (chunks waiting to be sent).
    send_queue: VecDeque<DataChunk>,
    /// Retransmission queue (keyed by TSN).
    retransmit_queue: BTreeMap<u32, RetransmitEntry>,

    // Configuration
    /// Association configuration.
    config: AssociationConfig,

    // Addresses
    /// Local address.
    local_addr: SocketAddr,
    /// Primary peer address.
    peer_addr: SocketAddr,
}

impl AssociationInner {
    /// Creates a new association inner state.
    fn new(local_addr: SocketAddr, peer_addr: SocketAddr, config: AssociationConfig) -> Self {
        // Generate random tags and TSNs
        let local_verification_tag = generate_random_u32();
        let local_initial_tsn = generate_random_u32();

        let streams = StreamManager::new(
            config.outbound_streams,
            config.max_inbound_streams,
            config.ordered_delivery,
        );

        let mut paths = PathManager::new();
        paths.add_path(local_addr, peer_addr);
        paths.set_default_heartbeat_interval(config.heartbeat_interval);

        let timers = TimerManager::with_heartbeat_interval(config.heartbeat_interval);

        Self {
            local_verification_tag,
            peer_verification_tag: 0,
            local_initial_tsn,
            peer_initial_tsn: 0,
            next_tsn: local_initial_tsn,
            last_acked_tsn: local_initial_tsn.wrapping_sub(1),
            peer_cumulative_tsn: 0,
            local_rwnd: config.a_rwnd,
            peer_rwnd: DEFAULT_RWND,
            state_machine: StateMachine::new(),
            streams,
            paths,
            timers,
            cookie_generator: CookieGenerator::new(),
            send_queue: VecDeque::new(),
            retransmit_queue: BTreeMap::new(),
            config,
            local_addr,
            peer_addr,
        }
    }

    /// Returns the current state.
    fn state(&self) -> AssociationState {
        self.state_machine.state()
    }

    /// Returns true if the association is established.
    fn is_established(&self) -> bool {
        self.state() == AssociationState::Established
    }

    /// Creates an INIT chunk for initiating the association.
    fn create_init_chunk(&self) -> InitChunk {
        InitChunk::new(
            self.local_verification_tag,
            self.config.a_rwnd,
            self.config.outbound_streams,
            self.config.max_inbound_streams,
            self.local_initial_tsn,
        )
    }

    /// Creates an INIT-ACK chunk in response to an INIT.
    fn create_init_ack_chunk(&self, init: &InitChunk) -> (InitAckChunk, Bytes) {
        // Create cookie data
        let cookie_data = CookieData::new(
            self.local_verification_tag,
            init.initiate_tag,
            self.local_initial_tsn,
            init.initial_tsn,
            self.config.outbound_streams.min(init.num_inbound_streams),
            self.config
                .max_inbound_streams
                .min(init.num_outbound_streams),
            self.peer_addr,
            self.local_addr,
        );

        let cookie = self.cookie_generator.generate(&cookie_data);

        let init_ack = InitAckChunk::from_init(
            init,
            self.local_verification_tag,
            self.config.a_rwnd,
            self.local_initial_tsn,
            cookie.clone(),
        );

        (init_ack, cookie)
    }

    /// Processes a received INIT chunk.
    fn process_init(&mut self, init: &InitChunk) -> Vec<StateAction> {
        // Store peer parameters
        self.peer_verification_tag = init.initiate_tag;
        self.peer_initial_tsn = init.initial_tsn;
        self.peer_cumulative_tsn = init.initial_tsn.wrapping_sub(1);
        self.peer_rwnd = init.a_rwnd;

        self.state_machine.process_event(StateEvent::ReceiveInit)
    }

    /// Processes a received INIT-ACK chunk.
    fn process_init_ack(&mut self, init_ack: &InitAckChunk) -> Vec<StateAction> {
        // Store peer parameters
        self.peer_verification_tag = init_ack.initiate_tag;
        self.peer_initial_tsn = init_ack.initial_tsn;
        self.peer_cumulative_tsn = init_ack.initial_tsn.wrapping_sub(1);
        self.peer_rwnd = init_ack.a_rwnd;

        // Update stream counts
        let outbound = self
            .config
            .outbound_streams
            .min(init_ack.num_inbound_streams);
        let inbound = self
            .config
            .max_inbound_streams
            .min(init_ack.num_outbound_streams);
        self.streams = StreamManager::new(outbound, inbound, self.config.ordered_delivery);

        self.state_machine.process_event(StateEvent::ReceiveInitAck)
    }

    /// Processes a received COOKIE-ECHO chunk.
    fn process_cookie_echo(&mut self, cookie: &Bytes) -> Result<Vec<StateAction>, String> {
        // Validate the cookie
        let cookie_data = self
            .cookie_generator
            .validate(cookie)
            .map_err(|e| e.to_string())?;

        // Restore association state from cookie
        self.peer_verification_tag = cookie_data.peer_verification_tag;
        self.local_verification_tag = cookie_data.local_verification_tag;
        self.peer_initial_tsn = cookie_data.peer_initial_tsn;
        self.local_initial_tsn = cookie_data.local_initial_tsn;
        self.peer_cumulative_tsn = cookie_data.peer_initial_tsn.wrapping_sub(1);
        self.next_tsn = cookie_data.local_initial_tsn;
        self.last_acked_tsn = cookie_data.local_initial_tsn.wrapping_sub(1);

        // Update streams
        self.streams = StreamManager::new(
            cookie_data.outbound_streams,
            cookie_data.inbound_streams,
            self.config.ordered_delivery,
        );

        Ok(self
            .state_machine
            .process_event(StateEvent::ReceiveCookieEcho))
    }

    /// Processes a received COOKIE-ACK chunk.
    fn process_cookie_ack(&mut self) -> Vec<StateAction> {
        self.state_machine
            .process_event(StateEvent::ReceiveCookieAck)
    }

    /// Processes a received DATA chunk.
    fn process_data(&mut self, data: DataChunk) -> Result<(), String> {
        if !self.is_established() {
            return Err("Association not established".to_string());
        }

        // Update peer cumulative TSN
        // Note: This is simplified; real implementation needs gap tracking
        if data.tsn == self.peer_cumulative_tsn.wrapping_add(1) {
            self.peer_cumulative_tsn = data.tsn;
        }

        // Process through stream manager
        self.streams.receive_data(data).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Processes a received SACK chunk.
    fn process_sack(&mut self, sack: &SackChunk) {
        if !self.is_established() {
            return;
        }

        // Update peer's receiver window
        self.peer_rwnd = sack.a_rwnd;

        // Process acknowledged TSNs
        let bytes_acked = self.acknowledge_tsns(sack.cumulative_tsn_ack);

        // Update congestion control
        if let Some(path) = self.paths.get_active_path_mut() {
            let is_new_ack = sack.cumulative_tsn_ack != self.last_acked_tsn;
            path.on_sack_received(bytes_acked, is_new_ack, None);
        }

        self.last_acked_tsn = sack.cumulative_tsn_ack;

        // TODO: Process gap ack blocks for selective acknowledgment
    }

    /// Acknowledges TSNs up to the given cumulative TSN.
    fn acknowledge_tsns(&mut self, cumulative_tsn: u32) -> u32 {
        let mut bytes_acked = 0u32;

        // Remove acknowledged entries from retransmit queue
        let tsns_to_remove: Vec<u32> = self
            .retransmit_queue
            .keys()
            .take_while(|&&tsn| tsn_le(tsn, cumulative_tsn))
            .copied()
            .collect();

        for tsn in tsns_to_remove {
            if let Some(entry) = self.retransmit_queue.remove(&tsn) {
                bytes_acked = bytes_acked.saturating_add(entry.chunk.data.len() as u32);
            }
        }

        bytes_acked
    }

    /// Queues data for sending.
    fn queue_data(&mut self, stream_id: u16, data: Bytes, ordered: bool) -> Result<u32, String> {
        if !self.is_established() {
            return Err("Association not established".to_string());
        }

        // Allocate SSN if ordered
        let ssn = if ordered {
            self.streams.allocate_ssn(stream_id)
        } else {
            0
        };

        // Create DATA chunk
        let tsn = self.next_tsn;
        self.next_tsn = self.next_tsn.wrapping_add(1);

        let mut chunk = DataChunk::new(tsn, stream_id, ssn, 0, data);
        if !ordered {
            chunk = chunk.with_unordered(true);
        }
        // Mark as both beginning and end (single fragment)
        chunk = chunk.with_fragment(true, true);

        self.send_queue.push_back(chunk);

        Ok(tsn)
    }

    /// Takes the next message from any stream.
    fn take_message(&mut self) -> Option<(u16, Bytes)> {
        self.streams.take_message()
    }

    /// Creates a SACK chunk for the current state.
    fn create_sack(&self) -> SackChunk {
        // TODO: Add gap ack blocks for out-of-order reception
        SackChunk::new(self.peer_cumulative_tsn, self.local_rwnd)
    }

    /// Creates a HEARTBEAT chunk.
    #[allow(dead_code)] // Will be used by heartbeat timer logic
    fn create_heartbeat(&self) -> HeartbeatChunk {
        // Include timestamp in heartbeat info for RTT measurement
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        HeartbeatChunk::new(Bytes::copy_from_slice(&now.to_be_bytes()))
    }

    /// Processes a HEARTBEAT-ACK and extracts RTT.
    fn process_heartbeat_ack(&mut self, hb_ack: &HeartbeatAckChunk, path_id: PathId) {
        if hb_ack.info.len() >= 8 {
            let sent_time = u64::from_be_bytes(hb_ack.info[..8].try_into().unwrap_or([0u8; 8]));

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            let rtt = Duration::from_millis(now.saturating_sub(sent_time));

            if let Some(path) = self.paths.get_path_mut(path_id) {
                path.on_heartbeat_ack(rtt);
            }
        }
    }

    /// Initiates graceful shutdown.
    fn initiate_shutdown(&mut self) -> Vec<StateAction> {
        self.state_machine.process_event(StateEvent::Shutdown)
    }

    /// Processes a SHUTDOWN chunk.
    fn process_shutdown(&mut self, _shutdown: &ShutdownChunk) -> Vec<StateAction> {
        self.state_machine
            .process_event(StateEvent::ReceiveShutdown)
    }

    /// Processes a SHUTDOWN-ACK chunk.
    fn process_shutdown_ack(&mut self) -> Vec<StateAction> {
        self.state_machine
            .process_event(StateEvent::ReceiveShutdownAck)
    }

    /// Aborts the association.
    fn abort(&mut self) -> Vec<StateAction> {
        self.state_machine.process_event(StateEvent::Abort)
    }
}

// =============================================================================
// Association Handle
// =============================================================================

/// Handle to an SCTP association.
///
/// This is the public interface for interacting with an association.
/// It wraps the inner state in an `Arc<RwLock<>>` for thread-safe access.
#[derive(Debug, Clone)]
pub struct AssociationHandle {
    inner: Arc<RwLock<AssociationInner>>,
}

impl AssociationHandle {
    /// Creates a new association handle.
    pub fn new(local_addr: SocketAddr, peer_addr: SocketAddr, config: AssociationConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AssociationInner::new(
                local_addr, peer_addr, config,
            ))),
        }
    }

    /// Returns the current association state.
    pub async fn state(&self) -> AssociationState {
        self.inner.read().await.state()
    }

    /// Returns true if the association is established.
    pub async fn is_established(&self) -> bool {
        self.inner.read().await.is_established()
    }

    /// Returns the local verification tag.
    pub async fn local_verification_tag(&self) -> u32 {
        self.inner.read().await.local_verification_tag
    }

    /// Returns the peer verification tag.
    pub async fn peer_verification_tag(&self) -> u32 {
        self.inner.read().await.peer_verification_tag
    }

    /// Queues data for sending on the specified stream.
    pub async fn send(&self, stream_id: u16, data: Bytes, ordered: bool) -> Result<u32, String> {
        self.inner
            .write()
            .await
            .queue_data(stream_id, data, ordered)
    }

    /// Takes the next received message.
    pub async fn recv(&self) -> Option<(u16, Bytes)> {
        self.inner.write().await.take_message()
    }

    /// Initiates graceful shutdown.
    pub async fn shutdown(&self) -> Vec<StateAction> {
        self.inner.write().await.initiate_shutdown()
    }

    /// Aborts the association.
    pub async fn abort(&self) -> Vec<StateAction> {
        self.inner.write().await.abort()
    }

    /// Processes a received packet.
    pub async fn process_packet(&self, packet: &SctpPacket) -> Result<Vec<Chunk>, String> {
        let mut inner = self.inner.write().await;
        let mut response_chunks = Vec::new();

        for chunk in &packet.chunks {
            match chunk {
                Chunk::Init(init) => {
                    let actions = inner.process_init(init);
                    for action in actions {
                        if action == StateAction::SendInitAck {
                            let (init_ack, _) = inner.create_init_ack_chunk(init);
                            response_chunks.push(Chunk::InitAck(init_ack));
                        }
                    }
                }
                Chunk::InitAck(init_ack) => {
                    let actions = inner.process_init_ack(init_ack);
                    for action in actions {
                        if action == StateAction::SendCookieEcho {
                            // Extract state cookie from INIT-ACK params
                            let cookie = init_ack
                                .params
                                .iter()
                                .find_map(|p| {
                                    if let InitParam::Cookie(c) = p {
                                        Some(c.clone())
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();
                            let cookie_echo = CookieEchoChunk::new(cookie);
                            response_chunks.push(Chunk::CookieEcho(cookie_echo));
                        }
                    }
                }
                Chunk::CookieEcho(cookie_echo) => {
                    let actions = inner.process_cookie_echo(&cookie_echo.cookie)?;
                    for action in actions {
                        if action == StateAction::SendCookieAck {
                            response_chunks.push(Chunk::CookieAck(CookieAckChunk));
                        }
                    }
                }
                Chunk::CookieAck(_) => {
                    inner.process_cookie_ack();
                }
                Chunk::Data(data) => {
                    inner.process_data(data.clone())?;
                    // Generate SACK
                    let sack = inner.create_sack();
                    response_chunks.push(Chunk::Sack(sack));
                }
                Chunk::Sack(sack) => {
                    inner.process_sack(sack);
                }
                Chunk::Heartbeat(hb) => {
                    // Echo back as HEARTBEAT-ACK
                    let hb_ack = HeartbeatAckChunk::from_heartbeat(hb);
                    response_chunks.push(Chunk::HeartbeatAck(hb_ack));
                }
                Chunk::HeartbeatAck(hb_ack) => {
                    if let Some(path_id) = inner.paths.primary_path_id() {
                        inner.process_heartbeat_ack(hb_ack, path_id);
                    }
                }
                Chunk::Shutdown(shutdown) => {
                    let actions = inner.process_shutdown(shutdown);
                    for action in actions {
                        if action == StateAction::SendShutdownAck {
                            response_chunks.push(Chunk::ShutdownAck(ShutdownAckChunk));
                        }
                    }
                }
                Chunk::ShutdownAck(_) => {
                    let actions = inner.process_shutdown_ack();
                    for action in actions {
                        if action == StateAction::SendShutdownComplete {
                            response_chunks
                                .push(Chunk::ShutdownComplete(ShutdownCompleteChunk::new(false)));
                        }
                    }
                }
                Chunk::ShutdownComplete(_) => {
                    // Association is now closed
                    inner
                        .state_machine
                        .process_event(StateEvent::ReceiveShutdownComplete);
                }
                Chunk::Abort(_) => {
                    inner.state_machine.process_event(StateEvent::ReceiveAbort);
                }
                _ => {
                    // Handle other chunks as needed
                }
            }
        }
        drop(inner);

        Ok(response_chunks)
    }

    /// Initiates the association (moves state machine to CookieWait).
    ///
    /// This should be called before `create_init_packet()` on the client side
    /// to properly initialize the state machine for the 4-way handshake.
    pub async fn initiate(&self) -> Vec<StateAction> {
        let mut inner = self.inner.write().await;
        inner.state_machine.process_event(StateEvent::Associate)
    }

    /// Creates an INIT packet to start the handshake.
    ///
    /// Note: Call `initiate()` first to move the state machine to CookieWait.
    pub async fn create_init_packet(&self) -> SctpPacket {
        let mut inner = self.inner.write().await;

        // If we're in Closed state, automatically initiate
        if inner.state() == AssociationState::Closed {
            inner.state_machine.process_event(StateEvent::Associate);
        }

        let init = inner.create_init_chunk();
        let local_port = inner.local_addr.port();
        let peer_port = inner.peer_addr.port();
        drop(inner);

        let mut packet = SctpPacket::new(
            local_port, peer_port, 0, // Verification tag is 0 for INIT
        );
        packet.add_chunk(Chunk::Init(init));
        packet
    }

    /// Gets pending data chunks to send.
    pub async fn get_pending_data(&self) -> Vec<DataChunk> {
        let mut inner = self.inner.write().await;
        let mut chunks = Vec::new();

        // Get available window
        let available = inner
            .paths
            .get_active_path()
            .map_or(0, super::path::Path::available_window);

        let mut total_size = 0u32;

        while let Some(chunk) = inner.send_queue.front() {
            let chunk_size = chunk.data.len() as u32;
            if total_size + chunk_size > available {
                break;
            }

            if let Some(chunk) = inner.send_queue.pop_front() {
                total_size += chunk_size;
                chunks.push(chunk);
            }
        }

        chunks
    }

    /// Confirms the primary path as reachable.
    ///
    /// In normal operation, paths are confirmed via HEARTBEAT-ACK responses
    /// or receiving data. This method allows external code (including tests)
    /// to simulate path confirmation without actual network I/O.
    pub async fn confirm_primary_path(&self) {
        let mut inner = self.inner.write().await;
        if let Some(path) = inner.paths.primary_path_mut() {
            path.confirm();
        }
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

/// TSN comparison with wrap-around (serial number arithmetic).
#[allow(clippy::cast_possible_wrap)] // Intentional wrap-around for serial arithmetic
fn tsn_lt(a: u32, b: u32) -> bool {
    let diff = a.wrapping_sub(b) as i32;
    diff < 0
}

fn tsn_le(a: u32, b: u32) -> bool {
    a == b || tsn_lt(a, b)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn test_config_default() {
        let config = AssociationConfig::default();
        assert_eq!(config.outbound_streams, DEFAULT_STREAMS);
        assert_eq!(config.a_rwnd, DEFAULT_RWND);
        assert!(config.ordered_delivery);
    }

    #[test]
    fn test_association_inner_creation() {
        let inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        assert_eq!(inner.state(), AssociationState::Closed);
        assert!(!inner.is_established());
        assert_ne!(inner.local_verification_tag, 0);
    }

    #[test]
    fn test_init_chunk_creation() {
        let inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        let init = inner.create_init_chunk();

        assert_eq!(init.initiate_tag, inner.local_verification_tag);
        assert_eq!(init.a_rwnd, DEFAULT_RWND);
        assert_eq!(init.num_outbound_streams, DEFAULT_STREAMS);
    }

    #[tokio::test]
    async fn test_association_handle() {
        let handle = AssociationHandle::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        assert_eq!(handle.state().await, AssociationState::Closed);
        assert!(!handle.is_established().await);
    }

    #[test]
    fn test_tsn_comparison() {
        assert!(tsn_lt(1, 2));
        assert!(!tsn_lt(2, 1));
        assert!(!tsn_lt(1, 1));

        // Wrap-around
        assert!(tsn_lt(u32::MAX, 0));
        assert!(!tsn_lt(0, u32::MAX));

        assert!(tsn_le(1, 1));
        assert!(tsn_le(1, 2));
    }
}
