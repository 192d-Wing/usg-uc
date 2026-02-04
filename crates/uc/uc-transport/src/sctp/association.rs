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
    AbortChunk, Chunk, CookieAckChunk, CookieEchoChunk, CwrChunk, DataChunk, EcneChunk, ErrorCause,
    ErrorChunk, HeartbeatAckChunk, HeartbeatChunk, InitAckChunk, InitChunk, InitParam, SackChunk,
    ShutdownAckChunk, ShutdownChunk, ShutdownCompleteChunk,
};
use super::cookie::{CookieData, CookieGenerator};
use super::packet::SctpPacket;
use super::path::{PathId, PathManager};
use super::state::{AssociationState, StateAction, StateEvent, StateMachine};
use super::stream::StreamManager;
use super::timer::TimerManager;
use super::udp_encap::UdpEncapConfig;
use bytes::Bytes;
use std::collections::{BTreeMap, HashSet, VecDeque};
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
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for RTT calculation and path selection in future
struct RetransmitEntry {
    /// The data chunk to retransmit.
    chunk: DataChunk,
    /// When the chunk was first sent (for RTT calculation).
    first_sent: Instant,
    /// When the chunk was last sent.
    last_sent: Instant,
    /// Number of retransmissions.
    retransmit_count: u32,
    /// Path the chunk was sent on (for multi-homing).
    path_id: PathId,
    /// Whether this chunk has been marked for fast retransmit.
    marked_for_fast_retransmit: bool,
    /// Number of times this chunk was reported missing in SACKs.
    miss_indications: u32,
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

        let actions = self
            .state_machine
            .process_event(StateEvent::ReceiveCookieEcho);

        // Start heartbeat timer when association becomes established (server side)
        if self.is_established() {
            self.timers.start_heartbeat();
        }

        Ok(actions)
    }

    /// Processes a received COOKIE-ACK chunk.
    fn process_cookie_ack(&mut self) -> Vec<StateAction> {
        let actions = self
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);

        // Start heartbeat timer when association becomes established
        if self.is_established() {
            self.timers.start_heartbeat();
        }

        actions
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

        // Process acknowledged TSNs (cumulative acknowledgment)
        let bytes_acked = self.acknowledge_tsns(sack.cumulative_tsn_ack);

        // Process gap ack blocks for selective acknowledgment (RFC 9260 Section 6.2.1)
        let gap_bytes_acked = self.process_gap_ack_blocks(sack);

        // Update miss indications for TSNs not acknowledged
        // This implements fast retransmit (RFC 9260 Section 7.2.4)
        self.update_miss_indications(sack);

        // Update congestion control
        if let Some(path) = self.paths.get_active_path_mut() {
            let is_new_ack = sack.cumulative_tsn_ack != self.last_acked_tsn;
            path.on_sack_received(bytes_acked + gap_bytes_acked, is_new_ack, None);
        }

        self.last_acked_tsn = sack.cumulative_tsn_ack;

        // Stop T3-rtx if no outstanding data remains (RFC 9260 Section 6.3.2)
        if !self.has_outstanding_data() {
            self.timers.stop_t3_rtx();
        }
    }

    /// Processes gap ack blocks from a SACK chunk.
    ///
    /// Gap ack blocks indicate TSNs that have been received out of order.
    /// The start and end values are offsets from the cumulative TSN ack.
    /// Returns the total bytes acknowledged via gap blocks.
    fn process_gap_ack_blocks(&mut self, sack: &SackChunk) -> u32 {
        let mut bytes_acked = 0u32;
        let cum_tsn = sack.cumulative_tsn_ack;

        for gap in &sack.gap_ack_blocks {
            // Gap block TSNs are offsets from cumulative TSN ack
            // Start and end are 1-based offsets (RFC 9260 Section 3.3.4)
            let start_tsn = cum_tsn.wrapping_add(u32::from(gap.start));
            let end_tsn = cum_tsn.wrapping_add(u32::from(gap.end));

            // Mark TSNs in range [start_tsn, end_tsn] as acknowledged
            let mut tsn = start_tsn;
            while tsn_le(tsn, end_tsn) {
                if let Some(entry) = self.retransmit_queue.remove(&tsn) {
                    bytes_acked = bytes_acked.saturating_add(entry.chunk.data.len() as u32);
                }
                tsn = tsn.wrapping_add(1);
            }
        }

        bytes_acked
    }

    /// Updates miss indications for TSNs not acknowledged.
    ///
    /// Per RFC 9260 Section 7.2.4, when a SACK arrives that advances the
    /// cumulative TSN ack point or reports gap blocks, increment the miss
    /// indication counter for each TSN that is NOT acknowledged.
    /// When a TSN reaches 3 miss indications, mark it for fast retransmit.
    fn update_miss_indications(&mut self, sack: &SackChunk) {
        let cum_tsn = sack.cumulative_tsn_ack;

        // Build a set of TSNs that are acknowledged (either cumulatively or via gaps)
        let mut acked_tsns = HashSet::new();

        // All TSNs <= cumulative are acked (already removed from queue, but track for logic)
        // Gap blocks acknowledge specific TSNs above cumulative
        for gap in &sack.gap_ack_blocks {
            let start_tsn = cum_tsn.wrapping_add(u32::from(gap.start));
            let end_tsn = cum_tsn.wrapping_add(u32::from(gap.end));
            let mut tsn = start_tsn;
            while tsn_le(tsn, end_tsn) {
                acked_tsns.insert(tsn);
                tsn = tsn.wrapping_add(1);
            }
        }

        // Update miss indications for TSNs still in retransmit queue
        // that are NOT in the gap blocks
        for entry in self.retransmit_queue.values_mut() {
            let tsn = entry.chunk.tsn;
            // Only count miss indications for TSNs above the cumulative ack
            // that are not acknowledged via gap blocks
            if tsn_lt(cum_tsn, tsn) && !acked_tsns.contains(&tsn) {
                entry.miss_indications = entry.miss_indications.saturating_add(1);

                // RFC 9260 Section 7.2.4: Fast Retransmit on 3 missing reports
                if entry.miss_indications >= 3 && !entry.marked_for_fast_retransmit {
                    entry.marked_for_fast_retransmit = true;
                }
            }
        }
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
    ///
    /// If the data exceeds the path MTU, it will be fragmented into multiple
    /// DATA chunks per RFC 9260 Section 6.9.
    fn queue_data(&mut self, stream_id: u16, data: Bytes, ordered: bool) -> Result<u32, String> {
        if !self.is_established() {
            return Err("Association not established".to_string());
        }

        // RFC 9260 Section 6.1: Flow control enforcement
        // Check if we have available receiver window space
        let data_len = data.len() as u32;
        let current_flight = self.flight_size();

        // Calculate available window (peer_rwnd - outstanding data)
        let available_window = self.peer_rwnd.saturating_sub(current_flight);
        if data_len > available_window {
            return Err(format!(
                "Peer receive window exhausted: need {} bytes, only {} available (peer_rwnd={}, flight={})",
                data_len, available_window, self.peer_rwnd, current_flight
            ));
        }

        // Also check congestion window
        if let Some(path) = self.paths.get_active_path() {
            let cwnd = path.congestion().cwnd();
            let cwnd_available = cwnd.saturating_sub(current_flight);
            if data_len > cwnd_available {
                return Err(format!(
                    "Congestion window exhausted: need {} bytes, only {} available (cwnd={}, flight={})",
                    data_len, cwnd_available, cwnd, current_flight
                ));
            }
        }

        // Allocate SSN if ordered
        let ssn = if ordered {
            self.streams.allocate_ssn(stream_id)
        } else {
            0
        };

        // Calculate max DATA chunk payload size
        // MTU - IP header (20/40) - UDP header (8) - SCTP common header (12) - DATA chunk header (16)
        // For simplicity, use a conservative estimate
        let data_chunk_header_size = 16;
        let sctp_header_size = 12;
        let udp_header_size = 8;
        let ip_header_size = 40; // Assume IPv6 worst case
        let max_payload = self.config.path_mtu as usize
            - ip_header_size
            - udp_header_size
            - sctp_header_size
            - data_chunk_header_size;

        // Check if fragmentation is needed
        if data.len() <= max_payload {
            // Single unfragmented message
            let tsn = self.next_tsn;
            self.next_tsn = self.next_tsn.wrapping_add(1);

            let mut chunk = DataChunk::new(tsn, stream_id, ssn, 0, data);
            if !ordered {
                chunk = chunk.with_unordered(true);
            }
            // Mark as both beginning and end (single fragment)
            chunk = chunk.with_fragment(true, true);

            self.send_queue.push_back(chunk);
            return Ok(tsn);
        }

        // Fragmentation required (RFC 9260 Section 6.9)
        let first_tsn = self.next_tsn;
        let mut offset = 0;
        let total_len = data.len();
        let mut is_first = true;

        while offset < total_len {
            let end = (offset + max_payload).min(total_len);
            let is_last = end == total_len;

            let fragment = data.slice(offset..end);
            let tsn = self.next_tsn;
            self.next_tsn = self.next_tsn.wrapping_add(1);

            let mut chunk = DataChunk::new(tsn, stream_id, ssn, 0, fragment);
            if !ordered {
                chunk = chunk.with_unordered(true);
            }
            // Set B and E flags appropriately
            chunk = chunk.with_fragment(is_first, is_last);

            self.send_queue.push_back(chunk);

            is_first = false;
            offset = end;
        }

        Ok(first_tsn)
    }

    /// Adds a sent chunk to the retransmission queue.
    fn add_to_retransmit_queue(&mut self, chunk: DataChunk) {
        let now = Instant::now();
        // Use primary path or create a fallback path ID
        let path_id = self
            .paths
            .primary_path_id()
            .unwrap_or_else(|| PathId::new(self.local_addr, self.peer_addr));

        let entry = RetransmitEntry {
            chunk,
            first_sent: now,
            last_sent: now,
            retransmit_count: 0,
            path_id,
            marked_for_fast_retransmit: false,
            miss_indications: 0,
        };

        self.retransmit_queue.insert(entry.chunk.tsn, entry);

        // Start T3-rtx timer if not already running
        if !self.timers.is_t3_running() {
            self.timers.start_t3_rtx();
        }
    }

    /// Gets chunks that need retransmission due to T3-rtx timeout.
    fn get_retransmit_chunks(&mut self) -> Vec<DataChunk> {
        let mut chunks = Vec::new();
        let now = Instant::now();
        let max_retransmissions = self.config.max_retransmissions;

        // Get chunks that need retransmission
        for entry in self.retransmit_queue.values_mut() {
            // Skip if we've exceeded max retransmissions
            if entry.retransmit_count >= max_retransmissions {
                continue;
            }

            // Include chunk for retransmission
            entry.retransmit_count += 1;
            entry.last_sent = now;
            chunks.push(entry.chunk.clone());
        }

        // Restart T3-rtx timer if we have outstanding data
        if !self.retransmit_queue.is_empty() {
            self.timers.start_t3_rtx();
        }

        chunks
    }

    /// Gets chunks marked for fast retransmit (3 miss indications).
    fn get_fast_retransmit_chunks(&mut self) -> Vec<DataChunk> {
        let mut chunks = Vec::new();
        let now = Instant::now();

        for entry in self.retransmit_queue.values_mut() {
            if entry.miss_indications >= 3 && !entry.marked_for_fast_retransmit {
                entry.marked_for_fast_retransmit = true;
                entry.retransmit_count += 1;
                entry.last_sent = now;
                chunks.push(entry.chunk.clone());
            }
        }

        chunks
    }

    /// Checks if there's outstanding data awaiting acknowledgment.
    fn has_outstanding_data(&self) -> bool {
        !self.retransmit_queue.is_empty()
    }

    /// Gets the flight size (bytes of outstanding data).
    fn flight_size(&self) -> u32 {
        self.retransmit_queue
            .values()
            .map(|e| e.chunk.data.len() as u32)
            .sum()
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

    /// Processes an ERROR chunk (RFC 9260 §3.3.10).
    ///
    /// ERROR chunks are used to report non-fatal errors to the peer.
    /// They do NOT cause association termination - that requires ABORT.
    /// The error causes are logged for diagnostic purposes.
    fn process_error_chunk(&mut self, error: &ErrorChunk) {
        for cause in &error.causes {
            match cause {
                ErrorCause::InvalidStreamIdentifier { stream_id } => {
                    tracing::warn!(
                        stream_id = stream_id,
                        "Peer reported invalid stream identifier"
                    );
                }
                ErrorCause::MissingMandatoryParameter { .. } => {
                    tracing::warn!("Peer reported missing mandatory parameter");
                }
                ErrorCause::StaleCookieError { measure } => {
                    tracing::warn!(
                        staleness_usec = measure,
                        "Peer reported stale cookie"
                    );
                }
                ErrorCause::OutOfResource => {
                    tracing::warn!("Peer reported out of resource");
                }
                ErrorCause::UnresolvableAddress { .. } => {
                    tracing::warn!("Peer reported unresolvable address");
                }
                ErrorCause::UnrecognizedChunkType { chunk } => {
                    // The chunk bytes contain the unrecognized chunk - first byte is the type
                    let chunk_type = chunk.first().copied().unwrap_or(0);
                    tracing::warn!(
                        chunk_type = chunk_type,
                        "Peer reported unrecognized chunk type"
                    );
                }
                ErrorCause::InvalidMandatoryParameter => {
                    tracing::warn!("Peer reported invalid mandatory parameter");
                }
                ErrorCause::UnrecognizedParameters { .. } => {
                    tracing::debug!("Peer reported unrecognized parameters");
                }
                ErrorCause::NoUserData { tsn } => {
                    tracing::warn!(
                        tsn = tsn,
                        "Peer reported DATA chunk with no user data"
                    );
                }
                ErrorCause::CookieReceivedWhileShuttingDown => {
                    tracing::warn!("Peer reported cookie received while shutting down");
                }
                ErrorCause::RestartWithNewAddresses { .. } => {
                    tracing::warn!("Peer reported restart with new addresses");
                }
                ErrorCause::UserInitiatedAbort { .. } => {
                    tracing::info!("Peer reported user-initiated abort");
                }
                ErrorCause::ProtocolViolation { .. } => {
                    tracing::warn!("Peer reported protocol violation");
                }
                ErrorCause::Unknown { cause_code, .. } => {
                    tracing::warn!(
                        cause_code = cause_code,
                        "Peer reported unknown error cause"
                    );
                }
            }
        }
    }

    /// Processes an ECNE chunk (RFC 9260 §7.2.5).
    ///
    /// ECNE (Explicit Congestion Notification Echo) indicates that the peer
    /// received a packet with the CE bit set in the IP header. We must:
    /// 1. Reduce our congestion window (handled by congestion controller)
    /// 2. Send a CWR chunk to acknowledge we received the ECNE
    fn process_ecne(&mut self, ecne: &EcneChunk, response_chunks: &mut Vec<Chunk>) {
        let lowest_tsn = ecne.lowest_tsn;

        tracing::debug!(
            lowest_tsn = lowest_tsn,
            "Received ECNE, reducing congestion window"
        );

        // Update congestion control on the active path
        if let Some(path) = self.paths.get_active_path_mut() {
            let reduced = path.congestion_mut().on_ecn_ce_received();
            if reduced {
                tracing::info!(
                    lowest_tsn = lowest_tsn,
                    cwnd = path.congestion().cwnd(),
                    "Congestion window reduced due to ECN"
                );
            }
        }

        // Send CWR to acknowledge the ECNE
        // The CWR contains the same lowest_tsn that was in the ECNE
        response_chunks.push(Chunk::Cwr(CwrChunk::new(lowest_tsn)));
    }

    /// Processes a CWR chunk (RFC 9260 §7.2.5).
    ///
    /// CWR (Congestion Window Reduced) indicates that the peer has received
    /// our ECNE and reduced its congestion window. This is purely informational
    /// and requires no action other than logging.
    fn process_cwr(&mut self) {
        tracing::debug!("Received CWR, peer has reduced its congestion window");
        // No action required - the CWR is just an acknowledgment
        // that the peer received our ECNE and acted on it
    }
}

// =============================================================================
// Verification Tag Error
// =============================================================================

/// Error type for verification tag validation failures (RFC 9260 §8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTagError {
    /// INIT chunk received with non-zero verification tag.
    InitNonZero,
    /// Verification tag doesn't match local verification tag.
    Mismatch,
    /// ABORT with T-bit set has wrong peer verification tag.
    AbortTBitMismatch,
    /// SHUTDOWN-COMPLETE with T-bit set has wrong peer verification tag.
    ShutdownCompleteTBitMismatch,
}

impl VerificationTagError {
    /// Returns true if this error should trigger an ABORT response.
    #[must_use]
    pub const fn should_send_abort(&self) -> bool {
        // Only send ABORT for clear protocol violations, not for
        // packets that might be from an old/stale association
        matches!(self, Self::InitNonZero)
    }
}

impl std::fmt::Display for VerificationTagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitNonZero => write!(f, "INIT chunk must have verification tag 0"),
            Self::Mismatch => write!(f, "Verification tag does not match local tag"),
            Self::AbortTBitMismatch => {
                write!(f, "ABORT with T-bit set has incorrect peer verification tag")
            }
            Self::ShutdownCompleteTBitMismatch => write!(
                f,
                "SHUTDOWN-COMPLETE with T-bit set has incorrect peer verification tag"
            ),
        }
    }
}

impl std::error::Error for VerificationTagError {}

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

    /// Validates the verification tag according to RFC 9260 §8.5.1.
    ///
    /// Returns Ok(()) if the tag is valid, or Err with an error message if invalid.
    /// Also returns a flag indicating if an ABORT should be sent with T-bit set.
    fn validate_verification_tag(
        &self,
        packet: &SctpPacket,
        inner: &AssociationInner,
    ) -> Result<(), VerificationTagError> {
        // Get the first chunk to determine validation rules
        let first_chunk = packet.chunks.first();

        match first_chunk {
            Some(Chunk::Init(_)) => {
                // RFC 9260 §8.5.1: INIT must have V-tag = 0
                if packet.verification_tag != 0 {
                    return Err(VerificationTagError::InitNonZero);
                }
            }
            Some(Chunk::Abort(abort)) => {
                // RFC 9260 §8.5.1: ABORT handling:
                // - If T-bit is 0, V-tag must match local V-tag
                // - If T-bit is 1 (TCB destroyed), V-tag must match peer's V-tag
                if abort.tcb_destroyed {
                    // T-bit set: verify against peer's tag
                    if inner.peer_verification_tag != 0
                        && packet.verification_tag != inner.peer_verification_tag
                    {
                        return Err(VerificationTagError::AbortTBitMismatch);
                    }
                } else {
                    // T-bit not set: verify against our local tag
                    if packet.verification_tag != inner.local_verification_tag {
                        return Err(VerificationTagError::Mismatch);
                    }
                }
            }
            Some(Chunk::ShutdownComplete(sc)) => {
                // RFC 9260 §8.5.1: SHUTDOWN-COMPLETE handling similar to ABORT
                if sc.tcb_destroyed {
                    // T-bit set: verify against peer's tag
                    if inner.peer_verification_tag != 0
                        && packet.verification_tag != inner.peer_verification_tag
                    {
                        return Err(VerificationTagError::ShutdownCompleteTBitMismatch);
                    }
                } else {
                    // T-bit not set: verify against our local tag
                    if packet.verification_tag != inner.local_verification_tag {
                        return Err(VerificationTagError::Mismatch);
                    }
                }
            }
            Some(Chunk::CookieEcho(_)) => {
                // RFC 9260 §5.1: COOKIE-ECHO can be received before we know
                // our local tag (when we're a server). The tag in the packet
                // should match the tag we put in the cookie.
                // For now, allow any tag for COOKIE-ECHO since the cookie
                // itself contains the verification data.
            }
            _ => {
                // RFC 9260 §8.5.1: All other packets must have V-tag equal to
                // the receiver's local V-tag (the one we sent in INIT/INIT-ACK)
                //
                // Special case: In CookieWait state, we haven't established
                // peer's tag yet, so we check against the INIT-ACK response
                if inner.state() != AssociationState::Closed
                    && inner.state() != AssociationState::CookieWait
                    && packet.verification_tag != inner.local_verification_tag
                {
                    return Err(VerificationTagError::Mismatch);
                }
            }
        }

        Ok(())
    }

    /// Processes a received packet.
    pub async fn process_packet(&self, packet: &SctpPacket) -> Result<Vec<Chunk>, String> {
        let mut inner = self.inner.write().await;
        let mut response_chunks = Vec::new();

        // RFC 9260 §8.5.1: Validate verification tag
        if let Err(vtag_error) = self.validate_verification_tag(packet, &inner) {
            tracing::warn!(
                vtag = packet.verification_tag,
                local_vtag = inner.local_verification_tag,
                peer_vtag = inner.peer_verification_tag,
                error = %vtag_error,
                "Invalid verification tag, discarding packet"
            );

            // For some errors, we may need to send an ABORT with T-bit set
            if vtag_error.should_send_abort() {
                let mut abort = AbortChunk::new();
                abort.tcb_destroyed = true;
                abort.add_cause(ErrorCause::ProtocolViolation {
                    info: bytes::Bytes::from(format!("Invalid verification tag: {vtag_error}")),
                });
                response_chunks.push(Chunk::Abort(abort));
            }

            return if response_chunks.is_empty() {
                Err(format!("Invalid verification tag: {vtag_error}"))
            } else {
                Ok(response_chunks)
            };
        }

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
                Chunk::Error(error_chunk) => {
                    // RFC 9260 §3.3.10: Process ERROR chunk
                    // ERROR chunks report non-fatal errors and do not abort the association
                    inner.process_error_chunk(error_chunk);
                }
                Chunk::Ecne(ecne) => {
                    // RFC 9260 §7.2.5: Process ECNE (Explicit Congestion Notification Echo)
                    inner.process_ecne(ecne, &mut response_chunks);
                }
                Chunk::Cwr(_cwr) => {
                    // RFC 9260 §7.2.5: Process CWR (Congestion Window Reduced)
                    // CWR acknowledges that we received the ECNE and reduced our cwnd
                    inner.process_cwr();
                }
                _ => {
                    // Handle unknown chunks per RFC 9260 §3.2 high-bit rules
                    // TODO: Implement unknown chunk handling with proper error reporting
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

    /// Adds sent chunks to the retransmission queue.
    ///
    /// Call this after successfully sending DATA chunks to track them
    /// for potential retransmission.
    pub async fn track_sent_chunks(&self, chunks: &[DataChunk]) {
        let mut inner = self.inner.write().await;
        for chunk in chunks {
            inner.add_to_retransmit_queue(chunk.clone());
        }
    }

    /// Checks for chunks that need retransmission due to T3-rtx timeout.
    ///
    /// Returns chunks that should be retransmitted. The caller is responsible
    /// for actually sending these chunks over the network.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn check_retransmissions(&self) -> Vec<DataChunk> {
        let mut inner = self.inner.write().await;

        // Check if T3-rtx has expired
        if inner.timers.is_t3_expired() {
            // Record the expiration and apply backoff
            let count = inner
                .timers
                .record_expiration(super::timer::TimerType::T3Rtx);

            // Check if we've exceeded max retransmissions
            if count > inner.config.max_retransmissions {
                // Association failure - should abort
                tracing::warn!(
                    count = count,
                    max = inner.config.max_retransmissions,
                    "T3-rtx exceeded max retransmissions"
                );
                return Vec::new();
            }

            // Update congestion control on timeout
            if let Some(path) = inner.paths.get_active_path_mut() {
                path.congestion_mut().on_timeout();
            }

            return inner.get_retransmit_chunks();
        }

        Vec::new()
    }

    /// Gets chunks marked for fast retransmit.
    ///
    /// Fast retransmit is triggered when a chunk receives 3 or more
    /// miss indications (gap ack blocks that skip it).
    pub async fn get_fast_retransmit_chunks(&self) -> Vec<DataChunk> {
        self.inner.write().await.get_fast_retransmit_chunks()
    }

    /// Returns true if there's outstanding data awaiting acknowledgment.
    pub async fn has_outstanding_data(&self) -> bool {
        self.inner.read().await.has_outstanding_data()
    }

    /// Returns the current flight size (bytes of outstanding data).
    pub async fn flight_size(&self) -> u32 {
        self.inner.read().await.flight_size()
    }

    /// Checks all timers and returns expired timer types.
    pub async fn check_timers(&self) -> Vec<super::timer::TimerType> {
        self.inner.read().await.timers.expired_timers()
    }

    /// Restarts the heartbeat timer after sending a heartbeat.
    ///
    /// Call this after successfully sending a HEARTBEAT chunk.
    pub async fn restart_heartbeat_timer(&self) {
        let mut inner = self.inner.write().await;
        // Record expiration and restart
        inner
            .timers
            .record_expiration(super::timer::TimerType::Heartbeat);
        inner.timers.start_heartbeat();
    }

    /// Starts the T3-rtx timer if there is outstanding data.
    ///
    /// This should be called after sending DATA chunks.
    pub async fn ensure_t3_running(&self) {
        let mut inner = self.inner.write().await;
        if inner.has_outstanding_data() && !inner.timers.is_t3_running() {
            inner.timers.start_t3_rtx();
        }
    }

    /// Stops the T3-rtx timer.
    ///
    /// Called when all outstanding data has been acknowledged.
    pub async fn stop_t3_if_no_data(&self) {
        let mut inner = self.inner.write().await;
        if !inner.has_outstanding_data() {
            inner.timers.stop_t3_rtx();
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a pseudo-random u32.
/// Generates a cryptographically secure random u32.
///
/// Uses the `rand` crate with OS-provided entropy for security-critical
/// values like verification tags and initial TSNs.
fn generate_random_u32() -> u32 {
    use rand::RngCore;
    rand::thread_rng().next_u32()
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
