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
    AbortChunk, AsconfAckChunk, AsconfAckParam, AsconfChunk, AsconfParam, Chunk, CookieAckChunk,
    CookieEchoChunk, CwrChunk, DataChunk, EcneChunk, ErrorCause, ErrorChunk, ForwardTsnChunk,
    GapAckBlock, HeartbeatAckChunk, HeartbeatChunk, InitAckChunk, InitChunk, InitParam,
    ReConfigChunk, ReConfigParam, ReConfigResult, SackChunk, ShutdownAckChunk, ShutdownChunk,
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

// =============================================================================
// INIT Validation Errors (RFC 9260 §5.1.2)
// =============================================================================

/// Errors from INIT/INIT-ACK validation per RFC 9260 §5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitValidationError {
    /// Initiate Tag was 0 (MUST NOT be 0).
    InvalidInitiateTag,
    /// Number of Inbound Streams was 0 (MUST NOT be 0).
    InvalidInboundStreams,
    /// Number of Outbound Streams was 0 (MUST NOT be 0).
    InvalidOutboundStreams,
}

impl std::fmt::Display for InitValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInitiateTag => write!(f, "Initiate Tag must not be 0"),
            Self::InvalidInboundStreams => write!(f, "Number of Inbound Streams must not be 0"),
            Self::InvalidOutboundStreams => write!(f, "Number of Outbound Streams must not be 0"),
        }
    }
}

impl std::error::Error for InitValidationError {}

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
    /// Additional local addresses for multi-homing.
    #[allow(dead_code)] // Used when sending ASCONF to advertise local addresses
    local_addresses: HashSet<SocketAddr>,
    /// Additional peer addresses for multi-homing.
    peer_addresses: HashSet<SocketAddr>,

    // ASCONF state (RFC 5061)
    /// Serial number for outgoing ASCONF chunks.
    asconf_serial_number: u32,
    /// Last received ASCONF serial number from peer.
    peer_asconf_serial_number: Option<u32>,

    // RE-CONFIG state (RFC 6525)
    /// Request sequence number for outgoing RE-CONFIG chunks.
    #[allow(dead_code)] // Used when sending RE-CONFIG requests
    reconfig_req_seq_num: u32,
    /// Last received RE-CONFIG request sequence number from peer.
    peer_reconfig_req_seq_num: Option<u32>,

    // Duplicate TSN tracking (RFC 9260 §6.2)
    /// Set of received TSNs above cumulative (for gap tracking and duplicate detection).
    received_tsns: HashSet<u32>,
    /// Duplicate TSNs to report in the next SACK (cleared after each SACK).
    duplicate_tsns: Vec<u32>,

    // Immediate SACK tracking (RFC 9260 §6.8)
    /// Whether immediate SACK is required (set when I-bit received).
    sack_immediately: bool,

    // SACK bundling state (RFC 9260 §6.2)
    /// Whether a SACK is pending (waiting for timer or bundling opportunity).
    sack_pending: bool,
    /// Number of DATA chunks received since last SACK (for every-other rule).
    data_chunks_since_sack: u32,

    // Heartbeat state (RFC 9260 §8.3)
    /// Whether automatic heartbeat sending is enabled.
    #[allow(dead_code)] // RFC 9260 §8.3 infrastructure - will be used when fully integrated
    heartbeat_enabled: bool,
    /// Time of last data chunk sent (for idle detection).
    #[allow(dead_code)] // RFC 9260 §8.3 infrastructure - will be used when fully integrated
    last_data_sent: Option<std::time::Instant>,

    // PMTU Discovery state (RFC 9260 §8.4)
    /// Current Path MTU.
    pmtu: u32,
    /// Minimum Path MTU (576 for IPv4, 1280 for IPv6).
    pmtu_min: u32,
    /// Maximum Path MTU to probe.
    pmtu_max: u32,
    /// Whether PMTU probing is in progress.
    pmtu_probe_pending: bool,

    // Peer capability tracking (RFC 9260)
    /// Whether peer supports ECN (RFC 9260 §5.1).
    peer_ecn_capable: bool,
    /// Whether peer supports PR-SCTP / Forward TSN (RFC 3758).
    peer_prsctp_capable: bool,
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
            local_addr,
            peer_addr,
            local_addresses: HashSet::new(),
            peer_addresses: HashSet::new(),
            asconf_serial_number: generate_random_u32(),
            peer_asconf_serial_number: None,
            reconfig_req_seq_num: generate_random_u32(),
            peer_reconfig_req_seq_num: None,
            received_tsns: HashSet::new(),
            duplicate_tsns: Vec::new(),
            sack_immediately: false,
            sack_pending: false,
            data_chunks_since_sack: 0,
            heartbeat_enabled: true,
            last_data_sent: None,
            pmtu: config.path_mtu.into(),
            pmtu_min: 576, // IPv4 minimum
            pmtu_max: 1500,
            pmtu_probe_pending: false,
            peer_ecn_capable: false,
            peer_prsctp_capable: false,
            config,
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

    /// Minimum receiver window per RFC 9260 §5.1.2.
    const MIN_RWND: u32 = 1500;

    /// Processes a received INIT chunk with RFC 9260 §5.1.2 validation.
    ///
    /// Validates:
    /// - Initiate Tag MUST NOT be 0
    /// - Number of Inbound Streams MUST NOT be 0
    /// - Number of Outbound Streams MUST NOT be 0
    /// - A-RWND SHOULD NOT be less than 1500
    fn process_init(&mut self, init: &InitChunk) -> Result<Vec<StateAction>, InitValidationError> {
        // RFC 9260 §5.1.2: Initiate Tag MUST NOT be 0
        if init.initiate_tag == 0 {
            return Err(InitValidationError::InvalidInitiateTag);
        }

        // RFC 9260 §5.1.2: Number of Inbound Streams MUST NOT be 0
        if init.num_inbound_streams == 0 {
            return Err(InitValidationError::InvalidInboundStreams);
        }

        // RFC 9260 §5.1.2: Number of Outbound Streams MUST NOT be 0
        if init.num_outbound_streams == 0 {
            return Err(InitValidationError::InvalidOutboundStreams);
        }

        // RFC 9260 §5.1.2: A-RWND SHOULD NOT be less than 1500
        if init.a_rwnd < Self::MIN_RWND {
            tracing::warn!(
                a_rwnd = init.a_rwnd,
                min = Self::MIN_RWND,
                "Peer advertised receiver window below minimum (continuing anyway)"
            );
        }

        // Store peer parameters
        self.peer_verification_tag = init.initiate_tag;
        self.peer_initial_tsn = init.initial_tsn;
        self.peer_cumulative_tsn = init.initial_tsn.wrapping_sub(1);
        self.peer_rwnd = init.a_rwnd;

        // Process optional parameters
        for param in &init.params {
            self.process_init_param(param);
        }

        Ok(self.state_machine.process_event(StateEvent::ReceiveInit))
    }

    /// Processes a received INIT-ACK chunk with RFC 9260 §5.1.2 validation.
    ///
    /// Validates:
    /// - Initiate Tag MUST NOT be 0
    /// - Number of Inbound Streams MUST NOT be 0
    /// - Number of Outbound Streams MUST NOT be 0
    /// - A-RWND SHOULD NOT be less than 1500
    fn process_init_ack(
        &mut self,
        init_ack: &InitAckChunk,
    ) -> Result<Vec<StateAction>, InitValidationError> {
        // RFC 9260 §5.1.2: Initiate Tag MUST NOT be 0
        if init_ack.initiate_tag == 0 {
            return Err(InitValidationError::InvalidInitiateTag);
        }

        // RFC 9260 §5.1.2: Number of Inbound Streams MUST NOT be 0
        if init_ack.num_inbound_streams == 0 {
            return Err(InitValidationError::InvalidInboundStreams);
        }

        // RFC 9260 §5.1.2: Number of Outbound Streams MUST NOT be 0
        if init_ack.num_outbound_streams == 0 {
            return Err(InitValidationError::InvalidOutboundStreams);
        }

        // RFC 9260 §5.1.2: A-RWND SHOULD NOT be less than 1500
        if init_ack.a_rwnd < Self::MIN_RWND {
            tracing::warn!(
                a_rwnd = init_ack.a_rwnd,
                min = Self::MIN_RWND,
                "Peer advertised receiver window below minimum (continuing anyway)"
            );
        }

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

        // Process optional parameters
        for param in &init_ack.params {
            self.process_init_param(param);
        }

        Ok(self.state_machine.process_event(StateEvent::ReceiveInitAck))
    }

    /// Processes an INIT/INIT-ACK parameter (RFC 9260 §5.1.2).
    fn process_init_param(&mut self, param: &InitParam) {
        match param {
            InitParam::Ipv4Address(addr) => {
                // Add peer's additional IPv4 address
                let sock_addr = SocketAddr::new((*addr).into(), self.peer_addr.port());
                self.peer_addresses.insert(sock_addr);
                tracing::debug!(addr = %sock_addr, "Peer advertised additional IPv4 address");
            }
            InitParam::Ipv6Address(addr) => {
                // Add peer's additional IPv6 address
                let sock_addr = SocketAddr::new((*addr).into(), self.peer_addr.port());
                self.peer_addresses.insert(sock_addr);
                tracing::debug!(addr = %sock_addr, "Peer advertised additional IPv6 address");
            }
            InitParam::EcnCapable => {
                tracing::debug!("Peer supports ECN");
                self.peer_ecn_capable = true;
            }
            InitParam::ForwardTsnSupported => {
                tracing::debug!("Peer supports Forward TSN (PR-SCTP)");
                self.peer_prsctp_capable = true;
            }
            InitParam::SupportedAddressTypes(types) => {
                tracing::debug!(types = ?types, "Peer supported address types");
            }
            InitParam::Cookie(_) | InitParam::CookiePreservative(_) => {
                // Handled separately
            }
            InitParam::HostnameAddress(hostname) => {
                // Note: DNS resolution for hostname addresses is not yet implemented.
                // Per RFC 9260, hostname addresses are optional and rarely used in practice.
                tracing::debug!(hostname = %hostname, "Peer hostname address (DNS resolution not implemented)");
            }
            InitParam::Unknown { param_type, .. } => {
                // RFC 9260 §3.2.1: Handle unknown parameters based on high bits
                let action = (*param_type >> 14) & 0x3;
                match action {
                    0 => {
                        // Stop processing and report unrecognized parameter
                        tracing::warn!(param_type = param_type, "Unrecognized parameter, stopping");
                    }
                    1 => {
                        // Stop processing and report unrecognized parameter
                        tracing::warn!(
                            param_type = param_type,
                            "Unrecognized parameter, stopping and reporting"
                        );
                    }
                    2 => {
                        // Skip and continue
                        tracing::debug!(param_type = param_type, "Skipping unrecognized parameter");
                    }
                    3 => {
                        // Skip, continue, and report
                        tracing::debug!(
                            param_type = param_type,
                            "Skipping unrecognized parameter and reporting"
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }
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
    ///
    /// Per RFC 9260 §6.2, implements duplicate TSN detection:
    /// - TSNs <= cumulative TSN are duplicates
    /// - TSNs already in received_tsns set are duplicates
    /// - Duplicate TSNs are recorded for reporting in the next SACK
    ///
    /// Per RFC 9260 §6.8, handles the I-bit (immediate) flag:
    /// - If set, sets `sack_immediately` to bypass delayed SACK
    fn process_data(&mut self, data: DataChunk) -> Result<(), String> {
        if !self.is_established() {
            return Err("Association not established".to_string());
        }

        let tsn = data.tsn;

        // RFC 9260 §6.8: Handle I-bit (immediate acknowledgment requested)
        if data.immediate {
            self.sack_immediately = true;
            tracing::trace!(tsn = tsn, "Immediate flag set, will SACK immediately");
        }

        // RFC 9260 §6.2: Detect duplicate TSNs
        let is_duplicate = if tsn_le(tsn, self.peer_cumulative_tsn) {
            // TSN is at or below cumulative - definitely a duplicate
            true
        } else if self.received_tsns.contains(&tsn) {
            // TSN is above cumulative but already received - duplicate
            true
        } else {
            false
        };

        if is_duplicate {
            // RFC 9260 §6.2: Report duplicate TSN in next SACK
            // Limit to prevent unbounded growth (RFC suggests reasonable limit)
            if self.duplicate_tsns.len() < 16 {
                self.duplicate_tsns.push(tsn);
            }
            tracing::trace!(tsn = tsn, "Duplicate TSN received");
            // Still return Ok - duplicates are not errors, just ignored
            return Ok(());
        }

        // Track this TSN as received (for gap detection)
        self.received_tsns.insert(tsn);

        // Update peer cumulative TSN and clean up received_tsns set
        if tsn == self.peer_cumulative_tsn.wrapping_add(1) {
            self.peer_cumulative_tsn = tsn;
            // Advance cumulative TSN as far as possible
            while self
                .received_tsns
                .remove(&self.peer_cumulative_tsn.wrapping_add(1))
            {
                self.peer_cumulative_tsn = self.peer_cumulative_tsn.wrapping_add(1);
            }
        }

        // Process through stream manager
        self.streams.receive_data(data).map_err(|e| e.to_string())?;

        // Track for SACK bundling (RFC 9260 §6.2)
        self.on_data_received();

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

    /// Creates a SACK chunk for the current state (RFC 9260 §6.2).
    ///
    /// Includes:
    /// - Cumulative TSN acknowledgment
    /// - Gap ack blocks for out-of-order TSNs
    /// - Duplicate TSN reports (clears the duplicate list after)
    ///
    /// Also clears the `sack_immediately` flag (RFC 9260 §6.8).
    fn create_sack(&mut self) -> SackChunk {
        let mut sack = SackChunk::new(self.peer_cumulative_tsn, self.local_rwnd);

        // Build gap ack blocks from received_tsns set
        // Gap blocks are offsets from the cumulative TSN
        let gap_blocks = self.build_gap_ack_blocks();
        for block in gap_blocks {
            sack.add_gap_block(block.start, block.end);
        }

        // Add duplicate TSNs and clear the list
        for dup_tsn in self.duplicate_tsns.drain(..) {
            sack.add_dup_tsn(dup_tsn);
        }

        // RFC 9260 §6.8: Clear immediate SACK flag after sending
        self.sack_immediately = false;

        sack
    }

    /// Returns true if immediate SACK is required (RFC 9260 §6.8).
    ///
    /// This is set when a DATA chunk with the I-bit (immediate) flag is received.
    /// The caller should send a SACK immediately instead of using delayed SACK.
    fn should_sack_immediately(&self) -> bool {
        self.sack_immediately
    }

    // =========================================================================
    // SACK Bundling (RFC 9260 §6.2)
    // =========================================================================

    /// Called when a DATA chunk is received to track SACK timing.
    ///
    /// Per RFC 9260 §6.2:
    /// - A SACK SHOULD be sent for every second DATA chunk received.
    /// - If delayed, the SACK MUST be sent within 200ms of the first unacknowledged DATA.
    fn on_data_received(&mut self) {
        self.data_chunks_since_sack += 1;
        self.sack_pending = true;

        // RFC 9260 §6.2: Send SACK for every second DATA chunk received.
        // Note: The I-bit (immediate) flag is handled separately in process_data().
        // Gap ack block reporting is checked in should_send_sack().
        if self.data_chunks_since_sack >= 2 {
            self.sack_immediately = true;
        }

        // Start delayed SACK timer if not already running
        if !self.timers.is_t4_sack_expired() {
            self.timers.start_t4_sack();
        }
    }

    /// Returns true if a SACK should be sent now (RFC 9260 §6.2).
    ///
    /// A SACK should be sent if:
    /// - Immediate SACK is required (I-bit was set)
    /// - Two or more DATA chunks have been received since last SACK
    /// - The delayed SACK timer (T4-sack, 200ms) has expired
    /// - Gap ack blocks need to be reported
    fn should_send_sack(&self) -> bool {
        if !self.sack_pending {
            return false;
        }

        // Immediate SACK requested via I-bit
        if self.sack_immediately {
            return true;
        }

        // Every-other-DATA rule: SACK after every 2nd DATA chunk
        if self.data_chunks_since_sack >= 2 {
            return true;
        }

        // Delayed SACK timer expired
        if self.timers.is_t4_sack_expired() {
            return true;
        }

        // Gap blocks present (out-of-order data received)
        if !self.received_tsns.is_empty() {
            return true;
        }

        false
    }

    /// Creates a SACK and resets the bundling state.
    ///
    /// This should be called when `should_send_sack()` returns true.
    fn create_sack_and_reset(&mut self) -> SackChunk {
        let sack = self.create_sack();

        // Reset SACK bundling state
        self.sack_pending = false;
        self.data_chunks_since_sack = 0;
        self.timers.stop_t4_sack();

        sack
    }

    /// Tries to bundle a SACK with outgoing DATA (RFC 9260 §6.2).
    ///
    /// Returns Some(SackChunk) if a SACK should be bundled with the DATA,
    /// or None if no SACK is needed.
    ///
    /// This implements the RFC recommendation to bundle SACKs with DATA
    /// whenever possible to reduce packet overhead.
    fn try_bundle_sack(&mut self) -> Option<SackChunk> {
        if self.sack_pending {
            Some(self.create_sack_and_reset())
        } else {
            None
        }
    }

    // =========================================================================
    // Automatic Heartbeat (RFC 9260 §8.3)
    // =========================================================================

    /// Checks if a HEARTBEAT should be sent to an idle path.
    ///
    /// Per RFC 9260 §8.3, HEARTBEAT chunks should be sent periodically
    /// to verify peer reachability when no DATA is being sent.
    #[allow(dead_code)] // RFC 9260 §8.3 infrastructure - will be used when fully integrated
    fn should_send_heartbeat(&self) -> bool {
        if !self.heartbeat_enabled || !self.is_established() {
            return false;
        }

        // Check if heartbeat timer has expired
        let expired = self.timers.expired_timers();
        expired.contains(&super::timer::TimerType::Heartbeat)
    }

    // =========================================================================
    // Path MTU Discovery (RFC 9260 §8.4)
    // =========================================================================

    /// Returns the current Path MTU.
    fn path_mtu(&self) -> u32 {
        self.pmtu
    }

    /// Starts PMTU probing by sending a PAD chunk.
    ///
    /// Per RFC 9260 §8.4, PMTU can be discovered by sending packets
    /// of increasing size and observing ICMP Packet Too Big messages.
    fn start_pmtu_probe(&mut self, probe_size: u32) -> Option<super::chunk::PadChunk> {
        if self.pmtu_probe_pending || probe_size <= self.pmtu {
            return None;
        }

        let padding_size = probe_size.saturating_sub(super::packet::HEADER_SIZE as u32 + 4);
        if padding_size == 0 {
            return None;
        }

        self.pmtu_probe_pending = true;
        Some(super::chunk::PadChunk::new(padding_size as usize))
    }

    /// Called when PMTU probe succeeds (no ICMP error received).
    fn on_pmtu_probe_success(&mut self, probe_size: u32) {
        if probe_size > self.pmtu {
            self.pmtu = probe_size.min(self.pmtu_max);
            tracing::info!(new_pmtu = self.pmtu, "PMTU increased");
        }
        self.pmtu_probe_pending = false;
    }

    /// Called when PMTU probe fails (ICMP Packet Too Big received).
    fn on_pmtu_probe_failure(&mut self, new_mtu: u32) {
        self.pmtu = new_mtu.max(self.pmtu_min);
        self.pmtu_probe_pending = false;
        tracing::info!(new_pmtu = self.pmtu, "PMTU decreased");
    }

    /// Builds gap ack blocks from the received TSNs set.
    ///
    /// Gap ack blocks indicate ranges of TSNs that have been received
    /// above the cumulative TSN ack. The start/end values are offsets
    /// from the cumulative TSN ack (1-based, per RFC 9260 §3.3.4).
    fn build_gap_ack_blocks(&self) -> Vec<GapAckBlock> {
        if self.received_tsns.is_empty() {
            return Vec::new();
        }

        // Sort TSNs relative to cumulative TSN
        let cum_tsn = self.peer_cumulative_tsn;
        let mut offsets: Vec<u32> = self
            .received_tsns
            .iter()
            .filter_map(|&tsn| {
                // Calculate offset from cumulative TSN
                let offset = tsn.wrapping_sub(cum_tsn);
                // Only include TSNs above cumulative (offset > 0)
                // and within u16 range (RFC limits)
                if offset > 0 && offset <= u32::from(u16::MAX) {
                    Some(offset)
                } else {
                    None
                }
            })
            .collect();

        offsets.sort_unstable();

        // Build contiguous blocks
        let mut blocks = Vec::new();
        let mut iter = offsets.into_iter();

        if let Some(first) = iter.next() {
            let mut start = first;
            let mut end = first;

            for offset in iter {
                if offset == end + 1 {
                    // Extend current block
                    end = offset;
                } else {
                    // Save current block, start new one
                    blocks.push(GapAckBlock {
                        start: start as u16,
                        end: end as u16,
                    });
                    start = offset;
                    end = offset;
                }
            }

            // Don't forget the last block
            blocks.push(GapAckBlock {
                start: start as u16,
                end: end as u16,
            });
        }

        // RFC 9260 recommends limiting gap blocks (typically 4)
        if blocks.len() > 4 {
            blocks.truncate(4);
        }

        blocks
    }

    /// Creates a simple HEARTBEAT chunk with timestamp for RTT measurement.
    ///
    /// Note: For multi-path heartbeats, use `AssociationHandle::create_heartbeat_for_path`
    /// instead, which includes path identification info.
    #[allow(dead_code)] // Kept for potential direct use, prefer create_heartbeat_for_path
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
                    tracing::warn!(staleness_usec = measure, "Peer reported stale cookie");
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
                    tracing::warn!(tsn = tsn, "Peer reported DATA chunk with no user data");
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
                    tracing::warn!(cause_code = cause_code, "Peer reported unknown error cause");
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

    /// Processes an ASCONF chunk (RFC 5061).
    ///
    /// ASCONF chunks allow dynamic address configuration changes during
    /// an established association. This includes:
    /// - ADD-IP: Add a new IP address to the association
    /// - DELETE-IP: Remove an IP address from the association
    /// - SET-PRIMARY: Change the primary destination address
    ///
    /// Returns an ASCONF-ACK chunk with the results of each operation.
    fn process_asconf(&mut self, asconf: &AsconfChunk) -> AsconfAckChunk {
        let serial = asconf.serial_number;

        // RFC 5061 §5.2: Check serial number to detect duplicates and ordering
        if let Some(peer_serial) = self.peer_asconf_serial_number {
            // Serial numbers use serial number arithmetic (like TSN)
            let diff = serial.wrapping_sub(peer_serial) as i32;

            if diff < 0 {
                // Old ASCONF - already processed, return empty ACK
                tracing::debug!(
                    serial = serial,
                    last_serial = peer_serial,
                    "Ignoring old ASCONF (already processed)"
                );
                return AsconfAckChunk::new(serial);
            } else if diff == 0 {
                // Duplicate - peer didn't receive our ACK, resend
                tracing::debug!(
                    serial = serial,
                    "Received duplicate ASCONF, will resend ACK"
                );
                // Fall through to reprocess
            }
            // diff > 0 means new ASCONF
        }

        // Update the last received serial number
        self.peer_asconf_serial_number = Some(serial);

        let mut ack = AsconfAckChunk::new(serial);

        // Process each parameter in order
        for param in &asconf.params {
            let result = self.process_asconf_param(param);
            ack.params.push(result);
        }

        ack
    }

    /// Processes a single ASCONF parameter and returns the result.
    fn process_asconf_param(&mut self, param: &AsconfParam) -> AsconfAckParam {
        // RFC 9260 error cause codes
        const ERROR_INVALID_MANDATORY_PARAMETER: u16 = 7;
        const ERROR_UNRESOLVABLE_ADDRESS: u16 = 5;

        match param {
            AsconfParam::AddIp {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                // RFC 5061 §4.2.1: ADD IP Address
                let addr = if let Some(ip) = ipv4 {
                    // Use default SCTP port (could be tracked per-address)
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else if let Some(ip) = ipv6 {
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else {
                    None
                };

                if let Some(addr) = addr {
                    if self.peer_addresses.contains(&addr) || addr == self.peer_addr {
                        // Address already exists
                        tracing::debug!(addr = %addr, "ADD-IP: Address already exists");
                        AsconfAckParam::Success {
                            correlation_id: *correlation_id,
                        }
                    } else {
                        // Add the new address
                        self.peer_addresses.insert(addr);

                        // Add path for multi-homing
                        self.paths.add_path(self.local_addr, addr);

                        tracing::info!(addr = %addr, "ADD-IP: Added new peer address");
                        AsconfAckParam::Success {
                            correlation_id: *correlation_id,
                        }
                    }
                } else {
                    // No valid address provided
                    tracing::warn!("ADD-IP: No valid address in parameter");
                    AsconfAckParam::ErrorCause {
                        correlation_id: *correlation_id,
                        error_code: ERROR_INVALID_MANDATORY_PARAMETER,
                        error_info: Bytes::new(),
                    }
                }
            }

            AsconfParam::DeleteIp {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                // RFC 5061 §4.2.2: DELETE IP Address
                let addr = if let Some(ip) = ipv4 {
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else if let Some(ip) = ipv6 {
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else {
                    None
                };

                if let Some(addr) = addr {
                    // RFC 5061 §4.2.2: Cannot delete the last address
                    if self.peer_addresses.is_empty() && addr == self.peer_addr {
                        tracing::warn!(addr = %addr, "DELETE-IP: Cannot delete last remaining address");
                        AsconfAckParam::ErrorCause {
                            correlation_id: *correlation_id,
                            error_code: ERROR_INVALID_MANDATORY_PARAMETER,
                            error_info: Bytes::from_static(b"cannot delete last address"),
                        }
                    } else if addr == self.peer_addr {
                        // Deleting primary - must have alternates
                        if self.peer_addresses.is_empty() {
                            tracing::warn!("DELETE-IP: Cannot delete primary with no alternates");
                            AsconfAckParam::ErrorCause {
                                correlation_id: *correlation_id,
                                error_code: ERROR_INVALID_MANDATORY_PARAMETER,
                                error_info: Bytes::from_static(
                                    b"cannot delete primary without alternates",
                                ),
                            }
                        } else {
                            // Pick a new primary from the peer addresses
                            if let Some(&new_primary) = self.peer_addresses.iter().next() {
                                self.peer_addr = new_primary;
                                self.peer_addresses.remove(&new_primary);
                                tracing::info!(
                                    old_addr = %addr,
                                    new_primary = %new_primary,
                                    "DELETE-IP: Deleted primary, new primary selected"
                                );
                            }
                            AsconfAckParam::Success {
                                correlation_id: *correlation_id,
                            }
                        }
                    } else if self.peer_addresses.remove(&addr) {
                        // Remove the path
                        let path_id = PathId::new(self.local_addr, addr);
                        self.paths.remove_path(path_id);

                        tracing::info!(addr = %addr, "DELETE-IP: Removed peer address");
                        AsconfAckParam::Success {
                            correlation_id: *correlation_id,
                        }
                    } else {
                        // Address not found
                        tracing::debug!(addr = %addr, "DELETE-IP: Address not found");
                        AsconfAckParam::ErrorCause {
                            correlation_id: *correlation_id,
                            error_code: ERROR_UNRESOLVABLE_ADDRESS,
                            error_info: Bytes::new(),
                        }
                    }
                } else {
                    tracing::warn!("DELETE-IP: No valid address in parameter");
                    AsconfAckParam::ErrorCause {
                        correlation_id: *correlation_id,
                        error_code: ERROR_INVALID_MANDATORY_PARAMETER,
                        error_info: Bytes::new(),
                    }
                }
            }

            AsconfParam::SetPrimaryAddress {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                // RFC 5061 §4.2.3: SET PRIMARY Address
                let addr = if let Some(ip) = ipv4 {
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else if let Some(ip) = ipv6 {
                    Some(SocketAddr::from((*ip, self.peer_addr.port())))
                } else {
                    None
                };

                if let Some(addr) = addr {
                    if addr == self.peer_addr {
                        // Already the primary
                        tracing::debug!(addr = %addr, "SET-PRIMARY: Already primary");
                        AsconfAckParam::Success {
                            correlation_id: *correlation_id,
                        }
                    } else if self.peer_addresses.contains(&addr) {
                        // Move current primary to peer_addresses
                        let old_primary = self.peer_addr;
                        self.peer_addresses.insert(old_primary);
                        self.peer_addresses.remove(&addr);
                        self.peer_addr = addr;

                        // Update path manager primary
                        let path_id = PathId::new(self.local_addr, addr);
                        self.paths.set_primary_path(path_id);

                        tracing::info!(
                            old_primary = %old_primary,
                            new_primary = %addr,
                            "SET-PRIMARY: Changed primary address"
                        );
                        AsconfAckParam::Success {
                            correlation_id: *correlation_id,
                        }
                    } else {
                        // Address not known
                        tracing::warn!(addr = %addr, "SET-PRIMARY: Address not known");
                        AsconfAckParam::ErrorCause {
                            correlation_id: *correlation_id,
                            error_code: ERROR_UNRESOLVABLE_ADDRESS,
                            error_info: Bytes::new(),
                        }
                    }
                } else {
                    tracing::warn!("SET-PRIMARY: No valid address in parameter");
                    AsconfAckParam::ErrorCause {
                        correlation_id: *correlation_id,
                        error_code: ERROR_INVALID_MANDATORY_PARAMETER,
                        error_info: Bytes::new(),
                    }
                }
            }
        }
    }

    /// Processes an ASCONF-ACK chunk (RFC 5061).
    ///
    /// ASCONF-ACK confirms the result of our ASCONF request.
    /// Each parameter in the ACK corresponds to a parameter we sent.
    fn process_asconf_ack(&mut self, asconf_ack: &AsconfAckChunk) {
        let serial = asconf_ack.serial_number;

        tracing::debug!(
            serial = serial,
            num_params = asconf_ack.params.len(),
            "Received ASCONF-ACK"
        );

        for (i, param) in asconf_ack.params.iter().enumerate() {
            match param {
                AsconfAckParam::Success { correlation_id } => {
                    tracing::debug!(
                        index = i,
                        correlation_id = correlation_id,
                        "ASCONF param succeeded"
                    );
                }
                AsconfAckParam::ErrorCause {
                    correlation_id,
                    error_code,
                    ..
                } => {
                    tracing::warn!(
                        index = i,
                        correlation_id = correlation_id,
                        error_code = error_code,
                        "ASCONF param failed"
                    );
                }
            }
        }
    }

    /// Creates an ASCONF chunk to add a new local address.
    #[allow(dead_code)] // Will be used by public API
    fn create_add_ip_asconf(&mut self, addr: SocketAddr) -> AsconfChunk {
        let serial = self.asconf_serial_number;
        self.asconf_serial_number = self.asconf_serial_number.wrapping_add(1);

        let correlation_id = generate_random_u32();
        let param = match addr {
            SocketAddr::V4(v4) => AsconfParam::AddIp {
                correlation_id,
                ipv4: Some(*v4.ip()),
                ipv6: None,
            },
            SocketAddr::V6(v6) => AsconfParam::AddIp {
                correlation_id,
                ipv4: None,
                ipv6: Some(*v6.ip()),
            },
        };

        let chunk = AsconfChunk::new(serial);
        // Set sender address based on local address type
        let mut chunk = match self.local_addr {
            SocketAddr::V4(v4) => chunk.with_sender_ipv4(*v4.ip()),
            SocketAddr::V6(v6) => chunk.with_sender_ipv6(*v6.ip()),
        };
        chunk.params.push(param);
        chunk
    }

    /// Creates an ASCONF chunk to delete a local address.
    #[allow(dead_code)] // Will be used by public API
    fn create_delete_ip_asconf(&mut self, addr: SocketAddr) -> AsconfChunk {
        let serial = self.asconf_serial_number;
        self.asconf_serial_number = self.asconf_serial_number.wrapping_add(1);

        let correlation_id = generate_random_u32();
        let param = match addr {
            SocketAddr::V4(v4) => AsconfParam::DeleteIp {
                correlation_id,
                ipv4: Some(*v4.ip()),
                ipv6: None,
            },
            SocketAddr::V6(v6) => AsconfParam::DeleteIp {
                correlation_id,
                ipv4: None,
                ipv6: Some(*v6.ip()),
            },
        };

        let chunk = AsconfChunk::new(serial);
        // Set sender address based on local address type
        let mut chunk = match self.local_addr {
            SocketAddr::V4(v4) => chunk.with_sender_ipv4(*v4.ip()),
            SocketAddr::V6(v6) => chunk.with_sender_ipv6(*v6.ip()),
        };
        chunk.params.push(param);
        chunk
    }

    /// Creates an ASCONF chunk to set a new primary address.
    #[allow(dead_code)] // Will be used by public API
    fn create_set_primary_asconf(&mut self, addr: SocketAddr) -> AsconfChunk {
        let serial = self.asconf_serial_number;
        self.asconf_serial_number = self.asconf_serial_number.wrapping_add(1);

        let correlation_id = generate_random_u32();
        let param = match addr {
            SocketAddr::V4(v4) => AsconfParam::SetPrimaryAddress {
                correlation_id,
                ipv4: Some(*v4.ip()),
                ipv6: None,
            },
            SocketAddr::V6(v6) => AsconfParam::SetPrimaryAddress {
                correlation_id,
                ipv4: None,
                ipv6: Some(*v6.ip()),
            },
        };

        let chunk = AsconfChunk::new(serial);
        // Set sender address based on local address type
        let mut chunk = match self.local_addr {
            SocketAddr::V4(v4) => chunk.with_sender_ipv4(*v4.ip()),
            SocketAddr::V6(v6) => chunk.with_sender_ipv6(*v6.ip()),
        };
        chunk.params.push(param);
        chunk
    }

    /// Processes a FORWARD-TSN chunk (RFC 3758).
    ///
    /// FORWARD-TSN advances the cumulative TSN to skip abandoned data.
    /// This is used for partial reliability extensions where data may be
    /// abandoned due to lifetime expiration or other policies.
    fn process_forward_tsn(&mut self, ftsn: &ForwardTsnChunk) {
        let new_cum_tsn = ftsn.new_cumulative_tsn;

        // RFC 3758 §3.6: The receiver should advance its cumulative TSN
        // point if the FORWARD-TSN chunk indicates TSNs that should be skipped.

        // Only advance if the new cumulative TSN is ahead of our current
        if tsn_lt(self.peer_cumulative_tsn, new_cum_tsn) {
            tracing::debug!(
                old_cum_tsn = self.peer_cumulative_tsn,
                new_cum_tsn = new_cum_tsn,
                skipped_streams = ftsn.streams.len(),
                "Advancing cumulative TSN via FORWARD-TSN"
            );

            self.peer_cumulative_tsn = new_cum_tsn;

            // Update stream sequence numbers for affected streams
            // This ensures we don't wait for the skipped ordered data
            for stream_info in &ftsn.streams {
                self.streams
                    .advance_peer_ssn(stream_info.stream_id, stream_info.ssn);
            }
        } else {
            tracing::debug!(
                our_cum_tsn = self.peer_cumulative_tsn,
                fwd_tsn = new_cum_tsn,
                "Ignoring FORWARD-TSN with old cumulative TSN"
            );
        }
    }

    /// Processes a RE-CONFIG chunk (RFC 6525).
    ///
    /// RE-CONFIG chunks allow stream reconfiguration during an association:
    /// - Resetting SSN for specific streams
    /// - Adding new outgoing/incoming streams
    ///
    /// Returns a RE-CONFIG response chunk if applicable.
    fn process_reconfig(&mut self, reconfig: &ReConfigChunk) -> Option<ReConfigChunk> {
        let mut response_params = Vec::new();

        for param in &reconfig.params {
            match param {
                ReConfigParam::OutgoingSsnReset {
                    req_seq_num,
                    stream_ids,
                    ..
                } => {
                    // RFC 6525 §5.2.2: Process outgoing SSN reset request
                    // This resets the SSN for the specified streams on the sender side
                    // We need to reset our expected SSN for those streams

                    tracing::debug!(
                        req_seq_num = req_seq_num,
                        streams = ?stream_ids,
                        "Processing outgoing SSN reset request"
                    );

                    // Check sequence number to prevent replays
                    if let Some(peer_seq) = self.peer_reconfig_req_seq_num {
                        let diff = req_seq_num.wrapping_sub(peer_seq) as i32;
                        if diff <= 0 {
                            // Old or duplicate request
                            response_params.push(ReConfigParam::Response {
                                resp_seq_num: *req_seq_num,
                                result: ReConfigResult::ErrorBadSeqNum,
                                sender_next_tsn: None,
                                receiver_next_tsn: None,
                            });
                            continue;
                        }
                    }

                    self.peer_reconfig_req_seq_num = Some(*req_seq_num);

                    // Reset the expected SSN for each specified stream
                    if stream_ids.is_empty() {
                        // Reset all streams
                        self.streams.reset();
                    } else {
                        for &stream_id in stream_ids {
                            if let Some(stream) = self.streams.get_stream_mut(stream_id) {
                                stream.reset();
                            }
                        }
                    }

                    response_params.push(ReConfigParam::Response {
                        resp_seq_num: *req_seq_num,
                        result: ReConfigResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    });
                }

                ReConfigParam::IncomingSsnReset {
                    req_seq_num,
                    stream_ids,
                } => {
                    // RFC 6525 §5.2.1: Process incoming SSN reset request
                    // The peer wants us to reset our outgoing SSN for these streams

                    tracing::debug!(
                        req_seq_num = req_seq_num,
                        streams = ?stream_ids,
                        "Processing incoming SSN reset request"
                    );

                    // Check sequence number
                    if let Some(peer_seq) = self.peer_reconfig_req_seq_num {
                        let diff = req_seq_num.wrapping_sub(peer_seq) as i32;
                        if diff <= 0 {
                            response_params.push(ReConfigParam::Response {
                                resp_seq_num: *req_seq_num,
                                result: ReConfigResult::ErrorBadSeqNum,
                                sender_next_tsn: None,
                                receiver_next_tsn: None,
                            });
                            continue;
                        }
                    }

                    self.peer_reconfig_req_seq_num = Some(*req_seq_num);

                    // Reset our outgoing SSN for these streams
                    for &stream_id in stream_ids {
                        if let Some(stream) = self.streams.get_stream_mut(stream_id) {
                            stream.reset();
                        }
                    }

                    response_params.push(ReConfigParam::Response {
                        resp_seq_num: *req_seq_num,
                        result: ReConfigResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    });
                }

                ReConfigParam::SsnTsnReset { req_seq_num } => {
                    // RFC 6525 §5.2.3: Process SSN/TSN reset request
                    // This resets both SSN and TSN - a complete reset

                    tracing::info!(
                        req_seq_num = req_seq_num,
                        "Processing SSN/TSN reset request"
                    );

                    // Check sequence number
                    if let Some(peer_seq) = self.peer_reconfig_req_seq_num {
                        let diff = req_seq_num.wrapping_sub(peer_seq) as i32;
                        if diff <= 0 {
                            response_params.push(ReConfigParam::Response {
                                resp_seq_num: *req_seq_num,
                                result: ReConfigResult::ErrorBadSeqNum,
                                sender_next_tsn: None,
                                receiver_next_tsn: None,
                            });
                            continue;
                        }
                    }

                    self.peer_reconfig_req_seq_num = Some(*req_seq_num);

                    // Reset all streams
                    self.streams.reset();

                    // Generate new TSNs
                    let sender_next_tsn = self.next_tsn;
                    let receiver_next_tsn = self.peer_cumulative_tsn.wrapping_add(1);

                    response_params.push(ReConfigParam::Response {
                        resp_seq_num: *req_seq_num,
                        result: ReConfigResult::SuccessPerformed,
                        sender_next_tsn: Some(sender_next_tsn),
                        receiver_next_tsn: Some(receiver_next_tsn),
                    });
                }

                ReConfigParam::AddOutgoingStreams {
                    req_seq_num,
                    num_streams,
                } => {
                    // RFC 6525 §5.2.5: Process add outgoing streams request
                    tracing::debug!(
                        req_seq_num = req_seq_num,
                        num_streams = num_streams,
                        "Processing add outgoing streams request"
                    );

                    // For now, just acknowledge (actual stream limit checking could be added)
                    self.peer_reconfig_req_seq_num = Some(*req_seq_num);

                    response_params.push(ReConfigParam::Response {
                        resp_seq_num: *req_seq_num,
                        result: ReConfigResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    });
                }

                ReConfigParam::AddIncomingStreams {
                    req_seq_num,
                    num_streams,
                } => {
                    // RFC 6525 §5.2.6: Process add incoming streams request
                    tracing::debug!(
                        req_seq_num = req_seq_num,
                        num_streams = num_streams,
                        "Processing add incoming streams request"
                    );

                    self.peer_reconfig_req_seq_num = Some(*req_seq_num);

                    response_params.push(ReConfigParam::Response {
                        resp_seq_num: *req_seq_num,
                        result: ReConfigResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    });
                }

                ReConfigParam::Response {
                    resp_seq_num,
                    result,
                    ..
                } => {
                    // This is a response to our request
                    tracing::debug!(
                        resp_seq_num = resp_seq_num,
                        result = ?result,
                        "Received RE-CONFIG response"
                    );
                    // No response needed for responses
                }
            }
        }

        if response_params.is_empty() {
            None
        } else {
            let mut response = ReConfigChunk::new();
            response.params = response_params;
            Some(response)
        }
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
                write!(
                    f,
                    "ABORT with T-bit set has incorrect peer verification tag"
                )
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
                    // RFC 9260 §5.1.2: Validate INIT parameters
                    match inner.process_init(init) {
                        Ok(actions) => {
                            for action in actions {
                                if action == StateAction::SendInitAck {
                                    let (init_ack, _) = inner.create_init_ack_chunk(init);
                                    response_chunks.push(Chunk::InitAck(init_ack));
                                }
                            }
                        }
                        Err(e) => {
                            // RFC 9260 §5.1.2: Invalid INIT - send ABORT
                            tracing::warn!(error = %e, "Invalid INIT received, aborting");
                            let mut abort = AbortChunk::new();
                            abort.add_cause(ErrorCause::InvalidMandatoryParameter);
                            response_chunks.push(Chunk::Abort(abort));
                        }
                    }
                }
                Chunk::InitAck(init_ack) => {
                    // RFC 9260 §5.1.2: Validate INIT-ACK parameters
                    match inner.process_init_ack(init_ack) {
                        Ok(actions) => {
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
                        Err(e) => {
                            // RFC 9260 §5.1.2: Invalid INIT-ACK - abort
                            tracing::warn!(error = %e, "Invalid INIT-ACK received, aborting");
                            let _ = inner.abort();
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
                    // RFC 9260 §6.2: Use delayed/bundled SACK unless immediate is required
                    if inner.should_send_sack() {
                        let sack = inner.create_sack_and_reset();
                        response_chunks.push(Chunk::Sack(sack));
                    }
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
                Chunk::Asconf(asconf) => {
                    // RFC 5061: Process ASCONF (Address Configuration Change)
                    let asconf_ack = inner.process_asconf(asconf);
                    response_chunks.push(Chunk::AsconfAck(asconf_ack));
                }
                Chunk::AsconfAck(asconf_ack) => {
                    // RFC 5061: Process ASCONF-ACK (Address Configuration Acknowledgement)
                    inner.process_asconf_ack(asconf_ack);
                }
                Chunk::ForwardTsn(ftsn) => {
                    // RFC 3758: Process FORWARD-TSN (Partial Reliability)
                    inner.process_forward_tsn(ftsn);
                    // Mark SACK as needed (FORWARD-TSN advances cumulative TSN)
                    inner.sack_pending = true;
                    inner.sack_immediately = true; // FORWARD-TSN should be acknowledged quickly
                    if inner.should_send_sack() {
                        let sack = inner.create_sack_and_reset();
                        response_chunks.push(Chunk::Sack(sack));
                    }
                }
                Chunk::ReConfig(reconfig) => {
                    // RFC 6525: Process RE-CONFIG (Stream Reconfiguration)
                    if let Some(response) = inner.process_reconfig(reconfig) {
                        response_chunks.push(Chunk::ReConfig(response));
                    }
                }
                Chunk::Unknown(unknown) => {
                    // Handle unknown chunks per RFC 9260 §3.2 high-bit rules
                    let action = super::chunk::UnknownChunkAction::from_chunk_type(unknown.chunk_type);
                    tracing::debug!(
                        chunk_type = unknown.chunk_type,
                        action = ?action,
                        "Received unknown chunk"
                    );

                    if action.should_report() {
                        // Report unrecognized chunk type in ERROR chunk
                        let error = ErrorChunk::new(vec![ErrorCause::UnrecognizedChunkType {
                            chunk: unknown.clone(),
                        }]);
                        response_chunks.push(Chunk::Error(error));
                    }

                    if action.should_stop() {
                        // Stop processing further chunks in this packet
                        break;
                    }
                    // Otherwise skip and continue processing
                }
                _ => {
                    // All known chunk types should be handled above
                    tracing::warn!("Unhandled chunk type in process_packet");
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

    /// Gets paths that need heartbeats sent (RFC 9260 §8.3).
    ///
    /// Returns a list of (PathId, remote address) tuples for paths where
    /// the heartbeat interval has elapsed since the last heartbeat was sent.
    ///
    /// Per RFC 9260 §8.3, an endpoint should send HEARTBEAT chunks to each
    /// of the transport addresses of a peer endpoint, per heartbeat interval.
    pub async fn get_heartbeat_targets(&self) -> Vec<(PathId, SocketAddr)> {
        self.inner.read().await.paths.heartbeat_targets()
    }

    /// Marks a path as having sent a heartbeat (RFC 9260 §8.3).
    ///
    /// Call this after successfully sending a HEARTBEAT chunk to a specific path.
    /// This records the send time so the path won't need another heartbeat
    /// until the heartbeat interval elapses.
    pub async fn mark_heartbeat_sent(&self, path_id: PathId) {
        self.inner.write().await.paths.mark_heartbeat_sent(path_id);
    }

    /// Creates a HEARTBEAT chunk with sender address for path verification.
    ///
    /// The heartbeat info contains a timestamp for RTT measurement and
    /// the path ID for identifying which path this heartbeat is for when
    /// the HEARTBEAT-ACK is received.
    pub async fn create_heartbeat_for_path(&self, path_id: PathId) -> HeartbeatChunk {
        let inner = self.inner.read().await;
        // Include timestamp for RTT measurement
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Encode path ID info: timestamp (8 bytes) + local addr + remote addr
        // This allows us to identify the path when HEARTBEAT-ACK returns
        let mut info = Vec::with_capacity(40);
        info.extend_from_slice(&now.to_be_bytes());

        // Encode local address
        match path_id.local {
            SocketAddr::V4(addr) => {
                info.push(4); // IPv4 marker
                info.extend_from_slice(&addr.ip().octets());
                info.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                info.push(6); // IPv6 marker
                info.extend_from_slice(&addr.ip().octets());
                info.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        // Encode remote address
        match path_id.remote {
            SocketAddr::V4(addr) => {
                info.push(4); // IPv4 marker
                info.extend_from_slice(&addr.ip().octets());
                info.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                info.push(6); // IPv6 marker
                info.extend_from_slice(&addr.ip().octets());
                info.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        drop(inner);
        HeartbeatChunk::new(Bytes::from(info))
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

    /// Returns true if immediate SACK is required (RFC 9260 §6.8).
    ///
    /// This is set when a DATA chunk with the I-bit (immediate) flag is received.
    /// The caller should send a SACK immediately instead of using delayed SACK.
    /// The flag is cleared after `create_sack()` is called.
    pub async fn should_sack_immediately(&self) -> bool {
        self.inner.read().await.should_sack_immediately()
    }

    // =========================================================================
    // SACK Bundling (RFC 9260 §6.2)
    // =========================================================================

    /// Returns true if a SACK should be sent now.
    ///
    /// Per RFC 9260 §6.2, a SACK should be sent if:
    /// - Immediate SACK is required (I-bit was set)
    /// - Two or more DATA chunks have been received since last SACK
    /// - The delayed SACK timer (200ms) has expired
    /// - Gap ack blocks need to be reported
    pub async fn should_send_sack(&self) -> bool {
        self.inner.read().await.should_send_sack()
    }

    /// Creates a SACK and resets the bundling state.
    ///
    /// Call this when `should_send_sack()` returns true.
    pub async fn create_sack(&self) -> SackChunk {
        self.inner.write().await.create_sack_and_reset()
    }

    /// Tries to bundle a SACK with outgoing DATA.
    ///
    /// Returns Some(SackChunk) if a SACK should be bundled,
    /// or None if no SACK is pending.
    pub async fn try_bundle_sack(&self) -> Option<SackChunk> {
        self.inner.write().await.try_bundle_sack()
    }

    // =========================================================================
    // Path MTU Discovery (RFC 9260 §8.4)
    // =========================================================================

    /// Returns the current Path MTU.
    pub async fn path_mtu(&self) -> u32 {
        self.inner.read().await.path_mtu()
    }

    /// Starts PMTU probing by creating a PAD chunk.
    ///
    /// Returns Some(PadChunk) if probing should be started,
    /// or None if already probing or size <= current PMTU.
    pub async fn start_pmtu_probe(&self, probe_size: u32) -> Option<super::chunk::PadChunk> {
        self.inner.write().await.start_pmtu_probe(probe_size)
    }

    /// Called when PMTU probe succeeds (no ICMP error received).
    pub async fn on_pmtu_probe_success(&self, probe_size: u32) {
        self.inner.write().await.on_pmtu_probe_success(probe_size);
    }

    /// Called when PMTU probe fails (ICMP Packet Too Big received).
    pub async fn on_pmtu_probe_failure(&self, new_mtu: u32) {
        self.inner.write().await.on_pmtu_probe_failure(new_mtu);
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

    #[test]
    fn test_asconf_add_ip() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Create an ASCONF with ADD-IP parameter
        let mut asconf = AsconfChunk::new(1);
        asconf.params.push(AsconfParam::AddIp {
            correlation_id: 100,
            ipv4: Some("192.168.1.100".parse().unwrap()),
            ipv6: None,
        });

        let ack = inner.process_asconf(&asconf);

        assert_eq!(ack.serial_number, 1);
        assert_eq!(ack.params.len(), 1);
        assert!(matches!(
            ack.params[0],
            AsconfAckParam::Success {
                correlation_id: 100
            }
        ));

        // Verify the address was added
        let new_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();
        assert!(inner.peer_addresses.contains(&new_addr));
    }

    #[test]
    fn test_asconf_delete_ip() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // First add an address
        let addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();
        inner.peer_addresses.insert(addr);

        // Create an ASCONF with DELETE-IP parameter
        let mut asconf = AsconfChunk::new(1);
        asconf.params.push(AsconfParam::DeleteIp {
            correlation_id: 200,
            ipv4: Some("192.168.1.100".parse().unwrap()),
            ipv6: None,
        });

        let ack = inner.process_asconf(&asconf);

        assert_eq!(ack.serial_number, 1);
        assert_eq!(ack.params.len(), 1);
        assert!(matches!(
            ack.params[0],
            AsconfAckParam::Success {
                correlation_id: 200
            }
        ));

        // Verify the address was removed
        assert!(!inner.peer_addresses.contains(&addr));
    }

    #[test]
    fn test_asconf_delete_last_address_fails() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Try to delete the only (primary) address
        let mut asconf = AsconfChunk::new(1);
        asconf.params.push(AsconfParam::DeleteIp {
            correlation_id: 300,
            ipv4: Some("127.0.0.1".parse().unwrap()),
            ipv6: None,
        });

        let ack = inner.process_asconf(&asconf);

        assert_eq!(ack.params.len(), 1);
        assert!(matches!(
            ack.params[0],
            AsconfAckParam::ErrorCause {
                correlation_id: 300,
                ..
            }
        ));
    }

    #[test]
    fn test_asconf_set_primary() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Add an alternate address
        let new_primary: SocketAddr = "192.168.1.100:5061".parse().unwrap();
        inner.peer_addresses.insert(new_primary);

        // Create an ASCONF with SET-PRIMARY parameter
        let mut asconf = AsconfChunk::new(1);
        asconf.params.push(AsconfParam::SetPrimaryAddress {
            correlation_id: 400,
            ipv4: Some("192.168.1.100".parse().unwrap()),
            ipv6: None,
        });

        let ack = inner.process_asconf(&asconf);

        assert_eq!(ack.params.len(), 1);
        assert!(matches!(
            ack.params[0],
            AsconfAckParam::Success {
                correlation_id: 400
            }
        ));

        // Verify the primary was changed
        assert_eq!(inner.peer_addr, new_primary);
        // Old primary should now be in peer_addresses
        assert!(inner.peer_addresses.contains(&test_addr(5061)));
    }

    #[test]
    fn test_asconf_serial_number_tracking() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Process first ASCONF
        let mut asconf1 = AsconfChunk::new(100);
        asconf1.params.push(AsconfParam::AddIp {
            correlation_id: 1,
            ipv4: Some("10.0.0.1".parse().unwrap()),
            ipv6: None,
        });
        let ack1 = inner.process_asconf(&asconf1);
        assert_eq!(ack1.serial_number, 100);

        // Process second ASCONF with higher serial
        let mut asconf2 = AsconfChunk::new(101);
        asconf2.params.push(AsconfParam::AddIp {
            correlation_id: 2,
            ipv4: Some("10.0.0.2".parse().unwrap()),
            ipv6: None,
        });
        let ack2 = inner.process_asconf(&asconf2);
        assert_eq!(ack2.serial_number, 101);

        // Old serial number should be ignored (return empty ACK)
        let mut asconf_old = AsconfChunk::new(99);
        asconf_old.params.push(AsconfParam::AddIp {
            correlation_id: 3,
            ipv4: Some("10.0.0.3".parse().unwrap()),
            ipv6: None,
        });
        let ack_old = inner.process_asconf(&asconf_old);
        assert_eq!(ack_old.serial_number, 99);
        assert!(ack_old.params.is_empty()); // Old ASCONF, no params processed
    }

    #[test]
    fn test_create_add_ip_asconf() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        let initial_serial = inner.asconf_serial_number;
        let chunk = inner.create_add_ip_asconf("192.168.1.50:5060".parse().unwrap());

        assert_eq!(chunk.serial_number, initial_serial);
        assert_eq!(inner.asconf_serial_number, initial_serial.wrapping_add(1));
        assert_eq!(chunk.params.len(), 1);
        assert!(matches!(
            chunk.params[0],
            AsconfParam::AddIp { ipv4: Some(_), .. }
        ));
    }

    #[test]
    fn test_forward_tsn_advances_cumulative_tsn() {
        use crate::sctp::chunk::{ForwardTsnChunk, ForwardTsnStream};

        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Set initial peer cumulative TSN
        inner.peer_cumulative_tsn = 1000;

        // Process a FORWARD-TSN that advances the cumulative TSN
        let ftsn = ForwardTsnChunk::with_streams(
            1005,
            vec![ForwardTsnStream::new(0, 5), ForwardTsnStream::new(1, 10)],
        );

        inner.process_forward_tsn(&ftsn);

        // Verify cumulative TSN was advanced
        assert_eq!(inner.peer_cumulative_tsn, 1005);
    }

    #[test]
    fn test_forward_tsn_ignores_old_tsn() {
        use crate::sctp::chunk::ForwardTsnChunk;

        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Set initial peer cumulative TSN
        inner.peer_cumulative_tsn = 1000;

        // Process a FORWARD-TSN with an old TSN (should be ignored)
        let ftsn = ForwardTsnChunk::new(999);
        inner.process_forward_tsn(&ftsn);

        // Verify cumulative TSN was NOT changed
        assert_eq!(inner.peer_cumulative_tsn, 1000);
    }

    #[test]
    fn test_reconfig_outgoing_ssn_reset() {
        use crate::sctp::chunk::{ReConfigChunk, ReConfigParam};

        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Create an outgoing SSN reset request
        let reconfig = ReConfigChunk::outgoing_ssn_reset(100, 99, 5000, vec![0, 1]);

        let response = inner.process_reconfig(&reconfig);

        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.params.len(), 1);

        if let ReConfigParam::Response {
            resp_seq_num,
            result,
            ..
        } = &response.params[0]
        {
            assert_eq!(*resp_seq_num, 100);
            assert!(result.is_success());
        } else {
            panic!("Expected Response");
        }

        // Verify the peer req seq num was updated
        assert_eq!(inner.peer_reconfig_req_seq_num, Some(100));
    }

    #[test]
    fn test_reconfig_duplicate_request_rejected() {
        use crate::sctp::chunk::{ReConfigChunk, ReConfigParam, ReConfigResult};

        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Set an existing peer sequence number
        inner.peer_reconfig_req_seq_num = Some(100);

        // Try to process a request with an old sequence number
        let reconfig = ReConfigChunk::outgoing_ssn_reset(99, 98, 5000, vec![0]);

        let response = inner.process_reconfig(&reconfig);

        assert!(response.is_some());
        let response = response.unwrap();

        if let ReConfigParam::Response { result, .. } = &response.params[0] {
            assert_eq!(*result, ReConfigResult::ErrorBadSeqNum);
        } else {
            panic!("Expected Response");
        }
    }

    #[test]
    fn test_reconfig_response_no_response_needed() {
        use crate::sctp::chunk::{ReConfigChunk, ReConfigParam, ReConfigResult};

        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Create a response (which shouldn't generate another response)
        let mut reconfig = ReConfigChunk::new();
        reconfig.params.push(ReConfigParam::Response {
            resp_seq_num: 100,
            result: ReConfigResult::SuccessPerformed,
            sender_next_tsn: None,
            receiver_next_tsn: None,
        });

        let response = inner.process_reconfig(&reconfig);

        // No response should be generated for a response
        assert!(response.is_none());
    }

    #[test]
    fn test_duplicate_tsn_detection() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Create a DATA chunk with TSN 1001
        let chunk1 = DataChunk::new(1001, 0, 0, 0, Bytes::from("test1"));
        assert!(inner.process_data(chunk1).is_ok());

        // Verify it was received
        assert!(inner.received_tsns.contains(&1001));

        // Send the same TSN again (duplicate)
        let chunk1_dup = DataChunk::new(1001, 0, 0, 0, Bytes::from("test1"));
        assert!(inner.process_data(chunk1_dup).is_ok());

        // Verify duplicate was detected
        assert_eq!(inner.duplicate_tsns.len(), 1);
        assert_eq!(inner.duplicate_tsns[0], 1001);
    }

    #[test]
    fn test_duplicate_tsn_below_cumulative() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Send a TSN that's at or below the cumulative (always a duplicate)
        let old_chunk = DataChunk::new(999, 0, 0, 0, Bytes::from("old"));
        assert!(inner.process_data(old_chunk).is_ok());

        // Verify it was detected as duplicate
        assert_eq!(inner.duplicate_tsns.len(), 1);
        assert_eq!(inner.duplicate_tsns[0], 999);
    }

    #[test]
    fn test_gap_ack_blocks_generation() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Receive out-of-order TSNs (simulating gap)
        // TSN 1001 is missing, receive 1002 and 1003
        let chunk2 = DataChunk::new(1002, 0, 0, 0, Bytes::from("test2"));
        let chunk3 = DataChunk::new(1003, 0, 0, 0, Bytes::from("test3"));
        assert!(inner.process_data(chunk2).is_ok());
        assert!(inner.process_data(chunk3).is_ok());

        // Verify gap tracking
        assert!(inner.received_tsns.contains(&1002));
        assert!(inner.received_tsns.contains(&1003));
        assert_eq!(inner.peer_cumulative_tsn, 1000); // Didn't advance

        // Build gap ack blocks
        let blocks = inner.build_gap_ack_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start, 2); // 1000 + 2 = 1002
        assert_eq!(blocks[0].end, 3); // 1000 + 3 = 1003
    }

    #[test]
    fn test_gap_ack_blocks_multiple_gaps() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Create multiple gaps: receive 1002-1003, 1005-1007
        for tsn in [1002, 1003, 1005, 1006, 1007] {
            let chunk = DataChunk::new(tsn, 0, 0, 0, Bytes::from("test"));
            assert!(inner.process_data(chunk).is_ok());
        }

        let blocks = inner.build_gap_ack_blocks();
        assert_eq!(blocks.len(), 2);
        // First gap: 1002-1003
        assert_eq!(blocks[0].start, 2);
        assert_eq!(blocks[0].end, 3);
        // Second gap: 1005-1007
        assert_eq!(blocks[1].start, 5);
        assert_eq!(blocks[1].end, 7);
    }

    #[test]
    fn test_cumulative_tsn_advances_on_gap_fill() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Receive out of order: 1002, 1003
        let chunk2 = DataChunk::new(1002, 0, 0, 0, Bytes::from("test2"));
        let chunk3 = DataChunk::new(1003, 0, 0, 0, Bytes::from("test3"));
        assert!(inner.process_data(chunk2).is_ok());
        assert!(inner.process_data(chunk3).is_ok());

        // Cumulative should still be at 1000 (gap at 1001)
        assert_eq!(inner.peer_cumulative_tsn, 1000);

        // Now receive the missing 1001
        let chunk1 = DataChunk::new(1001, 0, 0, 0, Bytes::from("test1"));
        assert!(inner.process_data(chunk1).is_ok());

        // Cumulative should now advance to 1003
        assert_eq!(inner.peer_cumulative_tsn, 1003);

        // received_tsns should be cleared for processed TSNs
        assert!(!inner.received_tsns.contains(&1002));
        assert!(!inner.received_tsns.contains(&1003));
    }

    #[test]
    fn test_sack_includes_duplicates() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Create and receive a chunk, then receive it again
        let chunk = DataChunk::new(1001, 0, 0, 0, Bytes::from("test"));
        assert!(inner.process_data(chunk.clone()).is_ok());
        assert!(inner.process_data(chunk).is_ok());

        // Create SACK
        let sack = inner.create_sack();

        // Should report duplicate
        assert_eq!(sack.dup_tsns.len(), 1);
        assert_eq!(sack.dup_tsns[0], 1001);

        // Duplicates should be cleared after SACK creation
        assert!(inner.duplicate_tsns.is_empty());
    }

    #[test]
    fn test_init_validation_zero_initiate_tag() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Create an INIT with zero initiate tag (invalid per RFC 9260 §5.1.2)
        let invalid_init = InitChunk {
            initiate_tag: 0, // Invalid!
            a_rwnd: 65535,
            num_outbound_streams: 10,
            num_inbound_streams: 10,
            initial_tsn: 1000,
            params: Vec::new(),
        };

        let result = inner.process_init(&invalid_init);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InitValidationError::InvalidInitiateTag);
    }

    #[test]
    fn test_init_validation_zero_inbound_streams() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        let invalid_init = InitChunk {
            initiate_tag: 12345,
            a_rwnd: 65535,
            num_outbound_streams: 10,
            num_inbound_streams: 0, // Invalid!
            initial_tsn: 1000,
            params: Vec::new(),
        };

        let result = inner.process_init(&invalid_init);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InitValidationError::InvalidInboundStreams
        );
    }

    #[test]
    fn test_init_validation_zero_outbound_streams() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        let invalid_init = InitChunk {
            initiate_tag: 12345,
            a_rwnd: 65535,
            num_outbound_streams: 0, // Invalid!
            num_inbound_streams: 10,
            initial_tsn: 1000,
            params: Vec::new(),
        };

        let result = inner.process_init(&invalid_init);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InitValidationError::InvalidOutboundStreams
        );
    }

    #[test]
    fn test_init_validation_valid() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        let valid_init = InitChunk {
            initiate_tag: 12345,
            a_rwnd: 65535,
            num_outbound_streams: 10,
            num_inbound_streams: 10,
            initial_tsn: 1000,
            params: Vec::new(),
        };

        let result = inner.process_init(&valid_init);
        assert!(result.is_ok());

        // Verify parameters were stored
        assert_eq!(inner.peer_verification_tag, 12345);
        assert_eq!(inner.peer_initial_tsn, 1000);
    }

    #[test]
    fn test_init_validation_error_display() {
        assert_eq!(
            InitValidationError::InvalidInitiateTag.to_string(),
            "Initiate Tag must not be 0"
        );
        assert_eq!(
            InitValidationError::InvalidInboundStreams.to_string(),
            "Number of Inbound Streams must not be 0"
        );
        assert_eq!(
            InitValidationError::InvalidOutboundStreams.to_string(),
            "Number of Outbound Streams must not be 0"
        );
    }

    #[test]
    fn test_immediate_flag_handling() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Initially, no immediate SACK needed
        assert!(!inner.should_sack_immediately());

        // Receive a DATA chunk without immediate flag
        let chunk1 = DataChunk::new(1001, 0, 0, 0, Bytes::from("test1"));
        assert!(inner.process_data(chunk1).is_ok());
        assert!(!inner.should_sack_immediately());

        // Receive a DATA chunk with immediate flag set
        let mut chunk2 = DataChunk::new(1002, 0, 0, 0, Bytes::from("test2"));
        chunk2 = chunk2.with_immediate(true);
        assert!(inner.process_data(chunk2).is_ok());

        // Now immediate SACK should be required
        assert!(inner.should_sack_immediately());

        // Create SACK - should clear the flag
        let _sack = inner.create_sack();
        assert!(!inner.should_sack_immediately());
    }

    #[test]
    fn test_immediate_flag_cleared_on_sack() {
        let mut inner = AssociationInner::new(
            test_addr(5060),
            test_addr(5061),
            AssociationConfig::default(),
        );

        // Simulate established state
        inner.state_machine.process_event(StateEvent::Associate);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveInitAck);
        inner
            .state_machine
            .process_event(StateEvent::ReceiveCookieAck);
        inner.peer_cumulative_tsn = 1000;

        // Set immediate flag directly
        inner.sack_immediately = true;
        assert!(inner.should_sack_immediately());

        // Create SACK
        let sack = inner.create_sack();

        // Flag should be cleared
        assert!(!inner.should_sack_immediately());

        // SACK should still be valid
        assert_eq!(sack.cumulative_tsn_ack, 1000);
    }
}
