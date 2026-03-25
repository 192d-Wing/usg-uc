//! RTP packet handling for audio transmission and reception.
//!
//! This module handles RTP packet construction, parsing, and SRTP
//! encryption/decryption for secure audio streams.
//!
//! All operations are synchronous -- no tokio dependency.

use crate::jitter_buffer::{BufferedPacket, SharedJitterBuffer};
use crate::{AudioError, AudioResult};
use bytes::Bytes;
use client_types::DtmfEvent;
use proto_rtp::{ExtensionElement, RtpHeader};
use proto_srtp::{SrtpContext, SrtpProtect, SrtpUnprotect};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Environment variable to enable RTP packet capture.
/// Set `DUMP_DTMF=1` to write all received RTP packets to `/tmp/rtp-capture.pcap`.
const DUMP_DTMF_ENV: &str = "DUMP_DTMF";

/// Shared DTMF packet queue for jitter buffer bypass.
///
/// DTMF telephone-event packets are routed here instead of the jitter
/// buffer, matching pjproject's approach where DTMF is intercepted at
/// the RTP receive level.
#[derive(Clone)]
pub struct SharedDtmfQueue {
    inner: Arc<Mutex<VecDeque<BufferedPacket>>>,
}

impl Default for SharedDtmfQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedDtmfQueue {
    /// Creates a new shared DTMF queue.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(16))),
        }
    }

    /// Pushes a DTMF packet into the queue.
    pub fn push(&self, packet: BufferedPacket) {
        if let Ok(mut q) = self.inner.lock() {
            // Cap at 32 to prevent unbounded growth if consumer stalls
            if q.len() < 32 {
                q.push_back(packet);
            }
        }
    }

    /// Pops the next DTMF packet from the queue.
    pub fn pop(&self) -> Option<BufferedPacket> {
        self.inner.lock().ok()?.pop_front()
    }
}

/// Default RTP payload type for audio.
pub const DEFAULT_PAYLOAD_TYPE: u8 = 0; // PCMU

/// RTP header size in bytes.
pub const RTP_HEADER_SIZE: usize = 12;

/// Maximum RTP packet size.
pub const MAX_RTP_PACKET_SIZE: usize = 1500;

/// SRTP authentication tag size for AES-256-GCM.
pub const SRTP_AUTH_TAG_SIZE: usize = 16;

/// Default RTP payload type for RFC 2198 redundancy.
pub const REDUNDANCY_PAYLOAD_TYPE: u8 = 121;

/// Default payload type for telephone-event (DTMF).
pub const DTMF_PAYLOAD_TYPE: u8 = 101;

/// DTMF event clock rate (8000 Hz per RFC 4733).
pub const DTMF_CLOCK_RATE: u32 = 8000;

/// Statistics for RTP handling.
#[derive(Debug, Clone, Default)]
pub struct RtpStats {
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Bytes sent (including headers).
    pub bytes_sent: u64,
    /// Bytes received (including headers).
    pub bytes_received: u64,
    /// Packets dropped due to errors.
    pub packets_dropped: u64,
    /// SRTP protection errors.
    pub srtp_errors: u64,
}

/// Lock-free atomic counters for RTP statistics.
///
/// Replaces `Mutex<RtpStats>` on the hot path — every `send()` and
/// `receive()` now updates counters with a single `fetch_add(Relaxed)`
/// instead of a lock/unlock pair (~100+ times per second).
pub(crate) struct AtomicRtpStats {
    /// Packets sent.
    packets_sent: AtomicU64,
    /// Packets received.
    packets_received: AtomicU64,
    /// Bytes sent (including headers).
    bytes_sent: AtomicU64,
    /// Bytes received (including headers).
    bytes_received: AtomicU64,
    /// Packets dropped due to errors.
    packets_dropped: AtomicU64,
    /// SRTP protection errors.
    srtp_errors: AtomicU64,
}

impl AtomicRtpStats {
    /// Creates zeroed atomic counters.
    const fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            srtp_errors: AtomicU64::new(0),
        }
    }

    /// Takes a consistent snapshot as a plain `RtpStats`.
    fn snapshot(&self) -> RtpStats {
        RtpStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            srtp_errors: self.srtp_errors.load(Ordering::Relaxed),
        }
    }
}

/// RTP transmitter for sending audio packets.
pub struct RtpTransmitter {
    /// UDP socket for sending.
    socket: Arc<UdpSocket>,
    /// Remote address to send to.
    remote_addr: SocketAddr,
    /// SSRC for outgoing packets.
    ssrc: u32,
    /// Current sequence number.
    sequence: AtomicU16,
    /// Current timestamp.
    timestamp: AtomicU32,
    /// Payload type.
    payload_type: u8,
    /// Timestamp increment per packet.
    timestamp_increment: u32,
    /// SRTP context for encryption (no Mutex needed — interior mutability).
    srtp: Option<SrtpContext>,
    /// Statistics (lock-free atomic counters).
    stats: Arc<AtomicRtpStats>,
    /// DTMF payload type (telephone-event).
    dtmf_payload_type: u8,
    /// Timestamp of the current DTMF event (stays constant for one event).
    /// Per RFC 4733, this is the audio stream timestamp at event start.
    dtmf_event_timestamp: AtomicU32,
    /// Pre-allocated buffer for serializing non-SRTP packets (header + payload).
    send_buffer: Vec<u8>,
    /// Scratch buffer reused by SRTP `seal_into` to avoid per-packet allocation.
    srtp_scratch: Vec<u8>,
    /// RFC 2198 redundancy: previous frame's encoded payload.
    prev_payload: Vec<u8>,
    /// Whether RFC 2198 redundancy is enabled.
    redundancy_enabled: bool,
    /// RTP payload type for RFC 2198 redundancy packets.
    redundancy_pt: u8,
    /// Negotiated RTP header extension map (id → URI).
    ///
    /// When set, outgoing packets include a one-byte extension header
    /// with elements for each negotiated extension.
    extension_map: Vec<(u8, String)>,
    /// Cached pre-built extension header (rebuilt on `set_extension_map`).
    cached_ext_header: Option<proto_rtp::ExtensionHeader>,
    /// Total RTP header size including any extension (12 when no extension).
    header_size: usize,
    /// Wall-clock time of the last `send()` / `send_cn()` / `send_dtmf()` call.
    /// Used to catch up the audio timestamp before DTMF events when the
    /// stream has been silent (muted/DTX) — otherwise the marker timestamp
    /// would be "stale" and the remote end's jitter buffer might drop it.
    last_send_time: Instant,
}

impl RtpTransmitter {
    /// Creates a new RTP transmitter.
    pub fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        ssrc: u32,
        payload_type: u8,
        timestamp_increment: u32,
    ) -> Self {
        info!(
            "Creating RTP transmitter: remote={}, ssrc={}, pt={}",
            remote_addr, ssrc, payload_type
        );

        Self {
            socket,
            remote_addr,
            ssrc,
            sequence: AtomicU16::new(rand_u16()),
            timestamp: AtomicU32::new(rand_u32()),
            payload_type,
            timestamp_increment,
            srtp: None,
            stats: Arc::new(AtomicRtpStats::new()),
            dtmf_payload_type: DTMF_PAYLOAD_TYPE,
            dtmf_event_timestamp: AtomicU32::new(0),
            send_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            srtp_scratch: Vec::with_capacity(MAX_RTP_PACKET_SIZE),
            prev_payload: Vec::new(),
            redundancy_enabled: false,
            redundancy_pt: REDUNDANCY_PAYLOAD_TYPE,
            extension_map: Vec::new(),
            cached_ext_header: None,
            header_size: RTP_HEADER_SIZE,
            last_send_time: Instant::now(),
        }
    }

    /// Enables RFC 2198 redundancy (sends previous frame alongside current).
    pub fn enable_redundancy(&mut self, pt: u8) {
        self.redundancy_enabled = true;
        self.redundancy_pt = pt;
        debug!("RFC 2198 redundancy enabled, PT={}", pt);
    }

    /// Changes the local SSRC (used after collision detection per RFC 3550 §8.2).
    pub fn change_ssrc(&mut self, new_ssrc: u32) {
        info!(
            "Changing local SSRC: {:#010x} -> {:#010x} (collision resolution)",
            self.ssrc, new_ssrc
        );
        self.ssrc = new_ssrc;
    }

    /// Sets the DTMF payload type (default is 101).
    pub fn set_dtmf_payload_type(&mut self, pt: u8) {
        self.dtmf_payload_type = pt;
        debug!("DTMF payload type set to {}", pt);
    }

    /// Sets the SRTP context for encryption.
    pub fn set_srtp(&mut self, context: SrtpContext) {
        self.srtp = Some(context);
        debug!("SRTP encryption enabled for transmitter");
    }

    /// Sets the negotiated RTP header extension map.
    ///
    /// Each entry is `(id, uri)` where `id` is the one-byte extension ID (1-14)
    /// and `uri` identifies the extension type (e.g., `urn:ietf:params:rtp-hdrext:ssrc-audio-level`).
    ///
    /// Pre-builds a cached extension header for zero-allocation sending.
    pub fn set_extension_map(&mut self, map: Vec<(u8, String)>) {
        debug!("RTP extension map set: {} extensions", map.len());
        for (id, uri) in &map {
            debug!("  ext id={}: {}", id, uri);
        }

        if map.is_empty() {
            self.extension_map = map;
            self.cached_ext_header = None;
            self.header_size = RTP_HEADER_SIZE;
            return;
        }

        // Build default extension elements (placeholder data).
        // ssrc-audio-level: 1 byte = 0x7F (V=0, level=127 = silence)
        let elements: Vec<ExtensionElement> = map
            .iter()
            .map(|(id, _uri)| ExtensionElement {
                id: *id,
                data: Bytes::from_static(&[0x7F]),
            })
            .collect();

        match proto_rtp::ExtensionHeader::build_one_byte(&elements) {
            Ok(ext) => {
                // Calculate total header size: 12 (fixed) + 4 (ext profile+length) + ext.data.len()
                self.header_size = RTP_HEADER_SIZE + 4 + ext.data.len();
                self.cached_ext_header = Some(ext);
                debug!("Cached extension header: {} bytes total", self.header_size);
            }
            Err(e) => {
                warn!(
                    "Failed to build extension header: {}, extensions disabled",
                    e
                );
                self.cached_ext_header = None;
                self.header_size = RTP_HEADER_SIZE;
            }
        }

        self.extension_map = map;
    }

    /// Sends an RTP packet with the given audio payload.
    ///
    /// When RFC 2198 redundancy is enabled, the previous frame is included
    /// alongside the current frame in a single packet. The RTP payload type
    /// is set to the negotiated redundancy PT.
    ///
    /// Non-SRTP path: zero-allocation — header + payload are written directly
    /// into a pre-allocated `send_buffer` and sent from there.
    ///
    /// SRTP path: one allocation for the encrypted output (unavoidable), but
    /// avoids the intermediate `Bytes::copy_from_slice` on the payload.
    #[allow(clippy::cast_sign_loss)]
    pub fn send(&mut self, payload: &[u8]) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let ts = self
            .timestamp
            .fetch_add(self.timestamp_increment, Ordering::Relaxed);

        // Build the actual payload: RFC 2198 redundancy or plain.
        let effective_pt;
        let rtp_payload_start;
        let rtp_payload_end;

        // Use the actual header size (12 without extensions, larger with).
        let hdr_size = self.header_size;

        if self.redundancy_enabled && !self.prev_payload.is_empty() {
            // RFC 2198 format:
            //   Header block 1 (4 bytes): F=1 | PT | timestamp_offset(14) | block_len(10)
            //   Header block 2 (1 byte):  F=0 | PT
            //   Redundant data (prev_payload)
            //   Primary data (payload)
            effective_pt = self.redundancy_pt;

            // We write the RFC 2198 body into send_buffer AFTER the RTP header.
            // The RTP header will be written at offset 0 later.
            let prev_len = self.prev_payload.len();
            let red_header_size = 5; // 4 + 1 bytes
            let body_len = red_header_size + prev_len + payload.len();

            // Build redundancy headers in send_buffer (after space for RTP header).
            let off = hdr_size;
            // Redundant block header (4 bytes):
            //   bit 0: F=1 (more blocks follow)
            //   bits 1-7: block PT (original codec PT)
            //   bits 8-21: timestamp offset (14 bits)
            //   bits 22-31: block length (10 bits)
            let ts_offset = self.timestamp_increment;
            #[allow(clippy::cast_possible_truncation)]
            {
                self.send_buffer[off] = 0x80 | (self.payload_type & 0x7F);
                self.send_buffer[off + 1] = ((ts_offset >> 6) & 0xFF) as u8;
                self.send_buffer[off + 2] =
                    (((ts_offset & 0x3F) << 2) as u8) | ((prev_len >> 8) as u8 & 0x03);
                self.send_buffer[off + 3] = prev_len as u8;
            }
            // Primary block header (1 byte): F=0 | PT
            self.send_buffer[off + 4] = self.payload_type & 0x7F;

            // Copy redundant data (previous frame)
            let red_data_start = off + red_header_size;
            self.send_buffer[red_data_start..red_data_start + prev_len]
                .copy_from_slice(&self.prev_payload);

            // Copy primary data (current frame)
            let pri_data_start = red_data_start + prev_len;
            self.send_buffer[pri_data_start..pri_data_start + payload.len()]
                .copy_from_slice(payload);

            rtp_payload_start = off;
            rtp_payload_end = off + body_len;
        } else {
            effective_pt = self.payload_type;
            rtp_payload_start = hdr_size;
            rtp_payload_end = hdr_size + payload.len();
            self.send_buffer[rtp_payload_start..rtp_payload_end].copy_from_slice(payload);
        }

        // Store current payload for next frame's redundancy
        if self.redundancy_enabled {
            self.prev_payload.clear();
            self.prev_payload.extend_from_slice(payload);
        }

        // Build RTP header, attaching extension if negotiated.
        let header = {
            let h = RtpHeader::new(effective_pt, seq, ts, self.ssrc);
            if let Some(ref ext) = self.cached_ext_header {
                h.with_extension(ext.clone())
            } else {
                h
            }
        };

        let protected: Bytes;
        let send_data: &[u8] = if let Some(ref srtp) = self.srtp {
            let protector = SrtpProtect::new(srtp);
            let rtp_body = &self.send_buffer[rtp_payload_start..rtp_payload_end];
            match protector.protect_rtp_parts_into(&header, rtp_body, &mut self.srtp_scratch) {
                Ok(p) => {
                    protected = p;
                    &protected
                }
                Err(e) => {
                    self.stats.srtp_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(AudioError::SrtpError(format!("SRTP protect failed: {e}")));
                }
            }
        } else {
            // Zero-alloc: write header into send_buffer, payload is already there.
            let written = header.write_into(&mut self.send_buffer);
            debug_assert_eq!(written, hdr_size);
            &self.send_buffer[..rtp_payload_end]
        };

        match self.socket.send_to(send_data, self.remote_addr) {
            Ok(sent) => {
                trace!("Sent RTP packet: seq={}, ts={}, size={}", seq, ts, sent);
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(sent as u64, Ordering::Relaxed);
                self.last_send_time = Instant::now();
                Ok(())
            }
            Err(e) => {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                Err(AudioError::RtpError(format!("Send failed: {e}")))
            }
        }
    }

    /// Returns the current statistics.
    pub fn stats(&self) -> RtpStats {
        self.stats.snapshot()
    }

    /// Returns the SSRC.
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Sends an RFC 3389 Comfort Noise payload.
    ///
    /// CN packets share the same RTP sequence/timestamp space as audio packets
    /// (RFC 3389 §4). Only the payload type changes to PT=13.
    /// Call this once at the speech→silence transition.
    #[allow(clippy::cast_sign_loss)]
    pub fn send_cn(&mut self, payload: &[u8]) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let ts = self
            .timestamp
            .fetch_add(self.timestamp_increment, Ordering::Relaxed);

        let header = RtpHeader::new(proto_rtp::payload_types::CN, seq, ts, self.ssrc);

        let protected: Bytes;
        let send_data: &[u8] = if let Some(ref srtp) = self.srtp {
            let protector = SrtpProtect::new(srtp);
            match protector.protect_rtp_parts_into(&header, payload, &mut self.srtp_scratch) {
                Ok(p) => {
                    protected = p;
                    &protected
                }
                Err(e) => {
                    self.stats.srtp_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(AudioError::SrtpError(format!("SRTP protect failed: {e}")));
                }
            }
        } else {
            let header_size = header.write_into(&mut self.send_buffer);
            let total = header_size + payload.len();
            self.send_buffer[header_size..total].copy_from_slice(payload);
            &self.send_buffer[..total]
        };

        match self.socket.send_to(send_data, self.remote_addr) {
            Ok(sent) => {
                debug!("Sent CN packet: seq={}, ts={}, size={}", seq, ts, sent);
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(sent as u64, Ordering::Relaxed);
                self.last_send_time = Instant::now();
                Ok(())
            }
            Err(e) => {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                Err(AudioError::RtpError(format!("CN send failed: {e}")))
            }
        }
    }

    /// Sends a DTMF event packet (RFC 4733 telephone-event).
    ///
    /// For proper DTMF signaling, call this method multiple times:
    /// 1. Initial packet with marker bit (start of event)
    /// 2. Continuation packets every 20ms during the tone
    /// 3. Final packets (3x) with end bit set
    ///
    /// # Arguments
    /// * `event` - The DTMF event to send
    /// * `marker` - Set to true for the first packet of a new event
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn send_dtmf(&mut self, event: &DtmfEvent, marker: bool) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        // Per RFC 4733, the DTMF event timestamp must be on the same
        // timeline as the audio stream. The marker packet uses the current
        // audio timestamp; continuations/end packets reuse it.
        let ts = if marker {
            // If audio has been silent (muted/DTX), the audio timestamp is
            // stale. Advance it to "now" so the DTMF event isn't dropped by
            // the remote jitter buffer as too-late.
            let elapsed = self.last_send_time.elapsed();
            let elapsed_samples = (elapsed.as_millis() as u32) * 8; // 8 samples/ms at 8kHz
            let catch_up = (elapsed_samples / self.timestamp_increment) * self.timestamp_increment;
            if catch_up > 0 {
                self.timestamp.fetch_add(catch_up, Ordering::Relaxed);
                debug!(
                    "DTMF timestamp catch-up: advanced {} samples ({}ms silence)",
                    catch_up,
                    catch_up / 8
                );
            }
            let new_ts = self.timestamp.load(Ordering::Relaxed);
            self.dtmf_event_timestamp.store(new_ts, Ordering::Relaxed);
            new_ts
        } else {
            self.dtmf_event_timestamp.load(Ordering::Relaxed)
        };

        // Build RTP header with DTMF payload type
        let mut header = RtpHeader::new(self.dtmf_payload_type, seq, ts, self.ssrc);
        if marker {
            header.marker = true;
        }

        // Encode DTMF event payload (4 bytes per RFC 4733)
        let payload = event.encode();

        let protected: Bytes;
        let send_data: &[u8] = if let Some(ref srtp) = self.srtp {
            let protector = SrtpProtect::new(srtp);
            match protector.protect_rtp_parts_into(&header, &payload, &mut self.srtp_scratch) {
                Ok(p) => {
                    protected = p;
                    &protected
                }
                Err(e) => {
                    self.stats.srtp_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(AudioError::SrtpError(format!("SRTP protect failed: {e}")));
                }
            }
        } else {
            let header_size = header.write_into(&mut self.send_buffer);
            let total = header_size + payload.len();
            self.send_buffer[header_size..total].copy_from_slice(&payload);
            &self.send_buffer[..total]
        };

        match self.socket.send_to(send_data, self.remote_addr) {
            Ok(sent) => {
                trace!(
                    "Sent DTMF packet: digit={}, seq={}, ts={}, end={}, marker={}",
                    event.digit, seq, ts, event.end, marker
                );
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(sent as u64, Ordering::Relaxed);
                self.last_send_time = Instant::now();
                Ok(())
            }
            Err(e) => {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                Err(AudioError::RtpError(format!("DTMF send failed: {e}")))
            }
        }
    }

    /// Advances the audio timestamp after a DTMF event completes.
    ///
    /// Must be called exactly once per event, after all end packets are sent.
    /// This keeps the audio timestamp timeline continuous: the next audio
    /// packet after DTMF resumes at `event_start + duration + end_periods`.
    pub fn advance_dtmf_timestamp(&self, duration: u32) {
        self.timestamp.fetch_add(duration, Ordering::Relaxed);
    }
}

/// RTP receiver for receiving audio packets.
///
/// Receives RTP packets from a `std::net::UdpSocket` (blocking with
/// `recv_timeout`), decrypts via SRTP if configured, and pushes into
/// a `SharedJitterBuffer` for consumption by the decode thread.
pub struct RtpReceiver {
    /// UDP socket for receiving.
    socket: Arc<UdpSocket>,
    /// Expected remote address (for filtering).
    expected_remote: Option<SocketAddr>,
    /// SRTP context for decryption (no Mutex needed — interior mutability).
    srtp: Option<SrtpContext>,
    /// Shared jitter buffer (also read by decode thread).
    jitter_buffer: SharedJitterBuffer,
    /// Statistics (lock-free atomic counters).
    stats: Arc<AtomicRtpStats>,
    /// Buffer for receiving packets.
    recv_buffer: Vec<u8>,
    /// Pre-allocated buffer to avoid `.to_vec()` on receive
    /// (needed to break the self-borrow between `recv_buffer` and `process_packet`).
    process_buffer: Vec<u8>,
    /// Remote SSRC (learned from received RTP packets).
    remote_ssrc: Option<u32>,
    /// RFC 2198 redundancy payload type (if negotiated).
    redundancy_pt: Option<u8>,
    /// Our local SSRC (for collision detection per RFC 3550 §8.2).
    local_ssrc: Option<u32>,
    /// Set to `true` when an incoming SSRC matches our local SSRC.
    ssrc_collision: bool,
    /// Negotiated RTP header extension map (id → URI) for incoming packets.
    extension_map: Vec<(u8, String)>,
    /// DTMF telephone-event payload type (bypasses JB when set).
    dtmf_pt: Option<u8>,
    /// Shared queue for DTMF packets (bypasses jitter buffer).
    dtmf_queue: Option<SharedDtmfQueue>,
    /// Optional pcap dump file for packet capture (set `DUMP_DTMF=1`).
    pcap_dump: Option<std::io::BufWriter<std::fs::File>>,
    /// Start time for pcap timestamps.
    pcap_start: Instant,
}

impl RtpReceiver {
    /// Creates a new RTP receiver.
    pub fn new(socket: Arc<UdpSocket>, jitter_buffer: SharedJitterBuffer) -> Self {
        info!("Creating RTP receiver");

        // Initialize pcap dump if DUMP_DTMF=1
        let pcap_dump = std::env::var(DUMP_DTMF_ENV)
            .ok()
            .filter(|v| v == "1")
            .and_then(|_| {
                let path = "/tmp/rtp-capture.pcap";
                match std::fs::File::create(path) {
                    Ok(f) => {
                        let mut w = std::io::BufWriter::new(f);
                        // Write pcap global header (little-endian)
                        // Magic=0xa1b2c3d4, v2.4, tz=0, sigfigs=0, snaplen=65535,
                        // LINKTYPE_USER0=147 (raw RTP, decode-as in Wireshark)
                        let header: [u8; 24] = [
                            0xd4, 0xc3, 0xb2, 0xa1,
                            0x02, 0x00, 0x04, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0xff, 0xff, 0x00, 0x00,
                            0x93, 0x00, 0x00, 0x00,
                        ];
                        if w.write_all(&header).is_ok() {
                            info!("RTP pcap capture enabled: {path} (open in Wireshark, Decode As → RTP)");
                            Some(w)
                        } else {
                            warn!("Failed to write pcap header");
                            None
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create pcap file: {e}");
                        None
                    }
                }
            });

        Self {
            socket,
            expected_remote: None,
            srtp: None,
            jitter_buffer,
            stats: Arc::new(AtomicRtpStats::new()),
            recv_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            process_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            remote_ssrc: None,
            redundancy_pt: None,
            local_ssrc: None,
            ssrc_collision: false,
            extension_map: Vec::new(),
            dtmf_pt: None,
            dtmf_queue: None,
            pcap_dump,
            pcap_start: Instant::now(),
        }
    }

    /// Configures DTMF jitter buffer bypass.
    ///
    /// When set, telephone-event packets matching `pt` are routed to the
    /// dedicated DTMF queue instead of the jitter buffer (matches pjproject).
    pub fn set_dtmf_bypass(&mut self, pt: u8, queue: SharedDtmfQueue) {
        self.dtmf_pt = Some(pt);
        self.dtmf_queue = Some(queue);
        debug!("DTMF JB bypass enabled for PT={}", pt);
    }

    /// Sets the expected remote address for packet filtering.
    pub const fn set_expected_remote(&mut self, addr: SocketAddr) {
        self.expected_remote = Some(addr);
    }

    /// Sets the SRTP context for decryption.
    pub fn set_srtp(&mut self, context: SrtpContext) {
        self.srtp = Some(context);
        debug!("SRTP decryption enabled for receiver");
    }

    /// Sets the local SSRC for collision detection (RFC 3550 §8.2).
    pub const fn set_local_ssrc(&mut self, ssrc: u32) {
        self.local_ssrc = Some(ssrc);
    }

    /// Returns `true` if an SSRC collision has been detected since last clear.
    pub const fn ssrc_collision_detected(&self) -> bool {
        self.ssrc_collision
    }

    /// Clears the collision flag after the caller has handled it.
    pub const fn clear_ssrc_collision(&mut self) {
        self.ssrc_collision = false;
    }

    /// Enables RFC 2198 redundancy reception with the given payload type.
    pub fn set_redundancy_pt(&mut self, pt: u8) {
        self.redundancy_pt = Some(pt);
        debug!("RFC 2198 redundancy reception enabled, PT={}", pt);
    }

    /// Sets the negotiated RTP header extension map for incoming packets.
    ///
    /// Each entry is `(id, uri)` for interpreting received extension elements.
    pub fn set_extension_map(&mut self, map: Vec<(u8, String)>) {
        debug!("RX extension map set: {} extensions", map.len());
        self.extension_map = map;
    }

    /// Returns the negotiated extension map.
    pub fn extension_map(&self) -> &[(u8, String)] {
        &self.extension_map
    }

    /// Receives an RTP packet (blocking, respects socket `recv_timeout`).
    ///
    /// Returns `Ok(true)` if a packet was received and buffered,
    /// `Ok(false)` if no packet was available (timeout/would-block),
    /// or `Err` on socket/protocol error.
    pub fn receive(&mut self) -> AudioResult<bool> {
        let result = self.socket.recv_from(&mut self.recv_buffer);

        match result {
            Ok((len, addr)) => {
                // Check if from expected remote
                if let Some(expected) = self.expected_remote
                    && addr != expected
                {
                    trace!("Ignoring packet from unexpected address: {addr}");
                    return Ok(false);
                }

                // Copy into process_buffer to break the self-borrow on recv_buffer.
                // Uses a pre-allocated buffer instead of .to_vec() heap allocation.
                self.process_buffer[..len].copy_from_slice(&self.recv_buffer[..len]);

                // Write raw packet to pcap (before SRTP decrypt — captures wire format)
                if let Some(ref mut pcap) = self.pcap_dump {
                    let elapsed = self.pcap_start.elapsed();
                    #[allow(clippy::cast_possible_truncation)]
                    let ts_sec = (elapsed.as_secs() as u32).to_le_bytes();
                    let ts_microsec = elapsed.subsec_micros().to_le_bytes();
                    #[allow(clippy::cast_possible_truncation)]
                    let pkt_len = (len as u32).to_le_bytes();
                    let _ = pcap.write_all(&ts_sec);
                    let _ = pcap.write_all(&ts_microsec);
                    let _ = pcap.write_all(&pkt_len); // incl_len
                    let _ = pcap.write_all(&pkt_len); // orig_len
                    let _ = pcap.write_all(&self.recv_buffer[..len]);
                    let _ = pcap.flush();
                }

                self.process_packet(len)?;
                Ok(true)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No packet available within timeout
                Ok(false)
            }
            Err(e) => Err(AudioError::RtpError(format!("Receive failed: {e}"))),
        }
    }

    /// Processes a received packet from `self.process_buffer[..len]`.
    ///
    /// Non-SRTP path: parses only the 4 header fields we need (PT, seq, ts,
    /// SSRC) directly from bytes — avoids constructing the intermediate
    /// `RtpHeader` (with `Vec<u32>` csrc) and `RtpPacket` structs.
    ///
    /// SRTP path: delegates to `unprotect_rtp` which must construct the full
    /// header for AAD computation, then extracts the same 4 fields.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn process_packet(&mut self, len: usize) -> AudioResult<()> {
        let data = &self.process_buffer[..len];

        // Extract the 4 fields + payload, choosing the right path.
        let (pt, seq, ts, ssrc, payload): (u8, u16, u32, u32, Bytes) =
            if let Some(ref srtp) = self.srtp {
                let unprotector = SrtpUnprotect::new(srtp);
                match unprotector.unprotect_rtp(data) {
                    Ok(pkt) => (
                        pkt.header.payload_type,
                        pkt.header.sequence_number,
                        pkt.header.timestamp,
                        pkt.header.ssrc,
                        pkt.payload,
                    ),
                    Err(e) => {
                        self.stats.srtp_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(AudioError::SrtpError(format!("SRTP unprotect failed: {e}")));
                    }
                }
            } else {
                // Inline minimal parse — no RtpHeader/RtpPacket constructed.
                let (pt, seq, ts, ssrc, payload_start, payload_end) = parse_rtp_fields(data)?;
                (
                    pt,
                    seq,
                    ts,
                    ssrc,
                    Bytes::copy_from_slice(&data[payload_start..payload_end]),
                )
            };

        trace!("Received RTP packet: seq={}, ts={}, pt={}", seq, ts, pt);

        // SSRC collision detection (RFC 3550 §8.2): if the incoming
        // packet's SSRC matches our own local SSRC, flag the collision
        // so the I/O thread can regenerate our SSRC.
        if let Some(local) = self.local_ssrc
            && ssrc == local
        {
            warn!(
                "SSRC collision detected: remote sent SSRC={:#010x} which matches our local SSRC",
                ssrc
            );
            self.ssrc_collision = true;
        }

        // Track remote SSRC — detect changes mid-call (RFC 3550 §8.2).
        match self.remote_ssrc {
            None => {
                self.remote_ssrc = Some(ssrc);
                debug!("Learned remote SSRC: {:#010x}", ssrc);
            }
            Some(prev) if prev != ssrc => {
                warn!(
                    "Remote SSRC changed: {:#010x} -> {:#010x}, resetting jitter buffer",
                    prev, ssrc
                );
                self.remote_ssrc = Some(ssrc);
                self.jitter_buffer.reset();
            }
            _ => {}
        }

        // DTMF JB bypass: route telephone-event packets to the dedicated
        // queue instead of the jitter buffer (matches pjproject).
        if self.dtmf_pt == Some(pt)
            && let Some(ref queue) = self.dtmf_queue
        {
            let buffered = BufferedPacket::new(seq, ts, pt, payload);
            queue.push(buffered);
            self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
            #[allow(clippy::cast_possible_truncation)]
            self.stats
                .bytes_received
                .fetch_add(len as u64, Ordering::Relaxed);
            return Ok(());
            // No queue configured — fall through to JB (legacy path)
        }

        // RFC 2198 redundancy: extract primary + redundant payloads.
        if self.redundancy_pt == Some(pt) {
            if let Some((primary_pt, primary_data, redundant)) = parse_rfc2198(&payload, ts) {
                // Push redundant blocks first (they represent older packets).
                for (red_pt, ts_offset, red_data) in &redundant {
                    let red_ts = ts.wrapping_sub(*ts_offset);
                    let red_seq = seq.wrapping_sub(1); // assume 1 frame offset
                    let red_pkt = BufferedPacket::new(
                        red_seq,
                        red_ts,
                        *red_pt,
                        Bytes::copy_from_slice(red_data),
                    );
                    self.jitter_buffer.push(red_pkt);
                }
                // Push primary payload
                let buffered =
                    BufferedPacket::new(seq, ts, primary_pt, Bytes::copy_from_slice(primary_data));
                self.jitter_buffer.push(buffered);
            } else {
                warn!("Failed to parse RFC 2198 payload, dropping packet");
            }
        } else {
            // Normal (non-redundant) packet
            let buffered = BufferedPacket::new(seq, ts, pt, payload);
            self.jitter_buffer.push(buffered);
        }

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation)]
        self.stats
            .bytes_received
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Returns whether the jitter buffer is ready for playback.
    pub fn is_ready(&self) -> bool {
        self.jitter_buffer.is_ready()
    }

    /// Resets the receiver state.
    pub fn reset(&self) {
        self.jitter_buffer.reset();
    }

    /// Returns the current statistics.
    pub fn stats(&self) -> RtpStats {
        self.stats.snapshot()
    }

    /// Returns the jitter buffer statistics.
    pub fn jitter_buffer_stats(&self) -> crate::jitter_buffer::JitterBufferStats {
        self.jitter_buffer.stats()
    }

    /// Provides an RTCP RTT hint to the jitter buffer for adaptive depth.
    pub fn set_rtt_hint_ms(&self, rtt_ms: f32) {
        self.jitter_buffer.set_rtt_hint_ms(rtt_ms);
    }

    /// Returns the remote SSRC learned from received RTP packets.
    pub const fn remote_ssrc(&self) -> Option<u32> {
        self.remote_ssrc
    }
}

/// Mixes multiple entropy sources into a u64 for SSRC/sequence randomness.
///
/// Per RFC 3550 Section 5.1, SSRC should be chosen randomly. We combine
/// multiple entropy sources and apply a mixing function for good distribution
/// without requiring an external RNG crate.
fn entropy_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Source 1: High-resolution timestamp (nanoseconds)
    let time_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            #[allow(clippy::cast_possible_truncation)]
            let nanos = d.as_nanos() as u64;
            nanos
        })
        .unwrap_or(0);

    // Source 2: Thread ID (different per thread)
    let thread_id = {
        let id = format!("{:?}", std::thread::current().id());
        let mut h: u64 = 0;
        for b in id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(u64::from(b));
        }
        h
    };

    // Source 3: Stack address (ASLR provides entropy across runs)
    let stack_var: u64 = 0;
    let stack_addr = std::ptr::addr_of!(stack_var) as u64;

    // Source 4: Process ID
    let pid = u64::from(std::process::id());

    // Mix all sources with xorshift-style mixing (splitmix64)
    let mut state = time_nanos
        ^ thread_id.wrapping_shl(17)
        ^ stack_addr.wrapping_shl(31)
        ^ pid.wrapping_shl(47);

    // splitmix64 finalizer for good avalanche properties
    state ^= state >> 30;
    state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state ^= state >> 27;
    state = state.wrapping_mul(0x94d0_49bb_1331_11eb);
    state ^= state >> 31;

    state
}

/// Generates a random u16 for sequence number initialization (RFC 3550).
#[allow(clippy::cast_possible_truncation)]
fn rand_u16() -> u16 {
    (entropy_seed() & 0xFFFF) as u16
}

/// Generates a random u32 for SSRC/timestamp initialization (RFC 3550).
#[allow(clippy::cast_possible_truncation)]
fn rand_u32() -> u32 {
    (entropy_seed() & 0xFFFF_FFFF) as u32
}

/// Generates a random SSRC per RFC 3550 Section 5.1.
pub fn generate_ssrc() -> u32 {
    rand_u32()
}

/// Maximum redundant blocks supported in RFC 2198 parsing.
/// Typical use: 1-2 redundant copies. 4 provides generous headroom
/// while keeping allocations off the heap.
const MAX_REDUNDANT_BLOCKS: usize = 4;

/// Parses an RFC 2198 redundancy payload.
///
/// Returns `(primary_pt, primary_data, redundant_entries)` where each
/// redundant entry is `(pt, timestamp_offset, data)`.
#[allow(clippy::type_complexity)]
pub fn parse_rfc2198(
    data: &[u8],
    rtp_timestamp: u32,
) -> Option<(u8, &[u8], Vec<(u8, u32, &[u8])>)> {
    if data.is_empty() {
        return None;
    }

    let mut offset = 0;
    // Stack-allocated header array (avoids per-packet heap allocation)
    let mut redundant_headers = [(0u8, 0u32, 0usize); MAX_REDUNDANT_BLOCKS];
    let mut num_redundant = 0;

    // Parse header blocks
    loop {
        if offset >= data.len() {
            return None;
        }
        let f_bit = (data[offset] & 0x80) != 0;
        let block_pt = data[offset] & 0x7F;

        if f_bit {
            // Redundant block header: 4 bytes
            if offset + 4 > data.len() || num_redundant >= MAX_REDUNDANT_BLOCKS {
                return None;
            }
            let ts_offset = (u32::from(data[offset + 1]) << 6) | (u32::from(data[offset + 2]) >> 2);
            let block_len =
                (usize::from(data[offset + 2] & 0x03) << 8) | usize::from(data[offset + 3]);
            redundant_headers[num_redundant] = (block_pt, ts_offset, block_len);
            num_redundant += 1;
            offset += 4;
        } else {
            // Primary block header: 1 byte (F=0)
            offset += 1;

            // Now parse data blocks
            let mut data_offset = offset;
            let mut redundant_entries = Vec::with_capacity(num_redundant);
            for &(pt, ts_off, block_len) in &redundant_headers[..num_redundant] {
                if data_offset + block_len > data.len() {
                    return None;
                }
                let block_data = &data[data_offset..data_offset + block_len];
                redundant_entries.push((pt, ts_off, block_data));
                data_offset += block_len;
            }

            // Remaining data is primary
            let primary_data = &data[data_offset..];
            let _ = rtp_timestamp; // available for future use
            return Some((block_pt, primary_data, redundant_entries));
        }
    }
}

/// Extracts essential RTP fields from raw packet data without constructing
/// an intermediate `RtpHeader` or `RtpPacket`.
///
/// Returns `(payload_type, sequence_number, timestamp, ssrc, payload_start, payload_end)`.
#[inline]
pub fn parse_rtp_fields(data: &[u8]) -> AudioResult<(u8, u16, u32, u32, usize, usize)> {
    if data.len() < RTP_HEADER_SIZE {
        return Err(AudioError::RtpError("packet too short".into()));
    }
    let first = data[0];
    let version = (first >> 6) & 0x03;
    if version != 2 {
        return Err(AudioError::RtpError("invalid RTP version".into()));
    }

    let has_padding = (first & 0x20) != 0;
    let has_extension = (first & 0x10) != 0;
    let csrc_count = (first & 0x0F) as usize;

    let payload_type = data[1] & 0x7F;
    let sequence_number = u16::from_be_bytes([data[2], data[3]]);
    let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let mut header_end = RTP_HEADER_SIZE + csrc_count * 4;
    if data.len() < header_end {
        return Err(AudioError::RtpError("packet too short for CSRC".into()));
    }

    // Skip extension header if present
    if has_extension {
        if data.len() < header_end + 4 {
            return Err(AudioError::RtpError("extension header too short".into()));
        }
        #[allow(clippy::cast_possible_truncation)]
        let ext_len = u16::from_be_bytes([data[header_end + 2], data[header_end + 3]]) as usize * 4;
        header_end += 4 + ext_len;
    }

    let mut payload_end = data.len();
    if has_padding {
        let pad_len = data[data.len() - 1] as usize;
        if pad_len > 0 && pad_len <= data.len() - header_end {
            payload_end -= pad_len;
        }
    }

    Ok((
        payload_type,
        sequence_number,
        timestamp,
        ssrc,
        header_end,
        payload_end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ssrc() {
        let ssrc1 = generate_ssrc();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ssrc2 = generate_ssrc();
        // SSRCs should be different (high probability)
        // Note: This could theoretically fail but is extremely unlikely
        assert_ne!(ssrc1, ssrc2);
    }

    #[test]
    fn test_rand_u16() {
        let a = rand_u16();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = rand_u16();
        assert_ne!(a, b);
    }

    #[test]
    fn test_rtp_stats_default() {
        let stats = RtpStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_rtp_transmitter_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let tx = RtpTransmitter::new(socket, remote, 12345, 0, 160);
        assert_eq!(tx.ssrc(), 12345);
    }

    #[test]
    fn test_rtp_receiver_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let jb = SharedJitterBuffer::new(8000, 160, 60);

        let rx = RtpReceiver::new(socket, jb);
        assert!(!rx.is_ready());
    }

    #[test]
    fn test_dtmf_payload_type_default() {
        assert_eq!(DTMF_PAYLOAD_TYPE, 101);
        assert_eq!(DTMF_CLOCK_RATE, 8000);
    }

    #[test]
    fn test_parse_rtp_fields_basic() {
        // Build a minimal RTP packet: V=2, PT=0, seq=100, ts=1600, ssrc=0xABCD_EF01
        let header = proto_rtp::RtpHeader::new(0, 100, 1600, 0xABCD_EF01);
        let header_bytes = header.to_bytes();
        let payload = [0u8; 160];
        let mut packet = Vec::with_capacity(header_bytes.len() + payload.len());
        packet.extend_from_slice(&header_bytes);
        packet.extend_from_slice(&payload);

        let (pt, seq, ts, ssrc, payload_start, payload_end) = parse_rtp_fields(&packet).unwrap();
        assert_eq!(pt, 0);
        assert_eq!(seq, 100);
        assert_eq!(ts, 1600);
        assert_eq!(ssrc, 0xABCD_EF01);
        assert_eq!(payload_start, 12);
        assert_eq!(payload_end, 12 + 160);
    }

    #[test]
    fn test_parse_rtp_fields_too_short() {
        let data = [0u8; 8];
        assert!(parse_rtp_fields(&data).is_err());
    }

    #[test]
    fn test_parse_rtp_fields_bad_version() {
        let mut data = [0u8; 12];
        data[0] = 0xC0; // Version 3
        assert!(parse_rtp_fields(&data).is_err());
    }

    #[test]
    fn test_parse_rfc2198_single_redundant() {
        // Build an RFC 2198 payload with one redundant block + primary.
        //
        // Redundant header (4 bytes): F=1 | PT=0 | ts_offset=160 | block_len=160
        // Primary header (1 byte): F=0 | PT=0
        // Redundant data: 160 bytes of 0xAA
        // Primary data: 160 bytes of 0xBB
        let ts_offset: u32 = 160;
        let block_len: usize = 160;
        let primary_pt: u8 = 0;
        let redundant_pt: u8 = 0;

        #[allow(clippy::cast_possible_truncation)]
        let mut payload = vec![
            0x80 | (redundant_pt & 0x7F),
            ((ts_offset >> 6) & 0xFF) as u8,
            (((ts_offset & 0x3F) << 2) as u8) | ((block_len >> 8) as u8 & 0x03),
            block_len as u8,
        ];
        // Primary block header (1 byte)
        payload.push(primary_pt & 0x7F);
        // Redundant data
        payload.extend_from_slice(&[0xAA; 160]);
        // Primary data
        payload.extend_from_slice(&[0xBB; 160]);

        let rtp_ts = 1000u32;
        let (parsed_pt, primary_data, redundant) = parse_rfc2198(&payload, rtp_ts).unwrap();

        assert_eq!(parsed_pt, primary_pt);
        assert_eq!(primary_data.len(), 160);
        assert!(primary_data.iter().all(|&b| b == 0xBB));
        assert_eq!(redundant.len(), 1);
        assert_eq!(redundant[0].0, redundant_pt); // pt
        assert_eq!(redundant[0].1, ts_offset); // ts_offset
        assert_eq!(redundant[0].2.len(), 160);
        assert!(redundant[0].2.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_parse_rfc2198_empty_payload() {
        assert!(parse_rfc2198(&[], 0).is_none());
    }

    #[test]
    fn test_parse_rfc2198_truncated_header() {
        // Only 2 bytes: F=1 but not enough for the 4-byte redundant header
        let payload = [0x80, 0x00];
        assert!(parse_rfc2198(&payload, 0).is_none());
    }

    #[test]
    fn test_parse_rfc2198_primary_only() {
        // F=0 | PT=0, then 80 bytes of primary data (no redundant blocks)
        let mut payload = vec![0x00u8]; // F=0, PT=0
        payload.extend_from_slice(&[0xCC; 80]);

        let (pt, primary_data, redundant) = parse_rfc2198(&payload, 500).unwrap();
        assert_eq!(pt, 0);
        assert_eq!(primary_data.len(), 80);
        assert!(primary_data.iter().all(|&b| b == 0xCC));
        assert!(redundant.is_empty());
    }

    #[test]
    fn test_rfc2198_send_roundtrip() {
        // Verify that the transmitter's RFC 2198 encoding can be parsed back.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = socket.local_addr().unwrap();
        let socket = Arc::new(socket);

        // Create a transmitter that sends to itself
        let mut tx = RtpTransmitter::new(socket.clone(), local_addr, 12345, 0, 160);
        tx.enable_redundancy(REDUNDANCY_PAYLOAD_TYPE);

        // First send — no redundancy yet (prev_payload is empty)
        let frame1 = [0x11u8; 160];
        tx.send(&frame1).unwrap();

        // Receive the first packet — should be plain (PT=0, not redundancy)
        let mut buf = [0u8; MAX_RTP_PACKET_SIZE];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        let (pt1, _, _, _, ps1, pe1) = parse_rtp_fields(&buf[..len]).unwrap();
        assert_eq!(pt1, 0, "first packet should have audio PT (no prev frame)");
        assert_eq!(pe1 - ps1, 160);

        // Second send — now redundancy kicks in
        let frame2 = [0x22u8; 160];
        tx.send(&frame2).unwrap();

        let (len2, _) = socket.recv_from(&mut buf).unwrap();
        let (pt2, _, ts2, _, ps2, pe2) = parse_rtp_fields(&buf[..len2]).unwrap();
        assert_eq!(
            pt2, REDUNDANCY_PAYLOAD_TYPE,
            "second packet should use redundancy PT"
        );

        // Parse the RFC 2198 body
        let rfc2198_body = &buf[ps2..pe2];
        let (primary_pt, primary_data, redundant) = parse_rfc2198(rfc2198_body, ts2).unwrap();
        assert_eq!(primary_pt, 0);
        assert_eq!(primary_data.len(), 160);
        assert!(primary_data.iter().all(|&b| b == 0x22));
        assert_eq!(redundant.len(), 1);
        assert_eq!(redundant[0].0, 0); // redundant PT = audio PT
        assert_eq!(redundant[0].1, 160); // ts_offset = timestamp_increment
        assert_eq!(redundant[0].2.len(), 160);
        assert!(redundant[0].2.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn test_dtmf_send() {
        use client_types::DtmfDigit;

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let mut tx = RtpTransmitter::new(socket, remote, 12345, 0, 160);

        // Create a DTMF event for digit '5'
        let event = DtmfEvent::new(DtmfDigit::Five, DtmfEvent::duration_from_ms(100));

        // Send should not panic (will fail because remote isn't listening, but that's OK)
        // We're just testing the packet construction
        let result = tx.send_dtmf(&event, true);
        // The send will succeed even if no one is listening (UDP)
        assert!(result.is_ok());
    }

    // ── SSRC collision detection (RFC 3550 §8.2) ────────────────

    #[test]
    fn test_ssrc_collision_detection() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let mut rx = RtpReceiver::new(Arc::new(socket), jb);

        let local_ssrc = 0xDEAD_BEEF;
        rx.set_local_ssrc(local_ssrc);
        assert!(!rx.ssrc_collision_detected());

        // Simulate receiving a packet with our own SSRC — collision!
        let mut pkt = vec![0u8; RTP_HEADER_SIZE + 160];
        pkt[0] = 0x80; // V=2
        pkt[1] = 0; // PT=0
        pkt[2..4].copy_from_slice(&1u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&160u32.to_be_bytes());
        pkt[8..12].copy_from_slice(&local_ssrc.to_be_bytes());

        rx.process_buffer[..pkt.len()].copy_from_slice(&pkt);
        rx.process_packet(pkt.len()).unwrap();

        assert!(rx.ssrc_collision_detected());
    }

    #[test]
    fn test_ssrc_no_collision_different_ssrc() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let mut rx = RtpReceiver::new(Arc::new(socket), jb);

        rx.set_local_ssrc(0xAAAA_BBBB);

        // Packet with a different SSRC — no collision
        let mut pkt = vec![0u8; RTP_HEADER_SIZE + 160];
        pkt[0] = 0x80;
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&1u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&160u32.to_be_bytes());
        pkt[8..12].copy_from_slice(&0xCCCC_DDDDu32.to_be_bytes());

        rx.process_buffer[..pkt.len()].copy_from_slice(&pkt);
        rx.process_packet(pkt.len()).unwrap();

        assert!(!rx.ssrc_collision_detected());
    }

    #[test]
    fn test_ssrc_collision_clear() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let mut rx = RtpReceiver::new(Arc::new(socket), jb);

        let local_ssrc = 0x1234_5678;
        rx.set_local_ssrc(local_ssrc);

        // Trigger collision
        let mut pkt = vec![0u8; RTP_HEADER_SIZE + 160];
        pkt[0] = 0x80;
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&1u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&160u32.to_be_bytes());
        pkt[8..12].copy_from_slice(&local_ssrc.to_be_bytes());

        rx.process_buffer[..pkt.len()].copy_from_slice(&pkt);
        rx.process_packet(pkt.len()).unwrap();

        assert!(rx.ssrc_collision_detected());
        rx.clear_ssrc_collision();
        assert!(!rx.ssrc_collision_detected());
    }

    #[test]
    fn test_transmitter_change_ssrc() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut tx = RtpTransmitter::new(Arc::new(socket), remote, 0xAAAA, 0, 160);

        assert_eq!(tx.ssrc(), 0xAAAA);
        tx.change_ssrc(0xBBBB);
        assert_eq!(tx.ssrc(), 0xBBBB);
    }

    // ── RTP header extension tests ──────────────────────────────

    #[test]
    fn test_transmitter_extension_map_send() {
        // Verify that setting an extension map produces packets with extensions.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = socket.local_addr().unwrap();
        let socket = Arc::new(socket);

        let mut tx = RtpTransmitter::new(socket.clone(), local_addr, 0xABCD, 0, 160);
        tx.set_extension_map(vec![(
            1,
            "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
        )]);

        // Header size should be larger than 12 now
        assert!(tx.header_size > RTP_HEADER_SIZE);

        // Send a packet and receive it
        let payload = [0x42u8; 160];
        tx.send(&payload).unwrap();

        let mut buf = [0u8; MAX_RTP_PACKET_SIZE];
        let (len, _) = socket.recv_from(&mut buf).unwrap();

        // The extension bit should be set (byte 0, bit 4)
        assert_ne!(buf[0] & 0x10, 0, "Extension bit should be set");

        // Parse the packet — parse_rtp_fields skips the extension correctly
        let (pt, _seq, _ts, ssrc, payload_start, payload_end) =
            parse_rtp_fields(&buf[..len]).unwrap();
        assert_eq!(pt, 0);
        assert_eq!(ssrc, 0xABCD);
        // Payload should still be 160 bytes
        assert_eq!(payload_end - payload_start, 160);
        // Payload should match what we sent
        assert!(buf[payload_start..payload_end].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_transmitter_no_extension_default() {
        // Without extension map, no extension header in packets.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = socket.local_addr().unwrap();
        let socket = Arc::new(socket);

        let mut tx = RtpTransmitter::new(socket.clone(), local_addr, 0x1234, 0, 160);
        assert_eq!(tx.header_size, RTP_HEADER_SIZE);

        let payload = [0xAA; 160];
        tx.send(&payload).unwrap();

        let mut buf = [0u8; MAX_RTP_PACKET_SIZE];
        let (len, _) = socket.recv_from(&mut buf).unwrap();

        // Extension bit should NOT be set
        assert_eq!(buf[0] & 0x10, 0, "Extension bit should not be set");
        assert_eq!(len, RTP_HEADER_SIZE + 160);
    }

    #[test]
    fn test_receiver_extension_map() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let mut rx = RtpReceiver::new(Arc::new(socket), jb);

        assert!(rx.extension_map().is_empty());
        rx.set_extension_map(vec![(
            1,
            "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
        )]);
        assert_eq!(rx.extension_map().len(), 1);
        assert_eq!(rx.extension_map()[0].0, 1);
    }
}
