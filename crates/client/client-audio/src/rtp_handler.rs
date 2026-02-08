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
use proto_rtp::{RtpHeader, RtpPacket};
use proto_srtp::{SrtpContext, SrtpProtect, SrtpUnprotect};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

/// Default RTP payload type for audio.
pub const DEFAULT_PAYLOAD_TYPE: u8 = 0; // PCMU

/// RTP header size in bytes.
pub const RTP_HEADER_SIZE: usize = 12;

/// Maximum RTP packet size.
pub const MAX_RTP_PACKET_SIZE: usize = 1500;

/// SRTP authentication tag size for AES-256-GCM.
pub const SRTP_AUTH_TAG_SIZE: usize = 16;

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
    fn new() -> Self {
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
    /// Current DTMF timestamp (separate from audio).
    dtmf_timestamp: AtomicU32,
    /// Timestamp of the current DTMF event (stays constant for one event).
    #[allow(dead_code)] // Read via atomic operations
    dtmf_event_timestamp: AtomicU32,
    /// Pre-allocated buffer for serializing non-SRTP packets (header + payload).
    send_buffer: Vec<u8>,
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
            dtmf_timestamp: AtomicU32::new(rand_u32()),
            dtmf_event_timestamp: AtomicU32::new(0),
            send_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
        }
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

    /// Sends an RTP packet with the given audio payload.
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

        let header = RtpHeader::new(self.payload_type, seq, ts, self.ssrc);

        let protected: Bytes;
        let send_data: &[u8] = if let Some(ref srtp) = self.srtp {
            let protector = SrtpProtect::new(srtp);
            match protector.protect_rtp_parts(&header, payload) {
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
            // Zero-alloc: write header + payload into pre-allocated send_buffer.
            let header_size = header.write_into(&mut self.send_buffer);
            let total = header_size + payload.len();
            self.send_buffer[header_size..total].copy_from_slice(payload);
            &self.send_buffer[..total]
        };

        match self.socket.send_to(send_data, self.remote_addr) {
            Ok(sent) => {
                trace!("Sent RTP packet: seq={}, ts={}, size={}", seq, ts, sent);
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
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
            match protector.protect_rtp_parts(&header, payload) {
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
                self.stats.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
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
    #[allow(clippy::cast_sign_loss)]
    pub fn send_dtmf(&mut self, event: &DtmfEvent, marker: bool) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        // For DTMF, timestamp stays the same for the duration of the event
        // (it's the timestamp of when the event started)
        let ts = if marker {
            // Start of a new event - get a new timestamp and store it
            let new_ts = self.dtmf_timestamp.load(Ordering::Relaxed);
            self.dtmf_event_timestamp.store(new_ts, Ordering::Relaxed);
            new_ts
        } else {
            // Continuation/end - use the stored event timestamp
            self.dtmf_event_timestamp.load(Ordering::Relaxed)
        };

        // Advance the timestamp counter only at the end of the event
        if event.end {
            self.dtmf_timestamp
                .fetch_add(u32::from(event.duration), Ordering::Relaxed);
        }

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
            match protector.protect_rtp_parts(&header, &payload) {
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
                self.stats.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                Err(AudioError::RtpError(format!("DTMF send failed: {e}")))
            }
        }
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
}

impl RtpReceiver {
    /// Creates a new RTP receiver.
    pub fn new(socket: Arc<UdpSocket>, jitter_buffer: SharedJitterBuffer) -> Self {
        info!("Creating RTP receiver");

        Self {
            socket,
            expected_remote: None,
            srtp: None,
            jitter_buffer,
            stats: Arc::new(AtomicRtpStats::new()),
            recv_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            process_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            remote_ssrc: None,
        }
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
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn process_packet(&mut self, len: usize) -> AudioResult<()> {
        let data = &self.process_buffer[..len];

        // Decrypt if SRTP is configured
        let packet = if let Some(ref srtp) = self.srtp {
            let unprotector = SrtpUnprotect::new(srtp);
            match unprotector.unprotect_rtp(data) {
                Ok(pkt) => pkt,
                Err(e) => {
                    self.stats.srtp_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(AudioError::SrtpError(format!("SRTP unprotect failed: {e}")));
                }
            }
        } else {
            RtpPacket::parse(data)
                .map_err(|e| AudioError::RtpError(format!("Parse failed: {e}")))?
        };

        trace!(
            "Received RTP packet: seq={}, ts={}, pt={}",
            packet.header.sequence_number, packet.header.timestamp, packet.header.payload_type
        );

        // Track remote SSRC — detect changes mid-call (RFC 3550 §8.2).
        match self.remote_ssrc {
            None => {
                self.remote_ssrc = Some(packet.header.ssrc);
                debug!("Learned remote SSRC: {:#010x}", packet.header.ssrc);
            }
            Some(prev) if prev != packet.header.ssrc => {
                warn!(
                    "Remote SSRC changed: {:#010x} -> {:#010x}, resetting jitter buffer",
                    prev, packet.header.ssrc
                );
                self.remote_ssrc = Some(packet.header.ssrc);
                self.jitter_buffer.reset();
            }
            _ => {}
        }

        // Add to shared jitter buffer
        let buffered = BufferedPacket::new(
            packet.header.sequence_number,
            packet.header.timestamp,
            packet.header.payload_type,
            packet.payload,
        );
        self.jitter_buffer.push(buffered);

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation)]
        self.stats.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

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
        .map(|d| d.as_nanos() as u64)
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
    state = state.wrapping_mul(0xbf58476d1ce4e5b9);
    state ^= state >> 27;
    state = state.wrapping_mul(0x94d049bb133111eb);
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
}
