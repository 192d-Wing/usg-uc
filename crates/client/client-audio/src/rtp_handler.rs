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
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, trace};

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
    /// SRTP context for encryption.
    srtp: Option<Arc<Mutex<SrtpContext>>>,
    /// Statistics.
    stats: Arc<Mutex<RtpStats>>,
    /// DTMF payload type (telephone-event).
    dtmf_payload_type: u8,
    /// Current DTMF timestamp (separate from audio).
    dtmf_timestamp: AtomicU32,
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
            stats: Arc::new(Mutex::new(RtpStats::default())),
            dtmf_payload_type: DTMF_PAYLOAD_TYPE,
            dtmf_timestamp: AtomicU32::new(rand_u32()),
        }
    }

    /// Sets the DTMF payload type (default is 101).
    pub fn set_dtmf_payload_type(&mut self, pt: u8) {
        self.dtmf_payload_type = pt;
        debug!("DTMF payload type set to {}", pt);
    }

    /// Sets the SRTP context for encryption.
    pub fn set_srtp(&mut self, context: Arc<Mutex<SrtpContext>>) {
        self.srtp = Some(context);
        debug!("SRTP encryption enabled for transmitter");
    }

    /// Sends an RTP packet with the given audio payload.
    #[allow(clippy::cast_sign_loss, clippy::significant_drop_tightening)]
    pub fn send(&mut self, payload: &[u8]) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let ts = self
            .timestamp
            .fetch_add(self.timestamp_increment, Ordering::Relaxed);

        // Build RTP header
        let header = RtpHeader::new(self.payload_type, seq, ts, self.ssrc);

        // Build packet
        let packet = RtpPacket::new(header, Bytes::copy_from_slice(payload));
        let packet_bytes = packet.to_bytes();

        // Apply SRTP if configured
        let send_bytes = if let Some(ref srtp) = self.srtp {
            let srtp_guard = srtp
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let protector = SrtpProtect::new(&srtp_guard);
            match protector.protect_rtp(&packet) {
                Ok(protected) => protected.to_vec(),
                Err(e) => {
                    drop(srtp_guard);
                    let mut stats = self
                        .stats
                        .lock()
                        .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                    stats.srtp_errors += 1;
                    return Err(AudioError::SrtpError(format!("SRTP protect failed: {e}")));
                }
            }
        } else {
            packet_bytes.to_vec()
        };

        // Send packet
        match self.socket.send_to(&send_bytes, self.remote_addr) {
            Ok(sent) => {
                trace!("Sent RTP packet: seq={}, ts={}, size={}", seq, ts, sent);
                let mut stats = self
                    .stats
                    .lock()
                    .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                stats.packets_sent += 1;
                stats.bytes_sent += sent as u64;
                Ok(())
            }
            Err(e) => {
                let mut stats = self
                    .stats
                    .lock()
                    .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                stats.packets_dropped += 1;
                Err(AudioError::RtpError(format!("Send failed: {e}")))
            }
        }
    }

    /// Returns the current statistics.
    pub fn stats(&self) -> RtpStats {
        self.stats
            .lock()
            .map_or_else(|_| RtpStats::default(), |s| s.clone())
    }

    /// Returns the SSRC.
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
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
    #[allow(clippy::cast_sign_loss, clippy::significant_drop_tightening)]
    pub fn send_dtmf(&mut self, event: &DtmfEvent, marker: bool) -> AudioResult<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        // For DTMF, timestamp stays the same for the duration of the event
        // (it's the timestamp of when the event started)
        let ts = if marker {
            // Start of a new event - get a new timestamp
            self.dtmf_timestamp
                .fetch_add(u32::from(event.duration), Ordering::Relaxed)
        } else {
            // Continuation - use the current timestamp without incrementing
            self.dtmf_timestamp.load(Ordering::Relaxed) - u32::from(event.duration)
        };

        // Build RTP header with DTMF payload type
        let mut header = RtpHeader::new(self.dtmf_payload_type, seq, ts, self.ssrc);
        if marker {
            header.marker = true;
        }

        // Encode DTMF event payload (4 bytes per RFC 4733)
        let payload = event.encode();

        // Build packet
        let packet = RtpPacket::new(header, Bytes::copy_from_slice(&payload));
        let packet_bytes = packet.to_bytes();

        // Apply SRTP if configured
        let send_bytes = if let Some(ref srtp) = self.srtp {
            let srtp_guard = srtp
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let protector = SrtpProtect::new(&srtp_guard);
            match protector.protect_rtp(&packet) {
                Ok(protected) => protected.to_vec(),
                Err(e) => {
                    drop(srtp_guard);
                    let mut stats = self
                        .stats
                        .lock()
                        .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                    stats.srtp_errors += 1;
                    return Err(AudioError::SrtpError(format!("SRTP protect failed: {e}")));
                }
            }
        } else {
            packet_bytes.to_vec()
        };

        // Send packet
        match self.socket.send_to(&send_bytes, self.remote_addr) {
            Ok(sent) => {
                trace!(
                    "Sent DTMF packet: digit={}, seq={}, ts={}, end={}, marker={}",
                    event.digit, seq, ts, event.end, marker
                );
                let mut stats = self
                    .stats
                    .lock()
                    .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                stats.packets_sent += 1;
                stats.bytes_sent += sent as u64;
                Ok(())
            }
            Err(e) => {
                let mut stats = self
                    .stats
                    .lock()
                    .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                stats.packets_dropped += 1;
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
    /// SRTP context for decryption.
    srtp: Option<Arc<Mutex<SrtpContext>>>,
    /// Shared jitter buffer (also read by decode thread).
    jitter_buffer: SharedJitterBuffer,
    /// Statistics.
    stats: Arc<Mutex<RtpStats>>,
    /// Buffer for receiving packets.
    recv_buffer: Vec<u8>,
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
            stats: Arc::new(Mutex::new(RtpStats::default())),
            recv_buffer: vec![0u8; MAX_RTP_PACKET_SIZE],
            remote_ssrc: None,
        }
    }

    /// Sets the expected remote address for packet filtering.
    pub const fn set_expected_remote(&mut self, addr: SocketAddr) {
        self.expected_remote = Some(addr);
    }

    /// Sets the SRTP context for decryption.
    pub fn set_srtp(&mut self, context: Arc<Mutex<SrtpContext>>) {
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

                // Process the packet (copy to avoid borrow conflict with self)
                let data = self.recv_buffer[..len].to_vec();
                self.process_packet(&data)?;
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

    /// Processes a received packet.
    #[allow(clippy::needless_pass_by_ref_mut, clippy::significant_drop_tightening)]
    fn process_packet(&mut self, data: &[u8]) -> AudioResult<()> {
        // Decrypt if SRTP is configured
        let packet = if let Some(ref srtp) = self.srtp {
            let srtp_guard = srtp
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let unprotector = SrtpUnprotect::new(&srtp_guard);
            match unprotector.unprotect_rtp(data) {
                Ok(pkt) => pkt,
                Err(e) => {
                    drop(srtp_guard);
                    let mut stats = self
                        .stats
                        .lock()
                        .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
                    stats.srtp_errors += 1;
                    return Err(AudioError::SrtpError(format!("SRTP unprotect failed: {e}")));
                }
            }
        } else {
            // Parse RTP packet directly
            RtpPacket::parse(data)
                .map_err(|e| AudioError::RtpError(format!("Parse failed: {e}")))?
        };

        trace!(
            "Received RTP packet: seq={}, ts={}, pt={}",
            packet.header.sequence_number, packet.header.timestamp, packet.header.payload_type
        );

        // Add to shared jitter buffer
        let buffered = BufferedPacket::new(
            packet.header.sequence_number,
            packet.header.timestamp,
            packet.header.payload_type,
            packet.payload,
        );

        // Track remote SSRC (first packet sets it)
        if self.remote_ssrc.is_none() {
            self.remote_ssrc = Some(packet.header.ssrc);
            debug!("Learned remote SSRC: {}", packet.header.ssrc);
        }

        self.jitter_buffer.push(buffered);

        let mut stats = self
            .stats
            .lock()
            .map_err(|_| AudioError::RtpError("Failed to lock stats".to_string()))?;
        stats.packets_received += 1;
        #[allow(clippy::cast_possible_truncation)]
        {
            stats.bytes_received += data.len() as u64;
        }

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
        self.stats
            .lock()
            .map_or_else(|_| RtpStats::default(), |s| s.clone())
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

/// Generates a random u16 for sequence number initialization.
#[allow(clippy::cast_possible_truncation)]
fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (now & 0xFFFF) as u16
}

/// Generates a random u32 for SSRC/timestamp initialization.
#[allow(clippy::cast_possible_truncation)]
fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (now & 0xFFFF_FFFF) as u32
}

/// Generates a random SSRC.
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
