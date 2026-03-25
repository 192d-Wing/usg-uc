//! RTCP session handler for sending Sender Reports and Receiver Reports.
//!
//! Sends compound RTCP packets (SR + SDES or RR + SDES) every 5 seconds
//! via the RTCP socket (RTP port + 1). Tracks send/receive statistics
//! needed for RFC 3550 compliant reports.
//!
//! ## Compound Packet Format (RFC 3550 §6.1)
//!
//! ```text
//! ┌──────────────────┐
//! │  Sender Report   │  (if we are sending)
//! │  or              │
//! │  Receiver Report │  (if receive-only)
//! ├──────────────────┤
//! │  SDES (CNAME)    │
//! └──────────────────┘
//! ```

use crate::jitter_buffer::JitterBufferStats;
use crate::rtp_handler::RtpStats;
use bytes::{BufMut, BytesMut};
use proto_rtp::{ReceptionReport, RtcpHeader, RtcpType, SenderInfo};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};

/// RTCP send interval (5 seconds per RFC 3550 recommendation).
const RTCP_INTERVAL: Duration = Duration::from_secs(5);

/// NTP epoch offset: seconds between 1900-01-01 and 1970-01-01.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// SDES item type: CNAME (Canonical Name).
const SDES_CNAME: u8 = 1;

/// RTCP session state.
pub struct RtcpSession {
    /// UDP socket for RTCP (typically RTP port + 1).
    socket: Arc<UdpSocket>,
    /// Remote RTCP address.
    remote_addr: SocketAddr,
    /// Local SSRC (same as RTP SSRC).
    local_ssrc: u32,
    /// Remote SSRC (learned from received SR/RR).
    remote_ssrc: Option<u32>,
    /// CNAME for SDES (e.g., "user@host").
    cname: String,
    /// Codec clock rate (for jitter timestamp conversion).
    clock_rate: u32,
    /// Last time an RTCP packet was sent.
    last_send_time: Instant,
    /// Snapshot of TX stats at the time of last SR.
    last_sr_tx_stats: RtpStats,
    /// Last RTP timestamp sent (for SR).
    last_rtp_timestamp: u32,
    /// Timestamp of last received SR (middle 32 bits of NTP, for DLSR calc).
    last_received_sr_ntp: u32,
    /// When the last SR was received (for DLSR calc).
    last_received_sr_time: Option<Instant>,
    /// Previous cumulative packets received (for fraction lost calc).
    prev_packets_received: u64,
    /// Previous cumulative lost (for fraction lost calc).
    prev_cumulative_lost: u64,
    /// Receive buffer for incoming RTCP packets.
    recv_buffer: Vec<u8>,
    /// Latest measured round-trip time in milliseconds (from RR block LSR/DLSR).
    rtt_ms: Option<f32>,
}

impl RtcpSession {
    /// Creates a new RTCP session.
    ///
    /// # Arguments
    /// * `socket` - UDP socket (should be bound to RTP port + 1)
    /// * `remote_addr` - Remote RTCP address (remote RTP port + 1)
    /// * `local_ssrc` - Local SSRC (same as RTP stream)
    /// * `clock_rate` - Codec clock rate (Hz) for jitter conversion
    /// * `cname` - Canonical name for SDES
    pub fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        local_ssrc: u32,
        clock_rate: u32,
        cname: String,
    ) -> Self {
        debug!(
            "RTCP session created: remote={}, ssrc={}, clock_rate={}, cname={}",
            remote_addr, local_ssrc, clock_rate, cname
        );

        Self {
            socket,
            remote_addr,
            local_ssrc,
            remote_ssrc: None,
            cname,
            clock_rate,
            last_send_time: Instant::now(),
            last_sr_tx_stats: RtpStats::default(),
            last_rtp_timestamp: 0,
            last_received_sr_ntp: 0,
            last_received_sr_time: None,
            prev_packets_received: 0,
            prev_cumulative_lost: 0,
            recv_buffer: vec![0u8; 512],
            rtt_ms: None,
        }
    }

    /// Updates the local SSRC (used after SSRC collision resolution).
    pub fn set_local_ssrc(&mut self, ssrc: u32) {
        debug!("RTCP session SSRC updated to {:#010x}", ssrc);
        self.local_ssrc = ssrc;
    }

    /// Checks if it's time to send an RTCP report and sends one if so.
    ///
    /// Call this from the I/O thread on every iteration. It internally
    /// tracks the 5-second interval.
    pub fn maybe_send_report(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        if self.last_send_time.elapsed() < RTCP_INTERVAL {
            return;
        }
        self.last_send_time = Instant::now();

        self.send_compound_report(tx_stats, jb_stats);
    }

    /// Updates the last RTP timestamp (call after each RTP send).
    pub const fn update_rtp_timestamp(&mut self, ts: u32) {
        self.last_rtp_timestamp = ts;
    }

    /// Sets the remote SSRC (learned from received RTP/RTCP).
    pub const fn set_remote_ssrc(&mut self, ssrc: u32) {
        self.remote_ssrc = Some(ssrc);
    }

    /// Records receipt of a Sender Report from the remote.
    ///
    /// Extracts the middle 32 bits of NTP timestamp for DLSR calculation.
    #[allow(clippy::similar_names)]
    pub fn received_sender_report(&mut self, ntp_sec: u32, ntp_frac: u32) {
        // Middle 32 bits: lower 16 of seconds + upper 16 of fraction
        self.last_received_sr_ntp = ((ntp_sec & 0xFFFF) << 16) | ((ntp_frac >> 16) & 0xFFFF);
        self.last_received_sr_time = Some(Instant::now());
    }

    /// Receives and processes an incoming RTCP packet (non-blocking).
    ///
    /// Parses Sender Report headers from the remote to enable DLSR
    /// calculation in our outgoing Receiver Reports.
    pub fn try_receive(&mut self) {
        let result = self.socket.recv_from(&mut self.recv_buffer);
        match result {
            Ok((len, _addr)) if len >= 8 => {
                // Minimal RTCP header check: V=2
                let version = (self.recv_buffer[0] >> 6) & 0x03;
                let pt = self.recv_buffer[1];
                let rc = self.recv_buffer[0] & 0x1F; // report count
                if version == 2 && pt == 200 && len >= 28 {
                    // Sender Report: NTP timestamp at bytes 8-15
                    let ntp_sec = u32::from_be_bytes([
                        self.recv_buffer[8],
                        self.recv_buffer[9],
                        self.recv_buffer[10],
                        self.recv_buffer[11],
                    ]);
                    let ntp_frac = u32::from_be_bytes([
                        self.recv_buffer[12],
                        self.recv_buffer[13],
                        self.recv_buffer[14],
                        self.recv_buffer[15],
                    ]);
                    self.received_sender_report(ntp_sec, ntp_frac);
                    trace!(
                        "Received RTCP SR: ntp={}.{}, lsr={:#010x}",
                        ntp_sec, ntp_frac, self.last_received_sr_ntp
                    );

                    // Parse RR blocks within the SR (start at byte 28, each 24 bytes)
                    self.extract_rtt_from_rr_blocks(len, 28, rc);
                } else if version == 2 && pt == 201 && len >= 8 {
                    // Receiver Report: RR blocks start at byte 8 (after header + SSRC)
                    self.extract_rtt_from_rr_blocks(len, 8, rc);
                }
            }
            Ok(_) | Err(_) => {
                // No packet or too short — ignore
            }
        }
    }

    /// Extracts RTT from Reception Report blocks.
    ///
    /// Each RR block is 24 bytes. We look for one whose LSR matches our
    /// last sent SR (middle 32 bits of our NTP timestamp). RTT is then:
    ///   RTT = now_ntp_middle32 - LSR - DLSR
    #[allow(clippy::cast_precision_loss)]
    fn extract_rtt_from_rr_blocks(&mut self, data_len: usize, start: usize, count: u8) {
        for i in 0..count as usize {
            let offset = start + i * 24;
            if offset + 24 > data_len {
                break;
            }
            // RR block layout (24 bytes):
            //   0-3: SSRC of source
            //   4:   fraction lost
            //   5-7: cumulative lost (24 bits)
            //   8-11: extended highest seq
            //  12-15: interarrival jitter
            //  16-19: LSR (last SR NTP middle 32 bits)
            //  20-23: DLSR (delay since last SR, 1/65536 sec units)
            let lsr = u32::from_be_bytes([
                self.recv_buffer[offset + 16],
                self.recv_buffer[offset + 17],
                self.recv_buffer[offset + 18],
                self.recv_buffer[offset + 19],
            ]);
            let dlsr = u32::from_be_bytes([
                self.recv_buffer[offset + 20],
                self.recv_buffer[offset + 21],
                self.recv_buffer[offset + 22],
                self.recv_buffer[offset + 23],
            ]);

            // Skip if remote hasn't received an SR from us yet
            if lsr == 0 {
                continue;
            }

            // Current NTP time as middle 32 bits
            let (ntp_sec, ntp_frac) = get_ntp_timestamp();
            let now_mid = ((ntp_sec & 0xFFFF) << 16) | ((ntp_frac >> 16) & 0xFFFF);

            // RTT in 1/65536 second units
            let rtt_fixed = now_mid.wrapping_sub(lsr).wrapping_sub(dlsr);

            // Convert to milliseconds: rtt_fixed / 65536 * 1000
            let rtt = (rtt_fixed as f32 / 65536.0) * 1000.0;

            // Sanity check: RTT should be positive and < 10 seconds
            if rtt > 0.0 && rtt < 10_000.0 {
                debug!(
                    "RTCP RTT measured: {:.1}ms (LSR={:#010x}, DLSR={:#010x})",
                    rtt, lsr, dlsr
                );
                self.rtt_ms = Some(rtt);
            }
        }
    }

    /// Returns the latest measured RTT in milliseconds, or `None` if not yet available.
    pub const fn rtt_ms(&self) -> Option<f32> {
        self.rtt_ms
    }

    /// Sends a compound RTCP packet (SR + SDES or RR + SDES).
    fn send_compound_report(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        let mut compound = BytesMut::with_capacity(256);

        if tx_stats.packets_sent > 0 {
            // We are a sender — send Sender Report
            self.build_sender_report(&mut compound, tx_stats, jb_stats);
        } else {
            // Receive-only — send Receiver Report
            self.build_receiver_report(&mut compound, jb_stats);
        }

        // Always append SDES (CNAME)
        self.build_sdes(&mut compound);

        // Send
        match self.socket.send_to(&compound, self.remote_addr) {
            Ok(sent) => {
                trace!(
                    "Sent RTCP compound packet: {} bytes to {}",
                    sent, self.remote_addr
                );
            }
            Err(e) => {
                trace!("RTCP send failed: {e}");
                // Non-fatal — RTCP failure shouldn't affect audio
            }
        }
    }

    /// Builds a Sender Report packet into the compound buffer.
    #[allow(clippy::similar_names)]
    fn build_sender_report(
        &mut self,
        buf: &mut BytesMut,
        tx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        let (ntp_sec, ntp_frac) = get_ntp_timestamp();

        let has_rr = self.remote_ssrc.is_some() && jb_stats.packets_received > 0;
        let rc = u8::from(has_rr);

        #[allow(clippy::cast_possible_truncation)]
        let sender_info = SenderInfo {
            ssrc: self.local_ssrc,
            ntp_timestamp_msw: ntp_sec,
            ntp_timestamp_lsw: ntp_frac,
            rtp_timestamp: self.last_rtp_timestamp,
            sender_packet_count: tx_stats.packets_sent as u32,
            sender_octet_count: tx_stats.bytes_sent as u32,
        };

        let si_bytes = sender_info.to_bytes();

        // Build reception report block if we have a remote SSRC
        let rr_bytes = if has_rr {
            Some(self.build_reception_report_block(jb_stats))
        } else {
            None
        };

        // RTCP length = (total packet size / 4) - 1
        // SR with sender info = 4 (header) + 24 (sender info) = 28 bytes = 7 words → length = 6
        // SR with sender info + 1 RR = 4 + 24 + 24 = 52 bytes = 13 words → length = 12
        let payload_len: usize = 24 + if has_rr { 24 } else { 0 };
        let total_words = 1 + (payload_len / 4); // 1 for header word
        #[allow(clippy::cast_possible_truncation)]
        let length = (total_words - 1) as u16;

        let mut header = RtcpHeader::new(RtcpType::SenderReport, rc);
        header.length = length;

        buf.put(header.to_bytes());
        buf.put(si_bytes);

        if let Some(rr) = rr_bytes {
            buf.put(rr);
        }

        // Update snapshot for next interval's fraction lost calculation
        self.last_sr_tx_stats = tx_stats.clone();
    }

    /// Builds a Receiver Report packet into the compound buffer.
    fn build_receiver_report(&mut self, buf: &mut BytesMut, jb_stats: &JitterBufferStats) {
        let has_rr = self.remote_ssrc.is_some() && jb_stats.packets_received > 0;
        let rc = u8::from(has_rr);

        // RR: 4 (header) + 4 (SSRC) + 24*rc
        let payload_len: usize = 4 + if has_rr { 24 } else { 0 };
        #[allow(clippy::cast_possible_truncation)]
        let length = (payload_len / 4) as u16;

        let mut header = RtcpHeader::new(RtcpType::ReceiverReport, rc);
        header.length = length;

        buf.put(header.to_bytes());
        buf.put_u32(self.local_ssrc);

        if has_rr {
            let rr = self.build_reception_report_block(jb_stats);
            buf.put(rr);
        }
    }

    /// Builds a single reception report block (24 bytes).
    ///
    /// Uses jitter buffer stats for loss/jitter (the authoritative source
    /// for actual stream loss), and `self.clock_rate` for correct jitter
    /// timestamp conversion.
    fn build_reception_report_block(&mut self, jb_stats: &JitterBufferStats) -> bytes::Bytes {
        let remote_ssrc = self.remote_ssrc.unwrap_or(0);

        // Fraction lost: packets lost in this interval / packets expected in this interval.
        // Use jb_stats.packets_lost (actual stream gaps detected by the jitter buffer)
        // instead of rx_stats.packets_dropped (which counts SRTP/socket errors).
        let received_this_interval = jb_stats
            .packets_received
            .saturating_sub(self.prev_packets_received);
        let lost_this_interval = jb_stats
            .packets_lost
            .saturating_sub(self.prev_cumulative_lost);
        let expected_this_interval = received_this_interval + lost_this_interval;

        #[allow(clippy::cast_possible_truncation)]
        let fraction_lost = if expected_this_interval > 0 {
            ((lost_this_interval * 256) / expected_this_interval) as u8
        } else {
            0
        };

        // Cumulative lost (total)
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let cumulative_lost = jb_stats.packets_lost as i32;

        // Extended highest sequence (use total received + lost as proxy for highest seq)
        #[allow(clippy::cast_possible_truncation)]
        let extended_highest_seq = (jb_stats.packets_received + jb_stats.packets_lost) as u32;

        // Jitter in timestamp units: ms × (clock_rate / 1000)
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let jitter = (jb_stats.average_jitter_ms * (self.clock_rate as f32 / 1000.0)) as u32;

        // DLSR (delay since last SR in 1/65536 seconds)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let dlsr = self
            .last_received_sr_time
            .map_or(0, |t| (t.elapsed().as_secs_f64() * 65536.0) as u32);

        let report = ReceptionReport {
            ssrc: remote_ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq,
            jitter,
            last_sr: self.last_received_sr_ntp,
            delay_since_last_sr: dlsr,
        };

        // Update previous values for next interval
        self.prev_packets_received = jb_stats.packets_received;
        self.prev_cumulative_lost = jb_stats.packets_lost;

        report.to_bytes()
    }

    /// Builds an SDES packet with CNAME item into the compound buffer.
    fn build_sdes(&self, buf: &mut BytesMut) {
        let cname_bytes = self.cname.as_bytes();
        let cname_len = cname_bytes.len().min(255);

        // SDES chunk: SSRC (4) + CNAME item (2 + len) + end item (1) + padding
        let chunk_len = 4 + 2 + cname_len + 1; // SSRC + type + len + data + end
        let padded_len = (chunk_len + 3) & !3; // Round up to 4-byte boundary
        let padding = padded_len - chunk_len;

        // Total packet: header (4) + chunk
        #[allow(clippy::cast_possible_truncation)]
        let length = (padded_len / 4) as u16;

        let mut header = RtcpHeader::new(RtcpType::SourceDescription, 1); // 1 chunk
        header.length = length;

        buf.put(header.to_bytes());
        buf.put_u32(self.local_ssrc);
        buf.put_u8(SDES_CNAME);
        #[allow(clippy::cast_possible_truncation)]
        buf.put_u8(cname_len as u8);
        buf.put(&cname_bytes[..cname_len]);
        buf.put_u8(0); // End item
        // Pad to 4-byte boundary
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }
}

/// Returns the current time as NTP timestamp (seconds, fraction).
///
/// NTP timestamps count seconds since 1900-01-01.
fn get_ntp_timestamp() -> (u32, u32) {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);

    let ntp_secs = since_epoch.as_secs() + NTP_EPOCH_OFFSET;
    // Fractional part: subsec_nanos / 10^9 * 2^32
    #[allow(clippy::cast_possible_truncation)]
    let ntp_frac = ((u64::from(since_epoch.subsec_nanos()) << 32) / 1_000_000_000) as u32;

    #[allow(clippy::cast_possible_truncation)]
    (ntp_secs as u32, ntp_frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp() {
        let (sec, frac) = get_ntp_timestamp();
        // Seconds should be > NTP_EPOCH_OFFSET (we're past 1970)
        #[allow(clippy::cast_possible_truncation)]
        let offset = NTP_EPOCH_OFFSET as u32;
        assert!(sec > offset);
        // Fraction is fractional, just check it's a valid u32
        let _ = frac;
    }

    #[test]
    fn test_rtcp_session_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let session = RtcpSession::new(socket, remote, 12345, 8000, "user@host".to_string());
        assert_eq!(session.local_ssrc, 12345);
        assert!(session.remote_ssrc.is_none());
    }

    #[test]
    fn test_send_sr_compound() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());

        let tx_stats = RtpStats {
            packets_sent: 100,
            bytes_sent: 16000,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats::default();

        // Force immediate send by backdating last_send_time
        session.last_send_time = Instant::now() - Duration::from_secs(10);
        session.maybe_send_report(&tx_stats, &jb_stats);
        // Should not panic; packet sent to non-listening address is fine for UDP
    }

    #[test]
    fn test_send_rr_with_remote_ssrc() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());
        session.set_remote_ssrc(67890);

        let tx_stats = RtpStats::default(); // Not sending → RR
        let jb_stats = JitterBufferStats {
            packets_received: 500,
            packets_lost: 5,
            average_jitter_ms: 10.5,
            ..JitterBufferStats::default()
        };

        session.last_send_time = Instant::now() - Duration::from_secs(10);
        session.maybe_send_report(&tx_stats, &jb_stats);
    }

    #[test]
    fn test_interval_gating() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());

        let tx_stats = RtpStats::default();
        let jb_stats = JitterBufferStats::default();

        // Should NOT send (just created, interval not elapsed)
        let before = session.last_send_time;
        session.maybe_send_report(&tx_stats, &jb_stats);
        assert_eq!(
            session.last_send_time, before,
            "Should not have sent (interval not elapsed)"
        );
    }

    #[test]
    fn test_received_sender_report() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());

        // Simulate receiving an SR with NTP timestamp
        session.received_sender_report(0xDEAD_BEEF, 0x1234_5678);
        assert_eq!(session.last_received_sr_ntp, 0xBEEF_1234);
        assert!(session.last_received_sr_time.is_some());
    }

    #[test]
    fn test_build_sdes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let session =
            RtcpSession::new(socket, remote, 12345, 8000, "alice@example.com".to_string());

        let mut buf = BytesMut::new();
        session.build_sdes(&mut buf);

        // Should be at least 4 (header) + 4 (SSRC) + 2 (type+len) + cname + 1 (end)
        assert!(buf.len() >= 4 + 4 + 2 + 1);
        // Should be 4-byte aligned
        assert_eq!(buf.len() % 4, 0);
    }

    #[test]
    fn test_fraction_lost_calculation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());
        session.set_remote_ssrc(67890);

        // First interval: 100 received, 10 lost → 10/110 ≈ 9% → fraction ≈ 23/256
        let jb_stats = JitterBufferStats {
            packets_received: 100,
            packets_lost: 10,
            ..JitterBufferStats::default()
        };

        let rr_bytes = session.build_reception_report_block(&jb_stats);
        let rr = ReceptionReport::parse(&rr_bytes).unwrap();
        assert!(rr.fraction_lost > 0, "Should report some loss");
        assert!(rr.fraction_lost < 50, "Should not be extreme loss");
    }

    #[test]
    fn test_jitter_clock_rate_conversion() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        // 48kHz clock rate (e.g., Opus)
        let mut session = RtcpSession::new(socket, remote, 12345, 48000, "test@host".to_string());
        session.set_remote_ssrc(67890);

        let jb_stats = JitterBufferStats {
            packets_received: 100,
            average_jitter_ms: 10.0, // 10ms jitter
            ..JitterBufferStats::default()
        };

        let rr_bytes = session.build_reception_report_block(&jb_stats);
        let rr = ReceptionReport::parse(&rr_bytes).unwrap();

        // 10ms × 48 = 480 timestamp units (at 48kHz)
        assert_eq!(rr.jitter, 480);
    }
}
