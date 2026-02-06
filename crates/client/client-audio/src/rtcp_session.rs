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
use proto_rtp::{RtcpHeader, RtcpType, ReceptionReport, SenderInfo};
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
    /// Previous highest sequence number (for fraction lost calc).
    prev_highest_seq: u32,
    /// Previous cumulative packets received (for fraction lost calc).
    prev_packets_received: u64,
    /// Previous cumulative lost (for fraction lost calc).
    prev_cumulative_lost: u64,
}

impl RtcpSession {
    /// Creates a new RTCP session.
    ///
    /// # Arguments
    /// * `socket` - UDP socket (should be bound to RTP port + 1)
    /// * `remote_addr` - Remote RTCP address (remote RTP port + 1)
    /// * `local_ssrc` - Local SSRC (same as RTP stream)
    /// * `cname` - Canonical name for SDES
    pub fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        local_ssrc: u32,
        cname: String,
    ) -> Self {
        debug!(
            "RTCP session created: remote={}, ssrc={}, cname={}",
            remote_addr, local_ssrc, cname
        );

        Self {
            socket,
            remote_addr,
            local_ssrc,
            remote_ssrc: None,
            cname,
            last_send_time: Instant::now(),
            last_sr_tx_stats: RtpStats::default(),
            last_rtp_timestamp: 0,
            last_received_sr_ntp: 0,
            last_received_sr_time: None,
            prev_highest_seq: 0,
            prev_packets_received: 0,
            prev_cumulative_lost: 0,
        }
    }

    /// Checks if it's time to send an RTCP report and sends one if so.
    ///
    /// Call this from the I/O thread on every iteration. It internally
    /// tracks the 5-second interval.
    pub fn maybe_send_report(
        &mut self,
        tx_stats: &RtpStats,
        rx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        if self.last_send_time.elapsed() < RTCP_INTERVAL {
            return;
        }
        self.last_send_time = Instant::now();

        self.send_compound_report(tx_stats, rx_stats, jb_stats);
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

    /// Sends a compound RTCP packet (SR + SDES or RR + SDES).
    fn send_compound_report(
        &mut self,
        tx_stats: &RtpStats,
        rx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        let mut compound = BytesMut::with_capacity(256);

        if tx_stats.packets_sent > 0 {
            // We are a sender — send Sender Report
            self.build_sender_report(&mut compound, tx_stats, rx_stats, jb_stats);
        } else {
            // Receive-only — send Receiver Report
            self.build_receiver_report(&mut compound, rx_stats, jb_stats);
        }

        // Always append SDES (CNAME)
        self.build_sdes(&mut compound);

        // Send
        match self.socket.send_to(&compound, self.remote_addr) {
            Ok(sent) => {
                trace!("Sent RTCP compound packet: {} bytes to {}", sent, self.remote_addr);
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
        rx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        let (ntp_sec, ntp_frac) = get_ntp_timestamp();

        let has_rr = self.remote_ssrc.is_some() && rx_stats.packets_received > 0;
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
            Some(self.build_reception_report_block(rx_stats, jb_stats))
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
    fn build_receiver_report(
        &mut self,
        buf: &mut BytesMut,
        rx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        let has_rr = self.remote_ssrc.is_some() && rx_stats.packets_received > 0;
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
            let rr = self.build_reception_report_block(rx_stats, jb_stats);
            buf.put(rr);
        }
    }

    /// Builds a single reception report block (24 bytes).
    fn build_reception_report_block(
        &mut self,
        rx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) -> bytes::Bytes {
        let remote_ssrc = self.remote_ssrc.unwrap_or(0);

        // Fraction lost: packets lost in this interval / packets expected in this interval
        let received_this_interval = rx_stats
            .packets_received
            .saturating_sub(self.prev_packets_received);
        let lost_this_interval = rx_stats
            .packets_dropped
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
        let cumulative_lost = rx_stats.packets_dropped as i32;

        // Extended highest sequence (we don't track wraps, use packets_received as proxy)
        #[allow(clippy::cast_possible_truncation)]
        let extended_highest_seq = rx_stats.packets_received as u32;

        // Jitter in timestamp units (convert ms to timestamp units at 8kHz)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let jitter = (jb_stats.average_jitter_ms * 8.0) as u32;

        // DLSR (delay since last SR in 1/65536 seconds)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let dlsr = self.last_received_sr_time.map_or(0, |t| {
            (t.elapsed().as_secs_f64() * 65536.0) as u32
        });

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
        self.prev_packets_received = rx_stats.packets_received;
        self.prev_cumulative_lost = rx_stats.packets_dropped;
        #[allow(clippy::cast_possible_truncation)]
        {
            self.prev_highest_seq = rx_stats.packets_received as u32;
        }

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

        let session = RtcpSession::new(socket, remote, 12345, "user@host".to_string());
        assert_eq!(session.local_ssrc, 12345);
        assert!(session.remote_ssrc.is_none());
    }

    #[test]
    fn test_send_sr_compound() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, "test@host".to_string());

        let tx_stats = RtpStats {
            packets_sent: 100,
            bytes_sent: 16000,
            ..RtpStats::default()
        };
        let rx_stats = RtpStats::default();
        let jb_stats = JitterBufferStats::default();

        // Force immediate send by backdating last_send_time
        session.last_send_time = Instant::now() - Duration::from_secs(10);
        session.maybe_send_report(&tx_stats, &rx_stats, &jb_stats);
        // Should not panic; packet sent to non-listening address is fine for UDP
    }

    #[test]
    fn test_send_rr_with_remote_ssrc() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, "test@host".to_string());
        session.set_remote_ssrc(67890);

        let tx_stats = RtpStats::default(); // Not sending → RR
        let rx_stats = RtpStats {
            packets_received: 500,
            bytes_received: 80000,
            packets_dropped: 5,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats {
            average_jitter_ms: 10.5,
            ..JitterBufferStats::default()
        };

        session.last_send_time = Instant::now() - Duration::from_secs(10);
        session.maybe_send_report(&tx_stats, &rx_stats, &jb_stats);
    }

    #[test]
    fn test_interval_gating() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        let mut session = RtcpSession::new(socket, remote, 12345, "test@host".to_string());

        let tx_stats = RtpStats::default();
        let rx_stats = RtpStats::default();
        let jb_stats = JitterBufferStats::default();

        // Should NOT send (just created, interval not elapsed)
        let before = session.last_send_time;
        session.maybe_send_report(&tx_stats, &rx_stats, &jb_stats);
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

        let mut session = RtcpSession::new(socket, remote, 12345, "test@host".to_string());

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

        let session = RtcpSession::new(socket, remote, 12345, "alice@example.com".to_string());

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

        let mut session = RtcpSession::new(socket, remote, 12345, "test@host".to_string());
        session.set_remote_ssrc(67890);

        // First interval: 100 received, 10 dropped → 10/110 ≈ 9% → fraction ≈ 23/256
        let rx_stats = RtpStats {
            packets_received: 100,
            packets_dropped: 10,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats::default();

        let rr_bytes = session.build_reception_report_block(&rx_stats, &jb_stats);
        let rr = ReceptionReport::parse(&rr_bytes).unwrap();
        assert!(rr.fraction_lost > 0, "Should report some loss");
        assert!(rr.fraction_lost < 50, "Should not be extreme loss");
    }
}
