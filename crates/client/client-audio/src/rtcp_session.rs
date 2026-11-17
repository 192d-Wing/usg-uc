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
use proto_srtp::{SrtpContext, SrtpProtect, SrtpUnprotect};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, trace, warn};

/// Base RTCP send interval (5 seconds per RFC 3550 recommendation).
///
/// The actual interval is randomized to `5s × uniform[0.5, 1.5]` per
/// RFC 3550 §6.3.1 to avoid synchronized reports across participants.
const RTCP_BASE_INTERVAL_SECS: f64 = 5.0;

/// NTP epoch offset: seconds between 1900-01-01 and 1970-01-01.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// SDES item type: CNAME (Canonical Name).
const SDES_CNAME: u8 = 1;

/// Receive buffer size: one Ethernet MTU covers muxed SRTCP from any peer.
const RTCP_RECV_BUFFER: usize = 1500;

/// SRTCP contexts for one session (RFC 3711 §3.4). Separate instances from
/// the RTP contexts, so the SRTCP index and replay window are not shared.
struct SrtcpContexts {
    /// The call's outbound SRTCP context: its index goes on counting in
    /// the next session of the call (RFC 3711 §3.2.3).
    tx: Arc<SrtpContext>,
    /// The call's inbound SRTCP context: its replay window outlives this
    /// session (RFC 3711 §3.3.2).
    rx: Arc<SrtpContext>,
}

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
    /// Previous cumulative packets received (for fraction lost calc).
    prev_packets_received: u64,
    /// Previous cumulative lost (for fraction lost calc).
    prev_cumulative_lost: u64,
    /// Receive buffer for incoming RTCP packets.
    recv_buffer: Vec<u8>,
    /// Latest measured round-trip time in milliseconds (from RR block LSR/DLSR).
    rtt_ms: Option<f32>,
    /// Current randomized report interval (RFC 3550 §6.3.1).
    report_interval: Duration,
    /// LCG state for interval randomization (no external RNG dependency).
    interval_rng: u32,
    /// Set when an incoming RTCP packet carries our own SSRC from another
    /// participant (sender-side collision, RFC 3550 §8.2).
    ssrc_collision: bool,
    /// Whether an RTCP BYE has been sent (session ended).
    bye_sent: bool,
    /// SRTCP contexts. When set, every RTCP packet is protected before send
    /// and must authenticate on receive (RFC 3711 §3.4: SRTCP auth is
    /// mandatory). When unset the session is plaintext (insecure builds only).
    srtcp: Option<SrtcpContexts>,
    /// Whether RTCP is multiplexed on the RTP socket (RFC 5761). When set,
    /// [`Self::try_receive`] does not read the socket (the RTP receiver
    /// demultiplexes and hands packets to [`Self::handle_packet`]).
    rtcp_mux: bool,
    /// SRTCP protect/unprotect failures.
    srtcp_errors: u64,
    /// Packets dropped by the source check or for being malformed.
    rtcp_dropped: u64,
}

impl RtcpSession {
    /// Creates a new RTCP session.
    ///
    /// # Arguments
    /// * `socket` - UDP socket (should be bound to RTP port + 1)
    /// * `remote_addr` - Remote RTCP address (remote RTP port + 1)
    /// * `local_ssrc` - Local SSRC (same as RTP stream)
    /// * `clock_rate` - Codec clock rate (Hz), logged for diagnostics.
    ///   Jitter arrives from the jitter buffer already in timestamp units
    ///   (RFC 3550 §A.8), so no conversion happens here.
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

        // Seed the interval LCG from the SSRC mixed with the current time so
        // two endpoints sharing an SSRC-derived seed still diverge.
        let seed = local_ssrc
            ^ (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .subsec_nanos());

        let mut session = Self {
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
            prev_packets_received: 0,
            prev_cumulative_lost: 0,
            recv_buffer: vec![0u8; RTCP_RECV_BUFFER],
            rtt_ms: None,
            report_interval: Duration::from_secs_f64(RTCP_BASE_INTERVAL_SECS),
            interval_rng: seed,
            ssrc_collision: false,
            bye_sent: false,
            srtcp: None,
            rtcp_mux: false,
            srtcp_errors: 0,
            rtcp_dropped: 0,
        };
        session.report_interval = session.next_report_interval();
        session
    }

    /// Computes the next randomized report interval per RFC 3550 §6.3.1:
    /// `base × uniform[0.5, 1.5]`, using a small LCG (no `rand` dependency).
    fn next_report_interval(&mut self) -> Duration {
        // Numerical Recipes LCG constants.
        self.interval_rng = self
            .interval_rng
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        // Top 24 bits → uniform fraction in [0, 1).
        let frac = f64::from(self.interval_rng >> 8) / f64::from(1u32 << 24);
        let factor = 0.5 + frac; // [0.5, 1.5)
        Duration::from_secs_f64(RTCP_BASE_INTERVAL_SECS * factor)
    }

    /// Enables SRTCP with independent transmit / receive contexts.
    ///
    /// NIST 800-53 Rev5: SC-8(1) (RTCP confidentiality and integrity).
    pub fn set_srtcp(&mut self, tx: Arc<SrtpContext>, rx: Arc<SrtpContext>) {
        self.srtcp = Some(SrtcpContexts { tx, rx });
        debug!("SRTCP enabled for RTCP session");
    }

    /// Returns whether SRTCP is enabled.
    pub const fn is_secure(&self) -> bool {
        self.srtcp.is_some()
    }

    /// Marks RTCP as multiplexed on the RTP socket (RFC 5761).
    pub const fn set_rtcp_mux(&mut self, enabled: bool) {
        self.rtcp_mux = enabled;
    }

    /// Returns the number of SRTCP protect/unprotect failures.
    pub const fn srtcp_errors(&self) -> u64 {
        self.srtcp_errors
    }

    /// Returns the number of RTCP packets dropped (source check, runt,
    /// oversize).
    pub const fn rtcp_dropped(&self) -> u64 {
        self.rtcp_dropped
    }

    /// Updates the local SSRC (used after SSRC collision resolution).
    pub fn set_local_ssrc(&mut self, ssrc: u32) {
        debug!("RTCP session SSRC updated to {:#010x}", ssrc);
        self.local_ssrc = ssrc;
    }

    /// Checks if it's time to send an RTCP report and sends one if so.
    ///
    /// Call this from the I/O thread on every iteration. It internally
    /// tracks the randomized report interval (5s × uniform[0.5, 1.5],
    /// RFC 3550 §6.3.1).
    pub fn maybe_send_report(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        if self.last_send_time.elapsed() < self.report_interval {
            return;
        }
        self.send_report(tx_stats, jb_stats);
    }

    /// Sends a compound report (SR or RR, plus SDES) now and restarts the
    /// report interval. [`Self::maybe_send_report`] is the timed form the
    /// I/O thread uses; this one is for callers that must not wait for the
    /// interval (the interoperability tests, which need more than one
    /// SRTCP packet inside a short exchange).
    pub fn send_report(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        self.last_send_time = Instant::now();
        self.report_interval = self.next_report_interval();

        self.send_compound_report(tx_stats, jb_stats);
    }

    /// Returns `true` if an incoming RTCP packet carried our own SSRC
    /// (sender-side collision per RFC 3550 §8.2).
    pub const fn ssrc_collision_detected(&self) -> bool {
        self.ssrc_collision
    }

    /// Clears the collision flag after the caller has changed the local SSRC.
    pub const fn clear_ssrc_collision(&mut self) {
        self.ssrc_collision = false;
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
        if self.rtcp_mux {
            // RFC 5761: the RTP receiver owns the shared socket and
            // demultiplexes RTCP to `handle_packet`.
            return;
        }
        // No packet (timeout / would-block) is not an error.
        if let Ok((len, addr)) = self.socket.recv_from(&mut self.recv_buffer) {
            self.ingest(len, addr);
        }
    }

    /// Processes one RTCP datagram demultiplexed from the RTP socket
    /// (RFC 5761 §4). Oversize datagrams are dropped.
    pub fn handle_packet(&mut self, data: &[u8], from: SocketAddr) {
        let Some(dst) = self.recv_buffer.get_mut(..data.len()) else {
            self.rtcp_dropped += 1;
            return;
        };
        dst.copy_from_slice(data);
        self.ingest(data.len(), from);
    }

    /// Validates source, authenticates (SRTCP) and processes
    /// `self.recv_buffer[..len]`. Unauthenticated RTCP is never parsed on a
    /// secure session, so SSRC-collision and RTT inputs are authenticated.
    fn ingest(&mut self, len: usize, from: SocketAddr) {
        if len < 8 {
            self.rtcp_dropped += 1;
            return;
        }
        // Cheap source check: RTCP must come from the negotiated remote host.
        if from.ip() != self.remote_addr.ip() {
            self.rtcp_dropped += 1;
            trace!("Dropping RTCP from unexpected source {from}");
            return;
        }
        let plain_len = if let Some(ref srtcp) = self.srtcp {
            // RFC 3711 §3.4: authenticate before parsing.
            // POAM: POA&M-328 unprotect_rtcp_sync returns an owned buffer (one
            // allocation per received RTCP datagram, including forged ones
            // in a flood); add an in-place SRTCP unprotect to proto-srtp.
            match SrtpUnprotect::new(&srtcp.rx).unprotect_rtcp_sync(&self.recv_buffer[..len]) {
                Ok(plain) => {
                    let n = plain.len();
                    // Plaintext is never longer than the SRTCP packet.
                    let Some(dst) = self.recv_buffer.get_mut(..n) else {
                        self.rtcp_dropped += 1;
                        return;
                    };
                    dst.copy_from_slice(&plain);
                    n
                }
                Err(e) => {
                    self.srtcp_errors += 1;
                    trace!("SRTCP unprotect failed: {e}");
                    return;
                }
            }
        } else {
            len
        };
        if plain_len >= 8 {
            self.process_rtcp_packet(plain_len);
        }
    }

    /// Sends a compound packet, protecting it as SRTCP when keyed. On a
    /// secure session a protect failure drops the packet; plaintext RTCP is
    /// never sent in its place.
    fn transmit(&mut self, compound: &[u8]) -> Option<usize> {
        let result = if let Some(ref srtcp) = self.srtcp {
            match SrtpProtect::new(&srtcp.tx).protect_rtcp(compound) {
                Ok(protected) => self.socket.send_to(&protected, self.remote_addr),
                Err(e) => {
                    self.srtcp_errors += 1;
                    trace!("SRTCP protect failed: {e}");
                    return None;
                }
            }
        } else {
            self.socket.send_to(compound, self.remote_addr)
        };
        match result {
            Ok(sent) => Some(sent),
            Err(e) => {
                // Non-fatal — RTCP failure shouldn't affect audio
                trace!("RTCP send failed: {e}");
                None
            }
        }
    }

    /// Processes one incoming RTCP packet from `self.recv_buffer[..len]`.
    fn process_rtcp_packet(&mut self, len: usize) {
        // Minimal RTCP header check: V=2
        let version = (self.recv_buffer[0] >> 6) & 0x03;
        let pt = self.recv_buffer[1];
        let rc = self.recv_buffer[0] & 0x1F; // report count

        // Sender-side SSRC collision detection (RFC 3550 §8.2):
        // SR/RR/SDES/BYE/APP all carry the sender's SSRC in bytes
        // 4..8. If another participant uses our SSRC, flag it so the
        // I/O thread regenerates ours.
        if version == 2 && (200..=204).contains(&pt) {
            let sender_ssrc = u32::from_be_bytes([
                self.recv_buffer[4],
                self.recv_buffer[5],
                self.recv_buffer[6],
                self.recv_buffer[7],
            ]);
            if sender_ssrc == self.local_ssrc {
                warn!(
                    "RTCP SSRC collision: remote participant uses our SSRC {:#010x}",
                    sender_ssrc
                );
                self.ssrc_collision = true;
            }
        }

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

    /// Extracts RTT from Reception Report blocks.
    ///
    /// Each RR block is 24 bytes. We look for one whose LSR matches our
    /// last sent SR (middle 32 bits of our NTP timestamp). RTT is then:
    ///   RTT = `now_ntp_middle32` - LSR - DLSR
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
        if let Some(sent) = self.transmit(&compound) {
            trace!(
                "Sent RTCP compound packet: {} bytes to {}",
                sent, self.remote_addr
            );
        }
    }

    /// Sends an RTCP BYE on session shutdown (RFC 3550 §6.6).
    ///
    /// The BYE is sent as part of a compound packet (SR/RR + SDES + BYE,
    /// RFC 3550 §6.1) so the remote can distinguish a deliberate hangup
    /// from a crash/network failure. Idempotent: only the first call sends.
    pub fn send_bye(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        if self.bye_sent {
            return;
        }
        self.bye_sent = true;
        self.transmit_bye(tx_stats, jb_stats);
    }

    /// Ends this pipeline's RTCP session when its I/O thread stops.
    ///
    /// RFC 3550 §6.3.7, §6.6: a BYE says that the source leaves. With
    /// `stream_continues` set the pipeline stops for a restart within a
    /// call whose next pipeline goes on with the same SSRC (the call's
    /// SRTP state keeps it), so no BYE is sent: a receiver would drop the
    /// source's state, or take the BYE for the end of the stream.
    /// Otherwise (the call ends, or the next pipeline takes a new SSRC)
    /// the BYE is sent as by [`Self::send_bye`].
    pub fn finish(
        &mut self,
        tx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
        stream_continues: bool,
    ) {
        if stream_continues {
            debug!("RTCP BYE not sent: the call's stream continues with this SSRC");
            return;
        }
        self.send_bye(tx_stats, jb_stats);
    }

    /// Changes the local SSRC after a collision and tells the peer that
    /// the old one is gone.
    ///
    /// RFC 3550 §8.2: a participant that finds its own SSRC in use by
    /// another sends an RTCP BYE for the old identifier and chooses a new
    /// one. The session goes on, so this BYE does not count as the one of
    /// [`Self::send_bye`]. Once per collision, never per packet.
    pub fn abandon_local_ssrc(
        &mut self,
        new_ssrc: u32,
        tx_stats: &RtpStats,
        jb_stats: &JitterBufferStats,
    ) {
        if !self.bye_sent {
            self.transmit_bye(tx_stats, jb_stats);
        }
        self.set_local_ssrc(new_ssrc);
    }

    /// Sends the compound packet that ends with a BYE for the current
    /// local SSRC.
    fn transmit_bye(&mut self, tx_stats: &RtpStats, jb_stats: &JitterBufferStats) {
        let mut compound = BytesMut::with_capacity(256);

        if tx_stats.packets_sent > 0 {
            self.build_sender_report(&mut compound, tx_stats, jb_stats);
        } else {
            self.build_receiver_report(&mut compound, jb_stats);
        }
        self.build_sdes(&mut compound);
        self.build_bye(&mut compound);

        if let Some(sent) = self.transmit(&compound) {
            debug!(
                "Sent RTCP BYE compound packet: {} bytes to {}",
                sent, self.remote_addr
            );
        }
    }

    /// Builds a BYE packet (header + our SSRC) into the compound buffer.
    fn build_bye(&self, buf: &mut BytesMut) {
        // BYE: 4 (header) + 4 (SSRC) = 8 bytes → length = 1
        let mut header = RtcpHeader::new(RtcpType::Goodbye, 1); // 1 SSRC
        header.length = 1;
        buf.put(header.to_bytes());
        buf.put_u32(self.local_ssrc);
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
    /// for actual stream loss). Jitter is reported in RTP timestamp units
    /// per RFC 3550 §A.8.
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
        let fraction_lost = (lost_this_interval * 256)
            .checked_div(expected_this_interval)
            .unwrap_or(0) as u8;

        // Cumulative lost (total)
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let cumulative_lost = jb_stats.packets_lost as i32;

        // Extended highest sequence (use total received + lost as proxy for highest seq)
        #[allow(clippy::cast_possible_truncation)]
        let extended_highest_seq = (jb_stats.packets_received + jb_stats.packets_lost) as u32;

        // Interarrival jitter in RTP timestamp units (RFC 3550 §A.8).
        // The jitter buffer maintains this directly; the ms value in
        // `average_jitter_ms` is for local stats display only.
        let jitter = jb_stats.interarrival_jitter;

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
        session.last_send_time = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
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

        session.last_send_time = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
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
        assert!(buf.len() > 4 + 4 + 2);
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
    fn test_jitter_reported_in_timestamp_units() {
        // RFC 3550 §A.8: the RR jitter field is in RTP timestamp units,
        // taken verbatim from the jitter buffer's §A.8 estimator — NOT
        // converted from milliseconds.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        // 48kHz clock rate (e.g., Opus)
        let mut session = RtcpSession::new(socket, remote, 12345, 48000, "test@host".to_string());
        session.set_remote_ssrc(67890);

        let jb_stats = JitterBufferStats {
            packets_received: 100,
            average_jitter_ms: 10.0,  // local display value (ms)
            interarrival_jitter: 480, // 10ms × 48 = 480 ts units at 48kHz
            ..JitterBufferStats::default()
        };

        let rr_bytes = session.build_reception_report_block(&jb_stats);
        let rr = ReceptionReport::parse(&rr_bytes).unwrap();

        // The wire value must be the timestamp-unit estimate, not 10 (ms).
        assert_eq!(rr.jitter, 480);
    }

    #[test]
    fn test_report_interval_randomized() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let mut session = RtcpSession::new(socket, remote, 12345, 8000, "test@host".to_string());

        // RFC 3550 §6.3.1: every interval must be 5s × uniform[0.5, 1.5].
        let mut intervals = Vec::with_capacity(64);
        intervals.push(session.report_interval);
        for _ in 0..63 {
            intervals.push(session.next_report_interval());
        }

        for iv in &intervals {
            let secs = iv.as_secs_f64();
            assert!(
                (2.5..7.5).contains(&secs),
                "interval {secs}s outside [2.5, 7.5)"
            );
        }
        // The intervals must actually vary (not a fixed 5s).
        let first = intervals[0];
        assert!(
            intervals.iter().any(|iv| *iv != first),
            "intervals should be randomized, all were {first:?}"
        );
    }

    #[test]
    fn test_rtcp_ssrc_collision_detection() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let local_ssrc = 0xDEAD_BEEF;
        let mut session =
            RtcpSession::new(socket, remote, local_ssrc, 8000, "test@host".to_string());
        assert!(!session.ssrc_collision_detected());

        // Craft a minimal RR (PT=201) whose sender SSRC is OUR SSRC.
        let mut pkt = [0u8; 8];
        pkt[0] = 0x80; // V=2, RC=0
        pkt[1] = 201; // RR
        pkt[2..4].copy_from_slice(&1u16.to_be_bytes()); // length
        pkt[4..8].copy_from_slice(&local_ssrc.to_be_bytes());
        session.recv_buffer[..8].copy_from_slice(&pkt);
        session.process_rtcp_packet(8);

        assert!(session.ssrc_collision_detected());
        session.clear_ssrc_collision();
        assert!(!session.ssrc_collision_detected());

        // A packet with a different sender SSRC does NOT flag a collision.
        session.recv_buffer[4..8].copy_from_slice(&0xCAFE_F00Du32.to_be_bytes());
        session.process_rtcp_packet(8);
        assert!(!session.ssrc_collision_detected());
    }

    #[test]
    fn test_rtcp_ssrc_collision_on_sdes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(socket);
        let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let local_ssrc = 0x1234_5678;
        let mut session =
            RtcpSession::new(socket, remote, local_ssrc, 8000, "test@host".to_string());

        // SDES (PT=202) chunk with our SSRC.
        let mut pkt = [0u8; 12];
        pkt[0] = 0x81; // V=2, SC=1
        pkt[1] = 202; // SDES
        pkt[2..4].copy_from_slice(&2u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&local_ssrc.to_be_bytes());
        session.recv_buffer[..12].copy_from_slice(&pkt);
        session.process_rtcp_packet(12);

        assert!(session.ssrc_collision_detected());
    }

    fn keyed_pair() -> (RtcpSession, RtcpSession, UdpSocket) {
        use crate::media_security::{build_srtp_contexts, tests::keys};
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        b_sock
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        // DTLS-SRTP shaped: A's tx half is B's rx half and vice versa.
        let a_ctx = build_srtp_contexts(&keys(1, 2), 0xA).unwrap();
        let b_ctx = build_srtp_contexts(&keys(2, 1), 0xB).unwrap();
        let mut a = RtcpSession::new(a_sock, b_addr, 0xA, 8000, "a@h".to_string());
        a.set_srtcp(a_ctx.rtcp_tx, a_ctx.rtcp_rx);
        let mut b = RtcpSession::new(
            Arc::new(b_sock.try_clone().unwrap()),
            a_addr,
            0xB,
            8000,
            "b@h".to_string(),
        );
        b.set_srtcp(b_ctx.rtcp_tx, b_ctx.rtcp_rx);
        (a, b, b_sock)
    }

    #[test]
    fn srtcp_round_trip_and_no_plaintext_on_wire() {
        let (mut a, mut b, b_sock) = keyed_pair();
        let tx_stats = RtpStats {
            packets_sent: 5,
            ..RtpStats::default()
        };
        a.send_compound_report(&tx_stats, &JitterBufferStats::default());

        let mut buf = [0u8; 1500];
        let (len, from) = b_sock.recv_from(&mut buf).unwrap();
        // SRTCP trailer: E flag set in the last 4 bytes, CNAME not in clear.
        assert_ne!(buf[len - 4] & 0x80, 0, "E flag must be set");
        assert!(!buf[..len].windows(3).any(|w| w == b"a@h"));

        assert!(b.last_received_sr_time.is_none());
        b.handle_packet(&buf[..len], from);
        assert_eq!(b.srtcp_errors(), 0);
        assert!(b.last_received_sr_time.is_some(), "SR must be processed");
    }

    #[test]
    fn srtcp_tampered_and_plaintext_dropped() {
        let (mut a, mut b, b_sock) = keyed_pair();
        a.send_compound_report(&RtpStats::default(), &JitterBufferStats::default());
        let mut buf = [0u8; 1500];
        let (len, from) = b_sock.recv_from(&mut buf).unwrap();

        let mut tampered = buf[..len].to_vec();
        tampered[9] ^= 0x01;
        b.handle_packet(&tampered, from);
        assert_eq!(b.srtcp_errors(), 1);

        // Plaintext RR carrying B's own SSRC: must not be parsed (no
        // collision flag) because it does not authenticate.
        let mut rr = [0u8; 8];
        rr[0] = 0x80;
        rr[1] = 201;
        rr[2..4].copy_from_slice(&1u16.to_be_bytes());
        rr[4..8].copy_from_slice(&0xBu32.to_be_bytes());
        b.handle_packet(&rr, from);
        assert_eq!(b.srtcp_errors(), 2);
        assert!(!b.ssrc_collision_detected());
    }

    #[test]
    fn rtcp_from_wrong_source_dropped() {
        let (_a, mut b, _b_sock) = keyed_pair();
        let mut rr = [0u8; 8];
        rr[0] = 0x80;
        rr[1] = 201;
        rr[4..8].copy_from_slice(&0xBu32.to_be_bytes());
        b.handle_packet(&rr, "192.0.2.7:5005".parse().unwrap());
        assert_eq!(b.rtcp_dropped(), 1);
        assert_eq!(b.srtcp_errors(), 0);
        assert!(!b.ssrc_collision_detected());
    }

    #[test]
    fn test_send_bye_compound_contains_bye() {
        // Receive the BYE compound on a loopback socket and verify it ends
        // with a Goodbye packet (PT=203) carrying our SSRC.
        let rx_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let remote = rx_socket.local_addr().unwrap();

        let tx_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let local_ssrc = 0xABCD_0123;
        let mut session =
            RtcpSession::new(tx_socket, remote, local_ssrc, 8000, "test@host".to_string());

        let tx_stats = RtpStats {
            packets_sent: 50,
            bytes_sent: 8000,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats::default();
        session.send_bye(&tx_stats, &jb_stats);

        let mut buf = [0u8; 512];
        let (len, _) = rx_socket.recv_from(&mut buf).unwrap();

        // Walk the compound packet: each RTCP packet is 4*(length+1) bytes.
        let mut offset = 0;
        let mut found_bye = false;
        let mut first_pt = None;
        while offset + 4 <= len {
            let pt = buf[offset + 1];
            if first_pt.is_none() {
                first_pt = Some(pt);
            }
            let length = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            let pkt_len = 4 * (length + 1);
            if pt == 203 {
                found_bye = true;
                // BYE carries our SSRC
                let ssrc = u32::from_be_bytes([
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]);
                assert_eq!(ssrc, local_ssrc);
            }
            offset += pkt_len;
        }

        assert_eq!(first_pt, Some(200), "compound must start with SR (sender)");
        assert!(found_bye, "compound packet must contain a BYE (PT=203)");

        // Idempotent: a second call must not send again.
        session.send_bye(&tx_stats, &jb_stats);
        let res = rx_socket.recv_from(&mut buf);
        assert!(res.is_err(), "second send_bye must not transmit");
    }

    /// The SSRCs of the BYE packets (PT 203) in one compound RTCP packet.
    fn bye_ssrcs(compound: &[u8]) -> Vec<u32> {
        let mut found = Vec::new();
        let mut offset = 0;
        while let Some(header) = compound.get(offset..offset + 8) {
            if header[1] == 203 {
                found.push(u32::from_be_bytes([
                    header[4], header[5], header[6], header[7],
                ]));
            }
            let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
            offset += 4 * (length + 1);
        }
        found
    }

    /// RFC-013 (RFC 3550 §6.3.7, §6.6): a pipeline that stops for a
    /// restart on a call whose stream continues with the same SSRC sends
    /// no BYE; the pipeline that stops when the call ends does.
    #[test]
    fn no_bye_when_the_stream_continues_after_a_restart() {
        let rx_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let remote = rx_socket.local_addr().unwrap();
        let tx_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let local_ssrc = 0xABCD_0123;
        let session = || {
            RtcpSession::new(
                Arc::clone(&tx_socket),
                remote,
                local_ssrc,
                8000,
                "test@host".to_string(),
            )
        };
        let tx_stats = RtpStats {
            packets_sent: 50,
            bytes_sent: 8000,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats::default();
        let mut buf = [0u8; 512];

        // First pipeline of the call: stopped for a restart.
        let mut first = session();
        first.finish(&tx_stats, &jb_stats, true);
        assert!(
            rx_socket.recv_from(&mut buf).is_err(),
            "RTCP sent at a restart although the SSRC continues"
        );
        drop(first);

        // Second pipeline, same SSRC: stopped because the call ended.
        let mut second = session();
        second.finish(&tx_stats, &jb_stats, false);
        let (len, _) = rx_socket.recv_from(&mut buf).unwrap();
        assert_eq!(bye_ssrcs(&buf[..len]), [local_ssrc]);
    }

    /// RFC-013 (RFC 3550 §8.2): after an SSRC collision the abandoned
    /// SSRC is said goodbye to, the session goes on with the new one, and
    /// the new one gets its own BYE when the call ends, but not when the
    /// pipeline only restarts.
    #[test]
    fn bye_for_the_ssrc_abandoned_after_a_collision() {
        let rx_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let remote = rx_socket.local_addr().unwrap();
        let tx_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let (old_ssrc, new_ssrc) = (0xABCD_0123, 0xABCD_0124);
        let mut session =
            RtcpSession::new(tx_socket, remote, old_ssrc, 8000, "test@host".to_string());
        let tx_stats = RtpStats {
            packets_sent: 50,
            bytes_sent: 8000,
            ..RtpStats::default()
        };
        let jb_stats = JitterBufferStats::default();
        let mut buf = [0u8; 512];

        session.abandon_local_ssrc(new_ssrc, &tx_stats, &jb_stats);
        let (len, _) = rx_socket.recv_from(&mut buf).unwrap();
        assert_eq!(bye_ssrcs(&buf[..len]), [old_ssrc]);

        // A restart: the new SSRC continues, nothing is sent.
        session.finish(&tx_stats, &jb_stats, true);
        assert!(rx_socket.recv_from(&mut buf).is_err());
        // The call ends: a BYE for the new SSRC.
        session.finish(&tx_stats, &jb_stats, false);
        let (len, _) = rx_socket.recv_from(&mut buf).unwrap();
        assert_eq!(bye_ssrcs(&buf[..len]), [new_ssrc]);
    }
}
