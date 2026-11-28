//! Media-side DTLS/SRTP demux + handshake record pump.
//!
//! For a terminated leg the relay owns the media UDP socket. Until the DTLS
//! handshake completes, incoming DTLS records (RFC 7983: first byte 20..=63) are
//! pumped to the sidecar and its responses sent back to the peer; SRTP/RTCP
//! (128..=191) does not flow yet. On the sidecar's `Ready` the exported SRTP
//! keys are returned and the caller switches to the SRTP relay (next phase).
//! `Ready` does not end the sidecar session: the association stays open in the
//! sidecar, and the connection to it stays open, until the call ends.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use proto_srtp::{SrtpKeyMaterial, SrtpProfile};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::dtls_sidecar::{
    Role, SidecarClient, SidecarError, SidecarEvent, SidecarReader, SidecarWriter,
};
use crate::srtp_relay::DtlsForwardBucket;

/// RFC 5764 SRTP protection profile value for `SRTP_AEAD_AES_256_GCM` — the
/// only profile the sidecar offers (CNSA 2.0).
pub const SRTP_AEAD_AES_256_GCM: u16 = 8;

/// Upper bound on the DTLS handshake pump. Defense-in-depth: even if the sidecar
/// neither completes nor reports an error (wedged), the leg fails instead of
/// hanging. A healthy DTLS handshake (with retransmits) completes well within
/// this; it is not the per-flight timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// RFC 7714 §8.3 — AEAD_AES_256_GCM SRTP transform parameters.
const SRTP_MASTER_KEY_LEN: usize = 32;
const SRTP_MASTER_SALT_LEN: usize = 12;
/// Length of the DTLS-SRTP exported keying material for AEAD_AES_256_GCM:
/// `client_write_key || server_write_key || client_write_salt || server_write_salt`
/// (RFC 5764 §4.2). 32 + 32 + 12 + 12 = 88 bytes.
const EXPORTED_KEYING_LEN: usize = 2 * (SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN);

/// Classifies a demuxed media packet by its first byte (RFC 7983): DTLS records
/// are 20..=63; RTP/RTCP/SRTP are 128..=191; STUN is 0..=3.
#[must_use]
pub fn is_dtls_record(first_byte: u8) -> bool {
    (20..=63).contains(&first_byte)
}

/// Exported keying material from a completed handshake.
#[derive(Debug)]
pub struct HandshakeKeys {
    /// Negotiated SRTP protection profile (RFC 5764 value).
    pub profile: u16,
    /// Exported SRTP keying material for `proto-srtp`.
    pub srtp_keys: Vec<u8>,
    /// The source the handshake most likely completed with: the SDP address
    /// once it has sent DTLS, otherwise the last source whose DTLS was
    /// forwarded (the SDP address if none was). A hint only: DTLS does not
    /// bind transport addresses and the sidecar does not report which
    /// datagram completed the handshake. The terminate relay leg moves its
    /// latch away from it on the first packet that authenticates under the
    /// leg's SRTP key.
    pub peer_addr: SocketAddr,
    /// Every source whose DTLS the pump forwarded. Until the leg's first
    /// authenticated SRTP/SRTCP packet, post-handshake DTLS (a retransmitted
    /// final flight) is accepted from, and the sidecar's answer sent to,
    /// each of them (see [`crate::srtp_relay::TerminateRelayLeg`]).
    pub peers: HandshakePeers,
}

/// Per-handshake source counters of [`run_handshake_pump`], for the
/// caller's log line (the pump itself has no call id). The caller owns them,
/// so they survive a failed or timed-out handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeSourceStats {
    /// DTLS-class datagrams that failed the record-header plausibility walk.
    pub dropped_implausible: u64,
    /// Plausible DTLS from a new same-IP port while the source set was full.
    pub dropped_overflow: u64,
    /// Plausible DTLS from a new port after the SDP address had spoken.
    pub dropped_after_exact: u64,
    /// Plausible DTLS from an accepted source over the forward rate limit.
    pub dropped_rate_limited: u64,
    /// Plausible DTLS from an accepted source after the handshake's forward
    /// budget ([`MAX_HANDSHAKE_FORWARD_DATAGRAMS`] /
    /// [`MAX_HANDSHAKE_FORWARD_BYTES`]) was spent.
    pub dropped_budget: u64,
    /// Flight sends to one target that failed (the others were still sent).
    pub send_failures: u64,
    /// Non-SDP same-IP sources kept (at most [`MAX_HANDSHAKE_SOURCES`]).
    pub sources: usize,
}

impl HandshakeSourceStats {
    /// Whether anything was dropped or failed to send.
    #[must_use]
    pub const fn any_dropped(&self) -> bool {
        self.dropped_implausible > 0
            || self.dropped_overflow > 0
            || self.dropped_after_exact > 0
            || self.dropped_rate_limited > 0
            || self.dropped_budget > 0
            || self.send_failures > 0
    }
}

/// Most other same-IP ports the handshake pump accepts DTLS from.
///
/// New ports are accepted while the SDP address has not spoken (behind NAT
/// the peer's source port is unknown). Filled in arrival order and never
/// evicted, so a sender that arrives first cannot push the genuine peer out,
/// and a flood cannot grow the set.
pub const MAX_HANDSHAKE_SOURCES: usize = 4;

/// Most datagrams one handshake forwards to the sidecar.
///
/// The sidecar keeps handshake fragments it has not reassembled for the
/// life of the association (pion's fragment buffer is never trimmed), so the
/// rate limit alone, which admits about 68 datagrams of up to 4 KiB in the
/// 15 s handshake timeout, is not a bound on what a peer can make it keep.
/// A genuine handshake forwards a handful of datagrams (about 3 and 1 KiB,
/// measured with the sidecar's `TestGenuineHandshakeFitsTheBudget`), and a
/// few retransmitted flights more. The sidecar applies the same numbers on
/// its side (`dtlssession.PreHandshakeDatagrams` / `PreHandshakeBytes`).
pub const MAX_HANDSHAKE_FORWARD_DATAGRAMS: u32 = 32;

/// Most bytes one handshake forwards to the sidecar (see
/// [`MAX_HANDSHAKE_FORWARD_DATAGRAMS`]).
pub const MAX_HANDSHAKE_FORWARD_BYTES: usize = 16 * 1024;

/// The sources a handshake pump forwarded DTLS from: the SDP address (when it
/// spoke) and up to [`MAX_HANDSHAKE_SOURCES`] other same-IP ports. Fixed size,
/// no allocation.
// NIST 800-53 Rev5: SC-5 (bounded), SC-7
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakePeers {
    addrs: [Option<SocketAddr>; MAX_HANDSHAKE_SOURCES + 1],
}

impl HandshakePeers {
    /// A set of the given addresses; anything past the capacity is ignored.
    #[must_use]
    pub fn from_addrs(addrs: &[SocketAddr]) -> Self {
        let mut set = Self::default();
        for addr in addrs {
            set.insert(*addr);
        }
        set
    }

    /// Adds `addr` if it is new and there is room.
    fn insert(&mut self, addr: SocketAddr) {
        if self.contains(addr) {
            return;
        }
        if let Some(slot) = self.addrs.iter_mut().find(|s| s.is_none()) {
            *slot = Some(addr);
        }
    }

    /// Whether `addr` is in the set.
    #[must_use]
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.addrs.contains(&Some(addr))
    }

    /// The addresses, in the order they were added.
    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.addrs.iter().flatten().copied()
    }
}

/// DTLS record header length (RFC 6347 §4.1): type(1) version(2) epoch(2)
/// sequence(6) length(2).
const DTLS_RECORD_HEADER_LEN: usize = 13;

/// Record-header plausibility walk over one datagram (RFC 6347 §4.1): every
/// record has a full 13-byte header, a content type in 20..=24
/// (change_cipher_spec, alert, handshake, application_data, heartbeat),
/// version DTLS 1.0 (`0xFEFF`) or 1.2 (`0xFEFD`), and a length that fits in
/// what is left of the datagram; nothing trails the last record. Not
/// authentication; it keeps a datagram that only has a DTLS-class first byte
/// away from the sidecar. No allocation.
///
/// Content type 25 (`tls12_cid`, RFC 9146) has a longer header and is not
/// negotiated by the sidecar. DTLS 1.3 unified headers (RFC 9147 §4, first
/// byte `0b001xxxxx`) are rejected too, while the sidecar is pinned to
/// DTLS 1.2.
// NIST 800-53 Rev5: SI-10 (input validation before the sidecar parses it)
#[must_use]
fn is_plausible_dtls(datagram: &[u8]) -> bool {
    let mut rest = datagram;
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some((header, body)) = rest.split_first_chunk::<DTLS_RECORD_HEADER_LEN>() else {
            return false;
        };
        let [content_type, v_hi, v_lo, _, _, _, _, _, _, _, _, l_hi, l_lo] = *header;
        if !(20..=24).contains(&content_type) {
            return false;
        }
        if !matches!(u16::from_be_bytes([v_hi, v_lo]), 0xFEFF | 0xFEFD) {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([l_hi, l_lo]));
        let Some(next) = body.get(len..) else {
            return false;
        };
        rest = next;
    }
    true
}

/// Which same-IP sources the handshake pump forwards DTLS from and sends the
/// sidecar's flights to. Fixed size; nothing is evicted. The counters live
/// with the caller (`stats`), so a handshake that fails or times out still
/// reports them.
// NIST 800-53 Rev5: SC-7, SC-5
// POAM: POA&M-344 -- a sender on the peer's IP that knows the media port and
// fills every slot with plausible DTLS before the peer's first flight, while
// the peer does not send from its SDP port, gets the peer's datagrams
// dropped (`dropped_overflow`); one datagram spoofed from the SDP address
// closes the set to new ports (`dropped_after_exact`) before a NAT'd peer's
// first flight arrives; and a flood from an accepted source empties the
// forward bucket (`dropped_rate_limited`) or spends the handshake's forward
// budget (`dropped_budget`). In each case the handshake times out and the
// call ends (fail closed).
#[derive(Debug)]
struct HandshakeSources<'a> {
    /// The SDP (signalled) address.
    sdp: SocketAddr,
    /// The SDP address has sent plausible DTLS.
    exact_seen: bool,
    /// Other same-IP ports, in arrival order.
    others: [Option<SocketAddr>; MAX_HANDSHAKE_SOURCES],
    /// The last source whose DTLS was forwarded.
    last_src: Option<SocketAddr>,
    /// Token bucket in front of the sidecar, shared by every source.
    bucket: DtlsForwardBucket,
    /// Datagrams and bytes forwarded so far (the handshake's budget).
    forwarded: u32,
    forwarded_bytes: usize,
    stats: &'a mut HandshakeSourceStats,
}

impl<'a> HandshakeSources<'a> {
    fn new(sdp: SocketAddr, now: Instant, stats: &'a mut HandshakeSourceStats) -> Self {
        *stats = HandshakeSourceStats::default();
        Self {
            sdp,
            exact_seen: false,
            others: [None; MAX_HANDSHAKE_SOURCES],
            last_src: None,
            bucket: DtlsForwardBucket::new(now),
            forwarded: 0,
            forwarded_bytes: 0,
            stats,
        }
    }

    /// Decides whether a datagram from `src` goes to the sidecar, recording
    /// the source when it does.
    fn admit(&mut self, src: SocketAddr, datagram: &[u8], now: Instant) -> bool {
        // Wrong IP or not DTLS-class: no SRTP flows before the handshake, and
        // these are not counted (they are not handshake candidates).
        if src.ip() != self.sdp.ip() || !datagram.first().is_some_and(|b| is_dtls_record(*b)) {
            return false;
        }
        if !is_plausible_dtls(datagram) {
            self.stats.dropped_implausible += 1;
            return false;
        }
        // The slot a new port would take; `None` for the SDP address and for
        // a port already kept.
        let new_slot = if src == self.sdp || self.others.contains(&Some(src)) {
            None
        } else if self.exact_seen {
            // The signalled endpoint has spoken: no new ports. Ports kept
            // before it spoke stay, so one datagram spoofed from the SDP
            // address does not cut off a NAT'd peer already in the set.
            self.stats.dropped_after_exact += 1;
            return false;
        } else if let Some(i) = self.others.iter().position(Option::is_none) {
            Some(i)
        } else {
            self.stats.dropped_overflow += 1;
            return false;
        };
        // NIST 800-53 Rev5: SC-5 / SC-6 -- a fixed budget per handshake for
        // what the sidecar may be made to keep (SR-13). Checked before the
        // bucket, so a datagram over budget spends no token.
        if self.forwarded >= MAX_HANDSHAKE_FORWARD_DATAGRAMS
            || self.forwarded_bytes.saturating_add(datagram.len()) > MAX_HANDSHAKE_FORWARD_BYTES
        {
            self.stats.dropped_budget += 1;
            return false;
        }
        // NIST 800-53 Rev5: SC-5 -- the sidecar is shared by every call on
        // the node. Charged after the cheap checks and before any state
        // change, so a rate-limited datagram does not claim a slot.
        if !self.bucket.try_take(now) {
            self.stats.dropped_rate_limited += 1;
            return false;
        }
        self.forwarded += 1;
        self.forwarded_bytes += datagram.len();
        if src == self.sdp {
            self.exact_seen = true;
        }
        if let Some(slot) = new_slot.and_then(|i| self.others.get_mut(i)) {
            *slot = Some(src);
            self.stats.sources += 1;
        }
        self.last_src = Some(src);
        true
    }

    /// Where a sidecar flight goes: the SDP address and every kept source
    /// (all on the peer's IP). A copy, so the counters can be updated while
    /// sending.
    fn flight_targets(&self) -> [Option<SocketAddr>; MAX_HANDSHAKE_SOURCES + 1] {
        let mut targets = [None; MAX_HANDSHAKE_SOURCES + 1];
        for (slot, addr) in targets
            .iter_mut()
            .zip(std::iter::once(Some(self.sdp)).chain(self.others.iter().copied()))
        {
            *slot = addr;
        }
        targets
    }

    /// The source to seed the media latch with (see [`HandshakeKeys::peer_addr`]).
    const fn completed_from(&self) -> SocketAddr {
        if self.exact_seen {
            self.sdp
        } else {
            match self.last_src {
                Some(src) => src,
                None => self.sdp,
            }
        }
    }

    /// Every source whose DTLS was forwarded (see [`HandshakeKeys::peers`]).
    fn peers(&self) -> HandshakePeers {
        let mut set = HandshakePeers::default();
        if self.exact_seen {
            set.insert(self.sdp);
        }
        for src in self.others.iter().flatten() {
            set.insert(*src);
        }
        set
    }
}

/// Errors driving the media-side handshake pump.
#[derive(Debug, thiserror::Error)]
pub enum DtlsRelayError {
    /// Media-socket I/O error.
    #[error("media io: {0}")]
    Io(#[from] std::io::Error),
    /// IPC error talking to the sidecar.
    #[error("sidecar client: {0}")]
    Client(#[from] SidecarError),
    /// The sidecar failed the handshake.
    #[error("sidecar handshake failed: {0}")]
    Sidecar(String),
    /// The exported keying material was malformed or rejected by proto-srtp.
    #[error("srtp key material: {0}")]
    KeyMaterial(String),
}

/// Max inbound datagram we accept from the media socket. Kept strictly below the
/// sidecar's IPC frame limit ([`crate::dtls_sidecar::MAX_FRAME`]) so a full
/// received record always fits a frame once the 1-byte type tag is prepended —
/// a record of exactly this size used to be rejected as `frame too large`
/// (1 + 4096 > 4096) and fail the leg. DTLS fragments handshake messages to the
/// path MTU (~1200 bytes), so 4 KiB is ample for any real record.
const RECV_BUF: usize = 4096;

/// Pumps DTLS handshake records between the media socket and the sidecar until
/// the sidecar reports `Ready`, returning the exported SRTP keys.
///
/// - Inbound datagrams are forwarded to the sidecar only when they come from
///   the SDP peer's IP and pass the record-header plausibility walk
///   (see `is_plausible_dtls`); non-DTLS packets (no SRTP flows before the
///   handshake completes) are dropped.
/// - The SDP address (`signaling_peer`) is always accepted. Until it has
///   spoken, up to [`MAX_HANDSHAKE_SOURCES`] other ports on its IP are
///   accepted too (a peer behind NAT), in arrival order and never evicted.
///   Once it has spoken no new port is accepted; ports already kept stay.
/// - Forwards to the sidecar pass a token bucket
///   ([`crate::srtp_relay::DTLS_FORWARD_BURST`] /
///   [`crate::srtp_relay::DTLS_FORWARD_PER_SECOND`]) shared by all sources,
///   and a budget per handshake ([`MAX_HANDSHAKE_FORWARD_DATAGRAMS`] /
///   [`MAX_HANDSHAKE_FORWARD_BYTES`]); nothing is buffered here, a datagram
///   over either is dropped and counted.
/// - The sidecar's outbound records go to the SDP address and to every kept
///   source, so the genuine peer receives each flight whoever else spoke
///   first (at most five sends per record, all to the peer's IP; RFC 6347
///   §4.2.1 does not tie a flight to one transport address). A failed send
///   to one target is counted and the others are still sent. The SDP address
///   is the target before any record arrives, which the SBC needs as DTLS
///   client to send the first flight.
/// - No single datagram can redirect the pump. The returned
///   [`HandshakeKeys::peer_addr`] is a hint for the media latch, which SRTP
///   authentication then confirms or corrects.
///
/// `stats` is reset on entry and updated as datagrams arrive, so the caller
/// still has the counters when the handshake fails or a timeout around this
/// future fires.
///
/// The caller should bound this with a timeout and own the socket's lifetime.
///
/// # Errors
/// Media/IPC I/O failure or a sidecar-reported handshake error.
pub async fn run_handshake_pump(
    media: &UdpSocket,
    signaling_peer: SocketAddr,
    reader: &mut SidecarReader,
    writer: &mut SidecarWriter,
    stats: &mut HandshakeSourceStats,
) -> Result<HandshakeKeys, DtlsRelayError> {
    let mut buf = [0u8; RECV_BUF];
    // NIST 800-53 Rev5: SC-7, SI-10, SC-5 -- plausibility filter, exact SDP
    // source first, bounded never-evicted source set, rate limit.
    let mut sources = HandshakeSources::new(signaling_peer, Instant::now(), stats);
    loop {
        tokio::select! {
            // Media socket -> demux -> sidecar (inbound DTLS records).
            recv = media.recv_from(&mut buf) => {
                let (n, src) = recv?;
                let datagram = buf.get(..n).unwrap_or_default();
                if sources.admit(src, datagram, Instant::now()) {
                    writer.send_dtls(datagram).await?;
                }
            }
            // Sidecar -> media socket (outbound DTLS records) / Ready / Error.
            event = reader.read() => {
                match event? {
                    SidecarEvent::Dtls(record) => {
                        for dest in sources.flight_targets().into_iter().flatten() {
                            if let Err(e) = media.send_to(&record, dest).await {
                                sources.stats.send_failures += 1;
                                debug!(error = %e, dest = %dest, "DTLS flight send failed; sending to the other targets");
                            }
                        }
                    }
                    SidecarEvent::Ready { profile, srtp_keys } => {
                        return Ok(HandshakeKeys {
                            profile,
                            srtp_keys,
                            peer_addr: sources.completed_from(),
                            peers: sources.peers(),
                        });
                    }
                    SidecarEvent::Error(msg) => {
                        return Err(DtlsRelayError::Sidecar(msg));
                    }
                }
            }
        }
    }
}

/// Splits the sidecar's exported DTLS-SRTP keying material into the SBC leg's
/// `(outbound, inbound)` SRTP master key material.
///
/// The `exported` blob is the RFC 5764 §4.2 layout for AEAD_AES_256_GCM:
/// `client_write_key(32) || server_write_key(32) || client_write_salt(12) ||
/// server_write_salt(12)`. Which half is the SBC's *outbound* (local) key
/// depends on the DTLS role: the client uses the `client_write_*` values to
/// protect its own traffic, the server uses `server_write_*`. `sbc_is_client`
/// is true when the SBC drove the handshake as DTLS client (peer offered
/// `a=setup:passive`, so the SBC is `active`).
///
/// # Errors
/// The blob is not exactly [`EXPORTED_KEYING_LEN`] bytes, or proto-srtp rejects
/// the derived key/salt.
pub fn srtp_key_material(
    exported: &[u8],
    sbc_is_client: bool,
) -> Result<(SrtpKeyMaterial, SrtpKeyMaterial), DtlsRelayError> {
    if exported.len() != EXPORTED_KEYING_LEN {
        return Err(DtlsRelayError::KeyMaterial(format!(
            "exported keying material is {} bytes, expected {EXPORTED_KEYING_LEN}",
            exported.len()
        )));
    }
    // RFC 5764 §4.2: keys first (both directions), then salts.
    let (keys, salts) = exported.split_at(2 * SRTP_MASTER_KEY_LEN);
    let (client_key, server_key) = keys.split_at(SRTP_MASTER_KEY_LEN);
    let (client_salt, server_salt) = salts.split_at(SRTP_MASTER_SALT_LEN);

    // Outbound = what the SBC uses to protect its own sent traffic (its
    // write key); inbound = the peer's write key, for unprotecting.
    let (out_key, out_salt, in_key, in_salt) = if sbc_is_client {
        (client_key, client_salt, server_key, server_salt)
    } else {
        (server_key, server_salt, client_key, client_salt)
    };

    let outbound = SrtpKeyMaterial::new(
        SrtpProfile::AeadAes256Gcm,
        out_key.to_vec(),
        out_salt.to_vec(),
    )
    .map_err(|e| DtlsRelayError::KeyMaterial(format!("outbound: {e}")))?;
    let inbound = SrtpKeyMaterial::new(
        SrtpProfile::AeadAes256Gcm,
        in_key.to_vec(),
        in_salt.to_vec(),
    )
    .map_err(|e| DtlsRelayError::KeyMaterial(format!("inbound: {e}")))?;
    Ok((outbound, inbound))
}

/// A terminated leg after a successful DTLS handshake: the derived SRTP key
/// material for each direction plus the live sidecar connection halves.
///
/// The `reader`/`writer` are intentionally handed back rather than dropped: the
/// DTLS association must live for the whole call. The sidecar keeps it open for
/// as long as this connection is open and ends it, with `close_notify`, when
/// the connection (or its sending half) is closed; a peer that reads
/// `close_notify` treats it as teardown. The caller keeps both halves in the
/// session, pumps any post-handshake DTLS (a retransmitted final flight,
/// alerts) between the media socket and the sidecar, and closes them only at
/// call end (see `forward_dtls_to_sidecar` / `pump_sidecar_dtls_to_peer` in
/// `srtp_relay`).
#[derive(Debug)]
pub struct EstablishedLeg {
    /// SRTP master key material the SBC uses to protect its outbound media.
    pub outbound: SrtpKeyMaterial,
    /// SRTP master key material the SBC uses to unprotect inbound media.
    pub inbound: SrtpKeyMaterial,
    /// Live read half of the sidecar session (post-handshake DTLS in).
    pub reader: SidecarReader,
    /// Live write half of the sidecar session (post-handshake DTLS out).
    pub writer: SidecarWriter,
    /// The source the handshake completed with, a hint for the media latch
    /// (see [`HandshakeKeys::peer_addr`]).
    pub peer_addr: SocketAddr,
    /// The sources the handshake pump forwarded DTLS from (see
    /// [`HandshakeKeys::peers`]).
    pub handshake_peers: HandshakePeers,
}

/// Drives a full terminate-mode DTLS-SRTP handshake for one leg: connects to
/// the sidecar (verifying its live fingerprint matches `own_fingerprint`),
/// starts the handshake in the given `role`, pumps records over `media` until
/// the sidecar reports `Ready`, then derives the leg's SRTP key material.
///
/// `signaling_peer` is the peer's SDP media address, used to send the first
/// outbound flight before the peer's source is latched (see
/// [`run_handshake_pump`]). `stats` receives the pump's source counters,
/// also when the handshake fails or times out.
///
/// # Errors
/// Sidecar connect/fingerprint failure, a handshake error, a negotiated
/// profile other than `SRTP_AEAD_AES_256_GCM`, or malformed keying material.
pub async fn establish_srtp_leg(
    media: &UdpSocket,
    signaling_peer: SocketAddr,
    sidecar_socket: &Path,
    own_fingerprint: &str,
    peer_fingerprint: &str,
    role: Role,
    stats: &mut HandshakeSourceStats,
) -> Result<EstablishedLeg, DtlsRelayError> {
    let mut client = SidecarClient::connect(sidecar_socket, own_fingerprint).await?;
    client.start(role, peer_fingerprint).await?;
    let (mut reader, mut writer) = client.into_split();

    let keys = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_handshake_pump(media, signaling_peer, &mut reader, &mut writer, stats),
    )
    .await
    .map_err(|_| DtlsRelayError::Sidecar("DTLS handshake timed out".into()))??;

    if keys.profile != SRTP_AEAD_AES_256_GCM {
        return Err(DtlsRelayError::KeyMaterial(format!(
            "sidecar negotiated SRTP profile {}, expected AEAD_AES_256_GCM ({SRTP_AEAD_AES_256_GCM})",
            keys.profile
        )));
    }

    // The SBC is DTLS client iff it took the `active` role (peer was passive).
    let sbc_is_client = matches!(role, Role::Client);
    let (outbound, inbound) = srtp_key_material(&keys.srtp_keys, sbc_is_client)?;

    Ok(EstablishedLeg {
        outbound,
        inbound,
        reader,
        writer,
        peer_addr: keys.peer_addr,
        handshake_peers: keys.peers,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dtls_sidecar::{Role, SidecarClient};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn demux_classifies_dtls() {
        assert!(!is_dtls_record(0)); // STUN
        assert!(is_dtls_record(20)); // DTLS low
        assert!(is_dtls_record(22)); // DTLS handshake
        assert!(is_dtls_record(63)); // DTLS high
        assert!(!is_dtls_record(64)); // TURN channel
        assert!(!is_dtls_record(128)); // RTP/SRTP
    }

    // Distinct patterns per RFC 5764 field so the split is identifiable.
    fn sample_exported() -> Vec<u8> {
        let mut v = Vec::with_capacity(EXPORTED_KEYING_LEN);
        v.extend_from_slice(&[0x11u8; SRTP_MASTER_KEY_LEN]); // client_write_key
        v.extend_from_slice(&[0x22u8; SRTP_MASTER_KEY_LEN]); // server_write_key
        v.extend_from_slice(&[0x33u8; SRTP_MASTER_SALT_LEN]); // client_write_salt
        v.extend_from_slice(&[0x44u8; SRTP_MASTER_SALT_LEN]); // server_write_salt
        v
    }

    #[test]
    fn srtp_split_client_role() {
        // SBC is DTLS client: outbound = client_write_*, inbound = server_write_*.
        let (out, inb) = srtp_key_material(&sample_exported(), true).unwrap();
        assert_eq!(out.master_key(), [0x11u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(out.master_salt(), [0x33u8; SRTP_MASTER_SALT_LEN]);
        assert_eq!(inb.master_key(), [0x22u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(inb.master_salt(), [0x44u8; SRTP_MASTER_SALT_LEN]);
    }

    #[test]
    fn srtp_split_server_role() {
        // SBC is DTLS server: outbound = server_write_*, inbound = client_write_*.
        let (out, inb) = srtp_key_material(&sample_exported(), false).unwrap();
        assert_eq!(out.master_key(), [0x22u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(out.master_salt(), [0x44u8; SRTP_MASTER_SALT_LEN]);
        assert_eq!(inb.master_key(), [0x11u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(inb.master_salt(), [0x33u8; SRTP_MASTER_SALT_LEN]);
    }

    #[test]
    fn srtp_split_rejects_wrong_length() {
        assert!(matches!(
            srtp_key_material(&[0u8; EXPORTED_KEYING_LEN - 1], true),
            Err(DtlsRelayError::KeyMaterial(_))
        ));
        assert!(matches!(
            srtp_key_material(&[0u8; EXPORTED_KEYING_LEN + 1], false),
            Err(DtlsRelayError::KeyMaterial(_))
        ));
    }

    // Mock-sidecar framing (matches the Go service protocol).
    const MSG_HELLO: u8 = 1;
    const MSG_START: u8 = 2;
    const MSG_DTLS: u8 = 3;
    const MSG_READY: u8 = 4;

    async fn write_typed<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
        let n = 1 + body.len();
        let mut f = Vec::with_capacity(2 + n);
        f.extend_from_slice(&(u16::try_from(n).unwrap()).to_be_bytes());
        f.push(t);
        f.extend_from_slice(body);
        w.write_all(&f).await.unwrap();
    }
    async fn read_typed<R: AsyncReadExt + Unpin>(r: &mut R) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 2];
        r.read_exact(&mut hdr).await.unwrap();
        let n = usize::from(u16::from_be_bytes(hdr));
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await.unwrap();
        (buf[0], buf[1..].to_vec())
    }

    // A peer DTLS record is forwarded to the sidecar; the sidecar's response is
    // sent back to the peer; Ready yields the SRTP keys. Exercises the demux +
    // bidirectional pump (no real DTLS crypto).
    #[tokio::test]
    async fn pump_forwards_records_and_returns_keys() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let sock = std::env::temp_dir().join(format!("usg-dtls-relay-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let fp = "sha-384 SIDECAR";

        let sock2 = sock.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, fp.as_bytes()).await;
            let (t, _) = read_typed(&mut r).await; // Start
            assert_eq!(t, MSG_START);
            let (t, rec) = read_typed(&mut r).await; // forwarded peer DTLS record
            assert_eq!(t, MSG_DTLS);
            assert_eq!(rec, record(22, 1, b"hello"));
            write_typed(&mut w, MSG_DTLS, b"sidecar-record").await;
            let mut ready = vec![0u8, 8];
            ready.extend_from_slice(&[9u8; 88]);
            write_typed(&mut w, MSG_READY, &ready).await;
            let _ = std::fs::remove_file(&sock2);
        });

        let mut client = SidecarClient::connect(&sock, fp).await.unwrap();
        client.start(Role::Server, "sha-384 PEER").await.unwrap();
        let (mut reader, mut writer) = client.into_split();

        // Peer sends a DTLS handshake record (13-byte header, type 22).
        peer.send_to(&record(22, 1, b"hello"), relay_addr)
            .await
            .unwrap();

        let mut stats = HandshakeSourceStats::default();
        let keys = tokio::time::timeout(
            Duration::from_secs(5),
            run_handshake_pump(&relay, peer_addr, &mut reader, &mut writer, &mut stats),
        )
        .await
        .expect("pump timed out")
        .expect("pump failed");

        assert_eq!(keys.profile, 8);
        assert_eq!(keys.srtp_keys.len(), 88);
        // The SDP address spoke: it is the handshake source, nothing dropped.
        assert_eq!(keys.peer_addr, peer_addr);
        assert_eq!(keys.peers, HandshakePeers::from_addrs(&[peer_addr]));
        assert_eq!(stats, HandshakeSourceStats::default());

        // The sidecar's outbound record reached the peer.
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("peer recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"sidecar-record");

        sidecar.await.unwrap();
    }

    // End-to-end driver over a mock sidecar + UDP peer: connect (fingerprint
    // verify) -> start -> pump -> Ready(profile=8) -> derive SRTP material for
    // the SBC-as-server role, returning the live halves.
    #[tokio::test]
    async fn establish_leg_derives_material_and_keeps_halves() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let sock = std::env::temp_dir().join(format!("usg-dtls-estab-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let own_fp = "sha-384 SIDECAR";

        let sock2 = sock.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, own_fp.as_bytes()).await;
            let (t, start) = read_typed(&mut r).await; // Start(role, peer_fp)
            assert_eq!(t, MSG_START);
            assert_eq!(start[0], Role::Server as u8);
            assert_eq!(&start[1..], b"sha-384 PEER");
            let (t, _) = read_typed(&mut r).await; // forwarded peer DTLS
            assert_eq!(t, MSG_DTLS);
            write_typed(&mut w, MSG_DTLS, b"srv").await;
            let mut ready = vec![
                (SRTP_AEAD_AES_256_GCM >> 8) as u8,
                (SRTP_AEAD_AES_256_GCM & 0xff) as u8,
            ];
            ready.extend_from_slice(&sample_exported());
            write_typed(&mut w, MSG_READY, &ready).await;
            let _ = std::fs::remove_file(&sock2);
        });

        peer.send_to(&record(22, 9, &[9]), relay_addr)
            .await
            .unwrap();

        let mut stats = HandshakeSourceStats::default();
        let leg = tokio::time::timeout(
            Duration::from_secs(5),
            establish_srtp_leg(
                &relay,
                peer_addr,
                &sock,
                own_fp,
                "sha-384 PEER",
                Role::Server,
                &mut stats,
            ),
        )
        .await
        .expect("establish timed out")
        .expect("establish failed");

        // SBC is DTLS server: outbound = server_write_* (0x22/0x44),
        // inbound = client_write_* (0x11/0x33).
        assert_eq!(leg.outbound.master_key(), [0x22u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(leg.outbound.master_salt(), [0x44u8; SRTP_MASTER_SALT_LEN]);
        assert_eq!(leg.inbound.master_key(), [0x11u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(leg.inbound.master_salt(), [0x33u8; SRTP_MASTER_SALT_LEN]);
        // reader/writer are returned live (typed fields) rather than dropped at
        // key export — deferred finding #2.
        assert_eq!(leg.peer_addr, peer_addr);
        assert_eq!(
            leg.handshake_peers,
            HandshakePeers::from_addrs(&[peer_addr])
        );
        assert_eq!(stats, HandshakeSourceStats::default());

        sidecar.await.unwrap();
    }

    // ---- Handshake pump source handling --------------------------------------
    //
    // No single datagram may redirect the pump. Inbound DTLS must pass a
    // record-header plausibility walk; up to MAX_HANDSHAKE_SOURCES other
    // same-IP ports are kept (never evicted) until the exact SDP source
    // speaks, after which no new port is taken but kept ones stay; every
    // sidecar flight goes to the SDP address and each kept source; forwards
    // to the sidecar are rate-limited.

    /// One DTLS 1.2 record: 13-byte header (RFC 6347 §4.1) + `body`.
    fn record(content_type: u8, seq: u8, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(body.len()).unwrap().to_be_bytes();
        let mut r = vec![
            content_type,
            0xFE,
            0xFD,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            seq,
            len[0],
            len[1],
        ];
        r.extend_from_slice(body);
        r
    }

    /// Mock sidecar for one session: Hello, Start, then every DTLS record the
    /// pump forwards up to and including `last`, then one outbound DTLS
    /// record (`b"sidecar-flight"`) and `Ready`. With `last = None` it never
    /// answers. Returns the client halves and a handle yielding the
    /// forwarded records. Ends on a signal (the expected record), not on an
    /// idle timer.
    async fn mock_sidecar(
        name: &str,
        last: Option<Vec<u8>>,
    ) -> (
        SidecarReader,
        SidecarWriter,
        tokio::task::JoinHandle<Vec<Vec<u8>>>,
    ) {
        let path =
            std::env::temp_dir().join(format!("usg-hs-src-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let fp = "sha-384 SIDECAR";
        let path2 = path.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, fp.as_bytes()).await;
            let (t, _) = read_typed(&mut r).await;
            assert_eq!(t, MSG_START);
            let _ = std::fs::remove_file(&path2);
            let mut forwarded = Vec::new();
            let Some(last) = last else {
                // Never answers; read until the client goes away.
                while let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_secs(10), r.read_u8()).await
                {
                }
                return forwarded;
            };
            loop {
                let (t, rec) = tokio::time::timeout(Duration::from_secs(5), read_typed(&mut r))
                    .await
                    .expect("the expected last record never reached the sidecar");
                assert_eq!(t, MSG_DTLS);
                let done = rec == last;
                forwarded.push(rec);
                if done {
                    break;
                }
            }
            write_typed(&mut w, MSG_DTLS, b"sidecar-flight").await;
            let mut ready = vec![0u8, 8];
            ready.extend_from_slice(&[9u8; 88]);
            write_typed(&mut w, MSG_READY, &ready).await;
            // Keep the connection until the test is done reading.
            tokio::time::sleep(Duration::from_millis(200)).await;
            forwarded
        });
        let mut client = SidecarClient::connect(&path, fp).await.unwrap();
        client.start(Role::Server, "sha-384 PEER").await.unwrap();
        let (reader, writer) = client.into_split();
        (reader, writer, sidecar)
    }

    /// Whether `sock` receives the sidecar's flight within `ms`. The flight
    /// is sent before `Ready`, so by the time the pump has returned it is
    /// already queued wherever it was sent.
    async fn got_flight(sock: &UdpSocket, ms: u64) -> bool {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(ms), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => &buf[..n] == b"sidecar-flight",
            _ => false,
        }
    }

    /// Runs the pump to `Ready` (5 s bound) and returns the keys and stats.
    async fn pump(
        relay: &UdpSocket,
        sdp: SocketAddr,
        reader: &mut SidecarReader,
        writer: &mut SidecarWriter,
    ) -> (HandshakeKeys, HandshakeSourceStats) {
        let mut stats = HandshakeSourceStats::default();
        let keys = tokio::time::timeout(
            Duration::from_secs(5),
            run_handshake_pump(relay, sdp, reader, writer, &mut stats),
        )
        .await
        .expect("pump timed out")
        .expect("pump failed");
        (keys, stats)
    }

    // A forged but plausible record from P2 does not pin the pump: the
    // peer's record from P1 (neither is the SDP port) is forwarded too, the
    // sidecar's flight reaches P1, P2 and the SDP address, and the handshake
    // completes with P1 (the last source).
    // NIST 800-53 Rev5: SC-7, SI-10, SC-5
    #[tokio::test]
    async fn pump_is_not_pinned_by_one_forged_datagram() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let forged = record(22, 1, b"forged");
        let genuine = record(22, 1, b"client-hello");
        let (mut reader, mut writer, sidecar) = mock_sidecar("pinned", Some(genuine.clone())).await;

        p2.send_to(&forged, relay_addr).await.unwrap();
        p1.send_to(&genuine, relay_addr).await.unwrap();

        let (keys, stats) = pump(&relay, sdp.local_addr().unwrap(), &mut reader, &mut writer).await;
        assert_eq!(keys.profile, 8);

        let forwarded = sidecar.await.unwrap();
        assert_eq!(
            forwarded,
            vec![forged, genuine],
            "both same-IP sources must reach the sidecar"
        );
        assert!(got_flight(&p1, 2000).await, "flight did not reach P1");
        assert!(got_flight(&p2, 2000).await, "flight did not reach P2");
        assert!(
            got_flight(&sdp, 2000).await,
            "flight did not reach the SDP address"
        );
        let (p1, p2) = (p1.local_addr().unwrap(), p2.local_addr().unwrap());
        assert_eq!(keys.peer_addr, p1);
        assert_eq!(keys.peers, HandshakePeers::from_addrs(&[p2, p1]));
        assert_eq!(stats.sources, 2);
        assert!(!stats.any_dropped());
    }

    // SI-10 plausibility filter: a DTLS-class first byte is not enough. Too
    // short for a header, a wrong version, a content type outside 20..=24
    // (30, and 25 = tls12_cid), a DTLS 1.3 unified header, a length past the
    // datagram, and a valid record followed by a truncated header are all
    // dropped. A valid record and a datagram of two valid records are
    // forwarded.
    #[tokio::test]
    async fn pump_drops_implausible_dtls() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let short = vec![22u8, 1, 2, 3];
        let mut bad_version = record(22, 1, b"x");
        bad_version[1] = 0x03;
        bad_version[2] = 0x03;
        let bad_type = record(30, 1, b"x");
        let cid = record(25, 1, b"x");
        // RFC 9147 §4: 001CSLEE, epoch bits, 16-bit sequence, 16-bit length.
        let unified = vec![0x2Cu8, 0x00, 0x01, 0x00, 0x03, 1, 2, 3];
        let mut overlong = record(22, 1, b"abc");
        overlong[12] = 200;
        let mut truncated_tail = record(22, 1, b"ok");
        truncated_tail.extend_from_slice(&[22, 0xFE, 0xFD, 0]);
        let valid = record(22, 2, b"client-hello");
        let mut two = record(22, 3, b"first");
        two.extend_from_slice(&record(20, 4, &[1]));
        let (mut reader, mut writer, sidecar) =
            mock_sidecar("implausible", Some(two.clone())).await;

        for d in [
            &short,
            &bad_version,
            &bad_type,
            &cid,
            &unified,
            &overlong,
            &truncated_tail,
        ] {
            peer.send_to(d, relay_addr).await.unwrap();
        }
        peer.send_to(&valid, relay_addr).await.unwrap();
        peer.send_to(&two, relay_addr).await.unwrap();

        let (keys, stats) =
            pump(&relay, peer.local_addr().unwrap(), &mut reader, &mut writer).await;

        let forwarded = sidecar.await.unwrap();
        assert_eq!(
            forwarded,
            vec![valid, two],
            "only plausible DTLS datagrams may reach the sidecar"
        );
        assert_eq!(stats.dropped_implausible, 7);
        assert_eq!(keys.peer_addr, peer.local_addr().unwrap());
    }

    // Once the exact SDP source has spoken no new port is taken (P3 is
    // dropped and gets no flight), but a port kept before it spoke (P2)
    // stays: its later record is forwarded and it gets the flight, so one
    // datagram spoofed from the SDP address cannot cut off a NAT'd peer
    // already in the set.
    #[tokio::test]
    async fn pump_exact_source_closes_the_set_but_keeps_admitted_ports() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let early = record(22, 1, b"other-first");
        let genuine = record(22, 1, b"client-hello");
        let late = record(22, 2, b"other-late");
        let newcomer = record(22, 1, b"new-after-exact");
        let last = record(22, 3, b"last");
        let (mut reader, mut writer, sidecar) = mock_sidecar("exact", Some(last.clone())).await;
        p2.send_to(&early, relay_addr).await.unwrap();
        sdp.send_to(&genuine, relay_addr).await.unwrap();
        p2.send_to(&late, relay_addr).await.unwrap();
        p3.send_to(&newcomer, relay_addr).await.unwrap();
        sdp.send_to(&last, relay_addr).await.unwrap();

        let (keys, stats) = pump(&relay, sdp.local_addr().unwrap(), &mut reader, &mut writer).await;

        let forwarded = sidecar.await.unwrap();
        assert_eq!(
            forwarded,
            vec![early, genuine, late, last],
            "the SDP source and the kept port are forwarded; a new port after the SDP source is not"
        );
        assert!(
            got_flight(&sdp, 2000).await,
            "flight did not reach the SDP address"
        );
        assert!(
            got_flight(&p2, 2000).await,
            "flight did not reach the kept P2"
        );
        assert!(
            !got_flight(&p3, 200).await,
            "flight sent to a port first heard after the SDP source spoke"
        );
        let (sdp, p2) = (sdp.local_addr().unwrap(), p2.local_addr().unwrap());
        assert_eq!(keys.peer_addr, sdp);
        assert_eq!(keys.peers, HandshakePeers::from_addrs(&[sdp, p2]));
        assert_eq!(stats.dropped_after_exact, 1);
        assert_eq!(stats.dropped_overflow, 0);
    }

    // While the SDP source is silent, at most four other same-IP ports are
    // kept, in arrival order and never evicted: a fifth is dropped and gets
    // no flight; the first four and the SDP address all get it.
    #[tokio::test]
    async fn pump_source_set_is_bounded_and_not_evicted() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let mut ports = Vec::new();
        for _ in 0..5 {
            ports.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        let last = record(22, 2, b"last-from-source-0");
        let (mut reader, mut writer, sidecar) = mock_sidecar("bounded", Some(last.clone())).await;

        let mut sent = Vec::new();
        for (i, p) in ports.iter().enumerate() {
            let rec = record(22, 1, format!("source-{i}").as_bytes());
            p.send_to(&rec, relay_addr).await.unwrap();
            sent.push(rec);
        }
        ports[0].send_to(&last, relay_addr).await.unwrap();

        let (keys, stats) = pump(&relay, sdp.local_addr().unwrap(), &mut reader, &mut writer).await;

        let forwarded = sidecar.await.unwrap();
        let mut want = sent[..4].to_vec();
        want.push(last);
        assert_eq!(
            forwarded, want,
            "first four sources forwarded, fifth dropped"
        );
        for (i, p) in ports.iter().enumerate().take(4) {
            assert!(got_flight(p, 2000).await, "flight did not reach source {i}");
        }
        assert!(
            got_flight(&sdp, 2000).await,
            "flight did not reach the SDP address"
        );
        assert!(
            !got_flight(&ports[4], 200).await,
            "flight sent to the dropped fifth source"
        );
        assert_eq!(keys.peer_addr, ports[0].local_addr().unwrap());
        assert_eq!(stats.dropped_overflow, 1);
        assert_eq!(stats.sources, MAX_HANDSHAKE_SOURCES);
    }

    // SC-5: forwards to the sidecar pass a token bucket shared by all
    // sources (burst DTLS_FORWARD_BURST, then DTLS_FORWARD_PER_SECOND). A
    // rate-limited datagram from a new port does not take a slot; once a
    // token has refilled the same port is taken.
    #[test]
    fn handshake_sources_rate_limit_forwards() {
        use crate::srtp_relay::{DTLS_FORWARD_BURST, DTLS_FORWARD_PER_SECOND};
        let ip = std::net::Ipv4Addr::LOCALHOST;
        let sdp = SocketAddr::from((ip, 5000));
        let p1 = SocketAddr::from((ip, 5002));
        let p2 = SocketAddr::from((ip, 5004));
        let rec = record(22, 1, b"x");
        let now = Instant::now();
        let mut stats = HandshakeSourceStats::default();
        {
            let mut sources = HandshakeSources::new(sdp, now, &mut stats);
            let burst = usize::try_from(DTLS_FORWARD_BURST).unwrap();
            let admitted = (0..burst + 4)
                .filter(|_| sources.admit(p1, &rec, now))
                .count();
            assert_eq!(admitted, burst, "burst forwarded, the rest dropped");
            assert!(!sources.admit(p2, &rec, now), "over the limit");
            assert!(sources.others[1].is_none(), "rate-limited port took a slot");
            let refill = now + Duration::from_millis(1000 / u64::from(DTLS_FORWARD_PER_SECOND));
            assert!(
                sources.admit(p2, &rec, refill),
                "a refilled token admits P2"
            );
            assert_eq!(sources.others[1], Some(p2));
        }
        assert_eq!(stats.dropped_rate_limited, 5);
        assert_eq!(stats.sources, 2);
    }

    // SR-13: a flood from an accepted source reaches the sidecar only up to
    // the handshake's budget, in datagrams and in bytes, however long the
    // rate limit would let it go on; the budget is spent by forwards only.
    #[test]
    fn handshake_sources_budget_bounds_forwards() {
        use crate::srtp_relay::DTLS_FORWARD_PER_SECOND;
        let ip = std::net::Ipv4Addr::LOCALHOST;
        let sdp = SocketAddr::from((ip, 5000));
        let tick = Duration::from_millis(1000 / u64::from(DTLS_FORWARD_PER_SECOND));
        let start = Instant::now();

        // Small datagrams: the datagram budget binds.
        let small = record(22, 1, b"x");
        let mut stats = HandshakeSourceStats::default();
        let mut forwarded_bytes = 0usize;
        {
            let mut sources = HandshakeSources::new(sdp, start, &mut stats);
            let mut admitted = 0u32;
            // A whole minute at the rate limit: far more than the budget.
            for i in 0..240u32 {
                if sources.admit(sdp, &small, start + tick * i) {
                    admitted += 1;
                    forwarded_bytes += small.len();
                }
            }
            assert_eq!(admitted, MAX_HANDSHAKE_FORWARD_DATAGRAMS);
        }
        assert_eq!(
            stats.dropped_budget,
            u64::from(240 - MAX_HANDSHAKE_FORWARD_DATAGRAMS)
        );
        assert_eq!(
            stats.dropped_rate_limited, 0,
            "the pace never exceeds the rate"
        );
        assert!(forwarded_bytes <= MAX_HANDSHAKE_FORWARD_BYTES);

        // Full-size datagrams: the byte budget binds first.
        let big = record(22, 1, &[0u8; RECV_BUF - 13]);
        let mut stats = HandshakeSourceStats::default();
        let mut forwarded_bytes = 0usize;
        {
            let mut sources = HandshakeSources::new(sdp, start, &mut stats);
            for i in 0..240u32 {
                if sources.admit(sdp, &big, start + tick * i) {
                    forwarded_bytes += big.len();
                }
            }
        }
        assert_eq!(
            forwarded_bytes,
            (MAX_HANDSHAKE_FORWARD_BYTES / big.len()) * big.len()
        );
        assert!(forwarded_bytes <= MAX_HANDSHAKE_FORWARD_BYTES);
        assert!(stats.any_dropped());

        // A budget refusal spends no token: an implausible datagram, or one
        // over budget, leaves the bucket for nothing else either way.
        let mut stats = HandshakeSourceStats::default();
        {
            let mut sources = HandshakeSources::new(sdp, start, &mut stats);
            sources.forwarded = MAX_HANDSHAKE_FORWARD_DATAGRAMS;
            assert!(!sources.admit(sdp, &small, start));
            assert!(
                !sources.exact_seen,
                "a datagram over budget changed the source state"
            );
        }
        assert_eq!(stats.dropped_budget, 1);
        assert_eq!(stats.dropped_rate_limited, 0);
    }

    // The caller owns the counters, so a handshake that times out still
    // reports what the pump dropped.
    #[tokio::test]
    async fn pump_stats_survive_a_timeout() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (mut reader, mut writer, _sidecar) = mock_sidecar("timeout", None).await;
        peer.send_to(&[22u8, 1, 2, 3], relay_addr).await.unwrap();
        peer.send_to(&record(30, 1, b"x"), relay_addr)
            .await
            .unwrap();

        let mut stats = HandshakeSourceStats::default();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            run_handshake_pump(
                &relay,
                peer.local_addr().unwrap(),
                &mut reader,
                &mut writer,
                &mut stats,
            ),
        )
        .await;
        assert!(result.is_err(), "the mock sidecar never answers");
        assert_eq!(stats.dropped_implausible, 2);
        assert!(stats.any_dropped());
    }

    // SI-10: the plausibility walk never panics, and accepting a datagram
    // means every record header and body lies inside it.
    proptest::proptest! {
        #[test]
        fn plausibility_walk_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
            if is_plausible_dtls(&data) {
                let mut rest = &data[..];
                while !rest.is_empty() {
                    proptest::prop_assert!(rest.len() >= DTLS_RECORD_HEADER_LEN);
                    proptest::prop_assert!((20..=24).contains(&rest[0]));
                    let len = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
                    proptest::prop_assert!(rest.len() >= DTLS_RECORD_HEADER_LEN + len);
                    rest = &rest[DTLS_RECORD_HEADER_LEN + len..];
                }
            }
        }

        #[test]
        fn plausibility_walk_accepts_concatenated_records(
            bodies in proptest::collection::vec(
                (20u8..=24, proptest::collection::vec(proptest::num::u8::ANY, 0..64)),
                1..6,
            ),
        ) {
            let mut datagram = Vec::new();
            for (seq, (content_type, body)) in bodies.iter().enumerate() {
                datagram.extend_from_slice(&record(*content_type, u8::try_from(seq).unwrap(), body));
            }
            proptest::prop_assert!(is_plausible_dtls(&datagram));
            // One byte short of the last record's body is rejected.
            datagram.pop();
            proptest::prop_assert!(!is_plausible_dtls(&datagram));
        }
    }
}
