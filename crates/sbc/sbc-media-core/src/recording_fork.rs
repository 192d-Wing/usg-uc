//! SIPREC media fork: a send-only SRTP copy of each call leg's RTP toward a
//! Session Recording Server (RFC 7866 §8, the SRC acting as an RTP endpoint).
//!
//! Each recorded call has two fork streams, one per relay direction (the
//! caller's sent media and the callee's). A stream owns its own socket, its own
//! AES-256-GCM SRTP context (one master key per stream), an SBC-chosen SSRC and
//! an SBC-owned 48-bit packet counter. Payload type, marker, timestamp, CSRC
//! list and header extension are copied from the relayed packet; the SSRC and
//! sequence number are overwritten.
//!
//! Why the SSRC and sequence number are not the endpoint's: the AES-GCM nonce
//! is built from `(SSRC, ROC || SEQ)` (RFC 7714 §8.1). Forwarding
//! endpoint-chosen values would let a call party repeat a sequence number, or
//! change SSRC and back, and force nonce reuse under one key (RFC 7714 §8.4).
//! With a counter the nonce is unique by construction.
//!
//! Ownership: the control path builds a [`ForkStream`] and parks it in a
//! [`ForkControl`]; exactly one relay task holds the matching [`ForkTap`] and
//! takes the stream on the next epoch change. The steady-state path
//! ([`ForkTap::on_rtp`]) takes no lock, makes no heap allocation and never
//! awaits: one atomic load, one bounded copy, one AEAD seal in place and one
//! non-blocking `send`. A send that would block, or fails, drops that copy and
//! counts it; the call's own media is never delayed by the recorder path.
//!
//! The fork sockets are send-only. Nothing ever reads them, and they are
//! connected to the recorder's address so the kernel discards datagrams from
//! any other source; what the recorder itself sends (RTCP receiver reports
//! on the muxed port) is bounded by the socket receive buffer, which is
//! shrunk to [`FORK_RCVBUF_BYTES`] at bind, and then dropped by the kernel.
//!
//! ## NIST 800-53 Rev5: AU-14 (Session Audit), SC-8 (Transmission
//! Confidentiality and Integrity), SC-12 / SC-13 (one key per stream,
//! AES-256-GCM), SC-5 (bounded, non-blocking), SC-7 (send-only sockets)
//!
//! POAM: POA&M-301 - no RTCP (sender reports, CNAME) is sent to the recorder
//! (RFC 7866 §8.1.1, §8.1.5.1): the RS carries RTP without RTCP, and upstream
//! packet loss shows at the recorder as a timestamp gap, not a sequence gap.
//!
//! POAM: POA&M-301 - a fork stream keeps its one SBC-chosen SSRC when the
//! call party changes SSRC (RFC 3550 §5.1 would have a new source use a new
//! SSRC); the recorder sees one source with a timestamp discontinuity.
//!
//! POAM: POA&M-300 - forked / dropped packets are counted process-wide only;
//! there is no per-session count, so a recording that received no media is
//! not told apart from a complete one.

use crate::media_pipeline::{MediaKind, MediaPipelineError};
use proto_srtp::{MAX_PACKET_INDEX, SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProtect};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::watch;
use tracing::warn;

/// Largest RTP packet a fork stream copies. Matches the relay's receive
/// buffer, so every datagram the relay can forward fits.
pub const FORK_MAX_PACKET: usize = 2048;

/// Receive buffer requested for a fork socket.
///
/// The kernel rounds it up to its own minimum. The socket is never read, so
/// whatever the recorder sends back sits there until the socket closes: the
/// default (hundreds of kilobytes) times two sockets per recorded call is
/// memory a recorder could pin (SC-5).
pub const FORK_RCVBUF_BYTES: usize = 4096;

/// Tail room for the AES-256-GCM authentication tag (RFC 7714 §13.2).
const FORK_TAG_ROOM: usize = 16;

/// RFC 3550 §5.1: fixed RTP header length.
const RTP_FIXED_HEADER: usize = 12;

/// Process-wide count of RTP packets sent to the recorder.
static FORK_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Process-wide count of packets that should have been forked and were not
/// (send would block or failed, malformed RTP header, oversize, seal failure).
static FORK_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Returns the total RTP packets sent to the recorder since start.
#[must_use]
pub fn recording_fork_packets() -> u64 {
    FORK_PACKETS.load(Ordering::Relaxed)
}

/// Returns the total packets the fork dropped instead of sending since start.
/// A rising value on a recorded call means the recording has gaps (AU-5).
#[must_use]
pub fn recording_fork_dropped() -> u64 {
    FORK_DROPPED.load(Ordering::Relaxed)
}

fn count_dropped() {
    FORK_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Local RTP ports of a prepared fork, for the recording session SDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingForkPorts {
    /// Port the caller's (A-leg) sent media is forked from.
    pub a_leg_port: u16,
    /// Port the callee's (B-leg) sent media is forked from.
    pub b_leg_port: u16,
}

/// Length of the RTP header at the start of `pkt` (fixed part, CSRC list and
/// header extension, RFC 3550 §5.1 / §5.3.1), or `None` when `pkt` is not a
/// complete RTP version 2 header.
// NIST 800-53 Rev5: SI-10 - wire data, bounds checked, never indexed.
fn rtp_header_len(pkt: &[u8]) -> Option<usize> {
    let first = *pkt.first()?;
    if first >> 6 != 2 {
        return None;
    }
    let mut len = RTP_FIXED_HEADER + usize::from(first & 0x0F) * 4;
    if first & 0x10 != 0 {
        let &[_, _, words_hi, words_lo] = pkt.get(len..len.checked_add(4)?)? else {
            return None;
        };
        len += 4 + usize::from(u16::from_be_bytes([words_hi, words_lo])) * 4;
    }
    (len <= pkt.len()).then_some(len)
}

/// What happened to one packet offered to a [`ForkStream`].
enum Forked {
    /// Sealed and handed to the socket.
    Sent,
    /// Not sent; already counted.
    Dropped,
    /// The 48-bit packet index is used up; the stream must stop.
    Exhausted,
}

/// One send-only SRTP stream toward the recorder.
///
/// Dropping the stream closes its socket and drops the SRTP context, whose
/// session keys are wiped on drop by `proto-srtp`.
///
/// ## NIST 800-53 Rev5: SC-12 (key lifetime ends with the stream), SI-12
pub struct ForkStream {
    /// Outbound SRTP context for this stream only. Its ROC / sequence state is
    /// not used; `index` below is the packet index.
    srtp: SrtpContext,
    /// Non-blocking, never read, never registered with the reactor.
    socket: std::net::UdpSocket,
    /// SBC-chosen SSRC written into every forked packet.
    ssrc: u32,
    /// Next SRTP packet index (`ROC || SEQ`, RFC 3711 §3.3.1). Advanced for
    /// every seal attempt, so no `(SSRC, index)` pair is ever used twice.
    index: u64,
    /// Working copy of the packet being sealed.
    buf: [u8; FORK_MAX_PACKET + FORK_TAG_ROOM],
}

// Hand-written so neither the packet buffer nor anything derived from the key
// can reach a log line; `SrtpContext` redacts its own keys.
impl std::fmt::Debug for ForkStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkStream")
            .field("ssrc", &format_args!("{:#010x}", self.ssrc))
            .field("index", &self.index)
            .field("local", &self.socket.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl ForkStream {
    /// Binds a fork socket on `bind` and installs `key` as this stream's SRTP
    /// master key. The stream is idle until [`ForkControl::activate`].
    ///
    /// # Errors
    /// [`MediaPipelineError::BindFailed`] if the socket cannot be bound or
    /// made non-blocking; [`MediaPipelineError::SrtpContextCreationFailed`]
    /// if the key cannot be used.
    pub fn bind(
        key: &SrtpKeyMaterial,
        bind: SocketAddr,
        ssrc: u32,
    ) -> Result<Box<Self>, MediaPipelineError> {
        let srtp = SrtpContext::new(key, SrtpDirection::Outbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;
        let socket = std::net::UdpSocket::bind(bind)
            .map_err(|e| MediaPipelineError::BindFailed(format!("recording fork {bind}: {e}")))?;
        // The relay task must never block on the recorder path.
        socket
            .set_nonblocking(true)
            .map_err(|e| MediaPipelineError::BindFailed(format!("recording fork {bind}: {e}")))?;
        // Never read: keep the kernel receive queue as small as it allows.
        // Best effort; a platform that refuses still gets a working fork.
        if let Err(e) = socket2::SockRef::from(&socket).set_recv_buffer_size(FORK_RCVBUF_BYTES) {
            warn!(error = %e, "Recording fork: could not shrink SO_RCVBUF");
        }
        Ok(Box::new(Self {
            srtp,
            socket,
            ssrc,
            // RFC 3550 §5.1: random initial sequence number. Kept below 2^15
            // so the receiver's first ROC estimate is 0 (RFC 3711 §3.3.1).
            index: u64::from(rand::random::<u16>() & 0x7FFF),
            buf: [0u8; FORK_MAX_PACKET + FORK_TAG_ROOM],
        }))
    }

    /// The SSRC this stream sends with.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The local port the stream sends from.
    ///
    /// # Errors
    /// [`MediaPipelineError::BindFailed`] if the socket has no local address.
    pub fn local_port(&self) -> Result<u16, MediaPipelineError> {
        self.socket
            .local_addr()
            .map(|addr| addr.port())
            .map_err(|e| MediaPipelineError::BindFailed(format!("recording fork: {e}")))
    }

    /// Copies `header || payload`, rewrites SSRC and sequence number, seals
    /// and sends. `header` must be exactly the RTP header.
    fn send_copy(&mut self, header: &[u8], payload: &[u8]) -> Forked {
        // RFC 3711 §9.2: past 2^48 packets the key is used up; stop rather
        // than wrap the nonce.
        if self.index > MAX_PACKET_INDEX {
            return Forked::Exhausted;
        }
        let header_len = header.len();
        let Some(packet_len) = header_len
            .checked_add(payload.len())
            .filter(|len| header_len >= RTP_FIXED_HEADER && *len <= FORK_MAX_PACKET)
        else {
            count_dropped();
            return Forked::Dropped;
        };
        let index = self.index;
        let Some((dst_header, dst_payload)) = self
            .buf
            .get_mut(..packet_len)
            .and_then(|packet| packet.split_at_mut_checked(header_len))
        else {
            count_dropped();
            return Forked::Dropped;
        };
        dst_header.copy_from_slice(header);
        dst_payload.copy_from_slice(payload);
        // RFC 3550 §5.1: sequence number at octets 2..4 (the low 16 bits of
        // the index), SSRC at 8..12.
        if let Some(seq) = dst_header.get_mut(2..4) {
            seq.copy_from_slice(&(index as u16).to_be_bytes());
        }
        if let Some(ssrc) = dst_header.get_mut(8..12) {
            ssrc.copy_from_slice(&self.ssrc.to_be_bytes());
        }

        // The index is spent whether or not the seal or the send succeeds.
        self.index = index + 1;
        let sealed = SrtpProtect::new(&self.srtp).protect_rtp_in_place(
            &mut self.buf,
            header_len,
            packet_len,
            index,
        );
        let Some(datagram) = sealed.ok().and_then(|len| self.buf.get(..len)) else {
            count_dropped();
            return Forked::Dropped;
        };
        // Non-blocking: `WouldBlock` (full send buffer) or any other error
        // drops this copy. The primary relay has already sent its packet.
        if self.socket.send(datagram).is_ok() {
            FORK_PACKETS.fetch_add(1, Ordering::Relaxed);
            Forked::Sent
        } else {
            count_dropped();
            Forked::Dropped
        }
    }
}

/// Control-path half of one fork direction. Shared between the pipeline and
/// the single relay task that holds the matching [`ForkTap`].
///
/// The epoch is bumped while the slot lock is held, so a tap that takes the
/// slot always sees the content that belongs to the epoch it observed.
pub struct ForkControl {
    /// Bumped on every activate / stop; the tap checks it with one atomic
    /// load per packet and waits on it while idle.
    epoch: watch::Sender<u64>,
    /// An activated stream waiting for the relay task, or `None`.
    slot: Mutex<Option<Box<ForkStream>>>,
}

impl std::fmt::Debug for ForkControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkControl").finish_non_exhaustive()
    }
}

impl ForkControl {
    /// Creates an idle control with nothing to fork.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch: watch::Sender::new(0),
            slot: Mutex::new(None),
        })
    }

    // A poisoned lock only means another thread panicked while swapping the
    // slot; the `Option` inside is still valid, so keep going.
    fn lock_slot(&self) -> MutexGuard<'_, Option<Box<ForkStream>>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Creates the relay-task half. There must be exactly one live tap per
    /// control: a second one would take the stream away from the first.
    #[must_use]
    pub fn tap(self: &Arc<Self>) -> ForkTap {
        self.tap_for_kind(None)
    }

    /// As [`Self::tap`], forking only while `media_kind` reads audio.
    pub(crate) fn tap_for_kind(self: &Arc<Self>, media_kind: Option<Arc<AtomicU8>>) -> ForkTap {
        let mut slot = self.lock_slot();
        let epoch = self.epoch.subscribe();
        let stream = slot.take();
        drop(slot);
        ForkTap {
            control: Arc::clone(self),
            epoch,
            media_kind,
            stream,
        }
    }

    /// Points `stream` at the recorder and hands it to the relay task.
    /// Replaces (and drops) a stream activated earlier.
    ///
    /// # Errors
    /// [`MediaPipelineError::RecordingFork`] if `remote` is not a usable
    /// unicast destination or the socket cannot be connected to it (for
    /// example an address family that differs from the bind address). The
    /// stream is dropped.
    pub fn activate(
        &self,
        stream: Box<ForkStream>,
        remote: SocketAddr,
    ) -> Result<(), MediaPipelineError> {
        if remote.port() == 0 || remote.ip().is_unspecified() || remote.ip().is_multicast() {
            return Err(MediaPipelineError::RecordingFork(
                "recorder media address is not a unicast address and port".into(),
            ));
        }
        // NIST 800-53 Rev5: SC-7 - connected, so the kernel only accepts
        // datagrams from the recorder; they are never read.
        stream.socket.connect(remote).map_err(|e| {
            MediaPipelineError::RecordingFork(format!("connect to recorder media address: {e}"))
        })?;
        let mut slot = self.lock_slot();
        *slot = Some(stream);
        self.epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        Ok(())
    }

    /// Stops forking. A parked stream is dropped here; a stream the relay
    /// task already took is dropped by that task when it sees the new epoch
    /// (it waits on the epoch, so this does not depend on media arriving).
    pub fn stop(&self) {
        let mut slot = self.lock_slot();
        *slot = None;
        self.epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }
}

/// Relay-task half of one fork direction. Owned by exactly one task.
pub struct ForkTap {
    control: Arc<ForkControl>,
    epoch: watch::Receiver<u64>,
    /// The session's [`MediaKind`] as `u8`; `None` forks unconditionally.
    media_kind: Option<Arc<AtomicU8>>,
    /// The active stream, or `None` while the call is not being recorded.
    stream: Option<Box<ForkStream>>,
}

impl std::fmt::Debug for ForkTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkTap")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl ForkTap {
    /// Off the steady state: runs once per activate / stop.
    fn sync(&mut self) {
        let mut slot = self.control.lock_slot();
        self.epoch.mark_unchanged();
        // Taking `None` is how a stop reaches the task: the old stream (keys,
        // socket) is dropped right here.
        self.stream = slot.take();
    }

    /// Resolves when the control path has activated or stopped the fork, and
    /// applies the change. Cancel safe. Lets an idle relay task release a
    /// stopped stream without waiting for the next packet.
    pub async fn changed(&mut self) {
        if self.epoch.changed().await.is_err() {
            // Unreachable while `self.control` keeps the sender alive.
            std::future::pending::<()>().await;
        }
        self.sync();
    }

    /// Whether a stream is active on this tap.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.stream.is_some()
    }

    /// One atomic load per packet; the lock only on an epoch change.
    fn active_stream(&mut self) -> Option<&mut ForkStream> {
        if self.epoch.has_changed().unwrap_or(false) {
            self.sync();
        }
        // RFC 3362: a call switched to T.38 carries UDPTL, not RTP.
        if let Some(kind) = &self.media_kind
            && kind.load(Ordering::Relaxed) != MediaKind::Audio.as_u8()
        {
            return None;
        }
        self.stream.as_deref_mut()
    }

    fn finish(&mut self, outcome: &Forked) {
        if matches!(outcome, Forked::Exhausted) {
            // Once per stream, not per packet.
            warn!("recording fork packet index exhausted; stream stopped");
            self.stream = None;
        }
    }

    /// Offers one datagram the relay has just forwarded. Call only after the
    /// primary send. Forks it when it is a cleartext RTP packet; RTCP
    /// (RFC 5761 payload-type range), STUN and DTLS (RFC 7983 first-octet
    /// ranges) are not media and are skipped. A packet that claims RTP
    /// version 2 but has a truncated header is dropped and counted.
    ///
    /// No allocation, no lock, no await on this path.
    // NIST 800-53 Rev5: SC-5, SI-10
    pub fn on_rtp(&mut self, pkt: &[u8]) {
        let Some(stream) = self.active_stream() else {
            return;
        };
        let Some(&[first, second]) = pkt.get(..2) else {
            return;
        };
        if first >> 6 != 2 || (64..=95).contains(&(second & 0x7F)) {
            return;
        }
        let Some((header, payload)) = rtp_header_len(pkt).and_then(|len| pkt.split_at_checked(len))
        else {
            count_dropped();
            return;
        };
        let outcome = stream.send_copy(header, payload);
        self.finish(&outcome);
    }

    /// Offers one packet the DTLS-terminated relay has just decrypted and
    /// forwarded: `srtp_packet` is the datagram as received (its RTP header
    /// is cleartext and already authenticated), `payload` the decrypted RTP
    /// payload. The caller has already excluded RTCP and DTLS.
    pub fn on_decrypted_rtp(&mut self, srtp_packet: &[u8], payload: &[u8]) {
        let Some(stream) = self.active_stream() else {
            return;
        };
        let Some(header) = rtp_header_len(srtp_packet).and_then(|len| srtp_packet.get(..len))
        else {
            count_dropped();
            return;
        };
        let outcome = stream.send_copy(header, payload);
        self.finish(&outcome);
    }
}

/// Waits for a fork epoch change on `tap`; never resolves without a tap.
/// For use as a `select!` branch in the relay loops.
pub(crate) async fn fork_changed(tap: &mut Option<ForkTap>) {
    match tap {
        Some(tap) => tap.changed().await,
        None => std::future::pending().await,
    }
}

/// Per-session fork state held by the pipeline (control path only).
///
/// Index 0 is the A-leg stream (the caller's sent media, relay direction
/// A→B); index 1 the B-leg stream.
pub(crate) struct SessionFork {
    controls: [Arc<ForkControl>; 2],
    /// Streams bound by `prepare`, waiting for the recorder's answer.
    prepared: Option<[Box<ForkStream>; 2]>,
    /// Port pairs held in the pipeline's allocator while the fork exists.
    ports: Option<[u16; 2]>,
}

impl std::fmt::Debug for SessionFork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFork")
            .field("prepared", &self.prepared.is_some())
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl SessionFork {
    pub(crate) fn new() -> Self {
        Self {
            controls: [ForkControl::new(), ForkControl::new()],
            prepared: None,
            ports: None,
        }
    }

    /// The tap for one relay direction (`a_leg` = media received from the
    /// A-leg). Called once per direction when the relay starts.
    pub(crate) fn tap(&self, a_leg: bool, media_kind: &Arc<AtomicU8>) -> ForkTap {
        let [a, b] = &self.controls;
        let control = if a_leg { a } else { b };
        control.tap_for_kind(Some(Arc::clone(media_kind)))
    }

    /// Whether `prepare` has run and the fork has not been stopped since.
    pub(crate) fn exists(&self) -> bool {
        self.ports.is_some()
    }

    /// Records the bound streams and the allocator ports they hold.
    pub(crate) fn set_prepared(&mut self, streams: [Box<ForkStream>; 2], ports: [u16; 2]) {
        self.prepared = Some(streams);
        self.ports = Some(ports);
    }

    /// Hands both prepared streams to the relay tasks.
    ///
    /// On error nothing is left running: both streams are dropped, and the
    /// caller must release the ports ([`Self::stop`]).
    // NIST 800-53 Rev5: SC-24 - never a half-recorded call.
    pub(crate) fn activate(&mut self, remotes: [SocketAddr; 2]) -> Result<(), MediaPipelineError> {
        let [a_stream, b_stream] = self.prepared.take().ok_or_else(|| {
            MediaPipelineError::RecordingFork("recording fork is not prepared".into())
        })?;
        let [a_remote, b_remote] = remotes;
        let [a_control, b_control] = &self.controls;
        a_control.activate(a_stream, a_remote)?;
        b_control.activate(b_stream, b_remote)
    }

    /// Stops both directions and drops any prepared streams. Returns the
    /// allocator ports to release, once. Idempotent.
    pub(crate) fn stop(&mut self) -> Option<[u16; 2]> {
        self.prepared = None;
        for control in &self.controls {
            control.stop();
        }
        self.ports.take()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proto_srtp::{SrtpProfile, SrtpUnprotect};
    use std::time::Duration;

    fn material() -> (Vec<u8>, Vec<u8>) {
        // Generated per test, never hard-coded.
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let salt: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        (key, salt)
    }

    fn keys(key: &[u8], salt: &[u8]) -> SrtpKeyMaterial {
        SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.to_vec(), salt.to_vec()).unwrap()
    }

    // PERF-004 / SC-5: a fork socket is never read, so its receive queue is
    // shrunk at bind (the kernel may round the request up).
    #[test]
    fn fork_socket_receive_buffer_is_shrunk() {
        let (key, salt) = material();
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 1).unwrap();
        let size = socket2::SockRef::from(&stream.socket)
            .recv_buffer_size()
            .unwrap();
        assert!(size <= 16 * FORK_RCVBUF_BYTES, "SO_RCVBUF is {size}");
    }

    struct Rig {
        control: Arc<ForkControl>,
        tap: ForkTap,
        srs: std::net::UdpSocket,
        srs_ctx: SrtpContext,
        ssrc: u32,
        kind: Arc<AtomicU8>,
        fork_port: u16,
    }

    fn rig() -> Rig {
        let (key, salt) = material();
        let ssrc = 0x5BC0_0001;
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), ssrc).unwrap();
        let fork_port = stream.local_port().unwrap();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        srs.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let control = ForkControl::new();
        let kind = Arc::new(AtomicU8::new(MediaKind::Audio.as_u8()));
        let tap = control.tap_for_kind(Some(Arc::clone(&kind)));
        control.activate(stream, srs.local_addr().unwrap()).unwrap();
        Rig {
            control,
            tap,
            srs,
            srs_ctx: SrtpContext::new(&keys(&key, &salt), SrtpDirection::Inbound, ssrc).unwrap(),
            ssrc,
            kind,
            fork_port,
        }
    }

    fn rtp(pt: u8, marker: bool, seq: u16, ts: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x80, pt | if marker { 0x80 } else { 0 }];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&ts.to_be_bytes());
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    fn recv(srs: &std::net::UdpSocket) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2100];
        srs.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    }

    #[test]
    fn rewrites_ssrc_and_sequence_keeps_the_rest() {
        let mut r = rig();
        let payload = [0x11u8; 160];
        r.tap
            .on_rtp(&rtp(8, true, 40_000, 0xDEAD_BEEF, 0x0102_0304, &payload));
        r.tap
            .on_rtp(&rtp(8, false, 7, 0xDEAD_BF8F, 0x0A0B_0C0D, &payload));

        let first = recv(&r.srs).expect("first fork packet");
        let second = recv(&r.srs).expect("second fork packet");
        let un = SrtpUnprotect::new(&r.srs_ctx);
        let p1 = un.unprotect_rtp(&first).unwrap();
        let p2 = un.unprotect_rtp(&second).unwrap();

        assert_eq!(p1.header.ssrc, r.ssrc);
        assert_eq!(p2.header.ssrc, r.ssrc, "endpoint SSRC change is not copied");
        assert_eq!(
            p2.header.sequence_number,
            p1.header.sequence_number.wrapping_add(1),
            "sequence is the SBC's counter, not the endpoint's"
        );
        assert!(p1.header.sequence_number < 0x8000);
        assert_eq!(p1.header.payload_type, 8);
        assert!(p1.header.marker);
        assert!(!p2.header.marker);
        assert_eq!(p1.header.timestamp, 0xDEAD_BEEF);
        assert_eq!(p2.header.timestamp, 0xDEAD_BF8F);
        assert_eq!(p1.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn csrc_and_extension_are_copied() {
        let mut r = rig();
        // V=2, X=1, CC=1; one CSRC; extension profile 0xBEDE, one word.
        let mut pkt = vec![0x91, 0x00, 0x00, 0x01, 0, 0, 0, 1, 9, 9, 9, 9];
        pkt.extend_from_slice(&[0xC0, 0xC1, 0xC2, 0xC3]);
        pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x42; 20]);
        r.tap.on_rtp(&pkt);

        let got = recv(&r.srs).expect("fork packet");
        // Header octets other than seq / SSRC are byte-identical.
        assert_eq!(got[..2], pkt[..2]);
        assert_eq!(got[4..8], pkt[4..8]);
        assert_eq!(got[12..24], pkt[12..24]);
        let p = SrtpUnprotect::new(&r.srs_ctx).unprotect_rtp(&got).unwrap();
        assert_eq!(p.header.csrc, vec![0xC0C1_C2C3]);
        assert_eq!(p.payload.as_ref(), [0x42u8; 20].as_slice());
    }

    #[test]
    fn skips_everything_that_is_not_rtp_audio() {
        let mut r = rig();
        // RTCP SR (200) / RR (201): payload types 72 / 73 with the marker bit,
        // inside the RFC 5761 range.
        r.tap.on_rtp(&rtp(0x48, true, 1, 1, 1, &[0; 20]));
        r.tap.on_rtp(&rtp(0x49, true, 1, 1, 1, &[0; 20]));
        // STUN binding request (first octet 0) and a DTLS record (22).
        r.tap
            .on_rtp(&[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42]);
        r.tap
            .on_rtp(&[22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // RTP version 1 and 3.
        r.tap.on_rtp(&[0x40, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 5, 5]);
        r.tap.on_rtp(&[0xC0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 5, 5]);
        // Empty, one octet, shorter than the fixed header.
        r.tap.on_rtp(&[]);
        r.tap.on_rtp(&[0x80]);
        r.tap.on_rtp(&[0x80, 0, 0, 1, 0, 0, 0, 1]);
        // CC=15 with no CSRC octets present.
        r.tap.on_rtp(&[0x8F, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
        // X=1 with a truncated extension header, then an overlong extension.
        r.tap
            .on_rtp(&[0x90, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xBE, 0xDE]);
        r.tap.on_rtp(&[
            0x90, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xBE, 0xDE, 0xFF, 0xFF,
        ]);
        // Larger than the fork copies.
        let mut big = rtp(0, false, 1, 1, 1, &[]);
        big.resize(FORK_MAX_PACKET + 1, 0);
        r.tap.on_rtp(&big);
        // Non-audio kind (T.38 image): valid RTP-looking datagram is skipped.
        r.kind.store(MediaKind::Image.as_u8(), Ordering::Relaxed);
        r.tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));

        assert!(recv(&r.srs).is_none(), "nothing may reach the recorder");

        // Back to audio: forking resumes.
        r.kind.store(MediaKind::Audio.as_u8(), Ordering::Relaxed);
        r.tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));
        assert!(recv(&r.srs).is_some());
    }

    #[test]
    fn largest_packet_fits() {
        let mut r = rig();
        let mut pkt = rtp(0, false, 1, 1, 1, &[]);
        pkt.resize(FORK_MAX_PACKET, 0x33);
        r.tap.on_rtp(&pkt);
        let got = recv(&r.srs).expect("fork packet");
        assert_eq!(got.len(), FORK_MAX_PACKET + FORK_TAG_ROOM);
        assert!(SrtpUnprotect::new(&r.srs_ctx).unprotect_rtp(&got).is_ok());
    }

    #[test]
    fn idle_until_activated_and_silent_after_stop() {
        let (key, salt) = material();
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        srs.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let control = ForkControl::new();
        let mut tap = control.tap();
        let pkt = rtp(0, false, 1, 1, 1, &[0; 20]);

        tap.on_rtp(&pkt);
        assert!(!tap.is_active());
        assert!(recv(&srs).is_none(), "prepared but not activated");

        control.activate(stream, srs.local_addr().unwrap()).unwrap();
        tap.on_rtp(&pkt);
        assert!(tap.is_active());
        assert!(recv(&srs).is_some());

        control.stop();
        tap.on_rtp(&pkt);
        assert!(!tap.is_active(), "stream dropped on the first packet");
        assert!(recv(&srs).is_none(), "nothing after stop");
        // Idempotent.
        control.stop();
        tap.on_rtp(&pkt);
        assert!(recv(&srs).is_none());
    }

    #[test]
    fn stop_before_the_task_takes_the_stream_drops_it() {
        let (key, salt) = material();
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        let port = stream.local_port().unwrap();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let control = ForkControl::new();
        let mut tap = control.tap();
        control.activate(stream, srs.local_addr().unwrap()).unwrap();
        control.stop();
        // The socket is closed without the tap ever running.
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok());
        tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));
        assert!(!tap.is_active());
    }

    #[test]
    fn tap_created_after_activation_takes_the_stream() {
        let (key, salt) = material();
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        srs.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let control = ForkControl::new();
        control.activate(stream, srs.local_addr().unwrap()).unwrap();
        let mut tap = control.tap();
        tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));
        assert!(recv(&srs).is_some());
    }

    #[tokio::test]
    async fn idle_task_releases_a_stopped_stream_without_media() {
        let mut r = rig();
        r.tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));
        assert!(r.tap.is_active());
        let port = r.fork_port;
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_err());

        r.control.stop();
        tokio::time::timeout(Duration::from_secs(2), r.tap.changed())
            .await
            .expect("stop must wake an idle tap");
        assert!(!r.tap.is_active());
        assert!(
            std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok(),
            "fork socket closed"
        );
    }

    #[test]
    fn send_failure_is_counted_and_does_not_panic() {
        let (key, salt) = material();
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        // A recorder port with nothing listening: the connected socket
        // reports ICMP port-unreachable as a send error on a later packet.
        let dead = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let control = ForkControl::new();
        let mut tap = control.tap();
        control.activate(stream, dead).unwrap();
        let before = recording_fork_packets() + recording_fork_dropped();
        let pkt = rtp(0, false, 1, 1, 1, &[0; 20]);
        for _ in 0..50 {
            tap.on_rtp(&pkt);
        }
        // Every packet is accounted for as sent or dropped (other tests run
        // in parallel, so only a lower bound holds).
        assert!(recording_fork_packets() + recording_fork_dropped() - before >= 50);
        assert!(tap.is_active(), "send errors do not stop the stream");
    }

    #[test]
    fn index_exhaustion_stops_the_stream() {
        let mut r = rig();
        r.tap.on_rtp(&rtp(0, false, 1, 1, 1, &[0; 20]));
        assert!(recv(&r.srs).is_some());
        r.tap.stream.as_mut().unwrap().index = MAX_PACKET_INDEX;
        r.tap.on_rtp(&rtp(0, false, 2, 2, 1, &[0; 20]));
        assert!(recv(&r.srs).is_some(), "last index is still usable");
        r.tap.on_rtp(&rtp(0, false, 3, 3, 1, &[0; 20]));
        assert!(recv(&r.srs).is_none(), "no packet past 2^48 - 1");
        assert!(!r.tap.is_active());
    }

    #[test]
    fn activate_rejects_unusable_recorder_addresses() {
        let (key, salt) = material();
        let control = ForkControl::new();
        for bad in ["0.0.0.0:4000", "127.0.0.1:0", "224.0.0.1:4000"] {
            let stream =
                ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
            let err = control.activate(stream, bad.parse().unwrap()).unwrap_err();
            assert!(
                matches!(err, MediaPipelineError::RecordingFork(_)),
                "{bad}: {err:?}"
            );
        }
        // Address family mismatch (IPv4 socket, IPv6 recorder).
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        assert!(
            control
                .activate(stream, "[::1]:4000".parse().unwrap())
                .is_err()
        );
        assert!(!control.tap().is_active());
    }

    #[test]
    fn debug_output_has_no_key_material() {
        let key = vec![0xA7u8; 32];
        let salt = vec![0xB9u8; 12];
        let stream =
            ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 7).unwrap();
        let control = ForkControl::new();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        control.activate(stream, srs.local_addr().unwrap()).unwrap();
        let tap = control.tap();
        let mut session = SessionFork::new();
        let a = ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 8).unwrap();
        let b = ForkStream::bind(&keys(&key, &salt), "127.0.0.1:0".parse().unwrap(), 9).unwrap();
        let text_stream = format!("{a:?}");
        session.set_prepared([a, b], [0, 0]);
        let text = format!("{tap:?} {control:?} {session:?} {text_stream}").to_lowercase();
        for needle in ["a7a7", "b9b9", "167, 167", "185, 185"] {
            assert!(!text.contains(needle), "key bytes in Debug: {text}");
        }
        assert!(text.contains("ssrc"));
    }
}
