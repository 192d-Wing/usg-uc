//! Media pipeline for RTP/SRTP processing.
//!
//! This module integrates the media layer components:
//! - `proto-rtp` for RTP packet handling
//! - `proto-srtp` for SRTP encryption/decryption
//! - `proto-dtls` for DTLS-SRTP key exchange
//! - `sbc-media-engine` for media relay/pass-through
//! - `sbc-codecs` for codec negotiation
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality (SRTP encryption)
//! - **SC-12**: Cryptographic Key Establishment (DTLS-SRTP)
//! - **SC-13**: Cryptographic Protection (CNSA 2.0)

use proto_dtls::{DtlsConfig, DtlsConnection, DtlsRole, DtlsState, SrtpKeyingMaterial};
use proto_rtp::{RtpHeader, RtpPacket, SequenceTracker};

use crate::dtls_relay::{EstablishedLeg, HandshakePeers, HandshakeSourceStats, establish_srtp_leg};
use crate::dtls_sidecar::{Role, SidecarReader, SidecarWriter};
use crate::recording_fork::{ForkStream, ForkTap, SessionFork, fork_changed};
pub use crate::recording_fork::{
    RecordingForkPorts, recording_fork_dropped, recording_fork_packets,
};
use crate::srtp_relay::{
    AssociationLabel, HandshakeFanout, TerminateRelayLeg, forward_dtls_to_sidecar,
    pump_sidecar_dtls_to_peer,
};
use proto_srtp::{
    SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpProtect, SrtpUnprotect,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};
use uc_codecs::{CodecCapability, CodecRegistry};
use uc_media_engine::session::SessionState;
use uc_media_engine::{MediaMode, MediaSession, MediaSessionConfig};
use uc_types::address::SbcSocketAddr;

/// Media pipeline configuration.
#[derive(Debug, Clone)]
pub struct MediaPipelineConfig {
    /// Default media mode for new sessions.
    pub default_mode: MediaMode,
    /// `media.srtp.required`, copied onto each media session and reported
    /// in stats. The relay does not refuse packets on it: enforcement is in
    /// signalling (the SIP stack's SDP media security policy).
    // POAM: POA&M-352 - no media-plane backstop refuses cleartext RTP on a
    // session when SRTP is required; signalling is the only enforcement
    // point, and a remote media node only reports the flag.
    pub srtp_required: bool,
    /// Whether RTCP multiplexing is enabled.
    pub rtcp_mux: bool,
    /// Local codecs in preference order.
    pub local_codecs: Vec<CodecCapability>,
    /// Minimum RTP port for allocation.
    pub rtp_port_min: u16,
    /// Maximum RTP port for allocation.
    pub rtp_port_max: u16,
    /// Whether the SBC terminates DTLS-SRTP (vs. relaying it opaquely). When
    /// true, each terminated leg drives a DTLS handshake via the sidecar and
    /// the relay does SRTP protect/unprotect; the two `dtls_*` fields below
    /// must be set.
    pub terminate_dtls: bool,
    /// Path to the DTLS terminator sidecar's Unix socket (terminate mode).
    pub dtls_sidecar_socket: Option<std::path::PathBuf>,
    /// Source of the SBC's own SDP fingerprint (published by the sidecar), used
    /// to verify the sidecar's live identity on each per-leg connection
    /// (terminate mode). A file-backed source re-reads on demand so a sidecar
    /// restart is picked up rather than verified against a stale fingerprint.
    pub dtls_fingerprint: Option<Arc<crate::dtls_identity::DtlsFingerprintSource>>,
    /// Signalled with a call's session id when its DTLS-SRTP handshake fails at
    /// runtime — after the call was answered — so the SIP layer can tear the call
    /// down (BYE both legs) instead of leaving it up with black-holed media.
    /// Fail-closed for the async failure that startup validation can't catch.
    pub media_failure_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// This node's advertised media IP, returned per session so the signaling
    /// layer can steer SDP to it (Phase 3 media-node pool). `None` in the
    /// in-process / co-located deployments, where signaling uses its own zone
    /// media IP; a standalone `sbc-media` node sets it (e.g. from
    /// `SBC_MEDIA_ADVERTISED_IP`).
    pub advertised_media_ip: Option<std::net::IpAddr>,
    /// Whether calls on this pipeline may be forked to a SIPREC recorder
    /// (RFC 7866). [`RecordingMode::Disabled`] (the default): no fork tap is
    /// created for any relay, and the `*_recording_fork` calls return
    /// [`MediaPipelineError::RecordingUnsupported`].
    // NIST 800-53 Rev5: CM-7 (least functionality: off unless configured)
    pub recording: RecordingMode,
}

/// Whether a [`MediaPipeline`] can fork media to a SIPREC recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordingMode {
    /// No fork exists: relay tasks are started without a tap.
    #[default]
    Disabled,
    /// Relay tasks carry an idle tap that a recorded call can activate.
    Enabled,
}

impl RecordingMode {
    /// `Enabled` when `enabled` is true (for callers holding a config flag).
    #[must_use]
    pub const fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    /// Whether the fork is available.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl Default for MediaPipelineConfig {
    fn default() -> Self {
        Self {
            default_mode: MediaMode::Relay,
            srtp_required: true,
            rtcp_mux: true,
            local_codecs: vec![
                CodecCapability::opus(111),
                CodecCapability::g722(),
                CodecCapability::pcmu(),
                CodecCapability::pcma(),
            ],
            rtp_port_min: 16_384,
            rtp_port_max: 32_768,
            terminate_dtls: false,
            dtls_sidecar_socket: None,
            dtls_fingerprint: None,
            media_failure_tx: None,
            advertised_media_ip: None,
            recording: RecordingMode::Disabled,
        }
    }
}

/// Allocates RTP port pairs (even=RTP, odd=RTCP) from a configured range.
///
/// Pairs are handed out in random order: each allocation takes a free pair
/// chosen uniformly by the CSPRNG from a free list, so the ports of the next
/// call cannot be predicted from those of an earlier one (RFC 6056 port
/// randomisation, applied to media ports). Allocation and release are O(1)
/// under the lock; the random draw happens before the lock is taken.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection), SC-5 (fixed-size pool)
pub struct RtpPortAllocator {
    /// Minimum port in range.
    min_port: u16,
    /// Maximum port in range.
    max_port: u16,
    /// Free and in-use pair indices.
    pool: RwLock<PairPool>,
}

/// The pair indices of an [`RtpPortAllocator`] (pair `i` is
/// `min_port + 2i`, `min_port + 2i + 1`). Sized once from the range (at most
/// 32768 pairs).
struct PairPool {
    /// Indices of the free pairs, in no particular order.
    free: Vec<u16>,
    /// Whether each pair is allocated (so a stray or repeated release cannot
    /// put a pair on the free list twice).
    in_use: Vec<bool>,
}

impl RtpPortAllocator {
    /// Creates a new port allocator.
    ///
    /// A reversed range is swapped (with a warning) rather than panicking
    /// in the port arithmetic later.
    pub fn new(min_port: u16, max_port: u16) -> Self {
        let (min_port, max_port) = if min_port <= max_port {
            (min_port, max_port)
        } else {
            warn!(min_port, max_port, "RTP port range reversed, swapping");
            (max_port, min_port)
        };
        // Ensure min_port is even for RTP convention
        let min_port = if min_port.is_multiple_of(2) {
            min_port
        } else {
            min_port.saturating_add(1)
        };
        let pairs = Self::pairs_in(min_port, max_port);
        Self {
            min_port,
            max_port,
            pool: RwLock::new(PairPool {
                free: (0..pairs).collect(),
                in_use: vec![false; usize::from(pairs)],
            }),
        }
    }

    /// Number of usable pairs in `min_port..=max_port` (`min_port` even).
    /// At most 32768, so every pair index fits a `u16`.
    fn pairs_in(min_port: u16, max_port: u16) -> u16 {
        if max_port <= min_port {
            return 0;
        }
        // Each pair occupies (even, even+1); both ends inclusive.
        (max_port - min_port).div_ceil(2)
    }

    /// Number of usable (RTP, RTCP) port pairs in the range.
    fn pair_count(&self) -> u32 {
        u32::from(Self::pairs_in(self.min_port, self.max_port))
    }

    /// Allocates an even-numbered RTP port. Returns (rtp_port, rtcp_port).
    ///
    /// # Errors
    /// [`MediaPipelineError::PortExhausted`] when every pair is in use, and
    /// also when the CSPRNG fails (fail closed: no predictable fallback).
    // rtp/rtcp are the standard protocol names for the port pair.
    #[allow(clippy::similar_names)]
    pub async fn allocate_pair(&self) -> Result<(u16, u16), MediaPipelineError> {
        // NIST 800-53 Rev5: SC-7 -- the choice comes from the aws-lc DRBG
        // (uc-crypto), drawn before the lock. The modulo bias is below 2^-48
        // for any free-list length.
        let draw = match uc_crypto::random::generate_random::<8>() {
            Ok(bytes) => u64::from_le_bytes(bytes),
            Err(e) => {
                warn!(error = %e, "CSPRNG failure; not allocating an RTP port pair");
                return Err(MediaPipelineError::PortExhausted);
            }
        };

        let mut pool = self.pool.write().await;
        let len = u64::try_from(pool.free.len()).unwrap_or(u64::MAX);
        if len == 0 {
            return Err(MediaPipelineError::PortExhausted);
        }
        let pick = usize::try_from(draw % len).unwrap_or(0);
        let Some(&index) = pool.free.get(pick) else {
            return Err(MediaPipelineError::PortExhausted);
        };
        // index < pairs guarantees rtp <= max_port - 1, so rtcp fits; checked
        // all the same, before the pair leaves the free list.
        let pair = index
            .checked_mul(2)
            .and_then(|offset| self.min_port.checked_add(offset))
            .and_then(|rtp| Some((rtp, rtp.checked_add(1)?)))
            .ok_or(MediaPipelineError::PortExhausted)?;
        pool.free.swap_remove(pick);
        if let Some(used) = pool.in_use.get_mut(usize::from(index)) {
            *used = true;
        }
        Ok(pair)
    }

    /// Releases a port pair back to the pool. A port that is not the RTP
    /// port of an allocated pair is ignored.
    pub async fn release_pair(&self, rtp_port: u16) {
        let Some(offset) = rtp_port.checked_sub(self.min_port) else {
            return;
        };
        if offset % 2 != 0 {
            return;
        }
        let index = offset / 2;
        let mut pool = self.pool.write().await;
        if let Some(used) = pool.in_use.get_mut(usize::from(index))
            && *used
        {
            *used = false;
            pool.free.push(index);
        }
    }

    /// Number of ports (two per pair) currently allocated.
    #[cfg(test)]
    async fn allocated_port_count(&self) -> usize {
        let pool = self.pool.read().await;
        2 * pool.in_use.iter().filter(|used| **used).count()
    }
}

/// Media pipeline manages RTP/SRTP processing for all calls.
pub struct MediaPipeline {
    /// Configuration.
    config: MediaPipelineConfig,
    /// Codec registry for negotiation.
    codec_registry: CodecRegistry,
    /// Active media sessions by call ID.
    sessions: RwLock<HashMap<String, MediaSessionContext>>,
    /// DTLS connections by local address.
    dtls_connections: RwLock<HashMap<String, DtlsConnectionContext>>,
    /// RTP sequence trackers by SSRC.
    sequence_trackers: RwLock<HashMap<u32, TrackedSequence>>,
    /// Port allocator for RTP/RTCP ports.
    port_allocator: RtpPortAllocator,
}

/// Context for an active media session.
struct MediaSessionContext {
    /// The media session.
    session: MediaSession,
    /// SRTP context for outbound packets (A-leg).
    srtp_outbound_a: Option<SrtpContext>,
    /// SRTP context for inbound packets (A-leg).
    srtp_inbound_a: Option<SrtpContext>,
    /// SRTP context for outbound packets (B-leg).
    srtp_outbound_b: Option<SrtpContext>,
    /// SRTP context for inbound packets (B-leg).
    srtp_inbound_b: Option<SrtpContext>,
    /// A-leg remote address.
    a_leg_remote: Option<SbcSocketAddr>,
    /// B-leg remote address.
    b_leg_remote: Option<SbcSocketAddr>,
    /// A-leg SSRC.
    a_leg_ssrc: u32,
    /// B-leg SSRC.
    b_leg_ssrc: u32,
    /// A-leg local RTP port.
    a_leg_local_port: u16,
    /// B-leg local RTP port.
    b_leg_local_port: u16,
    /// A-leg local RTCP port (RTP port + 1; serviced for non-muxed endpoints).
    a_leg_rtcp_port: u16,
    /// B-leg local RTCP port (RTP port + 1; serviced for non-muxed endpoints).
    b_leg_rtcp_port: u16,
    /// A-leg bind IP (from zone, or 0.0.0.0).
    a_leg_bind_ip: std::net::IpAddr,
    /// B-leg bind IP (from zone, or 0.0.0.0).
    b_leg_bind_ip: std::net::IpAddr,
    /// Relay task handles (aborted on stop).
    relay_handles: Vec<JoinHandle<()>>,
    /// Shutdown sender for relay tasks.
    relay_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Shared A-leg target address (read by relay tasks, updated by `set_remote_address`).
    a_leg_target: Option<Arc<std::sync::RwLock<std::net::SocketAddr>>>,
    /// Shared B-leg target address (read by relay tasks, updated by `set_remote_address`).
    b_leg_target: Option<Arc<std::sync::RwLock<std::net::SocketAddr>>>,
    /// Transcoder for codec conversion (if A-leg and B-leg use different codecs).
    transcoder: Option<Transcoder>,
    /// A-leg negotiated codec.
    a_leg_codec: Option<NegotiatedCodec>,
    /// B-leg negotiated codec.
    b_leg_codec: Option<NegotiatedCodec>,
    /// Live A-leg sidecar DTLS session halves (terminate mode). Held for the
    /// whole call so the DTLS association is not torn down at key export
    /// (deferred finding #2); dropped with the session at teardown.
    dtls_sidecar_a: Option<(SidecarReader, SidecarWriter)>,
    /// Live B-leg sidecar DTLS session halves (terminate mode).
    dtls_sidecar_b: Option<(SidecarReader, SidecarWriter)>,
    /// A-leg re-latch control for the opaque relay (`None` until
    /// `start_relay`, and for terminate-mode relays).
    a_leg_remote_ctl: Option<Arc<LegRemote>>,
    /// B-leg re-latch control for the opaque relay.
    b_leg_remote_ctl: Option<Arc<LegRemote>>,
    /// What the anchored stream carries ([`MediaKind`] as `u8`), read by the
    /// relay legs for counter attribution only.
    media_kind: Arc<std::sync::atomic::AtomicU8>,
    /// `start_relay_terminate` ran for this session: media on both legs is
    /// DTLS-SRTP terminated and cannot carry UDPTL.
    terminated: bool,
    /// SIPREC fork control for this session. `None` unless the pipeline has
    /// recording enabled; then present from session creation so the relay
    /// tasks can be given their taps whenever they start.
    recording: Option<SessionFork>,
}

/// What a call's anchored stream carries. Used for metrics attribution; the
/// relay itself is payload-opaque either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// RTP audio (the default).
    Audio,
    /// T.38 fax over UDPTL (RFC 3362), relayed opaquely (POA&M-290).
    Image,
}

impl MediaKind {
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Audio => 0,
            Self::Image => 1,
        }
    }
}

/// Per-leg control the signalling plane uses to move an opaque relay leg to a
/// new SDP remote. `set_remote_address` stores the new address, then bumps
/// `epoch` with Release; the relay leg sees the change with one Acquire
/// atomic load per packet (pairing with that Release so the new `expected`
/// is visible), clears its symmetric latch and re-latches against the new
/// address (RFC 4961).
///
/// Re-latch is exact-first: only a packet from the signalled SDP `ip:port`
/// latches. A same-IP packet from another port (symmetric NAT, or a T.38
/// gateway that sends UDPTL from a port other than the one it signalled)
/// latches only after `grace` has passed with no exact match, so a late
/// datagram from the previous stream's port cannot capture the latch or the
/// reverse send target (RFC 3264 §8.3.1).
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
struct LegRemote {
    epoch: std::sync::atomic::AtomicU64,
    expected: std::sync::RwLock<std::net::SocketAddr>,
    /// How long a re-latch waits for an exact SDP `ip:port` match before a
    /// same-IP, different-port source may latch.
    grace: std::time::Duration,
}

/// Default re-latch grace window (see [`LegRemote`]).
const RELATCH_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Packets an exact SDP source must send after taking an opaque RTP leg's
/// latch before the latch is established: from then on silence from the
/// exact source no longer lets another port on its IP take the latch.
/// Eight packets is 160 ms of 20 ms audio; one spoofed datagram stays well
/// below it.
// NIST 800-53 Rev5: SC-7 (Boundary Protection)
const EXACT_ESTABLISHED_PACKETS: u32 = 8;

impl LegRemote {
    fn new(addr: std::net::SocketAddr) -> Self {
        Self::with_grace(addr, RELATCH_GRACE)
    }

    fn with_grace(addr: std::net::SocketAddr, grace: std::time::Duration) -> Self {
        Self {
            epoch: std::sync::atomic::AtomicU64::new(0),
            expected: std::sync::RwLock::new(addr),
            grace,
        }
    }

    /// Stores a new expected remote and bumps the epoch when it changed.
    fn update(&self, addr: std::net::SocketAddr) {
        let changed = match self.expected.write() {
            Ok(mut guard) if *guard != addr => {
                *guard = addr;
                true
            }
            _ => false,
        };
        if changed {
            self.epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Re-latch and attribution state shared with one opaque relay leg.
#[derive(Clone)]
struct LegRelayControl {
    /// Re-latch control (RTP legs; `None` for the RTCP port pair).
    remote: Option<Arc<LegRemote>>,
    /// The session's [`MediaKind`] as `u8`.
    media_kind: Arc<std::sync::atomic::AtomicU8>,
}

/// Allocated port info returned from `create_session`.
#[derive(Debug, Clone)]
pub struct AllocatedPorts {
    /// A-leg RTP port.
    pub a_leg_rtp_port: u16,
    /// B-leg RTP port.
    pub b_leg_rtp_port: u16,
    /// The media node's advertised IP for SDP media-address steering (Phase 3):
    /// where the relay actually lives, so callers send RTP to THIS node. `None`
    /// means the signaling layer falls back to its own zone/local media IP
    /// (the monolith and co-located-split behaviour) — a standalone media node
    /// reports its advertised IP here so signaling advertises it per call.
    pub media_ip: Option<std::net::IpAddr>,
    /// The media node's DTLS-SRTP fingerprint to advertise in SDP `a=fingerprint`
    /// (terminate mode). Per-session because each node has its own identity;
    /// `None` = not terminating, or use the signaling-side source.
    pub dtls_fingerprint: Option<String>,
}

/// The control-plane boundary the SIP signaling layer uses to drive media.
///
/// This is the seam for splitting the media plane out of the daemon: the SIP
/// stack depends on `dyn MediaController`, not on the concrete [`MediaPipeline`],
/// so an out-of-process (e.g. gRPC) implementation can drop in later. Every
/// method is `call_id`-addressed and takes/returns serializable data — no live
/// sockets or in-process handles cross this boundary.
#[async_trait::async_trait]
pub trait MediaController: Send + Sync {
    /// Allocates a media session's RTP/RTCP port pairs (per-zone bind IPs) and
    /// returns the caller/callee RTP ports to advertise in SDP. Called at INVITE.
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<std::net::IpAddr>,
        b_leg_media_ip: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError>;

    /// Sets a leg's remote RTP address (caller at INVITE, callee at 200 OK).
    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError>;

    /// Starts the opaque forwarding relay (plain RTP or SRTP pass-through).
    async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError>;

    /// Starts the DTLS-SRTP terminating relay for both legs.
    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError>;

    /// Stops a call's relay tasks and releases its media resources.
    async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError>;

    /// Removes all state for a call's media session.
    async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError>;

    /// Allocates a standalone RTP/RTCP port pair (for announcement playback),
    /// returning `(rtp, rtcp)`. Replaces reaching into the internal allocator.
    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError>;

    /// Records what the anchored stream carries (audio or T.38 image), for
    /// metrics attribution and latching grace. Default: no-op; the in-process
    /// pipeline and the gRPC controller (`SetMediaKind`) both implement it.
    async fn set_media_kind(
        &self,
        _call_id: &str,
        _kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }

    /// Applies up to two leg remotes (`(is_a_leg, address)`) and an optional
    /// media kind as one relay update. Default: the individual calls in
    /// order; [`MediaPipeline`] applies them under one session lock.
    async fn update_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        let mut result = Ok(());
        for (is_a_leg, address) in remotes.into_iter().flatten() {
            if let Err(e) = self.set_remote_address(call_id, is_a_leg, address).await {
                result = Err(e);
            }
        }
        if let Some(kind) = kind
            && let Err(e) = self.set_media_kind(call_id, kind).await
        {
            result = Err(e);
        }
        result
    }

    /// Applies a relay update (as [`MediaController::update_relay`]) and then
    /// starts the plain relay, as one operation. Any failure (kind, address
    /// or start) is an error, so a caller can fail closed. Default: the two
    /// calls in order; the gRPC controller sends one `UpdateRelay` RPC so a
    /// remote node never relays against a half-applied update.
    // NIST 800-53 Rev5: SC-24 (fail closed on partial update)
    async fn update_and_start_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        self.update_relay(call_id, remotes, kind).await?;
        self.start_relay(call_id).await
    }

    /// Binds the two send-only fork sockets for a recorded call and installs
    /// one SRTP master key per stream (`keys[0]`: the caller's sent media,
    /// `keys[1]`: the callee's). Nothing is sent until
    /// [`MediaController::activate_recording_fork`]. Returns the local ports
    /// for the recording session SDP (RFC 7866 §7.1.1).
    ///
    /// Default: [`MediaPipelineError::RecordingUnsupported`]. Only the
    /// in-process [`MediaPipeline`] implements the fork; a controller that
    /// cannot record must say so, so the caller's failure policy runs.
    // NIST 800-53 Rev5: SC-24 (fail to a known state), AU-14
    // POAM: POA&M-301 - no fork on remote gRPC media nodes: the media control
    // channel is not authenticated or encrypted, and this call carries keys.
    async fn prepare_recording_fork(
        &self,
        _call_id: &str,
        _keys: [SrtpKeyMaterial; 2],
        _bind_ip: Option<std::net::IpAddr>,
    ) -> Result<RecordingForkPorts, MediaPipelineError> {
        Err(MediaPipelineError::RecordingUnsupported)
    }

    /// Starts forking a prepared call to the recorder's media addresses
    /// (`remotes[0]` receives the caller's stream, `remotes[1]` the
    /// callee's). On error the fork is torn down completely.
    ///
    /// Default: [`MediaPipelineError::RecordingUnsupported`].
    async fn activate_recording_fork(
        &self,
        _call_id: &str,
        _remotes: [std::net::SocketAddr; 2],
    ) -> Result<(), MediaPipelineError> {
        Err(MediaPipelineError::RecordingUnsupported)
    }

    /// Stops a call's fork, drops its keys and releases its ports.
    /// Idempotent; also implied by `stop_relay` and `remove_session`.
    ///
    /// Default: [`MediaPipelineError::RecordingUnsupported`].
    async fn stop_recording_fork(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        Err(MediaPipelineError::RecordingUnsupported)
    }
}

#[async_trait::async_trait]
impl MediaController for MediaPipeline {
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<std::net::IpAddr>,
        b_leg_media_ip: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        // Inherent method (method resolution prefers it over this trait method).
        Self::create_session_with_zones(self, call_id, mode, a_leg_media_ip, b_leg_media_ip).await
    }

    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        Self::set_remote_address(self, call_id, is_a_leg, address).await
    }

    async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        Self::start_relay(self, call_id).await
    }

    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        Self::start_relay_terminate(self, call_id, a_leg, b_leg).await
    }

    async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        Self::stop_relay(self, call_id).await
    }

    async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        Self::remove_session(self, call_id).await
    }

    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        self.port_allocator().allocate_pair().await
    }

    async fn set_media_kind(
        &self,
        call_id: &str,
        kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        Self::set_media_kind(self, call_id, kind).await
    }

    async fn update_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        Self::update_relay(self, call_id, remotes, kind).await
    }

    async fn update_and_start_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        Self::update_and_start_relay(self, call_id, remotes, kind).await
    }

    async fn prepare_recording_fork(
        &self,
        call_id: &str,
        keys: [SrtpKeyMaterial; 2],
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<RecordingForkPorts, MediaPipelineError> {
        Self::prepare_recording_fork(self, call_id, keys, bind_ip).await
    }

    async fn activate_recording_fork(
        &self,
        call_id: &str,
        remotes: [std::net::SocketAddr; 2],
    ) -> Result<(), MediaPipelineError> {
        Self::activate_recording_fork(self, call_id, remotes).await
    }

    async fn stop_recording_fork(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        Self::stop_recording_fork(self, call_id).await
    }
}

/// Negotiated codec info for one leg.
#[derive(Debug, Clone)]
pub struct NegotiatedCodec {
    /// Codec name (PCMU, PCMA, G722, opus).
    pub name: String,
    /// RTP payload type.
    pub payload_type: u8,
    /// Clock rate in Hz.
    pub clock_rate: u32,
}

/// Returns false for payload formats that carry no audio samples.
fn is_audio_codec_name(name: &str) -> bool {
    !(name.eq_ignore_ascii_case("telephone-event") || name.eq_ignore_ascii_case("CN"))
}

/// Transcoder for converting between different codecs in the relay path.
///
/// When A-leg and B-leg negotiate different codecs, the transcoder
/// decodes incoming RTP payload to PCM and re-encodes for the outgoing leg.
struct Transcoder {
    /// A-leg codec info.
    a_codec: NegotiatedCodec,
    /// B-leg codec info.
    b_codec: NegotiatedCodec,
    /// G.722 encoder for A-leg direction (if needed).
    g722_enc_a: Option<uc_codecs::g722_adpcm::G722Encoder>,
    /// G.722 decoder for A-leg direction (if needed).
    g722_dec_a: Option<uc_codecs::g722_adpcm::G722Decoder>,
    /// G.722 encoder for B-leg direction (if needed).
    g722_enc_b: Option<uc_codecs::g722_adpcm::G722Encoder>,
    /// G.722 decoder for B-leg direction (if needed).
    g722_dec_b: Option<uc_codecs::g722_adpcm::G722Decoder>,
}

impl Transcoder {
    /// Creates a transcoder for the given codec pair.
    fn new(a_codec: NegotiatedCodec, b_codec: NegotiatedCodec) -> Self {
        let g722_enc_a = if b_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Encoder::new())
        } else {
            None
        };
        let g722_dec_a = if a_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Decoder::new())
        } else {
            None
        };
        let g722_enc_b = if a_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Encoder::new())
        } else {
            None
        };
        let g722_dec_b = if b_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Decoder::new())
        } else {
            None
        };

        Self {
            a_codec,
            b_codec,
            g722_enc_a,
            g722_dec_a,
            g722_enc_b,
            g722_dec_b,
        }
    }

    /// Transcodes RTP payload from one codec to another.
    ///
    /// `is_a_leg`: true = packet from A-leg (decode with a_codec, encode with b_codec)
    ///             false = packet from B-leg (decode with b_codec, encode with a_codec)
    ///
    /// Returns (transcoded_payload, outbound_payload_type).
    #[allow(clippy::cast_possible_truncation)]
    fn transcode(
        &mut self,
        payload: &[u8],
        is_a_leg: bool,
    ) -> Result<(Vec<u8>, u8), MediaPipelineError> {
        // Clone codec info to avoid borrow conflicts with &mut self
        let (in_name, in_rate, out_name, out_rate, out_pt) = if is_a_leg {
            (
                self.a_codec.name.clone(),
                self.a_codec.clock_rate,
                self.b_codec.name.clone(),
                self.b_codec.clock_rate,
                self.b_codec.payload_type,
            )
        } else {
            (
                self.b_codec.name.clone(),
                self.b_codec.clock_rate,
                self.a_codec.name.clone(),
                self.a_codec.clock_rate,
                self.a_codec.payload_type,
            )
        };

        // Decode to PCM
        let mut pcm = vec![0i16; payload.len() * 6];
        let pcm_samples = self.decode_payload(payload, &mut pcm, &in_name, is_a_leg)?;

        // Resample if clock rates differ
        let resampled;
        let pcm_out = if in_rate == out_rate {
            &pcm[..pcm_samples]
        } else {
            resampled = resample_linear(&pcm[..pcm_samples], in_rate, out_rate);
            &resampled
        };

        // Encode to output codec
        let mut output = vec![0u8; pcm_out.len() * 2];
        let encoded_len = self.encode_payload(pcm_out, &mut output, &out_name, !is_a_leg)?;

        output.truncate(encoded_len);
        Ok((output, out_pt))
    }

    /// Decodes payload bytes to PCM samples.
    fn decode_payload(
        &mut self,
        payload: &[u8],
        output: &mut [i16],
        codec_name: &str,
        is_a_leg: bool,
    ) -> Result<usize, MediaPipelineError> {
        match codec_name {
            "PCMU" => {
                let n = payload.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Ulaw::decode_sample(payload[i]);
                }
                Ok(n)
            }
            "PCMA" => {
                let n = payload.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Alaw::decode_sample(payload[i]);
                }
                Ok(n)
            }
            "G722" => {
                let decoder = if is_a_leg {
                    self.g722_dec_a.as_mut()
                } else {
                    self.g722_dec_b.as_mut()
                };
                decoder.map_or_else(
                    || {
                        Err(MediaPipelineError::DecryptionFailed(
                            "G.722 decoder not initialized".into(),
                        ))
                    },
                    |dec| {
                        dec.decode(payload, output).map_err(|e| {
                            MediaPipelineError::DecryptionFailed(format!("G.722 decode: {e}"))
                        })
                    },
                )
            }
            _ => Err(MediaPipelineError::DecryptionFailed(format!(
                "Unsupported codec for transcoding: {codec_name}"
            ))),
        }
    }

    /// Encodes PCM samples to codec payload.
    fn encode_payload(
        &mut self,
        pcm: &[i16],
        output: &mut [u8],
        codec_name: &str,
        is_a_leg: bool,
    ) -> Result<usize, MediaPipelineError> {
        match codec_name {
            "PCMU" => {
                let n = pcm.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Ulaw::encode_sample(pcm[i]);
                }
                Ok(n)
            }
            "PCMA" => {
                let n = pcm.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Alaw::encode_sample(pcm[i]);
                }
                Ok(n)
            }
            "G722" => {
                let encoder = if is_a_leg {
                    self.g722_enc_a.as_mut()
                } else {
                    self.g722_enc_b.as_mut()
                };
                encoder.map_or_else(
                    || {
                        Err(MediaPipelineError::EncryptionFailed(
                            "G.722 encoder not initialized".into(),
                        ))
                    },
                    |enc| {
                        enc.encode(pcm, output).map_err(|e| {
                            MediaPipelineError::EncryptionFailed(format!("G.722 encode: {e}"))
                        })
                    },
                )
            }
            _ => Err(MediaPipelineError::EncryptionFailed(format!(
                "Unsupported codec for transcoding: {codec_name}"
            ))),
        }
    }
}

/// Linear interpolation resampler for integer sample rate ratios.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn resample_linear(input: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    if from_rate == to_rate || input.is_empty() {
        return input.to_vec();
    }

    let ratio = f64::from(to_rate) / f64::from(from_rate);
    let out_len = (input.len() as f64 * ratio) as usize;
    let mut output = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let src_pos = i as f64 / ratio;
        let idx = src_pos as usize;
        let frac = src_pos - idx as f64;

        let sample = if idx + 1 < input.len() {
            let s0 = f64::from(input[idx]);
            let s1 = f64::from(input[idx + 1]);
            frac.mul_add(s1 - s0, s0) as i16
        } else {
            input[input.len() - 1]
        };

        output.push(sample);
    }

    output
}

/// Context for a DTLS connection.
struct DtlsConnectionContext {
    /// The DTLS connection.
    connection: DtlsConnection,
    /// Associated call ID.
    call_id: String,
    /// Whether keying material has been exported.
    keys_exported: bool,
}

/// Result of processing an RTP packet.
#[derive(Debug)]
pub enum RtpProcessResult {
    /// Forward the packet to the destination.
    Forward {
        /// Processed packet data.
        data: Vec<u8>,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Packet was consumed (e.g., RTCP).
    Consumed,
    /// Error processing packet.
    Error {
        /// Error reason.
        reason: String,
    },
}

impl MediaPipeline {
    /// Creates a new media pipeline.
    pub fn new(config: MediaPipelineConfig) -> Self {
        let mut codec_registry = CodecRegistry::new();

        // Register local codecs
        for codec in &config.local_codecs {
            codec_registry.register(codec.clone());
        }

        info!(
            default_mode = ?config.default_mode,
            srtp_required = config.srtp_required,
            codec_count = config.local_codecs.len(),
            "Media pipeline created"
        );

        let port_allocator = RtpPortAllocator::new(config.rtp_port_min, config.rtp_port_max);

        Self {
            config,
            codec_registry,
            sessions: RwLock::new(HashMap::new()),
            dtls_connections: RwLock::new(HashMap::new()),
            sequence_trackers: RwLock::new(HashMap::new()),
            port_allocator,
        }
    }

    /// Creates a new media session for a call, allocating RTP port pairs.
    ///
    /// Returns the allocated ports so the SIP stack can use them in SDP.
    pub async fn create_session(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        self.create_session_with_zones(call_id, mode, None, None)
            .await
    }

    /// Creates a new media session with zone-specific bind IPs.
    pub async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<std::net::IpAddr>,
        b_leg_media_ip: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        let mode = mode.unwrap_or(self.config.default_mode);

        let mut config = MediaSessionConfig::new(call_id)
            .with_mode(mode)
            .with_srtp(self.config.srtp_required);

        for codec in &self.config.local_codecs {
            config = config.with_codec(codec.clone());
        }

        let session = MediaSession::new(config);

        // Allocate port pairs for A-leg and B-leg. The RTCP port (RTP + 1) is
        // serviced for non-muxed endpoints; muxed RTCP shares the RTP port and
        // rides the RTP relay opaquely.
        let (a_rtp, a_rtcp) = self.port_allocator.allocate_pair().await?;
        let (b_rtp, b_rtcp) = match self.port_allocator.allocate_pair().await {
            Ok(pair) => pair,
            Err(e) => {
                self.port_allocator.release_pair(a_rtp).await;
                return Err(e);
            }
        };

        let a_leg_ssrc = generate_ssrc();
        let b_leg_ssrc = generate_ssrc();

        let context = MediaSessionContext {
            session,
            srtp_outbound_a: None,
            srtp_inbound_a: None,
            srtp_outbound_b: None,
            srtp_inbound_b: None,
            a_leg_remote: None,
            b_leg_remote: None,
            a_leg_ssrc,
            b_leg_ssrc,
            a_leg_local_port: a_rtp,
            b_leg_local_port: b_rtp,
            a_leg_rtcp_port: a_rtcp,
            b_leg_rtcp_port: b_rtcp,
            a_leg_bind_ip: a_leg_media_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            b_leg_bind_ip: b_leg_media_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            relay_handles: Vec::new(),
            relay_shutdown: None,
            a_leg_target: None,
            b_leg_target: None,
            transcoder: None,
            a_leg_codec: None,
            b_leg_codec: None,
            dtls_sidecar_a: None,
            dtls_sidecar_b: None,
            a_leg_remote_ctl: None,
            b_leg_remote_ctl: None,
            media_kind: Arc::new(std::sync::atomic::AtomicU8::new(MediaKind::Audio.as_u8())),
            terminated: false,
            recording: self.config.recording.is_enabled().then(SessionFork::new),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(call_id.to_string(), context);

        info!(
            call_id = %call_id,
            mode = ?mode,
            a_leg_port = a_rtp,
            b_leg_port = b_rtp,
            "Media session created with ports"
        );

        Ok(AllocatedPorts {
            a_leg_rtp_port: a_rtp,
            b_leg_rtp_port: b_rtp,
            media_ip: self.config.advertised_media_ip,
            // The SBC's own fingerprint to advertise (terminate mode only). A
            // file-backed source re-reads here so a sidecar restart is picked up.
            dtls_fingerprint: self.config.dtls_fingerprint.as_ref().map(|s| s.current()),
        })
    }

    /// Negotiates codecs with remote offer.
    ///
    /// Delegates to `uc_codecs::CodecRegistry::negotiate` (PT adoption,
    /// channel match, fmtp intersection). Fails unless at least one audio
    /// codec matched: telephone-event/CN alone cannot carry a call.
    // POAM: POA&M-142 -- sbc-daemon does not call this yet; the live SDP
    // answer path does not run uc-codecs negotiation.
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "async signature kept for callers; body has no await yet"
    )]
    pub async fn negotiate_codecs(
        &self,
        call_id: &str,
        remote_codecs: &[CodecCapability],
    ) -> Result<Vec<CodecCapability>, MediaPipelineError> {
        let negotiated = self.codec_registry.negotiate(remote_codecs);

        if !negotiated.iter().any(CodecCapability::is_audio_payload) {
            warn!(call_id = %call_id, "Codec negotiation failed - no common codecs");
            return Err(MediaPipelineError::CodecNegotiationFailed);
        }

        debug!(
            call_id = %call_id,
            negotiated_count = negotiated.len(),
            first_codec = %negotiated[0].name,
            "Codecs negotiated"
        );

        Ok(negotiated)
    }

    /// Initiates DTLS handshake for a leg.
    pub async fn start_dtls_handshake(
        &self,
        call_id: &str,
        local_addr: SbcSocketAddr,
        remote_addr: SbcSocketAddr,
        role: DtlsRole,
    ) -> Result<(), MediaPipelineError> {
        let config = DtlsConfig::new(role).with_identity(vec![vec![0u8; 32]], vec![0u8; 32]); // Placeholder cert

        let connection = DtlsConnection::new(config, local_addr, remote_addr)
            .map_err(|e| MediaPipelineError::DtlsHandshakeFailed(e.to_string()))?;

        let context = DtlsConnectionContext {
            connection,
            call_id: call_id.to_string(),
            keys_exported: false,
        };

        let key = format!("{call_id}:{local_addr}");
        let mut connections = self.dtls_connections.write().await;
        connections.insert(key.clone(), context);

        info!(
            call_id = %call_id,
            local_addr = %local_addr,
            role = ?role,
            "DTLS handshake initiated"
        );

        Ok(())
    }

    /// Completes DTLS handshake and exports SRTP keys.
    pub async fn complete_dtls_handshake(
        &self,
        call_id: &str,
        local_addr: &SbcSocketAddr,
        is_a_leg: bool,
        role: DtlsRole,
    ) -> Result<(), MediaPipelineError> {
        let key = format!("{call_id}:{local_addr}");

        let mut connections = self.dtls_connections.write().await;
        let context = connections
            .get_mut(&key)
            .ok_or(MediaPipelineError::DtlsConnectionNotFound)?;

        // Check if already connected
        if context.connection.state() != DtlsState::Connected {
            return Err(MediaPipelineError::DtlsHandshakeFailed(
                "Not connected".to_string(),
            ));
        }

        // Export keying material
        let keying_material = context
            .connection
            .export_srtp_keying_material()
            .await
            .map_err(|e| MediaPipelineError::SrtpKeyExportFailed(e.to_string()))?;

        context.keys_exported = true;

        // Get SSRC from session
        let sessions = self.sessions.read().await;
        let ssrc = sessions.get(call_id).map_or(0x1234_5678, |s| {
            if is_a_leg { s.a_leg_ssrc } else { s.b_leg_ssrc }
        });
        drop(sessions);

        // Create SRTP contexts
        let (outbound_ctx, inbound_ctx) =
            self.create_srtp_contexts(&keying_material, role, ssrc)?;

        // Store in session
        let mut sessions = self.sessions.write().await;
        if let Some(session_ctx) = sessions.get_mut(call_id) {
            if is_a_leg {
                session_ctx.srtp_outbound_a = Some(outbound_ctx);
                session_ctx.srtp_inbound_a = Some(inbound_ctx);
            } else {
                session_ctx.srtp_outbound_b = Some(outbound_ctx);
                session_ctx.srtp_inbound_b = Some(inbound_ctx);
            }
        }

        info!(
            call_id = %call_id,
            is_a_leg = is_a_leg,
            "DTLS handshake complete, SRTP keys exported"
        );

        Ok(())
    }

    /// Terminates DTLS-SRTP for one leg via the Go terminator sidecar.
    ///
    /// Drives the DTLS handshake over `media_socket` (the caller owns the socket
    /// and hands it off for the handshake), derives the leg's SRTP contexts, and
    /// stores them plus the live sidecar session halves in the session. The
    /// halves are kept for the whole call so the DTLS association is not torn
    /// down at key export (deferred review finding #2); they drop at teardown.
    ///
    /// `signaling_peer` is the peer's SDP media address (the destination for the
    /// first outbound flight, before the peer's source is latched);
    /// `peer_fingerprint` is the peer's `a=fingerprint`; `role` is the SBC's
    /// DTLS role for this leg (derived from `a=setup`).
    ///
    /// # Errors
    /// Terminate mode not configured (`dtls_sidecar_socket` / `dtls_fingerprint`
    /// unset), the handshake fails, or SRTP context creation fails.
    pub async fn terminate_leg_dtls(
        &self,
        call_id: &str,
        is_a_leg: bool,
        media_socket: &UdpSocket,
        signaling_peer: std::net::SocketAddr,
        peer_fingerprint: &str,
        role: Role,
    ) -> Result<(), MediaPipelineError> {
        let sidecar_socket = self.config.dtls_sidecar_socket.as_ref().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed(
                "terminate mode: no DTLS sidecar socket configured".to_string(),
            )
        })?;
        let own_fingerprint = self
            .config
            .dtls_fingerprint
            .as_ref()
            .ok_or_else(|| {
                MediaPipelineError::DtlsHandshakeFailed(
                    "terminate mode: no DTLS fingerprint configured".to_string(),
                )
            })?
            .current();

        let mut stats = HandshakeSourceStats::default();
        let result = establish_srtp_leg(
            media_socket,
            signaling_peer,
            sidecar_socket,
            &own_fingerprint,
            peer_fingerprint,
            role,
            &mut stats,
        )
        .await;
        log_handshake_sources(
            call_id,
            if is_a_leg { "A" } else { "B" },
            &stats,
            result.as_ref().ok().map(|leg| leg.peer_addr),
        );
        let leg = result.map_err(|e| MediaPipelineError::DtlsHandshakeFailed(e.to_string()))?;

        // SSRC for this leg (falls back if the session vanished mid-handshake;
        // the store below then fails cleanly with DtlsConnectionNotFound).
        let ssrc = {
            let sessions = self.sessions.read().await;
            sessions.get(call_id).map_or(0x1234_5678, |s| {
                if is_a_leg { s.a_leg_ssrc } else { s.b_leg_ssrc }
            })
        };

        let outbound = SrtpContext::new(&leg.outbound, SrtpDirection::Outbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;
        let inbound = SrtpContext::new(&leg.inbound, SrtpDirection::Inbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let mut sessions = self.sessions.write().await;
        let session_ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::DtlsConnectionNotFound)?;
        if is_a_leg {
            session_ctx.srtp_outbound_a = Some(outbound);
            session_ctx.srtp_inbound_a = Some(inbound);
            session_ctx.dtls_sidecar_a = Some((leg.reader, leg.writer));
        } else {
            session_ctx.srtp_outbound_b = Some(outbound);
            session_ctx.srtp_inbound_b = Some(inbound);
            session_ctx.dtls_sidecar_b = Some((leg.reader, leg.writer));
        }

        info!(
            call_id = %call_id,
            is_a_leg,
            ssrc,
            "DTLS-SRTP leg terminated via sidecar"
        );
        Ok(())
    }

    /// Test-only: whether a leg has both SRTP contexts and the live sidecar
    /// halves stored (i.e. `terminate_leg_dtls` completed for it).
    #[cfg(test)]
    async fn test_leg_srtp_active(&self, call_id: &str, is_a_leg: bool) -> bool {
        let sessions = self.sessions.read().await;
        sessions.get(call_id).is_some_and(|s| {
            if is_a_leg {
                s.srtp_outbound_a.is_some()
                    && s.srtp_inbound_a.is_some()
                    && s.dtls_sidecar_a.is_some()
            } else {
                s.srtp_outbound_b.is_some()
                    && s.srtp_inbound_b.is_some()
                    && s.dtls_sidecar_b.is_some()
            }
        })
    }

    /// Creates SRTP contexts from DTLS keying material.
    fn create_srtp_contexts(
        &self,
        keying: &SrtpKeyingMaterial,
        role: DtlsRole,
        ssrc: u32,
    ) -> Result<(SrtpContext, SrtpContext), MediaPipelineError> {
        // Create key material for outbound (local -> remote)
        let outbound_key = keying.local_key(role).to_vec();
        let outbound_salt = keying.local_salt(role).to_vec();

        let outbound_material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, outbound_key, outbound_salt)
                .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let outbound = SrtpContext::new(&outbound_material, SrtpDirection::Outbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        // Create key material for inbound (remote -> local)
        let inbound_key = keying.remote_key(role).to_vec();
        let inbound_salt = keying.remote_salt(role).to_vec();

        let inbound_material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, inbound_key, inbound_salt)
                .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let inbound = SrtpContext::new(&inbound_material, SrtpDirection::Inbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        Ok((outbound, inbound))
    }

    /// Processes an incoming RTP packet.
    pub async fn process_rtp_packet(
        &self,
        call_id: &str,
        data: &[u8],
        _source: SbcSocketAddr,
        is_a_leg: bool,
    ) -> RtpProcessResult {
        let sessions = self.sessions.read().await;
        let Some(session_ctx) = sessions.get(call_id) else {
            return RtpProcessResult::Error {
                reason: "Session not found".to_string(),
            };
        };

        // Determine destination based on leg
        let destination = if is_a_leg {
            match &session_ctx.b_leg_remote {
                Some(addr) => *addr,
                None => {
                    return RtpProcessResult::Error {
                        reason: "B-leg not connected".to_string(),
                    };
                }
            }
        } else {
            match &session_ctx.a_leg_remote {
                Some(addr) => *addr,
                None => {
                    return RtpProcessResult::Error {
                        reason: "A-leg not connected".to_string(),
                    };
                }
            }
        };

        // Check media mode
        match session_ctx.session.mode() {
            MediaMode::PassThrough => {
                // Pass-through mode: forward without modification
                trace!(call_id = %call_id, "RTP pass-through");
                RtpProcessResult::Forward {
                    data: data.to_vec(),
                    destination,
                }
            }
            MediaMode::Relay | MediaMode::EarlyRelay => {
                // Relay mode: decrypt, process, encrypt
                let processed = self.relay_rtp_packet(session_ctx, data, is_a_leg).await;

                match processed {
                    Ok(packet_data) => RtpProcessResult::Forward {
                        data: packet_data,
                        destination,
                    },
                    Err(e) => RtpProcessResult::Error {
                        reason: e.to_string(),
                    },
                }
            }
        }
    }

    /// Relays an RTP packet (decrypt from one leg, encrypt for other).
    async fn relay_rtp_packet(
        &self,
        session_ctx: &MediaSessionContext,
        data: &[u8],
        is_a_leg: bool,
    ) -> Result<Vec<u8>, MediaPipelineError> {
        // Get appropriate SRTP contexts
        let (inbound_ctx, outbound_ctx) = if is_a_leg {
            (&session_ctx.srtp_inbound_a, &session_ctx.srtp_outbound_b)
        } else {
            (&session_ctx.srtp_inbound_b, &session_ctx.srtp_outbound_a)
        };

        // Decrypt incoming packet (if SRTP)
        let packet = if let Some(ctx) = inbound_ctx {
            let unprotect = SrtpUnprotect::new(ctx);
            unprotect
                .unprotect_rtp(data)
                .map_err(|e| MediaPipelineError::DecryptionFailed(e.to_string()))?
        } else {
            // Parse as unencrypted RTP. Guard the payload slice: never trust
            // the parser's header_size against attacker-controlled input.
            let (header, header_size) = RtpHeader::parse(data)
                .map_err(|e| MediaPipelineError::DecryptionFailed(e.to_string()))?;
            let payload = data.get(header_size..).ok_or_else(|| {
                MediaPipelineError::DecryptionFailed(format!(
                    "RTP header size {header_size} exceeds packet length {}",
                    data.len()
                ))
            })?;
            RtpPacket::new(header, payload.to_vec())
        };

        // Track sequence for the packet. The map is keyed by the
        // attacker-controlled SSRC, so it is bounded: idle entries are
        // evicted once the soft cap is reached, and brand-new SSRCs are
        // rejected at the hard cap (random-SSRC floods previously grew
        // this map without limit).
        let mut trackers = self.sequence_trackers.write().await;
        let now = std::time::Instant::now();
        if trackers.len() >= SSRC_TRACKER_SOFT_CAP && !trackers.contains_key(&packet.header.ssrc) {
            trackers.retain(|_, t| now.duration_since(t.last_seen) < SSRC_TRACKER_IDLE_TIMEOUT);
            if trackers.len() >= SSRC_TRACKER_HARD_CAP {
                return Err(MediaPipelineError::DecryptionFailed(
                    "SSRC tracker capacity exceeded".to_string(),
                ));
            }
        }
        let tracker = trackers
            .entry(packet.header.ssrc)
            .or_insert_with(TrackedSequence::new);
        tracker.last_seen = now;

        let is_valid = tracker.inner.update(packet.header.sequence_number);
        if !is_valid {
            warn!(
                ssrc = packet.header.ssrc,
                seq = packet.header.sequence_number,
                "Duplicate or old packet"
            );
        }
        drop(trackers);

        // Encrypt outgoing packet (if SRTP)
        let ciphertext = if let Some(ctx) = outbound_ctx {
            let protect = SrtpProtect::new(ctx);
            protect
                .protect_rtp(&packet)
                .map_err(|e| MediaPipelineError::EncryptionFailed(e.to_string()))?
                .to_vec()
        } else {
            // Return as unencrypted
            packet.to_bytes().to_vec()
        };

        trace!(
            is_a_leg = is_a_leg,
            size = ciphertext.len(),
            "RTP packet relayed"
        );

        Ok(ciphertext)
    }

    /// Sets the remote address for a leg.
    pub async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let session_ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;
        Self::apply_remote(session_ctx, is_a_leg, address);

        debug!(
            call_id = %call_id,
            is_a_leg = is_a_leg,
            address = %address,
            "Remote address set"
        );

        Ok(())
    }

    /// Applies both leg remotes and the media kind of a T.38 switchover
    /// under one session write lock, so the relay legs never observe a
    /// half-applied update.
    ///
    /// # Errors
    /// [`MediaPipelineError::SessionNotFound`] for an unknown call.
    pub async fn update_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let session_ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;
        for (is_a_leg, address) in remotes.into_iter().flatten() {
            Self::apply_remote(session_ctx, is_a_leg, address);
            debug!(call_id = %call_id, is_a_leg, address = %address, "Remote address set");
        }
        if let Some(kind) = kind {
            session_ctx
                .media_kind
                .store(kind.as_u8(), std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Applies a relay update (as [`Self::update_relay`]) and starts the
    /// plain relay. If the start fails, the prior remotes and media kind are
    /// restored before the error is returned, so a failed `UpdateRelay`
    /// leaves no half-applied state behind (the caller then tears the call
    /// down).
    ///
    /// # Errors
    /// [`MediaPipelineError::SessionNotFound`] for an unknown call, or the
    /// [`Self::start_relay`] error.
    // NIST 800-53 Rev5: SC-24 (fail closed; roll back on start failure)
    pub async fn update_and_start_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        let prior = {
            let sessions = self.sessions.read().await;
            let ctx = sessions
                .get(call_id)
                .ok_or(MediaPipelineError::SessionNotFound)?;
            (
                ctx.a_leg_remote,
                ctx.b_leg_remote,
                ctx.media_kind.load(std::sync::atomic::Ordering::Relaxed),
            )
        };
        self.update_relay(call_id, remotes, kind).await?;
        let Err(e) = self.start_relay(call_id).await else {
            return Ok(());
        };
        let mut sessions = self.sessions.write().await;
        if let Some(ctx) = sessions.get_mut(call_id) {
            for (is_a_leg, prev) in [(true, prior.0), (false, prior.1)] {
                match prev {
                    Some(address) => Self::apply_remote(ctx, is_a_leg, address),
                    None if is_a_leg => ctx.a_leg_remote = None,
                    None => ctx.b_leg_remote = None,
                }
            }
            ctx.media_kind
                .store(prior.2, std::sync::atomic::Ordering::Relaxed);
        }
        Err(e)
    }

    fn apply_remote(session_ctx: &mut MediaSessionContext, is_a_leg: bool, address: SbcSocketAddr) {
        let (remote, target, ctl) = if is_a_leg {
            (
                &mut session_ctx.a_leg_remote,
                &session_ctx.a_leg_target,
                &session_ctx.a_leg_remote_ctl,
            )
        } else {
            (
                &mut session_ctx.b_leg_remote,
                &session_ctx.b_leg_target,
                &session_ctx.b_leg_remote_ctl,
            )
        };
        *remote = Some(address);
        if let Some(target) = target
            && let Ok(mut guard) = target.write()
        {
            *guard = address.into();
        }
        // RFC 4961: a new SDP remote re-arms the symmetric latch so the relay
        // follows the far end to its new source (e.g. UDPTL after a T.38
        // re-INVITE); the source-IP check still applies to the new address.
        if let Some(ctl) = ctl {
            ctl.update(address.into());
        }
    }

    /// Records what the anchored stream carries; see [`MediaController::set_media_kind`].
    ///
    /// # Errors
    /// [`MediaPipelineError::SessionNotFound`] for an unknown call.
    pub async fn set_media_kind(
        &self,
        call_id: &str,
        kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        let sessions = self.sessions.read().await;
        let ctx = sessions
            .get(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;
        ctx.media_kind
            .store(kind.as_u8(), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// A leg's current SDP remote (test inspection of all-or-nothing updates).
    #[cfg(test)]
    pub(crate) async fn leg_remote(&self, call_id: &str, is_a_leg: bool) -> Option<SbcSocketAddr> {
        let sessions = self.sessions.read().await;
        let ctx = sessions.get(call_id)?;
        if is_a_leg {
            ctx.a_leg_remote
        } else {
            ctx.b_leg_remote
        }
    }

    /// The call's current media kind, or `None` for an unknown call.
    pub async fn media_kind(&self, call_id: &str) -> Option<MediaKind> {
        let sessions = self.sessions.read().await;
        let raw = sessions
            .get(call_id)?
            .media_kind
            .load(std::sync::atomic::Ordering::Relaxed);
        Some(if raw == MediaKind::Image.as_u8() {
            MediaKind::Image
        } else {
            MediaKind::Audio
        })
    }

    /// Returns true if the call's relay is DTLS-SRTP terminated
    /// (`start_relay_terminate`), so it cannot carry UDPTL (POA&M-291).
    pub async fn is_terminated(&self, call_id: &str) -> bool {
        self.sessions
            .read()
            .await
            .get(call_id)
            .is_some_and(|ctx| ctx.terminated)
    }

    /// Sets the negotiated codecs for a call. Creates a transcoder if they differ.
    pub async fn set_negotiated_codecs(
        &self,
        call_id: &str,
        a_codec: NegotiatedCodec,
        b_codec: NegotiatedCodec,
    ) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let needs_transcoding = a_codec.name != b_codec.name;

        // RFC 4733 events and comfort noise are not audio samples: they must
        // never reach the transcoder factory.
        // NIST 800-53 Rev5: SI-10
        if needs_transcoding
            && (!is_audio_codec_name(&a_codec.name) || !is_audio_codec_name(&b_codec.name))
        {
            warn!(
                call_id = %call_id,
                a_codec = %a_codec.name,
                b_codec = %b_codec.name,
                "Refusing to transcode a non-audio payload format"
            );
            return Err(MediaPipelineError::CodecNegotiationFailed);
        }

        if needs_transcoding {
            info!(
                call_id = %call_id,
                a_codec = %a_codec.name,
                b_codec = %b_codec.name,
                "Transcoding enabled"
            );
            ctx.transcoder = Some(Transcoder::new(a_codec.clone(), b_codec.clone()));
        } else {
            debug!(
                call_id = %call_id,
                codec = %a_codec.name,
                "Same codec on both legs, no transcoding needed"
            );
        }

        ctx.a_leg_codec = Some(a_codec);
        ctx.b_leg_codec = Some(b_codec);

        Ok(())
    }

    /// Starts RTP relay for a call. Binds UDP sockets and spawns relay tasks.
    ///
    /// Must be called after both `set_remote_address` calls (A-leg and B-leg).
    pub async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let a_remote = ctx
            .a_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("A-leg remote not set".into()))?;
        let b_remote = ctx
            .b_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("B-leg remote not set".into()))?;

        // Bind UDP sockets to zone-specific media IPs
        let a_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_local_port);
        let b_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_local_port);

        let a_socket = Arc::new(
            UdpSocket::bind(&a_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{a_bind}: {e}")))?,
        );
        let b_socket = Arc::new(
            UdpSocket::bind(&b_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{b_bind}: {e}")))?,
        );

        // Shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Per-leg send targets, shared between the two directions so that
        // symmetric-RTP latching on one leg redirects the opposite
        // direction's sends (RFC 4961: reply to where media actually
        // arrives from, not where SDP claimed it would).
        let a_addr: std::net::SocketAddr = a_remote.into();
        let b_addr: std::net::SocketAddr = b_remote.into();
        let a_target = Arc::new(std::sync::RwLock::new(a_addr));
        let b_target = Arc::new(std::sync::RwLock::new(b_addr));
        let a_ctl = Arc::new(LegRemote::new(a_addr));
        let b_ctl = Arc::new(LegRemote::new(b_addr));
        let no_relatch = LegRelayControl {
            remote: None,
            media_kind: Arc::clone(&ctx.media_kind),
        };

        // Spawn A→B RTP relay task
        let handle_ab = tokio::spawn(relay_leg(
            Arc::clone(&a_socket),
            Arc::clone(&b_socket),
            a_addr,
            Arc::clone(&a_target),
            Arc::clone(&b_target),
            call_id.to_string(),
            "A→B",
            RelayKind::Rtp,
            LegRelayControl {
                remote: Some(Arc::clone(&a_ctl)),
                media_kind: Arc::clone(&ctx.media_kind),
            },
            shutdown_rx.clone(),
            ctx.recording
                .as_ref()
                .map(|fork| fork.tap(true, &ctx.media_kind)),
        ));

        // Spawn B→A RTP relay task
        let handle_ba = tokio::spawn(relay_leg(
            Arc::clone(&b_socket),
            Arc::clone(&a_socket),
            b_addr,
            Arc::clone(&b_target),
            Arc::clone(&a_target),
            call_id.to_string(),
            "B→A",
            RelayKind::Rtp,
            LegRelayControl {
                remote: Some(Arc::clone(&b_ctl)),
                media_kind: Arc::clone(&ctx.media_kind),
            },
            shutdown_rx.clone(),
            ctx.recording
                .as_ref()
                .map(|fork| fork.tap(false, &ctx.media_kind)),
        ));

        let mut relay_handles = vec![handle_ab, handle_ba];

        // RTCP relay for non-muxed endpoints: forward the RTP-port+1 pair so
        // sender/receiver reports traverse the SBC. Muxed RTCP already rides the
        // RTP relay above. Best-effort — a port-overflow or bind failure disables
        // RTCP forwarding for this call but leaves audio untouched. RTCP remotes
        // default to the RTP remote's port + 1 and then latch symmetrically.
        let rtcp_started = if let (Some(a_rtcp_rport), Some(b_rtcp_rport)) =
            (a_addr.port().checked_add(1), b_addr.port().checked_add(1))
        {
            let a_rtcp_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_rtcp_port);
            let b_rtcp_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_rtcp_port);
            match (
                UdpSocket::bind(&a_rtcp_bind).await,
                UdpSocket::bind(&b_rtcp_bind).await,
            ) {
                (Ok(a_rtcp_sock), Ok(b_rtcp_sock)) => {
                    let a_rtcp_sock = Arc::new(a_rtcp_sock);
                    let b_rtcp_sock = Arc::new(b_rtcp_sock);
                    let a_rtcp_addr = std::net::SocketAddr::new(a_addr.ip(), a_rtcp_rport);
                    let b_rtcp_addr = std::net::SocketAddr::new(b_addr.ip(), b_rtcp_rport);
                    let a_rtcp_target = Arc::new(std::sync::RwLock::new(a_rtcp_addr));
                    let b_rtcp_target = Arc::new(std::sync::RwLock::new(b_rtcp_addr));

                    relay_handles.push(tokio::spawn(relay_leg(
                        Arc::clone(&a_rtcp_sock),
                        Arc::clone(&b_rtcp_sock),
                        a_rtcp_addr,
                        Arc::clone(&a_rtcp_target),
                        Arc::clone(&b_rtcp_target),
                        call_id.to_string(),
                        "A→B",
                        RelayKind::Rtcp,
                        no_relatch.clone(),
                        shutdown_rx.clone(),
                        None,
                    )));
                    relay_handles.push(tokio::spawn(relay_leg(
                        b_rtcp_sock,
                        a_rtcp_sock,
                        b_rtcp_addr,
                        b_rtcp_target,
                        a_rtcp_target,
                        call_id.to_string(),
                        "B→A",
                        RelayKind::Rtcp,
                        no_relatch,
                        shutdown_rx,
                        None,
                    )));
                    true
                }
                (a_res, b_res) => {
                    warn!(
                        call_id = %call_id,
                        a_err = ?a_res.err(),
                        b_err = ?b_res.err(),
                        "RTCP relay sockets failed to bind (audio unaffected)"
                    );
                    false
                }
            }
        } else {
            false
        };

        ctx.relay_handles = relay_handles;
        ctx.relay_shutdown = Some(shutdown_tx);
        ctx.a_leg_target = Some(a_target);
        ctx.b_leg_target = Some(b_target);
        ctx.a_leg_remote_ctl = Some(a_ctl);
        ctx.b_leg_remote_ctl = Some(b_ctl);

        info!(
            call_id = %call_id,
            a_leg_port = ctx.a_leg_local_port,
            b_leg_port = ctx.b_leg_local_port,
            a_rtcp_port = ctx.a_leg_rtcp_port,
            b_rtcp_port = ctx.b_leg_rtcp_port,
            rtcp_started,
            a_remote = %a_remote,
            b_remote = %b_remote,
            "Media relay started"
        );

        Ok(())
    }

    /// Starts a DTLS-SRTP **terminating** relay for a call: drives the DTLS
    /// handshake on each leg's media socket (via the sidecar), and once both
    /// complete, relays media by unprotecting on the ingress leg and
    /// re-protecting for the egress leg — the SBC is a crypto endpoint on both
    /// legs.
    ///
    /// The handshakes can take seconds, so they run in a spawned supervisor and
    /// this returns promptly (like `start_relay`); media flows once both legs
    /// are established. Call teardown (`stop_relay`) signals the shutdown watch,
    /// which stops the supervisor's relay/DTLS tasks and drops the sidecar
    /// connections.
    ///
    /// # Errors
    /// Terminate mode not configured, missing remotes, or socket bind failure.
    pub async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        let sidecar_socket = self.config.dtls_sidecar_socket.clone().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed("no DTLS sidecar socket configured".into())
        })?;
        // Read the current fingerprint (a file-backed source re-reads here) so a
        // call started after a sidecar restart verifies against the live identity.
        let own_fingerprint = self
            .config
            .dtls_fingerprint
            .as_ref()
            .ok_or_else(|| {
                MediaPipelineError::DtlsHandshakeFailed("no DTLS fingerprint configured".into())
            })?
            .current();

        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let a_remote: std::net::SocketAddr = ctx
            .a_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("A-leg remote not set".into()))?
            .into();
        let b_remote: std::net::SocketAddr = ctx
            .b_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("B-leg remote not set".into()))?
            .into();
        let a_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_local_port);
        let b_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_local_port);
        let a_ssrc = ctx.a_leg_ssrc;
        let b_ssrc = ctx.b_leg_ssrc;

        let a_socket = Arc::new(
            UdpSocket::bind(&a_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{a_bind}: {e}")))?,
        );
        let b_socket = Arc::new(
            UdpSocket::bind(&b_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{b_bind}: {e}")))?,
        );

        // RFC 5761; RFC 5764 §4.1: terminate mode relays RTCP only when it is
        // multiplexed on the media port, where the leg's DTLS association
        // keys it. No RTP + 1 socket is bound: RTCP on a separate port would
        // need its own DTLS handshake on that transport, which the SBC does
        // not run, so non-muxed RTCP is not relayed in terminate mode.
        // NIST 800-53 Rev5: CM-7 (Least Functionality), SC-13 -- one SRTP
        // context per key and direction, each owned by a single relay task.
        // POAM: POA&M-343 - non-muxed (separate-port) RTCP is not relayed in
        // terminate mode.

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let a_target = Arc::new(std::sync::RwLock::new(a_remote));
        let b_target = Arc::new(std::sync::RwLock::new(b_remote));

        let supervisor = tokio::spawn(terminate_supervisor(TerminateSetup {
            call_id: call_id.to_string(),
            sidecar_socket,
            own_fingerprint,
            a_socket,
            b_socket,
            a_remote,
            b_remote,
            a_ssrc,
            b_ssrc,
            a_leg,
            b_leg,
            a_target: Arc::clone(&a_target),
            b_target: Arc::clone(&b_target),
            shutdown: shutdown_rx,
            media_failure_tx: self.config.media_failure_tx.clone(),
            a_fork: ctx
                .recording
                .as_ref()
                .map(|fork| fork.tap(true, &ctx.media_kind)),
            b_fork: ctx
                .recording
                .as_ref()
                .map(|fork| fork.tap(false, &ctx.media_kind)),
        }));

        // The supervisor handle stands in for the relay tasks it spawns; those
        // stop via the shutdown watch (task abort does not cascade to children).
        ctx.relay_handles = vec![supervisor];
        ctx.relay_shutdown = Some(shutdown_tx);
        ctx.terminated = true;
        ctx.a_leg_target = Some(a_target);
        ctx.b_leg_target = Some(b_target);

        info!(call_id = %call_id, "DTLS-SRTP terminating relay starting (handshakes in progress)");
        Ok(())
    }

    /// Stops the RTP relay for a call and releases ports.
    pub async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        // Signal shutdown
        if let Some(tx) = ctx.relay_shutdown.take() {
            let _ = tx.send(true);
        }

        // Abort relay tasks
        for handle in ctx.relay_handles.drain(..) {
            handle.abort();
        }

        // The recording fork ends with the relay (keys dropped, ports freed).
        self.end_recording_fork(ctx).await;

        // Release ports and zero them so remove_session won't double-release
        self.port_allocator.release_pair(ctx.a_leg_local_port).await;
        self.port_allocator.release_pair(ctx.b_leg_local_port).await;
        ctx.a_leg_local_port = 0;
        ctx.b_leg_local_port = 0;

        info!(call_id = %call_id, "RTP relay stopped");
        Ok(())
    }

    /// Removes a media session, stopping any running relay tasks, releasing
    /// allocated ports, and cleaning up associated DTLS connections.
    pub async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        if let Some(mut ctx) = sessions.remove(call_id) {
            // Stop relay tasks (mirrors stop_relay logic)
            if let Some(tx) = ctx.relay_shutdown.take() {
                let _ = tx.send(true);
            }
            for handle in ctx.relay_handles.drain(..) {
                handle.abort();
            }
            self.end_recording_fork(&mut ctx).await;

            // Release allocated port pairs (skip if already released by stop_relay)
            if ctx.a_leg_local_port != 0 {
                self.port_allocator.release_pair(ctx.a_leg_local_port).await;
            }
            if ctx.b_leg_local_port != 0 {
                self.port_allocator.release_pair(ctx.b_leg_local_port).await;
            }

            // Drop sessions lock before acquiring dtls_connections lock
            drop(sessions);

            // Remove DTLS connections keyed by this call_id
            let mut connections = self.dtls_connections.write().await;
            connections.retain(|key, _| !key.starts_with(&format!("{call_id}:")));

            info!(call_id = %call_id, "Media session removed");
            Ok(())
        } else {
            Err(MediaPipelineError::SessionNotFound)
        }
    }

    /// Stops a session's recording fork, if any, and returns its ports to
    /// the allocator. Idempotent.
    // NIST 800-53 Rev5: SC-12 / SI-12 - the fork keys do not outlive the fork.
    async fn end_recording_fork(&self, ctx: &mut MediaSessionContext) {
        let Some(ports) = ctx.recording.as_mut().and_then(SessionFork::stop) else {
            return;
        };
        for port in ports {
            self.port_allocator.release_pair(port).await;
        }
    }

    /// Binds the two send-only fork sockets for a recorded call and installs
    /// one SRTP master key per stream (`keys[0]`: the caller's sent media,
    /// `keys[1]`: the callee's). Each stream gets its own SBC-chosen SSRC.
    /// The fork is idle until [`Self::activate_recording_fork`].
    ///
    /// `bind_ip` is the local address the fork sends from (and the address
    /// to put in the recording session SDP); `None` binds the wildcard IPv4
    /// address, as an unzoned leg does. It must be of the same address family
    /// as the recorder's media address, or activation fails.
    ///
    /// The caller's `keys` are consumed and wiped when this returns; the
    /// pipeline keeps only the derived SRTP contexts.
    ///
    /// ## NIST 800-53 Rev5: AU-14, SC-8, SC-12, SC-13, SC-5 (ports come from
    /// the bounded RTP port range)
    ///
    /// # Errors
    /// - [`MediaPipelineError::RecordingUnsupported`]: recording is not
    ///   enabled on this pipeline.
    /// - [`MediaPipelineError::SessionNotFound`]: unknown call.
    /// - [`MediaPipelineError::RecordingFork`]: a fork already exists for the
    ///   call, or its relay has been stopped.
    /// - [`MediaPipelineError::PortExhausted`], `BindFailed`,
    ///   `SrtpContextCreationFailed`: nothing is left allocated.
    pub async fn prepare_recording_fork(
        &self,
        call_id: &str,
        keys: [SrtpKeyMaterial; 2],
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<RecordingForkPorts, MediaPipelineError> {
        if !self.config.recording.is_enabled() {
            return Err(MediaPipelineError::RecordingUnsupported);
        }
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;
        let fork = ctx
            .recording
            .as_mut()
            .ok_or(MediaPipelineError::RecordingUnsupported)?;
        if fork.exists() {
            return Err(MediaPipelineError::RecordingFork(
                "recording fork already prepared".into(),
            ));
        }
        if ctx.a_leg_local_port == 0 {
            return Err(MediaPipelineError::RecordingFork(
                "media relay already stopped".into(),
            ));
        }

        let bind_ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let [a_key, b_key] = &keys;
        // Distinct SSRCs per stream (RFC 3550 §8.1); each stream also has its
        // own key, so the nonce spaces are separate either way.
        let a_ssrc = generate_ssrc();
        let b_ssrc = loop {
            let candidate = generate_ssrc();
            if candidate != a_ssrc {
                break candidate;
            }
        };

        // The RTCP port of each pair stays reserved and unused: the recording
        // session offers `a=rtcp-mux` (RFC 5761) and no RTCP is sent yet.
        let (a_port, _) = self.port_allocator.allocate_pair().await?;
        let (b_port, _) = match self.port_allocator.allocate_pair().await {
            Ok(pair) => pair,
            Err(e) => {
                self.port_allocator.release_pair(a_port).await;
                return Err(e);
            }
        };
        let bound = ForkStream::bind(a_key, std::net::SocketAddr::new(bind_ip, a_port), a_ssrc)
            .and_then(|a| {
                ForkStream::bind(b_key, std::net::SocketAddr::new(bind_ip, b_port), b_ssrc)
                    .map(|b| [a, b])
            });
        let streams = match bound {
            Ok(streams) => streams,
            Err(e) => {
                self.port_allocator.release_pair(a_port).await;
                self.port_allocator.release_pair(b_port).await;
                return Err(e);
            }
        };
        fork.set_prepared(streams, [a_port, b_port]);

        info!(
            call_id = %call_id,
            a_leg_port = a_port,
            b_leg_port = b_port,
            "Recording fork prepared"
        );
        Ok(RecordingForkPorts {
            a_leg_port: a_port,
            b_leg_port: b_port,
        })
    }

    /// Starts forking a prepared call: `remotes[0]` receives the caller's
    /// sent media, `remotes[1]` the callee's. The relay tasks pick the
    /// streams up on their next packet.
    ///
    /// On any error the fork is torn down completely (keys dropped, ports
    /// released); a new `prepare_recording_fork` is needed to try again.
    ///
    /// ## NIST 800-53 Rev5: SC-24 (never a half-recorded call), SC-7
    ///
    /// # Errors
    /// - [`MediaPipelineError::RecordingUnsupported`]: recording is not
    ///   enabled on this pipeline.
    /// - [`MediaPipelineError::SessionNotFound`]: unknown call.
    /// - [`MediaPipelineError::RecordingFork`]: not prepared (or already
    ///   active), or a recorder address that is not a usable unicast
    ///   destination for the fork socket.
    pub async fn activate_recording_fork(
        &self,
        call_id: &str,
        remotes: [std::net::SocketAddr; 2],
    ) -> Result<(), MediaPipelineError> {
        if !self.config.recording.is_enabled() {
            return Err(MediaPipelineError::RecordingUnsupported);
        }
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;
        let result = ctx
            .recording
            .as_mut()
            .ok_or(MediaPipelineError::RecordingUnsupported)?
            .activate(remotes);
        if let Err(e) = result {
            self.end_recording_fork(ctx).await;
            return Err(e);
        }
        info!(call_id = %call_id, "Recording fork active");
        Ok(())
    }

    /// Stops a call's recording fork: nothing more is sent, the SRTP keys are
    /// dropped (and wiped) and the fork ports go back to the allocator.
    /// Idempotent: a call with no fork, or a call that is already gone (the
    /// fork ended with its session), is `Ok`.
    ///
    /// # Errors
    /// [`MediaPipelineError::RecordingUnsupported`] if recording is not
    /// enabled on this pipeline.
    pub async fn stop_recording_fork(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        if !self.config.recording.is_enabled() {
            return Err(MediaPipelineError::RecordingUnsupported);
        }
        let mut sessions = self.sessions.write().await;
        if let Some(ctx) = sessions.get_mut(call_id) {
            let had_fork = ctx.recording.as_ref().is_some_and(SessionFork::exists);
            self.end_recording_fork(ctx).await;
            if had_fork {
                info!(call_id = %call_id, "Recording fork stopped");
            }
        }
        Ok(())
    }

    /// Returns session statistics.
    pub async fn get_session_stats(&self, call_id: &str) -> Option<SessionStats> {
        let sessions = self.sessions.read().await;
        sessions.get(call_id).map(|ctx| SessionStats {
            call_id: call_id.to_string(),
            state: ctx.session.state(),
            mode: ctx.session.mode(),
            srtp_enabled: ctx.session.srtp_enabled(),
            has_a_leg: ctx.a_leg_remote.is_some(),
            has_b_leg: ctx.b_leg_remote.is_some(),
        })
    }

    /// Returns the number of active sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Returns a reference to the port allocator.
    pub fn port_allocator(&self) -> &RtpPortAllocator {
        &self.port_allocator
    }

    /// This node's advertised media IP, if configured. A standalone media node
    /// binds its relay sockets on this (it lives on its own host, not the
    /// signaling daemon's zone media interface).
    #[must_use]
    pub fn advertised_media_ip(&self) -> Option<std::net::IpAddr> {
        self.config.advertised_media_ip
    }
}

/// Soft cap on tracked SSRCs: eviction of idle entries starts here.
const SSRC_TRACKER_SOFT_CAP: usize = 4096;
/// Hard cap on tracked SSRCs: new SSRCs are rejected beyond this.
const SSRC_TRACKER_HARD_CAP: usize = 8192;
/// Idle eviction window for SSRC trackers.
const SSRC_TRACKER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// A sequence tracker with a last-activity timestamp for idle eviction.
struct TrackedSequence {
    inner: SequenceTracker,
    last_seen: std::time::Instant,
}

impl TrackedSequence {
    fn new() -> Self {
        Self {
            inner: SequenceTracker::new(),
            last_seen: std::time::Instant::now(),
        }
    }
}

/// Which stream a relay leg carries. RTP legs feed the "audio flowing" metric
/// and log; RTCP legs are counted separately so control traffic doesn't inflate
/// the audio signal.
#[derive(Clone, Copy)]
enum RelayKind {
    Rtp,
    Rtcp,
}

impl RelayKind {
    /// Uppercase protocol label for logs.
    fn label(self) -> &'static str {
        match self {
            Self::Rtp => "RTP",
            Self::Rtcp => "RTCP",
        }
    }
}

/// Process-global count of RTP packets forwarded across all relay legs. A
/// working relay increments this; a black-holed one never does. Exposed for
/// observability and as the media "did audio actually flow" signal.
static RTP_PACKETS_RELAYED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-global count of RTCP packets forwarded (non-muxed endpoints only;
/// muxed RTCP rides the RTP relay and counts as RTP).
static RTCP_PACKETS_RELAYED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Records one forwarded RTP packet. Called by both the opaque relay leg and the
/// DTLS-terminate relay leg so the black-hole metric ("did audio actually flow")
/// covers terminated calls too — otherwise terminate-mode media would read as a
/// permanent black-hole even when audio flows fine.
pub fn record_rtp_relayed() {
    RTP_PACKETS_RELAYED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Returns the total RTP packets forwarded by the media relay since start.
#[must_use]
pub fn rtp_packets_relayed() -> u64 {
    RTP_PACKETS_RELAYED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Process-global count of UDPTL (T.38 fax) datagrams forwarded by the opaque
/// relay on calls switched to image (RFC 3362). Counted instead of
/// `RTP_PACKETS_RELAYED` so fax does not read as audio.
static UDPTL_PACKETS_RELAYED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Returns the total UDPTL datagrams forwarded by the media relay since start.
#[must_use]
pub fn udptl_packets_relayed() -> u64 {
    UDPTL_PACKETS_RELAYED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Records one forwarded RTCP packet. Called by the opaque non-muxed RTCP leg
/// and by the DTLS-terminate relay for muxed SRTCP, so RTCP is counted without
/// inflating the RTP "audio flowed" signal.
pub fn record_rtcp_relayed() {
    RTCP_PACKETS_RELAYED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Returns the total RTCP packets forwarded by the media relay since start.
#[must_use]
pub fn rtcp_packets_relayed() -> u64 {
    RTCP_PACKETS_RELAYED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Per-leg DTLS parameters for a terminating relay ([`MediaPipeline::start_relay_terminate`]).
pub struct LegDtlsParams {
    /// The peer's SDP `a=fingerprint`, verified during the handshake.
    pub peer_fingerprint: String,
    /// The SBC's DTLS role for this leg (derived from `a=setup`).
    pub role: Role,
}

/// Everything the terminate supervisor owns for one call (bundled so the spawn
/// and the supervisor signature stay manageable).
struct TerminateSetup {
    call_id: String,
    sidecar_socket: std::path::PathBuf,
    own_fingerprint: String,
    a_socket: Arc<UdpSocket>,
    b_socket: Arc<UdpSocket>,
    a_remote: std::net::SocketAddr,
    b_remote: std::net::SocketAddr,
    a_ssrc: u32,
    b_ssrc: u32,
    a_leg: LegDtlsParams,
    b_leg: LegDtlsParams,
    a_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    b_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// Signalled with `call_id` if a leg's handshake fails, so the call is torn
    /// down rather than left up with dead media.
    media_failure_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// SIPREC fork tap for media received from the A-leg (`None` when
    /// recording is disabled on the pipeline).
    a_fork: Option<ForkTap>,
    /// SIPREC fork tap for media received from the B-leg.
    b_fork: Option<ForkTap>,
}

/// Drives both legs' DTLS handshakes concurrently, then spawns the bidirectional
/// SRTP relay and the post-handshake DTLS pump tasks. If either handshake fails,
/// no media is relayed (fail-closed). All spawned tasks stop on the shutdown
/// watch (task abort does not cascade to children, so teardown signals it).
async fn terminate_supervisor(s: TerminateSetup) {
    // Owned here so that a failed or timed-out handshake still reports them.
    let mut a_stats = HandshakeSourceStats::default();
    let mut b_stats = HandshakeSourceStats::default();
    let (a_res, b_res) = tokio::join!(
        establish_srtp_leg(
            &s.a_socket,
            s.a_remote,
            &s.sidecar_socket,
            &s.own_fingerprint,
            &s.a_leg.peer_fingerprint,
            s.a_leg.role,
            &mut a_stats,
        ),
        establish_srtp_leg(
            &s.b_socket,
            s.b_remote,
            &s.sidecar_socket,
            &s.own_fingerprint,
            &s.b_leg.peer_fingerprint,
            s.b_leg.role,
            &mut b_stats,
        ),
    );
    // NIST 800-53 Rev5: AU-2, AU-3 -- on success and on failure.
    log_handshake_sources(
        &s.call_id,
        "A",
        &a_stats,
        a_res.as_ref().ok().map(|leg| leg.peer_addr),
    );
    log_handshake_sources(
        &s.call_id,
        "B",
        &b_stats,
        b_res.as_ref().ok().map(|leg| leg.peer_addr),
    );
    let (a_est, b_est) = match (a_res, b_res) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            warn!(
                call_id = %s.call_id,
                a_err = ?a.err(), b_err = ?b.err(),
                "DTLS termination handshake failed; tearing down call"
            );
            // Fail-closed: the call was already answered, so leaving it up means
            // black-holed media on a connected call. Signal the SIP layer to BYE
            // both legs. (Best-effort: a dropped receiver just reverts to the
            // old fail-open behaviour.)
            if let Some(tx) = &s.media_failure_tx {
                let _ = tx.send(s.call_id.clone());
            }
            return;
        }
    };

    let EstablishedLeg {
        inbound: a_in,
        outbound: a_out,
        reader: a_reader,
        writer: a_writer,
        peer_addr: a_peer,
        handshake_peers: a_peers,
    } = a_est;
    let EstablishedLeg {
        inbound: b_in,
        outbound: b_out,
        reader: b_reader,
        writer: b_writer,
        peer_addr: b_peer,
        handshake_peers: b_peers,
    } = b_est;
    // Set by the first authenticated packet from each side (its media leg;
    // RTCP is muxed); until then post-handshake DTLS is accepted from, and
    // sent to, every handshake source of that side.
    let a_authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Four SRTP contexts. The ssrc only seeds per-stream replay state — the AEAD
    // nonce uses the packet's SSRC (see proto-srtp) — so the leg ssrc is fine.
    // NIST 800-53 Rev5: SC-13, SC-8 -- these are the only contexts built from
    // the keys, and each is moved into exactly one relay task, so every key
    // and direction has one replay window (RFC 3711 §3.3.2) and one
    // SRTP/SRTCP index sequence (RFC 7714 §8.1, §9.1). Muxed SRTCP rides the
    // media-port tasks; there is no RTP + 1 relay in terminate mode.
    let ctxs = (
        SrtpContext::new(&a_in, SrtpDirection::Inbound, s.a_ssrc),
        SrtpContext::new(&a_out, SrtpDirection::Outbound, s.a_ssrc),
        SrtpContext::new(&b_in, SrtpDirection::Inbound, s.b_ssrc),
        SrtpContext::new(&b_out, SrtpDirection::Outbound, s.b_ssrc),
    );
    let (a_ingress, a_egress, b_ingress, b_egress) = if let (Ok(ai), Ok(ae), Ok(bi), Ok(be)) = ctxs
    {
        (ai, ae, bi, be)
    } else {
        warn!(call_id = %s.call_id, "SRTP context creation failed; media not relayed");
        return;
    };

    // Peer→sidecar DTLS (post-handshake: a retransmitted final flight, alerts)
    // demuxed by each relay leg.
    let (a_dtls_tx, a_dtls_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let (b_dtls_tx, b_dtls_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    // NIST 800-53 Rev5: SC-7 -- seed each leg's latch (and the send target
    // of the opposite direction and of the sidecar's post-handshake DTLS)
    // with the source the handshake completed with, before any task that
    // reads it is spawned. The seed is a hint: a wrong one is corrected by
    // the leg on the peer's first authenticated SRTP packet.
    for (target, peer) in [(&s.a_target, a_peer), (&s.b_target, b_peer)] {
        if let Ok(mut t) = target.write() {
            *t = peer;
        }
    }

    // A→B: unprotect A's media, re-protect for B.
    tokio::spawn(
        TerminateRelayLeg {
            recv_sock: Arc::clone(&s.a_socket),
            send_sock: Arc::clone(&s.b_socket),
            ingress: a_ingress,
            egress: b_egress,
            expected_remote: s.a_remote,
            recv_target: Arc::clone(&s.a_target),
            forward_target: Arc::clone(&s.b_target),
            dtls_out: Some(a_dtls_tx),
            handshake_peers: a_peers,
            media_authenticated: Arc::clone(&a_authenticated),
            call_id: s.call_id.clone(),
            direction: "A→B",
            fork: s.a_fork,
        }
        .run(s.shutdown.clone()),
    );
    // B→A: unprotect B's media, re-protect for A.
    tokio::spawn(
        TerminateRelayLeg {
            recv_sock: Arc::clone(&s.b_socket),
            send_sock: Arc::clone(&s.a_socket),
            ingress: b_ingress,
            egress: a_egress,
            expected_remote: s.b_remote,
            recv_target: Arc::clone(&s.b_target),
            forward_target: Arc::clone(&s.a_target),
            dtls_out: Some(b_dtls_tx),
            handshake_peers: b_peers,
            media_authenticated: Arc::clone(&b_authenticated),
            call_id: s.call_id.clone(),
            direction: "B→A",
            fork: s.b_fork,
        }
        .run(s.shutdown.clone()),
    );

    // Post-handshake DTLS pumps own the sidecar halves. The sidecar keeps each
    // association open for as long as its connection is open, so these tasks
    // are what keeps it up for the whole call; on shutdown they close the
    // connection and relay the sidecar's close_notify to the peer.
    tokio::spawn(forward_dtls_to_sidecar(
        a_dtls_rx,
        a_writer,
        s.shutdown.clone(),
    ));
    tokio::spawn(forward_dtls_to_sidecar(
        b_dtls_rx,
        b_writer,
        s.shutdown.clone(),
    ));
    // NIST 800-53 Rev5: AU-3 -- each pump writes the association's
    // `dtls.association.closed` record with the call id and the leg.
    tokio::spawn(pump_sidecar_dtls_to_peer(
        a_reader,
        Arc::clone(&s.a_socket),
        Arc::clone(&s.a_target),
        HandshakeFanout {
            peers: a_peers,
            media_authenticated: Arc::clone(&a_authenticated),
        },
        s.shutdown.clone(),
        AssociationLabel {
            call_id: s.call_id.clone(),
            leg: "A",
        },
    ));
    tokio::spawn(pump_sidecar_dtls_to_peer(
        b_reader,
        Arc::clone(&s.b_socket),
        Arc::clone(&s.b_target),
        HandshakeFanout {
            peers: b_peers,
            media_authenticated: Arc::clone(&b_authenticated),
        },
        s.shutdown.clone(),
        AssociationLabel {
            call_id: s.call_id.clone(),
            leg: "B",
        },
    ));

    info!(call_id = %s.call_id, "DTLS-SRTP termination established; relaying media");
}

/// Logs one warn line per handshake that dropped datagrams while choosing
/// sources, whether it completed (`peer` is then the latch seed) or not (the
/// pump has no call id; see [`crate::dtls_relay::HandshakeSourceStats`]).
fn log_handshake_sources(
    call_id: &str,
    leg: &'static str,
    stats: &HandshakeSourceStats,
    peer: Option<std::net::SocketAddr>,
) {
    if stats.any_dropped() {
        warn!(
            call_id = %call_id, leg,
            completed = peer.is_some(),
            dropped_implausible = stats.dropped_implausible,
            dropped_overflow = stats.dropped_overflow,
            dropped_after_exact = stats.dropped_after_exact,
            dropped_rate_limited = stats.dropped_rate_limited,
            send_failures = stats.send_failures,
            sources = stats.sources,
            peer = ?peer,
            "DTLS handshake pump dropped datagrams from the peer's IP"
        );
    }
}

/// One direction of the media relay (RTP or RTCP, per `kind`) with source
/// validation and symmetric latching.
///
/// Only packets whose source IP matches the SDP-negotiated remote are
/// considered. The latch is exact-first, both at the start of the leg and
/// after a signalled remote change: a packet from the exact SDP `ip:port`
/// latches at once; another port on that IP (NAT) latches only after the
/// grace window (the leg's [`LegRemote`] grace, or [`RELATCH_GRACE`]) has
/// passed with no exact match. The latched source's packets are forwarded
/// and the opposite direction's send target follows the latch (RFC 4961
/// symmetric RTP); packets from any other source are dropped and counted.
///
/// Once latched, only an RTP leg moves without a signalled re-latch:
/// - A leg latched to a non-exact source moves to the exact SDP source as
///   soon as it sends.
/// - A leg latched to the exact SDP source moves to another port on its IP
///   that keeps sending once the exact source has been silent for the grace
///   window, but only while the exact latch is weak: the exact source has
///   sent fewer than [`EXACT_ESTABLISHED_PACKETS`] packets since it took
///   the latch. One datagram spoofed from the SDP address therefore does
///   not cut a NAT'd peer off for the rest of the call, while a peer that
///   has been streaming from its SDP port keeps its latch through silence
///   (hold, VAD).
///
/// An RTCP leg's SDP address is only a guess (RTP port + 1; `a=rtcp`,
/// RFC 3605, is not honoured), so neither move applies to it: a sender on
/// the guessed port does not take the latch from the peer's real RTCP
/// source, and an RTCP leg latched to the exact address stays there until a
/// signalled re-latch. A non-exact RTCP latch comes only from the initial
/// (or re-latch) grace fallback.
///
/// This relay holds no keys, so it cannot tell a peer behind NAT that sends
/// from an unsignalled port from another sender on the same IP once the
/// grace has passed.
///
/// `call_id` + `direction` are carried for structured logging/metrics; the
/// socket/target set is inherent to a bidirectional forwarder.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection), SC-8
// POAM: POA&M-345 -- opaque relay residual: after the grace window a
// same-IP sender on an unsignalled port can take the latch of a leg whose
// peer does not send from its SDP port, and a sender spoofing the SDP
// address at least once per grace window holds an RTP leg's latch there,
// away from a NAT'd peer, for as long as it sends, and a same-IP sender
// can take a weak exact RTP latch (fewer than EXACT_ESTABLISHED_PACKETS
// from the exact source) once the exact source has been silent for the
// grace window. Authenticated (SRTP) media is the fix.
#[allow(clippy::too_many_arguments)]
async fn relay_leg(
    recv_sock: Arc<UdpSocket>,
    send_sock: Arc<UdpSocket>,
    expected_remote: std::net::SocketAddr,
    recv_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    forward_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    call_id: String,
    direction: &'static str,
    kind: RelayKind,
    control: LegRelayControl,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    // SIPREC fork tap (RTP legs of a pipeline with recording enabled only).
    mut fork: Option<ForkTap>,
) {
    // POAM: POA&M-290 - tokio truncates datagrams over 2048 bytes silently;
    // UDPTL is relayed opaquely with no IFP validation or truncation check.
    let mut buf = [0u8; 2048];
    let mut expected_remote = expected_remote;
    let mut seen_epoch: u64 = 0;
    let mut latched: Option<std::net::SocketAddr> = None;
    // Set while the leg (at its start, or after a signalled re-latch) waits
    // for the exact SDP `ip:port`: the earliest instant a same-IP,
    // different-port source may latch.
    // NIST 800-53 Rev5: SC-7 -- the initial latch is exact-first too.
    let grace = control
        .remote
        .as_ref()
        .map_or(RELATCH_GRACE, |ctl| ctl.grace);
    let mut relatch_fallback_at: Option<tokio::time::Instant> =
        Some(tokio::time::Instant::now() + grace);
    // While latched to the exact SDP source: when another same-IP port was
    // first heard since the exact source last sent, and whether the exact
    // source has sent since then. The clock is read only for packets that
    // are not the latched source's.
    let mut other_heard_at: Option<tokio::time::Instant> = None;
    let mut exact_heard = false;
    // Packets from the exact SDP source since it last took the latch,
    // saturating at EXACT_ESTABLISHED_PACKETS.
    let mut exact_packets: u32 = 0;
    let mut latch_moves: u64 = 0;
    let mut dropped: u64 = 0;
    let mut forwarded: u64 = 0;
    let has_fork = fork.is_some();

    loop {
        tokio::select! {
            result = recv_sock.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        // Re-latch after a signalled remote change: one
                        // atomic load per packet, the lock only on change.
                        if let Some(ctl) = &control.remote {
                            let epoch = ctl.epoch.load(std::sync::atomic::Ordering::Acquire);
                            if epoch != seen_epoch {
                                seen_epoch = epoch;
                                latched = None;
                                if let Ok(guard) = ctl.expected.read() {
                                    expected_remote = *guard;
                                }
                                relatch_fallback_at =
                                    Some(tokio::time::Instant::now() + ctl.grace);
                                other_heard_at = None;
                                exact_heard = false;
                                exact_packets = 0;
                            }
                        }
                        if src == expected_remote {
                            exact_heard = true;
                        }
                        // RFC 3264 §8.3.1 / RFC 4961: at the start and after a
                        // re-latch only the exact SDP address latches until the
                        // grace window passes; then a same-IP source may
                        // (symmetric NAT). A stale packet from the old port is
                        // dropped and never touches the reverse send target.
                        // On RTP legs only, the exact SDP address takes the latch
                        // back from a non-exact source, and a same-IP port takes
                        // it from a weak exact latch whose source has been
                        // silent for the grace (see the function docs).
                        // NIST 800-53 Rev5: SC-7
                        let acceptable = match latched {
                            Some(latched_src) if src == latched_src => true,
                            Some(_) if src == expected_remote => matches!(kind, RelayKind::Rtp),
                            Some(latched_src)
                                if matches!(kind, RelayKind::Rtp)
                                    && latched_src == expected_remote
                                    && exact_packets < EXACT_ESTABLISHED_PACKETS
                                    && src.ip() == expected_remote.ip() =>
                            {
                                let now = tokio::time::Instant::now();
                                match other_heard_at {
                                    Some(at) if !exact_heard => now.saturating_duration_since(at) >= grace,
                                    _ => {
                                        // Start (or restart) the silence window.
                                        other_heard_at = Some(now);
                                        exact_heard = false;
                                        false
                                    }
                                }
                            }
                            Some(_) => false,
                            None if src == expected_remote => true,
                            None if src.ip() != expected_remote.ip() => false,
                            None => relatch_fallback_at
                                .is_none_or(|at| tokio::time::Instant::now() >= at),
                        };
                        if !acceptable {
                            dropped += 1;
                            if dropped == 1 || dropped.is_multiple_of(1000) {
                                warn!(
                                    call_id = %call_id,
                                    direction,
                                    kind = kind.label(),
                                    source = %src,
                                    expected = %expected_remote,
                                    dropped,
                                    "Dropping packet from unexpected source"
                                );
                            }
                            continue;
                        }

                        if latched != Some(src) {
                            let basis = if src == expected_remote {
                                "sdp-exact"
                            } else if latched == Some(expected_remote) {
                                "exact-silent"
                            } else {
                                "grace-elapsed"
                            };
                            latched = Some(src);
                            relatch_fallback_at = None;
                            other_heard_at = None;
                            exact_heard = false;
                            exact_packets = 0;
                            if src != expected_remote {
                                debug!(
                                    call_id = %call_id,
                                    direction,
                                    sdp_remote = %expected_remote,
                                    actual = %src,
                                    "Symmetric RTP latch"
                                );
                            }
                            if let Ok(mut target) = recv_target.write() {
                                let from = *target;
                                if from != src {
                                    *target = src;
                                    latch_moves += 1;
                                    if latch_moves == 1 || latch_moves.is_multiple_of(100) {
                                        info!(
                                            event = "media.latch.moved",
                                            call_id = %call_id,
                                            direction,
                                            kind = kind.label(),
                                            from = %from,
                                            to = %src,
                                            basis,
                                            latch_moves,
                                            "relay leg latch moved"
                                        );
                                    }
                                }
                            }
                        }

                        if src == expected_remote && exact_packets < EXACT_ESTABLISHED_PACKETS {
                            exact_packets += 1;
                        }

                        let dest = match forward_target.read() {
                            Ok(guard) => *guard,
                            Err(_) => continue,
                        };
                        match send_sock.send_to(&buf[..n], dest).await {
                            Ok(_) => {
                                forwarded += 1;
                                // Count + log once, the moment traffic actually
                                // flows. Fires inside the loop (relay tasks are
                                // abort()ed on teardown, so post-loop code can't
                                // be relied on). The RTP first-forward line is the
                                // "audio is relaying" signal the CI gate greps for;
                                // RTCP is counted separately so it doesn't inflate
                                // the audio metric.
                                let image = control
                                    .media_kind
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                    == MediaKind::Image.as_u8();
                                match kind {
                                    RelayKind::Rtp if image => {
                                        UDPTL_PACKETS_RELAYED
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    RelayKind::Rtp => {
                                        RTP_PACKETS_RELAYED
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        // RFC 7866 §8: copy to the recorder
                                        // after the call's own packet is
                                        // out. Never blocks, never allocates.
                                        if let Some(tap) = fork.as_mut()
                                            && let Some(pkt) = buf.get(..n)
                                        {
                                            tap.on_rtp(pkt);
                                        }
                                        if forwarded == 1 {
                                            info!(
                                                call_id = %call_id,
                                                direction,
                                                "RTP relay forwarding media"
                                            );
                                        }
                                    }
                                    RelayKind::Rtcp => {
                                        RTCP_PACKETS_RELAYED
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        if forwarded == 1 {
                                            debug!(
                                                call_id = %call_id,
                                                direction,
                                                "RTCP relay forwarding"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, call_id = %call_id, direction, "Relay send error");
                            }
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, call_id = %call_id, direction, "Relay recv error");
                        break;
                    }
                }
            }
            // Recording fork activated or stopped: applied inside the tap, so
            // a stopped stream is released even when no media is arriving.
            () = fork_changed(&mut fork), if has_fork => {}
            _ = shutdown.changed() => {
                debug!(call_id = %call_id, direction, "Relay shutdown");
                break;
            }
        }
    }

    // Emit the per-leg forwarded count at info so operators (and the CI harness)
    // can confirm media actually flowed rather than black-holed.
    info!(
        call_id = %call_id,
        direction,
        kind = kind.label(),
        forwarded,
        dropped,
        "Relay leg finished"
    );
}

/// Generates a random SSRC.
///
/// Cryptographically random — a timestamp-derived SSRC is predictable and
/// collision-prone, aiding RTP injection.
fn generate_ssrc() -> u32 {
    rand::random::<u32>()
}

/// Session statistics.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Call identifier.
    pub call_id: String,
    /// Session state.
    pub state: SessionState,
    /// Media mode.
    pub mode: MediaMode,
    /// Whether SRTP is enabled.
    pub srtp_enabled: bool,
    /// Whether A-leg is connected.
    pub has_a_leg: bool,
    /// Whether B-leg is connected.
    pub has_b_leg: bool,
}

/// Media pipeline errors.
#[derive(Debug)]
pub enum MediaPipelineError {
    /// Session not found.
    SessionNotFound,
    /// Codec negotiation failed.
    CodecNegotiationFailed,
    /// DTLS connection not found.
    DtlsConnectionNotFound,
    /// DTLS handshake failed.
    DtlsHandshakeFailed(String),
    /// SRTP key export failed.
    SrtpKeyExportFailed(String),
    /// SRTP context creation failed.
    SrtpContextCreationFailed(String),
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed.
    DecryptionFailed(String),
    /// RTP port range exhausted.
    PortExhausted,
    /// Failed to bind UDP socket.
    BindFailed(String),
    /// A control-plane RPC to an out-of-process media controller failed
    /// (transport error, or a server-side error with no closer variant).
    /// Only produced by the gRPC [`MediaController`] client; the in-process
    /// [`MediaPipeline`] never returns it.
    Rpc(String),
    /// This media controller cannot fork media to a recorder: recording is
    /// not enabled on the pipeline, or the controller is a remote media node
    /// (POA&M-301). The caller's recording failure policy applies.
    RecordingUnsupported,
    /// A recording fork request was invalid for the call's current state, or
    /// the recorder's media address was unusable.
    RecordingFork(String),
}

impl std::fmt::Display for MediaPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "Media session not found"),
            Self::CodecNegotiationFailed => write!(f, "Codec negotiation failed"),
            Self::DtlsConnectionNotFound => write!(f, "DTLS connection not found"),
            Self::DtlsHandshakeFailed(e) => write!(f, "DTLS handshake failed: {e}"),
            Self::SrtpKeyExportFailed(e) => write!(f, "SRTP key export failed: {e}"),
            Self::SrtpContextCreationFailed(e) => write!(f, "SRTP context creation failed: {e}"),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {e}"),
            Self::DecryptionFailed(e) => write!(f, "Decryption failed: {e}"),
            Self::PortExhausted => write!(f, "RTP port range exhausted"),
            Self::BindFailed(e) => write!(f, "Failed to bind UDP socket: {e}"),
            Self::Rpc(e) => write!(f, "Media controller RPC failed: {e}"),
            Self::RecordingUnsupported => {
                write!(f, "Recording fork not supported by this media controller")
            }
            Self::RecordingFork(e) => write!(f, "Recording fork failed: {e}"),
        }
    }
}

impl std::error::Error for MediaPipelineError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The relay must latch to the first valid source and drop packets from
    /// any other source (RTP injection defense).
    #[tokio::test]
    async fn test_relay_leg_drops_unexpected_sources() {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let legit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let relay_addr = relay_in.local_addr().unwrap();
        let expected = legit.local_addr().unwrap();
        let recv_target = Arc::new(std::sync::RwLock::new(expected));
        let forward_target = Arc::new(std::sync::RwLock::new(receiver.local_addr().unwrap()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let _task = tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            expected,
            recv_target,
            forward_target,
            "test-call".to_string(),
            "A→B",
            RelayKind::Rtp,
            LegRelayControl {
                remote: None,
                media_kind: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            },
            shutdown_rx,
            None,
        ));

        let mut buf = [0u8; 64];

        // First packet from the negotiated source latches and forwards.
        legit.send_to(b"one", relay_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("legit packet must be forwarded")
        .unwrap();
        assert_eq!(&buf[..n], b"one");

        // Attacker (same IP, different port — post-latch) must be dropped:
        // the next packet the receiver sees is the second legit one.
        attacker.send_to(b"evil", relay_addr).await.unwrap();
        legit.send_to(b"two", relay_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("second legit packet must be forwarded")
        .unwrap();
        assert_eq!(&buf[..n], b"two", "injected packet must not be relayed");
    }

    async fn recv_payload(receiver: &UdpSocket) -> Option<Vec<u8>> {
        let mut buf = [0u8; 64];
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            receiver.recv_from(&mut buf),
        )
        .await
        .ok()?
        .ok()
        .map(|(n, _)| buf[..n].to_vec())
    }

    /// RFC 4961 re-latch: after the signalling plane moves the leg to a new
    /// SDP remote (a T.38 gateway sending UDPTL from a new port), the old
    /// latched source is dropped and the new source latches. Before it
    /// latches, a source whose IP differs from the new SDP address is still
    /// dropped. UDPTL is counted separately once the kind is Image.
    #[tokio::test]
    async fn relay_leg_relatches_on_remote_change_and_counts_udptl() {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_src = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udptl_src = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_in.local_addr().unwrap();
        let expected = rtp_src.local_addr().unwrap();
        let ctl = Arc::new(LegRemote::new(expected));
        let kind = Arc::new(std::sync::atomic::AtomicU8::new(MediaKind::Audio.as_u8()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            expected,
            Arc::new(std::sync::RwLock::new(expected)),
            Arc::new(std::sync::RwLock::new(receiver.local_addr().unwrap())),
            "relatch".to_string(),
            "A→B",
            RelayKind::Rtp,
            LegRelayControl {
                remote: Some(Arc::clone(&ctl)),
                media_kind: Arc::clone(&kind),
            },
            shutdown_rx,
            None,
        ));

        rtp_src.send_to(b"rtp", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"rtp"[..]));
        // Before the switchover the UDPTL source is not the latched one.
        udptl_src.send_to(b"early", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await, None);

        // Move to an address whose IP is not ours: localhost sources drop.
        ctl.update("192.0.2.1:9".parse().unwrap());
        rtp_src.send_to(b"x", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await, None);

        // Switch to image at the gateway's new UDPTL port.
        kind.store(
            MediaKind::Image.as_u8(),
            std::sync::atomic::Ordering::Relaxed,
        );
        ctl.update(udptl_src.local_addr().unwrap());
        let before = udptl_packets_relayed();
        // Opaque, non-RTP first byte.
        udptl_src
            .send_to(&[0x00, 0xff, 0x10], relay_addr)
            .await
            .unwrap();
        assert_eq!(
            recv_payload(&receiver).await.as_deref(),
            Some(&[0x00, 0xff, 0x10][..])
        );
        assert!(udptl_packets_relayed() > before);
        // Latched to the new source with the same IP: localhost on another
        // port (the old RTP source) is dropped.
        rtp_src.send_to(b"old", relay_addr).await.unwrap();
        udptl_src.send_to(b"fax", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"fax"[..]));
    }

    /// QA: flip-flop re-latch (audio -> T.38 -> audio). Each
    /// `set_remote_address` re-opens the latch exactly once; the previous
    /// source is dropped each time, and an update to the same address does
    /// not unlatch.
    #[tokio::test]
    async fn relay_leg_relatch_flip_flop_back_to_audio() {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_src = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udptl_src = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_in.local_addr().unwrap();
        let rtp = rtp_src.local_addr().unwrap();
        let udptl = udptl_src.local_addr().unwrap();
        let ctl = Arc::new(LegRemote::new(rtp));
        let kind = Arc::new(std::sync::atomic::AtomicU8::new(MediaKind::Audio.as_u8()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            rtp,
            Arc::new(std::sync::RwLock::new(rtp)),
            Arc::new(std::sync::RwLock::new(receiver.local_addr().unwrap())),
            "flipflop".to_string(),
            "A→B",
            RelayKind::Rtp,
            LegRelayControl {
                remote: Some(Arc::clone(&ctl)),
                media_kind: Arc::clone(&kind),
            },
            shutdown_rx,
            None,
        ));

        rtp_src.send_to(b"a1", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"a1"[..]));
        // Same address again: latch kept, a different port stays dropped.
        ctl.update(rtp);
        udptl_src.send_to(b"no", relay_addr).await.unwrap();
        rtp_src.send_to(b"a2", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"a2"[..]));

        // To T.38.
        kind.store(
            MediaKind::Image.as_u8(),
            std::sync::atomic::Ordering::Relaxed,
        );
        ctl.update(udptl);
        udptl_src.send_to(b"f1", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"f1"[..]));

        // Back to audio at the original RTP port.
        kind.store(
            MediaKind::Audio.as_u8(),
            std::sync::atomic::Ordering::Relaxed,
        );
        ctl.update(rtp);
        let before = udptl_packets_relayed();
        udptl_src.send_to(b"stale", relay_addr).await.unwrap();
        rtp_src.send_to(b"a3", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"a3"[..]));
        assert_eq!(recv_payload(&receiver).await, None, "stale UDPTL dropped");
        assert_eq!(
            udptl_packets_relayed(),
            before,
            "audio not counted as UDPTL"
        );
    }

    /// Re-latch NAT fallback: when no packet arrives from the exact SDP
    /// `ip:port` within the grace window, a same-IP, different-port source
    /// (symmetric NAT) latches and becomes the reverse send target. Inside
    /// the window it is dropped and the reverse target is untouched.
    #[tokio::test]
    async fn relay_leg_relatch_nat_fallback_after_grace() {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_src = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let natted = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Signalled UDPTL port that never sends (the NAT rewrites it).
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_in.local_addr().unwrap();
        let rtp = rtp_src.local_addr().unwrap();
        let grace = std::time::Duration::from_millis(200);
        let ctl = Arc::new(LegRemote::with_grace(rtp, grace));
        let recv_target = Arc::new(std::sync::RwLock::new(rtp));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            rtp,
            Arc::clone(&recv_target),
            Arc::new(std::sync::RwLock::new(receiver.local_addr().unwrap())),
            "natfallback".to_string(),
            "A→B",
            RelayKind::Rtp,
            LegRelayControl {
                remote: Some(Arc::clone(&ctl)),
                media_kind: Arc::new(std::sync::atomic::AtomicU8::new(MediaKind::Audio.as_u8())),
            },
            shutdown_rx,
            None,
        ));

        rtp_src.send_to(b"a1", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"a1"[..]));

        ctl.update(silent.local_addr().unwrap());
        // Inside the grace window: dropped, reverse target unchanged.
        natted.send_to(b"early", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await, None);
        assert_eq!(*recv_target.read().unwrap(), rtp);

        // The 500 ms recv timeout above already exceeds the grace window.
        natted.send_to(b"nat", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"nat"[..]));
        assert_eq!(*recv_target.read().unwrap(), natted.local_addr().unwrap());
        // Latched: the old RTP port is now dropped.
        rtp_src.send_to(b"old", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await, None);
    }

    #[tokio::test]
    async fn media_kind_and_terminated_flags() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("k", None).await.unwrap();
        assert!(!pipeline.is_terminated("k").await);
        assert!(!pipeline.is_terminated("missing").await);
        pipeline
            .set_media_kind("k", MediaKind::Image)
            .await
            .unwrap();
        assert!(matches!(
            pipeline.set_media_kind("missing", MediaKind::Image).await,
            Err(MediaPipelineError::SessionNotFound)
        ));
    }

    /// End-to-end relay: the full path the SIP call flow drives
    /// (`create_session` → `set_remote_address` both legs → `start_relay`) must
    /// forward RTP in BOTH directions. This is the audio gate — it fails if the
    /// relay is not actually wired to move packets caller ⇄ SBC ⇄ callee.
    #[tokio::test]
    async fn test_full_relay_forwards_both_directions() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Stand-ins for the caller (A leg) and callee (B leg) endpoints.
        let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_addr = caller.local_addr().unwrap();
        let callee_addr = callee.local_addr().unwrap();

        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            ..Default::default()
        });
        // Bind the relay's sockets on loopback so 127.0.0.1:<port> reaches them.
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // A-leg remote = caller, B-leg remote = callee.
        pipeline
            .set_remote_address("call", true, SbcSocketAddr::from(caller_addr))
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, SbcSocketAddr::from(callee_addr))
            .await
            .unwrap();
        let relayed_before = rtp_packets_relayed();
        pipeline.start_relay("call").await.unwrap();

        let a_relay = format!("127.0.0.1:{}", ports.a_leg_rtp_port);
        let b_relay = format!("127.0.0.1:{}", ports.b_leg_rtp_port);
        let mut buf = [0u8; 64];

        // Caller → SBC A-leg port → forwarded to the callee.
        caller.send_to(b"rtp-a2b", &a_relay).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), callee.recv_from(&mut buf))
            .await
            .expect("callee must receive the relayed A→B packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtp-a2b");

        // Callee → SBC B-leg port → forwarded to the caller.
        callee.send_to(b"rtp-b2a", &b_relay).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), caller.recv_from(&mut buf))
            .await
            .expect("caller must receive the relayed B→A packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtp-b2a");

        // The relay metric must have counted both forwarded packets (fetch_add
        // lands just after send_to; give it a moment before reading).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rtp_packets_relayed() >= relayed_before + 2,
            "rtp_packets_relayed must count forwarded packets"
        );

        pipeline.stop_relay("call").await.unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_relay_forwards_non_muxed() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Stand-ins for the caller (A leg) and callee (B leg) endpoints. Their
        // RTCP is modeled on the same sockets; the relay accepts an RTCP packet
        // from another port on the SDP IP once the grace window has passed,
        // then latches the exact source (symmetric RTCP).
        let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_addr = caller.local_addr().unwrap();
        let callee_addr = callee.local_addr().unwrap();

        // Distinct port range from the other relay test: start_relay now binds
        // the RTCP pair too, so two default-range relays running concurrently
        // would fight over the same 127.0.0.1 ports.
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            rtp_port_min: 40_000,
            rtp_port_max: 40_200,
            ..Default::default()
        });
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ports = pipeline
            .create_session_with_zones(
                "rtcp-call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();
        pipeline
            .set_remote_address("rtcp-call", true, SbcSocketAddr::from(caller_addr))
            .await
            .unwrap();
        pipeline
            .set_remote_address("rtcp-call", false, SbcSocketAddr::from(callee_addr))
            .await
            .unwrap();

        let rtcp_before = rtcp_packets_relayed();
        pipeline.start_relay("rtcp-call").await.unwrap();

        // RTCP relay sockets live at RTP port + 1.
        let a_rtcp = format!("127.0.0.1:{}", ports.a_leg_rtp_port + 1);
        let b_rtcp = format!("127.0.0.1:{}", ports.b_leg_rtp_port + 1);
        let mut buf = [0u8; 64];

        // The modeled RTCP sources are not the SDP RTCP ports (RTP port + 1),
        // so they latch only after the initial grace window (exact-first,
        // NAT fallback).
        tokio::time::sleep(RELATCH_GRACE + Duration::from_millis(100)).await;

        // The B→A RTCP send target defaults to callee_rtp_port+1; latch it to the
        // callee's real socket first by sending a report from the callee side.
        callee.send_to(b"rtcp-b0", &b_rtcp).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Caller RTCP → SBC A-leg RTCP port → forwarded to the latched callee.
        caller.send_to(b"rtcp-a2b", &a_rtcp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), callee.recv_from(&mut buf))
            .await
            .expect("callee must receive the relayed A→B RTCP packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtcp-a2b");

        // RTCP counts on its own metric, never the RTP "audio flowing" one.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rtcp_packets_relayed() > rtcp_before,
            "rtcp_packets_relayed must count forwarded RTCP"
        );

        pipeline.stop_relay("rtcp-call").await.unwrap();
    }

    /// Port allocator must survive index wraparound and tiny/reversed ranges.
    // rtp/rtcp are the standard protocol names for the port pair.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn test_port_allocator_bounds() {
        // Reversed range is swapped, not panicked on.
        let allocator = RtpPortAllocator::new(20010, 20000);
        let (rtp, rtcp) = allocator.allocate_pair().await.unwrap();
        assert!(rtp >= 20000 && rtcp <= 20010);

        // Exhausting a tiny range fails cleanly and recovers after release.
        let allocator = RtpPortAllocator::new(30000, 30003);
        let (p1, _) = allocator.allocate_pair().await.unwrap();
        let (p2, _) = allocator.allocate_pair().await.unwrap();
        assert_ne!(p1, p2);
        assert!(allocator.allocate_pair().await.is_err());
        allocator.release_pair(p1).await;
        assert_eq!(allocator.allocate_pair().await.unwrap().0, p1);

        // Top-of-range allocation never overflows u16. The order is random;
        // the two pairs handed out are exactly the two in the range.
        let allocator = RtpPortAllocator::new(65532, 65535);
        let first = allocator.allocate_pair().await.unwrap();
        let second = allocator.allocate_pair().await.unwrap();
        let mut got = [first, second];
        got.sort_unstable();
        assert_eq!(got, [(65532, 65533), (65534, 65535)]);
        assert!(allocator.allocate_pair().await.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = MediaPipelineConfig::default();
        assert!(config.srtp_required);
        assert!(config.rtcp_mux);
        assert!(!config.local_codecs.is_empty());
    }

    #[test]
    fn test_media_pipeline_creation() {
        let config = MediaPipelineConfig::default();
        let pipeline = MediaPipeline::new(config);

        // Verify codec registry was populated
        assert!(pipeline.codec_registry.find_by_name("PCMU").is_some());
        assert!(pipeline.codec_registry.find_by_name("PCMA").is_some());
    }

    #[tokio::test]
    async fn test_create_session() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call-1", None).await.unwrap();

        assert_eq!(pipeline.active_session_count().await, 1);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call-1", None).await.unwrap();

        pipeline.remove_session("test-call-1").await.unwrap();
        assert_eq!(pipeline.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        let result = pipeline.remove_session("nonexistent").await;
        assert!(matches!(result, Err(MediaPipelineError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_codec_negotiation() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        let remote_codecs = vec![CodecCapability::pcmu(), CodecCapability::pcma()];

        let negotiated = pipeline
            .negotiate_codecs("test-call", &remote_codecs)
            .await
            .unwrap();

        assert!(!negotiated.is_empty());
    }

    #[tokio::test]
    async fn test_codec_negotiation_failure() {
        // Config with only Opus
        let config = MediaPipelineConfig {
            local_codecs: vec![CodecCapability::opus(111)],
            ..Default::default()
        };
        let pipeline = MediaPipeline::new(config);

        // Remote only supports G.711
        let remote_codecs = vec![CodecCapability::pcmu()];

        let result = pipeline.negotiate_codecs("test-call", &remote_codecs).await;

        assert!(matches!(
            result,
            Err(MediaPipelineError::CodecNegotiationFailed)
        ));
    }

    #[tokio::test]
    async fn test_codec_negotiation_with_telephone_event() {
        let mut config = MediaPipelineConfig::default();
        config
            .local_codecs
            .push(CodecCapability::telephone_event(101));
        let pipeline = MediaPipeline::new(config);

        let remote = vec![
            CodecCapability::telephone_event(96),
            CodecCapability::pcmu(),
        ];
        let negotiated = pipeline.negotiate_codecs("call", &remote).await.unwrap();
        assert!(
            negotiated
                .iter()
                .any(|c| c.name == "telephone-event" && c.payload_type == 96)
        );
        // The first audio codec is what a transcoder would be built from.
        let audio = negotiated.iter().find(|c| c.is_audio_payload()).unwrap();
        assert_eq!(audio.name, "PCMU");

        // DTMF-only overlap is a negotiation failure.
        let result = pipeline
            .negotiate_codecs("call", &[CodecCapability::telephone_event(96)])
            .await;
        assert!(matches!(
            result,
            Err(MediaPipelineError::CodecNegotiationFailed)
        ));
    }

    #[tokio::test]
    async fn test_telephone_event_never_reaches_transcoder() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("te-call", None).await.unwrap();
        let a = NegotiatedCodec {
            name: "telephone-event".to_string(),
            payload_type: 101,
            clock_rate: 8000,
        };
        let b = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };
        let result = pipeline.set_negotiated_codecs("te-call", a, b).await;
        assert!(matches!(
            result,
            Err(MediaPipelineError::CodecNegotiationFailed)
        ));
        let sessions = pipeline.sessions.read().await;
        assert!(sessions.get("te-call").unwrap().transcoder.is_none());
    }

    #[tokio::test]
    async fn test_set_remote_address() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call", None).await.unwrap();

        let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        pipeline
            .set_remote_address("test-call", true, addr)
            .await
            .unwrap();

        let stats = pipeline.get_session_stats("test-call").await.unwrap();
        assert!(stats.has_a_leg);
        assert!(!stats.has_b_leg);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline
            .create_session("test-call", Some(MediaMode::Relay))
            .await
            .unwrap();

        let stats = pipeline.get_session_stats("test-call").await.unwrap();
        assert_eq!(stats.call_id, "test-call");
        assert!(matches!(stats.mode, MediaMode::Relay));
        assert!(stats.srtp_enabled);
    }

    #[test]
    fn test_transcoder_pcmu_to_pcma() {
        let a_codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };
        let b_codec = NegotiatedCodec {
            name: "PCMA".to_string(),
            payload_type: 8,
            clock_rate: 8000,
        };

        let mut transcoder = Transcoder::new(a_codec, b_codec);

        // Create a PCMU payload (160 bytes = 20ms @ 8kHz)
        let pcmu_payload: Vec<u8> = (0..160).map(|i| (i % 256) as u8).collect();

        // Transcode A→B (PCMU → PCMA)
        let (output, pt) = transcoder.transcode(&pcmu_payload, true).unwrap();
        assert_eq!(pt, 8, "Output should be PCMA payload type");
        assert_eq!(output.len(), 160, "Same frame size for G.711");

        // Transcode B→A (PCMA → PCMU)
        let (output2, pt2) = transcoder.transcode(&output, false).unwrap();
        assert_eq!(pt2, 0, "Output should be PCMU payload type");
        assert_eq!(output2.len(), 160);
    }

    #[test]
    fn test_resample_linear() {
        // 8kHz to 16kHz (2x upsample)
        let input: Vec<i16> = vec![0, 1000, 2000, 3000, 4000];
        let output = resample_linear(&input, 8000, 16_000);
        assert_eq!(output.len(), 10);
        assert_eq!(output[0], 0);
        // Interpolated values should be between samples
        assert!(output[1] > 0 && output[1] < 1000);
    }

    #[tokio::test]
    async fn test_set_negotiated_codecs_same() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("test-call", None).await.unwrap();

        let codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };

        pipeline
            .set_negotiated_codecs("test-call", codec.clone(), codec)
            .await
            .unwrap();

        // No transcoder should be created for same codec
        let sessions = pipeline.sessions.read().await;
        let ctx = sessions.get("test-call").unwrap();
        assert!(ctx.transcoder.is_none());
    }

    #[tokio::test]
    async fn test_set_negotiated_codecs_different() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("test-call", None).await.unwrap();

        let a_codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };
        let b_codec = NegotiatedCodec {
            name: "PCMA".to_string(),
            payload_type: 8,
            clock_rate: 8000,
        };

        pipeline
            .set_negotiated_codecs("test-call", a_codec, b_codec)
            .await
            .unwrap();

        // Transcoder should be created
        let sessions = pipeline.sessions.read().await;
        let ctx = sessions.get("test-call").unwrap();
        assert!(ctx.transcoder.is_some());
    }

    #[test]
    fn test_generate_ssrc() {
        let ssrc1 = generate_ssrc();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ssrc2 = generate_ssrc();
        // SSRCs should be different (high probability)
        assert_ne!(ssrc1, ssrc2);
    }

    // Drives terminate_leg_dtls end-to-end over a mock sidecar + UDP peer and
    // asserts the leg's SRTP contexts and live sidecar halves are stored.
    #[tokio::test]
    async fn terminate_leg_stores_srtp_contexts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
            let n = 1 + body.len();
            let mut f = Vec::with_capacity(2 + n);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.push(t);
            f.extend_from_slice(body);
            w.write_all(&f).await.unwrap();
        }
        async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) -> u8 {
            let mut h = [0u8; 2];
            r.read_exact(&mut h).await.unwrap();
            let n = usize::from(u16::from_be_bytes(h));
            let mut b = vec![0u8; n];
            r.read_exact(&mut b).await.unwrap();
            b[0]
        }

        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let sock = std::env::temp_dir().join(format!("usg-mp-term-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let fp = "sha-384 SIDECAR";

        let sock2 = sock.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            wr(&mut w, 1, fp.as_bytes()).await; // Hello
            assert_eq!(rd(&mut r).await, 2); // Start
            assert_eq!(rd(&mut r).await, 3); // forwarded peer DTLS
            wr(&mut w, 3, b"srv").await; // Dtls
            let mut ready = vec![0u8, 8]; // profile 8 = AEAD_AES_256_GCM
            ready.extend_from_slice(&[7u8; 88]);
            wr(&mut w, 4, &ready).await; // Ready
            let _ = std::fs::remove_file(&sock2);
        });

        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock.clone()),
            dtls_fingerprint: Some(Arc::new(
                crate::dtls_identity::DtlsFingerprintSource::from_static(fp.to_string()),
            )),
            ..Default::default()
        });
        pipeline
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();

        // Peer's first DTLS record (type 22 = handshake, DTLS 1.2, empty
        // body): it has to pass the pump's record-header plausibility walk.
        peer.send_to(
            &[22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
            relay_addr,
        )
        .await
        .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipeline.terminate_leg_dtls(
                "call",
                true,
                &relay,
                peer_addr,
                "sha-384 PEER",
                Role::Server,
            ),
        )
        .await
        .expect("terminate timed out")
        .expect("terminate failed");

        assert!(pipeline.test_leg_srtp_active("call", true).await);
        assert!(!pipeline.test_leg_srtp_active("call", false).await);
        sidecar.await.unwrap();
    }

    #[tokio::test]
    async fn terminate_leg_errors_without_sidecar_config() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = relay.local_addr().unwrap();
        // terminate_dtls set but no socket/fingerprint configured.
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            terminate_dtls: true,
            ..Default::default()
        });
        pipeline
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        let err = pipeline
            .terminate_leg_dtls("call", true, &relay, peer, "sha-384 PEER", Role::Server)
            .await
            .unwrap_err();
        assert!(matches!(err, MediaPipelineError::DtlsHandshakeFailed(_)));
    }

    // End-to-end terminate relay over a mock sidecar (no real DTLS): both legs
    // "handshake" (the mock returns known SRTP keys after one pumped record),
    // then real SRTP media protected by peer A crosses the SBC and is recovered
    // by peer B. Exercises start_relay_terminate + the supervisor + both
    // TerminateRelayLeg tasks with the crypto wired end to end.
    #[tokio::test]
    async fn terminate_relay_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
            let n = 1 + body.len();
            let mut f = Vec::with_capacity(2 + n);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.push(t);
            f.extend_from_slice(body);
            w.write_all(&f).await.unwrap();
        }
        async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) {
            let mut h = [0u8; 2];
            r.read_exact(&mut h).await.unwrap();
            let mut b = vec![0u8; usize::from(u16::from_be_bytes(h))];
            r.read_exact(&mut b).await.unwrap();
        }
        fn srtp_ctx(key: &[u8], salt: &[u8], dir: SrtpDirection, ssrc: u32) -> SrtpContext {
            let m = SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.to_vec(), salt.to_vec())
                .unwrap();
            SrtpContext::new(&m, dir, ssrc).unwrap()
        }

        let fp = "sha-384 SIDECAR";
        // Known exported keying material (RFC 5764 layout), generated at runtime.
        let blob: Vec<u8> = (0..88).map(|_| rand::random::<u8>()).collect();
        let client_key = blob[0..32].to_vec();
        let server_key = blob[32..64].to_vec();
        let client_salt = blob[64..76].to_vec();
        let server_salt = blob[76..88].to_vec();

        // One mock sidecar UDS, accepts both legs' connections; each returns the
        // same Ready(blob) after Hello/Start/one Dtls.
        let sock = std::env::temp_dir().join(format!("usg-e2e-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let blob2 = blob.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let blob = blob2.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    wr(&mut w, 1, fp.as_bytes()).await; // Hello
                    rd(&mut r).await; // Start
                    rd(&mut r).await; // forwarded DTLS trigger
                    let mut ready = vec![0u8, 8];
                    ready.extend_from_slice(&blob);
                    wr(&mut w, 4, &ready).await; // Ready(profile=8, keys)
                    // Hold the connection open for the call.
                    let mut sink = [0u8; 64];
                    let _ = r.read(&mut sink).await;
                });
            }
        });

        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        // Unique high port range per run so parallel pipeline tests (which all
        // default to 16384) don't collide on bind.
        let port_base = 24_000_u16.wrapping_add((rand::random::<u16>() % 8_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock.clone()),
            dtls_fingerprint: Some(Arc::new(
                crate::dtls_identity::DtlsFingerprintSource::from_static(fp.to_string()),
            )),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        let peer_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_relay = format!("127.0.0.1:{}", ports.a_leg_rtp_port);
        let b_relay = format!("127.0.0.1:{}", ports.b_leg_rtp_port);
        pipeline
            .set_remote_address("call", true, peer_a.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, peer_b.local_addr().unwrap().into())
            .await
            .unwrap();

        // SBC is DTLS server on both legs: each peer (DTLS client) protects with
        // the client_write key; the SBC re-protects for the far peer with the
        // server_write key, which that peer unprotects.
        pipeline
            .start_relay_terminate(
                "call",
                LegDtlsParams {
                    peer_fingerprint: "sha-384 A".into(),
                    role: Role::Server,
                },
                LegDtlsParams {
                    peer_fingerprint: "sha-384 B".into(),
                    role: Role::Server,
                },
            )
            .await
            .unwrap();

        // Trigger both handshakes (a plausible DTLS 1.2 handshake record on
        // each media port, from the SDP address).
        let hello = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
        peer_a.send_to(&hello, &a_relay).await.unwrap();
        peer_b.send_to(&hello, &b_relay).await.unwrap();

        let media_ssrc = 0x0001_2345;
        let peer_a_send = srtp_ctx(
            &client_key,
            &client_salt,
            SrtpDirection::Outbound,
            media_ssrc,
        );
        let peer_b_recv = srtp_ctx(
            &server_key,
            &server_salt,
            SrtpDirection::Inbound,
            media_ssrc,
        );

        // Retry A→B media until it crosses (handshakes may still be completing).
        let payload = vec![0x5Au8; 160];
        let mut buf = [0u8; 512];
        let mut received = None;
        for i in 0..40u32 {
            let pkt = RtpPacket::new(
                RtpHeader::new(0, 100 + i as u16, 900, media_ssrc),
                payload.clone(),
            );
            let srtp = SrtpProtect::new(&peer_a_send).protect_rtp(&pkt).unwrap();
            peer_a.send_to(&srtp, &a_relay).await.unwrap();
            if let Ok(Ok((n, _))) = tokio::time::timeout(
                std::time::Duration::from_millis(150),
                peer_b.recv_from(&mut buf),
            )
            .await
            {
                received = Some(n);
                break;
            }
        }
        let n = received.expect("peer B never received terminated media");
        let out = SrtpUnprotect::new(&peer_b_recv)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(out.payload.as_ref(), payload.as_slice());

        let _ = pipeline.stop_relay("call").await;
        let _ = std::fs::remove_file(&sock);
    }

    // ---- srtp-audio gate (real DTLS handshake, real SRTP media) ----------
    // Spawns the REAL Go sidecar + two REAL DTLS-SRTP media peers and drives a
    // terminated call: each peer completes a real DTLS handshake with the SBC
    // (pumped through the Rust relay to the sidecar), then sends SRTP media that
    // the SBC decrypts on ingress and re-encrypts on egress for the far peer.
    // Both peers must recover relayed audio. Ignored by default (needs the built
    // binaries); the srtp-audio CI job runs it with SIDECAR_BIN + PEER_BIN set.
    //
    // The SBC is the DTLS *client* on both legs so the peers (servers) don't send
    // to the SBC's media port before start_relay_terminate binds it (which would
    // draw ICMP-unreachable and abort their handshake).
    struct PeerProc {
        child: tokio::process::Child,
        fingerprint: String,
        local: std::net::SocketAddr,
        lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    }

    async fn read_peer_header(bin: &str, sbc_port: u16, sbc_fp: &str, ssrc: u32) -> PeerProc {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let mut child = Command::new(bin)
            .args([
                "-role",
                "server",
                "-remote",
                &format!("127.0.0.1:{sbc_port}"),
                "-peer-fp",
                sbc_fp,
                "-count",
                "40",
                "-ssrc",
                &ssrc.to_string(),
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn peer");
        let stdout = child.stdout.take().expect("peer stdout");
        let mut lines = BufReader::new(stdout).lines();
        let mut fp: Option<String> = None;
        let mut local: Option<std::net::SocketAddr> = None;
        while fp.is_none() || local.is_none() {
            let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
                .await
                .expect("timeout reading peer header")
                .expect("peer stdout io")
                .expect("peer closed stdout before header");
            if let Some(v) = line.strip_prefix("FINGERPRINT ") {
                fp = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("LOCAL ") {
                local = Some(v.parse().expect("parse LOCAL addr"));
            }
        }
        PeerProc {
            child,
            fingerprint: fp.unwrap(),
            local: local.unwrap(),
            lines,
        }
    }

    /// Returns `(rtp_received, rtcp_received)` from the peer's RESULT line.
    async fn peer_received(peer: &mut PeerProc) -> (usize, usize) {
        loop {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(35), peer.lines.next_line())
                    .await
                    .expect("timeout awaiting peer RESULT")
                    .expect("peer stdout io")
                    .expect("peer closed stdout before RESULT");
            if let Some(rest) = line.strip_prefix("RESULT ") {
                // "sent=40 received=NN rtcp_sent=X rtcp_received=MM profile=8"
                let mut rtp = None;
                let mut rtcp = None;
                for tok in rest.split_whitespace() {
                    if let Some(n) = tok.strip_prefix("rtcp_received=") {
                        rtcp = Some(n.parse().expect("parse rtcp_received count"));
                    } else if let Some(n) = tok.strip_prefix("received=") {
                        rtp = Some(n.parse().expect("parse received count"));
                    }
                }
                return (
                    rtp.expect("RESULT missing received="),
                    rtcp.expect("RESULT missing rtcp_received="),
                );
            }
        }
    }

    /// Surfaces the relay's warnings (e.g. an SRTP unprotect failure) if a gate
    /// ever fails in CI. Quiet by default; raise with RUST_LOG.
    fn init_gate_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sbc_media_core=warn")),
            )
            .with_test_writer()
            .try_init();
    }

    /// Spawns the real DTLS-SRTP terminator sidecar and waits for it to publish
    /// its fingerprint + bind its UDS. Returns the (`kill_on_drop`) child and the
    /// published SBC fingerprint.
    async fn spawn_sidecar(
        sidecar_bin: &str,
        uds: &std::path::Path,
        fp_file: &std::path::Path,
    ) -> (tokio::process::Child, String) {
        let _ = std::fs::remove_file(uds);
        let _ = std::fs::remove_file(fp_file);
        let child = tokio::process::Command::new(sidecar_bin)
            .args([
                "-socket",
                uds.to_str().unwrap(),
                "-fingerprint-file",
                fp_file.to_str().unwrap(),
            ])
            .env("GODEBUG", "fips140=on")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sidecar");

        let mut sbc_fp = String::new();
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(fp_file)
                && !s.trim().is_empty()
                && uds.exists()
            {
                sbc_fp = s.trim().to_string();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(!sbc_fp.is_empty(), "sidecar never published a fingerprint");
        (child, sbc_fp)
    }

    #[tokio::test]
    #[ignore = "spawns the real sidecar + peer binaries; run via the srtp-audio CI job with SIDECAR_BIN + PEER_BIN set"]
    async fn srtp_audio_end_to_end_real() {
        init_gate_tracing();

        let sidecar_bin = std::env::var("SIDECAR_BIN").expect("SIDECAR_BIN not set");
        let peer_bin = std::env::var("PEER_BIN").expect("PEER_BIN not set");

        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        let uds = tmp.join(format!("srtp-audio-{pid}.sock"));
        let fp_file = tmp.join(format!("srtp-audio-{pid}.fp"));

        // 1. Real sidecar.
        let (mut sidecar, sbc_fp) = spawn_sidecar(&sidecar_bin, &uds, &fp_file).await;

        // 2. Terminate-mode pipeline (unique high port range to avoid collisions).
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let port_base = 26_000_u16.wrapping_add((rand::random::<u16>() % 6_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(uds.clone()),
            dtls_fingerprint: Some(Arc::new(
                crate::dtls_identity::DtlsFingerprintSource::from_static(sbc_fp.clone()),
            )),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // 3. Two real peers (DTLS servers), each pointed at its SBC media leg.
        let mut a = read_peer_header(&peer_bin, ports.a_leg_rtp_port, &sbc_fp, 0x1111_1111).await;
        let mut b = read_peer_header(&peer_bin, ports.b_leg_rtp_port, &sbc_fp, 0x2222_2222).await;

        // 4. Point the relay at each peer, then terminate (SBC = DTLS client).
        pipeline
            .set_remote_address("call", true, a.local.into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, b.local.into())
            .await
            .unwrap();
        pipeline
            .start_relay_terminate(
                "call",
                LegDtlsParams {
                    peer_fingerprint: a.fingerprint.clone(),
                    role: Role::Client,
                },
                LegDtlsParams {
                    peer_fingerprint: b.fingerprint.clone(),
                    role: Role::Client,
                },
            )
            .await
            .unwrap();

        // 5. Both peers must recover relayed audio AND relayed SRTCP (the SBC
        // decrypted + re-encrypted each on the correct transform).
        let (rtp_a, rtcp_a) = peer_received(&mut a).await;
        let (rtp_b, rtcp_b) = peer_received(&mut b).await;
        let _ = a.child.wait().await;
        let _ = b.child.wait().await;
        let _ = pipeline.stop_relay("call").await;
        let _ = sidecar.kill().await;
        let _ = std::fs::remove_file(&uds);
        let _ = std::fs::remove_file(&fp_file);

        eprintln!("srtp-audio gate: A rtp={rtp_a} rtcp={rtcp_a}, B rtp={rtp_b} rtcp={rtcp_b}");
        assert!(rtp_a > 0, "peer A recovered no relayed audio");
        assert!(rtp_b > 0, "peer B recovered no relayed audio");
        // SRTCP interop (RFC 7714 §9.2): the SBC re-protected muxed SRTCP and the
        // far peer's pion/srtp decrypted it — the H6 path the unit tests can't cover.
        assert!(rtcp_a > 0, "peer A recovered no relayed SRTCP");
        assert!(rtcp_b > 0, "peer B recovered no relayed SRTCP");
    }

    /// The DTLS-SRTP interop gate, driven across the signaling↔media SPLIT: the
    /// same real sidecar + pion peers, but every control operation
    /// (GetDtlsFingerprint, create_session, set_remote_address,
    /// start_relay_terminate, stop_relay) goes over gRPC through
    /// [`GrpcMediaController`] → [`MediaControllerServer`] → the pipeline. Proves
    /// the gRPC control plane drives DTLS-SRTP termination end-to-end — including
    /// that the fingerprint signaling advertises is the one fetched over
    /// `GetDtlsFingerprint`, not read from a shared file.
    #[cfg(feature = "grpc")]
    #[tokio::test]
    #[ignore = "spawns the real sidecar + peer binaries; run via the srtp-audio CI job (grpc) with SIDECAR_BIN + PEER_BIN set"]
    async fn srtp_audio_end_to_end_split() {
        use crate::grpc_media_controller::GrpcMediaController;
        use crate::grpc_media_server::MediaControllerServer;
        use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerServiceServer;

        init_gate_tracing();

        let sidecar_bin = std::env::var("SIDECAR_BIN").expect("SIDECAR_BIN not set");
        let peer_bin = std::env::var("PEER_BIN").expect("PEER_BIN not set");

        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        // Distinct paths + port range from the _real test: both are #[ignore]d and
        // may run in the same process (same pid) concurrently.
        let uds = tmp.join(format!("srtp-split-{pid}.sock"));
        let fp_file = tmp.join(format!("srtp-split-{pid}.fp"));

        // 1. Real sidecar — owned by the media plane in the split.
        let (mut sidecar, sbc_fp) = spawn_sidecar(&sidecar_bin, &uds, &fp_file).await;

        // 2. Terminate-mode pipeline, hosted behind the gRPC MediaControllerServer
        // (the sbc-media process). The fingerprint source + failure channel are the
        // same ones the media pod wires.
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let port_base = 28_000_u16.wrapping_add((rand::random::<u16>() % 4_000) & !1);
        let fp_source = Arc::new(crate::dtls_identity::DtlsFingerprintSource::from_static(
            sbc_fp.clone(),
        ));
        let (failure_tx, failure_rx) = tokio::sync::mpsc::unbounded_channel();
        let pipeline = Arc::new(MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(uds.clone()),
            dtls_fingerprint: Some(fp_source.clone()),
            media_failure_tx: Some(failure_tx),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        }));
        let server = MediaControllerServer::new(pipeline, Some(fp_source), failure_rx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MediaControllerServiceServer::new(server))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        // 3. The signaling-side client drives everything over gRPC.
        let client = GrpcMediaController::connect(format!("http://{grpc_addr}"))
            .await
            .unwrap();

        // 3a. The fingerprint signaling would stamp into SDP, fetched over gRPC.
        let advertised_fp = client.fetch_dtls_fingerprint().await.unwrap();
        assert_eq!(
            advertised_fp, sbc_fp,
            "GetDtlsFingerprint returned an identity that differs from the sidecar's"
        );

        // 3b. Allocate the session's media ports over gRPC.
        let ports = client
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // 4. Two real peers (DTLS servers), each pointed at its SBC media leg,
        // verifying against the gRPC-fetched fingerprint.
        let mut a =
            read_peer_header(&peer_bin, ports.a_leg_rtp_port, &advertised_fp, 0x3333_3333).await;
        let mut b =
            read_peer_header(&peer_bin, ports.b_leg_rtp_port, &advertised_fp, 0x4444_4444).await;

        // 5. Point the relay at each peer and terminate — all over gRPC.
        client
            .set_remote_address("call", true, a.local.into())
            .await
            .unwrap();
        client
            .set_remote_address("call", false, b.local.into())
            .await
            .unwrap();
        client
            .start_relay_terminate(
                "call",
                LegDtlsParams {
                    peer_fingerprint: a.fingerprint.clone(),
                    role: Role::Client,
                },
                LegDtlsParams {
                    peer_fingerprint: b.fingerprint.clone(),
                    role: Role::Client,
                },
            )
            .await
            .unwrap();

        // 6. Both peers must recover relayed audio AND SRTCP across the split.
        let (rtp_a, rtcp_a) = peer_received(&mut a).await;
        let (rtp_b, rtcp_b) = peer_received(&mut b).await;
        let _ = a.child.wait().await;
        let _ = b.child.wait().await;
        let _ = client.stop_relay("call").await;
        let _ = sidecar.kill().await;
        let _ = std::fs::remove_file(&uds);
        let _ = std::fs::remove_file(&fp_file);

        eprintln!(
            "srtp-audio split gate: A rtp={rtp_a} rtcp={rtcp_a}, B rtp={rtp_b} rtcp={rtcp_b}"
        );
        assert!(rtp_a > 0, "peer A recovered no relayed audio (split)");
        assert!(rtp_b > 0, "peer B recovered no relayed audio (split)");
        assert!(rtcp_a > 0, "peer A recovered no relayed SRTCP (split)");
        assert!(rtcp_b > 0, "peer B recovered no relayed SRTCP (split)");
    }
    // ---- Opaque initial latch, random port pairs, terminate seed ----------

    /// Spawns an opaque RTP relay leg for `expected` with re-latch control
    /// `grace`; returns the relay's receive address, the shared reverse
    /// target and the shutdown sender (kept alive by the caller).
    async fn spawn_opaque_leg(
        expected: std::net::SocketAddr,
        receiver: std::net::SocketAddr,
        grace: Option<std::time::Duration>,
        kind: RelayKind,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::RwLock<std::net::SocketAddr>>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_in.local_addr().unwrap();
        let recv_target = Arc::new(std::sync::RwLock::new(expected));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            expected,
            Arc::clone(&recv_target),
            Arc::new(std::sync::RwLock::new(receiver)),
            "opaque-latch".to_string(),
            "A→B",
            kind,
            LegRelayControl {
                remote: grace.map(|g| Arc::new(LegRemote::with_grace(expected, g))),
                media_kind: Arc::new(std::sync::atomic::AtomicU8::new(MediaKind::Audio.as_u8())),
            },
            shutdown_rx,
            None,
        ));
        (relay_addr, recv_target, shutdown_tx)
    }

    /// The initial latch is exact-first, like a re-latch: inside the grace
    /// window a same-IP, other-port source is dropped and does not touch the
    /// reverse target; the exact SDP source latches at once. Checked on an
    /// RTP leg (grace from its `LegRemote`) and an RTCP leg (no control,
    /// `RELATCH_GRACE`).
    // NIST 800-53 Rev5: SC-7
    #[tokio::test]
    async fn relay_leg_initial_latch_is_exact_first() {
        for (kind, grace) in [
            (RelayKind::Rtp, Some(std::time::Duration::from_millis(400))),
            (RelayKind::Rtcp, None),
        ] {
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let exact = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let neighbour = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let exact_addr = exact.local_addr().unwrap();
            let (relay_addr, recv_target, _sd) =
                spawn_opaque_leg(exact_addr, receiver.local_addr().unwrap(), grace, kind).await;

            neighbour.send_to(b"spray", relay_addr).await.unwrap();
            let mut buf = [0u8; 64];
            let early = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                receiver.recv_from(&mut buf),
            )
            .await;
            assert!(
                early.is_err(),
                "{}: other-port packet inside the initial grace was forwarded",
                kind.label()
            );
            assert_eq!(*recv_target.read().unwrap(), exact_addr, "{}", kind.label());

            exact.send_to(b"media", relay_addr).await.unwrap();
            assert_eq!(
                recv_payload(&receiver).await.as_deref(),
                Some(&b"media"[..]),
                "{}: exact SDP source must latch at once",
                kind.label()
            );
            assert_eq!(*recv_target.read().unwrap(), exact_addr);
        }
    }

    /// With no packet from the exact SDP source, a same-IP, other-port source
    /// (NAT) latches only after the initial grace window.
    #[tokio::test]
    async fn relay_leg_initial_nat_fallback_after_grace() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let natted = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sdp = silent.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            sdp,
            receiver.local_addr().unwrap(),
            Some(std::time::Duration::from_millis(200)),
            RelayKind::Rtp,
        )
        .await;

        natted.send_to(b"early", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await,
            None,
            "other-port packet inside the initial grace was forwarded"
        );
        assert_eq!(*recv_target.read().unwrap(), sdp);

        // The 500 ms receive timeout above exceeds the 200 ms grace.
        natted.send_to(b"nat", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"nat"[..]));
        assert_eq!(*recv_target.read().unwrap(), natted.local_addr().unwrap());
    }

    /// A leg latched to a non-exact source (after the grace) moves to the
    /// exact SDP source as soon as it sends; the neighbour is then dropped.
    #[tokio::test]
    async fn relay_leg_exact_source_overrides_non_exact_latch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let neighbour = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact_addr = exact.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            exact_addr,
            receiver.local_addr().unwrap(),
            Some(std::time::Duration::from_millis(50)),
            RelayKind::Rtp,
        )
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        neighbour.send_to(b"n1", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"n1"[..]));
        assert_eq!(
            *recv_target.read().unwrap(),
            neighbour.local_addr().unwrap()
        );

        exact.send_to(b"e1", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await.as_deref(),
            Some(&b"e1"[..]),
            "exact SDP source must override a non-exact latch"
        );
        assert_eq!(*recv_target.read().unwrap(), exact_addr);

        neighbour.send_to(b"n2", relay_addr).await.unwrap();
        exact.send_to(b"e2", relay_addr).await.unwrap();
        assert_eq!(recv_payload(&receiver).await.as_deref(), Some(&b"e2"[..]));
        assert_eq!(
            recv_payload(&receiver).await,
            None,
            "neighbour still forwarded"
        );
    }

    /// Sends `payload` from `sock` to `to` every 20 ms (an RTP-like stream)
    /// until the returned flag is set.
    fn stream_from(
        sock: Arc<UdpSocket>,
        to: std::net::SocketAddr,
        payload: &'static [u8],
    ) -> Arc<std::sync::atomic::AtomicBool> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        tokio::spawn(async move {
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = sock.send_to(payload, to).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        stop
    }

    /// Reads from `receiver` until `want` arrives (true) or `ms` pass.
    async fn recv_until(receiver: &UdpSocket, want: &[u8], ms: u64) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms);
        let mut buf = [0u8; 64];
        while let Ok(Ok((n, _))) =
            tokio::time::timeout_at(deadline, receiver.recv_from(&mut buf)).await
        {
            if &buf[..n] == want {
                return true;
            }
        }
        false
    }

    /// The exact-source override is not sticky while weak. A leg latched to a
    /// NAT'd peer's port receives one datagram spoofed from the SDP `ip:port`
    /// and moves there; the NAT'd peer keeps sending and takes the latch back
    /// once the SDP source has been silent for the grace.
    // NIST 800-53 Rev5: SC-7
    #[tokio::test]
    async fn relay_leg_nat_source_recovers_from_one_spoofed_exact_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let natted = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let exact_addr = exact.local_addr().unwrap();
        let nat_addr = natted.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            exact_addr,
            receiver.local_addr().unwrap(),
            Some(std::time::Duration::from_millis(200)),
            RelayKind::Rtp,
        )
        .await;

        // The NAT'd peer streams; it latches once the initial grace passes.
        let stop = stream_from(Arc::clone(&natted), relay_addr, b"nat");
        assert!(
            recv_until(&receiver, b"nat", 2000).await,
            "NAT source never latched"
        );
        assert_eq!(*recv_target.read().unwrap(), nat_addr);

        // One spoofed datagram from the SDP address takes the latch...
        exact.send_to(b"spoof", relay_addr).await.unwrap();
        assert!(
            recv_until(&receiver, b"spoof", 2000).await,
            "exact override"
        );
        // ...and the NAT'd peer takes it back after the grace of silence.
        assert!(
            recv_until(&receiver, b"nat", 3000).await,
            "NAT source did not recover the latch"
        );
        assert_eq!(*recv_target.read().unwrap(), nat_addr);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// An exact SDP source that keeps sending holds the latch against a
    /// same-IP neighbour that sprays well past the grace window.
    #[tokio::test]
    async fn relay_leg_exact_source_that_keeps_sending_holds_the_latch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let neighbour = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let exact_addr = exact.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            exact_addr,
            receiver.local_addr().unwrap(),
            Some(std::time::Duration::from_millis(100)),
            RelayKind::Rtp,
        )
        .await;

        let stop_exact = stream_from(Arc::clone(&exact), relay_addr, b"exact");
        assert!(recv_until(&receiver, b"exact", 2000).await);
        let stop_spray = stream_from(Arc::clone(&neighbour), relay_addr, b"spray");
        // Six grace windows of spraying.
        assert!(
            !recv_until(&receiver, b"spray", 600).await,
            "the neighbour took the latch from a sending exact source"
        );
        assert_eq!(*recv_target.read().unwrap(), exact_addr);
        stop_spray.store(true, std::sync::atomic::Ordering::Relaxed);
        stop_exact.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// On an RTCP leg the SDP address is only RTP port + 1 (a=rtcp is not
    /// honoured), so it does not take the latch from the source the leg
    /// latched to.
    #[tokio::test]
    async fn relay_leg_rtcp_exact_source_does_not_override() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let guessed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let actual = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let guessed_addr = guessed.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            guessed_addr,
            receiver.local_addr().unwrap(),
            None,
            RelayKind::Rtcp,
        )
        .await;

        tokio::time::sleep(RELATCH_GRACE + std::time::Duration::from_millis(100)).await;
        actual.send_to(b"rtcp-1", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await.as_deref(),
            Some(&b"rtcp-1"[..])
        );
        assert_eq!(*recv_target.read().unwrap(), actual.local_addr().unwrap());

        guessed.send_to(b"guessed", relay_addr).await.unwrap();
        actual.send_to(b"rtcp-2", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await.as_deref(),
            Some(&b"rtcp-2"[..]),
            "the RTP+1 address took an RTCP latch"
        );
        assert_eq!(*recv_target.read().unwrap(), actual.local_addr().unwrap());
    }

    /// An RTCP leg latched to its exact SDP address stays there: a same-IP
    /// port that sends two packets more than the grace apart, then keeps
    /// sending for 2 s while the exact source is silent, never takes the
    /// latch, and the exact source's RTCP is still relayed afterwards.
    // NIST 800-53 Rev5: SC-7
    #[tokio::test]
    async fn relay_leg_rtcp_exact_latch_has_no_silence_takeover() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let neighbour = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let exact_addr = exact.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            exact_addr,
            receiver.local_addr().unwrap(),
            None,
            RelayKind::Rtcp,
        )
        .await;

        exact.send_to(b"rtcp-1", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await.as_deref(),
            Some(&b"rtcp-1"[..])
        );
        assert_eq!(*recv_target.read().unwrap(), exact_addr);

        // Two packets more than the grace apart (the first arms a silence
        // window on an RTP leg, the second would complete it).
        neighbour.send_to(b"spray-1", relay_addr).await.unwrap();
        tokio::time::sleep(RELATCH_GRACE + std::time::Duration::from_millis(100)).await;
        neighbour.send_to(b"spray-2", relay_addr).await.unwrap();
        assert_eq!(
            recv_payload(&receiver).await,
            None,
            "a same-IP port took an exact RTCP latch after the grace"
        );

        // Then a packet every 100 ms for 2 s.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let sprayer = Arc::clone(&neighbour);
        tokio::spawn(async move {
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = sprayer.send_to(b"spray", relay_addr).await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        assert!(
            !recv_until(&receiver, b"spray", 2000).await,
            "a same-IP port took an exact RTCP latch during the exact source's silence"
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(*recv_target.read().unwrap(), exact_addr);

        exact.send_to(b"rtcp-2", relay_addr).await.unwrap();
        assert!(
            recv_until(&receiver, b"rtcp-2", 2000).await,
            "the exact source's RTCP was not relayed"
        );
        assert_eq!(*recv_target.read().unwrap(), exact_addr);
    }

    /// Once the exact SDP source has sent EXACT_ESTABLISHED_PACKETS since it
    /// took an RTP leg's latch, the latch is established: the source going
    /// silent for well over the grace does not let a same-IP port take it.
    // NIST 800-53 Rev5: SC-7
    #[tokio::test]
    async fn relay_leg_established_exact_latch_survives_silence() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exact = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let neighbour = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let exact_addr = exact.local_addr().unwrap();
        let (relay_addr, recv_target, _sd) = spawn_opaque_leg(
            exact_addr,
            receiver.local_addr().unwrap(),
            Some(std::time::Duration::from_millis(100)),
            RelayKind::Rtp,
        )
        .await;

        // The exact source sends past the threshold, then goes silent.
        let established = usize::try_from(EXACT_ESTABLISHED_PACKETS).unwrap() + 2;
        for _ in 0..established {
            exact.send_to(b"exact", relay_addr).await.unwrap();
            assert_eq!(
                recv_payload(&receiver).await.as_deref(),
                Some(&b"exact"[..])
            );
        }
        assert_eq!(*recv_target.read().unwrap(), exact_addr);

        let stop_spray = stream_from(Arc::clone(&neighbour), relay_addr, b"spray");
        // Eight grace windows of spraying against a silent exact source.
        assert!(
            !recv_until(&receiver, b"spray", 800).await,
            "a same-IP port took an established exact latch"
        );
        assert_eq!(*recv_target.read().unwrap(), exact_addr);
        stop_spray.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The free list hands out each pair once, takes a released pair back
    /// once (a repeated or stray release does not duplicate it), and ignores
    /// ports that are not the RTP port of a pair in range.
    #[tokio::test]
    async fn port_allocator_free_list_release_is_idempotent() {
        let allocator = RtpPortAllocator::new(40_000, 40_007);
        assert_eq!(allocator.pair_count(), 4);
        let mut got = Vec::new();
        for _ in 0..4 {
            got.push(allocator.allocate_pair().await.unwrap().0);
        }
        assert!(allocator.allocate_pair().await.is_err());
        assert_eq!(allocator.allocated_port_count().await, 8);

        let freed = got[1];
        allocator.release_pair(freed).await;
        allocator.release_pair(freed).await;
        allocator.release_pair(freed + 1).await; // the RTCP port
        allocator.release_pair(39_998).await; // below the range
        allocator.release_pair(40_100).await; // above the range
        assert_eq!(allocator.allocated_port_count().await, 6);
        assert_eq!(allocator.allocate_pair().await.unwrap(), (freed, freed + 1));
        assert!(
            allocator.allocate_pair().await.is_err(),
            "a double release put the pair on the free list twice"
        );

        // A full u16 range has 32768 pairs and every index fits.
        let full = RtpPortAllocator::new(0, 65535);
        assert_eq!(full.pair_count(), 32_768);
        let (even, odd) = full.allocate_pair().await.unwrap();
        assert!(even % 2 == 0 && odd == even + 1);
    }

    /// Port pairs are drawn at random from the free list, not handed out in
    /// sequence. Over 64 allocations from 1000 pairs, a sequential allocator
    /// gives 63 steps of +2; a random one gives (almost always) none, and the
    /// sequence is not increasing (probability of either under a uniform
    /// draw is far below 2^-60).
    // NIST 800-53 Rev5: SC-7
    #[tokio::test]
    async fn port_allocation_is_not_sequential() {
        let allocator = RtpPortAllocator::new(20_000, 21_999);
        assert_eq!(allocator.pair_count(), 1000);
        let mut rtp = Vec::new();
        for _ in 0..64 {
            let (p, c) = allocator.allocate_pair().await.unwrap();
            assert!(p % 2 == 0 && c == p + 1 && (20_000..=21_998).contains(&p));
            rtp.push(p);
        }
        let mut uniq = rtp.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 64, "a pair was handed out twice");

        let steps_of_two = rtp.windows(2).filter(|w| w[1] == w[0] + 2).count();
        let increasing = rtp.windows(2).all(|w| w[1] > w[0]);
        assert!(
            steps_of_two < 32,
            "{steps_of_two} of 63 allocations were the previous pair + 2: {rtp:?}"
        );
        assert!(
            !increasing,
            "allocations were monotonically increasing: {rtp:?}"
        );
    }

    /// The supervisor seeds the leg's send target with the source the
    /// handshake completed with, before any SRTP: a peer that handshakes from
    /// a port other than its SDP port gets the SBC's media there.
    #[tokio::test]
    async fn terminate_supervisor_seeds_target_with_handshake_source() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
            let n = 1 + body.len();
            let mut f = Vec::with_capacity(2 + n);
            f.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            f.push(t);
            f.extend_from_slice(body);
            w.write_all(&f).await.unwrap();
        }
        async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) {
            let mut h = [0u8; 2];
            r.read_exact(&mut h).await.unwrap();
            let mut b = vec![0u8; usize::from(u16::from_be_bytes(h))];
            r.read_exact(&mut b).await.unwrap();
        }
        // A plausible DTLS 1.2 handshake record (13-byte header + body).
        let hello: Vec<u8> = {
            let mut r = vec![22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4];
            r.extend_from_slice(b"helo");
            r
        };

        let fp = "sha-384 SIDECAR";
        let sock = std::env::temp_dir().join(format!("usg-term-seed-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        // One message per session once its Ready is written.
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let ready_tx = ready_tx.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    wr(&mut w, 1, fp.as_bytes()).await; // Hello
                    rd(&mut r).await; // Start
                    rd(&mut r).await; // the peer's first record
                    let mut ready = vec![0u8, 8];
                    ready.extend_from_slice(&[7u8; 88]);
                    wr(&mut w, 4, &ready).await; // Ready
                    let _ = ready_tx.send(());
                    let mut sink = [0u8; 64];
                    let _ = r.read(&mut sink).await;
                });
            }
        });

        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let port_base = 24_000_u16.wrapping_add((rand::random::<u16>() % 8_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock.clone()),
            dtls_fingerprint: Some(Arc::new(
                crate::dtls_identity::DtlsFingerprintSource::from_static(fp.to_string()),
            )),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "seed",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // A's SDP port never sends; A handshakes from another port.
        let a_sdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_actual = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        pipeline
            .set_remote_address("seed", true, a_sdp.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("seed", false, peer_b.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .start_relay_terminate(
                "seed",
                LegDtlsParams {
                    peer_fingerprint: "sha-384 A".into(),
                    role: Role::Server,
                },
                LegDtlsParams {
                    peer_fingerprint: "sha-384 B".into(),
                    role: Role::Server,
                },
            )
            .await
            .unwrap();
        let a_target = {
            let sessions = pipeline.sessions.read().await;
            Arc::clone(sessions.get("seed").unwrap().a_leg_target.as_ref().unwrap())
        };

        a_actual
            .send_to(&hello, format!("127.0.0.1:{}", ports.a_leg_rtp_port))
            .await
            .unwrap();
        peer_b
            .send_to(&hello, format!("127.0.0.1:{}", ports.b_leg_rtp_port))
            .await
            .unwrap();

        // Precondition: both handshakes completed (the sidecar sent Ready).
        for _ in 0..2 {
            tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx.recv())
                .await
                .expect("a leg's handshake did not reach Ready")
                .unwrap();
        }
        // No SRTP is sent: only the handshake can have moved the target.
        let want = a_actual.local_addr().unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while *a_target.read().unwrap() != want && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            *a_target.read().unwrap(),
            want,
            "A-leg target is not the handshake source (SDP address {})",
            a_sdp.local_addr().unwrap()
        );

        let _ = pipeline.stop_relay("seed").await;
        let _ = std::fs::remove_file(&sock);
    }
}

/// SIPREC recording fork through the pipeline (RFC 7866 §8).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod recording_fork_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn material() -> (Vec<u8>, Vec<u8>) {
        // Generated per test, never hard-coded.
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let salt: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        (key, salt)
    }

    fn keys(m: &(Vec<u8>, Vec<u8>)) -> SrtpKeyMaterial {
        SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, m.0.clone(), m.1.clone()).unwrap()
    }

    fn pipeline(recording_enabled: bool) -> MediaPipeline {
        // Unique range per test so parallel tests do not collide on bind.
        let port_base = 33_000_u16 + (rand::random::<u16>() % 14_000) * 2;
        MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            rtp_port_min: port_base,
            rtp_port_max: port_base + 40,
            recording: RecordingMode::from_enabled(recording_enabled),
            ..Default::default()
        })
    }

    struct Call {
        pipeline: MediaPipeline,
        a: UdpSocket,
        b: UdpSocket,
        sbc_a: SocketAddr,
        sbc_b: SocketAddr,
    }

    /// A relaying two-party call on loopback with latched endpoints.
    async fn call(recording_enabled: bool) -> Call {
        let pipeline = pipeline(recording_enabled);
        let ports = pipeline
            .create_session_with_zones("rec", None, Some(LOOPBACK), Some(LOOPBACK))
            .await
            .unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        pipeline
            .set_remote_address("rec", true, a.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("rec", false, b.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline.start_relay("rec").await.unwrap();
        Call {
            pipeline,
            a,
            b,
            sbc_a: SocketAddr::new(LOOPBACK, ports.a_leg_rtp_port),
            sbc_b: SocketAddr::new(LOOPBACK, ports.b_leg_rtp_port),
        }
    }

    fn rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        RtpPacket::new(
            RtpHeader::new(0, seq, u32::from(seq) * 160, ssrc),
            payload.to_vec(),
        )
        .to_bytes()
        .to_vec()
    }

    async fn recv(sock: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2100];
        tokio::time::timeout(wait, sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()
            .map(|(n, _)| buf[..n].to_vec())
    }

    async fn allocated_ports(pipeline: &MediaPipeline) -> usize {
        pipeline.port_allocator.allocated_port_count().await
    }

    /// Polls until `port` can be bound again (the relay task drops a stopped
    /// stream asynchronously).
    async fn port_is_freed(port: u16) -> bool {
        for _ in 0..100 {
            if std::net::UdpSocket::bind((LOOPBACK, port)).is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn disabled_pipeline_has_no_fork_at_all() {
        let c = call(false).await;
        let (m1, m2) = (material(), material());
        assert!(matches!(
            c.pipeline
                .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                .await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(
            c.pipeline
                .activate_recording_fork("rec", [remote, remote])
                .await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
        assert!(matches!(
            c.pipeline.stop_recording_fork("rec").await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
        assert!(
            c.pipeline
                .sessions
                .read()
                .await
                .get("rec")
                .unwrap()
                .recording
                .is_none()
        );
        // Two leg pairs only; the relay itself is unaffected.
        assert_eq!(allocated_ports(&c.pipeline).await, 4);
        c.a.send_to(&rtp(1, 1, &[7; 160]), c.sbc_a).await.unwrap();
        assert!(recv(&c.b, Duration::from_secs(2)).await.is_some());
    }

    /// The trait default (what a remote media controller inherits) refuses
    /// every fork call.
    #[tokio::test]
    async fn trait_default_reports_recording_unsupported() {
        struct Remote;
        #[async_trait::async_trait]
        impl MediaController for Remote {
            async fn create_session_with_zones(
                &self,
                _: &str,
                _: Option<MediaMode>,
                _: Option<IpAddr>,
                _: Option<IpAddr>,
            ) -> Result<AllocatedPorts, MediaPipelineError> {
                Err(MediaPipelineError::SessionNotFound)
            }
            async fn set_remote_address(
                &self,
                _: &str,
                _: bool,
                _: SbcSocketAddr,
            ) -> Result<(), MediaPipelineError> {
                Ok(())
            }
            async fn start_relay(&self, _: &str) -> Result<(), MediaPipelineError> {
                Ok(())
            }
            async fn start_relay_terminate(
                &self,
                _: &str,
                _: LegDtlsParams,
                _: LegDtlsParams,
            ) -> Result<(), MediaPipelineError> {
                Ok(())
            }
            async fn stop_relay(&self, _: &str) -> Result<(), MediaPipelineError> {
                Ok(())
            }
            async fn remove_session(&self, _: &str) -> Result<(), MediaPipelineError> {
                Ok(())
            }
            async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
                Err(MediaPipelineError::PortExhausted)
            }
        }
        let remote: &dyn MediaController = &Remote;
        let (m1, m2) = (material(), material());
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(
            remote
                .prepare_recording_fork("c", [keys(&m1), keys(&m2)], None)
                .await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
        assert!(matches!(
            remote.activate_recording_fork("c", [addr, addr]).await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
        assert!(matches!(
            remote.stop_recording_fork("c").await,
            Err(MediaPipelineError::RecordingUnsupported)
        ));
    }

    #[tokio::test]
    async fn state_errors() {
        let c = call(true).await;
        let (m1, m2) = (material(), material());
        let srs: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // Unknown call.
        assert!(matches!(
            c.pipeline
                .prepare_recording_fork("nope", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                .await,
            Err(MediaPipelineError::SessionNotFound)
        ));
        assert!(matches!(
            c.pipeline.activate_recording_fork("nope", [srs, srs]).await,
            Err(MediaPipelineError::SessionNotFound)
        ));
        // Stop is idempotent: unknown call and never-prepared call are fine.
        c.pipeline.stop_recording_fork("nope").await.unwrap();
        c.pipeline.stop_recording_fork("rec").await.unwrap();

        // Activate without prepare.
        assert!(matches!(
            c.pipeline.activate_recording_fork("rec", [srs, srs]).await,
            Err(MediaPipelineError::RecordingFork(_))
        ));
        assert_eq!(allocated_ports(&c.pipeline).await, 4);

        // Prepare twice.
        let ports = c
            .pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();
        assert_ne!(ports.a_leg_port, ports.b_leg_port);
        assert_eq!(allocated_ports(&c.pipeline).await, 8);
        assert!(matches!(
            c.pipeline
                .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                .await,
            Err(MediaPipelineError::RecordingFork(_))
        ));
        assert_eq!(allocated_ports(&c.pipeline).await, 8, "no leak on refusal");

        // A bad recorder address tears the whole fork down.
        let bad: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(matches!(
            c.pipeline.activate_recording_fork("rec", [srs, bad]).await,
            Err(MediaPipelineError::RecordingFork(_))
        ));
        assert_eq!(allocated_ports(&c.pipeline).await, 4);
        assert!(port_is_freed(ports.a_leg_port).await);
        assert!(port_is_freed(ports.b_leg_port).await);
        // Activate twice: the second finds nothing prepared.
        c.pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();
        c.pipeline
            .activate_recording_fork("rec", [srs, srs])
            .await
            .unwrap();
        assert!(matches!(
            c.pipeline.activate_recording_fork("rec", [srs, srs]).await,
            Err(MediaPipelineError::RecordingFork(_))
        ));
        assert_eq!(
            allocated_ports(&c.pipeline).await,
            4,
            "failed re-activate ends the fork"
        );
    }

    #[tokio::test]
    async fn prepare_without_free_ports_leaks_nothing() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            // Exactly three pairs: two for the legs, one left for the fork.
            rtp_port_min: 61_000,
            rtp_port_max: 61_006,
            recording: RecordingMode::Enabled,
            ..Default::default()
        });
        pipeline.create_session("rec", None).await.unwrap();
        let (m1, m2) = (material(), material());
        assert!(matches!(
            pipeline
                .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                .await,
            Err(MediaPipelineError::PortExhausted)
        ));
        assert_eq!(allocated_ports(&pipeline).await, 4);
    }

    /// Both directions are forked under their own key and SSRC; the fork
    /// stops with `stop_recording_fork`, and the call's media keeps flowing.
    #[tokio::test]
    async fn forks_both_directions_and_stops() {
        let c = call(true).await;
        let (m1, m2) = (material(), material());
        let srs_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srs_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let ports = c
            .pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();

        // Prepared, not active: relayed, not forked.
        c.a.send_to(&rtp(1, 0xAAAA, &[1; 160]), c.sbc_a)
            .await
            .unwrap();
        c.b.send_to(&rtp(1, 0xBBBB, &[2; 160]), c.sbc_b)
            .await
            .unwrap();
        assert!(recv(&c.b, Duration::from_secs(2)).await.is_some());
        assert!(recv(&c.a, Duration::from_secs(2)).await.is_some());
        assert!(recv(&srs_a, Duration::from_millis(200)).await.is_none());
        assert!(recv(&srs_b, Duration::from_millis(50)).await.is_none());

        c.pipeline
            .activate_recording_fork(
                "rec",
                [srs_a.local_addr().unwrap(), srs_b.local_addr().unwrap()],
            )
            .await
            .unwrap();

        let forked_before = recording_fork_packets();
        c.a.send_to(&rtp(2, 0xAAAA, &[3; 160]), c.sbc_a)
            .await
            .unwrap();
        c.b.send_to(&rtp(2, 0xBBBB, &[4; 160]), c.sbc_b)
            .await
            .unwrap();
        assert!(recv(&c.b, Duration::from_secs(2)).await.is_some());
        assert!(recv(&c.a, Duration::from_secs(2)).await.is_some());

        let mut buf = [0u8; 2100];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), srs_a.recv_from(&mut buf))
            .await
            .expect("caller stream forked")
            .unwrap();
        assert_eq!(from.port(), ports.a_leg_port, "sent from the SDP port");
        let ctx_a = SrtpContext::new(&keys(&m1), SrtpDirection::Inbound, 0).unwrap();
        let got_a = SrtpUnprotect::new(&ctx_a).unprotect_rtp(&buf[..n]).unwrap();
        assert_eq!(got_a.payload.as_ref(), [3u8; 160].as_slice());

        let from_b = recv(&srs_b, Duration::from_secs(2))
            .await
            .expect("callee stream forked");
        let ctx_b = SrtpContext::new(&keys(&m2), SrtpDirection::Inbound, 0).unwrap();
        let got_b = SrtpUnprotect::new(&ctx_b).unprotect_rtp(&from_b).unwrap();
        assert_eq!(got_b.payload.as_ref(), [4u8; 160].as_slice());
        // The caller's key does not open the callee's stream.
        assert!(SrtpUnprotect::new(&ctx_a).unprotect_rtp(&from_b).is_err());

        assert_ne!(got_a.header.ssrc, got_b.header.ssrc);
        assert_ne!(got_a.header.ssrc, 0xAAAA);
        assert_ne!(got_b.header.ssrc, 0xBBBB);
        assert!(recording_fork_packets() - forked_before >= 2);

        // Anything the recorder sends back is never relayed to a call party.
        srs_a
            .send_to(&rtp(9, 9, &[9; 160]), (LOOPBACK, ports.a_leg_port))
            .await
            .unwrap();
        assert!(recv(&c.a, Duration::from_millis(150)).await.is_none());
        assert!(recv(&c.b, Duration::from_millis(50)).await.is_none());

        c.pipeline.stop_recording_fork("rec").await.unwrap();
        assert_eq!(allocated_ports(&c.pipeline).await, 4);
        assert!(port_is_freed(ports.a_leg_port).await, "idle task drops it");
        assert!(port_is_freed(ports.b_leg_port).await);
        c.a.send_to(&rtp(3, 0xAAAA, &[5; 160]), c.sbc_a)
            .await
            .unwrap();
        assert!(recv(&c.b, Duration::from_secs(2)).await.is_some());
        assert!(recv(&srs_a, Duration::from_millis(200)).await.is_none());
        c.pipeline.stop_recording_fork("rec").await.unwrap();
    }

    /// A recorder that is not there costs the call nothing.
    #[tokio::test]
    async fn dead_recorder_does_not_disturb_the_relay() {
        let c = call(true).await;
        let (m1, m2) = (material(), material());
        c.pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();
        let dead = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        c.pipeline
            .activate_recording_fork("rec", [dead, dead])
            .await
            .unwrap();
        for seq in 0..50u16 {
            let payload = [seq as u8; 160];
            c.a.send_to(&rtp(seq, 0xAAAA, &payload), c.sbc_a)
                .await
                .unwrap();
            let got = recv(&c.b, Duration::from_secs(2)).await.expect("relayed");
            assert_eq!(&got[12..], payload.as_slice());
        }
    }

    #[tokio::test]
    async fn stop_relay_and_remove_session_end_the_fork() {
        for remove in [false, true] {
            let c = call(true).await;
            let (m1, m2) = (material(), material());
            let srs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let ports = c
                .pipeline
                .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                .await
                .unwrap();
            let addr = srs.local_addr().unwrap();
            c.pipeline
                .activate_recording_fork("rec", [addr, addr])
                .await
                .unwrap();
            c.a.send_to(&rtp(1, 1, &[1; 160]), c.sbc_a).await.unwrap();
            assert!(recv(&srs, Duration::from_secs(2)).await.is_some());

            if remove {
                c.pipeline.remove_session("rec").await.unwrap();
            } else {
                c.pipeline.stop_relay("rec").await.unwrap();
            }
            assert_eq!(allocated_ports(&c.pipeline).await, 0, "remove={remove}");
            assert!(port_is_freed(ports.a_leg_port).await);
            assert!(port_is_freed(ports.b_leg_port).await);
            if !remove {
                // A stopped relay cannot be given a new fork.
                assert!(matches!(
                    c.pipeline
                        .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
                        .await,
                    Err(MediaPipelineError::RecordingFork(_))
                ));
                assert_eq!(allocated_ports(&c.pipeline).await, 0);
            }
        }
    }

    /// The fork may be prepared and activated before the relay starts.
    #[tokio::test]
    async fn fork_activated_before_start_relay_is_picked_up() {
        let pipeline = pipeline(true);
        let ports = pipeline
            .create_session_with_zones("rec", None, Some(LOOPBACK), Some(LOOPBACK))
            .await
            .unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (m1, m2) = (material(), material());
        pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();
        let addr = srs.local_addr().unwrap();
        pipeline
            .activate_recording_fork("rec", [addr, addr])
            .await
            .unwrap();
        pipeline
            .set_remote_address("rec", true, a.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("rec", false, b.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline.start_relay("rec").await.unwrap();
        a.send_to(
            &rtp(1, 1, &[1; 160]),
            SocketAddr::new(LOOPBACK, ports.a_leg_rtp_port),
        )
        .await
        .unwrap();
        assert!(recv(&b, Duration::from_secs(2)).await.is_some());
        assert!(recv(&srs, Duration::from_secs(2)).await.is_some());
    }

    /// T.38: once the call is image, UDPTL is relayed but not forked.
    #[tokio::test]
    async fn image_kind_is_not_forked() {
        let c = call(true).await;
        let (m1, m2) = (material(), material());
        let srs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.pipeline
            .prepare_recording_fork("rec", [keys(&m1), keys(&m2)], Some(LOOPBACK))
            .await
            .unwrap();
        let addr = srs.local_addr().unwrap();
        c.pipeline
            .activate_recording_fork("rec", [addr, addr])
            .await
            .unwrap();
        c.pipeline
            .set_media_kind("rec", MediaKind::Image)
            .await
            .unwrap();
        // A UDPTL datagram that happens to look like RTP version 2.
        c.a.send_to(&rtp(1, 1, &[1; 40]), c.sbc_a).await.unwrap();
        assert!(recv(&c.b, Duration::from_secs(2)).await.is_some());
        assert!(recv(&srs, Duration::from_millis(200)).await.is_none());
    }
}

/// Terminate mode: one SRTP context per key and direction, RTCP only on the
/// media port (RFC 5761; RFC 5764 §4.1), and no RTP + 1 relay socket.
///
/// Drives `start_relay_terminate` over a mock sidecar (same framing as
/// `terminate_relay_end_to_end`) with real UDP peers on 127.0.0.1.
///
/// NIST 800-53 Rev5: SC-8, SC-13, SC-23
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod terminate_srtp_context_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    const FP: &str = "sha-384 SIDECAR";
    /// SSRC used by peer A for both RTP and RTCP (RTCP sender SSRC).
    const A_SSRC: u32 = 0x0001_2345;
    /// SSRC used by peer B for both RTP and RTCP (RTCP sender SSRC).
    const B_SSRC: u32 = 0x0006_7890;

    async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
        let n = 1 + body.len();
        let mut f = Vec::with_capacity(2 + n);
        f.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
        f.push(t);
        f.extend_from_slice(body);
        w.write_all(&f).await.unwrap();
    }

    async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await.unwrap();
        let mut b = vec![0u8; usize::from(u16::from_be_bytes(h))];
        r.read_exact(&mut b).await.unwrap();
    }

    fn srtp_ctx(key: &[u8], salt: &[u8], dir: SrtpDirection, ssrc: u32) -> SrtpContext {
        let m =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.to_vec(), salt.to_vec()).unwrap();
        SrtpContext::new(&m, dir, ssrc).unwrap()
    }

    fn leg_params(peer_fingerprint: &str) -> LegDtlsParams {
        LegDtlsParams {
            peer_fingerprint: peer_fingerprint.into(),
            role: Role::Server,
        }
    }

    /// Binds a UDP socket on an even/odd port pair `(p, p + 1)` on loopback, so
    /// anything the relay emitted towards a peer's RTP + 1 port is observed.
    async fn bind_pair() -> (UdpSocket, UdpSocket) {
        for _ in 0..200 {
            let rtp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = rtp.local_addr().unwrap().port();
            let Some(next) = port.checked_add(1) else {
                continue;
            };
            if let Ok(rtcp) = UdpSocket::bind(("127.0.0.1", next)).await {
                return (rtp, rtcp);
            }
        }
        unreachable!("no free loopback port pair");
    }

    async fn recv(s: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut b = [0u8; 2048];
        match tokio::time::timeout(wait, s.recv_from(&mut b)).await {
            Ok(Ok((n, _))) => Some(b[..n].to_vec()),
            _ => None,
        }
    }

    /// RTCP RR (PT 201) from `A_SSRC` with a distinguishable 4-byte body.
    fn rtcp_rr(fill: u8) -> Vec<u8> {
        rtcp_rr_from(A_SSRC, fill)
    }

    /// RTCP RR (PT 201) from `ssrc` with a distinguishable 4-byte body.
    fn rtcp_rr_from(ssrc: u32, fill: u8) -> Vec<u8> {
        let s = ssrc.to_be_bytes();
        vec![
            0x80, 201, 0, 2, s[0], s[1], s[2], s[3], fill, fill, fill, fill,
        ]
    }

    /// SRTCP index from the trailing `E || index` word (RFC 3711 §3.4; no MKI).
    fn srtcp_index(pkt: &[u8]) -> u32 {
        let t = &pkt[pkt.len() - 4..];
        u32::from_be_bytes([t[0], t[1], t[2], t[3]]) & 0x7fff_ffff
    }

    struct Call {
        pipeline: MediaPipeline,
        sock_path: std::path::PathBuf,
        /// SBC A-leg media port and its RTP + 1 port.
        a_relay: SocketAddr,
        a_relay_rtcp: SocketAddr,
        /// SBC B-leg media port and its RTP + 1 port.
        b_relay: SocketAddr,
        b_relay_rtcp: SocketAddr,
        /// Peer A sends from here (media port remote).
        peer_a: UdpSocket,
        /// Peer A's RTP + 1 port (observed: must receive nothing).
        peer_a_rtcp: UdpSocket,
        /// Peer B media port and its RTP + 1 port.
        peer_b: UdpSocket,
        peer_b_rtcp: UdpSocket,
        /// Peer A's sending context (client_write key).
        a_send: SrtpContext,
        /// Peer B's receiving context (server_write key).
        b_recv: SrtpContext,
        /// One SRTP packet peer A sent on the media port that the SBC accepted
        /// and relayed to peer B.
        accepted_rtp: Vec<u8>,
        /// Mock sidecar keying material: (client key, client salt, server
        /// key, server salt). The SBC is DTLS server on both legs, so each
        /// peer sends under the client_write key.
        keys: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    }

    impl Call {
        async fn stop(self) {
            let _ = self.pipeline.stop_relay("call").await;
            let _ = std::fs::remove_file(&self.sock_path);
        }
    }

    /// Sets up a terminated call (SBC is DTLS server on both legs), completes
    /// both mock handshakes and waits until A->B media crosses the media port.
    async fn terminated_call(tag: &str) -> Call {
        let blob: Vec<u8> = (0..88).map(|_| rand::random::<u8>()).collect();
        let client_key = blob[0..32].to_vec();
        let server_key = blob[32..64].to_vec();
        let client_salt = blob[64..76].to_vec();
        let server_salt = blob[76..88].to_vec();

        let sock_path = std::env::temp_dir().join(format!(
            "usg-srtpctx-{tag}-{}-{}.sock",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();
        let blob2 = blob.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let blob = blob2.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    wr(&mut w, 1, FP.as_bytes()).await; // Hello
                    rd(&mut r).await; // Start
                    rd(&mut r).await; // forwarded DTLS trigger
                    let mut ready = vec![0u8, 8];
                    ready.extend_from_slice(&blob);
                    wr(&mut w, 4, &ready).await; // Ready(profile=8, keys)
                    let mut sink = [0u8; 64];
                    let _ = r.read(&mut sink).await;
                });
            }
        });

        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let port_base = 32_000_u16.wrapping_add((rand::random::<u16>() % 8_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock_path.clone()),
            dtls_fingerprint: Some(Arc::new(
                crate::dtls_identity::DtlsFingerprintSource::from_static(FP.to_string()),
            )),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        let (peer_a, peer_a_rtcp) = bind_pair().await;
        let (peer_b, peer_b_rtcp) = bind_pair().await;
        let a_relay: SocketAddr = ([127, 0, 0, 1], ports.a_leg_rtp_port).into();
        let b_relay: SocketAddr = ([127, 0, 0, 1], ports.b_leg_rtp_port).into();
        let a_relay_rtcp: SocketAddr = ([127, 0, 0, 1], ports.a_leg_rtp_port + 1).into();
        let b_relay_rtcp: SocketAddr = ([127, 0, 0, 1], ports.b_leg_rtp_port + 1).into();
        pipeline
            .set_remote_address("call", true, peer_a.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, peer_b.local_addr().unwrap().into())
            .await
            .unwrap();

        pipeline
            .start_relay_terminate("call", leg_params("sha-384 A"), leg_params("sha-384 B"))
            .await
            .unwrap();

        peer_a
            .send_to(&[22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0], a_relay)
            .await
            .unwrap();
        peer_b
            .send_to(&[22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0], b_relay)
            .await
            .unwrap();

        let a_send = srtp_ctx(&client_key, &client_salt, SrtpDirection::Outbound, A_SSRC);
        let b_recv = srtp_ctx(&server_key, &server_salt, SrtpDirection::Inbound, A_SSRC);

        let mut accepted_rtp = None;
        for i in 0..40u16 {
            let pkt = RtpPacket::new(RtpHeader::new(0, 100 + i, 900, A_SSRC), vec![0x5A; 160]);
            let srtp = SrtpProtect::new(&a_send).protect_rtp(&pkt).unwrap();
            peer_a.send_to(&srtp, a_relay).await.unwrap();
            if recv(&peer_b, Duration::from_millis(150)).await.is_some() {
                accepted_rtp = Some(srtp.to_vec());
                break;
            }
        }
        let accepted_rtp = accepted_rtp.expect("terminated media never crossed A->B");
        // Let the supervisor finish spawning the remaining relay tasks.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Call {
            pipeline,
            sock_path,
            a_relay,
            a_relay_rtcp,
            b_relay,
            b_relay_rtcp,
            peer_a,
            peer_a_rtcp,
            peer_b,
            peer_b_rtcp,
            a_send,
            b_recv,
            accepted_rtp,
            keys: (client_key, client_salt, server_key, server_salt),
        }
    }

    /// Asserts nothing reaches either of a peer's ports within the wait.
    async fn assert_silent(what: &str, media: &UdpSocket, rtcp_port: &UdpSocket) {
        let on_rtcp = recv(rtcp_port, Duration::from_millis(300)).await;
        let on_media = recv(media, Duration::from_millis(100)).await;
        assert!(
            on_rtcp.is_none() && on_media.is_none(),
            "{what} re-emitted (RTP + 1: {}, media: {})",
            on_rtcp.is_some(),
            on_media.is_some()
        );
    }

    // Muxed SRTCP towards B is protected by the single A->B task under B's
    // egress key, so its SRTCP index (part of the AEAD nonce with the SSRC,
    // RFC 7714 §9.1) never repeats.
    #[tokio::test]
    async fn terminate_egress_srtcp_indices_unique_on_media_port() {
        let c = terminated_call("idx").await;

        let mut indices = Vec::new();
        for round in 0..8u8 {
            let p = SrtpProtect::new(&c.a_send)
                .protect_rtcp(&rtcp_rr(0x10 + round))
                .unwrap();
            c.peer_a.send_to(&p, c.a_relay).await.unwrap();
            let out = recv(&c.peer_b, Duration::from_millis(500))
                .await
                .expect("muxed SRTCP relayed to B");
            assert!(
                SrtpUnprotect::new(&c.b_recv)
                    .unprotect_rtcp_sync(&out)
                    .is_ok(),
                "B must authenticate media-port SRTCP"
            );
            indices.push(srtcp_index(&out));
        }

        let mut seen = std::collections::HashSet::new();
        for idx in &indices {
            assert!(
                seen.insert(*idx),
                "egress SRTCP index {idx} repeated; all: {indices:?}"
            );
        }
        c.stop().await;
    }

    // Terminate mode relays nothing that arrives on a leg's RTP + 1 port:
    // neither SRTP nor SRTCP, fresh or already accepted on the media port.
    #[tokio::test]
    async fn terminate_rtp_plus_one_traffic_not_reemitted() {
        let c = terminated_call("rtp1").await;
        let (ck, cs, _, _) = &c.keys;
        let b_send = srtp_ctx(ck, cs, SrtpDirection::Outbound, B_SSRC);

        // A-leg RTP + 1: replayed SRTP, fresh SRTP, fresh and replayed SRTCP.
        c.peer_a
            .send_to(&c.accepted_rtp, c.a_relay_rtcp)
            .await
            .unwrap();
        assert_silent("SRTP replayed to A RTP + 1", &c.peer_b, &c.peer_b_rtcp).await;

        let fresh = SrtpProtect::new(&c.a_send)
            .protect_rtp(&RtpPacket::new(
                RtpHeader::new(0, 400, 900, A_SSRC),
                vec![0x5A; 160],
            ))
            .unwrap();
        c.peer_a.send_to(&fresh, c.a_relay_rtcp).await.unwrap();
        assert_silent("fresh SRTP to A RTP + 1", &c.peer_b, &c.peer_b_rtcp).await;

        let p = SrtpProtect::new(&c.a_send)
            .protect_rtcp(&rtcp_rr(0x33))
            .unwrap();
        c.peer_a.send_to(&p, c.a_relay_rtcp).await.unwrap();
        assert_silent("fresh SRTCP to A RTP + 1", &c.peer_b, &c.peer_b_rtcp).await;
        c.peer_a.send_to(&p, c.a_relay).await.unwrap();
        assert!(
            recv(&c.peer_b, Duration::from_millis(500)).await.is_some(),
            "muxed SRTCP relayed to B"
        );
        c.peer_a.send_to(&p, c.a_relay_rtcp).await.unwrap();
        assert_silent("SRTCP replayed to A RTP + 1", &c.peer_b, &c.peer_b_rtcp).await;

        // B-leg RTP + 1: fresh SRTP and SRTCP from B.
        let srtp = SrtpProtect::new(&b_send)
            .protect_rtp(&RtpPacket::new(
                RtpHeader::new(0, 500, 900, B_SSRC),
                vec![0xA5; 160],
            ))
            .unwrap();
        c.peer_b.send_to(&srtp, c.b_relay_rtcp).await.unwrap();
        assert_silent("SRTP to B RTP + 1", &c.peer_a, &c.peer_a_rtcp).await;
        let p = SrtpProtect::new(&b_send)
            .protect_rtcp(&rtcp_rr_from(B_SSRC, 0x44))
            .unwrap();
        c.peer_b.send_to(&p, c.b_relay_rtcp).await.unwrap();
        assert_silent("SRTCP to B RTP + 1", &c.peer_a, &c.peer_a_rtcp).await;

        c.stop().await;
    }

    // NIST 800-53 Rev5: CM-7 -- once the terminated call is relaying, the
    // relay holds no A-leg or B-leg RTP + 1 socket (both stay bindable).
    #[tokio::test]
    async fn terminate_binds_no_rtp_plus_one_port() {
        let c = terminated_call("nobind").await;

        for (leg, addr) in [("A", c.a_relay_rtcp), ("B", c.b_relay_rtcp)] {
            let r = UdpSocket::bind(addr).await;
            assert!(
                r.is_ok(),
                "{leg}-leg RTP + 1 port {addr} is bound by the relay: {:?}",
                r.err()
            );
        }
        c.stop().await;
    }
}
