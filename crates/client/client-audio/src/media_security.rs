//! Media security mode for the audio pipeline (fail-closed SRTP gate).
//!
//! A pipeline can only be built from a [`MediaSecurity`] value. In a default
//! build the only variant is [`MediaSecurity::Srtp`], so plaintext RTP cannot
//! be constructed at all; `MediaSecurity::Plaintext` exists only behind the
//! `insecure-rtp` feature (lab / UDP-TCP accounts).
//!
//! ```compile_fail
//! # // Fails to compile unless the `insecure-rtp` feature is enabled.
//! # #[cfg(feature = "insecure-rtp")] compile_error!("feature enabled");
//! let _ = client_audio::MediaSecurity::Plaintext;
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8 / SC-8(1)**: media confidentiality; no plaintext RTP path in
//!   default builds (fail closed).
//! - **SC-13**: `AEAD_AES_256_GCM` only (CNSA 2.0).
//! - **SC-12**: key management -- key halves held in `Zeroizing` (wiped on
//!   drop), private fields, redacted `Debug`, no `Clone`.
//! - **CM-7**: plaintext media only under an explicit build feature.
//! - **SC-13 / SC-23**: [`SrtpCallState`] carries what must outlive one
//!   audio pipeline while the master keys stay the same: the receive
//!   side's rollover counter, highest sequence number and replay windows
//!   (RFC 3711 §3.3.1, §3.3.2), the transmit side's SSRC, packet index
//!   and SRTCP index (RFC 3711 §3.2.3, §3.3.1), and the transmit SSRCs
//!   already used (RFC 7714 §8.4: an (SSRC, index) pair is never used
//!   twice under one key).
//!
//! ## RFC Compliance
//!
//! - RFC 5764 §4.1: media on a DTLS-SRTP stream MUST be SRTP.
//! - RFC 5764 §4.2: separate client-write / server-write keys per direction.
//! - RFC 7714: AES-256-GCM SRTP/SRTCP.
//! - RFC 3711 §3.3.1 / §3.3.2 / §9.1: the receiver's index estimate and
//!   replay list belong to the cryptographic context, which lives as long
//!   as the master key, not as long as an audio pipeline.
//! - RFC 3711 §3.2.3 / §3.3.1: the sender keeps its SSRC, rollover counter
//!   and sequence number for as long as it sends under one master key; a
//!   restarted pipeline goes on where the last one stopped.

use crate::{AudioError, AudioResult};
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;
use zeroize::Zeroizing;

/// AES-256-GCM master key length (RFC 7714 §12).
pub const SRTP_KEY_LEN: usize = 32;
/// AES-256-GCM master salt length (RFC 7714 §12).
pub const SRTP_SALT_LEN: usize = 12;

/// Security mode for one media stream.
#[derive(Debug)]
pub enum MediaSecurity {
    /// SRTP/SRTCP with per-direction keys. Always available.
    Srtp(SrtpSessionKeys),
    /// Plaintext RTP/RTCP. Only for lab / non-TLS accounts.
    #[cfg(feature = "insecure-rtp")]
    Plaintext,
}

/// Per-direction SRTP master keys and salts, e.g. resolved from a DTLS-SRTP
/// export by the final DTLS role (RFC 5764 §4.2).
///
/// Not `Clone`; `Debug` never prints key bytes; buffers are wiped on drop.
pub struct SrtpSessionKeys {
    /// SRTP protection profile. Only `AeadAes256Gcm` is accepted (CNSA 2.0).
    profile: SrtpProfile,
    /// Master key for media we send.
    tx_key: Zeroizing<Vec<u8>>,
    /// Master salt for media we send.
    tx_salt: Zeroizing<Vec<u8>>,
    /// Master key for media we receive.
    rx_key: Zeroizing<Vec<u8>>,
    /// Master salt for media we receive.
    rx_salt: Zeroizing<Vec<u8>>,
    /// The call's SRTP state, when these keys are used by more than one
    /// pipeline (see [`SrtpSessionKeys::with_call_state`]).
    call_state: Option<SrtpCallState>,
}

/// SRTP state of one call that must outlive a single audio pipeline.
///
/// A call's audio pipeline is stopped and started again during the call
/// (codec change or new remote address in a re-INVITE, hold and resume),
/// each time from the same DTLS-SRTP master keys. Two things must then
/// not start from zero:
///
/// - **Receive side** (RFC 3711 §3.3.1, §3.3.2): the rollover counter and
///   highest sequence number, without which packets of a stream that has
///   wrapped its 16-bit sequence number no longer authenticate, and the
///   SRTP and SRTCP replay windows, without which a packet recorded before
///   the restart is accepted again after it. The inbound contexts are
///   created once and every pipeline of the call uses the same two.
/// - **Transmit side** (RFC 3711 §3.2.3, §3.3.1; RFC 7714 §8.4): the
///   outbound SRTP and SRTCP contexts and the SSRC are created once and
///   every pipeline of the call sends with the same ones. A restarted
///   pipeline goes on at the context's highest sent sequence number plus
///   one ([`SrtpContextSet::tx_resume`]), so the peer sees one stream
///   whose rollover counter it already knows, and the SRTCP index goes
///   on counting. Starting again with a new SSRC and a random sequence
///   number would be safe for the nonce but a receiver that keeps one
///   context per association (the SBC's leg, this client) would judge
///   the new stream against the old one's rollover counter and drop it.
///
/// Create one per call when its keys are established, attach a clone to
/// each [`SrtpSessionKeys`] built for that call
/// ([`SrtpSessionKeys::with_call_state`]) and drop it with the call. If
/// keys other than the ones it was first used with are presented (a new
/// DTLS association), both directions start afresh for them.
///
/// Invariant: at most one live transmitter per call. The pipelines of a
/// call must use the state one after the other, never two at once: the
/// contexts stay memory-safe under concurrent use, but the index estimate
/// and its update are not one atomic step, and a second transmitter
/// starts at the highest sequence number sent plus one on the same SSRC
/// and context, so two of them would seal different packets under one
/// (SSRC, index) pair, which repeats an AES-GCM nonce (RFC 7714 §8.4,
/// §9). This is enforced, not left to the caller: building contexts from
/// the state ([`build_srtp_contexts`]) claims the outbound stream
/// ([`TransmitClaim`]) and a second claim is refused with
/// [`AudioError::SrtpError`] (no audio start) until the first is dropped,
/// which the transmitter holding it does when it goes away. Resolving an
/// SSRC collision does not claim: it is done by the I/O thread that owns
/// the one transmitter.
///
/// Used when a pipeline starts or stops or resolves an SSRC collision;
/// never per packet. Cloning shares the state.
///
/// It keeps the transmit master key and salt for the life of the call
/// (wiped on drop, never printed), which a new outbound context after an
/// SSRC collision is derived from.
///
/// NIST 800-53 Rev5: SC-13, SC-23 (replay protection, nonce uniqueness
/// -- one transmitter at a time, enforced by the claim -- and one
/// continuous cryptographic context per direction across pipeline
/// restarts), SC-12 (transmit key material wiped on drop). The first SSRC
/// comes from `uc-crypto`'s DRBG.
// POAM: POA&M-338 -- what is left: (1) there is one receive context per
// call, not one per remote SSRC (a `proto-srtp` property, shared with the
// SBC): a peer that restarts its own stream with a new SSRC and a rollover
// counter of zero after the old stream had wrapped is not followed (its
// packets fail authentication; nothing is accepted that should not be).
// (2) After an SSRC collision (RFC 3550 §8.2) the new SSRC starts a new
// outbound SRTP context with a rollover counter of zero, as RFC 3711
// §3.2.3 requires of a new source; a peer with one context per
// association (the SBC) that has already counted a rollover for the old
// SSRC then drops the new stream until signalling ends the call. (3) The
// RTCP statistics start from zero in each pipeline although the SSRC goes
// on: the packet and octet counts in sender reports, and the cumulative
// loss and extended highest sequence number in receiver reports (RFC 3550
// §6.4.1, §6.4.2). (4) No test through `AudioPipeline::start` with audio
// devices. (5) Deliberate deviation from RFC 7160 §4.1: a restart that
// changes the RTP clock rate (G.711 or G.722 at 8000 to or from Opus at
// 48000) keeps the SSRC, where a sender with RTCP is to use a different
// SSRC per clock rate. The timestamp goes on from the old stream's value
// plus the pause counted at the new rate, with the marker bit. Reason: a
// new SSRC needs a new outbound context at rollover zero (RFC 3711
// §3.2.3), which a peer with one context per association (the SBC's leg)
// that has counted a rollover does not follow, see (2): keeping the SSRC
// costs the receiver one wrong jitter and sender-report mapping across
// the switch, a new SSRC would cost the audio. Pinned by the test
// `clock_rate_change_keeps_the_ssrc`. To be revisited with per-SSRC
// receive contexts.
#[derive(Clone)]
pub struct SrtpCallState {
    inner: Arc<CallStateInner>,
}

struct CallStateInner {
    /// The inbound contexts every pipeline of the call shares.
    inbound: Mutex<Option<InboundContexts>>,
    /// The outbound stream every pipeline of the call continues.
    outbound: Mutex<Option<OutboundStream>>,
    /// Where the last transmitter of the call stopped in RTP time.
    tx_clock: Mutex<Option<TxClock>>,
    /// The first transmit SSRC of the call (random).
    ssrc_base: u32,
    /// How many transmit SSRCs were handed out.
    ssrcs_used: AtomicU64,
    /// Set while a [`TransmitClaim`] on the outbound stream is alive.
    /// Written at a pipeline start and when its transmitter is dropped,
    /// never per packet.
    tx_in_use: AtomicBool,
}

/// The inbound SRTP and SRTCP contexts of a call.
#[derive(Clone)]
struct InboundContexts {
    rtp: Arc<SrtpContext>,
    rtcp: Arc<SrtpContext>,
}

/// The outbound SRTP and SRTCP contexts of a call and the SSRC they are
/// used with.
struct OutboundStream {
    rtp: Arc<SrtpContext>,
    rtcp: Arc<SrtpContext>,
    ssrc: u32,
    /// The transmit master key and salt, for the new SRTP context an SSRC
    /// collision needs. Wiped on drop (`proto-srtp`).
    material: SrtpKeyMaterial,
}

/// The RTP timestamp the call's last transmitter would have used next,
/// and when it stopped.
#[derive(Clone, Copy)]
struct TxClock {
    timestamp: u32,
    stopped: Instant,
}

/// What a pipeline's transmitter is built from: the call's outbound
/// contexts, the SSRC in force and, when an earlier pipeline of the call
/// already sent with them, the sequence number to go on with.
struct OutboundSelection {
    rtp: Arc<SrtpContext>,
    rtcp: Arc<SrtpContext>,
    ssrc: u32,
    resume: Option<u16>,
    /// The claim on the call's outbound stream; `None` without a call
    /// state (nothing is shared then).
    claim: Option<TransmitClaim>,
}

/// The exclusive use of a call's outbound SRTP stream.
///
/// It lasts from [`build_srtp_contexts`] until it is dropped. The
/// transmitter that sends with the stream holds it
/// ([`crate::rtp_handler::RtpTransmitter::start_srtp`]); while it lives no
/// second set of contexts can be built from the call's state.
///
/// RFC 7714 §8.4: two transmitters on one SSRC and context would use an
/// (SSRC, index) pair, and so a nonce, twice. NIST 800-53 Rev5: SC-13.
pub struct TransmitClaim {
    state: SrtpCallState,
}

impl Drop for TransmitClaim {
    fn drop(&mut self) {
        // Once per pipeline, off the packet path.
        self.state.inner.tx_in_use.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for TransmitClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransmitClaim").finish_non_exhaustive()
    }
}

/// A new transmit SSRC after a collision (RFC 3550 §8.2), with the
/// outbound SRTP context that belongs to it.
pub struct CollisionSsrc {
    /// The new SSRC; this call has not sent with it before.
    pub ssrc: u32,
    /// The new outbound SRTP context for it (rollover counter zero, RFC
    /// 3711 §3.2.3). `None` when the call has no outbound contexts yet.
    pub rtp_tx: Option<Arc<SrtpContext>>,
}

impl std::fmt::Debug for SrtpCallState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No SSRC and nothing of the contexts: counters only.
        f.debug_struct("SrtpCallState")
            .field("ssrcs_used", &self.inner.ssrcs_used.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SrtpCallState {
    /// Creates the state for one call.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] if the random generator fails.
    pub fn new() -> AudioResult<Self> {
        Ok(Self {
            inner: Arc::new(CallStateInner {
                inbound: Mutex::new(None),
                outbound: Mutex::new(None),
                tx_clock: Mutex::new(None),
                ssrc_base: random_ssrc()?,
                ssrcs_used: AtomicU64::new(0),
                tx_in_use: AtomicBool::new(false),
            }),
        })
    }

    /// Returns a transmit SSRC that this call has not used before.
    ///
    /// The first is random; each further one is the previous plus one
    /// (wrapping), so 2^32 distinct values are handed out before the
    /// space is used up, and none twice.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] once all 2^32 SSRCs were used:
    /// the caller must not send under these keys with a repeated SSRC
    /// (RFC 7714 §8.4).
    pub fn next_local_ssrc(&self) -> AudioResult<u32> {
        // A 64-bit count of calls: it cannot wrap, and the first 2^32
        // values are the offsets that are still free.
        let used = self.inner.ssrcs_used.fetch_add(1, Ordering::Relaxed);
        let offset = u32::try_from(used).map_err(|_| {
            AudioError::SrtpError("no unused SSRC left for this call's SRTP keys".to_string())
        })?;
        Ok(self.inner.ssrc_base.wrapping_add(offset))
    }

    /// The SSRC a pipeline that is about to start sends with: the one the
    /// call's outbound stream already has, or a new one if the call has
    /// not sent yet.
    ///
    /// # Errors
    /// As [`Self::next_local_ssrc`].
    pub fn transmit_ssrc(&self) -> AudioResult<u32> {
        let kept = self
            .inner
            .outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|stream| stream.ssrc);
        kept.map_or_else(|| self.next_local_ssrc(), Ok)
    }

    /// Resolves an SSRC collision (RFC 3550 §8.2): a transmit SSRC the
    /// call has not used, and a new outbound SRTP context for it, which
    /// becomes the call's. The outbound SRTCP context is kept: its index
    /// travels in every packet, so it goes on counting under the new SSRC.
    ///
    /// RFC 3711 §3.2.3: the rollover counter belongs to the SSRC, so the
    /// new source starts at zero. The transmitter keeps its sequence
    /// number. See POA&M-338 (2) on [`SrtpCallState`] for the receiver
    /// this does not suit.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] if no unused SSRC is left or the
    /// context cannot be derived; the caller then keeps its SSRC.
    pub fn ssrc_after_collision(&self) -> AudioResult<CollisionSsrc> {
        let ssrc = self.next_local_ssrc()?;
        let mut outbound = self
            .inner
            .outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let rtp_tx = match outbound.as_mut() {
            Some(stream) => {
                let context = Arc::new(new_context(
                    &stream.material,
                    SrtpDirection::Outbound,
                    ssrc,
                )?);
                stream.rtp = Arc::clone(&context);
                stream.ssrc = ssrc;
                Some(context)
            }
            None => None,
        };
        drop(outbound);
        Ok(CollisionSsrc { ssrc, rtp_tx })
    }

    /// Records where a transmitter of the call stopped: the RTP timestamp
    /// it would have used next. Called once when the transmitter goes
    /// away, not per packet.
    pub fn note_transmit_stopped(&self, next_timestamp: u32) {
        *self
            .inner
            .tx_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(TxClock {
            timestamp: next_timestamp,
            stopped: Instant::now(),
        });
    }

    /// The RTP timestamp for the first packet of a transmitter that
    /// continues the call's stream: where the last one stopped plus the
    /// time since then at `clock_rate` (RFC 3550 §5.1: the timestamp of
    /// one SSRC advances with the sampling clock, also across a pause).
    /// `None` if no transmitter of the call has stopped yet.
    #[must_use]
    pub fn resume_timestamp(&self, clock_rate: u32) -> Option<u32> {
        let clock = (*self
            .inner
            .tx_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner))?;
        let ticks = clock.stopped.elapsed().as_millis() * u128::from(clock_rate) / 1000;
        // RTP timestamps are modulo 2^32.
        let ticks = u32::try_from(ticks % (1_u128 << 32)).unwrap_or(0);
        Some(clock.timestamp.wrapping_add(ticks))
    }

    /// Claims the call's outbound stream for one transmitter.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] while an earlier claim is alive
    /// (fail closed: the caller starts no audio).
    fn claim_transmit(&self) -> AudioResult<TransmitClaim> {
        // RFC 7714 §8.4; NIST 800-53 Rev5: SC-13 -- a second transmitter
        // would repeat the first one's (SSRC, index) pairs under one key.
        self.inner
            .tx_in_use
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                AudioError::SrtpError(
                    "the call's outbound SRTP stream is in use by another transmitter".to_string(),
                )
            })?;
        Ok(TransmitClaim {
            state: self.clone(),
        })
    }

    /// Returns the call's outbound stream if its contexts were derived
    /// from `material`, with the sequence number to go on with; otherwise
    /// starts a new stream with `ssrc`, which becomes the call's. Either
    /// way the stream is claimed for the caller's transmitter.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] if the stream is claimed already
    /// (the call's state is then left as it was) or a context cannot be
    /// derived.
    fn outbound_for(
        &self,
        material: &SrtpKeyMaterial,
        ssrc: u32,
    ) -> AudioResult<OutboundSelection> {
        // Before anything is read or replaced; released again on every
        // error path below (drop).
        let claim = self.claim_transmit()?;
        // First pipeline of the call, or another association's keys.
        let fresh = OutboundStream {
            rtp: Arc::new(new_context(material, SrtpDirection::Outbound, ssrc)?),
            rtcp: Arc::new(new_context(material, SrtpDirection::Outbound, ssrc)?),
            ssrc,
            material: material.clone(),
        };
        let mut outbound = self
            .inner
            .outbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let selection = match outbound.as_ref() {
            Some(kept) if same_session_keys(&kept.rtp, &fresh.rtp) => {
                // RFC 3711 §3.3.1: the low 16 bits of the highest index
                // sent, plus one; the context supplies the rollover.
                let last = kept.rtp.highest_rtp_index() & 0xFFFF;
                OutboundSelection {
                    rtp: Arc::clone(&kept.rtp),
                    rtcp: Arc::clone(&kept.rtcp),
                    ssrc: kept.ssrc,
                    resume: Some(u16::try_from(last).unwrap_or(0).wrapping_add(1)),
                    claim: Some(claim),
                }
            }
            _ => {
                let selection = OutboundSelection {
                    rtp: Arc::clone(&fresh.rtp),
                    rtcp: Arc::clone(&fresh.rtcp),
                    ssrc,
                    resume: None,
                    claim: Some(claim),
                };
                *outbound = Some(fresh);
                selection
            }
        };
        drop(outbound);
        if selection.resume.is_none() {
            // A timestamp of the old keys' stream is not continued.
            *self
                .inner
                .tx_clock
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
        }
        Ok(selection)
    }

    /// Returns the call's inbound contexts if they were derived from the
    /// same master key and salt as `fresh`, and otherwise makes `fresh`
    /// the call's inbound contexts and returns those.
    ///
    /// The comparison is of the derived session keys and salts, in
    /// constant time; no key byte is kept outside the contexts.
    fn inbound_for(&self, fresh: InboundContexts) -> InboundContexts {
        let mut inbound = self
            .inner
            .inbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(kept) = inbound.as_ref()
            && same_session_keys(&kept.rtp, &fresh.rtp)
            && same_session_keys(&kept.rtcp, &fresh.rtcp)
        {
            return kept.clone();
        }
        *inbound = Some(fresh.clone());
        fresh
    }
}

/// Whether two contexts hold the same session keys and salts (and so come
/// from the same master key and salt). Constant time in the key bytes.
fn same_session_keys(a: &SrtpContext, b: &SrtpContext) -> bool {
    use uc_crypto::constant_time::eq;
    // `&` rather than `&&`: every comparison runs.
    eq(a.rtp_key(), b.rtp_key())
        & eq(a.rtp_salt(), b.rtp_salt())
        & eq(a.rtcp_key(), b.rtcp_key())
        & eq(a.rtcp_salt(), b.rtcp_salt())
}

/// Derives one SRTP context.
fn new_context(
    material: &SrtpKeyMaterial,
    direction: SrtpDirection,
    ssrc: u32,
) -> AudioResult<SrtpContext> {
    SrtpContext::new(material, direction, ssrc)
        .map_err(|e| AudioError::SrtpError(format!("failed to create SRTP context: {e}")))
}

/// A random SSRC from `uc-crypto`'s DRBG (RFC 3550 §8.1).
fn random_ssrc() -> AudioResult<u32> {
    uc_crypto::random::generate_random::<4>()
        .map(u32::from_be_bytes)
        .map_err(|_| AudioError::SrtpError("random generation failed".to_string()))
}

impl std::fmt::Debug for SrtpSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpSessionKeys")
            .field("profile", &self.profile)
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SrtpSessionKeys {
    /// Wraps per-direction key material. Call [`Self::validate`] (or
    /// [`build_srtp_contexts`], which does) before use.
    #[must_use]
    pub const fn new(
        profile: SrtpProfile,
        tx_key: Zeroizing<Vec<u8>>,
        tx_salt: Zeroizing<Vec<u8>>,
        rx_key: Zeroizing<Vec<u8>>,
        rx_salt: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            profile,
            tx_key,
            tx_salt,
            rx_key,
            rx_salt,
            call_state: None,
        }
    }

    /// Attaches the call's SRTP state. Required whenever more than one
    /// pipeline is started from the same keys during a call: without it
    /// every pipeline starts with an empty replay window, a rollover
    /// counter of zero and a new outbound stream (random SSRC, sequence
    /// number and SRTCP index from the start).
    #[must_use]
    pub fn with_call_state(mut self, state: SrtpCallState) -> Self {
        self.call_state = Some(state);
        self
    }

    /// The call's SRTP state, if one is attached.
    #[must_use]
    pub const fn call_state(&self) -> Option<&SrtpCallState> {
        self.call_state.as_ref()
    }

    /// The transmit SSRC for a pipeline that is about to start with these
    /// keys: the SSRC of the call's outbound stream when the call's state
    /// is attached and has one (RFC 3711 §3.2.3: the stream goes on), a
    /// new one otherwise.
    ///
    /// # Errors
    /// As [`Self::next_local_ssrc`].
    pub fn transmit_ssrc(&self) -> AudioResult<u32> {
        self.call_state
            .as_ref()
            .map_or_else(random_ssrc, SrtpCallState::transmit_ssrc)
    }

    /// A transmit SSRC that has not been used with these keys: one the
    /// call has not used before when the call's state is attached, a
    /// random one otherwise.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] if the call's SSRCs are used up
    /// or random generation fails.
    pub fn next_local_ssrc(&self) -> AudioResult<u32> {
        self.call_state
            .as_ref()
            .map_or_else(random_ssrc, SrtpCallState::next_local_ssrc)
    }

    /// SRTP protection profile.
    #[must_use]
    pub const fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Master key for media we send.
    #[must_use]
    pub fn tx_key(&self) -> &[u8] {
        &self.tx_key
    }

    /// Master salt for media we send.
    #[must_use]
    pub fn tx_salt(&self) -> &[u8] {
        &self.tx_salt
    }

    /// Master key for media we receive.
    #[must_use]
    pub fn rx_key(&self) -> &[u8] {
        &self.rx_key
    }

    /// Master salt for media we receive.
    #[must_use]
    pub fn rx_salt(&self) -> &[u8] {
        &self.rx_salt
    }

    /// Validates profile and key/salt lengths without touching any I/O.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] for a non-CNSA profile or a key or
    /// salt of the wrong length.
    pub fn validate(&self) -> AudioResult<()> {
        // CNSA 2.0: AES-256-GCM only.
        if self.profile != SrtpProfile::AeadAes256Gcm {
            return Err(AudioError::SrtpError(
                "only AEAD_AES_256_GCM is permitted (CNSA 2.0)".to_string(),
            ));
        }
        if self.tx_key.len() != SRTP_KEY_LEN || self.rx_key.len() != SRTP_KEY_LEN {
            return Err(AudioError::SrtpError(
                "SRTP master key must be 32 bytes".to_string(),
            ));
        }
        if self.tx_salt.len() != SRTP_SALT_LEN || self.rx_salt.len() != SRTP_SALT_LEN {
            return Err(AudioError::SrtpError(
                "SRTP master salt must be 12 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// Independent SRTP/SRTCP contexts for one stream. Each context owns its
/// own index and replay state, so RTP and RTCP never share mutable state.
///
/// The contexts are reference-counted: with a [`SrtpCallState`] attached
/// to the keys they are the call's, used by every pipeline of the call in
/// turn.
pub struct SrtpContextSet {
    /// Outbound RTP.
    pub rtp_tx: Arc<SrtpContext>,
    /// Inbound RTP.
    pub rtp_rx: Arc<SrtpContext>,
    /// Outbound RTCP (SRTCP).
    pub rtcp_tx: Arc<SrtpContext>,
    /// Inbound RTCP (SRTCP).
    pub rtcp_rx: Arc<SrtpContext>,
    /// The SSRC the outbound contexts are used with. With a call state
    /// that already holds an outbound stream for these keys this is the
    /// call's SSRC, not the one passed to [`build_srtp_contexts`].
    pub local_ssrc: u32,
    /// `Some(sequence number)` when the outbound contexts continue a
    /// stream an earlier pipeline of the call sent: the transmitter must
    /// start there (highest sequence number sent, plus one) and set the
    /// marker bit on its first packet
    /// ([`crate::rtp_handler::RtpTransmitter::continue_stream`]). `None`
    /// for a new stream, which may start anywhere.
    pub tx_resume: Option<u16>,
    /// The claim on the call's outbound stream, `Some` whenever the keys
    /// carry a [`SrtpCallState`]. Give it to the transmitter that sends
    /// with `rtp_tx`
    /// ([`crate::rtp_handler::RtpTransmitter::start_srtp`]); until it is
    /// dropped no further set can be built from the call's state.
    pub tx_claim: Option<TransmitClaim>,
}

/// Builds the four SRTP contexts for a stream from validated keys.
///
/// `local_ssrc` is the transmit SSRC for a new outbound stream; take it
/// from [`SrtpSessionKeys::transmit_ssrc`]. When the keys carry a
/// [`SrtpCallState`] that already holds contexts for the same keys, the
/// call's contexts are returned instead of new ones, in both directions:
///
/// - inbound (RFC 3711 §3.3.1, §3.3.2): the index estimate and the replay
///   windows continue;
/// - outbound (RFC 3711 §3.2.3, §3.3.1): the SSRC, the rollover counter
///   and the SRTCP index continue, and [`SrtpContextSet::tx_resume`] says
///   at which sequence number.
///
/// With a call state the outbound stream is claimed for one transmitter
/// ([`SrtpContextSet::tx_claim`]): while a set built earlier from the same
/// state, or the transmitter it went to, is alive, this fails.
///
/// # Errors
/// Returns [`AudioError::SrtpError`] if validation or key derivation
/// fails, or if the call's outbound stream is in use by another
/// transmitter (RFC 7714 §8.4; NIST 800-53 Rev5: SC-13).
pub fn build_srtp_contexts(keys: &SrtpSessionKeys, local_ssrc: u32) -> AudioResult<SrtpContextSet> {
    keys.validate()?;
    let material = |key: &[u8], salt: &[u8]| {
        SrtpKeyMaterial::new(keys.profile, key.to_vec(), salt.to_vec())
            .map_err(|e| AudioError::SrtpError(format!("invalid SRTP key material: {e}")))
    };
    let tx = material(&keys.tx_key, &keys.tx_salt)?;
    let rx = material(&keys.rx_key, &keys.rx_salt)?;
    let fresh = InboundContexts {
        rtp: Arc::new(new_context(&rx, SrtpDirection::Inbound, 0)?),
        rtcp: Arc::new(new_context(&rx, SrtpDirection::Inbound, 0)?),
    };
    // NIST 800-53 Rev5: SC-23 -- under the same keys the state of the call
    // goes on in both directions; it is never reset by a pipeline restart.
    let (inbound, outbound) = match &keys.call_state {
        Some(state) => {
            // Outbound first: a refused claim leaves the call's state,
            // inbound contexts included, as it was.
            let outbound = state.outbound_for(&tx, local_ssrc)?;
            (state.inbound_for(fresh), outbound)
        }
        None => (
            fresh,
            OutboundSelection {
                rtp: Arc::new(new_context(&tx, SrtpDirection::Outbound, local_ssrc)?),
                rtcp: Arc::new(new_context(&tx, SrtpDirection::Outbound, local_ssrc)?),
                ssrc: local_ssrc,
                resume: None,
                claim: None,
            },
        ),
    };
    Ok(SrtpContextSet {
        rtp_tx: outbound.rtp,
        rtp_rx: inbound.rtp,
        rtcp_tx: outbound.rtcp,
        rtcp_rx: inbound.rtcp,
        local_ssrc: outbound.ssrc,
        tx_resume: outbound.resume,
        tx_claim: outbound.claim,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Keys shaped like a DTLS-SRTP export (RFC 5764 §4.2): `a` is the
    /// client-write half, `b` the server-write half.
    pub fn keys(tx: u8, rx: u8) -> SrtpSessionKeys {
        SrtpSessionKeys::new(
            SrtpProfile::AeadAes256Gcm,
            Zeroizing::new(vec![tx; SRTP_KEY_LEN]),
            Zeroizing::new(vec![tx ^ 0x5A; SRTP_SALT_LEN]),
            Zeroizing::new(vec![rx; SRTP_KEY_LEN]),
            Zeroizing::new(vec![rx ^ 0x5A; SRTP_SALT_LEN]),
        )
    }

    #[test]
    fn wrong_lengths_rejected() {
        let mut k = keys(1, 2);
        k.tx_key = Zeroizing::new(vec![0; 16]);
        assert!(k.validate().is_err());
        assert!(build_srtp_contexts(&k, 1).is_err());

        let mut k = keys(1, 2);
        k.rx_salt = Zeroizing::new(vec![0; 14]);
        assert!(k.validate().is_err());

        keys(1, 2).validate().unwrap();
    }

    #[test]
    fn debug_is_redacted() {
        let s = format!("{:?}", keys(0xAB, 0xCD));
        assert!(s.contains("redacted"));
        assert!(!s.contains("171"), "key byte value leaked: {s}");
        let state = SrtpCallState::new().unwrap();
        let ssrc = state.next_local_ssrc().unwrap();
        let s = format!(
            "{:?} {state:?}",
            keys(0xAB, 0xCD).with_call_state(state.clone())
        );
        assert!(!s.contains("171"), "key byte value leaked: {s}");
        assert!(!s.contains(&ssrc.to_string()), "SSRC in debug output: {s}");
    }

    /// RFC 7714 §8.4: the transmit SSRCs of one call never repeat, and
    /// when none is left the caller gets an error, not a reused one.
    #[test]
    fn call_state_never_hands_out_an_ssrc_twice() {
        let state = SrtpCallState::new().unwrap();
        let shared = keys(1, 2).with_call_state(state.clone());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(state.next_local_ssrc().unwrap()));
            assert!(seen.insert(shared.next_local_ssrc().unwrap()));
        }
        // All 2^32 used.
        state
            .inner
            .ssrcs_used
            .store(u64::from(u32::MAX) + 1, Ordering::Relaxed);
        assert!(state.next_local_ssrc().is_err());
        assert!(shared.next_local_ssrc().is_err());
        // Without a call state the SSRC is random and always available.
        keys(1, 2).next_local_ssrc().unwrap();
    }

    /// RFC-011 (RFC 3711 §3.2.3): the call's outbound contexts and SSRC
    /// are kept for the same keys, with the sequence number to go on
    /// with, and replaced for other keys.
    #[test]
    fn call_state_keeps_the_outbound_stream_per_key() {
        use proto_srtp::SrtpProtect;
        let state = SrtpCallState::new().unwrap();
        // One pipeline after the other: each set's claim on the outbound
        // stream is given up here, as when its transmitter is dropped.
        let build = |tx, rx| {
            let keys = keys(tx, rx).with_call_state(state.clone());
            let mut set = build_srtp_contexts(&keys, keys.transmit_ssrc().unwrap()).unwrap();
            assert!(set.tx_claim.take().is_some());
            set
        };
        let first = build(1, 2);
        assert_eq!(first.tx_resume, None, "a new stream has nothing to resume");
        // The first pipeline sends sequence numbers 0xFFFE, 0xFFFF, 0.
        for seq in [0xFFFE_u16, 0xFFFF, 0] {
            let header = proto_rtp::RtpHeader::new(0, seq, 0, first.local_ssrc);
            SrtpProtect::new(&first.rtp_tx)
                .protect_rtp_parts(&header, &[0; 160])
                .unwrap();
        }
        let second = build(1, 2);
        assert!(Arc::ptr_eq(&first.rtp_tx, &second.rtp_tx));
        assert!(Arc::ptr_eq(&first.rtcp_tx, &second.rtcp_tx));
        assert!(!Arc::ptr_eq(&first.rtp_tx, &first.rtcp_tx));
        assert_eq!(second.local_ssrc, first.local_ssrc);
        assert_eq!(second.tx_resume, Some(1));
        assert_eq!(second.rtp_tx.highest_rtp_index(), 0x1_0000);
        // An SSRC passed in is not used while the call has a stream.
        let keys12 = keys(1, 2).with_call_state(state.clone());
        let third = build_srtp_contexts(&keys12, first.local_ssrc ^ 1).unwrap();
        assert_eq!(third.local_ssrc, first.local_ssrc);
        drop(third);

        // Another association's keys: a new outbound stream, which is
        // then the call's.
        let rekeyed = build(3, 2);
        assert!(!Arc::ptr_eq(&first.rtp_tx, &rekeyed.rtp_tx));
        assert_eq!(rekeyed.tx_resume, None);
        assert_ne!(first.rtp_tx.rtp_key(), rekeyed.rtp_tx.rtp_key());
        assert!(Arc::ptr_eq(&rekeyed.rtp_tx, &build(3, 2).rtp_tx));

        // Without a call state nothing is shared.
        let a = build_srtp_contexts(&keys(1, 2), 7).unwrap();
        let b = build_srtp_contexts(&keys(1, 2), 7).unwrap();
        assert!(!Arc::ptr_eq(&a.rtp_tx, &b.rtp_tx));
        assert_eq!((a.local_ssrc, a.tx_resume), (7, None));
        assert!(a.tx_claim.is_none() && b.tx_claim.is_none());
    }

    /// SEC-017 / NIST-019 (RFC 7714 §8.4): one live transmitter per call.
    /// While a set built from the call's state (or the transmitter its
    /// claim went to) is alive, a second set is refused, also for other
    /// keys, and the call's state is left as it was; once the claim is
    /// dropped the next set continues the stream at the highest sequence
    /// number sent plus one.
    #[test]
    fn second_transmit_claim_is_refused_while_the_first_lives() {
        use proto_srtp::SrtpProtect;
        let state = SrtpCallState::new().unwrap();
        let build = |tx, rx| {
            let keys = keys(tx, rx).with_call_state(state.clone());
            build_srtp_contexts(&keys, keys.transmit_ssrc()?)
        };
        let first = build(1, 2).unwrap();
        assert!(first.tx_claim.is_some());
        for seq in [0xFFFE_u16, 0xFFFF, 0] {
            let header = proto_rtp::RtpHeader::new(0, seq, 0, first.local_ssrc);
            SrtpProtect::new(&first.rtp_tx)
                .protect_rtp_parts(&header, &[0; 160])
                .unwrap();
        }

        // Same keys: refused, fail closed.
        assert!(matches!(build(1, 2), Err(AudioError::SrtpError(_))));
        // Another association's keys, either direction: refused as well,
        // and neither direction of the call's state was replaced.
        assert!(matches!(build(3, 4), Err(AudioError::SrtpError(_))));
        // A refusal does not release the first claim.
        assert!(matches!(build(1, 2), Err(AudioError::SrtpError(_))));
        // The SSRC collision path belongs to the claim's holder and is
        // not a second claim (covered in
        // `ssrc_collision_starts_a_new_outbound_srtp_context`).

        let (rtp_tx, rtp_rx, ssrc) = (
            Arc::clone(&first.rtp_tx),
            Arc::clone(&first.rtp_rx),
            first.local_ssrc,
        );
        drop(first);
        let second = build(1, 2).unwrap();
        assert!(Arc::ptr_eq(&second.rtp_tx, &rtp_tx));
        assert!(Arc::ptr_eq(&second.rtp_rx, &rtp_rx));
        assert_eq!(second.local_ssrc, ssrc);
        assert_eq!(second.tx_resume, Some(1), "highest sent (0) plus one");
        // A set that fails for another reason releases its claim too.
        drop(second);
        let mut bad = keys(1, 2).with_call_state(state.clone());
        bad.tx_key = Zeroizing::new(vec![0; 16]);
        assert!(build_srtp_contexts(&bad, 1).is_err());
        assert_eq!(build(1, 2).unwrap().tx_resume, Some(1));
    }

    /// RFC 3711 §3.4: the SRTCP index of the call goes on counting across
    /// a restart, so a peer with one SRTCP replay window for the
    /// association accepts the reports of every pipeline.
    #[test]
    fn srtcp_index_continues_across_a_restart() {
        use proto_srtp::{SrtpProtect, SrtpUnprotect};
        let state = SrtpCallState::new().unwrap();
        let ours = || {
            let keys = keys(2, 1).with_call_state(state.clone());
            build_srtp_contexts(&keys, keys.transmit_ssrc().unwrap()).unwrap()
        };
        let peer = build_srtp_contexts(&keys(1, 2), 0x1111).unwrap();
        let report = [0x80, 201, 0, 1, 0, 0, 0x22, 0x22];
        let index = |packet: &[u8]| {
            let tail: [u8; 4] = packet[packet.len() - 4..].try_into().unwrap();
            u32::from_be_bytes(tail) & 0x7FFF_FFFF
        };
        let mut indices = Vec::new();
        // More reports than the replay window is wide, over three
        // pipelines.
        for _ in 0..3 {
            let pipeline = ours();
            for _ in 0..100 {
                let packet = SrtpProtect::new(&pipeline.rtcp_tx)
                    .protect_rtcp(&report)
                    .unwrap();
                SrtpUnprotect::new(&peer.rtcp_rx)
                    .unprotect_rtcp_sync(&packet)
                    .unwrap();
                indices.push(index(&packet));
            }
        }
        assert!(indices.windows(2).all(|pair| pair[1] == pair[0] + 1));
        assert_eq!(indices.len(), 300);
    }

    /// RFC 3550 §8.2 / RFC 3711 §3.2.3: an SSRC collision gives the call
    /// a new SSRC with a new outbound SRTP context (rollover counter
    /// zero); the SRTCP context is kept; later pipelines continue the new
    /// stream.
    #[test]
    fn ssrc_collision_starts_a_new_outbound_srtp_context() {
        use proto_srtp::SrtpProtect;
        let state = SrtpCallState::new().unwrap();
        // Before the call has contexts: an unused SSRC, nothing else.
        let early = state.ssrc_after_collision().unwrap();
        assert!(early.rtp_tx.is_none());

        let build = || {
            let keys = keys(1, 2).with_call_state(state.clone());
            build_srtp_contexts(&keys, keys.transmit_ssrc().unwrap()).unwrap()
        };
        let first = build();
        assert!(first.tx_claim.is_some());
        assert_ne!(first.local_ssrc, early.ssrc);
        for seq in [0xFFFF_u16, 0, 1] {
            let header = proto_rtp::RtpHeader::new(0, seq, 0, first.local_ssrc);
            SrtpProtect::new(&first.rtp_tx)
                .protect_rtp_parts(&header, &[0; 160])
                .unwrap();
        }
        let collision = state.ssrc_after_collision().unwrap();
        let new_rtp = collision.rtp_tx.unwrap();
        assert_ne!(collision.ssrc, first.local_ssrc);
        assert!(!Arc::ptr_eq(&new_rtp, &first.rtp_tx));
        assert_eq!(new_rtp.highest_rtp_index(), 0);
        assert_eq!(new_rtp.rtp_key(), first.rtp_tx.rtp_key());

        // The collision was resolved while `first` held the claim on the
        // stream (as the I/O thread does for its own transmitter). The
        // next pipeline starts once that one is gone.
        let first_rtcp_tx = Arc::clone(&first.rtcp_tx);
        drop(first);
        let next = build();
        assert_eq!(next.local_ssrc, collision.ssrc);
        assert!(Arc::ptr_eq(&next.rtp_tx, &new_rtp));
        assert!(Arc::ptr_eq(&next.rtcp_tx, &first_rtcp_tx));
        assert_eq!(next.tx_resume, Some(1));
    }

    /// The call's inbound contexts are kept for the same keys and replaced
    /// for other keys.
    #[test]
    fn call_state_keeps_inbound_contexts_per_key() {
        let state = SrtpCallState::new().unwrap();
        // One pipeline after the other: the claim on the outbound stream
        // is given up here, as when the set's transmitter is dropped.
        let build = |tx, rx| {
            let mut set =
                build_srtp_contexts(&keys(tx, rx).with_call_state(state.clone()), 1).unwrap();
            set.tx_claim = None;
            set
        };
        let first = build(1, 2);
        let second = build(1, 2);
        assert!(Arc::ptr_eq(&first.rtp_rx, &second.rtp_rx));
        assert!(Arc::ptr_eq(&first.rtcp_rx, &second.rtcp_rx));
        assert!(!Arc::ptr_eq(&first.rtp_rx, &first.rtcp_rx));

        // Another association's keys: new inbound state, which is then
        // the call's.
        let rekeyed = build(1, 3);
        assert!(!Arc::ptr_eq(&first.rtp_rx, &rekeyed.rtp_rx));
        assert_ne!(first.rtp_rx.rtp_key(), rekeyed.rtp_rx.rtp_key());
        assert!(Arc::ptr_eq(&rekeyed.rtp_rx, &build(1, 3).rtp_rx));

        // Without a call state nothing is shared.
        let a = build_srtp_contexts(&keys(1, 2), 1).unwrap();
        let b = build_srtp_contexts(&keys(1, 2), 1).unwrap();
        assert!(!Arc::ptr_eq(&a.rtp_rx, &b.rtp_rx));
    }

    /// RFC 3711 §3.3.2: the SRTCP replay window also belongs to the call.
    #[test]
    fn srtcp_replay_across_a_restart_is_refused() {
        use proto_srtp::{SrtpProtect, SrtpUnprotect};
        let state = SrtpCallState::new().unwrap();
        let ours = || build_srtp_contexts(&keys(2, 1).with_call_state(state.clone()), 9).unwrap();
        let peer = build_srtp_contexts(&keys(1, 2), 0x1111).unwrap();
        // A minimal receiver report (RFC 3550 §6.4.2): V=2, RR, length 1.
        let report = [0x80, 201, 0, 1, 0, 0, 0x11, 0x11];
        let recorded: Vec<_> = (0..3)
            .map(|_| {
                SrtpProtect::new(&peer.rtcp_tx)
                    .protect_rtcp(&report)
                    .unwrap()
            })
            .collect();

        let first = ours();
        for packet in &recorded {
            SrtpUnprotect::new(&first.rtcp_rx)
                .unprotect_rtcp_sync(packet)
                .unwrap();
        }
        drop(first);
        let second = ours();
        for packet in &recorded {
            assert!(
                SrtpUnprotect::new(&second.rtcp_rx)
                    .unprotect_rtcp_sync(packet)
                    .is_err(),
                "replayed SRTCP packet accepted after the restart"
            );
        }
        let next = SrtpProtect::new(&peer.rtcp_tx)
            .protect_rtcp(&report)
            .unwrap();
        SrtpUnprotect::new(&second.rtcp_rx)
            .unprotect_rtcp_sync(&next)
            .unwrap();
    }
}
