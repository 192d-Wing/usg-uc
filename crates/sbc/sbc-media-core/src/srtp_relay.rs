//! SRTP media transform for DTLS-SRTP termination.
//!
//! When the SBC terminates DTLS-SRTP it is a crypto endpoint on **both** legs,
//! so a media packet crossing the SBC is decrypted on the leg it arrived on and
//! re-encrypted for the far leg — never forwarded opaquely. Each leg has an
//! *ingress* context (unprotect what that peer sent) and an *egress* context
//! (protect what the SBC sends to that peer), derived from the per-leg DTLS
//! handshake ([`crate::dtls_relay::establish_srtp_leg`]).
//!
//! For the A→B direction the transform is `unprotect(A-ingress)` then
//! `protect(B-egress)`; B→A is the mirror. This module owns that per-packet
//! transform; the relay task that pumps sockets is layered on top.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use proto_srtp::{SrtpContext, SrtpProtect, SrtpResult, SrtpUnprotect};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::dtls_relay::{HandshakePeers, is_dtls_record};
use crate::dtls_sidecar::{SidecarError, SidecarEvent, SidecarReader, SidecarWriter};
use crate::recording_fork::{ForkTap, fork_changed};

/// Re-protects one RTP packet crossing the SBC: unprotect with the ingress
/// leg's context (decrypt what the arriving peer sent), then protect with the
/// egress leg's context (encrypt for the far peer).
///
/// # Errors
/// Unprotect failure (auth/replay/short packet) or protect failure.
pub fn reprotect_rtp(
    ingress: &SrtpContext,
    egress: &SrtpContext,
    srtp_packet: &[u8],
) -> SrtpResult<Bytes> {
    let rtp = SrtpUnprotect::new(ingress).unprotect_rtp(srtp_packet)?;
    SrtpProtect::new(egress).protect_rtp(&rtp)
}

/// Re-protects one SRTCP packet crossing the SBC — the mirror of
/// [`reprotect_rtp`] for the RTCP control leg: unprotect with the ingress
/// context, then protect with the egress context. (`unprotect_rtcp` is `async`
/// in proto-srtp, hence the await.)
///
/// # Errors
/// Unprotect failure (auth/replay/short packet) or protect failure.
pub async fn reprotect_rtcp(
    ingress: &SrtpContext,
    egress: &SrtpContext,
    srtcp_packet: &[u8],
) -> SrtpResult<Bytes> {
    let rtcp = SrtpUnprotect::new(ingress)
        .unprotect_rtcp(srtcp_packet)
        .await?;
    SrtpProtect::new(egress).protect_rtcp(&rtcp)
}

/// RFC 5761 rtcp-mux demux: on a port carrying both RTP and RTCP, a packet is
/// RTCP when its second byte (the payload-type field, marker bit masked off) is
/// in `64..=95` — the range RTP payload types avoid precisely so the two can be
/// told apart. The RTP/RTCP header (including this byte) is cleartext in both
/// SRTP and SRTCP, so this classifies the still-encrypted packet.
#[must_use]
fn is_rtcp_packet(pkt: &[u8]) -> bool {
    pkt.len() >= 2 && (64..=95).contains(&(pkt[1] & 0x7f))
}

/// Post-handshake DTLS-class datagrams one leg forwards to the sidecar at
/// once (token-bucket depth). Same numbers as the soft client's forward path.
pub const DTLS_FORWARD_BURST: u32 = 8;
/// Sustained post-handshake DTLS-class forwards per second and leg.
pub const DTLS_FORWARD_PER_SECOND: u32 = 4;

/// Token bucket in front of the sidecar for one leg's post-handshake DTLS, in
/// thousandths of a token.
///
/// NIST 800-53 Rev5: SC-5 -- the sidecar is one process for every call on the
/// node and keeps each association for the whole call. Without a limit here
/// anyone able to send from one leg's latched source could make it spend a
/// whole core on DTLS-class datagrams (about 40 us each for handshake-type
/// records) and starve the handshakes of new calls. With the bucket a flood
/// costs the relay loop one clock read and one compare per datagram, and at
/// most [`DTLS_FORWARD_PER_SECOND`] per second reach the sidecar (no
/// allocation for the rest).
///
/// A genuine peer sends, after the handshake, a retransmitted final flight
/// (a handful of datagrams per retransmission, at intervals of a second or
/// more: RFC 6347 §4.2.4.1) and one alert; both fit the burst.
///
/// The handshake does not pass through a leg's bucket: a
/// [`TerminateRelayLeg`] is only started once both legs' handshakes have
/// completed and their keys are exported
/// ([`crate::dtls_relay::run_handshake_pump`] reads the socket until then,
/// behind a bucket of its own with the same numbers).
// POAM: POA&M-335 -- residual: the bucket is charged before authentication
// (the relay cannot tell a forged DTLS-class datagram from a genuine one),
// and forged and genuine datagrams share it. A sender spoofing the leg's
// latched source at DTLS_FORWARD_PER_SECOND or more keeps the bucket empty
// for as long as it sends, with no time limit, so the genuine peer's
// `close_notify`, alert or retransmitted final flight is dropped here and
// never reaches the sidecar. Fail closed in every case: nothing forged is
// accepted, media is not affected, and the call then ends by signalling
// only (or that peer's handshake fails at its own timeout); the drops are
// counted and logged with the call id.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DtlsForwardBucket {
    /// Thousandths of a token available.
    millitokens: u32,
    /// When the bucket was last refilled.
    refilled: Instant,
}

impl DtlsForwardBucket {
    const CAPACITY: u32 = DTLS_FORWARD_BURST * 1000;

    pub(crate) const fn new(now: Instant) -> Self {
        Self {
            millitokens: Self::CAPACITY,
            refilled: now,
        }
    }

    /// Takes one token if there is one.
    pub(crate) fn try_take(&mut self, now: Instant) -> bool {
        let elapsed_ms = u64::try_from(now.saturating_duration_since(self.refilled).as_millis())
            .unwrap_or(u64::MAX);
        if elapsed_ms > 0 {
            // One millisecond adds DTLS_FORWARD_PER_SECOND thousandths.
            let added = u32::try_from(elapsed_ms)
                .unwrap_or(u32::MAX)
                .saturating_mul(DTLS_FORWARD_PER_SECOND);
            self.millitokens = self.millitokens.saturating_add(added).min(Self::CAPACITY);
            // Advance by the whole milliseconds credited, so the rest of a
            // millisecond counts towards the next refill.
            self.refilled = self
                .refilled
                .checked_add(Duration::from_millis(elapsed_ms))
                .unwrap_or(now);
        }
        if self.millitokens >= 1000 {
            self.millitokens -= 1000;
            true
        } else {
            false
        }
    }
}

/// One direction of a terminated media relay.
///
/// Reads SRTP from `recv_sock`, re-protects it for the far leg, and sends it
/// on `send_sock`. Post-handshake DTLS records (a retransmitted final flight,
/// alerts; first byte 20..=63) from the latched source are forwarded to the
/// sidecar via `dtls_out`, rate-limited, rather than treated as media.
///
/// Source latching: the leg starts latched to the value in `recv_target`
/// (the supervisor writes the handshake's source there). Only datagrams from
/// `expected_remote`'s IP are considered. A datagram from the latched source
/// is processed as usual. A media datagram from another port on that IP is
/// tried (unprotected like any other) only when it has the shape of
/// SRTP/SRTCP under the leg's profile, its SSRC is one this leg has already
/// authenticated (any SSRC before the first authenticated packet, so that a
/// wrong seed can be corrected) and, for SRTP, its index is above the
/// highest authenticated one (for SRTCP, an index the RTCP replay window
/// accepts); the latch moves to that port (and `recv_target` with it) only
/// when the unprotect succeeds. Otherwise it is dropped and counted:
/// `dropped_stale_relatch` for an SRTP index that does not advance or an
/// SRTCP index the replay window rejects (dropped before unprotect, so the
/// context is not touched), `dropped_unauth_source` for everything else. The latch is never moved by
/// an unauthenticated datagram.
///
/// DTLS-class datagrams reach the sidecar from the latched source and, until
/// the first packet on this side of the call authenticates
/// (`media_authenticated`), also from any of `handshake_peers`: a peer whose
/// final flight was lost retransmits it from wherever it ran the handshake.
pub struct TerminateRelayLeg {
    /// Socket this leg receives the near peer's SRTP/DTLS on.
    pub recv_sock: Arc<UdpSocket>,
    /// Socket to send re-protected media to the far peer on.
    pub send_sock: Arc<UdpSocket>,
    /// Unprotects packets arriving on `recv_sock` (this leg's ingress key).
    ///
    /// NIST 800-53 Rev5: SC-13, SC-8 -- owned by this task alone, so the key
    /// and direction have one replay window (RFC 3711 §3.3.2).
    pub ingress: SrtpContext,
    /// Protects packets sent on `send_sock` (the far leg's egress key).
    ///
    /// NIST 800-53 Rev5: SC-13 -- owned by this task alone, so the SRTP and
    /// SRTCP indices (and AEAD nonces) under the key are used once
    /// (RFC 7714 §8.1, §9.1).
    pub egress: SrtpContext,
    /// The near peer's SDP media address. Only its IP is used: datagrams
    /// from any other IP are dropped.
    pub expected_remote: SocketAddr,
    /// Shared latch for this leg's near-peer address (the opposite direction
    /// and the sidecar's post-handshake DTLS send here). Its value when the
    /// leg starts is the initial latch; the leg writes it when an
    /// authenticated packet moves the latch.
    pub recv_target: Arc<RwLock<SocketAddr>>,
    /// Where to send re-protected media — the far leg's latched address.
    pub forward_target: Arc<RwLock<SocketAddr>>,
    /// Post-handshake DTLS records demuxed off `recv_sock` go here (to the
    /// sidecar). `None` drops them (tests).
    pub dtls_out: Option<mpsc::Sender<Vec<u8>>>,
    /// The sources the handshake pump forwarded DTLS from (empty on the
    /// separate-port RTCP legs).
    pub handshake_peers: HandshakePeers,
    /// Set by the first packet that authenticates on this side of the call
    /// (shared with the side's RTCP leg and its [`pump_sidecar_dtls_to_peer`]);
    /// from then on DTLS is accepted from, and sent to, the latched source
    /// only.
    pub media_authenticated: Arc<AtomicBool>,
    /// Call id for logging.
    pub call_id: String,
    /// Direction label for logging ("A→B" / "B→A").
    pub direction: &'static str,
    /// SIPREC fork tap for the media this leg decrypts (RFC 7866 §8). `None`
    /// when recording is disabled on the pipeline.
    pub fork: Option<ForkTap>,
}

impl TerminateRelayLeg {
    /// Runs the relay loop until `shutdown` fires or the socket errors.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut buf = [0u8; 2048];
        let mut fork = self.fork.take();
        let has_fork = fork.is_some();
        // NIST 800-53 Rev5: SC-7 -- the initial latch is the seed the
        // supervisor wrote (the handshake's source, a hint); a poisoned lock
        // still holds a whole address.
        let mut latched: SocketAddr = *self
            .recv_target
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut latch_moves: u64 = 0;
        let mut forwarded: u64 = 0;
        // Kept separate so an off-path spoofing attempt (SC-7 boundary event) is
        // distinguishable from crypto/keying breakage or sidecar backpressure:
        // wrong IP, same IP but not latched and not authenticated, same IP
        // but not latched with a stale SRTP index, and the latched source
        // failing auth.
        let mut dropped_source: u64 = 0;
        let mut dropped_unauth_source: u64 = 0;
        let mut dropped_stale_relatch: u64 = 0;
        let mut dropped_auth: u64 = 0;
        // SSRCs that have authenticated on this leg (bounded, no allocation):
        // a packet from another port is only tried under one of them.
        let mut auth_ssrcs = AuthenticatedSsrcs::default();
        // Local copy of `media_authenticated` for this leg's own packets.
        let mut authenticated = false;
        let mut dropped_dtls: u64 = 0;
        let mut dtls_rate_limited: u64 = 0;
        let mut dtls_bucket = DtlsForwardBucket::new(Instant::now());

        loop {
            tokio::select! {
                result = self.recv_sock.recv_from(&mut buf) => {
                    let (n, src) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            debug!(error = %e, call_id = %self.call_id, direction = self.direction, "SRTP relay recv error");
                            break;
                        }
                    };
                    if n == 0 {
                        continue;
                    }

                    // Source filter: only the SDP peer's IP. The exact latched
                    // source is checked below.
                    if src.ip() != self.expected_remote.ip() {
                        dropped_source += 1;
                        if dropped_source == 1 || dropped_source.is_multiple_of(1000) {
                            warn!(
                                call_id = %self.call_id, direction = self.direction,
                                source = %src, expected = %self.expected_remote, dropped_source,
                                "SRTP relay dropping packet from unexpected source"
                            );
                        }
                        continue;
                    }
                    // NIST 800-53 Rev5: SC-7, SC-23, SI-10 -- another port on
                    // the peer's IP is not trusted until a packet from it
                    // authenticates under this leg's SRTP key (RFC 3711 §3.3,
                    // RFC 7362 §7).
                    let from_latched = src == latched;

                    // Demux (RFC 7983 + RFC 5761): post-handshake DTLS (a
                    // retransmitted final flight, an alert) → sidecar;
                    // otherwise SRTP media or muxed SRTCP → reprotect for the
                    // far leg and forward.
                    if is_dtls_record(buf[0]) {
                        // RFC 6347 §4.2.4: until media authenticates, a
                        // retransmitted final flight may come from any source
                        // the handshake ran with (the seed is only a hint).
                        // One atomic load, DTLS-class datagrams only.
                        let admissible = from_latched
                            || (!self.media_authenticated.load(Ordering::Acquire)
                                && self.handshake_peers.contains(src));
                        if !admissible {
                            // DTLS cannot be authenticated here: only the
                            // latched source's (and, before media
                            // authenticates, the handshake sources') reaches
                            // the sidecar.
                            dropped_unauth_source += 1;
                            self.warn_unauth_source(src, latched, dropped_unauth_source);
                            continue;
                        }
                        if let Some(tx) = &self.dtls_out {
                            // NIST 800-53 Rev5: SC-5 -- the bucket comes before
                            // the copy, so a flood allocates nothing and the
                            // shared sidecar sees at most burst + rate. The
                            // clock is read for DTLS-class datagrams only.
                            // POAM: POA&M-335 -- charged before authentication:
                            // a spoofed source at the rate or above starves the
                            // genuine peer's post-handshake DTLS for the call
                            // (see `DtlsForwardBucket`).
                            let admitted = dtls_bucket.try_take(Instant::now());
                            if !admitted {
                                dtls_rate_limited += 1;
                            }
                            // Non-blocking send: awaiting on this bounded
                            // channel would let sidecar backpressure
                            // head-of-line block all media forwarding on this
                            // leg. A dropped handshake record is retransmitted
                            // by DTLS; a dropped alert leaves the call to end
                            // by signalling.
                            if !admitted || tx.try_send(buf[..n].to_vec()).is_err() {
                                dropped_dtls += 1;
                                if dropped_dtls == 1 || dropped_dtls.is_multiple_of(1000) {
                                    warn!(
                                        call_id = %self.call_id, direction = self.direction,
                                        dropped_dtls, dtls_rate_limited,
                                        "post-handshake DTLS from the peer dropped (rate limit, or sidecar channel full/closed)"
                                    );
                                }
                            }
                        }
                        continue;
                    }

                    let is_rtcp = is_rtcp_packet(&buf[..n]);
                    let pkt_ssrc = packet_ssrc(&buf[..n], is_rtcp);
                    // Trial path for a non-latched source: cheap checks first
                    // (shape, so junk does not reach proto-srtp's allocating
                    // error paths; a known SSRC, so junk does not cost an AEAD
                    // open; a fresh SRTP index, so a replay does not touch the
                    // context), then the same unprotect the latched source's
                    // packets get.
                    // NIST 800-53 Rev5: SC-5, SC-7
                    if !from_latched {
                        match self.trial_gate(&buf[..n], is_rtcp, pkt_ssrc, &auth_ssrcs) {
                            TrialGate::Try => {}
                            TrialGate::Stale => {
                                dropped_stale_relatch += 1;
                                self.warn_stale_relatch(src, latched, dropped_stale_relatch);
                                continue;
                            }
                            TrialGate::Refuse => {
                                dropped_unauth_source += 1;
                                self.warn_unauth_source(src, latched, dropped_unauth_source);
                                continue;
                            }
                        }
                    }
                    // Decrypted media kept for the recording fork (the same
                    // steps as `reprotect_rtp`, with the plaintext retained).
                    let mut decrypted = None;
                    let reprotected = if is_rtcp {
                        reprotect_rtcp(&self.ingress, &self.egress, &buf[..n]).await
                    } else if has_fork {
                        SrtpUnprotect::new(&self.ingress)
                            .unprotect_rtp(&buf[..n])
                            .and_then(|rtp| {
                                let out = SrtpProtect::new(&self.egress).protect_rtp(&rtp);
                                decrypted = Some(rtp.payload);
                                out
                            })
                    } else {
                        reprotect_rtp(&self.ingress, &self.egress, &buf[..n])
                    };
                    let reprotected = match reprotected {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            // Auth/replay/short-packet failures are dropped, never
                            // forwarded — the SBC must not emit unauthenticated media.
                            if !from_latched {
                                dropped_unauth_source += 1;
                                self.warn_unauth_source(src, latched, dropped_unauth_source);
                                continue;
                            }
                            dropped_auth += 1;
                            if dropped_auth == 1 || dropped_auth.is_multiple_of(1000) {
                                warn!(error = %e, call_id = %self.call_id, direction = self.direction, is_rtcp, dropped_auth, "SRTP/SRTCP unprotect failed; dropping");
                            }
                            continue;
                        }
                    };
                    // Authenticated: record the SSRC (the first authenticated
                    // packet seeds the set) and, once, tell the DTLS paths.
                    if let Some(ssrc) = pkt_ssrc {
                        auth_ssrcs.insert(ssrc);
                    }
                    if !authenticated {
                        authenticated = true;
                        self.media_authenticated.store(true, Ordering::Release);
                    }
                    if !from_latched {
                        // A stale SRTP index, and an SRTCP index the RTCP
                        // replay window rejects, were refused before
                        // unprotect (`trial_gate`).
                        // POAM: POA&M-346 -- SRTCP needs only an index the
                        // replay window accepts, not a new highest one: an
                        // observer of a genuine SRTCP packet that the relay
                        // never received can replay it from another port on
                        // the peer's IP and move the latch until the peer's
                        // next packet moves it back.
                        latch_moves += 1;
                        if latch_moves == 1 || latch_moves.is_multiple_of(100) {
                            info!(
                                event = "media.latch.moved",
                                call_id = %self.call_id, direction = self.direction,
                                from = %latched, to = %src, basis = "srtp-auth", latch_moves,
                                "relay leg latch moved to an authenticated source"
                            );
                        }
                        latched = src;
                        if let Ok(mut t) = self.recv_target.write() {
                            *t = src;
                        }
                    }

                    let dest = match self.forward_target.read() {
                        Ok(g) => *g,
                        Err(_) => continue,
                    };
                    match self.send_sock.send_to(&reprotected, dest).await {
                        Ok(_) => {
                            if is_rtcp {
                                // Muxed SRTCP rides the media port; count it on the
                                // RTCP metric so it doesn't inflate the audio signal.
                                crate::media_pipeline::record_rtcp_relayed();
                            } else {
                                // Count terminated-leg media on the same black-hole
                                // metric the opaque relay uses, so DTLS-terminated
                                // calls aren't reported as mute when audio flows.
                                crate::media_pipeline::record_rtp_relayed();
                                forwarded += 1;
                                // RFC 7866 §8: copy the decrypted media to the
                                // recorder under the fork's own key, after the
                                // call's packet is out. The tap adds no
                                // allocation and never blocks.
                                // NIST 800-53 Rev5: AU-14, SC-8
                                if let (Some(tap), Some(payload)) = (fork.as_mut(), &decrypted) {
                                    tap.on_decrypted_rtp(&buf[..n], payload);
                                }
                                if forwarded == 1 {
                                    info!(call_id = %self.call_id, direction = self.direction, "SRTP relay forwarding media");
                                }
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, call_id = %self.call_id, direction = self.direction, "SRTP relay send error");
                        }
                    }
                }
                // Recording fork activated or stopped (applied inside the tap).
                () = fork_changed(&mut fork), if has_fork => {}
                _ = shutdown.changed() => {
                    debug!(call_id = %self.call_id, direction = self.direction, "SRTP relay shutdown");
                    break;
                }
            }
        }
    }

    /// Whether a packet from a port that is not latched may be tried (see
    /// the type docs). No allocation, no crypto.
    fn trial_gate(
        &self,
        pkt: &[u8],
        is_rtcp: bool,
        ssrc: Option<u32>,
        auth_ssrcs: &AuthenticatedSsrcs,
    ) -> TrialGate {
        if !could_be_srtp(pkt, is_rtcp, self.ingress.profile().auth_tag_len()) {
            return TrialGate::Refuse;
        }
        if auth_ssrcs.is_empty() {
            // Nothing has authenticated yet (the seed may be wrong): any
            // well-formed packet may be tried.
            return TrialGate::Try;
        }
        if !ssrc.is_some_and(|s| auth_ssrcs.contains(s)) {
            return TrialGate::Refuse;
        }
        if is_rtcp {
            // RFC 3711 §3.4 / RFC 7714 §17: the SRTCP index is the low 31
            // bits of the trailing word (E || index; no MKI on these legs).
            // An index the RTCP replay window would reject is dropped before
            // the AEAD open; the check is read-only, as in unprotect.
            let Some(index_word) = pkt
                .len()
                .checked_sub(4)
                .and_then(|at| pkt.get(at..))
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes)
            else {
                return TrialGate::Refuse;
            };
            if self
                .ingress
                .check_rtcp_replay(u64::from(index_word & 0x7FFF_FFFF))
                .is_err()
            {
                return TrialGate::Stale;
            }
        } else {
            // RFC 3711 §3.3.1: the index this packet would have. A relatch
            // needs a new highest index; anything else is a replay or a
            // packet the latched source already moved past.
            let Some(&[hi, lo]) = pkt.get(2..4) else {
                return TrialGate::Refuse;
            };
            let index = self.ingress.compute_rtp_index(u16::from_be_bytes([hi, lo]));
            if index <= self.ingress.highest_rtp_index() {
                return TrialGate::Stale;
            }
        }
        TrialGate::Try
    }

    /// Logs a packet from the peer's IP that was dropped because its port
    /// is not latched and its SRTP index does not advance the highest
    /// authenticated one (first, then every 1000th).
    fn warn_stale_relatch(&self, src: SocketAddr, latched: SocketAddr, dropped_stale_relatch: u64) {
        if dropped_stale_relatch == 1 || dropped_stale_relatch.is_multiple_of(1000) {
            warn!(
                call_id = %self.call_id, direction = self.direction,
                source = %src, latched = %latched, dropped_stale_relatch,
                "SRTP relay dropping a stale-index packet from a port that is not latched"
            );
        }
    }

    /// Logs a datagram from the peer's IP that was dropped because its port
    /// is not latched and it did not authenticate (first, then every 1000th).
    fn warn_unauth_source(&self, src: SocketAddr, latched: SocketAddr, dropped_unauth_source: u64) {
        if dropped_unauth_source == 1 || dropped_unauth_source.is_multiple_of(1000) {
            warn!(
                call_id = %self.call_id, direction = self.direction,
                source = %src, latched = %latched, dropped_unauth_source,
                "SRTP relay dropping unauthenticated packet from a port that is not latched"
            );
        }
    }
}

/// What [`TerminateRelayLeg::trial_gate`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrialGate {
    /// Unprotect it.
    Try,
    /// An SRTP index that does not advance, or an SRTCP index the replay
    /// window rejects: dropped before unprotect.
    Stale,
    /// Wrong shape or an SSRC not authenticated on the leg.
    Refuse,
}

/// Most SSRCs one leg remembers as authenticated. A peer sends one media
/// SSRC per leg (and RTCP under the same one); the rest is headroom.
const MAX_AUTH_SSRCS: usize = 4;

/// SSRCs that have authenticated on one leg. Fixed size; once full, further
/// SSRCs are not remembered (packets under them are still relayed from the
/// latched source, but cannot move the latch).
// NIST 800-53 Rev5: SC-5
#[derive(Debug, Default)]
struct AuthenticatedSsrcs {
    ssrcs: [Option<u32>; MAX_AUTH_SSRCS],
}

impl AuthenticatedSsrcs {
    fn is_empty(&self) -> bool {
        self.ssrcs.iter().all(Option::is_none)
    }

    fn contains(&self, ssrc: u32) -> bool {
        self.ssrcs.contains(&Some(ssrc))
    }

    /// Adds `ssrc` if it is new and there is room. A compare per slot.
    fn insert(&mut self, ssrc: u32) {
        for slot in &mut self.ssrcs {
            match slot {
                Some(s) if *s == ssrc => return,
                Some(_) => {}
                None => {
                    *slot = Some(ssrc);
                    return;
                }
            }
        }
    }
}

/// Whether `pkt` has the shape of SRTP (or SRTCP when `is_rtcp`) under a
/// profile with `tag`-byte authentication tags. SRTP: version 2 and long
/// enough for the fixed header, the CSRC list, any header extension
/// (RFC 3550 §5.1, §5.3.1) and the tag. SRTCP: version 2, long enough for
/// the header, the tag and the index word, and the E flag set (RFC 3711
/// §3.4; the AEAD profile always encrypts). Checked before a trial
/// unprotect. No allocation.
fn could_be_srtp(pkt: &[u8], is_rtcp: bool, tag: usize) -> bool {
    let Some(&b0) = pkt.first() else {
        return false;
    };
    if b0 & 0xC0 != 0x80 {
        return false;
    }
    if is_rtcp {
        let e_flag = pkt
            .len()
            .checked_sub(4)
            .and_then(|i| pkt.get(i))
            .is_some_and(|b| b & 0x80 != 0);
        return pkt.len() >= 8 + tag + 4 && e_flag;
    }
    let mut header = proto_rtp::RTP_HEADER_MIN_SIZE + 4 * usize::from(b0 & 0x0F);
    if b0 & 0x10 != 0 {
        // Extension: profile(2) length-in-words(2), then the words.
        let Some(&[hi, lo]) = pkt.get(header + 2..header + 4) else {
            return false;
        };
        header += 4 + 4 * usize::from(u16::from_be_bytes([hi, lo]));
    }
    pkt.len() >= header + tag
}

/// The cleartext SSRC of an SRTP packet (bytes 8..12) or the sender SSRC of
/// an SRTCP packet (bytes 4..8, RFC 3550 §6.4).
fn packet_ssrc(pkt: &[u8], is_rtcp: bool) -> Option<u32> {
    let at = if is_rtcp { 4 } else { 8 };
    pkt.get(at..at + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
}

/// How long [`pump_sidecar_dtls_to_peer`] keeps relaying after the call has
/// ended, for the sidecar's `close_notify` to reach the peer. The sidecar
/// answers the closed connection at once; this only bounds a sidecar that
/// does not.
// POAM: POA&M-341 -- for this long after `stop_relay` the pump still holds
// the leg's media socket although its port pair is already released: with a
// sidecar that does not answer, a new call handed the same ports inside the
// window fails to bind (it cannot receive another call's media: the socket
// is bound exclusively).
const SIDECAR_CLOSE_GRACE: Duration = Duration::from_millis(500);

/// Forwards post-handshake DTLS records from the peer to the sidecar.
///
/// The records (a retransmitted final flight, alerts) are demuxed off the
/// media socket by [`TerminateRelayLeg`]. Owns the [`SidecarWriter`] so the
/// sidecar connection stays open for the whole call (the DTLS association
/// must outlive key export); ends on shutdown, a closed channel, or a sidecar
/// write error.
///
/// Returning drops the writer, which shuts down the sending half of the
/// connection. That is how the sidecar learns the call is over: it then sends
/// `close_notify` for the peer and closes its end, which
/// [`pump_sidecar_dtls_to_peer`] relays.
pub async fn forward_dtls_to_sidecar(
    mut records: mpsc::Receiver<Vec<u8>>,
    mut writer: SidecarWriter,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            msg = records.recv() => match msg {
                Some(record) => {
                    if let Err(e) = writer.send_dtls(&record).await {
                        debug!(error = %e, "forwarding DTLS to sidecar failed");
                        break;
                    }
                }
                None => break,
            },
            _ = shutdown.changed() => break,
        }
    }
}

/// Pumps DTLS records the sidecar emits *after* the handshake back to the peer.
///
/// Those are its final flight again when the peer retransmits its own
/// (RFC 6347 §4.2.4), the answer to the peer's `close_notify`, and its own
/// `close_notify` when the call ends. Owns the [`SidecarReader`] so the
/// connection stays open for the call.
///
/// Ends when the sidecar reports the end of the association (`Error`, e.g. the
/// peer closed it) or closes the connection. On shutdown it does not stop at
/// once: [`forward_dtls_to_sidecar`] closes the sending half at the same
/// moment, the sidecar answers with `close_notify` and closes, and the pump
/// relays that record first, for at most [`SIDECAR_CLOSE_GRACE`].
///
/// Each record goes to the leg's latched address (`peer`) and, until the
/// first packet on this side of the call authenticates, to every source the
/// handshake ran with as well (`fanout`; at most
/// [`crate::dtls_relay::MAX_HANDSHAKE_SOURCES`] + 1 sends, all to the peer's
/// IP): the latch seed is a hint, and a peer whose final flight was lost has
/// to receive the retransmission where it ran the handshake (RFC 6347
/// §4.2.4).
///
/// However the association ends, one `dtls.association.closed` record is
/// written with the call id, the leg and the peer's address (`assoc`): at
/// info when the call ended, at warn for everything else.
// RFC 5246 §7.2.1 / RFC 5764 §5.1.2: the association is closed with
// close_notify when the SRTP session it keyed ends.
// NIST 800-53 Rev5: AU-2, AU-3 (attributable record of the end of a DTLS
// association), SC-10.
pub async fn pump_sidecar_dtls_to_peer(
    mut reader: SidecarReader,
    sock: Arc<UdpSocket>,
    peer: Arc<RwLock<SocketAddr>>,
    fanout: HandshakeFanout,
    mut shutdown: watch::Receiver<bool>,
    assoc: AssociationLabel,
) {
    loop {
        tokio::select! {
            event = reader.read() => {
                if let Some(end) = relay_sidecar_event(event, &sock, &peer, &fanout).await {
                    // POAM: POA&M-340 -- the association is gone but the call
                    // is not ended here: the relay legs keep this leg's SRTP
                    // keys and keep relaying until signalling ends the call.
                    assoc.record_closed(&peer, end.reason_mid_call(), end.detail());
                    return;
                }
            }
            _ = shutdown.changed() => break,
        }
    }
    // The call is over. The sidecar closing its end is the expected answer.
    let drain = async {
        loop {
            if let Some(end) = relay_sidecar_event(reader.read().await, &sock, &peer, &fanout).await
            {
                return end;
            }
        }
    };
    match tokio::time::timeout(SIDECAR_CLOSE_GRACE, drain).await {
        Ok(end) => assoc.record_closed(&peer, end.reason_at_call_end(), end.detail()),
        Err(_) => assoc.record_closed(&peer, CLOSED_SIDECAR_TIMEOUT, ""),
    }
}

/// Where [`pump_sidecar_dtls_to_peer`] also sends the sidecar's records until
/// media authenticates.
#[derive(Debug, Clone, Default)]
pub struct HandshakeFanout {
    /// The sources the handshake pump forwarded DTLS from.
    pub peers: HandshakePeers,
    /// Shared with the side's relay legs (see
    /// [`TerminateRelayLeg::media_authenticated`]).
    pub media_authenticated: Arc<AtomicBool>,
}

/// Which association a [`pump_sidecar_dtls_to_peer`] task serves, for its
/// `dtls.association.closed` record.
#[derive(Debug, Clone)]
pub struct AssociationLabel {
    /// Call id.
    pub call_id: String,
    /// Leg of the call ("A" / "B").
    pub leg: &'static str,
}

// Reason tokens of the `dtls.association.closed` record. Fixed strings, so
// that the record can be matched on without parsing free text.
/// The call ended and the sidecar closed the association (`close_notify`).
const CLOSED_CALL_ENDED: &str = "call-ended";
/// The call ended and the sidecar did not close within the grace.
const CLOSED_SIDECAR_TIMEOUT: &str = "sidecar-close-timeout";
/// The peer sent `close_notify` during the call, as inferred by the
/// sidecar (pion reports both peer-initiated ends as end-of-stream; the
/// sidecar tells them apart by whether an alert of its own went out).
const CLOSED_PEER_CLOSE_NOTIFY: &str = "peer-close-notify";
/// The peer sent a fatal alert during the call, as inferred by the
/// sidecar (see [`CLOSED_PEER_CLOSE_NOTIFY`]).
const CLOSED_PEER_FATAL_ALERT: &str = "peer-fatal-alert";
/// The sidecar is stopping.
const CLOSED_SIDECAR_SHUTDOWN: &str = "sidecar-shutdown";
/// The sidecar reported an end this relay has no token for.
const CLOSED_SIDECAR_ERROR: &str = "sidecar-error";
/// The sidecar connection ended during the call (sidecar crash or kill).
const CLOSED_SIDECAR_LOST: &str = "sidecar-connection-lost";

impl AssociationLabel {
    /// Writes the one `dtls.association.closed` record of the association.
    /// `remote` is the bare address, as in the soft client's record.
    fn record_closed(&self, peer: &RwLock<SocketAddr>, reason: &'static str, detail: &str) {
        // A poisoned lock still holds a whole address.
        let remote = *peer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if reason == CLOSED_CALL_ENDED {
            info!(
                event = "dtls.association.closed",
                call_id = %self.call_id, leg = self.leg, remote = %remote, reason,
                "DTLS association closed with the call"
            );
        } else {
            warn!(
                event = "dtls.association.closed",
                call_id = %self.call_id, leg = self.leg, remote = %remote, reason, detail,
                "DTLS association ended; SRTP relaying on this leg continues until signalling ends the call"
            );
        }
    }
}

/// How the sidecar's side of a session ended.
#[derive(Debug)]
enum SidecarEnd {
    /// The sidecar sent `Error` with this text.
    Reported(String),
    /// The connection ended (closed by the sidecar, or broken).
    Disconnected,
    /// The peer's address could not be read or the sidecar broke protocol.
    Fault(&'static str),
}

impl SidecarEnd {
    /// The reason token when this happens while the call is up.
    fn reason_mid_call(&self) -> &'static str {
        match self {
            Self::Reported(text) => sidecar_reason(text),
            Self::Disconnected => CLOSED_SIDECAR_LOST,
            Self::Fault(_) => CLOSED_SIDECAR_ERROR,
        }
    }

    /// The reason token when this happens after the call has ended: the
    /// sidecar closing its end is then the normal close.
    fn reason_at_call_end(&self) -> &'static str {
        match self {
            Self::Disconnected => CLOSED_CALL_ENDED,
            other => other.reason_mid_call(),
        }
    }

    /// What the sidecar said, for a reason this relay has no token for.
    fn detail(&self) -> &str {
        match self {
            Self::Reported(text) if sidecar_reason(text) == CLOSED_SIDECAR_ERROR => text,
            Self::Fault(what) => what,
            _ => "",
        }
    }
}

/// Maps the sidecar's `Error` text after `Ready` to a reason token. The text
/// starts with the token, up to a colon (`sidecar/dtls-terminator`,
/// `service/session.go`).
fn sidecar_reason(text: &str) -> &'static str {
    match text.split(':').next().map_or("", str::trim) {
        "peer-close-notify" => CLOSED_PEER_CLOSE_NOTIFY,
        "peer-fatal-alert" => CLOSED_PEER_FATAL_ALERT,
        "sidecar-shutdown" => CLOSED_SIDECAR_SHUTDOWN,
        _ => CLOSED_SIDECAR_ERROR,
    }
}

/// Sends one post-handshake DTLS record from the sidecar to the peer. Returns
/// how the sidecar's side of the session ended, or `None` while it goes on.
async fn relay_sidecar_event(
    event: Result<SidecarEvent, SidecarError>,
    sock: &UdpSocket,
    peer: &RwLock<SocketAddr>,
    fanout: &HandshakeFanout,
) -> Option<SidecarEnd> {
    match event {
        Ok(SidecarEvent::Dtls(record)) => {
            let Ok(dest) = peer.read().map(|g| *g) else {
                return Some(SidecarEnd::Fault("peer address unavailable"));
            };
            let _ = sock.send_to(&record, dest).await;
            // NIST 800-53 Rev5: SC-5 -- bounded by the fixed-size set.
            if !fanout.media_authenticated.load(Ordering::Acquire) {
                for other in fanout.peers.iter().filter(|a| *a != dest) {
                    let _ = sock.send_to(&record, other).await;
                }
            }
            None
        }
        // After the handshake an `Error` is the sidecar's report that the
        // association ended (the peer closed it, or the sidecar is stopping).
        Ok(SidecarEvent::Error(reason)) => Some(SidecarEnd::Reported(reason)),
        Ok(SidecarEvent::Ready { .. }) => Some(SidecarEnd::Fault(
            "unexpected Ready from the sidecar after the handshake",
        )),
        Err(e) => {
            debug!(error = %e, "sidecar reader ended");
            Some(SidecarEnd::Disconnected)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proto_rtp::{RtpHeader, RtpPacket};
    use proto_srtp::{SrtpDirection, SrtpKeyMaterial, SrtpProfile};

    // Fresh AEAD_AES_256_GCM master key + salt per DTLS-SRTP association.
    // Generated at runtime (not hard-coded) so the round-trip is key-agnostic.
    fn random_material() -> (Vec<u8>, Vec<u8>) {
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let salt: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        (key, salt)
    }

    fn ctx(key: &[u8], salt: &[u8], dir: SrtpDirection, ssrc: u32) -> SrtpContext {
        let material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.to_vec(), salt.to_vec()).unwrap();
        SrtpContext::new(&material, dir, ssrc).unwrap()
    }

    // Full termination topology for one direction: peer-A protects → SBC
    // unprotects (A-ingress) + re-protects (B-egress) → peer-B unprotects and
    // recovers the original RTP. A-leg and B-leg use DIFFERENT keys (the SBC
    // bridges two independent DTLS-SRTP associations).
    #[test]
    fn reprotect_rtp_bridges_two_associations() {
        let ssrc = 0x0CAF_E123;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let peer_a_send = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let sbc_ingress_a = ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc);
        let sbc_egress_b = ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc);
        let peer_b_recv = ctx(&key_b, &salt_b, SrtpDirection::Inbound, ssrc);

        let payload = vec![0xABu8; 160];
        let packet = RtpPacket::new(RtpHeader::new(0, 1000, 160_000, ssrc), payload.clone());

        // Peer A → SBC (A-leg crypto).
        let srtp_a = SrtpProtect::new(&peer_a_send).protect_rtp(&packet).unwrap();
        // SBC re-protects A→B.
        let srtp_b = reprotect_rtp(&sbc_ingress_a, &sbc_egress_b, &srtp_a).unwrap();
        // The A-leg ciphertext must not survive onto the B leg (keys differ).
        assert_ne!(srtp_a.as_ref(), srtp_b.as_ref());
        // SBC → Peer B (B-leg crypto) recovers the original plaintext.
        let out = SrtpUnprotect::new(&peer_b_recv)
            .unprotect_rtp(&srtp_b)
            .unwrap();
        assert_eq!(out.payload.as_ref(), payload.as_slice());
        assert_eq!(out.header.sequence_number, 1000);
    }

    // A packet the ingress context can't authenticate (wrong key) is rejected,
    // not forwarded — the SBC never emits unauthenticated media.
    #[test]
    fn reprotect_rtp_rejects_unauthenticated() {
        let ssrc = 0x11u32;
        let (key_wrong, salt_wrong) = random_material();
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let wrong_sender = ctx(&key_wrong, &salt_wrong, SrtpDirection::Outbound, ssrc);
        let sbc_ingress_a = ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc);
        let sbc_egress_b = ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc);

        let packet = RtpPacket::new(RtpHeader::new(0, 1, 1, ssrc), vec![0u8; 160]);
        let bad = SrtpProtect::new(&wrong_sender)
            .protect_rtp(&packet)
            .unwrap();

        assert!(reprotect_rtp(&sbc_ingress_a, &sbc_egress_b, &bad).is_err());
    }

    // The relay leg re-protects SRTP media it receives from the near peer and
    // delivers it to the far peer, who recovers the original plaintext.
    #[tokio::test]
    async fn terminate_relay_leg_reprotects_media() {
        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_recv_addr = relay_recv.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let far_addr = far.local_addr().unwrap();

        let ssrc = 0x2222_u32;
        let (key_a, salt_a) = random_material(); // near leg (peer ↔ SBC)
        let (key_b, salt_b) = random_material(); // far leg (SBC ↔ far)
        let peer_send = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let ingress = ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc);
        let egress = ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc);
        let far_recv = ctx(&key_b, &salt_b, SrtpDirection::Inbound, ssrc);

        let (sd_tx, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: Arc::clone(&relay_recv),
            send_sock: Arc::clone(&relay_send),
            ingress,
            egress,
            expected_remote: peer_addr,
            recv_target: Arc::new(RwLock::new(peer_addr)),
            forward_target: Arc::new(RwLock::new(far_addr)),
            dtls_out: None,
            handshake_peers: HandshakePeers::default(),
            media_authenticated: Arc::default(),
            call_id: "call".into(),
            direction: "A→B",
            fork: None,
        };
        let handle = tokio::spawn(leg.run(sd_rx));

        let payload = vec![0x5Au8; 160];
        let pkt = RtpPacket::new(RtpHeader::new(0, 7, 700, ssrc), payload.clone());
        let srtp = SrtpProtect::new(&peer_send).protect_rtp(&pkt).unwrap();
        peer.send_to(&srtp, relay_recv_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), far.recv_from(&mut buf))
                .await
                .expect("far recv timed out")
                .unwrap();
        let out = SrtpUnprotect::new(&far_recv)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(out.payload.as_ref(), payload.as_slice());

        let _ = sd_tx.send(true);
        let _ = handle.await;
    }

    // SIPREC (RFC 7866 §8): with a fork tap, the decrypted media is also sent
    // to the recorder under the fork's own key, SSRC and sequence; the far
    // peer still gets the normally re-protected packet. SRTCP is not forked.
    #[tokio::test]
    async fn terminate_relay_leg_forks_decrypted_media() {
        use crate::recording_fork::{ForkControl, ForkStream};

        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_recv_addr = relay_recv.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let far_addr = far.local_addr().unwrap();

        let ssrc = 0x6666_u32;
        let fork_ssrc = 0x0F0F_0001_u32;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let (key_r, salt_r) = random_material();
        let peer_send = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let far_recv = ctx(&key_b, &salt_b, SrtpDirection::Inbound, ssrc);
        let srs_recv = ctx(&key_r, &salt_r, SrtpDirection::Inbound, fork_ssrc);

        let fork_key =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key_r.clone(), salt_r.clone())
                .unwrap();
        let stream =
            ForkStream::bind(&fork_key, "127.0.0.1:0".parse().unwrap(), fork_ssrc).unwrap();
        let control = ForkControl::new();
        let tap = control.tap();

        let (sd_tx, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: Arc::clone(&relay_recv),
            send_sock: Arc::clone(&relay_send),
            ingress: ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc),
            egress: ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc),
            expected_remote: peer_addr,
            recv_target: Arc::new(RwLock::new(peer_addr)),
            forward_target: Arc::new(RwLock::new(far_addr)),
            dtls_out: None,
            handshake_peers: HandshakePeers::default(),
            media_authenticated: Arc::default(),
            call_id: "call".into(),
            direction: "A→B",
            fork: Some(tap),
        };
        let handle = tokio::spawn(leg.run(sd_rx));
        let wait = std::time::Duration::from_secs(2);
        let mut buf = [0u8; 512];

        // Before activation: relayed, not forked.
        let pkt = RtpPacket::new(RtpHeader::new(0, 7, 700, ssrc), vec![0x5Au8; 160]);
        let srtp = SrtpProtect::new(&peer_send).protect_rtp(&pkt).unwrap();
        peer.send_to(&srtp, relay_recv_addr).await.unwrap();
        tokio::time::timeout(wait, far.recv_from(&mut buf))
            .await
            .expect("far recv timed out")
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                srs.recv_from(&mut buf)
            )
            .await
            .is_err()
        );

        control.activate(stream, srs.local_addr().unwrap()).unwrap();

        let payload = vec![0xA5u8; 160];
        let pkt = RtpPacket::new(
            RtpHeader::new(8, 8, 860, ssrc).with_marker(true),
            payload.clone(),
        );
        let srtp = SrtpProtect::new(&peer_send).protect_rtp(&pkt).unwrap();
        peer.send_to(&srtp, relay_recv_addr).await.unwrap();

        let (n, _) = tokio::time::timeout(wait, far.recv_from(&mut buf))
            .await
            .expect("far recv timed out")
            .unwrap();
        let out = SrtpUnprotect::new(&far_recv)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(out.payload.as_ref(), payload.as_slice());
        assert_eq!(out.header.ssrc, ssrc, "the call's own packet is unchanged");

        let (n, _) = tokio::time::timeout(wait, srs.recv_from(&mut buf))
            .await
            .expect("recorder recv timed out")
            .unwrap();
        // Neither leg's key opens the recorder's copy.
        assert!(
            SrtpUnprotect::new(&far_recv)
                .unprotect_rtp(&buf[..n])
                .is_err()
        );
        let rec = SrtpUnprotect::new(&srs_recv)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(rec.payload.as_ref(), payload.as_slice());
        assert_eq!(rec.header.ssrc, fork_ssrc);
        assert_eq!(rec.header.payload_type, 8);
        assert!(rec.header.marker);
        assert_eq!(rec.header.timestamp, 860);

        // Muxed SRTCP is relayed but not forked.
        let rtcp = vec![
            0x80, 201, 0x00, 0x02, 0x00, 0x00, 0x66, 0x66, 0x01, 0x02, 0x03, 0x04,
        ];
        let muxed = SrtpProtect::new(&peer_send).protect_rtcp(&rtcp).unwrap();
        peer.send_to(&muxed, relay_recv_addr).await.unwrap();
        tokio::time::timeout(wait, far.recv_from(&mut buf))
            .await
            .expect("far recv timed out")
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                srs.recv_from(&mut buf)
            )
            .await
            .is_err()
        );

        // A packet that fails authentication is neither relayed nor forked.
        let mut forged = SrtpProtect::new(&peer_send)
            .protect_rtp(&RtpPacket::new(
                RtpHeader::new(0, 9, 900, ssrc),
                vec![1u8; 160],
            ))
            .unwrap()
            .to_vec();
        forged[20] ^= 0xFF;
        peer.send_to(&forged, relay_recv_addr).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                srs.recv_from(&mut buf)
            )
            .await
            .is_err()
        );

        let _ = sd_tx.send(true);
        let _ = handle.await;
    }

    // A post-handshake DTLS record (first byte 22) is demuxed to the sidecar
    // channel, not treated as media / forwarded to the far peer.
    #[tokio::test]
    async fn terminate_relay_leg_demuxes_dtls() {
        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_recv_addr = relay_recv.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let far_addr = far.local_addr().unwrap();

        let ssrc = 0x3333_u32;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let (dtls_tx, mut dtls_rx) = mpsc::channel::<Vec<u8>>(4);
        let (sd_tx, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: Arc::clone(&relay_recv),
            send_sock: Arc::clone(&relay_send),
            ingress: ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc),
            egress: ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc),
            expected_remote: peer_addr,
            recv_target: Arc::new(RwLock::new(peer_addr)),
            forward_target: Arc::new(RwLock::new(far_addr)),
            dtls_out: Some(dtls_tx),
            handshake_peers: HandshakePeers::default(),
            media_authenticated: Arc::default(),
            call_id: "call".into(),
            direction: "A→B",
            fork: None,
        };
        let handle = tokio::spawn(leg.run(sd_rx));

        let record = [22u8, 0xFE, 0xFD, 1, 2, 3]; // DTLS 1.2 handshake-ish
        peer.send_to(&record, relay_recv_addr).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), dtls_rx.recv())
            .await
            .expect("dtls demux timed out")
            .expect("channel closed");
        assert_eq!(got, record);
        // The far peer must not receive a DTLS record as "media".
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                far.recv_from(&mut buf)
            )
            .await
            .is_err()
        );

        let _ = sd_tx.send(true);
        let _ = handle.await;
    }

    // PERF-011 (SC-5): a flood of DTLS-class datagrams from the latched peer
    // reaches the sidecar channel at the bucket's burst plus its refill, not
    // at the flood's rate; media on the leg is not affected; and after a
    // pause the peer's records pass again.
    #[tokio::test]
    async fn terminate_relay_leg_rate_limits_post_handshake_dtls() {
        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_recv_addr = relay_recv.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let ssrc = 0x4444_u32;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        // Room for the whole flood: only the bucket limits what arrives.
        let (dtls_tx, mut dtls_rx) = mpsc::channel::<Vec<u8>>(4096);
        let (sd_tx, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: Arc::clone(&relay_recv),
            send_sock: Arc::clone(&relay_send),
            ingress: ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc),
            egress: ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc),
            expected_remote: peer_addr,
            recv_target: Arc::new(RwLock::new(peer_addr)),
            forward_target: Arc::new(RwLock::new(far.local_addr().unwrap())),
            dtls_out: Some(dtls_tx),
            handshake_peers: HandshakePeers::default(),
            media_authenticated: Arc::default(),
            call_id: "call".into(),
            direction: "A→B",
            fork: None,
        };
        let handle = tokio::spawn(leg.run(sd_rx));

        // 2000 handshake-type datagrams, paced so that none is lost in the
        // socket buffer, then one SRTP packet as the end marker.
        let record = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0];
        let started = Instant::now();
        for i in 0..2000 {
            peer.send_to(&record, relay_recv_addr).await.unwrap();
            if i % 50 == 49 {
                tokio::task::yield_now().await;
            }
        }
        let peer_tx = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let rtp = RtpPacket::new(
            RtpHeader::new(0, 1, 160, ssrc),
            Bytes::from_static(&[7; 160]),
        );
        let srtp = SrtpProtect::new(&peer_tx).protect_rtp(&rtp).unwrap();
        peer.send_to(&srtp, relay_recv_addr).await.unwrap();
        // Media is relayed, and by then the leg has seen the whole flood.
        let mut buf = [0u8; 512];
        tokio::time::timeout(Duration::from_secs(5), far.recv_from(&mut buf))
            .await
            .expect("media not relayed during a DTLS flood")
            .unwrap();
        let elapsed_secs = u32::try_from(started.elapsed().as_secs()).unwrap() + 1;

        let mut forwarded = 0_u32;
        while dtls_rx.try_recv().is_ok() {
            forwarded += 1;
        }
        let limit = DTLS_FORWARD_BURST + DTLS_FORWARD_PER_SECOND * elapsed_secs;
        assert!(
            forwarded >= DTLS_FORWARD_BURST && forwarded <= limit,
            "{forwarded} of 2000 flood datagrams reached the sidecar channel, limit {limit}"
        );

        // After a pause a genuine record passes again (a refilled token).
        tokio::time::sleep(Duration::from_millis(600)).await;
        peer.send_to(&record, relay_recv_addr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), dtls_rx.recv())
            .await
            .expect("record after the flood was not forwarded")
            .unwrap();
        assert_eq!(got, record);

        let _ = sd_tx.send(true);
        let _ = handle.await;
    }

    #[test]
    fn dtls_forward_bucket_allows_burst_then_rate() {
        let start = Instant::now();
        let mut bucket = DtlsForwardBucket::new(start);
        let taken = (0..100).filter(|_| bucket.try_take(start)).count();
        assert_eq!(taken, DTLS_FORWARD_BURST as usize);
        // One second later: the rate's worth, no more.
        let later = start + Duration::from_secs(1);
        let taken = (0..100).filter(|_| bucket.try_take(later)).count();
        assert_eq!(taken, DTLS_FORWARD_PER_SECOND as usize);
        // A long pause refills to the burst, not beyond.
        let much_later = later + Duration::from_secs(3600);
        let taken = (0..100).filter(|_| bucket.try_take(much_later)).count();
        assert_eq!(taken, DTLS_FORWARD_BURST as usize);
    }

    #[test]
    fn sidecar_error_text_maps_to_fixed_reason_tokens() {
        for (text, reason) in [
            (
                "peer-close-notify: the peer ended the DTLS association with close_notify",
                CLOSED_PEER_CLOSE_NOTIFY,
            ),
            ("peer-fatal-alert: anything", CLOSED_PEER_FATAL_ALERT),
            (
                "sidecar-shutdown: the DTLS terminator is stopping",
                CLOSED_SIDECAR_SHUTDOWN,
            ),
            (
                "peer ended the DTLS association (close_notify or fatal alert)",
                CLOSED_SIDECAR_ERROR,
            ),
            ("", CLOSED_SIDECAR_ERROR),
        ] {
            let end = SidecarEnd::Reported(text.to_string());
            assert_eq!(end.reason_mid_call(), reason, "{text:?}");
            // Free text is only carried for a reason without a token.
            assert_eq!(
                end.detail().is_empty(),
                reason != CLOSED_SIDECAR_ERROR || text.is_empty()
            );
        }
        assert_eq!(
            SidecarEnd::Disconnected.reason_mid_call(),
            CLOSED_SIDECAR_LOST
        );
        assert_eq!(
            SidecarEnd::Disconnected.reason_at_call_end(),
            CLOSED_CALL_ENDED
        );
        assert_eq!(
            SidecarEnd::Reported("sidecar-shutdown: x".into()).reason_at_call_end(),
            CLOSED_SIDECAR_SHUTDOWN
        );
    }

    // ---- post-handshake sidecar pumps (association lifetime) ----------------

    const MSG_HELLO: u8 = 1;
    const MSG_DTLS: u8 = 3;
    const MSG_ERROR: u8 = 5;

    async fn write_typed(w: &mut tokio::net::unix::OwnedWriteHalf, t: u8, body: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let n = 1 + body.len();
        let mut f = Vec::with_capacity(2 + n);
        f.extend_from_slice(&(u16::try_from(n).unwrap()).to_be_bytes());
        f.push(t);
        f.extend_from_slice(body);
        w.write_all(&f).await.unwrap();
    }

    /// A mock sidecar session after `Ready`, both pumps running against it,
    /// and the peer's socket.
    struct Pumps {
        sidecar_r: tokio::net::unix::OwnedReadHalf,
        sidecar_w: tokio::net::unix::OwnedWriteHalf,
        peer: UdpSocket,
        dtls_tx: mpsc::Sender<Vec<u8>>,
        shutdown: watch::Sender<bool>,
        pump: tokio::task::JoinHandle<()>,
    }

    async fn pumps(name: &str) -> Pumps {
        pumps_with(name, HandshakeFanout::default()).await
    }

    async fn pumps_with(name: &str, fanout: HandshakeFanout) -> Pumps {
        let path =
            std::env::temp_dir().join(format!("usg-pump-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let fp = "sha-384 SIDECAR";
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, fp.as_bytes()).await;
            (r, w)
        });
        let client = crate::dtls_sidecar::SidecarClient::connect(&path, fp)
            .await
            .unwrap();
        let (sidecar_r, sidecar_w) = accept.await.unwrap();
        let _ = std::fs::remove_file(&path);
        let (reader, writer) = client.into_split();

        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Arc::new(RwLock::new(peer.local_addr().unwrap()));
        let (dtls_tx, dtls_rx) = mpsc::channel::<Vec<u8>>(4);
        let (shutdown, sd_rx) = watch::channel(false);
        tokio::spawn(forward_dtls_to_sidecar(dtls_rx, writer, sd_rx.clone()));
        let pump = tokio::spawn(pump_sidecar_dtls_to_peer(
            reader,
            relay,
            target,
            fanout,
            sd_rx,
            AssociationLabel {
                call_id: format!("call-{name}"),
                leg: "A",
            },
        ));
        Pumps {
            sidecar_r,
            sidecar_w,
            peer,
            dtls_tx,
            shutdown,
            pump,
        }
    }

    async fn peer_recv(peer: &UdpSocket) -> Vec<u8> {
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("peer recv timed out")
            .unwrap();
        buf[..n].to_vec()
    }

    // The call ends: the sidecar sees its receiving side closed (and only
    // that side), and the close_notify it then sends still reaches the peer.
    #[tokio::test]
    async fn call_end_half_closes_the_sidecar_and_relays_its_close_notify() {
        use tokio::io::AsyncReadExt;
        let mut p = pumps("close").await;

        // During the call records cross in both directions.
        p.dtls_tx.send(vec![22, 1, 2, 3]).await.unwrap();
        let mut frame = [0u8; 7];
        p.sidecar_r.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0, 5, MSG_DTLS, 22, 1, 2, 3]);
        write_typed(&mut p.sidecar_w, MSG_DTLS, b"final-flight").await;
        assert_eq!(peer_recv(&p.peer).await, b"final-flight");

        p.shutdown.send(true).unwrap();
        // End of stream from the relay: the call is over.
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), p.sidecar_r.read_to_end(&mut rest))
            .await
            .expect("sidecar never saw the connection closed")
            .unwrap();
        assert_eq!(rest, [] as [u8; 0]);
        // The sidecar can still write: close_notify, then it closes.
        write_typed(&mut p.sidecar_w, MSG_DTLS, b"close-notify").await;
        drop(p.sidecar_w);
        assert_eq!(peer_recv(&p.peer).await, b"close-notify");
        tokio::time::timeout(Duration::from_secs(2), p.pump)
            .await
            .expect("pump did not end")
            .unwrap();
    }

    // A sidecar that does not answer the closed connection cannot keep the
    // pump (and the media socket it holds) alive.
    #[tokio::test]
    async fn call_end_is_bounded_when_the_sidecar_does_not_close() {
        let p = pumps("wedged").await;
        let started = std::time::Instant::now();
        p.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), p.pump)
            .await
            .expect("pump did not end")
            .unwrap();
        assert!(started.elapsed() >= SIDECAR_CLOSE_GRACE);
        drop((p.sidecar_r, p.sidecar_w));
    }

    // The sidecar reports that the peer ended the association: the record
    // before the report is relayed, then the pump ends.
    #[tokio::test]
    async fn sidecar_error_after_the_handshake_ends_the_pump() {
        let mut p = pumps("error").await;
        write_typed(&mut p.sidecar_w, MSG_DTLS, b"close-notify-reply").await;
        write_typed(
            &mut p.sidecar_w,
            MSG_ERROR,
            b"peer-close-notify: the peer ended the DTLS association with close_notify",
        )
        .await;
        assert_eq!(peer_recv(&p.peer).await, b"close-notify-reply");
        tokio::time::timeout(Duration::from_secs(2), p.pump)
            .await
            .expect("pump did not end")
            .unwrap();
    }

    // SBC bridges SRTCP across two associations (mirror of the RTP test): peer-A
    // protects → SBC unprotects (A-ingress) + re-protects (B-egress) → peer-B
    // recovers the original RTCP.
    #[tokio::test]
    async fn reprotect_rtcp_bridges_two_associations() {
        let ssrc = 0x0CAF_E123;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let peer_a_send = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let sbc_ingress_a = ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc);
        let sbc_egress_b = ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc);
        let peer_b_recv = ctx(&key_b, &salt_b, SrtpDirection::Inbound, ssrc);

        // Minimal RTCP SR (PT 200): [V|PT][len][ssrc][one word].
        let rtcp = vec![
            0x80, 200, 0x00, 0x02, 0x0C, 0xAF, 0xE1, 0x23, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        assert!(is_rtcp_packet(&rtcp), "PT 200 must classify as RTCP");

        let srtcp_a = SrtpProtect::new(&peer_a_send).protect_rtcp(&rtcp).unwrap();
        let srtcp_b = reprotect_rtcp(&sbc_ingress_a, &sbc_egress_b, &srtcp_a)
            .await
            .unwrap();
        // The A-leg ciphertext must not survive onto the B leg (keys differ).
        assert_ne!(srtcp_a.as_ref(), srtcp_b.as_ref());
        let out = SrtpUnprotect::new(&peer_b_recv)
            .unprotect_rtcp(&srtcp_b)
            .await
            .unwrap();
        assert_eq!(out.as_ref(), rtcp.as_slice());
    }

    // A muxed SRTCP packet received by the relay leg is re-protected via the RTCP
    // path (not the RTP path) and delivered to the far peer, who recovers it.
    #[tokio::test]
    async fn terminate_relay_leg_reprotects_muxed_srtcp() {
        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_recv_addr = relay_recv.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let far_addr = far.local_addr().unwrap();

        let ssrc = 0x4444_u32;
        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let peer_send = ctx(&key_a, &salt_a, SrtpDirection::Outbound, ssrc);
        let ingress = ctx(&key_a, &salt_a, SrtpDirection::Inbound, ssrc);
        let egress = ctx(&key_b, &salt_b, SrtpDirection::Outbound, ssrc);
        let far_recv = ctx(&key_b, &salt_b, SrtpDirection::Inbound, ssrc);

        let (sd_tx, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: Arc::clone(&relay_recv),
            send_sock: Arc::clone(&relay_send),
            ingress,
            egress,
            expected_remote: peer_addr,
            recv_target: Arc::new(RwLock::new(peer_addr)),
            forward_target: Arc::new(RwLock::new(far_addr)),
            dtls_out: None,
            handshake_peers: HandshakePeers::default(),
            media_authenticated: Arc::default(),
            call_id: "call".into(),
            direction: "A→B",
            fork: None,
        };
        let handle = tokio::spawn(leg.run(sd_rx));

        // RTCP RR (PT 201).
        let rtcp = vec![
            0x80, 201, 0x00, 0x02, 0x44, 0x44, 0x44, 0x44, 0x01, 0x02, 0x03, 0x04,
        ];
        let srtcp = SrtpProtect::new(&peer_send).protect_rtcp(&rtcp).unwrap();
        peer.send_to(&srtcp, relay_recv_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), far.recv_from(&mut buf))
                .await
                .expect("far recv timed out")
                .unwrap();
        let out = SrtpUnprotect::new(&far_recv)
            .unprotect_rtcp(&buf[..n])
            .await
            .unwrap();
        assert_eq!(out.as_ref(), rtcp.as_slice());

        let _ = sd_tx.send(true);
        let _ = handle.await;
    }

    // ---- Source latching on the terminated leg ------------------------------
    //
    // The leg's initial latch is the value in `recv_target` when it starts
    // (the handshake's source). Another port on the expected IP moves the
    // latch only with a packet that passes unprotect (and, for RTP, advances
    // the highest authenticated index). DTLS-class datagrams are forwarded to
    // the sidecar from the latched source only.

    /// Captures `tracing` output for the current thread (the tests run on
    /// tokio's current-thread runtime, so the leg's events land here).
    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    fn capture_logs() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        // tracing-core caches a callsite's interest when it is first hit.
        // With a single registered dispatcher it asks only the hitting
        // thread's default, so a concurrent test thread with no subscriber
        // would cache "never" for this thread's capture as well. A second,
        // process-wide dispatcher that is never dropped keeps every capture
        // in the interest computation.
        static KEEP: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        KEEP.get_or_init(|| {
            tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_writer(std::io::sink)
                    .with_max_level(tracing::Level::DEBUG)
                    .finish(),
            )
        });
        let cap = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (cap, guard)
    }

    /// One running leg with its peer-side sockets: `p1` is the seed (the
    /// handshake source), `p2` another port on the same IP.
    struct LatchLeg {
        relay_addr: SocketAddr,
        p1: UdpSocket,
        p2: UdpSocket,
        far: UdpSocket,
        recv_target: Arc<RwLock<SocketAddr>>,
        dtls_rx: mpsc::Receiver<Vec<u8>>,
        media_authenticated: Arc<AtomicBool>,
        peer_send: SrtpContext,
        far_recv: SrtpContext,
        shutdown: watch::Sender<bool>,
        handle: tokio::task::JoinHandle<()>,
    }

    const LATCH_SSRC: u32 = 0x5151_0001;

    async fn latch_leg(direction: &'static str) -> LatchLeg {
        latch_leg_with(direction, false).await
    }

    /// As [`latch_leg`]; with `handshake_peers`, P1 and P2 are both
    /// handshake sources.
    async fn latch_leg_with(direction: &'static str, handshake_peers: bool) -> LatchLeg {
        let relay_recv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_send = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let p1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_recv.local_addr().unwrap();
        let p1_addr = p1.local_addr().unwrap();
        let peers = if handshake_peers {
            HandshakePeers::from_addrs(&[p1_addr, p2.local_addr().unwrap()])
        } else {
            HandshakePeers::default()
        };
        let media_authenticated = Arc::new(AtomicBool::new(false));

        let (key_a, salt_a) = random_material();
        let (key_b, salt_b) = random_material();
        let recv_target = Arc::new(RwLock::new(p1_addr));
        let (dtls_tx, dtls_rx) = mpsc::channel::<Vec<u8>>(16);
        let (shutdown, sd_rx) = watch::channel(false);
        let leg = TerminateRelayLeg {
            recv_sock: relay_recv,
            send_sock: relay_send,
            ingress: ctx(&key_a, &salt_a, SrtpDirection::Inbound, LATCH_SSRC),
            egress: ctx(&key_b, &salt_b, SrtpDirection::Outbound, LATCH_SSRC),
            expected_remote: p1_addr,
            recv_target: Arc::clone(&recv_target),
            forward_target: Arc::new(RwLock::new(far.local_addr().unwrap())),
            dtls_out: Some(dtls_tx),
            handshake_peers: peers,
            media_authenticated: Arc::clone(&media_authenticated),
            call_id: "latch-call".into(),
            direction,
            fork: None,
        };
        let handle = tokio::spawn(leg.run(sd_rx));
        LatchLeg {
            relay_addr,
            p1,
            p2,
            far,
            recv_target,
            dtls_rx,
            media_authenticated,
            peer_send: ctx(&key_a, &salt_a, SrtpDirection::Outbound, LATCH_SSRC),
            far_recv: ctx(&key_b, &salt_b, SrtpDirection::Inbound, LATCH_SSRC),
            shutdown,
            handle,
        }
    }

    impl LatchLeg {
        fn srtp(&self, seq: u16) -> Vec<u8> {
            self.srtp_ssrc(seq, LATCH_SSRC)
        }

        /// SRTP under the leg's key with another SSRC in the header.
        fn srtp_ssrc(&self, seq: u16, ssrc: u32) -> Vec<u8> {
            let pkt = RtpPacket::new(
                RtpHeader::new(0, seq, u32::from(seq) * 160, ssrc),
                vec![0x5A; 160],
            );
            SrtpProtect::new(&self.peer_send)
                .protect_rtp(&pkt)
                .unwrap()
                .to_vec()
        }

        fn srtcp(&self, marker: u8) -> Vec<u8> {
            let rr = [
                0x80, 201, 0, 2, 0x51, 0x51, 0, 1, marker, marker, marker, marker,
            ];
            SrtpProtect::new(&self.peer_send)
                .protect_rtcp(&rr)
                .unwrap()
                .to_vec()
        }

        fn target(&self) -> SocketAddr {
            *self.recv_target.read().unwrap()
        }

        /// The next datagram at the far peer within `ms`, if any.
        async fn far_next(&self, ms: u64) -> Option<Vec<u8>> {
            let mut buf = [0u8; 2048];
            match tokio::time::timeout(Duration::from_millis(ms), self.far.recv_from(&mut buf))
                .await
            {
                Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
                _ => None,
            }
        }

        async fn stop(self) {
            let _ = self.shutdown.send(true);
            let _ = self.handle.await;
        }
    }

    // Port of the review probe `terminate_leg_latches_before_auth`, with the
    // assertions inverted: one unauthenticated datagram from another port on
    // the peer's IP neither captures the latch nor blocks genuine SRTP from
    // the seed.
    // NIST 800-53 Rev5: SC-7, SC-23, SI-10
    #[tokio::test]
    async fn terminate_leg_ignores_unauthenticated_first_datagram() {
        let (logs, _guard) = capture_logs();
        let leg = latch_leg("A→B").await;
        let seed = leg.p1.local_addr().unwrap();

        leg.p2.send_to(&[0x80u8; 40], leg.relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        for seq in 1..=20u16 {
            leg.p1
                .send_to(&leg.srtp(seq), leg.relay_addr)
                .await
                .unwrap();
        }
        // Counted by sequence number once everything is sent, so the result
        // does not depend on per-packet scheduling.
        let mut relayed = std::collections::BTreeSet::new();
        while relayed.len() < 20 {
            let Some(out) = leg.far_next(2000).await else {
                break;
            };
            let rtp = SrtpUnprotect::new(&leg.far_recv)
                .unprotect_rtp(&out)
                .expect("relayed packet must open under the far leg's key");
            relayed.insert(rtp.header.sequence_number);
        }
        assert_eq!(
            relayed,
            (1..=20u16).collect(),
            "genuine SRTP from the seed relayed {}/20",
            relayed.len()
        );
        assert_eq!(leg.target(), seed);

        let text = logs.text();
        assert!(
            !text.contains("media.latch.moved"),
            "no latch move expected:\n{text}"
        );
        assert!(
            text.contains("dropped_unauth_source=1"),
            "the junk datagram is counted as dropped_unauth_source:\n{text}"
        );
        leg.stop().await;
    }

    // NAT rebinding: junk from P2 does not move the latch; genuine SRTP from
    // P2 is relayed and moves it; junk from the old port does not move it
    // back; genuine SRTP from the old port (authenticated, fresh index) does.
    #[tokio::test]
    async fn terminate_leg_relatches_only_on_authenticated_packet() {
        let (logs, _guard) = capture_logs();
        let leg = latch_leg("A→B").await;
        let p1 = leg.p1.local_addr().unwrap();
        let p2 = leg.p2.local_addr().unwrap();

        leg.p2.send_to(&[0x80u8; 40], leg.relay_addr).await.unwrap();
        assert_eq!(leg.far_next(150).await, None, "junk must not be relayed");
        assert_eq!(leg.target(), p1, "junk from P2 moved the latch");

        leg.p2.send_to(&leg.srtp(1), leg.relay_addr).await.unwrap();
        let out = leg
            .far_next(1000)
            .await
            .expect("authenticated SRTP from P2 must be relayed");
        let rtp = SrtpUnprotect::new(&leg.far_recv)
            .unprotect_rtp(&out)
            .unwrap();
        assert_eq!(rtp.header.sequence_number, 1);
        assert_eq!(
            leg.target(),
            p2,
            "authenticated SRTP from P2 moves the latch"
        );

        leg.p1.send_to(&[0x80u8; 40], leg.relay_addr).await.unwrap();
        assert_eq!(leg.far_next(150).await, None);
        assert_eq!(
            leg.target(),
            p2,
            "junk from the old port moved the latch back"
        );

        leg.p1.send_to(&leg.srtp(2), leg.relay_addr).await.unwrap();
        let out = leg
            .far_next(1000)
            .await
            .expect("authenticated SRTP from P1 must be relayed");
        let rtp = SrtpUnprotect::new(&leg.far_recv)
            .unprotect_rtp(&out)
            .unwrap();
        assert_eq!(rtp.header.sequence_number, 2);
        assert_eq!(leg.target(), p1);

        let text = logs.text();
        assert!(
            text.contains("media.latch.moved") && text.contains("srtp-auth"),
            "expected a media.latch.moved event with basis srtp-auth:\n{text}"
        );
        assert!(text.contains("dropped_unauth_source"), "{text}");
        leg.stop().await;
    }

    // A genuine packet already accepted from the seed, replayed from another
    // port, fails the replay check: not relayed, no latch move. A genuine
    // packet that never arrived (lost), replayed from another port after a
    // later one was accepted, authenticates but does not advance the highest
    // index: no latch move.
    #[tokio::test]
    async fn terminate_leg_refuses_replayed_packet_as_relatch() {
        let (logs, _guard) = capture_logs();
        let leg = latch_leg("A→B").await;
        let p1 = leg.p1.local_addr().unwrap();

        let first = leg.srtp(10);
        leg.p1.send_to(&first, leg.relay_addr).await.unwrap();
        assert!(leg.far_next(1000).await.is_some());
        leg.p2.send_to(&first, leg.relay_addr).await.unwrap();
        assert_eq!(leg.far_next(150).await, None, "replay must not be relayed");
        assert_eq!(leg.target(), p1, "replayed packet moved the latch");

        // Captured on the path but lost before the relay.
        let lost = leg.srtp(11);
        leg.p1.send_to(&leg.srtp(12), leg.relay_addr).await.unwrap();
        assert!(leg.far_next(1000).await.is_some());
        leg.p2.send_to(&lost, leg.relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            leg.target(),
            p1,
            "a stale (non-advancing) authenticated packet moved the latch"
        );
        // Both are refused before unprotect, on their own counter.
        let text = logs.text();
        assert!(
            text.contains("dropped_stale_relatch=1"),
            "the replays are counted as dropped_stale_relatch:\n{text}"
        );
        assert!(!text.contains("media.latch.moved"), "{text}");
        leg.stop().await;
    }

    // SRTCP authenticates a relatch too: on the media port (rtcp-mux) and on a
    // separate RTCP-port leg seeded with the SDP RTCP address.
    #[tokio::test]
    async fn terminate_leg_relatches_on_authenticated_srtcp() {
        for direction in ["A→B", "A→B RTCP"] {
            let leg = latch_leg(direction).await;
            let p1 = leg.p1.local_addr().unwrap();
            let p2 = leg.p2.local_addr().unwrap();

            // The seed's first SRTCP is relayed (latched source).
            leg.p1.send_to(&leg.srtcp(1), leg.relay_addr).await.unwrap();
            assert!(
                leg.far_next(1000).await.is_some(),
                "{direction}: SRTCP from the seed"
            );
            // Junk RTCP-looking datagram from P2: dropped, no move.
            let mut junk = vec![0x80u8, 201, 0, 2];
            junk.extend_from_slice(&[0u8; 36]);
            leg.p2.send_to(&junk, leg.relay_addr).await.unwrap();
            assert_eq!(leg.far_next(150).await, None, "{direction}: junk relayed");
            assert_eq!(leg.target(), p1, "{direction}: junk SRTCP moved the latch");

            // Authenticated SRTCP from P2 (rebinding): relayed, latch moves.
            leg.p2.send_to(&leg.srtcp(2), leg.relay_addr).await.unwrap();
            let out = leg.far_next(1000).await;
            assert!(
                out.is_some(),
                "{direction}: authenticated SRTCP from P2 not relayed"
            );
            let out = out.unwrap();
            let rtcp = SrtpUnprotect::new(&leg.far_recv)
                .unprotect_rtcp(&out)
                .await
                .unwrap();
            assert_eq!(rtcp[8], 2);
            assert_eq!(
                leg.target(),
                p2,
                "{direction}: latch did not follow SRTCP auth"
            );
            leg.stop().await;
        }
    }

    // An SRTCP packet already accepted from the seed, replayed from another
    // port, is refused before unprotect by the RTCP replay window: not
    // relayed, no latch move, counted as dropped_stale_relatch. On the media
    // port (rtcp-mux) and on a separate RTCP-port leg.
    // NIST 800-53 Rev5: SC-7, SC-23
    #[tokio::test]
    async fn terminate_leg_refuses_replayed_srtcp_before_unprotect() {
        for direction in ["A→B", "A→B RTCP"] {
            let (logs, _guard) = capture_logs();
            let leg = latch_leg(direction).await;
            let p1 = leg.p1.local_addr().unwrap();

            let first = leg.srtcp(1);
            leg.p1.send_to(&first, leg.relay_addr).await.unwrap();
            assert!(
                leg.far_next(1000).await.is_some(),
                "{direction}: SRTCP from the seed"
            );
            leg.p2.send_to(&first, leg.relay_addr).await.unwrap();
            assert_eq!(
                leg.far_next(150).await,
                None,
                "{direction}: replayed SRTCP relayed"
            );
            assert_eq!(
                leg.target(),
                p1,
                "{direction}: replayed SRTCP moved the latch"
            );

            let text = logs.text();
            assert!(
                text.contains("dropped_stale_relatch=1"),
                "{direction}: the replay is counted as dropped_stale_relatch:\n{text}"
            );
            assert!(!text.contains("media.latch.moved"), "{direction}: {text}");
            leg.stop().await;
        }
    }

    // A DTLS-class datagram from a port that is not latched never reaches the
    // sidecar channel; the latched (seed) source's does.
    #[tokio::test]
    async fn terminate_leg_drops_dtls_from_unlatched_source() {
        let mut leg = latch_leg("A→B").await;
        let p1 = leg.p1.local_addr().unwrap();

        let forged = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0xEE];
        let genuine = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x11];
        leg.p2.send_to(&forged, leg.relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(leg.target(), p1, "DTLS from P2 moved the latch");
        leg.p1.send_to(&genuine, leg.relay_addr).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), leg.dtls_rx.recv())
            .await
            .expect("the seed's DTLS record was not forwarded")
            .unwrap();
        assert_eq!(
            got, genuine,
            "first record at the sidecar must be the seed's"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), leg.dtls_rx.recv())
                .await
                .is_err(),
            "nothing else may reach the sidecar"
        );
        leg.stop().await;
    }

    // Until media authenticates on this side, the sidecar's records also go
    // to every handshake source (a peer whose final flight was lost, on a
    // port the seed did not pick); afterwards to the latched address only.
    // NIST 800-53 Rev5: SC-5 (bounded fan-out), SC-7
    #[tokio::test]
    async fn sidecar_records_fan_out_to_handshake_sources_until_media_authenticates() {
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authenticated = Arc::new(AtomicBool::new(false));
        let mut p = pumps_with(
            "fanout",
            HandshakeFanout {
                peers: HandshakePeers::from_addrs(&[other.local_addr().unwrap()]),
                media_authenticated: Arc::clone(&authenticated),
            },
        )
        .await;

        write_typed(&mut p.sidecar_w, MSG_DTLS, b"final-flight").await;
        assert_eq!(peer_recv(&p.peer).await, b"final-flight");
        assert_eq!(
            peer_recv(&other).await,
            b"final-flight",
            "handshake source did not get the record before media authenticated"
        );

        authenticated.store(true, Ordering::Release);
        write_typed(&mut p.sidecar_w, MSG_DTLS, b"after-auth").await;
        assert_eq!(peer_recv(&p.peer).await, b"after-auth");
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), other.recv_from(&mut buf))
                .await
                .is_err(),
            "record fanned out after media authenticated"
        );
        let _ = p.shutdown.send(true);
        drop(p.sidecar_w);
        let _ = tokio::time::timeout(Duration::from_secs(2), p.pump).await;
    }

    // Until the first packet authenticates, post-handshake DTLS from any
    // handshake source reaches the sidecar (a retransmitted final flight
    // from the port the seed did not pick); a port that was not a handshake
    // source never does; after the first authenticated packet only the
    // latched source's does.
    // NIST 800-53 Rev5: SC-7, SC-5
    #[tokio::test]
    async fn terminate_leg_accepts_handshake_source_dtls_until_media_authenticates() {
        let mut leg = latch_leg_with("A→B", true).await;
        let p3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p1 = leg.p1.local_addr().unwrap();
        let retransmit = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0x33];
        let stranger = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0x44];
        let late = [22u8, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 5, 0, 1, 0x55];

        p3.send_to(&stranger, leg.relay_addr).await.unwrap();
        leg.p2.send_to(&retransmit, leg.relay_addr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), leg.dtls_rx.recv())
            .await
            .expect("the handshake source's DTLS was not forwarded")
            .unwrap();
        assert_eq!(
            got, retransmit,
            "a non-handshake port's DTLS reached the sidecar"
        );
        assert_eq!(leg.target(), p1, "DTLS moved the latch");

        // The peer's first SRTP from the seed authenticates: the window closes.
        leg.p1.send_to(&leg.srtp(1), leg.relay_addr).await.unwrap();
        assert!(leg.far_next(2000).await.is_some());
        assert!(leg.media_authenticated.load(Ordering::Acquire));
        leg.p2.send_to(&late, leg.relay_addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), leg.dtls_rx.recv())
                .await
                .is_err(),
            "handshake-source DTLS forwarded after media authenticated"
        );
        leg.stop().await;
    }

    // Once an SSRC has authenticated on the leg, a packet from
    // another port is only tried under one of the leg's SSRCs. A packet
    // under a new SSRC (even one that would authenticate) neither moves the
    // latch nor is relayed; the known SSRC from the same port does move it.
    #[tokio::test]
    async fn terminate_leg_tries_other_ports_only_under_authenticated_ssrcs() {
        let (logs, _guard) = capture_logs();
        let leg = latch_leg("A→B").await;
        let p2 = leg.p2.local_addr().unwrap();

        leg.p1.send_to(&leg.srtp(1), leg.relay_addr).await.unwrap();
        assert!(leg.far_next(2000).await.is_some());
        leg.p2
            .send_to(&leg.srtp_ssrc(2, 0x0BAD_5555), leg.relay_addr)
            .await
            .unwrap();
        assert_eq!(leg.far_next(200).await, None, "unknown SSRC relayed");
        assert_eq!(leg.target(), leg.p1.local_addr().unwrap());

        leg.p2.send_to(&leg.srtp(3), leg.relay_addr).await.unwrap();
        assert!(leg.far_next(2000).await.is_some());
        assert_eq!(
            leg.target(),
            p2,
            "known SSRC from P2 did not move the latch"
        );
        let text = logs.text();
        assert!(text.contains("dropped_unauth_source=1"), "{text}");
        leg.stop().await;
    }

    // The shape check before a trial unprotect: version, CSRC list, header
    // extension length and tag for SRTP; length and E flag for SRTCP.
    #[test]
    fn could_be_srtp_checks_header_fit() {
        const TAG: usize = 16;
        let mut media = vec![0x80u8, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1];
        media.extend_from_slice(&[0u8; TAG]);
        assert!(could_be_srtp(&media, false, TAG));
        // Version 1.
        let mut v1 = media.clone();
        v1[0] = 0x40;
        assert!(!could_be_srtp(&v1, false, TAG));
        // CC = 15 claims 60 bytes of CSRCs that are not there.
        let mut csrc = media.clone();
        csrc[0] = 0x8F;
        assert!(!could_be_srtp(&csrc, false, TAG));
        // X set: an extension of 0xFFFF words does not fit.
        let mut ext = vec![
            0x90u8, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xBE, 0xDE, 0xFF, 0xFF,
        ];
        ext.extend_from_slice(&[0u8; TAG]);
        assert!(!could_be_srtp(&ext, false, TAG));
        // X set with a one-word extension that fits.
        let mut ext_ok = vec![
            0x90u8, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xBE, 0xDE, 0, 1, 0, 0, 0, 0,
        ];
        ext_ok.extend_from_slice(&[0u8; TAG]);
        assert!(could_be_srtp(&ext_ok, false, TAG));
        // X set but too short for the extension header.
        assert!(!could_be_srtp(&ext[..13], false, TAG));

        let mut control = vec![0x80u8, 201, 0, 1, 0, 0, 0, 1];
        control.extend_from_slice(&[0u8; TAG]);
        control.extend_from_slice(&[0x80, 0, 0, 1]);
        assert!(could_be_srtp(&control, true, TAG));
        let mut no_e = control.clone();
        let e = no_e.len() - 4;
        no_e[e] = 0;
        assert!(!could_be_srtp(&no_e, true, TAG), "SRTCP without the E flag");
        assert!(!could_be_srtp(&control[..control.len() - 1], true, TAG + 1));
        assert!(!could_be_srtp(&[], false, TAG));
    }

    #[test]
    fn authenticated_ssrcs_are_bounded() {
        let mut set = AuthenticatedSsrcs::default();
        assert!(set.is_empty());
        for ssrc in 1..=u32::try_from(MAX_AUTH_SSRCS).unwrap() + 2 {
            set.insert(ssrc);
            set.insert(ssrc);
        }
        assert!(!set.is_empty());
        assert!(set.contains(1));
        assert!(set.contains(u32::try_from(MAX_AUTH_SSRCS).unwrap()));
        assert!(!set.contains(u32::try_from(MAX_AUTH_SSRCS).unwrap() + 1));
        assert_eq!(
            packet_ssrc(&[0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4], false),
            Some(0x0102_0304)
        );
        assert_eq!(
            packet_ssrc(&[0x80, 201, 0, 0, 9, 8, 7, 6], true),
            Some(0x0908_0706)
        );
        assert_eq!(packet_ssrc(&[0x80, 0, 0], false), None);
    }
}
