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
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use proto_srtp::{SrtpContext, SrtpProtect, SrtpResult, SrtpUnprotect};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::dtls_relay::is_dtls_record;
use crate::dtls_sidecar::{SidecarEvent, SidecarReader, SidecarWriter};

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

/// One direction of a terminated media relay: reads SRTP from `recv_sock`,
/// re-protects it for the far leg, and sends it on `send_sock`. Post-handshake
/// DTLS records (rekey/alerts, first byte 20..=63) are forwarded to the sidecar
/// via `dtls_out` rather than treated as media.
pub struct TerminateRelayLeg {
    /// Socket this leg receives the near peer's SRTP/DTLS on.
    pub recv_sock: Arc<UdpSocket>,
    /// Socket to send re-protected media to the far peer on.
    pub send_sock: Arc<UdpSocket>,
    /// Unprotects packets arriving on `recv_sock` (this leg's ingress key).
    pub ingress: SrtpContext,
    /// Protects packets sent on `send_sock` (the far leg's egress key).
    pub egress: SrtpContext,
    /// The near peer's SDP media address (until the source is latched).
    pub expected_remote: SocketAddr,
    /// Shared latch for this leg's near-peer address (the opposite direction
    /// sends here); updated on the first accepted packet.
    pub recv_target: Arc<RwLock<SocketAddr>>,
    /// Where to send re-protected media — the far leg's latched address.
    pub forward_target: Arc<RwLock<SocketAddr>>,
    /// Post-handshake DTLS records demuxed off `recv_sock` go here (to the
    /// sidecar). `None` drops them (e.g. in tests / if rekey is unsupported).
    pub dtls_out: Option<mpsc::Sender<Vec<u8>>>,
    /// Call id for logging.
    pub call_id: String,
    /// Direction label for logging ("A→B" / "B→A").
    pub direction: &'static str,
}

impl TerminateRelayLeg {
    /// Runs the relay loop until `shutdown` fires or the socket errors.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut buf = [0u8; 2048];
        let mut latched: Option<SocketAddr> = None;
        let mut forwarded: u64 = 0;
        // Kept separate so an off-path spoofing attempt (SC-7 boundary event) is
        // distinguishable from crypto/keying breakage or sidecar backpressure.
        let mut dropped_source: u64 = 0;
        let mut dropped_auth: u64 = 0;
        let mut dropped_dtls: u64 = 0;

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

                    // Source filter: before latching accept only the SDP peer's
                    // IP; after, only the exact latched source (symmetric RTP).
                    let acceptable = latched.map_or_else(
                        || src.ip() == self.expected_remote.ip(),
                        |latched_src| src == latched_src,
                    );
                    if !acceptable {
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
                    if latched.is_none() {
                        latched = Some(src);
                        if let Ok(mut t) = self.recv_target.write() {
                            *t = src;
                        }
                    }

                    // Demux (RFC 7983 + RFC 5761): post-handshake DTLS (rekey/
                    // alert) → sidecar; otherwise SRTP media or muxed SRTCP →
                    // reprotect for the far leg and forward.
                    if is_dtls_record(buf[0]) {
                        // Non-blocking send: awaiting on this bounded channel would
                        // let sidecar backpressure head-of-line block all media
                        // forwarding on this leg. A dropped rekey record is
                        // retransmitted by DTLS, so dropping is safe.
                        if let Some(tx) = &self.dtls_out
                            && tx.try_send(buf[..n].to_vec()).is_err()
                        {
                            dropped_dtls += 1;
                            if dropped_dtls == 1 || dropped_dtls.is_multiple_of(1000) {
                                warn!(call_id = %self.call_id, direction = self.direction, dropped_dtls, "sidecar DTLS channel full/closed; dropping rekey record");
                            }
                        }
                        continue;
                    }

                    let is_rtcp = is_rtcp_packet(&buf[..n]);
                    let reprotected = if is_rtcp {
                        reprotect_rtcp(&self.ingress, &self.egress, &buf[..n]).await
                    } else {
                        reprotect_rtp(&self.ingress, &self.egress, &buf[..n])
                    };
                    let reprotected = match reprotected {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            // Auth/replay/short-packet failures are dropped, never
                            // forwarded — the SBC must not emit unauthenticated media.
                            dropped_auth += 1;
                            if dropped_auth == 1 || dropped_auth.is_multiple_of(1000) {
                                warn!(error = %e, call_id = %self.call_id, direction = self.direction, is_rtcp, dropped_auth, "SRTP/SRTCP unprotect failed; dropping");
                            }
                            continue;
                        }
                    };

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
                _ = shutdown.changed() => {
                    debug!(call_id = %self.call_id, direction = self.direction, "SRTP relay shutdown");
                    break;
                }
            }
        }
    }
}

/// Forwards post-handshake DTLS records (peer-initiated rekey/alerts, demuxed
/// off the media socket by [`TerminateRelayLeg`]) to the sidecar. Owns the
/// [`SidecarWriter`] so the sidecar connection stays open for the whole call
/// (the DTLS association must outlive key export); ends on shutdown, a closed
/// channel, or a sidecar write error.
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

/// Pumps DTLS records the sidecar emits *after* the handshake (sidecar-initiated
/// rekey) back to the peer on the media socket. Owns the [`SidecarReader`] so the
/// connection stays open for the call; ends on shutdown or a reader error. A
/// terminal `Ready`/`Error` (unexpected post-handshake) also ends it.
pub async fn pump_sidecar_dtls_to_peer(
    mut reader: SidecarReader,
    sock: Arc<UdpSocket>,
    peer: Arc<RwLock<SocketAddr>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            event = reader.read() => match event {
                Ok(SidecarEvent::Dtls(record)) => {
                    let dest = match peer.read() {
                        Ok(g) => *g,
                        Err(_) => break,
                    };
                    let _ = sock.send_to(&record, dest).await;
                }
                Ok(_) => break,
                Err(e) => {
                    debug!(error = %e, "sidecar reader ended");
                    break;
                }
            },
            _ = shutdown.changed() => break,
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
            call_id: "call".into(),
            direction: "A→B",
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
            call_id: "call".into(),
            direction: "A→B",
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
            call_id: "call".into(),
            direction: "A→B",
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
}
