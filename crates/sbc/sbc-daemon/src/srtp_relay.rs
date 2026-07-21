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

use bytes::Bytes;
use proto_srtp::{SrtpContext, SrtpProtect, SrtpResult, SrtpUnprotect};

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

// NOTE: the SRTCP re-protect (`unprotect_rtcp`/`protect_rtcp`) lands with the
// RTCP relay leg, where it can be tested against a real SRTCP exchange rather
// than shipped untested here.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
}
