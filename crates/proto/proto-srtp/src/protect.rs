//! SRTP packet protection (encryption/decryption).
//!
//! ## CNSA 2.0 Compliance
//!
//! Uses AES-256-GCM for authenticated encryption per RFC 7714.
//!
//! ## Performance
//!
//! AES key schedules are pre-expanded in [`SrtpContext`] and reused across
//! all `protect`/`unprotect` calls, avoiding ~100ns of key expansion per packet.

use crate::context::SrtpContext;
use crate::error::{SrtpError, SrtpResult};
use bytes::{BufMut, Bytes, BytesMut};
use proto_rtp::packet::{RtpHeader, RtpPacket};

/// SRTP protection (encryption).
pub struct SrtpProtect<'a> {
    context: &'a SrtpContext,
}

impl<'a> SrtpProtect<'a> {
    /// Creates a new SRTP protector.
    pub fn new(context: &'a SrtpContext) -> Self {
        Self { context }
    }

    /// Protects (encrypts) an RTP packet.
    ///
    /// ## RFC 7714: AEAD_AES_256_GCM
    ///
    /// - Encrypts the RTP payload
    /// - Authenticates header + encrypted payload
    /// - Appends 16-byte auth tag
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn protect_rtp(&self, packet: &RtpPacket) -> SrtpResult<Bytes> {
        let index = self
            .context
            .compute_rtp_index(packet.header.sequence_number);
        self.context.update_rtp_state(index);

        let nonce = self
            .context
            .compute_nonce(self.context.rtp_salt(), packet.header.ssrc, index);

        let header_bytes = packet.header.to_bytes();
        let aad = header_bytes.as_ref();

        let ciphertext = self
            .context
            .cached_rtp_key()
            .seal(&nonce, aad, &packet.payload)
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "AES-256-GCM encryption failed".to_string(),
            })?;

        let mut output = BytesMut::with_capacity(header_bytes.len() + ciphertext.len());
        output.put(header_bytes);
        output.put(ciphertext.as_slice());

        Ok(output.freeze())
    }

    /// Protects (encrypts) an RTP payload given a header and raw payload
    /// bytes, without requiring construction of an [`RtpPacket`] (avoids
    /// the `Bytes::copy_from_slice` allocation in the caller).
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn protect_rtp_parts(&self, header: &RtpHeader, payload: &[u8]) -> SrtpResult<Bytes> {
        let index = self.context.compute_rtp_index(header.sequence_number);
        self.context.update_rtp_state(index);

        let nonce = self
            .context
            .compute_nonce(self.context.rtp_salt(), header.ssrc, index);

        // Write header into stack buffer for AAD (max header: 12 + 15*4 = 72 bytes)
        let mut header_buf = [0u8; 128];
        let header_size = header.write_into(&mut header_buf);
        let aad = &header_buf[..header_size];

        let ciphertext = self
            .context
            .cached_rtp_key()
            .seal(&nonce, aad, payload)
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "AES-256-GCM encryption failed".to_string(),
            })?;

        let mut output = BytesMut::with_capacity(header_size + ciphertext.len());
        output.put_slice(aad);
        output.put(ciphertext.as_slice());

        Ok(output.freeze())
    }

    /// Like [`protect_rtp_parts`](Self::protect_rtp_parts) but reuses a
    /// caller-provided scratch buffer for the ciphertext, avoiding one
    /// heap allocation per packet on the hot path.
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn protect_rtp_parts_into(
        &self,
        header: &RtpHeader,
        payload: &[u8],
        scratch: &mut Vec<u8>,
    ) -> SrtpResult<Bytes> {
        let index = self.context.compute_rtp_index(header.sequence_number);
        self.context.update_rtp_state(index);

        let nonce = self
            .context
            .compute_nonce(self.context.rtp_salt(), header.ssrc, index);

        let mut header_buf = [0u8; 128];
        let header_size = header.write_into(&mut header_buf);
        let aad = &header_buf[..header_size];

        self.context
            .cached_rtp_key()
            .seal_into(&nonce, aad, payload, scratch)
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "AES-256-GCM encryption failed".to_string(),
            })?;

        let mut output = BytesMut::with_capacity(header_size + scratch.len());
        output.put_slice(aad);
        output.put_slice(scratch);

        Ok(output.freeze())
    }

    /// Protects (encrypts) an RTCP packet.
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn protect_rtcp(&self, rtcp_data: &[u8]) -> SrtpResult<Bytes> {
        if rtcp_data.len() < 8 {
            return Err(SrtpError::InvalidPacket {
                reason: "RTCP packet too short".to_string(),
            });
        }

        let index = self.context.next_rtcp_index()?;

        let aad = &rtcp_data[..8];
        let plaintext = &rtcp_data[8..];

        let ssrc = u32::from_be_bytes([rtcp_data[4], rtcp_data[5], rtcp_data[6], rtcp_data[7]]);
        let nonce = self
            .context
            .compute_nonce(self.context.rtcp_salt(), ssrc, index as u64);

        let ciphertext = self
            .context
            .cached_rtcp_key()
            .seal(&nonce, aad, plaintext)
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "SRTCP encryption failed".to_string(),
            })?;

        let mut output = BytesMut::with_capacity(aad.len() + ciphertext.len() + 4);
        output.put(aad);
        output.put(ciphertext.as_slice());
        // E flag (1) + index (31 bits)
        output.put_u32(0x80000000 | index);

        Ok(output.freeze())
    }
}

/// SRTP unprotection (decryption).
pub struct SrtpUnprotect<'a> {
    context: &'a SrtpContext,
}

impl<'a> SrtpUnprotect<'a> {
    /// Creates a new SRTP unprotector.
    pub fn new(context: &'a SrtpContext) -> Self {
        Self { context }
    }

    /// Unprotects (decrypts) an SRTP packet.
    ///
    /// # Errors
    /// Returns an error if decryption or authentication fails.
    pub fn unprotect_rtp(&self, data: &[u8]) -> SrtpResult<RtpPacket> {
        let auth_tag_len = self.context.profile().auth_tag_len();

        if data.len() < proto_rtp::RTP_HEADER_MIN_SIZE + auth_tag_len {
            return Err(SrtpError::InvalidPacket {
                reason: "SRTP packet too short".to_string(),
            });
        }

        let (header, header_size) =
            RtpHeader::parse(data).map_err(|e| SrtpError::InvalidPacket {
                reason: e.to_string(),
            })?;

        let index = self.context.compute_rtp_index(header.sequence_number);
        // Read-only replay check before auth; the window is only advanced after
        // the tag verifies (RFC 3711 §3.3.2) so a forged cleartext-header packet
        // cannot poison it.
        self.context.check_replay(index)?;

        let nonce = self
            .context
            .compute_nonce(self.context.rtp_salt(), header.ssrc, index);

        let aad = &data[..header_size];
        let ciphertext = &data[header_size..];

        let plaintext = self
            .context
            .cached_rtp_key()
            .open(&nonce, aad, ciphertext)
            .map_err(|_| SrtpError::AuthenticationFailed)?;

        // Authenticated — now it is safe to advance replay + rollover state.
        self.context.commit_replay(index);
        self.context.update_rtp_state(index);

        Ok(RtpPacket::new(header, plaintext))
    }

    /// Unprotects (decrypts) an SRTCP packet.
    ///
    /// # Errors
    /// Returns an error if decryption or authentication fails.
    #[allow(clippy::unused_async)]
    pub async fn unprotect_rtcp(&self, data: &[u8]) -> SrtpResult<Bytes> {
        let auth_tag_len = self.context.profile().auth_tag_len();

        if data.len() < 8 + auth_tag_len + 4 {
            return Err(SrtpError::InvalidPacket {
                reason: "SRTCP packet too short".to_string(),
            });
        }

        let trailer_offset = data.len() - 4 - auth_tag_len;
        let index_bytes = &data[trailer_offset..trailer_offset + 4];
        let index_word = u32::from_be_bytes([
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ]);

        let e_flag = (index_word & 0x80000000) != 0;
        if !e_flag {
            return Err(SrtpError::InvalidPacket {
                reason: "SRTCP E flag not set".to_string(),
            });
        }

        let index = (index_word & 0x7FFFFFFF) as u64;
        // Read-only replay check before auth; committed only after the tag
        // verifies (RFC 3711 §3.3.2).
        self.context.check_replay(index)?;

        let aad = &data[..8];
        let ciphertext = &data[8..trailer_offset];

        let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let nonce = self
            .context
            .compute_nonce(self.context.rtcp_salt(), ssrc, index);

        let plaintext = self
            .context
            .cached_rtcp_key()
            .open(&nonce, aad, ciphertext)
            .map_err(|_| SrtpError::AuthenticationFailed)?;

        // Authenticated — safe to advance the replay window.
        self.context.commit_replay(index);

        let mut output = BytesMut::with_capacity(8 + plaintext.len());
        output.put(&data[..8]);
        output.put(plaintext.as_slice());

        Ok(output.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SrtpKeyMaterial;
    use crate::{SrtpDirection, SrtpProfile};

    fn test_contexts() -> (SrtpContext, SrtpContext) {
        let material = SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            vec![0x42u8; 32],
            vec![0x24u8; 12],
        )
        .unwrap();

        let sender = SrtpContext::new(&material, SrtpDirection::Outbound, 0xDEADBEEF).unwrap();
        let receiver = SrtpContext::new(&material, SrtpDirection::Inbound, 0xDEADBEEF).unwrap();

        (sender, receiver)
    }

    #[test]
    fn test_rtp_protect_unprotect() {
        let (sender, receiver) = test_contexts();

        let header = RtpHeader::new(0, 1000, 160000, 0xDEADBEEF);
        let payload = vec![0u8; 160];
        let packet = RtpPacket::new(header, payload.clone());

        let protected = SrtpProtect::new(&sender).protect_rtp(&packet).unwrap();
        assert!(protected.len() > packet.size());

        let unprotected = SrtpUnprotect::new(&receiver)
            .unprotect_rtp(&protected)
            .unwrap();

        assert_eq!(unprotected.payload.as_ref(), payload.as_slice());
        assert_eq!(unprotected.header.sequence_number, 1000);
    }

    #[test]
    fn test_tampered_packet() {
        let (sender, receiver) = test_contexts();

        let header = RtpHeader::new(0, 1000, 160000, 0xDEADBEEF);
        let packet = RtpPacket::new(header, vec![0u8; 160]);

        let protected = SrtpProtect::new(&sender).protect_rtp(&packet).unwrap();

        let mut tampered = protected.to_vec();
        tampered[20] ^= 0xFF;

        let result = SrtpUnprotect::new(&receiver).unprotect_rtp(&tampered);
        assert!(matches!(result, Err(SrtpError::AuthenticationFailed)));
    }

    #[test]
    fn test_replay_detection() {
        let (sender, receiver) = test_contexts();

        let header = RtpHeader::new(0, 1000, 160000, 0xDEADBEEF);
        let packet = RtpPacket::new(header, vec![0u8; 160]);

        let protected = SrtpProtect::new(&sender).protect_rtp(&packet).unwrap();

        SrtpUnprotect::new(&receiver)
            .unprotect_rtp(&protected)
            .unwrap();

        let result = SrtpUnprotect::new(&receiver).unprotect_rtp(&protected);
        assert!(matches!(result, Err(SrtpError::ReplayDetected { .. })));
    }

    // Regression for the inverted ROC estimator (C-H2): once highest_seq crosses
    // 0x8000, a reordered (earlier) packet must still authenticate. Reordering is
    // what exposes the bug in a round-trip — in-order traffic hides it because
    // both endpoints would mis-estimate the ROC identically.
    #[test]
    fn reorder_after_median_still_decrypts() {
        let (sender, receiver) = test_contexts();
        let ssrc = 0xDEADBEEF;
        let seal = |seq: u16| {
            let pkt = RtpPacket::new(RtpHeader::new(0, seq, 160_000, ssrc), vec![0xABu8; 160]);
            SrtpProtect::new(&sender).protect_rtp(&pkt).unwrap()
        };

        // Sender emits in order across the median: highest advances 0x8FFE -> 0x9000.
        let low = seal(0x8FFE);
        let high = seal(0x9000);

        // Receiver sees the later packet first, then the reordered earlier one.
        let u_high = SrtpUnprotect::new(&receiver).unprotect_rtp(&high).unwrap();
        assert_eq!(u_high.header.sequence_number, 0x9000);
        // Must still decrypt after reordering — the regression being guarded.
        let u_low = SrtpUnprotect::new(&receiver).unprotect_rtp(&low).unwrap();
        assert_eq!(u_low.header.sequence_number, 0x8FFE);
    }

    // In-order 16-bit rollover round-trips (correctness guard for the
    // index-based update_rtp_state change).
    #[test]
    fn in_order_rollover_round_trips() {
        let (sender, receiver) = test_contexts();
        let ssrc = 0xDEADBEEF;
        for seq in [0xFFFEu16, 0xFFFF, 0x0000, 0x0001, 0x0002] {
            let pkt = RtpPacket::new(RtpHeader::new(0, seq, 160_000, ssrc), vec![0x5Au8; 160]);
            let protected = SrtpProtect::new(&sender).protect_rtp(&pkt).unwrap();
            let out = SrtpUnprotect::new(&receiver)
                .unprotect_rtp(&protected)
                .unwrap();
            assert_eq!(out.header.sequence_number, seq, "seq {seq:#06x} round-trip");
        }
    }

    // Regression for replay-before-auth (C-H1): a forged packet whose cleartext
    // header carries a far-future sequence number must NOT advance the replay
    // window, or every subsequent genuine packet would be rejected as "too old".
    #[test]
    fn forged_packet_does_not_wedge_replay_window() {
        let (sender, receiver) = test_contexts();
        let ssrc = 0xDEADBEEF;
        let seal = |seq: u16| {
            let pkt = RtpPacket::new(RtpHeader::new(0, seq, 160_000, ssrc), vec![0xABu8; 160]);
            SrtpProtect::new(&sender).protect_rtp(&pkt).unwrap()
        };

        // A genuine packet decrypts and sets the window highest to 1000.
        let g1 = seal(1000);
        assert!(SrtpUnprotect::new(&receiver).unprotect_rtp(&g1).is_ok());

        // Forge a far-future packet: sealed under a DIFFERENT key so it fails
        // authentication at the receiver, but its cleartext header seq is 60000.
        let wrong_material = SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            vec![0x99u8; 32],
            vec![0x88u8; 12],
        )
        .unwrap();
        let attacker = SrtpContext::new(&wrong_material, SrtpDirection::Outbound, ssrc).unwrap();
        let forged = {
            let pkt = RtpPacket::new(RtpHeader::new(0, 60000, 160_000, ssrc), vec![0u8; 160]);
            SrtpProtect::new(&attacker).protect_rtp(&pkt).unwrap()
        };
        assert!(matches!(
            SrtpUnprotect::new(&receiver).unprotect_rtp(&forged),
            Err(SrtpError::AuthenticationFailed)
        ));

        // The forged packet must not have poisoned the window: the next genuine
        // in-window packet still decrypts.
        let g2 = seal(1001);
        assert!(
            SrtpUnprotect::new(&receiver).unprotect_rtp(&g2).is_ok(),
            "genuine packet after a forged one must still decrypt"
        );
    }
}
