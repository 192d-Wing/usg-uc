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

use crate::MAX_PACKET_INDEX;
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

    /// Protects (encrypts) an RTP packet in place, with no heap allocation
    /// on the success path.
    ///
    /// `buf[..packet_len]` holds a complete RTP packet whose header is
    /// `header_len` octets. On success `buf[..header_len]` is unchanged
    /// (it is the AEAD associated data), `buf[header_len..packet_len]` is
    /// the ciphertext and the 16-byte tag follows it; the returned value is
    /// the SRTP packet length (`packet_len + 16`). `buf` must therefore
    /// have at least 16 octets of tail room after `packet_len`.
    ///
    /// Unlike [`protect_rtp`](Self::protect_rtp), the 48-bit packet index
    /// (`ROC || SEQ`, RFC 3711 §3.3.1) is supplied by the caller and this
    /// context's ROC / sequence state is neither read nor advanced. This is
    /// for senders that own their sequence space (the recording fork uses an
    /// SBC-owned SSRC and a per-stream counter). The caller MUST:
    ///
    /// - never pass the same `(SSRC, index)` twice under one key
    ///   (RFC 7714 §8.4: nonce reuse is catastrophic for AES-GCM);
    /// - not mix this method with the index-estimating `protect_rtp*`
    ///   methods on the same context.
    ///
    /// The SSRC is read from the header in `buf`. The header's sequence
    /// number must equal the low 16 bits of `index`, otherwise the receiver
    /// would derive a different index and drop the packet.
    ///
    /// `header_len` is checked against the length implied by the header
    /// itself (CSRC count and extension, RFC 3550 §5.1 / §5.3.1): a larger
    /// value would send payload octets in the clear, a smaller one would
    /// encrypt header fields the receiver needs.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and
    /// Integrity), SC-13 (Cryptographic Protection), SC-5 (no per-packet
    /// allocation), SI-10 (lengths validated, never a panic)
    ///
    /// # Errors
    /// - [`SrtpError::IndexOverflow`] if `index` exceeds 2^48 - 1.
    /// - [`SrtpError::InvalidPacket`] if `buf` lacks the tail room, the
    ///   lengths are inconsistent, or the header is not a valid RTP v2
    ///   header matching `header_len` and `index`.
    /// - [`SrtpError::EncryptionFailed`] if the AEAD seal fails; the
    ///   payload region of `buf` is then unspecified and must not be sent.
    pub fn protect_rtp_in_place(
        &self,
        buf: &mut [u8],
        header_len: usize,
        packet_len: usize,
        index: u64,
    ) -> SrtpResult<usize> {
        // RFC 3711 §3.3.1 / §9.2: the index is 48 bits; past that the key
        // is exhausted and the stream must stop rather than wrap the nonce.
        if index > MAX_PACKET_INDEX {
            return Err(SrtpError::IndexOverflow);
        }

        let tag_len = self.context.profile().auth_tag_len();
        let srtp_len = packet_len
            .checked_add(tag_len)
            .filter(|len| *len <= buf.len())
            .ok_or_else(|| SrtpError::InvalidPacket {
                reason: "buffer too short for RTP packet and auth tag".to_string(),
            })?;

        let invalid_lengths = || SrtpError::InvalidPacket {
            reason: "RTP header length inconsistent with packet".to_string(),
        };
        let (packet, tail) = buf
            .split_at_mut_checked(packet_len)
            .ok_or_else(invalid_lengths)?;
        if rtp_header_len(packet)? != header_len {
            return Err(invalid_lengths());
        }
        let (header, payload) = packet
            .split_at_mut_checked(header_len)
            .ok_or_else(invalid_lengths)?;

        // Fixed header: seq at octets 2..4, SSRC at 8..12 (RFC 3550 §5.1).
        let (Some(&[seq_hi, seq_lo]), Some(&[s0, s1, s2, s3])) =
            (header.get(2..4), header.get(8..12))
        else {
            return Err(invalid_lengths());
        };
        if u64::from(u16::from_be_bytes([seq_hi, seq_lo])) != index & 0xFFFF {
            return Err(SrtpError::InvalidPacket {
                reason: "RTP sequence number does not match packet index".to_string(),
            });
        }
        let ssrc = u32::from_be_bytes([s0, s1, s2, s3]);

        // RFC 7714 §8.1: IV from salt, SSRC and the 48-bit index.
        let nonce = self
            .context
            .compute_nonce(self.context.rtp_salt(), ssrc, index);

        // RFC 7714 §8.2: AAD is the RTP header; payload is encrypted and
        // the tag appended.
        let tag = self
            .context
            .cached_rtp_key()
            .seal_in_place(&nonce, header, payload)
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "AES-256-GCM encryption failed".to_string(),
            })?;

        let tag_out = tail
            .get_mut(..tag_len)
            .filter(|out| out.len() == tag.len())
            .ok_or_else(invalid_lengths)?;
        tag_out.copy_from_slice(&tag);

        Ok(srtp_len)
    }

    /// Protects (encrypts) an RTCP packet as AEAD SRTCP (RFC 7714 §9.2).
    ///
    /// Wire layout: `RTCP header (8) || ciphertext+tag || E-flag+SRTCP-index (4)`.
    /// The AEAD associated data is the 8-byte RTCP header **concatenated with the
    /// 4-byte E+index trailer** — both are authenticated but not encrypted, and
    /// the trailer must be covered or a modified index would go undetected.
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
        // E flag (encrypted) set + 31-bit SRTCP index; part of the AAD.
        let e_index = (0x8000_0000 | index).to_be_bytes();

        let ssrc = u32::from_be_bytes([rtcp_data[4], rtcp_data[5], rtcp_data[6], rtcp_data[7]]);
        let nonce = self
            .context
            .compute_nonce(self.context.rtcp_salt(), ssrc, u64::from(index));

        // AAD = RTCP header (first 8 octets) || E+SRTCP-index trailer.
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&rtcp_data[..8]);
        aad[8..].copy_from_slice(&e_index);

        let ciphertext = self
            .context
            .cached_rtcp_key()
            .seal(&nonce, &aad, &rtcp_data[8..])
            .map_err(|_| SrtpError::EncryptionFailed {
                reason: "SRTCP encryption failed".to_string(),
            })?;

        let mut output = BytesMut::with_capacity(8 + ciphertext.len() + 4);
        output.put(&rtcp_data[..8]);
        output.put(ciphertext.as_slice());
        output.put(&e_index[..]);

        Ok(output.freeze())
    }
}

/// Returns the RTP header length implied by the header octets in `packet`
/// (fixed header, CSRC list, optional extension), with every read bounds
/// checked. Allocation-free counterpart of `RtpHeader::parse` for the
/// in-place protect path.
///
/// RFC 3550 §5.1: 12 fixed octets plus 4 per CSRC. §5.3.1: when X is set, a
/// 4-octet extension header whose length field counts 32-bit words follows.
fn rtp_header_len(packet: &[u8]) -> SrtpResult<usize> {
    let invalid = |reason: &str| SrtpError::InvalidPacket {
        reason: reason.to_string(),
    };

    if packet.len() < proto_rtp::RTP_HEADER_MIN_SIZE {
        return Err(invalid("RTP packet too short"));
    }
    let first = *packet
        .first()
        .ok_or_else(|| invalid("RTP packet too short"))?;
    if first >> 6 != proto_rtp::RTP_VERSION {
        return Err(invalid("RTP version is not 2"));
    }

    let mut len = proto_rtp::RTP_HEADER_MIN_SIZE + usize::from(first & 0x0F) * 4;
    if first & 0x10 != 0 {
        let Some(&[_, _, words_hi, words_lo]) = packet.get(len..len + 4) else {
            return Err(invalid("RTP extension header truncated"));
        };
        len += 4 + usize::from(u16::from_be_bytes([words_hi, words_lo])) * 4;
    }
    if len > packet.len() {
        return Err(invalid("RTP header longer than packet"));
    }
    Ok(len)
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
        self.context.check_rtp_replay(index)?;

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
        self.context.commit_rtp_replay(index);
        self.context.update_rtp_state(index);

        Ok(RtpPacket::new(header, plaintext))
    }

    /// Unprotects (decrypts) an AEAD SRTCP packet (RFC 7714 §9.2).
    ///
    /// Inverse of [`SrtpProtect::protect_rtcp`]: the `E-flag+SRTCP-index` is the
    /// last 4 octets, the AEAD ciphertext (payload + tag) sits between the 8-byte
    /// header and that trailer, and the AAD is `header || E+index`.
    ///
    /// # Errors
    /// Returns an error if decryption or authentication fails.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async kept for API stability with the RTP path"
    )]
    pub async fn unprotect_rtcp(&self, data: &[u8]) -> SrtpResult<Bytes> {
        let auth_tag_len = self.context.profile().auth_tag_len();

        // header(8) + ciphertext(>=tag) + E+SRTCP-index(4).
        if data.len() < 8 + auth_tag_len + 4 {
            return Err(SrtpError::InvalidPacket {
                reason: "SRTCP packet too short".to_string(),
            });
        }

        // The E-flag + 31-bit SRTCP index is the trailing 4 octets.
        let index_start = data.len() - 4;
        let index_word = u32::from_be_bytes([
            data[index_start],
            data[index_start + 1],
            data[index_start + 2],
            data[index_start + 3],
        ]);

        let e_flag = (index_word & 0x80000000) != 0;
        if !e_flag {
            return Err(SrtpError::InvalidPacket {
                reason: "SRTCP E flag not set".to_string(),
            });
        }

        let index = u64::from(index_word & 0x7FFF_FFFF);
        // Read-only replay check before auth; committed only after the tag
        // verifies (RFC 3711 §3.3.2). RTCP has its own replay window.
        self.context.check_rtcp_replay(index)?;

        let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let nonce = self
            .context
            .compute_nonce(self.context.rtcp_salt(), ssrc, index);

        // AAD = RTCP header (first 8 octets) || E+SRTCP-index trailer.
        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&data[..8]);
        aad[8..].copy_from_slice(&data[index_start..]);

        let ciphertext = &data[8..index_start];
        let plaintext = self
            .context
            .cached_rtcp_key()
            .open(&nonce, &aad, ciphertext)
            .map_err(|_| SrtpError::AuthenticationFailed)?;

        // Authenticated — safe to advance the RTCP replay window.
        self.context.commit_rtcp_replay(index);

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

    const TAG: usize = 16;

    /// Serializes `packet` into a fixed buffer with tail room, the way the
    /// recording fork holds it. Returns `(buf, header_len, packet_len)`.
    fn in_place_buf(packet: &RtpPacket) -> ([u8; 512], usize, usize) {
        let wire = packet.to_bytes();
        let mut buf = [0xEEu8; 512];
        buf[..wire.len()].copy_from_slice(&wire);
        (buf, packet.header.size(), wire.len())
    }

    // The in-place path must be byte-identical to the allocating path for
    // the same key, SSRC and index, across header shapes (plain, marker,
    // CSRC list, extension) and an empty payload.
    #[test]
    fn in_place_equals_allocating_protect() {
        let ssrc = 0xDEADBEEF;
        let ext = proto_rtp::packet::ExtensionHeader {
            profile: 0xBEDE,
            data: Bytes::from_static(&[0x10, 0xAA, 0, 0, 0x21, 0xBB, 0xCC, 0]),
        };
        let headers = [
            RtpHeader::new(0, 1000, 160_000, ssrc),
            RtpHeader::new(96, 1000, 160_000, ssrc).with_marker(true),
            RtpHeader::new(8, 1000, 160_000, ssrc)
                .with_csrc(0x0102_0304)
                .with_csrc(0x0506_0708),
            RtpHeader::new(111, 1000, 160_000, ssrc)
                .with_csrc(7)
                .with_extension(ext),
        ];
        for header in headers {
            for payload_len in [0usize, 1, 15, 16, 17, 160] {
                let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
                let packet = RtpPacket::new(header.clone(), payload);

                // Fresh contexts: `protect_rtp` advances estimator state.
                let (alloc_ctx, _) = test_contexts();
                let expected = SrtpProtect::new(&alloc_ctx).protect_rtp(&packet).unwrap();

                let (ctx, _) = test_contexts();
                let (mut buf, header_len, packet_len) = in_place_buf(&packet);
                let n = SrtpProtect::new(&ctx)
                    .protect_rtp_in_place(&mut buf, header_len, packet_len, 1000)
                    .unwrap();

                assert_eq!(n, packet_len + TAG);
                assert_eq!(&buf[..n], expected.as_ref());
                // Nothing past the tag is written.
                assert!(buf[n..].iter().all(|b| *b == 0xEE));
            }
        }
    }

    // A peer context accepts the in-place output with a caller-owned counter
    // as the index, including across the 16-bit wrap (ROC 0 -> 1).
    #[test]
    fn in_place_round_trips_across_counter_wrap() {
        let (sender, receiver) = test_contexts();
        let ssrc = 0xDEADBEEF;
        for index in 0xFFF0u64..=0x1_0010 {
            let seq = (index & 0xFFFF) as u16;
            let payload = vec![seq as u8; 160];
            let packet = RtpPacket::new(RtpHeader::new(0, seq, 160_000, ssrc), payload.clone());
            let (mut buf, header_len, packet_len) = in_place_buf(&packet);

            let n = SrtpProtect::new(&sender)
                .protect_rtp_in_place(&mut buf, header_len, packet_len, index)
                .unwrap();
            // Header (AAD) is left in the clear and untouched.
            assert_eq!(&buf[..header_len], packet.header.to_bytes().as_ref());
            assert_ne!(&buf[header_len..packet_len], payload.as_slice());

            let out = SrtpUnprotect::new(&receiver)
                .unprotect_rtp(&buf[..n])
                .unwrap();
            assert_eq!(out.header.sequence_number, seq, "index {index:#x}");
            assert_eq!(out.header.ssrc, ssrc);
            assert_eq!(out.payload.as_ref(), payload.as_slice());
        }
        // The receiver's estimator followed the sender's counter into ROC 1.
        assert_eq!(receiver.compute_rtp_index(0x0011), 0x1_0011);
    }

    // The supplied index (not the context's own state) drives the nonce: a
    // high ROC from a fresh context matches the allocating path once that
    // path's estimator has been advanced to the same ROC.
    #[test]
    fn in_place_uses_caller_index_for_roc() {
        let ssrc = 0xDEADBEEF;
        let packet = RtpPacket::new(RtpHeader::new(0, 0x0102, 1, ssrc), vec![9u8; 40]);

        let (alloc_ctx, _) = test_contexts();
        alloc_ctx.update_rtp_state(0x7_0101);
        let expected = SrtpProtect::new(&alloc_ctx).protect_rtp(&packet).unwrap();

        let (ctx, _) = test_contexts();
        let (mut buf, header_len, packet_len) = in_place_buf(&packet);
        let n = SrtpProtect::new(&ctx)
            .protect_rtp_in_place(&mut buf, header_len, packet_len, 0x7_0102)
            .unwrap();
        assert_eq!(&buf[..n], expected.as_ref());
        // Context estimator state is not touched by the in-place path.
        assert_eq!(ctx.compute_rtp_index(0x0103), 0x0103);
    }

    // The SSRC in the buffer feeds the nonce, so the same index under two
    // SSRCs never yields the same keystream (RFC 7714 §8.1).
    #[test]
    fn in_place_reads_ssrc_from_header() {
        let (sender, _) = test_contexts();
        let seal = |ssrc: u32| {
            let packet = RtpPacket::new(RtpHeader::new(0, 5, 1, ssrc), vec![0u8; 32]);
            let (mut buf, header_len, packet_len) = in_place_buf(&packet);
            SrtpProtect::new(&sender)
                .protect_rtp_in_place(&mut buf, header_len, packet_len, 5)
                .unwrap();
            buf[header_len..packet_len].to_vec()
        };
        assert_ne!(seal(0x1111_1111), seal(0x2222_2222));
    }

    #[test]
    fn in_place_rejects_bad_lengths_without_writing() {
        let (sender, _) = test_contexts();
        let protect = SrtpProtect::new(&sender);
        let packet = RtpPacket::new(RtpHeader::new(0, 1000, 1, 0xDEADBEEF), vec![0x33u8; 160]);
        let (orig, header_len, packet_len) = in_place_buf(&packet);
        let invalid = |r: SrtpResult<usize>| matches!(r, Err(SrtpError::InvalidPacket { .. }));

        // Tail room: one octet short, none at all, empty buffer.
        let mut buf = orig;
        assert!(invalid(protect.protect_rtp_in_place(
            &mut buf[..packet_len + TAG - 1],
            header_len,
            packet_len,
            1000
        )));
        assert!(invalid(protect.protect_rtp_in_place(
            &mut buf[..packet_len],
            header_len,
            packet_len,
            1000
        )));
        assert!(invalid(protect.protect_rtp_in_place(&mut [], 12, 12, 1000)));
        assert!(invalid(protect.protect_rtp_in_place(&mut [], 0, 0, 0)));
        // Exactly enough tail room is accepted.
        let mut exact = orig;
        assert_eq!(
            protect
                .protect_rtp_in_place(&mut exact[..packet_len + TAG], header_len, packet_len, 1000)
                .unwrap(),
            packet_len + TAG
        );

        // packet_len beyond the buffer, and overflowing usize.
        for bad_len in [buf.len(), buf.len() + 1, usize::MAX - 15, usize::MAX] {
            assert!(invalid(
                protect.protect_rtp_in_place(&mut buf, header_len, bad_len, 1000)
            ));
        }
        // packet_len shorter than a fixed header.
        for bad_len in [0, 1, 11] {
            assert!(invalid(
                protect.protect_rtp_in_place(&mut buf, header_len, bad_len, 1000)
            ));
        }

        // header_len not the header's real length: short (would encrypt
        // header fields), long (would leak payload in clear), past the
        // packet, overflowing.
        for bad_hdr in [0, 8, 11, 13, 16, packet_len, packet_len + 1, usize::MAX] {
            assert!(
                invalid(protect.protect_rtp_in_place(&mut buf, bad_hdr, packet_len, 1000)),
                "header_len {bad_hdr}"
            );
        }

        // Sequence number in the header disagrees with the index.
        assert!(invalid(
            protect.protect_rtp_in_place(&mut buf, header_len, packet_len, 1001)
        ));
        assert!(invalid(protect.protect_rtp_in_place(
            &mut buf, header_len, packet_len, 0x1_0000
        )));

        // Index past 48 bits.
        assert!(matches!(
            protect.protect_rtp_in_place(
                &mut buf,
                header_len,
                packet_len,
                crate::MAX_PACKET_INDEX + 1 + 1000
            ),
            Err(SrtpError::IndexOverflow)
        ));
        assert!(matches!(
            protect.protect_rtp_in_place(&mut buf, header_len, packet_len, u64::MAX),
            Err(SrtpError::IndexOverflow)
        ));

        // Every rejection above left the buffer untouched (no half-sealed
        // packet a caller could send by mistake).
        assert_eq!(buf, orig);
    }

    #[test]
    fn in_place_rejects_malformed_headers() {
        let (sender, _) = test_contexts();
        let protect = SrtpProtect::new(&sender);
        let invalid = |r: SrtpResult<usize>| matches!(r, Err(SrtpError::InvalidPacket { .. }));
        let base = {
            let packet = RtpPacket::new(RtpHeader::new(0, 7, 1, 0xDEADBEEF), vec![0u8; 20]);
            in_place_buf(&packet).0
        };

        // Version 0, 1, 3 (STUN / DTLS / garbage first octets).
        for first in [0x00u8, 0x40, 0xC0, 0x16] {
            let mut buf = base;
            buf[0] = first;
            assert!(invalid(protect.protect_rtp_in_place(&mut buf, 12, 32, 7)));
        }

        // CSRC count claims more than the packet holds.
        let mut buf = base;
        buf[0] = 0x8F; // CC = 15 -> 72-octet header, packet is 32
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 12, 32, 7)));
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 72, 32, 7)));

        // X set, extension header truncated (packet ends inside it).
        let mut buf = base;
        buf[0] = 0x90;
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 12, 14, 7)));
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 16, 15, 7)));

        // X set, extension length runs past the packet.
        let mut buf = base;
        buf[0] = 0x90;
        buf[14] = 0xFF;
        buf[15] = 0xFF;
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 16, 32, 7)));
        assert!(invalid(protect.protect_rtp_in_place(
            &mut buf,
            16 + 0xFFFF * 4,
            32,
            7
        )));

        // X set, zero-length extension: the header is 16 octets, not 12.
        let mut buf = base;
        buf[0] = 0x90;
        buf[14] = 0;
        buf[15] = 0;
        assert!(invalid(protect.protect_rtp_in_place(&mut buf, 12, 32, 7)));
        assert_eq!(
            protect.protect_rtp_in_place(&mut buf, 16, 32, 7).unwrap(),
            48
        );
    }

    // Hostile-input sweep: arbitrary first octets, lengths and header_len
    // values never panic, and success implies a well-formed result.
    #[test]
    fn in_place_never_panics_on_arbitrary_input() {
        let (sender, _) = test_contexts();
        let protect = SrtpProtect::new(&sender);
        // Small deterministic xorshift; no RNG dependency.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0u32;
        for _ in 0..20_000 {
            let mut buf = [0u8; 128];
            for b in &mut buf {
                *b = next() as u8;
            }
            // Bias half the cases toward version 2 so the deeper checks run.
            if next() & 1 == 0 {
                buf[0] = 0x80 | (buf[0] & 0x3F);
            }
            let buf_len = (next() % 129) as usize;
            let packet_len = (next() % 140) as usize;
            let header_len = if next() % 4 == 0 {
                (next() % 140) as usize
            } else {
                // The right value when the header is well formed.
                rtp_header_len(&buf[..packet_len.min(buf_len)]).unwrap_or(12)
            };
            let seq = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
            let index = if next() % 8 == 0 { next() } else { seq };

            if let Ok(n) =
                protect.protect_rtp_in_place(&mut buf[..buf_len], header_len, packet_len, index)
            {
                accepted += 1;
                assert_eq!(n, packet_len + TAG);
                assert!(n <= buf_len);
                assert!((12..=packet_len).contains(&header_len));
            }
        }
        assert!(accepted > 0, "sweep never reached the seal path");
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
