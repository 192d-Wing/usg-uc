//! HMAC-SHA1 for STUN MESSAGE-INTEGRITY.
//!
//! CNSA-EXCEPTION: RFC 8489 §14.5 / RFC 8445 §7.2.2 (POA&M-500). STUN
//! MESSAGE-INTEGRITY is defined as HMAC-SHA1 with a 20-byte tag; ICE
//! connectivity checks have no other integrity mechanism that every peer
//! implements (MESSAGE-INTEGRITY-SHA256 is optional and not used by ICE
//! short-term credentials). Used for per-message authentication of ICE
//! connectivity checks only, never for confidentiality or key derivation.
//! HMAC-SHA1 remains approved for message authentication under
//! NIST SP 800-131A Rev. 2 and is computed by the aws-lc FIPS module.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), SC-8
// POAM: POA&M-500 (HMAC-SHA1 STUN MESSAGE-INTEGRITY; retire if ICE adopts
// MESSAGE-INTEGRITY-SHA256 or a CNSA alternative).

use aws_lc_rs::{constant_time, hmac};

/// HMAC-SHA1 tag length in bytes.
pub const HMAC_SHA1_OUTPUT_LEN: usize = 20;

/// Computes HMAC-SHA1 of `data` under `key` (RFC 2104).
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_OUTPUT_LEN] {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; HMAC_SHA1_OUTPUT_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verifies an HMAC-SHA1 tag in constant time. A tag of the wrong length
/// fails.
#[must_use]
pub fn verify_hmac_sha1(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    tag.len() == HMAC_SHA1_OUTPUT_LEN
        && constant_time::verify_slices_are_equal(&hmac_sha1(key, data), tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2202 §3 test case 2.
    #[test]
    fn rfc2202_case_2() {
        let tag = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            tag,
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
            ]
        );
        assert!(verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing!",
            &tag
        ));
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag[..19]
        ));
    }
}
