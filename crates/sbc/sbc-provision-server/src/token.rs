//! Provisioning device tokens: `hex(HMAC-SHA-384(secret, normalized_mac))`.
//!
//! Phones never compute or verify the token; they echo an opaque boot URL
//! (`?token=...`) the operator configured out of band (DHCP option 66/150 or
//! the vendor boot-server field). Operators mint it with
//! `sbc-provision-server --mint-token <MAC>` or the equivalent
//! `printf %s <mac> | openssl dgst -sha384 -mac HMAC -macopt hexkey:<secret>`.
//!
//! ## NIST 800-53 Rev5
//! - **SC-13**: Cryptographic Protection (HMAC-SHA-384, CNSA 2.0)
//! - **IA-3 / IA-5**: Device authentication, secret length floor
//! - **SI-10**: Token format validation (length + hex) before decoding

use std::sync::Arc;

use uc_crypto::hash::{hmac_sha384, verify_hmac_sha384};
use zeroize::Zeroizing;

/// Minimum decoded `SBC_PROVISION_SECRET` length in bytes (256 bits).
/// The env value is hex, so at least 64 hex chars (consistent with uc-auth).
pub const MIN_PROVISION_SECRET_BYTES: usize = 32;

/// Hex length of a device token (48-byte HMAC-SHA-384 output).
pub const TOKEN_HEX_LEN: usize = 96;

/// Provisioning shared secret: zeroized on drop, redacted in `Debug`.
///
/// NIST 800-53 Rev5: SC-12 (Cryptographic Key Management)
#[derive(Clone)]
pub struct ProvisionSecret(Arc<Zeroizing<Vec<u8>>>);

impl std::fmt::Debug for ProvisionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionSecret(<redacted>)")
    }
}

impl ProvisionSecret {
    /// Hex-decodes `secret` and rejects keys shorter than
    /// [`MIN_PROVISION_SECRET_BYTES`] decoded bytes, so the floor measures
    /// key material rather than characters. The error string never contains
    /// the secret.
    ///
    /// NIST 800-53 Rev5: IA-5 (Authenticator Management)
    pub fn new(secret: String) -> Result<Self, String> {
        let secret = Zeroizing::new(secret);
        let key =
            Zeroizing::new(hex::decode(secret.trim()).map_err(|_| {
                "secret must be hex-encoded (e.g. `openssl rand -hex 48`)".to_string()
            })?);
        if key.len() < MIN_PROVISION_SECRET_BYTES {
            return Err(format!(
                "secret decodes to {} bytes; at least {MIN_PROVISION_SECRET_BYTES} bytes \
                 ({} hex chars) required",
                key.len(),
                MIN_PROVISION_SECRET_BYTES * 2
            ));
        }
        Ok(Self(Arc::new(key)))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Normalizes a MAC as the token input / DB key: separators removed,
/// lowercase.
pub fn normalize_mac(mac: &str) -> String {
    mac.replace([':', '-'], "").to_lowercase()
}

/// Mints the hex device token for an already-normalized MAC.
pub fn mint_device_token(secret: &ProvisionSecret, mac_key: &str) -> String {
    // NIST 800-53 Rev5: SC-13 — HMAC-SHA-384 in the aws-lc FIPS module.
    hex::encode(hmac_sha384(secret.as_bytes(), mac_key.as_bytes()))
}

/// Verifies `token_hex` for `mac_key` in constant time. Wrong-length
/// (including legacy 64-char HMAC-SHA-256) and non-hex tokens are rejected
/// before any MAC work.
pub fn verify_device_token(secret: &ProvisionSecret, mac_key: &str, token_hex: &str) -> bool {
    if token_hex.len() != TOKEN_HEX_LEN {
        return false;
    }
    let Ok(token_bytes) = hex::decode(token_hex) else {
        return false;
    };
    verify_hmac_sha384(secret.as_bytes(), mac_key.as_bytes(), &token_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn secret() -> ProvisionSecret {
        ProvisionSecret::new(SECRET.to_string()).unwrap()
    }

    #[test]
    fn sha384_token_roundtrip() {
        let s = secret();
        let t = mint_device_token(&s, "aabbccddeeff");
        assert_eq!(t.len(), TOKEN_HEX_LEN);
        assert!(verify_device_token(&s, "aabbccddeeff", &t));
        assert!(verify_device_token(&s, "aabbccddeeff", &t.to_uppercase()));
    }

    #[test]
    fn sha256_legacy_token_rejected() {
        // Legacy tokens were HMAC-SHA-256 (aws-lc-rs dev-dep; not in uc-crypto).
        let key =
            aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &hex::decode(SECRET).unwrap());
        let legacy = hex::encode(aws_lc_rs::hmac::sign(&key, b"aabbccddeeff"));
        assert!(!verify_device_token(&secret(), "aabbccddeeff", &legacy));
    }

    #[test]
    fn wrong_length_and_non_hex_rejected() {
        let s = secret();
        let good = mint_device_token(&s, "aabbccddeeff");
        assert!(!verify_device_token(&s, "aabbccddeeff", ""));
        assert!(!verify_device_token(&s, "aabbccddeeff", &good[..94]));
        assert!(!verify_device_token(
            &s,
            "aabbccddeeff",
            &format!("{good}00")
        ));
        assert!(!verify_device_token(&s, "aabbccddeeff", &"zz".repeat(48)));
        assert!(!verify_device_token(&s, "aabbccddeeff", &"é".repeat(48)));
    }

    #[test]
    fn token_for_other_mac_rejected() {
        let s = secret();
        let t = mint_device_token(&s, "aabbccddeeff");
        assert!(!verify_device_token(&s, "aabbccddee00", &t));
        let other = ProvisionSecret::new(format!("{SECRET}01")).unwrap();
        assert!(!verify_device_token(&other, "aabbccddeeff", &t));
    }

    #[test]
    fn short_provision_secret_rejected() {
        // 32 chars of non-hex text no longer passes the floor.
        assert!(ProvisionSecret::new("x".repeat(MIN_PROVISION_SECRET_BYTES * 2)).is_err());
        // The floor applies to decoded bytes, not characters.
        assert!(ProvisionSecret::new("ab".repeat(MIN_PROVISION_SECRET_BYTES - 1)).is_err());
        assert!(ProvisionSecret::new("ab".repeat(MIN_PROVISION_SECRET_BYTES)).is_ok());
        assert!(ProvisionSecret::new("a".repeat(MIN_PROVISION_SECRET_BYTES * 2 + 1)).is_err());
        let err = ProvisionSecret::new("zz".repeat(40)).err().unwrap();
        assert!(!err.contains("zz"));
        let err = ProvisionSecret::new("hunter2".to_string()).err().unwrap();
        assert!(!err.contains("hunter2"));
        assert!(!format!("{:?}", secret()).contains(SECRET));
    }

    // SR-16 golden vectors (captured from RustCrypto, cross-checked with
    // openssl): the move to uc_crypto::hash::hmac_sha384 must keep every
    // provisioned device token valid.

    /// `printf %s aabbccddeeff | openssl dgst -sha384 -mac HMAC -macopt hexkey:<SECRET>`
    const GOLDEN_TOKEN: &str = "0cacf2d0ac4e2422c81bd69ff3f7137b2f1eb727c83bdf48\
                                f0d5b3ba2ca494edfb94ebf8b39a4258a49cf49811cf5d4a";

    #[test]
    fn device_token_golden_vector() {
        let s = secret();
        assert_eq!(mint_device_token(&s, "aabbccddeeff"), GOLDEN_TOKEN);
        assert!(verify_device_token(&s, "aabbccddeeff", GOLDEN_TOKEN));
        assert!(verify_device_token(
            &s,
            "aabbccddeeff",
            &GOLDEN_TOKEN.to_uppercase()
        ));
        let mut flipped = GOLDEN_TOKEN.to_string();
        flipped.replace_range(0..1, "1");
        assert!(!verify_device_token(&s, "aabbccddeeff", &flipped));
    }

    #[test]
    fn hmac_sha384_rfc4231_test_case_6() {
        // RFC 4231 section 4.7: 131-byte key 0xaa.
        let s = ProvisionSecret::new("aa".repeat(131)).unwrap();
        let data = "Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f\
                        3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952";
        assert_eq!(mint_device_token(&s, data), expected);
        assert!(verify_device_token(&s, data, expected));
    }

    #[test]
    fn normalize_mac_strips_separators() {
        assert_eq!(normalize_mac("AA:BB-CC:dd:EE:ff"), "aabbccddeeff");
    }
}
