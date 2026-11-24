//! TLS 1.2 / DTLS 1.2 services from the FIPS module.
//!
//! Two services that a DTLS 1.2 stack needs beyond the generic primitives in
//! this crate:
//!
//! - [`prf_sha384`]: the TLS 1.2 PRF (RFC 5246 §5) with `P_SHA384`, computed
//!   by the module's TLS KDF (`CRYPTO_tls1_prf`) instead of a hand-composed
//!   HMAC loop. It is a TLS 1.2 protocol KDF, not a general-purpose one: the
//!   label is a [`Tls12Label`], so no other use can be expressed.
//! - [`Tls12GcmSealer`]: AES-256-GCM record sealing with the module's TLS 1.2
//!   GCM construction, which refuses a nonce whose 64-bit explicit part does
//!   not increase.
//!
//! ## CNSA 2.0
//!
//! SHA-384 and AES-256-GCM only; no other hash or key size is reachable.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
//!
//! Both services run inside aws-lc. Note for assessors: the module's
//! approved-service indicator for the TLS 1.2 KDF is set only for the
//! `"extended master secret"` label (RFC 7627). The same function is used
//! here for the `key expansion`, `finished` and exporter labels, as every
//! TLS 1.2 stack on this module does; those calls compute inside the module
//! but are not individually flagged by the indicator.
//!
//! POAM: POA&M-332 (SC-13) -- approved-service status of the TLS 1.2 PRF for
//! key expansion, `Finished` and the RFC 5705 exporter is not shown by the
//! module's service indicator; evidence (CMVP certificate and Security
//! Policy, CAVP TLS v1.2 KDF RFC 7627 SHA2-384, lab/ISSO statement for the
//! other labels) is to be collected for the ATO package.

use crate::aead::{KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, TlsProtocolId, TlsRecordSealingKey};
use aws_lc_rs::tls_prf::{P_SHA384, Secret};

/// The labels the TLS 1.2 PRF is used with (SEC-008).
///
/// A closed set: the PRF is a protocol KDF for TLS 1.2 / DTLS 1.2 key
/// schedules and must not become a general-purpose KDF through an arbitrary
/// label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tls12Label {
    /// `"extended master secret"` (RFC 7627 §4). The one label for which the
    /// module's approved-service indicator is set.
    ExtendedMasterSecret,
    /// `"key expansion"` (RFC 5246 §6.3).
    KeyExpansion,
    /// `"client finished"` (RFC 5246 §7.4.9).
    ClientFinished,
    /// `"server finished"` (RFC 5246 §7.4.9).
    ServerFinished,
    /// `"EXTRACTOR-dtls_srtp"` (RFC 5705 §4, RFC 5764 §4.2).
    ExporterDtlsSrtp,
}

impl Tls12Label {
    /// The label bytes as they enter the PRF.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::ExtendedMasterSecret => b"extended master secret",
            Self::KeyExpansion => b"key expansion",
            Self::ClientFinished => b"client finished",
            Self::ServerFinished => b"server finished",
            Self::ExporterDtlsSrtp => b"EXTRACTOR-dtls_srtp",
        }
    }
}

/// TLS 1.2 PRF with `P_SHA384` (RFC 5246 §5): fills `out` with
/// `PRF(secret, label, seed)`. For TLS 1.2 / DTLS 1.2 key schedules only.
///
/// The intermediate buffer returned by the module is wiped by aws-lc-rs when
/// it is dropped; `out` belongs to the caller, who wipes it if it is secret.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment), SC-13
///
/// Computed by the FIPS module's TLS 1.2 KDF. The module's approved-service
/// indicator is set only for [`Tls12Label::ExtendedMasterSecret`]; see the
/// module documentation (POA&M-332).
///
/// # Errors
/// Returns [`CryptoError::KeyDerivationFailed`] if `secret` or `out` is
/// empty, or if the module rejects the derivation.
pub fn prf_sha384(
    secret: &[u8],
    label: Tls12Label,
    seed: &[u8],
    out: &mut [u8],
) -> CryptoResult<()> {
    prf_sha384_raw(secret, label.as_bytes(), seed, out)
}

/// The PRF with an arbitrary label. Private: callers go through
/// [`prf_sha384`] and its closed label set.
fn prf_sha384_raw(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) -> CryptoResult<()> {
    if out.is_empty() {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let derived = Secret::new(&P_SHA384, secret)
        .and_then(|s| s.derive(label, seed, out.len()))
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let bytes: &[u8] = derived.as_ref();
    if bytes.len() != out.len() {
        return Err(CryptoError::KeyDerivationFailed);
    }
    out.copy_from_slice(bytes);
    Ok(())
}

/// AES-256-GCM sealing key for TLS 1.2 / DTLS 1.2 records (RFC 5288).
///
/// Wraps the module's TLS 1.2 GCM AEAD. The last eight bytes of each nonce
/// (the explicit part: the TLS sequence number, or epoch and sequence number
/// in DTLS) must be strictly greater than those of the previous call, so a
/// nonce can never be reused under one key.
///
/// ## Key material lifecycle
///
/// The key lives only inside an aws-lc AEAD context, which aws-lc cleanses
/// when it is freed. This type holds no key bytes of its own, is not `Clone`
/// and prints nothing secret.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), SC-12
pub struct Tls12GcmSealer {
    key: TlsRecordSealingKey,
}

impl Tls12GcmSealer {
    /// Creates a sealer from a 32-byte AES-256 key.
    ///
    /// The caller still owns (and should wipe) its copy of `key`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKeyMaterial`] if the module rejects the key.
    pub fn new(key: &[u8; KEY_LEN]) -> CryptoResult<Self> {
        let key = TlsRecordSealingKey::new(&AES_256_GCM, TlsProtocolId::TLS12, key)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self { key })
    }

    /// Seals `plaintext`, returning the ciphertext with the 16-byte tag appended.
    ///
    /// # Errors
    /// Returns [`CryptoError::SealFailed`] if sealing fails, including when
    /// the explicit part of `nonce` is not greater than the previous one.
    pub fn seal(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let mut in_out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| CryptoError::SealFailed)?;
        Ok(in_out)
    }
}

impl std::fmt::Debug for Tls12GcmSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls12GcmSealer")
            .field("algorithm", &"AES-256-GCM (TLS 1.2)")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::aead::{Aes256GcmKey, CachedAeadKey};
    use crate::hkdf::hmac_sha384_multi;

    /// Reference `P_SHA384` composed from HMAC (RFC 5246 §5), used only to
    /// cross-check the module KDF.
    fn reference_prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut a = hmac_sha384_multi(secret, &[label, seed]);
        while out.len() < len {
            out.extend_from_slice(&hmac_sha384_multi(secret, &[&a, label, seed]));
            a = hmac_sha384_multi(secret, &[&a]);
        }
        out.truncate(len);
        out
    }

    fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
    }

    /// Widely circulated TLS 1.2 PRF SHA-384 vector ("test label").
    #[test]
    fn prf_sha384_known_answer() {
        let secret = unhex("b80b733d6ceefcdc71566ea48e5567df");
        let seed = unhex("cd665cf6a8447dd6ff8b27555edb7465");
        let expected = unhex(
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd\
             e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd\
             8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425\
             9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6\
             91c8f3a26854308d5eaa3be85e0990703d73e56f",
        );
        assert_eq!(expected.len(), 148);
        let mut out = vec![0u8; 148];
        prf_sha384_raw(&secret, b"test label", &seed, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn prf_sha384_matches_hmac_composition() {
        for (i, len) in [1usize, 12, 47, 48, 49, 72, 88, 96, 200]
            .into_iter()
            .enumerate()
        {
            let secret = crate::random::generate_random::<48>().unwrap();
            let seed = crate::random::generate_random::<64>().unwrap();
            let label = [
                Tls12Label::ExtendedMasterSecret,
                Tls12Label::KeyExpansion,
                Tls12Label::ClientFinished,
                Tls12Label::ServerFinished,
                Tls12Label::ExporterDtlsSrtp,
            ][i % 5];
            let mut out = vec![0u8; len];
            prf_sha384(&secret, label, &seed, &mut out).unwrap();
            assert_eq!(out, reference_prf(&secret, label.as_bytes(), &seed, len));
        }
    }

    #[test]
    fn prf_sha384_rejects_empty_inputs() {
        let mut out = [0u8; 12];
        let label = Tls12Label::KeyExpansion;
        assert!(prf_sha384(&[], label, b"s", &mut out).is_err());
        assert!(prf_sha384(b"k", label, b"s", &mut []).is_err());
    }

    #[test]
    fn labels_are_the_rfc_strings() {
        let labels = [
            (Tls12Label::ExtendedMasterSecret, "extended master secret"),
            (Tls12Label::KeyExpansion, "key expansion"),
            (Tls12Label::ClientFinished, "client finished"),
            (Tls12Label::ServerFinished, "server finished"),
            (Tls12Label::ExporterDtlsSrtp, "EXTRACTOR-dtls_srtp"),
        ];
        for (label, text) in labels {
            assert_eq!(label.as_bytes(), text.as_bytes());
        }
    }

    fn dtls_nonce(iv: [u8; 4], epoch: u16, seq: u64) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&iv);
        nonce[4..6].copy_from_slice(&epoch.to_be_bytes());
        nonce[6..].copy_from_slice(&seq.to_be_bytes()[2..]);
        nonce
    }

    /// The DTLS explicit nonce (epoch || sequence) is accepted, and the
    /// output opens with the plain AES-256-GCM opener.
    #[test]
    fn sealer_accepts_dtls_nonces_and_interoperates_with_opener() {
        let key_bytes = [0x42u8; KEY_LEN];
        let mut sealer = Tls12GcmSealer::new(&key_bytes).unwrap();
        let opener = Aes256GcmKey::new(key_bytes).unwrap();
        let cached = CachedAeadKey::new(&key_bytes).unwrap();
        for seq in [0u64, 1, 2, 7, 1 << 40] {
            let nonce = dtls_nonce([1, 2, 3, 4], 1, seq);
            let record = sealer.seal(&nonce, b"aad", b"record").unwrap();
            assert_eq!(record.len(), 6 + TAG_LEN);
            assert_eq!(opener.open(&nonce, b"aad", &record).unwrap(), b"record");
            assert_eq!(record, cached.seal(&nonce, b"aad", b"record").unwrap());
        }
    }

    #[test]
    fn sealer_refuses_repeated_or_decreasing_nonce() {
        let mut sealer = Tls12GcmSealer::new(&[7u8; KEY_LEN]).unwrap();
        let n5 = dtls_nonce([0; 4], 1, 5);
        sealer.seal(&n5, b"", b"x").unwrap();
        assert!(sealer.seal(&n5, b"", b"x").is_err());
        assert!(sealer.seal(&dtls_nonce([0; 4], 1, 4), b"", b"x").is_err());
        sealer.seal(&dtls_nonce([0; 4], 1, 6), b"", b"x").unwrap();
    }

    #[test]
    fn sealer_debug_is_redacted() {
        let sealer = Tls12GcmSealer::new(&[0xAAu8; KEY_LEN]).unwrap();
        let text = format!("{sealer:?}");
        assert!(text.contains("REDACTED"));
        assert!(!text.to_lowercase().contains("aaaa"));
    }
}
