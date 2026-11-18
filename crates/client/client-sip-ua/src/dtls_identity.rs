//! The soft client's DTLS-SRTP identity: certificate, private key and SDP
//! fingerprint.
//!
//! DTLS-SRTP certificates are bound to the call by the SDP `a=fingerprint`
//! carried over TLS signalling, not by a CA (RFC 5763 §5, RFC 8122). The
//! client therefore generates an ephemeral self-signed P-384 certificate once
//! per process unless an exportable P-384 user key is configured. On the
//! smart-card path the private key is not exportable, so the ephemeral
//! identity is kept.
//!
//! Ported from `sbc-media-core/src/dtls_identity.rs::generate()`; client
//! crates cannot depend on SBC crates. Follow-up: move the generator into
//! `proto-dtls` behind an `rcgen` feature and share it.
//!
//! ## NIST 800-53 Rev5 Controls
//! - **SC-12**: Cryptographic Key Establishment and Management (DTLS-SRTP
//!   identity; redacted `Debug`, no `Clone`). The signing key is loaded
//!   into one `uc_crypto` key pair per identity and shared with every
//!   call's DTLS association by reference count
//!   ([`DtlsIdentity::credentials`]): no per-call copy of the key is made.
//!   The PKCS#8 encoding the identity is built from is not kept: it is
//!   wiped (`Zeroizing`) when construction returns, so the only copy of
//!   the private key the identity holds is the one inside that key pair.
//!   POAM: POA&M-330 -- the `rcgen::KeyPair` copy made while generating or
//!   checking the identity is not zeroized, and the key inside the
//!   `uc_crypto` key pair stays in memory for the life of the process.
//! - **SC-13**: Cryptographic Protection (P-384 / SHA-384, CNSA 2.0)
//! - **SI-10**: a user certificate is used only if its SPKI matches the key
//!   and it is signed with ecdsa-with-SHA384

use crate::{SipUaError, SipUaResult};
use proto_dtls::{CertificateFingerprint, DtlsCredentials};
use std::sync::Arc;
use uc_crypto::ecdsa::P384KeyPair;
use zeroize::Zeroizing;

/// Subject CN of the ephemeral self-signed certificate.
const IDENTITY_CN: &str = "usg-client";

/// DTLS-SRTP identity (DER certificate chain, signing key, fingerprint).
pub struct DtlsIdentity {
    /// DER-encoded certificate chain (leaf first).
    cert_chain_der: Vec<Vec<u8>>,
    /// SHA-384 fingerprint of the leaf certificate.
    fingerprint: CertificateFingerprint,
    /// Chain and signing key in the form the DTLS association takes; the
    /// key pair is built once here and shared by reference count.
    credentials: DtlsCredentials,
}

impl std::fmt::Debug for DtlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl DtlsIdentity {
    /// Generates an ephemeral self-signed P-384/SHA-384 identity (CNSA 2.0).
    ///
    /// CPU-bound (one P-384 keygen and signature, about 1 ms). The call
    /// manager calls it once, synchronously, in `CallManager::new`; never
    /// call it per call or per packet.
    ///
    /// # Errors
    /// Returns [`SipUaError::CertificateError`] if key generation or
    /// self-signing fails.
    pub fn generate() -> SipUaResult<Self> {
        let (cert_der, key_der) = Self::generate_der()?;
        Self::from_der(vec![cert_der], key_der)
    }

    /// The certificate and PKCS#8 key of a new ephemeral identity.
    fn generate_der() -> SipUaResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};

        let err = |e: rcgen::Error| SipUaError::CertificateError(e.to_string());
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).map_err(err)?;
        let params = CertificateParams::new(vec![IDENTITY_CN.to_string()]).map_err(err)?;
        let cert = params.self_signed(&key_pair).map_err(err)?;

        let cert_der = cert.der().to_vec();
        let key_der = Zeroizing::new(key_pair.serialize_der());
        Ok((cert_der, key_der))
    }

    /// Builds an identity from a DER certificate chain and PKCS#8 key.
    ///
    /// NIST 800-53 Rev5: SC-12 -- `key_der` is consumed: it is loaded into
    /// the key pair and wiped when this function returns. The identity
    /// keeps no encoding of the private key.
    ///
    /// # Errors
    /// Returns [`SipUaError::CertificateError`] if the chain or key is
    /// empty, the key is not a PKCS#8 P-384 key, or the leaf certificate
    /// does not hold that key.
    pub fn from_der(
        cert_chain_der: Vec<Vec<u8>>,
        key_der: Zeroizing<Vec<u8>>,
    ) -> SipUaResult<Self> {
        let leaf = cert_chain_der
            .first()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| SipUaError::CertificateError("empty DTLS certificate chain".into()))?;
        if key_der.is_empty() {
            return Err(SipUaError::CertificateError(
                "DTLS private key is not exportable".into(),
            ));
        }
        let fingerprint = CertificateFingerprint::from_certificate_sha384(leaf);
        // NIST 800-53 Rev5: SC-12 / SC-13 -- the key is loaded into the
        // FIPS module once per identity; associations share it. Fixed error
        // text: nothing of the key or the parser's message is reflected.
        let key_pair = P384KeyPair::from_pkcs8(&key_der).map_err(|_| {
            SipUaError::CertificateError("DTLS key is not a PKCS#8 P-384 key (CNSA 2.0)".into())
        })?;
        // NIST 800-53 Rev5: SC-12 -- the PKCS#8 encoding is not needed
        // any more; wipe it now rather than keep it with the identity.
        drop(key_der);
        let credentials = DtlsCredentials::new(cert_chain_der.clone(), Arc::new(key_pair))
            .map_err(|_| {
                SipUaError::CertificateError(
                    "DTLS certificate does not match the private key".into(),
                )
            })?;
        Ok(Self {
            cert_chain_der,
            fingerprint,
            credentials,
        })
    }

    /// Builds an identity from a user-supplied certificate chain and
    /// PKCS#8 key, accepting only an exportable P-384 (ECDSA SHA-384) key
    /// (CNSA 2.0). Smart-card keys are not exportable (empty), so callers
    /// keep the ephemeral identity in that case.
    ///
    /// # Errors
    /// Returns [`SipUaError::CertificateError`] if the key is empty, does not
    /// parse as PKCS#8, or is not P-384.
    pub fn from_user_der(
        cert_chain_der: Vec<Vec<u8>>,
        key_der: Zeroizing<Vec<u8>>,
    ) -> SipUaResult<Self> {
        check_user_identity(&cert_chain_der, &key_der)?;
        Self::from_der(cert_chain_der, key_der)
    }

    /// The SDP `a=fingerprint` value (e.g. `sha-384 AB:CD:...`), exactly one
    /// hash-name prefix.
    #[must_use]
    pub fn sdp_fingerprint(&self) -> String {
        self.fingerprint.to_sdp()
    }

    /// The leaf certificate fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &CertificateFingerprint {
        &self.fingerprint
    }

    /// Certificate chain and signing key for a DTLS association
    /// (`proto_dtls::AssociationConfig::credentials`). Cloning shares the
    /// key; it does not copy it.
    #[must_use]
    pub const fn credentials(&self) -> &DtlsCredentials {
        &self.credentials
    }

    /// DER-encoded certificate chain (leaf first).
    #[must_use]
    pub fn cert_chain_der(&self) -> &[Vec<u8>] {
        &self.cert_chain_der
    }
}

/// Checks a user-supplied certificate chain and PKCS#8 key (CNSA 2.0).
///
/// The key must be ECDSA P-384, the leaf certificate must carry that key's
/// public key, and the leaf must be signed with ecdsa-with-SHA384. Shared
/// by the DTLS identity and the SIP-TLS client certificate.
///
/// # Errors
/// Returns [`SipUaError::CertificateError`] if the key is not PKCS#8 or not
/// P-384, the chain is empty or not DER, the leaf does not match the key,
/// or the leaf is not signed with ecdsa-with-SHA384.
// NIST 800-53 Rev5: SC-13, SI-10 (CNSA 2.0 identity; key proves the leaf).
pub fn check_user_identity(cert_chain_der: &[Vec<u8>], key_der: &[u8]) -> SipUaResult<()> {
    let key_pair = rcgen::KeyPair::try_from(key_der)
        .map_err(|_| SipUaError::CertificateError("key is not PKCS#8".into()))?;
    if key_pair.algorithm() != &rcgen::PKCS_ECDSA_P384_SHA384 {
        return Err(SipUaError::CertificateError(
            "key must be ECDSA P-384 (CNSA 2.0)".into(),
        ));
    }
    let leaf = cert_chain_der
        .first()
        .ok_or_else(|| SipUaError::CertificateError("empty certificate chain".into()))?;
    let (spki, sig_alg_oid) = leaf_spki_and_sig_alg(leaf)
        .ok_or_else(|| SipUaError::CertificateError("certificate is not valid DER".into()))?;
    // NIST 800-53 Rev5: SI-10 -- the certificate we present (or whose
    // fingerprint we advertise) must be one our key can prove possession of.
    if spki != key_pair.public_key_der().as_slice() {
        return Err(SipUaError::CertificateError(
            "certificate does not match the private key".into(),
        ));
    }
    if sig_alg_oid != OID_ECDSA_WITH_SHA384 {
        return Err(SipUaError::CertificateError(
            "certificate must be signed with ecdsa-with-SHA384 (CNSA 2.0)".into(),
        ));
    }
    Ok(())
}

/// DER content of OID 1.2.840.10045.4.3.3 (ecdsa-with-SHA384, RFC 5758 §3.2).
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// One DER TLV and the bytes after it.
struct Tlv<'a> {
    tag: u8,
    /// Tag, length and content.
    whole: &'a [u8],
    content: &'a [u8],
    rest: &'a [u8],
}

/// Reads one DER TLV from `input`.
///
/// Bounded: definite lengths of at most 4 length octets, every slice
/// checked (the certificate is configuration input, still untrusted).
/// Strict DER (X.690 §10.1): the length must use the fewest octets, so the
/// long form is refused for lengths below 128 or with a leading zero octet.
fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let tag = *input.first()?;
    let first_len = *input.get(1)?;
    let (len, header) = if first_len < 0x80 {
        (usize::from(first_len), 2usize)
    } else {
        let n = usize::from(first_len & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = input.get(2..2 + n)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let len = bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        if len < 0x80 {
            return None;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    Some(Tlv {
        tag,
        whole: input.get(..end)?,
        content: input.get(header..end)?,
        rest: input.get(end..)?,
    })
}

const DER_SEQUENCE: u8 = 0x30;
const DER_OID: u8 = 0x06;
const DER_CONTEXT_0: u8 = 0xA0;

/// The algorithm OID content of an `AlgorithmIdentifier` body.
fn alg_oid(alg_id: &[u8]) -> Option<&[u8]> {
    let oid = der_tlv(alg_id)?;
    (oid.tag == DER_OID).then_some(oid.content)
}

/// Reads a SEQUENCE TLV.
fn der_seq(input: &[u8]) -> Option<Tlv<'_>> {
    der_tlv(input).filter(|t| t.tag == DER_SEQUENCE)
}

/// Extracts the leaf's `SubjectPublicKeyInfo` TLV and the outer
/// `signatureAlgorithm` OID content (RFC 5280 §4.1), requiring the inner
/// `tbsCertificate.signature` OID to match the outer one. Bytes after the
/// certificate are refused: they would be hashed into the fingerprint we
/// advertise without being part of the certificate.
fn leaf_spki_and_sig_alg(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let cert = der_seq(cert)?;
    if !cert.rest.is_empty() {
        return None;
    }
    let tbs = der_seq(cert.content)?;
    let outer_alg = der_seq(tbs.rest)?;
    let outer_oid = alg_oid(outer_alg.content)?;

    // tbsCertificate: [0] version (optional), serial, signature, issuer,
    // validity, subject, subjectPublicKeyInfo.
    let mut cur = tbs.content;
    let first = der_tlv(cur)?;
    if first.tag == DER_CONTEXT_0 {
        cur = first.rest;
    }
    let serial = der_tlv(cur)?;
    let inner_alg = der_seq(serial.rest)?;
    if alg_oid(inner_alg.content)? != outer_oid {
        return None;
    }
    let issuer = der_tlv(inner_alg.rest)?;
    let validity = der_tlv(issuer.rest)?;
    let subject = der_tlv(validity.rest)?;
    let spki = der_seq(subject.rest)?;
    Some((spki.whole, outer_oid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_dtls::fingerprint::FingerprintAlgorithm;

    /// A generated identity together with its PKCS#8 key, which the
    /// identity itself no longer gives out (SEC-009).
    struct Generated {
        id: DtlsIdentity,
        key_der: Zeroizing<Vec<u8>>,
    }

    impl Generated {
        fn new() -> Self {
            let (cert_der, key_der) = DtlsIdentity::generate_der().unwrap();
            let id = DtlsIdentity::from_der(vec![cert_der], key_der.clone()).unwrap();
            Self { id, key_der }
        }

        fn key_der(&self) -> &[u8] {
            &self.key_der
        }
    }

    impl std::ops::Deref for Generated {
        type Target = DtlsIdentity;

        fn deref(&self) -> &DtlsIdentity {
            &self.id
        }
    }

    #[test]
    fn generate_p384_identity_with_single_prefix_fingerprint() {
        let id = Generated::new();
        assert_eq!(id.fingerprint().algorithm(), FingerprintAlgorithm::Sha384);
        assert_eq!(id.fingerprint().bytes().len(), 48);
        let sdp = id.sdp_fingerprint();
        assert!(sdp.starts_with("sha-384 "));
        assert_eq!(sdp.matches("sha-384").count(), 1, "{sdp}");
        assert!(id.key_der().len() > 48);
        assert!(!format!("{:?}", id.id).contains(&format!("{:?}", id.key_der())));
    }

    // Fingerprint mismatch at the verify layer (RFC 8122 §5).
    #[test]
    fn verify_any_accepts_own_cert_rejects_other() {
        let a = DtlsIdentity::generate().unwrap();
        let b = DtlsIdentity::generate().unwrap();
        let expected = [a.fingerprint().clone()];
        CertificateFingerprint::verify_any(&expected, &a.cert_chain_der()[0]).unwrap();
        assert!(CertificateFingerprint::verify_any(&expected, &b.cert_chain_der()[0]).is_err());
    }

    #[test]
    fn from_user_der_accepts_p384_only() {
        let id = Generated::new();
        let reused = DtlsIdentity::from_user_der(
            id.cert_chain_der().to_vec(),
            Zeroizing::new(id.key_der().to_vec()),
        )
        .unwrap();
        assert_eq!(reused.fingerprint(), id.fingerprint());

        let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(
            DtlsIdentity::from_user_der(
                id.cert_chain_der().to_vec(),
                Zeroizing::new(p256.serialize_der())
            )
            .is_err()
        );
        assert!(
            DtlsIdentity::from_user_der(id.cert_chain_der().to_vec(), Zeroizing::new(Vec::new()))
                .is_err()
        );
    }

    #[test]
    fn from_user_der_requires_matching_key_and_sha384_signature() {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
        let id = Generated::new();
        // Same algorithm, different key: SPKI mismatch.
        let other = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(
            DtlsIdentity::from_user_der(
                id.cert_chain_der().to_vec(),
                Zeroizing::new(other.serialize_der())
            )
            .is_err()
        );
        // P-384 key in a certificate signed by a P-256 issuer
        // (ecdsa-with-SHA256).
        let issuer = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer_cert = CertificateParams::new(vec!["ca".to_string()])
            .unwrap()
            .self_signed(&issuer)
            .unwrap();
        let leaf = CertificateParams::new(vec!["leaf".to_string()])
            .unwrap()
            .signed_by(&other, &issuer_cert, &issuer)
            .unwrap();
        assert!(
            DtlsIdentity::from_user_der(
                vec![leaf.der().to_vec()],
                Zeroizing::new(other.serialize_der())
            )
            .is_err()
        );
        // Garbage / truncated DER.
        let mut truncated = id.cert_chain_der()[0].clone();
        truncated.truncate(truncated.len() / 2);
        for bad in [vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], truncated, vec![]] {
            assert!(
                DtlsIdentity::from_user_der(vec![bad], Zeroizing::new(id.key_der().to_vec()))
                    .is_err()
            );
        }
    }

    /// SEC-011: trailing bytes after the certificate and non-minimal DER
    /// length encodings are refused.
    #[test]
    fn from_user_der_rejects_trailing_data_and_non_minimal_lengths() {
        let id = Generated::new();
        let key = || Zeroizing::new(id.key_der().to_vec());
        let cert = id.cert_chain_der()[0].clone();
        assert!(DtlsIdentity::from_user_der(vec![cert.clone()], key()).is_ok());

        let mut trailing = cert.clone();
        trailing.push(0);
        assert!(DtlsIdentity::from_user_der(vec![trailing], key()).is_err());

        // The outer SEQUENCE uses a two-octet length (0x82 hi lo); re-encode
        // it in three octets with a leading zero. Same content, not DER.
        assert_eq!(cert.get(..2), Some(&[0x30, 0x82][..]));
        let mut padded = vec![0x30, 0x83, 0x00];
        padded.extend_from_slice(&cert[2..]);
        assert!(der_tlv(&padded).is_none());
        assert!(DtlsIdentity::from_user_der(vec![padded], key()).is_err());

        // Long form for a length that fits the short form.
        assert!(der_tlv(&[0x04, 0x81, 0x03, 1, 2, 3]).is_none());
        assert!(der_tlv(&[0x04, 0x82, 0x00, 0x80]).is_none());
        // Minimal encodings still parse.
        assert_eq!(
            der_tlv(&[0x04, 0x03, 1, 2, 3]).map(|t| t.content),
            Some(&[1, 2, 3][..])
        );
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[7; 0x80]);
        assert_eq!(der_tlv(&long).map(|t| t.content.len()), Some(0x80));
    }

    /// The credentials handed to the association are for the certificate
    /// whose fingerprint goes into SDP.
    #[test]
    fn credentials_match_sdp_fingerprint() {
        let id = DtlsIdentity::generate().unwrap();
        assert_eq!(id.credentials().fingerprint(), id.fingerprint());
        assert_eq!(
            id.credentials().fingerprint().to_sdp(),
            id.sdp_fingerprint()
        );
        assert_eq!(id.credentials().certificate_chain(), id.cert_chain_der());
        assert!(!format!("{:?}", id.credentials()).contains("key_der"));
    }

    /// `from_der` itself now refuses a key that is not the certificate's.
    #[test]
    fn from_der_requires_matching_p384_key() {
        let a = DtlsIdentity::generate().unwrap();
        let b = Generated::new();
        assert!(
            DtlsIdentity::from_der(
                a.cert_chain_der().to_vec(),
                Zeroizing::new(b.key_der().to_vec())
            )
            .is_err()
        );
        assert!(
            DtlsIdentity::from_der(a.cert_chain_der().to_vec(), Zeroizing::new(vec![1, 2, 3]))
                .is_err()
        );
        let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(
            DtlsIdentity::from_der(
                a.cert_chain_der().to_vec(),
                Zeroizing::new(p256.serialize_der())
            )
            .is_err()
        );
    }

    #[test]
    fn from_der_rejects_empty_key_or_chain() {
        assert!(DtlsIdentity::from_der(vec![vec![1, 2, 3]], Zeroizing::new(Vec::new())).is_err());
        assert!(DtlsIdentity::from_der(Vec::new(), Zeroizing::new(vec![1])).is_err());
    }
}
