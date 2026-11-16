//! Strict extraction of a P-384 public key from an X.509 certificate.
//!
//! The association authenticates the peer by the SDP fingerprint of its
//! certificate (RFC 5763 §5, RFC 8122 §5), not by a chain. The only thing
//! needed from the certificate itself is the subject public key, to check
//! the peer's handshake signature. This module walks the DER structure down
//! to `subjectPublicKeyInfo` and accepts exactly one form:
//! `id-ecPublicKey` with the named curve `secp384r1` and an uncompressed
//! point.
//!
//! It deliberately does not check the signature on the certificate, its
//! issuer, its validity period or its extensions.
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation), SC-13
//!
//! Every length is checked against the remaining input; malformed input is
//! an `Err`, never a panic. Any key that is not ECDSA P-384 is refused
//! (CNSA 2.0).

#![deny(clippy::indexing_slicing)]

use crate::wire::reader::Reader;

/// Length of an uncompressed P-384 point (`0x04 || X || Y`).
pub const P384_POINT_LEN: usize = 97;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_VERSION: u8 = 0xA0;

/// OID 1.2.840.10045.2.1 (`id-ecPublicKey`), content bytes.
const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// OID 1.3.132.0.34 (`secp384r1`), content bytes.
const OID_SECP384R1: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];

/// Why a certificate's public key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpkiError {
    /// The DER structure is malformed or truncated.
    Malformed,
    /// The key is well formed but is not an uncompressed ECDSA P-384 key.
    UnsupportedKey,
}

/// Reads one DER TLV and returns its tag and content.
///
/// Definite lengths only, minimal length encoding required, single-byte
/// tags only.
fn tlv<'a>(r: &mut Reader<'a>) -> Result<(u8, &'a [u8]), SpkiError> {
    let tag = r.u8().map_err(|_| SpkiError::Malformed)?;
    if tag & 0x1F == 0x1F {
        return Err(SpkiError::Malformed);
    }
    let first = r.u8().map_err(|_| SpkiError::Malformed)?;
    let len = match first {
        0..=0x7F => usize::from(first),
        0x81 => {
            let len = usize::from(r.u8().map_err(|_| SpkiError::Malformed)?);
            if len < 0x80 {
                return Err(SpkiError::Malformed);
            }
            len
        }
        0x82 => {
            let len = usize::from(r.u16().map_err(|_| SpkiError::Malformed)?);
            if len < 0x100 {
                return Err(SpkiError::Malformed);
            }
            len
        }
        0x83 => {
            let len = r.u24().map_err(|_| SpkiError::Malformed)?;
            if len < 0x1_0000 {
                return Err(SpkiError::Malformed);
            }
            usize::try_from(len).map_err(|_| SpkiError::Malformed)?
        }
        _ => return Err(SpkiError::Malformed),
    };
    let content = r.take(len).map_err(|_| SpkiError::Malformed)?;
    Ok((tag, content))
}

/// Reads a TLV and requires `tag`.
fn expect<'a>(r: &mut Reader<'a>, tag: u8) -> Result<&'a [u8], SpkiError> {
    match tlv(r)? {
        (t, content) if t == tag => Ok(content),
        _ => Err(SpkiError::Malformed),
    }
}

/// Extracts the uncompressed P-384 subject public key from a DER certificate.
///
/// # Errors
/// [`SpkiError::Malformed`] if the certificate cannot be walked,
/// [`SpkiError::UnsupportedKey`] if the key is not ECDSA P-384 uncompressed.
pub fn extract_p384_public_key(cert_der: &[u8]) -> Result<[u8; P384_POINT_LEN], SpkiError> {
    let mut outer = Reader::new(cert_der);
    let mut certificate = Reader::new(expect(&mut outer, TAG_SEQUENCE)?);
    if !outer.is_empty() {
        return Err(SpkiError::Malformed);
    }
    let mut tbs = Reader::new(expect(&mut certificate, TAG_SEQUENCE)?);

    // version [0] EXPLICIT is optional; serialNumber follows.
    let (tag, _) = tlv(&mut tbs)?;
    match tag {
        TAG_VERSION => {
            expect(&mut tbs, TAG_INTEGER)?;
        }
        TAG_INTEGER => {}
        _ => return Err(SpkiError::Malformed),
    }
    // signature, issuer, validity, subject.
    for _ in 0..4 {
        expect(&mut tbs, TAG_SEQUENCE)?;
    }

    let mut spki = Reader::new(expect(&mut tbs, TAG_SEQUENCE)?);
    let mut algorithm = Reader::new(expect(&mut spki, TAG_SEQUENCE)?);
    let key_bits = expect(&mut spki, TAG_BIT_STRING)?;
    if !spki.is_empty() {
        return Err(SpkiError::Malformed);
    }

    let algorithm_oid = expect(&mut algorithm, TAG_OID)?;
    if algorithm_oid != OID_EC_PUBLIC_KEY {
        return Err(SpkiError::UnsupportedKey);
    }
    // ECParameters must be the namedCurve choice.
    let (tag, curve) = tlv(&mut algorithm)?;
    if tag != TAG_OID || curve != OID_SECP384R1 || !algorithm.is_empty() {
        return Err(SpkiError::UnsupportedKey);
    }

    // BIT STRING: one "unused bits" byte (must be 0), then the point.
    let (unused_bits, point) = key_bits.split_first().ok_or(SpkiError::Malformed)?;
    if *unused_bits != 0 {
        return Err(SpkiError::Malformed);
    }
    let point: [u8; P384_POINT_LEN] = point.try_into().map_err(|_| SpkiError::UnsupportedKey)?;
    if point.first() != Some(&0x04) {
        return Err(SpkiError::UnsupportedKey);
    }
    Ok(point)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn cert(alg: &'static rcgen::SignatureAlgorithm) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["peer.invalid".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.der().to_vec(), key.public_key_raw().to_vec())
    }

    #[test]
    fn extracts_p384_key() {
        let (der, public) = cert(&rcgen::PKCS_ECDSA_P384_SHA384);
        let point = extract_p384_public_key(&der).unwrap();
        assert_eq!(point.as_slice(), public.as_slice());
        assert_eq!(point[0], 0x04);
    }

    #[test]
    fn rejects_other_key_types() {
        for alg in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ED25519] {
            let (der, _) = cert(alg);
            assert_eq!(
                extract_p384_public_key(&der),
                Err(SpkiError::UnsupportedKey)
            );
        }
    }

    /// A syntactically valid certificate skeleton carrying an RSA SPKI.
    #[test]
    fn rejects_rsa_spki() {
        // rsaEncryption 1.2.840.113549.1.1.1 with NULL parameters.
        let alg = [
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let bits = [0x03, 0x03, 0x00, 0x01, 0x02];
        let mut spki = vec![0x30, u8::try_from(alg.len() + bits.len()).unwrap()];
        spki.extend_from_slice(&alg);
        spki.extend_from_slice(&bits);
        let mut tbs_body = vec![0x02, 0x01, 0x01];
        for _ in 0..4 {
            tbs_body.extend_from_slice(&[0x30, 0x00]);
        }
        tbs_body.extend_from_slice(&spki);
        let mut tbs = vec![0x30, u8::try_from(tbs_body.len()).unwrap()];
        tbs.extend_from_slice(&tbs_body);
        let mut der = vec![0x30, u8::try_from(tbs.len()).unwrap()];
        der.extend_from_slice(&tbs);
        assert_eq!(
            extract_p384_public_key(&der),
            Err(SpkiError::UnsupportedKey)
        );
    }

    #[test]
    fn truncated_and_garbage_input_is_rejected_without_panic() {
        let (der, _) = cert(&rcgen::PKCS_ECDSA_P384_SHA384);
        for cut in 0..der.len() {
            assert!(extract_p384_public_key(&der[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(
            extract_p384_public_key(&trailing),
            Err(SpkiError::Malformed)
        );

        // Flip every byte in turn: must return (Ok or Err), never panic.
        for i in 0..der.len() {
            let mut mutated = der.clone();
            mutated[i] ^= 0xFF;
            let _ = extract_p384_public_key(&mutated);
        }
        for garbage in [
            &[][..],
            &[0x30][..],
            &[0x30, 0x80][..],
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF][..],
            &[0x30, 0x81, 0x05, 0, 0, 0, 0, 0][..],
            &[0x1F, 0x81, 0x00][..],
            &[0xFF; 64][..],
        ] {
            assert!(extract_p384_public_key(garbage).is_err());
        }
    }
}
