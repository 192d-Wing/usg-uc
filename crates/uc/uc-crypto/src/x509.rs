//! X.509 certificate path validation for STI (Secure Telephone Identity)
//! certificates (RFC 8226, ATIS-1000080).
//!
//! Path building and signature checks are delegated to `rustls-webpki` (the
//! same validator the TLS stack uses). On top of that this module extracts the
//! fields webpki does not expose and STIR needs:
//!
//! - the end-entity P-256 public key (uncompressed point),
//! - `notBefore` / `notAfter`,
//! - the TNAuthList extension (RFC 8226 §9, OID 1.3.6.1.5.5.7.1.26).
//!
//! Certificates arrive from attacker-chosen `x5u` URLs, so the DER walker is
//! bounds-checked throughout and never panics on malformed input.
//!
//! CNSA-EXCEPTION: ATIS-1000074 mandates ES256; STI-CA certificates carry
//! P-256 keys and are signed with ecdsa-with-SHA256 (or SHA-384).
//!
//! ## NIST 800-53 Rev5: IA-5(2) (PKI-Based Authentication), SC-17 (PKI Certificates), SI-10
// POAM: no revocation checking (CRL/OCSP) of STI certificates in v1.

use crate::error::{CryptoError, CryptoResult};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use std::time::Duration;

/// Maximum accepted DER size for a single certificate.
pub const MAX_CERT_DER_LEN: usize = 8 * 1024;

/// Maximum number of TNAuthList entries retained.
pub const MAX_TN_AUTH_ENTRIES: usize = 256;

/// Maximum length of a TN or SPC string inside TNAuthList.
const MAX_TN_AUTH_STRING: usize = 64;

/// One TNAuthList entry (RFC 8226 §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TnAuthEntry {
    /// Service Provider Code (`spc [0]`).
    Spc(String),
    /// Telephone number range (`range [1]`): `count` numbers from `start`.
    Range {
        /// First number (digits only).
        start: String,
        /// Number of TNs in the range.
        count: u64,
    },
    /// Single telephone number (`one [2]`).
    One(String),
}

impl TnAuthEntry {
    /// Returns true if `tn` (digits only, E.164 without `+`) is in scope of
    /// this entry. SPC entries never match a TN directly.
    #[must_use]
    pub fn covers_tn(&self, tn: &str) -> bool {
        match self {
            Self::Spc(_) => false,
            Self::One(n) => n == tn,
            Self::Range { start, count } => {
                if start.len() != tn.len() || *count == 0 {
                    return false;
                }
                match (start.parse::<u128>(), tn.parse::<u128>()) {
                    (Ok(s), Ok(t)) => t >= s && t - s < u128::from(*count),
                    _ => false,
                }
            }
        }
    }
}

/// The fields of a validated STI end-entity certificate STIR needs.
#[derive(Debug, Clone)]
pub struct StiCertificate {
    /// End-entity public key, uncompressed P-256 point (65 bytes).
    pub public_key: Vec<u8>,
    /// `notBefore`, seconds since the Unix epoch.
    pub not_before: u64,
    /// `notAfter`, seconds since the Unix epoch.
    pub not_after: u64,
    /// TNAuthList entries (empty if the extension is absent).
    pub tn_auth: Vec<TnAuthEntry>,
    /// SHA-384 fingerprint of the end-entity DER.
    pub fingerprint_sha384: [u8; 48],
}

/// An owned set of trust anchors (the STI-CR list).
#[derive(Debug, Default)]
pub struct TrustAnchorSet {
    anchors: Vec<TrustAnchor<'static>>,
}

impl TrustAnchorSet {
    /// Builds a set from DER certificates. Certificates that are not valid
    /// trust anchors are skipped; the number skipped is returned.
    #[must_use]
    pub fn from_der_certs<'a>(certs: impl IntoIterator<Item = &'a [u8]>) -> (Self, usize) {
        let mut anchors = Vec::new();
        let mut skipped = 0;
        for der in certs {
            let cert = CertificateDer::from(der);
            match webpki::anchor_from_trusted_cert(&cert) {
                Ok(ta) => anchors.push(ta.to_owned()),
                Err(_) => skipped += 1,
            }
        }
        (Self { anchors }, skipped)
    }

    /// Number of anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// True if the set holds no anchors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Splits a PEM bundle into DER certificates. Non-certificate PEM sections are
/// ignored; a malformed section ends parsing with an error.
///
/// # Errors
/// Returns [`CryptoError::CertificateInvalid`] if the PEM is malformed.
pub fn pem_certificates(pem: &[u8]) -> CryptoResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        let cert = item.map_err(|_| CryptoError::CertificateInvalid("malformed-pem"))?;
        out.push(cert.as_ref().to_vec());
    }
    Ok(out)
}

/// Validates `end_entity` (with optional `intermediates`) to one of
/// `anchors` at time `now_unix`, then extracts the STI fields.
///
/// The end-entity key must be P-256 (`ES256`).
///
/// # Errors
/// Returns [`CryptoError::CertificateInvalid`] with a fixed reason token.
pub fn verify_sti_chain(
    anchors: &TrustAnchorSet,
    end_entity: &[u8],
    intermediates: &[Vec<u8>],
    now_unix: u64,
) -> CryptoResult<StiCertificate> {
    if end_entity.len() > MAX_CERT_DER_LEN {
        return Err(CryptoError::CertificateInvalid("too-large"));
    }
    if anchors.is_empty() {
        return Err(CryptoError::CertificateInvalid("no-trust-anchors"));
    }
    let parsed = parse_sti_certificate(end_entity)?;

    let ee_der = CertificateDer::from(end_entity);
    let ee = webpki::EndEntityCert::try_from(&ee_der)
        .map_err(|_| CryptoError::CertificateInvalid("malformed"))?;
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    // STI certificates carry no serverAuth EKU; accept any EKU set that
    // does not exclude the (absent) purpose.
    let usage = webpki::KeyUsage::required_if_present(&ID_KP_SERVER_AUTH);
    ee.verify_for_usage(
        STI_SIG_ALGS,
        &anchors.anchors,
        &inter,
        UnixTime::since_unix_epoch(Duration::from_secs(now_unix)),
        usage,
        None,
        None,
    )
    .map_err(|e| CryptoError::CertificateInvalid(webpki_reason(&e)))?;
    Ok(parsed)
}

/// Parses an STI certificate without path validation (used for the local
/// signing certificate self-check).
///
/// # Errors
/// Returns [`CryptoError::CertificateInvalid`] on malformed DER or a non-P-256 key.
pub fn parse_sti_certificate(der: &[u8]) -> CryptoResult<StiCertificate> {
    if der.len() > MAX_CERT_DER_LEN {
        return Err(CryptoError::CertificateInvalid("too-large"));
    }
    let bad = || CryptoError::CertificateInvalid("malformed");
    let mut top = Der::new(der);
    let cert = top.expect(TAG_SEQUENCE).ok_or_else(bad)?;
    if !top.is_empty() {
        return Err(bad());
    }
    let mut cert = Der::new(cert);
    let mut tbs = Der::new(cert.expect(TAG_SEQUENCE).ok_or_else(bad)?);

    // version [0] EXPLICIT (optional)
    if tbs.peek_tag() == Some(0xA0) {
        tbs.expect(0xA0).ok_or_else(bad)?;
    }
    tbs.expect(TAG_INTEGER).ok_or_else(bad)?; // serial
    tbs.expect(TAG_SEQUENCE).ok_or_else(bad)?; // signature alg
    tbs.expect(TAG_SEQUENCE).ok_or_else(bad)?; // issuer
    let mut validity = Der::new(tbs.expect(TAG_SEQUENCE).ok_or_else(bad)?);
    let not_before = parse_time(&mut validity).ok_or_else(bad)?;
    let not_after = parse_time(&mut validity).ok_or_else(bad)?;
    tbs.expect(TAG_SEQUENCE).ok_or_else(bad)?; // subject
    let public_key = parse_p256_spki(tbs.expect(TAG_SEQUENCE).ok_or_else(bad)?)?;

    let mut tn_auth = Vec::new();
    while let Some((tag, body)) = tbs.next() {
        if tag == 0xA3 {
            let mut exts_outer = Der::new(body);
            let mut exts = Der::new(exts_outer.expect(TAG_SEQUENCE).ok_or_else(bad)?);
            while !exts.is_empty() {
                let mut ext = Der::new(exts.expect(TAG_SEQUENCE).ok_or_else(bad)?);
                let oid = ext.expect(TAG_OID).ok_or_else(bad)?;
                if ext.peek_tag() == Some(TAG_BOOLEAN) {
                    ext.expect(TAG_BOOLEAN).ok_or_else(bad)?;
                }
                let value = ext.expect(TAG_OCTET_STRING).ok_or_else(bad)?;
                if oid == OID_TN_AUTH_LIST {
                    tn_auth = parse_tn_auth_list(value)?;
                }
            }
        }
    }

    Ok(StiCertificate {
        public_key,
        not_before,
        not_after,
        tn_auth,
        fingerprint_sha384: crate::hash::sha384(der),
    })
}

// --- webpki glue -----------------------------------------------------------

/// id-kp-serverAuth, DER-encoded OID value.
const ID_KP_SERVER_AUTH: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// Signature algorithms accepted on STI chains: ECDSA only (P-256 per
/// ATIS-1000080, P-384 for CNSA-aligned CAs).
static STI_SIG_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
];

fn webpki_reason(e: &webpki::Error) -> &'static str {
    match e {
        webpki::Error::CertExpired { .. } => "expired",
        webpki::Error::CertNotValidYet { .. } => "not-yet-valid",
        webpki::Error::UnknownIssuer => "untrusted",
        webpki::Error::InvalidSignatureForPublicKey
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        | webpki::Error::UnsupportedSignatureAlgorithmContext(_) => "bad-chain-signature",
        _ => "chain-invalid",
    }
}

// --- bounded DER reader ----------------------------------------------------

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_IA5: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GEN_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;

/// 1.3.6.1.5.5.7.1.26 (id-pe-TNAuthList).
const OID_TN_AUTH_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1a];
/// 1.2.840.10045.2.1 (id-ecPublicKey).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// 1.2.840.10045.3.1.7 (prime256v1).
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A cursor over DER TLVs. Single-byte tags only (all X.509 fields we read
/// use low tag numbers); lengths up to 4 bytes.
struct Der<'a> {
    buf: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// Reads the next TLV; `None` on truncation or a malformed length.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.buf.split_first()?;
        if tag & 0x1f == 0x1f {
            return None; // multi-byte tag: not used by the fields we parse
        }
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let (len_bytes, r) = rest.split_at(n);
            rest = r;
            let mut len = 0usize;
            for &b in len_bytes {
                len = len.checked_mul(256)?.checked_add(usize::from(b))?;
            }
            len
        };
        if rest.len() < len {
            return None;
        }
        let (body, after) = rest.split_at(len);
        self.buf = after;
        Some((tag, body))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        match self.next()? {
            (t, body) if t == tag => Some(body),
            _ => None,
        }
    }
}

fn parse_p256_spki(spki: &[u8]) -> CryptoResult<Vec<u8>> {
    let bad = || CryptoError::CertificateInvalid("unsupported-key");
    let mut spki = Der::new(spki);
    let mut alg = Der::new(spki.expect(TAG_SEQUENCE).ok_or_else(bad)?);
    if alg.expect(TAG_OID).ok_or_else(bad)? != OID_EC_PUBLIC_KEY
        || alg.expect(TAG_OID).ok_or_else(bad)? != OID_P256
    {
        return Err(bad());
    }
    let bits = spki.expect(TAG_BIT_STRING).ok_or_else(bad)?;
    match bits.split_first() {
        Some((0, point)) if point.len() == 65 && point.first() == Some(&0x04) => Ok(point.to_vec()),
        _ => Err(bad()),
    }
}

/// RFC 8226 §9:
/// ```text
/// TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry
/// TNEntry ::= CHOICE {
///   spc   [0] ServiceProviderCode,         -- IA5String
///   range [1] TelephoneNumberRange,        -- SEQUENCE { start, count }
///   one   [2] TelephoneNumber }            -- IA5String
/// ```
/// Tags are EXPLICIT (the module uses `DEFINITIONS EXPLICIT TAGS`).
fn parse_tn_auth_list(value: &[u8]) -> CryptoResult<Vec<TnAuthEntry>> {
    let bad = || CryptoError::CertificateInvalid("malformed-tnauthlist");
    let mut outer = Der::new(value);
    let mut list = Der::new(outer.expect(TAG_SEQUENCE).ok_or_else(bad)?);
    let mut out = Vec::new();
    while !list.is_empty() {
        if out.len() >= MAX_TN_AUTH_ENTRIES {
            return Err(bad());
        }
        let (tag, body) = list.next().ok_or_else(bad)?;
        let mut inner = Der::new(body);
        let entry = match tag {
            0xA0 => TnAuthEntry::Spc(ia5(inner.expect(TAG_IA5).ok_or_else(bad)?).ok_or_else(bad)?),
            0xA2 => TnAuthEntry::One(ia5(inner.expect(TAG_IA5).ok_or_else(bad)?).ok_or_else(bad)?),
            0xA1 => {
                let mut range = Der::new(inner.expect(TAG_SEQUENCE).ok_or_else(bad)?);
                let start = ia5(range.expect(TAG_IA5).ok_or_else(bad)?).ok_or_else(bad)?;
                let count = der_uint(range.expect(TAG_INTEGER).ok_or_else(bad)?).ok_or_else(bad)?;
                TnAuthEntry::Range { start, count }
            }
            _ => return Err(bad()),
        };
        out.push(entry);
    }
    Ok(out)
}

fn ia5(body: &[u8]) -> Option<String> {
    if body.is_empty() || body.len() > MAX_TN_AUTH_STRING || !body.iter().all(u8::is_ascii_graphic)
    {
        return None;
    }
    std::str::from_utf8(body).ok().map(str::to_owned)
}

fn der_uint(body: &[u8]) -> Option<u64> {
    let body = match body {
        [0, rest @ ..] if !rest.is_empty() => rest,
        [b, ..] if b & 0x80 != 0 => return None, // negative
        b => b,
    };
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    Some(body.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

fn parse_time(d: &mut Der<'_>) -> Option<u64> {
    let (tag, body) = d.next()?;
    let s = std::str::from_utf8(body).ok()?;
    let s = s.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, s.len()) {
        (TAG_UTC_TIME, 12) => {
            let yy: u64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        (TAG_GEN_TIME, 14) => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| -> Option<u64> { rest.get(r)?.parse().ok() };
    let (mo, day, h, mi, sec) = (num(0..2)?, num(2..4)?, num(4..6)?, num(6..8)?, num(8..10)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, mo, day)?;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm), years >= 1970.
fn days_from_civil(y: u64, m: u64, d: u64) -> Option<u64> {
    if y < 1970 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11_017));
    }

    #[test]
    fn time_parsing() {
        let mut d = Der::new(b"\x17\x0d491231235959Z");
        assert_eq!(parse_time(&mut d), Some(2_524_607_999));
        let mut d = Der::new(b"\x18\x0f20240229000000Z");
        assert!(parse_time(&mut d).is_some());
        let mut d = Der::new(b"\x17\x0d4912312359xxZ");
        assert!(parse_time(&mut d).is_none());
    }

    #[test]
    fn der_reader_rejects_truncation() {
        assert!(Der::new(&[0x30, 0x05, 0x01]).next().is_none());
        assert!(Der::new(&[0x30, 0x85, 0, 0, 0, 0, 1]).next().is_none());
        assert!(Der::new(&[0x30]).next().is_none());
        assert!(Der::new(&[0x1f, 0x01, 0x00]).next().is_none());
    }

    #[test]
    fn tn_auth_list_parse_and_scope() {
        // SEQUENCE { [0] IA5 "1234", [1] SEQ { IA5 "12025550100", INT 100 }, [2] IA5 "12025551234" }
        let mut v = vec![];
        let spc = [0xA0, 6, 0x16, 4, b'1', b'2', b'3', b'4'];
        let mut range = vec![0xA1, 18, 0x30, 16, 0x16, 11];
        range.extend_from_slice(b"12025550100");
        range.extend_from_slice(&[0x02, 1, 100]);
        let mut one = vec![0xA2, 13, 0x16, 11];
        one.extend_from_slice(b"12025551234");
        let body_len = spc.len() + range.len() + one.len();
        v.push(0x30);
        v.push(u8::try_from(body_len).unwrap());
        v.extend_from_slice(&spc);
        v.extend_from_slice(&range);
        v.extend_from_slice(&one);
        let list = parse_tn_auth_list(&v).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], TnAuthEntry::Spc("1234".into()));
        assert!(list[1].covers_tn("12025550199"));
        assert!(!list[1].covers_tn("12025550200"));
        assert!(list[2].covers_tn("12025551234"));
        assert!(!list[0].covers_tn("1234"));
    }

    #[test]
    fn garbage_never_panics() {
        for len in 0..64u8 {
            let data: Vec<u8> = (0..len).map(|i| i.wrapping_mul(37) ^ 0x30).collect();
            let _ = parse_sti_certificate(&data);
            let _ = parse_tn_auth_list(&data);
        }
        assert!(parse_sti_certificate(&vec![0u8; MAX_CERT_DER_LEN + 1]).is_err());
    }

    #[test]
    fn empty_anchor_set_rejects() {
        let (set, _) = TrustAnchorSet::from_der_certs(std::iter::empty());
        assert!(matches!(
            verify_sti_chain(&set, &[0x30, 0], &[], 0),
            Err(CryptoError::CertificateInvalid("no-trust-anchors"))
        ));
    }
}
