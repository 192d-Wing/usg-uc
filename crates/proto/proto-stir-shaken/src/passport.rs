//! PASSporT (RFC 8225) with the SHAKEN extension (RFC 8588).
//!
//! Encoding is deterministic (RFC 8225 §9) and decoding is strict: unknown
//! `alg`, `typ` other than `passport`, duplicate JSON members, and
//! unsupported `crit` entries are all rejected.
//!
//! ## NIST 800-53 Rev5: IA-9 (Service Identification and Authentication), SI-10

use crate::canon::{TelephoneNumber, canonicalize_tn};
use crate::error::{StirShakenError, StirShakenResult};
use crate::jws::{b64url_decode, b64url_encode_into, push_json_str, split_compact};
use serde::Deserialize;
use uc_types::attestation::AttestationLevel;

/// Attestation level (RFC 8588 §4). Re-export of the workspace-wide enum.
pub type Attestation = AttestationLevel;

/// Maximum number of `dest.tn` entries accepted.
pub const MAX_DEST_TNS: usize = 16;

/// Maximum `origid` / `x5u` length accepted.
const MAX_ORIGID_LEN: usize = 64;
const MAX_X5U_LEN: usize = 1024;

/// The `ppt` value for SHAKEN (RFC 8588 §3).
pub const PPT_SHAKEN: &str = "shaken";
/// The `ppt` value for diversion PASSporTs (RFC 8946).
pub const PPT_DIV: &str = "div";

/// JWS signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    /// ECDSA P-256 / SHA-256. Mandatory for `ppt=shaken` (RFC 8225 §5.2,
    /// ATIS-1000074). CNSA-EXCEPTION.
    Es256,
    /// ECDSA P-384 / SHA-384. CNSA 2.0; bilateral/non-SHAKEN use only.
    Es384,
}

impl Alg {
    /// JOSE name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    /// Parses a JOSE name. `none` and every other algorithm are rejected.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            _ => None,
        }
    }

    /// Fixed `R || S` signature length.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Es256 => 64,
            Self::Es384 => 96,
        }
    }
}

/// Produces a raw `R || S` JWS signature over the signing input.
///
/// Implemented outside this crate (e.g. `uc-sti::FileSigner`) so the protocol
/// layer stays free of key material and I/O.
pub trait Signer: Send + Sync {
    /// Algorithm this signer produces.
    fn alg(&self) -> Alg;
    /// Signs `input`.
    ///
    /// # Errors
    /// [`StirShakenError::SigningFailed`] if the key is unusable.
    fn sign(&self, input: &[u8]) -> StirShakenResult<Vec<u8>>;
}

/// PASSporT protected header (RFC 8225 §5, RFC 8588 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportHeader {
    /// Signature algorithm.
    pub alg: Alg,
    /// `ppt` extension (for SHAKEN: `shaken`).
    pub ppt: Option<String>,
    /// Certificate URL.
    pub x5u: String,
}

/// SHAKEN PASSporT claims (RFC 8225 §5.2, RFC 8588 §4-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportClaims {
    /// Attestation level.
    pub attest: Attestation,
    /// Destination TNs (`dest.tn`).
    pub dest: Vec<TelephoneNumber>,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: u64,
    /// Originating TN (`orig.tn`).
    pub orig: TelephoneNumber,
    /// Origination identifier (UUID per RFC 8588 §5).
    pub origid: String,
}

/// A decoded but not yet signature-checked PASSporT.
#[derive(Debug, Clone)]
pub struct DecodedPassport {
    /// Protected header.
    pub header: PassportHeader,
    /// Claims.
    pub claims: PassportClaims,
    /// `header.payload` signing input.
    pub signing_input: String,
    /// Raw `R || S` signature.
    pub signature: Vec<u8>,
}

/// PASSporT encode/decode entry points.
#[derive(Debug)]
pub struct PASSporT;

impl PASSporT {
    /// Signs `claims` and returns the compact JWS (full form).
    ///
    /// RFC 8225 §9: deterministic JSON with keys in lexicographic order.
    ///
    /// # Errors
    /// Returns [`StirShakenError::InvalidClaim`] for an empty `dest`, an
    /// oversized `origid`/`x5u`, or [`StirShakenError::SigningFailed`].
    pub fn sign(
        claims: &PassportClaims,
        x5u: &str,
        signer: &dyn Signer,
    ) -> StirShakenResult<String> {
        if claims.dest.is_empty() || claims.dest.len() > MAX_DEST_TNS {
            return Err(StirShakenError::InvalidClaim { claim: "dest" });
        }
        if !valid_origid(&claims.origid) {
            return Err(StirShakenError::InvalidClaim { claim: "origid" });
        }
        if x5u.is_empty() || x5u.len() > MAX_X5U_LEN {
            return Err(StirShakenError::InvalidClaim { claim: "x5u" });
        }
        let alg = signer.alg();

        let mut json = String::with_capacity(256);
        json.push_str("{\"alg\":\"");
        json.push_str(alg.as_str());
        json.push_str("\",\"ppt\":\"shaken\",\"typ\":\"passport\",\"x5u\":");
        push_json_str(&mut json, x5u);
        json.push('}');

        let mut token = String::with_capacity(640);
        b64url_encode_into(json.as_bytes(), &mut token);
        token.push('.');

        json.clear();
        json.push_str("{\"attest\":\"");
        json.push(claims.attest.as_code());
        json.push_str("\",\"dest\":{\"tn\":[");
        for (i, tn) in claims.dest.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            push_json_str(&mut json, tn.as_str());
        }
        json.push_str("]},\"iat\":");
        json.push_str(&claims.iat.to_string());
        json.push_str(",\"orig\":{\"tn\":");
        push_json_str(&mut json, claims.orig.as_str());
        json.push_str("},\"origid\":");
        push_json_str(&mut json, &claims.origid);
        json.push('}');
        b64url_encode_into(json.as_bytes(), &mut token);

        let sig = signer.sign(token.as_bytes())?;
        if sig.len() != alg.signature_len() {
            return Err(StirShakenError::SigningFailed);
        }
        token.push('.');
        b64url_encode_into(&sig, &mut token);
        Ok(token)
    }

    /// Decodes only the protected header (used to route `ppt=div` and other
    /// non-SHAKEN PASSporTs before claim parsing).
    ///
    /// # Errors
    /// Returns [`StirShakenError::Malformed`] or
    /// [`StirShakenError::UnsupportedAlgorithm`].
    pub fn decode_header(token: &str) -> StirShakenResult<PassportHeader> {
        let parts = split_compact(token)?;
        parse_header(&b64url_decode(parts.header)?)
    }

    /// Decodes a SHAKEN PASSporT (header, claims, signature) without checking
    /// the signature.
    ///
    /// # Errors
    /// [`StirShakenError::Malformed`], [`StirShakenError::UnsupportedAlgorithm`]
    /// (any `alg` other than ES256 with `ppt=shaken`), or
    /// [`StirShakenError::InvalidClaim`].
    pub fn decode(token: &str) -> StirShakenResult<DecodedPassport> {
        let parts = split_compact(token)?;
        let header = parse_header(&b64url_decode(parts.header)?)?;
        if header.ppt.as_deref() != Some(PPT_SHAKEN) {
            return Err(StirShakenError::Malformed { reason: "ppt" });
        }
        // RFC 8225 §5.2 / ATIS-1000074: SHAKEN PASSporTs are ES256 only.
        // Refusing anything else prevents algorithm confusion.
        if header.alg != Alg::Es256 {
            return Err(StirShakenError::UnsupportedAlgorithm);
        }
        let claims = parse_claims(&b64url_decode(parts.payload)?)?;
        let signature = b64url_decode(parts.signature)?;
        if signature.len() != header.alg.signature_len() {
            return Err(StirShakenError::Malformed {
                reason: "signature-length",
            });
        }
        Ok(DecodedPassport {
            header,
            claims,
            signing_input: parts.signing_input.to_owned(),
            signature,
        })
    }
}

fn valid_origid(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ORIGID_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

// --- strict JSON shapes -----------------------------------------------------
// serde's derived struct deserializers reject duplicate members, which closes
// the "first vs last duplicate wins" ambiguity between implementations.

#[derive(Deserialize)]
struct RawHeader {
    alg: String,
    typ: Option<String>,
    ppt: Option<String>,
    x5u: Option<String>,
    crit: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawOrig {
    tn: Option<String>,
}

#[derive(Deserialize)]
struct RawDest {
    tn: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawClaims {
    attest: Option<String>,
    dest: Option<RawDest>,
    iat: Option<u64>,
    orig: Option<RawOrig>,
    origid: Option<String>,
}

fn parse_header(json: &[u8]) -> StirShakenResult<PassportHeader> {
    let raw: RawHeader = serde_json::from_slice(json).map_err(|_| StirShakenError::Malformed {
        reason: "header-json",
    })?;
    let alg = Alg::parse(&raw.alg).ok_or(StirShakenError::UnsupportedAlgorithm)?;
    // RFC 8225 §5.1.1: typ MUST be "passport".
    if raw.typ.as_deref() != Some("passport") {
        return Err(StirShakenError::Malformed { reason: "typ" });
    }
    // RFC 8225 §8.1 / RFC 7515 §4.1.11: a crit entry we do not implement
    // must fail the token. SHAKEN defines no critical header extensions.
    if raw.crit.is_some_and(|c| !c.is_empty()) {
        return Err(StirShakenError::Malformed { reason: "crit" });
    }
    let x5u = raw
        .x5u
        .filter(|u| !u.is_empty() && u.len() <= MAX_X5U_LEN)
        .ok_or(StirShakenError::Malformed { reason: "x5u" })?;
    Ok(PassportHeader {
        alg,
        ppt: raw.ppt,
        x5u,
    })
}

fn parse_claims(json: &[u8]) -> StirShakenResult<PassportClaims> {
    let raw: RawClaims = serde_json::from_slice(json).map_err(|_| StirShakenError::Malformed {
        reason: "claims-json",
    })?;
    // RFC 8588 §4: attest MUST be A, B or C.
    let attest = raw
        .attest
        .as_deref()
        .and_then(|a| match a {
            "A" | "B" | "C" => a.chars().next().and_then(Attestation::from_code),
            _ => None,
        })
        .ok_or(StirShakenError::InvalidClaim { claim: "attest" })?;
    let iat = raw
        .iat
        .ok_or(StirShakenError::InvalidClaim { claim: "iat" })?;
    let orig = raw
        .orig
        .and_then(|o| o.tn)
        .as_deref()
        .and_then(canonicalize_tn)
        .ok_or(StirShakenError::InvalidClaim { claim: "orig" })?;
    let dest_raw = raw
        .dest
        .and_then(|d| d.tn)
        .filter(|d| !d.is_empty() && d.len() <= MAX_DEST_TNS)
        .ok_or(StirShakenError::InvalidClaim { claim: "dest" })?;
    let mut dest = Vec::with_capacity(dest_raw.len());
    for d in &dest_raw {
        dest.push(canonicalize_tn(d).ok_or(StirShakenError::InvalidClaim { claim: "dest" })?);
    }
    // RFC 8588 §5: origid MUST be present.
    let origid = raw
        .origid
        .filter(|o| valid_origid(o))
        .ok_or(StirShakenError::InvalidClaim { claim: "origid" })?;
    Ok(PassportClaims {
        attest,
        dest,
        iat,
        orig,
        origid,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Deterministic fake signer for protocol tests (no crypto).
    pub struct FakeSigner(pub Alg);
    impl Signer for FakeSigner {
        fn alg(&self) -> Alg {
            self.0
        }
        fn sign(&self, input: &[u8]) -> StirShakenResult<Vec<u8>> {
            let mut v = vec![0u8; self.0.signature_len()];
            for (i, b) in input.iter().enumerate() {
                let n = v.len();
                v[i % n] ^= *b;
            }
            Ok(v)
        }
    }

    pub fn claims() -> PassportClaims {
        PassportClaims {
            attest: Attestation::Full,
            dest: vec![canonicalize_tn("+12025550101").unwrap()],
            iat: 1_700_000_000,
            orig: canonicalize_tn("+12025550100").unwrap(),
            origid: "123e4567-e89b-12d3-a456-426614174000".into(),
        }
    }

    fn enc(json: &str) -> String {
        let mut s = String::new();
        b64url_encode_into(json.as_bytes(), &mut s);
        s
    }

    #[test]
    fn canonical_json_bytes() {
        let tok = PASSporT::sign(
            &claims(),
            "https://cert.example.invalid/c.pem",
            &FakeSigner(Alg::Es256),
        )
        .unwrap();
        let parts = split_compact(&tok).unwrap();
        assert_eq!(
            String::from_utf8(b64url_decode(parts.header).unwrap()).unwrap(),
            r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.invalid/c.pem"}"#
        );
        assert_eq!(
            String::from_utf8(b64url_decode(parts.payload).unwrap()).unwrap(),
            r#"{"attest":"A","dest":{"tn":["12025550101"]},"iat":1700000000,"orig":{"tn":"12025550100"},"origid":"123e4567-e89b-12d3-a456-426614174000"}"#
        );
    }

    #[test]
    fn sign_decode_roundtrip() {
        let tok =
            PASSporT::sign(&claims(), "https://x.invalid/c", &FakeSigner(Alg::Es256)).unwrap();
        let d = PASSporT::decode(&tok).unwrap();
        assert_eq!(d.claims, claims());
        assert_eq!(d.header.alg, Alg::Es256);
        assert_eq!(d.signature.len(), 64);
    }

    #[test]
    fn es384_rejected_for_shaken() {
        let tok =
            PASSporT::sign(&claims(), "https://x.invalid/c", &FakeSigner(Alg::Es384)).unwrap();
        assert_eq!(
            PASSporT::decode(&tok).unwrap_err(),
            StirShakenError::UnsupportedAlgorithm
        );
    }

    fn tok(h: &str, p: &str) -> String {
        format!("{}.{}.{}", enc(h), enc(p), {
            let mut s = String::new();
            b64url_encode_into(&[1u8; 64], &mut s);
            s
        })
    }

    const H: &str =
        r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://x.invalid/c"}"#;
    const P: &str = r#"{"attest":"A","dest":{"tn":["12025550101"]},"iat":1,"orig":{"tn":"12025550100"},"origid":"u"}"#;

    #[test]
    fn malformed_cases() {
        assert!(PASSporT::decode(&tok(H, P)).is_ok());
        let none = r#"{"alg":"none","ppt":"shaken","typ":"passport","x5u":"https://x"}"#;
        assert_eq!(
            PASSporT::decode(&tok(none, P)).unwrap_err(),
            StirShakenError::UnsupportedAlgorithm
        );
        let dup =
            r#"{"alg":"ES256","alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://x"}"#;
        assert!(PASSporT::decode(&tok(dup, P)).is_err());
        let dup_claim = r#"{"attest":"A","attest":"C","dest":{"tn":["1"]},"iat":1,"orig":{"tn":"2"},"origid":"u"}"#;
        assert!(PASSporT::decode(&tok(H, dup_claim)).is_err());
        let crit =
            r#"{"alg":"ES256","crit":["foo"],"ppt":"shaken","typ":"passport","x5u":"https://x"}"#;
        assert!(PASSporT::decode(&tok(crit, P)).is_err());
        let typ = r#"{"alg":"ES256","ppt":"shaken","typ":"JWT","x5u":"https://x"}"#;
        assert!(PASSporT::decode(&tok(typ, P)).is_err());
        let no_origid = r#"{"attest":"A","dest":{"tn":["1"]},"iat":1,"orig":{"tn":"2"}}"#;
        assert_eq!(
            PASSporT::decode(&tok(H, no_origid)).unwrap_err(),
            StirShakenError::InvalidClaim { claim: "origid" }
        );
        let bad_attest =
            r#"{"attest":"a","dest":{"tn":["1"]},"iat":1,"orig":{"tn":"2"},"origid":"u"}"#;
        assert!(PASSporT::decode(&tok(H, bad_attest)).is_err());
        let neg_iat =
            r#"{"attest":"A","dest":{"tn":["1"]},"iat":-1,"orig":{"tn":"2"},"origid":"u"}"#;
        assert!(PASSporT::decode(&tok(H, neg_iat)).is_err());
        let bomb = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
        assert!(PASSporT::decode(&tok(H, &bomb)).is_err());
        // Short signature.
        let short = format!("{}.{}.AAAA", enc(H), enc(P));
        assert!(PASSporT::decode(&short).is_err());
        // Non-UTF-8 JSON.
        let bin = format!("{}.{}", enc(H), {
            let mut s = String::new();
            b64url_encode_into(&[0xff, 0xfe, 0x00], &mut s);
            s
        });
        assert!(PASSporT::decode(&format!("{bin}.AAAA")).is_err());
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics(s in ".{0,600}") {
            let _ = PASSporT::decode(&s);
            let _ = PASSporT::decode_header(&s);
        }

        #[test]
        fn roundtrip_claims(orig in "[0-9]{4,15}", dest in proptest::collection::vec("[0-9]{4,15}", 1..4), iat in 0u64..4_000_000_000) {
            let c = PassportClaims {
                attest: Attestation::Partial,
                dest: dest.iter().map(|d| canonicalize_tn(d).unwrap()).collect(),
                iat,
                orig: canonicalize_tn(&orig).unwrap(),
                origid: "id".into(),
            };
            let t = PASSporT::sign(&c, "https://x.invalid/c", &FakeSigner(Alg::Es256)).unwrap();
            proptest::prop_assert_eq!(PASSporT::decode(&t).unwrap().claims, c);
        }
    }
}
