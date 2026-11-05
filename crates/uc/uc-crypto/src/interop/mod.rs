//! Interoperability-only algorithms that are **not** CNSA 2.0 compliant.
//!
//! Everything in this module exists because an external standard mandates an
//! algorithm CNSA 2.0 does not permit. It is compiled only with an explicit
//! cargo feature, is never re-exported from the crate root, and every call
//! site outside this crate must carry a `// CNSA-EXCEPTION:` tag naming the
//! mandating standard.
//!
//! | Module | Feature | Mandated by |
//! |--------|---------|-------------|
//! | [`ecdsa_p256`] | `stir-shaken-es256` | ATIS-1000074, RFC 8225 §5.2 (ES256) |
//!
//! These algorithms are used for **authentication of caller identity only**
//! (signatures). They are never used for confidentiality.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
//!
//! The deviation is documented in `docs/CNSA-2-COMPLIANCE.md` and tracked as a
//! POA&M item.
// POAM: ES256 (P-256/SHA-256) is a CNSA 2.0 deviation required for SHAKEN
// interop; retire when ATIS/STI-GA permit ES384 PASSporTs.

#[cfg(feature = "stir-shaken-es256")]
pub mod ecdsa_p256;

/// Minimal base64url decoder for test vectors (no padding).
#[cfg(test)]
pub(crate) fn test_b64url(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
