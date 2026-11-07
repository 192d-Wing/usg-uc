//! Compact JWS encoding helpers for PASSporT (RFC 7515 §7.1, RFC 8225 §9).
//!
//! - base64url without padding (RFC 7515 §2), table-driven.
//! - Deterministic JSON (RFC 8225 §9): members in lexicographic key order,
//!   no insignificant whitespace. Writers in this crate emit keys in sorted
//!   order by construction.

use crate::error::{StirShakenError, StirShakenResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Maximum compact PASSporT length accepted (also bounds JSON size, so no
/// JSON bomb can exceed a few KiB).
pub const MAX_TOKEN_LEN: usize = 4096;

/// Appends the base64url (no padding) encoding of `data` to `out`.
pub fn b64url_encode_into(data: &[u8], out: &mut String) {
    URL_SAFE_NO_PAD.encode_string(data, out);
}

/// Decodes base64url without padding. Padding, whitespace, or any non-alphabet
/// byte is rejected.
///
/// # Errors
/// Returns [`StirShakenError::Malformed`].
pub fn b64url_decode(s: &str) -> StirShakenResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| StirShakenError::Malformed {
            reason: "base64url",
        })
}

/// Appends `s` as a JSON string literal (RFC 8259 §7) to `out`.
pub fn push_json_str(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The three segments of a compact JWS.
#[derive(Debug, Clone, Copy)]
pub struct CompactParts<'a> {
    /// Encoded protected header.
    pub header: &'a str,
    /// Encoded payload.
    pub payload: &'a str,
    /// Encoded signature.
    pub signature: &'a str,
    /// `header "." payload`, the JWS signing input.
    pub signing_input: &'a str,
}

/// Splits a compact JWS into its segments.
///
/// # Errors
/// Returns [`StirShakenError::Malformed`] if the token is oversized, does not
/// have exactly three non-empty segments, or uses the RFC 8224 §7 compact
/// form (empty payload), which SHAKEN does not use.
pub fn split_compact(token: &str) -> StirShakenResult<CompactParts<'_>> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(StirShakenError::Malformed { reason: "too-long" });
    }
    let mut it = token.splitn(4, '.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(StirShakenError::Malformed { reason: "segments" });
    };
    if h.is_empty() || p.is_empty() || s.is_empty() {
        return Err(StirShakenError::Malformed {
            reason: "empty-segment",
        });
    }
    let signing_input = token
        .get(..h.len() + 1 + p.len())
        .ok_or(StirShakenError::Malformed { reason: "segments" })?;
    Ok(CompactParts {
        header: h,
        payload: p,
        signature: s,
        signing_input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip_and_strict() {
        let mut s = String::new();
        b64url_encode_into(b"\xff\xfe hello", &mut s);
        assert!(!s.contains('='));
        assert_eq!(b64url_decode(&s).unwrap(), b"\xff\xfe hello");
        assert!(b64url_decode("aGk=").is_err());
        assert!(b64url_decode("a b").is_err());
        assert!(b64url_decode("+/+/").is_err());
    }

    #[test]
    fn json_escape() {
        let mut s = String::new();
        push_json_str(&mut s, "a\"b\\c\r\n\u{1}");
        assert_eq!(s, r#""a\"b\\c\r\n\u0001""#);
    }

    #[test]
    fn split() {
        let p = split_compact("aa.bb.cc").unwrap();
        assert_eq!(p.signing_input, "aa.bb");
        assert!(split_compact("aa..cc").is_err());
        assert!(split_compact("aa.bb").is_err());
        assert!(split_compact("aa.bb.cc.dd").is_err());
        assert!(split_compact(&"a".repeat(MAX_TOKEN_LEN + 1)).is_err());
    }
}
