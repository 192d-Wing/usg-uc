//! SIP Identity header (RFC 8224 §4.1).
//!
//! ```text
//! Identity = "Identity" HCOLON signed-identity-digest SEMI ident-info
//!            *( SEMI ident-info-params )
//! ident-info = "info" EQUAL ident-info-uri
//! ident-info-uri = LAQUOT absoluteURI RAQUOT
//! ident-info-params = ident-info-alg / ident-type / ident-info-extension
//! ident-info-alg = "alg" EQUAL token
//! ident-type = "ppt" EQUAL token          ; quoted-string accepted too
//! ```
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation)

use crate::error::{StirShakenError, StirShakenResult};
use crate::passport::Alg;

/// Maximum Identity header value length accepted (DoS bound).
pub const MAX_IDENTITY_HEADER_LEN: usize = 4096;

/// Maximum number of header parameters accepted.
const MAX_PARAMS: usize = 16;

/// A parsed Identity header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityHeader {
    /// The compact PASSporT (`signed-identity-digest`).
    pub token: String,
    /// The `info` URI (angle brackets removed).
    pub info: String,
    /// The `alg` parameter, if present.
    pub alg: Option<Alg>,
    /// The `ppt` parameter, if present (quotes removed).
    pub ppt: Option<String>,
}

impl IdentityHeader {
    /// Builds a SHAKEN Identity header for an already-signed token.
    #[must_use]
    pub fn shaken(token: String, info: String, alg: Alg) -> Self {
        Self {
            token,
            info,
            alg: Some(alg),
            ppt: Some(crate::passport::PPT_SHAKEN.to_owned()),
        }
    }

    /// Parses a header value (everything after `Identity:`).
    ///
    /// # Errors
    /// - [`StirShakenError::Malformed`]: oversize, bad token charset,
    ///   duplicate or malformed parameters, unknown `alg`.
    /// - [`StirShakenError::BadInfo`]: `info` missing, or not an `https:` URI
    ///   (RFC 8224 §6.2.2 → 436).
    pub fn parse(value: &str) -> StirShakenResult<Self> {
        if value.len() > MAX_IDENTITY_HEADER_LEN {
            return Err(StirShakenError::Malformed { reason: "too-long" });
        }
        let value = value.trim();
        let (token, mut rest) = value.split_once(';').unwrap_or((value, ""));
        let token = token.trim();
        if token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(StirShakenError::Malformed { reason: "token" });
        }

        let mut info = None;
        let mut alg = None;
        let mut ppt: Option<String> = None;
        let mut count = 0;
        while !rest.trim().is_empty() {
            count += 1;
            if count > MAX_PARAMS {
                return Err(StirShakenError::Malformed { reason: "params" });
            }
            let (name, after) = rest
                .split_once('=')
                .ok_or(StirShakenError::Malformed { reason: "param" })?;
            let name = name.trim();
            let after = after.trim_start();
            let (val, next) = if let Some(uri) = after.strip_prefix('<') {
                let end = uri
                    .find('>')
                    .ok_or(StirShakenError::Malformed { reason: "laquot" })?;
                let (u, tail) = uri.split_at(end);
                (u, tail.get(1..).unwrap_or(""))
            } else if let Some(q) = after.strip_prefix('"') {
                let end = q
                    .find('"')
                    .ok_or(StirShakenError::Malformed { reason: "quote" })?;
                let (u, tail) = q.split_at(end);
                (u, tail.get(1..).unwrap_or(""))
            } else {
                let end = after.find(';').unwrap_or(after.len());
                let (u, tail) = after.split_at(end);
                (u.trim_end(), tail)
            };
            let next = next.trim_start();
            rest = match next.strip_prefix(';') {
                Some(r) => r,
                None if next.is_empty() => "",
                None => return Err(StirShakenError::Malformed { reason: "param" }),
            };
            if val.bytes().any(|b| b.is_ascii_control()) {
                return Err(StirShakenError::Malformed { reason: "param" });
            }
            let dup = || StirShakenError::Malformed {
                reason: "duplicate-param",
            };
            if name.eq_ignore_ascii_case("info") {
                if info.replace(val.to_owned()).is_some() {
                    return Err(dup());
                }
            } else if name.eq_ignore_ascii_case("alg") {
                let a = Alg::parse(val).ok_or(StirShakenError::UnsupportedAlgorithm)?;
                if alg.replace(a).is_some() {
                    return Err(dup());
                }
            } else if name.eq_ignore_ascii_case("ppt") && ppt.replace(val.to_owned()).is_some() {
                return Err(dup());
            }
            // Other ident-info-extension params are ignored (RFC 8224 §4.1).
        }

        let info = info.ok_or(StirShakenError::BadInfo { reason: "missing" })?;
        // RFC 8224 §12 / ATIS-1000074 §5.3.1: only https certificate URIs
        // are dereferenced.
        let is_https = info
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
        if !is_https || info.len() <= 8 {
            return Err(StirShakenError::BadInfo { reason: "scheme" });
        }
        Ok(Self {
            token: token.to_owned(),
            info,
            alg,
            ppt,
        })
    }

    /// Serialises the header value. Only fields this crate produced or
    /// validated are emitted, so no CR/LF can reach the wire.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        let mut s = String::with_capacity(self.token.len() + self.info.len() + 32);
        s.push_str(&self.token);
        s.push_str(";info=<");
        s.push_str(&self.info);
        s.push('>');
        if let Some(a) = self.alg {
            s.push_str(";alg=");
            s.push_str(a.as_str());
        }
        if let Some(p) = &self.ppt {
            s.push_str(";ppt=\"");
            s.push_str(p);
            s.push('"');
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shaken_header() {
        let h = IdentityHeader::parse(
            "eyJh.eyJh.c2ln;info=<https://cert.example.invalid/a.pem>;alg=ES256;ppt=\"shaken\"",
        )
        .unwrap();
        assert_eq!(h.token, "eyJh.eyJh.c2ln");
        assert_eq!(h.info, "https://cert.example.invalid/a.pem");
        assert_eq!(h.alg, Some(Alg::Es256));
        assert_eq!(h.ppt.as_deref(), Some("shaken"));
        assert_eq!(IdentityHeader::parse(&h.to_header_value()).unwrap(), h);
    }

    #[test]
    fn whitespace_and_unquoted_ppt() {
        let h = IdentityHeader::parse(
            "a.b.c ; info = <https://x.invalid/c;v=1> ; ppt=shaken ; foo=bar",
        )
        .unwrap();
        assert_eq!(h.info, "https://x.invalid/c;v=1");
        assert_eq!(h.ppt.as_deref(), Some("shaken"));
    }

    #[test]
    fn rejects() {
        assert!(matches!(
            IdentityHeader::parse("a.b.c"),
            Err(StirShakenError::BadInfo { .. })
        ));
        assert!(matches!(
            IdentityHeader::parse("a.b.c;info=<http://x/c>"),
            Err(StirShakenError::BadInfo { .. })
        ));
        assert!(matches!(
            IdentityHeader::parse("a.b.c;info=<https://x/c>;alg=none"),
            Err(StirShakenError::UnsupportedAlgorithm)
        ));
        assert!(IdentityHeader::parse("a.b.c;info=<https://x/c>;info=<https://y/c>").is_err());
        assert!(IdentityHeader::parse("a b.c;info=<https://x/c>").is_err());
        assert!(IdentityHeader::parse("a.b.c;info=<https://x/c").is_err());
        assert!(IdentityHeader::parse(";info=<https://x/c>").is_err());
        assert!(IdentityHeader::parse("a.b.c;info=<https://x/c>junk").is_err());
        assert!(
            IdentityHeader::parse(&format!("{};info=<https://x/c>", "a".repeat(5000))).is_err()
        );
        assert!(IdentityHeader::parse("a.b.c;info=<https://x/\r\nc>").is_err());
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC{0,300}") {
            let _ = IdentityHeader::parse(&s);
        }

        #[test]
        fn roundtrip(tok in "[A-Za-z0-9_-]{1,40}\\.[A-Za-z0-9_-]{1,40}\\.[A-Za-z0-9_-]{1,40}",
                     host in "[a-z]{1,20}") {
            let h = IdentityHeader::shaken(tok, format!("https://{host}.invalid/c.pem"), Alg::Es256);
            proptest::prop_assert_eq!(IdentityHeader::parse(&h.to_header_value()).unwrap(), h);
        }
    }
}
