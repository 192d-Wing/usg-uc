//! Bounded parsing of the SDP attributes DTLS-SRTP depends on:
//! `m=` transport protocol, `a=fingerprint`, `a=setup` and `a=rtcp-mux`.
//!
//! SDP is attacker-controlled input. Every function here is bounded: at most
//! [`MAX_FINGERPRINTS`] fingerprint attributes per level, each at most
//! [`MAX_SDP_FINGERPRINT_LEN`] bytes, and no indexing on untrusted data.
//!
//! ## NIST 800-53 Rev5 Controls
//! - **SI-10**: input validation of fingerprint/setup/proto
//! - **SC-5**: bounded parsing (count and length caps)
//! - **SC-13**: sha-384 / sha-512 fingerprints only (CNSA 2.0)
//! - **SC-23**: fingerprint binding of the DTLS session to signalling.
//!   POAM: POA&M-324 -- the parsed fingerprints are verified against the
//!   peer certificate only once the DTLS handshake lands; until then no
//!   handshake completes and every TLS-account call fails closed.
//!
//! ## RFC Compliance
//! - RFC 8122 §5: fingerprint grammar; media-level attributes override
//!   session-level ones; the certificate MUST match at least one.
//! - RFC 4145 §4: `a=setup` semantics (default `active` when absent).
//! - RFC 5763 §5: offerer uses `actpass`; answerer SHOULD be `active`;
//!   `actpass` in an answer is a protocol error.
//! - RFC 5764 §8 / RFC 3264 §5.1: `UDP/TLS/RTP/SAVP(F)` describes DTLS-SRTP.

use crate::{SipUaError, SipUaResult};
use proto_dtls::fingerprint::MAX_SDP_FINGERPRINT_LEN;
use proto_dtls::{CertificateFingerprint, DtlsRole};

/// Maximum `a=fingerprint` attributes accepted per SDP level.
pub const MAX_FINGERPRINTS: usize = 8;

/// Maximum `a=setup` value length after trimming (`holdconn` is 8).
pub const MAX_SETUP_VALUE_LEN: usize = 16;

/// Maximum length of a whole `a=setup:` line.
pub const MAX_SETUP_LINE_LEN: usize = 64;

/// DTLS `a=setup` value (RFC 4145 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// Endpoint initiates the DTLS handshake (DTLS client).
    Active,
    /// Endpoint waits for the handshake (DTLS server).
    Passive,
    /// Endpoint accepts either role (offers only).
    ActPass,
    /// No connection (not usable for DTLS-SRTP).
    HoldConn,
}

impl Setup {
    /// Parses an `a=setup` value, case-insensitively.
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] for an unknown value.
    pub fn parse(value: &str) -> SipUaResult<Self> {
        let v = value.trim();
        if v.eq_ignore_ascii_case("active") {
            Ok(Self::Active)
        } else if v.eq_ignore_ascii_case("passive") {
            Ok(Self::Passive)
        } else if v.eq_ignore_ascii_case("actpass") {
            Ok(Self::ActPass)
        } else if v.eq_ignore_ascii_case("holdconn") {
            Ok(Self::HoldConn)
        } else {
            Err(SipUaError::DtlsError("invalid a=setup value".to_string()))
        }
    }

    /// SDP attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
            Self::HoldConn => "holdconn",
        }
    }

    /// Our `a=setup` when answering an offer with `self` (RFC 5763 §5: the
    /// answerer SHOULD be active).
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] for `holdconn`.
    pub fn answer_to_offer(self) -> SipUaResult<Self> {
        match self {
            Self::ActPass | Self::Passive => Ok(Self::Active),
            Self::Active => Ok(Self::Passive),
            Self::HoldConn => Err(SipUaError::DtlsError(
                "offer a=setup:holdconn cannot carry DTLS-SRTP".to_string(),
            )),
        }
    }

    /// The DTLS role our own (resolved) `a=setup` implies.
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] for `actpass`/`holdconn`.
    pub fn local_role(self) -> SipUaResult<DtlsRole> {
        match self {
            Self::Active => Ok(DtlsRole::Client),
            Self::Passive => Ok(DtlsRole::Server),
            Self::ActPass | Self::HoldConn => {
                Err(SipUaError::DtlsError("unresolved a=setup role".to_string()))
            }
        }
    }

    /// Our DTLS role after offering `actpass` and receiving `answer`.
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] if the answer says `actpass`
    /// (RFC 5763 §5 protocol error) or `holdconn`.
    pub fn role_from_answer(answer: Self) -> SipUaResult<DtlsRole> {
        match answer {
            Self::Active => Ok(DtlsRole::Server),
            Self::Passive => Ok(DtlsRole::Client),
            Self::ActPass => Err(SipUaError::DtlsError(
                "answer a=setup:actpass is a protocol error (RFC 5763 §5)".to_string(),
            )),
            Self::HoldConn => Err(SipUaError::DtlsError(
                "answer a=setup:holdconn cannot carry DTLS-SRTP".to_string(),
            )),
        }
    }
}

/// DTLS parameters signalled for one media section.
#[derive(Debug, Clone)]
pub struct DtlsSdpParams {
    /// Accepted (CNSA) fingerprints; never empty.
    pub fingerprints: Vec<CertificateFingerprint>,
    /// Effective `a=setup` (RFC 4145 §4: `active` when absent).
    pub setup: Setup,
}

#[derive(Default)]
struct Level<'a> {
    fingerprints: Vec<&'a str>,
    setup: Option<&'a str>,
}

impl<'a> Level<'a> {
    fn push_fingerprint(&mut self, value: &'a str) -> SipUaResult<()> {
        if self.fingerprints.len() >= MAX_FINGERPRINTS {
            return Err(SipUaError::DtlsError(
                "too many a=fingerprint attributes".to_string(),
            ));
        }
        if value.len() > MAX_SDP_FINGERPRINT_LEN {
            return Err(SipUaError::DtlsError(
                "a=fingerprint attribute too long".to_string(),
            ));
        }
        self.fingerprints.push(value);
        Ok(())
    }

    /// Records an `a=setup` value. A repeated attribute with a different
    /// value is ambiguous and rejected (RFC 4145 §4 allows one per level).
    fn set_setup(&mut self, line: &str, value: &'a str) -> SipUaResult<()> {
        // NIST 800-53 Rev5: SI-10, SC-5 (bounded attribute length)
        if line.len() > MAX_SETUP_LINE_LEN || value.trim().len() > MAX_SETUP_VALUE_LEN {
            return Err(SipUaError::DtlsError(
                "a=setup attribute too long".to_string(),
            ));
        }
        match self.setup {
            Some(prev) if !prev.trim().eq_ignore_ascii_case(value.trim()) => Err(
                SipUaError::DtlsError("conflicting a=setup attributes".to_string()),
            ),
            _ => {
                self.setup = Some(value);
                Ok(())
            }
        }
    }
}

fn sdp_lines(sdp: &str) -> impl Iterator<Item = &str> {
    sdp.split('\n').map(|l| l.trim_end_matches('\r'))
}

/// Parses the DTLS fingerprint and setup for media section `media_index`
/// (0-based count of `m=` lines).
///
/// Fingerprints using non-CNSA hashes (`sha-1`, `sha-224`, `sha-256`, `md5`)
/// are not used. A malformed value for a supported hash is an error. At least
/// one acceptable fingerprint must remain.
///
/// # Errors
/// Returns [`SipUaError::DtlsError`] if the media section does not exist,
/// a cap is exceeded, a value is malformed, `a=setup` is invalid, or no
/// acceptable fingerprint is present.
pub fn parse_dtls_params(sdp: &str, media_index: usize) -> SipUaResult<DtlsSdpParams> {
    let mut session = Level::default();
    let mut media = Level::default();
    let mut current: Option<usize> = None;
    let mut found = false;

    for line in sdp_lines(sdp) {
        if line.starts_with("m=") {
            current = Some(current.map_or(0, |i| i + 1));
            if current == Some(media_index) {
                found = true;
            }
            continue;
        }
        let level = match current {
            None => &mut session,
            Some(i) if i == media_index => &mut media,
            Some(_) => continue,
        };
        if let Some(v) = line.strip_prefix("a=fingerprint:") {
            level.push_fingerprint(v)?;
        } else if let Some(v) = line.strip_prefix("a=setup:") {
            level.set_setup(line, v)?;
        }
    }

    if !found {
        return Err(SipUaError::DtlsError(format!(
            "no media section {media_index}"
        )));
    }

    // RFC 8122 §5: media-level attributes take precedence.
    let raw_fps = if media.fingerprints.is_empty() {
        session.fingerprints
    } else {
        media.fingerprints
    };
    let mut fingerprints = Vec::with_capacity(raw_fps.len());
    for raw in raw_fps {
        let hash = raw.trim().split(' ').next().unwrap_or_default();
        if !(hash.eq_ignore_ascii_case("sha-384") || hash.eq_ignore_ascii_case("sha-512")) {
            // CNSA 2.0: weaker hashes are never used for binding.
            continue;
        }
        let fp = CertificateFingerprint::from_sdp_strict(raw)
            .map_err(|_| SipUaError::DtlsError("malformed a=fingerprint".to_string()))?;
        fingerprints.push(fp);
    }
    if fingerprints.is_empty() {
        return Err(SipUaError::DtlsError(
            "no sha-384/sha-512 a=fingerprint (CNSA 2.0)".to_string(),
        ));
    }

    let setup = match media.setup.or(session.setup) {
        Some(v) => Setup::parse(v)?,
        None => Setup::Active,
    };

    Ok(DtlsSdpParams {
        fingerprints,
        setup,
    })
}

/// Returns the `m=` line for media section `media_index`.
fn media_line(sdp: &str, media_index: usize) -> Option<&str> {
    sdp_lines(sdp)
        .filter(|l| l.starts_with("m="))
        .nth(media_index)
}

/// Returns the index of the first `m=audio` section.
#[must_use]
pub fn first_audio_index(sdp: &str) -> Option<usize> {
    sdp_lines(sdp)
        .filter(|l| l.starts_with("m="))
        .position(|l| l.starts_with("m=audio "))
}

/// Whether an `m=` line describes an active stream: a zero port disables
/// it (RFC 3264 §5.1 / §6). `port/count` form (RFC 4566 §5.14): only the
/// port matters. A line with no port field is not active.
fn media_line_is_active(line: &str) -> bool {
    line.split_ascii_whitespace()
        .nth(1)
        .and_then(|port| port.split('/').next())
        .is_some_and(|port| !port.is_empty() && port != "0")
}

/// Returns the index (among all `m=` lines) of the first active
/// (non-zero port) `m=audio` section.
#[must_use]
pub fn first_active_audio_index(sdp: &str) -> Option<usize> {
    sdp_lines(sdp)
        .filter(|l| l.starts_with("m="))
        .position(|l| l.starts_with("m=audio ") && media_line_is_active(l))
}

/// Returns whether media section `media_index` uses `UDP/TLS/RTP/SAVP` or
/// `UDP/TLS/RTP/SAVPF` (RFC 5764 §8).
#[must_use]
pub fn media_is_dtls_srtp(sdp: &str, media_index: usize) -> bool {
    media_line(sdp, media_index)
        .and_then(|l| l.split_ascii_whitespace().nth(2))
        .is_some_and(|proto| {
            proto.eq_ignore_ascii_case("UDP/TLS/RTP/SAVP")
                || proto.eq_ignore_ascii_case("UDP/TLS/RTP/SAVPF")
        })
}

/// Returns whether every active (non-zero port) `m=` section uses
/// DTLS-SRTP, and at least one is active.
///
/// RFC 5764 §4.1 / RFC 3264 §6: a stream we cannot secure must not be
/// accepted next to a secure one (NIST 800-53 Rev5: SC-8(1)).
#[must_use]
pub fn all_active_media_dtls_srtp(sdp: &str) -> bool {
    let mut active = 0usize;
    for (idx, line) in sdp_lines(sdp).filter(|l| l.starts_with("m=")).enumerate() {
        let port = line.split_ascii_whitespace().nth(1).unwrap_or_default();
        // `port/count` form (RFC 4566 §5.14): only the port matters.
        let port = port.split('/').next().unwrap_or_default();
        if port == "0" {
            continue;
        }
        if !media_is_dtls_srtp(sdp, idx) {
            return false;
        }
        active += 1;
    }
    active > 0
}

/// Returns whether media section `media_index` carries `a=rtcp-mux`
/// (RFC 5761 §5.1.1).
#[must_use]
pub fn media_has_rtcp_mux(sdp: &str, media_index: usize) -> bool {
    let mut current: Option<usize> = None;
    for line in sdp_lines(sdp) {
        if line.starts_with("m=") {
            current = Some(current.map_or(0, |i| i + 1));
        } else if current == Some(media_index) && line.trim_end() == "a=rtcp-mux" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp384(seed: &[u8]) -> CertificateFingerprint {
        CertificateFingerprint::from_certificate_sha384(seed)
    }

    fn sdp(session: &str, media: &str) -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{session}\
             m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\n{media}"
        )
    }

    #[test]
    fn media_level_overrides_session_level() {
        let s = fp384(b"session");
        let m = fp384(b"media");
        let text = sdp(
            &format!("a=fingerprint:{}\r\na=setup:passive\r\n", s.to_sdp()),
            &format!("a=fingerprint:{}\r\na=setup:active\r\n", m.to_sdp()),
        );
        let p = parse_dtls_params(&text, 0).unwrap();
        assert_eq!(p.fingerprints, vec![m]);
        assert_eq!(p.setup, Setup::Active);

        // Session level used when media level is absent.
        let text = sdp(
            &format!("a=fingerprint:{}\r\na=setup:passive\r\n", s.to_sdp()),
            "",
        );
        let p = parse_dtls_params(&text, 0).unwrap();
        assert_eq!(p.fingerprints, vec![s]);
        assert_eq!(p.setup, Setup::Passive);
    }

    #[test]
    fn multiple_fingerprints_and_case() {
        let a = fp384(b"a");
        let b = CertificateFingerprint::from_certificate_sha512(b"b");
        let text = sdp(
            "",
            &format!(
                "a=fingerprint:{}\r\na=fingerprint:{}\r\na=setup:ACTPASS\r\n",
                a.to_sdp().replace("sha-384", "SHA-384").to_lowercase(),
                b.to_sdp()
            ),
        );
        let p = parse_dtls_params(&text, 0).unwrap();
        assert_eq!(p.fingerprints, vec![a, b]);
        assert_eq!(p.setup, Setup::ActPass);
    }

    #[test]
    fn sha256_only_rejected_mixed_keeps_cnsa() {
        let hex = fp384(b"x").to_sdp();
        let hex = hex.trim_start_matches("sha-384 ");
        let sha256 = format!("a=fingerprint:sha-256 {}\r\n", &hex[..95]);
        assert!(parse_dtls_params(&sdp("", &sha256), 0).is_err());

        let good = fp384(b"y");
        let mixed = format!("{sha256}a=fingerprint:{}\r\n", good.to_sdp());
        assert_eq!(
            parse_dtls_params(&sdp("", &mixed), 0).unwrap().fingerprints,
            vec![good]
        );
    }

    #[test]
    fn malformed_and_caps_rejected() {
        let good = fp384(b"z").to_sdp();
        for bad in [
            "a=fingerprint:sha-384 ZZ:00\r\n".to_string(),
            "a=fingerprint:sha-384 ABC\r\n".to_string(),
            format!("a=fingerprint:{good}:00\r\n"),
            format!("a=fingerprint:{}\r\n", &good[..good.len() - 3]),
            format!("a=fingerprint:{good}{}\r\n", " ".repeat(300)),
            format!("a=fingerprint:{good}\r\n").repeat(MAX_FINGERPRINTS + 1),
            "a=setup:active\r\n".to_string(),
        ] {
            assert!(
                parse_dtls_params(&sdp("", &bad), 0).is_err(),
                "accepted {bad}"
            );
        }
        // Missing media section.
        assert!(parse_dtls_params(&sdp("", &format!("a=fingerprint:{good}\r\n")), 1).is_err());
    }

    #[test]
    fn setup_values() {
        let good = fp384(b"s").to_sdp();
        let with = |setup: &str| sdp("", &format!("a=fingerprint:{good}\r\n{setup}"));
        assert_eq!(
            parse_dtls_params(&with(""), 0).unwrap().setup,
            Setup::Active
        );
        assert_eq!(
            parse_dtls_params(&with("a=setup:holdconn\r\n"), 0)
                .unwrap()
                .setup,
            Setup::HoldConn
        );
        assert!(parse_dtls_params(&with("a=setup:sideways\r\n"), 0).is_err());
    }

    // RFC 5763 §5 role table.
    #[test]
    fn role_table() {
        assert_eq!(Setup::ActPass.answer_to_offer().unwrap(), Setup::Active);
        assert_eq!(Setup::Passive.answer_to_offer().unwrap(), Setup::Active);
        assert_eq!(Setup::Active.answer_to_offer().unwrap(), Setup::Passive);
        assert!(Setup::HoldConn.answer_to_offer().is_err());
        // Offer actpass -> answer active -> answerer is Client, we are Server.
        assert_eq!(Setup::Active.local_role().unwrap(), DtlsRole::Client);
        assert_eq!(
            Setup::role_from_answer(Setup::Active).unwrap(),
            DtlsRole::Server
        );
        assert_eq!(
            Setup::role_from_answer(Setup::Passive).unwrap(),
            DtlsRole::Client
        );
        assert!(Setup::role_from_answer(Setup::ActPass).is_err());
    }

    #[test]
    fn proto_and_mux_helpers() {
        let text = sdp("", "a=rtcp-mux\r\n");
        assert!(media_is_dtls_srtp(&text, 0));
        assert!(media_has_rtcp_mux(&text, 0));
        assert_eq!(first_audio_index(&text), Some(0));
        let avp = text.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP");
        assert!(!media_is_dtls_srtp(&avp, 0));
        assert!(!media_is_dtls_srtp(&text, 3));
    }

    /// QA (B2): weak-only hash lists, empty or injected values, wrong
    /// lengths for the declared hash, and oversized `a=setup` are rejected.
    #[test]
    fn qa_hostile_fingerprint_and_setup_rejected() {
        let good = fp384(b"q").to_sdp();
        let hex384 = good.trim_start_matches("sha-384 ").to_string();
        let sha512 = CertificateFingerprint::from_certificate_sha512(b"q").to_sdp();
        for bad in [
            // Only non-CNSA hashes (mixed list, nothing acceptable left).
            format!(
                "a=fingerprint:sha-1 {}\r\na=fingerprint:md5 {}\r\n\
                 a=fingerprint:sha-224 {}\r\na=fingerprint:sha-256 {}\r\n",
                &hex384[..59],
                &hex384[..47],
                &hex384[..83],
                &hex384[..95]
            ),
            // Empty / hash-only / value-only.
            "a=fingerprint:\r\n".to_string(),
            "a=fingerprint:sha-384\r\n".to_string(),
            "a=fingerprint:sha-384 \r\n".to_string(),
            format!("a=fingerprint:{hex384}\r\n"),
            // sha-512 label on 48 octets; sha-384 label on 64 octets.
            format!("a=fingerprint:sha-512 {hex384}\r\n"),
            format!(
                "a=fingerprint:sha-384 {}\r\n",
                sha512.trim_start_matches("sha-512 ")
            ),
            // Embedded NUL / bare CR / tab separators.
            format!("a=fingerprint:{good}\0\r\n"),
            format!("a=fingerprint:sha-384\t{hex384}\r\n"),
            format!("a=fingerprint:{}\r{}\r\n", &good[..40], &good[40..]),
            // Valid sha-384 beside a malformed sha-384 is still an error.
            format!("a=fingerprint:{good}\r\na=fingerprint:sha-384 00:GG\r\n"),
            // Oversized / garbage a=setup.
            format!("a=fingerprint:{good}\r\na=setup:{}\r\n", "a".repeat(4096)),
            format!("a=fingerprint:{good}\r\na=setup:activepassive\r\n"),
            format!("a=fingerprint:{good}\r\na=setup:\r\n"),
            format!("a=fingerprint:{good}\r\na=setup:active;x=1\r\n"),
        ] {
            assert!(
                parse_dtls_params(&sdp("", &bad), 0).is_err(),
                "accepted {:?}",
                &bad[..bad.len().min(120)]
            );
        }
    }

    /// QA (B2): a media-level list with only weak hashes does not fall
    /// back to an acceptable session-level fingerprint (RFC 8122 §5
    /// precedence, fail closed). Strong-plus-weak mixed lists keep the
    /// strong entries in order regardless of position.
    #[test]
    fn qa_mixed_lists_precedence_and_order() {
        let s = fp384(b"session");
        let hex = s.to_sdp();
        let weak = format!(
            "a=fingerprint:sha-256 {}\r\n",
            &hex.trim_start_matches("sha-384 ")[..95]
        );
        let text = sdp(&format!("a=fingerprint:{hex}\r\n"), &weak);
        assert!(parse_dtls_params(&text, 0).is_err());

        let a = fp384(b"a");
        let b = CertificateFingerprint::from_certificate_sha512(b"b");
        let media = format!(
            "{weak}a=fingerprint:{}\r\n{weak}a=fingerprint:{}\r\n{weak}",
            a.to_sdp(),
            b.to_sdp()
        );
        let p = parse_dtls_params(&sdp("", &media), 0).unwrap();
        assert_eq!(p.fingerprints, vec![a, b]);

        // Exactly MAX_FINGERPRINTS (weak ones count toward the cap).
        let at_cap = format!(
            "{}a=fingerprint:{}\r\n",
            weak.repeat(MAX_FINGERPRINTS - 1),
            s.to_sdp()
        );
        assert_eq!(
            parse_dtls_params(&sdp("", &at_cap), 0)
                .unwrap()
                .fingerprints,
            vec![s.clone()]
        );
        let over = format!("{weak}{at_cap}");
        assert!(parse_dtls_params(&sdp("", &over), 0).is_err());

        // Line length cap: exactly at the limit vs one over.
        let pad = MAX_SDP_FINGERPRINT_LEN - s.to_sdp().len();
        let at_len = format!("a=fingerprint:{}{}\r\n", s.to_sdp(), " ".repeat(pad));
        assert!(parse_dtls_params(&sdp("", &at_len), 0).is_ok());
        let over_len = format!("a=fingerprint:{}{}\r\n", s.to_sdp(), " ".repeat(pad + 1));
        assert!(parse_dtls_params(&sdp("", &over_len), 0).is_err());
    }

    /// QA gaps 1-2: conflicting duplicate `a=setup` and long values.
    #[test]
    fn duplicate_and_long_setup() {
        let good = fp384(b"d").to_sdp();
        let with = |setup: &str| sdp("", &format!("a=fingerprint:{good}\r\n{setup}"));
        assert!(parse_dtls_params(&with("a=setup:active\r\na=setup:passive\r\n"), 0).is_err());
        assert_eq!(
            parse_dtls_params(&with("a=setup:active\r\na=setup:ACTIVE\r\n"), 0)
                .unwrap()
                .setup,
            Setup::Active
        );
        let long = format!("a=setup:active{}\r\n", " ".repeat(MAX_SETUP_LINE_LEN));
        assert!(parse_dtls_params(&with(&long), 0).is_err());
        let long_value = format!("a=setup:{}\r\n", "x".repeat(MAX_SETUP_VALUE_LEN + 1));
        assert!(parse_dtls_params(&with(&long_value), 0).is_err());
    }

    #[test]
    fn all_active_media_checked() {
        let base = sdp("", "a=rtcp-mux\r\n");
        assert!(all_active_media_dtls_srtp(&base));
        let video = format!("{base}m=video 5000 RTP/AVP 96\r\n");
        assert!(!all_active_media_dtls_srtp(&video));
        let disabled = format!("{base}m=video 0 RTP/AVP 96\r\n");
        assert!(all_active_media_dtls_srtp(&disabled));
        assert!(!all_active_media_dtls_srtp("v=0\r\n"));
    }

    #[test]
    fn first_active_audio_skips_disabled_sections() {
        let base = sdp("", "a=rtcp-mux\r\n");
        assert_eq!(first_active_audio_index(&base), Some(0));
        assert_eq!(
            first_active_audio_index(&base.replace("m=audio 4000", "m=audio 0")),
            None
        );
        assert_eq!(
            first_active_audio_index(&base.replace("m=audio 4000", "m=audio 0/2")),
            None
        );
        let second = format!(
            "{}m=video 0 RTP/AVP 96\r\nm=audio 4002/2 UDP/TLS/RTP/SAVPF 0\r\n",
            base.replace("m=audio 4000", "m=audio 0")
        );
        assert_eq!(first_active_audio_index(&second), Some(2));
        assert_eq!(first_active_audio_index("v=0\r\nm=audio\r\n"), None);
        assert_eq!(
            first_active_audio_index("v=0\r\nm=video 9 RTP/AVP 96\r\n"),
            None
        );
    }

    #[test]
    fn round_trip_every_seed() {
        for i in 0..64u8 {
            let fp = fp384(&[i; 7]);
            let text = sdp("", &format!("a=fingerprint:{}\r\n", fp.to_sdp()));
            assert_eq!(parse_dtls_params(&text, 0).unwrap().fingerprints, vec![fp]);
        }
    }
}
