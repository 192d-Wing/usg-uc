//! SDP `a=fmtp` parameter intersection for offer/answer.
//!
//! Remote fmtp text comes from an untrusted SDP offer. Nothing from it is
//! copied into the answer verbatim: only known keys with numeric values
//! are parsed, and the answer text is rebuilt from those numbers. This
//! closes CRLF/attribute injection into the answer SDP.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SI-10**: Information Input Validation (bounded parse, allow-listed keys)
//! - **SC-5**: Denial of Service Protection (length and parameter-count caps)

use std::fmt::Write as _;

/// Maximum accepted length of a remote fmtp value, in bytes.
pub const MAX_FMTP_LEN: usize = 512;

/// Maximum number of `;`- or `,`-separated items parsed from one fmtp value.
pub const MAX_FMTP_PARAMS: usize = 32;

/// Default telephone-event list when fmtp is absent (RFC 4733 §2.4.1: "0-15").
const TELEPHONE_EVENT_DEFAULT: &str = "0-15";

/// Outcome of intersecting local and remote fmtp for one codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FmtpIntersection {
    /// The codec is usable; the answer carries these parameters (if any).
    Compatible(Option<String>),
    /// The parameters cannot be reconciled (e.g. disjoint telephone-event
    /// ranges or malformed remote fmtp); the codec must be dropped.
    Incompatible,
}

/// Intersects local and remote fmtp for codec `name`.
///
/// - Opus (RFC 7587 §6.1): the declarative parameters (`useinbandfec`,
///   `stereo`, `sprop-stereo`, `maxplaybackrate`, `maxaveragebitrate`,
///   `usedtx`, `cbr`) are answered with our local values unchanged;
///   `minptime` takes the maximum. Use [`remote_params`] for the peer's
///   values.
/// - telephone-event (RFC 4733 §2.4.1): the event lists are intersected;
///   an empty intersection is [`FmtpIntersection::Incompatible`].
/// - Any other codec: the local fmtp is answered unchanged.
///
/// Remote fmtp longer than [`MAX_FMTP_LEN`], with more than
/// [`MAX_FMTP_PARAMS`] items, or containing control characters is treated
/// as [`FmtpIntersection::Incompatible`].
pub fn intersect_fmtp(name: &str, local: Option<&str>, remote: Option<&str>) -> FmtpIntersection {
    // NIST 800-53 Rev5: SI-10 (reject oversized or control-character fmtp)
    if let Some(r) = remote
        && !is_well_formed(r)
    {
        return FmtpIntersection::Incompatible;
    }

    if name.eq_ignore_ascii_case("opus") {
        FmtpIntersection::Compatible(intersect_opus(local, remote))
    } else if name.eq_ignore_ascii_case("telephone-event") {
        intersect_telephone_event(local, remote)
    } else {
        FmtpIntersection::Compatible(local.map(str::to_string))
    }
}

/// Length, item-count and character-class check for untrusted fmtp text.
fn is_well_formed(value: &str) -> bool {
    value.len() <= MAX_FMTP_LEN
        && !value.bytes().any(|b| b.is_ascii_control())
        && value.split([';', ',']).count() <= MAX_FMTP_PARAMS
}

/// Opus fmtp parameters we understand (RFC 7587 §6.1). `None` = absent.
#[derive(Debug, Default, Clone, Copy)]
struct OpusParams {
    maxplaybackrate: Option<u32>,
    maxaveragebitrate: Option<u32>,
    minptime: Option<u32>,
    useinbandfec: Option<bool>,
    stereo: Option<bool>,
    sprop_stereo: Option<bool>,
    usedtx: Option<bool>,
    cbr: Option<bool>,
}

impl OpusParams {
    fn parse(fmtp: Option<&str>) -> Self {
        let mut p = Self::default();
        let Some(fmtp) = fmtp else {
            return p;
        };
        for item in fmtp.split(';').take(MAX_FMTP_PARAMS) {
            let Some((key, value)) = item.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            // Unknown keys and non-numeric values are dropped, never echoed.
            let num = value.parse::<u32>().ok();
            let flag = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
            match key.to_ascii_lowercase().as_str() {
                // RFC 7587 §6.1: maxplaybackrate 8000..=48000.
                "maxplaybackrate" => {
                    p.maxplaybackrate = num.filter(|n| (8000..=48000).contains(n));
                }
                // RFC 7587 §6.1: maxaveragebitrate 6000..=510000.
                "maxaveragebitrate" => {
                    p.maxaveragebitrate = num.filter(|n| (6000..=510_000).contains(n));
                }
                "minptime" => p.minptime = num.filter(|n| (3..=120).contains(n)),
                "useinbandfec" => p.useinbandfec = flag,
                "stereo" => p.stereo = flag,
                "sprop-stereo" => p.sprop_stereo = flag,
                "usedtx" => p.usedtx = flag,
                "cbr" => p.cbr = flag,
                _ => {}
            }
        }
        p
    }
}

/// Combines two optional values, picking with `f` when both are present.
fn combine<T: Copy>(lhs: Option<T>, rhs: Option<T>, pick: impl Fn(T, T) -> T) -> Option<T> {
    match (lhs, rhs) {
        (Some(x), Some(y)) => Some(pick(x, y)),
        (x, y) => x.or(y),
    }
}

// RFC 7587 §6.1, RFC 3264 §6.1: `useinbandfec`, `stereo`, `sprop-stereo`,
// `maxplaybackrate`, `maxaveragebitrate`, `usedtx` and `cbr` are
// declarative -- each side states what it wants to receive / will send, so
// the answer carries our local values unchanged. Only `minptime` is
// reconciled (the larger of the two), so both directions honour it. The
// peer's values are exposed separately via [`remote_params`] for encoder
// configuration.
fn intersect_opus(local: Option<&str>, remote: Option<&str>) -> Option<String> {
    let mut out = OpusParams::parse(local);
    let r = OpusParams::parse(remote);
    out.minptime = combine(out.minptime, r.minptime, u32::max);
    format_opus(&out)
}

/// Rebuilds Opus fmtp text from parsed values (never echoes input text).
fn format_opus(p: &OpusParams) -> Option<String> {
    let mut s = String::new();
    let mut push = |k: &str, v: u32| {
        if !s.is_empty() {
            s.push(';');
        }
        let _ = write!(s, "{k}={v}");
    };
    if let Some(v) = p.minptime {
        push("minptime", v);
    }
    if let Some(v) = p.useinbandfec {
        push("useinbandfec", u32::from(v));
    }
    if let Some(v) = p.stereo {
        push("stereo", u32::from(v));
    }
    if let Some(v) = p.sprop_stereo {
        push("sprop-stereo", u32::from(v));
    }
    if let Some(v) = p.maxplaybackrate {
        push("maxplaybackrate", v);
    }
    if let Some(v) = p.maxaveragebitrate {
        push("maxaveragebitrate", v);
    }
    if let Some(v) = p.usedtx {
        push("usedtx", u32::from(v));
    }
    if let Some(v) = p.cbr {
        push("cbr", u32::from(v));
    }
    (!s.is_empty()).then_some(s)
}

/// Returns the peer's declared fmtp for codec `name`, for encoder config.
///
/// The text is rebuilt from parsed and range-checked values (unknown keys
/// dropped). Returns `None` if the remote fmtp is absent,
/// malformed, carries nothing we understand, or `name` has no parser.
///
/// The text is never taken from the input verbatim, so it is safe to log
/// or store; it is not meant to be placed in the answer SDP.
// NIST 800-53 Rev5: SI-10 (same bounds as intersect_fmtp)
pub fn remote_params(name: &str, remote: Option<&str>) -> Option<String> {
    let remote = remote?;
    if !is_well_formed(remote) {
        return None;
    }
    if name.eq_ignore_ascii_case("opus") {
        format_opus(&OpusParams::parse(Some(remote)))
    } else if name.eq_ignore_ascii_case("telephone-event") {
        parse_events(remote).map(|set| format_events(&set))
    } else {
        None
    }
}

/// Parses an RFC 4733 §2.4.1 event list (`0-15,66,70`) into a 256-bit set.
/// Returns `None` if any item is malformed or out of range.
fn parse_events(list: &str) -> Option<[bool; 256]> {
    let mut set = [false; 256];
    for item in list.split(',').take(MAX_FMTP_PARAMS) {
        let item = item.trim();
        let (lo, hi) = if let Some((first, last)) = item.split_once('-') {
            (
                first.trim().parse::<u8>().ok()?,
                last.trim().parse::<u8>().ok()?,
            )
        } else {
            let v = item.parse::<u8>().ok()?;
            (v, v)
        };
        if lo > hi {
            return None;
        }
        for e in lo..=hi {
            set[e as usize] = true;
        }
    }
    Some(set)
}

/// Formats an event set as compact ranges (`0-15,66`).
fn format_events(set: &[bool; 256]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < set.len() {
        if !set[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i + 1 < set.len() && set[i + 1] {
            i += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == i {
            let _ = write!(out, "{start}");
        } else {
            let _ = write!(out, "{start}-{i}");
        }
        i += 1;
    }
    out
}

// RFC 4733 §2.4.1, §7.1.1
fn intersect_telephone_event(local: Option<&str>, remote: Option<&str>) -> FmtpIntersection {
    let Some(l) = parse_events(local.unwrap_or(TELEPHONE_EVENT_DEFAULT)) else {
        return FmtpIntersection::Incompatible;
    };
    let Some(r) = parse_events(remote.unwrap_or(TELEPHONE_EVENT_DEFAULT)) else {
        return FmtpIntersection::Incompatible;
    };
    let mut both = [false; 256];
    for (i, slot) in both.iter_mut().enumerate() {
        *slot = l[i] && r[i];
    }
    if !both.iter().any(|&b| b) {
        return FmtpIntersection::Incompatible;
    }
    FmtpIntersection::Compatible(Some(format_events(&both)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compat(s: &str) -> FmtpIntersection {
        FmtpIntersection::Compatible(Some(s.to_string()))
    }

    #[test]
    fn test_opus_declarative_params_answer_local() {
        // RFC 7587 §6.1: stereo is declarative; the answer keeps ours.
        assert_eq!(
            intersect_fmtp("opus", Some("stereo=1"), Some("stereo=0")),
            compat("stereo=1")
        );
        assert_eq!(
            intersect_fmtp("opus", Some("stereo=0"), None),
            compat("stereo=0")
        );
        // Remote declaring no FEC must not switch off our useinbandfec=1.
        assert_eq!(
            intersect_fmtp("opus", Some("useinbandfec=1"), Some("useinbandfec=0")),
            compat("useinbandfec=1")
        );
        assert_eq!(
            intersect_fmtp("opus", Some("minptime=10;useinbandfec=1"), None),
            compat("minptime=10;useinbandfec=1")
        );
        // Remote-only declarative values are not copied into the answer.
        assert_eq!(
            intersect_fmtp("opus", None, Some("stereo=1;useinbandfec=1")),
            FmtpIntersection::Compatible(None)
        );
    }

    #[test]
    fn test_opus_minptime_max() {
        assert_eq!(
            intersect_fmtp(
                "OPUS",
                Some("minptime=10;useinbandfec=1"),
                Some("minptime=20; useinbandfec=0")
            ),
            compat("minptime=20;useinbandfec=1")
        );
        assert_eq!(
            intersect_fmtp("opus", None, Some("minptime=40")),
            compat("minptime=40")
        );
    }

    #[test]
    fn test_opus_rates_and_dtx_answer_local() {
        assert_eq!(
            intersect_fmtp(
                "opus",
                Some("maxplaybackrate=48000;usedtx=1"),
                Some("maxplaybackrate=16000;maxaveragebitrate=20000;usedtx=0")
            ),
            compat("maxplaybackrate=48000;usedtx=1")
        );
    }

    #[test]
    fn test_remote_params_rebuilt() {
        assert_eq!(
            remote_params(
                "opus",
                Some("useinbandfec=0; stereo=1;foo=bar;maxplaybackrate=16000;minptime=2")
            )
            .as_deref(),
            Some("useinbandfec=0;stereo=1;maxplaybackrate=16000")
        );
        assert_eq!(remote_params("opus", None), None);
        assert_eq!(remote_params("opus", Some("foo=bar")), None);
        assert_eq!(remote_params("opus", Some("stereo=1\r\na=x")), None);
        assert_eq!(
            remote_params("telephone-event", Some("0-15,16")).as_deref(),
            Some("0-16")
        );
        assert_eq!(remote_params("telephone-event", Some("0-300")), None);
        assert_eq!(remote_params("PCMU", Some("x=1")), None);
    }

    #[test]
    fn test_opus_unknown_and_bad_values_dropped() {
        assert_eq!(
            intersect_fmtp("opus", None, Some("foo=bar;stereo=yes;minptime=abc")),
            FmtpIntersection::Compatible(None)
        );
    }

    #[test]
    fn test_injection_rejected() {
        assert_eq!(
            intersect_fmtp("opus", Some("useinbandfec=1"), Some("stereo=1\r\na=evil")),
            FmtpIntersection::Incompatible
        );
        let long = "stereo=1;".repeat(100);
        assert_eq!(
            intersect_fmtp("opus", None, Some(&long)),
            FmtpIntersection::Incompatible
        );
    }

    #[test]
    fn test_telephone_event_intersection() {
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-16"), Some("0-15")),
            compat("0-15")
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-16"), None),
            compat("0-15")
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-16,66"), Some("10-20,66,70")),
            compat("10-16,66")
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-15"), Some("32-40")),
            FmtpIntersection::Incompatible
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-15"), Some("0-300")),
            FmtpIntersection::Incompatible
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-15"), Some("9-3")),
            FmtpIntersection::Incompatible
        );
    }

    #[test]
    fn test_other_codecs_keep_local() {
        assert_eq!(
            intersect_fmtp("PCMU", Some("x=1"), Some("y=2")),
            compat("x=1")
        );
        assert_eq!(
            intersect_fmtp("PCMU", None, Some("y=2")),
            FmtpIntersection::Compatible(None)
        );
    }

    // QA: boundary and malformed fmtp (SI-10, SC-5).
    #[test]
    fn test_qa_fmtp_length_boundary() {
        let pad = |n: usize| format!("stereo=1;x={}", "9".repeat(n - "stereo=1;x=".len()));
        let at = pad(MAX_FMTP_LEN);
        assert_eq!(at.len(), MAX_FMTP_LEN);
        assert_eq!(
            intersect_fmtp("opus", Some("stereo=1"), Some(&at)),
            compat("stereo=1"),
            "exactly MAX_FMTP_LEN accepted"
        );
        assert_eq!(
            intersect_fmtp("opus", None, Some(&pad(MAX_FMTP_LEN + 1))),
            FmtpIntersection::Incompatible
        );
    }

    #[test]
    fn test_qa_fmtp_param_count_boundary() {
        let n = |k: usize| vec!["stereo=1"; k].join(";");
        assert_eq!(
            intersect_fmtp("opus", Some("stereo=1"), Some(&n(MAX_FMTP_PARAMS))),
            compat("stereo=1")
        );
        assert_eq!(
            intersect_fmtp("opus", None, Some(&n(MAX_FMTP_PARAMS + 1))),
            FmtpIntersection::Incompatible
        );
    }

    #[test]
    fn test_qa_fmtp_control_chars_rejected() {
        for bad in ["stereo=1\r", "stereo=1\na=x", "stereo=1\0", "stereo=1\t"] {
            assert_eq!(
                intersect_fmtp("opus", None, Some(bad)),
                FmtpIntersection::Incompatible,
                "{bad:?}"
            );
            assert_eq!(
                intersect_fmtp("telephone-event", None, Some(bad)),
                FmtpIntersection::Incompatible,
                "{bad:?}"
            );
            // Other codecs too: remote text is validated before dispatch.
            assert_eq!(
                intersect_fmtp("G722", None, Some(bad)),
                FmtpIntersection::Incompatible,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn test_qa_telephone_event_malformed() {
        for bad in ["256", "0-256", "15-0", "a-b", "", ",", "0-", "-5", "1-2-3"] {
            assert_eq!(
                intersect_fmtp("telephone-event", None, Some(bad)),
                FmtpIntersection::Incompatible,
                "{bad:?}"
            );
        }
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-255"), Some("255")),
            compat("255")
        );
        assert_eq!(
            intersect_fmtp("telephone-event", Some("0-16"), Some(" 0 - 3 , 16 ")),
            compat("0-3,16")
        );
    }

    #[test]
    fn test_qa_opus_out_of_range_values_dropped() {
        assert_eq!(
            intersect_fmtp(
                "opus",
                None,
                Some("maxplaybackrate=7999;maxaveragebitrate=510001;minptime=2;stereo=2")
            ),
            FmtpIntersection::Compatible(None)
        );
    }
}
