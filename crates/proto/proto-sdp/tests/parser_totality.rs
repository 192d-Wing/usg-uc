//! POA&M-283: the SDP parser must be total on untrusted input.
//!
//! RFC 8866 §5: each line is `<type>=<value>` with `<type>` a single ASCII
//! letter. Anything else is a parse error, never a panic.
// NIST 800-53 Rev5: SI-10, SC-5 — malformed remote SDP is rejected, not fatal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use proto_sdp::media::ConnectionData;
use proto_sdp::{
    Attribute, BandwidthInfo, CryptoAttribute, Extmap, MediaDescription, MulticastAddress, Origin,
    RepeatTimes, SessionDescription, SessionParams, TimeValue, Timing, extract_crypto_attributes,
};

const VALID: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 5000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

fn parse(s: &str) -> Result<SessionDescription, proto_sdp::SdpError> {
    s.parse()
}

/// Calls every public string parser; the only assertion is "no panic".
fn exercise_all(s: &str) {
    let _ = parse(s);
    let _ = Attribute::parse(s);
    let _ = Extmap::parse(s);
    let _ = MediaDescription::parse_mline(s);
    let _ = ConnectionData::parse(s);
    let _ = Origin::parse(s);
    let _ = Timing::parse(s);
    let _ = TimeValue::parse(s);
    let _ = RepeatTimes::parse(s);
    let _ = BandwidthInfo::parse(s);
    let _ = CryptoAttribute::parse(s);
    let _ = SessionParams::parse(s);
    let _ = MulticastAddress::parse(s, false);
    let _ = MulticastAddress::parse(s, true);
    let lines: Vec<&str> = s.lines().collect();
    let _ = extract_crypto_attributes(&lines);
}

#[test]
fn multibyte_first_char_is_rejected_not_panicking() {
    for line in ["é=0", "€=x", "😀=x", "日本", "é", "\u{80}=", "ß"] {
        let sdp = format!("{line}\r\n{VALID}");
        assert!(parse(&sdp).is_err(), "accepted {line:?}");
        let sdp = format!("{VALID}{line}\r\n");
        assert!(parse(&sdp).is_err(), "accepted trailing {line:?}");
    }
}

#[test]
fn multibyte_second_char_is_rejected() {
    for line in ["vé0", "a€", "m😀audio"] {
        assert!(parse(&format!("{VALID}{line}\r\n")).is_err(), "{line:?}");
    }
}

#[test]
fn non_letter_type_is_rejected() {
    for line in ["1=0", "==x", "-=x", " =x", "_=x"] {
        assert!(parse(&format!("{VALID}{line}\r\n")).is_err(), "{line:?}");
    }
}

#[test]
fn short_lines_are_rejected() {
    for line in ["v", "a", "="] {
        assert!(parse(&format!("{VALID}{line}\r\n")).is_err(), "{line:?}");
    }
}

#[test]
fn multibyte_values_are_accepted() {
    let sdp = format!("{VALID}a=x-note:héllo 😀\r\n");
    parse(&sdp).expect("UTF-8 in values is allowed");
    let sdp = VALID.replace("s=-", "s=Ünïcödé");
    assert_eq!(parse(&sdp).unwrap().session_name, "Ünïcödé");
}

#[test]
fn valid_sdp_still_parses() {
    parse(VALID).unwrap();
}

#[test]
fn crypto_non_ascii_key_method_is_rejected() {
    for v in [
        "1 AES_CM_128_HMAC_SHA1_80 İnline:AAAA",
        "1 AES_CM_128_HMAC_SHA1_80 \u{212A}nline:AAAA",
        "1 AES_CM_128_HMAC_SHA1_80 inlin€:AAAA",
        "1 AES_CM_128_HMAC_SHA1_80 日本語日本語",
    ] {
        assert!(CryptoAttribute::parse(v).is_err(), "{v:?}");
    }
}

#[test]
fn crypto_lifetime_exponent_overflow_is_rejected() {
    let key = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
    let v = format!("1 AES_CM_128_HMAC_SHA1_80 inline:{key}|2^64");
    assert!(CryptoAttribute::parse(&v).is_err());
    let v = format!("1 AES_CM_128_HMAC_SHA1_80 inline:{key}|2^4294967295");
    assert!(CryptoAttribute::parse(&v).is_err());
}

#[test]
fn time_value_overflow_is_rejected() {
    assert!(TimeValue::parse("18446744073709551615d").is_err());
    assert!(TimeValue::parse("213503982334602d").is_err());
    assert!(RepeatTimes::parse("7d 1h 999999999999999999m").is_err());
}

#[test]
fn plus_signed_numbers_are_rejected() {
    assert!(TimeValue::parse("+5").is_err());
    assert!(TimeValue::parse("+7d").is_err());
    let key = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
    for lt in ["2^+10", "+1000"] {
        let v = format!("1 AES_CM_128_HMAC_SHA1_80 inline:{key}|{lt}");
        assert!(CryptoAttribute::parse(&v).is_err(), "{lt}");
    }
    let v = format!("1 AES_CM_128_HMAC_SHA1_80 inline:{key}|2^20");
    assert!(CryptoAttribute::parse(&v).is_ok());
}

#[test]
fn origin_version_increment_saturates() {
    let mut o = Origin::parse("- 1 18446744073709551615 IN IP4 192.0.2.1").unwrap();
    o.increment_version();
    assert_eq!(o.session_version, "18446744073709551615");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        exercise_all(&String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn arbitrary_strings_never_panic(s in "\\PC{0,256}") {
        exercise_all(&s);
    }

    #[test]
    fn sdp_shaped_lines_never_panic(
        lines in proptest::collection::vec("(.|[a-z]=)[\\PC=:/ |^0-9]{0,40}", 0..24)
    ) {
        let body = lines.join("\r\n");
        exercise_all(&body);
        let _ = parse(&format!("{VALID}{body}"));
    }

    #[test]
    fn mutated_valid_sdp_never_panics(idx in 0usize..VALID.len(), c in any::<char>()) {
        let mut s: String = VALID.chars().collect();
        let pos = s.char_indices().nth(idx % s.chars().count()).map_or(0, |(i, _)| i);
        s.insert(pos, c);
        exercise_all(&s);
    }
}
