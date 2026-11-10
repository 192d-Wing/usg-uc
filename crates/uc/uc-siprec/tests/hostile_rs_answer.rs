//! QA: hostile/malformed SRS answers to the RS offer, and `a=recordpref`
//! detection on hostile CS SDP. Nothing here may panic; every bad answer is
//! a `SiprecError::SdpError`.

use std::fmt::Write as _;

use proptest::prelude::*;
use proto_sdp::SessionDescription;
use uc_siprec::rs_answer::{MAX_RECORDPREF_SCAN_BYTES, MAX_RS_ANSWER_STREAMS};
use uc_siprec::{RsAnswerStream, SiprecError, has_recordpref_never, parse_rs_answer};

type R = Result<(), Box<dyn std::error::Error>>;

/// 44 zero octets in base64: syntactically valid key || salt, not a secret.
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const HEAD: &str =
    "v=0\r\no=- 1 1 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n";

fn stream(port: u16) -> String {
    format!(
        "m=audio {port} RTP/SAVP 0 8\r\na=recvonly\r\na=rtcp-mux\r\n\
         a=crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n"
    )
}

fn good() -> String {
    format!("{HEAD}{}{}", stream(40000), stream(40002))
}

/// Parses `text` and validates it as a two-stream RS answer. An SDP parse
/// failure counts as a rejection too (the daemon treats both the same).
fn check(text: &str) -> Result<Vec<RsAnswerStream>, SiprecError> {
    let sdp: SessionDescription = text.parse()?;
    parse_rs_answer(&sdp, 2)
}

fn assert_rejected(what: &str, text: &str) {
    assert!(
        matches!(
            check(text),
            Err(SiprecError::SdpError { .. } | SiprecError::SdpParseError(_))
        ),
        "{what}: accepted or wrong error"
    );
}

#[test]
fn good_answer_is_accepted() -> R {
    let streams = check(&good())?;
    assert_eq!(streams.len(), 2);
    assert_eq!(
        streams.first().map(|s| s.addr),
        Some("198.51.100.7:40000".parse()?)
    );
    assert_eq!(
        streams.get(1).map(|s| s.addr),
        Some("198.51.100.7:40002".parse()?)
    );
    assert!(streams.iter().all(|s| s.rtcp_mux));
    Ok(())
}

#[test]
fn rtcp_mux_is_reported_per_stream() -> R {
    let text = good().replacen("a=rtcp-mux\r\n", "", 1);
    let streams = check(&text)?;
    assert_eq!(
        streams.iter().map(|s| s.rtcp_mux).collect::<Vec<_>>(),
        vec![false, true]
    );
    Ok(())
}

#[test]
fn wrong_m_line_count_is_rejected() {
    assert_rejected("no m-line", HEAD);
    assert_rejected("one m-line", &format!("{HEAD}{}", stream(40000)));
    assert_rejected("three m-lines", &format!("{}{}", good(), stream(40004)));
}

#[test]
fn rejected_stream_is_an_error_not_a_partial_recording() {
    assert_rejected("port 0 first", &good().replace("40000", "0"));
    assert_rejected("port 0 second", &good().replace("40002", "0"));
    assert_rejected("port count", &good().replace("40000", "40000/2"));
    assert_rejected("port overflow", &good().replace("40000", "65536"));
    assert_rejected("negative port", &good().replace("40000", "-1"));
}

#[test]
fn wrong_profile_or_media_is_rejected() {
    for proto in [
        "RTP/AVP",
        "RTP/AVPF",
        "RTP/SAVPF",
        "UDP/TLS/RTP/SAVP",
        "UDP/TLS/RTP/SAVPF",
        "UDP",
        "udptl",
        "RTP/BOGUS",
    ] {
        assert_rejected(proto, &good().replacen("RTP/SAVP", proto, 1));
    }
    assert_rejected("video", &good().replacen("m=audio", "m=video", 1));
    assert_rejected("image", &good().replacen("m=audio", "m=image", 1));
}

#[test]
fn crypto_must_be_exactly_the_offered_line() {
    let line = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n");
    let swap = |with: &str| good().replacen(&line, with, 1);
    let cases: Vec<(&str, String)> = vec![
        ("missing", String::new()),
        ("no value", "a=crypto\r\n".into()),
        ("empty value", "a=crypto:\r\n".into()),
        ("duplicate", format!("{line}{line}")),
        (
            "extra other suite",
            format!("{line}a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:AAAA\r\n"),
        ),
        (
            "extra, different case name",
            format!("{line}a=Crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "AES-128 GCM",
            format!("a=crypto:1 AEAD_AES_128_GCM inline:{KEY}\r\n"),
        ),
        (
            "SHA-1 suite",
            format!("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY}\r\n"),
        ),
        (
            "AES-256 CM",
            format!("a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:{KEY}\r\n"),
        ),
        (
            "suite with suffix",
            format!("a=crypto:1 AEAD_AES_256_GCM_8 inline:{KEY}\r\n"),
        ),
        (
            "tag 2",
            format!("a=crypto:2 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "tag 0",
            format!("a=crypto:0 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "tag +1",
            format!("a=crypto:+1 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "tag 01",
            format!("a=crypto:01 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "tag overflow",
            format!("a=crypto:4294967297 AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
        (
            "no tag",
            format!("a=crypto:AEAD_AES_256_GCM inline:{KEY}\r\n"),
        ),
    ];
    for (what, with) in cases {
        assert_rejected(what, &swap(&with));
    }
}

#[test]
fn crypto_key_and_session_params_are_checked() {
    let line = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n");
    let swap = |with: &str| good().replacen(&line, with, 1);
    let short = &KEY[..56];
    let cases: Vec<(&str, String)> = vec![
        ("no key", "a=crypto:1 AEAD_AES_256_GCM\r\n".into()),
        (
            "empty key",
            "a=crypto:1 AEAD_AES_256_GCM inline:\r\n".into(),
        ),
        (
            "short key",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{short}\r\n"),
        ),
        (
            "long key",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:AAAA{KEY}\r\n"),
        ),
        (
            "non-base64 key",
            format!(
                "a=crypto:1 AEAD_AES_256_GCM inline:{}\r\n",
                KEY.replacen('A', "!", 1)
            ),
        ),
        (
            "multibyte key",
            format!(
                "a=crypto:1 AEAD_AES_256_GCM inline:{}\r\n",
                KEY.replacen("AA", "\u{e9}", 1)
            ),
        ),
        (
            "multibyte key method",
            format!("a=crypto:1 AEAD_AES_256_GCM inlin\u{e9}{KEY}\r\n"),
        ),
        (
            "other key method",
            format!("a=crypto:1 AEAD_AES_256_GCM uri:{KEY}\r\n"),
        ),
        (
            "two keys",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY};inline:{KEY}\r\n"),
        ),
        (
            "UNENCRYPTED_SRTP",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY} UNENCRYPTED_SRTP\r\n"),
        ),
        (
            "unencrypted_srtcp",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY} KDR=1 unencrypted_srtcp\r\n"),
        ),
        (
            "UNAUTHENTICATED_SRTP",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY} UNAUTHENTICATED_SRTP\r\n"),
        ),
        (
            "FEC_ORDER",
            format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY} FEC_ORDER=FEC_SRTP\r\n"),
        ),
    ];
    for (what, with) in cases {
        assert_rejected(what, &swap(&with));
    }
}

#[test]
fn declarative_key_and_session_params_are_tolerated() -> R {
    let line = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n");
    let with = format!("a=crypto:1 aead_aes_256_gcm INLINE:{KEY}|2^31|1:4 KDR=2 WSH=128\r\n");
    check(&good().replace(&line, &with))?;
    Ok(())
}

#[test]
fn direction_must_be_recvonly() {
    for dir in ["a=sendonly", "a=sendrecv", "a=inactive"] {
        assert_rejected(dir, &good().replacen("a=recvonly", dir, 1));
    }
    // No direction at all defaults to sendrecv (RFC 3264 §6.1).
    assert_rejected("default", &good().replacen("a=recvonly\r\n", "", 1));
    assert_rejected(
        "conflicting",
        &good().replacen("a=recvonly\r\n", "a=recvonly\r\na=sendrecv\r\n", 1),
    );
    assert_rejected(
        "conflicting, hostile first",
        &good().replacen("a=recvonly\r\n", "a=sendrecv\r\na=recvonly\r\n", 1),
    );
    // Session-level sendonly does not satisfy an m-line without direction.
    assert_rejected(
        "session sendonly",
        &good()
            .replace("a=recvonly\r\n", "")
            .replace("t=0 0\r\n", "t=0 0\r\na=sendonly\r\n"),
    );
}

#[test]
fn connection_address_must_be_usable_unicast() {
    let c = "c=IN IP4 198.51.100.7";
    for bad in [
        "c=IN IP4 127.0.0.1",
        "c=IN IP4 127.255.255.254",
        "c=IN IP4 0.0.0.0",
        "c=IN IP4 224.0.0.1",
        "c=IN IP4 239.255.255.255",
        "c=IN IP4 224.2.1.1/127",
        "c=IN IP4 255.255.255.255",
        "c=IN IP6 ::1",
        "c=IN IP6 ::",
        "c=IN IP6 ff02::1",
        "c=IN IP6 ::ffff:127.0.0.1",
        "c=IN IP6 ::ffff:0.0.0.0",
        "c=IN IP6 ::ffff:224.0.0.1",
        // Family / type confusion and non-literals.
        "c=IN IP6 198.51.100.7",
        "c=IN IP4 2001:db8::7",
        "c=IN IP4 srs.example.com",
        "c=IN IP4 198.51.100.7:5060",
        "c=IN IP4 198.51.100",
        "c=IN IP4 0x7f.0.0.1",
        "c=IN IP6 [2001:db8::7]",
        "c=IN IP6 fe80::1%eth0",
        "c=ATM NSAP 47.0091",
        "c=in ip4 198.51.100.7",
        "c=IN IP4",
        "c=",
    ] {
        assert_rejected(bad, &good().replace(c, bad));
    }
    // No c= anywhere.
    assert_rejected("no c=", &good().replace("c=IN IP4 198.51.100.7\r\n", ""));
    // A hostile media-level c= overrides a good session-level one.
    assert_rejected(
        "media-level loopback",
        &good().replacen("a=recvonly\r\n", "c=IN IP4 127.0.0.1\r\na=recvonly\r\n", 1),
    );
}

#[test]
fn media_level_connection_wins_over_session_level() -> R {
    let text = good()
        .replace("c=IN IP4 198.51.100.7", "c=IN IP4 127.0.0.1")
        .replace("a=recvonly\r\n", "c=IN IP6 2001:db8::9\r\na=recvonly\r\n");
    let streams = check(&text)?;
    assert_eq!(
        streams.first().map(|s| s.addr),
        Some("[2001:db8::9]:40000".parse()?)
    );
    Ok(())
}

#[test]
fn oversized_answers_do_not_panic_or_slip_through() {
    // Far more m-lines than offered.
    let mut many = String::from(HEAD);
    for i in 0..2000u16 {
        many.push_str(&stream(10000 + i));
    }
    assert_rejected("2000 m-lines", &many);

    // A huge attribute list hiding a second crypto line at the very end.
    let mut padded = good();
    for i in 0..20_000 {
        let _ = write!(padded, "a=x-pad-{i}:{}\r\n", "p".repeat(32));
    }
    assert!(check(&padded).is_ok(), "padding alone is harmless");
    padded.push_str("a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:AAAA\r\n");
    assert_rejected("trailing extra crypto", &padded);

    // One enormous crypto value / connection address.
    let huge = "A".repeat(1 << 20);
    assert_rejected("1 MiB key", &good().replacen(KEY, &huge, 1));
    assert_rejected(
        "1 MiB address",
        &good().replace("198.51.100.7\r\nt=", &format!("{huge}\r\nt=")),
    );
    assert_rejected(
        "1 MiB session params",
        &good().replacen(
            &format!("{KEY}\r\n"),
            &format!("{KEY} {huge} UNENCRYPTED_SRTP\r\n"),
            1,
        ),
    );
}

#[test]
fn expected_stream_count_is_bounded() -> R {
    let sdp: SessionDescription = good().parse()?;
    assert!(parse_rs_answer(&sdp, 0).is_err());
    assert!(parse_rs_answer(&sdp, 1).is_err());
    assert!(parse_rs_answer(&sdp, 3).is_err());
    assert!(parse_rs_answer(&sdp, MAX_RS_ANSWER_STREAMS + 1).is_err());
    assert!(parse_rs_answer(&sdp, usize::MAX).is_err());
    Ok(())
}

#[test]
fn garbage_bodies_are_rejected() {
    for body in [
        "",
        "\r\n\r\n",
        "not sdp at all",
        "<?xml version=\"1.0\"?><recording/>",
        "v=0",
        "m=audio",
        "m=audio 40000 RTP/SAVP",
        "\0\0\0\0",
        "v=0\r\nm=audio 40000 RTP/SAVP 0\r\nm=audio 40002 RTP/SAVP 0\r\n",
    ] {
        assert_rejected(body, body);
    }
}

#[test]
fn error_text_does_not_echo_hostile_values() -> R {
    let marker = "EVIL\u{1b}[31mMARKER";
    let texts = [
        good().replacen("AEAD_AES_256_GCM", marker, 1),
        good().replacen("a=recvonly", &format!("a=sendonly:{marker}"), 1),
        good().replace("198.51.100.7\r\nt=", &format!("{marker}\r\nt=")),
        good().replacen(KEY, &format!("{marker}{KEY}"), 1),
    ];
    for text in texts {
        let sdp: SessionDescription = text.parse()?;
        let err = parse_rs_answer(&sdp, 2).err().ok_or("accepted")?;
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("MARKER"), "{shown}");
        assert!(!shown.contains(KEY), "{shown}");
    }
    Ok(())
}

#[test]
fn recordpref_session_and_media_level() {
    let session = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\na=recordpref:off\r\n\
                   m=audio 10000 RTP/AVP 0\r\n";
    let media = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
                 m=audio 10000 RTP/AVP 0\r\na=sendrecv\r\na=recordpref:never\r\n";
    assert!(has_recordpref_never(session));
    assert!(has_recordpref_never(media));
    assert!(!has_recordpref_never(&session.replace("off", "on")));
    assert!(!has_recordpref_never(
        &media.replace("never", "nopreference")
    ));
    assert!(!has_recordpref_never(&media.replace("never", "pause")));
}

#[test]
fn recordpref_case_and_whitespace_variants() {
    for line in [
        "a=recordpref:off",
        "a=recordpref:never",
        "a=recordpref:OFF",
        "a=recordpref:Never",
        "a=RecordPref:off",
        "a=RECORDPREF:NEVER",
        "a=recordpref: off",
        "a=recordpref:off ",
        "a=recordpref:\toff\t",
        "a=recordpref : off",
        "  a=recordpref:off",
    ] {
        for eol in ["\r\n", "\n", ""] {
            assert!(
                has_recordpref_never(&format!(
                    "v=0{}{line}{eol}",
                    if eol.is_empty() { "\n" } else { eol }
                )),
                "{line:?} {eol:?}"
            );
        }
    }
    for line in [
        "a=recordpref",
        "a=recordpref:",
        "a=recordpref:o ff",
        "a=recordpref:off;x",
        "a=recordpref:never,on",
        "a=recordprefs:off",
        "a=xrecordpref:off",
        "a=record:off",
        "b=recordpref:off",
        "recordpref:off",
        "a =recordpref:off",
        "i=the caller said a=recordpref:off",
        "a=fmtp:101 a=recordpref:off",
    ] {
        assert!(
            !has_recordpref_never(&format!("v=0\r\n{line}\r\n")),
            "{line:?}"
        );
    }
}

#[test]
fn recordpref_scan_is_bounded() {
    // Opt-out inside the window is seen even in a large body.
    let mut text = String::from("v=0\r\na=recordpref:off\r\n");
    text.push_str(&"a=x:pad\r\n".repeat(100_000));
    assert!(has_recordpref_never(&text));

    // Past the window it is not examined (the sender only fails to opt out).
    let mut late = "a=x:pad\r\n".repeat(MAX_RECORDPREF_SCAN_BYTES / 9 + 1);
    assert!(late.len() >= MAX_RECORDPREF_SCAN_BYTES);
    late.push_str("a=recordpref:off\r\n");
    assert!(!has_recordpref_never(&late));

    // One giant line, multibyte content, NULs: no panic.
    assert!(!has_recordpref_never(&"\u{e9}".repeat(1 << 20)));
    assert!(!has_recordpref_never(&"\0".repeat(1 << 16)));
    assert!(!has_recordpref_never(&"\n".repeat(1 << 20)));
}

/// Fragments that steer random input towards the validator's branches.
fn sdp_line() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("v=0".to_string()),
        Just("o=- 1 1 IN IP4 198.51.100.7".to_string()),
        Just("s=-".to_string()),
        Just("t=0 0".to_string()),
        "c=IN IP[46] [0-9a-f:.]{0,20}",
        "m=(audio|video|image) [0-9]{1,6}(/[0-9]{1,3})? (RTP/SAVP|RTP/AVP|RTP/SAVPF|udptl) [0-9 ]{1,8}",
        "a=(recvonly|sendonly|sendrecv|inactive|rtcp-mux)",
        "a=crypto:[0-9+]{0,3} (AEAD_AES_256_GCM|AEAD_AES_128_GCM|\\PC{0,12}) (inline:)?[A-Za-z0-9+/=|;:^]{0,70}( \\PC{0,20})?",
        "a=crypto:\\PC{0,80}",
        "a=recordpref:\\PC{0,12}",
        "[a-z]=\\PC{0,40}",
        "\\PC{0,40}",
    ]
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,400}", n in 0usize..20) {
        let _ = has_recordpref_never(&text);
        if let Ok(sdp) = text.parse::<SessionDescription>() {
            let _ = parse_rs_answer(&sdp, n);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = has_recordpref_never(&text);
        if let Ok(sdp) = text.parse::<SessionDescription>() {
            let _ = parse_rs_answer(&sdp, 2);
        }
    }

    #[test]
    fn structured_sdp_never_panics_and_accepts_only_safe_answers(
        lines in proptest::collection::vec(sdp_line(), 0..24),
        eol in prop_oneof![Just("\r\n"), Just("\n")],
        n in 1usize..4,
    ) {
        let text = lines.join(eol);
        let _ = has_recordpref_never(&text);
        if let Ok(sdp) = text.parse::<SessionDescription>()
            && let Ok(streams) = parse_rs_answer(&sdp, n)
        {
            prop_assert_eq!(streams.len(), n);
            prop_assert_eq!(sdp.media.len(), n);
            for s in streams {
                prop_assert!(s.addr.port() != 0);
                let ip = s.addr.ip();
                prop_assert!(!ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast());
            }
        }
    }

    #[test]
    fn mutated_good_answer_never_panics(at in 0usize..400, with in "\\PC{0,6}", cut in 0usize..400) {
        let base = good();
        let mut chars: Vec<char> = base.chars().collect();
        let at = at.min(chars.len());
        let end = at.saturating_add(cut % 8).min(chars.len());
        chars.splice(at..end, with.chars());
        let text: String = chars.into_iter().collect();
        let _ = has_recordpref_never(&text);
        if let Ok(sdp) = text.parse::<SessionDescription>() {
            let _ = parse_rs_answer(&sdp, 2);
        }
    }
}
