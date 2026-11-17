//! Unit tests for `proto_b2bua::media_policy::apply_media_security` (SDES
//! rules). Pending: rename to `media_policy_tests.rs` once the module
//! exists; written against the interface in the plan (§3).
//!
//! RFC 4568 §6.3.1, §7.1.2, §8, §9.1; RFC 4567; RFC 7714 §14.1;
//! RFC 3264 §6, §8. CNSA 2.0: AEAD_AES_256_GCM only.
//! NIST 800-53 Rev5: SC-8, SC-12, SC-13, SI-10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proto_b2bua::media_policy::{
    KeyingMode, LegContext, LegKeying, MediaPolicyViolation, MediaSecurityPolicy, SdpRole,
    apply_media_security,
};
use std::borrow::Cow;

/// 44 octets (AEAD_AES_256_GCM key || salt): bytes 0..44. Not a secret.
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis=";
/// 44 octets: bytes 100..144.
const KEY_256_B: &str = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8=";
/// 30 octets (`AES_CM_128` key || salt): bytes 200..230 (not a prefix of
/// `KEY_256`, so a substring check on it is meaningful).
const KEY_128: &str = "yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl";
const FP_384: &str = "sha-384 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";

// PR-B adds `require_srtp`; only this helper changes then.
fn policy(mode: KeyingMode) -> MediaSecurityPolicy {
    MediaSecurityPolicy { mode }
}

const PASS: KeyingMode = KeyingMode::Passthrough;

const TLS_TLS: LegContext = LegContext {
    from_confidential: true,
    to_confidential: true,
};
const TLS_UDP: LegContext = LegContext {
    from_confidential: true,
    to_confidential: false,
};
const UDP_TLS: LegContext = LegContext {
    from_confidential: false,
    to_confidential: true,
};
const UDP_UDP: LegContext = LegContext {
    from_confidential: false,
    to_confidential: false,
};

fn sdp(media: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{media}")
}

fn gcm(tag: u32, key: &str) -> String {
    format!("a=crypto:{tag} AEAD_AES_256_GCM inline:{key}\r\n")
}

fn aes128(tag: u32) -> String {
    format!("a=crypto:{tag} AES_CM_128_HMAC_SHA1_80 inline:{KEY_128}\r\n")
}

fn savp(crypto: &str) -> String {
    sdp(&format!(
        "m=audio 4000 RTP/SAVP 0\r\n{crypto}a=sendrecv\r\n"
    ))
}

fn ok(body: &str, role: SdpRole, mode: KeyingMode, legs: &LegContext) -> String {
    apply_media_security(body, role, &policy(mode), legs)
        .unwrap_or_else(|e| panic!("refused: {}", e.as_str()))
        .sdp
        .into_owned()
}

fn err(body: &str, role: SdpRole, mode: KeyingMode, legs: &LegContext) -> MediaPolicyViolation {
    match apply_media_security(body, role, &policy(mode), legs) {
        Ok(s) => panic!("accepted: {}", s.sdp),
        Err(e) => e,
    }
}

fn crypto_lines(body: &str) -> Vec<&str> {
    body.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("a=crypto"))
        .collect()
}

// --- Transport rule (RFC 4568 §8.3) -----------------------------------

#[test]
fn sdes_offer_needs_both_hops_confidential() {
    let body = savp(&gcm(1, KEY_256));
    for legs in [TLS_UDP, UDP_TLS, UDP_UDP] {
        for role in [SdpRole::Offer, SdpRole::Answer] {
            assert!(matches!(
                err(&body, role, PASS, &legs),
                MediaPolicyViolation::SdesOverInsecureSignalling { index: 0 }
            ));
        }
    }
    assert!(ok(&body, SdpRole::Offer, PASS, &TLS_TLS).contains(KEY_256));
}

#[test]
fn sdes_on_second_mline_reports_its_index() {
    let body = sdp(&format!(
        "m=audio 4000 RTP/AVP 0\r\nm=video 4002 RTP/SAVP 96\r\n{}",
        gcm(1, KEY_256)
    ));
    assert!(matches!(
        err(&body, SdpRole::Offer, PASS, &TLS_UDP),
        MediaPolicyViolation::SdesOverInsecureSignalling { index: 1 }
    ));
}

// --- Suite filter (CNSA 2.0, RFC 7714) --------------------------------

#[test]
fn offer_strips_non_cnsa_suites() {
    let body = savp(&format!(
        "{}{}a=crypto:3 AEAD_AES_128_GCM inline:{KEY_128}\r\n\
         a=crypto:4 F8_128_HMAC_SHA1_80 inline:{KEY_128}\r\n\
         a=crypto:5 AES_256_CM_HMAC_SHA1_80 inline:{KEY_256}\r\n",
        aes128(1),
        gcm(2, KEY_256)
    ));
    let s = apply_media_security(&body, SdpRole::Offer, &policy(PASS), &TLS_TLS).unwrap();
    assert_eq!(s.stripped_crypto, 4);
    assert!(matches!(s.keying, LegKeying::Sdes));
    assert_eq!(
        crypto_lines(&s.sdp),
        vec![format!("a=crypto:2 AEAD_AES_256_GCM inline:{KEY_256}").as_str()]
    );
}

#[test]
fn offer_with_no_cnsa_suite_is_refused() {
    assert!(matches!(
        err(&savp(&aes128(1)), SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 }
    ));
}

#[test]
fn unknown_suite_and_unparseable_lines_are_stripped() {
    let body = savp(&format!(
        "a=crypto:1 NOT_A_SUITE inline:{KEY_256}\r\na=crypto:garbage\r\na=crypto:\r\n\
         a=crypto:7 AEAD_AES_256_GCM\r\n{}",
        gcm(2, KEY_256)
    ));
    let out = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
    assert_eq!(crypto_lines(&out).len(), 1, "{out}");
    assert!(out.contains("a=crypto:2 AEAD_AES_256_GCM"));
}

#[test]
fn wrong_key_length_is_stripped() {
    // A 30-octet key under the 256-bit AEAD suite does not parse as valid.
    let body = savp(&format!(
        "a=crypto:1 AEAD_AES_256_GCM inline:{KEY_128}\r\n{}",
        gcm(2, KEY_256)
    ));
    let out = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
    assert!(!out.contains(KEY_128), "{out}");
    assert_eq!(crypto_lines(&out).len(), 1);
}

#[test]
fn mki_and_lifetime_accepted_multiple_inline_keys_refused() {
    let line = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}|2^20|1:4\r\n");
    let out = ok(&savp(&line), SdpRole::Offer, PASS, &TLS_TLS);
    assert_eq!(crypto_lines(&out).len(), 1, "{out}");
    // One inline key-param per line; a multi-key line is stripped
    // from an offer and refused when it is the only one.
    let multi = format!(
        "a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}|2^20|1:4;inline:{KEY_256_B}|2^20|2:4\r\n"
    );
    assert!(matches!(
        err(&savp(&multi), SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 }
    ));
    let out = ok(
        &savp(&format!("{multi}{}", gcm(2, KEY_256))),
        SdpRole::Offer,
        PASS,
        &TLS_TLS,
    );
    assert!(!out.contains(KEY_256_B), "{out}");
    assert_eq!(crypto_lines(&out).len(), 1, "{out}");
    assert!(matches!(
        err(&savp(&multi), SdpRole::Answer, PASS, &TLS_TLS),
        MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 }
    ));
}

/// `FEC_KEY` and unknown session parameters are not acceptable.
#[test]
fn fec_key_and_unknown_session_params_are_stripped() {
    for p in [format!("FEC_KEY=inline:{KEY_256_B}"), "-EXT".to_string()] {
        let body = savp(&format!(
            "a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256_B} {p}\r\n{}",
            gcm(2, KEY_256)
        ));
        let out = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
        assert!(!out.contains(KEY_256_B), "{p}: {out}");
        assert_eq!(crypto_lines(&out).len(), 1, "{p}: {out}");
    }
}

#[test]
fn uppercase_attribute_name_is_policed() {
    let body = savp(&format!(
        "a=CRYPTO:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY_128}\r\n{}",
        gcm(2, KEY_256)
    ));
    let out = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
    assert!(!out.contains(KEY_128), "{out}");
    assert!(matches!(
        err(&body, SdpRole::Offer, PASS, &TLS_UDP),
        MediaPolicyViolation::SdesOverInsecureSignalling { .. }
    ));
}

// --- Session parameters (RFC 4568 §6.3.1) -----------------------------

#[test]
fn weakening_session_params_are_stripped_in_offers() {
    for p in [
        "UNENCRYPTED_SRTP",
        "UNENCRYPTED_SRTCP",
        "UNAUTHENTICATED_SRTP",
    ] {
        let weak = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256_B} {p}\r\n");
        let out = ok(
            &savp(&format!("{weak}{}", gcm(2, KEY_256))),
            SdpRole::Offer,
            PASS,
            &TLS_TLS,
        );
        assert!(!out.contains(p), "{p}: {out}");
        assert!(!out.contains(KEY_256_B), "{p}: {out}");
        assert!(matches!(
            err(&savp(&weak), SdpRole::Offer, PASS, &TLS_TLS),
            MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 }
        ));
    }
}

#[test]
fn benign_session_params_are_kept() {
    let line = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256} KDR=0 WSH=64\r\n");
    let out = ok(&savp(&line), SdpRole::Offer, PASS, &TLS_TLS);
    assert!(out.contains("KDR=0 WSH=64"), "{out}");
}

// --- Answers (RFC 4568 §7.1.2): no stripping ----------------------------

#[test]
fn answer_with_one_compliant_line_is_borrowed() {
    let body = savp(&gcm(1, KEY_256));
    let s = apply_media_security(&body, SdpRole::Answer, &policy(PASS), &TLS_TLS).unwrap();
    assert!(matches!(s.sdp, Cow::Borrowed(_)));
    assert_eq!(s.stripped_crypto, 0);
}

#[test]
fn answer_with_weak_or_extra_crypto_is_refused() {
    let cases = [
        aes128(1),
        format!("{}{}", gcm(1, KEY_256), gcm(2, KEY_256_B)),
        format!("{}{}", gcm(1, KEY_256), aes128(2)),
        format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256} UNENCRYPTED_SRTP\r\n"),
        format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256} UNAUTHENTICATED_SRTP\r\n"),
    ];
    for c in cases {
        let e = err(&savp(&c), SdpRole::Answer, PASS, &TLS_TLS);
        assert!(
            matches!(
                e,
                MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 }
            ),
            "{c}: {}",
            e.as_str()
        );
    }
}

// --- Session-level crypto (RFC 4568 §9.1) -------------------------------

#[test]
fn session_level_crypto_is_stripped_in_offers_and_refused_in_answers() {
    let body = format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{}\
         m=audio 4000 RTP/SAVP 0\r\n{}",
        gcm(9, KEY_256_B),
        gcm(1, KEY_256)
    );
    let out = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
    assert!(!out.contains(KEY_256_B), "{out}");
    assert_eq!(crypto_lines(&out).len(), 1);
    assert!(apply_media_security(&body, SdpRole::Answer, &policy(PASS), &TLS_TLS).is_err());
}

// --- key-mgmt (RFC 4567) ------------------------------------------------

#[test]
fn key_mgmt_is_stripped_in_offers_refused_in_answers_and_alone() {
    let mikey = "a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyO7wlKGJBAAAAAAAAAAAAAAAAA==\r\n";
    let body = savp(&format!("{mikey}{}", gcm(1, KEY_256)));
    let s = apply_media_security(&body, SdpRole::Offer, &policy(PASS), &TLS_TLS).unwrap();
    assert_eq!(s.stripped_key_mgmt, 1);
    assert!(!s.sdp.contains("key-mgmt"));
    assert!(matches!(
        err(&body, SdpRole::Answer, PASS, &TLS_TLS),
        MediaPolicyViolation::UnsupportedKeyManagement { index: 0 }
    ));
    assert!(matches!(
        err(&savp(mikey), SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::UnsupportedKeyManagement { index: 0 }
    ));
}

// --- Port 0 (RFC 3264 §8) -----------------------------------------------

#[test]
fn declined_section_crypto_is_stripped_and_not_checked() {
    let body = sdp(&format!(
        "m=audio 4000 RTP/AVP 0\r\nm=video 0 RTP/SAVP 96\r\n{}",
        aes128(1)
    ));
    for role in [SdpRole::Offer, SdpRole::Answer] {
        let out = ok(&body, role, PASS, &TLS_UDP);
        assert!(!out.contains("a=crypto"), "{out}");
        assert!(out.contains("m=video 0 RTP/SAVP 96"), "m-line kept: {out}");
    }
}

#[test]
fn all_sections_declined_is_no_active_stream() {
    let body = sdp(&format!("m=audio 0 RTP/SAVP 0\r\n{}", gcm(1, KEY_256)));
    let s = apply_media_security(&body, SdpRole::Offer, &policy(PASS), &UDP_UDP).unwrap();
    assert!(matches!(s.keying, LegKeying::NoActiveStream));
    assert!(!s.sdp.contains("a=crypto"));
}

#[test]
fn image_section_is_exempt_audio_is_checked() {
    let body = sdp(&format!(
        "m=audio 4000 RTP/SAVP 0\r\n{}m=image 4100 udptl t38\r\na=T38FaxVersion:0\r\n",
        gcm(1, KEY_256)
    ));
    assert!(ok(&body, SdpRole::Offer, PASS, &TLS_TLS).contains("m=image 4100 udptl t38"));
    assert!(apply_media_security(&body, SdpRole::Offer, &policy(PASS), &TLS_UDP).is_err());
}

// --- Terminate mode -----------------------------------------------------

#[test]
fn terminate_strips_crypto_from_dtls_line() {
    let body = sdp(&format!(
        "m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:{FP_384}\r\n{}",
        gcm(1, KEY_256)
    ));
    let s = apply_media_security(
        &body,
        SdpRole::Offer,
        &policy(KeyingMode::Terminate),
        &TLS_TLS,
    )
    .unwrap();
    assert!(!s.sdp.contains("a=crypto"));
    assert!(s.sdp.contains("a=fingerprint:"));
    assert!(matches!(s.keying, LegKeying::DtlsSrtp));
}

#[test]
fn terminate_refuses_sdes_only_line() {
    for legs in [TLS_TLS, TLS_UDP] {
        assert!(matches!(
            err(
                &savp(&gcm(1, KEY_256)),
                SdpRole::Offer,
                KeyingMode::Terminate,
                &legs
            ),
            MediaPolicyViolation::SdesNotTerminable { index: 0 }
        ));
    }
}

// --- Malformed input (SI-10) --------------------------------------------

#[test]
fn bare_cr_nul_and_non_utf8_like_input_are_malformed() {
    let cr = sdp(&format!("m=audio 4000 RTP/AVP 0\r\na=foo\r{}", aes128(1)));
    assert!(matches!(
        err(&cr, SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::MalformedSdp
    ));
    let nul = sdp("m=audio 4000 RTP/AVP 0\r\na=foo\0\r\n");
    assert!(matches!(
        err(&nul, SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::MalformedSdp
    ));
    let bad_port = sdp("m=audio notaport RTP/AVP 0\r\n");
    assert!(matches!(
        err(&bad_port, SdpRole::Offer, PASS, &TLS_TLS),
        MediaPolicyViolation::MalformedSdp
    ));
}

// --- Rewrite shape ------------------------------------------------------

#[test]
fn unchanged_input_is_borrowed_and_rewrite_preserves_line_endings() {
    let body = savp(&gcm(1, KEY_256));
    let s = apply_media_security(&body, SdpRole::Offer, &policy(PASS), &TLS_TLS).unwrap();
    assert!(matches!(s.sdp, Cow::Borrowed(_)));

    let crlf = savp(&format!("{}{}", aes128(1), gcm(2, KEY_256)));
    let out = ok(&crlf, SdpRole::Offer, PASS, &TLS_TLS);
    assert_eq!(out, crlf.replace(&aes128(1), ""));

    let lf = crlf.replace("\r\n", "\n");
    let out = ok(&lf, SdpRole::Offer, PASS, &TLS_TLS);
    assert!(!out.contains('\r'));
    assert_eq!(out, lf.replace(&aes128(1).replace("\r\n", "\n"), ""));
}

#[test]
fn idempotent() {
    let body = savp(&format!("{}{}", aes128(1), gcm(2, KEY_256)));
    let once = ok(&body, SdpRole::Offer, PASS, &TLS_TLS);
    let twice = ok(&once, SdpRole::Offer, PASS, &TLS_TLS);
    assert_eq!(once, twice);
}

#[test]
fn rtp_avp_is_not_refused_in_pr_a() {
    // Cleartext refusal is the `require_srtp` rule (later change).
    let body = sdp("m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n");
    for legs in [TLS_TLS, TLS_UDP, UDP_UDP] {
        assert!(matches!(
            apply_media_security(&body, SdpRole::Offer, &policy(PASS), &legs),
            Ok(ref s) if matches!(s.sdp, Cow::Borrowed(_))
        ));
    }
}

// --- Labels (metrics/audit; SI-11) ---------------------------------------

#[test]
fn labels_and_warning_codes() {
    let v = MediaPolicyViolation::SdesOverInsecureSignalling { index: 0 };
    assert_eq!(v.as_str(), "sdes_over_insecure_signalling");
    assert_eq!(v.warning_code(), 399);
    let v = MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 };
    assert_eq!(v.warning_code(), 306);
    let v = MediaPolicyViolation::SdesNotTerminable { index: 0 };
    assert_eq!(v.warning_code(), 399);
    for v in [
        MediaPolicyViolation::MalformedSdp,
        MediaPolicyViolation::NoAcceptableCryptoSuite { index: 3 },
        MediaPolicyViolation::UnsupportedKeyManagement { index: 1 },
    ] {
        assert!(!v.warning_text().contains("inline"));
        assert!(
            v.as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
        );
    }
}
