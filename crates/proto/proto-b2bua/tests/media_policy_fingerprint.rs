//! DTLS fingerprint rule of `proto_b2bua::media_policy::apply_media_security`
//! (applies whatever `require_srtp` says).
//!
//! Each active DTLS m-line (`UDP/TLS/RTP/SAVP(F)`, RFC 5764 §8) needs at
//! least one applicable `a=fingerprint` (RFC 8122 §5) whose hash is
//! `sha-384` (CNSA 2.0; matched case-insensitively) and whose value is 48
//! colon-separated hex octets. Media-level lines apply first, else the
//! session-level ones (RFC 8122 §5). An offer strips every other line and
//! is refused (Warning 306) when none is left; an answer is refused on any
//! non-sha-384 line and never rewritten. Declined (port 0) sections are not
//! checked (RFC 3264 §8).
//!
//! These cases use only today's API. They assert the warn-code (306) and
//! the m-line index, not variant names, so they compile before and after
//! the variants are added; only `policy()` changes when the policy struct
//! gains `require_srtp` (set it to `false` there: the rule is independent
//! of it).
//!
//! NIST 800-53 Rev5: SC-8, SC-13, SI-10. RFC 8122 §5; RFC 5763 §5;
//! RFC 5764 §8; RFC 3264 §8.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use proto_b2bua::media_policy::{
    KeyingMode, LegContext, MediaPolicyViolation, MediaSecurityPolicy, SdpRole,
    apply_media_security,
};
use std::borrow::Cow;

// The fingerprint rule is independent of `require_srtp`.
const fn policy(mode: KeyingMode) -> MediaSecurityPolicy {
    MediaSecurityPolicy {
        mode,
        require_srtp: false,
    }
}

const TLS_TLS: LegContext = LegContext {
    from_confidential: true,
    to_confidential: true,
};

const MODES: [KeyingMode; 2] = [KeyingMode::Passthrough, KeyingMode::Terminate];

/// `<hash> <octets colon-separated upper-case hex octets>` from `seed`.
/// A fixed pattern, not a certificate digest.
fn fp(hash: &str, octets: usize, seed: u8) -> String {
    let hex: Vec<String> = (0..octets)
        .map(|i| {
            format!(
                "{:02X}",
                seed.wrapping_add(u8::try_from(i % 256).unwrap_or(0))
            )
        })
        .collect();
    format!("{hash} {}", hex.join(":"))
}

fn sha384() -> String {
    fp("sha-384", 48, 0x11)
}

fn sha256() -> String {
    fp("sha-256", 32, 0x80)
}

fn sdp(session_attrs: &str, media: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         {session_attrs}{media}"
    )
}

fn dtls(port: u16, fps: &[&str]) -> String {
    let mut s = format!("m=audio {port} UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\n");
    for f in fps {
        s.push_str("a=fingerprint:");
        s.push_str(f);
        s.push_str("\r\n");
    }
    s
}

fn fingerprint_lines(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("a=fingerprint"))
        .map(str::to_string)
        .collect()
}

fn refused(body: &str, role: SdpRole, mode: KeyingMode) -> MediaPolicyViolation {
    match apply_media_security(body, role, &policy(mode), &TLS_TLS) {
        Ok(s) => panic!("{role:?} {mode:?} accepted: {}", s.sdp),
        Err(e) => e,
    }
}

fn assert_306(e: MediaPolicyViolation, index: usize) {
    assert_eq!(e.warning_code(), 306, "{}", e.as_str());
    assert_eq!(e.index(), Some(index), "{}", e.as_str());
}

// --- Offers -----------------------------------------------------------

#[test]
fn offer_with_only_non_sha384_fingerprint_is_refused() {
    for hash in [("sha-1", 20), ("sha-256", 32), ("sha-512", 64), ("md5", 16)] {
        let f = fp(hash.0, hash.1, 0x22);
        for mode in MODES {
            let e = refused(&sdp("", &dtls(4000, &[&f])), SdpRole::Offer, mode);
            assert_306(e, 0);
        }
    }
}

#[test]
fn offer_dtls_mline_without_any_fingerprint_is_refused() {
    for mode in MODES {
        assert_306(refused(&sdp("", &dtls(4000, &[])), SdpRole::Offer, mode), 0);
    }
}

#[test]
fn offer_strips_extra_hash_lines_and_keeps_sha384() {
    let keep = sha384();
    let drop = sha256();
    for mode in MODES {
        let body = sdp("", &dtls(4000, &[&drop, &keep]));
        let s = apply_media_security(&body, SdpRole::Offer, &policy(mode), &TLS_TLS)
            .unwrap_or_else(|e| panic!("{mode:?}: {}", e.as_str()));
        assert!(matches!(s.sdp, Cow::Owned(_)), "rewritten");
        assert_eq!(
            fingerprint_lines(&s.sdp),
            vec![format!("a=fingerprint:{keep}")],
            "{mode:?}"
        );
    }
}

#[test]
fn offer_strips_session_level_extra_hash_line() {
    let keep = sha384();
    let drop = sha256();
    let body = sdp(&format!("a=fingerprint:{drop}\r\n"), &dtls(4000, &[&keep]));
    let s = apply_media_security(
        &body,
        SdpRole::Offer,
        &policy(KeyingMode::Passthrough),
        &TLS_TLS,
    )
    .unwrap_or_else(|e| panic!("{}", e.as_str()));
    assert_eq!(
        fingerprint_lines(&s.sdp),
        vec![format!("a=fingerprint:{keep}")]
    );
}

#[test]
fn offer_session_level_sha384_applies_when_media_level_absent() {
    let keep = sha384();
    let body = sdp(&format!("a=fingerprint:{keep}\r\n"), &dtls(4000, &[]));
    let s = apply_media_security(
        &body,
        SdpRole::Offer,
        &policy(KeyingMode::Passthrough),
        &TLS_TLS,
    )
    .unwrap_or_else(|e| panic!("{}", e.as_str()));
    assert!(matches!(s.sdp, Cow::Borrowed(_)), "unchanged");
}

/// A media-level sha-256 line next to a session-level sha-384 line: the
/// plan leaves open whether the session line then applies (accept) or the
/// m-line has none left (refuse, 306). Either way no sha-256 line crosses.
#[test]
fn offer_media_level_sha256_with_session_sha384_never_crosses_sha256() {
    let keep = sha384();
    let drop = sha256();
    let body = sdp(&format!("a=fingerprint:{keep}\r\n"), &dtls(4000, &[&drop]));
    match apply_media_security(
        &body,
        SdpRole::Offer,
        &policy(KeyingMode::Passthrough),
        &TLS_TLS,
    ) {
        Ok(s) => {
            assert!(!s.sdp.contains(&drop), "sha-256 crossed: {}", s.sdp);
            assert!(s.sdp.contains(&keep), "{}", s.sdp);
        }
        Err(e) => assert_306(e, 0),
    }
}

#[test]
fn offer_hash_name_and_hex_are_case_insensitive() {
    let upper = sha384().replacen("sha-384", "SHA-384", 1);
    let body = sdp("", &dtls(4000, &[&upper]));
    let s = apply_media_security(
        &body,
        SdpRole::Offer,
        &policy(KeyingMode::Passthrough),
        &TLS_TLS,
    )
    .unwrap_or_else(|e| panic!("{}", e.as_str()));
    assert!(matches!(s.sdp, Cow::Borrowed(_)));
    let lower = sha384().to_ascii_lowercase();
    let body = sdp("", &dtls(4000, &[&lower]));
    assert!(
        apply_media_security(
            &body,
            SdpRole::Offer,
            &policy(KeyingMode::Passthrough),
            &TLS_TLS
        )
        .is_ok()
    );
}

#[test]
fn offer_malformed_sha384_value_is_refused() {
    let good = sha384();
    let cases = [
        fp("sha-384", 47, 0x11),
        fp("sha-384", 49, 0x11),
        fp("sha-384", 32, 0x11),
        good.replacen("11", "G1", 1),
        good.replacen(':', "", 1),
        good.replacen(':', "::", 1),
        format!("{good}:"),
        "sha-384".to_string(),
        "sha-384 ".to_string(),
        good.replacen(' ', "", 1),
    ];
    for (i, bad) in cases.iter().enumerate() {
        for mode in MODES {
            let e = match apply_media_security(
                &sdp("", &dtls(4000, &[bad])),
                SdpRole::Offer,
                &policy(mode),
                &TLS_TLS,
            ) {
                Ok(s) => panic!("case {i} ({bad:?}) {mode:?} accepted: {}", s.sdp),
                Err(e) => e,
            };
            assert_eq!(e.warning_code(), 306, "case {i}: {}", e.as_str());
        }
    }
}

#[test]
fn offer_refusal_reports_the_failing_mline() {
    let good = sha384();
    let bad = sha256();
    let body = sdp(
        "",
        &format!("{}{}", dtls(4000, &[&good]), dtls(4002, &[&bad])),
    );
    assert_306(refused(&body, SdpRole::Offer, KeyingMode::Passthrough), 1);
}

#[test]
fn declined_dtls_mline_is_not_checked() {
    let good = sha384();
    let bad = sha256();
    let body = sdp("", &format!("{}{}", dtls(4000, &[&good]), dtls(0, &[&bad])));
    for role in [SdpRole::Offer, SdpRole::Answer] {
        assert!(
            apply_media_security(&body, role, &policy(KeyingMode::Passthrough), &TLS_TLS).is_ok(),
            "{role:?}"
        );
    }
}

// --- Answers ----------------------------------------------------------

#[test]
fn answer_with_any_non_sha384_line_is_refused_not_stripped() {
    let good = sha384();
    let bad = sha256();
    for mode in MODES {
        for fps in [vec![good.as_str(), bad.as_str()], vec![bad.as_str()]] {
            let body = sdp("", &dtls(5000, &fps));
            assert_306(refused(&body, SdpRole::Answer, mode), 0);
        }
        let session = sdp(&format!("a=fingerprint:{bad}\r\n"), &dtls(5000, &[&good]));
        assert_eq!(
            refused(&session, SdpRole::Answer, mode).warning_code(),
            306,
            "session-level sha-256 in an answer"
        );
    }
}

#[test]
fn answer_dtls_without_fingerprint_is_refused() {
    for mode in MODES {
        assert_306(
            refused(&sdp("", &dtls(5000, &[])), SdpRole::Answer, mode),
            0,
        );
    }
}

#[test]
fn answer_malformed_sha384_value_is_refused() {
    let bad = fp("sha-384", 32, 0x11);
    assert_306(
        refused(
            &sdp("", &dtls(5000, &[&bad])),
            SdpRole::Answer,
            KeyingMode::Passthrough,
        ),
        0,
    );
}

// --- Guards (pass before and after) -----------------------------------

#[test]
fn compliant_sha384_offer_and_answer_are_borrowed() {
    let good = sha384();
    let body = sdp("", &dtls(4000, &[&good]));
    for role in [SdpRole::Offer, SdpRole::Answer] {
        for mode in MODES {
            let s = apply_media_security(&body, role, &policy(mode), &TLS_TLS)
                .unwrap_or_else(|e| panic!("{role:?} {mode:?}: {}", e.as_str()));
            assert!(matches!(s.sdp, Cow::Borrowed(_)), "{role:?} {mode:?}");
        }
    }
}

// --- Properties -------------------------------------------------------

fn fp_line() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(sha384()),
        Just(sha384().replacen("sha-384", "SHA-384", 1)),
        Just(fp("sha-384", 32, 1)),
        Just(sha256()),
        Just(fp("sha-512", 64, 2)),
        Just(fp("sha-1", 20, 3)),
        Just("sha-384 zz".to_string()),
    ]
    .prop_map(|f| format!("a=fingerprint:{f}"))
}

fn dtls_section() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just(0u16), Just(4000u16)],
        prop_oneof![Just("UDP/TLS/RTP/SAVP"), Just("UDP/TLS/RTP/SAVPF")],
        prop::collection::vec(fp_line(), 0..4),
    )
        .prop_map(|(port, proto, fps)| {
            let mut s = format!("m=audio {port} {proto} 0\r\na=setup:actpass\r\n");
            for f in fps {
                s.push_str(&f);
                s.push_str("\r\n");
            }
            s
        })
}

fn dtls_body() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(fp_line(), 0..2),
        prop::collection::vec(dtls_section(), 1..4),
    )
        .prop_map(|(session, sections)| {
            let mut attrs = String::new();
            for f in session {
                attrs.push_str(&f);
                attrs.push_str("\r\n");
            }
            sdp(&attrs, &sections.concat())
        })
}

/// Fingerprint lines that apply to each active m-line of `body`:
/// media-level if any, else session-level.
fn applicable(body: &str) -> Vec<(bool, Vec<String>)> {
    let mut session = Vec::new();
    let mut sections: Vec<(bool, Vec<String>)> = Vec::new();
    for l in body.lines() {
        if let Some(m) = l.strip_prefix("m=") {
            let port = m.split_ascii_whitespace().nth(1).unwrap_or("0");
            sections.push((port != "0", Vec::new()));
        } else if l.to_ascii_lowercase().starts_with("a=fingerprint:") {
            match sections.last_mut() {
                Some((_, v)) => v.push(l.to_string()),
                None => session.push(l.to_string()),
            }
        }
    }
    sections
        .into_iter()
        .map(|(active, v)| (active, if v.is_empty() { session.clone() } else { v }))
        .collect()
}

fn is_sha384(line: &str) -> bool {
    let v = line.split_once(':').map_or("", |(_, v)| v);
    let Some((hash, value)) = v.split_once(' ') else {
        return false;
    };
    let octets: Vec<&str> = value.split(':').collect();
    hash.eq_ignore_ascii_case("sha-384")
        && octets.len() == 48
        && octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
}

proptest! {
    /// An accepted offer keeps at least one sha-384 line for every active
    /// DTLS m-line, and every line that applies to an active m-line is
    /// sha-384 (declined sections are not checked).
    #[test]
    fn accepted_offer_has_only_sha384_fingerprints(body in dtls_body()) {
        for mode in MODES {
            if let Ok(s) = apply_media_security(&body, SdpRole::Offer, &policy(mode), &TLS_TLS) {
                for (active, lines) in applicable(&s.sdp) {
                    if active {
                        prop_assert!(!lines.is_empty(), "{}", s.sdp);
                        for l in &lines {
                            prop_assert!(is_sha384(l), "{mode:?}: {l} crossed in\n{}", s.sdp);
                        }
                    }
                }
            }
        }
    }

    /// An accepted answer is unchanged in its fingerprints, and every line
    /// that applies to an active m-line is sha-384.
    #[test]
    fn accepted_answer_has_only_sha384_fingerprints(body in dtls_body()) {
        if let Ok(s) = apply_media_security(
            &body,
            SdpRole::Answer,
            &policy(KeyingMode::Passthrough),
            &TLS_TLS,
        ) {
            prop_assert_eq!(fingerprint_lines(&s.sdp), fingerprint_lines(&body));
            for (active, lines) in applicable(&s.sdp) {
                if active {
                    prop_assert!(!lines.is_empty(), "{}", s.sdp);
                    for l in &lines {
                        prop_assert!(is_sha384(l), "{l}");
                    }
                }
            }
        }
    }

    /// Idempotent, and m-lines (count, ports, protocols) are kept.
    #[test]
    fn offer_rewrite_is_idempotent_and_keeps_mlines(body in dtls_body()) {
        let p = policy(KeyingMode::Passthrough);
        if let Ok(once) = apply_media_security(&body, SdpRole::Offer, &p, &TLS_TLS) {
            let mlines = |b: &str| -> Vec<String> {
                b.lines().filter(|l| l.starts_with("m=")).map(str::to_string).collect()
            };
            prop_assert_eq!(mlines(&once.sdp), mlines(&body));
            let twice = apply_media_security(&once.sdp, SdpRole::Offer, &p, &TLS_TLS)
                .expect("an accepted offer is accepted again");
            prop_assert_eq!(twice.sdp.as_ref(), once.sdp.as_ref());
        }
    }
}
