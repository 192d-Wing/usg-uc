//! `require_srtp` rules of `proto_b2bua::media_policy::apply_media_security`
//! and `classify_keying`.
//!
//! PENDING: not built (Cargo only discovers `tests/*.rs`). Written against
//! the planned interface:
//!
//! - `MediaSecurityPolicy { mode: KeyingMode, require_srtp: bool }`;
//! - `MediaPolicyViolation::CleartextMedia { index }` and
//!   `UnsupportedProtocol { index }` (Warning 302, labels `cleartext_media`
//!   and `unsupported_protocol`), `FingerprintMissing { index }` and
//!   `FingerprintHashNotAllowed { index }` (Warning 306, labels
//!   `fingerprint_missing` and `fingerprint_hash_not_allowed`);
//! - `pub fn classify_keying(sdp: &str) -> LegKeying`, re-exported at the
//!   crate root.
//!
//! Enable: `git mv tests/media_policy_required.rs.pending
//! tests/media_policy_required.rs`; adjust names here if the change chose
//! different ones.
//!
//! Rules: with `require_srtp`, every active non-image m-line must be a
//! DTLS profile with a passing sha-384 fingerprint, or `RTP/SAVP(F)` with
//! SDES that passes the SDES rules. `RTP/AVP(F)` is `CleartextMedia`; UDP,
//! TCP and unknown protocols are `UnsupportedProtocol`. One failing m-line
//! refuses the whole body. Terminate mode with `require_srtp` needs DTLS on
//! every active non-image m-line. Declined (port 0) m-lines and
//! `m=image udptl` are not checked here; an SDP with no active stream is
//! allowed (`NoActiveStream`).
//!
//! NIST 800-53 Rev5: SC-8, SC-8(1), SC-13, CM-6, SI-10. RFC 3264 §6, §8;
//! RFC 5764 §8; RFC 8122 §5; RFC 4568 §8.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use proto_b2bua::media_policy::{
    KeyingMode, LegContext, LegKeying, MediaPolicyViolation, MediaSecurityPolicy, SdpRole,
    apply_media_security, classify_keying,
};
use std::borrow::Cow;

/// 44 octets (`AEAD_AES_256_GCM` key || salt), bytes 0..44. Not a secret.
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis=";

const TLS_TLS: LegContext = LegContext {
    from_confidential: true,
    to_confidential: true,
};
const UDP_UDP: LegContext = LegContext {
    from_confidential: false,
    to_confidential: false,
};

const PASS: KeyingMode = KeyingMode::Passthrough;
const TERM: KeyingMode = KeyingMode::Terminate;
const ROLES: [SdpRole; 2] = [SdpRole::Offer, SdpRole::Answer];

fn policy(mode: KeyingMode, require_srtp: bool) -> MediaSecurityPolicy {
    MediaSecurityPolicy { mode, require_srtp }
}

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

fn sdp(media: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{media}")
}

fn dtls(kind: &str, port: u16, proto: &str) -> String {
    format!(
        "m={kind} {port} {proto} 0\r\na=setup:actpass\r\na=fingerprint:{}\r\n",
        sha384()
    )
}

fn sdes(kind: &str, port: u16, proto: &str) -> String {
    format!("m={kind} {port} {proto} 0\r\na=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n")
}

fn clear(kind: &str, port: u16, proto: &str) -> String {
    format!("m={kind} {port} {proto} 0\r\n")
}

fn image(port: u16) -> String {
    format!("m=image {port} udptl t38\r\na=T38FaxVersion:0\r\n")
}

fn apply(
    body: &str,
    role: SdpRole,
    mode: KeyingMode,
    required: bool,
    legs: &LegContext,
) -> Result<String, MediaPolicyViolation> {
    apply_media_security(body, role, &policy(mode, required), legs).map(|s| s.sdp.into_owned())
}

// --- Rule matrix: role x mode x require_srtp --------------------------

/// What one body yields for each (mode, require_srtp), offer and answer
/// alike. `None` is accepted; `Some(label)` is refused with that label.
struct Row {
    name: &'static str,
    body: String,
    pass_required: Option<&'static str>,
    pass_optional: Option<&'static str>,
    term_required: Option<&'static str>,
    term_optional: Option<&'static str>,
}

fn matrix() -> Vec<Row> {
    vec![
        Row {
            name: "dtls audio",
            body: sdp(&dtls("audio", 4000, "UDP/TLS/RTP/SAVP")),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
        Row {
            name: "dtls audio savpf",
            body: sdp(&dtls("audio", 4000, "UDP/TLS/RTP/SAVPF")),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
        Row {
            name: "sdes audio",
            body: sdp(&sdes("audio", 4000, "RTP/SAVP")),
            pass_required: None,
            pass_optional: None,
            term_required: Some("sdes_not_terminable"),
            term_optional: Some("sdes_not_terminable"),
        },
        Row {
            name: "rtp/avp audio",
            body: sdp(&clear("audio", 4000, "RTP/AVP")),
            pass_required: Some("cleartext_media"),
            pass_optional: None,
            term_required: Some("cleartext_media"),
            term_optional: None,
        },
        Row {
            name: "rtp/avpf video",
            body: sdp(&clear("video", 4002, "RTP/AVPF")),
            pass_required: Some("cleartext_media"),
            pass_optional: None,
            term_required: Some("cleartext_media"),
            term_optional: None,
        },
        Row {
            name: "rtp/savp without keying",
            body: sdp(&clear("audio", 4000, "RTP/SAVP")),
            pass_required: Some("cleartext_media"),
            pass_optional: None,
            term_required: Some("cleartext_media"),
            term_optional: None,
        },
        Row {
            name: "udp application",
            body: sdp(&clear("application", 4004, "UDP")),
            pass_required: Some("unsupported_protocol"),
            pass_optional: None,
            term_required: Some("unsupported_protocol"),
            term_optional: None,
        },
        Row {
            name: "tcp text",
            body: sdp(&clear("text", 4006, "TCP")),
            pass_required: Some("unsupported_protocol"),
            pass_optional: None,
            term_required: Some("unsupported_protocol"),
            term_optional: None,
        },
        Row {
            name: "dtls audio + rtp/avp video",
            body: sdp(&format!(
                "{}{}",
                dtls("audio", 4000, "UDP/TLS/RTP/SAVP"),
                clear("video", 4002, "RTP/AVP")
            )),
            pass_required: Some("cleartext_media"),
            pass_optional: None,
            term_required: Some("cleartext_media"),
            term_optional: None,
        },
        Row {
            name: "dtls audio + declined rtp/avp video",
            body: sdp(&format!(
                "{}{}",
                dtls("audio", 4000, "UDP/TLS/RTP/SAVP"),
                clear("video", 0, "RTP/AVP")
            )),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
        Row {
            name: "all declined",
            body: sdp(&format!(
                "{}{}",
                clear("audio", 0, "RTP/AVP"),
                clear("video", 0, "RTP/AVP")
            )),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
        Row {
            name: "dtls audio + image",
            body: sdp(&format!(
                "{}{}",
                dtls("audio", 4000, "UDP/TLS/RTP/SAVP"),
                image(4100)
            )),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
        Row {
            name: "declined audio + image",
            body: sdp(&format!("{}{}", clear("audio", 0, "RTP/AVP"), image(4100))),
            pass_required: None,
            pass_optional: None,
            term_required: None,
            term_optional: None,
        },
    ]
}

#[test]
fn rule_matrix_offer_answer_mode_required() {
    for row in matrix() {
        for role in ROLES {
            for (mode, required, want) in [
                (PASS, true, row.pass_required),
                (PASS, false, row.pass_optional),
                (TERM, true, row.term_required),
                (TERM, false, row.term_optional),
            ] {
                let got = apply(&row.body, role, mode, required, &TLS_TLS);
                match (want, got) {
                    (None, Ok(_)) => {}
                    (Some(label), Err(e)) => assert_eq!(
                        e.as_str(),
                        label,
                        "{} {role:?} {mode:?} required={required}",
                        row.name
                    ),
                    (want, got) => panic!(
                        "{} {role:?} {mode:?} required={required}: want {want:?}, got {:?}",
                        row.name,
                        got.map_err(|e| e.as_str())
                    ),
                }
            }
        }
    }
}

#[test]
fn cleartext_and_unsupported_report_index_and_302() {
    let body = sdp(&format!(
        "{}{}",
        dtls("audio", 4000, "UDP/TLS/RTP/SAVP"),
        clear("video", 4002, "RTP/AVP")
    ));
    let e = apply(&body, SdpRole::Offer, PASS, true, &TLS_TLS).unwrap_err();
    assert!(
        matches!(e, MediaPolicyViolation::CleartextMedia { index: 1 }),
        "{e:?}"
    );
    assert_eq!(e.warning_code(), 302);
    assert_eq!(e.index(), Some(1));

    let body = sdp(&format!(
        "{}{}",
        clear("application", 4004, "UDP"),
        dtls("audio", 4000, "UDP/TLS/RTP/SAVP")
    ));
    let e = apply(&body, SdpRole::Offer, PASS, true, &TLS_TLS).unwrap_err();
    assert!(
        matches!(e, MediaPolicyViolation::UnsupportedProtocol { index: 0 }),
        "{e:?}"
    );
    assert_eq!(e.warning_code(), 302);
}

#[test]
fn fingerprint_variants_and_codes() {
    let missing = sdp("m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\n");
    let e = apply(&missing, SdpRole::Offer, PASS, false, &TLS_TLS).unwrap_err();
    assert!(
        matches!(e, MediaPolicyViolation::FingerprintMissing { index: 0 }),
        "{e:?}"
    );
    assert_eq!(e.warning_code(), 306);
    assert_eq!(e.as_str(), "fingerprint_missing");

    let sha256 = sdp(&format!(
        "m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=fingerprint:{}\r\n",
        fp("sha-256", 32, 0x80)
    ));
    for role in ROLES {
        let e = apply(&sha256, role, PASS, false, &TLS_TLS).unwrap_err();
        assert_eq!(e.warning_code(), 306, "{role:?}");
        assert!(
            matches!(
                e,
                MediaPolicyViolation::FingerprintHashNotAllowed { index: 0 }
                    | MediaPolicyViolation::FingerprintMissing { index: 0 }
            ),
            "{role:?}: {e:?}"
        );
    }
    let answer_mixed = sdp(&format!(
        "m=audio 5000 UDP/TLS/RTP/SAVP 0\r\na=fingerprint:{}\r\na=fingerprint:{}\r\n",
        sha384(),
        fp("sha-256", 32, 0x80)
    ));
    let e = apply(&answer_mixed, SdpRole::Answer, PASS, true, &TLS_TLS).unwrap_err();
    assert!(
        matches!(
            e,
            MediaPolicyViolation::FingerprintHashNotAllowed { index: 0 }
        ),
        "{e:?}"
    );
    assert_eq!(e.as_str(), "fingerprint_hash_not_allowed");
}

#[test]
fn labels_and_warning_texts_are_fixed() {
    for (v, label, code) in [
        (
            MediaPolicyViolation::CleartextMedia { index: 0 },
            "cleartext_media",
            302,
        ),
        (
            MediaPolicyViolation::UnsupportedProtocol { index: 0 },
            "unsupported_protocol",
            302,
        ),
        (
            MediaPolicyViolation::FingerprintMissing { index: 0 },
            "fingerprint_missing",
            306,
        ),
        (
            MediaPolicyViolation::FingerprintHashNotAllowed { index: 0 },
            "fingerprint_hash_not_allowed",
            306,
        ),
    ] {
        assert_eq!(v.as_str(), label);
        assert_eq!(v.warning_code(), code);
        let text = v.warning_text();
        assert!(
            !text.is_empty() && text.is_ascii() && !text.contains('"'),
            "{text}"
        );
    }
}

/// `require_srtp` does not relax the SDES transport rule, and SDES over
/// TLS still satisfies it.
#[test]
fn required_sdes_still_needs_confidential_hops() {
    let body = sdp(&sdes("audio", 4000, "RTP/SAVP"));
    assert!(apply(&body, SdpRole::Offer, PASS, true, &TLS_TLS).is_ok());
    assert!(matches!(
        apply(&body, SdpRole::Offer, PASS, true, &UDP_UDP),
        Err(MediaPolicyViolation::SdesOverInsecureSignalling { index: 0 })
    ));
}

/// Case-insensitive protocol names: `rtp/avp` is cleartext, `udp/tls/rtp/savp`
/// is DTLS.
#[test]
fn protocol_names_are_case_insensitive() {
    let lower = sdp(&clear("audio", 4000, "rtp/avp"));
    assert_eq!(
        apply(&lower, SdpRole::Offer, PASS, true, &TLS_TLS)
            .unwrap_err()
            .as_str(),
        "cleartext_media"
    );
    let dtls_lower = sdp(&dtls("audio", 4000, "udp/tls/rtp/savp"));
    assert!(apply(&dtls_lower, SdpRole::Offer, PASS, true, &TLS_TLS).is_ok());
}

#[test]
fn unchanged_body_is_borrowed_under_require_srtp() {
    let body = sdp(&dtls("audio", 4000, "UDP/TLS/RTP/SAVP"));
    for role in ROLES {
        for mode in [PASS, TERM] {
            let s = apply_media_security(&body, role, &policy(mode, true), &TLS_TLS).unwrap();
            assert!(matches!(s.sdp, Cow::Borrowed(_)), "{role:?} {mode:?}");
            assert_eq!(s.keying, LegKeying::DtlsSrtp);
        }
    }
}

// --- classify_keying --------------------------------------------------

#[test]
fn classify_keying_cases() {
    assert_eq!(
        classify_keying(&sdp(&dtls("audio", 4000, "UDP/TLS/RTP/SAVP"))),
        LegKeying::DtlsSrtp
    );
    assert_eq!(
        classify_keying(&sdp(&sdes("audio", 4000, "RTP/SAVP"))),
        LegKeying::Sdes
    );
    assert_eq!(
        classify_keying(&sdp(&clear("audio", 4000, "RTP/AVP"))),
        LegKeying::Cleartext
    );
    assert_eq!(
        classify_keying(&sdp(&format!(
            "{}{}",
            dtls("audio", 4000, "UDP/TLS/RTP/SAVP"),
            clear("video", 4002, "RTP/AVP")
        ))),
        LegKeying::Cleartext,
        "one cleartext active stream makes the leg cleartext"
    );
    assert_eq!(
        classify_keying(&sdp(&clear("audio", 0, "RTP/AVP"))),
        LegKeying::NoActiveStream
    );
    assert_eq!(classify_keying(&sdp("")), LegKeying::NoActiveStream);
    // A DTLS m-line without a fingerprint is not keyed.
    assert_eq!(
        classify_keying(&sdp("m=audio 4000 UDP/TLS/RTP/SAVP 0\r\n")),
        LegKeying::Cleartext
    );
}

#[test]
fn classify_keying_is_reexported() {
    assert_eq!(
        proto_b2bua::classify_keying(&sdp(&clear("audio", 4000, "RTP/AVP"))),
        LegKeying::Cleartext
    );
}

// --- Properties -------------------------------------------------------

fn any_section() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            Just("audio"),
            Just("video"),
            Just("application"),
            Just("image")
        ],
        prop_oneof![Just(0u16), Just(4000u16)],
        prop_oneof![
            Just("RTP/AVP"),
            Just("RTP/AVPF"),
            Just("RTP/SAVP"),
            Just("RTP/SAVPF"),
            Just("UDP/TLS/RTP/SAVP"),
            Just("UDP/TLS/RTP/SAVPF"),
            Just("UDP"),
            Just("TCP"),
            Just("udptl"),
        ],
        prop::bool::ANY,
        prop::bool::ANY,
    )
        .prop_map(|(kind, port, proto, with_fp, with_crypto)| {
            let mut s = format!("m={kind} {port} {proto} 0\r\n");
            if with_fp {
                s.push_str(&format!(
                    "a=setup:actpass\r\na=fingerprint:{}\r\n",
                    sha384()
                ));
            }
            if with_crypto {
                s.push_str(&format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n"));
            }
            s
        })
}

fn any_body() -> impl Strategy<Value = String> {
    prop::collection::vec(any_section(), 0..4).prop_map(|v| sdp(&v.concat()))
}

fn secure_proto(proto: &str) -> bool {
    [
        "RTP/SAVP",
        "RTP/SAVPF",
        "UDP/TLS/RTP/SAVP",
        "UDP/TLS/RTP/SAVPF",
        "TCP/DTLS/RTP/SAVP",
        "TCP/DTLS/RTP/SAVPF",
    ]
    .iter()
    .any(|p| p.eq_ignore_ascii_case(proto))
}

proptest! {
    /// With `require_srtp`, every active non-image m-line of an accepted
    /// body has a secure profile.
    #[test]
    fn required_accepts_only_secure_active_streams(body in any_body()) {
        for role in ROLES {
            for mode in [PASS, TERM] {
                if let Ok(s) = apply_media_security(&body, role, &policy(mode, true), &TLS_TLS) {
                    for l in s.sdp.lines().filter(|l| l.starts_with("m=")) {
                        let f: Vec<&str> = l[2..].split_ascii_whitespace().collect();
                        if f[0] == "image" || f[1] == "0" {
                            continue;
                        }
                        prop_assert!(secure_proto(f[2]), "{role:?} {mode:?}: {l}");
                        if mode == TERM {
                            prop_assert!(
                                f[2].to_ascii_uppercase().contains("TLS/RTP/SAVP")
                                    || f[2].to_ascii_uppercase().contains("DTLS/RTP/SAVP"),
                                "terminate needs DTLS: {l}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// `require_srtp = true` never accepts what `false` refuses.
    #[test]
    fn required_is_stricter(body in any_body()) {
        for role in ROLES {
            for mode in [PASS, TERM] {
                let strict = apply(&body, role, mode, true, &TLS_TLS);
                let loose = apply(&body, role, mode, false, &TLS_TLS);
                if loose.is_err() {
                    prop_assert!(strict.is_err());
                }
                if let (Ok(a), Ok(b)) = (&strict, &loose) {
                    prop_assert_eq!(a, b, "same rewrite when both accept");
                }
            }
        }
    }

    /// Idempotent; m-line count, ports and protocols preserved.
    #[test]
    fn required_rewrite_is_idempotent(body in any_body()) {
        let p = policy(PASS, true);
        if let Ok(once) = apply_media_security(&body, SdpRole::Offer, &p, &TLS_TLS) {
            let mlines = |b: &str| -> Vec<String> {
                b.lines().filter(|l| l.starts_with("m=")).map(str::to_string).collect()
            };
            prop_assert_eq!(mlines(&once.sdp), mlines(&body));
            let twice = apply_media_security(&once.sdp, SdpRole::Offer, &p, &TLS_TLS).unwrap();
            prop_assert_eq!(twice.sdp.as_ref(), once.sdp.as_ref());
        }
    }

    /// Total: no panic on arbitrary input, either flag, either mode.
    #[test]
    fn required_never_panics(body in ".{0,400}") {
        for required in [true, false] {
            for mode in [PASS, TERM] {
                for role in ROLES {
                    let _ = apply_media_security(&body, role, &policy(mode, required), &TLS_TLS);
                }
            }
        }
        let _ = classify_keying(&body);
    }
}
