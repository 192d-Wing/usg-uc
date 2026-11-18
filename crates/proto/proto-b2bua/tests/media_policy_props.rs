//! Properties of `proto_b2bua::media_policy::apply_media_security` on
//! generated SDP (RFC 4568 §8, RFC 7714 §14.1, RFC 3264 §8).
//!
//! - Total: no panic on arbitrary input, including NUL, bare CR and
//!   non-SDP text.
//! - An accepted body never carries an `a=crypto` line with a suite other
//!   than `AEAD_AES_256_GCM`, and none at all when a hop is not
//!   confidential.
//! - Idempotent, and m-lines (count, order, text) are kept.
// NIST 800-53 Rev5: SC-8, SC-12, SC-13, SI-10.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use proto_b2bua::media_policy::{
    KeyingMode, LegContext, MediaSecurityPolicy, SdpRole, apply_media_security,
};

/// 44 octets (`AEAD_AES_256_GCM` key || salt), bytes 0..44. Not a secret.
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis=";
/// 30 octets, bytes 200..230.
const KEY_128: &str = "yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl";

fn crypto_line() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}")),
        Just(format!("a=CRYPTO:2 AEAD_AES_256_GCM inline:{KEY_256}|2^20")),
        Just(format!(
            "a=crypto:3 AEAD_AES_256_GCM inline:{KEY_256} UNENCRYPTED_SRTP"
        )),
        Just(format!(
            "a=crypto:4 AES_CM_128_HMAC_SHA1_80 inline:{KEY_128}"
        )),
        Just(format!("a=crypto:5 AEAD_AES_128_GCM inline:{KEY_128}")),
        Just("a=crypto:6 AEAD_AES_256_GCM".to_string()),
        Just("a=crypto:garbage".to_string()),
    ]
}

fn other_line() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a=sendrecv".to_string()),
        Just("a=rtpmap:0 PCMU/8000".to_string()),
        Just("a=key-mgmt:mikey AQAFgM0X".to_string()),
        Just("a=setup:actpass".to_string()),
        Just(
            "a=fingerprint:sha-384 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                .to_string()
        ),
    ]
}

fn mline() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("audio"), Just("video"), Just("image")],
        prop_oneof![Just(0u16), Just(4000u16), Just(4002u16)],
        prop_oneof![
            Just("RTP/AVP"),
            Just("RTP/SAVP"),
            Just("RTP/SAVPF"),
            Just("UDP/TLS/RTP/SAVP"),
            Just("udptl"),
        ],
    )
        .prop_map(|(media, port, proto)| format!("m={media} {port} {proto} 0"))
}

fn section() -> impl Strategy<Value = Vec<String>> {
    (
        mline(),
        prop::collection::vec(prop_oneof![crypto_line(), other_line()], 0..5),
    )
        .prop_map(|(m, mut attrs)| {
            attrs.insert(0, m);
            attrs
        })
}

fn sdp() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(prop_oneof![crypto_line(), other_line()], 0..2),
        prop::collection::vec(section(), 0..4),
        any::<bool>(),
    )
        .prop_map(|(session_attrs, sections, crlf)| {
            let eol = if crlf { "\r\n" } else { "\n" };
            let mut lines = vec![
                "v=0".to_string(),
                "o=- 1 1 IN IP4 192.0.2.1".to_string(),
                "s=-".to_string(),
                "c=IN IP4 192.0.2.1".to_string(),
                "t=0 0".to_string(),
            ];
            lines.extend(session_attrs);
            lines.extend(sections.into_iter().flatten());
            let mut out = lines.join(eol);
            out.push_str(eol);
            out
        })
}

fn context() -> impl Strategy<Value = (SdpRole, MediaSecurityPolicy, LegContext)> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
        |(answer, terminate, from, to)| {
            (
                if answer {
                    SdpRole::Answer
                } else {
                    SdpRole::Offer
                },
                MediaSecurityPolicy {
                    mode: if terminate {
                        KeyingMode::Terminate
                    } else {
                        KeyingMode::Passthrough
                    },
                },
                LegContext {
                    from_confidential: from,
                    to_confidential: to,
                },
            )
        },
    )
}

fn crypto_lines(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| l.to_ascii_lowercase().starts_with("a=crypto"))
        .map(str::to_string)
        .collect()
}

fn mlines(body: &str) -> Vec<&str> {
    body.lines()
        .filter(|l| l.trim().starts_with("m="))
        .collect()
}

proptest! {
    #[test]
    fn total_on_arbitrary_input(s in "\\PC*", (role, policy, legs) in context()) {
        let _ = apply_media_security(&s, role, &policy, &legs);
    }

    #[test]
    fn total_with_control_bytes(
        s in prop::collection::vec(prop_oneof![Just('\r'), Just('\n'), Just('\0'), Just('a'), Just('='), Just('m'), Just(' ')], 0..64),
        (role, policy, legs) in context(),
    ) {
        let s: String = s.into_iter().collect();
        let _ = apply_media_security(&s, role, &policy, &legs);
    }

    #[test]
    fn accepted_body_keeps_only_cnsa_sdes(body in sdp(), (role, policy, legs) in context()) {
        if let Ok(out) = apply_media_security(&body, role, &policy, &legs) {
            let lines = crypto_lines(&out.sdp);
            for l in &lines {
                prop_assert!(
                    l.to_ascii_uppercase().contains(" AEAD_AES_256_GCM "),
                    "non-CNSA line crossed: {l}"
                );
                prop_assert!(!l.to_ascii_uppercase().contains("UNENCRYPTED"), "{l}");
            }
            if !(legs.from_confidential && legs.to_confidential)
                || policy.mode == KeyingMode::Terminate
            {
                prop_assert!(lines.is_empty(), "SDES crossed: {:?}", lines);
            }
            // RFC 3264 §8: m-lines are never removed or changed.
            prop_assert_eq!(mlines(&out.sdp), mlines(&body));
        }
    }

    #[test]
    fn idempotent(body in sdp(), (role, policy, legs) in context()) {
        if let Ok(once) = apply_media_security(&body, role, &policy, &legs) {
            let once = once.sdp.into_owned();
            let twice = apply_media_security(&once, role, &policy, &legs)
                .expect("an accepted body is accepted again");
            prop_assert_eq!(twice.sdp.as_ref(), once.as_str());
        }
    }
}
