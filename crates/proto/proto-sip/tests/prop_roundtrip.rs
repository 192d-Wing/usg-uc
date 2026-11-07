//! Property tests for the SIP message layer (stable-toolchain stand-in for
//! fuzzing). Case count: `PROPTEST_CASES` (default 256).
//!
//! NIST 800-53 Rev5: SA-11 (Developer Testing and Evaluation).

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use proto_sip::{Framing, SipMessage, split_list_bounded};
use std::fmt::Write as _;

fn header_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("X-Foo".to_string()),
        Just("subject".to_string()),
        Just("s".to_string()),
        Just("SUPPORTED".to_string()),
        Just("k".to_string()),
        Just("User-Agent".to_string()),
        Just("x".to_string()),
        "[A-Za-z][A-Za-z0-9!%*_+`'~.-]{0,15}".prop_filter("not single-valued", |n| {
            let l = n.to_ascii_lowercase();
            ![
                "i",
                "t",
                "f",
                "l",
                "to",
                "from",
                "cseq",
                "call-id",
                "max-forwards",
                "content-length",
            ]
            .contains(&l.as_str())
        }),
    ]
}

fn header_value() -> impl Strategy<Value = String> {
    // No CTLs; may contain UTF-8; no leading/trailing WSP (they are trimmed).
    "[!-~\u{00e9}\u{4e2d}]([ -~\u{00e9}\t]{0,40}[!-~])?"
}

fn message() -> impl Strategy<Value = (bool, Vec<(String, String)>, Vec<u8>)> {
    (
        any::<bool>(),
        prop::collection::vec((header_name(), header_value()), 0..20),
        prop::collection::vec(any::<u8>(), 0..200),
    )
}

fn build(is_req: bool, hdrs: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut m = if is_req {
        "MESSAGE sip:a@example.com SIP/2.0\r\nCSeq: 7 MESSAGE\r\n".to_string()
    } else {
        "SIP/2.0 200 OK\r\nCSeq: 7 MESSAGE\r\n".to_string()
    };
    for (n, v) in hdrs {
        m.push_str(n);
        m.push_str(": ");
        m.push_str(v);
        m.push_str("\r\n");
    }
    let _ = write!(m, "Content-Length: {}\r\n\r\n", body.len());
    let mut out = m.into_bytes();
    out.extend_from_slice(body);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256)
    ))]

    /// (a) parse(serialize(m)) == m structurally, and serialization is
    /// idempotent.
    #[test]
    fn roundtrip((is_req, hdrs, body) in message()) {
        let wire = build(is_req, &hdrs, &body);
        for framing in [Framing::Datagram, Framing::Stream] {
            let m = SipMessage::parse_with(&wire, framing).unwrap();
            prop_assert_eq!(m.headers().len(), hdrs.len() + 2);
            for (h, (n, v)) in m.headers().iter().skip(1).zip(&hdrs) {
                let parsed: proto_sip::HeaderName = n.parse().unwrap();
                prop_assert_eq!(&h.name, &parsed);
                prop_assert_eq!(&h.value, v);
            }
            let got_body = m.body().map(|b| b.to_vec()).unwrap_or_default();
            prop_assert_eq!(&got_body, &body);

            let out = m.to_bytes();
            let m2 = SipMessage::parse_with(&out, framing).unwrap();
            prop_assert_eq!(m2.headers().len(), m.headers().len());
            for (a, b) in m.headers().iter().zip(m2.headers().iter()) {
                prop_assert_eq!(a, b);
            }
            prop_assert_eq!(m2.body(), m.body());
            prop_assert_eq!(m2.to_bytes(), out);
        }
    }

    /// (b) splitting a ", "-joined list of quoted/angled elements that
    /// contain commas returns the original elements.
    #[test]
    fn split_list_inverse(elems in prop::collection::vec(
        ("[a-zA-Z ,\u{00dc}]{0,10}", "[a-z0-9.,;=]{1,12}"), 1..10)
    ) {
        let rendered: Vec<String> = elems
            .iter()
            .map(|(dn, uri)| format!("\"{}\" <sip:{uri}>", dn.replace('"', "")))
            .collect();
        let joined = rendered.join(", ");
        let parts = split_list_bounded(&joined, 64).unwrap();
        prop_assert_eq!(parts, rendered.iter().map(String::as_str).collect::<Vec<_>>());
    }

    /// (c) arbitrary bytes never panic.
    #[test]
    fn arbitrary_bytes_no_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = SipMessage::parse_with(&data, Framing::Datagram);
        let _ = SipMessage::parse_with(&data, Framing::Stream);
    }

    /// (c') arbitrary header lines after a valid start line never panic.
    #[test]
    fn arbitrary_header_section_no_panic(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut v = b"INVITE sip:a@example.com SIP/2.0\r\n".to_vec();
        v.extend_from_slice(&tail);
        let _ = SipMessage::parse(&v);
        if let Ok(s) = std::str::from_utf8(&tail) {
            let _ = split_list_bounded(s, 64);
            let _ = s.parse::<proto_sip::ViaHeader>();
            let _ = s.parse::<proto_sip::NameAddr>();
            let _ = s.parse::<proto_sip::CSeqHeader>();
            let _ = s.parse::<proto_sip::SipUri>();
        }
    }
}
