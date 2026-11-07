//! POAM-150 regression tests: RFC 3261 §25.1 URI grammar, §19.1.4
//! comparison, 416 for non-SIP Request-URIs.
//!
//! NIST 800-53 Rev5: SI-10 (Information Input Validation), SA-11.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use proto_sip::{Framing, SipError, SipMessage, SipUri, Uri};

fn p(s: &str) -> SipUri {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

// POAM-150: userinfo delimiter is the last `@`.
#[test]
fn userinfo_with_semicolon_resolves_real_host() {
    let u = p("sip:victim;x=@evil.com");
    assert_eq!(u.host, "evil.com");
    assert_eq!(u.user.as_deref(), Some("victim;x="));
    assert_eq!(u.params.len(), 0);

    let u = p("sip:+1555;phone-context=example.com@gw.example.net");
    assert_eq!(u.host, "gw.example.net");
    assert_eq!(u.user.as_deref(), Some("+1555;phone-context=example.com"));

    let u = p("sip:a?b@evil.com");
    assert_eq!(u.host, "evil.com");
    assert_eq!(u.headers.len(), 0);
}

// POAM-150: a raw `@` inside userinfo is illegal.
#[test]
fn double_at_rejected() {
    assert!("sip:a@b@evil.com".parse::<SipUri>().is_err());
}

// POAM-150: strict ports, no silent drop.
#[test]
fn bad_ports_rejected() {
    for s in [
        "sip:a@h.example:0",
        "sip:a@h.example:65536",
        "sip:a@h.example:abc",
        "sip:a@h.example:",
        "sip:a@h.example:5060x",
        "sip:[::1",
        "sip:[::1]:",
        "sip:[not-v6]",
    ] {
        assert!(s.parse::<SipUri>().is_err(), "{s} accepted");
    }
    assert_eq!(p("sip:[::1]:5061").port, Some(5061));
    assert_eq!(p("sip:[fe80::1]").host, "fe80::1");
    assert_eq!(p("sip:a@h.example:65535").port, Some(65535));
}

// POAM-150: escapes and charset.
#[test]
fn bad_escapes_and_chars_rejected() {
    for s in [
        "sip:%G1@h.example",
        "sip:%4@h.example",
        "sip:a b@h.example",
        "sip:a\x01@h.example",
        "sip:a<@h.example",
        "sip:a\"@h.example",
        "sip:a@h_x.example",
        "sip:a@h.example;p=%zz",
        "sip:a@h.example?h=<x>",
        "sip:a@-bad.example",
        "sip:a@h.123",
    ] {
        assert!(s.parse::<SipUri>().is_err(), "{s:?} accepted");
    }
    let u = p("sip:%61lice@example.com");
    assert_eq!(u.user_decoded().as_deref(), Some("alice"));
    assert_eq!(u.to_string(), "sip:%61lice@example.com");
}

// POAM-150: duplicate special params are ambiguous.
#[test]
fn duplicate_special_params_rejected() {
    assert!(
        "sip:a@h.example;transport=udp;transport=tls"
            .parse::<SipUri>()
            .is_err()
    );
    assert!("sip:a@h.example;LR;lr".parse::<SipUri>().is_err());
    // Unknown params may repeat.
    assert!("sip:a@h.example;x=1;x=2".parse::<SipUri>().is_ok());
}

// RFC 3261 §19.1.4 equivalent pairs.
#[test]
fn rfc3261_19_1_4_equal() {
    for (a, b) in [
        (
            "sip:%61lice@atlanta.com;transport=TCP",
            "sip:alice@AtLanTa.CoM;Transport=tcp",
        ),
        ("sip:carol@chicago.com", "sip:carol@chicago.com;newparam=5"),
        ("sip:carol@chicago.com", "sip:carol@chicago.com;security=on"),
        (
            "sip:carol@chicago.com;newparam=5",
            "sip:carol@chicago.com;security=on",
        ),
        (
            "sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com",
            "sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com",
        ),
        (
            "sip:alice@atlanta.com?subject=project%20x&priority=urgent",
            "sip:alice@atlanta.com?priority=urgent&subject=project%20x",
        ),
        ("sip:a@[::1]", "sip:a@[0:0::1]"),
        // Escaped reserved chars compare by octet, hex case-insensitive.
        ("sip:a%3Bb@h.example", "sip:a%3bb@h.example"),
    ] {
        assert!(p(a).equivalent(&p(b)), "{a} != {b}");
        assert!(p(b).equivalent(&p(a)), "{b} != {a}");
    }
}

// RFC 3261 §19.1.4 non-equivalent pairs.
#[test]
fn rfc3261_19_1_4_unequal() {
    for (a, b) in [
        (
            "SIP:ALICE@AtLanTa.CoM;Transport=udp",
            "sip:alice@AtLanTa.CoM;Transport=UDP",
        ),
        ("sip:bob@biloxi.com", "sip:bob@biloxi.com:5060"),
        ("sip:bob@biloxi.com", "sip:bob@biloxi.com;transport=udp"),
        (
            "sip:bob@biloxi.com",
            "sip:bob@biloxi.com:6000;transport=tcp",
        ),
        (
            "sip:carol@chicago.com",
            "sip:carol@chicago.com?Subject=next%20meeting",
        ),
        ("sip:bob@phone21.boxesbybob.com", "sip:bob@192.0.2.4"),
        ("sip:x.example", "sip:x.example:5060"),
        ("sips:a@x.example", "sip:a@x.example"),
        // RFC-001: an escaped reserved char is not its literal form.
        ("sip:a;b@h", "sip:a%3Bb@h"),
    ] {
        assert!(!p(a).equivalent(&p(b)), "{a} == {b}");
        assert!(!p(b).equivalent(&p(a)), "{b} == {a}");
    }
}

// POAM-150: generic Uri.
#[test]
fn generic_uri_schemes() {
    match "tel:+15551234567;phone-context=+1".parse::<Uri>().unwrap() {
        Uri::Tel(t) => {
            assert!(t.global);
            assert_eq!(t.number, "+15551234567");
        }
        other => panic!("{other:?}"),
    }
    let u: Uri = "urn:service:sos".parse().unwrap();
    assert!(matches!(u, Uri::Absolute(_)));
    assert_eq!(u.scheme(), "urn");
    assert_eq!(u.to_string(), "urn:service:sos");
    assert!("tel:".parse::<Uri>().is_err());
    assert!("urn:a b".parse::<Uri>().is_err());
    assert!(matches!(
        "tel:+1555".parse::<SipUri>(),
        Err(SipError::UnsupportedUriScheme { .. })
    ));
}

// POAM-150: non-SIP Request-URI -> 416.
#[test]
fn tel_request_uri_is_416() {
    let msg = b"INVITE tel:+15551234567 SIP/2.0\r\nVia: SIP/2.0/UDP h.example;branch=z9hG4bK1\r\nContent-Length: 0\r\n\r\n";
    let e = SipMessage::parse_with(msg, Framing::Datagram).unwrap_err();
    assert_eq!(e.status_code(), 416);
    let msg = b"INVITE sip:a@h.example:99999 SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    let e = SipMessage::parse_with(msg, Framing::Datagram).unwrap_err();
    assert_eq!(e.status_code(), 400);
}

fn user_part() -> impl Strategy<Value = String> {
    "([A-Za-z0-9_.!~*'()&=+$,;?/-]|%[0-9A-F]{2}){1,12}"
}

fn host_part() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]([a-z0-9-]{0,6}[a-z0-9])?(\\.[a-z]([a-z0-9-]{0,6}[a-z0-9])?){0,3}",
        (0u8..=255, 0u8..=255, 0u8..=255, 1u8..=255)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
        Just("[2001:db8::1]".to_string()),
    ]
}

proptest! {
    // Round-trip: display is byte-identical to the input for valid URIs.
    #[test]
    fn uri_roundtrip(
        user in proptest::option::of(user_part()),
        host in host_part(),
        port in proptest::option::of(1u16..),
        params in prop::collection::vec("[a-z]{1,5}(=[A-Za-z0-9:/\\[\\]&+$-]{1,6})?", 0..4),
    ) {
        let mut s = "sip:".to_string();
        if let Some(u) = &user {
            s.push_str(u);
            s.push('@');
        }
        s.push_str(&host);
        if let Some(p) = port {
            s.push(':');
            s.push_str(&p.to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for p in &params {
            let n = p.split('=').next().unwrap_or_default();
            if ["transport", "user", "ttl", "method", "maddr", "lr"].contains(&n)
                && !seen.insert(n.to_string())
            {
                continue;
            }
            s.push(';');
            s.push_str(p);
        }
        let u: SipUri = s.parse().unwrap_or_else(|e| panic!("{s}: {e}"));
        prop_assert_eq!(u.to_string(), s.clone());
        let again: SipUri = u.to_string().parse().unwrap();
        prop_assert_eq!(again, u);
    }

    // Arbitrary input never panics.
    #[test]
    fn uri_no_panic(s in "\\PC{0,64}") {
        let _ = s.parse::<SipUri>();
        let _ = s.parse::<Uri>();
    }
}
