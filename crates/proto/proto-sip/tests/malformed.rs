//! QA malformed-input and boundary tests for the Phase 1 message layer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use proto_sip::{
    Framing, HeaderName, MAX_HEADER_LEN, MAX_HEADERS, MAX_LEADING_CRLF, SipMessage, split_list,
    split_list_bounded,
};

fn req(extra: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "OPTIONS sip:b@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP h.example.com;branch=z9hG4bK1\r\n\
         To: <sip:b@example.com>\r\n\
         From: <sip:a@example.com>;tag=1\r\n\
         Call-ID: c1\r\n\
         CSeq: 1 OPTIONS\r\n\
         Max-Forwards: 70\r\n{extra}\r\n"
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

fn parse(b: &[u8]) -> Result<SipMessage, proto_sip::SipError> {
    SipMessage::parse(b)
}

#[test]
fn baseline_parses() {
    let m = parse(&req("Content-Length: 0\r\n", b"")).unwrap();
    m.validate_semantics().unwrap();
}

#[test]
fn lone_cr_rejected() {
    assert!(parse(&req("X-A: a\rb\r\nContent-Length: 0\r\n", b"")).is_err());
    assert!(parse(b"OPTIONS sip:b@example.com SIP/2.0\rCall-ID: x\r\n\r\n").is_err());
}

#[test]
fn bare_lf_rejected() {
    assert!(parse(&req("X-A: a\nX-B: b\r\nContent-Length: 0\r\n", b"")).is_err());
}

#[test]
fn nul_and_ctl_rejected() {
    assert!(parse(&req("X-A: a\0b\r\nContent-Length: 0\r\n", b"")).is_err());
    assert!(parse(&req("X-A: a\x07b\r\nContent-Length: 0\r\n", b"")).is_err());
    assert!(parse(&req("X-A: a\x7fb\r\nContent-Length: 0\r\n", b"")).is_err());
    // HTAB allowed.
    assert!(parse(&req("X-A: a\tb\r\nContent-Length: 0\r\n", b"")).is_ok());
}

#[test]
fn non_token_header_names_rejected() {
    for n in ["X A", "X@A", "X(A)", "X<A>", "X\"A", "X/A", "\u{e9}t\u{e9}"] {
        let line = format!("{n}: v\r\nContent-Length: 0\r\n");
        assert!(parse(&req(&line, b"")).is_err(), "{n:?} accepted");
    }
    assert!(HeaderName::from_name("X A").is_err());
    assert!(HeaderName::from_name("").is_err());
}

#[test]
fn crlf_injection_value_rejected() {
    assert!(parse(&req("X-A: a\r\nBogus\r\nContent-Length: 0\r\n", b"")).is_err());
}

#[test]
fn compact_and_long_content_length_duplicate_rejected() {
    assert!(parse(&req("l: 0\r\nContent-Length: 0\r\n", b"")).is_err());
    assert!(parse(&req("Content-Length: 0\r\nContent-Length: 0\r\n", b"")).is_err());
    assert!(parse(&req("l: 3\r\nl: 3\r\n", b"abc")).is_err());
}

#[test]
fn content_length_bad_forms_rejected() {
    for cl in [
        "+3",
        "-3",
        "3a",
        "0x3",
        "",
        " ",
        "3 3",
        "99999999999",
        "18446744073709551616",
    ] {
        let line = format!("Content-Length: {cl}\r\n");
        assert!(parse(&req(&line, b"abc")).is_err(), "C-L {cl:?} accepted");
    }
    // 10 digits allowed syntactically but exceeds datagram -> reject.
    assert!(parse(&req("Content-Length: 4294967295\r\n", b"abc")).is_err());
}

#[test]
fn udp_excess_truncated_shortfall_rejected() {
    let m = parse(&req("Content-Length: 3\r\n", b"abcdef")).unwrap();
    assert_eq!(m.body().unwrap().as_ref(), b"abc");
    assert!(parse(&req("Content-Length: 10\r\n", b"abc")).is_err());
}

#[test]
fn udp_missing_cl_takes_rest() {
    let m = parse(&req("", b"xyz")).unwrap();
    assert_eq!(m.body().map(|b| b.to_vec()).unwrap_or_default(), b"xyz");
}

#[test]
fn stream_missing_cl_rejected_and_exact_required() {
    assert!(SipMessage::parse_with(&req("", b""), Framing::Stream).is_err());
    assert!(SipMessage::parse_with(&req("", b"xyz"), Framing::Stream).is_err());
    assert!(SipMessage::parse_with(&req("Content-Length: 3\r\n", b"xyz"), Framing::Stream).is_ok());
    assert!(
        SipMessage::parse_with(&req("Content-Length: 5\r\n", b"xyz"), Framing::Stream).is_err()
    );
    assert!(
        SipMessage::parse_with(&req("Content-Length: 1\r\n", b"xyz"), Framing::Stream).is_err()
    );
}

#[test]
fn header_len_boundary() {
    // Line "X-A: " + value; find the accepted max by checking both sides.
    let ok_val = "a".repeat(MAX_HEADER_LEN - 5);
    let bad_val = "a".repeat(MAX_HEADER_LEN + 1);
    assert!(
        parse(&req(
            &format!("X-A: {ok_val}\r\nContent-Length: 0\r\n"),
            b""
        ))
        .is_ok()
    );
    assert!(
        parse(&req(
            &format!("X-A: {bad_val}\r\nContent-Length: 0\r\n"),
            b""
        ))
        .is_err()
    );
}

#[test]
fn header_count_boundary() {
    // req() has 6 headers + Content-Length = 7.
    let fill = |n: usize| {
        (0..n).fold(String::new(), |mut acc, i| {
            use std::fmt::Write as _;
            let _ = write!(acc, "X-{i}: v\r\n");
            acc
        })
    };
    let ok = fill(MAX_HEADERS - 7) + "Content-Length: 0\r\n";
    let bad = fill(MAX_HEADERS - 6) + "Content-Length: 0\r\n";
    assert!(parse(&req(&ok, b"")).is_ok(), "at limit rejected");
    assert!(parse(&req(&bad, b"")).is_err(), "over limit accepted");
}

#[test]
fn leading_crlf_boundary() {
    let base = req("Content-Length: 0\r\n", b"");
    let mut ok = "\r\n".repeat(MAX_LEADING_CRLF).into_bytes();
    ok.extend_from_slice(&base);
    assert!(parse(&ok).is_ok());
    let mut bad = "\r\n".repeat(MAX_LEADING_CRLF + 1).into_bytes();
    bad.extend_from_slice(&base);
    assert!(parse(&bad).is_err());
}

#[test]
fn oversized_message_rejected() {
    let body = vec![b'a'; proto_sip::MAX_MESSAGE_SIZE];
    let cl = format!("Content-Length: {}\r\n", body.len());
    assert!(parse(&req(&cl, &body)).is_err());
}

#[test]
fn truncated_messages_rejected() {
    let full = req("Content-Length: 0\r\n", b"");
    for cut in [0, 5, 20, 40, full.len() - 3] {
        assert!(parse(&full[..cut]).is_err(), "cut {cut} accepted");
    }
}

#[test]
fn non_utf8_body_roundtrip_bytes_exact() {
    let body: Vec<u8> = (0u8..=255).collect();
    let raw = req(&format!("Content-Length: {}\r\n", body.len()), &body);
    let m = parse(&raw).unwrap();
    assert_eq!(m.body().unwrap().as_ref(), body.as_slice());
    let out = m.to_bytes();
    assert!(out.ends_with(&body));
    let m2 = parse(&out).unwrap();
    assert_eq!(m2.body().unwrap().as_ref(), body.as_slice());
    assert_eq!(m2.to_bytes(), out);
}

#[test]
fn non_utf8_header_value_rejected() {
    let mut raw = b"OPTIONS sip:b@example.com SIP/2.0\r\nX-A: ".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe]);
    raw.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
    assert!(parse(&raw).is_err());
}

#[test]
fn compact_forms_map_to_full_names() {
    let raw = b"OPTIONS sip:b@example.com SIP/2.0\r\n\
v: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
t: <sip:b@example.com>\r\n\
f: <sip:a@example.com>;tag=1\r\n\
i: cid\r\n\
CSeq: 1 OPTIONS\r\n\
m: <sip:a@h>\r\n\
k: path\r\n\
s: subj\r\n\
c: text/plain\r\n\
e: gzip\r\n\
x: 60\r\n\
l: 0\r\n\r\n";
    let m = parse(raw).unwrap();
    let h = m.headers();
    assert_eq!(h.call_id(), Some("cid"));
    for n in [
        HeaderName::Via,
        HeaderName::To,
        HeaderName::From,
        HeaderName::Contact,
        HeaderName::Supported,
        HeaderName::Subject,
        HeaderName::ContentType,
        HeaderName::ContentEncoding,
        HeaderName::SessionExpires,
        HeaderName::ContentLength,
    ] {
        assert!(h.contains(&n), "{n:?} missing");
    }
    assert_eq!(h.content_length(), Some(0));
}

#[test]
fn custom_header_case_insensitive() {
    let a = HeaderName::from_name("X-Foo").unwrap();
    let b = HeaderName::from_name("x-fOO").unwrap();
    assert_eq!(a, b);
    let hs = |n: &HeaderName| {
        let mut s = DefaultHasher::new();
        n.hash(&mut s);
        s.finish()
    };
    assert_eq!(hs(&a), hs(&b));
    let m = parse(&req("X-FOO: 1\r\nContent-Length: 0\r\n", b"")).unwrap();
    assert_eq!(m.headers().get_value(&a), Some("1"));
    assert_eq!(
        HeaderName::from_name("call-id").unwrap(),
        HeaderName::CallId
    );
}

#[test]
fn splitter_multibyte_and_quoted_commas() {
    let v = "\"D\u{e9}j\u{e0}, vu\" <sip:a@x>, <sip:b@y;p=\u{1f600}>, \"q\\\",x\" <sip:c@z>";
    let parts: Vec<&str> = split_list(v).map(Result::unwrap).collect();
    assert_eq!(parts.len(), 3, "{parts:?}");
    assert!(parts[0].contains("D\u{e9}j\u{e0}, vu"));
    assert!(parts[1].contains('\u{1f600}'));
    assert!(parts[2].ends_with("<sip:c@z>"));
    let parts: Vec<&str> = split_list("<sip:a@x;p=1,2>, <sip:b@y>")
        .map(Result::unwrap)
        .collect();
    assert_eq!(parts.len(), 2);
    assert!(split_list("\"unterminated, x").any(|r| r.is_err()));
    assert!(split_list("<sip:a@x, y").any(|r| r.is_err()));
    // multibyte immediately before/after comma: must not panic on char boundary.
    let parts: Vec<&str> = split_list("\u{e9},\u{1f600},\u{e9}")
        .map(Result::unwrap)
        .collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn splitter_bounded() {
    let v = ["a"; 4].join(",");
    assert_eq!(split_list_bounded(&v, 4).unwrap().len(), 4);
    assert!(split_list_bounded(&v, 3).is_err());
}

#[test]
fn cseq_bounds() {
    let mk = |c: &str| {
        let raw = format!(
            "OPTIONS sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
             To: <sip:b@x>\r\nFrom: <sip:a@x>;tag=1\r\nCall-ID: c\r\nCSeq: {c}\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        parse(raw.as_bytes()).and_then(|m| m.validate_semantics())
    };
    assert!(mk("0 OPTIONS").is_ok());
    assert!(mk("2147483647 OPTIONS").is_ok());
    assert!(mk("2147483648 OPTIONS").is_err());
    assert!(mk("99999999999999999999 OPTIONS").is_err());
    assert!(mk("-1 OPTIONS").is_err());
    assert!(mk("+1 OPTIONS").is_err());
    assert!(mk("1 INVITE").is_err(), "method mismatch accepted");
}

/// RFC 3261 §7.1: methods are case-sensitive, so `CSeq: 1 options` on an
/// OPTIONS request is a mismatch.
#[test]
fn cseq_method_case_sensitive() {
    let raw = "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
               To: <sip:b@x>\r\nFrom: <sip:a@x>;tag=1\r\nCall-ID: c\r\nCSeq: 1 options\r\n\
               Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
    assert!(
        parse(raw.as_bytes())
            .and_then(|m| m.validate_semantics())
            .is_err()
    );
}

#[test]
fn duplicate_single_valued_headers_rejected() {
    let m = parse(&req("Call-ID: c2\r\nContent-Length: 0\r\n", b"")).ok();
    assert!(m.is_none_or(|m| m.validate_semantics().is_err()));
}

#[test]
fn max_forwards_bounds() {
    let mk = |mf: &str| {
        let raw = format!(
            "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nTo: <sip:b@x>\r\n\
             From: <sip:a@x>;tag=1\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: {mf}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        parse(raw.as_bytes()).and_then(|m| m.validate_semantics())
    };
    assert!(mk("0").is_ok());
    assert!(mk("255").is_ok());
    assert!(mk("256").is_err());
}

#[test]
fn bad_start_lines_rejected() {
    for s in [
        "OPTIONS  sip:b@x SIP/2.0",
        "OPTIONS sip:b@x  SIP/2.0",
        "OPTIONS sip:b@x SIP/2.0 ",
        "OPTIONS sip:b@x",
        "SIP/2.0 20 OK",
        "SIP/2.0 2000 OK",
        "SIP/2.0 abc OK",
    ] {
        let raw = format!("{s}\r\nCall-ID: c\r\nContent-Length: 0\r\n\r\n");
        assert!(parse(raw.as_bytes()).is_err(), "{s:?} accepted");
    }
}
