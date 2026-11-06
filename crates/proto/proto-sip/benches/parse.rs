//! SIP message parse / serialize benchmarks (performance baseline for the
//! Phase 1 parser hardening; acceptance is a <= 5% median regression).

#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use proto_sip::SipMessage;
use std::fmt::Write;
use std::hint::black_box;

fn options_msg() -> Vec<u8> {
    b"OPTIONS sip:sbc.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKopt1\r\n\
Max-Forwards: 70\r\n\
To: <sip:sbc.example.com>\r\n\
From: <sip:probe@example.org>;tag=abc\r\n\
Call-ID: opt-1@192.0.2.10\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n"
        .to_vec()
}

fn invite_msg() -> Vec<u8> {
    let sdp = "v=0\r\no=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\ns=-\r\n\
c=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0 8 101\r\n\
a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\na=ptime:20\r\na=sendrecv\r\n";
    let mut m = String::new();
    m.push_str("INVITE sip:bob@example.com SIP/2.0\r\n");
    m.push_str("Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK74bf9;rport\r\n");
    m.push_str("Max-Forwards: 70\r\n");
    m.push_str("To: \"Bob\" <sip:bob@example.com>\r\n");
    m.push_str("From: \"Alice\" <sip:alice@example.org>;tag=9fxced76sl\r\n");
    m.push_str("Call-ID: 3848276298220188511@192.0.2.10\r\n");
    m.push_str("CSeq: 1 INVITE\r\n");
    m.push_str("Contact: <sip:alice@192.0.2.10:5060;transport=udp>\r\n");
    m.push_str("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, UPDATE\r\n");
    m.push_str("Supported: replaces, timer, 100rel\r\n");
    m.push_str("User-Agent: bench-ua/1.0\r\n");
    m.push_str("Content-Type: application/sdp\r\n");
    let _ = write!(m, "Content-Length: {}\r\n\r\n{sdp}", sdp.len());
    m.into_bytes()
}

fn register_msg() -> Vec<u8> {
    let mut m = String::new();
    m.push_str("REGISTER sip:registrar.example.com SIP/2.0\r\n");
    for i in 0..4 {
        let _ = write!(
            m,
            "Via: SIP/2.0/TCP proxy{i}.example.com;branch=z9hG4bKreg{i}\r\n"
        );
    }
    m.push_str("Max-Forwards: 66\r\n");
    m.push_str("To: <sip:alice@example.com>\r\n");
    m.push_str("From: <sip:alice@example.com>;tag=reg1\r\n");
    m.push_str("Call-ID: reg-1@192.0.2.10\r\n");
    m.push_str("CSeq: 42 REGISTER\r\n");
    m.push_str("Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n");
    for i in 0..8 {
        let _ = write!(m, "Path: <sip:edge{i}.example.com;lr>\r\n");
    }
    for i in 0..8 {
        let _ = write!(m, "Route: <sip:core{i}.example.com;lr>\r\n");
    }
    m.push_str("Expires: 3600\r\n");
    m.push_str("Supported: path, outbound\r\n");
    m.push_str("User-Agent: bench-ua/1.0\r\n");
    m.push_str("Content-Length: 0\r\n\r\n");
    m.into_bytes()
}

fn bench_parse(c: &mut Criterion) {
    for (name, msg) in [
        ("options", options_msg()),
        ("invite_sdp", invite_msg()),
        ("register_30h", register_msg()),
    ] {
        c.bench_function(&format!("parse/{name}"), |b| {
            b.iter(|| SipMessage::parse(black_box(&msg)));
        });
        if let Ok(parsed) = SipMessage::parse(&msg) {
            c.bench_function(&format!("to_bytes/{name}"), |b| {
                b.iter(|| black_box(&parsed).to_bytes());
            });
        }
    }
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
