//! SR-59 (D3): PROXY protocol v2 parser (haproxy.org proxy-protocol.txt §2.2).
//!
//! Red-first tests for the new `uc_transport::proxy_protocol` module: a pure,
//! bounded parser plus an exact-read `read_v2` that never consumes bytes past
//! the header. TLVs are skipped, not interpreted (POA&M-456).
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, SI-10, AU-3

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uc_transport::proxy_protocol::{
    Command, MAX_V2_ADDR_LEN, ProxyError, ProxyV2, V2_HEADER_LEN, V2_SIGNATURE, parse_v2, read_v2,
};

const SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Builds a v2 header: signature, ver/cmd, fam/proto, length, body.
fn header(ver_cmd: u8, fam: u8, body: &[u8]) -> Vec<u8> {
    let mut v = SIG.to_vec();
    v.push(ver_cmd);
    v.push(fam);
    v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Header with an arbitrary declared length (body may be shorter).
fn header_declared(ver_cmd: u8, fam: u8, declared: u16, body: &[u8]) -> Vec<u8> {
    let mut v = SIG.to_vec();
    v.push(ver_cmd);
    v.push(fam);
    v.extend_from_slice(&declared.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn tcp4_body(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("v4 only");
    };
    let mut b = Vec::new();
    b.extend_from_slice(&s.octets());
    b.extend_from_slice(&d.octets());
    b.extend_from_slice(&src.port().to_be_bytes());
    b.extend_from_slice(&dst.port().to_be_bytes());
    b
}

fn tcp6_body(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (IpAddr::V6(s), IpAddr::V6(d)) = (src.ip(), dst.ip()) else {
        panic!("v6 only");
    };
    let mut b = Vec::new();
    b.extend_from_slice(&s.octets());
    b.extend_from_slice(&d.octets());
    b.extend_from_slice(&src.port().to_be_bytes());
    b.extend_from_slice(&dst.port().to_be_bytes());
    b
}

fn v4(a: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::from(a), port))
}

fn v6(s: &str, port: u16) -> SocketAddr {
    SocketAddr::from((s.parse::<Ipv6Addr>().unwrap(), port))
}

const PROXY: u8 = 0x21;
const LOCAL: u8 = 0x20;
const TCP4: u8 = 0x11;
const TCP6: u8 = 0x21;
const UNSPEC: u8 = 0x00;

#[test]
fn constants_match_spec() {
    assert_eq!(V2_SIGNATURE, SIG);
    assert_eq!(V2_HEADER_LEN, 16);
    // 216-byte AF_UNIX pair + TLV room: the spec's 536-byte recommended cap.
    assert_eq!(MAX_V2_ADDR_LEN, 536);
}

#[test]
fn parse_v2_tcp4() {
    let src = v4([192, 0, 2, 33], 5000);
    let dst = v4([198, 51, 100, 1], 443);
    let buf = header(PROXY, TCP4, &tcp4_body(src, dst));
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 28);
    assert_eq!(
        h,
        ProxyV2 {
            command: Command::Proxy,
            source: Some(src),
            destination: Some(dst),
        }
    );
}

#[test]
fn parse_v2_tcp6() {
    let src = v6("2001:db8::1", 4711);
    let dst = v6("2001:db8:cafe::17", 7080);
    let buf = header(PROXY, TCP6, &tcp6_body(src, dst));
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 52);
    assert_eq!(h.command, Command::Proxy);
    assert_eq!(h.source, Some(src));
    assert_eq!(h.destination, Some(dst));
}

// The haproxy spec's literal example bytes for a TCP4 PROXY header
// (127.0.0.1:56324 -> 127.0.0.1:443), followed by the first HTTP bytes.
#[test]
fn parse_v2_known_answer_vector_with_trailing_payload() {
    let mut buf: Vec<u8> = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // sig
        0x21, 0x11, 0x00, 0x0C, // v2 PROXY, TCP4, len 12
        0x7F, 0x00, 0x00, 0x01, // src 127.0.0.1
        0x7F, 0x00, 0x00, 0x01, // dst 127.0.0.1
        0xDC, 0x04, // sport 56324
        0x01, 0xBB, // dport 443
    ];
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 28, "consumed must stop at the header end");
    assert_eq!(h.source, Some(v4([127, 0, 0, 1], 56324)));
    assert_eq!(h.destination, Some(v4([127, 0, 0, 1], 443)));
    assert_eq!(&buf[n..n + 4], b"GET ");
}

#[test]
fn parse_v2_skips_tlvs() {
    let src = v4([203, 0, 113, 9], 1234);
    let dst = v4([192, 0, 2, 1], 80);
    let mut body = tcp4_body(src, dst);
    // PP2_TYPE_NOOP (0x04) len 4, PP2_TYPE_UNIQUE_ID (0x05) len 3.
    body.extend_from_slice(&[0x04, 0x00, 0x04, 0, 0, 0, 0]);
    body.extend_from_slice(&[0x05, 0x00, 0x03, b'a', b'b', b'c']);
    let buf = header(PROXY, TCP4, &body);
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 16 + body.len());
    assert_eq!(h.source, Some(src));
}

#[test]
fn parse_v2_local_has_no_source() {
    let buf = header(LOCAL, UNSPEC, &[]);
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 16);
    assert_eq!(h.command, Command::Local);
    assert_eq!(h.source, None);
    assert_eq!(h.destination, None);
}

// Spec: for LOCAL the receiver must ignore any address block.
#[test]
fn parse_v2_local_ignores_address_block() {
    let body = tcp4_body(v4([192, 0, 2, 33], 5000), v4([192, 0, 2, 1], 80));
    let buf = header(LOCAL, TCP4, &body);
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 28);
    assert_eq!(h.command, Command::Local);
    assert_eq!(h.source, None);
}

// Spec: PROXY with AF_UNSPEC is valid; the real connection endpoints apply.
#[test]
fn parse_v2_proxy_unspec_has_no_source() {
    let buf = header(PROXY, UNSPEC, &[]);
    let (h, n) = parse_v2(&buf).unwrap().unwrap();
    assert_eq!(n, 16);
    assert_eq!(h.command, Command::Proxy);
    assert_eq!(h.source, None);
}

// RFC-006: valid family/protocol pairs this receiver does not implement
// (UDP over IPv4/IPv6, AF_UNIX stream/datagram) take the AF_UNSPEC path:
// parsed, no source, address block skipped (spec §2.2).
#[test]
fn parse_v2_unimplemented_families_take_unspec_path() {
    for fam in [0x12u8, 0x22, 0x31, 0x32] {
        for body in [&[][..], &[0u8; 12][..], &[7u8; 216][..]] {
            let buf = header(PROXY, fam, body);
            let (h, n) = parse_v2(&buf).unwrap().unwrap();
            assert_eq!(n, 16 + body.len(), "fam {fam:#x}");
            assert_eq!(h.command, Command::Proxy);
            assert_eq!(h.source, None, "fam {fam:#x}");
            assert_eq!(h.destination, None, "fam {fam:#x}");
        }
    }
}

// SEC-005: a PROXY source of port 0 or an unspecified, multicast or
// broadcast address cannot be a TCP client and is Malformed.
#[test]
fn parse_v2_unusable_source_is_malformed() {
    let dst = v4([198, 51, 100, 1], 443);
    for src in [
        v4([192, 0, 2, 33], 0),
        v4([0, 0, 0, 0], 5000),
        v4([224, 0, 0, 1], 5000),
        v4([239, 255, 255, 250], 5000),
        v4([255, 255, 255, 255], 5000),
    ] {
        let buf = header(PROXY, TCP4, &tcp4_body(src, dst));
        assert_eq!(parse_v2(&buf), Err(ProxyError::Malformed), "{src}");
    }
    let dst6 = v6("2001:db8::2", 443);
    for src in [
        v6("2001:db8::1", 0),
        v6("::", 5000),
        v6("ff02::1", 5000),
        v6("::ffff:0.0.0.0", 5000),
        v6("::ffff:255.255.255.255", 5000),
    ] {
        let buf = header(PROXY, TCP6, &tcp6_body(src, dst6));
        assert_eq!(parse_v2(&buf), Err(ProxyError::Malformed), "{src}");
    }
    // LOCAL ignores the block, so the same bytes are accepted there.
    let buf = header(LOCAL, TCP4, &tcp4_body(v4([0, 0, 0, 0], 0), dst));
    assert_eq!(parse_v2(&buf).unwrap().unwrap().0.command, Command::Local);
}

#[test]
fn parse_v2_rejects_bad_signature_version_family() {
    let good = header(
        PROXY,
        TCP4,
        &tcp4_body(v4([192, 0, 2, 1], 1), v4([192, 0, 2, 2], 2)),
    );
    // Each signature byte flipped.
    for i in 0..12 {
        let mut b = good.clone();
        b[i] ^= 0xFF;
        assert_eq!(parse_v2(&b), Err(ProxyError::BadSignature), "byte {i}");
    }
    // Version nibble other than 2.
    for ver_cmd in [0x11u8, 0x31, 0x01, 0xF1] {
        let mut b = good.clone();
        b[12] = ver_cmd;
        assert_eq!(
            parse_v2(&b),
            Err(ProxyError::Unsupported),
            "ver {ver_cmd:#x}"
        );
    }
    // Command other than LOCAL (0) / PROXY (1).
    for ver_cmd in [0x22u8, 0x2F] {
        let mut b = good.clone();
        b[12] = ver_cmd;
        assert_eq!(
            parse_v2(&b),
            Err(ProxyError::Unsupported),
            "cmd {ver_cmd:#x}"
        );
    }
    // Unknown address family / transport protocol under PROXY.
    for fam in [0x41u8, 0x51, 0xF1, 0x13, 0x1F] {
        let mut b = good.clone();
        b[13] = fam;
        assert_eq!(parse_v2(&b), Err(ProxyError::Unsupported), "fam {fam:#x}");
    }
}

#[test]
fn parse_v2_rejects_http_and_v1_text() {
    assert_eq!(
        parse_v2(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        Err(ProxyError::BadSignature)
    );
    assert_eq!(
        parse_v2(b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\r\n"),
        Err(ProxyError::BadSignature)
    );
    // A mismatch inside the first bytes is reported without waiting for 16.
    assert_eq!(parse_v2(b"G"), Err(ProxyError::BadSignature));
    assert_eq!(
        parse_v2(&[0x0D, 0x0A, 0x0D, 0x0B]),
        Err(ProxyError::BadSignature)
    );
}

#[test]
fn parse_v2_rejects_length_over_cap() {
    // Only the 16-byte preamble is present: the cap is enforced before
    // waiting for (or allocating) the declared body.
    for declared in [537u16, 1000, u16::MAX] {
        let b = header_declared(PROXY, TCP4, declared, &[]);
        assert_eq!(parse_v2(&b), Err(ProxyError::TooLong), "len {declared}");
    }
    // At the cap: legal, just needs more bytes.
    let b = header_declared(PROXY, TCP4, 536, &[]);
    assert_eq!(parse_v2(&b), Ok(None));
}

#[test]
fn parse_v2_rejects_address_block_shorter_than_family() {
    // TCP4 needs 12 bytes, TCP6 needs 36.
    let b = header(PROXY, TCP4, &[0u8; 8]);
    assert!(
        matches!(
            parse_v2(&b),
            Err(ProxyError::Truncated | ProxyError::Malformed)
        ),
        "{:?}",
        parse_v2(&b)
    );
    let b = header(PROXY, TCP6, &[0u8; 12]);
    assert!(matches!(
        parse_v2(&b),
        Err(ProxyError::Truncated | ProxyError::Malformed)
    ));
}

#[test]
fn parse_v2_rejects_malformed_tlv() {
    let mut body = tcp4_body(v4([192, 0, 2, 1], 1), v4([192, 0, 2, 2], 2));
    // TLV declares 9 value bytes but only 2 follow inside the block.
    body.extend_from_slice(&[0x04, 0x00, 0x09, 0, 0]);
    let b = header(PROXY, TCP4, &body);
    // Either reject, or skip (TLVs are not interpreted) — never panic and
    // never consume past the declared length.
    match parse_v2(&b) {
        Err(ProxyError::Malformed | ProxyError::Truncated) => {}
        Ok(Some((_, n))) => assert_eq!(n, b.len()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn parse_v2_needs_more() {
    let mut body = tcp6_body(v6("2001:db8::1", 4711), v6("2001:db8::2", 443));
    body.extend_from_slice(&[0x04, 0x00, 0x02, 0, 0]);
    let full = header(PROXY, TCP6, &body);
    for cut in 0..full.len() {
        assert_eq!(parse_v2(&full[..cut]), Ok(None), "prefix of {cut} bytes");
    }
    assert!(parse_v2(&full).unwrap().is_some());
}

fn arb_sockaddr() -> impl Strategy<Value = (SocketAddr, SocketAddr)> {
    prop_oneof![
        (
            any::<[u8; 4]>(),
            any::<u16>(),
            any::<[u8; 4]>(),
            any::<u16>()
        )
            .prop_map(|(a, p, b, q)| (v4(a, p), v4(b, q))),
        (
            any::<[u8; 16]>(),
            any::<u16>(),
            any::<[u8; 16]>(),
            any::<u16>()
        )
            .prop_map(|(a, p, b, q)| (
                SocketAddr::from((Ipv6Addr::from(a), p)),
                SocketAddr::from((Ipv6Addr::from(b), q))
            )),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn proxy_v2_roundtrip(
        (src, dst) in arb_sockaddr(),
        tlv in proptest::collection::vec(any::<u8>(), 0..=64),
        trailer in proptest::collection::vec(any::<u8>(), 0..=32),
    ) {
        let (fam, mut body) = if src.is_ipv4() {
            (TCP4, tcp4_body(src, dst))
        } else {
            (TCP6, tcp6_body(src, dst))
        };
        // One NOOP TLV carrying the random bytes.
        body.push(0x04);
        body.extend_from_slice(&u16::try_from(tlv.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&tlv);
        let mut buf = header(PROXY, fam, &body);
        let hdr_len = buf.len();
        buf.extend_from_slice(&trailer);
        // SEC-005: a source no TCP client can have is refused.
        let ip = src.ip().to_canonical();
        let unusable = src.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip == IpAddr::V4(Ipv4Addr::BROADCAST);
        if unusable {
            prop_assert_eq!(parse_v2(&buf), Err(ProxyError::Malformed));
            return Ok(());
        }
        let (h, n) = parse_v2(&buf).unwrap().unwrap();
        prop_assert_eq!(n, hdr_len);
        prop_assert_eq!(h.command, Command::Proxy);
        prop_assert_eq!(h.source, Some(src));
        prop_assert_eq!(h.destination, Some(dst));
    }

    #[test]
    fn random_bytes_never_panic(buf in proptest::collection::vec(any::<u8>(), 0..=700)) {
        if let Ok(Some((_, n))) = parse_v2(&buf) {
            prop_assert!(n <= buf.len());
            prop_assert!(n <= V2_HEADER_LEN + MAX_V2_ADDR_LEN);
        }
    }

    // Signature fixed, the rest random: exercises the deeper branches.
    #[test]
    fn random_after_signature_never_panics(
        rest in proptest::collection::vec(any::<u8>(), 0..=700)
    ) {
        let mut buf = SIG.to_vec();
        buf.extend_from_slice(&rest);
        match parse_v2(&buf) {
            Ok(Some((_, n))) => {
                prop_assert!(n >= V2_HEADER_LEN);
                prop_assert!(n <= buf.len());
                prop_assert!(n <= V2_HEADER_LEN + MAX_V2_ADDR_LEN);
            }
            Ok(None) => prop_assert!(buf.len() < V2_HEADER_LEN + MAX_V2_ADDR_LEN),
            Err(ProxyError::BadSignature) => prop_assert!(false, "signature was valid"),
            Err(_) => {}
        }
    }
}

/// Loopback socket pair: (client, server-side accepted stream).
async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (c, s) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
    (c.unwrap(), s.unwrap().0)
}

#[tokio::test]
async fn read_v2_leaves_payload_unread() {
    let (mut client, mut server) = pair().await;
    let src = v4([192, 0, 2, 33], 5000);
    let mut wire = header(PROXY, TCP4, &tcp4_body(src, v4([127, 0, 0, 1], 7080)));
    wire.extend_from_slice(b"GET / HTTP/1.1\r\n");
    client.write_all(&wire).await.unwrap();
    let h = tokio::time::timeout(Duration::from_secs(5), read_v2(&mut server))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h.source, Some(src));
    let mut next = [0u8; 4];
    server.read_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"GET ");
}

#[tokio::test]
async fn read_v2_handles_split_writes() {
    let (mut client, mut server) = pair().await;
    let src = v6("2001:db8::1", 4711);
    let wire = header(PROXY, TCP6, &tcp6_body(src, v6("2001:db8::2", 443)));
    let reader = tokio::spawn(async move {
        let h = read_v2(&mut server).await;
        (h, server)
    });
    for chunk in [&wire[..5], &wire[5..16], &wire[16..30], &wire[30..]] {
        client.write_all(chunk).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    client.write_all(b"GET").await.unwrap();
    let (h, mut server) = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h.unwrap().source, Some(src));
    let mut next = [0u8; 3];
    server.read_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"GET");
}

#[tokio::test]
async fn read_v2_rejects_over_cap_without_waiting_for_body() {
    let (mut client, mut server) = pair().await;
    client
        .write_all(&header_declared(PROXY, TCP4, 600, &[]))
        .await
        .unwrap();
    // The client keeps the socket open and sends nothing more: the error
    // must come from the length check, not from EOF or a deadline.
    let r = tokio::time::timeout(Duration::from_secs(2), read_v2(&mut server))
        .await
        .expect("read_v2 must fail fast on a declared length over the cap");
    assert!(r.is_err());
    drop(client);
}

#[tokio::test]
async fn read_v2_rejects_http_request() {
    let (mut client, mut server) = pair().await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(2), read_v2(&mut server))
        .await
        .unwrap();
    assert!(r.is_err());
}

#[tokio::test]
async fn read_v2_eof_mid_header_is_error() {
    let (mut client, mut server) = pair().await;
    let wire = header(
        PROXY,
        TCP4,
        &tcp4_body(v4([192, 0, 2, 1], 1), v4([192, 0, 2, 2], 2)),
    );
    client.write_all(&wire[..20]).await.unwrap();
    drop(client);
    let r = tokio::time::timeout(Duration::from_secs(2), read_v2(&mut server))
        .await
        .unwrap();
    assert!(r.is_err());
}

#[tokio::test]
async fn read_v2_local_command() {
    let (mut client, mut server) = pair().await;
    client.write_all(&header(LOCAL, UNSPEC, &[])).await.unwrap();
    let h = tokio::time::timeout(Duration::from_secs(2), read_v2(&mut server))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h.command, Command::Local);
    assert_eq!(h.source, None);
}
