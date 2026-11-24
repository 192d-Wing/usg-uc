//! SR-59 (D3): the WebSocket client address behind a trusted reverse proxy.
//!
//! Red-first tests for `ClientAddressMode`, the `X-Forwarded-For` /
//! `Forwarded` (RFC 7239) extractors, and the listener wiring: a forwarding
//! header or PROXY v2 preamble is believed only from a trusted peer, only
//! the rightmost untrusted hop is used, and a trusted peer that omits it is
//! refused (never a fallback to the proxy's own address).
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, AU-3; RFC 7239 §4, §5.2, §8.1

#![cfg(feature = "websocket")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use futures_util::SinkExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, StatusCode};
use uc_transport::error::TransportResult;
use uc_transport::websocket::{
    ClientAddressMode, ForwardedClient, ForwardedError, TrustedProxyFn, WebSocketListener,
    WebSocketListenerOptions, WebSocketTransport, client_from_forwarded,
    client_from_x_forwarded_for,
};
use uc_transport::{StreamTransport, Transport};
use uc_types::address::SbcSocketAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const fn none_trusted(_: IpAddr) -> bool {
    false
}

fn fc(s: &str, port: Option<u16>) -> ForwardedClient {
    ForwardedClient { ip: ip(s), port }
}

// ---------------------------------------------------------------------------
// Pure extraction: X-Forwarded-For
// ---------------------------------------------------------------------------

#[test]
fn client_address_mode_default_is_peer() {
    assert_eq!(ClientAddressMode::default(), ClientAddressMode::Peer);
}

#[test]
fn xff_rightmost_hop_is_used() {
    let got = client_from_x_forwarded_for(&[b"203.0.113.9, 198.51.100.7"], none_trusted);
    assert_eq!(got, Ok(fc("198.51.100.7", None)));
}

#[test]
fn xff_skips_trusted_proxy_chain() {
    // Client -> edge proxy 10.0.0.5 -> inner proxy 10.0.0.6 -> SBC.
    let trusted = |a: IpAddr| matches!(a, IpAddr::V4(v) if v.octets()[0] == 10);
    let got = client_from_x_forwarded_for(&[b"6.6.6.6, 198.51.100.7, 10.0.0.5"], trusted);
    assert_eq!(got, Ok(fc("198.51.100.7", None)));
}

#[test]
fn xff_all_trusted_uses_leftmost() {
    let trusted = |a: IpAddr| matches!(a, IpAddr::V4(v) if v.octets()[0] == 10);
    let got = client_from_x_forwarded_for(&[b"10.0.0.9, 10.0.0.5"], trusted);
    assert_eq!(got, Ok(fc("10.0.0.9", None)));
}

#[test]
fn xff_multiple_header_lines_are_one_list() {
    // RFC 9110 §5.3: field lines combine in order; the last line is rightmost.
    let got =
        client_from_x_forwarded_for(&[&b"203.0.113.9"[..], &b"198.51.100.7"[..]], none_trusted);
    assert_eq!(got, Ok(fc("198.51.100.7", None)));
}

#[test]
fn xff_client_spoofed_prefix_is_ignored() {
    // Attacker-controlled garbage to the left of the proxy-appended hop must
    // neither win nor fail the request.
    let got = client_from_x_forwarded_for(
        &[b"not-an-ip, 127.0.0.1, x, ;;, 198.51.100.7"],
        none_trusted,
    );
    assert_eq!(got, Ok(fc("198.51.100.7", None)));
}

#[test]
fn xff_strips_ports_and_brackets() {
    for (v, want) in [
        (&b"198.51.100.7:4711"[..], "198.51.100.7"),
        (b"2001:db8::1", "2001:db8::1"),
        (b"[2001:db8::1]", "2001:db8::1"),
        (b"[2001:db8::1]:4711", "2001:db8::1"),
        (b"  198.51.100.7  ", "198.51.100.7"),
    ] {
        assert_eq!(
            client_from_x_forwarded_for(&[v], none_trusted),
            Ok(fc(want, None)),
            "{}",
            String::from_utf8_lossy(v)
        );
    }
}

#[test]
fn xff_unmaps_v4_mapped_v6() {
    let got = client_from_x_forwarded_for(&[b"::ffff:192.0.2.1"], none_trusted);
    assert_eq!(got, Ok(fc("192.0.2.1", None)));
}

#[test]
fn xff_missing_and_malformed() {
    assert_eq!(
        client_from_x_forwarded_for(&[], none_trusted),
        Err(ForwardedError::Missing)
    );
    assert_eq!(
        client_from_x_forwarded_for(&[&b""[..], &b"   "[..]], none_trusted),
        Err(ForwardedError::Missing)
    );
    for bad in [
        &b"198.51.100.7, garbage"[..],
        b"198.51.100.7,",
        b"999.1.1.1",
        b"198.51.100",
        b"[2001:db8::1",
        b"2001:db8::1]:80",
        b"[198.51.100.7]:80:90",
        b"198.51.100.7:99999",
        b"unknown",
        b"198.51.100.7\r\nX-Evil: 1",
        b"\xff\xfe",
    ] {
        assert_eq!(
            client_from_x_forwarded_for(&[bad], none_trusted),
            Err(ForwardedError::Malformed),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn xff_long_chain_is_bounded_and_does_not_panic() {
    let mut v = Vec::new();
    for i in 0..10_000u32 {
        if i > 0 {
            v.extend_from_slice(b", ");
        }
        v.extend_from_slice(
            format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255).as_bytes(),
        );
    }
    // All trusted: must return quickly (leftmost) or refuse; never panic.
    let trusted = |a: IpAddr| matches!(a, IpAddr::V4(v) if v.octets()[0] == 10);
    let _ = client_from_x_forwarded_for(&[v.as_slice()], trusted);
}

// ---------------------------------------------------------------------------
// Pure extraction: Forwarded (RFC 7239)
// ---------------------------------------------------------------------------

#[test]
fn forwarded_for_parses_quoted_v6_with_port() {
    let got = client_from_forwarded(&[br#"for="[2001:db8::1]:4711""#], none_trusted);
    assert_eq!(got, Ok(fc("2001:db8::1", Some(4711))));
}

#[test]
fn forwarded_rfc7239_examples() {
    // RFC 7239 §4 / §7.1 examples.
    assert_eq!(
        client_from_forwarded(&[br#"for="_gazonk""#], none_trusted),
        Err(ForwardedError::Obfuscated)
    );
    assert_eq!(
        client_from_forwarded(&[br#"For="[2001:db8:cafe::17]:4711""#], none_trusted),
        Ok(fc("2001:db8:cafe::17", Some(4711)))
    );
    assert_eq!(
        client_from_forwarded(
            &[b"for=192.0.2.60;proto=http;by=203.0.113.43"],
            none_trusted
        ),
        Ok(fc("192.0.2.60", None))
    );
    assert_eq!(
        client_from_forwarded(&[b"for=192.0.2.43, for=198.51.100.17"], none_trusted),
        Ok(fc("198.51.100.17", None))
    );
    assert_eq!(
        client_from_forwarded(&[br#"for="192.0.2.43:47011""#], none_trusted),
        Ok(fc("192.0.2.43", Some(47011)))
    );
}

#[test]
fn forwarded_rightmost_untrusted_hop() {
    let trusted = |a: IpAddr| matches!(a, IpAddr::V4(v) if v.octets()[0] == 10);
    let got = client_from_forwarded(
        &[b"for=6.6.6.6, for=198.51.100.17;proto=https, for=10.0.0.5"],
        trusted,
    );
    assert_eq!(got, Ok(fc("198.51.100.17", None)));
}

#[test]
fn forwarded_obfuscated_or_unknown_hop_is_refused() {
    for v in [
        &b"for=unknown"[..],
        b"for=_hidden",
        br#"for="_SEVKISEK""#,
        b"for=192.0.2.43, for=unknown",
    ] {
        assert_eq!(
            client_from_forwarded(&[v], none_trusted),
            Err(ForwardedError::Obfuscated),
            "{}",
            String::from_utf8_lossy(v)
        );
    }
}

#[test]
fn forwarded_obfuscated_port_keeps_ip() {
    let got = client_from_forwarded(&[br#"for="[2001:db8::1]:_abc""#], none_trusted);
    assert_eq!(got, Ok(fc("2001:db8::1", None)));
}

#[test]
fn forwarded_quoted_comma_and_semicolon_do_not_split() {
    let got = client_from_forwarded(
        &[br#"for=192.0.2.43, for=198.51.100.17;by="a,b;c""#],
        none_trusted,
    );
    assert_eq!(got, Ok(fc("198.51.100.17", None)));
}

#[test]
fn forwarded_missing_and_malformed() {
    assert_eq!(
        client_from_forwarded(&[], none_trusted),
        Err(ForwardedError::Missing)
    );
    for bad in [
        // Unquoted IPv6 (':' is not a tchar, RFC 7239 §6).
        &b"for=2001:db8::1"[..],
        // Unterminated quoted-string.
        br#"for="[2001:db8::1]:4711"#,
        // Quoted IPv6 without brackets.
        br#"for="2001:db8::1""#,
        // Duplicate parameter in one element (§4 MUST NOT).
        b"for=192.0.2.1;for=192.0.2.2",
        // Rightmost element without for=.
        b"for=192.0.2.1, proto=https",
        b"for=",
        b"for=999.0.0.1",
        br#"for="[2001:db8::1]:99999""#,
        b"for=192.0.2.1\r\nX-Evil: 1",
        b"=192.0.2.1",
    ] {
        assert!(
            matches!(
                client_from_forwarded(&[bad], none_trusted),
                Err(ForwardedError::Malformed | ForwardedError::Missing)
            ),
            "{} -> {:?}",
            String::from_utf8_lossy(bad),
            client_from_forwarded(&[bad], none_trusted)
        );
    }
}

#[test]
fn forwarded_spoofed_left_elements_never_win() {
    // A client-supplied Forwarded line followed by the proxy's own line.
    // A strict parser may refuse the whole header (the client only hurts
    // itself); it must never return the attacker's value.
    let attacker = fc("6.6.6.6", None);
    for lines in [
        &[&br#"for="6.6.6.6"#[..], &b"for=198.51.100.17"[..]][..],
        &[&b"for=6.6.6.6;;;, for=198.51.100.17"[..]][..],
        &[&b"for=6.6.6.6, for=198.51.100.17"[..]][..],
    ] {
        let got = client_from_forwarded(lines, none_trusted);
        assert!(
            got == Ok(fc("198.51.100.17", None)) || got.is_err(),
            "{got:?}"
        );
        assert_ne!(got, Ok(attacker));
    }
}

// ---------------------------------------------------------------------------
// Listener wiring
// ---------------------------------------------------------------------------

fn loopback_trusted() -> TrustedProxyFn {
    Arc::new(|a: IpAddr| a.is_loopback())
}

fn nobody_trusted() -> TrustedProxyFn {
    Arc::new(|_: IpAddr| false)
}

async fn listener(mode: Option<(ClientAddressMode, TrustedProxyFn)>) -> Arc<WebSocketListener> {
    let addr = SbcSocketAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
    let mut l = WebSocketListener::bind(&addr, false)
        .await
        .unwrap()
        .with_options(WebSocketListenerOptions {
            require_sip_subprotocol: true,
        });
    if let Some((m, f)) = mode {
        l = l.with_client_address(m, f);
    }
    Arc::new(l)
}

fn serve_one(
    l: &Arc<WebSocketListener>,
) -> tokio::task::JoinHandle<TransportResult<(SbcSocketAddr, WebSocketTransport)>> {
    let l = Arc::clone(l);
    tokio::spawn(async move {
        let (tcp, peer) = l.accept_tcp().await?;
        let ws = l.complete_handshake(tcp, peer).await?;
        Ok((peer, ws))
    })
}

fn request(addr: SocketAddr, headers: &[(&str, &str)]) -> Request {
    let mut req = format!("ws://{addr}/").into_client_request().unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static("sip"));
    for (k, v) in headers {
        req.headers_mut().append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    req
}

/// Connects with the given headers on a fresh TCP stream (optionally
/// preceded by raw `preface` bytes); returns the client's local address and
/// the HTTP status of the upgrade (101 on success).
async fn upgrade(
    addr: SocketAddr,
    preface: &[u8],
    headers: &[(&str, &str)],
) -> (
    SocketAddr,
    Option<StatusCode>,
    Option<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>,
) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let local = tcp.local_addr().unwrap();
    if !preface.is_empty() {
        tcp.write_all(preface).await.unwrap();
    }
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async(request(addr, headers), tcp),
    )
    .await
    .unwrap()
    {
        Ok((ws, resp)) => (local, Some(resp.status()), Some(ws)),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            (local, Some(resp.status()), None)
        }
        Err(_) => (local, None, None),
    }
}

fn local(l: &WebSocketListener) -> SocketAddr {
    l.bound_addr().unwrap()
}

#[tokio::test]
async fn default_listener_trusts_nobody() {
    let l = listener(None).await;
    assert!(!l.is_trusted_proxy(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server = serve_one(&l);
    let (me, status, _ws) = upgrade(local(&l), &[], &[("x-forwarded-for", "192.0.2.1")]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(me));
}

#[tokio::test]
async fn xff_rightmost_used_only_when_trusted() {
    let l = listener(Some((ClientAddressMode::XForwardedFor, loopback_trusted()))).await;
    assert!(l.is_trusted_proxy(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!l.is_trusted_proxy(ip("192.0.2.1")));
    let server = serve_one(&l);
    let (me, status, ws_client) = upgrade(
        local(&l),
        &[],
        &[("x-forwarded-for", "203.0.113.9, 198.51.100.7")],
    )
    .await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    // Client IP from the header; the proxy-side TCP source port keeps the
    // flow key unique (no port in XFF).
    assert_eq!(
        *ws.peer_addr(),
        SbcSocketAddr::from(SocketAddr::new(ip("198.51.100.7"), me.port()))
    );

    // The received message is attributed to the client too.
    let mut ws_client = ws_client.unwrap();
    ws_client
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "OPTIONS".into(),
        ))
        .await
        .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg.source.ip(), ip("198.51.100.7"));
}

#[tokio::test]
async fn xff_from_untrusted_peer_is_ignored() {
    let l = listener(Some((ClientAddressMode::XForwardedFor, nobody_trusted()))).await;
    let server = serve_one(&l);
    let (me, status, _ws) = upgrade(local(&l), &[], &[("x-forwarded-for", "198.51.100.7")]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(me));
}

#[tokio::test]
async fn untrusted_peer_without_header_is_admitted_as_socket_address() {
    let l = listener(Some((ClientAddressMode::Forwarded, nobody_trusted()))).await;
    let server = serve_one(&l);
    let (me, status, _ws) = upgrade(local(&l), &[], &[]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(me));
}

#[tokio::test]
async fn trusted_without_header_fails_upgrade() {
    let l = listener(Some((ClientAddressMode::XForwardedFor, loopback_trusted()))).await;
    let server = serve_one(&l);
    let (_me, status, _ws) = upgrade(local(&l), &[], &[]).await;
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn trusted_with_malformed_header_fails_upgrade() {
    let l = listener(Some((ClientAddressMode::XForwardedFor, loopback_trusted()))).await;
    let server = serve_one(&l);
    let (_me, status, _ws) = upgrade(
        local(&l),
        &[],
        &[("x-forwarded-for", "198.51.100.7, bogus")],
    )
    .await;
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn trusted_forwarded_mode_ignores_xff() {
    // Mode selects the header: XFF alone does not satisfy `forwarded`.
    let l = listener(Some((ClientAddressMode::Forwarded, loopback_trusted()))).await;
    let server = serve_one(&l);
    let (_me, status, _ws) = upgrade(local(&l), &[], &[("x-forwarded-for", "198.51.100.7")]).await;
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn forwarded_mode_uses_client_port() {
    let l = listener(Some((ClientAddressMode::Forwarded, loopback_trusted()))).await;
    let server = serve_one(&l);
    let (_me, status, _ws) = upgrade(
        local(&l),
        &[],
        &[("forwarded", r#"for="[2001:db8::1]:4711";proto=https"#)],
    )
    .await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(
        *ws.peer_addr(),
        SbcSocketAddr::from("[2001:db8::1]:4711".parse::<SocketAddr>().unwrap())
    );
}

fn proxy_v2_tcp4(src: SocketAddr, dst: SocketAddr, local_cmd: bool) -> Vec<u8> {
    let mut v = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    v.push(if local_cmd { 0x20 } else { 0x21 });
    v.push(0x11);
    v.extend_from_slice(&12u16.to_be_bytes());
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("v4");
    };
    v.extend_from_slice(&s.octets());
    v.extend_from_slice(&d.octets());
    v.extend_from_slice(&src.port().to_be_bytes());
    v.extend_from_slice(&dst.port().to_be_bytes());
    v
}

#[tokio::test]
async fn proxy_v2_trusted_sets_client_address() {
    let l = listener(Some((ClientAddressMode::ProxyV2, loopback_trusted()))).await;
    let server = serve_one(&l);
    let src: SocketAddr = "192.0.2.33:5000".parse().unwrap();
    let (_me, status, _ws) = upgrade(local(&l), &proxy_v2_tcp4(src, local(&l), false), &[]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(src));
}

#[tokio::test]
async fn proxy_v2_local_keeps_proxy_address() {
    let l = listener(Some((ClientAddressMode::ProxyV2, loopback_trusted()))).await;
    let server = serve_one(&l);
    let src: SocketAddr = "192.0.2.33:5000".parse().unwrap();
    let (me, status, _ws) = upgrade(local(&l), &proxy_v2_tcp4(src, local(&l), true), &[]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(me));
}

#[tokio::test]
async fn proxy_v2_trusted_without_header_is_refused() {
    let l = listener(Some((ClientAddressMode::ProxyV2, loopback_trusted()))).await;
    let server = serve_one(&l);
    let (_me, status, _ws) = upgrade(local(&l), &[], &[]).await;
    assert_ne!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn proxy_v2_from_untrusted_peer_fails_as_bad_http() {
    let l = listener(Some((ClientAddressMode::ProxyV2, nobody_trusted()))).await;
    let server = serve_one(&l);
    let src: SocketAddr = "192.0.2.33:5000".parse().unwrap();
    let (_me, status, _ws) = upgrade(local(&l), &proxy_v2_tcp4(src, local(&l), false), &[]).await;
    assert_ne!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn proxy_v2_untrusted_plain_upgrade_still_works() {
    let l = listener(Some((ClientAddressMode::ProxyV2, nobody_trusted()))).await;
    let server = serve_one(&l);
    let (me, status, _ws) = upgrade(local(&l), &[], &[]).await;
    assert_eq!(status, Some(StatusCode::SWITCHING_PROTOCOLS));
    let (_peer, ws) = server.await.unwrap().unwrap();
    assert_eq!(*ws.peer_addr(), SbcSocketAddr::from(me));
}
