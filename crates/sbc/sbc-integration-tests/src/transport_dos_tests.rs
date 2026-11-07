//! Transport-level DoS scenarios (2026-11-06 audit, Transport section).
//!
//! The daemon is a binary crate, so end-to-end stream-loop behaviour (400 on
//! duplicate Content-Length, first-message deadline, per-listener pools) is
//! covered by `sbc-daemon` unit tests; these exercise the shared building
//! blocks as the daemon wires them.
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, SI-10

use sbc_config::load_from_str;
use std::fmt::Write as _;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uc_dos_protection::{RateLimiter, RateLimiterConfig};
use uc_transport::websocket::{WebSocketListener, WebSocketListenerOptions};
use uc_types::address::SbcSocketAddr;

#[test]
fn transport_dos_keys_load_from_toml() {
    let config = load_from_str(
        r#"
        [rate_limit]
        ipv6_prefix_len = 56
        max_blocked_sources = 100
        audit_interval_secs = 30

        [transport]
        udp_listen = ["0.0.0.0:5060"]
        max_connections_per_source = 16
        max_connections_total = 30000
        ws_require_sip_subprotocol = false
    "#,
    )
    .unwrap();
    assert_eq!(config.rate_limit.ipv6_prefix_len, 56);
    assert_eq!(config.rate_limit.max_blocked_sources, 100);
    assert_eq!(config.transport.max_connections_per_source, 16);
    assert!(!config.transport.ws_require_sip_subprotocol);

    assert!(
        load_from_str(
            "[transport]\nudp_listen = [\"0.0.0.0:5060\"]\nmax_connections_per_source = 0\n"
        )
        .is_err()
    );
}

/// A global flood from A rejects but never blocks; B is not blocked either.
#[test]
fn global_flood_from_a_does_not_block_b() {
    let mut per_ip = RateLimiter::new(RateLimiterConfig::new(100, 200));
    let mut global = RateLimiter::new(RateLimiterConfig::new(50, 50).with_per_ip(false));
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();
    // Daemon order: per-IP first, global second.
    for _ in 0..1_000 {
        if per_ip.check(a).is_allowed() {
            let _ = global.check(a);
        }
    }
    assert!(!per_ip.is_blocked(b));
    assert!(per_ip.check(b).is_allowed());
    assert_eq!(global.blocked_sources(), 0);
}

async fn ws_upgrade_status(require: bool, protocol: Option<&str>) -> String {
    let addr = SbcSocketAddr::from("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap());
    let listener = WebSocketListener::bind(&addr, false)
        .await
        .unwrap()
        .with_options(WebSocketListenerOptions {
            require_sip_subprotocol: require,
        });
    let std_addr = listener.bound_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, peer) = listener.accept_tcp().await.unwrap();
        listener.complete_handshake(tcp, peer).await.is_ok()
    });
    let mut client = tokio::net::TcpStream::connect(std_addr).await.unwrap();
    let mut req = format!(
        "GET / HTTP/1.1\r\nHost: {std_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    );
    if let Some(p) = protocol {
        let _ = write!(req, "Sec-WebSocket-Protocol: {p}\r\n");
    }
    req.push_str("\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let _ = server.await;
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn ws_upgrade_without_sip_subprotocol_is_refused() {
    let resp = ws_upgrade_status(true, None).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    let resp = ws_upgrade_status(true, Some("chat")).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    let resp = ws_upgrade_status(true, Some("sip")).await;
    assert!(resp.starts_with("HTTP/1.1 101"), "{resp}");
    assert!(
        resp.to_ascii_lowercase()
            .contains("sec-websocket-protocol: sip")
    );
}
