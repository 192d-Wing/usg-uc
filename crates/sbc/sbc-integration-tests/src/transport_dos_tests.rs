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

/// SR-58: the aggregate connection-cap keys load from TOML and are
/// validated. Compile-red until the `[transport]` fields exist.
mod sr58_aggregate_keys {
    use sbc_config::load_from_str;

    #[test]
    fn sr58_aggregate_keys_load_from_toml() {
        let config = load_from_str(
            r#"
            [rate_limit]
            ipv6_prefix_len = 64

            [transport]
            udp_listen = ["0.0.0.0:5060"]
            v6_aggregate_prefix_len = 56
            max_connections_per_v6_aggregate = 2048
            max_connections_per_v4_24 = 512
        "#,
        )
        .unwrap();
        assert_eq!(config.transport.v6_aggregate_prefix_len, 56);
        assert_eq!(config.transport.max_connections_per_v6_aggregate, 2048);
        assert_eq!(config.transport.max_connections_per_v4_24, 512);

        let defaults = load_from_str("[transport]\nudp_listen = [\"0.0.0.0:5060\"]\n").unwrap();
        assert_eq!(defaults.transport.v6_aggregate_prefix_len, 48);
        assert_eq!(defaults.transport.max_connections_per_v6_aggregate, 1024);
        assert_eq!(defaults.transport.max_connections_per_v4_24, 1024);

        // Cross-section: an aggregate narrower than the per-source key
        // still loads (configs that loaded before keep loading) and is
        // clamped to the per-source prefix.
        let clamped = load_from_str(
            "[rate_limit]\nipv6_prefix_len = 48\n[transport]\nudp_listen = \
             [\"0.0.0.0:5060\"]\nv6_aggregate_prefix_len = 56\n",
        )
        .unwrap();
        assert_eq!(
            clamped
                .transport
                .effective_v6_aggregate_prefix_len(clamped.rate_limit.ipv6_prefix_len),
            48
        );
        // Explicitly invalid prefixes are rejected.
        for bad in [30, 72] {
            assert!(
                load_from_str(&format!(
                    "[transport]\nudp_listen = [\"0.0.0.0:5060\"]\nv6_aggregate_prefix_len = {bad}\n"
                ))
                .is_err()
            );
        }
    }
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

// SR-55: spoofable UDP cannot block a configured trunk (limiter trust and
// auto-block switches, `[rate_limit]` keys).
mod sr55 {
    use super::*;
    use uc_dos_protection::RateLimitAction;

    /// Built as the daemon wires its UDP limiter: auto-block off, trunk IP
    /// trusted with its own bucket.
    #[test]
    fn spoofed_udp_flood_cannot_block_trunk() {
        let (trunk_rps, trunk_burst) = (1_000, 2_000);
        let mut udp = RateLimiter::new(
            RateLimiterConfig::new(100, 200)
                .with_auto_block(false)
                .with_trusted_bucket(trunk_rps, trunk_burst),
        );
        let trunk: IpAddr = "2001:db8::5".parse().unwrap();
        let spoofed: IpAddr = "2001:db8::66".parse().unwrap();
        udp.set_trusted_sources([trunk]);
        let (mut trunk_allowed, mut trunk_rejected) = (0u32, 0u32);
        for _ in 0..10_000 {
            let s = udp.check(spoofed);
            assert!(
                !matches!(s, RateLimitAction::Block { .. }),
                "spoofed source must not be blocked"
            );
            let t = udp.check(trunk);
            assert!(
                !matches!(t, RateLimitAction::Block { .. }),
                "trunk must not be blocked"
            );
            if t.is_allowed() {
                trunk_allowed += 1;
            } else {
                trunk_rejected += 1;
            }
        }
        assert!(
            trunk_allowed >= trunk_burst,
            "trunk rejected within its burst"
        );
        assert!(trunk_rejected > 0, "trunk never rejected over trunk_rps");
        assert!(!udp.is_blocked(trunk));
        assert!(!udp.is_blocked(spoofed));
        assert_eq!(udp.blocked_sources(), 0);
    }

    #[test]
    fn rate_limit_c_keys_load_from_toml() {
        let config = load_from_str(
            r#"
            [rate_limit]
            udp_auto_block = true
            trunk_rps = 2000

            [transport]
            udp_listen = ["0.0.0.0:5060"]
        "#,
        )
        .unwrap();
        assert!(config.rate_limit.udp_auto_block);
        assert_eq!(config.rate_limit.trunk_rps, 2_000);
        assert_eq!(config.rate_limit.effective_trunk_rps(), 2_000);
        let defaults = load_from_str("[transport]\nudp_listen = [\"0.0.0.0:5060\"]\n").unwrap();
        assert!(!defaults.rate_limit.udp_auto_block);
        assert_eq!(defaults.rate_limit.effective_trunk_rps(), 1_000);
    }
}

/// SR-55: out-of-range `trunk_rps` fails the load.
#[test]
fn rate_limit_c_trunk_rps_range_enforced_by_loader() {
    let with = |v: u32| {
        load_from_str(&format!(
            "[rate_limit]\ntrunk_rps = {v}\n[transport]\nudp_listen = [\"0.0.0.0:5060\"]\n"
        ))
    };
    assert!(with(5).is_err(), "below per_ip_rps accepted");
    assert!(with(1_000_000).is_err(), "above global_rps accepted");
    assert!(with(2_000).is_ok());
}

/// SR-56 accept-admission keys.
///
/// ## NIST 800-53 Rev5: SC-5, CM-6
mod sr56_accept_keys {
    use sbc_config::load_from_str;

    #[test]
    fn accept_rate_and_handshake_keys_load_from_toml() {
        let config = load_from_str(
            r#"
            [transport]
            udp_listen = ["0.0.0.0:5060"]
            max_connections_per_source = 32
            accept_rate_per_source = 40
            accept_burst_per_source = 80
            max_handshakes_in_flight = 512
            max_handshakes_per_source = 8
        "#,
        )
        .unwrap();
        assert_eq!(config.transport.accept_rate_per_source, 40);
        assert_eq!(config.transport.accept_burst_per_source, 80);
        assert_eq!(config.transport.max_handshakes_in_flight, 512);
        assert_eq!(config.transport.max_handshakes_per_source, 8);

        let defaults = load_from_str("[transport]\nudp_listen = [\"0.0.0.0:5060\"]\n").unwrap();
        assert_eq!(defaults.transport.accept_rate_per_source, 20);
        assert_eq!(defaults.transport.accept_burst_per_source, 50);
        assert_eq!(defaults.transport.max_handshakes_in_flight, 0);
        assert_eq!(defaults.transport.max_handshakes_per_source, 16);

        for bad in [
            "accept_burst_per_source = 0",
            "accept_rate_per_source = 60\naccept_burst_per_source = 50",
            "max_handshakes_per_source = 0",
        ] {
            let text = format!("[transport]\nudp_listen = [\"0.0.0.0:5060\"]\n{bad}\n");
            assert!(load_from_str(&text).is_err(), "{bad:?} must be rejected");
        }
    }

    // NIST-002: lowering only max_connections_per_source below the
    // default max_handshakes_per_source (16) still loads; the daemon
    // clamps the handshake cap to 8 at startup with a warning.
    #[test]
    fn handshake_cap_above_connection_cap_loads() {
        for extra in ["", "max_handshakes_per_source = 9\n"] {
            let text = format!(
                "[transport]\nudp_listen = [\"0.0.0.0:5060\"]\nmax_connections_per_source = 8\n{extra}"
            );
            let config = load_from_str(&text).unwrap();
            assert_eq!(config.transport.max_connections_per_source, 8);
            assert!(config.transport.max_handshakes_per_source > 8, "{extra:?}");
        }
    }
}
