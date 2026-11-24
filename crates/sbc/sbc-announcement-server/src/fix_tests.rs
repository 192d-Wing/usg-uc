//! SR-41 fix round 1: address-family refusal (SEC-002) and fixed status
//! text (NIST-009) on Play.
//!
//! ## NIST 800-53 Rev5: SC-7, SI-10, SI-11

use std::collections::HashMap;

use sbc_grpc_api::sbc::announcement_service_server::AnnouncementService;
use sbc_grpc_api::sbc::{AnnouncementKind, PlayAnnouncementRequest};
use tonic::{Code, Request};

use crate::AnnouncementServiceImpl;
use crate::config::Config;

fn svc(extra: &[(&str, &str)]) -> Result<AnnouncementServiceImpl, String> {
    let mut m: HashMap<String, String> = [
        ("SBC_ANN_GRPC_LISTEN", "127.0.0.1:0"),
        ("SBC_ANN_ADVERTISED_IP", "127.0.0.1"),
        ("SBC_ANN_BIND_IP", "127.0.0.1"),
        ("SBC_ANN_ALLOW_LOOPBACK_DEST", "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        m.insert((*k).to_string(), (*v).to_string());
    }
    Config::from_lookup(|k: &str| m.get(k).cloned()).map(AnnouncementServiceImpl::new)
}

fn req(dest: &str) -> PlayAnnouncementRequest {
    PlayAnnouncementRequest {
        kind: AnnouncementKind::Silence as i32,
        rtp_destination: dest.to_string(),
        ssrc: 1,
        initial_delay_ms: 1,
        call_id: "fix".to_string(),
    }
}

#[tokio::test]
async fn ipv6_destination_on_ipv4_socket_refused() -> Result<(), String> {
    let s = svc(&[])?;
    let st = s
        .play(Request::new(req("[2001:db8::1]:40000")))
        .await
        .err()
        .ok_or("must be refused")?;
    assert_eq!(st.code(), Code::InvalidArgument);
    assert!(!st.message().contains("2001:db8"), "{}", st.message());
    assert_eq!(s.limits().active(), 0);
    Ok(())
}

#[tokio::test]
async fn bind_failure_status_is_fixed_text() -> Result<(), String> {
    let held = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = held
        .local_addr()
        .map_err(|e| e.to_string())?
        .port()
        .to_string();
    let s = svc(&[
        ("SBC_ANN_RTP_PORT_MIN", port.as_str()),
        ("SBC_ANN_RTP_PORT_MAX", port.as_str()),
    ])?;
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let dest = sink.local_addr().map_err(|e| e.to_string())?.to_string();
    let st = s
        .play(Request::new(req(&dest)))
        .await
        .err()
        .ok_or("bind must fail")?;
    assert_eq!(st.code(), Code::ResourceExhausted);
    assert_eq!(st.message(), "no RTP port available");
    // The refusal released its slot.
    tokio::task::yield_now().await;
    assert_eq!(s.limits().active(), 0);
    Ok(())
}

/// SEC-009: the renewal restart delay stays within 0..=10 s and varies.
#[test]
fn restart_jitter_bounded() {
    let draws: Vec<std::time::Duration> = (0..64).map(|_| crate::restart_jitter()).collect();
    assert!(
        draws
            .iter()
            .all(|d| *d <= std::time::Duration::from_secs(10))
    );
    assert!(draws.iter().any(|d| *d != draws[0]), "jitter is constant");
}
