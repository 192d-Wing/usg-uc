//! Opaque media relay source latching under a same-IP sprayer (SR-12).
//!
//! Drives the real `sbc-media-core` opaque relay through `start_relay`. An
//! attacker socket on the callee's IP sprays the SBC's B-leg port from the
//! moment the relay starts. The initial latch is exact-first: inside the
//! grace window only the callee's signalled `ip:port` latches, and while the
//! callee keeps sending from it the sprayer cannot take it, so the caller's
//! media goes to the callee and never to the attacker. A sprayer that
//! latched after the grace (callee silent) loses the latch as soon as the
//! callee sends from its signalled port.
//!
//! The callee is modelled as an RTP stream (a datagram every 20 ms), and
//! the assertions wait for content rather than for a scheduling window, so
//! the outcome does not depend on the relay task running within the 500 ms
//! grace.
//!
//! ## NIST 800-53 Rev5: SC-7 (source latch), SC-5

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sbc_media_core::media_pipeline::{MediaPipeline, MediaPipelineConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use uc_types::address::SbcSocketAddr;

async fn bound() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

/// The next datagram within `ms`, if any.
async fn recv_within(sock: &UdpSocket, ms: u64) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    tokio::time::timeout(Duration::from_millis(ms), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()
        .map(|(n, _)| buf[..n].to_vec())
}

/// Sends `payload` to `target` from `sock` every `every_ms` until `stop` is
/// set.
fn stream(
    sock: Arc<UdpSocket>,
    target: String,
    payload: &'static [u8],
    every_ms: u64,
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            let _ = sock.send_to(payload, &target).await;
            tokio::time::sleep(Duration::from_millis(every_ms)).await;
        }
    });
}

/// Sprays `target` from `sock` every 5 ms until `stop` is set.
fn spray(sock: Arc<UdpSocket>, target: String, stop: Arc<AtomicBool>) {
    stream(sock, target, b"spray", 5, stop);
}

/// Reads `sock` until `want` arrives (true) or `ms` pass, returning also
/// whether anything in `forbidden` arrived first.
async fn recv_until(sock: &UdpSocket, want: &[u8], forbidden: &[u8], ms: u64) -> (bool, bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut buf = [0u8; 2048];
    let mut saw_forbidden = false;
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        let got = &buf[..n];
        if got == want {
            return (true, saw_forbidden);
        }
        saw_forbidden |= got == forbidden;
    }
    (false, saw_forbidden)
}

/// A call whose caller and callee are on loopback; returns the pipeline,
/// the SBC's A-leg and B-leg addresses (`a_peer` is the caller, `b_peer`
/// the callee).
async fn call(
    call_id: &str,
    port_min: u16,
    a_peer: &UdpSocket,
    b_peer: &UdpSocket,
) -> (MediaPipeline, String, String) {
    let pipeline = MediaPipeline::new(MediaPipelineConfig {
        srtp_required: false,
        rtp_port_min: port_min,
        rtp_port_max: port_min + 198,
        ..MediaPipelineConfig::default()
    });
    let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let ports = pipeline
        .create_session_with_zones(call_id, None, Some(loopback), Some(loopback))
        .await
        .unwrap();
    pipeline
        .set_remote_address(
            call_id,
            true,
            SbcSocketAddr::from(a_peer.local_addr().unwrap()),
        )
        .await
        .unwrap();
    pipeline
        .set_remote_address(
            call_id,
            false,
            SbcSocketAddr::from(b_peer.local_addr().unwrap()),
        )
        .await
        .unwrap();
    pipeline.start_relay(call_id).await.unwrap();
    (
        pipeline,
        format!("127.0.0.1:{}", ports.a_leg_rtp_port),
        format!("127.0.0.1:{}", ports.b_leg_rtp_port),
    )
}

/// The callee streams from its SDP port from relay start; the attacker
/// sprays the B-leg port as soon as the callee's media is flowing. The
/// caller's media reaches the callee and never the attacker; the callee's
/// media reaches the caller and the spray does not, also well past the
/// grace window.
#[tokio::test]
async fn sprayer_on_callee_ip_never_captures_the_initial_latch() {
    let a_peer = bound().await;
    let b_peer = Arc::new(bound().await);
    let attacker = Arc::new(bound().await);
    let (pipeline, sbc_a, sbc_b) = call("latch-spray", 45_000, &a_peer, &b_peer).await;

    // The callee speaks from its signalled port: it latches at once.
    let stop_callee = Arc::new(AtomicBool::new(false));
    stream(
        Arc::clone(&b_peer),
        sbc_b.clone(),
        b"callee-rtp",
        20,
        Arc::clone(&stop_callee),
    );
    assert_eq!(
        recv_until(&a_peer, b"callee-rtp", b"spray", 2000).await,
        (true, false)
    );

    let stop = Arc::new(AtomicBool::new(false));
    spray(Arc::clone(&attacker), sbc_b.clone(), Arc::clone(&stop));

    // Caller -> SBC -> callee, never the attacker.
    for i in 0..5u8 {
        a_peer.send_to(&[0x80, i], &sbc_a).await.unwrap();
        assert_eq!(
            recv_within(&b_peer, 2000).await.as_deref(),
            Some(&[0x80, i][..]),
            "caller media must reach the callee"
        );
    }
    // Keep spraying past the grace window: the exact latch holds while
    // the callee keeps sending.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    a_peer.send_to(b"late", &sbc_a).await.unwrap();
    assert_eq!(
        recv_within(&b_peer, 2000).await.as_deref(),
        Some(&b"late"[..])
    );
    stop.store(true, Ordering::Relaxed);
    stop_callee.store(true, Ordering::Relaxed);

    assert_eq!(
        recv_within(&attacker, 200).await,
        None,
        "the attacker received the caller's media"
    );
    // Nothing from the spray reached the caller.
    while let Some(got) = recv_within(&a_peer, 100).await {
        assert_ne!(got, b"spray", "spray relayed to the caller");
    }
    pipeline.stop_relay("latch-spray").await.unwrap();
}

/// With the callee silent past the grace window the sprayer latches (a NAT
/// fallback the opaque relay cannot tell apart, POA&M-345); the callee's
/// first packet from its signalled port takes the latch back and the
/// caller's media follows it.
#[tokio::test]
async fn callee_sending_from_its_sdp_port_takes_the_latch_back() {
    let a_peer = bound().await;
    let b_peer = Arc::new(bound().await);
    let attacker = Arc::new(bound().await);
    let (pipeline, sbc_a, sbc_b) = call("latch-back", 45_400, &a_peer, &b_peer).await;

    let stop = Arc::new(AtomicBool::new(false));
    spray(Arc::clone(&attacker), sbc_b.clone(), Arc::clone(&stop));
    // The spray is relayed once the grace has passed (the fallback); waiting
    // for it rather than sleeping keeps the test independent of timing.
    assert!(
        recv_until(&a_peer, b"spray", b"", 5000).await.0,
        "the sprayer never latched after the grace"
    );

    // The callee starts its stream from its signalled port.
    let stop_callee = Arc::new(AtomicBool::new(false));
    stream(
        Arc::clone(&b_peer),
        sbc_b.clone(),
        b"callee-rtp",
        20,
        Arc::clone(&stop_callee),
    );
    // The caller may see spray relayed before the take-over; the callee's
    // packet must arrive.
    assert!(
        recv_until(&a_peer, b"callee-rtp", b"", 5000).await.0,
        "the callee's media did not reach the caller"
    );
    stop.store(true, Ordering::Relaxed);

    // Drain whatever the attacker got while latched.
    while recv_within(&attacker, 100).await.is_some() {}
    a_peer.send_to(b"after", &sbc_a).await.unwrap();
    assert_eq!(
        recv_within(&b_peer, 2000).await.as_deref(),
        Some(&b"after"[..]),
        "caller media must follow the latch back to the callee"
    );
    assert_eq!(recv_within(&attacker, 200).await, None);
    stop_callee.store(true, Ordering::Relaxed);
    pipeline.stop_relay("latch-back").await.unwrap();
}
