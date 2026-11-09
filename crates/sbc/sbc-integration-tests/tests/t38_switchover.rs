//! T.38 fax switchover through the SBC media relay (RFC 3362, T.38 Annex D).
//!
//! Drives the path `sip_stack` takes on an audio -> T.38 -> audio re-INVITE
//! switchover: `proto-b2bua` picks the anchored m-line and its address from
//! the SDP, and the real `sbc-media-core` opaque relay follows the far ends
//! to their new UDPTL ports (RFC 4961 re-latch) and forwards arbitrary
//! datagrams both ways. The SIP signalling side (488 when disabled, 2xx-only
//! relay moves, audit, gauge) is covered by the `sbc-daemon` unit tests,
//! since the daemon is a binary crate.
//!
//! ## NIST 800-53 Rev5: SC-7 (anchoring and source latch), SI-10

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proto_b2bua::{
    StreamKind, StreamPreference, extract_media_address_for, select_anchored_stream,
};
use sbc_media_core::media_pipeline::{
    MediaKind, MediaPipeline, MediaPipelineConfig, udptl_packets_relayed,
};
use std::time::Duration;
use tokio::net::UdpSocket;
use uc_types::address::SbcSocketAddr;

fn sdp(port_line: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n{port_line}")
}

fn remote_of(sdp: &str, prefer: StreamPreference) -> (StreamKind, SbcSocketAddr) {
    let sel = select_anchored_stream(sdp, prefer).expect("selection");
    let m = extract_media_address_for(sdp, sel.index).expect("address");
    let addr: std::net::SocketAddr = format!("{}:{}", m.address, m.port).parse().unwrap();
    (sel.kind, SbcSocketAddr::from(addr))
}

async fn recv(sock: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()
        .map(|(n, _)| buf[..n].to_vec())
}

async fn bound() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn audio_to_t38_and_back_relays_opaque_udptl_from_new_ports() {
    let pipeline = MediaPipeline::new(MediaPipelineConfig {
        rtp_port_min: 41_000,
        rtp_port_max: 41_998,
        ..MediaPipelineConfig::default()
    });
    let ports = pipeline.create_session("fax", None).await.unwrap();
    let sbc_a = format!("127.0.0.1:{}", ports.a_leg_rtp_port);
    let sbc_b = format!("127.0.0.1:{}", ports.b_leg_rtp_port);

    // Audio call: caller and callee RTP sockets.
    let (a_rtp, b_rtp) = (bound().await, bound().await);
    let a_sdp = sdp(&format!(
        "m=audio {} RTP/AVP 0\r\n",
        a_rtp.local_addr().unwrap().port()
    ));
    let b_sdp = sdp(&format!(
        "m=audio {} RTP/AVP 0\r\n",
        b_rtp.local_addr().unwrap().port()
    ));
    let (_, a_addr) = remote_of(&a_sdp, StreamPreference::Audio);
    let (_, b_addr) = remote_of(&b_sdp, StreamPreference::Audio);
    pipeline
        .set_remote_address("fax", true, a_addr)
        .await
        .unwrap();
    pipeline
        .set_remote_address("fax", false, b_addr)
        .await
        .unwrap();
    pipeline.start_relay("fax").await.unwrap();

    a_rtp.send_to(&[0x80, 0, 0, 1], &sbc_a).await.unwrap();
    assert_eq!(recv(&b_rtp).await.as_deref(), Some(&[0x80, 0, 0, 1][..]));
    b_rtp.send_to(&[0x80, 0, 0, 2], &sbc_b).await.unwrap();
    assert_eq!(recv(&a_rtp).await.as_deref(), Some(&[0x80, 0, 0, 2][..]));

    // T.38 re-INVITE: both gateways move to new UDPTL ports.
    let (a_fax, b_fax) = (bound().await, bound().await);
    let a_t38 = sdp(&format!(
        "m=audio 0 RTP/AVP 0\r\nm=image {} udptl t38\r\na=T38FaxVersion:0\r\n",
        a_fax.local_addr().unwrap().port()
    ));
    let b_t38 = sdp(&format!(
        "m=audio 0 RTP/AVP 0\r\nm=image {} udptl t38\r\na=T38FaxVersion:0\r\n",
        b_fax.local_addr().unwrap().port()
    ));
    let (kind, a_new) = remote_of(&a_t38, StreamPreference::Image);
    assert_eq!(kind, StreamKind::Image);
    let (_, b_new) = remote_of(&b_t38, StreamPreference::Image);
    // Applied at the 2xx, as sip_stack does.
    pipeline
        .set_remote_address("fax", false, b_new)
        .await
        .unwrap();
    pipeline
        .set_remote_address("fax", true, a_new)
        .await
        .unwrap();
    pipeline
        .set_media_kind("fax", MediaKind::Image)
        .await
        .unwrap();

    let before = udptl_packets_relayed();
    // Opaque UDPTL-like datagrams (first byte not RTP), both directions.
    let ifp_a: Vec<u8> = (0u8..=200).rev().collect();
    a_fax.send_to(&ifp_a, &sbc_a).await.unwrap();
    assert_eq!(recv(&b_fax).await, Some(ifp_a));
    b_fax.send_to(&[0x00, 0x01, 0xfe], &sbc_b).await.unwrap();
    assert_eq!(recv(&a_fax).await.as_deref(), Some(&[0x00, 0x01, 0xfe][..]));
    assert!(udptl_packets_relayed() >= before + 2);

    // The old RTP source is no longer latched.
    a_rtp.send_to(b"stale", &sbc_a).await.unwrap();
    a_fax.send_to(b"page", &sbc_a).await.unwrap();
    assert_eq!(recv(&b_fax).await.as_deref(), Some(&b"page"[..]));

    // Back to audio on the original RTP ports.
    pipeline
        .set_remote_address("fax", false, b_addr)
        .await
        .unwrap();
    pipeline
        .set_remote_address("fax", true, a_addr)
        .await
        .unwrap();
    pipeline
        .set_media_kind("fax", MediaKind::Audio)
        .await
        .unwrap();
    a_rtp.send_to(&[0x80, 0, 0, 3], &sbc_a).await.unwrap();
    assert_eq!(recv(&b_rtp).await.as_deref(), Some(&[0x80, 0, 0, 3][..]));

    pipeline.remove_session("fax").await.unwrap();
}
