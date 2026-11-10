//! SIPREC media fork through the real SBC media relay (RFC 7866 §8).
//!
//! Drives the media half of a recorded call the way `sbc-daemon` does: a real
//! `sbc-media-core` pipeline relays plain RTP between two endpoints, the fork
//! is prepared with one SRTP master key per stream, and a fake Session
//! Recording Server (two sockets, two peer SRTP contexts) receives the copy
//! once the fork is activated. The SIP half (recording INVITE, failure
//! policy, audit, CDR) is covered by the `sbc-daemon` unit tests, since the
//! daemon is a binary crate.
//!
//! ## NIST 800-53 Rev5: AU-14 (session content capture), SC-8 / SC-13 (SRTP
//! AES-256-GCM to the recorder), SC-12 (one key per stream), SC-7 (send-only
//! fork), SI-10 (hostile RTP cannot force nonce reuse, RFC 7714 §8.4)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpUnprotect};
use sbc_media_core::media_pipeline::{
    MediaController, MediaPipeline, MediaPipelineConfig, MediaPipelineError, RecordingForkPorts,
    RecordingMode,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use uc_types::address::SbcSocketAddr;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Per-run random bytes from the OS-seeded hasher (no fixed test key).
fn random_bytes(n: usize) -> Vec<u8> {
    use std::hash::{BuildHasher, Hasher};
    (0..n)
        .map(|_| {
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
                .to_le_bytes()[0]
        })
        .collect()
}

/// One stream's SRTP master key and salt, as the daemon would generate them
/// for the recording session's `a=crypto` line.
struct StreamKey {
    key: Vec<u8>,
    salt: Vec<u8>,
}

impl StreamKey {
    fn new() -> Self {
        Self {
            key: random_bytes(32),
            salt: random_bytes(12),
        }
    }

    fn material(&self) -> SrtpKeyMaterial {
        SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            self.key.clone(),
            self.salt.clone(),
        )
        .unwrap()
    }

    /// The recorder's receive context for this stream.
    fn recorder(&self) -> SrtpContext {
        SrtpContext::new(&self.material(), SrtpDirection::Inbound, 0).unwrap()
    }
}

fn rtp(pt: u8, seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x80, pt & 0x7F];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&timestamp.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

async fn recv(sock: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2100];
    tokio::time::timeout(wait, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()
        .map(|(n, _)| buf[..n].to_vec())
}

const LONG: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(200);

struct RecordedCall {
    pipeline: MediaPipeline,
    alice: UdpSocket,
    bob: UdpSocket,
    sbc_a: SocketAddr,
    sbc_b: SocketAddr,
    srs_caller_stream: UdpSocket,
    srs_callee_stream: UdpSocket,
    alice_key: StreamKey,
    bob_key: StreamKey,
    fork_ports: RecordingForkPorts,
}

/// An answered two-party audio call with a prepared (not yet active) fork.
async fn recorded_call(call_id: &str, rtp_port_min: u16) -> RecordedCall {
    let pipeline = MediaPipeline::new(MediaPipelineConfig {
        srtp_required: false,
        rtp_port_min,
        rtp_port_max: rtp_port_min + 98,
        recording: RecordingMode::Enabled,
        ..MediaPipelineConfig::default()
    });
    let ports = pipeline
        .create_session_with_zones(call_id, None, Some(LOOPBACK), Some(LOOPBACK))
        .await
        .unwrap();
    let alice = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    pipeline
        .set_remote_address(
            call_id,
            true,
            SbcSocketAddr::from(alice.local_addr().unwrap()),
        )
        .await
        .unwrap();
    pipeline
        .set_remote_address(
            call_id,
            false,
            SbcSocketAddr::from(bob.local_addr().unwrap()),
        )
        .await
        .unwrap();
    pipeline.start_relay(call_id).await.unwrap();

    let alice_key = StreamKey::new();
    let bob_key = StreamKey::new();
    // Through the trait object, as the daemon calls it.
    let controller: &dyn MediaController = &pipeline;
    let fork_ports = controller
        .prepare_recording_fork(
            call_id,
            [alice_key.material(), bob_key.material()],
            Some(LOOPBACK),
        )
        .await
        .unwrap();

    RecordedCall {
        sbc_a: SocketAddr::new(LOOPBACK, ports.a_leg_rtp_port),
        sbc_b: SocketAddr::new(LOOPBACK, ports.b_leg_rtp_port),
        pipeline,
        alice,
        bob,
        srs_caller_stream: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        srs_callee_stream: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        alice_key,
        bob_key,
        fork_ports,
    }
}

impl RecordedCall {
    async fn activate(&self, call_id: &str) {
        let controller: &dyn MediaController = &self.pipeline;
        controller
            .activate_recording_fork(
                call_id,
                [
                    self.srs_caller_stream.local_addr().unwrap(),
                    self.srs_callee_stream.local_addr().unwrap(),
                ],
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn both_legs_are_forked_as_srtp_between_activate_and_stop() {
    let call = recorded_call("rec-1", 42_000).await;
    let alice_ssrc = 0x1111_0001;
    let bob_ssrc = 0x2222_0002;

    // Answered, recorder not yet answered: media flows, nothing is forked.
    call.alice
        .send_to(&rtp(0, 100, 16_000, alice_ssrc, &[0x01; 160]), call.sbc_a)
        .await
        .unwrap();
    call.bob
        .send_to(&rtp(0, 900, 48_000, bob_ssrc, &[0x02; 160]), call.sbc_b)
        .await
        .unwrap();
    assert!(recv(&call.bob, LONG).await.is_some());
    assert!(recv(&call.alice, LONG).await.is_some());
    assert!(recv(&call.srs_caller_stream, SHORT).await.is_none());
    assert!(recv(&call.srs_callee_stream, SHORT).await.is_none());

    call.activate("rec-1").await;

    let alice_rx = call.alice_key.recorder();
    let bob_rx = call.bob_key.recorder();
    let mut fork_ssrcs = HashSet::new();
    let mut last_seq: [Option<u16>; 2] = [None, None];
    for i in 0..20u16 {
        let alice_payload = [0xA0 ^ i.to_le_bytes()[0]; 160];
        let bob_payload = [0x50 ^ i.to_le_bytes()[0]; 160];
        let alice_pkt = rtp(
            0,
            101 + i,
            16_160 + u32::from(i) * 160,
            alice_ssrc,
            &alice_payload,
        );
        let bob_pkt = rtp(
            8,
            901 + i,
            48_160 + u32::from(i) * 160,
            bob_ssrc,
            &bob_payload,
        );
        call.alice.send_to(&alice_pkt, call.sbc_a).await.unwrap();
        call.bob.send_to(&bob_pkt, call.sbc_b).await.unwrap();

        // The call's own media is relayed unchanged.
        assert_eq!(recv(&call.bob, LONG).await.unwrap(), alice_pkt);
        assert_eq!(recv(&call.alice, LONG).await.unwrap(), bob_pkt);

        // Stream 1: the caller's sent media, under the caller-stream key.
        let forked = recv(&call.srs_caller_stream, LONG)
            .await
            .expect("caller stream");
        assert_ne!(&forked[12..172], alice_payload.as_slice(), "encrypted");
        let got = SrtpUnprotect::new(&alice_rx)
            .unprotect_rtp(&forked)
            .unwrap();
        assert_eq!(got.payload.as_ref(), alice_payload.as_slice());
        assert_eq!(got.header.payload_type, 0);
        assert_eq!(got.header.timestamp, 16_160 + u32::from(i) * 160);
        assert_ne!(got.header.ssrc, alice_ssrc);
        if let Some(prev) = last_seq[0] {
            assert_eq!(got.header.sequence_number, prev.wrapping_add(1));
        }
        last_seq[0] = Some(got.header.sequence_number);
        fork_ssrcs.insert(("caller", got.header.ssrc));
        // The other stream's key does not open it.
        assert!(
            SrtpUnprotect::new(&call.bob_key.recorder())
                .unprotect_rtp(&forked)
                .is_err()
        );

        // Stream 2: the callee's sent media.
        let forked = recv(&call.srs_callee_stream, LONG)
            .await
            .expect("callee stream");
        let got = SrtpUnprotect::new(&bob_rx).unprotect_rtp(&forked).unwrap();
        assert_eq!(got.payload.as_ref(), bob_payload.as_slice());
        assert_eq!(got.header.payload_type, 8);
        assert_ne!(got.header.ssrc, bob_ssrc);
        if let Some(prev) = last_seq[1] {
            assert_eq!(got.header.sequence_number, prev.wrapping_add(1));
        }
        last_seq[1] = Some(got.header.sequence_number);
        fork_ssrcs.insert(("callee", got.header.ssrc));
    }
    // One SSRC per stream, and the two streams differ.
    assert_eq!(fork_ssrcs.len(), 2);
    let ssrcs: HashSet<u32> = fork_ssrcs.iter().map(|(_, ssrc)| *ssrc).collect();
    assert_eq!(ssrcs.len(), 2);
}

/// What is not the call's audio never reaches the recorder, the fork ports
/// are send-only, and nothing is sent after stop.
#[tokio::test]
async fn fork_skips_rtcp_is_send_only_and_stops() {
    let call = recorded_call("rec-4", 42_800).await;
    call.activate("rec-4").await;
    let alice_ssrc = 0x1111_0001;
    let first = rtp(0, 1, 160, alice_ssrc, &[0x21; 160]);
    call.alice.send_to(&first, call.sbc_a).await.unwrap();
    call.bob.send_to(&first, call.sbc_b).await.unwrap();
    assert!(recv(&call.bob, LONG).await.is_some());
    assert!(recv(&call.alice, LONG).await.is_some());
    assert!(recv(&call.srs_caller_stream, LONG).await.is_some());
    assert!(recv(&call.srs_callee_stream, LONG).await.is_some());

    // RTCP muxed on the media port is relayed but not forked (POA&M-301).
    let rtcp = [0x80u8, 200, 0, 1, 0x11, 0x11, 0, 1, 0, 0, 0, 0];
    call.alice.send_to(&rtcp, call.sbc_a).await.unwrap();
    assert_eq!(recv(&call.bob, LONG).await.unwrap(), rtcp);
    assert!(recv(&call.srs_caller_stream, SHORT).await.is_none());

    // Send-only: what arrives on a fork port goes nowhere.
    call.srs_caller_stream
        .send_to(
            &rtp(0, 1, 1, 0xDEAD, &[0xEE; 160]),
            (LOOPBACK, call.fork_ports.a_leg_port),
        )
        .await
        .unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger
        .send_to(
            &rtp(0, 1, 1, 0xDEAD, &[0xEE; 160]),
            (LOOPBACK, call.fork_ports.b_leg_port),
        )
        .await
        .unwrap();
    assert!(recv(&call.alice, SHORT).await.is_none());
    assert!(recv(&call.bob, SHORT).await.is_none());
    assert!(recv(&call.srs_callee_stream, SHORT).await.is_none());

    // Stop: the call continues, the recorder gets nothing more.
    let controller: &dyn MediaController = &call.pipeline;
    controller.stop_recording_fork("rec-4").await.unwrap();
    let after = rtp(0, 500, 99_000, alice_ssrc, &[0x0F; 160]);
    call.alice.send_to(&after, call.sbc_a).await.unwrap();
    call.bob.send_to(&after, call.sbc_b).await.unwrap();
    assert_eq!(recv(&call.bob, LONG).await.unwrap(), after);
    assert_eq!(recv(&call.alice, LONG).await.unwrap(), after);
    assert!(recv(&call.srs_caller_stream, SHORT).await.is_none());
    assert!(recv(&call.srs_callee_stream, SHORT).await.is_none());
    controller.stop_recording_fork("rec-4").await.unwrap();
}

/// RFC 7714 §8.4: an endpoint that repeats sequence numbers and flips its
/// SSRC back and forth must not be able to make the SBC reuse an AES-GCM
/// nonce toward the recorder. The fork's `(SSRC, sequence)` comes from the
/// SBC, so every forked packet has a fresh pair and passes the recorder's
/// replay check.
#[tokio::test]
async fn hostile_endpoint_cannot_force_a_repeated_ssrc_and_index() {
    let call = recorded_call("rec-2", 42_200).await;
    call.activate("rec-2").await;
    let recorder = call.alice_key.recorder();

    let mut seen = HashSet::new();
    let mut ssrcs = HashSet::new();
    let mut previous: Option<u16> = None;
    for i in 0..300u32 {
        // Sequence number stuck on two values; SSRC alternating between two.
        let seq = if i % 2 == 0 { 7 } else { 8 };
        let ssrc = if (i / 3) % 2 == 0 {
            0xAAAA_AAAA
        } else {
            0xBBBB_BBBB
        };
        let payload = [(i % 251) as u8; 160];
        let pkt = rtp(0, seq, 1_000, ssrc, &payload);
        call.alice.send_to(&pkt, call.sbc_a).await.unwrap();
        assert_eq!(recv(&call.bob, LONG).await.unwrap(), pkt);

        let forked = recv(&call.srs_caller_stream, LONG).await.expect("forked");
        let fork_seq = u16::from_be_bytes([forked[2], forked[3]]);
        let fork_ssrc = u32::from_be_bytes([forked[8], forked[9], forked[10], forked[11]]);
        assert!(
            seen.insert((fork_ssrc, fork_seq)),
            "(SSRC, sequence) repeated at packet {i}"
        );
        ssrcs.insert(fork_ssrc);
        if let Some(prev) = previous {
            assert_eq!(fork_seq, prev.wrapping_add(1), "strictly increasing");
        }
        previous = Some(fork_seq);
        // Authenticates, and is not a replay: the recorder's window accepts
        // every packet exactly once.
        let got = SrtpUnprotect::new(&recorder)
            .unprotect_rtp(&forked)
            .unwrap();
        assert_eq!(got.payload.as_ref(), payload.as_slice());
        assert!(
            SrtpUnprotect::new(&recorder)
                .unprotect_rtp(&forked)
                .is_err(),
            "the same datagram again is a replay"
        );
    }
    assert_eq!(
        ssrcs.len(),
        1,
        "the endpoint's SSRC flips never reach the recorder"
    );
    assert!(!ssrcs.contains(&0xAAAA_AAAA) && !ssrcs.contains(&0xBBBB_BBBB));
}

/// The fork ends with the call, and a pipeline without recording enabled has
/// no fork to give.
#[tokio::test]
async fn fork_ends_with_the_call_and_is_absent_when_disabled() {
    let call = recorded_call("rec-3", 42_400).await;
    call.activate("rec-3").await;
    let pkt = rtp(0, 1, 160, 1, &[0x42; 160]);
    call.alice.send_to(&pkt, call.sbc_a).await.unwrap();
    assert!(recv(&call.srs_caller_stream, LONG).await.is_some());

    call.pipeline.stop_relay("rec-3").await.unwrap();
    call.pipeline.remove_session("rec-3").await.unwrap();
    // The fork sockets are closed: their ports can be bound again.
    let mut freed = false;
    for _ in 0..100 {
        if std::net::UdpSocket::bind((LOOPBACK, call.fork_ports.a_leg_port)).is_ok()
            && std::net::UdpSocket::bind((LOOPBACK, call.fork_ports.b_leg_port)).is_ok()
        {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(freed, "fork ports still bound after the call ended");
    // And the allocator hands the whole range out again (49 pairs).
    for _ in 0..49 {
        call.pipeline
            .port_allocator()
            .allocate_pair()
            .await
            .unwrap();
    }

    let disabled = MediaPipeline::new(MediaPipelineConfig {
        srtp_required: false,
        rtp_port_min: 42_600,
        rtp_port_max: 42_698,
        ..MediaPipelineConfig::default()
    });
    disabled.create_session("plain", None).await.unwrap();
    let controller: &dyn MediaController = &disabled;
    let key = StreamKey::new();
    assert!(matches!(
        controller
            .prepare_recording_fork("plain", [key.material(), key.material()], None)
            .await,
        Err(MediaPipelineError::RecordingUnsupported)
    ));
}

// ---------------------------------------------------------------------------
// QA additions: IPv6 recorder, address-family mismatch, recorder outage
// ---------------------------------------------------------------------------

const LOOPBACK6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

/// An answered IPv4 call whose fork is prepared on `fork_ip`.
async fn call_with_fork_on(
    call_id: &str,
    rtp_port_min: u16,
    fork_ip: IpAddr,
) -> (
    MediaPipeline,
    UdpSocket,
    UdpSocket,
    SocketAddr,
    StreamKey,
    StreamKey,
    RecordingForkPorts,
) {
    let pipeline = MediaPipeline::new(MediaPipelineConfig {
        srtp_required: false,
        rtp_port_min,
        rtp_port_max: rtp_port_min + 98,
        recording: RecordingMode::Enabled,
        ..MediaPipelineConfig::default()
    });
    let ports = pipeline
        .create_session_with_zones(call_id, None, Some(LOOPBACK), Some(LOOPBACK))
        .await
        .unwrap();
    let alice = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (is_a, sock) in [(true, &alice), (false, &bob)] {
        pipeline
            .set_remote_address(
                call_id,
                is_a,
                SbcSocketAddr::from(sock.local_addr().unwrap()),
            )
            .await
            .unwrap();
    }
    pipeline.start_relay(call_id).await.unwrap();
    let (alice_key, bob_key) = (StreamKey::new(), StreamKey::new());
    let controller: &dyn MediaController = &pipeline;
    let fork_ports = controller
        .prepare_recording_fork(
            call_id,
            [alice_key.material(), bob_key.material()],
            Some(fork_ip),
        )
        .await
        .unwrap();
    let sbc_a = SocketAddr::new(LOOPBACK, ports.a_leg_rtp_port);
    (pipeline, alice, bob, sbc_a, alice_key, bob_key, fork_ports)
}

/// QA: an IPv6 recorder. The call itself is IPv4; the fork binds an IPv6
/// address and the recorder's media address is IPv6. The copy arrives from
/// the prepared fork port and decrypts with the stream's key.
#[tokio::test]
async fn qa_fork_to_an_ipv6_recorder() {
    if std::net::UdpSocket::bind((LOOPBACK6, 0)).is_err() {
        eprintln!("SKIPPED qa_fork_to_an_ipv6_recorder: no IPv6 loopback on this host");
        return;
    }
    let (pipeline, alice, bob, sbc_a, alice_key, _bob_key, fork_ports) =
        call_with_fork_on("rec-v6", 43_000, LOOPBACK6).await;
    let srs_caller = UdpSocket::bind((LOOPBACK6, 0)).await.unwrap();
    let idle_stream = UdpSocket::bind((LOOPBACK6, 0)).await.unwrap();
    let controller: &dyn MediaController = &pipeline;
    controller
        .activate_recording_fork(
            "rec-v6",
            [
                srs_caller.local_addr().unwrap(),
                idle_stream.local_addr().unwrap(),
            ],
        )
        .await
        .unwrap();

    let recorder = alice_key.recorder();
    for i in 0..5u16 {
        let payload = [0x60 ^ i.to_le_bytes()[0]; 160];
        let pkt = rtp(0, 10 + i, 1_600 + u32::from(i) * 160, 0x1111_0001, &payload);
        alice.send_to(&pkt, sbc_a).await.unwrap();
        assert_eq!(recv(&bob, LONG).await.unwrap(), pkt);
        let mut buf = [0u8; 2100];
        let (n, from) = tokio::time::timeout(LONG, srs_caller.recv_from(&mut buf))
            .await
            .expect("forked to the IPv6 recorder")
            .unwrap();
        assert_eq!(
            from,
            SocketAddr::new(LOOPBACK6, fork_ports.a_leg_port),
            "from the prepared IPv6 fork port"
        );
        let got = SrtpUnprotect::new(&recorder)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(got.payload.as_ref(), payload.as_slice());
    }
    assert!(
        recv(&idle_stream, SHORT).await.is_none(),
        "bob sent nothing"
    );
}

/// QA: a recorder media address of the other address family than the fork
/// socket is refused at activation; the fork is torn down completely (its
/// ports are free again, a later activate has nothing to act on) and the
/// call's own media is not disturbed.
#[tokio::test]
async fn qa_address_family_mismatch_fails_activation_and_frees_the_fork() {
    let (pipeline, alice, bob, sbc_a, _ak, _bk, fork_ports) =
        call_with_fork_on("rec-af", 43_200, LOOPBACK).await;
    let controller: &dyn MediaController = &pipeline;
    let v6: SocketAddr = "[2001:db8::7]:40000".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::7]:40002".parse().unwrap();
    assert!(matches!(
        controller
            .activate_recording_fork("rec-af", [v6, v6b])
            .await,
        Err(MediaPipelineError::RecordingFork(_))
    ));
    // One good and one bad address: still all-or-nothing.
    let good = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(
        controller
            .activate_recording_fork("rec-af", [good.local_addr().unwrap(), v6b])
            .await
            .is_err(),
        "the fork is gone after a failed activation; no half-recorded call"
    );
    let mut freed = false;
    for _ in 0..100 {
        if std::net::UdpSocket::bind((LOOPBACK, fork_ports.a_leg_port)).is_ok()
            && std::net::UdpSocket::bind((LOOPBACK, fork_ports.b_leg_port)).is_ok()
        {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(freed, "fork ports still bound after the failed activation");

    let pkt = rtp(0, 1, 160, 0x1111_0001, &[0x33; 160]);
    alice.send_to(&pkt, sbc_a).await.unwrap();
    assert_eq!(
        recv(&bob, LONG).await.unwrap(),
        pkt,
        "call media unaffected"
    );
    assert!(recv(&good, SHORT).await.is_none(), "nothing was forked");
}

/// QA: forced send failure. The recorder's media port goes away mid-call
/// (ICMP port unreachable makes the fork's sends fail): the call's own
/// media keeps flowing untouched and the lost copies are counted. When a
/// recorder listens on that port again, forking resumes with fresh packet
/// indices (the counter advanced over the failed sends, so no AES-GCM nonce
/// is reused, RFC 7714 §8.4) and the packets still authenticate.
#[tokio::test]
async fn qa_recorder_outage_drops_copies_counts_them_and_recovers() {
    /// Packets sent while the recorder is down.
    const LOST: u16 = 40;
    let call = recorded_call("rec-out", 43_400).await;
    call.activate("rec-out").await;
    let recorder = call.alice_key.recorder();
    let ssrc = 0x1111_0001;

    let first = rtp(0, 1, 160, ssrc, &[0x01; 160]);
    call.alice.send_to(&first, call.sbc_a).await.unwrap();
    assert_eq!(recv(&call.bob, LONG).await.unwrap(), first);
    let forked = recv(&call.srs_caller_stream, LONG).await.expect("forked");
    let before = SrtpUnprotect::new(&recorder)
        .unprotect_rtp(&forked)
        .unwrap()
        .header
        .sequence_number;

    // The recorder's port closes.
    let srs_addr = call.srs_caller_stream.local_addr().unwrap();
    let dropped_before = sbc_media_core::media_pipeline::recording_fork_dropped();
    let RecordedCall {
        pipeline,
        alice,
        bob,
        sbc_a,
        srs_caller_stream,
        ..
    } = call;
    drop(srs_caller_stream);
    for i in 0..LOST {
        let pkt = rtp(0, 2 + i, 320 + u32::from(i) * 160, ssrc, &[0x02; 160]);
        alice.send_to(&pkt, sbc_a).await.unwrap();
        assert_eq!(
            recv(&bob, LONG).await.unwrap(),
            pkt,
            "the call's media is never delayed or dropped by a dead recorder"
        );
    }
    let dropped = sbc_media_core::media_pipeline::recording_fork_dropped() - dropped_before;
    assert!(
        dropped >= 1,
        "send failures toward the dead recorder are counted (got {dropped})"
    );

    // The recorder is back on the same port.
    let back = match UdpSocket::bind(srs_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SKIPPED recovery half of qa_recorder_outage: cannot rebind {srs_addr}: {e}");
            return;
        }
    };
    let mut got_after = None;
    for i in 0..20u16 {
        let payload = [0x70 ^ i.to_le_bytes()[0]; 160];
        let pkt = rtp(0, 100 + i, 90_000 + u32::from(i) * 160, ssrc, &payload);
        alice.send_to(&pkt, sbc_a).await.unwrap();
        assert_eq!(recv(&bob, LONG).await.unwrap(), pkt);
        if let Some(forked) = recv(&back, SHORT).await {
            let got = SrtpUnprotect::new(&recorder)
                .unprotect_rtp(&forked)
                .expect("authenticates after the outage");
            assert_eq!(got.payload.as_ref(), payload.as_slice());
            got_after = Some(got.header.sequence_number);
            break;
        }
    }
    let after = got_after.expect("forking resumes when the recorder is reachable again");
    let advanced = after.wrapping_sub(before);
    assert!(
        advanced > LOST,
        "the packet index moved past every failed send ({advanced} <= {LOST}): \
         a reused index would reuse an AES-GCM nonce"
    );
    drop(pipeline);
}
