//! QA additions for SIPREC phase 3 (RFC 7866 SRC; POA&M-300, -301, -302, -306).
//!
//! What the coder's notes list as not exercised, plus the fail-secure and
//! hostile-recorder cases:
//!
//! - the real `sbc-media-core` pipeline under the daemon's recording glue,
//!   with a fake SRS that decrypts the fork with the keys of the RS offer;
//! - Timer B on the RS INVITE through the timer loop (real clock);
//! - a DTLS-terminated call through the answer hook;
//! - IPv6 recorder signaling / media addresses;
//! - the emergency exemption for every failure source;
//! - forged and hostile SRS responses;
//! - every `[recording]` key reaching the stack;
//! - key material never reaching the log output.
//!
//! ## NIST 800-53 Rev5: AU-14, AU-5, AU-12, SC-5, SC-8, SC-12, SC-23, SC-24,
//! SI-10, CM-6

use super::*;
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpUnprotect};
use sbc_media_core::media_pipeline::{MediaPipeline, MediaPipelineConfig, RecordingMode};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

// ----------------------------------------------------------------------
// Real media pipeline under the recording glue
// ----------------------------------------------------------------------

/// A non-loopback address of this host that sockets can bind to and reach
/// each other on. The daemon refuses loopback media addresses in SDP
/// (`admitted_media_addr`) and in the SRS answer (`parse_rs_answer`), so the
/// live-media tests cannot run on 127.0.0.1. `None` on a host with no
/// routable interface: the test then reports itself skipped.
fn host_ip() -> Option<IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Nothing is sent: connect() on UDP only selects the source address.
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() || sbc_announcement::is_disallowed_media_ip(ip) {
        return None;
    }
    // Reachable from itself (some sandboxes forbid non-loopback traffic).
    let a = std::net::UdpSocket::bind((ip, 0)).ok()?;
    let b = std::net::UdpSocket::bind((ip, 0)).ok()?;
    b.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    a.send_to(b"probe", b.local_addr().ok()?).ok()?;
    let mut buf = [0u8; 8];
    b.recv_from(&mut buf).ok()?;
    Some(ip)
}

fn audio_sdp(ip: IpAddr, port: u16, proto: &str, extra: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} {proto} 0\r\na=sendrecv\r\n{extra}"
    )
}

/// The ports of every `m=audio` line of an SDP (or multipart body holding one).
fn audio_ports(body: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|l| l.strip_prefix("m=audio "))
        .filter_map(|l| l.split(' ').next()?.parse().ok())
        .collect()
}

/// The SDES keys of the RS offer, in m-line order (master key || salt).
fn offered_keys(invite: &SipRequest) -> Vec<Vec<u8>> {
    String::from_utf8_lossy(invite.body.as_ref().unwrap())
        .lines()
        .filter_map(|l| l.strip_prefix("a=crypto:1 AEAD_AES_256_GCM inline:"))
        .map(|k| b64(k.trim()))
        .collect()
}

/// The recorder's SRTP receive context for a key taken from the RS offer.
fn recorder_context(key_and_salt: &[u8]) -> SrtpContext {
    assert_eq!(key_and_salt.len(), 44, "32-byte key + 12-byte salt");
    let material = SrtpKeyMaterial::new(
        SrtpProfile::AeadAes256Gcm,
        key_and_salt[..32].to_vec(),
        key_and_salt[32..].to_vec(),
    )
    .unwrap();
    SrtpContext::new(&material, SrtpDirection::Inbound, 0).unwrap()
}

fn rtp(pt: u8, seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x80, pt & 0x7F];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&timestamp.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

async fn recv_from(sock: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 2100];
    tokio::time::timeout(wait, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()
        .map(|(n, from)| (buf[..n].to_vec(), from))
}

const LONG: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(250);

/// An answered call on a stack that uses the real in-process media pipeline,
/// with the RS INVITE the answer produced. Alice, Bob and the fake SRS are
/// UDP sockets on this host's own address.
struct LiveCall {
    stack: SipStack,
    cdr: Arc<uc_cdr::CdrEmitter>,
    ip: IpAddr,
    alice: UdpSocket,
    bob: UdpSocket,
    /// SBC media ports facing the caller and the callee.
    sbc_a: SocketAddr,
    sbc_b: SocketAddr,
    /// Fake SRS media sockets: stream 1 (caller's media), stream 2 (callee's).
    srs_media: [UdpSocket; 2],
    rs_invite: SipRequest,
    call_id: &'static str,
}

impl LiveCall {
    async fn start(
        ip: IpAddr,
        policy: RecordingFailureAction,
        call_id: &'static str,
        rtp_port_min: u16,
    ) -> Self {
        let (mut stack, cdr) = cdr_stack().await;
        // Built as `server.rs` builds it for `[recording] enabled = true`.
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            rtp_port_min,
            rtp_port_max: rtp_port_min + 98,
            recording: RecordingMode::from_enabled(true),
            ..MediaPipelineConfig::default()
        });
        stack.set_media_pipeline(Arc::new(pipeline) as _);
        let mut s = settings(policy);
        s.local_media_ip = Some(ip);
        // As `server.rs` wires it: the SBC's own RTP ports. The fake SRS
        // shares this host's address but not these ports.
        s.media_ports = rtp_port_min..=rtp_port_min + 98;
        stack.set_recording(s);

        let alice = UdpSocket::bind((ip, 0)).await.unwrap();
        let bob = UdpSocket::bind((ip, 0)).await.unwrap();
        let offer = audio_sdp(ip, alice.local_addr().unwrap().port(), "RTP/AVP", "");
        let placed = flatten(
            stack
                .process_message(
                    &caller_request("INVITE", DIALED, call_id, 1, None, Some(&offer)),
                    super::alice(),
                    None,
                )
                .await,
        );
        let b_invite = forwarded(&placed, &Method::Invite)
            .expect("INVITE to the callee")
            .0;
        let sbc_b = audio_ports(b_invite.body.as_ref().unwrap())[0];
        let answer = audio_sdp(ip, bob.local_addr().unwrap().port(), "RTP/AVP", "");
        let results = answer_with(&stack, &placed, &answer).await;
        let (ok, _) = responded(&results, 200).expect("200 to the caller");
        let sbc_a = audio_ports(ok.body.as_ref().unwrap())[0];
        let rs_invite = rs_invite(&results);
        caller_ack(&stack, call_id).await;
        Self {
            stack,
            cdr,
            ip,
            alice,
            bob,
            sbc_a: SocketAddr::new(ip, sbc_a),
            sbc_b: SocketAddr::new(ip, sbc_b),
            srs_media: [
                UdpSocket::bind((ip, 0)).await.unwrap(),
                UdpSocket::bind((ip, 0)).await.unwrap(),
            ],
            rs_invite,
            call_id,
        }
    }

    /// The SRS answer naming the fake recorder's two media sockets.
    fn srs_answer(&self) -> String {
        let stream = |port: u16| {
            format!(
                "m=audio {port} RTP/SAVP 0\r\na=recvonly\r\na=rtcp-mux\r\n\
                 a=crypto:1 AEAD_AES_256_GCM inline:{SRS_KEY}\r\n"
            )
        };
        format!(
            "v=0\r\no=- 9 9 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n{}{}",
            stream(self.srs_media[0].local_addr().unwrap().port()),
            stream(self.srs_media[1].local_addr().unwrap().port()),
            ip = self.ip,
        )
    }

    async fn srs_answers(&self) -> Vec<ProcessResult> {
        from_srs(
            &self.stack,
            &response_to(
                &self.rs_invite,
                200,
                Some("srstag"),
                Some(&self.srs_answer()),
            ),
        )
        .await
    }

    /// Alice sends one packet; Bob must get it unchanged.
    async fn alice_sends(&self, seq: u16, payload: &[u8]) -> Vec<u8> {
        let pkt = rtp(0, seq, u32::from(seq) * 160, 0x1111_0001, payload);
        self.alice.send_to(&pkt, self.sbc_a).await.unwrap();
        let (got, _) = recv_from(&self.bob, LONG)
            .await
            .expect("the call's own media is relayed to the callee");
        assert_eq!(got, pkt, "relayed unchanged");
        pkt
    }

    /// Bob sends one packet; Alice must get it unchanged.
    async fn bob_sends(&self, seq: u16, payload: &[u8]) -> Vec<u8> {
        let pkt = rtp(0, seq, u32::from(seq) * 160, 0x2222_0002, payload);
        self.bob.send_to(&pkt, self.sbc_b).await.unwrap();
        let (got, _) = recv_from(&self.alice, LONG)
            .await
            .expect("the call's own media is relayed to the caller");
        assert_eq!(got, pkt, "relayed unchanged");
        pkt
    }

    async fn srs_gets_nothing(&self, what: &str) {
        for (i, sock) in self.srs_media.iter().enumerate() {
            assert!(
                recv_from(sock, SHORT).await.is_none(),
                "{what}: stream {} reached the recorder",
                i + 1
            );
        }
    }
}

/// Waits until a UDP port can be bound again (its previous owner closed it).
async fn port_is_released(ip: IpAddr, port: u16) -> bool {
    for _ in 0..100 {
        if std::net::UdpSocket::bind((ip, port)).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

// POA&M-300 / -301 acceptance, end to end in one process: the daemon's
// recording glue drives the real media pipeline. The RS INVITE offers two
// keys and two fork ports; once the fake SRS answers, each leg's media
// arrives at the recorder from the offered port, encrypted, and decrypts
// to the original payload with the offered key of that stream (RFC 4568
// §6.1: the offerer's key protects what the offerer sends). Nothing is
// forked before the SRS answers or after the call ends, and the fork ports
// are released with the call.
#[tokio::test]
async fn qa_real_pipeline_forks_decryptable_media_to_the_fake_srs() {
    let Some(ip) = host_ip() else {
        eprintln!(
            "SKIPPED qa_real_pipeline_forks_decryptable_media_to_the_fake_srs: no routable host address"
        );
        return;
    };
    let capture = uc_audit::capture::start();
    let call = Box::pin(LiveCall::start(ip, REJECT, "live-1@test", 44_000)).await;

    // The offer: this host's address, two fork ports, two distinct keys.
    let body = String::from_utf8(call.rs_invite.body.as_ref().unwrap().to_vec()).unwrap();
    assert!(body.contains(&format!("c=IN IP4 {ip}")), "{ip}");
    let fork_ports = audio_ports(body.as_bytes());
    assert_eq!(fork_ports.len(), 2);
    assert!(
        fork_ports
            .iter()
            .all(|p| (44_000..=44_098).contains(p) && *p != 0),
        "fork ports come from the RTP range: {fork_ports:?}"
    );
    let keys = offered_keys(&call.rs_invite);
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1], "SC-12: one key per stream");

    // Answered, recorder not yet answered: media flows, nothing is forked.
    call.alice_sends(1, &[0x01; 160]).await;
    call.bob_sends(1, &[0x02; 160]).await;
    call.srs_gets_nothing("before the SRS answered").await;

    let results = call.srs_answers().await;
    assert!(to_srs(&results, &Method::Ack).is_some(), "{results:?}");
    assert_eq!(started(&capture.events()).len(), 1);

    let rx = [recorder_context(&keys[0]), recorder_context(&keys[1])];
    let before = sbc_media_core::media_pipeline::recording_fork_packets();
    let mut fork_ssrc = [0u32; 2];
    for i in 0..10u16 {
        let a_payload = [0xA0 ^ i.to_le_bytes()[0]; 160];
        let b_payload = [0x50 ^ i.to_le_bytes()[0]; 160];
        let a_pkt = call.alice_sends(100 + i, &a_payload).await;
        let b_pkt = call.bob_sends(900 + i, &b_payload).await;
        for (stream, (payload, plain)) in [(&a_payload, &a_pkt), (&b_payload, &b_pkt)]
            .into_iter()
            .enumerate()
        {
            let (forked, from) = recv_from(&call.srs_media[stream], LONG)
                .await
                .unwrap_or_else(|| panic!("stream {} packet {i}", stream + 1));
            assert_eq!(
                from,
                SocketAddr::new(ip, fork_ports[stream]),
                "sent from the port offered for stream {}",
                stream + 1
            );
            assert_ne!(&forked[12..172], payload.as_slice(), "encrypted");
            assert_eq!(forked.len(), plain.len() + 16, "AES-GCM tag appended");
            let got = SrtpUnprotect::new(&rx[stream])
                .unprotect_rtp(&forked)
                .unwrap_or_else(|e| {
                    panic!("stream {} does not open with its key: {e}", stream + 1)
                });
            assert_eq!(got.payload.as_ref(), payload.as_slice());
            assert_eq!(got.header.payload_type, 0);
            // The other stream's key must not open it.
            assert!(
                SrtpUnprotect::new(&recorder_context(&keys[1 - stream]))
                    .unprotect_rtp(&forked)
                    .is_err()
            );
            if i == 0 {
                fork_ssrc[stream] = got.header.ssrc;
            }
            assert_eq!(got.header.ssrc, fork_ssrc[stream], "one SSRC per stream");
        }
    }
    assert_ne!(fork_ssrc[0], fork_ssrc[1]);
    assert!(
        !fork_ssrc.contains(&0x1111_0001) && !fork_ssrc.contains(&0x2222_0002),
        "SBC-owned SSRCs (RFC 7714 §8.4 nonce safety)"
    );
    assert!(
        sbc_media_core::media_pipeline::recording_fork_packets() >= before + 20,
        "fork packet counter (exported as sbc_recording_fork_packets_total)"
    );

    // Call end: RS BYE, fork gone (ports free), CDR `recorded`.
    let ended = caller_bye(&call.stack, call.call_id).await;
    assert!(responded(&ended, 200).is_some());
    assert!(to_srs(&poll(&call.stack).await, &Method::Bye).is_some());
    for port in &fork_ports {
        assert!(
            port_is_released(ip, *port).await,
            "fork port {port} still bound after the call ended"
        );
    }
    call.srs_gets_nothing("after the call ended").await;
    let c = one_cdr(&call.cdr);
    assert_eq!(c.recording, Some(RecordingTag::Recorded));
    assert!(is_uuid(c.recording_session_id.as_deref().unwrap()));
    let events = capture.events();
    assert_eq!(stopped(&events).len(), 1);
    assert!(failed(&events).is_empty());
    assert_eq!(call.stack.recording_counters().slots_held(), 0);
}

/// An SDES key line of a call leg (passthrough SRTP the SBC cannot read).
const LEG_CRYPTO: &str =
    "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n";

// Fail secure with the real pipeline: a recorded cleartext call that is
// re-negotiated to SDES SRTP (passed through unread) must stop reaching the
// recorder. Under `continue` the call stays up and its media is still
// relayed, but not one more packet is forked; under `reject` the call is
// torn down. Either way the fork ports are released.
#[tokio::test]
async fn qa_real_pipeline_stops_forking_when_the_call_becomes_srtp_passthrough() {
    let Some(ip) = host_ip() else {
        eprintln!(
            "SKIPPED qa_real_pipeline_stops_forking_when_the_call_becomes_srtp_passthrough: no routable host address"
        );
        return;
    };
    for (policy, port_min) in [(CONTINUE, 44_200), (REJECT, 44_400)] {
        let call = Box::pin(LiveCall::start(ip, policy, "live-up@test", port_min)).await;
        let fork_ports = audio_ports(call.rs_invite.body.as_ref().unwrap());
        call.srs_answers().await;
        call.alice_sends(1, &[0x11; 160]).await;
        assert!(
            recv_from(&call.srs_media[0], LONG).await.is_some(),
            "recording is live before the re-INVITE"
        );

        let offer = audio_sdp(
            ip,
            call.alice.local_addr().unwrap().port(),
            "RTP/SAVP",
            LEG_CRYPTO,
        );
        let answer = audio_sdp(
            ip,
            call.bob.local_addr().unwrap().port(),
            "RTP/SAVP",
            LEG_CRYPTO,
        );
        let results = flatten(
            call.stack
                .process_message(
                    &caller_request(
                        "INVITE",
                        DIALED,
                        call.call_id,
                        2,
                        Some("bobtag"),
                        Some(&offer),
                    ),
                    super::alice(),
                    None,
                )
                .await,
        );
        let reinvite = forwarded(&results, &Method::Invite)
            .expect("re-INVITE relayed")
            .0
            .clone();
        let mut results = flatten(
            call.stack
                .process_message(
                    &response_to(&reinvite, 200, Some("bobtag"), Some(&answer)),
                    t1(),
                    None,
                )
                .await,
        );
        let queued = poll(&call.stack).await;
        assert!(to_srs(&queued, &Method::Bye).is_some(), "RS BYE");
        results.extend(queued);
        // RFC 3261 §15: the caller's BYE (under `reject`) waits for its ACK
        // of the re-INVITE's 2xx.
        results.extend(caller_ack_for(&call.stack, DIALED, call.call_id, 2).await);
        for port in &fork_ports {
            assert!(
                port_is_released(ip, *port).await,
                "{policy:?}: fork port {port} still bound"
            );
        }
        if policy == CONTINUE {
            assert_no_leg_bye(&results);
            // The call's (now encrypted) media is still relayed...
            for seq in 2..6 {
                call.alice_sends(seq, &[0xEE; 160]).await;
                call.bob_sends(seq, &[0xDD; 160]).await;
            }
            // ...and none of it reaches the recorder.
            call.srs_gets_nothing("after the switch to SDES passthrough")
                .await;
            assert_eq!(
                recording_of(&call.stack, call.call_id).await.tag,
                Some(RecordingTag::Partial)
            );
        } else {
            assert_both_legs_byed(&results);
            let c = one_cdr(&call.cdr);
            assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
            assert_eq!(c.recording, Some(RecordingTag::Partial));
        }
        assert_eq!(call.stack.recording_counters().slots_held(), 0);
    }
}

// The real pipeline's own refusal reaches the policy: an SRS answer whose
// media address the fork socket cannot reach (IPv6 while the fork is bound
// to IPv4) passes SDP validation but fails `activate_recording_fork`. The
// RS is ACKed and BYE'd, the fork is torn down (ports released) and under
// `reject` both call legs are BYE'd. Needs no routable address.
#[tokio::test]
async fn qa_real_pipeline_activation_error_fails_closed() {
    for (policy, port_min) in [(REJECT, 44_600), (CONTINUE, 44_800)] {
        let (mut stack, cdr) = cdr_stack().await;
        stack.set_media_pipeline(Arc::new(MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            rtp_port_min: port_min,
            rtp_port_max: port_min + 98,
            recording: RecordingMode::Enabled,
            ..MediaPipelineConfig::default()
        })) as _);
        let lo = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut s = settings(policy);
        s.local_media_ip = Some(lo);
        stack.set_recording(s);
        let f = Fixture {
            stack,
            media: Arc::new(ForkMedia::default()),
            cdr,
        };
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "live-af@test").await);
        let fork_ports = audio_ports(inv.body.as_ref().unwrap());
        assert_eq!(fork_ports.len(), 2);
        assert!(
            std::net::UdpSocket::bind((lo, fork_ports[0])).is_err(),
            "the prepared fork holds its port"
        );
        let v6_answer = srs_answer_sdp().replace("IN IP4 198.51.100.7", "IN IP6 2001:db8::7");
        let mut results = from_srs(
            &f.stack,
            &response_to(&inv, 200, Some("srstag"), Some(&v6_answer)),
        )
        .await;
        assert!(to_srs(&results, &Method::Ack).is_some(), "2xx is ACKed");
        let queued = poll(&f.stack).await;
        assert!(to_srs(&queued, &Method::Bye).is_some(), "RS BYE");
        results.extend(queued);
        for port in &fork_ports {
            assert!(
                port_is_released(lo, *port).await,
                "{policy:?}: fork port {port} still bound after the activation error"
            );
        }
        let events = capture.events();
        assert!(started(&events).is_empty(), "never audited as started");
        assert_policy(
            &f,
            "live-af@test",
            policy,
            &results,
            &events,
            RecordingFailReason::ForkSetup,
            RecordingTag::Failed,
        )
        .await;
    }
}

// ----------------------------------------------------------------------
// Timer B through the timer loop (RFC 3261 §17.1.1.2)
// ----------------------------------------------------------------------

// The coder's test calls `fail_timed_out_request` directly. Here the RS
// INVITE's own client transaction expires on the real clock and
// `poll_timers` turns Timer B (64*T1 = 32 s on a reliable transport) into
// the recording failure. `rs_invite_timeout_ms` is set out of the way (the
// config caps it at Timer B, so in production the deadline fires first).
//
// Slow by nature (32 s, real time): `proto-transaction` reads
// `std::time::Instant` and has no clock or timer-config seam, so neither a
// paused tokio clock nor a shorter T1 can reach Timer B from here.
//
// Ignored by default (QA-005): it would add 30 s to every run of this
// suite for a path that is defence in depth (`rs_invite_timeout_ms` is
// capped at Timer B, so the recording deadline fires first in production)
// and whose policy outcome `rs_invite_timer_b_applies_the_policy` covers in
// the normal run. Run it with
// `cargo test -p sbc-daemon -- --ignored qa_rs_invite_timer_b`.
#[tokio::test]
#[ignore = "32 s on the real clock: proto-transaction has no clock seam (QA-005)"]
async fn qa_rs_invite_timer_b_fires_from_the_timer_loop() {
    let f = fixture_with(REJECT, |s| {
        s.invite_timeout = Duration::from_secs(3600);
    })
    .await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "tb-real@test").await);
    // RFC 3261 §17.1.1.2: no Timer A on TLS; nothing is due yet.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let early = poll(&f.stack).await;
    assert!(
        to_srs(&early, &Method::Invite).is_none(),
        "no INVITE retransmission on a reliable transport: {early:?}"
    );
    assert!(failed(&capture.events()).is_empty());
    assert!(call_is_up(&f.stack, "tb-real@test").await);

    tokio::time::sleep(Duration::from_millis(31_200)).await;
    let results = poll(&f.stack).await;
    let events = capture.events();
    assert_policy(
        &f,
        "tb-real@test",
        REJECT,
        &results,
        &events,
        RecordingFailReason::SrsTimeout,
        RecordingTag::Failed,
    )
    .await;
    // A 2xx that still arrives is ACKed and BYE'd; the fork stays off.
    let late = srs_ok(&f.stack, &inv).await;
    assert!(to_srs(&late, &Method::Ack).is_some(), "{late:?}");
    assert!(to_srs(&late, &Method::Bye).is_some(), "{late:?}");
    assert_eq!(f.media.count("activate"), 0);
}

// ----------------------------------------------------------------------
// DTLS-terminated relay through the answer hook
// ----------------------------------------------------------------------

const FP_A: &str = "sha-384 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
const FP_B: &str = "sha-384 FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00";

// A call whose relay terminates DTLS-SRTP on both legs is recordable (the
// SBC holds the plaintext): the RS INVITE goes out, the RS offer is still
// SDES `RTP/SAVP` with the SBC's own keys (never the legs' DTLS material),
// and the audit event names the relay as `dtls_terminated`. The terminated
// tap itself is covered in sbc-media-core; a full DTLS handshake needs the
// external sidecar and is not run here.
#[tokio::test]
async fn qa_dtls_terminated_call_is_recorded_as_dtls_terminated() {
    let mut f = fixture(REJECT).await;
    f.stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(
            "sha-384 AB:CD".to_string(),
        ),
    ));
    let capture = uc_audit::capture::start();
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n\
         m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:{FP_A}\r\n"
    );
    let answer = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio 5000 UDP/TLS/RTP/SAVP 0\r\na=setup:active\r\na=fingerprint:{FP_B}\r\n"
    );
    let placed = flatten(
        f.stack
            .process_message(
                &caller_request("INVITE", DIALED, "dtls@test", 1, None, Some(&offer)),
                alice(),
                None,
            )
            .await,
    );
    let results = answer_with(&f.stack, &placed, &answer).await;
    assert_no_leg_bye(&results);
    let inv = rs_invite(&results);
    let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
    assert_eq!(body.matches("RTP/SAVP 0").count(), 2, "{body}");
    assert!(
        !body.contains("UDP/TLS"),
        "the RS is SDES, not DTLS: {body}"
    );
    assert!(
        !body.contains("fingerprint") && !body.contains("11:22:33") && !body.contains("FF:EE:DD"),
        "no DTLS identity of a call leg reaches the recorder offer"
    );
    assert_eq!(
        body.matches("a=crypto:1 AEAD_AES_256_GCM inline:").count(),
        2
    );
    assert_eq!(
        recording_of(&f.stack, "dtls@test").await.leg.unwrap().relay,
        RecordingRelay::DtlsTerminated
    );
    srs_ok(&f.stack, &inv).await;
    let s = started(&capture.events());
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].relay, RecordingRelay::DtlsTerminated);
    assert_eq!(f.media.count("activate"), 1);
    caller_bye(&f.stack, "dtls@test").await;
    assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_some());
    assert_eq!(one_cdr(&f.cdr).recording, Some(RecordingTag::Recorded));
    assert_recording_released(&f).await;
}

// The other half of the rule: DTLS-SRTP the SBC does *not* terminate (no
// SBC DTLS identity, so the handshake passes through end to end) is
// ciphertext to the SBC and must never be forked.
#[tokio::test]
async fn qa_dtls_passthrough_call_is_not_recordable() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let offer = format!(
            "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n\
             m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:{FP_A}\r\n"
        );
        let answer = format!(
            "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio 5000 UDP/TLS/RTP/SAVP 0\r\na=setup:active\r\na=fingerprint:{FP_B}\r\n"
        );
        // RFC-001 (a): the offer alone shows it (no SBC DTLS identity), so
        // under `reject` the INVITE is refused before the B-leg is dialled.
        assert_refused_at_invite(&f, "dtls-pt@test", policy, Some(&offer), &answer).await;
    }
}

// ----------------------------------------------------------------------
// IPv6
// ----------------------------------------------------------------------

// An IPv6 recorder: the RS INVITE goes to the IPv6 SRS address, the RS SDP
// advertises the SBC's IPv6 media address (`c=IN IP6`), the fork binds to
// it, responses are accepted from the IPv6 source, and the fork is
// activated toward the IPv6 media addresses of the answer.
#[tokio::test]
async fn qa_ipv6_recorder_signaling_and_media() {
    let srs6 = SbcSocketAddr::from("[2001:db8::50]:5061".parse::<SocketAddr>().unwrap());
    let f = fixture_with(REJECT, |s| {
        s.srs_addr = srs6;
        s.local_media_ip = Some("2001:db8::9".parse().unwrap());
    })
    .await;
    let capture = uc_audit::capture::start();
    let results = answered(&f.stack, "v6@test").await;
    let inv = results
        .iter()
        .find_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                destination,
                flow: Flow::Leg(flow),
            } if req.method == Method::Invite && *destination == srs6 => {
                assert!(flow.recorder);
                assert_eq!(flow.transport, AddrTransport::Tls);
                Some(req.clone())
            }
            _ => None,
        })
        .expect("RS INVITE to the IPv6 SRS");
    let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
    assert!(body.contains("c=IN IP6 2001:db8::9"), "{body}");
    assert!(!body.contains("IN IP4"), "one family in the RS SDP: {body}");
    assert_eq!(f.media.count("prepare Some(2001:db8::9)"), 1);

    let answer = srs_answer_sdp().replace("IN IP4 198.51.100.7", "IN IP6 2001:db8::7");
    let data = response_to(&inv, 200, Some("srstag"), Some(&answer));
    let results = flatten(
        f.stack
            .process_message_on(&data, srs6, None, AddrTransport::Tls)
            .await,
    );
    assert!(
        results.iter().any(|r| matches!(r, ProcessResult::Forward {
            message: SipMessage::Request(q), destination, ..
        } if q.method == Method::Ack && *destination == srs6)),
        "ACK to the IPv6 SRS: {results:?}"
    );
    assert_eq!(
        f.media
            .count("activate [2001:db8::7]:40000 [2001:db8::7]:40002"),
        1,
        "{:?}",
        f.media.log()
    );
    assert_eq!(started(&capture.events()).len(), 1);
    // The same 200 from the IPv4 look-alike of nothing in particular is not
    // the SRS: a second call's RS is not answered by another source.
    let inv2 = results_rs_invite_to(&answered(&f.stack, "v6-b@test").await, srs6);
    let forged = response_to(&inv2, 200, Some("srstag"), Some(&answer));
    let other = SbcSocketAddr::from("[2001:db8::51]:5061".parse::<SocketAddr>().unwrap());
    let results = flatten(
        f.stack
            .process_message_on(&forged, other, None, AddrTransport::Tls)
            .await,
    );
    assert!(results.is_empty(), "{results:?}");
    assert_eq!(f.media.count("activate"), 1, "not activated by a stranger");
}

fn results_rs_invite_to(results: &[ProcessResult], srs_addr: SbcSocketAddr) -> SipRequest {
    results
        .iter()
        .find_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                destination,
                ..
            } if req.method == Method::Invite && *destination == srs_addr => Some(req.clone()),
            _ => None,
        })
        .expect("RS INVITE")
}

// ----------------------------------------------------------------------
// Emergency exemption for every failure source (47 CFR 9.16, plan Q5)
// ----------------------------------------------------------------------

/// What must hold after any recording failure on an emergency call under
/// `reject`: the call is up, nothing was BYE'd on its legs, the audit
/// action is `emergency_continued`, no call was counted as rejected and
/// the slot is back.
async fn assert_emergency_kept(
    f: &Fixture,
    call_id: &str,
    results: &[ProcessResult],
    events: &[uc_audit::AuditEvent],
    reason: RecordingFailReason,
    tag: RecordingTag,
) {
    assert_no_leg_bye(results);
    assert!(
        call_is_up(&f.stack, call_id).await,
        "{reason:?}: emergency call kept"
    );
    let fails = failed(events);
    assert_eq!(fails.len(), 1, "{reason:?}: {fails:?}");
    assert_eq!(fails[0].reason, reason);
    assert_eq!(fails[0].action, RecordingFailAction::EmergencyContinued);
    assert_eq!(f.stack.recording_counters().calls_rejected(), 0);
    assert_eq!(f.stack.recording_counters().slots_held(), 0);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, uc_audit::AuditEvent::CallTerminated(_))),
        "{reason:?}: no teardown audited"
    );
    let bye = caller_request("BYE", "911", call_id, 2, Some("bobtag"), None);
    f.stack.process_message(&bye, alice(), None).await;
    let c = one_cdr(&f.cdr);
    assert!(c.emergency);
    assert_eq!(c.disposition, uc_cdr::Disposition::Answered, "{reason:?}");
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::Normal, "{reason:?}");
    assert_eq!(c.recording, Some(tag), "{reason:?}");
    assert_recording_released(f).await;
}

#[tokio::test]
async fn qa_emergency_call_survives_every_recording_failure_under_reject() {
    const ID: &str = "e911-m@test";

    // SRS answers 488 (AES-128-only recorder) and 503.
    for (status, reason) in [
        (488, RecordingFailReason::SrsNotAcceptable488),
        (503, RecordingFailReason::SrsRejected),
    ] {
        let f = fixture(REJECT).await;
        let capture = uc_audit::capture::start();
        let placed = place_call_to(&f.stack, "911", ID).await;
        let inv = rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
        let results = from_srs(&f.stack, &response_to(&inv, status, Some("srstag"), None)).await;
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            reason,
            RecordingTag::Failed,
        )
        .await;
    }

    // SRS never answers (`rs_invite_timeout_ms`).
    {
        let f = fixture_with(REJECT, |s| s.invite_timeout = Duration::ZERO).await;
        let capture = uc_audit::capture::start();
        let placed = place_call_to(&f.stack, "911", ID).await;
        rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
        let results = poll(&f.stack).await;
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            RecordingFailReason::SrsTimeout,
            RecordingTag::Failed,
        )
        .await;
    }

    // Unusable SRS answer.
    {
        let f = fixture(REJECT).await;
        let capture = uc_audit::capture::start();
        let placed = place_call_to(&f.stack, "911", ID).await;
        let inv = rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
        let mut results = from_srs(&f.stack, &srs_2xx(&inv, "", None, "")).await;
        results.extend(poll(&f.stack).await);
        assert!(to_srs(&results, &Method::Bye).is_some(), "RS BYE");
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            RecordingFailReason::SrsBadAnswer,
            RecordingTag::Failed,
        )
        .await;
    }

    // SRS hangs up mid-call.
    {
        let f = fixture(REJECT).await;
        let capture = uc_audit::capture::start();
        let placed = place_call_to(&f.stack, "911", ID).await;
        let inv = rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
        srs_ok(&f.stack, &inv).await;
        let results = from_srs(&f.stack, &srs_request(&inv, "BYE", "srstag")).await;
        assert!(responded(&results, 200).is_some());
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            RecordingFailReason::SrsBye,
            RecordingTag::Partial,
        )
        .await;
    }

    // Fork cannot be prepared / activated.
    for activate in [false, true] {
        let f = fixture(REJECT).await;
        let flag = if activate {
            &f.media.fail_activate
        } else {
            &f.media.fail_prepare
        };
        flag.store(true, AtomicOrdering::Relaxed);
        let capture = uc_audit::capture::start();
        let placed = place_call_to(&f.stack, "911", ID).await;
        let mut results = answer_with(&f.stack, &placed, BOB_SDP).await;
        if activate {
            let inv = rs_invite(&results);
            results.extend(srs_ok(&f.stack, &inv).await);
            results.extend(poll(&f.stack).await);
        }
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            RecordingFailReason::ForkSetup,
            RecordingTag::Failed,
        )
        .await;
    }

    // Media the SBC cannot read (SDES passthrough).
    {
        let f = fixture(REJECT).await;
        let capture = uc_audit::capture::start();
        let placed = flatten(
            f.stack
                .process_message(
                    &caller_request("INVITE", "911", ID, 1, None, Some(SAVP_OFFER)),
                    alice(),
                    None,
                )
                .await,
        );
        let results = answer_with(&f.stack, &placed, SAVP_ANSWER).await;
        assert!(to_srs(&results, &Method::Invite).is_none());
        assert_emergency_kept(
            &f,
            ID,
            &results,
            &capture.events(),
            RecordingFailReason::MediaNotRecordable,
            RecordingTag::NotRecordable,
        )
        .await;
    }
}

// ----------------------------------------------------------------------
// Forged and hostile SRS responses (SC-23, SI-10)
// ----------------------------------------------------------------------

// A 2xx for the RS INVITE from an address that is not the SRS changes
// nothing: no ACK, no fork activation, the RS stays pending; the genuine
// 2xx afterwards still establishes it. The same for a non-2xx: a stranger
// cannot fail a recording (and, under `reject`, drop the call).
#[tokio::test]
async fn qa_rs_responses_from_another_source_are_ignored() {
    let other = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 66), 5061);
    let f = fixture(REJECT).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "forged@test").await);
    let hostile_answer = srs_answer_sdp().replace("198.51.100.7", "203.0.113.66");
    for (what, data) in [
        (
            "forged 200",
            response_to(&inv, 200, Some("evil"), Some(&hostile_answer)),
        ),
        ("forged 488", response_to(&inv, 488, Some("evil"), None)),
        ("forged 503", response_to(&inv, 503, Some("evil"), None)),
    ] {
        let results = flatten(
            f.stack
                .process_message_on(&data, other, None, AddrTransport::Tls)
                .await,
        );
        assert!(
            !results.iter().any(|r| matches!(r, ProcessResult::Forward {
                message: SipMessage::Request(q), ..
            } if q.method == Method::Bye)),
            "{what}: must not tear anything down: {results:?}"
        );
        assert_eq!(f.media.count("activate"), 0, "{what}");
        assert!(call_is_up(&f.stack, "forged@test").await, "{what}");
        let events = capture.events();
        assert!(
            failed(&events).is_empty() && started(&events).is_empty(),
            "{what}: no recording outcome from a stranger"
        );
    }
    assert_eq!(f.media.count("fork-stop"), 0);
    assert_eq!(f.stack.recording_counters().slots_held(), 1);
}

// SI-10 wiring check: answers `uc_siprec::parse_rs_answer` refuses are
// refused by the daemon too (the parser's own cases are in uc-siprec), plus
// SIP-level defects of the 2xx. The fork is never activated and the reason
// is `srs_bad_answer`.
#[tokio::test]
async fn qa_hostile_rs_2xx_never_activates_the_fork() {
    let good = srs_answer_sdp();
    let one_stream = good.split("m=audio 40002").next().unwrap().to_string();
    let three_streams = format!(
        "{good}m=audio 40004 RTP/SAVP 0\r\na=recvonly\r\n\
         a=crypto:1 AEAD_AES_256_GCM inline:{SRS_KEY}\r\n"
    );
    let two_keys = good.replacen(
        "a=recvonly\r\n",
        &format!("a=recvonly\r\na=crypto:2 AEAD_AES_256_GCM inline:{SRS_KEY}\r\n"),
        1,
    );
    let cases: Vec<(&str, String)> = vec![
        ("one m-line", one_stream),
        ("three m-lines", three_streams),
        (
            "second stream declined",
            good.replace("m=audio 40002", "m=audio 0"),
        ),
        ("sendrecv", good.replace("a=recvonly", "a=sendrecv")),
        ("sendonly", good.replacen("a=recvonly", "a=sendonly", 1)),
        ("cleartext RTP/AVP", good.replace("RTP/SAVP", "RTP/AVP")),
        (
            "no crypto",
            good.replace(
                "a=crypto:1 AEAD_AES_256_GCM",
                "a=x-crypto:1 AEAD_AES_256_GCM",
            ),
        ),
        ("crypto tag 2", good.replace("a=crypto:1", "a=crypto:2")),
        ("two crypto lines", two_keys),
        ("multicast", good.replace("198.51.100.7", "224.0.0.9")),
        ("unspecified", good.replace("198.51.100.7", "0.0.0.0")),
        ("broadcast", good.replace("198.51.100.7", "255.255.255.255")),
        (
            "v4-mapped loopback",
            good.replace("IN IP4 198.51.100.7", "IN IP6 ::ffff:127.0.0.1"),
        ),
        ("truncated", good[..good.len() / 2].to_string()),
        (
            "CRLF-injected attribute",
            good.replace("a=rtcp-mux", "a=rtcp-mux\r\n\r\nINVITE sip:x SIP/2.0"),
        ),
    ];
    for (what, body) in &cases {
        let f = fixture(CONTINUE).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "hostile@test").await);
        let results = from_srs(&f.stack, &srs_2xx(&inv, "", Some("application/sdp"), body)).await;
        assert!(
            to_srs(&results, &Method::Ack).is_some(),
            "{what}: a 2xx is ACKed whatever it carries"
        );
        assert!(
            to_srs(&poll(&f.stack).await, &Method::Bye).is_some(),
            "{what}: the unusable RS dialog is BYE'd"
        );
        assert_eq!(f.media.count("activate"), 0, "{what}");
        let events = capture.events();
        let fails = failed(&events);
        assert_eq!(fails.len(), 1, "{what}");
        assert_eq!(fails[0].reason, RecordingFailReason::SrsBadAnswer, "{what}");
        assert!(started(&events).is_empty(), "{what}");
        assert_eq!(f.stack.recording_counters().slots_held(), 0, "{what}");
        assert!(call_is_up(&f.stack, "hostile@test").await, "{what}");
    }

    // A To tag that is not a token (RFC 3261 §25.1) is not stored: there is
    // no dialog to ACK into, and it is still a bad answer.
    for tag in ["a b", "x\"y", "<srs>", ""] {
        let f = fixture(CONTINUE).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "badtag@test").await);
        let msg = format!(
            "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag={tag}\r\nCall-ID: {}\r\n\
             CSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{good}",
            inv.headers.get_value(&HeaderName::Via).unwrap(),
            inv.headers.get_value(&HeaderName::From).unwrap(),
            inv.headers.get_value(&HeaderName::To).unwrap(),
            inv.headers.call_id().unwrap(),
            good.len(),
        );
        from_srs(&f.stack, &Bytes::from(msg)).await;
        assert_eq!(f.media.count("activate"), 0, "tag {tag:?}");
        let events = capture.events();
        assert!(started(&events).is_empty(), "tag {tag:?}");
        // Either refused as a bad answer or dropped by the parser; never
        // an established recording.
        let rec = recording_of(&f.stack, "badtag@test").await;
        assert_ne!(rec.tag, Some(RecordingTag::Recorded), "tag {tag:?}");
        assert!(
            rec.leg
                .as_ref()
                .is_none_or(|l| l.state == RsState::Inviting && l.remote_tag.is_none()),
            "tag {tag:?}: no dialog state from a malformed tag"
        );
    }
}

// SC-5: a 2xx with an oversized Record-Route list gives no route set (it is
// not truncated into a wrong one) and the recording still works on the
// pinned SRS flow; a hostile Record-Route never becomes a destination.
#[tokio::test]
async fn qa_oversized_record_route_is_dropped_not_followed() {
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "rr@test").await);
    let many = (0..crate::recording::MAX_RS_ROUTES + 5)
        .map(|i| format!("<sips:hop{i}.attacker.example;lr>"))
        .collect::<Vec<_>>()
        .join(", ");
    let extra = format!("Record-Route: {many}\r\n");
    let results = from_srs(
        &f.stack,
        &srs_2xx(&inv, &extra, Some("application/sdp"), &srs_answer_sdp()),
    )
    .await;
    // `to_srs` asserts the destination is the pinned SRS on the recorder flow.
    let ack = to_srs(&results, &Method::Ack).expect("ACK");
    assert_eq!(ack.headers.get_all(&HeaderName::Route).count(), 0);
    assert_eq!(f.media.count("activate"), 1, "still recorded");
    caller_bye(&f.stack, "rr@test").await;
    let bye = to_srs(&poll(&f.stack).await, &Method::Bye).expect("RS BYE");
    assert_eq!(bye.headers.get_all(&HeaderName::Route).count(), 0);
    assert_recording_released(&f).await;
}

// ----------------------------------------------------------------------
// A re-INVITE from the callee's side (fail secure in both directions)
// ----------------------------------------------------------------------

// The coder's test upgrades to SDES from the caller's side. The callee can
// do the same: its re-INVITE is relayed to the caller, and once the caller
// answers with SRTP the recording must end through the policy as well.
#[tokio::test]
async fn qa_callee_initiated_switch_to_srtp_passthrough_ends_the_recording() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let placed = place_call(&f.stack, "bup@test").await;
        let b_invite = forwarded(&placed, &Method::Invite).unwrap().0.clone();
        let inv = rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
        srs_ok(&f.stack, &inv).await;
        caller_ack(&f.stack, "bup@test").await;

        let capture = uc_audit::capture::start();
        let from = format!(
            "{};tag=bobtag",
            b_invite.headers.get_value(&HeaderName::To).unwrap()
        );
        let reinvite = Bytes::from(format!(
            "INVITE sip:sbc@sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.2:5060;branch=z9hG4bK-bup-re\r\n\
             From: {from}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 9 INVITE\r\n\
             Contact: <sip:bob@127.0.0.2:5060>\r\nMax-Forwards: 70\r\n\
             Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{SAVP_ANSWER}",
            b_invite.headers.get_value(&HeaderName::From).unwrap(),
            b_invite.headers.call_id().unwrap(),
            SAVP_ANSWER.len(),
        ));
        let results = flatten(f.stack.process_message(&reinvite, t1(), None).await);
        let (to_caller, dest) = forwarded(&results, &Method::Invite)
            .unwrap_or_else(|| panic!("callee re-INVITE relayed to the caller: {results:?}"));
        assert_eq!(dest, alice());
        let to_caller = to_caller.clone();
        let mut results = flatten(
            f.stack
                .process_message(
                    &response_to(&to_caller, 200, None, Some(SAVP_OFFER)),
                    alice(),
                    None,
                )
                .await,
        );
        results.extend(poll(&f.stack).await);
        assert!(
            to_srs(&results, &Method::Bye).is_some(),
            "{policy:?}: RS BYE after the callee's SRTP upgrade: {results:?}"
        );
        if policy == REJECT {
            // RFC 3261 §15: the SBC is the UAS of the callee's re-INVITE, so
            // the callee's BYE waits for the callee's ACK of that 2xx.
            assert_eq!(leg_byes(&results), vec![alice()], "{results:?}");
            let ack = String::from_utf8(reinvite.to_vec())
                .unwrap()
                .replace("INVITE sip:sbc@sbc.local", "ACK sip:sbc@sbc.local")
                .replace("z9hG4bK-bup-re", "z9hG4bK-bup-re-ack")
                .replace("CSeq: 9 INVITE", "CSeq: 9 ACK");
            let ack = ack.split("Content-Type:").next().unwrap().to_string()
                + "Content-Length: 0\r\n\r\n";
            results.extend(flatten(
                f.stack.process_message(&Bytes::from(ack), t1(), None).await,
            ));
        }
        assert_eq!(f.media.count("fork-stop"), 1, "{policy:?}");
        let events = capture.events();
        let fails = failed(&events);
        assert_eq!(fails.len(), 1, "{policy:?}");
        assert_eq!(fails[0].reason, RecordingFailReason::MediaNotRecordable);
        assert_eq!(f.stack.recording_counters().slots_held(), 0);
        if policy == REJECT {
            assert_both_legs_byed(&results);
            assert_eq!(
                one_cdr(&f.cdr).disposition,
                uc_cdr::Disposition::RecordingFailure
            );
        } else {
            assert_no_leg_bye(&results);
            assert_eq!(
                recording_of(&f.stack, "bup@test").await.tag,
                Some(RecordingTag::Partial)
            );
        }
    }
}

// ----------------------------------------------------------------------
// Config keys reach the stack (CM-6): one assertion per `[recording]` key
// ----------------------------------------------------------------------

#[test]
fn qa_every_recording_config_key_reaches_the_settings() {
    let rec = RecordingConfig {
        enabled: true,
        notice_acknowledged: true,
        srs_uri: Some("sips:rec@srs.example.test:5099".to_string()),
        srs_tls_ca_file: Some("/unused".to_string()),
        srs_tls_server_name: Some("recorder.internal.test".to_string()),
        record_all: false,
        trunk_groups: vec!["carriers".to_string()],
        zones: vec!["lan".to_string()],
        max_sessions: 3,
        rs_invite_timeout_ms: 1234,
        on_failure: CONTINUE,
        recordpref_never: RecordprefPolicy::Ignore,
        srs_zone: Some("rec-zone".to_string()),
    };
    let media_ip: IpAddr = "192.0.2.9".parse().unwrap();
    let s = RecordingSettings::from_config(&rec, srs(), Some(media_ip)).unwrap();
    assert_eq!(s.srs_uri.to_string(), "sips:rec@srs.example.test:5099");
    assert_eq!(s.srs_addr, srs());
    assert_eq!(
        s.flow.dial.as_deref(),
        Some("recorder.internal.test"),
        "srs_tls_server_name is the verified TLS name"
    );
    assert!(s.flow.recorder);
    assert!(!s.record_all);
    assert_eq!(s.trunk_groups, vec!["carriers"]);
    assert_eq!(s.zones, vec!["lan"]);
    assert_eq!(s.max_sessions, 3);
    assert_eq!(s.invite_timeout, Duration::from_millis(1234));
    assert_eq!(s.on_failure, CONTINUE);
    assert!(!s.honour_recordpref, "recordpref_never = ignore");
    assert_eq!(s.srs_zone.as_deref(), Some("rec-zone"));
    assert_eq!(s.local_media_ip, Some(media_ip));
    assert_eq!(
        s.action(false),
        RecordingFailAction::ContinuedUnrecorded,
        "on_failure = continue"
    );

    // Defaults: fail closed, and a participant opt-out is not honoured
    // unless the operator says so (SEC-002).
    let d = RecordingSettings::from_config(
        &RecordingConfig {
            srs_uri: Some("sips:srs.example.test".to_string()),
            ..RecordingConfig::default()
        },
        srs(),
        None,
    )
    .unwrap();
    assert_eq!(d.action(false), RecordingFailAction::CallRejected);
    assert_eq!(d.action(true), RecordingFailAction::EmergencyContinued);
    assert!(!d.honour_recordpref);
    assert_eq!(d.max_sessions, 256);
    assert_eq!(d.invite_timeout, Duration::from_millis(5000));
    assert!(!d.record_all && d.trunk_groups.is_empty() && d.zones.is_empty());
}

// `max_sessions`, `rs_invite_timeout_ms`, `on_failure` and
// `recordpref_never` taken from a `[recording]` table (not from a
// hand-built settings struct) are what the stack enforces.
#[tokio::test]
async fn qa_recording_config_values_are_enforced_by_the_stack() {
    let rec = RecordingConfig {
        enabled: true,
        notice_acknowledged: true,
        srs_uri: Some("sips:srs.example.test:5061".to_string()),
        srs_tls_ca_file: Some("/unused".to_string()),
        record_all: true,
        max_sessions: 1,
        rs_invite_timeout_ms: 1000,
        on_failure: CONTINUE,
        recordpref_never: RecordprefPolicy::Ignore,
        ..RecordingConfig::default()
    };
    let from_cfg = RecordingSettings::from_config(
        &rec,
        srs(),
        Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
    )
    .unwrap();
    let f = fixture_with(REJECT, |s| *s = from_cfg).await;
    let capture = uc_audit::capture::start();

    // recordpref_never = ignore: the opt-out does not stop the recording.
    let offer_off = format!("{ALICE_SDP}a=recordpref:off\r\n");
    let placed = flatten(
        f.stack
            .process_message(
                &caller_request("INVITE", DIALED, "cfg-1@test", 1, None, Some(&offer_off)),
                alice(),
                None,
            )
            .await,
    );
    let first = answer_with(&f.stack, &placed, BOB_SDP).await;
    assert!(to_srs(&first, &Method::Invite).is_some(), "recorded anyway");
    assert_eq!(skipped(&capture.events()), 0);

    // max_sessions = 1 with on_failure = continue: the second call is
    // admitted unrecorded.
    let second = answered(&f.stack, "cfg-2@test").await;
    assert!(responded(&second, 200).is_some());
    assert!(to_srs(&second, &Method::Invite).is_none());
    let fails = failed(&capture.events());
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].reason, RecordingFailReason::NoSessionSlot);
    assert_eq!(fails[0].action, RecordingFailAction::ContinuedUnrecorded);

    // rs_invite_timeout_ms = 1000: not due at once, due after one second.
    assert!(
        failed(&{
            poll(&f.stack).await;
            capture.events()
        })
        .len()
            == 1,
        "the RS deadline is not due immediately"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let results = poll(&f.stack).await;
    assert_no_leg_bye(&results);
    let fails = failed(&capture.events());
    assert_eq!(fails.len(), 2, "{fails:?}");
    assert_eq!(fails[1].reason, RecordingFailReason::SrsTimeout);
    assert_eq!(fails[1].action, RecordingFailAction::ContinuedUnrecorded);
    assert!(
        call_is_up(&f.stack, "cfg-1@test").await,
        "on_failure = continue"
    );
    caller_bye(&f.stack, "cfg-1@test").await;
    caller_bye(&f.stack, "cfg-2@test").await;
    assert_recording_released(&f).await;
}

// `srs_zone`: the zone's media address is where the fork binds and what the
// RS SDP advertises; its signaling address is the RS Via / Contact host. It
// wins over the startup-resolved source address. A zone the registry does
// not know falls back to that address; with neither, the recording fails
// closed (`fork_setup`) instead of advertising an unusable address.
#[tokio::test]
async fn qa_srs_zone_selects_the_fork_and_signaling_addresses() {
    use crate::zone::ResolvedZoneRegistry;
    use sbc_config::interface::ResolvedZone;
    let registry = || {
        Arc::new(ResolvedZoneRegistry::from_resolved(vec![ResolvedZone {
            name: "rec".to_string(),
            signaling_ip: "10.9.9.10".parse().unwrap(),
            media_ip: "10.9.9.20".parse().unwrap(),
            external_ip: None,
            external_ip_source: None,
        }]))
    };

    let mut f = fixture_with(REJECT, |s| s.srs_zone = Some("rec".to_string())).await;
    f.stack.set_zone_registry(registry());
    let inv = rs_invite(&answered(&f.stack, "zone@test").await);
    let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
    assert!(body.contains("c=IN IP4 10.9.9.20"), "{body}");
    assert!(!body.contains("192.0.2.9"), "the zone wins: {body}");
    assert_eq!(
        f.media.count("prepare Some(10.9.9.20)"),
        1,
        "{:?}",
        f.media.log()
    );
    let via = inv.headers.get_value(&HeaderName::Via).unwrap();
    assert!(via.starts_with("SIP/2.0/TLS 10.9.9.10:"), "{via}");
    let contact = inv.headers.get_value(&HeaderName::Contact).unwrap();
    assert!(contact.contains("10.9.9.10"), "{contact}");

    // Unknown zone, no fallback address: fail closed, no RS INVITE.
    let mut f = fixture_with(REJECT, |s| {
        s.srs_zone = Some("gone".to_string());
        s.local_media_ip = None;
    })
    .await;
    f.stack.set_zone_registry(registry());
    let capture = uc_audit::capture::start();
    let results = answered(&f.stack, "zone-x@test").await;
    assert!(to_srs(&results, &Method::Invite).is_none());
    assert_eq!(f.media.count("prepare"), 0);
    // Found at the callee's 2xx, so the call is refused, not cut (RFC-001).
    assert_policy_as(
        &f,
        "zone-x@test",
        REJECT,
        &results,
        &capture.events(),
        (
            RecordingFailReason::ForkSetup,
            RecordingTag::Failed,
            Reject::AtAnswer(503),
        ),
    )
    .await;
}

// ----------------------------------------------------------------------
// Key hygiene in the log output (SC-12, SI-12, AU-9)
// ----------------------------------------------------------------------

/// Collects everything a `tracing` subscriber writes.
#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A syntactically valid 44-octet key || salt in base64 that is easy to
/// find in a log (unlike the all-`A` test key).
fn marker_key() -> String {
    format!("{}A=", "QA".repeat(29))
}

// At TRACE level, a recorded call's whole life (RS INVITE with the SBC's
// keys, SRS 2xx with the recorder's key, a refused answer, a rejected RS,
// SRS BYE, teardown) writes neither the offered keys, nor the recorder's
// key, nor any `a=crypto` / `inline:` text to the log. Covers the plan's
// requirement that no log statement at any level prints an RS body.
//
// `tracing` caches per-callsite interest process-wide, so a thread-scoped
// subscriber misses events whose callsite another test thread registered
// first. The test therefore re-runs itself alone in a child process (same
// test binary, `--exact`, one thread) and does the work there.
#[tokio::test]
async fn qa_recording_keys_never_reach_the_log() {
    const CHILD: &str = "SBC_QA_LOG_HYGIENE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = format!(
            "{}::qa_recording_keys_never_reach_the_log",
            module_path!().split_once("::").map_or("", |(_, m)| m)
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("re-run this test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "isolated run failed:\n{stdout}\n{stderr}"
        );
        return;
    }
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let marker = marker_key();
    assert_eq!(b64(&marker).len(), 44);
    let answer = srs_answer_sdp().replace(SRS_KEY, &marker);
    let mut offered: Vec<String> = Vec::new();
    let mut note_keys = |inv: &SipRequest| {
        let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
        offered.extend(
            body.lines()
                .filter_map(|l| l.strip_prefix("a=crypto:1 AEAD_AES_256_GCM inline:"))
                .map(|k| k.trim().to_string()),
        );
    };

    // 1. Recorded call, ended by the SRS (policy reject tears it down).
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "log-1@test").await);
    note_keys(&inv);
    from_srs(
        &f.stack,
        &response_to(&inv, 200, Some("srstag"), Some(&answer)),
    )
    .await;
    assert_eq!(
        f.media.count("activate"),
        1,
        "the marker key is a valid answer"
    );
    from_srs(&f.stack, &srs_request(&inv, "BYE", "srstag")).await;
    poll(&f.stack).await;

    // 2. An answer that is refused after it was parsed (wrong direction),
    //    and one that is not SDP at all but carries the key text.
    for (ct, body) in [
        (
            "application/sdp",
            answer.replace("a=recvonly", "a=sendrecv"),
        ),
        ("text/plain", answer.clone()),
    ] {
        let f = fixture(CONTINUE).await;
        let inv = rs_invite(&answered(&f.stack, "log-2@test").await);
        note_keys(&inv);
        from_srs(&f.stack, &srs_2xx(&inv, "", Some(ct), &body)).await;
        poll(&f.stack).await;
        caller_bye(&f.stack, "log-2@test").await;
        poll(&f.stack).await;
    }

    // 3. Rejected RS INVITE, failed send, timeout: the failure paths log.
    let f = fixture(CONTINUE).await;
    let inv = rs_invite(&answered(&f.stack, "log-3@test").await);
    note_keys(&inv);
    from_srs(&f.stack, &response_to(&inv, 488, Some("srstag"), None)).await;
    let f = fixture_with(REJECT, |s| s.invite_timeout = Duration::ZERO).await;
    let inv = rs_invite(&answered(&f.stack, "log-4@test").await);
    note_keys(&inv);
    poll(&f.stack).await;
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "log-5@test").await);
    note_keys(&inv);
    f.stack
        .on_invite_sent_with(&SipMessage::Request(inv), false, true)
        .await;

    drop(guard);
    let log = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    // The capture works and saw the recording paths.
    assert!(
        log.contains("Recording session INVITE to the SRS"),
        "log capture is live: {} bytes",
        log.len()
    );
    assert!(log.contains("Recording session active"));
    assert!(log.contains("Recording failed"));
    assert_eq!(offered.len(), 12, "two keys per RS INVITE, six calls");
    for key in &offered {
        assert!(
            !log.contains(key.as_str()),
            "an offered SDES key is in the log"
        );
        // Not even a recognisable part of one.
        assert!(
            !log.contains(&key[..16]),
            "part of an offered key is in the log"
        );
    }
    assert!(
        !log.contains(&marker),
        "the recorder's SDES key is in the log"
    );
    assert!(!log.contains(&marker[..16]));
    for needle in [
        "inline:",
        "a=crypto",
        "AEAD_AES_256_GCM inline",
        "rs-metadata",
    ] {
        assert!(
            !log.contains(needle),
            "{needle:?} (RS body text) is in the log"
        );
    }
}

// ----------------------------------------------------------------------
// Dialog / transaction state
// ----------------------------------------------------------------------

// RFC 3261 §13.2.2.4: the callee retransmits its 200 until it sees the ACK.
// The retransmission must not start a second recording session (one RS
// INVITE, one fork, one slot per call).
#[tokio::test]
async fn qa_retransmitted_call_answer_does_not_start_a_second_recording() {
    let f = fixture(REJECT).await;
    let placed = place_call(&f.stack, "rtx@test").await;
    let first = answer_with(&f.stack, &placed, BOB_SDP).await;
    let inv = rs_invite(&first);
    for _ in 0..3 {
        let again = answer_with(&f.stack, &placed, BOB_SDP).await;
        assert!(
            to_srs(&again, &Method::Invite).is_none(),
            "a retransmitted 200 starts no second RS: {again:?}"
        );
        assert_no_leg_bye(&again);
    }
    assert_eq!(f.media.count("prepare"), 1, "{:?}", f.media.log());
    assert_eq!(f.stack.recording_counters().slots_held(), 1);
    assert_eq!(f.stack.call_correlation.read().await.rs_leg.len(), 1);
    srs_ok(&f.stack, &inv).await;
    // ...nor after the recording is active.
    let again = answer_with(&f.stack, &placed, BOB_SDP).await;
    assert!(to_srs(&again, &Method::Invite).is_none());
    assert_eq!(f.media.count("activate"), 1);
    caller_bye(&f.stack, "rtx@test").await;
    assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_some());
    assert_recording_released(&f).await;
}

// RFC 3311: the same re-negotiation by UPDATE. A recorded cleartext call
// moved to SDES passthrough with an UPDATE ends the recording through the
// policy, like the re-INVITE.
#[tokio::test]
async fn qa_update_to_srtp_passthrough_ends_the_recording() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let inv = rs_invite(&answered(&f.stack, "upd@test").await);
        srs_ok(&f.stack, &inv).await;
        f.stack
            .process_message(
                &caller_request("ACK", DIALED, "upd@test", 1, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        let capture = uc_audit::capture::start();
        let results = flatten(
            f.stack
                .process_message(
                    &caller_request(
                        "UPDATE",
                        DIALED,
                        "upd@test",
                        2,
                        Some("bobtag"),
                        Some(SAVP_OFFER),
                    ),
                    alice(),
                    None,
                )
                .await,
        );
        let update = forwarded(&results, &Method::Update)
            .expect("UPDATE relayed")
            .0
            .clone();
        let mut results = flatten(
            f.stack
                .process_message(
                    &response_to(&update, 200, Some("bobtag"), Some(SAVP_ANSWER)),
                    t1(),
                    None,
                )
                .await,
        );
        results.extend(poll(&f.stack).await);
        assert!(
            to_srs(&results, &Method::Bye).is_some(),
            "{policy:?}: RS BYE"
        );
        assert_eq!(f.media.count("fork-stop"), 1, "{policy:?}");
        let events = capture.events();
        let st = stopped(&events);
        assert_eq!(st.len(), 1, "{policy:?}");
        assert_eq!(st[0].reason, RecordingStopReason::MediaNotRecordable);
        let fails = failed(&events);
        assert_eq!(fails.len(), 1, "{policy:?}");
        assert_eq!(fails[0].reason, RecordingFailReason::MediaNotRecordable);
        assert_eq!(f.stack.recording_counters().slots_held(), 0);
        if policy == REJECT {
            assert_eq!(fails[0].action, RecordingFailAction::CallRejected);
            assert_both_legs_byed(&results);
            let c = one_cdr(&f.cdr);
            assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
            assert_eq!(c.recording, Some(RecordingTag::Partial));
        } else {
            assert_eq!(fails[0].action, RecordingFailAction::ContinuedUnrecorded);
            assert_no_leg_bye(&results);
            assert!(call_is_up(&f.stack, "upd@test").await);
            assert_eq!(
                recording_of(&f.stack, "upd@test").await.tag,
                Some(RecordingTag::Partial)
            );
        }
    }
}

// A late-offer call (INVITE without SDP, RFC 3264 §5): the SBC has no
// stored offer to judge the media by, so the call is "not recordable" and
// obeys the policy. It must never be recorded on the answer alone. The
// INVITE already shows it, so under `reject` it is refused there (488).
#[tokio::test]
async fn qa_late_offer_call_is_not_recordable() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        assert_refused_at_invite(&f, "late@test", policy, None, BOB_SDP).await;
    }
}

// ----------------------------------------------------------------------
// Back-pressure (SC-5, plan §5; PERF-001)
// ----------------------------------------------------------------------

// RS BYE / CANCEL ride their own wind-down queue, bounded by
// `max_sessions`, and are handed to the recorder flow a bounded number per
// timer tick, so a mass teardown cannot overrun the recorder's send lane
// (256) and lose them. Nothing lands on the shared deferred-send queue.
#[tokio::test]
async fn qa_mass_teardown_paces_rs_byes_to_the_recorder_lane() {
    use crate::sip_stack::recording_session::RS_WIND_DOWN_PER_TICK;
    const CALLS: usize = 300;
    // A tick's burst fits the recorder lane with room to spare.
    const { assert!(RS_WIND_DOWN_PER_TICK * 4 <= crate::flows::LANE_DEPTH) };
    // Trunks that carry that many calls at once.
    let mut stack = trunk_stack_cfg(SipStackConfig::default(), 400, ("none", ""), None).await;
    let cdr = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&cdr),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let media = Arc::new(ForkMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    let mut s = settings(REJECT);
    s.max_sessions = CALLS;
    stack.set_recording(s);
    let f = Fixture { stack, media, cdr };
    let mut ids = Vec::new();
    for i in 0..CALLS {
        let id = format!("mass-{i}@test");
        let inv = rs_invite(&answered(&f.stack, &id).await);
        srs_ok(&f.stack, &inv).await;
        ids.push(id);
    }
    poll(&f.stack).await;
    assert_eq!(f.stack.recording_counters().slots_held(), CALLS);

    // Everything ends within one tick.
    for id in &ids {
        caller_bye(&f.stack, id).await;
    }
    assert_eq!(lock_leaf(&f.stack.rs_wind_down).len(), CALLS);
    assert!(
        lock_leaf(&f.stack.deferred_sends).queue.is_empty(),
        "the shared deferred-send queue is not used"
    );
    let mut sent = 0usize;
    let mut ticks = 0usize;
    while sent < CALLS {
        let tick = poll(&f.stack).await;
        let byes = tick
            .iter()
            .filter(|r| to_srs(std::slice::from_ref(r), &Method::Bye).is_some())
            .count();
        assert!(byes <= RS_WIND_DOWN_PER_TICK, "{byes} RS BYEs in one tick");
        assert!(byes > 0, "the queue drains");
        sent += byes;
        ticks += 1;
    }
    assert_eq!(sent, CALLS, "every RS BYE is sent");
    assert_eq!(ticks, CALLS.div_ceil(RS_WIND_DOWN_PER_TICK));
    let m: HashMap<_, _> = f
        .stack
        .recording_counters()
        .metric_values()
        .into_iter()
        .collect();
    assert_eq!(m["sbc_recording_rs_bye_dropped_total"], 0, "none dropped");
    assert_eq!(m["sbc_recording_stopped_total"], CALLS as u64);
    assert_recording_released(&f).await;
}

// When the wind-down queue is full the RS BYE is dropped, and the drop is
// counted (`sbc_recording_rs_bye_dropped_total`) instead of blocking or
// growing the queue; the call itself still ends cleanly, its slot is
// released and the audit trail and CDR are complete. (The SRS then ends
// the session on its own RTP timeout.)
#[tokio::test]
async fn qa_full_wind_down_queue_drops_the_rs_bye_and_counts_it() {
    let f = fixture_with(REJECT, |s| s.max_sessions = 1).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "bp@test").await);
    srs_ok(&f.stack, &inv).await;

    // The bound: `max_sessions` plus one tick's burst.
    let cap = 1 + crate::sip_stack::recording_session::RS_WIND_DOWN_PER_TICK;
    {
        let mut q = lock_leaf(&f.stack.rs_wind_down);
        while q.len() < cap {
            q.push_back(inv.clone());
        }
    }

    let ended = caller_bye(&f.stack, "bp@test").await;
    assert!(responded(&ended, 200).is_some(), "the call still ends");
    assert_eq!(
        lock_leaf(&f.stack.rs_wind_down).len(),
        cap,
        "the queue did not grow past its bound"
    );
    let m: HashMap<_, _> = f
        .stack
        .recording_counters()
        .metric_values()
        .into_iter()
        .collect();
    assert_eq!(m["sbc_recording_rs_bye_dropped_total"], 1);
    assert_eq!(m["sbc_recording_stopped_total"], 1);
    assert_eq!(m["sbc_recording_sessions_active"], 0);
    let st = stopped(&capture.events());
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].reason, RecordingStopReason::CallEnded);
    lock_leaf(&f.stack.rs_wind_down).clear();
    assert_eq!(one_cdr(&f.cdr).recording, Some(RecordingTag::Recorded));
    assert_recording_released(&f).await;
}

// ----------------------------------------------------------------------
// Reviewer reproductions (SEC-008 / QA-001, SEC-004 / QA-002, SEC-005)
// ----------------------------------------------------------------------

// QA-001 / SEC-008 / NIST-006 (SC-8, SC-23): a response to the RS INVITE is
// taken only from the recorder's TLS flow. The same 2xx from the SRS
// address over UDP (or TCP) is dropped before the transaction layer: no
// ACK, no activation, the leg stays `Inviting`, and the genuine answer over
// TLS still works afterwards. A forged 488 cannot fail the recording.
#[tokio::test]
async fn qa_rs_2xx_over_udp_is_ignored() {
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "udp-rs@test").await);
    let ok = response_to(&inv, 200, Some("srstag"), Some(&srs_answer_sdp()));
    let refused = response_to(&inv, 488, Some("srstag"), None);
    for transport in [AddrTransport::Udp, AddrTransport::Tcp] {
        for data in [&ok, &refused] {
            let results = flatten(
                f.stack
                    .process_message_on(data, srs(), None, transport)
                    .await,
            );
            assert!(results.is_empty(), "{transport:?}: {results:?}");
        }
        assert_eq!(f.media.count("activate"), 0, "{transport:?}");
        let rec = recording_of(&f.stack, "udp-rs@test").await;
        assert_eq!(rec.leg.unwrap().state, RsState::Inviting, "{transport:?}");
        assert!(call_is_up(&f.stack, "udp-rs@test").await, "{transport:?}");
    }
    // The client transaction was not touched: the real answer is accepted.
    let results = srs_ok(&f.stack, &inv).await;
    assert!(to_srs(&results, &Method::Ack).is_some(), "{results:?}");
    assert_eq!(f.media.count("activate"), 1);
    caller_bye(&f.stack, "udp-rs@test").await;
    assert_recording_released(&f).await;
}

/// [`ForkMedia`] that yields once while starting the relay (so two copies
/// of the callee's 2xx interleave) and, like the real pipeline, refuses a
/// second `prepare_recording_fork` for the same call.
#[derive(Default)]
struct RacyMedia {
    inner: ForkMedia,
    prepared: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl MediaController for RacyMedia {
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<uc_media_engine::MediaMode>,
        a: Option<IpAddr>,
        b: Option<IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        self.inner
            .create_session_with_zones(call_id, mode, a, b)
            .await
    }
    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        self.inner
            .set_remote_address(call_id, is_a_leg, address)
            .await
    }
    async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        tokio::task::yield_now().await;
        self.inner.start_relay(call_id).await
    }
    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a: LegDtlsParams,
        b: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        self.inner.start_relay_terminate(call_id, a, b).await
    }
    async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        self.inner.stop_relay(call_id).await
    }
    async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        self.inner.remove_session(call_id).await
    }
    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        self.inner.allocate_ports().await
    }
    async fn set_media_kind(
        &self,
        call_id: &str,
        kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        self.inner.set_media_kind(call_id, kind).await
    }
    async fn prepare_recording_fork(
        &self,
        call_id: &str,
        keys: [proto_srtp::SrtpKeyMaterial; 2],
        bind_ip: Option<IpAddr>,
    ) -> Result<RecordingForkPorts, MediaPipelineError> {
        tokio::task::yield_now().await;
        if self.prepared.fetch_add(1, AtomicOrdering::SeqCst) > 0 {
            return Err(MediaPipelineError::RecordingFork(
                "already prepared".to_string(),
            ));
        }
        self.inner
            .prepare_recording_fork(call_id, keys, bind_ip)
            .await
    }
    async fn activate_recording_fork(
        &self,
        call_id: &str,
        remotes: [SocketAddr; 2],
    ) -> Result<(), MediaPipelineError> {
        self.inner.activate_recording_fork(call_id, remotes).await
    }
    async fn stop_recording_fork(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        self.inner.stop_recording_fork(call_id).await
    }
}

// QA-002 / SEC-004 (SC-24): two copies of the callee's 200 handled
// concurrently (a duplicated datagram) must not tear a recorded call down.
// The first copy claims the answer; the second is a retransmission: it is
// ACKed and starts no second recording session, fork or failure.
#[tokio::test]
async fn qa_duplicated_callee_200_does_not_tear_down_a_recorded_call() {
    let (mut stack, cdr) = cdr_stack().await;
    let media = Arc::new(RacyMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    stack.set_recording(settings(REJECT));
    let capture = uc_audit::capture::start();
    let placed = place_call(&stack, "dup@test").await;
    let b_invite = forwarded(&placed, &Method::Invite).unwrap().0.clone();
    let ok = response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP));
    let (first, second) = tokio::join!(
        stack.process_message(&ok, t1(), None),
        stack.process_message(&ok, t1(), None),
    );
    let results: Vec<ProcessResult> = flatten(first).into_iter().chain(flatten(second)).collect();

    assert!(call_is_up(&stack, "dup@test").await, "the call stays up");
    assert!(leg_byes(&results).is_empty(), "no teardown: {results:?}");
    assert!(failed(&capture.events()).is_empty(), "no recording failure");
    assert_eq!(
        results
            .iter()
            .filter(|r| responded(std::slice::from_ref(*r), 200).is_some())
            .count(),
        1,
        "the caller gets one 200: {results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| to_srs(std::slice::from_ref(*r), &Method::Invite).is_some())
            .count(),
        1,
        "one RS INVITE: {results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| forwarded(std::slice::from_ref(*r), &Method::Ack).is_some())
            .count(),
        2,
        "both copies of the 200 are ACKed: {results:?}"
    );
    assert_eq!(media.prepared.load(AtomicOrdering::SeqCst), 1, "one fork");
    assert_eq!(stack.recording_counters().slots_held(), 1);
    assert_eq!(stack.recording_counters().calls_rejected(), 0);
    assert_eq!(stack.call_correlation.read().await.rs_leg.len(), 1);
    assert!(cdrs(&cdr).is_empty(), "no CDR yet: the call is live");
}

// SEC-005 (SC-7): an SRS answer that names one of the SBC's own sockets
// (its media address with a port of its RTP range, or a SIP listener port)
// is a bad answer: the fork is never aimed back at the SBC.
#[tokio::test]
async fn qa_rs_answer_naming_an_sbc_socket_is_a_bad_answer() {
    // `settings()` advertises 192.0.2.9 as the SBC's media address.
    for (what, addr, ports, bad) in [
        ("relay port", "192.0.2.9", (40_000, 40_002), true),
        ("SIP listener", "192.0.2.9", (5060, 5061), true),
        ("one stream only", "192.0.2.9", (50_000, 40_002), true),
        ("co-located recorder", "192.0.2.9", (50_000, 50_002), false),
        ("another host", "198.51.100.7", (40_000, 40_002), false),
    ] {
        let f = fixture_with(CONTINUE, |s| s.media_ports = 40_000..=40_100).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "own@test").await);
        let sdp = srs_answer_sdp()
            .replace("198.51.100.7", addr)
            .replace("m=audio 40000", &format!("m=audio {}", ports.0))
            .replace("m=audio 40002", &format!("m=audio {}", ports.1));
        let results = from_srs(
            &f.stack,
            &response_to(&inv, 200, Some("srstag"), Some(&sdp)),
        )
        .await;
        assert!(to_srs(&results, &Method::Ack).is_some(), "{what}: ACKed");
        let fails = failed(&capture.events());
        if bad {
            assert_eq!(f.media.count("activate"), 0, "{what}: never activated");
            assert_eq!(fails.len(), 1, "{what}");
            assert_eq!(fails[0].reason, RecordingFailReason::SrsBadAnswer, "{what}");
            assert!(
                to_srs(&poll(&f.stack).await, &Method::Bye).is_some(),
                "{what}: RS BYE"
            );
        } else {
            assert_eq!(f.media.count("activate"), 1, "{what}");
            assert!(fails.is_empty(), "{what}");
        }
    }
    // SEC-005 residual (fix round 2): an unzoned relay binds the wildcard
    // address, so an address of any local interface (learned at startup),
    // configured or not, is the SBC's own. Same port rule.
    for (what, ports, bad) in [
        ("interface address, relay port", (40_000, 40_002), true),
        ("interface address, SIP listener", (5060, 50_002), true),
        (
            "interface address, recorder's own ports",
            (50_000, 50_002),
            false,
        ),
    ] {
        let f = fixture_with(CONTINUE, |s| {
            s.media_ports = 40_000..=40_100;
            // Sorted, as `sbc_config::interface::local_addresses` returns.
            s.local_addrs = vec![
                "198.51.100.7".parse().unwrap(),
                "2001:db8::7".parse().unwrap(),
            ];
        })
        .await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "own-if@test").await);
        let sdp = srs_answer_sdp()
            .replace("m=audio 40000", &format!("m=audio {}", ports.0))
            .replace("m=audio 40002", &format!("m=audio {}", ports.1));
        from_srs(
            &f.stack,
            &response_to(&inv, 200, Some("srstag"), Some(&sdp)),
        )
        .await;
        let fails = failed(&capture.events());
        if bad {
            assert_eq!(f.media.count("activate"), 0, "{what}: never activated");
            assert_eq!(fails.len(), 1, "{what}");
            assert_eq!(fails[0].reason, RecordingFailReason::SrsBadAnswer, "{what}");
        } else {
            assert_eq!(f.media.count("activate"), 1, "{what}");
            assert!(fails.is_empty(), "{what}");
        }
    }
    // Until the daemon sets the real range every port of an SBC address is
    // refused (fail closed).
    let f = fixture(CONTINUE).await;
    let inv = rs_invite(&answered(&f.stack, "own-default@test").await);
    let sdp = srs_answer_sdp().replace("198.51.100.7", "192.0.2.9");
    from_srs(
        &f.stack,
        &response_to(&inv, 200, Some("srstag"), Some(&sdp)),
    )
    .await;
    assert_eq!(f.media.count("activate"), 0);
}
