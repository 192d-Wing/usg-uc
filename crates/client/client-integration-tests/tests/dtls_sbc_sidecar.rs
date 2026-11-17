//! The soft client's media stack through the SBC's DTLS-SRTP termination,
//! for longer than a handshake (POA&M-324, review finding RFC-001).
//!
//! One call, two soft-client media stacks, the real SBC media path between
//! them:
//!
//! ```text
//! client A (DTLS client) <-> SBC leg A (DTLS server) --+
//!                                                      | sbc-media-core relay:
//! client B (DTLS server) <-> SBC leg B (DTLS client) --+ decrypt, re-encrypt
//! ```
//!
//! Each client side is what a call uses: `MediaSession::begin_secure` and
//! the DTLS driver task for the handshake, then `client-audio`'s
//! `RtpTransmitter`, `RtpReceiver` (rtcp-mux, DTLS forward sink) and
//! `RtcpSession` on the same socket. The SBC side is
//! `MediaPipeline::start_relay_terminate` with the real `dtls-terminator`
//! sidecar binary, so both DTLS roles of the sidecar are exercised in one
//! call.
//!
//! What the test proves:
//!
//! - both handshakes complete, and SRTP and SRTCP of each client reach the
//!   other through the SBC, with no SRTP or SRTCP error on either side;
//! - the associations stay up: for more than two seconds of media no side
//!   reports the association closed. The client treats `close_notify` as
//!   the end of its audio, so an SBC that closed the association after the
//!   handshake (what the sidecar did before RFC-001 was fixed) fails here;
//! - a client's media objects are rebuilt mid-call from the same keys, as
//!   an audio pipeline restart does (re-INVITE, hold and resume), after
//!   the client's stream has wrapped its sequence number; media still
//!   crosses the SBC in both directions afterwards, with the same SSRC
//!   (review finding RFC-011: the SBC leg has one SRTP context for the
//!   association, RFC 3711 §3.2.3);
//! - when the SBC ends the call (`stop_relay`), both clients are told with
//!   `close_notify`, which reaches the client's driver through the audio
//!   receiver's DTLS forward sink.
//!
//! Not proven here: SIP signalling, the `AudioPipeline` with real devices.
//!
//! The test is in this crate because it needs `sbc-media-core`; see the
//! note in this crate's `Cargo.toml`.
//!
//! `#[ignore]`d because it needs the Go sidecar binary. To run:
//!
//! ```text
//! (cd sidecar/dtls-terminator && GOFIPS140=v1.26.0 go build -o /tmp/dtls-terminator ./cmd/dtls-terminator)
//! SIDECAR_BIN=/tmp/dtls-terminator cargo test -p client-integration-tests --test dtls_sbc_sidecar -- --ignored --nocapture
//! ```
// NIST 800-53 Rev5: SA-11 (end-to-end evidence), SC-8(1), SC-23.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use client_audio::{
    DtlsSink, JitterBufferResult, RtcpSession, RtpReceiver, RtpTransmitter, SharedJitterBuffer,
    SrtpCallState, SrtpProfile, SrtpSessionKeys, build_srtp_contexts,
};
use client_sip_ua::sdp_dtls::{DtlsSdpParams, Setup};
use client_sip_ua::{
    DriverTimings, DtlsIdentity, DtlsRole, DtlsSrtpProfile, MediaSession, MediaSessionEvent,
    SecureProgress, SecurityCause,
};
use proto_dtls::CertificateFingerprint;
use proto_ice::IceConfig;
use sbc_media_core::dtls_identity::DtlsFingerprintSource;
use sbc_media_core::dtls_sidecar::Role;
use sbc_media_core::media_pipeline::{LegDtlsParams, MediaPipeline, MediaPipelineConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long the call is held with media flowing before anything is ended.
/// The client gives a peer one second after `close_notify` before it fails
/// the call, so this is well past the point where the defect showed.
const HOLD: Duration = Duration::from_millis(2500);
/// How long media is watched after the mid-call restart of both clients'
/// media objects.
const AFTER_RESTART: Duration = Duration::from_millis(1500);
/// The first sequence number of each client's stream: 32 packets (0.64 s)
/// before the 16-bit wrap, so the restart happens with a rollover counter
/// of one on the SBC's leg.
const FIRST_SEQUENCE: u16 = 0xFFE0;
/// One RTP packet per 20 ms, as the audio thread sends.
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// What one client's media objects have seen so far.
#[derive(Debug, Default, Clone, Copy)]
struct MediaStats {
    rtp_sent: u64,
    /// Peer SRTP packets authenticated and decrypted.
    rtp_received: u64,
    /// Of those, packets carrying the other client's payload.
    payload_matches: u64,
    srtp_errors: u64,
    rtcp_handled: u64,
    srtcp_errors: u64,
    rtcp_dropped: u64,
    dtls_dropped: u64,
    dtls_forwarded: u64,
    non_media_dropped: u64,
    /// Times the media objects were rebuilt from the call's keys.
    restarts: u64,
}

/// One soft-client media stack: session and driver on the async side, the
/// media objects on a thread of their own, as the audio I/O thread is.
struct Client {
    name: &'static str,
    session: MediaSession,
    socket: Option<UdpSocket>,
    ssrc: u32,
    /// Byte this client fills its RTP payload with.
    fill: u8,
    stats: Arc<Mutex<MediaStats>>,
    stop: Arc<AtomicBool>,
    /// Asks the media thread to rebuild its media objects once.
    restart: Arc<AtomicBool>,
    media: Option<std::thread::JoinHandle<()>>,
    _events: mpsc::Receiver<MediaSessionEvent>,
}

impl Client {
    fn new(name: &'static str, role: DtlsRole, ssrc: u32, fill: u8) -> (Self, DtlsIdentity) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let identity = DtlsIdentity::generate().unwrap();
        let (events_tx, events) = mpsc::channel::<MediaSessionEvent>(32);
        let session = MediaSession::new(
            local,
            role == DtlsRole::Client,
            IceConfig::default(),
            socket.try_clone().unwrap(),
            &identity,
            events_tx,
        );
        let client = Self {
            name,
            session,
            socket: Some(socket),
            ssrc,
            fill,
            stats: Arc::default(),
            stop: Arc::default(),
            restart: Arc::default(),
            media: None,
            _events: events,
        };
        (client, identity)
    }

    fn local(&self) -> SocketAddr {
        self.socket.as_ref().unwrap().local_addr().unwrap()
    }

    /// Starts the handshake towards the SBC leg at `sbc`, whose certificate
    /// must match `sbc_fingerprint`.
    async fn begin(&mut self, role: DtlsRole, sbc: SocketAddr, sbc_fingerprint: &str) {
        self.session.set_remote_addr(sbc);
        self.session.set_dtls_role(role).unwrap();
        let remote = DtlsSdpParams {
            fingerprints: vec![CertificateFingerprint::from_sdp_strict(sbc_fingerprint).unwrap()],
            // The SBC's side of the answer: the opposite of our role.
            setup: if role == DtlsRole::Client {
                Setup::Passive
            } else {
                Setup::Active
            },
        };
        self.session
            .begin_secure(self.name, &remote, DriverTimings::default())
            .await
            .unwrap();
    }

    async fn await_ready(&mut self) {
        let started = Instant::now();
        let progress = loop {
            match self.session.poll_secure() {
                SecureProgress::Pending if started.elapsed() < Duration::from_secs(12) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => break other,
            }
        };
        assert_eq!(
            progress,
            SecureProgress::Ready,
            "{}: handshake with the SBC",
            self.name
        );
    }

    /// The handoff of `CallManager::start_audio_session`: keys into the audio
    /// key type, the session lets go of the socket, the receiver gets the
    /// DTLS sink, and the media objects run on their own thread.
    fn start_media(&mut self, sbc: SocketAddr, peer_fill: u8) {
        let (profile, tx_key, tx_salt, rx_key, rx_salt) =
            self.session.negotiated_srtp_keys().unwrap().into_parts();
        let profile = match profile {
            DtlsSrtpProfile::AeadAes256Gcm => SrtpProfile::AeadAes256Gcm,
        };
        // As `CallManager::with_srtp_call_state`: the call's SRTP state
        // goes with the keys, so a restart continues both directions.
        let keys = SrtpSessionKeys::new(profile, tx_key, tx_salt, rx_key, rx_salt)
            .with_call_state(SrtpCallState::new().unwrap());

        self.session.release_socket();
        let dtls_remote = self.session.dtls_remote().unwrap();
        assert_eq!(dtls_remote, sbc);
        // One forward ring for the call; each set of media objects gets a
        // sink onto it (the test's stand-in for re-attaching a ring).
        let forward = Arc::new(Mutex::new(
            self.session.dtls_forward_tx().expect("forward ring"),
        ));
        let dtls_sink = move || -> DtlsSink {
            let forward = Arc::clone(&forward);
            Box::new(move |datagram: &[u8]| forward.lock().unwrap().try_forward(datagram))
        };

        let socket = self.socket.take().unwrap();
        let (ssrc, fill) = (self.ssrc, self.fill);
        let (stats, stop) = (Arc::clone(&self.stats), Arc::clone(&self.stop));
        let restart = Arc::clone(&self.restart);
        let run = MediaRun {
            socket,
            sbc,
            keys,
            ssrc,
            fill,
            peer_fill,
            dtls_sink: Box::new(dtls_sink),
            dtls_remote,
            stats,
            stop,
            restart,
        };
        self.media = Some(std::thread::spawn(move || run.run()));
    }

    /// Has the media thread drop its transmitter, receiver and RTCP session
    /// and build new ones from the call's keys, and waits until it has.
    async fn restart_media(&self) {
        let before = self.stats().restarts;
        self.restart.store(true, Ordering::Relaxed);
        let started = Instant::now();
        while self.stats().restarts == before {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{}: the media thread did not restart",
                self.name
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn stats(&self) -> MediaStats {
        *self.stats.lock().unwrap()
    }

    /// Waits until the driver reports the end of the association.
    async fn await_closed(&mut self, limit: Duration) -> Option<SecurityCause> {
        let started = Instant::now();
        loop {
            if let Some(cause) = self.session.poll_security_closed() {
                return Some(cause);
            }
            if started.elapsed() >= limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn finish(mut self) -> MediaStats {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(media) = self.media.take() {
            media.join().unwrap();
        }
        self.session.close().await.unwrap();
        self.stats()
    }
}

/// What one client's media thread works with.
struct MediaRun {
    socket: UdpSocket,
    /// The SBC leg this client sends to and receives from.
    sbc: SocketAddr,
    keys: SrtpSessionKeys,
    ssrc: u32,
    fill: u8,
    /// Byte the other client fills its RTP payload with.
    peer_fill: u8,
    /// Makes a DTLS sink for one set of media objects.
    dtls_sink: Box<dyn Fn() -> DtlsSink + Send>,
    dtls_remote: SocketAddr,
    stats: Arc<Mutex<MediaStats>>,
    stop: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
}

impl MediaRun {
    /// Transmitter, receiver and RTCP session on the socket the way the audio
    /// I/O thread runs them (blocking reads with a short timeout), until
    /// `stop`. On `restart` the three are dropped and built again from the
    /// call's keys, as `AudioPipeline::start` builds them after a stop.
    fn run(self) {
        // As `client_audio::pipeline::prepare_media_socket` does at handoff: the
        // handshake left the shared socket non-blocking.
        self.socket.set_nonblocking(false).unwrap();
        self.socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let socket = Arc::new(self.socket.try_clone().unwrap());
        let mut done = MediaStats::default();
        let mut stream_ssrc = None;
        loop {
            let finished = self.run_media_objects(&socket, &mut stream_ssrc, done);
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            done = MediaStats {
                restarts: finished.restarts + 1,
                ..finished
            };
            self.restart.store(false, Ordering::Relaxed);
            *self.stats.lock().unwrap() = done;
        }
    }

    /// One set of media objects, until `stop` or `restart`. `done` is what
    /// earlier sets of this call counted; the returned totals include it.
    fn run_media_objects(
        &self,
        socket: &Arc<UdpSocket>,
        stream_ssrc: &mut Option<u32>,
        done: MediaStats,
    ) -> MediaStats {
        let (sbc, keys) = (self.sbc, &self.keys);
        let first_ssrc = if done.restarts == 0 {
            self.ssrc
        } else {
            keys.transmit_ssrc().unwrap()
        };
        let contexts = build_srtp_contexts(keys, first_ssrc).unwrap();
        let ssrc = contexts.local_ssrc;
        // RFC 3711 §3.2.3: one SSRC for the call, and every set after the
        // first continues the stream.
        assert_eq!(*stream_ssrc.get_or_insert(ssrc), ssrc, "SSRC changed");
        assert_eq!(contexts.tx_resume.is_some(), done.restarts > 0);
        let mut transmitter = RtpTransmitter::new(Arc::clone(socket), sbc, ssrc, 0, 160);
        if done.restarts == 0 {
            transmitter.continue_stream(FIRST_SEQUENCE, None);
        }
        transmitter.start_srtp(
            contexts.rtp_tx,
            contexts.tx_resume,
            contexts.tx_claim,
            keys.call_state(),
            8000,
        );
        let jitter_buffer = SharedJitterBuffer::new(8000, 160, 60);
        let mut receiver = RtpReceiver::new(Arc::clone(socket), jitter_buffer.clone());
        receiver.set_expected_remote(sbc);
        receiver.set_rtcp_mux(true);
        receiver.set_srtp(contexts.rtp_rx);
        receiver.set_dtls_sink((self.dtls_sink)(), self.dtls_remote);
        let mut rtcp = RtcpSession::new(
            Arc::clone(socket),
            sbc,
            ssrc,
            8000,
            "sbc-e2e@client.invalid".to_string(),
        );
        rtcp.set_rtcp_mux(true);
        rtcp.set_srtcp(contexts.rtcp_tx, contexts.rtcp_rx);

        let payload = [self.fill; 160];
        let peer_payload = [self.peer_fill; 160];
        let mut next_send = Instant::now();
        let (mut sent, mut rtcp_handled, mut payload_matches) = (0u64, 0u64, 0u64);
        let mut totals = done;
        while !self.stop.load(Ordering::Relaxed) && !self.restart.load(Ordering::Relaxed) {
            if Instant::now() >= next_send {
                transmitter.send(&payload).unwrap();
                sent += 1;
                next_send += PACKET_INTERVAL;
                // One SRTCP compound report per second of media, and one
                // early in each set so that every set sends SRTCP.
                if sent % 50 == 10 {
                    rtcp.send_report(&transmitter.stats(), &receiver.jitter_buffer_stats());
                }
            }
            let _ = receiver.receive().unwrap();
            if let Some((data, from)) = receiver.take_muxed_rtcp() {
                rtcp.handle_packet(data, from);
                rtcp_handled += 1;
            }
            while let JitterBufferResult::Packet(packet) = jitter_buffer.pop() {
                if packet.payload.as_ref() == peer_payload {
                    payload_matches += 1;
                }
            }
            let stats = receiver.stats();
            totals = MediaStats {
                rtp_sent: done.rtp_sent + transmitter.stats().packets_sent,
                rtp_received: done.rtp_received + stats.packets_received,
                payload_matches: done.payload_matches + payload_matches,
                srtp_errors: done.srtp_errors + stats.srtp_errors,
                rtcp_handled: done.rtcp_handled + rtcp_handled,
                srtcp_errors: done.srtcp_errors + rtcp.srtcp_errors(),
                rtcp_dropped: done.rtcp_dropped + rtcp.rtcp_dropped(),
                dtls_dropped: done.dtls_dropped + stats.dtls_dropped,
                dtls_forwarded: done.dtls_forwarded + stats.dtls_forwarded,
                non_media_dropped: done.non_media_dropped + stats.non_media_dropped,
                restarts: done.restarts,
            };
            *self.stats.lock().unwrap() = totals;
        }
        totals
    }
}

/// Starts the sidecar (it refuses to run outside the FIPS module) and waits
/// for its fingerprint file and socket.
async fn spawn_sidecar(uds: &Path, fp_file: &Path) -> (tokio::process::Child, String) {
    let bin = std::env::var("SIDECAR_BIN").expect(
        "SIDECAR_BIN must point at the built sidecar \
         (cd sidecar/dtls-terminator && GOFIPS140=v1.26.0 go build -o /tmp/dtls-terminator ./cmd/dtls-terminator)",
    );
    let child = tokio::process::Command::new(bin)
        .args([
            "-socket",
            uds.to_str().unwrap(),
            "-fingerprint-file",
            fp_file.to_str().unwrap(),
        ])
        .env("GODEBUG", "fips140=on")
        .kill_on_drop(true)
        .spawn()
        .expect("spawn SIDECAR_BIN");
    for _ in 0..200 {
        if let Ok(fingerprint) = std::fs::read_to_string(fp_file)
            && !fingerprint.trim().is_empty()
            && uds.exists()
        {
            return (child, fingerprint.trim().to_string());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the sidecar never published a fingerprint");
}

/// Media crossed the SBC to this client, with nothing wrong on the way.
fn assert_media(name: &str, stats: &MediaStats, at_least: u64) {
    assert_eq!(stats.srtp_errors, 0, "{name}: {stats:?}");
    assert_eq!(stats.srtcp_errors, 0, "{name}: {stats:?}");
    assert_eq!(stats.rtcp_dropped, 0, "{name}: {stats:?}");
    assert!(stats.rtp_sent >= at_least, "{name}: {stats:?}");
    assert!(stats.rtp_received >= at_least, "{name}: {stats:?}");
    assert!(stats.payload_matches >= 1, "{name}: {stats:?}");
    assert!(stats.rtcp_handled >= 1, "{name}: {stats:?}");
    // RFC 7983: nothing of the DTLS class was thrown away, and nothing
    // unclassifiable arrived.
    assert_eq!(stats.dtls_dropped, 0, "{name}: {stats:?}");
    assert_eq!(stats.non_media_dropped, 0, "{name}: {stats:?}");
}

/// RFC-011: both clients rebuild their media objects from the call's keys,
/// as an audio pipeline restart does. Each stream started 32 packets before
/// its sequence wrap, so the SBC legs have counted one rollover by now;
/// media must go on crossing in both directions. `held_*` are the clients'
/// counts before the restart.
async fn restart_media_and_check(
    a: &mut Client,
    b: &mut Client,
    held_a: &MediaStats,
    held_b: &MediaStats,
) {
    a.restart_media().await;
    b.restart_media().await;
    let restarted = Instant::now();
    while restarted.elapsed() < AFTER_RESTART {
        for client in [&mut *a, &mut *b] {
            assert_eq!(
                client.session.poll_security_closed(),
                None,
                "{}: association closed after the restart",
                client.name
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (again_a, again_b) = (a.stats(), b.stats());
    eprintln!("after the restart: A {again_a:?}; B {again_b:?}");
    for (name, before, after) in [
        ("client-a", held_a, &again_a),
        ("client-b", held_b, &again_b),
    ] {
        assert_eq!(after.restarts, 1, "{name}: {after:?}");
        assert_media(name, after, 60);
        // 1.5 s at 50 packets per second is 75; SRTP and SRTCP of the
        // restarted peer both arrive.
        assert!(
            after.rtp_received >= before.rtp_received + 35,
            "{name}: media did not cross the SBC after the restart: {before:?} -> {after:?}"
        );
        assert!(
            after.payload_matches >= before.payload_matches + 20,
            "{name}: {before:?} -> {after:?}"
        );
        assert!(
            after.rtcp_handled > before.rtcp_handled,
            "{name}: no SRTCP after the restart: {before:?} -> {after:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Go sidecar: build sidecar/dtls-terminator and set SIDECAR_BIN (see file header)"]
async fn call_through_the_sbc_stays_up_and_ends_with_close_notify() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("dtls.sock");
    let fp_file = dir.path().join("dtls.fp");
    let (mut sidecar, sbc_fp) = spawn_sidecar(&uds, &fp_file).await;

    // The SBC media path in terminate mode.
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let port_base = 34_000_u16 + (u16::try_from(std::process::id() % 2_000).unwrap() & !1);
    let pipeline = MediaPipeline::new(MediaPipelineConfig {
        srtp_required: false,
        terminate_dtls: true,
        dtls_sidecar_socket: Some(uds.clone()),
        dtls_fingerprint: Some(Arc::new(DtlsFingerprintSource::from_static(sbc_fp.clone()))),
        rtp_port_min: port_base,
        rtp_port_max: port_base + 200,
        ..Default::default()
    });
    let ports = pipeline
        // No explicit mode: the pipeline's default, which is relay.
        .create_session_with_zones("call", None, Some(loopback), Some(loopback))
        .await
        .unwrap();
    let sbc_a = SocketAddr::new(loopback, ports.a_leg_rtp_port);
    let sbc_b = SocketAddr::new(loopback, ports.b_leg_rtp_port);

    // A is the DTLS client of its leg (the usual case for a client that
    // answers an `actpass` offer), B the DTLS server of its leg.
    let (mut a, a_identity) = Client::new("client-a", DtlsRole::Client, 0x000A_11CE, 0xA5);
    let (mut b, b_identity) = Client::new("client-b", DtlsRole::Server, 0x0000_0B0B, 0x5A);

    pipeline
        .set_remote_address("call", true, a.local().into())
        .await
        .unwrap();
    pipeline
        .set_remote_address("call", false, b.local().into())
        .await
        .unwrap();
    pipeline
        .start_relay_terminate(
            "call",
            LegDtlsParams {
                peer_fingerprint: a_identity.fingerprint().to_sdp(),
                role: Role::Server,
            },
            LegDtlsParams {
                peer_fingerprint: b_identity.fingerprint().to_sdp(),
                role: Role::Client,
            },
        )
        .await
        .unwrap();

    a.begin(DtlsRole::Client, sbc_a, &sbc_fp).await;
    b.begin(DtlsRole::Server, sbc_b, &sbc_fp).await;
    a.await_ready().await;
    b.await_ready().await;
    let connected = Instant::now();
    a.start_media(sbc_a, 0x5A);
    b.start_media(sbc_b, 0xA5);

    // Hold the call. Nothing may end either association.
    while connected.elapsed() < HOLD {
        for client in [&mut a, &mut b] {
            let closed = client.session.poll_security_closed();
            assert_eq!(
                closed,
                None,
                "{}: the SBC ended the DTLS association {:?} into the call",
                client.name,
                connected.elapsed()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a.session.is_ready() && b.session.is_ready());
    let (held_a, held_b) = (a.stats(), b.stats());
    eprintln!("after {HOLD:?}: A {held_a:?}; B {held_b:?}");
    // 2.5 s at 50 packets per second is 125; half of that leaves room for
    // the SBC's own start-up and a loaded runner.
    assert_media("client-a", &held_a, 60);
    assert_media("client-b", &held_b, 60);

    restart_media_and_check(&mut a, &mut b, &held_a, &held_b).await;

    // The SBC ends the call: both clients are told with close_notify. Their
    // media threads are still running, so the alert takes the path it takes
    // in a call: audio receiver, DTLS forward sink, driver.
    pipeline.stop_relay("call").await.unwrap();
    let closed_a = a.await_closed(Duration::from_secs(3)).await;
    let closed_b = b.await_closed(Duration::from_secs(3)).await;
    assert_eq!(closed_a, Some(SecurityCause::ClosedByPeer), "client-a");
    assert_eq!(closed_b, Some(SecurityCause::ClosedByPeer), "client-b");

    let (end_a, end_b) = (a.finish().await, b.finish().await);
    eprintln!("at the end: A {end_a:?}; B {end_b:?}");
    assert!(end_a.dtls_forwarded >= 1, "client-a: {end_a:?}");
    assert!(end_b.dtls_forwarded >= 1, "client-b: {end_b:?}");
    assert_eq!(end_a.srtp_errors + end_b.srtp_errors, 0);
    assert_eq!(end_a.dtls_dropped + end_b.dtls_dropped, 0);

    let _ = sidecar.kill().await;
}
