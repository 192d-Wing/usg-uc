//! Interop: the soft client's media stack against pion, in both DTLS roles
//! (POA&M-324).
//!
//! Our side is what a call uses: `MediaSession::begin_secure` and the DTLS
//! driver task for the handshake, then, on the *same* socket after the
//! handoff, `client-audio`'s `RtpTransmitter`, `RtpReceiver` (rtcp-mux,
//! with the DTLS forward sink installed) and `RtcpSession`, keyed from the
//! exported material exactly as the call manager keys the audio pipeline.
//!
//! The peer is `sidecar/srtp-test-peer`: the same pion/dtls configuration
//! as the SBC's DTLS sidecar, followed by pion/srtp. It sends 50 SRTP
//! packets and 5 SRTCP reports and counts what it can decrypt of ours.
//!
//! What each test proves:
//!
//! - the handshake completes against pion through the client's driver, with
//!   the CNSA 2.0 profile only, in the given role; with pion as DTLS client
//!   its `ClientHello` is on the wire before our association exists
//!   (RFC 5763 §5) and the handshake still completes;
//! - **pion -> us**: the client's receiver authenticates and decrypts
//!   pion's SRTP with no SRTP error, and its RTCP session does the same
//!   for pion's SRTCP arriving on the RTP port (RFC 5761);
//! - **us -> pion**: pion decrypts the SRTP our transmitter sent and the
//!   two SRTCP compound packets our RTCP session sent (SRTCP index 0 and
//!   1);
//! - nothing of the DTLS class was dropped by the receiver.
//!
//! Not proven here: the `AudioPipeline` with real devices, the SBC relay
//! path, non-pion peers.
//!
//! `#[ignore]`d because it needs the Go binary. To run:
//!
//! ```text
//! (cd sidecar/srtp-test-peer && go build -o /tmp/srtp-test-peer .)
//! PEER_BIN=/tmp/srtp-test-peer cargo test -p client-core --test dtls_interop_pion -- --ignored --nocapture
//! ```
// NIST 800-53 Rev5: SA-11 (interop evidence), SC-8(1), SC-23.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use client_audio::{
    DtlsSink, RtcpSession, RtpReceiver, RtpTransmitter, SharedJitterBuffer, SrtpProfile,
    SrtpSessionKeys, build_srtp_contexts,
};
use client_sip_ua::sdp_dtls::{DtlsSdpParams, Setup};
use client_sip_ua::{
    DriverTimings, DtlsIdentity, DtlsRole, DtlsSrtpProfile, MediaSession, MediaSessionEvent,
    SecureProgress,
};
use proto_dtls::CertificateFingerprint;
use proto_ice::IceConfig;
use std::net::{SocketAddr, UdpSocket};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;

/// SSRC the peer sends with (`-ssrc`), and the payload of its RTP packets
/// (`sidecar/srtp-test-peer/peer.go`).
const PEER_SSRC: u32 = 0x1234;
const PEER_PAYLOAD: &[u8] = b"SBC-DTLS-SRTP-terminate-audio-frame";
/// RTP packets the peer sends (`-count`); it adds one SRTCP report per ten.
const PEER_RTP: u64 = 50;
const PEER_RTCP: usize = 5;
/// What we send to the peer: 20 SRTP packets and two SRTCP compound
/// packets from the same RTCP session (SR + SDES, then SR + SDES + BYE),
/// so that pion has to accept an SRTCP index that advanced (0, then 1) and
/// not only the first packet of a context (NIST-009).
const OUR_SSRC: u32 = 0x00C0_FFEE;
const OUR_RTP: usize = 20;
const OUR_RTCP: usize = 2;

const fn opposite(role: DtlsRole) -> DtlsRole {
    match role {
        DtlsRole::Client => DtlsRole::Server,
        DtlsRole::Server => DtlsRole::Client,
    }
}

/// A running `srtp-test-peer` (spawn and parse logic as in
/// `proto-dtls/tests/interop_pion.rs`; tests of different crates cannot
/// share it).
struct Peer {
    child: Child,
    stdout: BufReader<ChildStdout>,
    fingerprint: CertificateFingerprint,
    addr: SocketAddr,
}

/// The peer's own summary line.
#[derive(Debug, Default, PartialEq, Eq)]
struct PeerResult {
    sent: usize,
    received: usize,
    rtcp_sent: usize,
    rtcp_received: usize,
    profile: usize,
}

impl Peer {
    /// Starts the peer in `role`, pointed at `remote`, expecting a
    /// certificate with `expect` as fingerprint. Reads its `FINGERPRINT`
    /// and `LOCAL` lines.
    async fn spawn(role: DtlsRole, remote: SocketAddr, expect: &CertificateFingerprint) -> Self {
        let bin = std::env::var("PEER_BIN").expect(
            "PEER_BIN must point at the built sidecar/srtp-test-peer binary \
             (cd sidecar/srtp-test-peer && go build -o /tmp/srtp-test-peer .)",
        );
        let mut child = Command::new(bin)
            .args([
                "-role",
                if role == DtlsRole::Client {
                    "client"
                } else {
                    "server"
                },
                "-remote",
                &remote.to_string(),
                "-peer-fp",
                &expect.to_sdp(),
                "-count",
                &PEER_RTP.to_string(),
                "-ssrc",
                &PEER_SSRC.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn PEER_BIN");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let (mut fingerprint, mut addr) = (None, None);
        let read = async {
            let mut line = String::new();
            while fingerprint.is_none() || addr.is_none() {
                line.clear();
                assert_ne!(
                    stdout.read_line(&mut line).await.unwrap(),
                    0,
                    "peer exited early"
                );
                if let Some(value) = line.strip_prefix("FINGERPRINT ") {
                    fingerprint =
                        Some(CertificateFingerprint::from_sdp_strict(value.trim()).unwrap());
                } else if let Some(value) = line.strip_prefix("LOCAL ") {
                    addr = Some(value.trim().parse().unwrap());
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("peer did not print FINGERPRINT and LOCAL");
        Self {
            child,
            stdout,
            fingerprint: fingerprint.unwrap(),
            addr: addr.unwrap(),
        }
    }

    /// Waits for the peer to exit. Returns whether it exited 0, its
    /// `RESULT` line if it printed one, and its stderr.
    async fn finish(mut self) -> (bool, Option<PeerResult>, String) {
        let status = tokio::time::timeout(Duration::from_secs(40), self.child.wait())
            .await
            .expect("peer did not exit")
            .unwrap();
        let mut out = String::new();
        self.stdout.read_to_string(&mut out).await.unwrap();
        let mut err = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            stderr.read_to_string(&mut err).await.unwrap();
        }
        let result = out
            .lines()
            .find_map(|line| line.strip_prefix("RESULT "))
            .map(|fields| {
                let mut result = PeerResult::default();
                for field in fields.split_whitespace() {
                    let (name, value) = field.split_once('=').unwrap();
                    let value = value.parse().unwrap();
                    match name {
                        "sent" => result.sent = value,
                        "received" => result.received = value,
                        "rtcp_sent" => result.rtcp_sent = value,
                        "rtcp_received" => result.rtcp_received = value,
                        "profile" => result.profile = value,
                        other => panic!("unknown RESULT field {other}"),
                    }
                }
                result
            });
        (status.success(), result, err)
    }
}

/// What the client's media objects saw and did on the shared socket.
#[derive(Debug)]
struct MediaOutcome {
    /// Peer SRTP packets authenticated, decrypted and buffered.
    rtp_received: u64,
    /// Buffered packets whose payload is the one the peer sends.
    payload_matches: u64,
    srtp_errors: u64,
    /// Peer SRTCP datagrams handed to the RTCP session.
    rtcp_handled: usize,
    srtcp_errors: u64,
    rtcp_dropped: u64,
    dtls_dropped: u64,
    dtls_forwarded: u64,
    non_media_dropped: u64,
    rtp_sent: u64,
}

/// Runs transmitter, receiver and RTCP session on `socket` the way the
/// audio I/O thread does (blocking reads with a short timeout), until the
/// peer's media has arrived or `limit` is over.
fn exchange_media(
    socket: UdpSocket,
    peer: SocketAddr,
    keys: &SrtpSessionKeys,
    dtls_sink: DtlsSink,
    dtls_remote: SocketAddr,
    limit: Duration,
) -> MediaOutcome {
    // As `client_audio::pipeline::prepare_media_socket` does at handoff:
    // the handshake left the shared socket non-blocking.
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let socket = Arc::new(socket);

    let contexts = build_srtp_contexts(keys, OUR_SSRC).unwrap();
    let mut transmitter = RtpTransmitter::new(Arc::clone(&socket), peer, OUR_SSRC, 0, 160);
    transmitter.set_srtp(contexts.rtp_tx);
    let jitter_buffer = SharedJitterBuffer::new(8000, 160, 60);
    let mut receiver = RtpReceiver::new(Arc::clone(&socket), jitter_buffer.clone());
    receiver.set_expected_remote(peer);
    receiver.set_rtcp_mux(true);
    receiver.set_srtp(contexts.rtp_rx);
    receiver.set_dtls_sink(dtls_sink, dtls_remote);
    let mut rtcp = RtcpSession::new(
        Arc::clone(&socket),
        peer,
        OUR_SSRC,
        8000,
        "interop@client.invalid".to_string(),
    );
    rtcp.set_rtcp_mux(true);
    rtcp.set_srtcp(contexts.rtcp_tx, contexts.rtcp_rx);

    let payload = [0xA5u8; 160];
    let deadline = Instant::now() + limit;
    let (mut sent, mut rtcp_handled, mut payload_matches) = (0usize, 0usize, 0u64);
    let mut bye_sent = false;
    loop {
        if sent < OUR_RTP {
            transmitter.send(&payload).unwrap();
            sent += 1;
        } else if !bye_sent {
            // Two SRTCP compound packets under one context: a report
            // (SRTCP index 0), then the report with BYE (index 1).
            rtcp.send_report(&transmitter.stats(), &receiver.jitter_buffer_stats());
            rtcp.send_bye(&transmitter.stats(), &receiver.jitter_buffer_stats());
            bye_sent = true;
        }
        let _ = receiver.receive().unwrap();
        if let Some((data, from)) = receiver.take_muxed_rtcp() {
            rtcp.handle_packet(data, from);
            rtcp_handled += 1;
        }
        while let client_audio::JitterBufferResult::Packet(packet) = jitter_buffer.pop() {
            if packet.payload.as_ref() == PEER_PAYLOAD {
                payload_matches += 1;
            }
        }
        let stats = receiver.stats();
        let complete = bye_sent && stats.packets_received >= PEER_RTP && rtcp_handled >= PEER_RTCP;
        if complete || Instant::now() >= deadline {
            return MediaOutcome {
                rtp_received: stats.packets_received,
                payload_matches,
                srtp_errors: stats.srtp_errors,
                rtcp_handled,
                srtcp_errors: rtcp.srtcp_errors(),
                rtcp_dropped: rtcp.rtcp_dropped(),
                dtls_dropped: stats.dtls_dropped,
                dtls_forwarded: stats.dtls_forwarded,
                non_media_dropped: stats.non_media_dropped,
                rtp_sent: transmitter.stats().packets_sent,
            };
        }
    }
}

/// Handshake against pion through the client's media session and driver,
/// then SRTP and SRTCP in both directions on the same socket.
async fn interoperates(ours: DtlsRole) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = socket.local_addr().unwrap();
    let identity = DtlsIdentity::generate().unwrap();
    let (events_tx, _events) = mpsc::channel::<MediaSessionEvent>(32);
    let mut session = MediaSession::new(
        local,
        ours == DtlsRole::Client,
        IceConfig::default(),
        socket.try_clone().unwrap(),
        &identity,
        events_tx,
    );

    // The peer learns our address and fingerprint as it would from SDP. In
    // client role it sends its ClientHello at once, before our association
    // exists.
    let peer = Peer::spawn(opposite(ours), local, identity.fingerprint()).await;
    if ours == DtlsRole::Server {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let started = Instant::now();
    session.set_remote_addr(peer.addr);
    session.set_dtls_role(ours).unwrap();
    let remote = DtlsSdpParams {
        fingerprints: vec![peer.fingerprint.clone()],
        setup: Setup::Active,
    };
    session
        .begin_secure("pion-interop", &remote, DriverTimings::default())
        .await
        .unwrap();
    let progress = loop {
        match session.poll_secure() {
            SecureProgress::Pending if started.elapsed() < Duration::from_secs(12) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            other => break other,
        }
    };
    assert_eq!(
        progress,
        SecureProgress::Ready,
        "handshake with pion as {ours:?}"
    );
    let handshake_time = started.elapsed();
    assert!(session.is_ready());

    // Keys by role into the audio pipeline's key type: the mapping of
    // `client_core::media_security::srtp_session_keys` (private to the
    // crate), profile matched exhaustively.
    let (profile, tx_key, tx_salt, rx_key, rx_salt) =
        session.negotiated_srtp_keys().unwrap().into_parts();
    let profile = match profile {
        DtlsSrtpProfile::AeadAes256Gcm => SrtpProfile::AeadAes256Gcm,
    };
    let keys = SrtpSessionKeys::new(profile, tx_key, tx_salt, rx_key, rx_salt);

    // Handoff as in `CallManager::start_audio_session`: the session lets go
    // of the socket, the receiver gets the DTLS sink for the DTLS remote.
    session.release_socket();
    let dtls_remote = session.dtls_remote().unwrap();
    assert_eq!(dtls_remote, peer.addr);
    let mut forward = session.dtls_forward_tx().expect("forward ring");
    let dtls_sink: DtlsSink = Box::new(move |datagram: &[u8]| forward.try_forward(datagram));

    let peer_addr = peer.addr;
    let outcome = tokio::task::spawn_blocking(move || {
        exchange_media(
            socket,
            peer_addr,
            &keys,
            dtls_sink,
            dtls_remote,
            Duration::from_secs(5),
        )
    })
    .await
    .unwrap();

    // Nothing ended the association meanwhile.
    assert_eq!(session.poll_security_closed(), None);
    assert!(session.is_ready());

    let (exited_ok, result, stderr) = peer.finish().await;
    let result = result.unwrap_or_else(|| panic!("peer printed no RESULT; stderr: {stderr}"));
    eprintln!(
        "client interop ours={ours:?}: handshake {handshake_time:?}; pion->us {outcome:?}; \
         us->pion {result:?}"
    );
    session.close().await.unwrap();

    assert!(exited_ok, "peer exited non-zero; stderr: {stderr}");
    assert_media_crossed(&outcome, &result);
}

/// Both directions, by each side's own count of what it could decrypt.
fn assert_media_crossed(outcome: &MediaOutcome, result: &PeerResult) {
    assert_eq!(result.profile, 8, "SRTP_AEAD_AES_256_GCM");
    assert_eq!(u64::try_from(result.sent).unwrap(), PEER_RTP);
    assert_eq!(result.rtcp_sent, PEER_RTCP);

    // pion -> us. Loopback UDP does not lose packets in practice; allow a
    // little slack so a loaded runner cannot fail the gate on scheduling.
    assert_eq!(outcome.srtp_errors, 0, "{outcome:?}");
    assert!(outcome.rtp_received >= PEER_RTP - 5, "{outcome:?}");
    assert!(outcome.rtp_received <= PEER_RTP, "{outcome:?}");
    assert!(outcome.payload_matches >= 1, "{outcome:?}");
    assert_eq!(outcome.srtcp_errors, 0, "{outcome:?}");
    assert_eq!(outcome.rtcp_dropped, 0, "{outcome:?}");
    assert!(outcome.rtcp_handled >= PEER_RTCP - 1, "{outcome:?}");
    // RFC 7983: nothing of the DTLS class was thrown away, and nothing
    // unclassifiable arrived.
    assert_eq!(outcome.dtls_dropped, 0, "{outcome:?}");
    assert_eq!(outcome.non_media_dropped, 0, "{outcome:?}");
    // What was forwarded to the driver (a retransmitted final flight, if
    // any) stayed within the receiver's burst limit.
    assert!(
        outcome.dtls_forwarded <= u64::from(client_audio::DTLS_FORWARD_BURST),
        "{outcome:?}"
    );

    // us -> pion (its counters only count successful decryption).
    assert_eq!(usize::try_from(outcome.rtp_sent).unwrap(), OUR_RTP);
    assert!(
        result.received >= OUR_RTP - 2 && result.received <= OUR_RTP,
        "pion decrypted {} of {OUR_RTP} SRTP packets",
        result.received
    );
    assert_eq!(
        result.rtcp_received, OUR_RTCP,
        "pion decrypted {} of {OUR_RTCP} SRTCP packets",
        result.rtcp_received
    );
}

/// The SBC-facing case: we are the DTLS client (`a=setup:active`), pion is
/// the server, as the SBC's sidecar is for an `actpass` offer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn pion_as_server_we_are_client() {
    interoperates(DtlsRole::Client).await;
}

/// We are the DTLS server (`a=setup:passive`), pion is the client and has
/// sent its `ClientHello` before our association exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn pion_as_client_we_are_server() {
    interoperates(DtlsRole::Server).await;
}
