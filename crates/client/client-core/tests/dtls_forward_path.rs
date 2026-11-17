//! The audio thread's DTLS forward path, end to end over real UDP
//! (POA&M-324 stage 2, acceptance criteria 3 and 5): the production
//! `RtpReceiver` reads the call's media socket after the handshake, and
//! what it forwards goes through the production ring to the call's DTLS
//! driver.
//!
//! peer socket -> media socket -> `RtpReceiver::receive` (source check,
//! token bucket) -> `DtlsForwardTx::try_forward` -> driver -> association
//! -> `MediaSession::poll_security_closed` / the driver's reply on the wire.
//!
//! No audio device is opened: the receiver is driven by the test the way
//! the audio I/O thread drives it (blocking reads with a short timeout).
//! The tests run on a current-thread runtime, so the driver task only runs
//! while the test awaits; a burst read without awaiting therefore shows
//! what the audio thread does when the driver is not scheduled.
// NIST 800-53 Rev5: SC-5, SC-23, SI-10. RFC 5764 §5.1.2, RFC 7983 §7.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use client_audio::{DTLS_FORWARD_BURST, DtlsSink, RtpReceiver, RtpStats, SharedJitterBuffer};
use client_sip_ua::sdp_dtls::{DtlsSdpParams, Setup};
use client_sip_ua::{
    DriverTimings, DtlsIdentity, MediaSession, MediaSessionEvent, SecureProgress, SecurityCause,
};
use common::{Peer, dtls, opposite};
use proto_dtls::DtlsRole;
use proto_ice::IceConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const BOTH_ROLES: [DtlsRole; 2] = [DtlsRole::Client, DtlsRole::Server];
/// Read timeout of the "audio thread".
const READ_TIMEOUT: Duration = Duration::from_millis(10);

/// A media session past its handshake whose socket is read by a real
/// `RtpReceiver` with the DTLS sink installed, as
/// `CallManager::start_audio_session` and the pipeline set it up.
struct Media {
    session: MediaSession,
    receiver: RtpReceiver,
    addr: SocketAddr,
    peer: Peer,
    _events: mpsc::Receiver<MediaSessionEvent>,
}

fn timings() -> DriverTimings {
    DriverTimings {
        initial_rto: Duration::from_millis(200),
        handshake_budget: Duration::from_secs(5),
        ..DriverTimings::default()
    }
}

/// Polls the session and drives the peer until the session has an outcome.
/// `accept` decides which of our DTLS datagrams the peer gets.
async fn run_handshake(
    session: &mut MediaSession,
    peer: &mut Peer,
    addr: SocketAddr,
    stop_peer: impl Fn(&Peer) -> bool,
    accept: impl FnMut(&[u8]) -> bool,
) -> SecureProgress {
    let settle = async {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match session.poll_secure() {
                SecureProgress::Pending if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => return other,
            }
        }
    };
    tokio::select! {
        progress = settle => progress,
        () = peer.drive(addr, Duration::from_secs(6), stop_peer, accept) => session.poll_secure(),
    }
}

/// Hands the socket to a receiver the way the call manager and the audio
/// pipeline do.
fn audio_receiver(
    session: &mut MediaSession,
    socket: std::net::UdpSocket,
    rtp_remote: SocketAddr,
) -> RtpReceiver {
    session.release_socket();
    let dtls_remote = session.dtls_remote().expect("DTLS remote");
    let mut forward = session.dtls_forward_tx().expect("forward ring");
    let sink: DtlsSink = Box::new(move |datagram: &[u8]| forward.try_forward(datagram));
    // As `client_audio::pipeline::prepare_media_socket` does at handoff.
    socket.set_nonblocking(false).unwrap();
    socket.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let mut receiver = RtpReceiver::new(Arc::new(socket), SharedJitterBuffer::new(8000, 160, 60));
    receiver.set_expected_remote(rtp_remote);
    receiver.set_rtcp_mux(true);
    receiver.set_dtls_sink(sink, dtls_remote);
    receiver
}

async fn connected(role: DtlsRole) -> Media {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let identity = DtlsIdentity::generate().unwrap();
    let (events_tx, events) = mpsc::channel(64);
    let mut session = MediaSession::new(
        addr,
        role == DtlsRole::Client,
        IceConfig::default(),
        socket.try_clone().unwrap(),
        &identity,
        events_tx,
    );
    let mut peer = Peer::new().await;
    peer.start(opposite(role), identity.fingerprint().clone());
    session.set_remote_addr(peer.addr);
    session.set_dtls_role(role).unwrap();
    let remote = DtlsSdpParams {
        fingerprints: vec![peer.fingerprint()],
        setup: Setup::Active,
    };
    session
        .begin_secure("forward-path", &remote, timings())
        .await
        .unwrap();
    let progress = run_handshake(&mut session, &mut peer, addr, |_| false, |_| true).await;
    assert_eq!(progress, SecureProgress::Ready, "as {role:?}");
    // Let the peer finish as well (it may still wait for our last flight).
    peer.drive(addr, Duration::from_secs(2), Peer::settled, |_| true)
        .await;
    assert!(peer.keys.is_some(), "peer connected");
    let receiver = audio_receiver(&mut session, socket, peer.addr);
    // The driver takes the ring.
    tokio::time::sleep(Duration::from_millis(20)).await;
    Media {
        session,
        receiver,
        addr,
        peer,
        _events: events,
    }
}

impl Media {
    /// Reads the socket like the audio I/O loop until it stays empty, and
    /// returns the longest single `receive()` call.
    fn read_until_idle(&mut self) -> Duration {
        let mut longest = Duration::ZERO;
        let mut idle = 0;
        while idle < 3 {
            let before = self.stats();
            let started = Instant::now();
            let _ = self.receiver.receive().unwrap();
            longest = longest.max(started.elapsed());
            let after = self.stats();
            if after.dtls_dropped == before.dtls_dropped
                && after.dtls_forwarded == before.dtls_forwarded
                && after.non_media_dropped == before.non_media_dropped
                && after.packets_received == before.packets_received
            {
                idle += 1;
            } else {
                idle = 0;
            }
        }
        longest
    }

    fn stats(&self) -> RtpStats {
        self.receiver.stats()
    }

    /// Waits (letting the driver run) for the association to be reported
    /// closed.
    async fn closed_within(&mut self, limit: Duration) -> Option<SecurityCause> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(cause) = self.session.poll_security_closed() {
                return Some(cause);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The peer's genuine `close_notify` datagram (epoch 1), not yet sent.
    fn peer_close_notify(&mut self) -> Vec<u8> {
        self.peer.association().close();
        self.peer
            .association()
            .poll_transmit()
            .expect("close_notify")
    }
}

/// Criterion 5: the peer's `close_notify`, sent over the wire to the media
/// socket after the audio thread took it over, is forwarded by the
/// receiver exactly once and reported by the session.
#[tokio::test]
async fn close_notify_on_the_wire_reaches_the_driver_through_the_receiver() {
    for role in BOTH_ROLES {
        let mut media = connected(role).await;
        let close_notify = media.peer_close_notify();
        media
            .peer
            .socket
            .send_to(&close_notify, media.addr)
            .await
            .unwrap();
        media.read_until_idle();
        let stats = media.stats();
        assert_eq!(stats.dtls_forwarded, 1, "as {role:?}: {stats:?}");
        assert_eq!(stats.dtls_dropped, 0, "as {role:?}: {stats:?}");
        assert_eq!(
            media.closed_within(Duration::from_secs(2)).await,
            Some(SecurityCause::ClosedByPeer),
            "as {role:?}"
        );
        assert!(!media.session.is_ready());
        assert!(media.session.negotiated_srtp_keys().is_none());
    }
}

/// Criterion 3 / SC-23: a DTLS datagram from an address that is not the
/// negotiated remote is dropped by the receiver, even when its bytes are
/// the peer's genuine `close_notify`. The same bytes from the peer's own
/// address do close the association: the source address is the only
/// difference.
#[tokio::test]
async fn dtls_from_a_non_negotiated_source_is_dropped_before_the_association() {
    for role in BOTH_ROLES {
        let mut media = connected(role).await;
        let close_notify = media.peer_close_notify();
        // Same host, another port: what an on-host or NAT-sharing third
        // party would be.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(&close_notify, media.addr).await.unwrap();
        stranger
            .send_to(&dtls::plaintext_alert(0, 2, 40), media.addr)
            .await
            .unwrap();
        stranger.send_to(&[22; 1200], media.addr).await.unwrap();
        media.read_until_idle();
        let stats = media.stats();
        assert_eq!(stats.dtls_forwarded, 0, "as {role:?}: {stats:?}");
        assert_eq!(stats.dtls_dropped, 3, "as {role:?}: {stats:?}");
        assert_eq!(media.closed_within(Duration::from_millis(300)).await, None);
        assert!(media.session.is_ready(), "as {role:?}");

        media
            .peer
            .socket
            .send_to(&close_notify, media.addr)
            .await
            .unwrap();
        media.read_until_idle();
        assert_eq!(media.stats().dtls_forwarded, 1, "as {role:?}");
        assert_eq!(
            media.closed_within(Duration::from_secs(2)).await,
            Some(SecurityCause::ClosedByPeer),
            "as {role:?}"
        );
    }
}

/// Criterion 3 / PERF-006: a flood of DTLS-class datagrams from the DTLS
/// remote itself. The receiver forwards at most the burst, then counts and
/// drops; with the driver not scheduled the ring fills and the sink
/// refuses; no `receive()` call takes longer than about one read timeout;
/// the association survives the junk; and once tokens are back a genuine
/// `close_notify` still gets through.
#[tokio::test]
async fn flood_from_the_dtls_remote_is_rate_limited_and_never_blocks() {
    let mut media = connected(DtlsRole::Client).await;
    let junk = [22u8; 1400];
    let mut sent = 0u64;
    for _ in 0..200 {
        if media.peer.socket.send_to(&junk, media.addr).await.is_ok() {
            sent += 1;
        }
    }
    // Hostile sizes of the DTLS class as well: a runt and one larger than
    // any DTLS datagram the association accepts.
    for datagram in [vec![22u8], vec![22u8; 3000]] {
        if media
            .peer
            .socket
            .send_to(&datagram, media.addr)
            .await
            .is_ok()
        {
            sent += 1;
        }
    }

    // No await in here: the driver cannot run, as when its worker is busy.
    let started = Instant::now();
    let longest = media.read_until_idle();
    let read_time = started.elapsed();
    let stats = media.stats();
    eprintln!("flood: sent={sent} longest_receive={longest:?} total={read_time:?} {stats:?}");

    let seen = stats.dtls_forwarded + stats.dtls_dropped;
    assert!(seen >= 20 && seen <= sent, "{stats:?}");
    // Burst of 8 by the bucket, of which the 8 KiB ring holds five 1,400
    // byte frames while the driver does not drain; refill adds 4/s.
    let refill = u64::try_from(read_time.as_millis()).unwrap() * 4 / 1000 + 1;
    assert!(stats.dtls_forwarded >= 1, "{stats:?}");
    assert!(
        stats.dtls_forwarded <= u64::from(DTLS_FORWARD_BURST) + refill,
        "{stats:?}"
    );
    assert!(stats.dtls_dropped >= seen - u64::from(DTLS_FORWARD_BURST) - refill);
    // One read timeout is 10 ms; a generous bound that still shows the
    // call never waited on the driver or the ring.
    assert!(longest < Duration::from_millis(150), "{longest:?}");
    assert_eq!(stats.packets_received, 0);

    // The driver now drains the junk; the association is unharmed.
    assert_eq!(media.closed_within(Duration::from_millis(600)).await, None);
    assert!(media.session.is_ready());

    // More than a quarter second later one token is back.
    let close_notify = media.peer_close_notify();
    media
        .peer
        .socket
        .send_to(&close_notify, media.addr)
        .await
        .unwrap();
    media.read_until_idle();
    assert_eq!(
        media.closed_within(Duration::from_secs(2)).await,
        Some(SecurityCause::ClosedByPeer)
    );
}

/// Criterion 5 / RFC 6347 §4.2.4: as DTLS server our final flight is lost.
/// The peer retransmits its last flight to a socket that only the audio
/// receiver reads now; the receiver forwards it and the driver answers
/// with the final flight again through its std clone of the socket, so the
/// peer completes.
#[tokio::test]
async fn lost_final_flight_is_answered_through_the_audio_receiver() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let identity = DtlsIdentity::generate().unwrap();
    let (events_tx, _events) = mpsc::channel(64);
    let mut session = MediaSession::new(
        addr,
        false,
        IceConfig::default(),
        socket.try_clone().unwrap(),
        &identity,
        events_tx,
    );
    let mut peer = Peer::new().await;
    peer.start_with(DtlsRole::Client, identity.fingerprint().clone(), |config| {
        config.initial_rto = Duration::from_millis(100);
    });
    session.set_remote_addr(peer.addr);
    session.set_dtls_role(DtlsRole::Server).unwrap();
    let remote = DtlsSdpParams {
        fingerprints: vec![peer.fingerprint()],
        setup: Setup::Active,
    };
    session
        .begin_secure("final-flight", &remote, timings())
        .await
        .unwrap();
    // Our final flight starts with a ChangeCipherSpec record (type 20);
    // the peer never gets it.
    let progress = run_handshake(&mut session, &mut peer, addr, |_| false, |d| d[0] != 20).await;
    assert_eq!(progress, SecureProgress::Ready);
    // Our final flight was sent before `Ready` was reported and may still be
    // in the peer's socket queue (the `select!` in `run_handshake` drops the
    // peer's future as soon as we settle): lose it here too.
    peer.drive(addr, Duration::from_millis(20), |_| false, |d| d[0] != 20)
        .await;
    assert!(peer.keys.is_none(), "the peer has not seen our Finished");

    let mut receiver = audio_receiver(&mut session, socket, peer.addr);
    let deadline = Instant::now() + Duration::from_secs(5);
    while peer.keys.is_none() {
        assert!(Instant::now() < deadline, "final flight was not resent");
        // The peer's timer retransmits its flight (and the driver runs) ...
        peer.drive(
            addr,
            Duration::from_millis(50),
            |p| p.keys.is_some(),
            |_| true,
        )
        .await;
        // ... which the audio thread reads and forwards.
        for _ in 0..4 {
            let _ = receiver.receive().unwrap();
        }
    }
    let stats = receiver.stats();
    assert!(stats.dtls_forwarded >= 1, "{stats:?}");
    assert_eq!(peer.failed, None);
    assert_eq!(session.poll_security_closed(), None);
    assert!(session.is_ready());
}
