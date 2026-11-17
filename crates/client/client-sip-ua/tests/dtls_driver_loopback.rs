//! The soft client's DTLS driver against an in-process DTLS peer over real
//! UDP sockets on 127.0.0.1 (plan §9.2).
//!
//! The client side is the production path: `MediaSession::begin_secure`,
//! the driver task, `poll_secure` / `poll_security_closed`, and the forward
//! ring the audio I/O thread uses. There is no audio thread here, so where
//! a test needs a post-handshake datagram to reach the driver it reads the
//! media socket the way the pipeline would and pushes the datagram through
//! [`client_sip_ua::DtlsForwardTx`] itself.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use client_sip_ua::dtls_driver::{
    self, CauseBasis, DriverEvent, DriverHandle, DriverParams, DriverPoll, DriverTimings,
    SecureProgress, SecurityCause,
};
use client_sip_ua::{DtlsIdentity, MediaSessionState};
use common::dtls::{self, Puppet};
use common::{Client, Peer, connected, fast_timings, handshake, opposite};
use proto_dtls::record::ContentType;
use proto_dtls::{AssociationConfig, CertificateFingerprint, DtlsRole};
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const BOTH_ROLES: [DtlsRole; 2] = [DtlsRole::Client, DtlsRole::Server];

/// RFC 5764 §4.2: both sides hold the same exported material, and the
/// client's send/receive keys are resolved by its role.
fn assert_keys_mirror(client: &Client, peer: &Peer, role: DtlsRole) {
    let ours = client.session.negotiated_srtp_keys().expect("client keys");
    let theirs = peer.keys.as_ref().expect("peer keys");
    assert_eq!(ours.local_key(), theirs.local_key(role));
    assert_eq!(ours.local_salt(), theirs.local_salt(role));
    assert_eq!(ours.remote_key(), theirs.remote_key(role));
    assert_eq!(ours.remote_salt(), theirs.remote_salt(role));
    // What we send with is what the peer receives with, and the reverse.
    let peer_role = opposite(role);
    assert_eq!(ours.local_key(), theirs.remote_key(peer_role));
    assert_eq!(ours.remote_key(), theirs.local_key(peer_role));
    assert_ne!(ours.local_key(), ours.remote_key());
    assert_eq!(ours.local_key().len(), 32);
    assert_eq!(ours.local_salt().len(), 12);
}

#[tokio::test]
async fn both_roles_reach_ready_with_mirrored_keys() {
    for role in BOTH_ROLES {
        let (client, peer) = connected(role).await;
        assert!(client.session.is_ready());
        assert_eq!(client.session.state(), MediaSessionState::Active);
        assert_eq!(client.session.dtls_remote(), Some(peer.addr));
        assert_eq!(client.session.dtls_role(), role);
        assert_keys_mirror(&client, &peer, role);
    }
}

/// After `Ready` nothing on the client reads the media socket: a datagram
/// sent by the peer is still there for the pipeline, and the socket can be
/// made blocking again without disturbing the driver.
#[tokio::test]
async fn media_socket_is_left_to_the_pipeline_after_ready() {
    for role in BOTH_ROLES {
        let (mut client, peer) = connected(role).await;
        let rtp = [0x80u8, 0, 0, 1, 0, 0, 0, 160, 0, 0, 0, 7, 1, 2, 3];
        peer.socket.send_to(&rtp, client.addr).await.unwrap();
        // Give a stray reader every chance to take it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.take_socket_like_the_pipeline(Duration::from_millis(500));
        let mut buf = [0u8; 64];
        let (len, from) = client.socket.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..len], from), (&rtp[..], peer.addr));
        assert!(client.session.is_ready());
        assert_eq!(client.session.poll_security_closed(), None);
    }
}

/// RFC 5763 §5 (RFC-006): a `ClientHello` sent before the client started
/// its association waits in the socket's receive queue and is answered
/// without the peer having to retransmit.
#[tokio::test]
async fn early_client_hello_is_answered_without_retransmission() {
    let mut client = Client::new(DtlsRole::Server);
    let mut peer = Peer::new().await;
    peer.start(DtlsRole::Client, client.fingerprint());
    peer.flush(client.addr).await;
    assert_eq!(peer.sent.len(), 1, "the ClientHello left before the answer");
    tokio::time::sleep(Duration::from_millis(50)).await;

    client
        .begin(peer.addr, peer.fingerprint(), DriverTimings::default())
        .await;
    let progress = handshake(&mut client, &mut peer, Duration::from_secs(5)).await;
    assert_eq!(progress, SecureProgress::Ready);
    assert_eq!(peer.association().stats().retransmits, 0);
    assert_keys_mirror(&client, &peer, DtlsRole::Server);
}

/// RFC 8122 §5 / RFC 5763 §6.7.1: a certificate that does not match the
/// SDP fingerprint fails the call's media security. The association
/// reports it at the next retransmission-timer expiry.
#[tokio::test]
async fn fingerprint_mismatch_fails_closed_in_both_roles() {
    for role in BOTH_ROLES {
        let mut client = Client::new(role);
        let mut peer = Peer::new().await;
        peer.start(opposite(role), client.fingerprint());
        let someone_else = dtls::identity().fingerprint().clone();
        let started = Instant::now();
        client.begin(peer.addr, someone_else, fast_timings()).await;
        let progress = handshake(&mut client, &mut peer, Duration::from_secs(4)).await;
        assert_eq!(
            progress,
            SecureProgress::Failed(
                SecurityCause::FingerprintMismatch,
                CauseBasis::UnauthenticatedInput
            ),
            "client as {role:?}"
        );
        // One retransmission interval (200 ms here) plus margin.
        assert!(started.elapsed() < Duration::from_secs(3), "{role:?}");
        assert!(!client.session.is_ready());
        assert!(client.session.negotiated_srtp_keys().is_none());
        assert_eq!(client.session.state(), MediaSessionState::Failed);
        assert!(client.session.dtls_forward_tx().is_none());
        assert_eq!(client.session.poll_security_closed(), None);
        // Terminal: the same answer every time.
        assert_eq!(
            client.session.poll_secure(),
            SecureProgress::Failed(
                SecurityCause::FingerprintMismatch,
                CauseBasis::UnauthenticatedInput
            )
        );
    }
}

/// A peer that never answers: the handshake ends at the budget (10 s by
/// default), on the tokio clock.
#[tokio::test(start_paused = true)]
async fn silent_peer_times_out_at_the_default_budget() {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(DtlsRole::Client);
    let started = tokio::time::Instant::now();
    client
        .begin(
            silent.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            DriverTimings::default(),
        )
        .await;
    let progress = client.settle(Duration::from_secs(30)).await;
    assert_eq!(
        progress,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    let elapsed = started.elapsed();
    assert!(
        (Duration::from_secs(10)..Duration::from_secs(11)).contains(&elapsed),
        "{elapsed:?}"
    );
    assert!(client.session.negotiated_srtp_keys().is_none());
}

/// A plaintext fatal alert during the handshake is acted on at the next
/// timer expiry and reported as an alert (never as success).
#[tokio::test]
async fn plaintext_fatal_alert_fails_the_handshake() {
    let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = Client::new(DtlsRole::Client);
    client
        .begin(
            responder.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            fast_timings(),
        )
        .await;
    let mut buf = [0u8; 2048];
    let (_, from) = tokio::time::timeout(Duration::from_secs(2), responder.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, client.addr);
    // handshake_failure (40), fatal (2).
    responder
        .send_to(&dtls::plaintext_alert(0, 2, 40), from)
        .await
        .unwrap();
    assert_eq!(
        client.settle(Duration::from_secs(4)).await,
        SecureProgress::Failed(SecurityCause::Alert(40), CauseBasis::UnauthenticatedInput)
    );
    assert!(client.session.negotiated_srtp_keys().is_none());
}

/// NIST 800-53 Rev5: SC-23 -- DTLS-looking datagrams from another address
/// (here forged fatal alerts, more than one wake-up's worth) and non-DTLS
/// datagrams from the peer's own address never reach the association.
#[tokio::test]
async fn wrong_source_and_non_dtls_datagrams_do_not_disturb_the_handshake() {
    for role in BOTH_ROLES {
        let mut client = Client::new(role);
        let mut peer = Peer::new().await;
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for seq in 0..40u64 {
            stranger
                .send_to(&dtls::plaintext_alert(seq, 2, 40), client.addr)
                .await
                .unwrap();
        }
        // STUN-class and RTP-class datagrams from the peer itself.
        peer.socket
            .send_to(&[0x00, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42], client.addr)
            .await
            .unwrap();
        peer.socket
            .send_to(&[0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], client.addr)
            .await
            .unwrap();

        peer.start(opposite(role), client.fingerprint());
        client
            .begin(peer.addr, peer.fingerprint(), fast_timings())
            .await;
        let client_addr = client.addr;
        let flood = async {
            for seq in 40..80u64 {
                let _ = stranger
                    .send_to(&dtls::plaintext_alert(seq, 2, 40), client_addr)
                    .await;
                tokio::task::yield_now().await;
            }
        };
        let (progress, (), ()) = tokio::join!(
            client.settle(Duration::from_secs(5)),
            peer.drive(client_addr, Duration::from_secs(5), Peer::settled, |_| true),
            flood,
        );
        assert_eq!(progress, SecureProgress::Ready, "client as {role:?}");
        assert_keys_mirror(&client, &peer, role);
    }
}

/// RFC 6347 §4.2.4: as server our final flight can be lost. The peer then
/// retransmits its last flight, which now arrives on a socket the audio
/// thread reads; forwarded through the ring, the driver answers it with
/// the final flight again, through its std clone of the socket.
#[tokio::test]
async fn lost_final_flight_is_resent_after_the_handoff() {
    let mut client = Client::new(DtlsRole::Server);
    let mut peer = Peer::new().await;
    peer.start_with(DtlsRole::Client, client.fingerprint(), |config| {
        config.initial_rto = Duration::from_millis(100);
    });
    client
        .begin(peer.addr, peer.fingerprint(), fast_timings())
        .await;

    // The server's final flight starts with a ChangeCipherSpec record
    // (content type 20); the peer never gets it.
    let client_addr = client.addr;
    let progress = tokio::select! {
        progress = client.settle(Duration::from_secs(5)) => progress,
        () = peer.drive(client_addr, Duration::from_secs(5), |_| false, |d| d[0] != 20) => {
            SecureProgress::Pending
        }
    };
    assert_eq!(progress, SecureProgress::Ready);
    // The driver sent its final flight before it reported `Ready`, so the
    // datagram is in the peer's socket queue by now. When the client settles
    // before the peer has read it (seen under CPU load), the `select!` above
    // drops the peer's future with the datagram still queued: read it here
    // with the same filter, or the accept-all loop below would deliver it
    // and nothing would need forwarding.
    peer.drive(
        client_addr,
        Duration::from_millis(20),
        |_| false,
        |d| d[0] != 20,
    )
    .await;
    assert!(peer.keys.is_none(), "the peer has not seen our Finished");

    client.take_socket_like_the_pipeline(Duration::from_millis(10));
    let mut forward = client.session.dtls_forward_tx().expect("forward ring");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut forwarded = 0;
    while peer.keys.is_none() {
        assert!(Instant::now() < deadline, "final flight was not resent");
        // The peer's timer retransmits its flight ...
        peer.drive(
            client_addr,
            Duration::from_millis(50),
            |p| p.keys.is_some(),
            |_| true,
        )
        .await;
        // ... which the "audio thread" reads and forwards.
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = client.socket.recv_from(&mut buf) {
            assert_eq!(from, peer.addr);
            if (20..=63).contains(&buf[0]) && forward.try_forward(&buf[..len]) {
                forwarded += 1;
            }
        }
    }
    assert!(forwarded >= 1);
    assert_eq!(peer.failed, None);
    assert_keys_mirror(&client, &peer, DtlsRole::Server);
    assert_eq!(client.session.poll_security_closed(), None);
    assert!(client.session.is_ready());
}

/// The peer's `close_notify` mid-call, forwarded through the ring, is
/// reported once; the keys are dropped and the session is no longer ready.
#[tokio::test]
async fn peer_close_notify_is_reported_once() {
    for role in BOTH_ROLES {
        let (mut client, mut peer) = connected(role).await;
        let mut forward = client.session.dtls_forward_tx().expect("forward ring");
        assert_eq!(client.session.poll_security_closed(), None);

        peer.association().close();
        let close_notify = peer.association().poll_transmit().expect("close_notify");
        assert!(forward.try_forward(&close_notify));

        let deadline = Instant::now() + Duration::from_secs(2);
        let cause = loop {
            if let Some(cause) = client.session.poll_security_closed() {
                break cause;
            }
            assert!(Instant::now() < deadline, "close_notify not reported");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(cause, SecurityCause::ClosedByPeer, "client as {role:?}");
        assert!(!client.session.is_ready());
        assert!(client.session.negotiated_srtp_keys().is_none());
        assert!(client.session.dtls_forward_tx().is_none());
        assert_eq!(client.session.poll_security_closed(), None);
        assert_eq!(
            client.session.poll_secure(),
            SecureProgress::Failed(SecurityCause::ClosedByPeer, CauseBasis::PeerAuthenticated)
        );
        // RFC 5246 §7.2.1: our own close_notify went back, from the media
        // port, through the driver's std clone.
        let mut buf = [0u8; 256];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(2), peer.socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from, client.addr);
        assert_eq!(buf[0], 21, "an alert record ({len} bytes)");
    }
}

async fn receive(socket: &UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(2), socket.recv_from(buf))
        .await
        .expect("datagram from the client")
        .unwrap()
}

/// A scripted server that knows the session keys sends an authenticated
/// fatal alert after the handshake.
#[tokio::test]
async fn authenticated_fatal_alert_after_connect_is_reported() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let mut client = Client::new(DtlsRole::Client);
    client
        .begin(
            socket.local_addr().unwrap(),
            puppet.fingerprint(),
            DriverTimings::default(),
        )
        .await;

    let mut buf = [0u8; 4096];
    let (len, from) = receive(&socket, &mut buf).await;
    assert_eq!(from, client.addr);
    puppet.absorb(&buf[..len]);
    socket
        .send_to(&puppet.server_flight4(), from)
        .await
        .unwrap();
    while puppet.peer_finished_ok.is_none() {
        let (len, _) = receive(&socket, &mut buf).await;
        puppet.absorb(&buf[..len]);
    }
    assert_eq!(puppet.peer_finished_ok, Some(true));
    socket
        .send_to(&puppet.server_flight6(), from)
        .await
        .unwrap();
    assert_eq!(
        client.settle(Duration::from_secs(3)).await,
        SecureProgress::Ready
    );

    let mut forward = client.session.dtls_forward_tx().expect("forward ring");
    // A forged (plaintext, epoch 0) alert first: discarded, not reported.
    assert!(forward.try_forward(&dtls::plaintext_alert(9, 2, 40)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(client.session.poll_security_closed(), None);
    assert!(client.session.is_ready());

    // internal_error (80), fatal (2), protected in epoch 1.
    let alert = puppet.seal(1, ContentType::Alert, &[2, 80]);
    assert!(forward.try_forward(&alert));
    let deadline = Instant::now() + Duration::from_secs(2);
    let cause = loop {
        if let Some(cause) = client.session.poll_security_closed() {
            break cause;
        }
        assert!(Instant::now() < deadline, "alert not reported");
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(cause, SecurityCause::Alert(80));
    assert_eq!(cause.as_str(), "dtls-alert");
    assert!(!client.session.is_ready());
    assert!(client.session.negotiated_srtp_keys().is_none());
}

/// RFC 5246 §7.2.1: closing the session after the handshake sends exactly
/// one `close_notify`.
#[tokio::test]
async fn local_close_after_connect_sends_one_close_notify() {
    for role in BOTH_ROLES {
        let (mut client, mut peer) = connected(role).await;
        let before = peer.received.len();
        client.session.close().await.unwrap();
        assert_eq!(client.session.state(), MediaSessionState::Closed);
        assert!(client.session.negotiated_srtp_keys().is_none());

        let client_addr = client.addr;
        peer.drive(
            client_addr,
            Duration::from_secs(2),
            |p| p.saw_close,
            |_| true,
        )
        .await;
        assert!(peer.saw_close, "client as {role:?}");
        // Nothing follows it.
        peer.drive(client_addr, Duration::from_millis(300), |_| false, |_| true)
            .await;
        assert_eq!(peer.received.len(), before + 1, "client as {role:?}");
    }
}

/// Hang-up during the handshake cancels it: the session never becomes
/// ready and cannot be started again.
#[tokio::test]
async fn close_during_handshake_cancels_it() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = Client::new(DtlsRole::Client);
    let fingerprint = dtls::identity().fingerprint().clone();
    client
        .begin(
            silent.local_addr().unwrap(),
            fingerprint.clone(),
            fast_timings(),
        )
        .await;
    assert_eq!(client.session.poll_secure(), SecureProgress::Pending);
    client.session.close().await.unwrap();

    // The ClientHello, then one plaintext close_notify (an alert record),
    // then nothing: the driver is gone.
    let mut kinds = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(Ok((_, _))) =
        tokio::time::timeout(Duration::from_millis(600), silent.recv_from(&mut buf)).await
    {
        kinds.push(buf[0]);
    }
    assert_eq!(kinds, vec![22, 21]);

    assert!(matches!(
        client.session.poll_secure(),
        SecureProgress::Failed(..)
    ));
    assert!(!client.session.is_ready());
    assert!(client.session.dtls_forward_tx().is_none());
    assert!(
        client
            .session
            .begin_secure("again", &common::params(fingerprint), fast_timings())
            .await
            .is_err()
    );
}

// ----- the driver on its own ----------------------------------------------

struct Bare {
    handle: DriverHandle,
    /// Tells whether anything still holds the tokio view of the socket.
    tokio_view: Weak<UdpSocket>,
    addr: SocketAddr,
    fingerprint: CertificateFingerprint,
}

fn spawn_bare(role: DtlsRole, remote: SocketAddr, expect: CertificateFingerprint) -> Bare {
    let identity = DtlsIdentity::generate().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let send_socket = socket.try_clone().unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(UdpSocket::from_std(socket).unwrap());
    let tokio_view = Arc::downgrade(&socket);
    let mut config = AssociationConfig::new(role, identity.credentials().clone(), vec![expect]);
    config.peer_binding = dtls_driver::peer_binding(remote);
    let handle = dtls_driver::spawn(DriverParams {
        call_id: "bare".to_string(),
        config,
        remote,
        socket,
        send_socket,
        early: Vec::new(),
    })
    .unwrap();
    Bare {
        handle,
        tokio_view,
        addr,
        fingerprint: identity.fingerprint().clone(),
    }
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The driver has dropped its tokio view of the media socket by the time
/// `Connected` can be observed, in both roles, and keeps running.
#[tokio::test]
async fn driver_drops_its_tokio_view_before_reporting_connected() {
    for role in BOTH_ROLES {
        let mut peer = Peer::new().await;
        // The peer needs our fingerprint, which exists only after spawn;
        // a server-role driver waits for the ClientHello, a client-role
        // one retransmits its own.
        let mut bare = spawn_bare(role, peer.addr, peer.fingerprint());
        assert!(bare.tokio_view.upgrade().is_some());
        peer.start(opposite(role), bare.fingerprint.clone());

        let addr = bare.addr;
        let poll = async {
            loop {
                match bare.handle.poll() {
                    DriverPoll::Pending => tokio::time::sleep(Duration::from_millis(2)).await,
                    other => {
                        // Checked at once, before any other await.
                        let view_gone = bare.tokio_view.upgrade().is_none();
                        break (other, view_gone);
                    }
                }
            }
        };
        let ((event, view_gone), ()) = tokio::join!(
            poll,
            peer.drive(addr, Duration::from_secs(5), Peer::settled, |_| true)
        );
        let DriverPoll::Event(DriverEvent::Connected { keys }) = event else {
            panic!("expected Connected as {role:?}, got {event:?}");
        };
        assert!(view_gone, "tokio view still held as {role:?}");
        assert_eq!(
            dtls::exported(&keys),
            dtls::exported(peer.keys.as_ref().unwrap())
        );
        assert!(!bare.handle.is_finished(), "driver services the call");
        assert!(matches!(bare.handle.poll(), DriverPoll::Pending));

        bare.handle.close();
        wait_until("driver exits after close", || bare.handle.is_finished()).await;
        assert!(matches!(bare.handle.poll(), DriverPoll::Gone));
    }
}

/// `close()` during the handshake ends the task without any event.
#[tokio::test]
async fn driver_close_during_handshake_ends_the_task_without_events() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut bare = spawn_bare(
        DtlsRole::Server,
        silent.local_addr().unwrap(),
        dtls::identity().fingerprint().clone(),
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(matches!(bare.handle.poll(), DriverPoll::Pending));
    bare.handle.close();
    wait_until("driver exits", || bare.handle.is_finished()).await;
    assert!(matches!(bare.handle.poll(), DriverPoll::Gone));
    assert!(bare.tokio_view.upgrade().is_none());
}

/// Dropping the handle without `close()` ends the task too: no path leaks
/// a driver or its socket view. During the handshake and after it.
#[tokio::test]
async fn dropping_the_handle_ends_the_driver() {
    // During the handshake.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bare = spawn_bare(
        DtlsRole::Client,
        silent.local_addr().unwrap(),
        dtls::identity().fingerprint().clone(),
    );
    let view = bare.tokio_view.clone();
    drop(bare);
    wait_until("handshaking driver exits", || view.upgrade().is_none()).await;

    // After it: the peer gets our close_notify.
    let mut peer = Peer::new().await;
    let mut bare = spawn_bare(DtlsRole::Client, peer.addr, peer.fingerprint());
    peer.start(DtlsRole::Server, bare.fingerprint.clone());
    let addr = bare.addr;
    peer.drive(addr, Duration::from_secs(5), Peer::settled, |_| true)
        .await;
    assert!(peer.keys.is_some());
    wait_until("driver connected", || {
        matches!(
            bare.handle.poll(),
            DriverPoll::Event(DriverEvent::Connected { .. })
        )
    })
    .await;
    drop(bare);
    peer.drive(addr, Duration::from_secs(2), |p| p.saw_close, |_| true)
        .await;
    assert!(peer.saw_close);
}

/// A driver whose association is refused never starts.
#[tokio::test]
async fn spawn_refuses_an_invalid_configuration() {
    let identity = DtlsIdentity::generate().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let send_socket = socket.try_clone().unwrap();
    socket.set_nonblocking(true).unwrap();
    let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
    // No fingerprint to authenticate the peer against.
    let config =
        AssociationConfig::new(DtlsRole::Client, identity.credentials().clone(), Vec::new());
    let result = dtls_driver::spawn(DriverParams {
        call_id: "bad".to_string(),
        config,
        remote,
        socket: Arc::new(UdpSocket::from_std(socket).unwrap()),
        send_socket,
        early: Vec::new(),
    });
    assert!(result.is_err());
}
