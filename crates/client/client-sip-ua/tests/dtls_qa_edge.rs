//! QA edge cases for the soft client's DTLS driver (POA&M-324 stage 2):
//! paths the implementation tests leave open.
//!
//! - an early `ClientHello` that the ICE check loop read off the socket
//!   reaches the driver through the stash (RFC 5763 §5);
//! - a hang-up racing the end of the handshake never leaves a ready
//!   session or a driver that keeps sending;
//! - hostile post-handshake datagrams pushed through the forward ring do
//!   not end or desynchronise the association;
//! - a driver task that dies is reported (fail closed), during and after
//!   the handshake;
//! - one association per session, also after a failure;
//! - the handshake's retransmission timer under a datagram flood.
// NIST 800-53 Rev5: SC-5, SC-8(1), SC-23, SI-10. RFC 5763 §5, RFC 6347 §4.2.4.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use client_sip_ua::dtls_driver::{CauseBasis, DriverTimings, SecureProgress, SecurityCause};
use common::dtls;
use common::{Client, Peer, connected, fast_timings, handshake, opposite, params};
use proto_dtls::DtlsRole;
use proto_ice::IceCredentials;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};

const BOTH_ROLES: [DtlsRole; 2] = [DtlsRole::Client, DtlsRole::Server];

// ----- a capturing tracing layer (driver records only) ---------------------

#[derive(Default)]
struct FieldText(BTreeMap<String, String>);

impl Visit for FieldText {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "client_sip_ua::dtls_driver" {
            return;
        }
        let mut fields = FieldText::default();
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

impl Capture {
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        (capture, tracing::subscriber::set_default(subscriber))
    }

    fn named(&self, event: &str) -> Vec<BTreeMap<String, String>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.get("event").map(String::as_str) == Some(event))
            .cloned()
            .collect()
    }
}

// ----- early ClientHello through the ICE stash -----------------------------

/// RFC 5763 §5 / RFC-006: the peer's `ClientHello` arrives while our ICE
/// connectivity checks are the reader of the media socket. The check loop
/// must keep it and the driver must be given it.
///
/// The peer is set to retransmit only after 8 s, so its one `ClientHello`
/// (sent before `begin_secure`) is consumed by the ICE loop: the handshake
/// can complete inside the time limit only if that datagram went through
/// the stash into the association. The connected record says so as well
/// (`early_datagrams=1`).
///
/// The ICE checks themselves are not answered (the peer is not an ICE
/// agent), so the check phase runs to its 3 s limit and the session falls
/// back to the SDP address, which is the candidate's address.
#[tokio::test]
async fn early_client_hello_read_by_the_ice_loop_reaches_the_driver() {
    let (capture, _guard) = Capture::install();
    let mut client = Client::new(DtlsRole::Server);
    let mut peer = Peer::new().await;

    // ICE applies: the SDP default destination is one of the candidates.
    client.session.start().await.unwrap();
    client.session.set_remote_ice_credentials(IceCredentials {
        ufrag: "peerufrag".to_string(),
        pwd: "peerpasswordpeerpassword".to_string(),
    });
    client
        .session
        .add_remote_ice_candidate(&format!(
            "candidate:1 1 UDP 2130706431 {} {} typ host",
            peer.addr.ip(),
            peer.addr.port()
        ))
        .unwrap();

    // The peer's ClientHello is on the wire before we start.
    peer.start_with(DtlsRole::Client, client.fingerprint(), |config| {
        config.initial_rto = Duration::from_secs(8);
        config.handshake_budget = Duration::from_secs(30);
    });
    peer.flush(client.addr).await;
    assert_eq!(peer.sent.len(), 1, "one ClientHello sent");

    let client_addr = client.addr;
    let fingerprint = peer.fingerprint();
    let peer_addr = peer.addr;
    let started = Instant::now();
    // `begin_secure` runs the ICE checks inline; meanwhile the peer only
    // collects what we send (STUN checks, which it does not answer).
    tokio::join!(
        client.begin(peer_addr, fingerprint, fast_timings()),
        peer.drive(
            client_addr,
            Duration::from_millis(3300),
            |_| false,
            |_| true
        ),
    );
    let ice_time = started.elapsed();
    assert!(
        peer.media.iter().any(|d| d.first().is_some_and(|b| *b < 4)),
        "ICE connectivity checks ran (STUN seen by the peer)"
    );
    assert!(ice_time >= Duration::from_secs(2), "{ice_time:?}");

    let progress = handshake(&mut client, &mut peer, Duration::from_secs(4)).await;
    assert_eq!(progress, SecureProgress::Ready);
    assert_eq!(peer.failed, None);
    assert!(peer.keys.is_some());
    // The peer never had to send its ClientHello again.
    assert_eq!(peer.association().stats().retransmits, 0);
    assert!(started.elapsed() < Duration::from_secs(8));

    let connected = capture.named("dtls.handshake.connected");
    assert_eq!(connected.len(), 1, "{connected:?}");
    assert_eq!(
        connected[0].get("early_datagrams").map(String::as_str),
        Some("1"),
        "{connected:?}"
    );
}

/// The stash is filtered by source when it is handed to the driver: an
/// early DTLS-class datagram from an address that is not the selected
/// remote is not fed to the association (SC-23). A forged fatal alert from
/// a stranger during the ICE phase must not fail the handshake.
#[tokio::test]
async fn early_dtls_from_another_source_is_not_fed_to_the_driver() {
    let (capture, _guard) = Capture::install();
    let mut client = Client::new(DtlsRole::Server);
    let mut peer = Peer::new().await;
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client.session.start().await.unwrap();
    client.session.set_remote_ice_credentials(IceCredentials {
        ufrag: "peerufrag".to_string(),
        pwd: "peerpasswordpeerpassword".to_string(),
    });
    client
        .session
        .add_remote_ice_candidate(&format!(
            "candidate:1 1 UDP 2130706431 {} {} typ host",
            peer.addr.ip(),
            peer.addr.port()
        ))
        .unwrap();

    // handshake_failure (40), fatal (2), plaintext, from the stranger.
    stranger
        .send_to(&dtls::plaintext_alert(0, 2, 40), client.addr)
        .await
        .unwrap();
    peer.start_with(DtlsRole::Client, client.fingerprint(), |config| {
        config.initial_rto = Duration::from_secs(8);
        config.handshake_budget = Duration::from_secs(30);
    });
    peer.flush(client.addr).await;

    let client_addr = client.addr;
    let fingerprint = peer.fingerprint();
    let peer_addr = peer.addr;
    tokio::join!(
        client.begin(peer_addr, fingerprint, fast_timings()),
        peer.drive(
            client_addr,
            Duration::from_millis(3300),
            |_| false,
            |_| true
        ),
    );
    let progress = handshake(&mut client, &mut peer, Duration::from_secs(4)).await;
    assert_eq!(progress, SecureProgress::Ready);
    let connected = capture.named("dtls.handshake.connected");
    assert_eq!(
        connected[0].get("early_datagrams").map(String::as_str),
        Some("1"),
        "only the peer's datagram was fed: {connected:?}"
    );
    assert_eq!(capture.named("dtls.handshake.failed").len(), 0);
}

// ----- hang-up racing the handshake ----------------------------------------

/// A `close()` at any moment of the handshake, including the moment it
/// completes: the session never reports `Ready` afterwards, has no keys and
/// no forward ring, cannot be started again, and the driver stops sending
/// (at most one more datagram, the `close_notify`; no retransmissions).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_racing_handshake_completion_never_leaves_a_ready_session() {
    // How long a handshake takes here, to spread the close over it.
    let probe = Instant::now();
    let (probe_client, _probe_peer) = connected(DtlsRole::Client).await;
    let typical = probe.elapsed();
    drop(probe_client);

    for role in BOTH_ROLES {
        for step in 0..8u32 {
            let delay = typical * step / 5;
            let mut client = Client::new(role);
            let mut peer = Peer::new().await;
            peer.start(opposite(role), client.fingerprint());
            client
                .begin(peer.addr, peer.fingerprint(), fast_timings())
                .await;
            let client_addr = client.addr;
            // Drive the peer for `delay`, then close while it keeps running.
            peer.drive(client_addr, delay, |_| false, |_| true).await;
            client.session.close().await.unwrap();

            assert!(
                matches!(client.session.poll_secure(), SecureProgress::Failed(..)),
                "{role:?} step {step}"
            );
            assert!(!client.session.is_ready());
            assert!(client.session.negotiated_srtp_keys().is_none());
            assert!(client.session.dtls_forward_tx().is_none());
            assert_eq!(client.session.poll_security_closed(), None);

            // Let the close reach the wire, then the driver must be silent
            // for longer than two retransmission intervals (200 ms, 400 ms).
            peer.drive(client_addr, Duration::from_millis(150), |_| false, |_| true)
                .await;
            let after_close = peer.received.len();
            peer.drive(client_addr, Duration::from_millis(700), |_| false, |_| true)
                .await;
            assert_eq!(
                peer.received.len(),
                after_close,
                "{role:?} step {step}: the driver kept sending after close"
            );
            assert!(matches!(
                client.session.poll_secure(),
                SecureProgress::Failed(..)
            ));
            assert!(
                client
                    .session
                    .begin_secure("again", &params(peer.fingerprint()), fast_timings())
                    .await
                    .is_err()
            );
        }
    }
}

// ----- hostile input through the forward ring ------------------------------

/// SI-10: after the handshake, nothing that is not an authenticated
/// epoch-1 record ends the association or puts the ring out of step.
/// Truncated, oversized-length, forged and replayed datagrams are pushed
/// the way the audio thread would push them; then a genuine `close_notify`
/// is still delivered and reported.
#[tokio::test]
async fn hostile_datagrams_through_the_forward_ring_do_not_end_the_association() {
    for role in BOTH_ROLES {
        let (mut client, mut peer) = connected(role).await;
        let mut forward = client.session.dtls_forward_tx().expect("forward ring");

        let record = |kind: u8, epoch: u16, seq: u8, claimed: u16, body: &[u8]| {
            let mut datagram = vec![kind, 0xFE, 0xFD];
            datagram.extend_from_slice(&epoch.to_be_bytes());
            datagram.extend_from_slice(&[0, 0, 0, 0, 0, seq]);
            datagram.extend_from_slice(&claimed.to_be_bytes());
            datagram.extend_from_slice(body);
            datagram
        };
        let mut hostile: Vec<Vec<u8>> = vec![
            vec![22],
            vec![23, 0xFE, 0xFD],
            // Length field far beyond the datagram.
            record(22, 0, 9, 0xFFFF, &[0xAA; 20]),
            // Zero-length record.
            record(21, 1, 9, 0, &[]),
            // Forged epoch-1 alert and application data (no valid tag).
            record(21, 1, 50, 18, &[0x5A; 18]),
            record(23, 1, 51, 40, &[0xA5; 40]),
            // Unknown epoch.
            record(21, 7, 1, 18, &[0x11; 18]),
            // Plaintext fatal alert and plaintext close_notify.
            dtls::plaintext_alert(60, 2, 40),
            dtls::plaintext_alert(61, 1, 0),
            // Wrong protocol version.
            vec![21, 0x03, 0x03, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 2, 40],
            // Full-size junk.
            vec![22; 1500],
        ];
        // The peer's own handshake datagrams, replayed.
        hostile.extend(peer.sent.iter().cloned());

        for datagram in &hostile {
            assert!(
                forward.try_forward(datagram),
                "ring refused {} bytes",
                datagram.len()
            );
            // Let the driver drain (the ring holds five full datagrams).
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(
                client.session.poll_security_closed(),
                None,
                "{role:?}: ended by {:02x?}",
                &datagram[..datagram.len().min(16)]
            );
        }
        // Oversized and empty datagrams never enter the ring.
        assert!(!forward.try_forward(&[22; 1501]));
        assert!(!forward.try_forward(&[]));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(client.session.poll_security_closed(), None, "{role:?}");
        assert!(client.session.is_ready());
        assert!(client.session.negotiated_srtp_keys().is_some());

        // The stream is still in step: the real close_notify gets through.
        peer.association().close();
        let close_notify = peer.association().poll_transmit().expect("close_notify");
        assert!(forward.try_forward(&close_notify));
        let deadline = Instant::now() + Duration::from_secs(2);
        let closed = loop {
            if let Some(cause) = client.session.poll_security_closed() {
                break cause;
            }
            assert!(Instant::now() < deadline, "{role:?}: close_notify lost");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(closed, SecurityCause::ClosedByPeer);
        assert!(!client.session.is_ready());
    }
}

/// A full ring refuses at once and loses nothing that was queued: with the
/// driver not running (current-thread runtime, no await), only what fits
/// is taken; once the driver runs, the ring is usable again.
#[tokio::test]
async fn full_forward_ring_refuses_without_blocking_and_recovers() {
    let (mut client, mut peer) = connected(DtlsRole::Client).await;
    let mut forward = client.session.dtls_forward_tx().expect("forward ring");
    // Let the driver take the attach command and park.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let started = Instant::now();
    let mut taken = 0u32;
    for _ in 0..10_000 {
        if forward.try_forward(&[22; 1500]) {
            taken += 1;
        }
    }
    let spent = started.elapsed();
    assert_eq!(taken, 5, "8 KiB ring holds five full datagrams");
    assert!(spent < Duration::from_millis(500), "{spent:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(client.session.poll_security_closed(), None);
    assert!(client.session.is_ready());
    peer.association().close();
    let close_notify = peer.association().poll_transmit().expect("close_notify");
    assert!(forward.try_forward(&close_notify), "ring drained");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        client.session.poll_security_closed(),
        Some(SecurityCause::ClosedByPeer)
    );
}

/// The audio pipeline can be restarted (hold and resume): each start
/// attaches a new ring and the last one wins. A producer of an earlier
/// ring is harmless, and the newest ring delivers.
#[tokio::test]
async fn the_last_forward_ring_attached_is_the_one_serviced() {
    let (mut client, mut peer) = connected(DtlsRole::Server).await;
    let mut first = client.session.dtls_forward_tx().expect("first ring");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut second = client.session.dtls_forward_tx().expect("second ring");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut third = client.session.dtls_forward_tx().expect("third ring");
    tokio::time::sleep(Duration::from_millis(20)).await;

    peer.association().close();
    let close_notify = peer.association().poll_transmit().expect("close_notify");
    // Stale rings take the bytes but nobody reads them.
    assert!(first.try_forward(&close_notify));
    assert!(second.try_forward(&close_notify));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(client.session.poll_security_closed(), None);
    assert!(client.session.is_ready());

    assert!(third.try_forward(&close_notify));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        client.session.poll_security_closed(),
        Some(SecurityCause::ClosedByPeer)
    );
    // No ring for a closed association.
    assert!(client.session.dtls_forward_tx().is_none());
}

/// QA D2 / SEC-003: attaching a forward ring cannot fail for want of room.
/// Any number of pipeline starts in a row, without the driver task being
/// scheduled in between, each get a ring, and the newest one is serviced.
/// (With the former command queue of four the fifth start got none.)
#[tokio::test]
async fn any_number_of_forward_rings_can_be_attached_in_a_row() {
    let (mut client, mut peer) = connected(DtlsRole::Client).await;
    // No await between these: the driver cannot run.
    let mut rings: Vec<_> = (0..16)
        .map(|n| {
            client
                .session
                .dtls_forward_tx()
                .unwrap_or_else(|| panic!("ring {n} refused"))
        })
        .collect();
    let mut newest = rings.pop().expect("sixteen rings");

    peer.association().close();
    let close_notify = peer.association().poll_transmit().expect("close_notify");
    assert!(newest.try_forward(&close_notify));
    let deadline = Instant::now() + Duration::from_secs(2);
    while client.session.poll_security_closed() != Some(SecurityCause::ClosedByPeer) {
        assert!(Instant::now() < deadline, "newest ring not serviced");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A datagram already in a ring when the next ring replaces it is still
/// fed to the association: a pipeline restart loses nothing that the old
/// audio thread had forwarded.
#[tokio::test]
async fn a_replaced_forward_ring_is_drained_first() {
    let (mut client, mut peer) = connected(DtlsRole::Server).await;
    let mut first = client.session.dtls_forward_tx().expect("first ring");
    // Let the driver take the first ring.
    tokio::time::sleep(Duration::from_millis(50)).await;
    peer.association().close();
    let close_notify = peer.association().poll_transmit().expect("close_notify");
    // No await from here to the second attach: the driver sees the
    // datagram and the new ring in the same pass.
    assert!(first.try_forward(&close_notify));
    let _second = client.session.dtls_forward_tx().expect("second ring");
    let deadline = Instant::now() + Duration::from_secs(2);
    while client.session.poll_security_closed() != Some(SecurityCause::ClosedByPeer) {
        assert!(
            Instant::now() < deadline,
            "datagram in the replaced ring lost"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ----- hostile sizes during the handshake ----------------------------------

/// SI-10: datagrams from the negotiated remote that are no DTLS record the
/// association could take (empty, larger than any DTLS datagram, STUN and
/// RTP class) are dropped by the driver's demultiplexer during the
/// handshake and do not disturb it, in both roles.
#[tokio::test]
async fn oversized_empty_and_non_dtls_datagrams_from_the_remote_do_not_disturb_the_handshake() {
    for role in BOTH_ROLES {
        let mut client = Client::new(role);
        let mut peer = Peer::new().await;
        peer.start(opposite(role), client.fingerprint());
        client
            .begin(peer.addr, peer.fingerprint(), fast_timings())
            .await;
        for datagram in [
            Vec::new(),
            vec![22u8; 1501],
            vec![22u8; 9000],
            vec![0x80u8; 172],
            vec![0x00u8, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42],
            vec![0xFFu8; 64],
        ] {
            peer.socket.send_to(&datagram, client.addr).await.unwrap();
        }
        let progress = handshake(&mut client, &mut peer, Duration::from_secs(5)).await;
        assert_eq!(progress, SecureProgress::Ready, "client as {role:?}");
        assert_eq!(peer.failed, None);
        assert!(peer.keys.is_some());
    }
}

// ----- one association per session -----------------------------------------

/// SC-23: a session whose handshake failed cannot be started again, and a
/// refused second start sends nothing.
#[tokio::test]
async fn begin_secure_is_refused_after_a_failed_handshake() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = Client::new(DtlsRole::Client);
    let fingerprint = dtls::identity().fingerprint().clone();
    let timings = DriverTimings {
        initial_rto: Duration::from_millis(100),
        handshake_budget: Duration::from_millis(500),
        ..DriverTimings::default()
    };
    client
        .begin(silent.local_addr().unwrap(), fingerprint.clone(), timings)
        .await;
    // Refused while the first one runs.
    assert!(
        client
            .session
            .begin_secure("second", &params(fingerprint.clone()), timings)
            .await
            .is_err()
    );
    assert_eq!(
        client.settle(Duration::from_secs(3)).await,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    // Drain what the one driver sent.
    let mut buf = [0u8; 2048];
    while tokio::time::timeout(Duration::from_millis(100), silent.recv_from(&mut buf))
        .await
        .is_ok()
    {}

    for attempt in 0..3 {
        assert!(
            client
                .session
                .begin_secure("again", &params(fingerprint.clone()), timings)
                .await
                .is_err(),
            "attempt {attempt}"
        );
        assert!(client.session.set_dtls_role(DtlsRole::Server).is_err());
    }
    assert_eq!(
        client.session.poll_secure(),
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(400), silent.recv_from(&mut buf))
            .await
            .is_err(),
        "a refused start sent a datagram"
    );
}

// ----- a driver task that dies ---------------------------------------------

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The driver task is gone without having reported anything (its runtime
/// was shut down, as after a panic or an abort): the handshake is reported
/// failed, never ready.
#[test]
fn driver_task_death_during_the_handshake_is_a_failure() {
    let driver_runtime = current_thread();
    let (mut client, silent) = driver_runtime.block_on(async {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut client = Client::new(DtlsRole::Client);
        let fingerprint = dtls::identity().fingerprint().clone();
        client
            .begin(silent.local_addr().unwrap(), fingerprint, fast_timings())
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(client.session.poll_secure(), SecureProgress::Pending);
        (client, silent)
    });
    // Dropping the runtime drops the driver task where it stands.
    drop(driver_runtime);

    let (capture, _guard) = Capture::install();
    assert_eq!(
        client.session.poll_secure(),
        SecureProgress::Failed(SecurityCause::Internal, CauseBasis::Local)
    );
    assert!(!client.session.is_ready());
    assert!(client.session.negotiated_srtp_keys().is_none());
    assert!(client.session.dtls_forward_tx().is_none());
    // NIST-002: the driver wrote nothing, so its handle wrote the record.
    assert_eq!(
        client.session.poll_secure(),
        SecureProgress::Failed(SecurityCause::Internal, CauseBasis::Local)
    );
    let failed = capture.named("dtls.handshake.failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    let field = |name: &str| failed[0].get(name).map(String::as_str);
    assert_eq!(field("origin"), Some("driver-gone"));
    assert_eq!(field("cause"), Some("dtls-internal"));
    assert_eq!(field("cause_basis"), Some("local"));
    assert_eq!(field("role"), Some("client"));
    assert_eq!(capture.named("dtls.handshake.cancelled"), Vec::new());
    assert_eq!(capture.named("dtls.association.closed"), Vec::new());
    drop(silent);
}

/// The same after the handshake: the association is no longer serviced, so
/// the session reports it closed (`Internal`), once, and drops the keys.
#[test]
fn driver_task_death_after_the_handshake_is_reported_and_drops_the_keys() {
    for role in BOTH_ROLES {
        let driver_runtime = current_thread();
        let (mut client, peer) = driver_runtime.block_on(connected(role));
        assert!(client.session.is_ready());
        assert_eq!(client.session.poll_security_closed(), None);
        drop(peer);
        drop(driver_runtime);

        let (capture, _guard) = Capture::install();
        assert_eq!(
            client.session.poll_security_closed(),
            Some(SecurityCause::Internal),
            "{role:?}"
        );
        // NIST-002: one `closed` record from the handle, and no second
        // handshake outcome (the driver had recorded `connected`).
        let closed = capture.named("dtls.association.closed");
        assert_eq!(closed.len(), 1, "{closed:?}");
        let field = |name: &str| closed[0].get(name).map(String::as_str);
        assert_eq!(field("origin"), Some("driver-gone"));
        assert_eq!(field("reason"), Some("local-error"));
        assert_eq!(field("cause"), Some("dtls-internal"));
        assert_eq!(field("cause_basis"), Some("local"));
        assert_eq!(capture.named("dtls.handshake.failed"), Vec::new());
        assert!(!client.session.is_ready());
        assert!(client.session.negotiated_srtp_keys().is_none());
        assert!(client.session.dtls_forward_tx().is_none());
        assert_eq!(client.session.poll_security_closed(), None, "reported once");
        assert!(matches!(
            client.session.poll_secure(),
            SecureProgress::Failed(SecurityCause::Internal, CauseBasis::Local)
        ));
    }
}

// ----- timers under a flood ------------------------------------------------

/// What a silent peer saw of a client-role handshake with a 200 ms first
/// retransmission interval and a 2 s budget.
struct TimerRun {
    /// DTLS datagrams (`ClientHello` and its retransmissions) the peer got
    /// in the first 1.6 s.
    hellos: usize,
    outcome: SecureProgress,
    /// When the outcome was reported.
    reported_after: Duration,
}

async fn timer_run(flood: bool) -> TimerRun {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    silent.set_nonblocking(true).unwrap();
    let mut client = Client::new(DtlsRole::Client);
    let fingerprint = dtls::identity().fingerprint().clone();
    let timings = DriverTimings {
        initial_rto: Duration::from_millis(200),
        handshake_budget: Duration::from_secs(2),
        ..DriverTimings::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut flooders = Vec::new();
    if flood {
        // Senders that are not the negotiated remote (four unless
        // QA_FLOOD_SENDERS says otherwise): DTLS-class datagrams and
        // unclassifiable ones, alternating per sender.
        let senders: usize = std::env::var("QA_FLOOD_SENDERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        for first in [22u8, 0xFF].into_iter().cycle().take(senders) {
            let stop = Arc::clone(&stop);
            let target = client.addr;
            flooders.push(std::thread::spawn(move || {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let datagram = [first; 64];
                while !stop.load(Ordering::Relaxed) {
                    let _ = socket.send_to(&datagram, target);
                }
            }));
        }
    }
    let started = Instant::now();
    client
        .begin(silent.local_addr().unwrap(), fingerprint, timings)
        .await;
    let mut hellos = 0;
    let mut buf = [0u8; 2048];
    while started.elapsed() < Duration::from_millis(1600) {
        while silent.recv_from(&mut buf).is_ok() {
            hellos += 1;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let outcome = client.settle(Duration::from_secs(6)).await;
    let reported_after = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    for flooder in flooders {
        flooder.join().unwrap();
    }
    TimerRun {
        hellos,
        outcome,
        reported_after,
    }
}

/// Baseline for the flood test: `ClientHello` at 0, 0.2, 0.6 and 1.4 s
/// (RFC 6347 §4.2.4.1 doubling), `Timeout` at the 2 s budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_timers_without_a_flood() {
    let run = timer_run(false).await;
    assert_eq!(
        run.outcome,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert_eq!(run.hellos, 4, "ClientHello and three retransmissions");
    assert!(
        run.reported_after >= Duration::from_millis(1900)
            && run.reported_after < Duration::from_millis(2600),
        "{:?}",
        run.reported_after
    );
}

/// SC-5: under a flood of datagrams from addresses that are not the
/// negotiated remote the handshake still fails closed and is bounded: it
/// ends as `Timeout` no later than the driver's watchdog (budget + 1 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_under_a_wrong_source_flood_is_bounded_by_the_watchdog() {
    let run = timer_run(true).await;
    eprintln!(
        "flood: hellos={} outcome={:?} reported_after={:?}",
        run.hellos, run.outcome, run.reported_after
    );
    assert_eq!(
        run.outcome,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert!(run.hellos >= 1);
    // Budget 2 s + watchdog 1 s, plus slack for a loaded machine.
    assert!(
        run.reported_after < Duration::from_secs(5),
        "not bounded by the watchdog: {:?}",
        run.reported_after
    );
}

/// The same flood must not stop the handshake's own timers: the
/// `ClientHello` is still retransmitted and the handshake ends at its
/// budget, not one second later at the watchdog.
///
/// Regression test for QA finding D1 (RFC 6347 §4.2.4, SC-5). The driver's
/// `select!` is biased with the socket ahead of the timer, so while the
/// socket is always readable its timer arm is never polled; the driver
/// therefore handles a due association timer at the top of every pass of
/// its loop. Before that fix this test saw 1 `ClientHello` instead of 4
/// and an outcome from the watchdog at 3 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_timers_keep_running_under_a_wrong_source_flood() {
    let run = timer_run(true).await;
    eprintln!(
        "flood: hellos={} outcome={:?} reported_after={:?}",
        run.hellos, run.outcome, run.reported_after
    );
    assert_eq!(
        run.outcome,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert!(
        run.hellos >= 3,
        "retransmissions starved by the flood: {} ClientHello datagram(s) in 1.6 s (4 without a flood)",
        run.hellos
    );
    assert!(
        run.reported_after < Duration::from_millis(2700),
        "ended by the watchdog, not by the budget: {:?}",
        run.reported_after
    );
}
