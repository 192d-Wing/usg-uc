//! The DTLS driver's structured log records (plan §4.3, §9.5).
//!
//! NIST 800-53 Rev5: AU-2 / AU-3 -- exactly one record per handshake
//! outcome, with the role, a fixed cause, what the cause rests on, and
//! whether authentication was mutual. Unauthenticated (epoch 0) causes and
//! the presented fingerprint are labelled as such. SC-12: no key, salt or
//! random ever appears in a record.
//!
//! A capturing `tracing` layer is installed for the test's thread; the
//! tests run on a current-thread runtime, so the driver task logs there.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use client_sip_ua::dtls_driver::{CauseBasis, DriverTimings, SecureProgress, SecurityCause};
use common::dtls;
use common::{Client, Peer, connected, fast_timings, handshake, hex, opposite};
use proto_dtls::DtlsRole;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};

const TARGET: &str = "client_sip_ua::dtls_driver";

/// One captured event: level and every field rendered as text.
#[derive(Debug, Clone)]
struct Record {
    target: String,
    level: tracing::Level,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    fn event(&self) -> &str {
        self.get("event").unwrap_or_default()
    }

    /// Everything in the record as one string, for the secret scan.
    fn text(&self) -> String {
        use std::fmt::Write;
        self.fields
            .iter()
            .fold(String::new(), |mut text, (name, value)| {
                let _ = write!(text, "{name}={value} ");
                text
            })
            .to_ascii_lowercase()
    }
}

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
struct Capture(Arc<Mutex<Vec<Record>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = FieldText::default();
        event.record(&mut fields);
        self.0.lock().unwrap().push(Record {
            target: event.metadata().target().to_string(),
            level: *event.metadata().level(),
            fields: fields.0,
        });
    }
}

impl Capture {
    /// Installs the layer for this thread until the guard is dropped.
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    fn all(&self) -> Vec<Record> {
        self.0.lock().unwrap().clone()
    }

    /// The driver's records.
    fn driver(&self) -> Vec<Record> {
        self.all()
            .into_iter()
            .filter(|r| r.target == TARGET)
            .collect()
    }

    fn named(&self, event: &str) -> Vec<Record> {
        self.driver()
            .into_iter()
            .filter(|r| r.event() == event)
            .collect()
    }

    async fn wait_for(&self, event: &str) -> Record {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(record) = self.named(event).into_iter().next() {
                return record;
            }
            assert!(Instant::now() < deadline, "no {event} record");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

const OUTCOMES: [&str; 3] = [
    "dtls.handshake.connected",
    "dtls.handshake.failed",
    "dtls.handshake.cancelled",
];

fn outcome_records(capture: &Capture) -> Vec<String> {
    capture
        .driver()
        .iter()
        .map(|r| r.event().to_string())
        .filter(|e| OUTCOMES.contains(&e.as_str()))
        .collect()
}

/// The handshake randoms as they went over the wire (`ClientHello` and
/// `ServerHello` bodies: version, then 32 bytes of random).
fn wire_randoms(peer: &Peer) -> Vec<Vec<u8>> {
    peer.sent
        .iter()
        .chain(peer.received.iter())
        .flat_map(|datagram| dtls::records(datagram))
        .filter(|record| record.epoch == 0)
        .filter_map(|record| record.message())
        .filter(|message| matches!(message.msg_type, 1 | 2) && message.body.len() >= 34)
        .map(|message| message.body[2..34].to_vec())
        .collect()
}

/// SC-12: none of the exported keys or salts, and neither random, appears
/// in any record of any target, in hex or as a byte list.
fn assert_no_secrets(capture: &Capture, peer: &Peer) {
    let mut secrets: Vec<Vec<u8>> = wire_randoms(peer);
    if let Some(keys) = &peer.keys {
        secrets.extend([
            keys.client_write_key.clone(),
            keys.server_write_key.clone(),
            keys.client_write_salt.clone(),
            keys.server_write_salt.clone(),
        ]);
    }
    assert!(secrets.len() >= 2, "both randoms were seen on the wire");
    for record in capture.all() {
        let text = record.text();
        for secret in &secrets {
            assert!(!text.contains(&hex(secret)), "secret in {record:?}");
            let listed = format!("{secret:?}");
            assert!(!text.contains(&listed), "secret in {record:?}");
        }
    }
}

/// One test per role: each runs on its own thread, so a driver that is
/// still closing from another case cannot write into this capture.
async fn success_writes_one_connected_record(role: DtlsRole) {
    {
        let (capture, _guard) = Capture::install();
        let (client, peer) = connected(role).await;

        assert_eq!(outcome_records(&capture), ["dtls.handshake.connected"]);
        let record = capture.wait_for("dtls.handshake.connected").await;
        assert_eq!(record.level, tracing::Level::INFO);
        assert_eq!(record.get("call_id"), Some("test-call"));
        assert_eq!(
            record.get("role"),
            Some(if role == DtlsRole::Client {
                "client"
            } else {
                "server"
            })
        );
        assert_eq!(record.get("remote"), Some(peer.addr.to_string().as_str()));
        assert_eq!(record.get("srtp_profile"), Some("AEAD_AES_256_GCM"));
        assert_eq!(record.get("peer_authenticated"), Some("true"));
        // The verified certificate's fingerprint, computed locally.
        assert_eq!(
            record.get("peer_fingerprint"),
            Some(hex(peer.fingerprint().bytes()).as_str())
        );
        // IA-3: as server we always ask for the client's certificate; as
        // client it is mutual because this peer (our own server role)
        // asked for ours. Either way the flag equals what the association
        // on the asking side reports.
        assert_eq!(record.get("mutual_authentication"), Some("true"));
        assert!(peer.assoc.as_ref().unwrap().client_certificate_requested());
        for counter in [
            "duration_ms",
            "retransmits",
            "records_discarded",
            "replays",
            "fragments_rejected",
            "early_datagrams",
        ] {
            assert!(
                record
                    .get(counter)
                    .is_some_and(|v| v.parse::<u64>().is_ok()),
                "{counter} in {record:?}"
            );
        }
        assert!(capture.named("dtls.association.closed").is_empty());
        assert_no_secrets(&capture, &peer);
        drop(client);
    }
}

#[tokio::test]
async fn success_writes_one_connected_record_as_client() {
    success_writes_one_connected_record(DtlsRole::Client).await;
}

#[tokio::test]
async fn success_writes_one_connected_record_as_server() {
    success_writes_one_connected_record(DtlsRole::Server).await;
}

/// A server that sends no `CertificateRequest` authenticates itself only:
/// the record must not claim mutual authentication.
#[tokio::test]
async fn server_only_authentication_is_not_recorded_as_mutual() {
    use common::dtls::Puppet;
    use tokio::net::UdpSocket;

    let (capture, _guard) = Capture::install();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut puppet = Puppet::new(DtlsRole::Server);
    puppet.script.omit_certificate_request = true;
    let mut client = Client::new(DtlsRole::Client);
    client
        .begin(
            socket.local_addr().unwrap(),
            puppet.fingerprint(),
            DriverTimings::default(),
        )
        .await;
    let mut buf = [0u8; 4096];
    let (len, from) = socket.recv_from(&mut buf).await.unwrap();
    puppet.absorb(&buf[..len]);
    socket
        .send_to(&puppet.server_flight4(), from)
        .await
        .unwrap();
    while puppet.peer_finished_ok.is_none() {
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        puppet.absorb(&buf[..len]);
    }
    socket
        .send_to(&puppet.server_flight6(), from)
        .await
        .unwrap();
    assert_eq!(
        client.settle(Duration::from_secs(3)).await,
        SecureProgress::Ready
    );
    let record = capture.wait_for("dtls.handshake.connected").await;
    assert_eq!(record.get("peer_authenticated"), Some("true"));
    assert_eq!(record.get("mutual_authentication"), Some("false"));
}

async fn fingerprint_mismatch_is_recorded_as_unauthenticated_input(role: DtlsRole) {
    {
        let (capture, _guard) = Capture::install();
        let mut client = Client::new(role);
        let mut peer = Peer::new().await;
        peer.start(opposite(role), client.fingerprint());
        let someone_else = dtls::identity().fingerprint().clone();
        client
            .begin(peer.addr, someone_else.clone(), fast_timings())
            .await;
        let progress = handshake(&mut client, &mut peer, Duration::from_secs(4)).await;
        assert_eq!(
            progress,
            SecureProgress::Failed(
                SecurityCause::FingerprintMismatch,
                CauseBasis::UnauthenticatedInput
            )
        );

        assert_eq!(outcome_records(&capture), ["dtls.handshake.failed"]);
        let record = capture.wait_for("dtls.handshake.failed").await;
        assert_eq!(record.level, tracing::Level::WARN);
        assert_eq!(record.get("cause"), Some("dtls-fingerprint-mismatch"));
        assert_eq!(record.get("cause_basis"), Some("unauthenticated-input"));
        assert_eq!(record.get("watchdog"), Some("false"));
        assert_eq!(record.get("alert"), None);
        // What was presented, labelled unauthenticated; never under the
        // name used for a verified peer.
        assert_eq!(
            record.get("presented_fingerprint_unauthenticated"),
            Some(hex(peer.fingerprint().bytes()).as_str())
        );
        assert_eq!(record.get("peer_fingerprint"), None);
        assert_eq!(record.get("peer_authenticated"), None);
        assert_eq!(record.get("mutual_authentication"), None);
        assert!(!record.text().contains(&hex(someone_else.bytes())));
        assert_no_secrets(&capture, &peer);
    }
}

#[tokio::test]
async fn fingerprint_mismatch_is_recorded_as_unauthenticated_input_as_client() {
    fingerprint_mismatch_is_recorded_as_unauthenticated_input(DtlsRole::Client).await;
}

#[tokio::test]
async fn fingerprint_mismatch_is_recorded_as_unauthenticated_input_as_server() {
    fingerprint_mismatch_is_recorded_as_unauthenticated_input(DtlsRole::Server).await;
}

#[tokio::test]
async fn plaintext_alert_is_recorded_with_its_number_as_unauthenticated() {
    let (capture, _guard) = Capture::install();
    let responder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = Client::new(DtlsRole::Client);
    client
        .begin(
            responder.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            fast_timings(),
        )
        .await;
    let mut buf = [0u8; 2048];
    let (_, from) = responder.recv_from(&mut buf).await.unwrap();
    responder
        .send_to(&dtls::plaintext_alert(0, 2, 40), from)
        .await
        .unwrap();
    assert_eq!(
        client.settle(Duration::from_secs(4)).await,
        SecureProgress::Failed(SecurityCause::Alert(40), CauseBasis::UnauthenticatedInput)
    );
    assert_eq!(outcome_records(&capture), ["dtls.handshake.failed"]);
    let record = capture.wait_for("dtls.handshake.failed").await;
    assert_eq!(record.get("cause"), Some("dtls-alert"));
    assert_eq!(record.get("failure"), Some("PeerAlert"));
    assert_eq!(record.get("alert"), Some("40"));
    assert_eq!(record.get("cause_basis"), Some("unauthenticated-input"));
    assert_eq!(record.get("presented_fingerprint_unauthenticated"), None);
    assert_eq!(record.get("origin"), None, "written by the driver");
}

/// NIST-002: the owner's own deadline (the call manager's, budget + 2 s)
/// ends a handshake the driver has not ended. That is a security failure:
/// it leaves one `dtls.handshake.failed` record with a local basis and its
/// origin, and the driver, closed by it, writes no `cancelled` record.
#[tokio::test]
async fn owner_deadline_writes_one_failed_record_and_no_cancelled() {
    let (capture, _guard) = Capture::install();
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(DtlsRole::Server);
    client
        .begin(
            silent.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            fast_timings(),
        )
        .await;
    assert_eq!(client.session.poll_secure(), SecureProgress::Pending);
    assert_eq!(
        client.session.abandon_secure(),
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    // Terminal, and reported the same way from then on.
    assert_eq!(
        client.session.poll_secure(),
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert_eq!(
        client.session.abandon_secure(),
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert!(!client.session.is_ready());
    assert!(client.session.negotiated_srtp_keys().is_none());

    let record = capture.wait_for("dtls.handshake.failed").await;
    assert_eq!(record.level, tracing::Level::WARN);
    assert_eq!(record.get("cause"), Some("dtls-timeout"));
    assert_eq!(record.get("cause_basis"), Some("local"));
    assert_eq!(record.get("origin"), Some("call-manager-deadline"));
    assert_eq!(record.get("role"), Some("server"));
    assert_eq!(
        record.get("remote"),
        Some(silent.local_addr().unwrap().to_string().as_str())
    );
    assert!(record.get("duration_ms").is_some());
    // The driver gets the close, exits, and adds nothing.
    client.session.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(outcome_records(&capture), ["dtls.handshake.failed"]);
    assert!(capture.named("dtls.association.closed").is_empty());
}

/// SEC-016 / NIST-018: the handshake completes between the owner's last
/// poll and its deadline. The owner still ends the call as a timeout; the
/// trail is `connected` and then exactly one `dtls.association.closed`,
/// written for the owner (`local-error`, `origin="call-manager-deadline"`),
/// not a `local-close` that would read as a normal call.
#[tokio::test]
async fn owner_deadline_after_connect_writes_one_closed_record_with_its_origin() {
    let (capture, _guard) = Capture::install();
    let mut client = Client::new(DtlsRole::Client);
    let mut peer = Peer::new().await;
    peer.start(opposite(DtlsRole::Client), client.fingerprint());
    client
        .begin(peer.addr, peer.fingerprint(), fast_timings())
        .await;
    // The driver completes the handshake; the owner does not poll.
    let client_addr = client.addr;
    peer.drive(client_addr, Duration::from_secs(5), Peer::settled, |_| true)
        .await;
    capture.wait_for("dtls.handshake.connected").await;

    assert_eq!(
        client.session.abandon_secure(),
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert!(!client.session.is_ready());
    assert!(client.session.negotiated_srtp_keys().is_none());

    let record = capture.wait_for("dtls.association.closed").await;
    assert_eq!(record.level, tracing::Level::WARN);
    assert_eq!(record.get("reason"), Some("local-error"));
    assert_eq!(record.get("origin"), Some("call-manager-deadline"));
    assert_eq!(record.get("cause"), Some("dtls-timeout"));
    assert_eq!(record.get("cause_basis"), Some("local"));
    assert_eq!(record.get("role"), Some("client"));
    assert_eq!(record.get("remote"), Some(peer.addr.to_string().as_str()));
    // The driver gets the close, exits, and adds nothing.
    client.session.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(outcome_records(&capture), ["dtls.handshake.connected"]);
    assert_eq!(capture.named("dtls.association.closed").len(), 1);
    assert_no_secrets(&capture, &peer);
}

/// NIST-004 / SEC-007: a fatal alert in epoch 1 is the one end of a
/// connected association that is recorded as `peer-alert`, with the
/// failure's name, its basis, and the role and remote of the association.
#[tokio::test]
async fn authenticated_fatal_alert_after_connect_is_recorded_as_peer_alert() {
    use common::dtls::Puppet;
    use proto_dtls::record::ContentType;

    let (capture, _guard) = Capture::install();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    puppet.absorb(&buf[..len]);
    socket
        .send_to(&puppet.server_flight4(), from)
        .await
        .unwrap();
    while puppet.peer_finished_ok.is_none() {
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        puppet.absorb(&buf[..len]);
    }
    socket
        .send_to(&puppet.server_flight6(), from)
        .await
        .unwrap();
    assert_eq!(
        client.settle(Duration::from_secs(3)).await,
        SecureProgress::Ready
    );

    let mut forward = client.session.dtls_forward_tx().unwrap();
    // internal_error (80), fatal (2), protected in epoch 1.
    assert!(forward.try_forward(&puppet.seal(1, ContentType::Alert, &[2, 80])));
    let record = capture.wait_for("dtls.association.closed").await;
    assert_eq!(record.level, tracing::Level::WARN);
    assert_eq!(record.get("reason"), Some("peer-alert"));
    assert_eq!(record.get("alert"), Some("80"));
    assert_eq!(record.get("cause"), Some("dtls-alert"));
    assert_eq!(record.get("failure"), Some("PeerAlert"));
    assert_eq!(record.get("cause_basis"), Some("peer-authenticated"));
    assert_eq!(record.get("role"), Some("client"));
    assert_eq!(
        record.get("remote"),
        Some(socket.local_addr().unwrap().to_string().as_str())
    );
    assert_eq!(record.get("origin"), None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(capture.named("dtls.association.closed").len(), 1);
    assert_eq!(outcome_records(&capture), ["dtls.handshake.connected"]);
}

#[tokio::test(start_paused = true)]
async fn timeout_is_recorded_as_local() {
    let (capture, _guard) = Capture::install();
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(DtlsRole::Server);
    client
        .begin(
            silent.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            DriverTimings::default(),
        )
        .await;
    assert_eq!(
        client.settle(Duration::from_secs(30)).await,
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    );
    assert_eq!(outcome_records(&capture), ["dtls.handshake.failed"]);
    let record = capture.wait_for("dtls.handshake.failed").await;
    assert_eq!(record.get("cause"), Some("dtls-timeout"));
    assert_eq!(record.get("cause_basis"), Some("local"));
    assert_eq!(record.get("role"), Some("server"));
    assert_eq!(record.get("failure"), Some("Timeout"));
    assert_eq!(record.get("origin"), None, "written by the driver");
    // The association ended itself at its budget; the watchdog did not
    // have to.
    assert_eq!(record.get("watchdog"), Some("false"));
    assert_eq!(record.get("presented_fingerprint_unauthenticated"), None);
    assert_eq!(record.get("duration_ms"), Some("10000"));
}

#[tokio::test]
async fn cancel_writes_one_cancelled_record_and_no_failure() {
    let (capture, _guard) = Capture::install();
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Client::new(DtlsRole::Client);
    client
        .begin(
            silent.local_addr().unwrap(),
            dtls::identity().fingerprint().clone(),
            fast_timings(),
        )
        .await;
    client.session.close().await.unwrap();
    let record = capture.wait_for("dtls.handshake.cancelled").await;
    assert_eq!(record.level, tracing::Level::INFO);
    assert_eq!(record.get("role"), Some("client"));
    assert_eq!(
        record.get("remote"),
        Some(silent.local_addr().unwrap().to_string().as_str())
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(outcome_records(&capture), ["dtls.handshake.cancelled"]);
    assert!(capture.named("dtls.association.closed").is_empty());
}

#[tokio::test]
async fn peer_close_after_connect_writes_one_closed_record() {
    let (capture, _guard) = Capture::install();
    let (mut client, mut peer) = connected(DtlsRole::Client).await;
    let mut forward = client.session.dtls_forward_tx().unwrap();
    peer.association().close();
    let close_notify = peer.association().poll_transmit().unwrap();
    assert!(forward.try_forward(&close_notify));

    let record = capture.wait_for("dtls.association.closed").await;
    assert_eq!(record.level, tracing::Level::WARN);
    assert_eq!(record.get("reason"), Some("peer-close-notify"));
    assert_eq!(record.get("alert"), None);
    assert_eq!(record.get("failure"), None);
    assert_eq!(record.get("cause"), Some("dtls-closed-by-peer"));
    assert_eq!(record.get("cause_basis"), Some("peer-authenticated"));
    assert_eq!(record.get("role"), Some("client"));
    assert_eq!(record.get("remote"), Some(peer.addr.to_string().as_str()));
    assert!(record.get("transmit_dropped").is_some());
    assert!(record.get("transmit_would_block").is_some());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(outcome_records(&capture), ["dtls.handshake.connected"]);
    assert_eq!(capture.named("dtls.association.closed").len(), 1);
    assert_no_secrets(&capture, &peer);
}

#[tokio::test]
async fn local_close_after_connect_writes_one_closed_record() {
    let (capture, _guard) = Capture::install();
    let (mut client, peer) = connected(DtlsRole::Server).await;
    client.session.close().await.unwrap();
    let record = capture.wait_for("dtls.association.closed").await;
    assert_eq!(record.level, tracing::Level::INFO);
    assert_eq!(record.get("reason"), Some("local-close"));
    assert_eq!(record.get("role"), Some("server"));
    assert_eq!(record.get("remote"), Some(peer.addr.to_string().as_str()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(outcome_records(&capture), ["dtls.handshake.connected"]);
    assert_eq!(capture.named("dtls.association.closed").len(), 1);
    assert_no_secrets(&capture, &peer);
}
