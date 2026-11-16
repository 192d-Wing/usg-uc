//! Deterministic in-process loopback: a client `DtlsAssociation` against a
//! server `DtlsAssociation`, datagrams passed in memory, time driven by the
//! test. No sockets, no sleeping.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proto_dtls::record::{ContentType, DatagramRecords, encode_plaintext_record};
use proto_dtls::wire::handshake_msg::{
    ClientHello, HANDSHAKE_HEADER_LEN, HT_CLIENT_HELLO, HT_SERVER_HELLO, HandshakeHeader,
    ServerHello,
};
use proto_dtls::wire::reader::Reader;
use proto_dtls::{
    AssociationConfig, AssociationEvent, CertificateFingerprint, DtlsAssociation, DtlsCredentials,
    DtlsRole, FailureCause, SrtpKeyingMaterial,
};
use proto_rtp::{RtpHeader, RtpPacket};
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProtect, SrtpUnprotect};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uc_crypto::ecdsa::P384KeyPair;

/// A fresh self-signed P-384 identity.
fn identity() -> DtlsCredentials {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["loopback.invalid".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = Arc::new(P384KeyPair::from_pkcs8(&key.serialize_der()).unwrap());
    DtlsCredentials::new(vec![cert.der().to_vec()], key).unwrap()
}

/// An identity whose chain carries two more certificates after the leaf,
/// so its `Certificate` message (about 1.4 kB) does not fit one datagram at
/// the smallest MTU.
fn identity_with_long_chain() -> DtlsCredentials {
    let leaf = identity();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["chain.invalid".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = Arc::new(P384KeyPair::from_pkcs8(&key.serialize_der()).unwrap());
    let extra = leaf.certificate_chain()[0].clone();
    DtlsCredentials::new(vec![cert.der().to_vec(), extra.clone(), extra], key).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dir {
    ClientToServer,
    ServerToClient,
}

/// One side of the loopback and everything it reported.
struct Side {
    assoc: DtlsAssociation,
    keys: Option<SrtpKeyingMaterial>,
    failed: Option<FailureCause>,
    peer_closed: bool,
    connected_events: usize,
}

impl Side {
    fn new(config: AssociationConfig, now: Instant) -> Self {
        Self {
            assoc: DtlsAssociation::new(config, now).unwrap(),
            keys: None,
            failed: None,
            peer_closed: false,
            connected_events: 0,
        }
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.assoc.poll_event() {
            match event {
                AssociationEvent::Connected { keys } => {
                    self.connected_events += 1;
                    self.keys = Some(keys);
                }
                AssociationEvent::Failed { cause } => self.failed = Some(cause),
                AssociationEvent::PeerClosed => self.peer_closed = true,
            }
        }
    }

    const fn settled(&self) -> bool {
        self.keys.is_some() || self.failed.is_some()
    }
}

/// What the in-memory wire does with one datagram.
enum Wire {
    Deliver,
    Drop,
    Duplicate,
    Replace(Vec<u8>),
}

struct Loopback {
    client: Side,
    server: Side,
    start: Instant,
    now: Instant,
    /// Datagrams sent so far per direction (index passed to the wire).
    sent: [usize; 2],
}

impl Loopback {
    fn with(configure: impl Fn(&mut AssociationConfig, &mut AssociationConfig)) -> Self {
        let (client_id, server_id) = (identity(), identity());
        let mut client_cfg = AssociationConfig::new(
            DtlsRole::Client,
            client_id.clone(),
            vec![server_id.fingerprint().clone()],
        );
        let mut server_cfg = AssociationConfig::new(
            DtlsRole::Server,
            server_id,
            vec![client_id.fingerprint().clone()],
        );
        configure(&mut client_cfg, &mut server_cfg);
        let start = Instant::now();
        Self {
            client: Side::new(client_cfg, start),
            server: Side::new(server_cfg, start),
            start,
            now: start,
            sent: [0, 0],
        }
    }

    fn new() -> Self {
        Self::with(|_, _| {})
    }

    fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Moves every queued datagram across the wire once. Returns whether
    /// anything moved.
    fn pump(&mut self, wire: &mut impl FnMut(Dir, usize, &[u8]) -> Wire) -> bool {
        let mut moved = false;
        for dir in [Dir::ClientToServer, Dir::ServerToClient] {
            let (from, to, slot) = match dir {
                Dir::ClientToServer => (&mut self.client, &mut self.server, 0),
                Dir::ServerToClient => (&mut self.server, &mut self.client, 1),
            };
            while let Some(datagram) = from.assoc.poll_transmit() {
                moved = true;
                let index = self.sent[slot];
                self.sent[slot] += 1;
                match wire(dir, index, &datagram) {
                    Wire::Deliver => to.assoc.handle_datagram(&datagram, self.now),
                    Wire::Drop => {}
                    Wire::Duplicate => {
                        to.assoc.handle_datagram(&datagram, self.now);
                        to.assoc.handle_datagram(&datagram, self.now);
                    }
                    Wire::Replace(other) => to.assoc.handle_datagram(&other, self.now),
                }
            }
        }
        self.client.drain_events();
        self.server.drain_events();
        moved
    }

    /// Runs until both sides have connected or failed, advancing the fake
    /// clock to the next timeout whenever the wire is idle.
    fn run(&mut self, mut wire: impl FnMut(Dir, usize, &[u8]) -> Wire) {
        for _ in 0..10_000 {
            if self.pump(&mut wire) {
                continue;
            }
            if self.client.settled() && self.server.settled() {
                return;
            }
            let next = [
                self.client.assoc.poll_timeout(),
                self.server.assoc.poll_timeout(),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(next) = next else { return };
            self.now = self.now.max(next);
            self.client.assoc.handle_timeout(self.now);
            self.server.assoc.handle_timeout(self.now);
            self.client.drain_events();
            self.server.drain_events();
        }
        panic!("loopback did not settle");
    }

    fn assert_connected(&self) {
        assert_eq!(self.client.failed, None);
        assert_eq!(self.server.failed, None);
        let c = self.client.keys.as_ref().expect("client keys");
        let s = self.server.keys.as_ref().expect("server keys");
        assert_same_keys(c, s);
        assert_eq!(self.client.connected_events, 1);
        assert_eq!(self.server.connected_events, 1);
        assert!(self.client.assoc.is_connected());
        assert!(self.server.assoc.is_connected());
    }

    fn assert_no_keys(&self) {
        assert!(self.client.keys.is_none(), "client exported keys");
        assert!(self.server.keys.is_none(), "server exported keys");
        assert_eq!(self.client.connected_events, 0);
        assert_eq!(self.server.connected_events, 0);
    }
}

fn exported(keys: &SrtpKeyingMaterial) -> Vec<u8> {
    [
        keys.client_write_key.as_slice(),
        keys.server_write_key.as_slice(),
        keys.client_write_salt.as_slice(),
        keys.server_write_salt.as_slice(),
    ]
    .concat()
}

fn assert_same_keys(client: &SrtpKeyingMaterial, server: &SrtpKeyingMaterial) {
    let (c, s) = (exported(client), exported(server));
    assert_eq!(
        c.len(),
        88,
        "RFC 5764 §4.2: 2 x 32-byte key + 2 x 12-byte salt"
    );
    assert_eq!(c, s, "both sides must export identical keying material");
    assert_ne!(c, vec![0u8; 88]);
    assert_eq!(client.client_write_key.len(), 32);
    assert_eq!(client.client_write_salt.len(), 12);
    // The client's local (write) key is the server's remote (read) key.
    assert_eq!(
        client.local_key(DtlsRole::Client),
        server.remote_key(DtlsRole::Server)
    );
    assert_eq!(
        client.remote_key(DtlsRole::Client),
        server.local_key(DtlsRole::Server)
    );
    assert_eq!(
        client.local_salt(DtlsRole::Client),
        server.remote_salt(DtlsRole::Server)
    );
    assert_ne!(client.client_write_key, client.server_write_key);
}

const fn deliver(_: Dir, _: usize, _: &[u8]) -> Wire {
    Wire::Deliver
}

fn srtp_context(key: &[u8], salt: &[u8], direction: SrtpDirection, ssrc: u32) -> SrtpContext {
    let material = SrtpKeyMaterial::new(
        proto_srtp::SrtpProfile::AeadAes256Gcm,
        key.to_vec(),
        salt.to_vec(),
    )
    .unwrap();
    SrtpContext::new(&material, direction, ssrc).unwrap()
}

/// Rewrites the first record of `datagram` if it is an unfragmented
/// handshake message of `msg_type`, replacing its body with `edit(body)`.
/// Everything else is passed through untouched.
fn rewrite_hello(datagram: &[u8], msg_type: u8, edit: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, record) in DatagramRecords::new(datagram).enumerate() {
        let record = record.unwrap();
        let mut r = Reader::new(record.payload);
        let header = HandshakeHeader::parse(&mut r).ok();
        let is_target = i == 0
            && record.epoch == 0
            && record.content_type == ContentType::Handshake
            && header.is_some_and(|h| h.msg_type == msg_type && h.fragment_offset == 0);
        let payload = if is_target {
            let header = header.unwrap();
            let body = edit(&record.payload[HANDSHAKE_HEADER_LEN..]);
            let mut payload = Vec::new();
            HandshakeHeader::unfragmented(msg_type, header.message_seq, body.len())
                .unwrap()
                .encode(&mut payload)
                .unwrap();
            payload.extend_from_slice(&body);
            payload
        } else {
            record.payload.to_vec()
        };
        if record.epoch == 0 {
            out.extend(
                encode_plaintext_record(record.content_type, record.sequence_number, &payload)
                    .unwrap(),
            );
        } else {
            // Protected records are copied byte for byte.
            let start = record.payload.as_ptr() as usize - datagram.as_ptr() as usize - 13;
            out.extend_from_slice(&datagram[start..start + 13 + record.payload.len()]);
        }
    }
    out
}

// ----- success paths -------------------------------------------------------

#[test]
fn handshake_completes_and_both_sides_export_identical_keys() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();

    // No loss: nothing was retransmitted or discarded, and no time passed.
    assert_eq!(lo.client.assoc.stats().retransmits, 0);
    assert_eq!(lo.server.assoc.stats().retransmits, 0);
    assert_eq!(lo.client.assoc.stats().records_discarded, 0);
    assert_eq!(lo.server.assoc.stats().records_discarded, 0);
    assert_eq!(lo.elapsed(), Duration::ZERO);
    // ClientHello, ClientHello+cookie, flight 5 / HelloVerifyRequest,
    // flight 4, flight 6: the cookie exchange always happens.
    assert_eq!(lo.sent, [3, 3]);

    // Each side saw the other's certificate.
    assert!(lo.client.assoc.presented_fingerprint().is_some());
    assert!(lo.server.assoc.presented_fingerprint().is_some());
    // The client is done; the server keeps its last flight for a while.
    assert_eq!(lo.client.assoc.poll_timeout(), None);
    assert!(lo.server.assoc.poll_timeout().is_some());
    assert!(lo.client.assoc.poll_transmit().is_none());
    assert!(lo.server.assoc.poll_transmit().is_none());
}

#[test]
fn two_handshakes_export_different_keys() {
    let (mut a, mut b) = (Loopback::new(), Loopback::new());
    a.run(deliver);
    b.run(deliver);
    a.assert_connected();
    b.assert_connected();
    assert_ne!(
        exported(a.client.keys.as_ref().unwrap()),
        exported(b.client.keys.as_ref().unwrap())
    );
}

#[test]
fn exported_keys_protect_rtp_and_rtcp_in_both_directions() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();
    let ck = lo.client.keys.as_ref().unwrap();
    let sk = lo.server.keys.as_ref().unwrap();

    for (sender, sender_role, receiver, receiver_role, ssrc) in [
        (ck, DtlsRole::Client, sk, DtlsRole::Server, 0x1111_2222u32),
        (sk, DtlsRole::Server, ck, DtlsRole::Client, 0x3333_4444u32),
    ] {
        let tx = srtp_context(
            sender.local_key(sender_role),
            sender.local_salt(sender_role),
            SrtpDirection::Outbound,
            ssrc,
        );
        let rx = srtp_context(
            receiver.remote_key(receiver_role),
            receiver.remote_salt(receiver_role),
            SrtpDirection::Inbound,
            ssrc,
        );

        let payload = vec![0x5Au8; 160];
        let packet = RtpPacket::new(RtpHeader::new(0, 4242, 160_000, ssrc), payload.clone());
        let protected = SrtpProtect::new(&tx).protect_rtp(&packet).unwrap();
        assert!(!protected.windows(32).any(|w| w == &payload[..32]));
        let opened = SrtpUnprotect::new(&rx).unprotect_rtp(&protected).unwrap();
        assert_eq!(opened.payload.as_ref(), payload.as_slice());
        assert_eq!(opened.header.sequence_number, 4242);

        // A receiver keyed for the other direction must reject the packet.
        let wrong = srtp_context(
            receiver.local_key(receiver_role),
            receiver.local_salt(receiver_role),
            SrtpDirection::Inbound,
            ssrc,
        );
        assert!(
            SrtpUnprotect::new(&wrong)
                .unprotect_rtp(&protected)
                .is_err()
        );

        // RTCP sender report under the same keys (rtcp-mux).
        let mut sr = vec![0x80, 200, 0x00, 0x06];
        sr.extend_from_slice(&ssrc.to_be_bytes());
        sr.extend_from_slice(&[0x11u8; 20]);
        let protected = SrtpProtect::new(&tx).protect_rtcp(&sr).unwrap();
        let opened = SrtpUnprotect::new(&rx)
            .unprotect_rtcp_sync(&protected)
            .unwrap();
        assert_eq!(opened.as_ref(), sr.as_slice());
    }
}

/// At the smallest accepted MTU (576) with certificate chains of about
/// 1.4 kB, the `Certificate` messages are fragmented in both directions and
/// reassembled.
#[test]
fn small_mtu_fragments_and_reassembles() {
    let mut lo = Loopback::with(|c, s| {
        c.mtu = 576;
        s.mtu = 576;
        c.credentials = identity_with_long_chain();
        s.credentials = identity_with_long_chain();
        c.peer_fingerprints = vec![s.credentials.fingerprint().clone()];
        s.peer_fingerprints = vec![c.credentials.fingerprint().clone()];
    });
    let mut largest = 0;
    let mut fragments = [0usize; 2];
    lo.run(|dir, _, datagram| {
        largest = largest.max(datagram.len());
        for record in DatagramRecords::new(datagram) {
            let record = record.unwrap();
            if record.epoch != 0 || record.content_type != ContentType::Handshake {
                continue;
            }
            let header = HandshakeHeader::parse(&mut Reader::new(record.payload)).unwrap();
            if header.fragment_length < header.length {
                fragments[usize::from(dir == Dir::ServerToClient)] += 1;
            }
        }
        Wire::Deliver
    });
    lo.assert_connected();
    assert!(
        largest <= 576,
        "datagram of {largest} bytes exceeds the MTU"
    );
    assert!(
        fragments[0] >= 3 && fragments[1] >= 3,
        "certificates were not fragmented: {fragments:?}"
    );
    // The certificate flights no longer fit one datagram each.
    assert!(lo.sent[0] > 3 && lo.sent[1] > 3);
    assert_eq!(lo.client.assoc.stats().retransmits, 0);
    assert_eq!(lo.client.assoc.stats().transmit_dropped, 0);
    assert_eq!(lo.server.assoc.stats().transmit_dropped, 0);
}

#[test]
fn duplicated_datagrams_are_harmless() {
    let mut lo = Loopback::new();
    lo.run(|_, _, _| Wire::Duplicate);
    lo.assert_connected();
}

// ----- loss and retransmission ----------------------------------------------

/// Drops the `index`-th datagram in `dir` once; the handshake must recover
/// by retransmission (RFC 6347 §4.2.4).
fn recovers_from_loss(dir: Dir, index: usize) -> Loopback {
    let mut lo = Loopback::new();
    lo.run(|d, i, _| {
        if d == dir && i == index {
            Wire::Drop
        } else {
            Wire::Deliver
        }
    });
    lo.assert_connected();
    let retransmits = lo.client.assoc.stats().retransmits + lo.server.assoc.stats().retransmits;
    assert!(
        retransmits >= 1,
        "{dir:?} #{index}: nothing was retransmitted"
    );
    // One loss costs one initial timer interval, not more.
    assert_eq!(lo.elapsed(), Duration::from_secs(1), "{dir:?} #{index}");
    lo
}

#[test]
fn lost_first_client_hello_is_retransmitted() {
    let lo = recovers_from_loss(Dir::ClientToServer, 0);
    assert_eq!(lo.client.assoc.stats().retransmits, 1);
}

#[test]
fn lost_hello_verify_request_is_recovered() {
    recovers_from_loss(Dir::ServerToClient, 0);
}

#[test]
fn lost_client_hello_with_cookie_is_retransmitted() {
    recovers_from_loss(Dir::ClientToServer, 1);
}

#[test]
fn lost_server_flight_is_retransmitted() {
    let lo = recovers_from_loss(Dir::ServerToClient, 1);
    assert!(lo.server.assoc.stats().retransmits >= 1);
}

#[test]
fn lost_client_key_exchange_flight_is_retransmitted() {
    let lo = recovers_from_loss(Dir::ClientToServer, 2);
    assert!(lo.client.assoc.stats().retransmits >= 1);
}

/// The server's last flight has no timer of its own: the client's
/// retransmitted flight makes the (already connected) server send it again.
#[test]
fn lost_final_server_flight_is_resent_when_the_client_retransmits() {
    let lo = recovers_from_loss(Dir::ServerToClient, 2);
    assert_eq!(lo.client.assoc.stats().retransmits, 1);
    assert_eq!(lo.server.assoc.stats().retransmits, 1);
}

#[test]
fn silent_peer_times_out_after_backed_off_retransmits() {
    let mut lo = Loopback::new();
    let mut client_hello_times = Vec::new();
    let start = lo.start;
    // The wire callback cannot see the clock, so sample it around each pump.
    for _ in 0..100 {
        let before = lo.sent[0];
        lo.pump(&mut |_, _, _| Wire::Drop);
        if lo.sent[0] > before {
            client_hello_times.push((lo.now - start).as_secs());
        }
        if lo.client.settled() {
            break;
        }
        let next = lo.client.assoc.poll_timeout().unwrap();
        lo.now = next;
        lo.client.assoc.handle_timeout(lo.now);
        lo.client.drain_events();
    }
    assert_eq!(lo.client.failed, Some(FailureCause::Timeout));
    lo.assert_no_keys();
    // RFC 6347 §4.2.4.1: 1 s, then doubling: sends at 0, 1, 3 and 7 s.
    assert_eq!(client_hello_times, vec![0, 1, 3, 7]);
    assert_eq!(lo.client.assoc.stats().retransmits, 3);
    assert_eq!(lo.elapsed(), Duration::from_secs(10));
    assert!(lo.client.assoc.is_terminated());
    assert_eq!(lo.client.assoc.poll_timeout(), None);
}

// ----- authentication failures ---------------------------------------------

fn unrelated_fingerprint() -> CertificateFingerprint {
    identity().fingerprint().clone()
}

#[test]
fn client_rejects_server_certificate_with_wrong_fingerprint() {
    let mut lo = Loopback::with(|client, _| {
        client.peer_fingerprints = vec![unrelated_fingerprint()];
    });
    lo.run(deliver);
    assert_eq!(lo.client.failed, Some(FailureCause::FingerprintMismatch));
    // The client told the server why with a fatal bad_certificate (42).
    assert_eq!(lo.server.failed, Some(FailureCause::PeerAlert(42)));
    lo.assert_no_keys();
    assert!(lo.client.assoc.is_terminated());
    // The mismatching certificate's fingerprint is available for the log.
    assert!(lo.client.assoc.presented_fingerprint().is_some());
    // The client stopped at the server's Certificate: it never sent its own
    // certificate, key exchange or Finished.
    assert_eq!(lo.sent[0], 3, "ClientHello, ClientHello+cookie, alert");
}

#[test]
fn server_rejects_client_certificate_with_wrong_fingerprint() {
    let mut lo = Loopback::with(|_, server| {
        server.peer_fingerprints = vec![unrelated_fingerprint()];
    });
    lo.run(deliver);
    assert_eq!(lo.server.failed, Some(FailureCause::FingerprintMismatch));
    assert_eq!(lo.client.failed, Some(FailureCause::PeerAlert(42)));
    lo.assert_no_keys();
}

#[test]
fn matching_any_one_of_several_fingerprints_is_enough() {
    let mut lo = Loopback::with(|client, _| {
        client.peer_fingerprints.insert(0, unrelated_fingerprint());
    });
    lo.run(deliver);
    lo.assert_connected();
}

#[test]
fn empty_fingerprint_set_is_refused_at_construction() {
    let id = identity();
    for role in [DtlsRole::Client, DtlsRole::Server] {
        let config = AssociationConfig::new(role, id.clone(), Vec::new());
        assert!(DtlsAssociation::new(config, Instant::now()).is_err());
    }
}

#[test]
fn out_of_range_configuration_is_refused() {
    let (id, peer) = (identity(), identity());
    let base = || {
        AssociationConfig::new(
            DtlsRole::Client,
            id.clone(),
            vec![peer.fingerprint().clone()],
        )
    };
    let now = Instant::now();
    assert!(DtlsAssociation::new(base(), now).is_ok());
    let edits: [fn(&mut AssociationConfig); 9] = [
        |c| c.mtu = 100,
        |c| c.mtu = 575,
        |c| c.mtu = 9000,
        |c| c.initial_rto = Duration::ZERO,
        |c| c.initial_rto = Duration::from_millis(49),
        |c| c.initial_rto = Duration::from_secs(9),
        |c| c.peer_binding = vec![0; 65],
        |c| c.handshake_budget = Duration::ZERO,
        |c| c.handshake_budget = Duration::from_secs(3600),
    ];
    for edit in edits {
        let mut config = base();
        edit(&mut config);
        assert!(DtlsAssociation::new(config, now).is_err());
    }
}

#[test]
fn credentials_must_match_the_key() {
    let other = Arc::new(P384KeyPair::generate().unwrap());
    let id = identity();
    assert!(DtlsCredentials::new(id.certificate_chain().to_vec(), other.clone()).is_err());
    assert!(DtlsCredentials::new(Vec::new(), other).is_err());
    let debug = format!("{id:?}");
    assert!(debug.contains("REDACTED"));
}

// ----- extended master secret (RFC 7627) is required ------------------------

/// A client that does not offer `extended_master_secret`: the wire strips the
/// extension from every `ClientHello`, so the server sees a consistent peer
/// without it.
#[test]
fn server_fails_client_without_extended_master_secret() {
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir == Dir::ClientToServer {
            Wire::Replace(rewrite_hello(datagram, HT_CLIENT_HELLO, |body| {
                let mut hello = ClientHello::parse(body).unwrap();
                assert!(hello.extensions.extended_master_secret);
                hello.extensions.extended_master_secret = false;
                let mut out = Vec::new();
                hello.encode(&mut out).unwrap();
                out
            }))
        } else {
            Wire::Deliver
        }
    });
    assert_eq!(lo.server.failed, Some(FailureCause::NoExtendedMasterSecret));
    // handshake_failure (40), RFC 7627 §5.2.
    assert_eq!(lo.client.failed, Some(FailureCause::PeerAlert(40)));
    lo.assert_no_keys();
}

/// A server that does not select `extended_master_secret`.
#[test]
fn client_fails_server_without_extended_master_secret() {
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir == Dir::ServerToClient {
            Wire::Replace(rewrite_hello(datagram, HT_SERVER_HELLO, |body| {
                let mut hello = ServerHello::parse(body).unwrap();
                assert!(hello.extensions.extended_master_secret);
                hello.extensions.extended_master_secret = false;
                let mut out = Vec::new();
                hello.encode(&mut out).unwrap();
                out
            }))
        } else {
            Wire::Deliver
        }
    });
    assert_eq!(lo.client.failed, Some(FailureCause::NoExtendedMasterSecret));
    assert_eq!(lo.server.failed, Some(FailureCause::PeerAlert(40)));
    lo.assert_no_keys();
}

/// Tampering with a hello that both sides still accept is caught by
/// Finished: the transcripts differ, so no keys are exported.
#[test]
fn tampered_hello_is_caught_by_finished() {
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir == Dir::ServerToClient {
            Wire::Replace(rewrite_hello(datagram, HT_SERVER_HELLO, |body| {
                let mut hello = ServerHello::parse(body).unwrap();
                hello.session_id = vec![0xEE; 8];
                let mut out = Vec::new();
                hello.encode(&mut out).unwrap();
                out
            }))
        } else {
            Wire::Deliver
        }
    });
    lo.assert_no_keys();
    assert!(lo.client.failed.is_some() && lo.server.failed.is_some());
}

// ----- after the handshake ---------------------------------------------------

#[test]
fn close_notify_reaches_the_peer() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();

    lo.client.assoc.close();
    assert!(lo.client.assoc.is_terminated());
    lo.pump(&mut deliver);
    assert!(lo.server.peer_closed);
    assert!(lo.server.assoc.is_terminated());
    assert_eq!(lo.server.failed, None);
    // Closing emitted no event on the closing side, and no second Connected.
    assert!(!lo.client.peer_closed);
    assert_eq!(lo.client.connected_events, 1);
}

#[test]
fn garbage_and_replayed_datagrams_do_not_disturb_a_connected_association() {
    let mut lo = Loopback::new();
    let mut last_client_flight = Vec::new();
    lo.run(|dir, index, datagram| {
        if dir == Dir::ClientToServer && index == 2 {
            last_client_flight = datagram.to_vec();
        }
        Wire::Deliver
    });
    lo.assert_connected();

    let now = lo.now;
    for garbage in [
        &[][..],
        &[0x16][..],
        &[0x16, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF][..],
        &[0xFF; 100][..],
        &[0x17, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 9, 0, 1, 0][..],
    ] {
        lo.server.assoc.handle_datagram(garbage, now);
        lo.client.assoc.handle_datagram(garbage, now);
    }
    // A byte-for-byte replay of the client's Finished flight: the protected
    // record is caught by the replay window.
    let before = lo.server.assoc.stats();
    lo.server.assoc.handle_datagram(&last_client_flight, now);
    let after = lo.server.assoc.stats();
    assert_eq!(after.replays, before.replays + 1);

    lo.client.drain_events();
    lo.server.drain_events();
    assert_eq!(lo.client.failed, None);
    assert_eq!(lo.server.failed, None);
    assert!(lo.client.assoc.is_connected() && lo.server.assoc.is_connected());
    assert!(lo.server.assoc.stats().records_discarded > 0);
}
