//! Shared harness for the `DtlsAssociation` integration tests (negative,
//! property, UDP and pion interop suites).
//!
//! Three tools:
//!
//! - [`Loopback`]: two real associations joined by an in-memory wire that can
//!   drop, duplicate or rewrite datagrams, with a fake clock.
//! - Record and message helpers ([`records`], [`edit_message`], ...) to
//!   rewrite the plaintext (epoch 0) part of a handshake on the wire.
//! - [`Puppet`]: a hand-driven peer built from the crate's public codecs,
//!   key schedule and record layer. Unlike the wire, it knows the session
//!   keys, so it can send authenticated records the real association never
//!   would (a wrong `Finished`, a fatal alert after completion, records far
//!   outside the replay window, a renegotiation attempt).
//!
//! Test-only code: panicking on an unexpected shape is the intended failure
//! mode, and not every test binary uses every helper.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use proto_dtls::key_schedule::{MasterSecret, Transcript, server_key_exchange_signed_content};
use proto_dtls::record::{
    AssociationRecordLayer, ContentType, DTLS_1_2_VERSION, DatagramRecords, RecordView,
};
use proto_dtls::wire::extensions::{Extensions, UseSrtp};
use proto_dtls::wire::handshake_msg::{
    CertificateMsg, CertificateRequest, ClientHello, ClientKeyExchange, DigitallySigned,
    EcdheParams, HANDSHAKE_HEADER_LEN, HT_CERTIFICATE, HT_CERTIFICATE_REQUEST,
    HT_CERTIFICATE_VERIFY, HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED,
    HT_HELLO_VERIFY_REQUEST, HT_SERVER_HELLO, HT_SERVER_HELLO_DONE, HT_SERVER_KEY_EXCHANGE,
    HandshakeHeader, HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use proto_dtls::wire::reader::Reader;
use proto_dtls::{
    AssociationConfig, AssociationEvent, DtlsAssociation, DtlsCredentials, DtlsRole, FailureCause,
    SrtpKeyingMaterial,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uc_crypto::ecdh::P384EphemeralKeyPair;
use uc_crypto::ecdsa::P384KeyPair;

/// The one cipher suite of the profile.
pub const SUITE: u16 = 0xC02C;
/// secp384r1.
pub const GROUP_P384: u16 = 24;
/// `ecdsa_secp384r1_sha384`.
pub const SCHEME_P384_SHA384: u16 = 0x0503;
/// `ecdsa_secp256r1_sha256`: what stock pion signs with. Must be refused.
pub const SCHEME_P256_SHA256: u16 = 0x0403;
/// `SRTP_AEAD_AES_256_GCM`.
pub const SRTP_AES256_GCM: u16 = 0x0008;
/// `SRTP_AES128_CM_HMAC_SHA1_80`. Must be refused.
pub const SRTP_AES128_SHA1_80: u16 = 0x0001;

// ----- identities -----------------------------------------------------------

/// A self-signed P-384 certificate (DER) and its key.
pub fn identity_parts() -> (Vec<u8>, Arc<P384KeyPair>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["qa.invalid".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = Arc::new(P384KeyPair::from_pkcs8(&key.serialize_der()).unwrap());
    (cert.der().to_vec(), key)
}

/// A fresh self-signed P-384 identity.
pub fn identity() -> DtlsCredentials {
    let (cert, key) = identity_parts();
    DtlsCredentials::new(vec![cert], key).unwrap()
}

/// A self-signed certificate (DER) whose key uses `alg`, for the
/// "fingerprint matches but the key is not P-384" cases.
pub fn foreign_certificate(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    let key = rcgen::KeyPair::generate_for(alg).unwrap();
    rcgen::CertificateParams::new(vec!["foreign.invalid".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec()
}

// ----- loopback of two real associations ------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

/// One association and everything it reported.
pub struct Side {
    pub assoc: DtlsAssociation,
    pub keys: Option<SrtpKeyingMaterial>,
    pub failed: Option<FailureCause>,
    pub peer_closed: bool,
    pub connected_events: usize,
    pub failed_events: usize,
}

impl Side {
    pub fn new(config: AssociationConfig, now: Instant) -> Self {
        Self {
            assoc: DtlsAssociation::new(config, now).unwrap(),
            keys: None,
            failed: None,
            peer_closed: false,
            connected_events: 0,
            failed_events: 0,
        }
    }

    pub fn drain_events(&mut self) {
        while let Some(event) = self.assoc.poll_event() {
            match event {
                AssociationEvent::Connected { keys } => {
                    self.connected_events += 1;
                    self.keys = Some(keys);
                }
                AssociationEvent::Failed { cause } => {
                    self.failed_events += 1;
                    self.failed = Some(cause);
                }
                AssociationEvent::PeerClosed => self.peer_closed = true,
            }
        }
    }

    pub const fn settled(&self) -> bool {
        self.keys.is_some() || self.failed.is_some()
    }

    /// Everything queued for the peer.
    pub fn drain_transmit(&mut self) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| self.assoc.poll_transmit()).collect()
    }
}

/// What the in-memory wire does with one datagram.
pub enum Wire {
    Deliver,
    Drop,
    Duplicate,
    /// Deliver these datagrams instead (none = drop).
    Replace(Vec<Vec<u8>>),
}

impl Wire {
    pub fn replace(datagram: Vec<u8>) -> Self {
        if datagram.is_empty() {
            Self::Drop
        } else {
            Self::Replace(vec![datagram])
        }
    }
}

pub struct Loopback {
    pub client: Side,
    pub server: Side,
    pub start: Instant,
    pub now: Instant,
    /// Datagrams sent so far per direction (index passed to the wire).
    pub sent: [usize; 2],
    /// Every datagram put on the wire, before the wire touched it.
    pub log: Vec<(Dir, Vec<u8>)>,
}

impl Loopback {
    pub fn with(configure: impl Fn(&mut AssociationConfig, &mut AssociationConfig)) -> Self {
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
            log: Vec::new(),
        }
    }

    pub fn new() -> Self {
        Self::with(|_, _| {})
    }

    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Moves every queued datagram across the wire once. Returns whether
    /// anything moved.
    pub fn pump(&mut self, wire: &mut impl FnMut(Dir, usize, &[u8]) -> Wire) -> bool {
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
                self.log.push((dir, datagram.clone()));
                match wire(dir, index, &datagram) {
                    Wire::Deliver => to.assoc.handle_datagram(&datagram, self.now),
                    Wire::Drop => {}
                    Wire::Duplicate => {
                        to.assoc.handle_datagram(&datagram, self.now);
                        to.assoc.handle_datagram(&datagram, self.now);
                    }
                    Wire::Replace(others) => {
                        for other in others {
                            to.assoc.handle_datagram(&other, self.now);
                        }
                    }
                }
            }
        }
        self.client.drain_events();
        self.server.drain_events();
        moved
    }

    /// Advances the fake clock to the next timeout of either side and fires
    /// it. Returns false when neither side has a timer.
    pub fn advance(&mut self) -> bool {
        let next = [
            self.client.assoc.poll_timeout(),
            self.server.assoc.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(next) = next else { return false };
        self.now = self.now.max(next);
        self.client.assoc.handle_timeout(self.now);
        self.server.assoc.handle_timeout(self.now);
        self.client.drain_events();
        self.server.drain_events();
        true
    }

    /// Runs until both sides have connected or failed, advancing the fake
    /// clock to the next timeout whenever the wire is idle.
    pub fn run(&mut self, mut wire: impl FnMut(Dir, usize, &[u8]) -> Wire) {
        for _ in 0..10_000 {
            if self.pump(&mut wire) {
                continue;
            }
            if self.client.settled() && self.server.settled() {
                return;
            }
            if !self.advance() {
                return;
            }
        }
        panic!("loopback did not settle");
    }

    pub fn assert_connected(&self) {
        assert_eq!(self.client.failed, None);
        assert_eq!(self.server.failed, None);
        let c = self.client.keys.as_ref().expect("client keys");
        let s = self.server.keys.as_ref().expect("server keys");
        assert_eq!(exported(c), exported(s));
        assert_eq!(exported(c).len(), 88);
        assert_eq!(self.client.connected_events, 1);
        assert_eq!(self.server.connected_events, 1);
        assert!(self.client.assoc.is_connected());
        assert!(self.server.assoc.is_connected());
    }

    /// Neither side exported keys, reported `Connected`, or thinks it is
    /// connected.
    pub fn assert_no_keys(&self) {
        assert!(self.client.keys.is_none(), "client exported keys");
        assert!(self.server.keys.is_none(), "server exported keys");
        assert_eq!(self.client.connected_events, 0);
        assert_eq!(self.server.connected_events, 0);
        assert!(!self.client.assoc.is_connected());
        assert!(!self.server.assoc.is_connected());
    }
}

/// The 88 exported bytes in RFC 5764 §4.2 order.
pub fn exported(keys: &SrtpKeyingMaterial) -> Vec<u8> {
    [
        keys.client_write_key.as_slice(),
        keys.server_write_key.as_slice(),
        keys.client_write_salt.as_slice(),
        keys.server_write_salt.as_slice(),
    ]
    .concat()
}

pub const fn deliver(_: Dir, _: usize, _: &[u8]) -> Wire {
    Wire::Deliver
}

// ----- records and messages on the wire -------------------------------------

/// One record copied out of a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rec {
    pub content_type: ContentType,
    pub version: u16,
    pub epoch: u16,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl Rec {
    pub fn encode(&self) -> Vec<u8> {
        raw_record(
            self.content_type as u8,
            self.version,
            self.epoch,
            self.seq,
            &self.payload,
        )
    }

    /// The handshake message in this record, if it is an unfragmented
    /// plaintext one.
    pub fn message(&self) -> Option<Msg> {
        if self.epoch != 0 || self.content_type != ContentType::Handshake {
            return None;
        }
        let mut r = Reader::new(&self.payload);
        let header = HandshakeHeader::parse(&mut r).ok()?;
        let body = r.rest();
        (header.fragment_offset == 0
            && header.fragment_length == header.length
            && body.len() == header.length as usize)
            .then(|| Msg {
                msg_type: header.msg_type,
                seq: header.message_seq,
                body: body.to_vec(),
            })
    }
}

/// An unfragmented handshake message.
// `msg_type` is the name the crate's own `HandshakeHeader` uses.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub msg_type: u8,
    pub seq: u16,
    pub body: Vec<u8>,
}

impl Msg {
    /// Header plus body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        HandshakeHeader::unfragmented(self.msg_type, self.seq, self.body.len())
            .unwrap()
            .encode(&mut out)
            .unwrap();
        out.extend_from_slice(&self.body);
        out
    }
}

/// Encodes a record header and payload with no checks at all, so tests can
/// build records the crate's encoders refuse to.
pub fn raw_record(content_type: u8, version: u16, epoch: u16, seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..]);
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A plaintext handshake record holding one whole message.
pub fn message_record(record_seq: u64, msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let msg = Msg {
        msg_type,
        seq: message_seq,
        body: body.to_vec(),
    };
    raw_record(
        ContentType::Handshake as u8,
        DTLS_1_2_VERSION,
        0,
        record_seq,
        &msg.encode(),
    )
}

/// A plaintext handshake record holding one fragment with an arbitrary
/// (possibly inconsistent) header.
pub fn fragment_record(record_seq: u64, header: &HandshakeHeader, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    header.encode(&mut payload).unwrap();
    payload.extend_from_slice(data);
    raw_record(
        ContentType::Handshake as u8,
        DTLS_1_2_VERSION,
        0,
        record_seq,
        &payload,
    )
}

/// A plaintext (epoch 0) alert record.
pub fn plaintext_alert(record_seq: u64, level: u8, description: u8) -> Vec<u8> {
    raw_record(
        ContentType::Alert as u8,
        DTLS_1_2_VERSION,
        0,
        record_seq,
        &[level, description],
    )
}

/// The records of a datagram. Panics if it does not parse.
pub fn records(datagram: &[u8]) -> Vec<Rec> {
    DatagramRecords::new(datagram)
        .map(|record| {
            let record: RecordView<'_> = record.unwrap();
            Rec {
                content_type: record.content_type,
                version: record.version,
                epoch: record.epoch,
                seq: record.sequence_number,
                payload: record.payload.to_vec(),
            }
        })
        .collect()
}

/// The unfragmented plaintext handshake messages of a datagram.
pub fn messages(datagram: &[u8]) -> Vec<Msg> {
    records(datagram).iter().filter_map(Rec::message).collect()
}

/// The first message of `msg_type` in any logged datagram going `dir`.
pub fn find_message(log: &[(Dir, Vec<u8>)], dir: Dir, msg_type: u8) -> Option<Msg> {
    log.iter()
        .filter(|(d, _)| *d == dir)
        .flat_map(|(_, datagram)| messages(datagram))
        .find(|m| m.msg_type == msg_type)
}

/// Rewrites every unfragmented plaintext handshake message of `msg_type` in
/// `datagram`. `edit` returns the new message (type and body may change, the
/// `message_seq` is kept) or `None` to remove the record. Everything else is
/// copied byte for byte.
pub fn edit_message(
    datagram: &[u8],
    msg_type: u8,
    mut edit: impl FnMut(&[u8]) -> Option<(u8, Vec<u8>)>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for mut rec in records(datagram) {
        match rec.message() {
            Some(msg) if msg.msg_type == msg_type => {
                if let Some((new_type, body)) = edit(&msg.body) {
                    rec.payload = Msg {
                        msg_type: new_type,
                        seq: msg.seq,
                        body,
                    }
                    .encode();
                    out.extend(rec.encode());
                }
            }
            _ => out.extend(rec.encode()),
        }
    }
    out
}

/// A wire that rewrites one message type in one direction.
pub fn rewriting(
    dir: Dir,
    msg_type: u8,
    edit: impl Fn(&[u8]) -> Option<(u8, Vec<u8>)>,
) -> impl FnMut(Dir, usize, &[u8]) -> Wire {
    move |d, _, datagram| {
        if d == dir {
            Wire::replace(edit_message(datagram, msg_type, &edit))
        } else {
            Wire::Deliver
        }
    }
}

/// Rewrites every `ClientHello` on its way to the server. The server's
/// cookie is computed over the rewritten hello, so the peer looks like a
/// consistent client that really offers this.
pub fn rewrite_client_hello(
    edit: impl Fn(&mut ClientHello),
) -> impl FnMut(Dir, usize, &[u8]) -> Wire {
    rewriting(Dir::ClientToServer, HT_CLIENT_HELLO, move |body| {
        let mut hello = ClientHello::parse(body).unwrap();
        edit(&mut hello);
        let mut out = Vec::new();
        hello.encode(&mut out).unwrap();
        Some((HT_CLIENT_HELLO, out))
    })
}

/// Rewrites the `ServerHello` on its way to the client.
pub fn rewrite_server_hello(
    edit: impl Fn(&mut ServerHello),
) -> impl FnMut(Dir, usize, &[u8]) -> Wire {
    rewriting(Dir::ServerToClient, HT_SERVER_HELLO, move |body| {
        let mut hello = ServerHello::parse(body).unwrap();
        edit(&mut hello);
        let mut out = Vec::new();
        hello.encode(&mut out).unwrap();
        Some((HT_SERVER_HELLO, out))
    })
}

// ----- a hand-driven peer ----------------------------------------------------

/// The `ClientHello` extensions of the profile.
pub fn profile_extensions() -> Extensions {
    Extensions {
        supported_groups: Some(vec![GROUP_P384]),
        ec_point_formats: Some(vec![0]),
        signature_algorithms: Some(vec![SCHEME_P384_SHA384]),
        use_srtp: Some(UseSrtp {
            profiles: vec![SRTP_AES256_GCM],
            mki: Vec::new(),
        }),
        extended_master_secret: true,
        renegotiation_info: Some(Vec::new()),
        first_unknown: None,
    }
}

/// Deviations a [`Puppet`] can be told to make.
#[derive(Clone, Debug)]
pub struct Script {
    /// Send a `Finished` whose `verify_data` is wrong.
    pub corrupt_finished: bool,
    /// Client: sign `CertificateVerify` with this key instead of our own.
    pub certificate_verify_key: Option<Arc<P384KeyPair>>,
    /// Server: `signature_algorithms` of the `CertificateRequest`.
    pub certificate_request_schemes: Vec<u16>,
    /// Server: leave the `CertificateRequest` out.
    pub omit_certificate_request: bool,
    /// `srtp_mki` of the `use_srtp` extension in our hello (either role).
    pub hello_mki: Vec<u8>,
    /// Add an empty extension of this type, which the profile does not
    /// know, to our hello (either role).
    pub hello_unknown_extension: Option<u16>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            corrupt_finished: false,
            certificate_verify_key: None,
            certificate_request_schemes: vec![SCHEME_P384_SHA384],
            omit_certificate_request: false,
            hello_mki: Vec::new(),
            hello_unknown_extension: None,
        }
    }
}

/// Appends an empty extension of `ext_type` to a hello body whose extensions
/// block (two-byte length first) starts at `block_at`.
fn append_empty_extension(body: &mut Vec<u8>, block_at: usize, ext_type: u16) {
    let len = u16::from_be_bytes([body[block_at], body[block_at + 1]]) + 4;
    body[block_at..block_at + 2].copy_from_slice(&len.to_be_bytes());
    body.extend_from_slice(&ext_type.to_be_bytes());
    body.extend_from_slice(&[0, 0]);
}

/// A DTLS peer driven step by step by the test. It follows the profile
/// unless its [`Script`] says otherwise, and assumes the association under
/// test sends unfragmented messages (default MTU).
pub struct Puppet {
    pub role: DtlsRole,
    pub cert: Vec<u8>,
    pub key: Arc<P384KeyPair>,
    pub script: Script,
    pub records: AssociationRecordLayer,
    pub transcript: Transcript,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master: Option<MasterSecret>,
    pub next_seq: u16,
    pub ecdh: Option<P384EphemeralKeyPair>,
    pub peer_ecdh: Vec<u8>,
    pub cookie: Vec<u8>,
    /// Handshake messages received, in order.
    pub seen: Vec<Msg>,
    /// `(level, description)` of alerts received.
    pub alerts: Vec<(u8, u8)>,
    /// Records that did not open.
    pub undecodable: usize,
    /// Whether the peer's `Finished` matched what we computed.
    pub peer_finished_ok: Option<bool>,
}

impl Puppet {
    pub fn new(role: DtlsRole) -> Self {
        let (cert, key) = identity_parts();
        Self {
            role,
            cert,
            key,
            script: Script::default(),
            records: AssociationRecordLayer::new(),
            transcript: Transcript::new(),
            client_random: [0x11; 32],
            server_random: [0x22; 32],
            master: None,
            next_seq: 0,
            ecdh: None,
            peer_ecdh: Vec::new(),
            cookie: Vec::new(),
            seen: Vec::new(),
            alerts: Vec::new(),
            undecodable: 0,
            peer_finished_ok: None,
        }
    }

    pub fn fingerprint(&self) -> proto_dtls::CertificateFingerprint {
        proto_dtls::CertificateFingerprint::from_certificate_sha384(&self.cert)
    }

    /// The association to test against this puppet: the opposite role,
    /// expecting the puppet's certificate.
    pub fn counterpart(&self, now: Instant) -> (Side, DtlsCredentials) {
        let id = identity();
        let role = match self.role {
            DtlsRole::Client => DtlsRole::Server,
            DtlsRole::Server => DtlsRole::Client,
        };
        let config = AssociationConfig::new(role, id.clone(), vec![self.fingerprint()]);
        (Side::new(config, now), id)
    }

    /// Seals one record in `epoch`.
    pub fn seal(&mut self, epoch: u16, content_type: ContentType, payload: &[u8]) -> Vec<u8> {
        self.records.seal(epoch, content_type, payload).unwrap()
    }

    /// Seals one handshake message, adding it to the transcript unless it is
    /// a `ClientHello` (handled by [`Self::client_hello`]).
    pub fn handshake(&mut self, epoch: u16, msg_type: u8, body: &[u8]) -> Vec<u8> {
        let msg = Msg {
            msg_type,
            seq: self.next_seq,
            body: body.to_vec(),
        };
        self.next_seq += 1;
        if msg_type != HT_CLIENT_HELLO {
            self.transcript.push_raw(&msg.encode()).unwrap();
        }
        self.seal(epoch, ContentType::Handshake, &msg.encode())
    }

    /// Reads everything the association has queued.
    pub fn absorb_from(&mut self, side: &mut Side) {
        for datagram in side.drain_transmit() {
            self.absorb(&datagram);
        }
    }

    /// Processes one datagram from the association under test.
    pub fn absorb(&mut self, datagram: &[u8]) {
        for record in DatagramRecords::new(datagram) {
            let record = record.unwrap();
            let Ok(plaintext) = self.records.open(&record) else {
                self.undecodable += 1;
                continue;
            };
            match record.content_type {
                ContentType::Handshake => {
                    let mut r = Reader::new(&plaintext);
                    let header = HandshakeHeader::parse(&mut r).unwrap();
                    let body = r.rest().to_vec();
                    assert_eq!(header.fragment_offset, 0, "puppet does not reassemble");
                    assert_eq!(body.len(), header.length as usize);
                    self.on_message(Msg {
                        msg_type: header.msg_type,
                        seq: header.message_seq,
                        body,
                    });
                }
                ContentType::ChangeCipherSpec => self.records.activate_read().unwrap(),
                ContentType::Alert => self.alerts.push((plaintext[0], plaintext[1])),
                ContentType::ApplicationData => {}
            }
        }
    }

    fn on_message(&mut self, msg: Msg) {
        // A retransmission of something already seen is not processed twice.
        if self
            .seen
            .iter()
            .any(|m| m.seq == msg.seq && m.msg_type == msg.msg_type)
        {
            return;
        }
        match msg.msg_type {
            HT_CLIENT_HELLO => {
                let hello = ClientHello::parse(&msg.body).unwrap();
                self.client_random = hello.random;
                self.transcript = Transcript::new();
                self.transcript.push_raw(&msg.encode()).unwrap();
                self.next_seq = msg.seq;
            }
            HT_HELLO_VERIFY_REQUEST => {
                self.cookie = HelloVerifyRequest::parse(&msg.body).unwrap().cookie;
            }
            HT_SERVER_HELLO => {
                self.server_random = ServerHello::parse(&msg.body).unwrap().random;
                self.transcript.push_raw(&msg.encode()).unwrap();
            }
            HT_SERVER_KEY_EXCHANGE => {
                self.peer_ecdh = ServerKeyExchange::parse(&msg.body).unwrap().params.public;
                self.transcript.push_raw(&msg.encode()).unwrap();
            }
            HT_CLIENT_KEY_EXCHANGE => {
                self.transcript.push_raw(&msg.encode()).unwrap();
                let public = ClientKeyExchange::parse(&msg.body).unwrap().public;
                self.derive_keys(&public);
            }
            HT_FINISHED => {
                let peer = match self.role {
                    DtlsRole::Client => DtlsRole::Server,
                    DtlsRole::Server => DtlsRole::Client,
                };
                let expected = self
                    .master
                    .as_ref()
                    .unwrap()
                    .verify_data(peer, &self.transcript.hash())
                    .unwrap();
                self.peer_finished_ok = Some(expected.as_slice() == msg.body.as_slice());
                self.transcript.push_raw(&msg.encode()).unwrap();
            }
            _ => self.transcript.push_raw(&msg.encode()).unwrap(),
        }
        self.seen.push(msg);
    }

    /// ECDH, extended master secret over the transcript so far (which must
    /// end with `ClientKeyExchange`), record keys installed as pending.
    fn derive_keys(&mut self, peer_public: &[u8]) {
        let pre_master = self.ecdh.take().unwrap().agree(peer_public).unwrap();
        let master =
            MasterSecret::derive_extended(pre_master.as_bytes(), &self.transcript.hash()).unwrap();
        master
            .key_block(&self.client_random, &self.server_random)
            .unwrap()
            .install(self.role, &mut self.records)
            .unwrap();
        self.master = Some(master);
    }

    /// What this puppet would export for SRTP.
    pub fn export(&self) -> SrtpKeyingMaterial {
        self.master
            .as_ref()
            .unwrap()
            .export_srtp(&self.client_random, &self.server_random)
            .unwrap()
    }

    fn finished(&mut self) -> Vec<u8> {
        let mut verify_data = self
            .master
            .as_ref()
            .unwrap()
            .verify_data(self.role, &self.transcript.hash())
            .unwrap();
        if self.script.corrupt_finished {
            verify_data[0] ^= 0x01;
        }
        let mut out = self.seal(0, ContentType::ChangeCipherSpec, &[1]);
        self.records.activate_write().unwrap();
        out.extend(self.handshake(1, HT_FINISHED, &verify_data));
        out
    }

    // ----- client puppet ----------------------------------------------------

    /// `ClientHello` carrying the cookie learnt so far.
    pub fn client_hello(&mut self) -> Vec<u8> {
        let hello = ClientHello {
            version: DTLS_1_2_VERSION,
            random: self.client_random,
            session_id: Vec::new(),
            cookie: self.cookie.clone(),
            cipher_suites: vec![SUITE],
            compression_methods: vec![0],
            extensions: profile_extensions(),
        };
        let mut hello = hello;
        hello
            .extensions
            .use_srtp
            .as_mut()
            .unwrap()
            .mki
            .clone_from(&self.script.hello_mki);
        let mut body = Vec::new();
        hello.encode(&mut body).unwrap();
        if let Some(ext_type) = self.script.hello_unknown_extension {
            // version, random, session_id, cookie, one suite, one compression
            let block_at = 2 + 32 + 1 + 1 + self.cookie.len() + 4 + 2;
            append_empty_extension(&mut body, block_at, ext_type);
        }
        let msg = Msg {
            msg_type: HT_CLIENT_HELLO,
            seq: self.next_seq,
            body,
        };
        // RFC 6347 §4.2.6: only the ClientHello that gets answered counts.
        self.transcript = Transcript::new();
        self.transcript.push_raw(&msg.encode()).unwrap();
        self.next_seq += 1;
        self.seal(0, ContentType::Handshake, &msg.encode())
    }

    /// `Certificate`, `ClientKeyExchange`, `CertificateVerify`,
    /// `ChangeCipherSpec`, `Finished` in one datagram.
    pub fn client_flight5(&mut self) -> Vec<u8> {
        let mut certificate = Vec::new();
        CertificateMsg {
            chain: vec![self.cert.clone()],
        }
        .encode(&mut certificate)
        .unwrap();
        let mut out = self.handshake(0, HT_CERTIFICATE, &certificate);

        let ecdh = P384EphemeralKeyPair::generate().unwrap();
        let mut key_exchange = Vec::new();
        ClientKeyExchange {
            public: ecdh.public_key_bytes().to_vec(),
        }
        .encode(&mut key_exchange)
        .unwrap();
        self.ecdh = Some(ecdh);
        out.extend(self.handshake(0, HT_CLIENT_KEY_EXCHANGE, &key_exchange));
        let peer_ecdh = self.peer_ecdh.clone();
        self.derive_keys(&peer_ecdh);

        let signer = self
            .script
            .certificate_verify_key
            .clone()
            .unwrap_or_else(|| self.key.clone());
        let mut verify = Vec::new();
        DigitallySigned {
            scheme: SCHEME_P384_SHA384,
            signature: signer.sign(self.transcript.bytes()).unwrap(),
        }
        .encode(&mut verify)
        .unwrap();
        out.extend(self.handshake(0, HT_CERTIFICATE_VERIFY, &verify));
        out.extend(self.finished());
        out
    }

    // ----- server puppet ----------------------------------------------------

    /// `ServerHello` .. `ServerHelloDone` in one datagram, answering the
    /// `ClientHello` absorbed last (no cookie exchange).
    pub fn server_flight4(&mut self) -> Vec<u8> {
        let hello = ServerHello {
            version: DTLS_1_2_VERSION,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: SUITE,
            compression_method: 0,
            extensions: Extensions {
                supported_groups: None,
                ec_point_formats: Some(vec![0]),
                signature_algorithms: None,
                use_srtp: Some(UseSrtp {
                    profiles: vec![SRTP_AES256_GCM],
                    mki: self.script.hello_mki.clone(),
                }),
                extended_master_secret: true,
                renegotiation_info: Some(Vec::new()),
                first_unknown: None,
            },
        };
        let mut body = Vec::new();
        hello.encode(&mut body).unwrap();
        if let Some(ext_type) = self.script.hello_unknown_extension {
            // version, random, empty session_id, suite, compression
            append_empty_extension(&mut body, 2 + 32 + 1 + 2 + 1, ext_type);
        }
        let mut out = self.handshake(0, HT_SERVER_HELLO, &body);

        let mut certificate = Vec::new();
        CertificateMsg {
            chain: vec![self.cert.clone()],
        }
        .encode(&mut certificate)
        .unwrap();
        out.extend(self.handshake(0, HT_CERTIFICATE, &certificate));

        let ecdh = P384EphemeralKeyPair::generate().unwrap();
        let mut params = Vec::new();
        EcdheParams {
            named_curve: GROUP_P384,
            public: ecdh.public_key_bytes().to_vec(),
        }
        .encode(&mut params)
        .unwrap();
        self.ecdh = Some(ecdh);
        let signature = self
            .key
            .sign(&server_key_exchange_signed_content(
                &self.client_random,
                &self.server_random,
                &params,
            ))
            .unwrap();
        let mut key_exchange = params;
        DigitallySigned {
            scheme: SCHEME_P384_SHA384,
            signature,
        }
        .encode(&mut key_exchange)
        .unwrap();
        out.extend(self.handshake(0, HT_SERVER_KEY_EXCHANGE, &key_exchange));

        if !self.script.omit_certificate_request {
            let mut request = Vec::new();
            CertificateRequest {
                certificate_types: vec![64],
                signature_algorithms: self.script.certificate_request_schemes.clone(),
                certificate_authorities: Vec::new(),
            }
            .encode(&mut request)
            .unwrap();
            out.extend(self.handshake(0, HT_CERTIFICATE_REQUEST, &request));
        }
        out.extend(self.handshake(0, HT_SERVER_HELLO_DONE, &[]));
        out
    }

    /// `ChangeCipherSpec` and `Finished`.
    pub fn server_flight6(&mut self) -> Vec<u8> {
        self.finished()
    }
}

/// A scripted *server* completes (or tries to complete) a handshake with a
/// real client association. `prepare` can change the puppet's script or
/// identity first. Returns the client side and the puppet.
pub fn handshake_with_puppet_server(prepare: impl FnOnce(&mut Puppet)) -> (Side, Puppet, Instant) {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _client_id) = puppet.counterpart(now);
    prepare(&mut puppet);
    puppet.absorb_from(&mut client);
    let flight4 = puppet.server_flight4();
    client.assoc.handle_datagram(&flight4, now);
    client.drain_events();
    puppet.absorb_from(&mut client);
    if puppet.peer_finished_ok.is_some() {
        let flight6 = puppet.server_flight6();
        client.assoc.handle_datagram(&flight6, now);
        client.drain_events();
        puppet.absorb_from(&mut client);
    }
    (client, puppet, now)
}

/// A scripted *client* goes through the cookie exchange with a real server
/// association and reads its flight 4. Returns the server side (now waiting
/// for the client `Certificate`) and the puppet.
pub fn puppet_client_until_flight4(prepare: impl FnOnce(&mut Puppet)) -> (Side, Puppet, Instant) {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Client);
    let (mut server, _server_id) = puppet.counterpart(now);
    prepare(&mut puppet);
    let hello = puppet.client_hello();
    server.assoc.handle_datagram(&hello, now);
    puppet.absorb_from(&mut server);
    assert!(!puppet.cookie.is_empty(), "no HelloVerifyRequest");
    let hello = puppet.client_hello();
    server.assoc.handle_datagram(&hello, now);
    puppet.absorb_from(&mut server);
    assert!(!puppet.peer_ecdh.is_empty(), "no server flight");
    (server, puppet, now)
}

/// A scripted *client* completes (or tries to complete) a handshake with a
/// real server association. Returns the server side and the puppet.
pub fn handshake_with_puppet_client(prepare: impl FnOnce(&mut Puppet)) -> (Side, Puppet, Instant) {
    let (mut server, mut puppet, now) = puppet_client_until_flight4(prepare);
    let flight5 = puppet.client_flight5();
    server.assoc.handle_datagram(&flight5, now);
    server.drain_events();
    puppet.absorb_from(&mut server);
    (server, puppet, now)
}

/// Sanity check used by every puppet-based test that expects success.
pub fn assert_puppet_connected(side: &Side, puppet: &Puppet) {
    assert_eq!(side.failed, None);
    assert!(side.assoc.is_connected());
    assert_eq!(side.connected_events, 1);
    assert_eq!(puppet.peer_finished_ok, Some(true));
    assert_eq!(
        exported(side.keys.as_ref().expect("keys")),
        exported(&puppet.export()),
        "the association and the independent key schedule disagree"
    );
}

/// The handshake header of a fragment, for tests that build their own.
pub const fn header(
    msg_type: u8,
    length: u32,
    message_seq: u16,
    fragment_offset: u32,
    fragment_length: u32,
) -> HandshakeHeader {
    HandshakeHeader {
        msg_type,
        length,
        message_seq,
        fragment_offset,
        fragment_length,
    }
}

/// Size of the handshake header, re-exported for fragment arithmetic.
pub const HS_HEADER: usize = HANDSHAKE_HEADER_LEN;

// ----- driving an association over a real UDP socket --------------------------

/// What an association reported while being driven over a socket.
#[derive(Default)]
pub struct Driven {
    pub keys: Option<SrtpKeyingMaterial>,
    pub failed: Option<FailureCause>,
    pub peer_closed: bool,
    pub connected_events: usize,
    /// Datagrams from the peer that are not DTLS (RFC 7983 first byte
    /// outside 20..=63): SRTP and SRTCP on the same socket.
    pub media: Vec<Vec<u8>>,
    /// Datagrams from any other source address; never fed to the association.
    pub strangers: usize,
    /// DTLS datagrams sent and received.
    pub sent: usize,
    pub received: usize,
}

impl Driven {
    pub const fn settled(&self) -> bool {
        self.keys.is_some() || self.failed.is_some() || self.peer_closed
    }
}

/// Services `assoc` on `socket` in real time, the way impl-notes tells a
/// driver to: drain transmits, drain events, then wait for a datagram or
/// the association's timer. Returns when `stop` says so or at `deadline`.
///
/// Only datagrams from `peer` whose first byte is 20..=63 reach the
/// association (RFC 7983); the rest are kept in [`Driven::media`].
pub async fn drive(
    assoc: &mut DtlsAssociation,
    socket: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    state: &mut Driven,
    deadline: tokio::time::Instant,
    stop: impl Fn(&Driven) -> bool,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        while let Some(datagram) = assoc.poll_transmit() {
            // A send error (peer port not open yet) is the same as loss.
            if socket.send_to(&datagram, peer).await.is_ok() {
                state.sent += 1;
            }
        }
        while let Some(event) = assoc.poll_event() {
            match event {
                AssociationEvent::Connected { keys } => {
                    state.connected_events += 1;
                    state.keys = Some(keys);
                }
                AssociationEvent::Failed { cause } => state.failed = Some(cause),
                AssociationEvent::PeerClosed => state.peer_closed = true,
            }
        }
        if stop(state) || tokio::time::Instant::now() >= deadline {
            return;
        }
        let wake = assoc.poll_timeout().map_or(deadline, |at| {
            deadline.min(tokio::time::Instant::from_std(at))
        });
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let Ok((len, from)) = received else { continue };
                let datagram = &buf[..len];
                if from != peer {
                    state.strangers += 1;
                } else if datagram.first().is_some_and(|b| (20..=63).contains(b)) {
                    state.received += 1;
                    assoc.handle_datagram(datagram, Instant::now());
                } else {
                    state.media.push(datagram.to_vec());
                }
            }
            () = tokio::time::sleep_until(wake) => assoc.handle_timeout(Instant::now()),
        }
    }
}

/// SRTP context for one direction and SSRC from exported key material.
pub fn srtp_context(
    key: &[u8],
    salt: &[u8],
    direction: proto_srtp::SrtpDirection,
    ssrc: u32,
) -> proto_srtp::SrtpContext {
    let material = proto_srtp::SrtpKeyMaterial::new(
        proto_srtp::SrtpProfile::AeadAes256Gcm,
        key.to_vec(),
        salt.to_vec(),
    )
    .unwrap();
    proto_srtp::SrtpContext::new(&material, direction, ssrc).unwrap()
}

/// A minimal RTCP receiver report (RFC 3550 §6.4.2) with no report blocks.
pub fn rtcp_receiver_report(ssrc: u32) -> Vec<u8> {
    let mut rr = vec![0x80, 201, 0x00, 0x01];
    rr.extend_from_slice(&ssrc.to_be_bytes());
    rr
}

/// RFC 5761 §4: RTCP if the payload-type byte (marker masked) is 64..=95.
pub fn is_rtcp(packet: &[u8]) -> bool {
    packet
        .get(1)
        .is_some_and(|b| (64..=95).contains(&(b & 0x7F)))
}
