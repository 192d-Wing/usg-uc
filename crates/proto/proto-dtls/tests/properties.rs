//! Property tests for the DTLS association and its parsers (plan §6.1).
//!
//! Three groups:
//!
//! 1. Codecs: `parse(encode(x)) == x` for every handshake message and
//!    extension; arbitrary and truncated bytes never panic a parser.
//! 2. Building blocks against a model: reassembly (any fragmentation, order,
//!    overlap, duplication; memory bound) and the record replay window.
//! 3. The association itself: arbitrary bytes in every handshake state never
//!    panic and never produce keys; a real handshake over a network that
//!    drops, duplicates, delays, splits and re-fragments either completes
//!    with identical keys on both sides or ends in `Timeout` inside the
//!    budget, and nothing else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proto_dtls::key_schedule::MAX_TRANSCRIPT_LEN;
use proto_dtls::reassembly::{FUTURE_WINDOW, FragmentOutcome, MAX_BUFFERED_BYTES, Reassembler};
use proto_dtls::record::{
    AssociationRecordLayer, ContentType, DatagramRecords, MAX_RECORDS_PER_DATAGRAM,
};
use proto_dtls::spki::extract_p384_public_key;
use proto_dtls::wire::alert::Alert;
use proto_dtls::wire::extensions::{Extensions, UseSrtp};
use proto_dtls::wire::handshake_msg::{
    CertificateMsg, CertificateRequest, CertificateVerify, ClientHello, ClientKeyExchange,
    DigitallySigned, EcdheParams, Finished, HT_CERTIFICATE, HT_CLIENT_HELLO, HandshakeHeader,
    HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use proto_dtls::wire::reader::Reader;
use proto_dtls::{
    AssociationConfig, CertificateFingerprint, DtlsCredentials, DtlsRole, FailureCause,
};
use std::collections::{BTreeSet, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ----- strategies -------------------------------------------------------------

fn extensions() -> impl Strategy<Value = Extensions> {
    (
        option::of(vec(any::<u16>(), 0..6)),
        option::of(vec(any::<u8>(), 0..4)),
        option::of(vec(any::<u16>(), 0..6)),
        option::of((vec(any::<u16>(), 0..4), vec(any::<u8>(), 0..8))),
        any::<bool>(),
        option::of(vec(any::<u8>(), 0..16)),
    )
        .prop_map(|(groups, formats, schemes, srtp, ems, reneg)| Extensions {
            supported_groups: groups,
            ec_point_formats: formats,
            signature_algorithms: schemes,
            use_srtp: srtp.map(|(profiles, mki)| UseSrtp { profiles, mki }),
            extended_master_secret: ems,
            renegotiation_info: reneg,
            first_unknown: None,
        })
}

fn client_hello() -> impl Strategy<Value = ClientHello> {
    (
        any::<u16>(),
        any::<[u8; 32]>(),
        vec(any::<u8>(), 0..=32),
        vec(any::<u8>(), 0..=255),
        vec(any::<u16>(), 1..12),
        vec(any::<u8>(), 1..4),
        extensions(),
    )
        .prop_map(
            |(
                version,
                random,
                session_id,
                cookie,
                cipher_suites,
                compression_methods,
                extensions,
            )| {
                ClientHello {
                    version,
                    random,
                    session_id,
                    cookie,
                    cipher_suites,
                    compression_methods,
                    extensions,
                }
            },
        )
}

fn server_hello() -> impl Strategy<Value = ServerHello> {
    (
        any::<u16>(),
        any::<[u8; 32]>(),
        vec(any::<u8>(), 0..=32),
        any::<u16>(),
        any::<u8>(),
        extensions(),
    )
        .prop_map(
            |(version, random, session_id, cipher_suite, compression_method, extensions)| {
                ServerHello {
                    version,
                    random,
                    session_id,
                    cipher_suite,
                    compression_method,
                    extensions,
                }
            },
        )
}

fn digitally_signed() -> impl Strategy<Value = DigitallySigned> {
    (any::<u16>(), vec(any::<u8>(), 1..140))
        .prop_map(|(scheme, signature)| DigitallySigned { scheme, signature })
}

fn server_key_exchange() -> impl Strategy<Value = ServerKeyExchange> {
    (any::<u16>(), vec(any::<u8>(), 1..=255), digitally_signed()).prop_map(
        |(named_curve, public, signed)| ServerKeyExchange {
            params: EcdheParams {
                named_curve,
                public,
            },
            signed,
        },
    )
}

fn encoded<E: std::fmt::Debug>(encode: impl FnOnce(&mut Vec<u8>) -> Result<(), E>) -> Vec<u8> {
    let mut out = Vec::new();
    encode(&mut out).unwrap();
    out
}

/// Every proper prefix of a strictly framed encoding must be refused.
fn assert_prefixes_fail<T>(bytes: &[u8], parse: impl Fn(&[u8]) -> Option<T>) {
    for len in 0..bytes.len() {
        assert!(
            parse(&bytes[..len]).is_none(),
            "prefix of {len} bytes parsed"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // ----- 1. codecs ---------------------------------------------------------

    #[test]
    fn extensions_round_trip(ext in extensions()) {
        let bytes = encoded(|out| ext.encode(out));
        let parsed = Extensions::parse(&mut Reader::new(&bytes)).unwrap();
        prop_assert_eq!(parsed, ext);
    }

    #[test]
    fn client_hello_round_trips_and_splits_at_the_cookie(hello in client_hello()) {
        let bytes = encoded(|out| hello.encode(out));
        prop_assert_eq!(&ClientHello::parse(&bytes).unwrap(), &hello);
        // The cookie split used for the stateless cookie covers every byte
        // except the cookie itself.
        let parts = ClientHello::split_cookie(&bytes).unwrap();
        prop_assert_eq!(parts.cookie, hello.cookie.as_slice());
        prop_assert_eq!(
            parts.before.len() + 1 + parts.cookie.len() + parts.after.len(),
            bytes.len()
        );
        for len in 0..bytes.len() {
            // Never panics; a cut inside the fixed part never parses.
            let parsed = ClientHello::parse(&bytes[..len]);
            if len < 2 + 32 + 1 + hello.session_id.len() + 1 + hello.cookie.len() + 2 {
                prop_assert!(parsed.is_err());
            }
            let _ = ClientHello::split_cookie(&bytes[..len]);
        }
    }

    #[test]
    fn server_hello_round_trip(hello in server_hello()) {
        let bytes = encoded(|out| hello.encode(out));
        prop_assert_eq!(&ServerHello::parse(&bytes).unwrap(), &hello);
        for len in 0..bytes.len() {
            let _ = ServerHello::parse(&bytes[..len]);
        }
    }

    #[test]
    fn hello_verify_request_round_trip(version in any::<u16>(), cookie in vec(any::<u8>(), 0..=255)) {
        let request = HelloVerifyRequest { version, cookie };
        let bytes = encoded(|out| request.encode(out));
        prop_assert_eq!(&HelloVerifyRequest::parse(&bytes).unwrap(), &request);
        assert_prefixes_fail(&bytes, |b| HelloVerifyRequest::parse(b).ok());
    }

    #[test]
    fn certificate_round_trip(chain in vec(vec(any::<u8>(), 1..300), 0..4)) {
        let message = CertificateMsg { chain };
        let bytes = encoded(|out| message.encode(out));
        prop_assert_eq!(&CertificateMsg::parse(&bytes).unwrap(), &message);
        assert_prefixes_fail(&bytes, |b| CertificateMsg::parse(b).ok());
    }

    #[test]
    fn server_key_exchange_round_trip(exchange in server_key_exchange()) {
        let bytes = encoded(|out| exchange.encode(out));
        prop_assert_eq!(&ServerKeyExchange::parse(&bytes).unwrap(), &exchange);
        assert_prefixes_fail(&bytes, |b| ServerKeyExchange::parse(b).ok());
    }

    #[test]
    fn certificate_request_round_trip(
        certificate_types in vec(any::<u8>(), 0..6),
        signature_algorithms in vec(any::<u16>(), 0..8),
        certificate_authorities in vec(any::<u8>(), 0..64),
    ) {
        let request = CertificateRequest {
            certificate_types,
            signature_algorithms,
            certificate_authorities,
        };
        let bytes = encoded(|out| request.encode(out));
        prop_assert_eq!(&CertificateRequest::parse(&bytes).unwrap(), &request);
        assert_prefixes_fail(&bytes, |b| CertificateRequest::parse(b).ok());
    }

    #[test]
    fn certificate_verify_and_key_exchange_round_trip(
        signed in digitally_signed(),
        public in vec(any::<u8>(), 1..=255),
        verify_data in any::<[u8; 12]>(),
    ) {
        let verify = CertificateVerify { signed };
        let bytes = encoded(|out| verify.encode(out));
        prop_assert_eq!(&CertificateVerify::parse(&bytes).unwrap(), &verify);
        assert_prefixes_fail(&bytes, |b| CertificateVerify::parse(b).ok());

        let exchange = ClientKeyExchange { public };
        let bytes = encoded(|out| exchange.encode(out));
        prop_assert_eq!(&ClientKeyExchange::parse(&bytes).unwrap(), &exchange);
        assert_prefixes_fail(&bytes, |b| ClientKeyExchange::parse(b).ok());

        let finished = Finished { verify_data };
        let mut bytes = Vec::new();
        finished.encode(&mut bytes);
        prop_assert_eq!(&Finished::parse(&bytes).unwrap(), &finished);
        assert_prefixes_fail(&bytes, |b| Finished::parse(b).ok());
        bytes.push(0);
        prop_assert!(Finished::parse(&bytes).is_err());
    }

    #[test]
    fn handshake_header_and_alert_round_trip(
        msg_type in any::<u8>(),
        length in 0u32..1 << 24,
        message_seq in any::<u16>(),
        fragment_offset in 0u32..1 << 24,
        fragment_length in 0u32..1 << 24,
        level in any::<u8>(),
        description in any::<u8>(),
    ) {
        let head = header(msg_type, length, message_seq, fragment_offset, fragment_length);
        let bytes = encoded(|out| head.encode(out));
        prop_assert_eq!(bytes.len(), HS_HEADER);
        prop_assert_eq!(HandshakeHeader::parse(&mut Reader::new(&bytes)).unwrap(), head);
        assert_prefixes_fail(&bytes, |b| HandshakeHeader::parse(&mut Reader::new(b)).ok());

        let alert = Alert { level, description };
        prop_assert_eq!(Alert::parse(&alert.encode()).unwrap(), alert);
        prop_assert_eq!(alert.is_fatal(), level != 1);
    }

    /// No parser panics on arbitrary input, and whatever parses re-encodes
    /// to something that parses to the same value.
    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..600)) {
        if let Ok(hello) = ClientHello::parse(&bytes) {
            let again = encoded(|out| hello.encode(out));
            prop_assert_eq!(ClientHello::parse(&again).unwrap(), hello);
        }
        if let Ok(hello) = ServerHello::parse(&bytes) {
            let again = encoded(|out| hello.encode(out));
            prop_assert_eq!(ServerHello::parse(&again).unwrap(), hello);
        }
        let _ = ClientHello::split_cookie(&bytes);
        let _ = HelloVerifyRequest::parse(&bytes);
        let _ = CertificateMsg::parse(&bytes);
        let _ = ServerKeyExchange::parse(&bytes);
        let _ = CertificateRequest::parse(&bytes);
        let _ = CertificateVerify::parse(&bytes);
        let _ = ClientKeyExchange::parse(&bytes);
        let _ = Finished::parse(&bytes);
        let _ = Alert::parse(&bytes);
        let _ = Extensions::parse(&mut Reader::new(&bytes));
        let _ = HandshakeHeader::parse(&mut Reader::new(&bytes));
        let _ = EcdheParams::parse(&mut Reader::new(&bytes));
        let _ = extract_p384_public_key(&bytes);

        // The record iterator yields at most the cap plus one error, never
        // more payload than the datagram holds, and always terminates.
        let mut total = 0;
        let mut count = 0;
        for record in DatagramRecords::new(&bytes) {
            count += 1;
            if let Ok(record) = record {
                total += 13 + record.payload.len();
            }
        }
        prop_assert!(count <= MAX_RECORDS_PER_DATAGRAM + 1);
        prop_assert!(total <= bytes.len());
    }

    #[test]
    fn fingerprint_parser_never_panics(text in ".{0,200}", hex in vec(any::<u8>(), 0..70)) {
        let _ = CertificateFingerprint::from_sdp_strict(&text);
        let _ = CertificateFingerprint::from_sdp(&text);
        let joined = hex.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        for algorithm in ["sha-1", "sha-256", "sha-384", "sha-512", "SHA-384", ""] {
            let value = format!("{algorithm} {joined}");
            let strict = CertificateFingerprint::from_sdp_strict(&value);
            // CNSA 2.0: only sha-384 and sha-512 of the right length.
            if let Ok(fingerprint) = strict {
                prop_assert!(matches!(fingerprint.bytes().len(), 48 | 64));
                prop_assert_eq!(fingerprint.bytes(), hex.as_slice());
            }
        }
    }

    /// A real certificate with arbitrary damage: the SPKI walk never panics,
    /// and what it returns is always an uncompressed P-384 point.
    #[test]
    fn spki_extraction_survives_damaged_certificates(
        edits in vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
        cut in option::of(any::<prop::sample::Index>()),
    ) {
        let mut cert = shared_identity().certificate_chain()[0].clone();
        for (index, value) in edits {
            let at = index.index(cert.len());
            cert[at] = value;
        }
        if let Some(cut) = cut {
            cert.truncate(cut.index(cert.len()));
        }
        if let Ok(point) = extract_p384_public_key(&cert) {
            prop_assert_eq!(point.len(), 97);
            prop_assert_eq!(point[0], 0x04);
        }
    }

    // ----- 2. reassembly and replay window against a model -------------------

    /// Any cover of a message by fragments (overlapping, duplicated, in any
    /// order) reassembles to exactly that message.
    #[test]
    fn reassembly_of_any_fragmentation_yields_the_message(
        body in vec(any::<u8>(), 0..1500),
        cuts in vec((any::<prop::sample::Index>(), any::<prop::sample::Index>()), 0..12),
        order in any::<u64>(),
        seq in 0u16..1000,
    ) {
        let len = body.len();
        // Arbitrary extra fragments, then a guaranteed cover in 97-byte steps.
        let mut ranges: Vec<(usize, usize)> = cuts
            .iter()
            .map(|(a, b)| {
                let (a, b) = (a.index(len + 1), b.index(len + 1));
                (a.min(b), a.max(b))
            })
            .collect();
        ranges.extend((0..len).step_by(97).map(|start| (start, (start + 97).min(len))));
        if len == 0 {
            ranges.push((0, 0));
        }
        shuffle(&mut ranges, order);

        let mut reassembler = Reassembler::new(seq);
        for (start, end) in ranges {
            let head = header(
                HT_CERTIFICATE,
                u32::try_from(len).unwrap(),
                seq,
                u32::try_from(start).unwrap(),
                u32::try_from(end - start).unwrap(),
            );
            let outcome = reassembler.push(&head, &body[start..end], 0);
            // More than 16 disjoint ranges may be refused; never an error.
            prop_assert!(matches!(
                outcome,
                Ok(FragmentOutcome::Buffered | FragmentOutcome::Rejected)
            ));
        }
        // The 97-byte cover alone can exceed the range cap only transiently
        // when shuffled; feed it once more in order to finish.
        for start in (0..len).step_by(97) {
            let end = (start + 97).min(len);
            let head = header(
                HT_CERTIFICATE,
                u32::try_from(len).unwrap(),
                seq,
                u32::try_from(start).unwrap(),
                u32::try_from(end - start).unwrap(),
            );
            let _ = reassembler.push(&head, &body[start..end], 0);
        }
        let message = reassembler.pop().expect("complete message");
        prop_assert_eq!(message.body, body);
        prop_assert_eq!(message.message_seq, seq);
        prop_assert_eq!(reassembler.buffered_bytes(), 0);
        prop_assert!(reassembler.pop().is_none());
    }

    /// Arbitrary fragment headers: memory stays inside the bound, nothing
    /// panics, messages come out in strictly increasing order, and a
    /// violation stores nothing.
    #[test]
    fn reassembly_memory_is_bounded_for_arbitrary_fragments(
        fragments in vec(
            (
                prop_oneof![Just(HT_CERTIFICATE), any::<u8>()],
                prop_oneof![0u32..9000, any::<u32>().prop_map(|v| v & 0x00FF_FFFF)],
                0u16..12,
                prop_oneof![0u32..9000, any::<u32>().prop_map(|v| v & 0x00FF_FFFF)],
                0usize..300,
                any::<bool>(),
                0u16..2,
            ),
            0..80,
        ),
    ) {
        let mut reassembler = Reassembler::new(0);
        let mut last = None;
        for (msg_type, length, seq, offset, data_len, lie, epoch) in fragments {
            let claimed = u32::try_from(data_len).unwrap() + u32::from(lie);
            let head = header(msg_type, length, seq, offset, claimed);
            let before = reassembler.buffered_bytes();
            let outcome = reassembler.push(&head, &vec![0xC3; data_len], epoch);
            if outcome.is_err() {
                prop_assert_eq!(reassembler.buffered_bytes(), before);
            }
            prop_assert!(reassembler.buffered_bytes() <= MAX_BUFFERED_BYTES);
            while let Some(message) = reassembler.pop() {
                prop_assert!(last.is_none_or(|l| message.message_seq > l));
                prop_assert!(message.body.len() <= 8192);
                last = Some(message.message_seq);
            }
            prop_assert!(reassembler.next_seq() <= 12 + FUTURE_WINDOW);
        }
    }

    /// The record layer's replay protection against a reference model of
    /// RFC 6347 §4.1.2.6 with a 64-record window: each sequence number is
    /// accepted at most once, and never once it is 64 or more behind.
    #[test]
    fn replay_window_matches_the_reference_model(
        deliveries in vec(0usize..200, 1..300),
        forge in vec(any::<bool>(), 300),
    ) {
        let (mut sender, mut receiver) = keyed_record_layers();
        let sealed: Vec<Vec<u8>> = (0..200)
            .map(|_| sender.seal(1, ContentType::ApplicationData, b"x").unwrap())
            .collect();
        let mut seen = BTreeSet::new();
        let mut max: Option<usize> = None;
        for (step, seq) in deliveries.into_iter().enumerate() {
            let mut datagram = sealed[seq].clone();
            let forged = forge[step];
            if forged {
                *datagram.last_mut().unwrap() ^= 0x80;
            }
            let record = DatagramRecords::new(&datagram).next().unwrap().unwrap();
            let fresh = max.is_none_or(|m| seq > m || (m - seq < 64 && !seen.contains(&seq)));
            let opened = receiver.open(&record);
            prop_assert_eq!(opened.is_ok(), fresh && !forged, "seq {} forged {}", seq, forged);
            if opened.is_ok() {
                seen.insert(seq);
                max = Some(max.map_or(seq, |m| m.max(seq)));
            }
        }
    }
}

/// Deterministic Fisher-Yates from a seed, so a failing case replays.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed | 1;
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = usize::try_from(state % (i as u64 + 1)).unwrap();
        items.swap(i, j);
    }
}

fn shared_identity() -> &'static DtlsCredentials {
    static IDENTITY: OnceLock<DtlsCredentials> = OnceLock::new();
    IDENTITY.get_or_init(identity)
}

/// Two record layers with epoch 1 active in both directions.
fn keyed_record_layers() -> (AssociationRecordLayer, AssociationRecordLayer) {
    let (ka, kb) = ([0x11u8; 32], [0x22u8; 32]);
    let mut a = AssociationRecordLayer::new();
    let mut b = AssociationRecordLayer::new();
    a.install_pending_keys(&ka, &[1; 4], &kb, &[2; 4]).unwrap();
    b.install_pending_keys(&kb, &[2; 4], &ka, &[1; 4]).unwrap();
    a.activate_write().unwrap();
    b.activate_read().unwrap();
    (a, b)
}

// ----- 3. the association ------------------------------------------------------

/// One hostile input to an association.
#[derive(Debug, Clone)]
enum Hostile {
    /// Arbitrary bytes.
    Bytes(Vec<u8>),
    /// A well-formed record header around arbitrary content.
    Record {
        content_type: u8,
        version: u16,
        epoch: u16,
        seq: u64,
        payload: Vec<u8>,
    },
    /// A plaintext handshake fragment with an arbitrary header.
    Fragment {
        msg_type: u8,
        length: u32,
        message_seq: u16,
        offset: u32,
        data: Vec<u8>,
        lie: bool,
    },
    /// A datagram already seen on the wire, with bytes changed and possibly
    /// cut short.
    Damaged {
        which: prop::sample::Index,
        edits: Vec<(prop::sample::Index, u8)>,
        cut: Option<prop::sample::Index>,
    },
    /// Time passes.
    Wait(u16),
}

fn hostile() -> impl Strategy<Value = Hostile> {
    let content_type = prop_oneof![20u8..=23, any::<u8>()];
    let version = prop_oneof![Just(0xFEFDu16), Just(0xFEFF), any::<u16>()];
    let msg_type = prop_oneof![
        prop::sample::select(vec![0u8, 1, 2, 3, 11, 12, 13, 14, 15, 16, 20]),
        any::<u8>()
    ];
    prop_oneof![
        vec(any::<u8>(), 0..300).prop_map(Hostile::Bytes),
        (
            content_type,
            version,
            0u16..3,
            0u64..100,
            vec(any::<u8>(), 0..200)
        )
            .prop_map(
                |(content_type, version, epoch, seq, payload)| Hostile::Record {
                    content_type,
                    version,
                    epoch,
                    seq,
                    payload,
                }
            ),
        (
            msg_type,
            prop_oneof![0u32..300, 0u32..10_000, 0u32..1 << 24],
            0u16..10,
            prop_oneof![Just(0u32), 0u32..300, 0u32..1 << 24],
            vec(any::<u8>(), 0..200),
            any::<bool>(),
        )
            .prop_map(|(msg_type, length, message_seq, offset, data, lie)| {
                Hostile::Fragment {
                    msg_type,
                    length,
                    message_seq,
                    offset,
                    data,
                    lie,
                }
            }),
        (
            any::<prop::sample::Index>(),
            vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
            option::of(any::<prop::sample::Index>()),
        )
            .prop_map(|(which, edits, cut)| Hostile::Damaged { which, edits, cut }),
        (0u16..3000).prop_map(Hostile::Wait),
    ]
}

impl Hostile {
    /// The datagram to inject, given what has crossed the wire so far.
    fn datagram(&self, seen: &[Vec<u8>]) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Some(bytes.clone()),
            Self::Record {
                content_type,
                version,
                epoch,
                seq,
                payload,
            } => Some(raw_record(*content_type, *version, *epoch, *seq, payload)),
            Self::Fragment {
                msg_type,
                length,
                message_seq,
                offset,
                data,
                lie,
            } => {
                let claimed = u32::try_from(data.len()).unwrap() + u32::from(*lie);
                let head = header(*msg_type, *length, *message_seq, *offset, claimed);
                Some(fragment_record(0, &head, data))
            }
            Self::Damaged { which, edits, cut } => {
                if seen.is_empty() {
                    return None;
                }
                let mut datagram = seen[which.index(seen.len())].clone();
                for (at, value) in edits {
                    if !datagram.is_empty() {
                        let at = at.index(datagram.len());
                        datagram[at] = *value;
                    }
                }
                if let Some(cut) = cut {
                    datagram.truncate(cut.index(datagram.len() + 1));
                }
                Some(datagram)
            }
            Self::Wait(_) => None,
        }
    }
}

/// Delivers exactly `steps` datagrams of an honest handshake, one at a
/// time, alternating directions as they become available.
fn advance_honestly(lo: &mut Loopback, steps: usize) {
    for _ in 0..steps {
        let (dir, datagram) = if let Some(d) = lo.client.assoc.poll_transmit() {
            (Dir::ClientToServer, d)
        } else if let Some(d) = lo.server.assoc.poll_transmit() {
            (Dir::ServerToClient, d)
        } else {
            return;
        };
        lo.log.push((dir, datagram.clone()));
        match dir {
            Dir::ClientToServer => lo.server.assoc.handle_datagram(&datagram, lo.now),
            Dir::ServerToClient => lo.client.assoc.handle_datagram(&datagram, lo.now),
        }
        lo.client.drain_events();
        lo.server.drain_events();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Arbitrary input to either role in every handshake state (0..=6
    /// honest datagrams delivered first, then also after completion).
    ///
    /// - never panics;
    /// - never makes the victim report `Connected` or export keys: nothing
    ///   injected here is new genuine traffic, only noise and damaged copies
    ///   of datagrams the victim already had;
    /// - queues stay bounded and a terminal association stays silent;
    /// - when the honest handshake then continues, it either completes with
    ///   identical keys or fails without keys on the failing side.
    #[test]
    fn arbitrary_input_in_every_state_never_panics_or_yields_keys(
        steps in 0usize..=7,
        attack_client in any::<bool>(),
        inputs in vec(hostile(), 1..40),
    ) {
        let mut lo = Loopback::new();
        advance_honestly(&mut lo, steps);
        let seen: Vec<Vec<u8>> = lo
            .log
            .iter()
            .filter(|(dir, _)| (*dir == Dir::ServerToClient) == attack_client)
            .map(|(_, d)| d.clone())
            .collect();
        let connected_before = if attack_client {
            lo.client.connected_events
        } else {
            lo.server.connected_events
        };

        let mut now = lo.now;
        let mut held_back = Vec::new();
        {
            let victim = if attack_client { &mut lo.client } else { &mut lo.server };
            for input in &inputs {
                match input.datagram(&seen) {
                    Some(datagram) => victim.assoc.handle_datagram(&datagram, now),
                    None => {
                        if let Hostile::Wait(ms) = input {
                            now += Duration::from_millis(u64::from(*ms));
                            victim.assoc.handle_timeout(now);
                        }
                    }
                }
                let _ = format!("{:?} {:?}", victim.assoc, victim.assoc.stats());
                // SC-5: the transmit queue is capped at 64 datagrams.
                let queued = victim.drain_transmit();
                prop_assert!(queued.len() <= 64);
                held_back.extend(queued);
                victim.drain_events();
                prop_assert_eq!(victim.connected_events, connected_before);
                if victim.assoc.is_terminated() {
                    prop_assert!(victim.assoc.poll_timeout().is_none());
                    prop_assert!(!victim.assoc.is_connected());
                }
            }
            prop_assert!(victim.failed_events <= 1);
        }

        // Let the honest exchange carry on with whatever the victim sent
        // while under attack, and settle.
        lo.now = now;
        for datagram in held_back {
            if attack_client {
                lo.server.assoc.handle_datagram(&datagram, now);
            } else {
                lo.client.assoc.handle_datagram(&datagram, now);
            }
        }
        lo.run(deliver);
        if let (Some(c), Some(s)) = (&lo.client.keys, &lo.server.keys) {
            prop_assert_eq!(exported(c), exported(s));
        }
        for side in [&lo.client, &lo.server] {
            prop_assert!(side.connected_events <= 1);
            prop_assert!(side.failed_events <= 1);
            if side.failed.is_some() && side.keys.is_none() {
                prop_assert!(!side.assoc.is_connected());
            }
        }
        // The client only completes after the server did (it needs the
        // server's Finished), so client keys imply server keys.
        if lo.client.keys.is_some() {
            prop_assert!(lo.server.keys.is_some());
        }
        prop_assert!(lo.elapsed() <= Duration::from_secs(10 + 3 * 40));
    }

    /// Pure noise (no copies of genuine traffic) cannot fail a server that
    /// has no verified client yet, and cannot make it send anything but
    /// `HelloVerifyRequest`s: the pre-cookie server is stateless.
    #[test]
    fn noise_cannot_fail_or_provoke_a_server_before_the_cookie(
        inputs in vec(hostile(), 1..60),
    ) {
        let now = Instant::now();
        let config = AssociationConfig::new(
            DtlsRole::Server,
            shared_identity().clone(),
            vec![shared_identity().fingerprint().clone()],
        );
        let mut server = Side::new(config, now);
        for input in &inputs {
            if let Some(datagram) = input.datagram(&[]) {
                server.assoc.handle_datagram(&datagram, now);
            }
        }
        server.drain_events();
        prop_assert_eq!(server.failed, None);
        prop_assert!(!server.assoc.is_terminated());
        let sent = server.drain_transmit();
        prop_assert!(sent.len() <= 4, "more than 4 HelloVerifyRequests in one second");
        for datagram in sent {
            let types: Vec<u8> = messages(&datagram).iter().map(|m| m.msg_type).collect();
            prop_assert_eq!(types, vec![3u8]);
        }
    }
}

// ----- an unreliable network ---------------------------------------------------

/// What the network does to one datagram.
#[derive(Debug, Clone, Copy)]
enum Net {
    Deliver,
    Drop,
    Duplicate,
    /// Deliver after this many later datagrams (reordering across datagrams).
    Delay(u8),
    /// One datagram per record, in shuffled order.
    Split(u64),
    /// Cut every plaintext handshake fragment into smaller fragments at
    /// arbitrary points, shuffle all records, and repack them into datagrams
    /// of arbitrary size.
    Refragment(u64),
}

fn net() -> impl Strategy<Value = Net> {
    prop_oneof![
        5 => Just(Net::Deliver),
        1 => Just(Net::Drop),
        1 => Just(Net::Duplicate),
        1 => (1u8..4).prop_map(Net::Delay),
        1 => any::<u64>().prop_map(Net::Split),
        3 => any::<u64>().prop_map(Net::Refragment),
    ]
}

struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % (bound as u64)).unwrap()
    }
}

/// Re-fragments the plaintext handshake records of a datagram. A first
/// `ClientHello` is left whole: the server role does not reassemble it
/// before the cookie is verified (documented deviation, tested in
/// `negative.rs`).
fn refragment(datagram: &[u8], seed: u64) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed | 1);
    let mut out: Vec<Vec<u8>> = Vec::new();
    for rec in records(datagram) {
        if rec.epoch != 0 || rec.content_type != ContentType::Handshake {
            out.push(rec.encode());
            continue;
        }
        // A record may already hold a fragment (small MTU): split whatever
        // range it carries.
        let mut r = Reader::new(&rec.payload);
        let head = HandshakeHeader::parse(&mut r).unwrap();
        let data = r.rest();
        if head.msg_type == HT_CLIENT_HELLO || data.len() < 2 {
            out.push(rec.encode());
            continue;
        }
        let pieces = 1 + rng.below(4);
        let mut cuts: Vec<usize> = (0..pieces - 1).map(|_| rng.below(data.len() + 1)).collect();
        cuts.push(0);
        cuts.push(data.len());
        cuts.sort_unstable();
        for pair in cuts.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            if start == end {
                continue;
            }
            // Sometimes overlap the previous piece by a few bytes.
            let start = start.saturating_sub(rng.below(3));
            let piece = header(
                head.msg_type,
                head.length,
                head.message_seq,
                head.fragment_offset + u32::try_from(start).unwrap(),
                u32::try_from(end - start).unwrap(),
            );
            out.push(fragment_record(rec.seq, &piece, &data[start..end]));
        }
    }
    shuffle(&mut out, rng.next());
    // Repack into datagrams of 1..=3 records.
    let mut datagrams = Vec::new();
    let mut iter = out.into_iter().peekable();
    while iter.peek().is_some() {
        let take = 1 + rng.below(3);
        datagrams.push(iter.by_ref().take(take).flatten().collect());
    }
    datagrams
}

/// Result of one simulated handshake.
struct Outcome {
    lo: Loopback,
    largest: [usize; 2],
}

/// Runs a client and a server over the network described by `plan` (cycled
/// per datagram) until both have settled or no timer is left.
fn run_over(plan: &[Net], client_mtu: u16, server_mtu: u16) -> Outcome {
    let mut lo = Loopback::with(|client, server| {
        client.mtu = client_mtu;
        server.mtu = server_mtu;
    });
    // (deliver when the datagram counter reaches this, direction, bytes)
    let mut delayed: VecDeque<(usize, Dir, Vec<u8>)> = VecDeque::new();
    let mut counter = 0usize;
    let mut largest = [0usize; 2];

    for _ in 0..20_000 {
        let mut moved = false;
        for dir in [Dir::ClientToServer, Dir::ServerToClient] {
            let outgoing = match dir {
                Dir::ClientToServer => lo.client.drain_transmit(),
                Dir::ServerToClient => lo.server.drain_transmit(),
            };
            for datagram in outgoing {
                moved = true;
                let slot = usize::from(dir == Dir::ServerToClient);
                largest[slot] = largest[slot].max(datagram.len());
                let action = plan[counter % plan.len()];
                counter += 1;
                let deliveries: Vec<Vec<u8>> = match action {
                    Net::Deliver => vec![datagram],
                    Net::Drop => Vec::new(),
                    Net::Duplicate => vec![datagram.clone(), datagram],
                    Net::Delay(by) => {
                        delayed.push_back((counter + usize::from(by), dir, datagram));
                        Vec::new()
                    }
                    Net::Split(seed) => {
                        let mut parts: Vec<Vec<u8>> =
                            records(&datagram).iter().map(Rec::encode).collect();
                        shuffle(&mut parts, seed);
                        parts
                    }
                    Net::Refragment(seed) => refragment(&datagram, seed),
                };
                for delivery in deliveries {
                    match dir {
                        Dir::ClientToServer => lo.server.assoc.handle_datagram(&delivery, lo.now),
                        Dir::ServerToClient => lo.client.assoc.handle_datagram(&delivery, lo.now),
                    }
                }
            }
        }
        // Delayed datagrams whose turn has come, or all of them once the
        // wire is otherwise idle.
        while let Some(position) = delayed
            .iter()
            .position(|(due, _, _)| *due <= counter || !moved)
        {
            let (_, dir, datagram) = delayed.remove(position).unwrap();
            moved = true;
            match dir {
                Dir::ClientToServer => lo.server.assoc.handle_datagram(&datagram, lo.now),
                Dir::ServerToClient => lo.client.assoc.handle_datagram(&datagram, lo.now),
            }
        }
        lo.client.drain_events();
        lo.server.drain_events();
        if moved {
            continue;
        }
        if lo.client.settled() && lo.server.settled() {
            break;
        }
        if !lo.advance() {
            break;
        }
    }
    Outcome { lo, largest }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary fragmentation, reordering, duplication, delay and loss of
    /// a valid handshake, with arbitrary MTUs on both sides:
    ///
    /// - it never panics and always settles;
    /// - both sides that export keys export identical keys, and the client
    ///   never has keys the server lacks;
    /// - the only failure a faithful-but-unreliable network can cause is
    ///   `Timeout`, at exactly the 10 s budget -- never a protocol error;
    /// - no datagram exceeds the sender's MTU, and the handshake transcript
    ///   and retransmissions stay bounded.
    #[test]
    fn handshake_over_an_unreliable_network_completes_or_times_out(
        plan in vec(net(), 1..24),
        client_mtu in prop_oneof![Just(1200u16), 576u16..=1500],
        server_mtu in prop_oneof![Just(1200u16), 576u16..=1500],
    ) {
        let Outcome { lo, largest } = run_over(&plan, client_mtu, server_mtu);

        prop_assert!(lo.client.settled(), "client did not settle");
        prop_assert!(lo.server.settled(), "server did not settle");
        prop_assert!(largest[0] <= usize::from(client_mtu));
        prop_assert!(largest[1] <= usize::from(server_mtu));

        for (name, side) in [("client", &lo.client), ("server", &lo.server)] {
            prop_assert!(side.connected_events <= 1);
            prop_assert!(side.failed_events <= 1);
            if side.keys.is_none() {
                prop_assert_eq!(
                    side.failed,
                    Some(FailureCause::Timeout),
                    "{} failed with something other than Timeout", name
                );
                prop_assert!(!side.assoc.is_connected());
                prop_assert!(lo.elapsed() >= Duration::from_secs(10));
            }
            // Retransmissions are timer-driven: 1+2+4+8 s fits the budget
            // at most four times, plus peer-triggered ones.
            prop_assert!(side.assoc.stats().retransmits < 64);
        }
        if let (Some(c), Some(s)) = (&lo.client.keys, &lo.server.keys) {
            prop_assert_eq!(exported(c), exported(s));
            prop_assert_eq!(exported(c).len(), 88);
        }
        if lo.client.keys.is_some() {
            prop_assert!(lo.server.keys.is_some(), "client has keys the server lacks");
        }
        prop_assert!(lo.elapsed() <= Duration::from_secs(10));
        prop_assert!(MAX_TRANSCRIPT_LEN >= 4096);
    }
}

/// With no loss at all, re-fragmentation and reordering of every datagram
/// (retransmissions included) never fails a handshake: all 300 complete
/// inside the budget with identical keys.
///
/// They are not free, though. A `ChangeCipherSpec` that arrives before the
/// last handshake fragment ahead of it, or a protected `Finished` that
/// arrives before its `ChangeCipherSpec`, is dropped rather than buffered
/// (RFC 6347 §4.1 allows either), so the flight has to be retransmitted and
/// each round costs a timer interval. The histogram printed with
/// `--nocapture` shows the cost under this (deliberately hostile) network;
/// see qa-report.md, observation O1.
#[test]
fn lossless_refragmentation_always_completes() {
    let mut histogram = std::collections::BTreeMap::new();
    for seed in 1..=300u64 {
        let plan = [Net::Refragment(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15))];
        let Outcome { lo, .. } = run_over(&plan, 1200, 1200);
        lo.assert_connected();
        *histogram.entry(lo.elapsed().as_secs()).or_insert(0usize) += 1;
    }
    eprintln!("seconds of fake time to complete -> handshakes: {histogram:?}");
    assert_eq!(histogram.values().sum::<usize>(), 300);
    assert!(
        histogram.keys().all(|seconds| *seconds < 10),
        "{histogram:?}"
    );
}

/// The same network that only splits a flight into one datagram per record
/// and keeps the order costs nothing: no timer fires.
#[test]
fn one_record_per_datagram_in_order_costs_no_retransmission() {
    let mut lo = Loopback::new();
    lo.run(|_, _, datagram| Wire::Replace(records(datagram).iter().map(Rec::encode).collect()));
    lo.assert_connected();
    assert_eq!(lo.elapsed(), Duration::ZERO);
    assert_eq!(lo.client.assoc.stats().retransmits, 0);
    assert_eq!(lo.server.assoc.stats().retransmits, 0);
}
