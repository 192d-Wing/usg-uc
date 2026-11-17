//! Negative suite for `DtlsAssociation` (plan §6.1, threat sketch §5).
//!
//! Every test here ends one of three ways, and says which:
//!
//! - the association fails with a stated [`FailureCause`], exports no keys
//!   and reports no `Connected`;
//! - hostile or broken input is dropped and counted, and the association
//!   carries on;
//! - a connected association ends (`PeerClosed` / `Failed`) on an
//!   authenticated alert, and only on an authenticated one.
//!
//! Peers are either two real associations with a rewriting wire between
//! them, or a hand-driven [`Puppet`] that holds the session keys (see
//! `common/mod.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use proto_dtls::record::{ContentType, DTLS_1_0_VERSION, DTLS_1_2_VERSION};
use proto_dtls::wire::alert;
use proto_dtls::wire::extensions::UseSrtp;
use proto_dtls::wire::handshake_msg::{
    CertificateMsg, CertificateRequest, ClientHello, HT_CERTIFICATE, HT_CERTIFICATE_REQUEST,
    HT_CERTIFICATE_VERIFY, HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED, HT_HELLO_REQUEST,
    HT_HELLO_VERIFY_REQUEST, HT_SERVER_HELLO, HT_SERVER_HELLO_DONE, HT_SERVER_KEY_EXCHANGE,
    HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use proto_dtls::{
    AssociationConfig, AssociationStats, CertificateFingerprint, DtlsAssociation, DtlsRole,
    FailureCause,
};
use std::time::{Duration, Instant};

const SECOND: Duration = Duration::from_secs(1);

/// Both sides ended as stated, each with exactly one `Failed` event, and
/// nobody exported keys.
fn assert_failed(lo: &Loopback, client: FailureCause, server: FailureCause) {
    assert_eq!(lo.client.failed, Some(client), "client cause");
    assert_eq!(lo.server.failed, Some(server), "server cause");
    lo.assert_no_keys();
    for side in [&lo.client, &lo.server] {
        assert_eq!(side.failed_events, 1);
        assert!(side.assoc.is_terminated());
        assert_eq!(side.assoc.poll_timeout(), None);
    }
}

/// One side failed as stated and exported nothing.
fn assert_side_failed(side: &Side, cause: FailureCause) {
    assert_eq!(side.failed, Some(cause));
    assert!(side.keys.is_none(), "keys exported");
    assert_eq!(side.connected_events, 0);
    assert_eq!(side.failed_events, 1);
    assert!(side.assoc.is_terminated());
    assert!(!side.assoc.is_connected());
    assert_eq!(side.assoc.poll_timeout(), None);
}

/// The side is still handshaking: nothing failed, nothing exported.
fn assert_still_handshaking(side: &mut Side) {
    side.drain_events();
    assert_eq!(side.failed, None);
    assert!(side.keys.is_none());
    assert!(!side.assoc.is_terminated());
    assert!(!side.assoc.is_connected());
}

/// SEC-010: a plaintext message the side refused did not end the handshake
/// at once (it may be forged), and nothing was sent for it. The failure
/// surfaces when the retransmission timer next expires, which is at most
/// one interval after `now`. Fires that timer.
fn expire_retransmission_timer(side: &mut Side, now: Instant) {
    assert_still_handshaking(side);
    assert!(
        side.assoc.stats().fragments_rejected > 0,
        "the refused message was not counted"
    );
    let due = side.assoc.poll_timeout().expect("no timer");
    assert!(due <= now + SECOND, "later than one interval");
    side.assoc.handle_timeout(due);
    side.drain_events();
}

/// A client association that has sent its first `ClientHello`, and the
/// `ClientHello` itself.
fn fresh_client() -> (Side, ClientHello, Instant) {
    let now = Instant::now();
    let config = AssociationConfig::new(
        DtlsRole::Client,
        identity(),
        vec![identity().fingerprint().clone()],
    );
    let mut client = Side::new(config, now);
    let sent = client.drain_transmit();
    assert_eq!(sent.len(), 1);
    let hello = messages(&sent[0]).remove(0);
    assert_eq!(hello.msg_type, HT_CLIENT_HELLO);
    (client, ClientHello::parse(&hello.body).unwrap(), now)
}

/// A server association that has seen nothing yet.
fn fresh_server() -> (Side, Instant) {
    let now = Instant::now();
    let config = AssociationConfig::new(
        DtlsRole::Server,
        identity(),
        vec![identity().fingerprint().clone()],
    );
    (Side::new(config, now), now)
}

/// A `ServerHello` body inside the profile.
fn server_hello_body() -> Vec<u8> {
    let mut extensions = profile_extensions();
    extensions.supported_groups = None;
    extensions.signature_algorithms = None;
    let mut body = Vec::new();
    ServerHello {
        version: DTLS_1_2_VERSION,
        random: [7; 32],
        session_id: Vec::new(),
        cipher_suite: SUITE,
        compression_method: 0,
        extensions,
    }
    .encode(&mut body)
    .unwrap();
    body
}

fn fingerprint_of(cert: &[u8]) -> CertificateFingerprint {
    CertificateFingerprint::from_certificate_sha384(cert)
}

fn certificate_body(chain: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = Vec::new();
    CertificateMsg { chain }.encode(&mut body).unwrap();
    body
}

// =============================================================================
// The profile as it appears on the wire (CNSA 2.0; plan §2.2)
// =============================================================================

/// Task item 5: a pion client picks its `CertificateVerify` scheme from the
/// server's `CertificateRequest` list, so the list must hold 0x0503 and
/// nothing else, or a peer could answer with ECDSA/SHA-256.
#[test]
fn server_certificate_request_offers_only_ecdsa_p384_sha384() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();
    let request = find_message(&lo.log, Dir::ServerToClient, HT_CERTIFICATE_REQUEST)
        .expect("the server role must always request a client certificate");
    let request = CertificateRequest::parse(&request.body).unwrap();
    assert_eq!(request.signature_algorithms, vec![SCHEME_P384_SHA384]);
    assert_eq!(request.certificate_types, vec![64], "ecdsa_sign only");
    assert_eq!(request.certificate_authorities, Vec::<u8>::new());
}

#[test]
fn client_hello_offers_only_the_cnsa_profile() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();
    let hellos: Vec<_> = lo
        .log
        .iter()
        .filter(|(dir, _)| *dir == Dir::ClientToServer)
        .flat_map(|(_, datagram)| messages(datagram))
        .filter(|m| m.msg_type == HT_CLIENT_HELLO)
        .collect();
    assert_eq!(hellos.len(), 2, "one without and one with the cookie");
    for hello in hellos {
        let hello = ClientHello::parse(&hello.body).unwrap();
        assert_eq!(hello.version, DTLS_1_2_VERSION);
        assert_eq!(hello.cipher_suites, vec![SUITE], "no other suite, no SCSV");
        assert_eq!(hello.compression_methods, vec![0]);
        assert!(hello.session_id.is_empty(), "no resumption");
        let ext = hello.extensions;
        assert_eq!(ext.supported_groups, Some(vec![GROUP_P384]));
        assert_eq!(ext.signature_algorithms, Some(vec![SCHEME_P384_SHA384]));
        assert_eq!(ext.ec_point_formats, Some(vec![0]));
        assert_eq!(
            ext.use_srtp,
            Some(UseSrtp {
                profiles: vec![SRTP_AES256_GCM],
                mki: Vec::new()
            })
        );
        assert!(ext.extended_master_secret);
        assert_eq!(ext.renegotiation_info, Some(Vec::new()));
    }
}

#[test]
fn server_flight_and_client_proof_use_only_the_cnsa_profile() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();

    let hello = find_message(&lo.log, Dir::ServerToClient, HT_SERVER_HELLO).unwrap();
    let hello = ServerHello::parse(&hello.body).unwrap();
    assert_eq!(hello.version, DTLS_1_2_VERSION);
    assert_eq!(hello.cipher_suite, SUITE);
    assert_eq!(hello.compression_method, 0);
    assert_eq!(hello.session_id, Vec::<u8>::new(), "no session id");
    assert!(hello.extensions.extended_master_secret);
    assert_eq!(
        hello.extensions.use_srtp,
        Some(UseSrtp {
            profiles: vec![SRTP_AES256_GCM],
            mki: Vec::new()
        })
    );

    let exchange = find_message(&lo.log, Dir::ServerToClient, HT_SERVER_KEY_EXCHANGE).unwrap();
    let exchange = ServerKeyExchange::parse(&exchange.body).unwrap();
    assert_eq!(exchange.params.named_curve, GROUP_P384);
    assert_eq!(exchange.params.public.len(), 97, "uncompressed P-384 point");
    assert_eq!(exchange.signed.scheme, SCHEME_P384_SHA384);

    let verify = find_message(&lo.log, Dir::ClientToServer, HT_CERTIFICATE_VERIFY).unwrap();
    assert_eq!(&verify.body[..2], &SCHEME_P384_SHA384.to_be_bytes());

    // Every record on the wire says DTLS 1.2, and only epochs 0 and 1 exist.
    for (_, datagram) in &lo.log {
        for record in records(datagram) {
            assert_eq!(record.version, DTLS_1_2_VERSION);
            assert!(record.epoch <= 1);
            // Nothing but Finished travels protected, and Finished never
            // travels in the clear.
            if record.epoch == 1 {
                assert_eq!(record.content_type, ContentType::Handshake);
            } else if let Some(message) = record.message() {
                assert_ne!(message.msg_type, HT_FINISHED);
            }
        }
    }
}

/// RFC 6347 §4.2.1: the cookie exchange must not amplify, and the
/// `HelloVerifyRequest` carries version 1.0 or 1.2.
#[test]
fn hello_verify_request_is_smaller_than_the_client_hello() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    let hello = &lo
        .log
        .iter()
        .find(|(d, _)| *d == Dir::ClientToServer)
        .unwrap()
        .1;
    let request = &lo
        .log
        .iter()
        .find(|(d, _)| *d == Dir::ServerToClient)
        .unwrap()
        .1;
    assert!(request.len() < hello.len());
    let request = messages(request).remove(0);
    assert_eq!(request.msg_type, HT_HELLO_VERIFY_REQUEST);
    let request = HelloVerifyRequest::parse(&request.body).unwrap();
    assert!([DTLS_1_0_VERSION, DTLS_1_2_VERSION].contains(&request.version));
    assert_eq!(request.cookie.len(), 32);
}

// =============================================================================
// Parameters outside the profile: no fallback
// =============================================================================

/// A client whose offer lacks one mandatory parameter. The server refuses
/// with the stated cause and alert; the client sees only the alert.
#[test]
fn server_refuses_client_offers_outside_the_profile() {
    type Edit = fn(&mut ClientHello);
    let unsupported = FailureCause::UnsupportedParameters;
    let cases: [(&str, Edit, FailureCause, u8); 12] = [
        (
            "only ECDHE-ECDSA-AES128-GCM-SHA256",
            |h| h.cipher_suites = vec![0xC02B],
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "RSA, CHACHA20 and TLS 1.3 suites but not 0xC02C",
            |h| h.cipher_suites = vec![0xC030, 0xCCA9, 0x1302, 0x00FF],
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "DTLS 1.0",
            |h| h.version = DTLS_1_0_VERSION,
            unsupported,
            alert::PROTOCOL_VERSION,
        ),
        (
            "TLS 1.2 version number",
            |h| h.version = 0x0303,
            unsupported,
            alert::PROTOCOL_VERSION,
        ),
        (
            "only secp256r1",
            |h| h.extensions.supported_groups = Some(vec![23]),
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "no supported_groups",
            |h| h.extensions.supported_groups = None,
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "only ecdsa_secp256r1_sha256",
            |h| h.extensions.signature_algorithms = Some(vec![SCHEME_P256_SHA256]),
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "RSA and Ed25519 schemes only",
            |h| h.extensions.signature_algorithms = Some(vec![0x0804, 0x0401, 0x0807]),
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "no signature_algorithms",
            |h| h.extensions.signature_algorithms = None,
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "only compressed points",
            |h| h.extensions.ec_point_formats = Some(vec![1]),
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "only DEFLATE compression",
            |h| h.compression_methods = vec![1],
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "non-empty renegotiation_info on an initial handshake",
            |h| h.extensions.renegotiation_info = Some(vec![1, 2, 3]),
            FailureCause::ProtocolViolation,
            alert::HANDSHAKE_FAILURE,
        ),
    ];
    for (name, edit, cause, description) in cases {
        let mut lo = Loopback::new();
        lo.run(rewrite_client_hello(edit));
        assert_eq!(lo.server.failed, Some(cause), "{name}");
        assert_eq!(
            lo.client.failed,
            Some(FailureCause::PeerAlert(description)),
            "{name}"
        );
        assert_failed(&lo, FailureCause::PeerAlert(description), cause);
        // The server never got as far as its certificate flight.
        assert!(
            find_message(&lo.log, Dir::ServerToClient, HT_SERVER_HELLO).is_none(),
            "{name}: ServerHello sent"
        );
    }
}

/// A server that selects something outside the profile.
#[test]
fn client_refuses_server_selections_outside_the_profile() {
    type Edit = fn(&mut ServerHello);
    let unsupported = FailureCause::UnsupportedParameters;
    let cases: [(&str, Edit, FailureCause, u8); 8] = [
        (
            "AES-128-GCM suite",
            |h| h.cipher_suite = 0xC02B,
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "RSA suite",
            |h| h.cipher_suite = 0xC030,
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "DTLS 1.0",
            |h| h.version = DTLS_1_0_VERSION,
            unsupported,
            alert::PROTOCOL_VERSION,
        ),
        (
            "DTLS 1.3 version number",
            |h| h.version = 0xFEFC,
            unsupported,
            alert::PROTOCOL_VERSION,
        ),
        (
            "DEFLATE compression",
            |h| h.compression_method = 1,
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "compressed points only",
            |h| h.extensions.ec_point_formats = Some(vec![2]),
            unsupported,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "non-empty renegotiation_info",
            |h| h.extensions.renegotiation_info = Some(vec![0; 12]),
            FailureCause::ProtocolViolation,
            alert::HANDSHAKE_FAILURE,
        ),
        (
            "no extensions at all",
            |h| h.extensions = proto_dtls::wire::extensions::Extensions::default(),
            FailureCause::NoExtendedMasterSecret,
            alert::HANDSHAKE_FAILURE,
        ),
    ];
    for (name, edit, cause, description) in cases {
        let mut lo = Loopback::new();
        lo.run(rewrite_server_hello(edit));
        assert_eq!(lo.client.failed, Some(cause), "{name}");
        assert_failed(&lo, cause, FailureCause::PeerAlert(description));
        // The client stopped at the ServerHello: no certificate, no key
        // exchange, no Finished left it.
        assert!(
            find_message(&lo.log, Dir::ClientToServer, HT_CLIENT_KEY_EXCHANGE).is_none(),
            "{name}: ClientKeyExchange sent"
        );
    }
}

/// `HelloVerifyRequest` may say 1.0 or 1.2 (RFC 6347 §4.2.1), nothing else.
#[test]
fn client_refuses_hello_verify_request_with_a_foreign_version() {
    let mut lo = Loopback::new();
    lo.run(rewriting(
        Dir::ServerToClient,
        HT_HELLO_VERIFY_REQUEST,
        |body| {
            let mut request = HelloVerifyRequest::parse(body).unwrap();
            request.version = 0x0303;
            let mut out = Vec::new();
            request.encode(&mut out).unwrap();
            Some((HT_HELLO_VERIFY_REQUEST, out))
        },
    ));
    assert_side_failed(&lo.client, FailureCause::UnsupportedParameters);
    lo.assert_no_keys();
}

/// The server signs its ECDHE share with something other than
/// `ecdsa_secp384r1_sha384`. 0x0403 is what stock pion does with a P-384
/// key (impl-notes): it must be refused, not verified.
#[test]
fn client_refuses_server_key_exchange_signature_schemes_other_than_0x0503() {
    for scheme in [SCHEME_P256_SHA256, 0x0603, 0x0804, 0x0401, 0x0807, 0x0203] {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ServerToClient,
            HT_SERVER_KEY_EXCHANGE,
            move |body| {
                let mut exchange = ServerKeyExchange::parse(body).unwrap();
                exchange.signed.scheme = scheme;
                let mut out = Vec::new();
                exchange.encode(&mut out).unwrap();
                Some((HT_SERVER_KEY_EXCHANGE, out))
            },
        ));
        assert_failed(
            &lo,
            FailureCause::UnsupportedParameters,
            FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE),
        );
    }
}

/// The server's ECDHE share is on another curve, or is not a P-384 point.
#[test]
fn client_refuses_server_key_exchange_on_another_curve() {
    type Edit = fn(&mut ServerKeyExchange);
    let cases: [(&str, Edit); 4] = [
        ("secp256r1 with a P-256 sized point", |e| {
            e.params.named_curve = 23;
            e.params.public = vec![4; 65];
        }),
        ("x25519", |e| {
            e.params.named_curve = 29;
            e.params.public = vec![9; 32];
        }),
        ("secp384r1 id with a P-256 sized point", |e| {
            e.params.public.truncate(65);
        }),
        ("secp521r1 id with the P-384 point", |e| {
            e.params.named_curve = 25;
        }),
    ];
    for (name, edit) in cases {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ServerToClient,
            HT_SERVER_KEY_EXCHANGE,
            move |body| {
                let mut exchange = ServerKeyExchange::parse(body).unwrap();
                edit(&mut exchange);
                let mut out = Vec::new();
                exchange.encode(&mut out).unwrap();
                Some((HT_SERVER_KEY_EXCHANGE, out))
            },
        ));
        assert_eq!(
            lo.client.failed,
            Some(FailureCause::UnsupportedParameters),
            "{name}"
        );
        lo.assert_no_keys();
    }
}

/// The client proves possession with a scheme other than 0x0503.
#[test]
fn server_refuses_certificate_verify_schemes_other_than_0x0503() {
    for scheme in [SCHEME_P256_SHA256, 0x0603, 0x0804] {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ClientToServer,
            HT_CERTIFICATE_VERIFY,
            move |body| {
                let mut out = body.to_vec();
                out[..2].copy_from_slice(&scheme.to_be_bytes());
                Some((HT_CERTIFICATE_VERIFY, out))
            },
        ));
        assert_failed(
            &lo,
            FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE),
            FailureCause::UnsupportedParameters,
        );
    }
}

/// A `CertificateRequest` we cannot satisfy inside the profile.
#[test]
fn client_refuses_certificate_requests_it_cannot_answer_with_0x0503() {
    type Edit = fn(&mut CertificateRequest);
    let cases: [(&str, Edit); 3] = [
        ("only ecdsa_secp256r1_sha256", |r| {
            r.signature_algorithms = vec![SCHEME_P256_SHA256];
        }),
        ("only RSA schemes", |r| {
            r.signature_algorithms = vec![0x0401, 0x0804];
        }),
        ("only rsa_sign certificates", |r| {
            r.certificate_types = vec![1];
        }),
    ];
    for (name, edit) in cases {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ServerToClient,
            HT_CERTIFICATE_REQUEST,
            move |body| {
                let mut request = CertificateRequest::parse(body).unwrap();
                edit(&mut request);
                let mut out = Vec::new();
                request.encode(&mut out).unwrap();
                Some((HT_CERTIFICATE_REQUEST, out))
            },
        ));
        assert_eq!(
            lo.client.failed,
            Some(FailureCause::UnsupportedParameters),
            "{name}"
        );
        lo.assert_no_keys();
        assert!(
            find_message(&lo.log, Dir::ClientToServer, HT_CERTIFICATE_VERIFY).is_none(),
            "{name}: the client signed anyway"
        );
    }
}

/// A server that lists SHA-256 ahead of SHA-384 still gets a 0x0503
/// `CertificateVerify` from us: the client never signs with anything else.
#[test]
fn client_signs_with_0x0503_whatever_else_the_server_lists() {
    let (client, puppet, _) = handshake_with_puppet_server(|p| {
        p.script.certificate_request_schemes = vec![SCHEME_P256_SHA256, 0x0804, SCHEME_P384_SHA384];
    });
    assert_puppet_connected(&client, &puppet);
    let verify = puppet
        .seen
        .iter()
        .find(|m| m.msg_type == HT_CERTIFICATE_VERIFY)
        .expect("CertificateVerify");
    assert_eq!(&verify.body[..2], &SCHEME_P384_SHA384.to_be_bytes());
}

// =============================================================================
// use_srtp (RFC 5764 §4.1)
// =============================================================================

#[test]
fn server_fails_clients_without_the_aead_256_srtp_profile() {
    type Edit = fn(&mut ClientHello);
    let cases: [(&str, Edit); 4] = [
        ("no use_srtp extension", |h| h.extensions.use_srtp = None),
        ("only SRTP_AES128_CM_HMAC_SHA1_80", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = vec![SRTP_AES128_SHA1_80];
        }),
        ("only SRTP_AEAD_AES_128_GCM", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = vec![0x0007];
        }),
        ("empty profile list", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = Vec::new();
        }),
    ];
    for (name, edit) in cases {
        let mut lo = Loopback::new();
        lo.run(rewrite_client_hello(edit));
        assert_eq!(
            lo.server.failed,
            Some(FailureCause::NoSrtpProfile),
            "{name}"
        );
        assert_failed(
            &lo,
            FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE),
            FailureCause::NoSrtpProfile,
        );
    }
}

#[test]
fn client_fails_servers_without_the_aead_256_srtp_profile() {
    type Edit = fn(&mut ServerHello);
    let cases: [(&str, Edit); 5] = [
        ("no use_srtp extension", |h| h.extensions.use_srtp = None),
        ("SRTP_AES128_CM_HMAC_SHA1_80 selected", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = vec![SRTP_AES128_SHA1_80];
        }),
        ("SRTP_AEAD_AES_128_GCM selected", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = vec![0x0007];
        }),
        ("two profiles selected", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles =
                vec![SRTP_AES256_GCM, SRTP_AES128_SHA1_80];
        }),
        ("empty selection", |h| {
            h.extensions.use_srtp.as_mut().unwrap().profiles = Vec::new();
        }),
    ];
    for (name, edit) in cases {
        let mut lo = Loopback::new();
        lo.run(rewrite_server_hello(edit));
        assert_eq!(
            lo.client.failed,
            Some(FailureCause::NoSrtpProfile),
            "{name}"
        );
        assert_failed(
            &lo,
            FailureCause::NoSrtpProfile,
            FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE),
        );
    }
}

/// RFC 5764 §4.1.3: an MKI offered by the client is not a reason to fail.
/// The server ignores it and answers with an empty MKI, and the handshake
/// completes.
#[test]
fn server_ignores_an_offered_mki_and_answers_with_an_empty_one() {
    for mki in [vec![0xAB], vec![1, 2, 3, 4], vec![0x5A; 255]] {
        let (server, puppet, _) = handshake_with_puppet_client(|p| p.script.hello_mki = mki);
        assert_puppet_connected(&server, &puppet);
        let hello = puppet
            .seen
            .iter()
            .find(|m| m.msg_type == HT_SERVER_HELLO)
            .unwrap();
        let use_srtp = ServerHello::parse(&hello.body)
            .unwrap()
            .extensions
            .use_srtp
            .unwrap();
        assert_eq!(use_srtp.profiles, vec![SRTP_AES256_GCM]);
        assert!(use_srtp.mki.is_empty(), "the server echoed an MKI");
    }
}

/// RFC 5764 §4.1.3: the client offered no MKI, so a `ServerHello` that
/// carries one is refused with `illegal_parameter` (47), whatever the
/// profile next to it.
#[test]
fn client_refuses_a_server_hello_with_an_mki_with_illegal_parameter() {
    for mki in [vec![0xAB], vec![1, 2, 3, 4]] {
        let (mut client, mut puppet, now) =
            handshake_with_puppet_server(|p| p.script.hello_mki = mki);
        expire_retransmission_timer(&mut client, now);
        puppet.absorb_from(&mut client);
        assert_side_failed(&client, FailureCause::NoSrtpProfile);
        assert_eq!(
            puppet.alerts,
            vec![(alert::LEVEL_FATAL, alert::ILLEGAL_PARAMETER)]
        );
        assert_eq!(puppet.peer_finished_ok, None, "the client went on");
    }
}

/// RFC 5246 §7.4.1.4: a `ServerHello` extension the client did not offer
/// MUST end the handshake with `unsupported_extension` (110). The profile's
/// `ClientHello` offers every extension type the codec knows, so any other
/// type was not offered.
#[test]
fn client_refuses_a_server_hello_extension_it_did_not_offer() {
    // server_name, status_request, ALPN, session_ticket, a private type.
    for ext_type in [0u16, 5, 16, 35, 0xFDE8] {
        let (mut client, mut puppet, now) =
            handshake_with_puppet_server(|p| p.script.hello_unknown_extension = Some(ext_type));
        expire_retransmission_timer(&mut client, now);
        puppet.absorb_from(&mut client);
        assert_side_failed(&client, FailureCause::ProtocolViolation);
        assert_eq!(
            puppet.alerts,
            vec![(alert::LEVEL_FATAL, alert::UNSUPPORTED_EXTENSION)],
            "extension {ext_type}"
        );
        assert_eq!(alert::UNSUPPORTED_EXTENSION, 110);
        let types: Vec<u8> = puppet.seen.iter().map(|m| m.msg_type).collect();
        assert_eq!(types, vec![HT_CLIENT_HELLO], "extension {ext_type}");
    }
}

/// The other direction stays lenient (RFC 5246 §7.4.1.4: a server ignores
/// `ClientHello` extensions it does not understand).
#[test]
fn server_ignores_client_hello_extensions_it_does_not_know() {
    for ext_type in [0u16, 5, 16, 35, 0xFDE8] {
        let (server, puppet, _) =
            handshake_with_puppet_client(|p| p.script.hello_unknown_extension = Some(ext_type));
        assert_puppet_connected(&server, &puppet);
    }
}

/// A client that offers our profile among others is served, and gets
/// exactly our profile back.
#[test]
fn server_selects_only_aead_256_from_a_longer_offer() {
    let mut lo = Loopback::new();
    lo.run(rewrite_client_hello(|h| {
        h.extensions.use_srtp.as_mut().unwrap().profiles =
            vec![SRTP_AES128_SHA1_80, 0x0007, SRTP_AES256_GCM];
        h.cipher_suites = vec![0xC02B, SUITE, 0x00FF];
        h.extensions.supported_groups = Some(vec![29, 23, GROUP_P384]);
        h.extensions.signature_algorithms = Some(vec![SCHEME_P256_SHA256, SCHEME_P384_SHA384]);
    }));
    // The rewritten hello is not what the client hashed, so Finished cannot
    // verify; what matters here is what the server answered.
    lo.assert_no_keys();
    let hello = find_message(&lo.log, Dir::ServerToClient, HT_SERVER_HELLO).unwrap();
    let hello = ServerHello::parse(&hello.body).unwrap();
    assert_eq!(hello.cipher_suite, SUITE);
    assert_eq!(
        hello.extensions.use_srtp.unwrap().profiles,
        vec![SRTP_AES256_GCM]
    );
    let exchange = find_message(&lo.log, Dir::ServerToClient, HT_SERVER_KEY_EXCHANGE).unwrap();
    let exchange = ServerKeyExchange::parse(&exchange.body).unwrap();
    assert_eq!(exchange.signed.scheme, SCHEME_P384_SHA384);
    assert_eq!(exchange.params.named_curve, GROUP_P384);
}

// =============================================================================
// Proof of possession: ServerKeyExchange signature, CertificateVerify
// =============================================================================

#[test]
fn client_fails_on_a_bad_server_key_exchange_signature() {
    type Edit = fn(&[u8]) -> Vec<u8>;
    let cases: [(&str, Edit, u8); 6] = [
        (
            "last signature byte flipped",
            |body| {
                let mut out = body.to_vec();
                *out.last_mut().unwrap() ^= 0x01;
                out
            },
            alert::DECRYPT_ERROR,
        ),
        (
            "ECDHE share altered after signing",
            |body| {
                let mut out = body.to_vec();
                // curve_type(1) named_curve(2) length(1) 0x04 X...: flip a
                // byte of X.
                out[10] ^= 0x80;
                out
            },
            alert::DECRYPT_ERROR,
        ),
        (
            "signature missing",
            |body| {
                let exchange = ServerKeyExchange::parse(body).unwrap();
                let mut out = Vec::new();
                exchange.params.encode(&mut out).unwrap();
                out
            },
            alert::DECODE_ERROR,
        ),
        (
            "signature truncated",
            |body| body[..body.len() - 20].to_vec(),
            alert::DECODE_ERROR,
        ),
        (
            "empty signature",
            |body| {
                let exchange = ServerKeyExchange::parse(body).unwrap();
                let mut out = Vec::new();
                exchange.params.encode(&mut out).unwrap();
                out.extend_from_slice(&SCHEME_P384_SHA384.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                out
            },
            alert::DECODE_ERROR,
        ),
        (
            "bytes after the signature",
            |body| {
                let mut out = body.to_vec();
                out.push(0);
                out
            },
            alert::DECODE_ERROR,
        ),
    ];
    for (name, edit, description) in cases {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ServerToClient,
            HT_SERVER_KEY_EXCHANGE,
            move |body| Some((HT_SERVER_KEY_EXCHANGE, edit(body))),
        ));
        assert_eq!(lo.client.failed, Some(FailureCause::BadSignature), "{name}");
        assert_failed(
            &lo,
            FailureCause::BadSignature,
            FailureCause::PeerAlert(description),
        );
        assert!(
            find_message(&lo.log, Dir::ClientToServer, HT_CLIENT_KEY_EXCHANGE).is_none(),
            "{name}: the client went on to the key exchange"
        );
    }
}

/// The signature covers both randoms (RFC 8422 §5.4): a `ServerHello`
/// altered in flight is caught at the signature, before any key agreement.
#[test]
fn client_fails_when_the_signed_server_random_was_altered() {
    let mut lo = Loopback::new();
    lo.run(rewrite_server_hello(|h| h.random[0] ^= 0xFF));
    assert_failed(
        &lo,
        FailureCause::BadSignature,
        FailureCause::PeerAlert(alert::DECRYPT_ERROR),
    );
}

/// A server that presents the certificate we expect but does not hold its
/// key: the fingerprint matches, the signature cannot.
#[test]
fn client_fails_a_server_without_the_certificate_key() {
    let (mut client, mut puppet, now) = handshake_with_puppet_server(|p| {
        p.key = identity_parts().1;
    });
    // SEC-010: reported within one retransmission interval, not at once.
    assert!(puppet.alerts.is_empty(), "alerted at once");
    expire_retransmission_timer(&mut client, now);
    puppet.absorb_from(&mut client);
    assert_side_failed(&client, FailureCause::BadSignature);
    assert!(
        puppet
            .alerts
            .contains(&(alert::LEVEL_FATAL, alert::DECRYPT_ERROR))
    );
    assert!(puppet.master.is_none(), "the client sent a key exchange");
}

#[test]
fn server_fails_on_a_bad_certificate_verify() {
    type Edit = fn(&[u8]) -> (u8, Vec<u8>);
    let cases: [(&str, Edit, FailureCause, u8); 5] = [
        (
            "last signature byte flipped",
            |body| {
                let mut out = body.to_vec();
                *out.last_mut().unwrap() ^= 0x01;
                (HT_CERTIFICATE_VERIFY, out)
            },
            FailureCause::BadSignature,
            alert::DECRYPT_ERROR,
        ),
        (
            "signature truncated",
            |body| (HT_CERTIFICATE_VERIFY, body[..body.len() - 9].to_vec()),
            FailureCause::BadSignature,
            alert::DECODE_ERROR,
        ),
        (
            "empty body",
            |_| (HT_CERTIFICATE_VERIFY, Vec::new()),
            FailureCause::BadSignature,
            alert::DECODE_ERROR,
        ),
        (
            "bytes after the signature",
            |body| {
                let mut out = body.to_vec();
                out.push(0);
                (HT_CERTIFICATE_VERIFY, out)
            },
            FailureCause::BadSignature,
            alert::DECODE_ERROR,
        ),
        (
            "another message in the CertificateVerify slot",
            |body| (HT_CLIENT_KEY_EXCHANGE, body.to_vec()),
            FailureCause::BadSignature,
            alert::HANDSHAKE_FAILURE,
        ),
    ];
    for (name, edit, cause, description) in cases {
        let mut lo = Loopback::new();
        lo.run(rewriting(
            Dir::ClientToServer,
            HT_CERTIFICATE_VERIFY,
            move |body| Some(edit(body)),
        ));
        assert_eq!(lo.server.failed, Some(cause), "{name}");
        assert_failed(&lo, FailureCause::PeerAlert(description), cause);
    }
}

/// A client that presents the certificate we expect but signs with another
/// key.
#[test]
fn server_fails_a_client_without_the_certificate_key() {
    let (mut server, mut puppet, now) = handshake_with_puppet_client(|p| {
        p.script.certificate_verify_key = Some(identity_parts().1);
    });
    // SEC-010: reported within one retransmission interval, not at once.
    assert!(puppet.alerts.is_empty(), "alerted at once");
    expire_retransmission_timer(&mut server, now);
    puppet.absorb_from(&mut server);
    assert_side_failed(&server, FailureCause::BadSignature);
    assert!(
        puppet
            .alerts
            .contains(&(alert::LEVEL_FATAL, alert::DECRYPT_ERROR))
    );
    assert_eq!(puppet.peer_finished_ok, None, "the server sent a Finished");
}

/// impl-notes "Omitted CertificateVerify": a client that simply leaves the
/// message out (keeping its sequence slot) cannot be told from loss, so the
/// server waits and the handshake dies at the budget. What matters: the
/// client is never treated as authenticated.
#[test]
fn server_never_completes_without_certificate_verify() {
    let mut lo = Loopback::new();
    lo.run(rewriting(
        Dir::ClientToServer,
        HT_CERTIFICATE_VERIFY,
        |_| None,
    ));
    assert_failed(&lo, FailureCause::Timeout, FailureCause::Timeout);
    assert_eq!(lo.elapsed(), Duration::from_secs(10));
}

/// A client that skips `Certificate` and `CertificateVerify` altogether and
/// goes straight to the key exchange.
#[test]
fn server_fails_a_client_that_skips_its_certificate() {
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    let skipped = puppet.handshake(0, HT_CLIENT_KEY_EXCHANGE, &[97; 98]);
    server.assoc.handle_datagram(&skipped, now);
    // SEC-010: within one retransmission interval, not at once.
    expire_retransmission_timer(&mut server, now);
    assert_side_failed(&server, FailureCause::BadCertificate);
    puppet.absorb_from(&mut server);
    assert_eq!(
        puppet.alerts,
        vec![(alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE)]
    );
}

#[test]
fn server_fails_a_client_with_an_empty_certificate_list() {
    let mut lo = Loopback::new();
    lo.run(rewriting(Dir::ClientToServer, HT_CERTIFICATE, |_| {
        Some((HT_CERTIFICATE, certificate_body(Vec::new())))
    }));
    assert_failed(
        &lo,
        FailureCause::PeerAlert(alert::BAD_CERTIFICATE),
        FailureCause::BadCertificate,
    );
    assert!(lo.server.assoc.presented_fingerprint().is_none());
}

// =============================================================================
// Finished
// =============================================================================

#[test]
fn puppet_peers_complete_in_both_roles() {
    let (client, puppet, _) = handshake_with_puppet_server(|_| {});
    assert_puppet_connected(&client, &puppet);
    assert!(client.assoc.client_certificate_requested());
    let (server, puppet, _) = handshake_with_puppet_client(|_| {});
    assert_puppet_connected(&server, &puppet);
    assert!(server.assoc.client_certificate_requested());
}

/// An authenticated server whose `Finished` is wrong: everything before it
/// verified, and still no key leaves the client.
#[test]
fn client_fails_on_server_finished_mismatch() {
    let (client, puppet, _) = handshake_with_puppet_server(|p| p.script.corrupt_finished = true);
    assert_eq!(
        puppet.peer_finished_ok,
        Some(true),
        "the client side was fine"
    );
    assert_side_failed(&client, FailureCause::FinishedMismatch);
    assert!(
        puppet
            .alerts
            .contains(&(alert::LEVEL_FATAL, alert::DECRYPT_ERROR))
    );
}

#[test]
fn server_fails_on_client_finished_mismatch() {
    let (server, puppet, _) = handshake_with_puppet_client(|p| p.script.corrupt_finished = true);
    assert_side_failed(&server, FailureCause::FinishedMismatch);
    assert_eq!(
        puppet.alerts,
        vec![(alert::LEVEL_FATAL, alert::DECRYPT_ERROR)]
    );
    assert_eq!(
        puppet.peer_finished_ok, None,
        "the server sent its Finished"
    );
}

/// A `Finished` in the clear (epoch 0) is never accepted, whatever it says:
/// it is thrown away, and a peer that sends nothing better has failed the
/// handshake when the retransmission timer next expires.
#[test]
fn plaintext_finished_is_never_accepted() {
    // Client waiting for the first server message.
    let (mut client, _, now) = fresh_client();
    client
        .assoc
        .handle_datagram(&message_record(0, HT_FINISHED, 0, &[0; 12]), now);
    expire_retransmission_timer(&mut client, now);
    assert_side_failed(&client, FailureCause::ProtocolViolation);

    // Server waiting for the client certificate.
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    let finished = puppet.handshake(0, HT_FINISHED, &[0; 12]);
    server.assoc.handle_datagram(&finished, now);
    expire_retransmission_timer(&mut server, now);
    assert_side_failed(&server, FailureCause::ProtocolViolation);
}

// =============================================================================
// Peer certificate: fingerprint first, then P-384 only
// =============================================================================

/// The fingerprint matches (the SDP named this certificate) but its key is
/// not ECDSA P-384.
#[test]
fn client_fails_a_server_certificate_without_a_p384_key() {
    let foreign = [
        ("P-256", foreign_certificate(&rcgen::PKCS_ECDSA_P256_SHA256)),
        ("Ed25519", foreign_certificate(&rcgen::PKCS_ED25519)),
        ("not DER at all", vec![0x30, 0x82, 0xFF, 0xFF, 1, 2, 3]),
        ("one byte", vec![0x30]),
    ];
    for (name, cert) in foreign {
        let mut lo = Loopback::with(|client, _| {
            client.peer_fingerprints = vec![fingerprint_of(&cert)];
        });
        let body = certificate_body(vec![cert.clone()]);
        lo.run(rewriting(Dir::ServerToClient, HT_CERTIFICATE, move |_| {
            Some((HT_CERTIFICATE, body.clone()))
        }));
        assert_eq!(
            lo.client.failed,
            Some(FailureCause::BadCertificate),
            "{name}"
        );
        assert_failed(
            &lo,
            FailureCause::BadCertificate,
            FailureCause::PeerAlert(alert::BAD_CERTIFICATE),
        );
        assert_eq!(
            lo.client.assoc.presented_fingerprint(),
            Some(&fingerprint_of(&cert))
        );
    }
}

#[test]
fn server_fails_a_client_certificate_without_a_p384_key() {
    let foreign = [
        ("P-256", foreign_certificate(&rcgen::PKCS_ECDSA_P256_SHA256)),
        ("Ed25519", foreign_certificate(&rcgen::PKCS_ED25519)),
        ("not DER at all", vec![0xFF; 40]),
    ];
    for (name, cert) in foreign {
        let mut lo = Loopback::with(|_, server| {
            server.peer_fingerprints = vec![fingerprint_of(&cert)];
        });
        let body = certificate_body(vec![cert]);
        lo.run(rewriting(Dir::ClientToServer, HT_CERTIFICATE, move |_| {
            Some((HT_CERTIFICATE, body.clone()))
        }));
        assert_eq!(
            lo.server.failed,
            Some(FailureCause::BadCertificate),
            "{name}"
        );
        assert_failed(
            &lo,
            FailureCause::PeerAlert(alert::BAD_CERTIFICATE),
            FailureCause::BadCertificate,
        );
    }
}

/// Only the leaf is compared (RFC 8122 §5): the expected certificate
/// further down the chain does not authenticate an unknown leaf. Both roles.
#[test]
fn fingerprint_must_match_the_leaf_not_a_later_chain_entry() {
    let stranger = identity_parts().0;

    let mut lo = Loopback::new();
    let stranger_first = stranger.clone();
    lo.run(rewriting(
        Dir::ServerToClient,
        HT_CERTIFICATE,
        move |body| {
            let mut chain = CertificateMsg::parse(body).unwrap().chain;
            chain.insert(0, stranger_first.clone());
            Some((HT_CERTIFICATE, certificate_body(chain)))
        },
    ));
    assert_failed(
        &lo,
        FailureCause::FingerprintMismatch,
        FailureCause::PeerAlert(alert::BAD_CERTIFICATE),
    );

    let mut lo = Loopback::new();
    lo.run(rewriting(
        Dir::ClientToServer,
        HT_CERTIFICATE,
        move |body| {
            let mut chain = CertificateMsg::parse(body).unwrap().chain;
            chain.insert(0, stranger.clone());
            Some((HT_CERTIFICATE, certificate_body(chain)))
        },
    ));
    assert_failed(
        &lo,
        FailureCause::PeerAlert(alert::BAD_CERTIFICATE),
        FailureCause::FingerprintMismatch,
    );
}

/// Fingerprint mismatch in both roles when the peer holds a perfectly good
/// identity of its own (an active attacker with a certificate the SDP did
/// not name). Nothing after the certificate is processed, and the failure
/// is reported within one retransmission interval (SEC-010: the
/// certificate is in the clear, so not at once).
#[test]
fn fingerprint_mismatch_stops_both_roles_before_any_key_agreement() {
    let (mut client, mut puppet, now) = handshake_with_puppet_server(|p| {
        (p.cert, p.key) = identity_parts();
    });
    assert!(puppet.alerts.is_empty(), "alerted at once");
    expire_retransmission_timer(&mut client, now);
    puppet.absorb_from(&mut client);
    assert_side_failed(&client, FailureCause::FingerprintMismatch);
    assert_eq!(
        puppet.alerts,
        vec![(alert::LEVEL_FATAL, alert::BAD_CERTIFICATE)]
    );
    assert!(puppet.seen.iter().all(|m| m.msg_type == HT_CLIENT_HELLO));

    let (mut server, mut puppet, now) = handshake_with_puppet_client(|p| {
        (p.cert, p.key) = identity_parts();
    });
    assert!(puppet.alerts.is_empty(), "alerted at once");
    expire_retransmission_timer(&mut server, now);
    puppet.absorb_from(&mut server);
    assert_side_failed(&server, FailureCause::FingerprintMismatch);
    assert_eq!(
        puppet.alerts,
        vec![(alert::LEVEL_FATAL, alert::BAD_CERTIFICATE)]
    );
    assert_eq!(puppet.peer_finished_ok, None);
}

// =============================================================================
// Records after the handshake: replay, window, tag, epoch, size
// =============================================================================

/// A connected association and a puppet peer holding the same keys, for
/// both roles of the association under test.
fn connected_pairs() -> Vec<(Side, Puppet, Instant)> {
    let pairs = vec![
        handshake_with_puppet_server(|_| {}),
        handshake_with_puppet_client(|_| {}),
    ];
    for (side, puppet, _) in &pairs {
        assert_puppet_connected(side, puppet);
    }
    pairs
}

const fn delta(before: AssociationStats, after: AssociationStats) -> (u32, u32) {
    (
        after.records_discarded - before.records_discarded,
        after.replays - before.replays,
    )
}

/// Feeds one datagram and returns `(records_discarded, replays)` deltas.
fn feed(side: &mut Side, datagram: &[u8], now: Instant) -> (u32, u32) {
    let before = side.assoc.stats();
    side.assoc.handle_datagram(datagram, now);
    side.drain_events();
    delta(before, side.assoc.stats())
}

/// Authenticated application data is the probe: this profile carries none,
/// so an accepted record shows up as exactly one discard, a replayed one as
/// exactly one replay, and neither changes the association.
const ACCEPTED: (u32, u32) = (1, 0);
const REPLAYED: (u32, u32) = (0, 1);
const DISCARDED: (u32, u32) = (1, 0);

#[test]
fn replayed_records_are_dropped_and_counted() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let record = puppet.seal(1, ContentType::ApplicationData, b"probe");
        assert_eq!(feed(&mut side, &record, now), ACCEPTED);
        for _ in 0..3 {
            assert_eq!(feed(&mut side, &record, now), REPLAYED);
        }
        // The peer's Finished record (sequence 0) is as dead as any other.
        assert!(side.assoc.is_connected());
        assert_eq!(side.failed, None);
        assert_eq!(side.connected_events, 1, "no second Connected");
    }
}

/// RFC 6347 §4.1.2.6: 64-record window. With the highest sequence number at
/// 70, 7 is the oldest still acceptable and 6 is out.
#[test]
fn records_outside_the_replay_window_are_dropped() {
    for (mut side, mut puppet, now) in connected_pairs() {
        // The puppet's Finished used sequence 0; these are 1..=70.
        let sealed: Vec<Vec<u8>> = (1..=70)
            .map(|_| puppet.seal(1, ContentType::ApplicationData, b"probe"))
            .collect();
        let by_seq = |seq: usize| &sealed[seq - 1];
        assert_eq!(records(by_seq(70))[0].seq, 70);

        assert_eq!(feed(&mut side, by_seq(70), now), ACCEPTED);
        assert_eq!(feed(&mut side, by_seq(6), now), REPLAYED, "64 behind");
        assert_eq!(feed(&mut side, by_seq(1), now), REPLAYED, "69 behind");
        assert_eq!(feed(&mut side, by_seq(7), now), ACCEPTED, "63 behind");
        assert_eq!(feed(&mut side, by_seq(7), now), REPLAYED, "now seen");
        assert_eq!(feed(&mut side, by_seq(69), now), ACCEPTED, "reordered");
        assert_eq!(feed(&mut side, by_seq(70), now), REPLAYED);
        assert!(side.assoc.is_connected());
    }
}

/// A forged record must not move the window: the genuine record with the
/// same sequence number is still accepted afterwards (RFC 6347 §4.1.2.6,
/// "only after the MAC verifies").
#[test]
fn records_with_a_bad_tag_are_dropped_without_moving_the_window() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let genuine = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, 40]);
        // Flip one bit in every position after the header in turn: explicit
        // nonce, ciphertext, tag.
        for index in 13..genuine.len() {
            let mut forged = genuine.clone();
            forged[index] ^= 0x01;
            assert_eq!(feed(&mut side, &forged, now), DISCARDED, "byte {index}");
        }
        // Header fields are authenticated too: type, sequence, length.
        let mut wrong_type = genuine.clone();
        wrong_type[0] = ContentType::ApplicationData as u8;
        assert_eq!(feed(&mut side, &wrong_type, now), DISCARDED);
        let mut wrong_seq = genuine.clone();
        wrong_seq[10] ^= 0x04;
        assert_eq!(feed(&mut side, &wrong_seq, now), DISCARDED);
        assert!(side.assoc.is_connected(), "a forged fatal alert was obeyed");
        assert_eq!(side.failed, None);

        // The genuine alert still gets through and is obeyed.
        side.assoc.handle_datagram(&genuine, now);
        side.drain_events();
        assert_eq!(side.failed, Some(FailureCause::PeerAlert(40)));
    }
}

/// Once epoch 1 is being read, nothing in the clear is processed: a forged
/// fatal alert, `close_notify`, `ChangeCipherSpec` or handshake message
/// cannot end or disturb a connected association (plan §5, defect 12).
#[test]
fn plaintext_records_cannot_touch_a_connected_association() {
    for (mut side, _puppet, now) in connected_pairs() {
        let forged = [
            plaintext_alert(9, alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
            plaintext_alert(9, alert::LEVEL_WARNING, alert::CLOSE_NOTIFY),
            raw_record(
                ContentType::ChangeCipherSpec as u8,
                DTLS_1_2_VERSION,
                0,
                9,
                &[1],
            ),
            message_record(9, HT_CLIENT_HELLO, 9, &[0; 60]),
            message_record(9, HT_FINISHED, 9, &[0; 12]),
            message_record(9, HT_HELLO_REQUEST, 9, &[]),
            raw_record(
                ContentType::ApplicationData as u8,
                DTLS_1_2_VERSION,
                0,
                9,
                b"rtp?",
            ),
        ];
        for datagram in &forged {
            assert_eq!(feed(&mut side, datagram, now), DISCARDED);
        }
        assert!(side.assoc.is_connected());
        assert_eq!(side.failed, None);
        assert!(!side.peer_closed);
        assert!(side.drain_transmit().is_empty(), "replied to a forgery");
    }
}

#[test]
fn records_in_unknown_epochs_or_versions_are_dropped() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let genuine = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, 40]);
        let rec = records(&genuine).remove(0);
        for epoch in [2u16, 3, 0x7FFF, 0xFFFF] {
            let moved = Rec {
                epoch,
                ..rec.clone()
            };
            assert_eq!(
                feed(&mut side, &moved.encode(), now),
                DISCARDED,
                "epoch {epoch}"
            );
        }
        for version in [DTLS_1_0_VERSION, 0x0303, 0xFEFC, 0] {
            let other = Rec {
                version,
                ..rec.clone()
            };
            assert_eq!(
                feed(&mut side, &other.encode(), now),
                DISCARDED,
                "{version:#x}"
            );
        }
        assert!(side.assoc.is_connected());
    }
}

#[test]
fn truncated_and_oversized_protected_records_are_dropped() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let genuine = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, 40]);
        // Every proper prefix of the datagram.
        for len in 0..genuine.len() {
            let (discarded, replays) = feed(&mut side, &genuine[..len], now);
            assert_eq!((discarded, replays), DISCARDED, "prefix {len}");
        }
        // A record whose payload is shorter than nonce + tag.
        let rec = records(&genuine).remove(0);
        for len in [0usize, 1, 8, 23] {
            let short = Rec {
                payload: rec.payload[..len].to_vec(),
                ..rec.clone()
            };
            assert_eq!(
                feed(&mut side, &short.encode(), now),
                DISCARDED,
                "payload {len}"
            );
        }
        // A record far above the DTLS maximum fragment (2^14).
        let huge = Rec {
            payload: vec![0xA5; 20_000],
            ..rec
        };
        assert_eq!(feed(&mut side, &huge.encode(), now), DISCARDED);
        // A length field that promises more than the datagram holds.
        let mut lying = genuine.clone();
        lying[11] = 0xFF;
        lying[12] = 0xFF;
        assert_eq!(feed(&mut side, &lying, now), DISCARDED);
        assert!(side.assoc.is_connected());
        assert_eq!(side.failed, None);
    }
}

/// At most 16 records of one datagram are looked at (SC-5): a seventeenth,
/// even a genuine fatal alert, is not processed.
#[test]
fn records_beyond_the_per_datagram_cap_are_not_processed() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let mut datagram = Vec::new();
        for _ in 0..16 {
            datagram.extend(puppet.seal(1, ContentType::ApplicationData, b"x"));
        }
        let seventeenth = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, 40]);
        datagram.extend(&seventeenth);
        assert_eq!(feed(&mut side, &datagram, now), (17, 0));
        assert!(side.assoc.is_connected());
        // Sent on its own it counts.
        side.assoc.handle_datagram(&seventeenth, now);
        side.drain_events();
        assert_eq!(side.failed, Some(FailureCause::PeerAlert(40)));
    }
}

/// A valid record followed by rubbish: the valid one is processed, the tail
/// is dropped.
#[test]
fn corrupt_tail_does_not_hide_the_valid_records_before_it() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let mut datagram = puppet.seal(1, ContentType::ApplicationData, b"x");
        datagram.extend_from_slice(&[0x16, 0xFE, 0xFD, 0, 1, 0xFF]);
        assert_eq!(feed(&mut side, &datagram, now), (2, 0));
        assert!(side.assoc.is_connected());
    }
}

// =============================================================================
// Alerts and closing
// =============================================================================

#[test]
fn authenticated_close_notify_after_the_handshake_closes_the_association() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let close = puppet.seal(
            1,
            ContentType::Alert,
            &[alert::LEVEL_WARNING, alert::CLOSE_NOTIFY],
        );
        side.assoc.handle_datagram(&close, now);
        side.drain_events();
        assert!(side.peer_closed);
        assert_eq!(side.failed, None, "close_notify is not a failure");
        assert!(side.assoc.is_terminated());
        assert!(!side.assoc.is_connected());
        assert_eq!(side.assoc.poll_timeout(), None);
        // RFC 5246 §7.2.1: it answers with its own close_notify, protected.
        puppet.alerts.clear();
        let reply = side.drain_transmit();
        assert_eq!(reply.len(), 1);
        assert_eq!(records(&reply[0])[0].epoch, 1);
        puppet.absorb(&reply[0]);
        assert_eq!(
            puppet.alerts,
            vec![(alert::LEVEL_WARNING, alert::CLOSE_NOTIFY)]
        );

        // Terminal: nothing more is processed, sent or reported.
        let again = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, 40]);
        side.assoc.handle_datagram(&again, now);
        side.assoc.handle_timeout(now + Duration::from_secs(60));
        side.assoc.close();
        side.drain_events();
        assert_eq!(side.failed, None);
        assert!(
            side.drain_transmit().is_empty(),
            "sent something while terminal"
        );
        assert_eq!(side.connected_events, 1);
    }
}

#[test]
fn authenticated_fatal_alert_after_the_handshake_fails_the_association() {
    for description in [alert::HANDSHAKE_FAILURE, alert::INTERNAL_ERROR, 20, 255] {
        for (mut side, mut puppet, now) in connected_pairs() {
            let fatal = puppet.seal(1, ContentType::Alert, &[alert::LEVEL_FATAL, description]);
            side.assoc.handle_datagram(&fatal, now);
            side.drain_events();
            assert_eq!(side.failed, Some(FailureCause::PeerAlert(description)));
            assert_eq!(side.failed_events, 1);
            assert!(!side.peer_closed);
            assert!(side.assoc.is_terminated());
            assert!(!side.assoc.is_connected());
            assert_eq!(side.assoc.poll_timeout(), None);
            assert!(
                side.drain_transmit().is_empty(),
                "no alert in reply to an alert"
            );
            assert_eq!(side.connected_events, 1, "keys were exported once, before");
        }
    }
}

/// An alert level that is neither warning nor fatal is treated as fatal.
#[test]
fn alert_with_an_unknown_level_is_fatal() {
    for (mut side, mut puppet, now) in connected_pairs() {
        let odd = puppet.seal(1, ContentType::Alert, &[7, 99]);
        side.assoc.handle_datagram(&odd, now);
        side.drain_events();
        assert_eq!(side.failed, Some(FailureCause::PeerAlert(99)));
    }
}

#[test]
fn warnings_and_malformed_alerts_after_the_handshake_are_ignored() {
    for (mut side, mut puppet, now) in connected_pairs() {
        for payload in [
            &[alert::LEVEL_WARNING, 90][..],
            &[alert::LEVEL_WARNING, alert::NO_RENEGOTIATION][..],
            &[alert::LEVEL_FATAL][..],
            &[][..],
            &[alert::LEVEL_FATAL, 40, 0][..],
        ] {
            let record = puppet.seal(1, ContentType::Alert, payload);
            side.assoc.handle_datagram(&record, now);
            side.drain_events();
        }
        assert!(side.assoc.is_connected());
        assert_eq!(side.failed, None);
        assert!(!side.peer_closed);
    }
}

/// RFC 5746 §4.4 / plan §2.2: renegotiation is refused. A protected
/// `ClientHello` after completion gets a `no_renegotiation` warning (at most
/// one per second) and changes nothing.
#[test]
fn server_refuses_renegotiation_with_a_rate_limited_warning() {
    let (mut server, mut puppet, now) = handshake_with_puppet_client(|_| {});
    assert_puppet_connected(&server, &puppet);
    server.drain_transmit();
    puppet.alerts.clear();

    for _ in 0..5 {
        let hello = puppet.client_hello();
        let rec = records(&hello).remove(0);
        let protected = puppet.seal(1, ContentType::Handshake, &rec.payload);
        server.assoc.handle_datagram(&protected, now);
    }
    puppet.absorb_from(&mut server);
    assert_eq!(
        puppet.alerts,
        vec![(alert::LEVEL_WARNING, alert::NO_RENEGOTIATION)]
    );

    let hello = puppet.client_hello();
    let rec = records(&hello).remove(0);
    let protected = puppet.seal(1, ContentType::Handshake, &rec.payload);
    server.assoc.handle_datagram(&protected, now + SECOND);
    puppet.absorb_from(&mut server);
    assert_eq!(puppet.alerts.len(), 2);

    server.drain_events();
    assert!(server.assoc.is_connected());
    assert_eq!(server.failed, None);
    assert_eq!(server.connected_events, 1);
}

/// A `HelloRequest` after completion is ignored by the client: no new
/// handshake, no reply.
#[test]
fn client_ignores_hello_request_after_the_handshake() {
    let (mut client, mut puppet, now) = handshake_with_puppet_server(|_| {});
    assert_puppet_connected(&client, &puppet);
    client.drain_transmit();
    let request = Msg {
        msg_type: HT_HELLO_REQUEST,
        seq: puppet.next_seq,
        body: Vec::new(),
    };
    let protected = puppet.seal(1, ContentType::Handshake, &request.encode());
    assert_eq!(feed(&mut client, &protected, now), DISCARDED);
    assert!(client.assoc.is_connected());
    assert!(
        client.drain_transmit().is_empty(),
        "answered a HelloRequest"
    );
}

/// Alerts in the clear during the handshake (SEC-001). They are
/// unauthenticated, so one alone does not end the handshake; it becomes the
/// cause if the peer then stays silent until the retransmission timer
/// expires. Returns `(level, description)` pairs worth trying.
const fn plaintext_kill_alerts() -> [(u8, u8); 4] {
    [
        (alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
        (alert::LEVEL_FATAL, alert::BAD_CERTIFICATE),
        (alert::LEVEL_FATAL, 255),
        (alert::LEVEL_WARNING, alert::CLOSE_NOTIFY),
    ]
}

/// A genuine fatal alert during the handshake still ends it with the
/// alert's number, in both roles, within one retransmission interval: not
/// at once (the alert is in the clear), but when the timer that would have
/// retransmitted our flight expires and nothing else arrived. Nothing is
/// sent in answer, and the flight is not retransmitted to a peer that gave
/// up.
#[test]
fn fatal_alert_during_the_handshake_fails_with_the_alert_number() {
    for description in [alert::HANDSHAKE_FAILURE, alert::BAD_CERTIFICATE, 255] {
        let (mut client, _, now) = fresh_client();
        client
            .assoc
            .handle_datagram(&plaintext_alert(0, alert::LEVEL_FATAL, description), now);
        assert_still_handshaking(&mut client);
        assert_eq!(client.assoc.poll_timeout(), Some(now + SECOND));
        client
            .assoc
            .handle_timeout(now + Duration::from_nanos(999_999_999));
        assert_still_handshaking(&mut client);
        client.assoc.handle_timeout(now + SECOND);
        client.drain_events();
        assert_side_failed(&client, FailureCause::PeerAlert(description));
        assert!(
            client.drain_transmit().is_empty(),
            "answered a forged alert or retransmitted"
        );
        assert_eq!(client.assoc.stats().retransmits, 0);

        let (mut server, _, now) = puppet_client_until_flight4(|_| {});
        server
            .assoc
            .handle_datagram(&plaintext_alert(5, alert::LEVEL_FATAL, description), now);
        assert_still_handshaking(&mut server);
        server.assoc.handle_timeout(now + SECOND);
        server.drain_events();
        assert_side_failed(&server, FailureCause::PeerAlert(description));
        assert!(server.drain_transmit().is_empty(), "sent something");
    }
}

#[test]
fn close_notify_during_the_handshake_is_a_failure_not_a_close() {
    let (mut client, _, now) = fresh_client();
    client.assoc.handle_datagram(
        &plaintext_alert(0, alert::LEVEL_WARNING, alert::CLOSE_NOTIFY),
        now,
    );
    assert_still_handshaking(&mut client);
    client.assoc.handle_timeout(now + SECOND);
    client.drain_events();
    assert_side_failed(&client, FailureCause::PeerAlert(alert::CLOSE_NOTIFY));
    assert!(!client.peer_closed);
}

/// The first pending alert is the cause; later ones cannot rewrite it. At
/// the budget a pending alert is reported instead of `Timeout`.
#[test]
fn first_plaintext_alert_is_the_reported_cause() {
    let (mut client, _, now) = fresh_client();
    for description in [alert::BAD_CERTIFICATE, alert::HANDSHAKE_FAILURE, 255] {
        client
            .assoc
            .handle_datagram(&plaintext_alert(0, alert::LEVEL_FATAL, description), now);
    }
    client.assoc.handle_timeout(now + SECOND);
    client.drain_events();
    assert_side_failed(&client, FailureCause::PeerAlert(alert::BAD_CERTIFICATE));

    // Budget before the retransmission timer: 5 s against an 8 s interval.
    let mut config = AssociationConfig::new(
        DtlsRole::Client,
        identity(),
        vec![identity().fingerprint().clone()],
    );
    config.initial_rto = Duration::from_secs(8);
    config.handshake_budget = Duration::from_secs(5);
    let now = Instant::now();
    let mut client = Side::new(config, now);
    client
        .assoc
        .handle_datagram(&plaintext_alert(0, alert::LEVEL_FATAL, 49), now);
    assert_eq!(client.assoc.poll_timeout(), Some(now + SECOND * 5));
    client.assoc.handle_timeout(now + SECOND * 5);
    client.drain_events();
    assert_side_failed(&client, FailureCause::PeerAlert(49));
}

/// SEC-001 kill (1): forged plaintext fatal alerts and `close_notify`
/// ahead of every datagram, in both directions, for the whole handshake.
/// Each is followed by the peer's real message, so each is forgotten: the
/// handshake completes with matching keys and without a retransmission.
#[test]
fn forged_plaintext_alerts_do_not_stop_a_handshake_that_progresses() {
    for (level, description) in plaintext_kill_alerts() {
        let mut lo = Loopback::new();
        lo.run(|_, index, datagram| {
            Wire::Replace(vec![
                plaintext_alert(index as u64, level, description),
                plaintext_alert(index as u64 + 1, level, description),
                datagram.to_vec(),
            ])
        });
        lo.assert_connected();
        assert_eq!(lo.client.assoc.stats().retransmits, 0);
        assert_eq!(lo.server.assoc.stats().retransmits, 0);
    }
}

/// A forged alert that arrives *after* a flight was accepted is forgotten
/// when the next flight is: here the alert reaches the client between the
/// `HelloVerifyRequest` and the server's certificate flight, and the server
/// between the client's second `ClientHello` and its flight 5.
#[test]
fn forged_plaintext_alert_between_flights_is_forgotten_on_progress() {
    for (level, description) in plaintext_kill_alerts() {
        let mut lo = Loopback::new();
        lo.run(|dir, index, datagram| {
            let mut out = vec![datagram.to_vec()];
            // After the HelloVerifyRequest (server datagram 0) and after the
            // ClientHello with the cookie (client datagram 1).
            if matches!(
                (dir, index),
                (Dir::ServerToClient, 0) | (Dir::ClientToServer, 1)
            ) {
                out.push(plaintext_alert(9, level, description));
            }
            Wire::Replace(out)
        });
        lo.assert_connected();
    }
}

/// An alert in epoch 1 is authenticated and acts at once, also while the
/// handshake is still running: the server's `ChangeCipherSpec` followed by
/// a protected fatal alert instead of `Finished`.
#[test]
fn authenticated_alert_during_the_handshake_fails_at_once() {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _) = puppet.counterpart(now);
    puppet.absorb_from(&mut client);
    let flight4 = puppet.server_flight4();
    client.assoc.handle_datagram(&flight4, now);
    puppet.absorb_from(&mut client);
    assert_eq!(puppet.peer_finished_ok, Some(true));
    assert_still_handshaking(&mut client);

    let mut datagram = puppet.seal(0, ContentType::ChangeCipherSpec, &[1]);
    puppet.records.activate_write().unwrap();
    datagram.extend(puppet.seal(
        1,
        ContentType::Alert,
        &[alert::LEVEL_FATAL, alert::INTERNAL_ERROR],
    ));
    client.assoc.handle_datagram(&datagram, now);
    client.drain_events();
    assert_side_failed(&client, FailureCause::PeerAlert(alert::INTERNAL_ERROR));
}

#[test]
fn warning_alerts_during_the_handshake_do_not_stop_it() {
    let mut lo = Loopback::new();
    lo.run(|_, index, datagram| {
        let mut with_warning = plaintext_alert(index as u64, alert::LEVEL_WARNING, 90);
        with_warning.extend_from_slice(datagram);
        Wire::Replace(vec![
            plaintext_alert(40, alert::LEVEL_WARNING, alert::NO_RENEGOTIATION),
            with_warning,
        ])
    });
    lo.assert_connected();
}

/// A server with no client yet has nothing an alert could end: before a
/// valid cookie it reacts to nothing but a `ClientHello`.
#[test]
fn server_without_a_verified_client_ignores_everything_but_a_client_hello() {
    let (mut server, now) = fresh_server();
    let forged = [
        plaintext_alert(0, alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
        plaintext_alert(0, alert::LEVEL_WARNING, alert::CLOSE_NOTIFY),
        raw_record(
            ContentType::ChangeCipherSpec as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &[1],
        ),
        message_record(0, HT_FINISHED, 0, &[0; 12]),
        message_record(0, HT_CERTIFICATE, 0, &certificate_body(vec![vec![1, 2, 3]])),
        message_record(0, HT_SERVER_HELLO, 0, &server_hello_body()),
        raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            1,
            0,
            &[0; 40],
        ),
        raw_record(
            ContentType::ApplicationData as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &[0; 40],
        ),
        vec![0x80; 172],
    ];
    for datagram in &forged {
        server.assoc.handle_datagram(datagram, now);
    }
    assert_still_handshaking(&mut server);
    assert!(
        server.drain_transmit().is_empty(),
        "sent something before any ClientHello"
    );
    assert_eq!(server.assoc.stats().retransmits, 0);
}

/// `close()` during the handshake: one `close_notify`, terminal, no event,
/// and whatever the peer sends afterwards yields no keys.
#[test]
fn local_close_during_the_handshake_is_final() {
    let mut lo = Loopback::new();
    // Stop after the cookie exchange: the second ClientHello is queued.
    lo.pump(&mut deliver);
    assert!(!lo.client.settled());
    lo.client.drain_transmit();
    lo.client.assoc.close();
    assert!(lo.client.assoc.is_terminated());
    let sent = lo.client.drain_transmit();
    let alerts: Vec<_> = sent
        .iter()
        .flat_map(|d| records(d))
        .filter(|r| r.content_type == ContentType::Alert)
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].payload,
        vec![alert::LEVEL_WARNING, alert::CLOSE_NOTIFY]
    );
    // A complete, genuine server flight arrives afterwards.
    let (_, mut puppet, _) = handshake_with_puppet_server(|_| {});
    lo.client
        .assoc
        .handle_datagram(&puppet.server_flight4(), lo.now);
    lo.client
        .assoc
        .handle_timeout(lo.now + Duration::from_secs(30));
    lo.client.drain_events();
    assert_eq!(lo.client.failed, None, "close() emits no event");
    assert!(lo.client.keys.is_none());
    assert_eq!(lo.client.assoc.poll_timeout(), None);
    assert!(
        lo.client.drain_transmit().is_empty(),
        "sent something after close()"
    );
    // close() twice is harmless.
    lo.client.assoc.close();
    assert!(
        lo.client.drain_transmit().is_empty(),
        "second close() sent something"
    );
}

// =============================================================================
// Handshake fragments and reassembly limits (plan §5)
// =============================================================================

/// A named case: whether it is refused outright, and its fragments (header
/// and number of data bytes).
type FragmentCase = (
    &'static str,
    bool,
    Vec<(proto_dtls::wire::handshake_msg::HandshakeHeader, usize)>,
);

/// Fragment headers that break a reassembly rule or limit. Checked against
/// a client waiting for the server's first message (expects `message_seq`
/// 0); `true` marks the ones that are refused outright, the others replace
/// what the slot held.
fn rule_breaking_fragments() -> [FragmentCase; 9] {
    [
        (
            "message of 2,049 bytes (limit 2,048)",
            true,
            vec![(header(HT_SERVER_HELLO, 2049, 0, 0, 10), 10)],
        ),
        (
            "message of 16 MiB - 1",
            true,
            vec![(header(HT_SERVER_KEY_EXCHANGE, 0x00FF_FFFF, 0, 0, 10), 10)],
        ),
        (
            "Certificate of 8,193 bytes (limit 8,192)",
            true,
            vec![(header(HT_CERTIFICATE, 8193, 0, 0, 10), 10)],
        ),
        (
            "fragment ends past the message",
            true,
            vec![(header(HT_SERVER_HELLO, 100, 0, 95, 10), 10)],
        ),
        (
            "fragment offset past the message",
            true,
            vec![(header(HT_SERVER_HELLO, 100, 0, 101, 0), 0)],
        ),
        (
            "fragment offset near 2^24 (overflow probe)",
            true,
            vec![(header(HT_SERVER_HELLO, 100, 0, 0x00FF_FFFF, 0x00FF), 255)],
        ),
        (
            "second fragment disagrees about the length",
            false,
            vec![
                (header(HT_SERVER_HELLO, 100, 0, 0, 10), 10),
                (header(HT_SERVER_HELLO, 90, 0, 10, 10), 10),
            ],
        ),
        (
            "second fragment disagrees about the type",
            false,
            vec![
                (header(HT_SERVER_HELLO, 100, 0, 0, 10), 10),
                (header(HT_HELLO_VERIFY_REQUEST, 100, 0, 10, 10), 10),
            ],
        ),
        (
            "message_seq 5 ahead (window is 4)",
            true,
            vec![(header(HT_SERVER_HELLO_DONE, 0, 5, 0, 0), 0)],
        ),
    ]
}

/// SEC-001 kill (2): a plaintext fragment that breaks a reassembly rule or
/// limit is unauthenticated, so it is dropped and counted and the
/// association carries on -- no failure, no alert, nothing sent.
#[test]
fn fragments_that_break_a_limit_are_dropped_and_counted() {
    for (name, refused, fragments) in rule_breaking_fragments() {
        let (mut client, _, now) = fresh_client();
        for (seq, (head, len)) in fragments.iter().enumerate() {
            client
                .assoc
                .handle_datagram(&fragment_record(seq as u64, head, &vec![0x5A; *len]), now);
        }
        assert_still_handshaking(&mut client);
        assert_eq!(
            client.assoc.stats().fragments_rejected,
            u32::from(refused),
            "{name}"
        );
        assert!(client.drain_transmit().is_empty(), "{name}: sent an alert");
        assert_eq!(client.assoc.poll_timeout(), Some(now + SECOND), "{name}");
    }
}

/// The rest of a datagram that starts with a rule-breaking plaintext
/// fragment is ignored as well: a datagram of the peer's never holds one.
#[test]
fn datagram_with_a_rule_breaking_fragment_is_dropped_whole() {
    let (mut client, _, now) = fresh_client();
    let mut datagram = fragment_record(0, &header(HT_SERVER_HELLO, 2049, 0, 0, 10), &[0; 10]);
    // Would be processed, and refused as a protocol violation, on its own.
    datagram.extend(message_record(1, HT_FINISHED, 0, &[0; 12]));
    client.assoc.handle_datagram(&datagram, now);
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 1);
}

/// SEC-001 kill (2), end to end: every rule-breaking fragment is injected
/// ahead of every datagram of a real handshake, in both directions and for
/// every `message_seq` a side may be waiting for. The handshake completes
/// with matching keys (so both transcripts hold exactly the messages the
/// peers sent) and the forgeries show up in the counters.
#[test]
fn fragments_that_break_a_limit_do_not_stop_the_handshake() {
    for (name, _, fragments) in rule_breaking_fragments() {
        let mut lo = Loopback::new();
        lo.run(|_, index, datagram| {
            let mut out = Vec::new();
            for base in 0..7u16 {
                for (head, len) in &fragments {
                    let mut head = *head;
                    // The "too far ahead" case stays too far ahead.
                    head.message_seq = if head.message_seq == 5 { 60 } else { base };
                    out.push(fragment_record(index as u64, &head, &vec![0x5A; *len]));
                }
            }
            out.push(datagram.to_vec());
            Wire::Replace(out)
        });
        assert_eq!(lo.client.failed, None, "{name}");
        assert_eq!(lo.server.failed, None, "{name}");
        lo.assert_connected();
        assert!(lo.client.assoc.stats().fragments_rejected > 0, "{name}");
        assert!(lo.server.assoc.stats().fragments_rejected > 0, "{name}");
    }
}

/// The values just inside each limit are buffered, not refused.
#[test]
fn fragments_at_the_limits_are_accepted() {
    let (mut client, _, now) = fresh_client();
    let inside = [
        header(HT_CERTIFICATE, 8192, 1, 8182, 10),
        header(HT_SERVER_KEY_EXCHANGE, 2048, 2, 0, 10),
        header(HT_SERVER_HELLO_DONE, 0, 4, 0, 0),
    ];
    for head in &inside {
        client.assoc.handle_datagram(
            &fragment_record(0, head, &[0; 10][..head.fragment_length as usize]),
            now,
        );
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 0);
}

/// Reassembly memory is bounded at 16 KiB: two maximum-size `Certificate`
/// messages can be pending; a third announcement for a later message is
/// dropped and counted instead of growing the buffer -- and instead of
/// failing the association, since the announcements are unauthenticated.
/// Every pending message is announced by a 10-byte fragment, so the
/// attacker spends 35 bytes per 8 KiB asked for.
#[test]
fn reassembly_memory_bound_holds_without_failing_the_handshake() {
    let (mut client, _, now) = fresh_client();
    for seq in 0..2u16 {
        let head = header(HT_CERTIFICATE, 8192, seq, 0, 10);
        client
            .assoc
            .handle_datagram(&fragment_record(0, &head, &[0; 10]), now);
        assert_still_handshaking(&mut client);
    }
    assert_eq!(client.assoc.stats().fragments_rejected, 0);
    for seq in 2..5u16 {
        let head = header(HT_CERTIFICATE, 8192, seq, 0, 10);
        client
            .assoc
            .handle_datagram(&fragment_record(0, &head, &[0; 10]), now);
        assert_still_handshaking(&mut client);
    }
    assert_eq!(client.assoc.stats().fragments_rejected, 3);
    assert!(client.drain_transmit().is_empty(), "sent something");

    // Without Certificate-typed messages the window (5 x 2,048) stays under
    // the bound, so the per-message limit is what holds.
    let (mut client, _, now) = fresh_client();
    for seq in 0..5u16 {
        let head = header(HT_SERVER_KEY_EXCHANGE, 2048, seq, 0, 10);
        client
            .assoc
            .handle_datagram(&fragment_record(0, &head, &[0; 10]), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 0);
}

/// SEC-001 kill (3), memory: forged zero-length fragments announce
/// maximum-size `Certificate` messages for every `message_seq` a side may
/// be waiting for or about to, ahead of every datagram. They fill the
/// reassembly memory and sit in the slots of the real messages. The real
/// messages still get in (the next expected one evicts later ones, and a
/// message that disagrees with its slot replaces it) and the handshake
/// completes with matching keys.
#[test]
fn forged_announcements_cannot_fill_reassembly_memory_against_the_peer() {
    let mut lo = Loopback::new();
    lo.run(|_, index, datagram| {
        let mut out = Vec::new();
        for seq in 0..10u16 {
            let head = header(HT_CERTIFICATE, 8192, seq, 0, 0);
            out.push(fragment_record(index as u64, &head, &[]));
        }
        out.push(datagram.to_vec());
        Wire::Replace(out)
    });
    lo.assert_connected();
    assert_eq!(lo.client.assoc.stats().retransmits, 0);
    assert_eq!(lo.server.assoc.stats().retransmits, 0);
}

/// SEC-001 kill (3), slots: a forged first fragment for each of the next
/// five messages pins a type and a length that the real message does not
/// have. Tried with a wrong type, a wrong length, and both; the forged
/// fragment carries bytes that would corrupt the message if they were kept.
#[test]
fn forged_first_fragments_cannot_pin_a_slot_against_the_real_message() {
    let forgeries = [
        (HT_SERVER_HELLO_DONE, 40u32),
        (HT_CERTIFICATE, 1000),
        (HT_FINISHED, 12),
        (HT_CLIENT_KEY_EXCHANGE, 98),
    ];
    for (msg_type, length) in forgeries {
        let mut lo = Loopback::new();
        lo.run(|_, index, datagram| {
            let mut out = Vec::new();
            for seq in 0..10u16 {
                // Bytes 0..8 only: never a complete message.
                let head = header(msg_type, length, seq, 0, 8);
                out.push(fragment_record(index as u64, &head, &[0xEE; 8]));
            }
            out.push(datagram.to_vec());
            Wire::Replace(out)
        });
        assert_eq!(lo.client.failed, None, "type {msg_type}");
        assert_eq!(lo.server.failed, None, "type {msg_type}");
        lo.assert_connected();
    }
}

/// SEC-001 kill (4): a forged plaintext "Finished" parked in the slot of
/// the real one, before the cipher change. It must neither be accepted (a
/// `Finished` counts from epoch 1 only) nor keep the real one out. Server
/// role: the slot (`message_seq` 5) is inside the window as soon as the
/// client's flight is awaited.
#[test]
fn forged_plaintext_finished_cannot_occupy_the_finished_slot_of_a_server() {
    for (msg_type, body) in [
        (HT_FINISHED, vec![0u8; 12]),
        (HT_FINISHED, vec![0xEE; 5]),
        (HT_CERTIFICATE_VERIFY, vec![0xEE; 12]),
    ] {
        let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
        // Complete forged message, and a partial one for good measure.
        server
            .assoc
            .handle_datagram(&message_record(7, msg_type, 5, &body), now);
        assert_still_handshaking(&mut server);
        let flight5 = puppet.client_flight5();
        server.assoc.handle_datagram(&flight5, now);
        server.drain_events();
        puppet.absorb_from(&mut server);
        assert_puppet_connected(&server, &puppet);
        // The forgery was counted when the cipher changed.
        assert_eq!(server.assoc.stats().fragments_rejected, 1);
    }
}

/// The same for the client role: the server's `Finished` is `message_seq`
/// 6, which is inside the window once the server's flight is processed.
#[test]
fn forged_plaintext_finished_cannot_occupy_the_finished_slot_of_a_client() {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _) = puppet.counterpart(now);
    puppet.absorb_from(&mut client);
    let flight4 = puppet.server_flight4();
    client.assoc.handle_datagram(&flight4, now);
    puppet.absorb_from(&mut client);
    assert_eq!(puppet.peer_finished_ok, Some(true));

    // The client now waits for ChangeCipherSpec; a plaintext "Finished"
    // with the right sequence number arrives first.
    client
        .assoc
        .handle_datagram(&message_record(9, HT_FINISHED, 6, &[0; 12]), now);
    assert_still_handshaking(&mut client);

    let flight6 = puppet.server_flight6();
    client.assoc.handle_datagram(&flight6, now);
    client.drain_events();
    assert_puppet_connected(&client, &puppet);
    assert_eq!(client.assoc.stats().fragments_rejected, 1);
}

/// With the forged `Finished` in place and the real one never arriving, the
/// forged one is still not accepted: after the peer's `ChangeCipherSpec`
/// the association waits for an epoch-1 `Finished` until the budget ends.
#[test]
fn forged_plaintext_finished_never_completes_a_handshake() {
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    server
        .assoc
        .handle_datagram(&message_record(7, HT_FINISHED, 5, &[0; 12]), now);
    // The client's flight up to and including ChangeCipherSpec, without its
    // protected Finished (the last record of the datagram).
    let flight5 = puppet.client_flight5();
    let mut without_finished = Vec::new();
    for rec in records(&flight5) {
        if rec.epoch == 0 {
            without_finished.extend(rec.encode());
        }
    }
    server.assoc.handle_datagram(&without_finished, now);
    assert_still_handshaking(&mut server);
    // More plaintext "Finished" after the cipher change is not even read.
    server
        .assoc
        .handle_datagram(&message_record(8, HT_FINISHED, 5, &[0; 12]), now);
    assert_still_handshaking(&mut server);
    server.assoc.handle_timeout(now + SECOND * 10);
    server.drain_events();
    assert_side_failed(&server, FailureCause::Timeout);
}

/// Scattered one-byte fragments: at most 16 disjoint ranges are tracked per
/// message; more are dropped and counted, without failing.
#[test]
fn scattered_fragments_beyond_the_range_cap_are_dropped() {
    let (mut client, _, now) = fresh_client();
    for i in 0..40u32 {
        let head = header(HT_SERVER_HELLO, 200, 0, i * 2, 1);
        client
            .assoc
            .handle_datagram(&fragment_record(0, &head, &[0]), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 40 - 16);
}

/// A fragment whose header promises more bytes than the record holds, and a
/// record too short for a handshake header: dropped and counted.
#[test]
fn truncated_fragments_are_dropped() {
    let (mut client, _, now) = fresh_client();
    let head = header(HT_SERVER_HELLO, 100, 0, 0, 50);
    client
        .assoc
        .handle_datagram(&fragment_record(0, &head, &[0; 49]), now);
    for len in 0..12 {
        let short = raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &vec![2; len],
        );
        client.assoc.handle_datagram(&short, now);
    }
    assert_still_handshaking(&mut client);
    // An empty handshake record holds no fragment at all; the other twelve
    // are rejected.
    assert_eq!(client.assoc.stats().fragments_rejected, 12);
}

/// Overlapping fragments that agree reassemble to the same message; the
/// handshake completes with every server message cut into overlapping
/// thirds delivered back to front.
#[test]
fn overlapping_fragments_in_reverse_order_complete_the_handshake() {
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir != Dir::ServerToClient {
            return Wire::Deliver;
        }
        let mut out = Vec::new();
        for rec in records(datagram) {
            let Some(msg) = rec.message() else {
                out.push(rec.encode());
                continue;
            };
            let len = msg.body.len();
            if len < 6 {
                out.push(rec.encode());
                continue;
            }
            // [0, 2/3), [1/3, len), [1/6, 5/6): every byte covered twice.
            let cuts = [(0, 2 * len / 3), (len / 3, len), (len / 6, 5 * len / 6)];
            for (start, end) in cuts.into_iter().rev() {
                let head = header(
                    msg.msg_type,
                    u32::try_from(len).unwrap(),
                    msg.seq,
                    u32::try_from(start).unwrap(),
                    u32::try_from(end - start).unwrap(),
                );
                out.push(fragment_record(rec.seq, &head, &msg.body[start..end]));
            }
        }
        out.reverse();
        Wire::Replace(out)
    });
    lo.assert_connected();
    assert_eq!(lo.client.assoc.stats().fragments_rejected, 0);
}

/// impl-notes deviation: before the cookie is verified the server keeps no
/// state, so it cannot reassemble; a fragmented or oversized first
/// `ClientHello` is dropped and counted, never answered.
#[test]
fn server_drops_fragmented_or_oversized_first_client_hello() {
    let (mut server, now) = fresh_server();
    let (_, hello, _) = fresh_client();
    let mut body = Vec::new();
    hello.encode(&mut body).unwrap();
    let len = u32::try_from(body.len()).unwrap();
    let half = body.len() / 2;

    let first = header(HT_CLIENT_HELLO, len, 0, 0, u32::try_from(half).unwrap());
    let second = header(
        HT_CLIENT_HELLO,
        len,
        0,
        u32::try_from(half).unwrap(),
        len - u32::try_from(half).unwrap(),
    );
    server
        .assoc
        .handle_datagram(&fragment_record(0, &first, &body[..half]), now);
    server
        .assoc
        .handle_datagram(&fragment_record(1, &second, &body[half..]), now);
    // Length above the per-message limit, with a matching body.
    let huge = vec![0u8; 3000];
    server
        .assoc
        .handle_datagram(&message_record(2, HT_CLIENT_HELLO, 0, &huge), now);
    // A ClientHello that does not parse.
    server.assoc.handle_datagram(
        &message_record(3, HT_CLIENT_HELLO, 0, &body[..body.len() - 1]),
        now,
    );
    server
        .assoc
        .handle_datagram(&message_record(4, HT_CLIENT_HELLO, 0, &[]), now);

    assert_still_handshaking(&mut server);
    assert!(
        server.drain_transmit().is_empty(),
        "answered a bad ClientHello"
    );
    assert_eq!(server.assoc.stats().fragments_rejected, 5);

    // The same hello, whole, is answered.
    server
        .assoc
        .handle_datagram(&message_record(5, HT_CLIENT_HELLO, 0, &body), now);
    assert_eq!(server.drain_transmit().len(), 1);
}

/// At most 64 handshake messages are processed per association, accepted
/// or refused: a peer cannot keep one busy forever (nor buy more than 64
/// signature checks) with messages that are thrown away one by one. This
/// limit is immediate. `HelloRequest` fragments are dropped before they are
/// reassembled (RFC 5246 §7.4.1.1) and do not count.
#[test]
fn handshake_message_count_is_capped() {
    let (mut client, _, now) = fresh_client();
    for seq in 0..200u16 {
        client
            .assoc
            .handle_datagram(&message_record(0, HT_HELLO_REQUEST, seq % 5, &[]), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 200);
    // A refused message does not use up its message_seq: all at seq 0.
    for _ in 0..64 {
        client
            .assoc
            .handle_datagram(&message_record(0, HT_SERVER_HELLO_DONE, 0, &[]), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 264);
    client
        .assoc
        .handle_datagram(&message_record(0, HT_SERVER_HELLO_DONE, 0, &[]), now);
    client.drain_events();
    assert_side_failed(&client, FailureCause::ProtocolViolation);
}

// =============================================================================
// Truncated, oversized and foreign datagrams during the handshake
// =============================================================================

/// Every proper prefix of every handshake datagram arrives before the real
/// one, in both directions. Nothing a truncation produces may fail the
/// handshake or change its result.
#[test]
fn every_truncation_of_every_handshake_datagram_is_harmless() {
    let mut lo = Loopback::new();
    lo.run(|_, _, datagram| {
        let mut all: Vec<Vec<u8>> = (0..datagram.len())
            .map(|len| datagram[..len].to_vec())
            .collect();
        all.push(datagram.to_vec());
        Wire::Replace(all)
    });
    lo.assert_connected();
    assert_eq!(
        lo.elapsed(),
        Duration::ZERO,
        "a truncation cost a retransmission"
    );
}

/// Datagrams that are not DTLS at all (STUN, RTP, RTCP, zeros, a maximum
/// size UDP payload), and records with wrong versions or huge lengths,
/// interleaved with a real handshake.
#[test]
fn foreign_and_oversized_datagrams_during_the_handshake_are_harmless() {
    let noise: Vec<Vec<u8>> = vec![
        vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42],
        vec![0x80; 172],
        vec![0x81, 200, 0, 6, 0, 0, 0, 1],
        vec![0; 1500],
        vec![0xFF; 65_507],
        vec![0x16; 65_507],
        raw_record(ContentType::Handshake as u8, 0x0303, 0, 0, &[1; 64]),
        raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &vec![1; 17_000],
        ),
        raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            1,
            0,
            &[1; 64],
        ),
        raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            2,
            0,
            &[1; 64],
        ),
        raw_record(99, DTLS_1_2_VERSION, 0, 0, &[1; 64]),
        raw_record(
            ContentType::ApplicationData as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &[1; 64],
        ),
        raw_record(
            ContentType::ChangeCipherSpec as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &[2],
        ),
        raw_record(
            ContentType::ChangeCipherSpec as u8,
            DTLS_1_2_VERSION,
            0,
            0,
            &[1, 1],
        ),
        raw_record(ContentType::Alert as u8, DTLS_1_2_VERSION, 0, 0, &[2]),
        std::iter::repeat_n(
            raw_record(
                ContentType::ApplicationData as u8,
                DTLS_1_2_VERSION,
                0,
                0,
                &[],
            ),
            40,
        )
        .flatten()
        .collect(),
    ];
    let mut lo = Loopback::new();
    lo.run(|_, _, datagram| {
        let mut all = noise.clone();
        all.push(datagram.to_vec());
        all.extend(noise.iter().cloned());
        Wire::Replace(all)
    });
    lo.assert_connected();
    assert!(lo.client.assoc.stats().records_discarded > 0);
    assert!(lo.server.assoc.stats().records_discarded > 0);
    assert_eq!(lo.elapsed(), Duration::ZERO);
}

// =============================================================================
// HelloVerifyRequest and cookie (RFC 6347 §4.2.1; plan §5 "Amplification")
// =============================================================================

/// The client follows at most two `HelloVerifyRequest`s; a third is not
/// followed and fails it, when the retransmission timer next expires,
/// instead of looping.
#[test]
fn client_gives_up_after_two_hello_verify_requests() {
    let (mut client, _, now) = fresh_client();
    for round in 0..2u16 {
        let mut body = Vec::new();
        HelloVerifyRequest {
            version: DTLS_1_0_VERSION,
            cookie: vec![u8::try_from(round).unwrap(); 16],
        }
        .encode(&mut body)
        .unwrap();
        client.assoc.handle_datagram(
            &message_record(0, HT_HELLO_VERIFY_REQUEST, round, &body),
            now,
        );
        assert_still_handshaking(&mut client);
        let sent = client.drain_transmit();
        assert_eq!(sent.len(), 1, "one ClientHello per HelloVerifyRequest");
        let hello = ClientHello::parse(&messages(&sent[0])[0].body).unwrap();
        assert_eq!(hello.cookie, vec![u8::try_from(round).unwrap(); 16]);
    }
    let mut body = Vec::new();
    HelloVerifyRequest {
        version: DTLS_1_0_VERSION,
        cookie: vec![9; 16],
    }
    .encode(&mut body)
    .unwrap();
    client
        .assoc
        .handle_datagram(&message_record(0, HT_HELLO_VERIFY_REQUEST, 2, &body), now);
    assert!(client.drain_transmit().is_empty(), "followed a third one");
    expire_retransmission_timer(&mut client, now);
    assert_side_failed(&client, FailureCause::ProtocolViolation);
}

/// Within one retransmission interval, not at once: the message is in the
/// clear and is thrown away without using up its `message_seq` (SEC-010).
#[test]
fn client_fails_on_a_malformed_hello_verify_request() {
    for body in [
        &[][..],
        &[0xFE][..],
        &[0xFE, 0xFF][..],
        &[0xFE, 0xFF, 5, 1, 2][..],
        &[0xFE, 0xFF, 1, 1, 2][..],
    ] {
        let (mut client, _, now) = fresh_client();
        client
            .assoc
            .handle_datagram(&message_record(0, HT_HELLO_VERIFY_REQUEST, 0, body), now);
        expire_retransmission_timer(&mut client, now);
        assert_side_failed(&client, FailureCause::ProtocolViolation);
    }
}

/// A `HelloVerifyRequest` repeated or delayed (same `message_seq`) is a
/// retransmission, not a second request: it does not use up the allowance
/// and does not fail the client.
#[test]
fn duplicate_hello_verify_request_is_not_counted_twice() {
    let mut lo = Loopback::new();
    let mut request = Vec::new();
    lo.run(|dir, index, datagram| {
        if dir == Dir::ServerToClient && index == 0 {
            request = datagram.to_vec();
            return Wire::Replace(vec![datagram.to_vec(); 4]);
        }
        if dir == Dir::ServerToClient && index == 1 {
            // The old HelloVerifyRequest turns up again after the flight.
            return Wire::Replace(vec![datagram.to_vec(), request.clone(), request.clone()]);
        }
        Wire::Deliver
    });
    lo.assert_connected();
}

/// What a server sends back for a hello, as message types.
fn reply_types(server: &mut Side) -> Vec<u8> {
    server
        .drain_transmit()
        .iter()
        .flat_map(|d| messages(d))
        .map(|m| m.msg_type)
        .collect()
}

/// Without the right cookie the only answer is another `HelloVerifyRequest`:
/// no `ServerHello`, no certificate, no state, however often it is tried.
#[test]
fn wrong_cookie_never_gets_the_server_flight() {
    let (mut server, now) = fresh_server();
    let mut puppet = Puppet::new(DtlsRole::Client);
    let cookies: [Vec<u8>; 6] = [
        vec![0xAA; 32],
        vec![0; 32],
        vec![0xAA; 31],
        vec![0xAA; 33],
        vec![0xAA; 255],
        vec![1],
    ];
    for (i, cookie) in cookies.into_iter().enumerate() {
        puppet.cookie = cookie;
        let hello = puppet.client_hello();
        // Spread over time so the rate limit is not what stops the flight.
        server
            .assoc
            .handle_datagram(&hello, now + SECOND * u32::try_from(i).unwrap());
        assert_eq!(reply_types(&mut server), vec![HT_HELLO_VERIFY_REQUEST]);
        assert_still_handshaking(&mut server);
    }
}

/// The cookie is bound to the `ClientHello` it was issued for: with any
/// field changed, the returned cookie no longer verifies.
#[test]
fn cookie_does_not_verify_for_a_changed_client_hello() {
    type Edit = fn(&mut ClientHello);
    let edits: [(&str, Edit); 6] = [
        ("random", |h| h.random[31] ^= 1),
        ("cipher suites", |h| h.cipher_suites.push(0xC02B)),
        ("session id", |h| h.session_id = vec![1]),
        ("version", |h| h.version = DTLS_1_0_VERSION),
        ("use_srtp", |h| {
            h.extensions
                .use_srtp
                .as_mut()
                .unwrap()
                .profiles
                .push(SRTP_AES128_SHA1_80);
        }),
        ("signature_algorithms", |h| {
            h.extensions
                .signature_algorithms
                .as_mut()
                .unwrap()
                .push(SCHEME_P256_SHA256);
        }),
    ];
    for (name, edit) in edits {
        let (mut server, now) = fresh_server();
        let mut puppet = Puppet::new(DtlsRole::Client);
        let first = puppet.client_hello();
        server.assoc.handle_datagram(&first, now);
        puppet.absorb_from(&mut server);
        assert_eq!(puppet.cookie.len(), 32);

        let second = puppet.client_hello();
        let changed = edit_message(&second, HT_CLIENT_HELLO, |body| {
            let mut hello = ClientHello::parse(body).unwrap();
            edit(&mut hello);
            let mut out = Vec::new();
            hello.encode(&mut out).unwrap();
            Some((HT_CLIENT_HELLO, out))
        });
        server.assoc.handle_datagram(&changed, now);
        assert_eq!(
            reply_types(&mut server),
            vec![HT_HELLO_VERIFY_REQUEST],
            "{name}: flight 4 sent for a hello the cookie was not issued for"
        );
        assert_still_handshaking(&mut server);

        // The unchanged hello with the same cookie is accepted.
        server.assoc.handle_datagram(&second, now);
        let types = reply_types(&mut server);
        assert_eq!(types.first(), Some(&HT_SERVER_HELLO), "{name}");
    }
}

/// Cookies are keyed per association: one issued by another association
/// (another call) is worth nothing here.
#[test]
fn cookie_from_another_association_is_refused() {
    let (mut issuer, now) = fresh_server();
    let (mut target, _) = fresh_server();
    let mut puppet = Puppet::new(DtlsRole::Client);
    let first = puppet.client_hello();
    issuer.assoc.handle_datagram(&first, now);
    puppet.absorb_from(&mut issuer);
    let with_cookie = puppet.client_hello();
    target.assoc.handle_datagram(&with_cookie, now);
    assert_eq!(reply_types(&mut target), vec![HT_HELLO_VERIFY_REQUEST]);
    issuer.assoc.handle_datagram(&with_cookie, now);
    assert_eq!(reply_types(&mut issuer).first(), Some(&HT_SERVER_HELLO));
}

/// At most four `HelloVerifyRequest`s per second, each smaller than the
/// hello that asked for it: the cookie exchange cannot be used to flood a
/// spoofed address.
#[test]
fn hello_verify_requests_are_rate_limited() {
    let (mut server, now) = fresh_server();
    let mut puppet = Puppet::new(DtlsRole::Client);
    let hello = puppet.client_hello();
    for _ in 0..50 {
        server.assoc.handle_datagram(&hello, now);
    }
    let replies = server.drain_transmit();
    assert_eq!(replies.len(), 4);
    assert!(replies.iter().all(|r| r.len() < hello.len()));
    for _ in 0..50 {
        server
            .assoc
            .handle_datagram(&hello, now + Duration::from_millis(999));
    }
    assert!(
        server.drain_transmit().is_empty(),
        "HelloVerifyRequest inside the rate-limit window"
    );
    for _ in 0..50 {
        server.assoc.handle_datagram(&hello, now + SECOND);
    }
    assert_eq!(server.drain_transmit().len(), 4);
    assert_still_handshaking(&mut server);
}

/// The `HelloVerifyRequest` answers with the record sequence number and
/// `message_seq` of the hello (RFC 6347 §4.2.1), and identical hellos get
/// identical cookies (stateless).
#[test]
fn hello_verify_request_echoes_sequence_numbers_and_is_stateless() {
    let (mut server, now) = fresh_server();
    let (_, hello, _) = fresh_client();
    let mut body = Vec::new();
    hello.encode(&mut body).unwrap();
    let mut cookies = Vec::new();
    for (record_seq, message_seq) in [(0u64, 0u16), (7, 0), (300, 3)] {
        server.assoc.handle_datagram(
            &message_record(record_seq, HT_CLIENT_HELLO, message_seq, &body),
            now,
        );
        let reply = server.drain_transmit().remove(0);
        let rec = records(&reply).remove(0);
        assert_eq!(rec.seq, record_seq);
        let msg = rec.message().unwrap();
        assert_eq!(msg.seq, message_seq);
        cookies.push(HelloVerifyRequest::parse(&msg.body).unwrap().cookie);
    }
    assert!(cookies.windows(2).all(|w| w[0] == w[1]));
}

// =============================================================================
// Messages out of order
// =============================================================================

/// Handshake messages (type, body) to feed in order.
type Sequence<'a> = Vec<(u8, &'a [u8])>;

/// Server messages that arrive where another is due. The client fails with
/// `ProtocolViolation` and `unexpected_message` within one retransmission
/// interval (SEC-010: not at once, the message is in the clear); it never
/// skips a step.
#[test]
fn client_fails_on_out_of_order_server_messages() {
    let hello = server_hello_body();
    let certificate = certificate_body(vec![identity_parts().0]);
    let cases: [(&str, Sequence<'_>); 6] = [
        ("ServerHelloDone first", vec![(HT_SERVER_HELLO_DONE, &[])]),
        ("Certificate first", vec![(HT_CERTIFICATE, &certificate)]),
        (
            "ServerHelloDone straight after ServerHello",
            vec![(HT_SERVER_HELLO, &hello), (HT_SERVER_HELLO_DONE, &[])],
        ),
        (
            "ServerKeyExchange in place of Certificate",
            vec![
                (HT_SERVER_HELLO, &hello),
                (HT_SERVER_KEY_EXCHANGE, &[3, 0, 24, 1, 4]),
            ],
        ),
        (
            "second ServerHello",
            vec![(HT_SERVER_HELLO, &hello), (HT_SERVER_HELLO, &hello)],
        ),
        (
            "a client message (ClientKeyExchange) from the server",
            vec![(HT_SERVER_HELLO, &hello), (HT_CLIENT_KEY_EXCHANGE, &[1, 4])],
        ),
    ];
    for (name, sequence) in cases {
        let (mut client, _, now) = fresh_client();
        for (seq, (msg_type, body)) in sequence.iter().enumerate() {
            let seq = u16::try_from(seq).unwrap();
            client
                .assoc
                .handle_datagram(&message_record(u64::from(seq), *msg_type, seq, body), now);
        }
        assert!(client.drain_transmit().is_empty(), "{name}: answered");
        expire_retransmission_timer(&mut client, now);
        assert_eq!(
            client.failed,
            Some(FailureCause::ProtocolViolation),
            "{name}"
        );
        assert_side_failed(&client, FailureCause::ProtocolViolation);
        let sent = client.drain_transmit();
        assert_eq!(
            records(sent.last().unwrap())[0].payload,
            vec![alert::LEVEL_FATAL, alert::UNEXPECTED_MESSAGE],
            "{name}"
        );
    }
}

/// The server's certificate flight skipped: the certificate was accepted
/// but `ServerHelloDone` arrives where the signed key exchange is due. The
/// client must not go on without the server's proof of possession.
#[test]
fn client_fails_when_the_server_skips_its_key_exchange() {
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir != Dir::ServerToClient {
            return Wire::Deliver;
        }
        // Keep ServerHello and Certificate; renumber ServerHelloDone into
        // the ServerKeyExchange slot; drop the rest.
        let mut out = Vec::new();
        let mut slot = None;
        for rec in records(datagram) {
            match rec.message() {
                Some(m) if m.msg_type == HT_SERVER_KEY_EXCHANGE => slot = Some(m.seq),
                Some(m) if m.msg_type == HT_CERTIFICATE_REQUEST => {}
                Some(m) if m.msg_type == HT_SERVER_HELLO_DONE => {
                    out.extend(message_record(rec.seq, m.msg_type, slot.unwrap(), &m.body));
                }
                _ => out.extend(rec.encode()),
            }
        }
        Wire::replace(out)
    });
    assert_eq!(lo.client.failed, Some(FailureCause::ProtocolViolation));
    lo.assert_no_keys();
    assert!(find_message(&lo.log, Dir::ClientToServer, HT_CLIENT_KEY_EXCHANGE).is_none());
}

#[test]
fn server_fails_on_out_of_order_client_messages() {
    // CertificateVerify where ClientKeyExchange is due: swap the two types.
    let mut lo = Loopback::new();
    lo.run(|dir, _, datagram| {
        if dir != Dir::ClientToServer {
            return Wire::Deliver;
        }
        let swapped = edit_message(datagram, HT_CLIENT_KEY_EXCHANGE, |body| {
            Some((HT_CERTIFICATE_VERIFY, body.to_vec()))
        });
        Wire::replace(swapped)
    });
    assert_eq!(lo.server.failed, Some(FailureCause::ProtocolViolation));
    assert_eq!(
        lo.client.failed,
        Some(FailureCause::PeerAlert(alert::UNEXPECTED_MESSAGE))
    );
    lo.assert_no_keys();

    // A second ClientHello where the Certificate is due.
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    let hello = puppet.client_hello();
    server.assoc.handle_datagram(&hello, now);
    expire_retransmission_timer(&mut server, now);
    assert_side_failed(&server, FailureCause::BadCertificate);
}

/// `ChangeCipherSpec` early, repeated or malformed is dropped; it never
/// switches the read epoch before the keys exist, and the handshake still
/// completes.
#[test]
fn early_and_repeated_change_cipher_spec_is_dropped() {
    let ccs = |seq: u64, body: &[u8]| {
        raw_record(
            ContentType::ChangeCipherSpec as u8,
            DTLS_1_2_VERSION,
            0,
            seq,
            body,
        )
    };
    let mut lo = Loopback::new();
    lo.run(|_, index, datagram| {
        Wire::Replace(vec![
            ccs(index as u64, &[1]),
            ccs(index as u64, &[1]),
            ccs(index as u64, &[0]),
            datagram.to_vec(),
            ccs(index as u64, &[1]),
        ])
    });
    lo.assert_connected();
}

/// A server that does not ask for a client certificate is still
/// authenticated by the client (fingerprint and signed key exchange); the
/// client then sends neither `Certificate` nor `CertificateVerify`.
/// Mutual authentication is enforced by the *server* role only; the client
/// role reports whether it was asked (`client_certificate_requested`).
#[test]
fn client_role_completes_when_the_server_requests_no_certificate() {
    let (client, puppet, _) = handshake_with_puppet_server(|p| {
        p.script.omit_certificate_request = true;
    });
    assert_puppet_connected(&client, &puppet);
    let types: Vec<u8> = puppet.seen.iter().map(|m| m.msg_type).collect();
    assert_eq!(
        types,
        vec![HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED]
    );
    // The driver can tell that this handshake authenticated the server only.
    assert!(!client.assoc.client_certificate_requested());
}

// =============================================================================
// Timers and configuration: every accepted key is enforced
// =============================================================================

/// Server role against a client that goes silent after the cookie exchange:
/// flight 4 is retransmitted at 1, 3 and 7 s, then the budget ends it.
#[test]
fn server_times_out_a_client_that_goes_silent() {
    let (mut server, _, start) = puppet_client_until_flight4(|_| {});
    let mut sends = Vec::new();
    let mut now = start;
    while let Some(next) = server.assoc.poll_timeout() {
        now = next;
        server.assoc.handle_timeout(now);
        if !server.drain_transmit().is_empty() {
            sends.push((now - start).as_secs());
        }
        server.drain_events();
    }
    assert_eq!(sends, vec![1, 3, 7]);
    assert_eq!(now - start, Duration::from_secs(10));
    assert_side_failed(&server, FailureCause::Timeout);
    assert_eq!(server.assoc.stats().retransmits, 3);
}

/// A server nobody ever talks to still ends at the budget.
#[test]
fn idle_server_times_out_at_the_budget() {
    let (mut server, start) = fresh_server();
    assert_eq!(
        server.assoc.poll_timeout(),
        Some(start + Duration::from_secs(10))
    );
    server
        .assoc
        .handle_timeout(start + Duration::from_nanos(9_999_999_999));
    assert_still_handshaking(&mut server);
    server.assoc.handle_timeout(start + Duration::from_secs(10));
    server.drain_events();
    assert_side_failed(&server, FailureCause::Timeout);
    assert!(server.drain_transmit().is_empty(), "no alert to nobody");
}

/// The budget also binds when the driver never calls `handle_timeout`: a
/// datagram that arrives late cannot complete the handshake.
#[test]
fn datagram_after_the_budget_cannot_complete_the_handshake() {
    let mut lo = Loopback::new();
    // Cookie exchange, then the server's certificate flight is produced in
    // time but reaches the client only when the budget is over.
    lo.pump(&mut deliver);
    for datagram in lo.client.drain_transmit() {
        lo.server.assoc.handle_datagram(&datagram, lo.now);
    }
    let flight = lo.server.drain_transmit();
    assert_eq!(flight.len(), 1, "the server's certificate flight");
    let late = lo.start + Duration::from_secs(10);
    for datagram in &flight {
        lo.client.assoc.handle_datagram(datagram, late);
    }
    lo.client.drain_events();
    assert_side_failed(&lo.client, FailureCause::Timeout);
    assert!(
        lo.client.drain_transmit().is_empty(),
        "sent a flight after the budget"
    );
}

/// `handshake_budget` and `initial_rto` are honoured as configured.
#[test]
fn configured_budget_and_retransmission_interval_are_enforced() {
    let mut lo = Loopback::with(|client, _| {
        client.initial_rto = Duration::from_millis(100);
        client.handshake_budget = Duration::from_millis(2500);
    });
    let mut sends = vec![0u128];
    lo.client.drain_transmit();
    let start = lo.start;
    let mut now = start;
    while let Some(next) = lo.client.assoc.poll_timeout() {
        now = next;
        lo.client.assoc.handle_timeout(now);
        if !lo.client.drain_transmit().is_empty() {
            sends.push((now - start).as_millis());
        }
        lo.client.drain_events();
    }
    assert_eq!(sends, vec![0, 100, 300, 700, 1500]);
    assert_eq!(now - start, Duration::from_millis(2500));
    assert_side_failed(&lo.client, FailureCause::Timeout);
}

/// The retransmission interval stops doubling at 8 s.
#[test]
fn retransmission_interval_is_capped_at_eight_seconds() {
    let mut lo = Loopback::with(|client, _| {
        client.handshake_budget = Duration::from_secs(60);
    });
    lo.client.drain_transmit();
    let start = lo.start;
    let mut sends = Vec::new();
    while let Some(next) = lo.client.assoc.poll_timeout() {
        lo.client.assoc.handle_timeout(next);
        if !lo.client.drain_transmit().is_empty() {
            sends.push((next - start).as_secs());
        }
        lo.client.drain_events();
    }
    assert_eq!(sends, vec![1, 3, 7, 15, 23, 31, 39, 47, 55]);
    assert_side_failed(&lo.client, FailureCause::Timeout);
}

/// `mtu` is enforced on every datagram either role sends, including
/// retransmissions and the protected `Finished`.
#[test]
fn configured_mtu_bounds_every_datagram() {
    for mtu in [576u16, 577, 600, 1200, 1500] {
        let mut lo = Loopback::with(|client, server| {
            client.mtu = mtu;
            server.mtu = mtu;
        });
        // Lose one datagram each way so retransmissions are measured too.
        lo.run(|dir, index, _| match (dir, index) {
            (Dir::ClientToServer, 2) | (Dir::ServerToClient, 1) => Wire::Drop,
            _ => Wire::Deliver,
        });
        lo.assert_connected();
        let largest = lo.log.iter().map(|(_, d)| d.len()).max().unwrap();
        assert!(
            largest <= usize::from(mtu),
            "mtu {mtu}: sent {largest} bytes"
        );
    }
}

/// Defect D1 (qa-report.md), fixed: every MTU the configuration accepts can
/// complete a handshake against our own server role.
///
/// The minimum was 128, but a `ClientHello` with the cookie is 141 bytes,
/// and the server role drops a fragmented first `ClientHello`
/// (`association.rs`, `on_initial_record`), so 128..=140 could only time
/// out. The minimum is now 576 (`flight::MIN_MTU`); everything below is
/// refused at construction, and everything from there up connects.
#[test]
fn every_accepted_mtu_can_complete_a_handshake() {
    assert_eq!(proto_dtls::flight::MIN_MTU, 576);
    let base = |mtu: u16| {
        let mut config = AssociationConfig::new(
            DtlsRole::Client,
            identity(),
            vec![identity().fingerprint().clone()],
        );
        config.mtu = mtu;
        DtlsAssociation::new(config, Instant::now())
    };
    for mtu in (0u16..576).step_by(5).chain([128, 140, 141, 160, 575]) {
        assert!(base(mtu).is_err(), "mtu {mtu} accepted");
    }

    let mut failing = Vec::new();
    for mtu in (576u16..=608).chain([700, 900, 1199, 1200, 1499, 1500]) {
        let mut lo = Loopback::with(|client, server| {
            client.mtu = mtu;
            server.mtu = mtu;
        });
        lo.run(deliver);
        if lo.client.keys.is_none() || lo.server.keys.is_none() {
            failing.push(mtu);
        }
        let largest = lo.log.iter().map(|(_, d)| d.len()).max().unwrap();
        assert!(largest <= usize::from(mtu));
        // The first ClientHello with a cookie is never fragmented.
        let hello = find_message(&lo.log, Dir::ClientToServer, HT_CLIENT_HELLO);
        assert!(hello.is_some(), "mtu {mtu}: fragmented ClientHello");
        assert_eq!(lo.client.assoc.stats().transmit_dropped, 0);
        assert_eq!(lo.server.assoc.stats().transmit_dropped, 0);
    }
    assert!(
        failing.is_empty(),
        "accepted MTU values that can never complete a handshake: {failing:?}"
    );
}

/// `peer_fingerprints` is enforced per entry, and a sha-256 fingerprint is
/// not accepted by the strict SDP parser the client uses.
#[test]
fn peer_fingerprint_set_is_enforced() {
    let unrelated = || identity().fingerprint().clone();
    // Several wrong ones: still a mismatch.
    let mut lo = Loopback::with(|client, _| {
        client.peer_fingerprints = vec![unrelated(), unrelated(), unrelated()];
    });
    lo.run(deliver);
    assert_eq!(lo.client.failed, Some(FailureCause::FingerprintMismatch));
    lo.assert_no_keys();

    // A sha-512 fingerprint of the right certificate is accepted.
    let server_id = identity();
    let client_id = identity();
    let sha512 = CertificateFingerprint::from_certificate_sha512(&server_id.certificate_chain()[0]);
    let now = Instant::now();
    let mut client = Side::new(
        AssociationConfig::new(DtlsRole::Client, client_id.clone(), vec![sha512]),
        now,
    );
    let mut server = Side::new(
        AssociationConfig::new(
            DtlsRole::Server,
            server_id,
            vec![client_id.fingerprint().clone()],
        ),
        now,
    );
    for _ in 0..8 {
        for datagram in client.drain_transmit() {
            server.assoc.handle_datagram(&datagram, now);
        }
        for datagram in server.drain_transmit() {
            client.assoc.handle_datagram(&datagram, now);
        }
    }
    client.drain_events();
    server.drain_events();
    assert!(client.keys.is_some() && server.keys.is_some());

    let sha256 = "sha-256 ".to_string() + &["AB"; 32].join(":");
    assert!(CertificateFingerprint::from_sdp_strict(&sha256).is_err());
    let sha1 = "sha-1 ".to_string() + &["AB"; 20].join(":");
    assert!(CertificateFingerprint::from_sdp_strict(&sha1).is_err());
}

/// `role` decides who speaks first, and two associations in the same role
/// never connect.
#[test]
fn role_is_enforced() {
    let (a, b) = (identity(), identity());
    let now = Instant::now();
    for role in [DtlsRole::Client, DtlsRole::Server] {
        let mut x = Side::new(
            AssociationConfig::new(role, a.clone(), vec![b.fingerprint().clone()]),
            now,
        );
        let mut y = Side::new(
            AssociationConfig::new(role, b.clone(), vec![a.fingerprint().clone()]),
            now,
        );
        assert_eq!(x.assoc.role(), role);
        let first = x.drain_transmit();
        assert_eq!(first.len(), usize::from(role == DtlsRole::Client));
        for _ in 0..8 {
            for datagram in first.iter().cloned().chain(x.drain_transmit()) {
                y.assoc.handle_datagram(&datagram, now);
            }
            for datagram in y.drain_transmit() {
                x.assoc.handle_datagram(&datagram, now);
            }
        }
        x.drain_events();
        y.drain_events();
        assert!(x.keys.is_none() && y.keys.is_none());
        assert!(!x.assoc.is_connected() && !y.assoc.is_connected());
    }
}

/// Constructing an association never yields a usable one for a config the
/// profile cannot honour.
#[test]
fn invalid_configuration_is_refused_at_construction() {
    type Edit = fn(&mut AssociationConfig);
    let peer = identity().fingerprint().clone();
    let base = || AssociationConfig::new(DtlsRole::Server, identity(), vec![peer.clone()]);
    let now = Instant::now();
    let invalid: [(&str, Edit); 11] = [
        ("no fingerprints", |c| c.peer_fingerprints.clear()),
        ("mtu 0", |c| c.mtu = 0),
        ("mtu 127", |c| c.mtu = 127),
        ("mtu 575", |c| c.mtu = 575),
        ("mtu 1501", |c| c.mtu = 1501),
        ("rto 0", |c| c.initial_rto = Duration::ZERO),
        ("rto below 50 ms", |c| {
            c.initial_rto = Duration::from_micros(49_999);
        }),
        ("peer binding of 65 bytes", |c| c.peer_binding = vec![7; 65]),
        ("rto above 8 s", |c| {
            c.initial_rto = Duration::from_millis(8001);
        }),
        ("budget 0", |c| c.handshake_budget = Duration::ZERO),
        ("budget above 60 s", |c| {
            c.handshake_budget = Duration::from_millis(60_001);
        }),
    ];
    for (name, edit) in invalid {
        let mut config = base();
        edit(&mut config);
        assert!(DtlsAssociation::new(config, now).is_err(), "{name}");
    }
    let valid: [Edit; 7] = [
        |c| c.mtu = 1500,
        |c| c.mtu = 576,
        |c| c.initial_rto = Duration::from_millis(50),
        |c| c.peer_binding = vec![7; 64],
        |c| c.initial_rto = Duration::from_secs(8),
        |c| c.handshake_budget = Duration::from_secs(60),
        |c| c.handshake_budget = Duration::from_millis(1),
    ];
    for edit in valid {
        let mut config = base();
        edit(&mut config);
        assert!(DtlsAssociation::new(config, now).is_ok());
    }
}

/// Stage 1 changes no client behaviour: the legacy `DtlsSession` still
/// fails closed with a real identity and a signalled fingerprint, and names
/// the POA&M. (An integration test links the library without `cfg(test)`,
/// so this holds with and without `--all-features`.)
// The deprecated legacy constructor is the thing under test.
#[allow(deprecated)]
#[tokio::test]
async fn legacy_dtls_session_still_fails_closed() {
    let (cert, key) = identity_parts();
    let fingerprints = vec![identity().fingerprint().clone()];
    for is_client in [true, false] {
        let config = proto_dtls::DtlsConfig::new(DtlsRole::Client)
            .with_identity(vec![cert.clone()], key.pkcs8_bytes().to_vec());
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = proto_dtls::DtlsSession::new(
            &config,
            std::sync::Arc::new(socket),
            is_client,
            &fingerprints,
        )
        .await;
        let error = result.expect_err("DtlsSession::new must fail closed");
        assert!(
            matches!(error, proto_dtls::DtlsError::HandshakeFailed { .. }),
            "{error}"
        );
        // The text says what to use instead and names no tracking item.
        assert!(error.to_string().contains("legacy DtlsSession"), "{error}");
        assert!(!error.to_string().contains("POA&M"), "{error}");
    }
}

// =============================================================================
// Round 1 review: final-flight retention, resend limits, counters, cookie binding
// =============================================================================

/// A handshake record in epoch 1 that repeats the client's `Finished`
/// (`message_seq` 5), sealed with a fresh record sequence number -- what a
/// client that never saw the server's last flight keeps sending.
fn retransmitted_client_finished(puppet: &mut Puppet) -> Vec<u8> {
    let message = Msg {
        msg_type: HT_FINISHED,
        seq: 5,
        body: vec![0; 12],
    };
    puppet.seal(1, ContentType::Handshake, &message.encode())
}

/// RFC 6347 §4.2.4 (RFC-001): the server keeps its final flight for 240 s
/// (2 x MSL) and answers a retransmitted client `Finished` with it for all
/// of that time. Flight 6 is lost here; the client's retransmissions at
/// T+30 s, T+200 s and just before T+240 s each get the flight, which the
/// client can verify. After 240 s the flight is gone.
#[test]
fn server_keeps_its_final_flight_for_240_seconds() {
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    let flight5 = puppet.client_flight5();
    server.assoc.handle_datagram(&flight5, now);
    server.drain_events();
    assert!(server.assoc.is_connected());
    // Flight 6 is lost.
    assert_eq!(server.drain_transmit().len(), 1);
    assert_eq!(puppet.peer_finished_ok, None);
    assert_eq!(
        server.assoc.poll_timeout(),
        Some(now + Duration::from_secs(240)),
        "poll_timeout must cover the retention"
    );

    let mut resends = 0u32;
    for at in [
        Duration::from_secs(30),
        Duration::from_secs(200),
        Duration::from_millis(239_900),
    ] {
        // Timers in between change nothing.
        server.assoc.handle_timeout(now + at);
        let retransmission = retransmitted_client_finished(&mut puppet);
        server.assoc.handle_datagram(&retransmission, now + at);
        let sent = server.drain_transmit();
        assert_eq!(sent.len(), 1, "no flight 6 at T+{at:?}");
        resends += 1;
        let types: Vec<ContentType> = records(&sent[0]).iter().map(|r| r.content_type).collect();
        assert_eq!(
            types,
            vec![ContentType::ChangeCipherSpec, ContentType::Handshake]
        );
        assert_eq!(records(&sent[0])[1].epoch, 1);
        assert_eq!(server.assoc.stats().retransmits, resends);
        assert_eq!(
            server.assoc.poll_timeout(),
            Some(now + Duration::from_secs(240))
        );
        if resends == 1 {
            // The client finally gets, and verifies, the server Finished.
            puppet.absorb(&sent[0]);
            assert_eq!(puppet.peer_finished_ok, Some(true));
        }
    }

    // The hold-off is still the rate limit: a second retransmission within
    // half the initial interval (500 ms) gets nothing.
    let at = Duration::from_millis(239_950);
    let retransmission = retransmitted_client_finished(&mut puppet);
    server.assoc.handle_datagram(&retransmission, now + at);
    assert!(server.drain_transmit().is_empty(), "hold-off ignored");

    // After 2 x MSL the flight is freed and no timer is left.
    server.assoc.handle_timeout(now + Duration::from_secs(240));
    assert_eq!(server.assoc.poll_timeout(), None);
    let retransmission = retransmitted_client_finished(&mut puppet);
    server
        .assoc
        .handle_datagram(&retransmission, now + Duration::from_secs(241));
    assert!(server.drain_transmit().is_empty(), "sent something");
    assert!(server.assoc.is_connected());
    server.drain_events();
    assert_eq!(server.failed, None);
    assert_eq!(server.connected_events, 1);
}

/// SEC-003 / PERF-005 / SEC-014: a stale 25-byte plaintext fragment makes
/// the server resend its whole certificate flight, so that is limited: not
/// within half the *initial* interval of the last transmission, and at most
/// six times per flight. The trigger is unauthenticated, so it leaves the
/// retransmission timer alone: the interval is not backed off and the
/// deadline does not move, whatever the flood does.
#[test]
fn peer_triggered_retransmission_is_held_off_and_capped_and_leaves_the_timer_alone() {
    let (mut server, _, start) = puppet_client_until_flight4(|_| {});
    // Anything with a message_seq the server has already processed.
    let stale = fragment_record(3, &header(HT_CLIENT_HELLO, 100, 0, 0, 0), &[]);
    let ms = Duration::from_millis;

    // Inside the hold-off (500 ms after the flight went out): nothing.
    server.assoc.handle_datagram(&stale, start + ms(499));
    assert!(server.drain_transmit().is_empty(), "sent something");
    assert_eq!(server.assoc.poll_timeout(), Some(start + SECOND));

    // After it: the flight. The timer is where it was.
    server.assoc.handle_datagram(&stale, start + ms(500));
    assert_eq!(server.drain_transmit().len(), 1);
    assert_eq!(server.assoc.stats().retransmits, 1);
    assert_eq!(server.assoc.poll_timeout(), Some(start + SECOND));

    // A flood, one fragment every 100 ms. The driver is late with the
    // timer, so only the flood acts: five more flights, 500 ms apart, then
    // the cap, and the deadline never moves.
    let mut at = ms(500);
    let mut flights = 0;
    for _ in 0..45 {
        at += ms(100);
        server.assoc.handle_datagram(&stale, start + at);
        let sent = server.drain_transmit().len();
        assert!(sent <= 1);
        if sent == 1 {
            assert_eq!(at.as_millis() % 500, 0, "inside the hold-off");
        }
        flights += sent;
        assert_eq!(server.assoc.poll_timeout(), Some(start + SECOND));
    }
    assert_eq!(at, ms(5000));
    assert_eq!(flights, 5);
    assert_eq!(server.assoc.stats().retransmits, 6);
    assert_still_handshaking(&mut server);

    // The timer still works, and its interval was not stretched: this is
    // its first expiry, so the next one is 2 s later (not 8 s).
    server.assoc.handle_timeout(start + at);
    assert_eq!(server.drain_transmit().len(), 1);
    assert_eq!(server.assoc.stats().retransmits, 7);
    assert_eq!(server.assoc.poll_timeout(), Some(start + at + SECOND * 2));
    assert_still_handshaking(&mut server);
}

/// SEC-014: forged stale fragments cannot put off the moment a pending
/// failure is acted on. A genuine alert is still reported when the timer
/// set by our own flight expires, flood or no flood.
#[test]
fn peer_triggered_retransmission_does_not_postpone_a_pending_failure() {
    let (mut server, _, start) = puppet_client_until_flight4(|_| {});
    let stale = fragment_record(3, &header(HT_CLIENT_HELLO, 100, 0, 0, 0), &[]);
    let ms = Duration::from_millis;
    server.assoc.handle_datagram(
        &plaintext_alert(5, alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
        start,
    );
    for at in (100..1000).step_by(100) {
        server.assoc.handle_datagram(&stale, start + ms(at));
        assert_eq!(server.assoc.poll_timeout(), Some(start + SECOND));
    }
    assert_eq!(server.assoc.stats().retransmits, 1);
    assert_still_handshaking(&mut server);
    server.assoc.handle_timeout(start + SECOND);
    server.drain_events();
    assert_side_failed(&server, FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE));
}

/// SEC-003: the configured interval has a floor of 50 ms, which is also the
/// floor of the hold-off (25 ms).
#[test]
fn initial_retransmission_interval_has_a_floor() {
    assert_eq!(
        proto_dtls::association::MIN_INITIAL_RTO,
        Duration::from_millis(50)
    );
    let config = |rto: Duration| {
        let mut config = AssociationConfig::new(
            DtlsRole::Client,
            identity(),
            vec![identity().fingerprint().clone()],
        );
        config.initial_rto = rto;
        config
    };
    let now = Instant::now();
    for too_short in [0u64, 1, 10, 49] {
        assert!(DtlsAssociation::new(config(Duration::from_millis(too_short)), now).is_err());
    }
    let mut client = Side::new(config(Duration::from_millis(50)), now);
    assert_eq!(
        client.assoc.poll_timeout(),
        Some(now + Duration::from_millis(50))
    );
    client.assoc.handle_timeout(now + Duration::from_millis(50));
    assert_eq!(client.assoc.stats().retransmits, 1);
    assert_still_handshaking(&mut client);
}

/// PERF-002: a `ChangeCipherSpec` or a protected record that arrives before
/// the handshake is ready for it (reordering) is dropped, not buffered, and
/// has its own counter.
#[test]
fn early_change_cipher_spec_and_finished_have_their_own_counter() {
    let (mut server, _, now) = puppet_client_until_flight4(|_| {});
    let before = server.assoc.stats();
    let ccs = raw_record(
        ContentType::ChangeCipherSpec as u8,
        DTLS_1_2_VERSION,
        0,
        9,
        &[1],
    );
    let finished = raw_record(
        ContentType::Handshake as u8,
        DTLS_1_2_VERSION,
        1,
        0,
        &[0x5A; 48],
    );
    server.assoc.handle_datagram(&ccs, now);
    server.assoc.handle_datagram(&finished, now);
    let mut both = ccs.clone();
    both.extend(&finished);
    server.assoc.handle_datagram(&both, now);
    assert_still_handshaking(&mut server);
    let after = server.assoc.stats();
    assert_eq!(after.early_ccs_or_finished, 4);
    assert_eq!(after.records_discarded, before.records_discarded);
    assert_eq!(after.fragments_rejected, before.fragments_rejected);

    // After completion a stray ChangeCipherSpec is an ordinary discard.
    let (mut client, _, now) = handshake_with_puppet_server(|_| {});
    let before = client.assoc.stats();
    client.assoc.handle_datagram(&ccs, now);
    let after = client.assoc.stats();
    assert_eq!(after.early_ccs_or_finished, before.early_ccs_or_finished);
    assert_eq!(after.records_discarded, before.records_discarded + 1);
}

/// PERF-003: the transmit queue holds 64 datagrams; what a caller that does
/// not drain it loses is counted in `transmit_dropped`.
#[test]
fn undrained_transmit_queue_overflow_is_counted() {
    let mut config = AssociationConfig::new(
        DtlsRole::Server,
        identity(),
        vec![identity().fingerprint().clone()],
    );
    config.handshake_budget = Duration::from_secs(60);
    let now = Instant::now();
    let mut server = Side::new(config, now);
    let mut puppet = Puppet::new(DtlsRole::Client);
    // Four HelloVerifyRequests a second is the rate limit; 20 seconds of it.
    for second in 0..20u32 {
        for _ in 0..4 {
            puppet.cookie = Vec::new();
            let hello = puppet.client_hello();
            server.assoc.handle_datagram(&hello, now + SECOND * second);
        }
    }
    assert_eq!(server.assoc.stats().transmit_dropped, 16);
    assert_eq!(server.drain_transmit().len(), 64);
    assert_still_handshaking(&mut server);
}

/// SEC-005 / RFC-007: `peer_binding` is mixed into the cookie. A handshake
/// with a binding on the server completes as usual, and its cookie differs
/// from what an association without the binding (or with another one)
/// would accept: replayed there, it only gets another `HelloVerifyRequest`.
#[test]
fn cookie_is_bound_to_the_configured_peer_binding() {
    let mut lo = Loopback::with(|client, server| {
        client.peer_binding = b"198.51.100.7:40000".to_vec();
        server.peer_binding = b"192.0.2.1:5004".to_vec();
    });
    lo.run(deliver);
    lo.assert_connected();

    // The same ClientHello, cookie and all, at a server bound elsewhere.
    let with_cookie = lo
        .log
        .iter()
        .filter(|(dir, _)| *dir == Dir::ClientToServer)
        .nth(1)
        .map(|(_, datagram)| datagram.clone())
        .unwrap();
    assert_eq!(
        ClientHello::parse(&messages(&with_cookie)[0].body)
            .unwrap()
            .cookie
            .len(),
        32
    );
    for binding in [&b""[..], b"192.0.2.1:5005", b"192.0.2.2:5004"] {
        let (mut other, now) = fresh_server();
        let mut config = AssociationConfig::new(
            DtlsRole::Server,
            identity(),
            vec![identity().fingerprint().clone()],
        );
        config.peer_binding = binding.to_vec();
        other.assoc = DtlsAssociation::new(config, now).unwrap();
        other.assoc.handle_datagram(&with_cookie, now);
        assert_eq!(reply_types(&mut other), vec![HT_HELLO_VERIFY_REQUEST]);
        assert_still_handshaking(&mut other);
    }
}

/// PERF-008: once the `HelloVerifyRequest` rate is used up, a `ClientHello`
/// without a usable cookie is dropped before it is parsed or authenticated -- and a
/// client that does hold a valid cookie is still served during the flood.
#[test]
fn cookie_holders_are_served_while_the_hello_verify_rate_is_exhausted() {
    let (mut server, now) = fresh_server();
    let mut puppet = Puppet::new(DtlsRole::Client);
    let first = puppet.client_hello();
    server.assoc.handle_datagram(&first, now);
    puppet.absorb_from(&mut server);
    assert_eq!(puppet.cookie.len(), 32);

    // A flood of cookie-less hellos uses up the rate (4 per second).
    let mut flood = Puppet::new(DtlsRole::Client);
    for _ in 0..50 {
        flood.cookie = Vec::new();
        let hello = flood.client_hello();
        server.assoc.handle_datagram(&hello, now);
    }
    assert_eq!(server.drain_transmit().len(), 3, "rate limit");

    // The real client's second ClientHello still gets the server flight.
    let second = puppet.client_hello();
    server.assoc.handle_datagram(&second, now);
    let types = reply_types(&mut server);
    assert_eq!(types.first(), Some(&HT_SERVER_HELLO));
    assert_still_handshaking(&mut server);
}

// =============================================================================
// SEC-010: forged complete plaintext messages, at or parked ahead of their
// message_seq, do not end a handshake whose genuine messages arrive
// =============================================================================

/// What the forger sends: one whole plaintext handshake message, with a
/// record sequence number well away from the peer's own.
fn forged(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    message_record(40, msg_type, message_seq, body)
}

/// Client role, forged zero-length messages of (a) an unknown type, (b)
/// `HelloRequest`, (c) types that are valid only in another state or role,
/// at each `message_seq` from the next expected one (0) to the edge of the
/// buffering window, injected before the server's genuine flight. The
/// forged message is delivered in sequence the moment the genuine message
/// before it is accepted; it is thrown away without using up its
/// `message_seq`, the genuine message takes its place, and the handshake
/// completes with the keys of the independent key schedule.
#[test]
fn forged_complete_messages_do_not_stop_a_client_handshake() {
    let kinds = [
        ("unknown type", 99),
        ("HelloRequest", HT_HELLO_REQUEST),
        ("Finished (another state, epoch 1 only)", HT_FINISHED),
        ("ClientKeyExchange (another role)", HT_CLIENT_KEY_EXCHANGE),
        ("CertificateVerify (another role)", HT_CERTIFICATE_VERIFY),
        ("ClientHello (another role)", HT_CLIENT_HELLO),
    ];
    for (name, kind) in kinds {
        for seq in 0..=4u16 {
            let now = Instant::now();
            let mut puppet = Puppet::new(DtlsRole::Server);
            let (mut client, _) = puppet.counterpart(now);
            puppet.absorb_from(&mut client);
            client.assoc.handle_datagram(&forged(kind, seq, &[]), now);
            assert_still_handshaking(&mut client);
            assert!(client.drain_transmit().is_empty(), "{name} at {seq}");

            let flight4 = puppet.server_flight4();
            client.assoc.handle_datagram(&flight4, now);
            puppet.absorb_from(&mut client);
            assert_eq!(puppet.peer_finished_ok, Some(true), "{name} at {seq}");
            let flight6 = puppet.server_flight6();
            client.assoc.handle_datagram(&flight6, now);
            client.drain_events();
            assert_puppet_connected(&client, &puppet);
            let stats = client.assoc.stats();
            assert_eq!(stats.fragments_rejected, 1, "{name} at {seq}");
            assert_eq!(stats.retransmits, 0, "{name} at {seq}");
            assert!(puppet.alerts.is_empty(), "{name} at {seq}");
        }
    }
}

/// The same in the server role, after its flight 4: the client's messages
/// are due at `message_seq` 2 (`Certificate`) to 5 (`Finished`). A forged
/// message parked in the `Finished` slot or beyond is purged at the cipher
/// change (and counted then).
#[test]
fn forged_complete_messages_do_not_stop_a_server_handshake() {
    let kinds = [
        ("unknown type", 99),
        ("HelloRequest", HT_HELLO_REQUEST),
        ("Finished (another state, epoch 1 only)", HT_FINISHED),
        ("ServerHello (another role)", HT_SERVER_HELLO),
        ("ServerHelloDone (another role)", HT_SERVER_HELLO_DONE),
        ("ClientHello (another state)", HT_CLIENT_HELLO),
    ];
    for (name, kind) in kinds {
        for seq in 2..=6u16 {
            let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
            server.assoc.handle_datagram(&forged(kind, seq, &[]), now);
            assert_still_handshaking(&mut server);
            assert!(server.drain_transmit().is_empty(), "{name} at {seq}");

            let flight5 = puppet.client_flight5();
            server.assoc.handle_datagram(&flight5, now);
            server.drain_events();
            puppet.absorb_from(&mut server);
            assert_puppet_connected(&server, &puppet);
            let stats = server.assoc.stats();
            assert_eq!(stats.fragments_rejected, 1, "{name} at {seq}");
            assert_eq!(stats.retransmits, 0, "{name} at {seq}");
            assert!(puppet.alerts.is_empty(), "{name} at {seq}");
        }
    }
}

/// `count` forged zero-length messages of an unknown type, all at
/// `message_seq`, in one datagram of `records` plaintext records.
fn forged_burst(count: usize, records: usize, message_seq: u16, first_record_seq: u64) -> Vec<u8> {
    let forged_message = Msg {
        msg_type: 99,
        seq: message_seq,
        body: Vec::new(),
    }
    .encode();
    let per_record = count.div_ceil(records);
    let mut datagram = Vec::new();
    let mut left = count;
    let mut record_seq = first_record_seq;
    while left > 0 {
        let n = left.min(per_record);
        datagram.extend_from_slice(&raw_record(
            ContentType::Handshake as u8,
            DTLS_1_2_VERSION,
            0,
            record_seq,
            &forged_message.repeat(n),
        ));
        left -= n;
        record_seq += 1;
    }
    datagram
}

/// SEC-015: one forged datagram cannot use up the 64-message limit. Each
/// refused message leaves its `message_seq` open, so the next forged
/// message in the same datagram is delivered and refused in turn; after
/// six refusals the rest of the datagram is ignored. 200 forged messages
/// at the expected sequence number, in one record or spread over the 16
/// records that are looked at, cost six of the 64 and the genuine flight
/// that follows completes the handshake.
#[test]
fn one_forged_datagram_cannot_use_up_the_message_limit_of_a_client() {
    for records in [1usize, 16] {
        let now = Instant::now();
        let mut puppet = Puppet::new(DtlsRole::Server);
        let (mut client, _) = puppet.counterpart(now);
        puppet.absorb_from(&mut client);
        client
            .assoc
            .handle_datagram(&forged_burst(200, records, 0, 40), now);
        assert_still_handshaking(&mut client);
        assert!(client.drain_transmit().is_empty(), "{records} record(s)");
        assert_eq!(client.assoc.stats().fragments_rejected, 6);

        let flight4 = puppet.server_flight4();
        client.assoc.handle_datagram(&flight4, now);
        puppet.absorb_from(&mut client);
        assert_eq!(puppet.peer_finished_ok, Some(true), "{records} record(s)");
        let flight6 = puppet.server_flight6();
        client.assoc.handle_datagram(&flight6, now);
        client.drain_events();
        assert_puppet_connected(&client, &puppet);
        let stats = client.assoc.stats();
        assert_eq!(stats.fragments_rejected, 6, "{records} record(s)");
        assert_eq!(stats.retransmits, 0, "{records} record(s)");
        assert!(puppet.alerts.is_empty(), "{records} record(s)");
    }
}

/// The same in the server role, after its flight 4 (the client's
/// `Certificate` is due at `message_seq` 2).
#[test]
fn one_forged_datagram_cannot_use_up_the_message_limit_of_a_server() {
    for records in [1usize, 16] {
        let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
        server
            .assoc
            .handle_datagram(&forged_burst(200, records, 2, 40), now);
        assert_still_handshaking(&mut server);
        assert!(server.drain_transmit().is_empty(), "{records} record(s)");
        assert_eq!(server.assoc.stats().fragments_rejected, 6);

        let flight5 = puppet.client_flight5();
        server.assoc.handle_datagram(&flight5, now);
        server.drain_events();
        puppet.absorb_from(&mut server);
        assert_puppet_connected(&server, &puppet);
        let stats = server.assoc.stats();
        assert_eq!(stats.fragments_rejected, 6, "{records} record(s)");
        assert_eq!(stats.retransmits, 0, "{records} record(s)");
        assert!(puppet.alerts.is_empty(), "{records} record(s)");
    }
}

/// Nine such datagrams (54 refused messages) still leave room for the
/// genuine handshake, in both roles. This holds here because nothing is
/// parked ahead and the puppet server skips the cookie exchange; with both,
/// nine can reach the limit and eight cannot (see the module doc).
#[test]
fn nine_forged_datagrams_cannot_use_up_the_message_limit() {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _) = puppet.counterpart(now);
    puppet.absorb_from(&mut client);
    for i in 0..9u64 {
        client
            .assoc
            .handle_datagram(&forged_burst(200, 1, 0, 40 + i), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 54);
    let flight4 = puppet.server_flight4();
    client.assoc.handle_datagram(&flight4, now);
    puppet.absorb_from(&mut client);
    let flight6 = puppet.server_flight6();
    client.assoc.handle_datagram(&flight6, now);
    client.drain_events();
    assert_puppet_connected(&client, &puppet);

    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    for i in 0..9u64 {
        server
            .assoc
            .handle_datagram(&forged_burst(200, 1, 2, 40 + i), now);
    }
    assert_still_handshaking(&mut server);
    assert_eq!(server.assoc.stats().fragments_rejected, 54);
    let flight5 = puppet.client_flight5();
    server.assoc.handle_datagram(&flight5, now);
    server.drain_events();
    puppet.absorb_from(&mut server);
    assert_puppet_connected(&server, &puppet);
}

/// The bound must not cost the genuine flight its datagram (the round-1
/// problem): with a forged message parked in every slot ahead, each one
/// is refused in the middle of the genuine flight's single datagram, and
/// that datagram is still processed to its end.
#[test]
fn forged_messages_parked_in_every_slot_ahead_do_not_cost_the_genuine_datagram() {
    let now = Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _) = puppet.counterpart(now);
    puppet.absorb_from(&mut client);
    // Refused at once (0) and parked ahead (1..=4), each in its own datagram.
    for seq in 0..=4u16 {
        client.assoc.handle_datagram(&forged(99, seq, &[]), now);
    }
    assert_still_handshaking(&mut client);
    assert_eq!(client.assoc.stats().fragments_rejected, 1);
    let flight4 = puppet.server_flight4();
    client.assoc.handle_datagram(&flight4, now);
    puppet.absorb_from(&mut client);
    assert_eq!(puppet.peer_finished_ok, Some(true));
    let flight6 = puppet.server_flight6();
    client.assoc.handle_datagram(&flight6, now);
    client.drain_events();
    assert_puppet_connected(&client, &puppet);
    assert_eq!(client.assoc.stats().fragments_rejected, 5);
    assert_eq!(client.assoc.stats().retransmits, 0);

    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    for seq in 2..=6u16 {
        server.assoc.handle_datagram(&forged(99, seq, &[]), now);
    }
    assert_still_handshaking(&mut server);
    let flight5 = puppet.client_flight5();
    server.assoc.handle_datagram(&flight5, now);
    server.drain_events();
    puppet.absorb_from(&mut server);
    assert_puppet_connected(&server, &puppet);
    assert_eq!(server.assoc.stats().fragments_rejected, 5);
    assert_eq!(server.assoc.stats().retransmits, 0);
}

/// Builds a forged datagram from the genuine flight's messages.
type Forgery<'a> = &'a dyn Fn(&[Msg]) -> Vec<u8>;

/// Forged messages of the type that *is* due, where the message can be
/// checked on its own: a `Certificate` the SDP did not name, a
/// `ServerKeyExchange` or `CertificateVerify` whose signature does not
/// verify, and ones that do not parse. Each is refused before it changes
/// anything, so the genuine message that follows is accepted and the
/// handshake completes with the genuine peer's keys and certificate.
#[test]
fn forged_self_authenticating_messages_do_not_stop_a_handshake() {
    let foreign = certificate_body(vec![foreign_certificate(&rcgen::PKCS_ECDSA_P384_SHA384)]);

    // --- client role: Certificate is message 1, ServerKeyExchange 2.
    let flip_last = |body: &[u8]| {
        let mut body = body.to_vec();
        *body.last_mut().unwrap() ^= 0x01;
        body
    };
    let client_cases: [(&str, Forgery<'_>); 5] = [
        ("foreign Certificate", &|_| {
            forged(HT_CERTIFICATE, 1, &foreign)
        }),
        ("empty Certificate", &|_| {
            forged(HT_CERTIFICATE, 1, &[0, 0, 0])
        }),
        ("garbage Certificate", &|_| {
            forged(HT_CERTIFICATE, 1, &[9; 40])
        }),
        ("ServerKeyExchange with a bad signature", &|genuine| {
            forged(HT_SERVER_KEY_EXCHANGE, 2, &flip_last(&genuine[2].body))
        }),
        ("truncated ServerKeyExchange", &|genuine| {
            forged(HT_SERVER_KEY_EXCHANGE, 2, &genuine[2].body[..60])
        }),
    ];
    for (name, forge) in client_cases {
        let now = Instant::now();
        let mut puppet = Puppet::new(DtlsRole::Server);
        let (mut client, _) = puppet.counterpart(now);
        puppet.absorb_from(&mut client);
        let flight4 = puppet.server_flight4();
        let genuine = messages(&flight4);
        assert_eq!(genuine[2].msg_type, HT_SERVER_KEY_EXCHANGE);
        client.assoc.handle_datagram(&forge(&genuine), now);
        assert_still_handshaking(&mut client);

        client.assoc.handle_datagram(&flight4, now);
        puppet.absorb_from(&mut client);
        assert_eq!(puppet.peer_finished_ok, Some(true), "{name}");
        let flight6 = puppet.server_flight6();
        client.assoc.handle_datagram(&flight6, now);
        client.drain_events();
        assert_puppet_connected(&client, &puppet);
        assert_eq!(client.assoc.stats().fragments_rejected, 1, "{name}");
        assert_eq!(
            client.assoc.presented_fingerprint(),
            Some(&puppet.fingerprint()),
            "{name}"
        );
        assert!(puppet.alerts.is_empty(), "{name}");
    }

    // --- server role: Certificate is message 2, CertificateVerify 4.
    let server_cases: [(&str, Forgery<'_>); 4] = [
        ("foreign Certificate", &|_| {
            forged(HT_CERTIFICATE, 2, &foreign)
        }),
        ("garbage Certificate", &|_| {
            forged(HT_CERTIFICATE, 2, &[9; 40])
        }),
        ("CertificateVerify with a bad signature", &|genuine| {
            forged(HT_CERTIFICATE_VERIFY, 4, &flip_last(&genuine[2].body))
        }),
        ("truncated CertificateVerify", &|genuine| {
            forged(HT_CERTIFICATE_VERIFY, 4, &genuine[2].body[..10])
        }),
    ];
    for (name, forge) in server_cases {
        let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
        let flight5 = puppet.client_flight5();
        let genuine = messages(&flight5);
        assert_eq!(genuine[2].msg_type, HT_CERTIFICATE_VERIFY);
        server.assoc.handle_datagram(&forge(&genuine), now);
        assert_still_handshaking(&mut server);

        server.assoc.handle_datagram(&flight5, now);
        server.drain_events();
        puppet.absorb_from(&mut server);
        assert_puppet_connected(&server, &puppet);
        assert_eq!(server.assoc.stats().fragments_rejected, 1, "{name}");
        assert_eq!(
            server.assoc.presented_fingerprint(),
            Some(&puppet.fingerprint()),
            "{name}"
        );
        assert!(puppet.alerts.is_empty(), "{name}");
    }
}

/// Forged messages alone never complete a handshake or export a key,
/// whatever their type and place: without a genuine peer every association
/// ends in a failure, by the time its retransmission timer next expires.
#[test]
fn forged_messages_alone_end_in_failure_never_in_keys() {
    for kind in 0..=30u8 {
        for seq in 0..=4u16 {
            let (mut client, _, now) = fresh_client();
            client.assoc.handle_datagram(&forged(kind, seq, &[]), now);
            client
                .assoc
                .handle_datagram(&forged(kind, seq, &[0; 12]), now);
            let mut at = now;
            for _ in 0..40 {
                if client.settled() {
                    break;
                }
                at += Duration::from_millis(500);
                client.assoc.handle_timeout(at);
                client.drain_events();
            }
            assert!(client.failed.is_some(), "type {kind} at {seq}");
            assert!(client.keys.is_none(), "type {kind} at {seq}");
            assert_eq!(client.connected_events, 0);

            let (mut server, _, now) = puppet_client_until_flight4(|_| {});
            server
                .assoc
                .handle_datagram(&forged(kind, seq + 2, &[]), now);
            server
                .assoc
                .handle_datagram(&forged(kind, seq + 2, &[0; 12]), now);
            let mut at = now;
            for _ in 0..40 {
                if server.settled() {
                    break;
                }
                at += Duration::from_millis(500);
                server.assoc.handle_timeout(at);
                server.drain_events();
            }
            assert!(server.failed.is_some(), "type {kind} at {seq}");
            assert!(server.keys.is_none(), "type {kind} at {seq}");
            assert_eq!(server.connected_events, 0);
        }
    }
}

/// A refused message and a plaintext alert share one pending cause: the
/// first is kept, a `HelloRequest` is no progress and does not clear it
/// (RFC-016), and a driver that only ever feeds datagrams still gets it at
/// the budget instead of `Timeout`.
#[test]
fn pending_failure_keeps_the_first_cause_and_fires_at_the_timer_or_the_budget() {
    // Refused message first, alert second: the message's cause.
    let (mut client, _, now) = fresh_client();
    client.assoc.handle_datagram(&forged(99, 0, &[]), now);
    client.assoc.handle_datagram(
        &plaintext_alert(1, alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
        now,
    );
    client
        .assoc
        .handle_datagram(&forged(HT_HELLO_REQUEST, 0, &[]), now);
    expire_retransmission_timer(&mut client, now);
    assert_side_failed(&client, FailureCause::ProtocolViolation);
    let sent = client.drain_transmit();
    assert_eq!(
        records(sent.last().unwrap())[0].payload,
        vec![alert::LEVEL_FATAL, alert::UNEXPECTED_MESSAGE]
    );

    // Alert first, refused message second: the alert's, and no answer.
    let (mut client, _, now) = fresh_client();
    client.assoc.handle_datagram(
        &plaintext_alert(1, alert::LEVEL_FATAL, alert::HANDSHAKE_FAILURE),
        now,
    );
    client.assoc.handle_datagram(&forged(99, 0, &[]), now);
    client
        .assoc
        .handle_datagram(&forged(HT_HELLO_REQUEST, 0, &[]), now);
    expire_retransmission_timer(&mut client, now);
    assert_side_failed(&client, FailureCause::PeerAlert(alert::HANDSHAKE_FAILURE));
    assert!(client.drain_transmit().is_empty(), "answered an alert");

    // The budget, reached through handle_datagram alone.
    let (mut server, _, now) = puppet_client_until_flight4(|_| {});
    server
        .assoc
        .handle_datagram(&forged(HT_SERVER_HELLO, 2, &[]), now);
    assert_still_handshaking(&mut server);
    server
        .assoc
        .handle_datagram(&forged(99, 2, &[]), now + SECOND * 10);
    server.drain_events();
    assert_side_failed(&server, FailureCause::BadCertificate);
}

/// A refused message is forgotten once the genuine one is accepted: the
/// retransmission timer that expires afterwards retransmits, it does not
/// fail the handshake.
#[test]
fn refused_message_is_forgotten_when_the_handshake_moves_on() {
    let (mut server, mut puppet, now) = puppet_client_until_flight4(|_| {});
    server.assoc.handle_datagram(&forged(99, 2, &[]), now);
    assert_still_handshaking(&mut server);
    // The genuine Certificate alone (the rest of the flight is "lost").
    let certificate = certificate_body(vec![puppet.cert.clone()]);
    let genuine = puppet.handshake(0, HT_CERTIFICATE, &certificate);
    server.assoc.handle_datagram(&genuine, now);
    server.assoc.handle_timeout(now + SECOND);
    assert_still_handshaking(&mut server);
    assert_eq!(server.assoc.stats().retransmits, 1);
    assert_eq!(server.assoc.stats().fragments_rejected, 1);
}
