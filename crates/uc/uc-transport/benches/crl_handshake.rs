//! `crl_handshake`: TLS 1.3 handshake cost with CRL revocation checking
//! (SR-29, POA&M-401 phase (a); `docs/TLS-REVOCATION-DESIGN.md`).
//!
//! In-memory handshake (no sockets) between the CNSA server config and a
//! CNSA client config whose server verifier holds one CRL from the server
//! certificate's issuer with 0 (no CRL configured), 1k and 100k revoked
//! entries. Session resumption is off, so every iteration verifies the
//! server certificate. webpki verifies the CRL signature on every
//! handshake, so the cost grows with the CRL size (100k entries is about
//! 2.1 MB of DER).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustls::pki_types::PrivateKeyDer;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use uc_transport::revocation::{CrlSet, Revocation, RevocationPolicy};
use uc_transport::tls::{
    MinTlsVersion, TlsClientOptions, create_client_config_verified, create_client_config_with,
    create_server_config,
};

const ENTRIES: [usize; 3] = [0, 1_000, 100_000];

struct Fixture {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

fn fixture(entries: usize) -> Fixture {
    let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = p.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate_for(alg).unwrap();
    let mut lp = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    lp.serial_number = Some(rcgen::SerialNumber::from(u64::MAX));
    let leaf = lp.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let server = create_server_config(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let client = if entries == 0 {
        create_client_config_with(TlsClientOptions {
            roots,
            min_version: MinTlsVersion::V1_3,
            client_auth: None,
        })
        .unwrap()
    } else {
        let crl = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2090, 1, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: (1..=entries as u64)
                .map(|s| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(s),
                    revocation_time: rcgen::date_time_ymd(2020, 1, 1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&ca, &ca_key)
        .unwrap();
        let rev = Revocation {
            crls: Arc::new(CrlSet::from_bytes(Path::new("bench"), [crl.der().as_ref()]).unwrap()),
            policy: RevocationPolicy::default(),
        };
        create_client_config_verified(
            rev.server_verifier(Arc::new(roots)).unwrap(),
            MinTlsVersion::V1_3,
            None,
        )
        .unwrap()
    };
    // Every iteration is a full handshake: a resumed session skips
    // certificate verification, and with it the CRL check.
    let mut client = client;
    client.resumption = rustls::client::Resumption::disabled();
    Fixture {
        server: Arc::new(server),
        client: Arc::new(client),
    }
}

fn handshake(f: &Fixture) {
    let mut c =
        ClientConnection::new(Arc::clone(&f.client), "localhost".try_into().unwrap()).unwrap();
    let mut s = ServerConnection::new(Arc::clone(&f.server)).unwrap();
    while c.is_handshaking() || s.is_handshaking() {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets().unwrap();
        }
    }
    black_box((c, s));
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("crl_handshake");
    for entries in ENTRIES {
        let f = fixture(entries);
        g.bench_with_input(BenchmarkId::from_parameter(entries), &f, |b, f| {
            b.iter(|| handshake(f));
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
