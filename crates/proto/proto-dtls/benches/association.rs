//! Criterion benchmarks for `DtlsAssociation` (PERF-009).
//!
//! Run with: `cargo bench -p proto-dtls`
//!
//! - `handshake`: a complete in-memory handshake between two associations
//!   (both sides' work: two P-384 key generations, two ECDH, signatures and
//!   verifications, key schedule, six flights).
//! - `handle_datagram, connected`: what a connected association spends on
//!   one datagram it must discard, which is what a flood from the peer's
//!   address costs after the handshake: a forged epoch-1 record (fails
//!   authentication), a replayed genuine epoch-1 record (replay window)
//!   and plaintext junk (wrong epoch).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    missing_docs
)]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use proto_dtls::{AssociationConfig, AssociationEvent, DtlsAssociation, DtlsCredentials, DtlsRole};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;
use uc_crypto::ecdsa::P384KeyPair;

/// A self-signed P-384 identity.
fn identity() -> DtlsCredentials {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["bench.invalid".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = Arc::new(P384KeyPair::from_pkcs8(&key.serialize_der()).unwrap());
    DtlsCredentials::new(vec![cert.der().to_vec()], key).unwrap()
}

fn pair(
    client_id: &DtlsCredentials,
    server_id: &DtlsCredentials,
) -> (DtlsAssociation, DtlsAssociation) {
    let now = Instant::now();
    let client = DtlsAssociation::new(
        AssociationConfig::new(
            DtlsRole::Client,
            client_id.clone(),
            vec![server_id.fingerprint().clone()],
        ),
        now,
    )
    .unwrap();
    let server = DtlsAssociation::new(
        AssociationConfig::new(
            DtlsRole::Server,
            server_id.clone(),
            vec![client_id.fingerprint().clone()],
        ),
        now,
    )
    .unwrap();
    (client, server)
}

/// Moves datagrams between the two until both are connected. Returns the
/// last datagram the client sent (its final flight: epoch-1 records).
fn run_handshake(client: &mut DtlsAssociation, server: &mut DtlsAssociation) -> Vec<u8> {
    let now = Instant::now();
    let mut last_from_client = Vec::new();
    for _ in 0..32 {
        let mut moved = false;
        while let Some(datagram) = client.poll_transmit() {
            server.handle_datagram(&datagram, now);
            last_from_client = datagram;
            moved = true;
        }
        while let Some(datagram) = server.poll_transmit() {
            client.handle_datagram(&datagram, now);
            moved = true;
        }
        if !moved {
            break;
        }
    }
    for association in [&mut *client, &mut *server] {
        let mut connected = false;
        while let Some(event) = association.poll_event() {
            match event {
                AssociationEvent::Connected { .. } => connected = true,
                AssociationEvent::Failed { cause } => panic!("handshake failed: {cause:?}"),
                AssociationEvent::PeerClosed => panic!("peer closed"),
            }
        }
        assert!(connected, "handshake did not complete");
    }
    last_from_client
}

fn bench_handshake(c: &mut Criterion) {
    let (client_id, server_id) = (identity(), identity());
    let mut group = c.benchmark_group("association");
    group.sample_size(20);
    group.bench_function("handshake (client + server, in memory)", |b| {
        b.iter_batched(
            || pair(&client_id, &server_id),
            |(mut client, mut server)| {
                black_box(run_handshake(&mut client, &mut server));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_connected_discards(c: &mut Criterion) {
    let (client_id, server_id) = (identity(), identity());
    let (mut client, mut server) = pair(&client_id, &server_id);
    let final_flight = run_handshake(&mut client, &mut server);
    let now = Instant::now();

    // A record of the right shape in epoch 1 that cannot authenticate:
    // content type 23, DTLS 1.2, epoch 1, a high sequence number, 32 bytes.
    let mut forged = vec![23, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0xFF, 0xFF, 0, 32];
    forged.extend_from_slice(&[0xA5; 32]);
    // Plaintext (epoch 0) handshake-class junk.
    let mut plaintext = vec![22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 9, 0, 16];
    plaintext.extend_from_slice(&[0; 16]);

    {
        let mut group = c.benchmark_group("association/handle_datagram, connected");
        group.bench_function("forged epoch-1 record (authentication fails)", |b| {
            b.iter(|| server.handle_datagram(black_box(&forged), now));
        });
        group.bench_function("replayed final flight (replay window)", |b| {
            b.iter(|| server.handle_datagram(black_box(&final_flight), now));
        });
        group.bench_function("plaintext junk (wrong epoch)", |b| {
            b.iter(|| server.handle_datagram(black_box(&plaintext), now));
        });
        group.finish();
    }
    // Nothing above may have ended or disturbed the association.
    assert!(server.is_connected());
    while server.poll_transmit().is_some() {}
}

criterion_group!(benches, bench_handshake, bench_connected_discards);
criterion_main!(benches);
