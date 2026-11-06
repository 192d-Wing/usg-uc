//! `transport_rtt`: SIP-sized send/recv round trips on loopback (POA&M-50).
//!
//! TCP and TLS use the split read/write halves of `TcpTransport` /
//! `TlsTransport` (0.10.0): one iteration is client `send` -> server `recv`
//! (looped until the whole message is read) -> server `send` -> client
//! `recv`. UDP is one `send` + `recv` each way for comparison. Message sizes
//! are ~600 B (typical INVITE) and ~4 KB (INVITE with large SDP / Identity);
//! UDP only runs 600 B because it is capped at `MAX_UDP_MESSAGE_SIZE`.
// POAM: no bench of the sbc-daemon flow table / per-destination lanes, and
// no end-to-end INVITE-to-180 bench (sbc-daemon).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uc_transport::listener::ListenerConfig;
use uc_transport::tcp::{TcpListener, TcpTransport};
use uc_transport::tls::{TlsListener, TlsTransport, create_client_config, create_server_config};
use uc_transport::udp::UdpTransport;
use uc_transport::{SbcSocketAddr, Transport, TransportType};

const SIZES: [usize; 2] = [600, 4096];

fn loopback() -> SbcSocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0)).into()
}

fn msg(n: usize) -> Vec<u8> {
    (b'a'..=b'z').cycle().take(n).collect()
}

async fn recv_exact(t: &dyn Transport, n: usize) {
    let mut got = 0;
    while got < n {
        got += t.recv().await.unwrap().data.len();
    }
    assert_eq!(got, n);
}

async fn rtt(client: &dyn Transport, server: &dyn Transport, data: &[u8], dest: &SbcSocketAddr) {
    client.send(data, dest).await.unwrap();
    recv_exact(server, data.len()).await;
    server.send(data, dest).await.unwrap();
    recv_exact(client, data.len()).await;
}

fn tcp_pair(rt: &Runtime) -> (TcpTransport, TcpTransport) {
    rt.block_on(async {
        let l = TcpListener::bind(loopback()).await.unwrap();
        let addr = *l.local_addr();
        let (c, s) = tokio::join!(TcpTransport::connect(addr), l.accept());
        (c.unwrap(), s.unwrap().0)
    })
}

fn tls_pair(rt: &Runtime) -> (TlsTransport, TlsTransport) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let server_cfg = Arc::new(create_server_config(vec![cert_der.clone()], key_der).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = Arc::new(create_client_config(roots).unwrap());
    rt.block_on(async {
        let l = TlsListener::bind(
            ListenerConfig::new(loopback(), TransportType::Tls),
            server_cfg,
        )
        .await
        .unwrap();
        let addr = *l.local_addr();
        let (c, s) = tokio::join!(
            TlsTransport::connect(addr, "localhost", client_cfg),
            l.accept()
        );
        (c.unwrap(), s.unwrap().0)
    })
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut g = c.benchmark_group("transport_rtt");

    let (tc, ts) = tcp_pair(&rt);
    let (lc, ls) = tls_pair(&rt);
    let dest = *tc.local_addr(); // ignored by stream transports
    for n in SIZES {
        let data = msg(n);
        g.throughput(Throughput::Bytes(n as u64 * 2));
        g.bench_with_input(BenchmarkId::new("tcp", n), &data, |b, d| {
            b.iter(|| rt.block_on(rtt(&tc, &ts, black_box(d), &dest)));
        });
        g.bench_with_input(BenchmarkId::new("tls13", n), &data, |b, d| {
            b.iter(|| rt.block_on(rtt(&lc, &ls, black_box(d), &dest)));
        });
    }

    let (ua, ub) = rt.block_on(async {
        (
            UdpTransport::bind(loopback()).await.unwrap(),
            UdpTransport::bind(loopback()).await.unwrap(),
        )
    });
    let (a_addr, b_addr) = (*ua.local_addr(), *ub.local_addr());
    let data = msg(600);
    g.throughput(Throughput::Bytes(1200));
    g.bench_function(BenchmarkId::new("udp", 600), |b| {
        b.iter(|| {
            rt.block_on(async {
                ua.send(black_box(&data), &b_addr).await.unwrap();
                recv_exact(&ub, data.len()).await;
                ub.send(&data, &a_addr).await.unwrap();
                recv_exact(&ua, data.len()).await;
            });
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
