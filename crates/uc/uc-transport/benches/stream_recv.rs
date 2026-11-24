//! `stream_recv`: one-way TCP and TLS receive throughput on loopback (SR-57).
//!
//! One iteration sends `BATCH` messages from the client while the server
//! drains them with `recv`. The receiver copies each chunk into a
//! message-sized buffer and drops it before the next `recv`, as
//! `stream_connection_loop` does, so the transport's one reusable
//! `STREAM_READ_CHUNK` buffer is reclaimed on every read. Message sizes are
//! ~800 B (typical INVITE) and ~60 KB (near `MAX_STREAM_MESSAGE_SIZE`).
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
use uc_transport::{MAX_STREAM_MESSAGE_SIZE, SbcSocketAddr, Transport, TransportType};

const SIZES: [usize; 2] = [800, 60_000];

/// Messages per iteration.
const BATCH: usize = 16;

fn loopback() -> SbcSocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0)).into()
}

fn msg(n: usize) -> Vec<u8> {
    (b'a'..=b'z').cycle().take(n).collect()
}

/// Receives `total` bytes, copying each chunk into `framer` (cleared once it
/// holds a message's worth) and dropping the chunk before the next `recv`.
async fn drain(t: &dyn Transport, total: usize, framer: &mut Vec<u8>) {
    let mut got = 0;
    while got < total {
        let m = t.recv().await.unwrap();
        got += m.data.len();
        framer.extend_from_slice(&m.data);
        drop(m);
        if framer.len() >= MAX_STREAM_MESSAGE_SIZE {
            framer.clear();
        }
    }
    assert_eq!(got, total);
}

async fn one_way(
    client: &dyn Transport,
    server: &dyn Transport,
    data: &[u8],
    dest: &SbcSocketAddr,
    framer: &mut Vec<u8>,
) {
    let send = async {
        for _ in 0..BATCH {
            client.send(data, dest).await.unwrap();
        }
    };
    tokio::join!(send, drain(server, data.len() * BATCH, framer));
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
    let mut g = c.benchmark_group("stream_recv");

    let (tc, ts) = tcp_pair(&rt);
    let (lc, ls) = tls_pair(&rt);
    let dest = *tc.local_addr(); // ignored by stream transports
    let mut framer = Vec::with_capacity(2 * MAX_STREAM_MESSAGE_SIZE);
    for n in SIZES {
        let data = msg(n);
        g.throughput(Throughput::Bytes((n * BATCH) as u64));
        g.bench_with_input(BenchmarkId::new("tcp", n), &data, |b, d| {
            b.iter(|| rt.block_on(one_way(&tc, &ts, black_box(d), &dest, &mut framer)));
        });
        g.bench_with_input(BenchmarkId::new("tls13", n), &data, |b, d| {
            b.iter(|| rt.block_on(one_way(&lc, &ls, black_box(d), &dest, &mut framer)));
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
