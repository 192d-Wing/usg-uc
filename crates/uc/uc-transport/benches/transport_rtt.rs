//! `transport_rtt`: SIP-sized send/recv round trips on loopback (POA&M-50).
//!
//! TCP and TLS use the split read/write halves of `TcpTransport` /
//! `TlsTransport` (0.10.0): one iteration is client `send` -> server `recv`
//! (looped until the whole message is read) -> server `send` -> client
//! `recv`. UDP is one `send` + `recv` each way for comparison. Message sizes
//! are ~600 B (typical INVITE) and ~4 KB (INVITE with large SDP / Identity);
//! UDP only runs 600 B because it is capped at `MAX_UDP_MESSAGE_SIZE`.
//! With `--features websocket`, `ws` runs one text message each way per
//! iteration over a loopback `WebSocketTransport` pair (plain WS).
// POAM: no bench of the sbc-daemon flow table / per-destination lanes, and
// no end-to-end INVITE-to-180 bench (sbc-daemon).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{StreamPairs, loopback, msg, runtime};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use uc_transport::udp::UdpTransport;
use uc_transport::{SbcSocketAddr, Transport};

const SIZES: [usize; 2] = [600, 4096];

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

#[cfg(feature = "websocket")]
fn ws_pair(
    rt: &tokio::runtime::Runtime,
) -> (
    uc_transport::websocket::WebSocketTransport,
    uc_transport::websocket::WebSocketTransport,
) {
    use uc_transport::websocket::{
        WebSocketListener, WebSocketListenerOptions, WebSocketTransport,
    };
    rt.block_on(async {
        // `WebSocketTransport::connect` offers no subprotocol.
        let l = WebSocketListener::bind(&loopback(), false)
            .await
            .unwrap()
            .with_options(WebSocketListenerOptions {
                require_sip_subprotocol: false,
            });
        let addr = l.bound_addr().unwrap();
        let url = format!("ws://{addr}/");
        let (c, s) = tokio::join!(WebSocketTransport::connect(&url, loopback()), l.accept());
        (c.unwrap(), s.unwrap())
    })
}

fn bench(c: &mut Criterion) {
    let rt = runtime();
    let mut g = c.benchmark_group("transport_rtt");

    let pairs = StreamPairs::new(&rt);
    let dest = pairs.dest();
    for n in SIZES {
        let data = msg(n);
        g.throughput(Throughput::Bytes(n as u64 * 2));
        for (id, client, server) in pairs.each() {
            g.bench_with_input(BenchmarkId::new(id, n), &data, |b, d| {
                b.iter(|| rt.block_on(rtt(client, server, black_box(d), &dest)));
            });
        }
    }

    #[cfg(feature = "websocket")]
    {
        let (wc, ws) = ws_pair(&rt);
        for n in SIZES {
            let data = msg(n);
            g.throughput(Throughput::Bytes(n as u64 * 2));
            g.bench_with_input(BenchmarkId::new("ws", n), &data, |b, d| {
                b.iter(|| rt.block_on(rtt(&wc, &ws, black_box(d), &dest)));
            });
        }
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
