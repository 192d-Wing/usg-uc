//! `stream_recv`: one-way TCP and TLS receive throughput on loopback (SR-57).
//!
//! One iteration sends `BATCH` messages from the client while the server
//! drains them with `recv`. The receiver copies each chunk into a
//! message-sized buffer and drops it before the next `recv`, as
//! `stream_connection_loop` does, so the transport's one reusable
//! `STREAM_READ_CHUNK` buffer is reclaimed on every read. Message sizes are
//! ~800 B (typical INVITE) and ~60 KB (near `MAX_STREAM_MESSAGE_SIZE`).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{StreamPairs, msg, runtime};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use uc_transport::{MAX_STREAM_MESSAGE_SIZE, SbcSocketAddr, Transport};

const SIZES: [usize; 2] = [800, 60_000];

/// Messages per iteration.
const BATCH: usize = 16;

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

fn bench(c: &mut Criterion) {
    let rt = runtime();
    let mut g = c.benchmark_group("stream_recv");

    let pairs = StreamPairs::new(&rt);
    let dest = pairs.dest();
    let mut framer = Vec::with_capacity(2 * MAX_STREAM_MESSAGE_SIZE);
    for n in SIZES {
        let data = msg(n);
        g.throughput(Throughput::Bytes((n * BATCH) as u64));
        for (id, client, server) in pairs.each() {
            g.bench_with_input(BenchmarkId::new(id, n), &data, |b, d| {
                b.iter(|| rt.block_on(one_way(client, server, black_box(d), &dest, &mut framer)));
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
