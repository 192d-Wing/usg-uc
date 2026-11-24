//! `stream_framer`: `StreamFramer::next_frame` cost per stream read on
//! the TCP/TLS/WS receive path: pipelined small messages, a 60 KiB body,
//! a large head, and the 1-byte drip of an unterminated head that the
//! incremental search keeps linear (SR-54, PERF-001).
//!
#![allow(missing_docs)]

// `sbc-daemon` is a binary crate: include the framer's source so it is
// measured as-is (as `uc-sti/benches/sti_cache.rs` does). Under
// `--all-targets` the bench builds with `cfg(test)`, which pulls in the
// framer's unit-test helpers unused here.
#[allow(dead_code, unused_imports)]
#[path = "../src/stream_framer.rs"]
mod stream_framer;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use stream_framer::{KeepAlive, StreamFramer, UNFRAMED_CHARGE_BYTES};

/// `transport.max_header_bytes` default.
const MAX_HEADER_BYTES: usize = 16_384;

/// An INVITE with `pad` filler header lines and a `body`-byte body.
fn invite(body: usize, pad: usize) -> Vec<u8> {
    let mut m = b"INVITE sip:b@example.mil SIP/2.0\r\n\
        Via: SIP/2.0/TLS 192.0.2.1:5061;branch=z9hG4bK1234\r\n\
        From: <sip:a@example.mil>;tag=1\r\nTo: <sip:b@example.mil>\r\n\
        Call-ID: bench@example.mil\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n\
        Contact: <sip:a@192.0.2.1:5061;transport=tls>\r\n"
        .to_vec();
    for _ in 0..pad {
        m.extend_from_slice(
            b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
        );
    }
    m.extend_from_slice(format!("Content-Length: {body}\r\n\r\n").as_bytes());
    m.extend(std::iter::repeat_n(b'x', body));
    m
}

/// Header lines with no blank line, about `len` bytes.
fn unterminated_head(len: usize) -> Vec<u8> {
    let mut m = b"OPTIONS sip:sbc@example.mil SIP/2.0\r\n".to_vec();
    while m.len() < len {
        m.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    m
}

/// Feeds `stream` in `chunk`-byte reads, framing after each like the
/// connection loop; returns frames taken (stops on the first error).
fn feed(stream: &[u8], chunk: usize) -> usize {
    let mut framer = StreamFramer::new(true, MAX_HEADER_BYTES);
    let mut taken = 0;
    for read in stream.chunks(chunk) {
        framer.push(read);
        loop {
            let mut keepalive = KeepAlive::default();
            match framer.next_frame(&mut keepalive) {
                Ok(Some(frame)) => {
                    taken += 1;
                    black_box(frame);
                }
                Ok(None) => break,
                Err(e) => {
                    black_box(e.to_string());
                    return taken;
                }
            }
            black_box((keepalive.seen, keepalive.pings));
        }
        black_box(framer.buffered() / UNFRAMED_CHARGE_BYTES);
    }
    black_box(framer.as_bytes());
    framer.clear();
    taken
}

fn bench_next_frame(c: &mut Criterion) {
    let small = invite(300, 0);
    let mut pipelined = Vec::new();
    for _ in 0..64 {
        pipelined.extend_from_slice(&small);
    }
    let mut pinged = Vec::new();
    for _ in 0..64 {
        pinged.extend_from_slice(b"\r\n\r\n");
        pinged.extend_from_slice(&small);
    }
    let big_body = invite(60_000, 0);
    let big_head = invite(0, 200);
    let drip = unterminated_head(MAX_HEADER_BYTES + 1_024);

    let cases: [(&str, &[u8], usize); 8] = [
        ("64_small_pipelined_4096", &pipelined, 4_096),
        ("64_small_pipelined_1460", &pipelined, 1_460),
        ("64_small_with_pings_1460", &pinged, 1_460),
        ("small_in_3_reads", &small, small.len() / 3 + 1),
        ("60k_body_4096", &big_body, 4_096),
        ("14k_head_4096", &big_head, 4_096),
        ("14k_head_1_byte_drip", &big_head, 1),
        ("unterminated_head_1_byte_drip", &drip, 1),
    ];
    let mut g = c.benchmark_group("next_frame");
    for (name, stream, chunk) in cases {
        g.throughput(Throughput::Bytes(stream.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &stream, |b, s| {
            b.iter(|| feed(black_box(s), chunk));
        });
    }
    g.finish();
}

criterion_group!(benches, bench_next_frame);
criterion_main!(benches);
