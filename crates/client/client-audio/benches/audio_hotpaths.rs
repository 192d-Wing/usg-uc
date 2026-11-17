//! Criterion benchmarks for audio hot-path functions.
//!
//! Run with: `cargo bench -p client-audio`
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    missing_docs
)]

use std::hint::black_box;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

use client_audio::jitter_buffer::{BufferedPacket, SharedJitterBuffer};
use client_audio::rtp_handler::{
    DtlsSink, RTP_HEADER_SIZE, RtpReceiver, parse_rfc2198, parse_rtp_fields,
};
use client_audio::sinc_resampler::Resampler;
use uc_codecs::AudioCodec;
use uc_codecs::g711::G711Ulaw;

/// Builds a minimal valid RTP packet (V=2, PT=0, 160 bytes payload).
fn make_rtp_packet(seq: u16, ts: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; RTP_HEADER_SIZE + 160];
    pkt[0] = 0x80; // V=2
    pkt[1] = 0; // PT=0
    pkt[2..4].copy_from_slice(&seq.to_be_bytes());
    pkt[4..8].copy_from_slice(&ts.to_be_bytes());
    pkt[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    pkt
}

/// Builds an RFC 2198 redundancy payload (1 redundant block + primary).
fn make_rfc2198_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(5 + 160 + 160);
    // Redundant header (4 bytes): F=1, PT=0, ts_offset=160, block_len=160
    payload.push(0x80); // F=1 | PT=0
    payload.push(0x02); // ts_offset high: 160 >> 6 = 2
    payload.push(0x80); // ts_offset low: (160 & 0x3F) << 2 = 0x80, block_len high = 0
    payload.push(160); // block_len low = 160
    // Primary header (1 byte): F=0, PT=0
    payload.push(0x00);
    // Redundant data
    payload.extend_from_slice(&[0xAA; 160]);
    // Primary data
    payload.extend_from_slice(&[0xBB; 160]);
    payload
}

fn bench_parse_rtp_fields(c: &mut Criterion) {
    let pkt = make_rtp_packet(100, 1600);
    c.bench_function("parse_rtp_fields (160B payload)", |b| {
        b.iter(|| parse_rtp_fields(black_box(&pkt)).unwrap());
    });
}

fn bench_parse_rfc2198(c: &mut Criterion) {
    let payload = make_rfc2198_payload();
    c.bench_function("parse_rfc2198 (1 redundant + primary)", |b| {
        b.iter(|| parse_rfc2198(black_box(&payload), 1600));
    });
}

fn bench_g711_ulaw_encode(c: &mut Criterion) {
    let codec = G711Ulaw::new();
    // 20ms frame at 8kHz = 160 samples
    let pcm: Vec<i16> = (0..160).map(|i| (i * 200 - 16000) as i16).collect();
    let mut output = vec![0u8; 160];
    c.bench_function("g711_ulaw_encode (160 samples)", |b| {
        b.iter(|| codec.encode(black_box(&pcm), &mut output).unwrap());
    });
}

fn bench_g711_ulaw_decode(c: &mut Criterion) {
    let codec = G711Ulaw::new();
    let encoded: Vec<u8> = (0..160).map(|i| (i & 0xFF) as u8).collect();
    let mut output = vec![0i16; 160];
    c.bench_function("g711_ulaw_decode (160 bytes)", |b| {
        b.iter(|| codec.decode(black_box(&encoded), &mut output).unwrap());
    });
}

fn bench_resample_8k_to_48k(c: &mut Criterion) {
    let mut resampler = Resampler::new(8000, 48000);
    let input: Vec<i16> = (0..160).map(|i| (i * 200 - 16000) as i16).collect();
    let mut output = vec![0i16; 960];
    c.bench_function("resample 8kHz→48kHz zero-alloc (160→960)", |b| {
        b.iter(|| resampler.process_adjusted_into(black_box(&input), &mut output));
    });
}

fn bench_resample_48k_to_8k(c: &mut Criterion) {
    let mut resampler = Resampler::new(48000, 8000);
    let input: Vec<i16> = (0..960).map(|i| (i * 34 - 16000) as i16).collect();
    let mut output = vec![0i16; 160];
    c.bench_function("resample 48kHz→8kHz zero-alloc (960→160)", |b| {
        b.iter(|| resampler.process_adjusted_into(black_box(&input), &mut output));
    });
}

fn bench_resample_8k_to_48k_10frames(c: &mut Criterion) {
    let mut resampler = Resampler::new(8000, 48000);
    let input: Vec<i16> = (0..1600).map(|i| (i * 20 - 16000) as i16).collect();
    let mut output = vec![0i16; 9600];
    c.bench_function("resample 8kHz→48kHz 10×(160→960)", |b| {
        b.iter(|| resampler.process_adjusted_into(black_box(&input), &mut output));
    });
}

fn bench_jitter_buffer_push_pop(c: &mut Criterion) {
    c.bench_function("jitter_buffer push+pop (160B, depth=60ms)", |b| {
        b.iter(|| {
            let jb = SharedJitterBuffer::new(8000, 160, 60);
            // Fill to target depth (3 packets at 20ms each for 60ms)
            for i in 0..3u16 {
                let pkt =
                    BufferedPacket::new(i, u32::from(i) * 160, 0, Bytes::from_static(&[0u8; 160]));
                jb.push(pkt);
            }
            // Pop all
            for _ in 0..3 {
                let _ = black_box(jb.pop());
            }
        });
    });
}

/// Cost of the DTLS arm of `RtpReceiver::receive` (RFC 7983 demux), one
/// datagram per iteration: sent on loopback, then read and classified. The
/// send and the read are system calls and dominate; the three cases differ
/// only in what the arm does after classification, so the difference
/// between "no sink" and the other two is the cost the sink path adds.
/// The source matches in all cases; the rate limit lets only the first
/// few reach the sink, so "accepting" mostly measures the bucket refusal,
/// which is the steady state under a flood.
fn bench_dtls_arm(c: &mut Criterion) {
    use std::net::UdpSocket;
    use std::sync::Arc;

    let record = [22u8, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let cases: [(&str, Option<bool>); 3] = [
        ("receive DTLS-class datagram, no sink", None),
        ("receive DTLS-class datagram, refusing sink", Some(false)),
        ("receive DTLS-class datagram, accepting sink", Some(true)),
    ];
    for (name, accept) in cases {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        socket.set_nonblocking(true).unwrap();
        let dest = socket.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let mut rx = RtpReceiver::new(Arc::clone(&socket), jb);
        if let Some(accept) = accept {
            let sink: DtlsSink = Box::new(move |datagram: &[u8]| {
                black_box(datagram);
                accept
            });
            rx.set_dtls_sink(sink, peer.local_addr().unwrap());
        }
        c.bench_function(name, |b| {
            b.iter(|| {
                peer.send_to(&record, dest).unwrap();
                black_box(rx.receive().unwrap())
            });
        });
    }
}

/// The RTP arm of `RtpReceiver::receive`, one packet per iteration: sent on
/// loopback, read, classified (RFC 7983), parsed and put into the jitter
/// buffer, then popped again. No DTLS sink is installed; this is the path
/// every media packet takes, and the bench exists so that a change to the
/// receive loop (such as the DTLS forward arm) can be compared against the
/// previous commit. The send and the read are system calls and dominate.
fn bench_rtp_receive(c: &mut Criterion) {
    use std::net::UdpSocket;
    use std::sync::Arc;

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    // Blocking with a read timeout, as the audio I/O thread reads it. (On a
    // non-blocking socket a read straight after the send can find nothing
    // yet, and the iteration would measure `WouldBlock`.)
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .unwrap();
    let dest = socket.local_addr().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let jb = SharedJitterBuffer::new(8000, 160, 60);
    let mut rx = RtpReceiver::new(Arc::clone(&socket), jb.clone());
    let mut seq = 0u16;
    let mut ts = 0u32;
    // The path measured is the accepting one: a packet is buffered.
    peer.send_to(&make_rtp_packet(seq, ts), dest).unwrap();
    assert!(rx.receive().unwrap(), "RTP packet was not accepted");
    let _ = jb.pop();
    c.bench_function("receive RTP datagram (loopback, 160B payload)", |b| {
        b.iter(|| {
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(160);
            peer.send_to(&make_rtp_packet(seq, ts), dest).unwrap();
            let received = rx.receive().unwrap();
            assert!(received, "RTP packet was not accepted");
            black_box(jb.pop())
        });
    });
}

criterion_group!(
    benches,
    bench_parse_rtp_fields,
    bench_parse_rfc2198,
    bench_g711_ulaw_encode,
    bench_g711_ulaw_decode,
    bench_resample_8k_to_48k,
    bench_resample_48k_to_8k,
    bench_resample_8k_to_48k_10frames,
    bench_jitter_buffer_push_pop,
    bench_dtls_arm,
    bench_rtp_receive,
);
criterion_main!(benches);
