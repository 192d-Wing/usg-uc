//! Criterion benchmarks for audio hot-path functions.
//!
//! Run with: `cargo bench -p client-audio`

use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use client_audio::jitter_buffer::{BufferedPacket, SharedJitterBuffer};
use client_audio::rtp_handler::{parse_rfc2198, parse_rtp_fields, RTP_HEADER_SIZE};
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
    // 20ms at 8kHz = 160 samples
    let input: Vec<i16> = (0..160).map(|i| (i * 200 - 16000) as i16).collect();
    c.bench_function("resample 8kHz→48kHz (160→960 samples)", |b| {
        b.iter(|| resampler.process(black_box(&input)));
    });
}

fn bench_resample_48k_to_8k(c: &mut Criterion) {
    let mut resampler = Resampler::new(48000, 8000);
    // 20ms at 48kHz = 960 samples
    let input: Vec<i16> = (0..960).map(|i| (i * 34 - 16000) as i16).collect();
    c.bench_function("resample 48kHz→8kHz (960→160 samples)", |b| {
        b.iter(|| resampler.process(black_box(&input)));
    });
}

fn bench_jitter_buffer_push_pop(c: &mut Criterion) {
    c.bench_function("jitter_buffer push+pop (160B, depth=60ms)", |b| {
        b.iter(|| {
            let jb = SharedJitterBuffer::new(8000, 160, 60);
            // Fill to target depth (3 packets at 20ms each for 60ms)
            for i in 0..3u16 {
                let pkt = BufferedPacket::new(
                    i,
                    u32::from(i) * 160,
                    0,
                    Bytes::from_static(&[0u8; 160]),
                );
                jb.push(pkt);
            }
            // Pop all
            for _ in 0..3 {
                let _ = black_box(jb.pop());
            }
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
    bench_jitter_buffer_push_pop,
);
criterion_main!(benches);
