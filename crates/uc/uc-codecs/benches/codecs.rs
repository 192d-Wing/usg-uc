//! `codecs`: per-frame cost of the decode-thread codec work (PERF-002):
//! G.722 encode/decode of one 20 ms frame, Opus decode / in-band FEC
//! decode / native PLC of one 20 ms frame, and the RFC 6716 §3.1 TOC check
//! (`may_carry_fec`) run on every lost packet. Opus cases need `opus-ffi`.
#![allow(missing_docs, clippy::unwrap_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use uc_codecs::{AudioCodec, G722Codec, opus_toc};

/// 20 ms at 16 kHz (G.722 input rate).
const G722_FRAME: usize = 320;
/// 20 ms at 48 kHz mono (Opus `VoIP` default).
const OPUS_FRAME: usize = 960;

/// Deterministic speech-band test signal (no RNG, no float casts): a
/// triangle wave of `rate / 100` samples per period (100 Hz fundamental
/// plus odd harmonics) peaking at 10000 (about -10 dBFS).
fn tone<const N: usize>(rate: u32) -> Vec<i16> {
    let period = i64::from(rate / 100).max(4);
    (0..N)
        .map(|i| {
            let pos = i64::try_from(i).unwrap_or(0) % period;
            let half = period / 2;
            let tri = if pos < half { pos } else { period - pos };
            i16::try_from(tri * 40_000 / period - 10_000).unwrap_or(0)
        })
        .collect()
}

fn bench_g722(c: &mut Criterion) {
    let pcm = tone::<G722_FRAME>(16_000);
    let codec = G722Codec::new();
    let mut encoded = vec![0u8; G722_FRAME];
    let n = codec.encode(&pcm, &mut encoded).unwrap();
    let encoded = &encoded[..n];
    let mut enc_out = vec![0u8; G722_FRAME];
    let mut dec_out = vec![0i16; G722_FRAME * 2];

    c.bench_function("g722_encode_20ms", |b| {
        b.iter(|| codec.encode(black_box(&pcm), &mut enc_out).unwrap());
    });
    c.bench_function("g722_decode_20ms", |b| {
        b.iter(|| codec.decode(black_box(encoded), &mut dec_out).unwrap());
    });
}

/// SILK-only 20 ms TOC (config 1, code 0) and a CELT-only one (config 19).
fn bench_toc(c: &mut Criterion) {
    let silk = [0x08u8, 0, 0, 0];
    let celt = [0x98u8, 0, 0, 0];
    c.bench_function("may_carry_fec_silk", |b| {
        b.iter(|| opus_toc::may_carry_fec(black_box(&silk), OPUS_FRAME, 48_000));
    });
    c.bench_function("may_carry_fec_celt", |b| {
        b.iter(|| opus_toc::may_carry_fec(black_box(&celt), OPUS_FRAME, 48_000));
    });
}

#[cfg(feature = "opus-ffi")]
fn bench_opus(c: &mut Criterion) {
    use uc_codecs::{FfiOpusDecoder, FfiOpusEncoder, opus::OpusConfig};

    let enc = FfiOpusEncoder::new(OpusConfig::voip()).unwrap();
    let pcm = tone::<{ OPUS_FRAME * 10 }>(48_000);
    // Encode a few frames so the packet carries LBRR (FEC needs history).
    let mut pkt = vec![0u8; 1500];
    let mut len = 0;
    for frame in pcm.as_chunks::<OPUS_FRAME>().0 {
        len = enc.encode(frame, &mut pkt).unwrap();
    }
    let pkt = &pkt[..len];
    let dec = FfiOpusDecoder::new(48_000, 1).unwrap();
    let mut out = vec![0i16; OPUS_FRAME];

    c.bench_function("opus_decode_20ms", |b| {
        b.iter(|| dec.decode(black_box(pkt), &mut out).unwrap());
    });
    c.bench_function("opus_decode_fec_20ms", |b| {
        // A CELT-only packet returns Err without decoding; record either.
        b.iter(|| black_box(dec.decode_fec(black_box(pkt), &mut out)));
    });
    c.bench_function("opus_conceal_20ms", |b| {
        b.iter(|| dec.conceal(&mut out).unwrap());
    });
}

#[cfg(not(feature = "opus-ffi"))]
fn bench_opus(_c: &mut Criterion) {}

criterion_group!(benches, bench_g722, bench_toc, bench_opus);
criterion_main!(benches);
