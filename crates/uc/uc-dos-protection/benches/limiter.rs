//! `limiter`: per-packet `RateLimiter::check_outcome` costs on the SIP
//! receive path: allow, over-rate reject, the overflow bucket at the
//! tracked-source cap, new offenders against a full block map
//! (PERF-001), and trusted-source checks (SR-55).
#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use uc_dos_protection::{RateLimiter, RateLimiterConfig};

fn ip(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n))
}

fn bench_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("check_outcome");

    let mut allow = RateLimiter::new(RateLimiterConfig::new(u32::MAX / 2, u32::MAX / 2));
    g.bench_function("allow", |b| {
        b.iter(|| allow.check_outcome(black_box(ip(1))));
    });

    let mut reject = RateLimiter::new(RateLimiterConfig::new(1, 1).with_block_threshold(1e12));
    g.bench_function("reject", |b| {
        b.iter(|| reject.check_outcome(black_box(ip(1))));
    });

    let mut overflow = RateLimiter::new(
        RateLimiterConfig::new(100, 100)
            .with_max_tracked_sources(4_096)
            .with_overflow(1, 1),
    );
    for n in 0..4_096 {
        let _ = overflow.check_outcome(ip(n));
    }
    let mut n = 100_000u32;
    g.bench_function("overflow_at_cap", |b| {
        b.iter(|| {
            n = n.wrapping_add(1);
            overflow.check_outcome(black_box(ip(n)))
        });
    });

    let mut full = RateLimiter::new(
        RateLimiterConfig::new(1, 1)
            .with_block_threshold(1.0)
            .with_max_blocked_sources(16_384)
            .with_max_tracked_sources(1 << 20),
    );
    for n in 0..16_384 {
        let _ = full.block(ip(n), Duration::from_secs(3_600));
    }
    let mut m = 200_000u32;
    g.bench_function("new_offender_full_block_map", |b| {
        b.iter(|| {
            m = m.wrapping_add(1);
            // Burst 1: the second packet is over the block threshold.
            let _ = full.check_outcome(ip(m));
            full.check_outcome(black_box(ip(m)))
        });
    });

    // SR-55: a trusted (configured trunk) source among 64 trusted entries,
    // and an untrusted source paying the extra trusted-set lookup.
    let mut trusted = RateLimiter::new(
        RateLimiterConfig::new(u32::MAX / 2, u32::MAX / 2)
            .with_trusted_bucket(u32::MAX / 2, u32::MAX / 2),
    );
    trusted.set_trusted_sources((0..64).map(|n| ip(300_000 + n)));
    g.bench_function("trusted_allow", |b| {
        b.iter(|| trusted.check_outcome(black_box(ip(300_007))));
    });
    g.bench_function("untrusted_with_trusted_set", |b| {
        b.iter(|| trusted.check_outcome(black_box(ip(1))));
    });
    g.finish();
}

criterion_group!(benches, bench_check);
criterion_main!(benches);
