//! `sti_cache`: STIR/SHAKEN service-layer costs on the INVITE path
//! (POA&M-38): warm certificate-cache hit, audit-aggregator hit, LRU
//! insert/evict at capacity, and a cold miss that fills and evicts.
// POAM: no end-to-end INVITE-to-180 bench with STIR enabled (sbc-daemon).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::many_single_char_names
)]

// The LRU is crate-private; include its source so it is measured as-is
// without widening the crate's API.
#[allow(dead_code, unreachable_pub, unused_imports)]
#[path = "../src/lru.rs"]
mod lru;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use proto_stir_shaken::KeyResolver;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uc_sti::aggregate::FailureAggregator;
use uc_sti::anchors::{AnchorStore, load_anchors};
use uc_sti::cache::{CacheConfig, StiCertCache};
use uc_sti::error::FetchError;
use uc_sti::fetch::{CertSource, Fetched};
use uc_sti::ssrf::X5uUrl;

const X5U: &str = "https://cert.example.com/sti.pem";

/// Serves one fixed PEM chain for every URL.
struct FixedSource(bytes::Bytes);
impl CertSource for FixedSource {
    fn fetch<'a>(
        &'a self,
        _url: &'a X5uUrl,
        _timeout: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Fetched, FetchError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(Fetched {
                body: self.0.clone(),
                max_age_secs: None,
            })
        })
    }
}

/// CA + end-entity with an SPC `TNAuthList` (as in `sti_tests.rs`).
fn pki() -> (String, String) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ee = CertificateParams::new(Vec::<String>::new()).unwrap();
    ee.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 1, 26],
        vec![0x30, 8, 0xA0, 6, 0x16, 4, b'1', b'2', b'3', b'4'],
    )];
    let ee_cert = ee.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    (ca_cert.pem(), ee_cert.pem())
}

fn cache(entries: usize) -> Arc<StiCertCache> {
    let (ca, ee) = pki();
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ca.pem");
    std::fs::write(&f, ca).unwrap();
    let anchors = Arc::new(AnchorStore::new(load_anchors(&f).unwrap()));
    StiCertCache::new(
        CacheConfig {
            entries,
            ..CacheConfig::default()
        },
        Arc::new(FixedSource(bytes::Bytes::from(ee))),
        anchors,
    )
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // --- warm cache hit -------------------------------------------------
    let warm = cache(4096);
    rt.block_on(warm.get_or_fetch(X5U, Duration::from_secs(2)))
        .unwrap();
    c.bench_function("cache_hit_key_resolver_cached", |b| {
        b.iter(|| black_box(warm.cached(black_box(X5U)).unwrap()));
    });
    c.bench_function("cache_hit_get_or_fetch_block_on", |b| {
        b.iter(|| {
            black_box(
                rt.block_on(warm.get_or_fetch(black_box(X5U), Duration::from_secs(1)))
                    .unwrap(),
            )
        });
    });

    // --- cold miss at capacity: fetch + chain validation + insert/evict --
    let small = cache(16);
    let n = AtomicU64::new(0);
    c.bench_function("cache_miss_fill_evict_at_cap16", |b| {
        b.iter(|| {
            let i = n.fetch_add(1, Ordering::Relaxed);
            let url = format!("https://cert.example.com/sti-{i}.pem");
            black_box(
                // Distinct source per iteration: measures fetch + validate +
                // evict, not the shared `Unspecified` per-source budget.
                rt.block_on(small.get_or_fetch_from(
                    std::net::IpAddr::from(std::net::Ipv6Addr::from(u128::from(i) << 64)),
                    &url,
                    Duration::from_secs(2),
                ))
                .unwrap(),
            )
        });
    });
    assert!(small.len() <= 16);

    // --- FailureAggregator hit path (same key inside the window) --------
    let agg = FailureAggregator::new(Duration::from_secs(3600));
    let t0 = Instant::now();
    let _ = agg.record("carrier-a", "bad-signature", t0);
    c.bench_function("aggregator_record_hit", |b| {
        b.iter(|| black_box(agg.record(black_box("carrier-a"), "bad-signature", t0)));
    });

    // --- LRU insert/evict at capacity ------------------------------------
    // A full 256-entry shard (4096 / 16 shards) taking a new key each time.
    let keys: Vec<String> = (0..100_000)
        .map(|i| format!("https://cert.example.com/k-{i}.pem"))
        .collect();
    c.bench_function("lru_insert_evict_at_cap256", |b| {
        let mut l = lru::Lru::<Arc<u64>>::new(256);
        for k in &keys[..256] {
            l.insert(k, Arc::new(0), u64::MAX);
        }
        let mut i = 256usize;
        let v = Arc::new(1u64);
        b.iter(|| {
            let k = &keys[i % keys.len()];
            i = i.wrapping_add(1);
            l.insert(black_box(k), Arc::clone(&v), u64::MAX);
        });
        assert_eq!(l.len(), 256);
    });
    c.bench_function("lru_get_hit_cap256", |b| {
        b.iter_batched_ref(
            || {
                let mut l = lru::Lru::<Arc<u64>>::new(256);
                for k in &keys[..256] {
                    l.insert(k, Arc::new(0), u64::MAX);
                }
                l
            },
            |l| {
                for k in &keys[..256] {
                    black_box(l.get(black_box(k), 0));
                }
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
