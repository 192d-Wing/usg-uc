//! Cross-module tests: real STI chains (rcgen), cache behaviour, signing
//! key checks, and a local HTTPS repository.

use crate::anchors::{AnchorSet, AnchorStore, load_anchors};
use crate::cache::{CacheConfig, StiCertCache};
use crate::error::FetchError;
use crate::fetch::{CertSource, Fetched, HttpsFetcher, Resolve};
use crate::signer::FileSigner;
use crate::ssrf::X5uUrl;
use proto_stir_shaken::{
    Attestation, CallContext, FailureReason, KeyResolver, Verifier, Verstat, canonicalize_tn,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const X5U: &str = "https://cert.example.com/sti.pem";

/// DER `TNAuthList`: `SEQUENCE { [0] EXPLICIT IA5String spc }`.
fn tn_auth_spc(spc: &str) -> Vec<u8> {
    let s = spc.as_bytes();
    let ia5_len = u8::try_from(s.len()).unwrap();
    let mut v = vec![0x30, ia5_len + 4, 0xA0, ia5_len + 2, 0x16, ia5_len];
    v.extend_from_slice(s);
    v
}

pub struct Pki {
    pub ca_pem: String,
    pub ee_pem: String,
    pub ee_key_der: Vec<u8>,
}

pub fn pki(with_tn_auth: bool) -> Pki {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ee = CertificateParams::new(Vec::<String>::new()).unwrap();
    if with_tn_auth {
        ee.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 26],
            tn_auth_spc("1234"),
        )];
    }
    let ee_cert = ee.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    Pki {
        ca_pem: ca_cert.pem(),
        ee_pem: ee_cert.pem(),
        ee_key_der: ee_key.serialize_der(),
    }
}

fn anchors_for(p: &Pki) -> Arc<AnchorStore> {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ca.pem");
    std::fs::write(&f, &p.ca_pem).unwrap();
    Arc::new(AnchorStore::new(load_anchors(&f).unwrap()))
}

/// Serves a fixed body, counting calls; optional delay.
struct FakeSource {
    body: String,
    calls: AtomicUsize,
    delay: Duration,
}

impl CertSource for FakeSource {
    fn fetch<'a>(
        &'a self,
        _url: &'a X5uUrl,
        _timeout: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Fetched, FetchError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(Fetched {
                body: bytes::Bytes::from(self.body.clone()),
                max_age_secs: None,
            })
        })
    }
}

fn source(body: String, delay_ms: u64) -> Arc<FakeSource> {
    Arc::new(FakeSource {
        body,
        calls: AtomicUsize::new(0),
        delay: Duration::from_millis(delay_ms),
    })
}

#[tokio::test]
async fn end_to_end_sign_fetch_verify() {
    let p = pki(true);
    let src = source(p.ee_pem.clone(), 0);
    let cache = StiCertCache::new(CacheConfig::default(), src.clone(), anchors_for(&p));
    let signer = FileSigner::from_pkcs8(&p.ee_key_der, X5U).unwrap();
    let now = crate::cache::unix_now();
    let hdr = crate::sign_identity(
        &signer,
        X5U,
        Attestation::Full,
        canonicalize_tn("+12025550100").unwrap(),
        canonicalize_tn("+12025550101").unwrap(),
        now,
    )
    .unwrap();

    let v = Verifier::default();
    let prepared = v.prepare([hdr.as_str()]).unwrap().unwrap();
    let key = cache
        .get_or_fetch(prepared.x5u(), Duration::from_secs(1))
        .await
        .unwrap();
    let ctx = CallContext {
        orig: vec![canonicalize_tn("12025550100").unwrap()],
        dest: vec![canonicalize_tn("12025550101").unwrap()],
    };
    let r = v.verify(&prepared, &ctx, &key, now);
    assert_eq!(r.verstat, Verstat::Passed, "{r:?}");
    assert_eq!(r.attest, Some(Attestation::Full));

    // Cached: second lookup does not fetch.
    assert!(cache.cached(X5U).is_some());
    let _ = cache
        .get_or_fetch(X5U, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(src.calls.load(Ordering::SeqCst), 1);

    // Tampered token fails signature.
    let tampered = hdr.replacen('.', ".e", 1);
    if let Ok(Some(p2)) = v.prepare([tampered.as_str()]) {
        assert_eq!(
            v.verify(&p2, &ctx, &key, now).reason,
            Some(FailureReason::BadSignature)
        );
    }
}

#[tokio::test]
async fn single_flight_one_fetch_for_many_callers() {
    let p = pki(true);
    let src = source(p.ee_pem.clone(), 100);
    let cache = StiCertCache::new(CacheConfig::default(), src.clone(), anchors_for(&p));
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let c = Arc::clone(&cache);
        tasks.push(tokio::spawn(async move {
            c.get_or_fetch(X5U, Duration::from_secs(2)).await.is_ok()
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap());
    }
    assert_eq!(src.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn untrusted_and_missing_tnauthlist_are_negative_cached() {
    let p = pki(true);
    let other = pki(true);
    // Chain to a different CA.
    let src = source(p.ee_pem.clone(), 0);
    let cache = StiCertCache::new(CacheConfig::default(), src.clone(), anchors_for(&other));
    // Same (empty) issuer DN, different key: webpki reports the signature.
    let e = cache
        .get_or_fetch(X5U, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(matches!(e, FetchError::Untrusted(_)), "{e:?}");
    assert_eq!(e.reason(), FailureReason::CertUntrusted);
    assert!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert_eq!(src.calls.load(Ordering::SeqCst), 1, "negative cache hit");

    let no_tn = pki(false);
    let cache = StiCertCache::new(
        CacheConfig::default(),
        source(no_tn.ee_pem.clone(), 0),
        anchors_for(&no_tn),
    );
    assert_eq!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(1))
            .await
            .unwrap_err(),
        FetchError::Untrusted("missing-tnauthlist")
    );
}

#[tokio::test]
async fn negative_ttl_expires() {
    let p = pki(true);
    let now = Arc::new(std::sync::atomic::AtomicU64::new(crate::cache::unix_now()));
    let n2 = Arc::clone(&now);
    let src = source("garbage".into(), 0);
    let cache = StiCertCache::with_clock(
        CacheConfig {
            negative_ttl_secs: 5,
            ..CacheConfig::default()
        },
        src.clone(),
        anchors_for(&p),
        Arc::new(move || n2.load(Ordering::SeqCst)),
    );
    assert!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert_eq!(src.calls.load(Ordering::SeqCst), 1);
    now.fetch_add(6, Ordering::SeqCst);
    assert!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert_eq!(src.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn lru_bound_busy_timeout_and_ssrf() {
    let p = pki(true);
    let cache = StiCertCache::new(
        CacheConfig {
            entries: 2,
            ..CacheConfig::default()
        },
        source(p.ee_pem.clone(), 0),
        anchors_for(&p),
    );
    for i in 0..5 {
        let _ = cache
            .get_or_fetch(
                &format!("https://h{i}.example.com/c"),
                Duration::from_secs(1),
            )
            .await;
    }
    assert!(cache.len() <= 2);

    // SSRF: refused without any fetch, maps to 436.
    let e = cache
        .get_or_fetch("https://169.254.169.254/latest", Duration::from_secs(1))
        .await
        .unwrap_err();
    assert_eq!(e.reason(), FailureReason::BadInfo);

    // Busy: one permit, a slow fetch holds it.
    let slow = StiCertCache::new(
        CacheConfig {
            max_concurrent_fetches: 1,
            ..CacheConfig::default()
        },
        source(p.ee_pem.clone(), 500),
        anchors_for(&p),
    );
    let s2 = Arc::clone(&slow);
    let first = tokio::spawn(async move {
        s2.get_or_fetch("https://a.example.com/c", Duration::from_secs(2))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        slow.get_or_fetch("https://b.example.com/c", Duration::from_secs(2))
            .await
            .unwrap_err(),
        FetchError::Busy
    );
    // Timeout for a waiter; the fetch still fills the cache.
    assert_eq!(
        slow.get_or_fetch("https://a.example.com/c", Duration::from_millis(10))
            .await
            .unwrap_err(),
        FetchError::Timeout
    );
    assert!(first.await.unwrap().is_ok());
    assert!(slow.cached("https://a.example.com/c").is_some());
}

#[test]
fn anchor_reload_swaps() {
    let a = pki(true);
    let store = AnchorStore::default();
    assert_eq!(store.current().count, 0);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pem"), &a.ca_pem).unwrap();
    std::fs::write(dir.path().join("b.crt"), pki(true).ca_pem).unwrap();
    std::fs::write(dir.path().join("ignored.txt"), "x").unwrap();
    let set: AnchorSet = load_anchors(dir.path()).unwrap();
    assert_eq!(set.count, 2);
    assert_eq!(set.sha384.len(), 96);
    store.swap(set);
    assert_eq!(store.current().count, 2);
    let empty = tempfile::tempdir().unwrap();
    assert!(load_anchors(empty.path()).is_err());
}

#[cfg(unix)]
#[test]
fn file_signer_checks() {
    use std::os::unix::fs::PermissionsExt;
    let p = pki(true);
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("sti.key");
    let cert = dir.path().join("sti.pem");
    std::fs::write(&key, &p.ee_key_der).unwrap();
    std::fs::write(&cert, &p.ee_pem).unwrap();
    let now = crate::cache::unix_now();

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let e = FileSigner::load(&key, &cert, X5U, now)
        .unwrap_err()
        .to_string();
    assert!(e.contains("group or other"), "{e}");

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let s = FileSigner::load(&key, &cert, X5U, now).unwrap();
    assert_eq!(s.cert_fingerprint_sha384.len(), 96);

    let link = dir.path().join("link.key");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    let e = FileSigner::load(&link, &cert, X5U, now)
        .unwrap_err()
        .to_string();
    assert!(e.contains("symlink"), "{e}");

    // Cert for another key.
    let other = pki(true);
    std::fs::write(&cert, &other.ee_pem).unwrap();
    let e = FileSigner::load(&key, &cert, X5U, now)
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not match"), "{e}");

    // No TNAuthList.
    let no_tn = pki(false);
    std::fs::write(&key, &no_tn.ee_key_der).unwrap();
    std::fs::write(&cert, &no_tn.ee_pem).unwrap();
    let e = FileSigner::load(&key, &cert, X5U, now)
        .unwrap_err()
        .to_string();
    assert!(e.contains("TNAuthList"), "{e}");
}

// --- local HTTPS repository -------------------------------------------------

struct LoopbackResolver(std::net::SocketAddr);
impl Resolve for LoopbackResolver {
    fn resolve<'a>(
        &'a self,
        _h: &'a str,
        _p: u16,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send + 'a>,
    > {
        let a = self.0;
        Box::pin(async move { Ok(vec![a]) })
    }
}

/// Starts a one-shot-per-connection HTTPS server that answers every request
/// with `response` (raw HTTP/1.1 bytes). Returns the address and the TLS
/// client config trusting its CA.
async fn https_server(response: Vec<u8>) -> (std::net::SocketAddr, Arc<rustls::ClientConfig>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let srv_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let srv = CertificateParams::new(vec!["cert.example.com".to_string()])
        .unwrap()
        .signed_by(&srv_key, &ca_cert, &ca_key)
        .unwrap();
    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![srv.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(srv_key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let response = response.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 2048];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.write_all(&response).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    (addr, Arc::new(client))
}

fn fetcher(addr: std::net::SocketAddr, tls: Arc<rustls::ClientConfig>, max: usize) -> HttpsFetcher {
    let mut f = HttpsFetcher::new(tls, Arc::new(LoopbackResolver(addr)), max);
    f.allow_loopback = true;
    f
}

#[tokio::test]
async fn https_fetch_ok_cap_status_and_no_redirect() {
    let url = X5uUrl::parse("https://cert.example.com/sti.pem", &[]).unwrap();
    let body = "-----BEGIN CERTIFICATE-----\n";
    let ok = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=120\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (addr, tls) = https_server(ok.into_bytes()).await;
    let f = fetcher(addr, Arc::clone(&tls), 16384);
    let got = f.fetch(&url, Duration::from_secs(2)).await.unwrap();
    assert_eq!(got.body.as_ref(), body.as_bytes());
    assert_eq!(got.max_age_secs, Some(120));
    // Body cap.
    let f = fetcher(addr, tls, 4);
    assert_eq!(
        f.fetch(&url, Duration::from_secs(2)).await.unwrap_err(),
        FetchError::TooLarge
    );

    // Redirects are not followed.
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (addr, tls) = https_server(redirect).await;
    assert_eq!(
        fetcher(addr, tls, 16384)
            .fetch(&url, Duration::from_secs(2))
            .await
            .unwrap_err(),
        FetchError::Status(302)
    );

    // Chunked body over the cap.
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n".to_vec();
    let (addr, tls) = https_server(chunked).await;
    assert_eq!(
        fetcher(addr, tls, 8)
            .fetch(&url, Duration::from_secs(2))
            .await
            .unwrap_err(),
        FetchError::TooLarge
    );
}

#[tokio::test]
async fn https_fetch_timeout() {
    // Accepts TCP but never speaks TLS.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Keep accepted sockets open (never answered) until the test ends.
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
            if held.len() > 8 {
                held.remove(0);
            }
        }
    });
    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth(),
    );
    let url = X5uUrl::parse("https://cert.example.com/sti.pem", &[]).unwrap();
    assert_eq!(
        fetcher(addr, tls, 16384)
            .fetch(&url, Duration::from_millis(200))
            .await
            .unwrap_err(),
        FetchError::Timeout
    );
}

/// Serves `good` for paths starting with `/good`, garbage otherwise.
struct PathSource {
    good: String,
    calls: AtomicUsize,
    delay: Duration,
}

impl CertSource for PathSource {
    fn fetch<'a>(
        &'a self,
        url: &'a X5uUrl,
        _timeout: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Fetched, FetchError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            let body = if url.path.starts_with("/good") {
                self.good.clone()
            } else {
                "garbage".to_owned()
            };
            Ok(Fetched {
                body: bytes::Bytes::from(body),
                max_age_secs: None,
            })
        })
    }
}

/// SEC-002: failures live in a separate, smaller store, so a flood of bad
/// `x5u` values cannot evict a good certificate; policy refusals are not
/// cached at all.
#[tokio::test]
async fn negative_flood_cannot_evict_positive() {
    let p = pki(true);
    let src = Arc::new(PathSource {
        good: p.ee_pem.clone(),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    });
    let cache = StiCertCache::new(
        CacheConfig {
            entries: 8,
            ..CacheConfig::default()
        },
        src,
        anchors_for(&p),
    );
    let good = "https://cert.example.com/good.pem";
    assert!(
        cache
            .get_or_fetch(good, Duration::from_secs(1))
            .await
            .is_ok()
    );
    for i in 0..200 {
        let _ = cache
            .get_or_fetch(
                &format!("https://cert.example.com/bad{i}"),
                Duration::from_secs(1),
            )
            .await;
    }
    assert!(cache.cached(good).is_some(), "positive survived the flood");
    assert!(cache.negative_len() <= 2, "negative store is entries/4");
    assert!(cache.len() <= 8 + 2);

    let before = cache.len();
    for i in 0..50 {
        let e = cache
            .get_or_fetch(
                &format!("http://h{i}.example.com/c"),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert_eq!(e, FetchError::Policy("scheme"));
    }
    assert_eq!(cache.len(), before, "policy failures are not cached");
}

/// PERF-007: at most `MAX_FETCHES_PER_HOST` concurrent fetches per host, even
/// with global permits free.
#[tokio::test]
async fn per_host_fetch_cap() {
    let p = pki(true);
    let src = source(p.ee_pem.clone(), 300);
    let cache = StiCertCache::new(CacheConfig::default(), src.clone(), anchors_for(&p));
    let mut tasks = Vec::new();
    for i in 0..crate::cache::MAX_FETCHES_PER_HOST {
        let c = Arc::clone(&cache);
        tasks.push(tokio::spawn(async move {
            c.get_or_fetch(
                &format!("https://slow.example.com/{i}"),
                Duration::from_secs(2),
            )
            .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        cache
            .get_or_fetch("https://slow.example.com/extra", Duration::from_secs(2))
            .await
            .unwrap_err(),
        FetchError::Busy
    );
    // Another host is not affected.
    assert!(
        cache
            .get_or_fetch("https://other.example.com/c", Duration::from_secs(2))
            .await
            .is_ok()
    );
    for t in tasks {
        assert!(t.await.unwrap().is_ok());
    }
    // Slots are released when the fetches finish.
    assert!(
        cache
            .get_or_fetch("https://slow.example.com/extra", Duration::from_secs(2))
            .await
            .is_ok()
    );
}

/// SEC-003: a fetch that began before an anchor change cannot store its
/// result afterwards.
#[tokio::test]
async fn stale_generation_result_dropped() {
    let p = pki(true);
    let src = source(p.ee_pem.clone(), 200);
    let cache = StiCertCache::new(CacheConfig::default(), src.clone(), anchors_for(&p));
    let c = Arc::clone(&cache);
    let first = tokio::spawn(async move { c.get_or_fetch(X5U, Duration::from_secs(2)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let g = cache.generation();
    cache.invalidate();
    assert_eq!(cache.generation(), g + 1);
    // SEC-010: the waiter gets a failure, not the key validated under the
    // old anchors.
    assert!(matches!(
        first.await.unwrap(),
        Err(FetchError::Untrusted("anchors-changed"))
    ));
    assert!(cache.cached(X5U).is_none(), "old-generation result dropped");
    assert_eq!(cache.stats.stale_results.load(Ordering::Relaxed), 1);
    // A fresh fetch under the new generation fills the cache.
    assert!(
        cache
            .get_or_fetch(X5U, Duration::from_secs(2))
            .await
            .is_ok()
    );
    assert!(cache.cached(X5U).is_some());
    assert_eq!(src.calls.load(Ordering::SeqCst), 2);
}
