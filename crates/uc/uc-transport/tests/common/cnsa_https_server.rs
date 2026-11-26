//! Test-only HTTPS server with a selectable TLS profile (SR-16).
//!
//! Shared by `uc-transport/tests/https_client.rs` and, through `#[path]`,
//! by the management-plane HTTP client tests in sbc-daemon, sbc-api-server,
//! sbc-client-config-server, central-config-api and sbc-config-sync.
//!
//! Keys and certificates are generated at runtime (rcgen); nothing is
//! hard-coded. The server answers every request with `200 ok`.
#![allow(
    dead_code,
    missing_docs,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Leaf key type for the server certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafKey {
    /// ECDSA P-384 (CNSA).
    P384,
    /// RSA 2048 (accepted on TLS 1.3 only by the CNSA client).
    Rsa,
}

/// Random CA plus a leaf for `127.0.0.1` / `localhost`. The CA is always
/// ECDSA P-384.
pub struct TestPki {
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub fn pki(leaf: LeafKey) -> TestPki {
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sr16 test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_alg = match leaf {
        LeafKey::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        LeafKey::Rsa => &rcgen::PKCS_RSA_SHA256,
    };
    let leaf_key = rcgen::KeyPair::generate_for(leaf_alg).unwrap();
    let leaf_cert =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
    TestPki {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        chain: vec![leaf_cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    }
}

static TLS13_AND_12: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];
static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

/// What the test server offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// CNSA: TLS 1.3 `AES_256_GCM_SHA384` + TLS 1.2 `ECDHE_ECDSA_AES256_GCM_SHA384`,
    /// groups ML-KEM-1024 / P-384, P-384 leaf. TLS 1.2 and 1.3.
    Cnsa,
    /// CNSA suites and P-384 leaf, TLS 1.2 only.
    CnsaTls12Only,
    /// TLS 1.3 `TLS13_AES_128_GCM_SHA256` only (default groups).
    Aes128Only,
    /// AES-256 suites, X25519 only.
    X25519Only,
    /// TLS 1.2 only, `ECDHE_ECDSA_AES128_GCM_SHA256` only, P-384 leaf.
    Tls12NonCnsaSuite,
    /// TLS 1.2 only, `ECDHE_RSA_AES256_GCM_SHA384` only, RSA leaf.
    Tls12RsaLeaf,
}

impl Profile {
    /// Every profile a CNSA-only client must refuse.
    pub const NON_CNSA: [Self; 4] = [
        Self::Aes128Only,
        Self::X25519Only,
        Self::Tls12NonCnsaSuite,
        Self::Tls12RsaLeaf,
    ];

    pub const fn leaf_key(self) -> LeafKey {
        match self {
            Self::Tls12RsaLeaf => LeafKey::Rsa,
            _ => LeafKey::P384,
        }
    }

    fn provider(self) -> CryptoProvider {
        let base = rustls::crypto::aws_lc_rs::default_provider();
        match self {
            Self::Cnsa | Self::CnsaTls12Only => CryptoProvider {
                cipher_suites: vec![
                    cipher_suite::TLS13_AES_256_GCM_SHA384,
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                ],
                kx_groups: vec![kx_group::MLKEM1024, kx_group::SECP384R1],
                ..base
            },
            Self::Aes128Only => CryptoProvider {
                cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
                ..base
            },
            Self::X25519Only => CryptoProvider {
                cipher_suites: vec![
                    cipher_suite::TLS13_AES_256_GCM_SHA384,
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                ],
                kx_groups: vec![kx_group::X25519],
                ..base
            },
            Self::Tls12NonCnsaSuite => CryptoProvider {
                cipher_suites: vec![cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                kx_groups: vec![kx_group::SECP384R1],
                ..base
            },
            Self::Tls12RsaLeaf => CryptoProvider {
                cipher_suites: vec![cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
                kx_groups: vec![kx_group::SECP384R1],
                ..base
            },
        }
    }

    fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self {
            Self::Cnsa | Self::Aes128Only | Self::X25519Only => TLS13_AND_12,
            Self::CnsaTls12Only | Self::Tls12NonCnsaSuite | Self::Tls12RsaLeaf => TLS12_ONLY,
        }
    }

    pub fn server_config(self, pki: &TestPki) -> rustls::ServerConfig {
        rustls::ServerConfig::builder_with_provider(Arc::new(self.provider()))
            .with_protocol_versions(self.versions())
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.key.clone_key())
            .unwrap()
    }
}

/// One completed server-side handshake.
#[derive(Clone, Copy, Debug)]
pub struct Negotiated {
    pub version: rustls::ProtocolVersion,
    pub suite: rustls::CipherSuite,
    pub group: Option<rustls::NamedGroup>,
}

/// A running test server. Dropping it does not stop the accept task; the
/// test runtime does.
pub struct HttpsServer {
    pub addr: SocketAddr,
    pub profile: Profile,
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    /// Handshakes the server completed, in order.
    pub handshakes: Arc<Mutex<Vec<Negotiated>>>,
}

impl HttpsServer {
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}/", self.addr.port())
    }

    pub fn completed_handshakes(&self) -> Vec<Negotiated> {
        self.handshakes.lock().unwrap().clone()
    }

    /// Waits (up to 5 s) until the server has logged `n` handshakes. With
    /// TLS 1.3 the client finishes before the server reads its Finished.
    pub async fn wait_handshakes(&self, n: usize) -> Vec<Negotiated> {
        for _ in 0..500 {
            let hs = self.completed_handshakes();
            if hs.len() >= n {
                return hs;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.completed_handshakes()
    }
}

/// Starts an HTTPS server on `127.0.0.1:0` offering `profile`. Must be
/// called inside a tokio runtime.
pub async fn spawn(profile: Profile) -> HttpsServer {
    let pki = pki(profile.leaf_key());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(profile.server_config(&pki)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&handshakes);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                {
                    let (_, conn) = tls.get_ref();
                    log.lock().unwrap().push(Negotiated {
                        version: conn.protocol_version().unwrap(),
                        suite: conn.negotiated_cipher_suite().unwrap().suite(),
                        group: conn
                            .negotiated_key_exchange_group()
                            .map(rustls::crypto::SupportedKxGroup::name),
                    });
                }
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    if buf.len() > 64 * 1024 {
                        return;
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
                          content-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    HttpsServer {
        addr,
        profile,
        ca_pem: pki.ca_pem,
        ca_der: pki.ca_der,
        handshakes,
    }
}

/// Runs a rustls client handshake (no HTTP) against `server` and returns
/// the negotiated version and suite as the client saw them.
pub async fn rustls_handshake(
    config: rustls::ClientConfig,
    addr: SocketAddr,
) -> std::io::Result<Negotiated> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let name =
        rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into());
    let tls = connector.connect(name, tcp).await?;
    let (_, conn) = tls.get_ref();
    Ok(Negotiated {
        version: conn.protocol_version().unwrap(),
        suite: conn.negotiated_cipher_suite().unwrap().suite(),
        group: conn
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name),
    })
}

/// Writes `contents` to a fresh file under the cargo target dir (next to
/// the test binary) and returns its path. Not cleaned up.
pub fn temp_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe
        .parent()
        .unwrap()
        .join(format!("sr16-https-tmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{tag}-{}.pem", rand_suffix()));
    std::fs::write(&path, contents).unwrap();
    path
}

/// libtest name of `fn_name` declared in the module `module_path`
/// (pass `module_path!()`): the crate segment is dropped.
pub fn test_name(module_path: &str, fn_name: &str) -> String {
    module_path.split_once("::").map_or_else(
        || fn_name.to_string(),
        |(_, rest)| format!("{rest}::{fn_name}"),
    )
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// Env var that marks a re-executed child test process (value: mode).
pub const CHILD_ENV: &str = "SR16_HTTPS_CHILD";
/// Env var carrying the parent's test-server address to the child.
pub const SERVER_ADDR_ENV: &str = "SR16_HTTPS_SERVER_ADDR";

/// `Some(mode)` when running as a re-executed child, else `None`.
pub fn child_mode() -> Option<String> {
    std::env::var(CHILD_ENV).ok()
}

/// Address of the server the parent started (child side).
pub fn child_server_addr() -> SocketAddr {
    std::env::var(SERVER_ADDR_ENV).unwrap().parse().unwrap()
}

/// `https://` URL of the server the parent started (child side).
pub fn child_server_url() -> String {
    format!("https://127.0.0.1:{}/", child_server_addr().port())
}

/// Re-runs the current test binary for exactly `test_name` with
/// `SSL_CERT_FILE` set to `cert_file` and `SSL_CERT_DIR` cleared, so the
/// OS-root path of rustls-native-certs sees only that file. The parent's
/// environment is never mutated. `server` (if any) keeps running in the
/// parent and its address is passed to the child. Blocking: call it from
/// `spawn_blocking` when the server runs on the same runtime. Returns true
/// if the child passed.
pub fn run_child(
    test_name: &str,
    mode: &str,
    cert_file: &std::path::Path,
    server: Option<SocketAddr>,
) -> bool {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, mode)
        .env("SSL_CERT_FILE", cert_file)
        .env_remove("SSL_CERT_DIR");
    if let Some(addr) = server {
        cmd.env(SERVER_ADDR_ENV, addr.to_string());
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("--- child {test_name} ({mode}) stdout ---\n{stdout}");
    eprintln!("--- child {test_name} ({mode}) stderr ---\n{stderr}");
    // A filter that matched nothing also exits 0 ("0 passed").
    assert!(
        stdout.contains("1 passed") || !out.status.success(),
        "child run of {test_name} did not execute exactly one test"
    );
    out.status.success()
}

/// Async wrapper for [`run_child`] (multi-thread runtime required so the
/// parent's server keeps serving while the child runs).
pub async fn run_child_async(
    test_name: String,
    mode: &'static str,
    cert_file: std::path::PathBuf,
    server: Option<SocketAddr>,
) -> bool {
    tokio::task::spawn_blocking(move || run_child(&test_name, mode, &cert_file, server))
        .await
        .unwrap()
}
