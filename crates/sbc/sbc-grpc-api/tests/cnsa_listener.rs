//! SR-41 (NIST-002): a listener built with `sbc_grpc_api::mtls` under the
//! process-default `cnsa_provider()` refuses non-CNSA clients (AES-128 /
//! X25519 only, TLS 1.2 only) and still admits the daemon's client, which
//! uses rustls' aws-lc default provider, negotiating AES-256-GCM-SHA384.
//!
//! Its own test binary: the process-default provider is global, so it must
//! not share a process with tests that install another one.
//!
//! ## NIST 800-53 Rev5: SC-13, SC-8, IA-3

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sbc_grpc_api::health::health_check_response::ServingStatus;
use sbc_grpc_api::health::health_client::HealthClient;
use sbc_grpc_api::health::health_server::{Health, HealthServer};
use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse};
use sbc_grpc_api::mtls::{
    ClientNameGate, ClientTls, ServerTls, client_channel, cnsa_provider, load_server_tls,
};
use tonic::{Request, Response, Status};

struct Serving;

#[tonic::async_trait]
impl Health for Serving {
    async fn check(
        &self,
        _r: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        }))
    }

    type WatchStream = tonic::codegen::BoxStream<HealthCheckResponse>;

    async fn watch(
        &self,
        _r: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        Err(Status::unimplemented("watch"))
    }
}

struct Leaf {
    pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

struct Pki {
    pem: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Pki {
    fn new() -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(DnType::CommonName, "cnsa-test-ca");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = p.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            cert,
            key,
        }
    }

    fn leaf(&self, san: &str, eku: ExtendedKeyUsagePurpose) -> Leaf {
        self.leaf_with(san, eku, &PKCS_ECDSA_P384_SHA384)
    }

    fn leaf_with(
        &self,
        san: &str,
        eku: ExtendedKeyUsagePurpose,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> Leaf {
        let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate_for(alg).unwrap();
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        Leaf {
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
            key_der: key.serialize_der(),
        }
    }
}

struct Fixture {
    ca: Pki,
    client: Leaf,
    addr: SocketAddr,
    dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> Fixture {
    let _ = cnsa_provider().install_default();
    let ca = Pki::new();
    let server = ca.leaf("127.0.0.1", ExtendedKeyUsagePurpose::ServerAuth);
    let client = ca.leaf("sbc-sbc-daemon", ExtendedKeyUsagePurpose::ClientAuth);
    let dir = tempfile::tempdir().unwrap();
    let w = |n: &str, s: &str| {
        let p = dir.path().join(n);
        std::fs::write(&p, s).unwrap();
        p
    };
    let tls = ServerTls {
        cert: w("s.crt", &server.pem),
        key: w("s.key", &server.key_pem),
        client_ca: w("ca.crt", &ca.pem),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let gate = ClientNameGate::new(true, &["sbc-sbc-daemon".to_string()], "Health");
    let router = tonic::transport::Server::builder()
        .tls_config(load_server_tls(&tls).unwrap())
        .unwrap()
        .add_service(HealthServer::with_interceptor(Serving, gate));
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        router
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Fixture {
        ca,
        client,
        addr,
        dir,
        _stop: stop,
    }
}

/// A raw rustls client handshake with `provider` and `versions`.
async fn handshake(
    f: &Fixture,
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<(rustls::CipherSuite, rustls::NamedGroup), String> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            rustls_pemfile_like(&f.ca.pem).expect("ca der"),
        ))
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(f.client.key_der.clone()));
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![f.client.der.clone()], key)
        .map_err(|e| e.to_string())?;
    let mut cfg = cfg;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(f.addr)
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::IpAddress(f.addr.ip().into());
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (_, conn) = tls.get_ref();
    let suite = conn.negotiated_cipher_suite().ok_or("no suite")?.suite();
    let group = conn
        .negotiated_key_exchange_group()
        .ok_or("no group")?
        .name();
    Ok((suite, group))
}

/// DER of the first PEM block (test helper; the input is our own PEM).
fn rustls_pemfile_like(pem: &str) -> Option<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .ok()
        .map(|c| c.to_vec())
}

#[tokio::test]
async fn cnsa_listener_refuses_non_cnsa_and_admits_daemon_client() {
    let f = start().await;

    // AES-128-GCM / X25519 only: no common suite or group.
    let weak = CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256],
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..aws_lc_rs::default_provider()
    };
    let r = handshake(&f, weak, &[&rustls::version::TLS13]).await;
    assert!(r.is_err(), "AES-128/X25519 client admitted: {r:?}");

    // TLS 1.2 only.
    let r = handshake(
        &f,
        aws_lc_rs::default_provider(),
        &[&rustls::version::TLS12],
    )
    .await;
    assert!(r.is_err(), "TLS 1.2 client admitted: {r:?}");

    // The daemon's client: aws-lc default provider, default versions.
    let (suite, group) = handshake(&f, aws_lc_rs::default_provider(), rustls::DEFAULT_VERSIONS)
        .await
        .expect("daemon default client must connect");
    assert_eq!(suite, rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
    assert!(
        matches!(
            group,
            rustls::NamedGroup::secp384r1 | rustls::NamedGroup::MLKEM1024
        ),
        "{group:?}"
    );

    // And a real RPC through the shared client helper.
    let w = |n: &str, s: &str| {
        let p = f.dir.path().join(n);
        std::fs::write(&p, s).unwrap();
        p
    };
    let tls = ClientTls {
        ca: w("c-ca.crt", &f.ca.pem),
        cert: w("c.crt", &f.client.pem),
        key: w("c.key", &f.client.key_pem),
        domain: None,
    };
    let ch = client_channel(
        &format!("https://{}", f.addr),
        Some(&tls),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let resp = HealthClient::new(ch)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("health over the CNSA listener");
    assert_eq!(resp.into_inner().status, ServingStatus::Serving as i32);
}

/// SEC-010: the listener verifies ECDSA P-384 / SHA-384 signatures only, so
/// a client certificate with a P-256 key (even one issued by the trusted
/// P-384 CA) is refused, for the daemon's default-provider client too.
#[tokio::test]
async fn cnsa_listener_refuses_p256_client_certificate() {
    use tokio::io::AsyncReadExt;
    let f = start().await;
    let p256 = f.ca.leaf_with(
        "sbc-sbc-daemon",
        ExtendedKeyUsagePurpose::ClientAuth,
        &PKCS_ECDSA_P256_SHA256,
    );

    // Raw handshake with rustls' default provider (the daemon's), P-256 key.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            rustls_pemfile_like(&f.ca.pem).expect("ca der"),
        ))
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p256.key_der.clone()));
    let mut cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![p256.der.clone()], key)
            .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(f.addr).await.unwrap();
    let name = ServerName::IpAddress(f.addr.ip().into());
    let refused = match tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
    {
        Err(_) => true,
        // TLS 1.3: the client finishes before the server checks its
        // certificate; the refusal arrives as an alert / close on read. An
        // accepted client instead waits for the HTTP/2 exchange (timeout).
        Ok(mut tls) => {
            let mut b = [0u8; 1];
            matches!(
                tokio::time::timeout(Duration::from_secs(2), tls.read(&mut b)).await,
                Ok(Ok(0) | Err(_))
            )
        }
    };
    assert!(refused, "P-256 client certificate was admitted");

    // And over the shared client helper: the RPC fails.
    let w = |n: &str, s: &str| {
        let p = f.dir.path().join(n);
        std::fs::write(&p, s).unwrap();
        p
    };
    let tls = ClientTls {
        ca: w("p256-ca.crt", &f.ca.pem),
        cert: w("p256.crt", &p256.pem),
        key: w("p256.key", &p256.key_pem),
        domain: None,
    };
    let ch = client_channel(
        &format!("https://{}", f.addr),
        Some(&tls),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let r = HealthClient::new(ch)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await;
    assert!(r.is_err(), "P-256 client reached the service: {r:?}");
}
