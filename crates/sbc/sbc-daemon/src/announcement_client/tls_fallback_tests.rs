//! SR-41 fix round 1 (SEC-001 / NIST-001): which Play failures may fall
//! back to in-process playback. A TLS handshake or certificate failure
//! (foreign-CA server, rejected client certificate) and a client PEM error
//! are refusals; only a failure before TLS (connection refused, DNS) or the
//! setup timeout falls back. In-process stub AnnouncementService over
//! rcgen P-384 mTLS.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, SC-5, SC-7

use std::net::SocketAddr;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use sbc_grpc_api::mtls::{ClientNameGate, ServerTls, load_server_tls};
use sbc_grpc_api::sbc::announcement_service_server::{
    AnnouncementService, AnnouncementServiceServer,
};
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{AnnouncementBound, PlayAnnouncementEvent, PlayAnnouncementRequest};
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status};

use super::{
    AnnouncementTls, ClientTls, RemoteAnnouncement, RemoteAnnouncementError,
    start_remote_announcement_with,
};
use crate::announcement::AnnouncementType;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Answers Bound, or RESOURCE_EXHAUSTED for destination port 1.
struct Stub;

#[tonic::async_trait]
impl AnnouncementService for Stub {
    type PlayStream = tonic::codegen::BoxStream<PlayAnnouncementEvent>;

    async fn play(
        &self,
        request: Request<PlayAnnouncementRequest>,
    ) -> Result<Response<Self::PlayStream>, Status> {
        if request.get_ref().rtp_destination.ends_with(":1") {
            return Err(Status::resource_exhausted("cap"));
        }
        let bound = PlayAnnouncementEvent {
            event: Some(Event::Bound(AnnouncementBound {
                advertised_ip: "192.0.2.9".to_string(),
                rtp_port: 40000,
            })),
        };
        let stream = tokio_stream::iter([Ok(bound)]).chain(tokio_stream::pending());
        Ok(Response::new(Box::pin(stream)))
    }
}

struct Pki {
    pem: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Pki {
    fn new(cn: &str) -> Result<Self, rcgen::Error> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = p.self_signed(&key)?;
        Ok(Self {
            pem: cert.pem(),
            cert,
            key,
        })
    }

    fn leaf(
        &self,
        san: &str,
        eku: ExtendedKeyUsagePurpose,
    ) -> Result<(String, String), rcgen::Error> {
        let mut p = CertificateParams::new(vec![san.to_string()])?;
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = p.signed_by(&key, &self.cert, &self.key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }
}

struct Pod {
    addr: SocketAddr,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// Writes a test PEM file without blocking the runtime.
async fn write_pem(path: std::path::PathBuf, pem: &str) -> std::io::Result<std::path::PathBuf> {
    tokio::fs::write(&path, pem).await?;
    Ok(path)
}

/// An mTLS stub pod whose server certificate comes from `server_ca` and
/// which admits client certificates from `client_ca` named `sbc-sbc-daemon`.
async fn pod(
    dir: &std::path::Path,
    server_ca: &Pki,
    client_ca: &Pki,
) -> Result<Pod, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (crt, key) = server_ca.leaf("127.0.0.1", ExtendedKeyUsagePurpose::ServerAuth)?;
    let tls = ServerTls {
        cert: write_pem(dir.join("pod.crt"), &crt).await?,
        key: write_pem(dir.join("pod.key"), &key).await?,
        client_ca: write_pem(dir.join("pod-ca.crt"), &client_ca.pem).await?,
    };
    let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let gate = ClientNameGate::new(true, &["sbc-sbc-daemon".to_string()], "AnnouncementService");
    let router = tonic::transport::Server::builder()
        .tls_config(load_server_tls(&tls)?)?
        .add_service(AnnouncementServiceServer::with_interceptor(Stub, gate));
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        router
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    Ok(Pod { addr, _stop: stop })
}

/// Client TLS trusting `trust` with a leaf from `issuer`.
fn client(
    dir: &std::path::Path,
    tag: &str,
    trust: &Pki,
    issuer: &Pki,
    san: &str,
) -> Result<AnnouncementTls, Box<dyn std::error::Error>> {
    let (crt, key) = issuer.leaf(san, ExtendedKeyUsagePurpose::ClientAuth)?;
    let w = |n: &str, s: &str| -> std::io::Result<std::path::PathBuf> {
        let p = dir.join(format!("{tag}-{n}"));
        std::fs::write(&p, s)?;
        Ok(p)
    };
    Ok(ClientTls {
        ca: w("ca.crt", &trust.pem)?,
        cert: w("c.crt", &crt)?,
        key: w("c.key", &key)?,
        domain: None,
    })
}

async fn play(
    url: &str,
    tls: Option<&AnnouncementTls>,
    port: u16,
) -> Result<RemoteAnnouncement, RemoteAnnouncementError> {
    let dest = SocketAddr::from(([192, 0, 2, 50], port));
    start_remote_announcement_with(url, tls, AnnouncementType::Silence, dest, 7, "tls-test").await
}

#[tokio::test]
async fn tls_failures_do_not_fall_back() -> TestResult {
    let dir = tempfile::tempdir()?;
    let ca = Pki::new("pod-ca")?;
    let other = Pki::new("other-ca")?;
    let p = pod(dir.path(), &ca, &ca).await?;
    let url = format!("https://{}", p.addr);

    // Positive control: matching CA and an admitted client certificate.
    let good = client(dir.path(), "good", &ca, &ca, "sbc-sbc-daemon")?;
    let s = play(&url, Some(&good), 40000).await;
    assert!(
        s.as_ref().is_ok_and(|s| s.rtp_port == 40000),
        "{:?}",
        s.err()
    );

    // The pod's own refusal is final.
    let e = play(&url, Some(&good), 1)
        .await
        .err()
        .ok_or("cap refusal")?;
    assert_eq!(
        e.refused_code(),
        Some(tonic::Code::ResourceExhausted),
        "{e}"
    );
    assert!(!e.fallback_allowed());

    // Foreign-CA server: the daemon does not trust the pod certificate.
    let untrusting = client(dir.path(), "untrusting", &other, &ca, "sbc-sbc-daemon")?;
    let e = play(&url, Some(&untrusting), 40000)
        .await
        .err()
        .ok_or("foreign-CA server must fail")?;
    assert!(!e.fallback_allowed(), "foreign-CA server fell back: {e}");

    // Rejected client certificate: issued by a CA the pod does not trust.
    let rejected = client(dir.path(), "rejected", &ca, &other, "sbc-sbc-daemon")?;
    let e = play(&url, Some(&rejected), 40000)
        .await
        .err()
        .ok_or("rejected client cert must fail")?;
    assert!(!e.fallback_allowed(), "rejected client cert fell back: {e}");

    // Trusted CA but a name outside the allow-list: the gate's
    // PERMISSION_DENIED.
    let unlisted = client(dir.path(), "unlisted", &ca, &ca, "someone-else")?;
    let e = play(&url, Some(&unlisted), 40000)
        .await
        .err()
        .ok_or("unlisted name must fail")?;
    assert_eq!(e.refused_code(), Some(tonic::Code::PermissionDenied), "{e}");

    // A missing client PEM file is a configuration error, not a fallback.
    let mut broken = good.clone();
    broken.key = dir.path().join("missing.key");
    let e = play(&url, Some(&broken), 40000)
        .await
        .err()
        .ok_or("missing key must fail")?;
    assert!(!e.fallback_allowed(), "{e}");
    Ok(())
}

#[tokio::test]
async fn pre_tls_failures_fall_back() -> TestResult {
    let dir = tempfile::tempdir()?;
    let ca = Pki::new("pod-ca")?;
    let tls = client(dir.path(), "c", &ca, &ca, "sbc-sbc-daemon")?;

    // Nothing listening: TCP connect refused before TLS.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let e = play(&format!("https://127.0.0.1:{port}"), Some(&tls), 40000)
        .await
        .err()
        .ok_or("refused connect must fail")?;
    assert!(
        e.fallback_allowed(),
        "connection refused must fall back: {e}"
    );

    // Name resolution failure.
    let e = play("https://no-such-pod.invalid:9095", Some(&tls), 40000)
        .await
        .err()
        .ok_or("DNS failure must fail")?;
    assert!(e.fallback_allowed(), "DNS failure must fall back: {e}");
    Ok(())
}

#[tokio::test]
async fn setup_timeout_falls_back() -> TestResult {
    let dir = tempfile::tempdir()?;
    let ca = Pki::new("pod-ca")?;
    let tls = client(dir.path(), "c", &ca, &ca, "sbc-sbc-daemon")?;
    // Accepts TCP and never answers the TLS ClientHello.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = silent.local_addr()?;
    let hold = tokio::spawn(async move {
        // Accepted sockets are held open (never read) until the task ends.
        let mut held = Vec::new();
        while let Ok((c, _)) = silent.accept().await {
            held.push(c);
            tracing::trace!(open = held.len(), "silent pod holding connection");
        }
    });
    let e = play(&format!("https://{addr}"), Some(&tls), 40000)
        .await
        .err()
        .ok_or("silent pod must time out")?;
    assert!(e.fallback_allowed(), "setup timeout must fall back: {e}");
    hold.abort();
    Ok(())
}
