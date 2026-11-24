//! SR-41 QA: in-process mTLS handshake for the announcement listener. rcgen
//! P-384 CA, a server certificate with an IP SAN, client certificates;
//! the server is wired as `main` wires it (`sbc_grpc_api::mtls`), the
//! client side uses `sbc_grpc_api::mtls::client_endpoint` as the daemon does.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use sbc_grpc_api::mtls::{ClientNameGate, ClientTls, ServerTls, client_endpoint, load_server_tls};
use sbc_grpc_api::sbc::announcement_service_client::AnnouncementServiceClient;
use sbc_grpc_api::sbc::announcement_service_server::AnnouncementServiceServer;
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{AnnouncementKind, PlayAnnouncementEvent, PlayAnnouncementRequest};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Server};

use crate::AnnouncementServiceImpl;
use crate::config::Config;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Pki {
    pem: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Pki {
    fn new() -> Result<Self, rcgen::Error> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "test-ann-ca");
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
        sans: &[&str],
        eku: ExtendedKeyUsagePurpose,
    ) -> Result<(String, String), rcgen::Error> {
        let mut p =
            CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())?;
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = p.signed_by(&key, &self.cert, &self.key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn lab_config() -> Result<Config, String> {
    let m: HashMap<&str, &str> = [
        ("SBC_ANN_GRPC_LISTEN", "127.0.0.1:0"),
        ("SBC_ANN_ADVERTISED_IP", "127.0.0.1"),
        ("SBC_ANN_BIND_IP", "127.0.0.1"),
        ("SBC_ANN_ALLOW_LOOPBACK_DEST", "true"),
    ]
    .into_iter()
    .collect();
    Config::from_lookup(|k: &str| m.get(k).map(|v| (*v).to_string()))
}

fn play_req(dest: SocketAddr) -> PlayAnnouncementRequest {
    PlayAnnouncementRequest {
        kind: AnnouncementKind::Silence as i32,
        rtp_destination: dest.to_string(),
        ssrc: 7,
        initial_delay_ms: 1,
        call_id: "qa-mtls".to_string(),
    }
}

/// Outcome of one Play attempt.
#[derive(Debug)]
enum Outcome {
    /// The channel could not be set up (handshake refused).
    NoChannel,
    /// The RPC got a Bound event.
    Bound,
    /// The RPC ended with this status.
    Status(tonic::Code),
}

async fn play_over(ch: Result<tonic::transport::Channel, String>, dest: SocketAddr) -> Outcome {
    let Ok(ch) = ch else {
        return Outcome::NoChannel;
    };
    let mut client = AnnouncementServiceClient::new(ch);
    match client.play(play_req(dest)).await {
        Err(st) => Outcome::Status(st.code()),
        Ok(resp) => match resp.into_inner().message().await {
            Ok(Some(PlayAnnouncementEvent {
                event: Some(Event::Bound(_)),
            })) => Outcome::Bound,
            Ok(_) => Outcome::Status(tonic::Code::Unknown),
            Err(st) => Outcome::Status(st.code()),
        },
    }
}

struct Fixture {
    ca: Pki,
    other_ca: Pki,
    dir: tempfile::TempDir,
    port: u16,
    sink: tokio::net::UdpSocket,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Fixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = Pki::new()?;
        let other_ca = Pki::new()?;
        let server = ca.leaf(&["127.0.0.1"], ExtendedKeyUsagePurpose::ServerAuth)?;
        let dir = tempfile::tempdir()?;
        let w = |n: &str, s: &str| -> std::io::Result<std::path::PathBuf> {
            let p = dir.path().join(n);
            std::fs::write(&p, s)?;
            Ok(p)
        };
        let server_tls = ServerTls {
            cert: w("srv.crt", &server.0)?,
            key: w("srv.key", &server.1)?,
            client_ca: w("ca.crt", &ca.pem)?,
        };
        let port = free_port()?;
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        let gate =
            ClientNameGate::new(true, &["sbc-sbc-daemon".to_string()], "AnnouncementService");
        let svc = AnnouncementServiceImpl::new(lab_config()?);
        let router = Server::builder()
            .tls_config(load_server_tls(&server_tls)?)?
            .add_service(AnnouncementServiceServer::with_interceptor(svc, gate));
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            router
                .serve_with_shutdown(listen, async {
                    let _ = stop_rx.await;
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self {
            ca,
            other_ca,
            dir,
            port,
            sink,
            stop: Some(stop_tx),
        })
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn dest(&self) -> SocketAddr {
        self.sink
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9)))
    }

    /// Client TLS for a leaf with `sans`, issued by `ca`.
    fn client(
        &self,
        ca: &Pki,
        sans: &[&str],
        tag: &str,
    ) -> Result<ClientTls, Box<dyn std::error::Error>> {
        let leaf = ca.leaf(sans, ExtendedKeyUsagePurpose::ClientAuth)?;
        let w = |n: &str, s: &str| -> std::io::Result<std::path::PathBuf> {
            let p = self.dir.path().join(n);
            std::fs::write(&p, s)?;
            Ok(p)
        };
        Ok(ClientTls {
            ca: w(&format!("{tag}-ca.crt"), &self.ca.pem)?,
            cert: w(&format!("{tag}.crt"), &leaf.0)?,
            key: w(&format!("{tag}.key"), &leaf.1)?,
            domain: None,
        })
    }

    async fn channel(&self, tls: &ClientTls) -> Result<tonic::transport::Channel, String> {
        let ep = client_endpoint(
            &self.url(),
            Some(tls),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await?;
        ep.connect().await.map_err(|e| e.to_string())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

#[tokio::test]
async fn qa_mtls_allowed_client_plays() -> TestResult {
    let f = Fixture::start().await?;
    let tls = f.client(&f.ca, &["sbc-sbc-daemon"], "daemon")?;
    let r = play_over(f.channel(&tls).await, f.dest()).await;
    assert!(matches!(r, Outcome::Bound), "{r:?}");
    // SAN DNS names compare case-insensitively.
    let tls = f.client(&f.ca, &["SBC-SBC-Daemon"], "daemon-uc")?;
    let r = play_over(f.channel(&tls).await, f.dest()).await;
    assert!(matches!(r, Outcome::Bound), "{r:?}");
    Ok(())
}

#[tokio::test]
async fn qa_mtls_no_client_cert_refused() -> TestResult {
    let f = Fixture::start().await?;
    // Trusts the server, presents no client certificate.
    let ep = Endpoint::from_shared(f.url())?
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&f.ca.pem)))?;
    let ch = ep.connect().await.map_err(|e| e.to_string());
    let r = play_over(ch, f.dest()).await;
    assert!(
        !matches!(r, Outcome::Bound),
        "no client cert reached Play: {r:?}"
    );
    // A certificate from another CA is refused as well.
    let foreign = f.client(&f.other_ca, &["sbc-sbc-daemon"], "foreign")?;
    let r = play_over(f.channel(&foreign).await, f.dest()).await;
    assert!(
        !matches!(r, Outcome::Bound),
        "foreign CA reached Play: {r:?}"
    );
    Ok(())
}

#[tokio::test]
async fn qa_mtls_unlisted_san_permission_denied() -> TestResult {
    let f = Fixture::start().await?;
    let tls = f.client(&f.ca, &["other-workload"], "other")?;
    let r = play_over(f.channel(&tls).await, f.dest()).await;
    assert!(
        matches!(r, Outcome::Status(tonic::Code::PermissionDenied)),
        "{r:?}"
    );
    Ok(())
}

#[tokio::test]
async fn qa_plaintext_client_to_tls_listener_fails() -> TestResult {
    let f = Fixture::start().await?;
    let ch = Endpoint::from_shared(format!("http://127.0.0.1:{}", f.port))?
        .connect()
        .await
        .map_err(|e| e.to_string());
    let r = play_over(ch, f.dest()).await;
    assert!(!matches!(r, Outcome::Bound), "{r:?}");
    Ok(())
}
