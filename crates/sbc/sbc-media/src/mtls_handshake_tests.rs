//! In-process mTLS handshake for the `MediaController` listener: rcgen P-384
//! CA, a server certificate with an IP SAN (as the pool compose uses) and
//! client certificates, driven by the daemon-side client
//! (`sbc_media_core::grpc_media_controller::connect_channel`).
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use sbc_grpc_api::sbc::media_controller_service_client::MediaControllerServiceClient;
use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerServiceServer;
use sbc_media_core::grpc_media_controller::{MediaControllerTls, connect_channel};
use sbc_media_core::grpc_media_server::MediaControllerServer;
use sbc_media_core::media_pipeline::{MediaPipeline, MediaPipelineConfig};
use tonic::transport::Server;

use crate::grpc_tls::{ClientNameGate, ServerTls, load_server_tls};

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
        p.distinguished_name
            .push(DnType::CommonName, "test-media-ca");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = p.self_signed(&key)?;
        Ok(Self {
            pem: cert.pem(),
            cert,
            key,
        })
    }

    /// `(cert_pem, key_pem)` signed by this CA.
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

#[tokio::test]
async fn mtls_listener_admits_only_allow_listed_client() -> TestResult {
    let ca = Pki::new()?;
    let other_ca = Pki::new()?;
    let server = ca.leaf(&["127.0.0.1"], ExtendedKeyUsagePurpose::ServerAuth)?;
    let daemon = ca.leaf(&["sbc-daemon"], ExtendedKeyUsagePurpose::ClientAuth)?;
    let other = ca.leaf(&["other-workload"], ExtendedKeyUsagePurpose::ClientAuth)?;
    let foreign = other_ca.leaf(&["sbc-daemon"], ExtendedKeyUsagePurpose::ClientAuth)?;

    let dir = tempfile::tempdir()?;
    let write = |n: &str, s: &str| -> std::io::Result<std::path::PathBuf> {
        let p = dir.path().join(n);
        std::fs::write(&p, s)?;
        Ok(p)
    };
    let server_tls = ServerTls {
        cert: write("srv.crt", &server.0)?,
        key: write("srv.key", &server.1)?,
        client_ca: write("ca.crt", &ca.pem)?,
    };
    let port = free_port()?;
    let listen = SocketAddr::from(([127, 0, 0, 1], port));
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let service = MediaControllerServer::new(
        Arc::new(MediaPipeline::new(MediaPipelineConfig::default())),
        None,
        rx,
    );
    let gate = ClientNameGate::new(true, &["sbc-daemon".to_string()]);
    let router = Server::builder()
        .tls_config(load_server_tls(&server_tls)?)?
        .add_service(MediaControllerServiceServer::with_interceptor(
            service, gate,
        ));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        router
            .serve_with_shutdown(listen, async {
                let _ = stop_rx.await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let url = format!("https://127.0.0.1:{port}");
    let client_tls = |c: &(String, String), n: &str| -> std::io::Result<MediaControllerTls> {
        Ok(MediaControllerTls {
            ca: write("ca-client.crt", &ca.pem)?,
            cert: write(&format!("{n}.crt"), &c.0)?,
            key: write(&format!("{n}.key"), &c.1)?,
            domain: None,
        })
    };
    // One RPC: `None` when the channel cannot be set up, else the status
    // (code, message) the call ended with.
    let call = |tls: MediaControllerTls| {
        let url = url.clone();
        async move {
            let ch = connect_channel(&url, Some(&tls)).await.ok()?;
            let st = MediaControllerServiceClient::new(ch)
                .get_dtls_fingerprint(())
                .await
                .err()?;
            Some((st.code(), st.message().to_string()))
        }
    };
    // The service's own answer for this pipeline (no DTLS identity).
    let reached = |r: &Option<(tonic::Code, String)>| {
        r.as_ref()
            .is_some_and(|(_, m)| m.contains("DTLS not configured"))
    };

    // Allow-listed client: the RPC reaches the service.
    let ok = call(client_tls(&daemon, "daemon")?).await;
    assert!(reached(&ok), "allow-listed client: {ok:?}");
    // Same CA, name not on the list: refused by the gate.
    let refused = call(client_tls(&other, "other")?).await;
    assert!(
        refused
            .as_ref()
            .is_some_and(|(c, _)| *c == tonic::Code::PermissionDenied),
        "{refused:?}"
    );
    // Certificate from another CA: the handshake or the call fails.
    let foreign_r = call(client_tls(&foreign, "foreign")?).await;
    assert!(!reached(&foreign_r), "foreign CA: {foreign_r:?}");

    // A plaintext client cannot talk to the TLS listener.
    let plain = sbc_media_core::grpc_media_controller::GrpcMediaController::connect(format!(
        "http://127.0.0.1:{port}"
    ))
    .await;
    if let Ok(mc) = plain {
        assert!(mc.fetch_dtls_fingerprint().await.is_err());
    }

    let _ = stop_tx.send(());
    let _ = srv.await;
    Ok(())
}
