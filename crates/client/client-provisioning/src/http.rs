//! HTTP client construction with configurable CA trust.
//!
//! Discovery, OIDC metadata, token, and config endpoints live behind the
//! deployment's TLS (often an internal CA the workstation doesn't ship). The
//! client uses the OS trust store (rustls native roots) and can additionally
//! trust an explicit PEM — mirroring the server pods'
//! `SBC_CLIENT_CONFIG_EXTRA_CA_CERT_FILE`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::error::ProvisioningError;

/// How the provisioning HTTP client establishes TLS trust.
#[derive(Debug, Clone, Default)]
pub enum CaTrust {
    /// OS trust store only (rustls native roots).
    #[default]
    System,
    /// OS trust store plus the given extra CA PEM (the internal IdP CA).
    ExtraPem(PathBuf),
    /// Accept any certificate. **Development only** — this variant does not
    /// exist in release builds (mirrors `CertVerificationMode::Insecure` in
    /// `client-core`), so fielded clients cannot bypass TLS validation.
    #[cfg(debug_assertions)]
    Insecure,
}

/// Builds a reqwest client honouring `trust`, with conservative timeouts.
///
/// TLS is a preconfigured rustls `ClientConfig` on the shared CNSA 2.0
/// provider (TLS 1.3, AES-256-GCM, ML-KEM-1024 / P-384) rather than reqwest's
/// built-in default provider. Only `https` URLs are accepted and redirects
/// are never followed, so a bearer token is only sent to the URL that was
/// validated.
///
/// NIST 800-53 Rev5: SC-8 (https only), IA-5, AC-4 (no redirects).
///
/// # Errors
/// [`ProvisioningError::Http`] if the extra CA file cannot be read/parsed or
/// the client fails to build.
pub fn build_http_client(trust: &CaTrust) -> Result<reqwest::Client, ProvisioningError> {
    build_http_client_with(trust, true)
}

/// Same as [`build_http_client`] with `https_only` selectable so the
/// redirect policy can be exercised against a plaintext local listener in
/// tests. [`build_http_client`] calls this with `https_only = true`.
pub(crate) fn build_http_client_with(
    trust: &CaTrust,
    https_only: bool,
) -> Result<reqwest::Client, ProvisioningError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("usg-uc-softclient/", env!("CARGO_PKG_VERSION")))
        .https_only(https_only)
        // Every endpoint is validated before use; a 3xx surfaces as an error
        // status instead of being followed to an unvalidated location.
        .redirect(reqwest::redirect::Policy::none());

    match trust {
        CaTrust::System => {
            builder = builder.use_preconfigured_tls(build_tls_config(None)?);
        }
        CaTrust::ExtraPem(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                ProvisioningError::Http(format!(
                    "failed to read extra CA `{}`: {e}",
                    path.display()
                ))
            })?;
            builder = builder.use_preconfigured_tls(build_tls_config(Some(&pem))?);
        }
        #[cfg(debug_assertions)]
        CaTrust::Insecure => {
            // Development only (absent from release builds). Still the CNSA
            // provider: reqwest has no crypto provider of its own.
            tracing::warn!("INSECURE: provisioning TLS certificates are not validated");
            builder = builder.use_preconfigured_tls(build_insecure_tls_config()?);
        }
    }

    builder
        .build()
        .map_err(|e| ProvisioningError::Http(format!("http client build failed: {e}")))
}

/// Builds the CNSA 2.0 rustls client config: OS trust store plus an optional
/// extra CA PEM bundle.
///
/// NIST 800-53 Rev5: SC-8(1), SC-13 (CNSA 2.0 provider), IA-5(2) (PKI path
/// validation against the OS/extra trust anchors).
fn build_tls_config(extra_pem: Option<&[u8]>) -> Result<rustls::ClientConfig, ProvisioningError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        tracing::warn!(error = %e, "error loading native certificate");
    }
    let (_added, _ignored) = roots.add_parsable_certificates(native.certs);

    if let Some(pem) = extra_pem {
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| {
                ProvisioningError::Http(format!("failed to parse extra CA PEM: {e}"))
            })?;
            roots
                .add(cert)
                .map_err(|e| ProvisioningError::Http(format!("failed to add extra CA: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(ProvisioningError::Http(
                "failed to parse extra CA PEM: no certificates found".to_owned(),
            ));
        }
    }

    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(uc_transport::tls::cnsa_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ProvisioningError::Http(format!("failed to configure TLS 1.3: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(config)
}

/// Development-only config (absent from release builds): CNSA provider and
/// TLS 1.3, but the server certificate is not validated.
#[cfg(debug_assertions)]
fn build_insecure_tls_config() -> Result<rustls::ClientConfig, ProvisioningError> {
    let provider = Arc::new(uc_transport::tls::cnsa_provider());
    let verifier = Arc::new(InsecureCertVerifier(Arc::clone(&provider)));
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProvisioningError::Http(format!("failed to configure TLS 1.3: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// Accepts any server certificate (mirrors client-core's
/// `InsecureCertVerifier`). Handshake signatures are still checked with the
/// provider's algorithms. **Development only.**
#[cfg(debug_assertions)]
#[derive(Debug)]
struct InsecureCertVerifier(Arc<rustls::crypto::CryptoProvider>);

#[cfg(debug_assertions)]
impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_uses_cnsa_provider() -> Result<(), ProvisioningError> {
        let cfg = build_tls_config(None)?;
        let want = uc_transport::tls::cnsa_provider();
        let got = cfg.crypto_provider();
        let suites = |p: &rustls::crypto::CryptoProvider| {
            p.cipher_suites
                .iter()
                .map(rustls::SupportedCipherSuite::suite)
                .collect::<Vec<_>>()
        };
        let groups = |p: &rustls::crypto::CryptoProvider| {
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        };
        assert_eq!(suites(got), suites(&want));
        assert_eq!(groups(got), groups(&want));
        assert!(!groups(got).contains(&rustls::NamedGroup::X25519));
        Ok(())
    }

    #[test]
    fn extra_pem_without_certs_is_rejected() {
        assert!(build_tls_config(Some(b"not a pem")).is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn insecure_tls_config_uses_cnsa_provider() -> Result<(), ProvisioningError> {
        let cfg = build_insecure_tls_config()?;
        assert!(cfg.fips());
        let want = uc_transport::tls::cnsa_provider();
        let got = cfg.crypto_provider();
        let suites = |p: &rustls::crypto::CryptoProvider| {
            p.cipher_suites
                .iter()
                .map(rustls::SupportedCipherSuite::suite)
                .collect::<Vec<_>>()
        };
        let groups = |p: &rustls::crypto::CryptoProvider| {
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        };
        assert_eq!(suites(got), suites(&want));
        assert_eq!(groups(got), groups(&want));
        assert_eq!(
            got.signature_verification_algorithms.supported_schemes(),
            want.signature_verification_algorithms.supported_schemes()
        );
        build_http_client(&CaTrust::Insecure)?;
        Ok(())
    }

    #[test]
    fn build_http_client_system_ok() {
        assert!(build_http_client(&CaTrust::System).is_ok());
    }

    #[test]
    fn extra_pem_missing_file_is_rejected() {
        let trust = CaTrust::ExtraPem(PathBuf::from("/nonexistent/usg-uc-qa/extra-ca.pem"));
        assert!(matches!(
            build_http_client(&trust),
            Err(ProvisioningError::Http(_))
        ));
    }

    #[test]
    fn extra_pem_corrupt_cert_block_is_rejected() {
        let pem = b"-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n";
        assert!(build_tls_config(Some(pem)).is_err());
    }

    /// Reads one HTTP request head (up to the blank line) and answers with
    /// `response`, then closes.
    async fn serve_once(listener: tokio::net::TcpListener, response: String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = sock.write_all(response.as_bytes()).await;
        let _ = sock.shutdown().await;
    }

    #[tokio::test]
    async fn http_client_refuses_plain_http_without_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| unreachable!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| unreachable!("addr: {e}"))
            .port();
        let client =
            build_http_client(&CaTrust::System).unwrap_or_else(|e| unreachable!("client: {e}"));

        let res = tokio::time::timeout(
            Duration::from_secs(3),
            client.get(format!("http://127.0.0.1:{port}/")).send(),
        )
        .await;
        assert!(
            matches!(res, Ok(Err(_))),
            "plain-http request must fail fast: {res:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "no connection may be made for an http:// URL"
        );
    }

    #[tokio::test]
    async fn http_client_does_not_follow_cross_host_redirect() {
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| unreachable!("bind: {e}"));
        let origin_port = origin
            .local_addr()
            .unwrap_or_else(|e| unreachable!("addr: {e}"))
            .port();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| unreachable!("bind: {e}"));
        let target_port = target
            .local_addr()
            .unwrap_or_else(|e| unreachable!("addr: {e}"))
            .port();

        let location = format!("http://localhost:{target_port}/v1/client-config");
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let server = tokio::spawn(serve_once(origin, response));

        // Plaintext only so the redirect policy can be observed without a
        // TLS fixture; production uses `https_only = true`.
        let client = build_http_client_with(&CaTrust::System, false)
            .unwrap_or_else(|e| unreachable!("client: {e}"));
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .get(format!("http://127.0.0.1:{origin_port}/v1/client-config"))
                .bearer_auth("tok")
                .send(),
        )
        .await
        .unwrap_or_else(|_| unreachable!("request timed out"))
        .unwrap_or_else(|e| unreachable!("request failed: {e}"));
        assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
        let _ = server.await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), target.accept())
                .await
                .is_err(),
            "redirect to another host must not be followed"
        );
    }

    #[test]
    fn build_http_client_with_https_only_builds() {
        assert!(build_http_client_with(&CaTrust::System, true).is_ok());
    }

    #[test]
    fn extra_pem_non_cert_block_only_is_rejected() {
        // A key block alone must not be accepted as a trust anchor bundle.
        let pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(build_tls_config(Some(pem)).is_err());
    }
}
