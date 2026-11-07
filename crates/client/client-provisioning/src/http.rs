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
/// built-in default provider.
///
/// # Errors
/// [`ProvisioningError::Http`] if the extra CA file cannot be read/parsed or
/// the client fails to build.
pub fn build_http_client(trust: &CaTrust) -> Result<reqwest::Client, ProvisioningError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("usg-uc-softclient/", env!("CARGO_PKG_VERSION")));

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
            // Development only (absent from release builds); reqwest's own
            // stack is used so certificate checks can be disabled.
            builder = builder.danger_accept_invalid_certs(true);
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

    #[test]
    fn extra_pem_non_cert_block_only_is_rejected() {
        // A key block alone must not be accepted as a trust anchor bundle.
        let pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(build_tls_config(Some(pem)).is_err());
    }
}
