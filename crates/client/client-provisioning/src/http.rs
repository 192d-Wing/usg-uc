//! HTTP client construction with configurable CA trust.
//!
//! Discovery, OIDC metadata, token, and config endpoints live behind the
//! deployment's TLS (often an internal CA the workstation doesn't ship). The
//! client uses the OS trust store (rustls native roots) and can additionally
//! trust an explicit PEM — mirroring the server pods'
//! `SBC_CLIENT_CONFIG_EXTRA_CA_CERT_FILE`.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::ProvisioningError;

/// How the provisioning HTTP client establishes TLS trust.
#[derive(Debug, Clone, Default)]
pub enum CaTrust {
    /// OS trust store only (rustls native roots).
    #[default]
    System,
    /// OS trust store plus the given extra CA PEM (the internal IdP CA).
    ExtraPem(PathBuf),
    /// Accept any certificate. **Development only.**
    Insecure,
}

/// Builds a reqwest client honouring `trust`, with conservative timeouts.
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
        CaTrust::System => {}
        CaTrust::ExtraPem(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                ProvisioningError::Http(format!(
                    "failed to read extra CA `{}`: {e}",
                    path.display()
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                ProvisioningError::Http(format!("failed to parse extra CA PEM: {e}"))
            })?;
            builder = builder.add_root_certificate(cert);
        }
        CaTrust::Insecure => {
            builder = builder.danger_accept_invalid_certs(true);
        }
    }

    builder
        .build()
        .map_err(|e| ProvisioningError::Http(format!("http client build failed: {e}")))
}
