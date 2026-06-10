//! Self-signed TLS bootstrap certificate generation.
//!
//! HTTPS is the default for the management plane (REST API and gRPC). When
//! the operator has not configured a certificate, this module generates a
//! self-signed P-384 ECDSA certificate on first start, persists it with
//! restrictive permissions, and reuses it across restarts. The certificate's
//! SHA-256 fingerprint is logged at startup so operators can pin it in
//! clients (`sbc-cli --ca-cert`, browser trust prompt).
//!
//! Operator-provided certificates (`api.tls_cert_path` / `grpc.tls_cert_path`)
//! always take precedence; this is only a fallback so a fresh install never
//! serves the management plane in cleartext.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment and Management
//! - **SC-13**: Cryptographic Protection (P-384 / CNSA-aligned)

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// File name of the persisted bootstrap certificate (PEM).
const CERT_FILE: &str = "self-signed.crt";
/// File name of the persisted bootstrap private key (PEM).
const KEY_FILE: &str = "self-signed.key";

/// Paths to a persisted bootstrap certificate and key.
#[derive(Debug, Clone)]
pub struct BootstrapCert {
    /// Path to the certificate (PEM).
    pub cert_path: PathBuf,
    /// Path to the private key (PEM).
    pub key_path: PathBuf,
}

/// Errors from bootstrap certificate generation.
#[derive(Debug)]
pub struct BootstrapError {
    /// Human-readable failure reason.
    pub reason: String,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS bootstrap failed: {}", self.reason)
    }
}

impl std::error::Error for BootstrapError {}

/// Returns the directory used to persist the bootstrap certificate.
///
/// Resolution order: `SBC_TLS_DIR` env var, then `/var/lib/sbc/tls`.
pub fn default_tls_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SBC_TLS_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("/var/lib/sbc/tls")
}

/// Ensures a bootstrap certificate exists, generating one if needed.
///
/// Reuses an existing certificate/key pair in `dir` when both files are
/// present. If `dir` is not writable (e.g. running unprivileged in
/// development), falls back to `$HOME/.local/state/sbc/tls`.
///
/// Logs the certificate's SHA-256 fingerprint either way.
///
/// # Errors
///
/// Returns an error if generation or persistence fails in every candidate
/// directory.
pub fn ensure_bootstrap_cert(dir: &Path) -> Result<BootstrapCert, BootstrapError> {
    match ensure_in_dir(dir) {
        Ok(cert) => Ok(cert),
        Err(primary_err) => {
            let fallback = home_fallback_dir().ok_or_else(|| BootstrapError {
                reason: format!(
                    "{} (in {}); no HOME fallback available",
                    primary_err.reason,
                    dir.display()
                ),
            })?;
            warn!(
                primary = %dir.display(),
                fallback = %fallback.display(),
                error = %primary_err.reason,
                "TLS bootstrap directory not usable, falling back"
            );
            ensure_in_dir(&fallback)
        }
    }
}

/// Per-user fallback directory for unprivileged runs.
fn home_fallback_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("sbc")
            .join("tls"),
    )
}

fn ensure_in_dir(dir: &Path) -> Result<BootstrapCert, BootstrapError> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        let fingerprint = fingerprint_pem_file(&cert_path)?;
        info!(
            cert = %cert_path.display(),
            sha256_fingerprint = %fingerprint,
            "Reusing existing bootstrap TLS certificate"
        );
        return Ok(BootstrapCert {
            cert_path,
            key_path,
        });
    }

    std::fs::create_dir_all(dir).map_err(|e| BootstrapError {
        reason: format!("failed to create {}: {e}", dir.display()),
    })?;
    restrict_permissions(dir, 0o700);

    let (cert_pem, key_pem, fingerprint) = generate_self_signed()?;

    write_private(&key_path, &key_pem)?;
    write_private(&cert_path, &cert_pem)?;
    // The certificate itself is public; keep it operator-readable.
    restrict_permissions(&cert_path, 0o644);

    info!(
        cert = %cert_path.display(),
        sha256_fingerprint = %fingerprint,
        "Generated self-signed bootstrap TLS certificate (P-384); \
         configure api.tls_cert_path to use an operator-provided certificate"
    );

    Ok(BootstrapCert {
        cert_path,
        key_path,
    })
}

/// Generates a self-signed P-384 certificate.
///
/// Returns `(cert_pem, key_pem, sha256_fingerprint)`.
fn generate_self_signed() -> Result<(String, String, String), BootstrapError> {
    // SANs: loopback addresses plus the machine hostname when available.
    // rcgen parses IP literals into IP SANs automatically.
    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(hostname) = machine_hostname() {
        if !sans.contains(&hostname) {
            sans.push(hostname);
        }
    }

    let mut params = rcgen::CertificateParams::new(sans).map_err(|e| BootstrapError {
        reason: format!("invalid certificate parameters: {e}"),
    })?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sbc-daemon bootstrap");

    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).map_err(|e| {
            BootstrapError {
                reason: format!("P-384 key generation failed: {e}"),
            }
        })?;

    let cert = params.self_signed(&key_pair).map_err(|e| BootstrapError {
        reason: format!("self-signing failed: {e}"),
    })?;

    let fingerprint = hex_fingerprint(cert.der());

    Ok((cert.pem(), key_pair.serialize_pem(), fingerprint))
}

/// Reads the machine hostname for inclusion as a DNS SAN.
fn machine_hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Computes the SHA-256 fingerprint of a PEM certificate file.
fn fingerprint_pem_file(path: &Path) -> Result<String, BootstrapError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let cert = CertificateDer::from_pem_file(path).map_err(|e| BootstrapError {
        reason: format!("failed to parse {}: {e}", path.display()),
    })?;
    Ok(hex_fingerprint(&cert))
}

fn hex_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 3);
    for (i, byte) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// Writes a file with owner-only permissions (0600).
fn write_private(path: &Path, contents: &str) -> Result<(), BootstrapError> {
    std::fs::write(path, contents).map_err(|e| BootstrapError {
        reason: format!("failed to write {}: {e}", path.display()),
    })?;
    restrict_permissions(path, 0o600);
    Ok(())
}

/// Sets Unix permissions, logging (not failing) on error.
fn restrict_permissions(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            warn!(path = %path.display(), error = %e, "Failed to set permissions");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_reuse() {
        let dir = std::env::temp_dir().join(format!(
            "sbc-tls-bootstrap-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let first = ensure_in_dir(&dir).expect("generation should succeed");
        assert!(first.cert_path.exists());
        assert!(first.key_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&first.key_path)
                .expect("key metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key must be owner-only");
        }

        let first_pem = std::fs::read_to_string(&first.cert_path).expect("read cert");
        let second = ensure_in_dir(&dir).expect("reuse should succeed");
        let second_pem = std::fs::read_to_string(&second.cert_path).expect("read cert");
        assert_eq!(first_pem, second_pem, "existing cert must be reused");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_fingerprint_format() {
        let fp = hex_fingerprint(b"test");
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
    }
}
