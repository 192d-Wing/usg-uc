//! CNSA 2.0 rustls client configuration for outbound management-plane HTTPS
//! (identity provider / JWKS, central config API, token endpoints).
//!
//! Callers hand the returned [`rustls::ClientConfig`] to reqwest's
//! `ClientBuilder::use_preconfigured_tls`. reqwest is built without a crypto
//! provider (`rustls-tls-no-provider`), so this config is the only TLS stack
//! it uses. uc-transport itself stays reqwest-free.
//!
//! - Provider: [`cnsa_provider`] on the aws-lc FIPS module. TLS 1.3
//!   `TLS_AES_256_GCM_SHA384`; TLS 1.2 `ECDHE_ECDSA_AES256_GCM_SHA384`;
//!   ML-KEM-1024 then P-384.
//! - Trust: the OS store (`rustls-native-certs`, which honours
//!   `SSL_CERT_FILE` / `SSL_CERT_DIR`) plus an optional extra CA bundle.
//! - No ALPN: reqwest stays on HTTP/1.1.
//!
//! RFC 8446 §9.1 makes `TLS_AES_128_GCM_SHA256` and X25519/P-256 mandatory
//! to implement; they are deliberately not offered (CNSA 2.0), as on the
//! SIP-TLS listeners. A peer that offers nothing else fails the handshake.
//!
//! ## NIST 800-53 Rev5: SC-8(1), SC-13 (Cryptographic Protection), IA-5(2)

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tracing::warn;

use crate::error::{TransportError, TransportResult};
use crate::tls::{MinTlsVersion, cnsa_provider};

/// CNSA client config for outbound management-plane HTTPS (IdP/JWKS, central API).
///
/// Roots: OS store plus the optional `extra_ca_pem` bundle (PEM, one or more
/// certificates). `min_version` selects TLS 1.2 + 1.3 or 1.3 only; the
/// suites and groups are [`cnsa_provider`]'s either way. Returns a by-value
/// `ClientConfig`: reqwest's `use_preconfigured_tls` downcasts by value and
/// rejects an `Arc`.
///
/// Native roots that fail to load are logged and skipped. This reads
/// certificate files: call it once at startup, not per request.
///
/// ## Errors
///
/// - [`TransportError::TlsCertificateError`] if `extra_ca_pem` holds no
///   certificate or one fails to parse, or if the resulting root store is
///   empty (no trust anchors).
/// - [`TransportError::TlsHandshakeFailed`] if the protocol versions cannot
///   be configured.
pub fn create_https_client_config(
    extra_ca_pem: Option<&[u8]>,
    min_version: MinTlsVersion,
) -> TransportResult<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        warn!(error = %e, "skipping native root certificate");
    }
    let (_added, ignored) = roots.add_parsable_certificates(native.certs);
    if ignored > 0 {
        warn!(
            ignored,
            "native root certificates rejected by the root store"
        );
    }

    if let Some(pem) = extra_ca_pem {
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| TransportError::TlsCertificateError {
                reason: format!("extra CA PEM: {e}"),
            })?;
            roots
                .add(cert)
                .map_err(|e| TransportError::TlsCertificateError {
                    reason: format!("extra CA rejected: {e}"),
                })?;
            added += 1;
        }
        if added == 0 {
            return Err(TransportError::TlsCertificateError {
                reason: "extra CA PEM contains no certificates".to_string(),
            });
        }
    }

    // Fail closed at startup rather than on every request.
    if roots.is_empty() {
        return Err(TransportError::TlsCertificateError {
            reason: "no trust anchors (OS store empty and no extra CA)".to_string(),
        });
    }

    let versions: &[&'static rustls::SupportedProtocolVersion] = match min_version {
        MinTlsVersion::V1_3 => &[&rustls::version::TLS13],
        MinTlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };
    let config = ClientConfig::builder_with_provider(Arc::new(cnsa_provider()))
        .with_protocol_versions(versions)
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS protocol versions: {e}"),
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}
