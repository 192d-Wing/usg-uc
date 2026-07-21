//! The SBC's DTLS-SRTP identity: certificate + private key + SDP fingerprint.
//!
//! DTLS-SRTP certificates are validated by the SDP `a=fingerprint`, not by a
//! CA/PKI (RFC 8122). So the SBC generates an ephemeral self-signed P-384
//! certificate at startup unless an operator supplies `cert_path`/`key_path`.
//! The fingerprint is advertised in rewritten SDP so peers can bind the DTLS
//! handshake to the offered/answered identity.
//!
//! ## NIST 800-53 Rev5 Controls
//! - **SC-12**: Cryptographic Key Establishment (DTLS-SRTP)
//! - **SC-13**: Cryptographic Protection (P-384 / SHA-384, CNSA 2.0)

use proto_dtls::fingerprint::CertificateFingerprint;
use std::path::Path;

/// Errors building the SBC's DTLS identity.
#[derive(Debug, thiserror::Error)]
pub enum DtlsIdentityError {
    /// Self-signed certificate generation failed.
    #[error("DTLS certificate generation failed: {0}")]
    Generate(String),
    /// Loading an operator-provided cert/key failed.
    #[error("DTLS certificate load failed: {0}")]
    Load(String),
}

/// The SBC's DTLS-SRTP identity (ephemeral self-signed P-384 by default).
///
/// Holds the DER certificate chain + PKCS#8 key used to drive the DTLS
/// handshake (later phases) and the precomputed SDP `a=fingerprint` value
/// advertised in rewritten offers/answers.
#[derive(Clone)]
pub struct DtlsIdentity {
    /// DER-encoded certificate chain (leaf first).
    cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded PKCS#8 private key.
    key_der: Vec<u8>,
    /// SDP `a=fingerprint` value, e.g. `sha-384 AB:CD:...`.
    sdp_fingerprint: String,
}

impl DtlsIdentity {
    /// Generates an ephemeral self-signed P-384 identity (CNSA 2.0).
    ///
    /// # Errors
    /// Returns an error if key generation or self-signing fails.
    pub fn generate() -> Result<Self, DtlsIdentityError> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .map_err(|e| DtlsIdentityError::Generate(e.to_string()))?;
        let params = CertificateParams::new(vec!["usg-sbc".to_string()])
            .map_err(|e| DtlsIdentityError::Generate(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| DtlsIdentityError::Generate(e.to_string()))?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        Ok(Self::from_der(vec![cert_der], key_der))
    }

    /// Loads an identity from operator-provided PEM cert + key files, reusing
    /// proto-dtls' PEM parsing (yields a DER cert chain + DER key).
    ///
    /// # Errors
    /// Returns an error if the files cannot be read/parsed or contain no cert.
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self, DtlsIdentityError> {
        let cfg = proto_dtls::DtlsConfig::default()
            .with_pem_files(cert_path, key_path)
            .map_err(|e| DtlsIdentityError::Load(e.to_string()))?;
        if cfg.certificate_chain.is_empty() {
            return Err(DtlsIdentityError::Load(
                "no certificates found in PEM".to_string(),
            ));
        }
        Ok(Self::from_der(cfg.certificate_chain, cfg.private_key))
    }

    /// Builds the identity from a DER cert chain + DER key, computing the
    /// SHA-384 SDP fingerprint over the leaf certificate.
    fn from_der(cert_chain_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Self {
        let sdp_fingerprint =
            CertificateFingerprint::from_certificate_sha384(&cert_chain_der[0]).to_sdp();
        Self {
            cert_chain_der,
            key_der,
            sdp_fingerprint,
        }
    }

    /// The SDP `a=fingerprint` value to advertise (e.g. `sha-384 AB:CD:...`).
    #[must_use]
    pub fn sdp_fingerprint(&self) -> &str {
        &self.sdp_fingerprint
    }

    /// DER-encoded certificate chain (leaf first) for the DTLS handshake.
    #[must_use]
    pub fn cert_chain_der(&self) -> &[Vec<u8>] {
        &self.cert_chain_der
    }

    /// DER-encoded PKCS#8 private key for the DTLS handshake.
    #[must_use]
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generates_p384_identity_with_sha384_fingerprint() {
        let id = DtlsIdentity::generate().unwrap();

        // Advertised fingerprint is CNSA 2.0 SHA-384 in SDP form.
        let fp = id.sdp_fingerprint();
        assert!(fp.starts_with("sha-384 "), "fingerprint: {fp}");

        // A DER cert + key were produced.
        assert_eq!(id.cert_chain_der().len(), 1);
        assert!(!id.cert_chain_der()[0].is_empty());
        assert!(!id.key_der().is_empty());

        // The advertised fingerprint actually matches the leaf certificate.
        let parsed = CertificateFingerprint::from_sdp(fp).unwrap();
        parsed.verify(&id.cert_chain_der()[0]).unwrap();
    }

    #[test]
    fn each_generated_identity_is_unique() {
        let a = DtlsIdentity::generate().unwrap();
        let b = DtlsIdentity::generate().unwrap();
        assert_ne!(a.sdp_fingerprint(), b.sdp_fingerprint());
    }
}
