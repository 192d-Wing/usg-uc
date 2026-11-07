//! DoD PKI certificate identity extraction and validation.

use crate::error::UserMgmtError;

/// Identity information extracted from a DoD PKI X.509 certificate.
#[derive(Debug, Clone)]
pub struct PkiIdentity {
    /// Full Subject Distinguished Name.
    pub subject_dn: String,
    /// Subject Common Name (CN).
    pub subject_cn: String,
    /// Email address from Subject or SAN.
    pub email: Option<String>,
    /// User Principal Name from SAN.
    pub upn: Option<String>,
    /// DoD Electronic Data Interchange Personal Identifier.
    pub edipi: Option<String>,
    /// Issuer Common Name.
    pub issuer_cn: String,
    /// Certificate serial number (hex-encoded).
    pub serial_number: String,
    /// Certificate expiry as Unix timestamp.
    pub not_after: i64,
}

/// Validator for DoD PKI certificates.
///
/// Holds the CA bundle path. Identity extraction currently fails closed
/// (POA&M-233); no chain validation is performed.
pub struct PkiValidator {
    /// Path to the CA bundle PEM file.
    ca_bundle_path: String,
}

impl PkiValidator {
    /// Create a new PKI validator with the given CA bundle.
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::CertificateValidationFailed` if the CA bundle
    /// cannot be read or parsed.
    pub fn new(ca_bundle_path: &str) -> Result<Self, UserMgmtError> {
        // Verify the CA bundle path exists
        if !std::path::Path::new(ca_bundle_path).exists() {
            return Err(UserMgmtError::CertificateValidationFailed(format!(
                "CA bundle not found: {ca_bundle_path}"
            )));
        }

        Ok(Self {
            ca_bundle_path: ca_bundle_path.to_owned(),
        })
    }

    /// Return the configured CA bundle path.
    #[must_use]
    pub fn ca_bundle_path(&self) -> &str {
        &self.ca_bundle_path
    }

    /// Extract identity information from a DER-encoded X.509 certificate.
    ///
    /// **Fails closed: always returns an error.** The previous implementation
    /// substring-matched `CN=` in the raw DER bytes without validating the
    /// chain, validity period, key usage or revocation status, so any
    /// self-signed certificate containing `CN=` would have authenticated.
    /// No caller uses this today; it stays rejected until a real validator
    /// exists.
    ///
    /// NIST 800-53 Rev5: IA-2(12) (PIV acceptance), IA-5(2) (PKI-based
    /// authentication), SC-24 (fail in known state)
    ///
    /// POAM: POA&M-233 - implement RFC 5280 §6 path validation with
    /// rustls-webpki `EndEntityCert::verify_for_usage` (CNSA signature
    /// algorithms, client-auth EKU, `RevocationOptionsBuilder` with CRLs and
    /// `UnknownStatusPolicy::Deny`), plus a DER subject/SAN parser for
    /// EDIPI/UPN (needs an `x509-cert` dependency plan entry).
    ///
    /// # Errors
    ///
    /// Always returns `UserMgmtError::CertificateValidationFailed`.
    pub fn extract_identity(&self, cert_der: &[u8]) -> Result<PkiIdentity, UserMgmtError> {
        let _ = cert_der;
        Err(UserMgmtError::CertificateValidationFailed(
            "PKI certificate validation not implemented (POA&M-233)".to_owned(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn validator() -> PkiValidator {
        // Any existing path satisfies `new`; the bundle is not parsed.
        PkiValidator::new(env!("CARGO_MANIFEST_DIR")).unwrap()
    }

    #[test]
    fn missing_bundle_rejected() {
        assert!(PkiValidator::new("/nonexistent/ca-bundle.pem").is_err());
    }

    #[test]
    fn self_signed_with_cn_rejected() {
        // Bytes that the old substring parser would have accepted as
        // CN=DOE.JOHN.M.1234567890 with an EDIPI.
        let forged = b"\x30\x82CN=DOE.JOHN.M.1234567890,OU=DoD,E=x@example.mil";
        assert!(matches!(
            validator().extract_identity(forged),
            Err(UserMgmtError::CertificateValidationFailed(_))
        ));
    }

    #[test]
    fn any_input_rejected() {
        let v = validator();
        for input in [&[0x30u8, 0x03, 0x02, 0x01, 0x01][..], &[0xff; 64][..]] {
            assert!(v.extract_identity(input).is_err());
        }
    }

    #[test]
    fn empty_input_rejected() {
        assert!(validator().extract_identity(&[]).is_err());
    }
}
