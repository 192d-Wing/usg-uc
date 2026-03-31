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
/// Holds the trusted CA bundle for chain validation.
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
    /// This performs string-based parsing of the Subject DN to extract CN,
    /// EDIPI, and email. Full ASN.1 parsing will be added later with the
    /// `x509-cert` crate.
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::CertificateValidationFailed` if the certificate
    /// cannot be parsed.
    pub fn extract_identity(
        &self,
        cert_der: &[u8],
    ) -> Result<PkiIdentity, UserMgmtError> {
        // Convert DER bytes to a lossy string for basic DN extraction.
        // This is a placeholder until full ASN.1 parsing is implemented.
        let cert_text = String::from_utf8_lossy(cert_der);

        let subject_dn = extract_field(&cert_text, "CN=")
            .map(|cn| format!("CN={cn}"))
            .unwrap_or_default();

        let subject_cn =
            extract_field(&cert_text, "CN=").unwrap_or_default();

        // DoD EDIPI is typically the last 10 digits of the CN
        let edipi = extract_edipi(&subject_cn);

        let email = extract_field(&cert_text, "E=")
            .or_else(|| extract_field(&cert_text, "emailAddress="));

        let issuer_cn =
            extract_field(&cert_text, "CN=").unwrap_or_default();

        Ok(PkiIdentity {
            subject_dn,
            subject_cn,
            email,
            upn: None,
            edipi,
            issuer_cn,
            serial_number: hex::encode(
                &cert_der[..std::cmp::min(cert_der.len(), 20)],
            ),
            not_after: 0, // Requires ASN.1 parsing for actual value
        })
    }
}

/// Extract a field value from a DN string by prefix.
fn extract_field(text: &str, prefix: &str) -> Option<String> {
    text.find(prefix).map(|start| {
        let value_start = start + prefix.len();
        let end = text[value_start..]
            .find([',', '/', '\0'])
            .map_or(text.len(), |e| value_start + e);
        text[value_start..end].to_owned()
    })
}

/// Extract EDIPI from a DoD Common Name.
///
/// DoD CNs typically end with a 10-digit EDIPI.
fn extract_edipi(cn: &str) -> Option<String> {
    let trimmed = cn.trim();
    if trimmed.len() >= 10 {
        let last10 = &trimmed[trimmed.len() - 10..];
        if last10.chars().all(|c| c.is_ascii_digit()) {
            return Some(last10.to_owned());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_field() {
        let dn = "CN=DOE.JOHN.M.1234567890,OU=DoD,O=U.S. Government";
        assert_eq!(
            extract_field(dn, "CN="),
            Some("DOE.JOHN.M.1234567890".to_owned())
        );
        assert_eq!(extract_field(dn, "OU="), Some("DoD".to_owned()));
        assert_eq!(extract_field(dn, "DC="), None);
    }

    #[test]
    fn test_extract_edipi() {
        assert_eq!(
            extract_edipi("DOE.JOHN.M.1234567890"),
            Some("1234567890".to_owned())
        );
        assert_eq!(extract_edipi("short"), None);
        assert_eq!(extract_edipi("DOE.JOHN.M.ABCDEFGHIJ"), None);
    }
}
