//! PASSporT verification.

use crate::MAX_PASSPORT_AGE;
use crate::error::{StirShakenError, StirShakenResult};
use crate::identity::IdentityHeader;
use crate::passport::Attestation;

/// Verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Signature verified, certificate valid.
    Valid,
    /// Signature verified, but issues with certificate chain.
    ValidWithWarnings,
    /// PASSporT structure valid, signature not verified.
    Unverified,
    /// Verification failed.
    Failed,
    /// No Identity header present.
    NoIdentity,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::ValidWithWarnings => write!(f, "ValidWithWarnings"),
            Self::Unverified => write!(f, "Unverified"),
            Self::Failed => write!(f, "Failed"),
            Self::NoIdentity => write!(f, "NoIdentity"),
        }
    }
}

/// Verification failure reason.
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// Invalid PASSporT format.
    InvalidFormat(String),
    /// Signature verification failed.
    SignatureFailed(String),
    /// Certificate error.
    CertificateError(String),
    /// PASSporT expired.
    Expired {
        /// Age in seconds.
        age_seconds: u64,
        /// Maximum age allowed.
        max_age: u64,
    },
    /// Number mismatch.
    NumberMismatch {
        /// Claimed number.
        claim: String,
        /// Actual number.
        actual: String,
    },
    /// Algorithm not allowed.
    InvalidAlgorithm(String),
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(reason) => write!(f, "Invalid format: {}", reason),
            Self::SignatureFailed(reason) => write!(f, "Signature failed: {}", reason),
            Self::CertificateError(reason) => write!(f, "Certificate error: {}", reason),
            Self::Expired {
                age_seconds,
                max_age,
            } => {
                write!(f, "Expired: {}s > {}s", age_seconds, max_age)
            }
            Self::NumberMismatch { claim, actual } => {
                write!(f, "Number mismatch: claim={}, actual={}", claim, actual)
            }
            Self::InvalidAlgorithm(alg) => write!(f, "Invalid algorithm: {}", alg),
        }
    }
}

/// Verification result.
#[derive(Debug)]
pub struct VerificationResult {
    /// Status.
    status: VerificationStatus,
    /// Attestation level (if verified).
    attestation: Option<Attestation>,
    /// Originating number (if verified).
    orig_number: Option<String>,
    /// Destination numbers (if verified).
    dest_numbers: Vec<String>,
    /// Certificate URL.
    certificate_url: Option<String>,
    /// Failure reason (if failed).
    failure_reason: Option<FailureReason>,
    /// Warnings.
    warnings: Vec<String>,
}

impl VerificationResult {
    /// Creates a valid result.
    pub fn valid(
        attestation: Attestation,
        orig: impl Into<String>,
        dest: Vec<String>,
        cert_url: impl Into<String>,
    ) -> Self {
        Self {
            status: VerificationStatus::Valid,
            attestation: Some(attestation),
            orig_number: Some(orig.into()),
            dest_numbers: dest,
            certificate_url: Some(cert_url.into()),
            failure_reason: None,
            warnings: Vec::new(),
        }
    }

    /// Creates an unverified result.
    pub fn unverified(
        attestation: Attestation,
        orig: impl Into<String>,
        dest: Vec<String>,
    ) -> Self {
        Self {
            status: VerificationStatus::Unverified,
            attestation: Some(attestation),
            orig_number: Some(orig.into()),
            dest_numbers: dest,
            certificate_url: None,
            failure_reason: None,
            warnings: Vec::new(),
        }
    }

    /// Creates a failed result.
    pub fn failed(reason: FailureReason) -> Self {
        Self {
            status: VerificationStatus::Failed,
            attestation: None,
            orig_number: None,
            dest_numbers: Vec::new(),
            certificate_url: None,
            failure_reason: Some(reason),
            warnings: Vec::new(),
        }
    }

    /// Creates a no-identity result.
    pub fn no_identity() -> Self {
        Self {
            status: VerificationStatus::NoIdentity,
            attestation: None,
            orig_number: None,
            dest_numbers: Vec::new(),
            certificate_url: None,
            failure_reason: None,
            warnings: Vec::new(),
        }
    }

    /// Returns the status.
    pub fn status(&self) -> VerificationStatus {
        self.status
    }

    /// Returns the attestation level.
    pub fn attestation(&self) -> Option<Attestation> {
        self.attestation
    }

    /// Returns the originating number.
    pub fn orig_number(&self) -> Option<&str> {
        self.orig_number.as_deref()
    }

    /// Returns the destination numbers.
    pub fn dest_numbers(&self) -> &[String] {
        &self.dest_numbers
    }

    /// Returns the certificate URL.
    pub fn certificate_url(&self) -> Option<&str> {
        self.certificate_url.as_deref()
    }

    /// Returns the failure reason.
    pub fn failure_reason(&self) -> Option<&FailureReason> {
        self.failure_reason.as_ref()
    }

    /// Returns the warnings.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Adds a warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
        if self.status == VerificationStatus::Valid {
            self.status = VerificationStatus::ValidWithWarnings;
        }
    }

    /// Returns whether verification was successful.
    pub fn is_valid(&self) -> bool {
        matches!(
            self.status,
            VerificationStatus::Valid | VerificationStatus::ValidWithWarnings
        )
    }
}

/// Verifier configuration.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Maximum PASSporT age in seconds.
    pub max_age_seconds: u64,
    /// Whether to verify the certificate chain.
    pub verify_certificate: bool,
    /// Whether to require certificate.
    pub require_certificate: bool,
    /// Allowed attestation levels.
    pub allowed_attestations: Vec<Attestation>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_age_seconds: MAX_PASSPORT_AGE,
            verify_certificate: true,
            require_certificate: false,
            allowed_attestations: vec![
                Attestation::Full,
                Attestation::Partial,
                Attestation::Gateway,
            ],
        }
    }
}

impl VerifierConfig {
    /// Creates a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum age.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Sets whether to verify certificates.
    pub fn with_certificate_verification(mut self, verify: bool) -> Self {
        self.verify_certificate = verify;
        self
    }
}

/// PASSporT verifier.
#[derive(Debug)]
pub struct Verifier {
    /// Configuration.
    config: VerifierConfig,
}

impl Verifier {
    /// Creates a new verifier.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Creates a verifier with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(VerifierConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// Verifies an Identity header.
    ///
    /// Note: This is a structural verification. Full cryptographic verification
    /// requires access to the certificate and would be done at a higher level.
    pub fn verify_identity(&self, header: &IdentityHeader) -> StirShakenResult<VerificationResult> {
        // Parse the token
        let token = header.token();
        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() != 3 {
            return Ok(VerificationResult::failed(FailureReason::InvalidFormat(
                format!("Expected 3 parts, got {}", parts.len()),
            )));
        }

        // Verify algorithm
        if header.alg() != "ES384" {
            return Ok(VerificationResult::failed(FailureReason::InvalidAlgorithm(
                header.alg().to_string(),
            )));
        }

        // For now, return unverified since we don't have crypto implementation
        // In a real implementation, this would verify the signature
        Ok(VerificationResult::unverified(
            Attestation::Gateway, // Default if we can't parse claims
            "unknown".to_string(),
            Vec::new(),
        ))
    }

    /// Verifies the PASSporT age.
    pub fn verify_age(&self, iat: u64) -> StirShakenResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > iat {
            let age = now - iat;
            if age > self.config.max_age_seconds {
                return Err(StirShakenError::Expired {
                    age_seconds: age,
                    max_age: self.config.max_age_seconds,
                });
            }
        }

        Ok(())
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityInfo;

    #[test]
    fn test_verification_status_display() {
        assert_eq!(VerificationStatus::Valid.to_string(), "Valid");
        assert_eq!(VerificationStatus::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_failure_reason_display() {
        let reason = FailureReason::Expired {
            age_seconds: 120,
            max_age: 60,
        };
        assert!(reason.to_string().contains("120"));
    }

    #[test]
    fn test_verification_result_valid() {
        let result = VerificationResult::valid(
            Attestation::Full,
            "15551234567",
            vec!["15559876543".to_string()],
            "https://cert.example.com",
        );

        assert!(result.is_valid());
        assert_eq!(result.status(), VerificationStatus::Valid);
        assert_eq!(result.attestation(), Some(Attestation::Full));
        assert_eq!(result.orig_number(), Some("15551234567"));
    }

    #[test]
    fn test_verification_result_failed() {
        let result =
            VerificationResult::failed(FailureReason::InvalidAlgorithm("ES256".to_string()));

        assert!(!result.is_valid());
        assert_eq!(result.status(), VerificationStatus::Failed);
        assert!(result.failure_reason().is_some());
    }

    #[test]
    fn test_verification_result_warnings() {
        let mut result = VerificationResult::valid(
            Attestation::Full,
            "15551234567",
            Vec::new(),
            "https://cert.example.com",
        );

        result.add_warning("Certificate expires soon");
        assert_eq!(result.status(), VerificationStatus::ValidWithWarnings);
        assert_eq!(result.warnings().len(), 1);
    }

    #[test]
    fn test_verifier_config() {
        let config = VerifierConfig::new()
            .with_max_age(120)
            .with_certificate_verification(false);

        assert_eq!(config.max_age_seconds, 120);
        assert!(!config.verify_certificate);
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = Verifier::with_defaults();
        assert_eq!(verifier.config().max_age_seconds, MAX_PASSPORT_AGE);
    }

    #[test]
    fn test_verifier_verify_identity() {
        let verifier = Verifier::with_defaults();

        let header = IdentityHeader::new(
            "header.claims.signature",
            IdentityInfo::Url("https://cert.example.com".to_string()),
        );

        let result = verifier.verify_identity(&header).unwrap();
        // Without full crypto, returns unverified
        assert_eq!(result.status(), VerificationStatus::Unverified);
    }

    #[test]
    fn test_verifier_verify_identity_invalid_parts() {
        let verifier = Verifier::with_defaults();

        let header = IdentityHeader::new(
            "invalid-token-no-dots",
            IdentityInfo::Url("https://cert.example.com".to_string()),
        );

        let result = verifier.verify_identity(&header).unwrap();
        assert_eq!(result.status(), VerificationStatus::Failed);
    }

    #[test]
    fn test_verifier_verify_age() {
        let verifier = Verifier::with_defaults();

        // Current time should be valid
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(verifier.verify_age(now).is_ok());

        // Old timestamp should fail
        let old = now - 120; // 2 minutes ago
        assert!(verifier.verify_age(old).is_err());
    }
}
