//! DTLS cipher suite configuration.
//!
//! ## CNSA 2.0 Compliance
//!
//! This module provides only CNSA 2.0 compliant cipher suites:
//! - **TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384** (0xC02C)
//!
//! All other cipher suites (AES-128, SHA-256, P-256) are explicitly forbidden.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-13**: Cryptographic Protection

/// CNSA 2.0 compliant cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
///
/// This is the only cipher suite allowed for CNSA 2.0 compliance in this implementation.
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;

/// Cipher suite ID type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CipherSuiteId(pub u16);

impl CipherSuiteId {
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    pub const AES_256_GCM_SHA384: Self = Self(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);

    /// Returns the raw cipher suite ID value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns the human-readable name of this cipher suite.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            _ => "Unknown",
        }
    }
}

impl From<u16> for CipherSuiteId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:04X})", self.name(), self.0)
    }
}

/// Returns the list of CNSA 2.0 compliant cipher suites.
///
/// Currently only returns TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
#[must_use]
pub fn cnsa_cipher_suites() -> Vec<CipherSuiteId> {
    vec![CipherSuiteId::AES_256_GCM_SHA384]
}

/// Checks if a cipher suite is CNSA 2.0 compliant.
///
/// ## Returns
///
/// `true` only for TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
#[must_use]
pub fn is_cnsa_compliant(cipher_suite: CipherSuiteId) -> bool {
    cipher_suite.0 == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}

/// Checks if a cipher suite is acceptable (same as CNSA compliant).
#[must_use]
pub fn is_acceptable(cipher_suite: CipherSuiteId) -> bool {
    is_cnsa_compliant(cipher_suite)
}

/// Returns the preferred cipher suite (CNSA 2.0 compliant).
#[must_use]
pub const fn preferred_cipher_suite() -> CipherSuiteId {
    CipherSuiteId::AES_256_GCM_SHA384
}

/// Filters a list of cipher suites to CNSA 2.0 compliant ones.
#[must_use]
pub fn filter_acceptable(cipher_suites: &[CipherSuiteId]) -> Vec<CipherSuiteId> {
    cipher_suites
        .iter()
        .copied()
        .filter(|cs| is_acceptable(*cs))
        .collect()
}

/// Non-compliant cipher suites that must be rejected.
///
/// These are explicitly listed to document what is NOT allowed.
pub mod forbidden {
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - Uses AES-128 (forbidden).
    pub const AES_128_GCM_SHA256: u16 = 0xC02B;
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - Uses RSA (not recommended for CNSA 2.0).
    pub const RSA_AES_256_GCM: u16 = 0xC030;
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 - Uses CBC (not AEAD).
    pub const AES_256_CBC_SHA384: u16 = 0xC024;
}

/// Returns a reason why a cipher suite is forbidden.
#[must_use]
pub fn forbidden_reason(cipher_suite_id: u16) -> Option<&'static str> {
    match cipher_suite_id {
        forbidden::AES_128_GCM_SHA256 => Some("AES-128 forbidden by CNSA 2.0 - requires AES-256"),
        forbidden::RSA_AES_256_GCM => {
            Some("RSA key exchange not recommended - use ECDHE with P-384")
        }
        forbidden::AES_256_CBC_SHA384 => Some("CBC mode not recommended - use AEAD (GCM)"),
        id if id & 0xFF00 == 0xC000 && id < TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            Some("Cipher suite uses algorithms weaker than CNSA 2.0 requirements")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnsa_cipher_suite_value() {
        assert_eq!(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0xC02C);
    }

    #[test]
    fn test_cnsa_cipher_suites() {
        let suites = cnsa_cipher_suites();
        assert_eq!(suites.len(), 1);
        assert_eq!(suites[0], CipherSuiteId::AES_256_GCM_SHA384);
    }

    #[test]
    fn test_is_cnsa_compliant() {
        assert!(is_cnsa_compliant(CipherSuiteId::AES_256_GCM_SHA384));
        assert!(!is_cnsa_compliant(CipherSuiteId(
            forbidden::AES_128_GCM_SHA256
        )));
        assert!(!is_cnsa_compliant(CipherSuiteId(
            forbidden::RSA_AES_256_GCM
        )));
    }

    #[test]
    fn test_preferred_cipher_suite() {
        let preferred = preferred_cipher_suite();
        assert!(is_cnsa_compliant(preferred));
        assert_eq!(preferred.value(), 0xC02C);
    }

    #[test]
    fn test_filter_acceptable() {
        let offered = vec![
            CipherSuiteId(forbidden::AES_128_GCM_SHA256),
            CipherSuiteId::AES_256_GCM_SHA384,
            CipherSuiteId(forbidden::RSA_AES_256_GCM),
        ];

        let filtered = filter_acceptable(&offered);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], CipherSuiteId::AES_256_GCM_SHA384);
    }

    #[test]
    fn test_cipher_suite_display() {
        let suite = CipherSuiteId::AES_256_GCM_SHA384;
        let display = format!("{suite}");
        assert!(display.contains("AES_256_GCM_SHA384"));
        assert!(display.contains("0xC02C"));
    }

    #[test]
    fn test_forbidden_reasons() {
        assert!(forbidden_reason(forbidden::AES_128_GCM_SHA256).is_some());
        assert!(forbidden_reason(forbidden::RSA_AES_256_GCM).is_some());
        assert!(forbidden_reason(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384).is_none());
    }
}
