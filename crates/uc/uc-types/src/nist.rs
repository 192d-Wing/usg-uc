//! NIST 800-53 Rev5 control identifiers and mappings.
//!
//! This module provides type-safe representations of NIST security controls
//! used throughout the SBC for documentation and compliance tracking.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// NIST 800-53 Rev5 control family.
///
/// These represent the high-level security control families relevant
/// to the SBC implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ControlFamily {
    /// AC - Access Control.
    ///
    /// Controls related to system access, permissions, and session management.
    AccessControl,

    /// AU - Audit and Accountability.
    ///
    /// Controls related to logging, audit trails, and non-repudiation.
    Audit,

    /// IA - Identification and Authentication.
    ///
    /// Controls related to user/device identity verification.
    IdentificationAuthentication,

    /// SC - System and Communications Protection.
    ///
    /// Controls related to cryptography, network security, and data protection.
    SystemCommunications,

    /// SI - System and Information Integrity.
    ///
    /// Controls related to malware protection, monitoring, and error handling.
    SystemIntegrity,

    /// CM - Configuration Management.
    ///
    /// Controls related to baseline configurations and change control.
    ConfigurationManagement,

    /// SA - System and Services Acquisition.
    ///
    /// Controls related to development lifecycle and testing.
    SystemAcquisition,
}

impl ControlFamily {
    /// Returns the two-letter family identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AccessControl => "AC",
            Self::Audit => "AU",
            Self::IdentificationAuthentication => "IA",
            Self::SystemCommunications => "SC",
            Self::SystemIntegrity => "SI",
            Self::ConfigurationManagement => "CM",
            Self::SystemAcquisition => "SA",
        }
    }

    /// Returns the full family name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control",
            Self::Audit => "Audit and Accountability",
            Self::IdentificationAuthentication => "Identification and Authentication",
            Self::SystemCommunications => "System and Communications Protection",
            Self::SystemIntegrity => "System and Information Integrity",
            Self::ConfigurationManagement => "Configuration Management",
            Self::SystemAcquisition => "System and Services Acquisition",
        }
    }
}

impl std::fmt::Display for ControlFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// NIST 800-53 Rev5 control identifier.
///
/// Represents a specific control within a family.
///
/// ## Example
///
/// ```
/// use uc_types::nist::{ControlId, ControlFamily};
///
/// let control = ControlId::new(ControlFamily::SystemCommunications, 13, None);
/// assert_eq!(control.to_string(), "SC-13");
///
/// let enhanced = ControlId::new(ControlFamily::AccessControl, 3, Some(4));
/// assert_eq!(enhanced.to_string(), "AC-3(4)");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlId {
    family: ControlFamily,
    number: u16,
    enhancement: Option<u16>,
}

impl ControlId {
    /// Creates a new control identifier.
    #[must_use]
    pub const fn new(family: ControlFamily, number: u16, enhancement: Option<u16>) -> Self {
        Self {
            family,
            number,
            enhancement,
        }
    }

    /// Returns the control family.
    #[must_use]
    pub fn family(&self) -> ControlFamily {
        self.family
    }

    /// Returns the control number within the family.
    #[must_use]
    pub fn number(&self) -> u16 {
        self.number
    }

    /// Returns the control enhancement number, if any.
    #[must_use]
    pub fn enhancement(&self) -> Option<u16> {
        self.enhancement
    }

    // Common controls used in this project

    /// AC-3: Access Enforcement.
    pub const AC_3: Self = Self::new(ControlFamily::AccessControl, 3, None);

    /// AC-6: Least Privilege.
    pub const AC_6: Self = Self::new(ControlFamily::AccessControl, 6, None);

    /// AU-2: Event Logging.
    pub const AU_2: Self = Self::new(ControlFamily::Audit, 2, None);

    /// AU-3: Content of Audit Records.
    pub const AU_3: Self = Self::new(ControlFamily::Audit, 3, None);

    /// AU-9: Protection of Audit Information.
    pub const AU_9: Self = Self::new(ControlFamily::Audit, 9, None);

    /// IA-2: Identification and Authentication (Organizational Users).
    pub const IA_2: Self = Self::new(ControlFamily::IdentificationAuthentication, 2, None);

    /// IA-5: Authenticator Management.
    pub const IA_5: Self = Self::new(ControlFamily::IdentificationAuthentication, 5, None);

    /// IA-9: Service Identification and Authentication.
    pub const IA_9: Self = Self::new(ControlFamily::IdentificationAuthentication, 9, None);

    /// SC-5: Denial of Service Protection.
    pub const SC_5: Self = Self::new(ControlFamily::SystemCommunications, 5, None);

    /// SC-7: Boundary Protection.
    pub const SC_7: Self = Self::new(ControlFamily::SystemCommunications, 7, None);

    /// SC-8: Transmission Confidentiality and Integrity.
    pub const SC_8: Self = Self::new(ControlFamily::SystemCommunications, 8, None);

    /// SC-12: Cryptographic Key Establishment and Management.
    pub const SC_12: Self = Self::new(ControlFamily::SystemCommunications, 12, None);

    /// SC-13: Cryptographic Protection.
    pub const SC_13: Self = Self::new(ControlFamily::SystemCommunications, 13, None);

    /// SC-23: Session Authenticity.
    pub const SC_23: Self = Self::new(ControlFamily::SystemCommunications, 23, None);

    /// SI-3: Malicious Code Protection.
    pub const SI_3: Self = Self::new(ControlFamily::SystemIntegrity, 3, None);

    /// SI-4: System Monitoring.
    pub const SI_4: Self = Self::new(ControlFamily::SystemIntegrity, 4, None);

    /// SI-11: Error Handling.
    pub const SI_11: Self = Self::new(ControlFamily::SystemIntegrity, 11, None);

    /// CM-2: Baseline Configuration.
    pub const CM_2: Self = Self::new(ControlFamily::ConfigurationManagement, 2, None);

    /// SA-11: Developer Testing and Evaluation.
    pub const SA_11: Self = Self::new(ControlFamily::SystemAcquisition, 11, None);
}

impl std::fmt::Display for ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.enhancement {
            Some(enh) => write!(f, "{}-{}({})", self.family.code(), self.number, enh),
            None => write!(f, "{}-{}", self.family.code(), self.number),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_family_codes() {
        assert_eq!(ControlFamily::AccessControl.code(), "AC");
        assert_eq!(ControlFamily::Audit.code(), "AU");
        assert_eq!(ControlFamily::SystemCommunications.code(), "SC");
    }

    #[test]
    fn test_control_id_display() {
        assert_eq!(ControlId::SC_13.to_string(), "SC-13");
        assert_eq!(ControlId::AU_2.to_string(), "AU-2");

        let enhanced = ControlId::new(ControlFamily::AccessControl, 3, Some(4));
        assert_eq!(enhanced.to_string(), "AC-3(4)");
    }

    #[test]
    fn test_control_id_components() {
        let control = ControlId::SC_8;
        assert_eq!(control.family(), ControlFamily::SystemCommunications);
        assert_eq!(control.number(), 8);
        assert_eq!(control.enhancement(), None);
    }
}
