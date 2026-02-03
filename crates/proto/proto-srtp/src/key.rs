//! SRTP key material and derivation.
//!
//! ## CNSA 2.0 Compliance
//!
//! Key derivation uses HKDF-SHA384 instead of the standard SRTP KDF
//! which uses SHA-1. This provides CNSA 2.0 compliance.

use crate::SrtpProfile;
use crate::error::{SrtpError, SrtpResult};

/// Master key material for SRTP.
///
/// This contains the master key and salt from which session keys
/// are derived.
#[derive(Clone)]
pub struct SrtpKeyMaterial {
    /// Master key (256 bits for AES-256-GCM).
    master_key: Vec<u8>,
    /// Master salt (96 bits for AES-256-GCM).
    master_salt: Vec<u8>,
    /// SRTP profile.
    profile: SrtpProfile,
}

impl SrtpKeyMaterial {
    /// Creates new SRTP key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key or salt length is incorrect for the profile.
    pub fn new(
        profile: SrtpProfile,
        master_key: Vec<u8>,
        master_salt: Vec<u8>,
    ) -> SrtpResult<Self> {
        if master_key.len() != profile.master_key_len() {
            return Err(SrtpError::InvalidKey {
                reason: format!(
                    "master key length {} doesn't match profile requirement {}",
                    master_key.len(),
                    profile.master_key_len()
                ),
            });
        }

        if master_salt.len() != profile.master_salt_len() {
            return Err(SrtpError::InvalidKey {
                reason: format!(
                    "master salt length {} doesn't match profile requirement {}",
                    master_salt.len(),
                    profile.master_salt_len()
                ),
            });
        }

        Ok(Self {
            master_key,
            master_salt,
            profile,
        })
    }

    /// Returns the profile.
    #[must_use]
    pub fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Returns the master key.
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Returns the master salt.
    #[must_use]
    pub fn master_salt(&self) -> &[u8] {
        &self.master_salt
    }

    /// Derives a session encryption key.
    ///
    /// ## CNSA 2.0 Compliance
    ///
    /// Uses HKDF-SHA384 for key derivation.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_session_key(&self, label: KeyDerivationLabel) -> SrtpResult<Vec<u8>> {
        let key_len = self.profile.session_key_len();
        let mut output = vec![0u8; key_len];

        // Use HKDF-SHA384 for CNSA 2.0 compliance
        let info = [label.as_bytes(), b"srtp"].concat();

        uc_crypto::hkdf::hkdf_sha384(
            Some(&self.master_salt),
            &self.master_key,
            &[&info],
            &mut output,
        )
        .map_err(|_| SrtpError::KeyDerivationFailed {
            reason: "HKDF-SHA384 failed".to_string(),
        })?;

        Ok(output)
    }

    /// Derives a session salt.
    ///
    /// ## Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_session_salt(&self, label: KeyDerivationLabel) -> SrtpResult<Vec<u8>> {
        let salt_len = self.profile.master_salt_len();
        let mut output = vec![0u8; salt_len];

        let info = [label.as_bytes(), b"salt"].concat();

        uc_crypto::hkdf::hkdf_sha384(
            Some(&self.master_salt),
            &self.master_key,
            &[&info],
            &mut output,
        )
        .map_err(|_| SrtpError::KeyDerivationFailed {
            reason: "HKDF-SHA384 failed for salt".to_string(),
        })?;

        Ok(output)
    }
}

impl std::fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpKeyMaterial")
            .field("profile", &self.profile)
            .field("master_key", &"[REDACTED]")
            .field("master_salt", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SrtpKeyMaterial {
    fn drop(&mut self) {
        // Zeroize sensitive material
        self.master_key.fill(0);
        self.master_salt.fill(0);
    }
}

/// Labels for SRTP key derivation per RFC 3711 / RFC 7714.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDerivationLabel {
    /// RTP encryption key.
    RtpEncryption,
    /// RTP authentication key (not used with GCM).
    RtpAuthentication,
    /// RTP salt.
    RtpSalt,
    /// RTCP encryption key.
    RtcpEncryption,
    /// RTCP authentication key (not used with GCM).
    RtcpAuthentication,
    /// RTCP salt.
    RtcpSalt,
}

impl KeyDerivationLabel {
    /// Returns the label bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::RtpEncryption => b"\x00",
            Self::RtpAuthentication => b"\x01",
            Self::RtpSalt => b"\x02",
            Self::RtcpEncryption => b"\x03",
            Self::RtcpAuthentication => b"\x04",
            Self::RtcpSalt => b"\x05",
        }
    }
}

/// Derived session keys for SRTP.
#[derive(Clone)]
pub struct SessionKeys {
    /// RTP encryption key.
    pub rtp_key: Vec<u8>,
    /// RTP salt.
    pub rtp_salt: Vec<u8>,
    /// RTCP encryption key.
    pub rtcp_key: Vec<u8>,
    /// RTCP salt.
    pub rtcp_salt: Vec<u8>,
}

impl SessionKeys {
    /// Derives all session keys from master key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive(material: &SrtpKeyMaterial) -> SrtpResult<Self> {
        Ok(Self {
            rtp_key: material.derive_session_key(KeyDerivationLabel::RtpEncryption)?,
            rtp_salt: material.derive_session_salt(KeyDerivationLabel::RtpSalt)?,
            rtcp_key: material.derive_session_key(KeyDerivationLabel::RtcpEncryption)?,
            rtcp_salt: material.derive_session_salt(KeyDerivationLabel::RtcpSalt)?,
        })
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("rtp_key", &"[REDACTED]")
            .field("rtp_salt", &"[REDACTED]")
            .field("rtcp_key", &"[REDACTED]")
            .field("rtcp_salt", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.rtp_key.fill(0);
        self.rtp_salt.fill(0);
        self.rtcp_key.fill(0);
        self.rtcp_salt.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_material() -> SrtpKeyMaterial {
        SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, vec![1u8; 32], vec![2u8; 12]).unwrap()
    }

    #[test]
    fn test_key_material_creation() {
        let material = test_key_material();
        assert_eq!(material.profile(), SrtpProfile::AeadAes256Gcm);
        assert_eq!(material.master_key().len(), 32);
        assert_eq!(material.master_salt().len(), 12);
    }

    #[test]
    fn test_key_material_invalid_length() {
        let result = SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            vec![1u8; 16], // Too short
            vec![2u8; 12],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_session_key_derivation() {
        let material = test_key_material();
        let rtp_key = material
            .derive_session_key(KeyDerivationLabel::RtpEncryption)
            .unwrap();
        assert_eq!(rtp_key.len(), 32);
    }

    #[test]
    fn test_session_keys_derive() {
        let material = test_key_material();
        let keys = SessionKeys::derive(&material).unwrap();
        assert_eq!(keys.rtp_key.len(), 32);
        assert_eq!(keys.rtp_salt.len(), 12);
    }

    #[test]
    fn test_debug_redacted() {
        let material = test_key_material();
        let debug_str = format!("{material:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("[1, 1, 1"));
    }
}
