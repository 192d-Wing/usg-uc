//! SRTP key material and derivation.
//!
//! Session keys are derived with the standard SRTP KDF (RFC 3711 §4.3, an
//! AES counter-mode PRF), which is required to interoperate with other SRTP
//! endpoints. For AEAD_AES_256_GCM (RFC 7714) the PRF is AES-256-CM, so the
//! whole SRTP path stays CNSA 2.0 (AES-256) and FIPS 140-3 (aws-lc).

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

    /// The RFC 3711 §4.3 SRTP key-derivation function: an AES counter-mode PRF
    /// keyed with the master key, over an input block built from the master salt
    /// and the derivation `label`. For AEAD_AES_256_GCM the PRF is AES-256-CM
    /// (RFC 7714 §11).
    ///
    /// This is the standard SRTP KDF — required for interoperability with every
    /// other SRTP endpoint (libsrtp, pion, browsers, phones). Earlier this used
    /// HKDF-SHA384, which produced non-interoperable session keys.
    ///
    /// # Errors
    /// Returns an error if the cipher operation fails.
    fn derive(&self, label: u8, out_len: usize) -> SrtpResult<Vec<u8>> {
        // The PRF input block is the master salt padded to 16 octets, with the
        // label XORed at octet 7 and the 16-bit block counter in the last two
        // octets (RFC 3711 §4.3.1/§4.3.3, index DIV kdr = 0). Built from the
        // master salt (not a zero constant). AES-CM over a zero buffer yields
        // the keystream = the derived key material.
        if self.master_salt.len() > 16 {
            return Err(SrtpError::KeyDerivationFailed {
                reason: "master salt too long for KDF block".to_string(),
            });
        }
        let mut block = self.master_salt.clone();
        block.resize(16, 0);
        block[7] ^= label;
        let prf_in: [u8; 16] = block
            .try_into()
            .map_err(|_| SrtpError::KeyDerivationFailed {
                reason: "KDF block must be 16 octets".to_string(),
            })?;

        let mut output = vec![0u8; out_len];
        uc_crypto::cipher::aes256_ctr(&self.master_key, &prf_in, &mut output).map_err(|e| {
            SrtpError::KeyDerivationFailed {
                reason: format!("AES-CM KDF failed: {e}"),
            }
        })?;
        Ok(output)
    }

    /// Derives a session encryption key (RFC 3711 KDF).
    ///
    /// # Errors
    /// Returns an error if key derivation fails.
    pub fn derive_session_key(&self, label: KeyDerivationLabel) -> SrtpResult<Vec<u8>> {
        self.derive(label.as_byte(), self.profile.session_key_len())
    }

    /// Derives a session salt (RFC 3711 KDF).
    ///
    /// # Errors
    /// Returns an error if key derivation fails.
    pub fn derive_session_salt(&self, label: KeyDerivationLabel) -> SrtpResult<Vec<u8>> {
        self.derive(label.as_byte(), self.profile.master_salt_len())
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
    /// The single RFC 3711 §4.3.2 label octet for this key.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        match self {
            Self::RtpEncryption => 0x00,
            Self::RtpAuthentication => 0x01,
            Self::RtpSalt => 0x02,
            Self::RtcpEncryption => 0x03,
            Self::RtcpAuthentication => 0x04,
            Self::RtcpSalt => 0x05,
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
    ///
    /// # Errors
    /// Returns an error if the operation fails.
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

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    // The RFC 3711 §4.3 AES-CM KDF must match every other SRTP stack. This
    // reference vector was produced by pion/libsrtp's KDF (AES-256) for
    // master_key = 00..1f, master_salt = 10..1b. A regression here means the
    // SBC's SRTP would no longer interoperate with real endpoints (this is
    // exactly the bug the HKDF-SHA384 implementation had).
    #[test]
    fn kdf_matches_reference_srtp_vector() {
        let master_key: Vec<u8> = (0u8..32).collect();
        let master_salt: Vec<u8> = (0x10u8..0x1c).collect();
        let material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, master_key, master_salt).unwrap();

        let session_key = material
            .derive_session_key(KeyDerivationLabel::RtpEncryption)
            .unwrap();
        let session_salt = material
            .derive_session_salt(KeyDerivationLabel::RtpSalt)
            .unwrap();

        assert_eq!(
            hex(&session_key),
            "9c13e272e4d75e9d96e28cea265339f8018f5e9d66e6fbec03896ee4b1e8d030"
        );
        assert_eq!(hex(&session_salt), "f013ad8bf1b68d498401e8d6");
    }
}
