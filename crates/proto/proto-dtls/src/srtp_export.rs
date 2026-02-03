//! DTLS-SRTP keying material export per RFC 5764.
//!
//! This module implements the SRTP keying material export mechanism
//! defined in RFC 5764 for DTLS-SRTP.
//!
//! ## RFC 5764 Section 4.2 Key Derivation
//!
//! The keying material is exported from DTLS using the exporter
//! mechanism defined in RFC 5705, with the label "EXTRACTOR-dtls_srtp".
//!
//! ## Key Material Layout
//!
//! The exported keying material is laid out as:
//! ```text
//! client_write_SRTP_master_key[SRTPSecurityParams.master_key_len]
//! server_write_SRTP_master_key[SRTPSecurityParams.master_key_len]
//! client_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len]
//! server_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len]
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment
//! - **SC-13**: Cryptographic Protection

use crate::error::{DtlsError, DtlsResult};
use crate::{SrtpKeyingMaterial, SrtpProfile};

/// SRTP exporter label per RFC 5764 Section 4.2.
pub const SRTP_EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// SRTP protection profile negotiation extension type.
/// RFC 5764 Section 4.1.2.
pub const USE_SRTP_EXTENSION_TYPE: u16 = 14;

/// SRTP key exporter for DTLS-SRTP.
///
/// Handles the export and derivation of SRTP keying material
/// from a DTLS session.
pub struct SrtpKeyExporter {
    /// Negotiated SRTP profile.
    profile: SrtpProfile,
}

impl SrtpKeyExporter {
    /// Creates a new SRTP key exporter for the given profile.
    pub fn new(profile: SrtpProfile) -> Self {
        Self { profile }
    }

    /// Returns the negotiated profile.
    pub fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Calculates the total keying material length needed.
    ///
    /// Per RFC 5764, the layout is:
    /// - client_write_master_key
    /// - server_write_master_key
    /// - client_write_master_salt
    /// - server_write_master_salt
    pub fn keying_material_length(&self) -> usize {
        2 * self.profile.key_len() + 2 * self.profile.salt_len()
    }

    /// Exports keying material from raw exported bytes.
    ///
    /// This method takes the raw bytes exported from DTLS using
    /// the RFC 5705 exporter mechanism and parses them into
    /// the structured `SrtpKeyingMaterial`.
    ///
    /// ## Arguments
    ///
    /// * `exported` - Raw exported bytes from DTLS exporter
    ///
    /// ## Errors
    ///
    /// Returns an error if the exported material is the wrong length.
    pub fn parse_keying_material(&self, exported: &[u8]) -> DtlsResult<SrtpKeyingMaterial> {
        let expected_len = self.keying_material_length();

        if exported.len() != expected_len {
            return Err(DtlsError::SrtpKeyExportFailed {
                reason: format!(
                    "invalid keying material length: expected {}, got {}",
                    expected_len,
                    exported.len()
                ),
            });
        }

        let key_len = self.profile.key_len();
        let salt_len = self.profile.salt_len();

        // Parse layout per RFC 5764 Section 4.2
        let mut offset = 0;

        let client_write_key = exported[offset..offset + key_len].to_vec();
        offset += key_len;

        let server_write_key = exported[offset..offset + key_len].to_vec();
        offset += key_len;

        let client_write_salt = exported[offset..offset + salt_len].to_vec();
        offset += salt_len;

        let server_write_salt = exported[offset..offset + salt_len].to_vec();

        Ok(SrtpKeyingMaterial {
            client_write_key,
            server_write_key,
            client_write_salt,
            server_write_salt,
            profile: self.profile,
        })
    }

    /// Creates keying material from explicit keys and salts.
    ///
    /// This is useful for testing or when keys are derived through
    /// other means.
    pub fn create_keying_material(
        &self,
        client_write_key: Vec<u8>,
        server_write_key: Vec<u8>,
        client_write_salt: Vec<u8>,
        server_write_salt: Vec<u8>,
    ) -> DtlsResult<SrtpKeyingMaterial> {
        let key_len = self.profile.key_len();
        let salt_len = self.profile.salt_len();

        if client_write_key.len() != key_len {
            return Err(DtlsError::SrtpKeyExportFailed {
                reason: format!("invalid client key length: expected {key_len}"),
            });
        }
        if server_write_key.len() != key_len {
            return Err(DtlsError::SrtpKeyExportFailed {
                reason: format!("invalid server key length: expected {key_len}"),
            });
        }
        if client_write_salt.len() != salt_len {
            return Err(DtlsError::SrtpKeyExportFailed {
                reason: format!("invalid client salt length: expected {salt_len}"),
            });
        }
        if server_write_salt.len() != salt_len {
            return Err(DtlsError::SrtpKeyExportFailed {
                reason: format!("invalid server salt length: expected {salt_len}"),
            });
        }

        Ok(SrtpKeyingMaterial {
            client_write_key,
            server_write_key,
            client_write_salt,
            server_write_salt,
            profile: self.profile,
        })
    }

    /// Derives keying material using the TLS PRF.
    ///
    /// This implements the key derivation per RFC 5705 (TLS Exporters)
    /// using HKDF with SHA-384 for CNSA 2.0 compliance.
    ///
    /// ## Arguments
    ///
    /// * `master_secret` - The DTLS master secret
    /// * `client_random` - Client random from handshake
    /// * `server_random` - Server random from handshake
    ///
    /// ## Note
    ///
    /// In a full implementation, this would be called by the DTLS
    /// handshake layer with the actual secrets. For now, this provides
    /// the interface for integration.
    pub fn derive_keying_material(
        &self,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> DtlsResult<SrtpKeyingMaterial> {
        let output_len = self.keying_material_length();

        // Construct the seed: label + context
        // For SRTP export, the context is empty per RFC 5764
        let mut seed = Vec::with_capacity(SRTP_EXPORTER_LABEL.len() + 64);
        seed.extend_from_slice(SRTP_EXPORTER_LABEL);
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        // Use HKDF-SHA384 for CNSA 2.0 compliance
        let exported = prf_sha384(master_secret, &seed, output_len)?;

        self.parse_keying_material(&exported)
    }
}

/// TLS PRF using HKDF-SHA384 for CNSA 2.0 compliance.
///
/// This is a simplified PRF that uses HKDF instead of the traditional
/// TLS PRF. A full implementation would match the exact TLS 1.2 PRF.
fn prf_sha384(secret: &[u8], seed: &[u8], output_len: usize) -> DtlsResult<Vec<u8>> {
    // Use HKDF-Expand with SHA-384
    // Note: Full TLS 1.2 PRF is P_SHA384 which is more complex

    let mut output = Vec::with_capacity(output_len);
    let mut counter = 1u8;
    let mut a = seed.to_vec(); // A(1) = HMAC_hash(secret, seed)

    while output.len() < output_len {
        // A(i) = HMAC_hash(secret, A(i-1))
        a = uc_crypto::hash::hmac_sha384(secret, &a).to_vec();

        // P_hash = HMAC_hash(secret, A(i) + seed)
        let mut input = a.clone();
        input.extend_from_slice(seed);
        let p = uc_crypto::hash::hmac_sha384(secret, &input);

        output.extend_from_slice(&p[..p.len().min(output_len - output.len())]);
        counter += 1;

        // Safety check to avoid infinite loop
        if counter > 10 {
            break;
        }
    }

    output.truncate(output_len);
    Ok(output)
}

/// SRTP protection profile extension for use_srtp.
///
/// Encodes/decodes the use_srtp extension per RFC 5764.
#[derive(Debug, Clone)]
pub struct UseSrtpExtension {
    /// Offered/selected profiles.
    pub profiles: Vec<SrtpProfile>,
    /// MKI value (usually empty).
    pub mki: Vec<u8>,
}

impl UseSrtpExtension {
    /// Creates a new use_srtp extension with CNSA 2.0 profiles.
    pub fn cnsa_compliant() -> Self {
        Self {
            profiles: vec![SrtpProfile::AeadAes256Gcm],
            mki: Vec::new(),
        }
    }

    /// Creates a new extension with the given profiles.
    pub fn new(profiles: Vec<SrtpProfile>) -> Self {
        Self {
            profiles,
            mki: Vec::new(),
        }
    }

    /// Encodes the extension for the ClientHello.
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Profile IDs length (2 bytes per profile)
        let profiles_len = (self.profiles.len() * 2) as u16;
        data.push((profiles_len >> 8) as u8);
        data.push((profiles_len & 0xFF) as u8);

        // Profile IDs
        for profile in &self.profiles {
            let id = profile.profile_id();
            data.push((id >> 8) as u8);
            data.push((id & 0xFF) as u8);
        }

        // MKI length and value
        data.push(self.mki.len() as u8);
        data.extend_from_slice(&self.mki);

        data
    }

    /// Decodes the extension from bytes.
    pub fn decode(data: &[u8]) -> DtlsResult<Self> {
        if data.len() < 3 {
            return Err(DtlsError::HandshakeFailed {
                reason: "use_srtp extension too short".to_string(),
            });
        }

        let profiles_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + profiles_len + 1 {
            return Err(DtlsError::HandshakeFailed {
                reason: "use_srtp extension truncated".to_string(),
            });
        }

        let mut profiles = Vec::new();
        let mut offset = 2;

        while offset < 2 + profiles_len {
            let id = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            // Only accept CNSA 2.0 compliant profiles
            if id == SrtpProfile::AeadAes256Gcm.profile_id() {
                profiles.push(SrtpProfile::AeadAes256Gcm);
            }
            // Silently ignore non-CNSA profiles
        }

        let mki_len = data[2 + profiles_len] as usize;
        let mki = if mki_len > 0 && data.len() >= 2 + profiles_len + 1 + mki_len {
            data[2 + profiles_len + 1..2 + profiles_len + 1 + mki_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { profiles, mki })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keying_material_length() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);
        // 2 * 32 (keys) + 2 * 12 (salts) = 88
        assert_eq!(exporter.keying_material_length(), 88);
    }

    #[test]
    fn test_parse_keying_material() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);

        // Create test material: 32 + 32 + 12 + 12 = 88 bytes
        let mut exported = Vec::new();
        exported.extend_from_slice(&[1u8; 32]); // client key
        exported.extend_from_slice(&[2u8; 32]); // server key
        exported.extend_from_slice(&[3u8; 12]); // client salt
        exported.extend_from_slice(&[4u8; 12]); // server salt

        let material = exporter.parse_keying_material(&exported).unwrap();

        assert_eq!(material.client_write_key, vec![1u8; 32]);
        assert_eq!(material.server_write_key, vec![2u8; 32]);
        assert_eq!(material.client_write_salt, vec![3u8; 12]);
        assert_eq!(material.server_write_salt, vec![4u8; 12]);
    }

    #[test]
    fn test_parse_keying_material_wrong_length() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);

        let exported = vec![0u8; 50]; // Wrong length
        assert!(exporter.parse_keying_material(&exported).is_err());
    }

    #[test]
    fn test_create_keying_material() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);

        let material = exporter.create_keying_material(
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 12],
            vec![4u8; 12],
        ).unwrap();

        assert_eq!(material.profile, SrtpProfile::AeadAes256Gcm);
    }

    #[test]
    fn test_create_keying_material_wrong_key_length() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);

        // Wrong key length
        let result = exporter.create_keying_material(
            vec![1u8; 16], // Should be 32
            vec![2u8; 32],
            vec![3u8; 12],
            vec![4u8; 12],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_use_srtp_extension_roundtrip() {
        let ext = UseSrtpExtension::cnsa_compliant();
        let encoded = ext.encode();
        let decoded = UseSrtpExtension::decode(&encoded).unwrap();

        assert_eq!(decoded.profiles.len(), 1);
        assert_eq!(decoded.profiles[0], SrtpProfile::AeadAes256Gcm);
    }

    #[test]
    fn test_use_srtp_extension_encode() {
        let ext = UseSrtpExtension::new(vec![SrtpProfile::AeadAes256Gcm]);
        let encoded = ext.encode();

        // Length should be: 2 (profiles len) + 2 (profile id) + 1 (mki len) = 5
        assert_eq!(encoded.len(), 5);

        // Profiles length = 2 (one profile)
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 2);

        // Profile ID 0x0008 (AeadAes256Gcm)
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 8);

        // MKI length = 0
        assert_eq!(encoded[4], 0);
    }

    #[test]
    fn test_derive_keying_material() {
        let exporter = SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm);

        let master_secret = [0xABu8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let material = exporter.derive_keying_material(
            &master_secret,
            &client_random,
            &server_random,
        ).unwrap();

        // Verify key lengths
        assert_eq!(material.client_write_key.len(), 32);
        assert_eq!(material.server_write_key.len(), 32);
        assert_eq!(material.client_write_salt.len(), 12);
        assert_eq!(material.server_write_salt.len(), 12);

        // Keys should be different from each other
        assert_ne!(material.client_write_key, material.server_write_key);
    }
}
