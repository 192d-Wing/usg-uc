//! DTLS session management.
//!
//! This module provides a wrapper around webrtc-dtls for managing DTLS sessions
//! with CNSA 2.0 compliant configuration.
//!
//! ## Current Implementation Status
//!
//! This implementation provides the framework for DTLS integration with
//! webrtc-dtls. The current version uses placeholder keying material
//! generation for testing purposes. Full integration requires:
//! 1. Proper certificate handling for P-384 ECDSA
//! 2. webrtc-dtls cipher suite support (currently lacks AES-256-GCM)
//! 3. `KeyingMaterialExporter` trait integration
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment
//! - **SC-13**: Cryptographic Protection

use crate::config::DtlsConfig;
use crate::error::{DtlsError, DtlsResult};
use crate::{DtlsRole, SrtpKeyingMaterial, SrtpProfile};
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, instrument};

/// SRTP exporter label per RFC 5764.
#[allow(dead_code)]
const SRTP_EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";

/// Length of keying material to export (keys + salts for both directions).
/// For AES-256-GCM: 2 * (32 key + 12 salt) = 88 bytes
#[allow(dead_code)]
const SRTP_KEYING_MATERIAL_LEN: usize = 88;

/// DTLS session wrapper providing CNSA 2.0 compliant DTLS operations.
///
/// This struct wraps the DTLS connection and ensures all cryptographic
/// operations meet CNSA 2.0 requirements where possible.
pub struct DtlsSession {
    /// UDP socket for transport.
    socket: Arc<UdpSocket>,
    /// Role in the DTLS handshake.
    role: DtlsRole,
    /// Whether the session is established.
    established: bool,
    /// Cached keying material.
    keying_material: Option<SrtpKeyingMaterial>,
}

impl DtlsSession {
    /// Creates a new DTLS session by performing the handshake.
    ///
    /// ## Arguments
    ///
    /// * `config` - DTLS configuration
    /// * `socket` - UDP socket for transport
    /// * `is_client` - Whether this is the client (initiator) role
    ///
    /// ## Current Implementation
    ///
    /// This creates a session with placeholder keying material.
    /// Full webrtc-dtls integration is planned for a future phase.
    ///
    /// ## Errors
    ///
    /// Returns an error if the handshake fails or configuration is invalid.
    #[instrument(skip(config, socket))]
    pub async fn new(
        config: &DtlsConfig,
        socket: Arc<UdpSocket>,
        is_client: bool,
    ) -> DtlsResult<Self> {
        config.validate()?;

        let role = if is_client {
            DtlsRole::Client
        } else {
            DtlsRole::Server
        };

        debug!(
            role = ?role,
            "Creating DTLS session"
        );

        // Generate keying material
        // In full implementation, this would come from the DTLS handshake
        let keying_material = Self::generate_keying_material(config)?;

        debug!(
            role = ?role,
            "DTLS session created"
        );

        Ok(Self {
            socket,
            role,
            established: true,
            keying_material: Some(keying_material),
        })
    }

    /// Generates keying material for SRTP.
    ///
    /// ## Current Implementation
    ///
    /// Uses secure random generation for placeholder keys.
    /// In full implementation, this would be exported from the DTLS
    /// handshake using the RFC 5764 exporter.
    fn generate_keying_material(config: &DtlsConfig) -> DtlsResult<SrtpKeyingMaterial> {
        let profile = config
            .srtp_profiles
            .first()
            .copied()
            .unwrap_or(SrtpProfile::AeadAes256Gcm);

        let key_len = profile.key_len();
        let salt_len = profile.salt_len();

        // Generate random keys using CNSA 2.0 compliant random
        let mut client_key = vec![0u8; key_len];
        let mut server_key = vec![0u8; key_len];
        let mut client_salt = vec![0u8; salt_len];
        let mut server_salt = vec![0u8; salt_len];

        uc_crypto::random::fill_random(&mut client_key).map_err(|e| {
            DtlsError::SrtpKeyExportFailed {
                reason: format!("failed to generate client key: {e}"),
            }
        })?;
        uc_crypto::random::fill_random(&mut server_key).map_err(|e| {
            DtlsError::SrtpKeyExportFailed {
                reason: format!("failed to generate server key: {e}"),
            }
        })?;
        uc_crypto::random::fill_random(&mut client_salt).map_err(|e| {
            DtlsError::SrtpKeyExportFailed {
                reason: format!("failed to generate client salt: {e}"),
            }
        })?;
        uc_crypto::random::fill_random(&mut server_salt).map_err(|e| {
            DtlsError::SrtpKeyExportFailed {
                reason: format!("failed to generate server salt: {e}"),
            }
        })?;

        Ok(SrtpKeyingMaterial {
            client_write_key: client_key,
            server_write_key: server_key,
            client_write_salt: client_salt,
            server_write_salt: server_salt,
            profile,
        })
    }

    /// Returns whether the session is established.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.established
    }

    /// Returns the DTLS role.
    #[must_use]
    pub const fn role(&self) -> DtlsRole {
        self.role
    }

    /// Exports SRTP keying material per RFC 5764.
    ///
    /// ## Errors
    ///
    /// Returns an error if the session is not established or keying material
    /// is not available.
    #[instrument(skip(self))]
    pub async fn export_srtp_keying_material(&self) -> DtlsResult<SrtpKeyingMaterial> {
        if !self.established {
            return Err(DtlsError::NotConnected);
        }

        self.keying_material
            .clone()
            .ok_or_else(|| DtlsError::SrtpKeyExportFailed {
                reason: "keying material not available".to_string(),
            })
    }

    /// Sends encrypted data through the DTLS session.
    ///
    /// ## Current Implementation
    ///
    /// Sends data directly via UDP. Full implementation would
    /// encrypt via DTLS record layer.
    ///
    /// ## Errors
    ///
    /// Returns an error if the session is not established or send fails.
    #[instrument(skip(self, data))]
    pub async fn send(&self, data: &[u8]) -> DtlsResult<usize> {
        if !self.established {
            return Err(DtlsError::NotConnected);
        }

        let written = self
            .socket
            .send(data)
            .await
            .map_err(|e| DtlsError::SendFailed {
                reason: e.to_string(),
            })?;

        debug!(bytes = written, "DTLS send completed");
        Ok(written)
    }

    /// Receives decrypted data from the DTLS session.
    ///
    /// ## Current Implementation
    ///
    /// Receives data directly via UDP. Full implementation would
    /// decrypt via DTLS record layer.
    ///
    /// ## Errors
    ///
    /// Returns an error if the session is not established or receive fails.
    #[instrument(skip(self))]
    pub async fn recv(&self) -> DtlsResult<Bytes> {
        if !self.established {
            return Err(DtlsError::NotConnected);
        }

        let mut buf = vec![0u8; 8192];
        let n = self
            .socket
            .recv(&mut buf)
            .await
            .map_err(|e| DtlsError::ReceiveFailed {
                reason: e.to_string(),
            })?;

        buf.truncate(n);
        debug!(bytes = n, "DTLS recv completed");
        Ok(Bytes::from(buf))
    }

    /// Closes the DTLS session.
    ///
    /// ## Errors
    ///
    /// Returns an error if already closed.
    #[instrument(skip(self))]
    pub async fn close(&mut self) -> DtlsResult<()> {
        if !self.established {
            return Err(DtlsError::AlreadyClosed);
        }

        self.established = false;
        self.keying_material = None;
        debug!("DTLS session closed");
        Ok(())
    }
}

impl std::fmt::Debug for DtlsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsSession")
            .field("role", &self.role)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrtpProfile;

    #[test]
    fn test_srtp_keying_material_length() {
        // Verify our constant matches expected key material layout
        let key_len = SrtpProfile::AeadAes256Gcm.key_len();
        let salt_len = SrtpProfile::AeadAes256Gcm.salt_len();
        let expected_len = 2 * key_len + 2 * salt_len; // 2*(32+12) = 88

        assert_eq!(SRTP_KEYING_MATERIAL_LEN, expected_len);
    }

    #[test]
    fn test_exporter_label() {
        // RFC 5764 Section 4.2
        assert_eq!(SRTP_EXPORTER_LABEL, "EXTRACTOR-dtls_srtp");
    }

    fn create_test_config() -> DtlsConfig {
        DtlsConfig {
            certificate_chain: vec![vec![0u8; 100]],
            private_key: vec![0u8; 48],
            role: DtlsRole::Client,
            srtp_profiles: vec![SrtpProfile::AeadAes256Gcm],
            handshake_timeout: std::time::Duration::from_secs(30),
            mtu: 1200,
            extended_master_secret: true,
            replay_protection: true,
        }
    }

    #[tokio::test]
    async fn test_session_new_client() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let session = DtlsSession::new(&config, Arc::new(socket), true).await;
        assert!(session.is_ok());

        let session = session.unwrap();
        assert!(session.is_established());
        assert_eq!(session.role(), DtlsRole::Client);
    }

    #[tokio::test]
    async fn test_session_new_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = create_test_config();
        config.role = DtlsRole::Server;

        let session = DtlsSession::new(&config, Arc::new(socket), false).await;
        assert!(session.is_ok());

        let session = session.unwrap();
        assert!(session.is_established());
        assert_eq!(session.role(), DtlsRole::Server);
    }

    #[tokio::test]
    async fn test_session_invalid_config() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = DtlsConfig {
            certificate_chain: vec![], // Invalid: empty
            private_key: vec![0u8; 48],
            role: DtlsRole::Client,
            srtp_profiles: vec![SrtpProfile::AeadAes256Gcm],
            handshake_timeout: std::time::Duration::from_secs(30),
            mtu: 1200,
            extended_master_secret: true,
            replay_protection: true,
        };

        let result = DtlsSession::new(&config, Arc::new(socket), true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_export_srtp_keying_material() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        let keying_material = session.export_srtp_keying_material().await;
        assert!(keying_material.is_ok());

        let km = keying_material.unwrap();
        assert_eq!(km.profile, SrtpProfile::AeadAes256Gcm);
        assert_eq!(
            km.client_write_key.len(),
            SrtpProfile::AeadAes256Gcm.key_len()
        );
        assert_eq!(
            km.server_write_key.len(),
            SrtpProfile::AeadAes256Gcm.key_len()
        );
        assert_eq!(
            km.client_write_salt.len(),
            SrtpProfile::AeadAes256Gcm.salt_len()
        );
        assert_eq!(
            km.server_write_salt.len(),
            SrtpProfile::AeadAes256Gcm.salt_len()
        );
    }

    #[tokio::test]
    async fn test_export_srtp_keying_material_not_connected() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let mut session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        // Close the session
        session.close().await.unwrap();

        // Now try to export keying material
        let result = session.export_srtp_keying_material().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DtlsError::NotConnected)));
    }

    #[tokio::test]
    async fn test_session_close() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let mut session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        assert!(session.is_established());

        let result = session.close().await;
        assert!(result.is_ok());
        assert!(!session.is_established());
    }

    #[tokio::test]
    async fn test_session_close_twice() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let mut session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        // First close should succeed
        let result = session.close().await;
        assert!(result.is_ok());

        // Second close should fail
        let result = session.close().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DtlsError::AlreadyClosed)));
    }

    #[tokio::test]
    async fn test_send_not_connected() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let mut session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        session.close().await.unwrap();

        let result = session.send(b"test data").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DtlsError::NotConnected)));
    }

    #[tokio::test]
    async fn test_recv_not_connected() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let mut session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        session.close().await.unwrap();

        let result = session.recv().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DtlsError::NotConnected)));
    }

    #[tokio::test]
    async fn test_session_debug() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = create_test_config();

        let session = DtlsSession::new(&config, Arc::new(socket), true)
            .await
            .unwrap();

        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("DtlsSession"));
        assert!(debug_str.contains("Client"));
        assert!(debug_str.contains("established"));
    }

    #[test]
    fn test_generate_keying_material() {
        let config = create_test_config();
        let km = DtlsSession::generate_keying_material(&config);
        assert!(km.is_ok());

        let km = km.unwrap();
        // Keys should be non-zero (random)
        assert!(km.client_write_key.iter().any(|&b| b != 0));
        assert!(km.server_write_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_keying_material_uses_first_profile() {
        let mut config = create_test_config();
        config.srtp_profiles = vec![SrtpProfile::AeadAes256Gcm];

        let km = DtlsSession::generate_keying_material(&config).unwrap();
        assert_eq!(km.profile, SrtpProfile::AeadAes256Gcm);
    }

    #[test]
    fn test_generate_keying_material_empty_profiles_uses_default() {
        let mut config = create_test_config();
        config.srtp_profiles = vec![];

        let km = DtlsSession::generate_keying_material(&config).unwrap();
        // Should default to AeadAes256Gcm
        assert_eq!(km.profile, SrtpProfile::AeadAes256Gcm);
    }
}
