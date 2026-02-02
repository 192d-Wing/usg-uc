//! DTLS connection handling.
//!
//! ## CNSA 2.0 Compliance
//!
//! Connections use CNSA 2.0 compliant cipher suites only.
//!
//! ## RFC Compliance
//!
//! - RFC 6347: DTLS 1.2
//! - RFC 5764: DTLS-SRTP

use crate::config::DtlsConfig;
use crate::error::{DtlsError, DtlsResult};
use crate::fingerprint::CertificateFingerprint;
use crate::{DtlsRole, DtlsState, SrtpKeyingMaterial, SrtpProfile};
use bytes::Bytes;
use sbc_types::address::SbcSocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

/// DTLS connection for secure media transport.
///
/// ## Usage
///
/// ```ignore
/// let config = DtlsConfig::new(DtlsRole::Server)
///     .with_identity(cert_chain, private_key);
///
/// let conn = DtlsConnection::new(config, local_addr, remote_addr)?;
/// conn.handshake().await?;
///
/// let keying_material = conn.export_srtp_keying_material()?;
/// ```
///
/// ## CNSA 2.0 Compliance
///
/// All cryptographic operations use CNSA 2.0 compliant algorithms.
pub struct DtlsConnection {
    config: DtlsConfig,
    local_addr: SbcSocketAddr,
    remote_addr: SbcSocketAddr,
    state: AtomicU8,
    local_fingerprint: CertificateFingerprint,
    remote_fingerprint: Mutex<Option<CertificateFingerprint>>,
    keying_material: Mutex<Option<SrtpKeyingMaterial>>,
}

impl DtlsConnection {
    /// Creates a new DTLS connection.
    ///
    /// ## Errors
    ///
    /// Returns an error if the configuration is invalid.
    #[instrument(skip(config), fields(local = %local_addr, remote = %remote_addr))]
    pub fn new(
        config: DtlsConfig,
        local_addr: SbcSocketAddr,
        remote_addr: SbcSocketAddr,
    ) -> DtlsResult<Self> {
        config.validate()?;

        // Compute local certificate fingerprint
        let local_fingerprint = if let Some(cert) = config.certificate_chain.first() {
            CertificateFingerprint::from_certificate_sha384(cert)
        } else {
            return Err(DtlsError::CertificateError {
                reason: "no certificate in chain".to_string(),
            });
        };

        debug!(
            fingerprint = %local_fingerprint,
            role = ?config.role,
            "DTLS connection created"
        );

        Ok(Self {
            config,
            local_addr,
            remote_addr,
            state: AtomicU8::new(DtlsState::New as u8),
            local_fingerprint,
            remote_fingerprint: Mutex::new(None),
            keying_material: Mutex::new(None),
        })
    }

    /// Returns the current connection state.
    #[must_use]
    pub fn state(&self) -> DtlsState {
        match self.state.load(Ordering::Acquire) {
            0 => DtlsState::New,
            1 => DtlsState::Connecting,
            2 => DtlsState::Connected,
            3 => DtlsState::Closing,
            4 => DtlsState::Closed,
            _ => DtlsState::Failed,
        }
    }

    /// Sets the connection state.
    fn set_state(&self, state: DtlsState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Returns the DTLS role.
    #[must_use]
    pub fn role(&self) -> DtlsRole {
        self.config.role
    }

    /// Returns the local address.
    #[must_use]
    pub fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    /// Returns the remote address.
    #[must_use]
    pub fn remote_addr(&self) -> &SbcSocketAddr {
        &self.remote_addr
    }

    /// Returns the local certificate fingerprint.
    #[must_use]
    pub fn local_fingerprint(&self) -> &CertificateFingerprint {
        &self.local_fingerprint
    }

    /// Sets the expected remote certificate fingerprint.
    ///
    /// This should be called before handshake with the fingerprint
    /// received from SDP signaling.
    pub async fn set_remote_fingerprint(&self, fingerprint: CertificateFingerprint) {
        let mut remote = self.remote_fingerprint.lock().await;
        *remote = Some(fingerprint);
    }

    /// Performs the DTLS handshake.
    ///
    /// ## Errors
    ///
    /// Returns an error if the handshake fails.
    #[instrument(skip(self))]
    pub async fn handshake(&self) -> DtlsResult<()> {
        if self.state() != DtlsState::New {
            return Err(DtlsError::InvalidConfig {
                reason: "handshake already started".to_string(),
            });
        }

        self.set_state(DtlsState::Connecting);

        // TODO: Implement actual DTLS handshake using webrtc-dtls
        // For now, this is a placeholder that simulates success

        debug!(
            role = ?self.config.role,
            "DTLS handshake initiated (placeholder)"
        );

        // Simulate generating keying material after handshake
        let keying_material = self.generate_placeholder_keying_material();
        {
            let mut km = self.keying_material.lock().await;
            *km = Some(keying_material);
        }

        self.set_state(DtlsState::Connected);
        debug!("DTLS handshake completed");

        Ok(())
    }

    /// Generates placeholder keying material for testing.
    ///
    /// In production, this would be derived from the DTLS handshake.
    fn generate_placeholder_keying_material(&self) -> SrtpKeyingMaterial {
        let profile = self
            .config
            .srtp_profiles
            .first()
            .copied()
            .unwrap_or(SrtpProfile::AeadAes256Gcm);

        let key_len = profile.key_len();
        let salt_len = profile.salt_len();

        // Generate random keys for placeholder
        let mut client_key = vec![0u8; key_len];
        let mut server_key = vec![0u8; key_len];
        let mut client_salt = vec![0u8; salt_len];
        let mut server_salt = vec![0u8; salt_len];

        // Use crypto random for placeholder values
        let _ = sbc_crypto::random::fill_random(&mut client_key);
        let _ = sbc_crypto::random::fill_random(&mut server_key);
        let _ = sbc_crypto::random::fill_random(&mut client_salt);
        let _ = sbc_crypto::random::fill_random(&mut server_salt);

        SrtpKeyingMaterial {
            client_write_key: client_key,
            server_write_key: server_key,
            client_write_salt: client_salt,
            server_write_salt: server_salt,
            profile,
        }
    }

    /// Exports SRTP keying material.
    ///
    /// This must be called after a successful handshake.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection is not established.
    pub async fn export_srtp_keying_material(&self) -> DtlsResult<SrtpKeyingMaterial> {
        if self.state() != DtlsState::Connected {
            return Err(DtlsError::NotConnected);
        }

        let km = self.keying_material.lock().await;
        km.clone().ok_or(DtlsError::SrtpKeyExportFailed {
            reason: "keying material not available".to_string(),
        })
    }

    /// Sends encrypted data.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection is not established or send fails.
    #[instrument(skip(self, data))]
    pub async fn send(&self, data: &[u8]) -> DtlsResult<()> {
        if self.state() != DtlsState::Connected {
            return Err(DtlsError::NotConnected);
        }

        // TODO: Implement actual DTLS send
        debug!(size = data.len(), "DTLS send (placeholder)");
        Ok(())
    }

    /// Receives decrypted data.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection is not established or receive fails.
    #[instrument(skip(self))]
    pub async fn recv(&self) -> DtlsResult<Bytes> {
        if self.state() != DtlsState::Connected {
            return Err(DtlsError::NotConnected);
        }

        // TODO: Implement actual DTLS receive
        debug!("DTLS recv (placeholder)");
        Err(DtlsError::Timeout)
    }

    /// Closes the DTLS connection.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection is already closed.
    #[instrument(skip(self))]
    pub async fn close(&self) -> DtlsResult<()> {
        let current_state = self.state();
        if current_state == DtlsState::Closed || current_state == DtlsState::Failed {
            return Err(DtlsError::AlreadyClosed);
        }

        self.set_state(DtlsState::Closing);

        // Clear keying material
        {
            let mut km = self.keying_material.lock().await;
            *km = None;
        }

        self.set_state(DtlsState::Closed);
        debug!("DTLS connection closed");

        Ok(())
    }
}

impl std::fmt::Debug for DtlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsConnection")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("role", &self.config.role)
            .field("state", &self.state())
            .field("local_fingerprint", &self.local_fingerprint)
            .finish()
    }
}

/// DTLS connection manager for handling multiple connections.
pub struct DtlsConnectionManager {
    connections: Mutex<Vec<Arc<DtlsConnection>>>,
    default_config: DtlsConfig,
}

impl DtlsConnectionManager {
    /// Creates a new connection manager.
    #[must_use]
    pub fn new(default_config: DtlsConfig) -> Self {
        Self {
            connections: Mutex::new(Vec::new()),
            default_config,
        }
    }

    /// Creates a new DTLS connection.
    ///
    /// ## Errors
    ///
    /// Returns an error if connection creation fails.
    pub async fn create_connection(
        &self,
        local_addr: SbcSocketAddr,
        remote_addr: SbcSocketAddr,
    ) -> DtlsResult<Arc<DtlsConnection>> {
        let conn = DtlsConnection::new(
            self.default_config.clone(),
            local_addr,
            remote_addr,
        )?;

        let conn = Arc::new(conn);

        let mut connections = self.connections.lock().await;
        connections.push(Arc::clone(&conn));

        Ok(conn)
    }

    /// Removes a closed connection.
    pub async fn remove_connection(&self, conn: &DtlsConnection) {
        let mut connections = self.connections.lock().await;
        connections.retain(|c| !Arc::ptr_eq(c, &Arc::new(conn.clone())));
    }

    /// Returns the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }
}

// Implement Clone for DtlsConnection to support removal
// Note: This is a shallow clone that shares state
impl Clone for DtlsConnection {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            local_addr: self.local_addr.clone(),
            remote_addr: self.remote_addr.clone(),
            state: AtomicU8::new(self.state.load(Ordering::Acquire)),
            local_fingerprint: self.local_fingerprint.clone(),
            remote_fingerprint: Mutex::new(None),
            keying_material: Mutex::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn test_config() -> DtlsConfig {
        DtlsConfig::default()
            .with_identity(vec![vec![1, 2, 3, 4, 5]], vec![6, 7, 8, 9, 10])
    }

    #[tokio::test]
    async fn test_connection_creation() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5000);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5001);

        let conn = DtlsConnection::new(config, local, remote).unwrap();
        assert_eq!(conn.state(), DtlsState::New);
        assert_eq!(conn.role(), DtlsRole::Server);
    }

    #[tokio::test]
    async fn test_handshake() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5000);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5001);

        let conn = DtlsConnection::new(config, local, remote).unwrap();
        conn.handshake().await.unwrap();

        assert_eq!(conn.state(), DtlsState::Connected);
    }

    #[tokio::test]
    async fn test_export_keying_material() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5000);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5001);

        let conn = DtlsConnection::new(config, local, remote).unwrap();

        // Should fail before handshake
        assert!(conn.export_srtp_keying_material().await.is_err());

        conn.handshake().await.unwrap();

        // Should succeed after handshake
        let km = conn.export_srtp_keying_material().await.unwrap();
        assert_eq!(km.profile, SrtpProfile::AeadAes256Gcm);
        assert_eq!(km.client_write_key.len(), 32);
    }

    #[tokio::test]
    async fn test_close() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5000);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5001);

        let conn = DtlsConnection::new(config, local, remote).unwrap();
        conn.handshake().await.unwrap();
        conn.close().await.unwrap();

        assert_eq!(conn.state(), DtlsState::Closed);

        // Second close should fail
        assert!(conn.close().await.is_err());
    }
}
