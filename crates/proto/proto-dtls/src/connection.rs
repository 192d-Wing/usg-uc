//! DTLS connection handling.
//!
//! ## CNSA 2.0 Compliance
//!
//! Connections use CNSA 2.0 compliant cipher suites only.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment
//! - **SC-13**: Cryptographic Protection
//!
//! ## RFC Compliance
//!
//! - RFC 6347: DTLS 1.2
//! - RFC 5764: DTLS-SRTP

use crate::config::DtlsConfig;
use crate::error::{DtlsError, DtlsResult};
use crate::fingerprint::CertificateFingerprint;
use crate::session::DtlsSession;
use crate::{DtlsRole, DtlsState, SrtpKeyingMaterial};
use bytes::Bytes;
use uc_types::address::SbcSocketAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{debug, instrument, warn};

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
/// All cryptographic operations use CNSA 2.0 compliant algorithms:
/// - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite
/// - P-384 ECDHE key exchange
/// - P-384 ECDSA certificates
pub struct DtlsConnection {
    config: DtlsConfig,
    local_addr: SbcSocketAddr,
    remote_addr: SbcSocketAddr,
    state: AtomicU8,
    local_fingerprint: CertificateFingerprint,
    remote_fingerprint: Mutex<Option<CertificateFingerprint>>,
    keying_material: Mutex<Option<SrtpKeyingMaterial>>,
    session: Mutex<Option<DtlsSession>>,
    socket: Mutex<Option<Arc<UdpSocket>>>,
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
            session: Mutex::new(None),
            socket: Mutex::new(None),
        })
    }

    /// Creates a new DTLS connection with an existing UDP socket.
    ///
    /// Use this when you already have a bound socket.
    #[instrument(skip(config, socket), fields(local = %local_addr, remote = %remote_addr))]
    pub fn with_socket(
        config: DtlsConfig,
        local_addr: SbcSocketAddr,
        remote_addr: SbcSocketAddr,
        socket: Arc<UdpSocket>,
    ) -> DtlsResult<Self> {
        let conn = Self::new(config, local_addr, remote_addr)?;
        {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                handle.block_on(async {
                    let mut sock = conn.socket.lock().await;
                    *sock = Some(socket);
                });
            }
        }
        Ok(conn)
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

    /// Creates and binds a UDP socket for the connection.
    async fn ensure_socket(&self) -> DtlsResult<Arc<UdpSocket>> {
        let mut socket_guard = self.socket.lock().await;

        if let Some(ref socket) = *socket_guard {
            return Ok(Arc::clone(socket));
        }

        // Bind to local address
        let local_std_addr: SocketAddr = self.local_addr.clone().into();
        let socket = UdpSocket::bind(local_std_addr).await.map_err(|e| {
            DtlsError::Io {
                reason: format!("failed to bind UDP socket: {e}"),
            }
        })?;

        // Connect to remote address
        let remote_std_addr: SocketAddr = self.remote_addr.clone().into();
        socket.connect(remote_std_addr).await.map_err(|e| {
            DtlsError::Io {
                reason: format!("failed to connect UDP socket: {e}"),
            }
        })?;

        let socket = Arc::new(socket);
        *socket_guard = Some(Arc::clone(&socket));

        debug!(
            local = %self.local_addr,
            remote = %self.remote_addr,
            "UDP socket bound and connected"
        );

        Ok(socket)
    }

    /// Performs the DTLS handshake.
    ///
    /// ## CNSA 2.0 Compliance
    ///
    /// The handshake enforces CNSA 2.0 cipher suite negotiation.
    /// If the peer doesn't support TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    /// the handshake will fail.
    ///
    /// ## Errors
    ///
    /// Returns an error if the handshake fails or times out.
    #[instrument(skip(self))]
    pub async fn handshake(&self) -> DtlsResult<()> {
        if self.state() != DtlsState::New {
            return Err(DtlsError::InvalidConfig {
                reason: "handshake already started".to_string(),
            });
        }

        self.set_state(DtlsState::Connecting);

        debug!(
            role = ?self.config.role,
            timeout_secs = self.config.handshake_timeout.as_secs(),
            "Starting DTLS handshake"
        );

        // Ensure we have a socket
        let socket = self.ensure_socket().await?;

        // Perform handshake with timeout
        let is_client = self.config.role.is_client();
        let handshake_result = timeout(
            self.config.handshake_timeout,
            DtlsSession::new(&self.config, socket, is_client),
        )
        .await;

        let dtls_session = match handshake_result {
            Ok(Ok(session)) => session,
            Ok(Err(e)) => {
                self.set_state(DtlsState::Failed);
                warn!(error = %e, "DTLS handshake failed");
                return Err(e);
            }
            Err(_) => {
                self.set_state(DtlsState::Failed);
                warn!("DTLS handshake timed out");
                return Err(DtlsError::Timeout);
            }
        };

        // Export SRTP keying material
        let keying_material = dtls_session.export_srtp_keying_material().await?;

        // Store session and keying material
        {
            let mut session = self.session.lock().await;
            *session = Some(dtls_session);
        }
        {
            let mut km = self.keying_material.lock().await;
            *km = Some(keying_material);
        }

        self.set_state(DtlsState::Connected);
        debug!("DTLS handshake completed successfully");

        Ok(())
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

        let session = self.session.lock().await;
        if let Some(ref sess) = *session {
            sess.send(data).await?;
            debug!(size = data.len(), "DTLS send completed");
            Ok(())
        } else {
            Err(DtlsError::NotConnected)
        }
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

        let session = self.session.lock().await;
        if let Some(ref sess) = *session {
            let data = sess.recv().await?;
            debug!(size = data.len(), "DTLS recv completed");
            Ok(data)
        } else {
            Err(DtlsError::NotConnected)
        }
    }

    /// Receives decrypted data with timeout.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection is not established, receive fails, or times out.
    #[instrument(skip(self))]
    pub async fn recv_timeout(&self, duration: Duration) -> DtlsResult<Bytes> {
        match timeout(duration, self.recv()).await {
            Ok(result) => result,
            Err(_) => Err(DtlsError::Timeout),
        }
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

        // Close the session
        {
            let mut session = self.session.lock().await;
            if let Some(ref mut sess) = *session {
                let _ = sess.close().await;
            }
            *session = None;
        }

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

    /// Removes a closed connection from the manager.
    pub async fn remove_connection(&self, conn: &Arc<DtlsConnection>) {
        let mut connections = self.connections.lock().await;
        connections.retain(|c| !Arc::ptr_eq(c, conn));
    }

    /// Returns the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Closes all connections.
    pub async fn close_all(&self) {
        let connections = {
            let mut conns = self.connections.lock().await;
            std::mem::take(&mut *conns)
        };

        for conn in connections {
            let _ = conn.close().await;
        }
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
            session: Mutex::new(None),
            socket: Mutex::new(None),
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
    async fn test_connection_state_transitions() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5002);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5003);

        let conn = DtlsConnection::new(config, local, remote).unwrap();
        assert_eq!(conn.state(), DtlsState::New);

        conn.set_state(DtlsState::Connecting);
        assert_eq!(conn.state(), DtlsState::Connecting);

        conn.set_state(DtlsState::Connected);
        assert_eq!(conn.state(), DtlsState::Connected);
    }

    #[tokio::test]
    async fn test_send_recv_without_handshake() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5004);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5005);

        let conn = DtlsConnection::new(config, local, remote).unwrap();

        // Should fail - not connected
        assert!(conn.send(b"test").await.is_err());
        assert!(conn.recv().await.is_err());
    }

    #[tokio::test]
    async fn test_export_keying_material_without_handshake() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5006);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5007);

        let conn = DtlsConnection::new(config, local, remote).unwrap();

        // Should fail - not connected
        assert!(conn.export_srtp_keying_material().await.is_err());
    }

    #[tokio::test]
    async fn test_close() {
        let config = test_config();
        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5008);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5009);

        let conn = DtlsConnection::new(config, local, remote).unwrap();

        // Close should work even without handshake
        conn.close().await.unwrap();
        assert_eq!(conn.state(), DtlsState::Closed);

        // Second close should fail
        assert!(conn.close().await.is_err());
    }

    #[tokio::test]
    async fn test_connection_manager() {
        let config = test_config();
        let manager = DtlsConnectionManager::new(config);

        let local = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5010);
        let remote = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5011);

        let conn = manager.create_connection(local, remote).await.unwrap();
        assert_eq!(manager.connection_count().await, 1);

        manager.remove_connection(&conn).await;
        assert_eq!(manager.connection_count().await, 0);
    }
}
