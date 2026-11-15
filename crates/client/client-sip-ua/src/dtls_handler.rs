//! DTLS Handler for secure media.
//!
//! Manages DTLS handshake and SRTP key derivation for encrypting
//! RTP/RTCP media streams with AES-256-GCM (CNSA 2.0 compliant).

use crate::{SipUaError, SipUaResult};
use proto_dtls::{
    CertificateFingerprint, DtlsConfig, DtlsConnection, DtlsRole, DtlsState, SrtpKeyingMaterial,
    SrtpProfile,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uc_types::address::SbcSocketAddr;

/// DTLS handler for media security.
pub struct DtlsHandler {
    /// DTLS configuration.
    config: DtlsConfig,
    /// DTLS connection (created during handshake).
    connection: Option<DtlsConnection>,
    /// Event sender for DTLS state changes.
    event_tx: mpsc::Sender<DtlsEvent>,
    /// Local address.
    local_addr: SocketAddr,
    /// Remote address (set when starting handshake).
    remote_addr: Option<SocketAddr>,
    /// UDP socket for DTLS (shared with RTP).
    socket: Option<Arc<UdpSocket>>,
}

/// Events emitted by the DTLS handler.
#[derive(Debug, Clone)]
pub enum DtlsEvent {
    /// DTLS state changed.
    StateChanged {
        /// New state.
        state: DtlsState,
    },
    /// DTLS handshake completed successfully.
    HandshakeComplete {
        /// SRTP keying material for encryption.
        keying_material: SrtpKeyingMaterial,
    },
    /// DTLS handshake failed.
    HandshakeFailed {
        /// Error message.
        reason: String,
    },
    /// Remote fingerprint verification failed.
    FingerprintMismatch {
        /// Expected fingerprint (from SDP).
        expected: String,
        /// Actual fingerprint from peer certificate.
        actual: String,
    },
}

impl DtlsHandler {
    /// Creates a new DTLS handler.
    ///
    /// # Arguments
    /// * `config` - DTLS configuration with certificates
    /// * `local_addr` - Local address for DTLS
    /// * `event_tx` - Channel for sending DTLS events
    pub const fn new(
        config: DtlsConfig,
        local_addr: SocketAddr,
        event_tx: mpsc::Sender<DtlsEvent>,
    ) -> Self {
        Self {
            config,
            connection: None,
            event_tx,
            local_addr,
            remote_addr: None,
            socket: None,
        }
    }

    /// Creates a DTLS handler for outbound calls (Client role).
    pub fn for_outbound(
        cert_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        local_addr: SocketAddr,
        event_tx: mpsc::Sender<DtlsEvent>,
    ) -> Self {
        let config = DtlsConfig::new(DtlsRole::Client).with_identity(cert_chain, private_key);

        Self::new(config, local_addr, event_tx)
    }

    /// Creates a DTLS handler for inbound calls (Server role).
    pub fn for_inbound(
        cert_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        local_addr: SocketAddr,
        event_tx: mpsc::Sender<DtlsEvent>,
    ) -> Self {
        let config = DtlsConfig::new(DtlsRole::Server).with_identity(cert_chain, private_key);

        Self::new(config, local_addr, event_tx)
    }

    /// Gets the local certificate fingerprint for SDP.
    ///
    /// Returns the SHA-384 fingerprint in the format:
    /// `sha-384 XX:XX:XX:...`
    pub fn local_fingerprint(&self) -> String {
        // Create a temporary connection to get fingerprint
        self.connection.as_ref().map_or_else(
            || {
                // Create temp connection just for fingerprint
                let temp_addr: SocketAddr = "0.0.0.0:0".parse().unwrap_or(self.local_addr);
                let local_sbc: SbcSocketAddr = self.local_addr.into();
                let temp_sbc: SbcSocketAddr = temp_addr.into();
                DtlsConnection::new(self.config.clone(), local_sbc, temp_sbc).map_or_else(
                    |_| String::new(),
                    |conn| conn.local_fingerprint().to_string(),
                )
            },
            |conn| conn.local_fingerprint().to_string(),
        )
    }

    /// Sets the expected remote fingerprint from SDP.
    ///
    /// This will be verified during the handshake.
    /// Note: This is a no-op if no connection exists yet; fingerprint
    /// will be set when `handshake()` is called.
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] if the value does not parse as a
    /// CNSA (sha-384/sha-512) fingerprint; it is never silently dropped.
    pub async fn set_remote_fingerprint(&self, fingerprint: &str) -> SipUaResult<()> {
        let fp = CertificateFingerprint::from_sdp_strict(fingerprint)
            .map_err(|e| SipUaError::DtlsError(format!("invalid remote fingerprint: {e}")))?;
        if let Some(conn) = &self.connection {
            conn.set_remote_fingerprint(fp).await;
        }
        Ok(())
    }

    /// Gets the DTLS role.
    pub const fn role(&self) -> DtlsRole {
        self.config.role
    }

    /// Sets the DTLS role negotiated by `a=setup` (RFC 5763 §5). The role is
    /// not fixed by call direction.
    ///
    /// # Errors
    /// Returns [`SipUaError::InvalidState`] once a handshake has started.
    pub fn set_role(&mut self, role: DtlsRole) -> SipUaResult<()> {
        if self.connection.is_some() || self.remote_addr.is_some() {
            return Err(SipUaError::InvalidState(
                "DTLS role cannot change after the handshake started".to_string(),
            ));
        }
        self.config.role = role;
        Ok(())
    }

    /// Gets the current DTLS state.
    pub fn state(&self) -> DtlsState {
        self.connection
            .as_ref()
            .map_or(DtlsState::New, DtlsConnection::state)
    }

    /// Sets the UDP socket to use for DTLS.
    ///
    /// This socket should be shared with the RTP pipeline.
    pub fn set_socket(&mut self, socket: Arc<UdpSocket>) {
        self.socket = Some(socket);
    }

    /// Drops this handler's reference to the media socket (handoff to the
    /// audio pipeline).
    pub fn clear_socket(&mut self) {
        self.socket = None;
    }

    /// Performs the DTLS handshake.
    ///
    /// # Arguments
    /// * `remote_addr` - Remote address to connect to
    /// * `remote_fingerprints` - Fingerprints from the remote SDP; the peer
    ///   certificate must match at least one (RFC 8122 §5). Empty is an error.
    ///
    /// # Returns
    /// SRTP keying material on success.
    pub async fn handshake(
        &mut self,
        remote_addr: SocketAddr,
        remote_fingerprints: &[CertificateFingerprint],
    ) -> SipUaResult<SrtpKeyingMaterial> {
        // RFC 5763 §6.7.1: never handshake without a fingerprint to verify.
        if remote_fingerprints.is_empty() {
            return Err(SipUaError::DtlsError(
                "no remote fingerprint signalled".to_string(),
            ));
        }
        info!(
            local = %self.local_addr,
            remote = %remote_addr,
            role = ?self.config.role,
            "Starting DTLS handshake"
        );

        self.remote_addr = Some(remote_addr);

        let local_sbc: SbcSocketAddr = self.local_addr.into();
        let remote_sbc: SbcSocketAddr = remote_addr.into();

        // Create connection
        let connection = if let Some(socket) = &self.socket {
            DtlsConnection::with_socket(self.config.clone(), local_sbc, remote_sbc, socket.clone())
                .map_err(|e| SipUaError::DtlsError(e.to_string()))?
        } else {
            DtlsConnection::new(self.config.clone(), local_sbc, remote_sbc)
                .map_err(|e| SipUaError::DtlsError(e.to_string()))?
        };

        connection
            .set_remote_fingerprints(remote_fingerprints.to_vec())
            .await;

        // Notify state change
        let _ = self
            .event_tx
            .send(DtlsEvent::StateChanged {
                state: DtlsState::Connecting,
            })
            .await;

        // Perform handshake
        match connection.handshake().await {
            Ok(()) => {
                debug!("DTLS handshake successful");
            }
            Err(e) => {
                error!(error = %e, "DTLS handshake failed");

                let _ = self
                    .event_tx
                    .send(DtlsEvent::HandshakeFailed {
                        reason: e.to_string(),
                    })
                    .await;

                return Err(SipUaError::DtlsError(e.to_string()));
            }
        }

        // Export SRTP keying material
        let keying_material = connection
            .export_srtp_keying_material()
            .await
            .map_err(|e| SipUaError::DtlsError(e.to_string()))?;

        info!("DTLS handshake complete, SRTP keys derived");

        // Notify completion
        let _ = self
            .event_tx
            .send(DtlsEvent::StateChanged {
                state: DtlsState::Connected,
            })
            .await;

        let _ = self
            .event_tx
            .send(DtlsEvent::HandshakeComplete {
                keying_material: keying_material.clone(),
            })
            .await;

        // Store connection
        self.connection = Some(connection);

        Ok(keying_material)
    }

    /// Gets the SRTP keying material (after successful handshake).
    pub async fn get_keying_material(&self) -> SipUaResult<SrtpKeyingMaterial> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| SipUaError::DtlsError("DTLS not connected".to_string()))?;

        conn.export_srtp_keying_material()
            .await
            .map_err(|e| SipUaError::DtlsError(e.to_string()))
    }

    /// Gets the SRTP profile (always AES-256-GCM for CNSA 2.0).
    pub const fn srtp_profile(&self) -> SrtpProfile {
        SrtpProfile::AeadAes256Gcm
    }

    /// Closes the DTLS connection.
    pub async fn close(&mut self) -> SipUaResult<()> {
        if self.connection.is_some() {
            // Connection will be closed when dropped
            info!("Closing DTLS connection");
        }

        let _ = self
            .event_tx
            .send(DtlsEvent::StateChanged {
                state: DtlsState::Closed,
            })
            .await;

        self.connection = None;
        Ok(())
    }

    /// Formats the fingerprint for SDP.
    ///
    /// Returns: `a=fingerprint:sha-384 XX:XX:XX:...`
    pub fn format_sdp_fingerprint(&self) -> String {
        let fp = self.local_fingerprint();
        if fp.is_empty() {
            String::new()
        } else {
            format!("a=fingerprint:{fp}")
        }
    }

    /// Formats the DTLS setup attribute for SDP.
    ///
    /// Returns: `a=setup:active` or `a=setup:passive`
    pub fn format_sdp_setup(&self) -> String {
        match self.config.role {
            DtlsRole::Client => "a=setup:active".to_string(),
            DtlsRole::Server => "a=setup:passive".to_string(),
        }
    }

    /// Parses the remote setup attribute from SDP and returns our role.
    ///
    /// RFC 4145 §4 / RFC 5763 §5: they are `active` → we are passive
    /// (Server); they are `passive` or `actpass` → we are active (Client).
    ///
    /// # Errors
    /// Returns [`SipUaError::DtlsError`] for `holdconn` or an unknown value;
    /// garbage is never mapped to a role.
    pub fn parse_remote_setup(setup: &str) -> SipUaResult<DtlsRole> {
        crate::sdp_dtls::Setup::parse(setup)?
            .answer_to_offer()?
            .local_role()
    }
}

/// Helper to create DTLS config from PEM files.
pub fn load_dtls_config_from_pem(
    cert_path: &str,
    key_path: &str,
    role: DtlsRole,
) -> SipUaResult<DtlsConfig> {
    DtlsConfig::new(role)
        .with_pem_files(cert_path, key_path)
        .map_err(|e| SipUaError::CertificateError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dtls_handler_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:10000".parse().unwrap();

        // Create with empty cert for testing
        let config = DtlsConfig::new(DtlsRole::Client);
        let handler = DtlsHandler::new(config, local_addr, tx);

        assert_eq!(handler.role(), DtlsRole::Client);
        assert_eq!(handler.state(), DtlsState::New);
    }

    #[test]
    fn test_parse_remote_setup() {
        assert_eq!(
            DtlsHandler::parse_remote_setup("active").unwrap(),
            DtlsRole::Server
        );
        assert_eq!(
            DtlsHandler::parse_remote_setup("passive").unwrap(),
            DtlsRole::Client
        );
        assert_eq!(
            DtlsHandler::parse_remote_setup("ACTPASS").unwrap(),
            DtlsRole::Client
        );
        assert!(DtlsHandler::parse_remote_setup("holdconn").is_err());
        assert!(DtlsHandler::parse_remote_setup("garbage").is_err());
    }

    #[tokio::test]
    async fn handshake_requires_fingerprint_and_locks_role() {
        let (tx, _rx) = mpsc::channel(10);
        let id = crate::DtlsIdentity::generate().unwrap();
        let config = DtlsConfig::new(DtlsRole::Client)
            .with_identity(id.cert_chain_der().to_vec(), id.key_der().to_vec());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = sock.local_addr().unwrap();
        let mut handler = DtlsHandler::new(config, local, tx);
        handler.set_socket(sock);
        handler.set_role(DtlsRole::Server).unwrap();
        assert_eq!(handler.role(), DtlsRole::Server);

        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(handler.handshake(remote, &[]).await.is_err());

        // No DTLS handshake exists yet (POA&M-324): with a fingerprint the
        // handshake still fails closed, and the role is now locked.
        let fp = CertificateFingerprint::from_certificate_sha384(b"peer");
        assert!(handler.handshake(remote, &[fp]).await.is_err());
        assert!(handler.set_role(DtlsRole::Client).is_err());
        assert!(handler.get_keying_material().await.is_err());
    }

    #[tokio::test]
    async fn set_remote_fingerprint_rejects_bad_values() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = DtlsHandler::new(
            DtlsConfig::new(DtlsRole::Client),
            "127.0.0.1:0".parse().unwrap(),
            tx,
        );
        assert!(
            handler
                .set_remote_fingerprint("sha-256 AA:BB")
                .await
                .is_err()
        );
        assert!(handler.set_remote_fingerprint("garbage").await.is_err());
        let fp = CertificateFingerprint::from_certificate_sha384(b"x").to_sdp();
        handler.set_remote_fingerprint(&fp).await.unwrap();
    }

    #[test]
    fn test_srtp_profile() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:10000".parse().unwrap();
        let config = DtlsConfig::new(DtlsRole::Client);
        let handler = DtlsHandler::new(config, local_addr, tx);

        // Always AES-256-GCM for CNSA 2.0
        assert_eq!(handler.srtp_profile(), SrtpProfile::AeadAes256Gcm);
    }
}
