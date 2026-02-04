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
    pub fn new(
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
        if let Some(conn) = &self.connection {
            conn.local_fingerprint().to_string()
        } else {
            // Create temp connection just for fingerprint
            let temp_addr: SocketAddr = "0.0.0.0:0".parse().unwrap_or(self.local_addr);
            let local_sbc: SbcSocketAddr = self.local_addr.into();
            let temp_sbc: SbcSocketAddr = temp_addr.into();
            if let Ok(conn) = DtlsConnection::new(self.config.clone(), local_sbc, temp_sbc) {
                conn.local_fingerprint().to_string()
            } else {
                String::new()
            }
        }
    }

    /// Sets the expected remote fingerprint from SDP.
    ///
    /// This will be verified during the handshake.
    /// Note: This is a no-op if no connection exists yet; fingerprint
    /// will be set when handshake() is called.
    pub async fn set_remote_fingerprint(&self, fingerprint: &str) {
        if let Some(conn) = &self.connection {
            if let Ok(fp) = CertificateFingerprint::from_sdp(fingerprint) {
                conn.set_remote_fingerprint(fp).await;
            }
        }
    }

    /// Gets the DTLS role.
    pub fn role(&self) -> DtlsRole {
        self.config.role
    }

    /// Gets the current DTLS state.
    pub fn state(&self) -> DtlsState {
        self.connection
            .as_ref()
            .map(|c| c.state())
            .unwrap_or(DtlsState::New)
    }

    /// Sets the UDP socket to use for DTLS.
    ///
    /// This socket should be shared with the RTP pipeline.
    pub fn set_socket(&mut self, socket: Arc<UdpSocket>) {
        self.socket = Some(socket);
    }

    /// Performs the DTLS handshake.
    ///
    /// # Arguments
    /// * `remote_addr` - Remote address to connect to
    /// * `remote_fingerprint` - Expected fingerprint from SDP (optional)
    ///
    /// # Returns
    /// SRTP keying material on success.
    pub async fn handshake(
        &mut self,
        remote_addr: SocketAddr,
        remote_fingerprint: Option<&str>,
    ) -> SipUaResult<SrtpKeyingMaterial> {
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

        // Set remote fingerprint if provided
        if let Some(fp_str) = remote_fingerprint {
            if let Ok(fp) = CertificateFingerprint::from_sdp(fp_str) {
                connection.set_remote_fingerprint(fp).await;
            }
        }

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
    pub fn srtp_profile(&self) -> SrtpProfile {
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
    /// Returns: `a=setup:actpass`, `a=setup:active`, or `a=setup:passive`
    pub fn format_sdp_setup(&self) -> String {
        match self.config.role {
            DtlsRole::Client => "a=setup:active".to_string(),
            DtlsRole::Server => "a=setup:passive".to_string(),
        }
    }

    /// Parses the remote setup attribute from SDP.
    ///
    /// Returns the role we should use based on their setup.
    pub fn parse_remote_setup(setup: &str) -> DtlsRole {
        match setup.to_lowercase().as_str() {
            "active" => DtlsRole::Server,  // They're active, we're passive
            "passive" => DtlsRole::Client, // They're passive, we're active
            "actpass" => DtlsRole::Client, // They support both, we choose active
            _ => DtlsRole::Client,         // Default to client
        }
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
        assert_eq!(DtlsHandler::parse_remote_setup("active"), DtlsRole::Server);
        assert_eq!(DtlsHandler::parse_remote_setup("passive"), DtlsRole::Client);
        assert_eq!(DtlsHandler::parse_remote_setup("actpass"), DtlsRole::Client);
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
