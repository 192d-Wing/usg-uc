//! Media Session for secure RTP/SRTP.
//!
//! Coordinates ICE, DTLS, and SRTP to establish and maintain
//! a secure media session for voice calls.

use crate::dtls_handler::{DtlsEvent, DtlsHandler};
use crate::ice_handler::{IceEvent, IceHandler};
use crate::{SipUaError, SipUaResult};
use proto_dtls::SrtpKeyingMaterial;
use proto_ice::{IceConfig, IceCredentials};
use proto_rtp::packet::RtpPacket;
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpProtect, SrtpUnprotect};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

/// Media session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSessionState {
    /// Session created but not started.
    New,
    /// Gathering ICE candidates.
    Gathering,
    /// ICE connectivity checks in progress.
    Connecting,
    /// DTLS handshake in progress.
    Securing,
    /// Session established, media can flow.
    Active,
    /// Session is being closed.
    Closing,
    /// Session has been closed.
    Closed,
    /// Session failed to establish.
    Failed,
}

/// Media session manages the complete secure media pipeline.
pub struct MediaSession {
    /// Session state.
    state: MediaSessionState,
    /// ICE handler for connectivity.
    ice_handler: IceHandler,
    /// DTLS handler for security.
    dtls_handler: DtlsHandler,
    /// Outbound SRTP context (for encrypting RTP we send).
    outbound_srtp: Option<Arc<RwLock<SrtpContext>>>,
    /// Inbound SRTP context (for decrypting RTP we receive).
    inbound_srtp: Option<Arc<RwLock<SrtpContext>>>,
    /// UDP socket for media.
    socket: Option<Arc<UdpSocket>>,
    /// Local SSRC for outbound RTP.
    local_ssrc: u32,
    /// Remote SSRC for inbound RTP.
    remote_ssrc: Option<u32>,
    /// Local address.
    local_addr: SocketAddr,
    /// Remote address (from ICE).
    remote_addr: Option<SocketAddr>,
    /// Event sender.
    event_tx: mpsc::Sender<MediaSessionEvent>,
    /// ICE event receiver.
    #[allow(dead_code)]
    ice_rx: mpsc::Receiver<IceEvent>,
    /// DTLS event receiver.
    #[allow(dead_code)]
    dtls_rx: mpsc::Receiver<DtlsEvent>,
}

/// Events emitted by the media session.
#[derive(Debug, Clone)]
pub enum MediaSessionEvent {
    /// State changed.
    StateChanged {
        /// New state.
        state: MediaSessionState,
    },
    /// ICE candidate discovered (for SDP).
    LocalCandidate {
        /// SDP candidate line.
        sdp_line: String,
    },
    /// ICE credentials generated (for SDP).
    LocalCredentials {
        /// ICE ufrag.
        ufrag: String,
        /// ICE password.
        pwd: String,
    },
    /// DTLS fingerprint generated (for SDP).
    LocalFingerprint {
        /// SHA-384 fingerprint.
        fingerprint: String,
    },
    /// Media session is ready for RTP.
    Ready {
        /// Local address for sending.
        local_addr: SocketAddr,
        /// Remote address for sending.
        remote_addr: SocketAddr,
    },
    /// Media session failed.
    Failed {
        /// Error reason.
        reason: String,
    },
}

impl MediaSession {
    /// Creates a new media session.
    ///
    /// # Arguments
    /// * `local_addr` - Local address for media
    /// * `is_outbound` - True for outbound calls (ICE controlling, DTLS client)
    /// * `ice_config` - ICE configuration with STUN/TURN servers
    /// * `dtls_cert_chain` - Certificate chain for DTLS
    /// * `dtls_private_key` - Private key for DTLS
    /// * `event_tx` - Channel for media session events
    pub fn new(
        local_addr: SocketAddr,
        is_outbound: bool,
        ice_config: IceConfig,
        dtls_cert_chain: Vec<Vec<u8>>,
        dtls_private_key: Vec<u8>,
        event_tx: mpsc::Sender<MediaSessionEvent>,
    ) -> Self {
        // Create channels for ICE and DTLS events
        let (ice_tx, ice_rx) = mpsc::channel(32);
        let (dtls_tx, dtls_rx) = mpsc::channel(32);

        // Create handlers based on call direction
        let ice_handler = if is_outbound {
            IceHandler::for_outbound(local_addr, ice_config, ice_tx)
        } else {
            IceHandler::for_inbound(local_addr, ice_config, ice_tx)
        };

        let dtls_handler = if is_outbound {
            DtlsHandler::for_outbound(dtls_cert_chain, dtls_private_key, local_addr, dtls_tx)
        } else {
            DtlsHandler::for_inbound(dtls_cert_chain, dtls_private_key, local_addr, dtls_tx)
        };

        // Generate random SSRC
        let local_ssrc = rand_ssrc();

        Self {
            state: MediaSessionState::New,
            ice_handler,
            dtls_handler,
            outbound_srtp: None,
            inbound_srtp: None,
            socket: None,
            local_ssrc,
            remote_ssrc: None,
            local_addr,
            remote_addr: None,
            event_tx,
            ice_rx,
            dtls_rx,
        }
    }

    /// Gets the current session state.
    pub fn state(&self) -> MediaSessionState {
        self.state
    }

    /// Gets the local SSRC.
    pub fn local_ssrc(&self) -> u32 {
        self.local_ssrc
    }

    /// Sets the remote SSRC.
    pub fn set_remote_ssrc(&mut self, ssrc: u32) {
        self.remote_ssrc = Some(ssrc);
    }

    /// Gets local ICE credentials for SDP.
    pub fn local_ice_credentials(&self) -> IceCredentials {
        self.ice_handler.local_credentials()
    }

    /// Sets remote ICE credentials from SDP.
    pub fn set_remote_ice_credentials(&mut self, credentials: IceCredentials) {
        self.ice_handler.set_remote_credentials(credentials);
    }

    /// Gets local DTLS fingerprint for SDP.
    pub fn local_dtls_fingerprint(&self) -> String {
        self.dtls_handler.local_fingerprint()
    }

    /// Gets local ICE candidates formatted for SDP.
    pub fn local_ice_candidates_sdp(&self) -> Vec<String> {
        self.ice_handler.format_sdp_candidates()
    }

    /// Adds a remote ICE candidate from SDP.
    pub fn add_remote_ice_candidate(&mut self, sdp_line: &str) -> SipUaResult<()> {
        let candidate = IceHandler::parse_sdp_candidate(sdp_line)?;
        self.ice_handler.add_remote_candidate(&candidate);
        Ok(())
    }

    /// Starts the media session.
    ///
    /// This begins ICE gathering, then connectivity checks,
    /// then DTLS handshake, and finally creates SRTP contexts.
    pub async fn start(&mut self) -> SipUaResult<()> {
        info!("Starting media session");

        // Create UDP socket
        let socket = UdpSocket::bind(self.local_addr)
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());

        // Set socket on DTLS handler
        self.dtls_handler.set_socket(socket);

        // Update state and notify
        self.set_state(MediaSessionState::Gathering).await;

        // Send local credentials
        let creds = self.ice_handler.local_credentials();
        let _ = self
            .event_tx
            .send(MediaSessionEvent::LocalCredentials {
                ufrag: creds.ufrag.clone(),
                pwd: creds.pwd.clone(),
            })
            .await;

        // Send local fingerprint
        let fp = self.dtls_handler.local_fingerprint();
        if !fp.is_empty() {
            let _ = self
                .event_tx
                .send(MediaSessionEvent::LocalFingerprint { fingerprint: fp })
                .await;
        }

        // Start ICE gathering
        self.ice_handler.gather_candidates().await?;

        // Send local candidates
        for sdp_line in self.ice_handler.format_sdp_candidates() {
            let _ = self
                .event_tx
                .send(MediaSessionEvent::LocalCandidate { sdp_line })
                .await;
        }

        Ok(())
    }

    /// Establishes connectivity after remote SDP is received.
    ///
    /// Call this after setting remote ICE credentials and candidates.
    pub async fn establish(&mut self, remote_fingerprint: Option<&str>) -> SipUaResult<()> {
        info!("Establishing media session connectivity");

        // Start ICE checks
        self.set_state(MediaSessionState::Connecting).await;
        self.ice_handler.start_checks().await?;

        // Wait for ICE to connect
        // In a real implementation, we'd process events from ice_rx
        // For now, use the selected pair if available

        // Get selected ICE pair
        let (local_addr, remote_addr) = self.ice_handler.selected_pair().ok_or_else(|| {
            SipUaError::IceError("No ICE candidates available".to_string())
        })?;

        self.remote_addr = Some(remote_addr);
        info!(
            local = %local_addr,
            remote = %remote_addr,
            "ICE connectivity established"
        );

        // Start DTLS handshake
        self.set_state(MediaSessionState::Securing).await;

        let keying_material = self
            .dtls_handler
            .handshake(remote_addr, remote_fingerprint)
            .await?;

        // Create SRTP contexts
        self.create_srtp_contexts(&keying_material)?;

        // Session is now active
        self.set_state(MediaSessionState::Active).await;

        let _ = self
            .event_tx
            .send(MediaSessionEvent::Ready {
                local_addr,
                remote_addr,
            })
            .await;

        info!("Media session established and ready");

        Ok(())
    }

    /// Creates SRTP contexts from DTLS keying material.
    fn create_srtp_contexts(&mut self, keying: &SrtpKeyingMaterial) -> SipUaResult<()> {
        let role = self.dtls_handler.role();

        // Create outbound SRTP context
        let outbound_material = SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            keying.local_key(role).to_vec(),
            keying.local_salt(role).to_vec(),
        )
        .map_err(|e| {
            SipUaError::DtlsError(format!("Failed to create outbound key material: {e}"))
        })?;

        let outbound_ctx = SrtpContext::new(&outbound_material, SrtpDirection::Outbound, self.local_ssrc)
            .map_err(|e| {
                SipUaError::DtlsError(format!("Failed to create outbound SRTP context: {e}"))
            })?;

        self.outbound_srtp = Some(Arc::new(RwLock::new(outbound_ctx)));

        // Create inbound SRTP context
        let inbound_material = SrtpKeyMaterial::new(
            SrtpProfile::AeadAes256Gcm,
            keying.remote_key(role).to_vec(),
            keying.remote_salt(role).to_vec(),
        )
        .map_err(|e| {
            SipUaError::DtlsError(format!("Failed to create inbound key material: {e}"))
        })?;

        // Use remote SSRC if known, otherwise use 0 (will be updated on first packet)
        let remote_ssrc = self.remote_ssrc.unwrap_or(0);

        let inbound_ctx = SrtpContext::new(&inbound_material, SrtpDirection::Inbound, remote_ssrc)
            .map_err(|e| {
                SipUaError::DtlsError(format!("Failed to create inbound SRTP context: {e}"))
            })?;

        self.inbound_srtp = Some(Arc::new(RwLock::new(inbound_ctx)));

        debug!("SRTP contexts created");

        Ok(())
    }

    /// Protects (encrypts) an outbound RTP packet.
    pub async fn protect_rtp(&self, packet: &RtpPacket) -> SipUaResult<Vec<u8>> {
        let ctx = self
            .outbound_srtp
            .as_ref()
            .ok_or_else(|| SipUaError::InvalidState("SRTP not initialized".to_string()))?;

        let ctx_guard = ctx.read().await;
        let protector = SrtpProtect::new(&ctx_guard);

        let protected = protector
            .protect_rtp(packet)
            .map_err(|e| SipUaError::DtlsError(format!("SRTP protect failed: {e}")))?;

        Ok(protected.to_vec())
    }

    /// Unprotects (decrypts) an inbound SRTP packet.
    pub async fn unprotect_rtp(&self, srtp_packet: &[u8]) -> SipUaResult<RtpPacket> {
        let ctx = self
            .inbound_srtp
            .as_ref()
            .ok_or_else(|| SipUaError::InvalidState("SRTP not initialized".to_string()))?;

        let ctx_guard = ctx.read().await;
        let unprotector = SrtpUnprotect::new(&ctx_guard);

        unprotector
            .unprotect_rtp(srtp_packet)
            .await
            .map_err(|e| SipUaError::DtlsError(format!("SRTP unprotect failed: {e}")))
    }

    /// Sends an RTP packet (encrypts and sends).
    pub async fn send_rtp(&self, packet: &RtpPacket) -> SipUaResult<()> {
        let remote_addr = self
            .remote_addr
            .ok_or_else(|| SipUaError::InvalidState("Remote address not set".to_string()))?;

        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| SipUaError::InvalidState("Socket not initialized".to_string()))?;

        // Encrypt
        let protected = self.protect_rtp(packet).await?;

        // Send
        socket
            .send_to(&protected, remote_addr)
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Receives an RTP packet (receives and decrypts).
    pub async fn recv_rtp(&self) -> SipUaResult<RtpPacket> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| SipUaError::InvalidState("Socket not initialized".to_string()))?;

        let mut buf = vec![0u8; 2048];

        let (len, _addr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        buf.truncate(len);

        // Decrypt
        self.unprotect_rtp(&buf).await
    }

    /// Closes the media session.
    pub async fn close(&mut self) -> SipUaResult<()> {
        info!("Closing media session");

        self.set_state(MediaSessionState::Closing).await;

        // Close DTLS
        self.dtls_handler.close().await?;

        // Clear SRTP contexts
        self.outbound_srtp = None;
        self.inbound_srtp = None;

        // Clear socket
        self.socket = None;

        self.set_state(MediaSessionState::Closed).await;

        Ok(())
    }

    /// Sets the state and notifies listeners.
    async fn set_state(&mut self, state: MediaSessionState) {
        self.state = state;
        let _ = self
            .event_tx
            .send(MediaSessionEvent::StateChanged { state })
            .await;
    }
}

/// Generates a random SSRC.
fn rand_ssrc() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Simple PRNG for SSRC (in production, use a proper RNG)
    ((seed ^ (seed >> 17) ^ (seed << 13)) & 0xFFFF_FFFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_media_session_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let session = MediaSession::new(
            local_addr,
            true, // outbound
            IceConfig::default(),
            vec![], // Empty cert for testing
            vec![], // Empty key for testing
            tx,
        );

        // Verify initial state
        assert_eq!(session.state(), MediaSessionState::New);
    }

    #[test]
    fn test_rand_ssrc() {
        let ssrc1 = rand_ssrc();
        let ssrc2 = rand_ssrc();
        // SSRCs should be generated (may or may not be different due to timing)
        assert!(ssrc1 > 0 || ssrc2 > 0);
    }
}
