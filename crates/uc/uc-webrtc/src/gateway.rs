//! WebRTC gateway for SIP-to-WebRTC interworking.
//!
//! This module provides the main gateway component that bridges
//! SIP and WebRTC endpoints.

use crate::config::WebRtcConfig;
use crate::error::{WebRtcError, WebRtcResult};
use crate::sdp_munge::{SdpMunger, WebRtcSdpMode};
use crate::session::{SessionManager, WebRtcSessionState};
use crate::trickle::{TrickleCandidate, TrickleIce, TrickleManager};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// WebRTC gateway for SIP interworking.
pub struct WebRtcGateway {
    /// Configuration.
    config: WebRtcConfig,
    /// Session manager.
    sessions: SessionManager,
    /// Trickle ICE manager.
    trickle: TrickleManager,
    /// SDP munger.
    sdp_munger: SdpMunger,
    /// Gateway statistics.
    stats: Arc<RwLock<GatewayStats>>,
}

/// Gateway statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    /// Total sessions created.
    pub sessions_created: u64,
    /// Total sessions completed.
    pub sessions_completed: u64,
    /// Total sessions failed.
    pub sessions_failed: u64,
    /// Current active sessions.
    pub active_sessions: u64,
    /// Total SDP transformations.
    pub sdp_transformations: u64,
    /// Total ICE candidates processed.
    pub ice_candidates_processed: u64,
}

/// Offer/answer result from the gateway.
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    /// Session ID.
    pub session_id: String,
    /// Transformed SDP.
    pub sdp: String,
    /// ICE credentials (ufrag, pwd).
    pub ice_credentials: Option<(String, String)>,
    /// DTLS fingerprint (algorithm, fingerprint).
    pub dtls_fingerprint: Option<(String, String)>,
}

impl WebRtcGateway {
    /// Creates a new WebRTC gateway.
    #[must_use]
    pub fn new(config: WebRtcConfig) -> Self {
        let sdp_munger = SdpMunger::new(config.sdp.clone());
        let sessions = SessionManager::new(config.clone());

        Self {
            config,
            sessions,
            trickle: TrickleManager::new(),
            sdp_munger,
            stats: Arc::new(RwLock::new(GatewayStats::default())),
        }
    }

    /// Creates a new WebRTC session for an incoming SIP call.
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails.
    pub async fn create_session(&self, sip_call_id: &str) -> WebRtcResult<String> {
        let session_id = format!("webrtc-{}", uuid_simple());

        self.sessions.create_session(session_id.clone()).await?;

        self.sessions
            .update_session(&session_id, |s| {
                s.set_sip_call_id(sip_call_id);
            })
            .await?;

        // Create trickle handler
        self.trickle.create(session_id.clone()).await;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.sessions_created += 1;
            stats.active_sessions += 1;
        }

        info!(
            session_id = %session_id,
            sip_call_id = %sip_call_id,
            "Created WebRTC session for SIP call"
        );

        Ok(session_id)
    }

    /// Processes an incoming SIP offer and generates a WebRTC-compatible answer.
    ///
    /// # Errors
    ///
    /// Returns an error if SDP processing fails.
    pub async fn process_sip_offer(
        &self,
        session_id: &str,
        sip_sdp: &str,
    ) -> WebRtcResult<GatewayResponse> {
        // Transform SDP for WebRTC
        let webrtc_sdp = self
            .sdp_munger
            .transform(sip_sdp, WebRtcSdpMode::SipToWebRtc)?;

        // Extract ICE credentials
        let ice_credentials = SdpMunger::extract_ice_credentials(&webrtc_sdp);

        // Extract DTLS fingerprint
        let dtls_fingerprint = SdpMunger::extract_fingerprint(&webrtc_sdp);

        // Update session
        self.sessions
            .update_session(session_id, |s| {
                s.set_remote_sdp(sip_sdp.to_string());
                if let Some((ufrag, pwd)) = &ice_credentials {
                    s.set_ice_credentials(ufrag, pwd);
                }
                if let Some((_, fp)) = &dtls_fingerprint {
                    s.set_dtls_fingerprint(fp);
                }
            })
            .await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.sdp_transformations += 1;
        }

        debug!(
            session_id = %session_id,
            "Processed SIP offer for WebRTC"
        );

        Ok(GatewayResponse {
            session_id: session_id.to_string(),
            sdp: webrtc_sdp,
            ice_credentials,
            dtls_fingerprint,
        })
    }

    /// Processes a WebRTC offer and generates a SIP-compatible answer.
    ///
    /// # Errors
    ///
    /// Returns an error if SDP processing fails.
    pub async fn process_webrtc_offer(
        &self,
        session_id: &str,
        webrtc_sdp: &str,
    ) -> WebRtcResult<GatewayResponse> {
        // Transform SDP for SIP
        let sip_sdp = self
            .sdp_munger
            .transform(webrtc_sdp, WebRtcSdpMode::WebRtcToSip)?;

        // Extract ICE credentials
        let ice_credentials = SdpMunger::extract_ice_credentials(&sip_sdp);

        // Extract DTLS fingerprint
        let dtls_fingerprint = SdpMunger::extract_fingerprint(&sip_sdp);

        // Update session
        self.sessions
            .update_session(session_id, |s| {
                s.set_remote_sdp(webrtc_sdp.to_string());
                if let Some((ufrag, pwd)) = &ice_credentials {
                    s.set_ice_credentials(ufrag, pwd);
                }
                if let Some((_, fp)) = &dtls_fingerprint {
                    s.set_dtls_fingerprint(fp);
                }
            })
            .await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.sdp_transformations += 1;
        }

        debug!(
            session_id = %session_id,
            "Processed WebRTC offer for SIP"
        );

        Ok(GatewayResponse {
            session_id: session_id.to_string(),
            sdp: sip_sdp,
            ice_credentials,
            dtls_fingerprint,
        })
    }

    /// Adds a remote ICE candidate to a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub async fn add_ice_candidate(
        &self,
        session_id: &str,
        candidate: TrickleCandidate,
    ) -> WebRtcResult<()> {
        // Add to session
        self.sessions
            .update_session(session_id, |s| {
                s.add_remote_candidate(candidate.clone());
            })
            .await?;

        // Add to trickle handler
        if let Some(mut trickle) = self.trickle.get(session_id).await {
            trickle.add_remote_candidate(candidate);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.ice_candidates_processed += 1;
        }

        Ok(())
    }

    /// Gets local ICE candidates for a session.
    pub async fn get_local_candidates(
        &self,
        session_id: &str,
    ) -> WebRtcResult<Vec<TrickleCandidate>> {
        let session = self.sessions.get_session(session_id).await.ok_or_else(|| {
            WebRtcError::SessionNotFound {
                session_id: session_id.to_string(),
            }
        })?;

        Ok(session.local_candidates().to_vec())
    }

    /// Notifies the gateway that ICE gathering is complete.
    pub async fn ice_gathering_complete(&self, session_id: &str) -> WebRtcResult<()> {
        if let Some(mut trickle) = self.trickle.get(session_id).await {
            trickle.add_local_candidate(TrickleIce::end_of_candidates());
        }
        Ok(())
    }

    /// Marks a session as connected.
    pub async fn session_connected(&self, session_id: &str) -> WebRtcResult<()> {
        self.sessions
            .update_session(session_id, |s| {
                s.set_connected();
            })
            .await?;

        info!(session_id = %session_id, "WebRTC session connected");
        Ok(())
    }

    /// Closes a session.
    pub async fn close_session(&self, session_id: &str) -> WebRtcResult<()> {
        // Remove from managers
        self.sessions.remove_session(session_id).await;
        self.trickle.remove(session_id).await;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.sessions_completed += 1;
            stats.active_sessions = stats.active_sessions.saturating_sub(1);
        }

        info!(session_id = %session_id, "Closed WebRTC session");
        Ok(())
    }

    /// Gets session state.
    pub async fn get_session_state(&self, session_id: &str) -> WebRtcResult<WebRtcSessionState> {
        let session = self.sessions.get_session(session_id).await.ok_or_else(|| {
            WebRtcError::SessionNotFound {
                session_id: session_id.to_string(),
            }
        })?;

        Ok(session.state())
    }

    /// Gets gateway statistics.
    pub async fn stats(&self) -> GatewayStats {
        self.stats.read().await.clone()
    }

    /// Gets the number of active sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.session_count().await
    }

    /// Runs periodic cleanup of expired sessions.
    pub async fn cleanup(&self) -> usize {
        let expired = self.sessions.cleanup_expired().await;

        if expired > 0 {
            let mut stats = self.stats.write().await;
            stats.active_sessions = stats.active_sessions.saturating_sub(expired as u64);
        }

        expired
    }

    /// Returns true if the gateway is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &WebRtcConfig {
        &self.config
    }
}

impl std::fmt::Debug for WebRtcGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcGateway")
            .field("enabled", &self.config.enabled)
            .field("trickle_enabled", &self.config.ice.trickle_enabled)
            .finish_non_exhaustive()
    }
}

/// Generates a simple UUID-like identifier.
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    format!("{:016x}", now)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_creation() {
        let config = WebRtcConfig::default();
        let gateway = WebRtcGateway::new(config);

        assert!(gateway.is_enabled());
        assert_eq!(gateway.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_create_session() {
        let config = WebRtcConfig::default();
        let gateway = WebRtcGateway::new(config);

        let session_id = gateway.create_session("call-123").await.unwrap();
        assert!(session_id.starts_with("webrtc-"));
        assert_eq!(gateway.active_session_count().await, 1);

        let state = gateway.get_session_state(&session_id).await.unwrap();
        assert_eq!(state, WebRtcSessionState::New);
    }

    #[tokio::test]
    async fn test_process_sip_offer() {
        let config = WebRtcConfig::default();
        let gateway = WebRtcGateway::new(config);

        let session_id = gateway.create_session("call-123").await.unwrap();

        let sip_sdp = "v=0\r\n\
            o=- 123 123 IN IP4 192.168.1.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            m=audio 5000 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n";

        let response = gateway
            .process_sip_offer(&session_id, sip_sdp)
            .await
            .unwrap();
        assert!(!response.sdp.is_empty());
    }

    #[tokio::test]
    async fn test_close_session() {
        let config = WebRtcConfig::default();
        let gateway = WebRtcGateway::new(config);

        let session_id = gateway.create_session("call-123").await.unwrap();
        assert_eq!(gateway.active_session_count().await, 1);

        gateway.close_session(&session_id).await.unwrap();
        assert_eq!(gateway.active_session_count().await, 0);

        let stats = gateway.stats().await;
        assert_eq!(stats.sessions_created, 1);
        assert_eq!(stats.sessions_completed, 1);
    }

    #[tokio::test]
    async fn test_add_ice_candidate() {
        let config = WebRtcConfig::default();
        let gateway = WebRtcGateway::new(config);

        let session_id = gateway.create_session("call-123").await.unwrap();

        let candidate =
            TrickleCandidate::new("candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host");
        gateway
            .add_ice_candidate(&session_id, candidate)
            .await
            .unwrap();

        let stats = gateway.stats().await;
        assert_eq!(stats.ice_candidates_processed, 1);
    }
}
