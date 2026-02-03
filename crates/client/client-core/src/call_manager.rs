//! Call manager for coordinating call lifecycle.
//!
//! Provides high-level call management including:
//! - Making and receiving calls
//! - Call state tracking
//! - Media session coordination
//! - Call history integration

use crate::contact_manager::ContactManager;
use crate::{AppError, AppResult};
use client_sip_ua::{CallAgent, CallEvent, MediaSession, MediaSessionEvent, MediaSessionState};
use client_types::{
    CallDirection, CallEndReason, CallHistoryEntry, CallInfo, CallState, SipAccount,
};
use chrono::Utc;
use proto_ice::IceConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Call manager coordinates calls between SIP UA and media sessions.
pub struct CallManager {
    /// SIP call agent.
    call_agent: CallAgent,
    /// Active media sessions by call ID.
    media_sessions: HashMap<String, MediaSession>,
    /// Local address for media.
    local_media_addr: SocketAddr,
    /// ICE configuration.
    ice_config: IceConfig,
    /// DTLS certificate chain (from smart card or file).
    dtls_cert_chain: Vec<Vec<u8>>,
    /// DTLS private key.
    dtls_private_key: Vec<u8>,
    /// Event sender for application events.
    app_event_tx: mpsc::Sender<CallManagerEvent>,
    /// Contact manager for call history (optional).
    contact_manager: Option<Arc<RwLock<ContactManager>>>,
    /// Current SIP account.
    account: Option<SipAccount>,
    /// Active call ID (single call mode for now).
    active_call_id: Option<String>,
    /// Whether muted.
    is_muted: bool,
}

/// Events emitted by the call manager.
#[derive(Debug, Clone)]
pub enum CallManagerEvent {
    /// Call state changed.
    CallStateChanged {
        /// Call ID.
        call_id: String,
        /// New state.
        state: CallState,
        /// Call info.
        info: CallInfo,
    },
    /// Incoming call (ring!).
    IncomingCall {
        /// Call ID.
        call_id: String,
        /// Remote party URI.
        remote_uri: String,
        /// Remote party display name.
        remote_display_name: Option<String>,
    },
    /// Call connected, media ready.
    CallConnected {
        /// Call ID.
        call_id: String,
        /// Local media address.
        local_addr: SocketAddr,
        /// Remote media address.
        remote_addr: SocketAddr,
    },
    /// Call ended.
    CallEnded {
        /// Call ID.
        call_id: String,
        /// End reason.
        reason: CallEndReason,
        /// Call duration in seconds (if connected).
        duration_secs: Option<u64>,
    },
    /// Media session state changed.
    MediaStateChanged {
        /// Call ID.
        call_id: String,
        /// New media state.
        state: MediaSessionState,
    },
    /// Error occurred.
    Error {
        /// Call ID (if applicable).
        call_id: Option<String>,
        /// Error message.
        message: String,
    },
}

impl CallManager {
    /// Creates a new call manager.
    ///
    /// # Arguments
    /// * `local_sip_addr` - Local address for SIP signaling
    /// * `local_media_addr` - Local address for RTP media
    /// * `app_event_tx` - Channel for application events
    pub fn new(
        local_sip_addr: SocketAddr,
        local_media_addr: SocketAddr,
        app_event_tx: mpsc::Sender<CallManagerEvent>,
    ) -> Self {
        // Create internal channel for call agent events
        let (call_event_tx, _call_event_rx) = mpsc::channel(64);

        let call_agent = CallAgent::new(
            local_sip_addr,
            String::new(), // Will be set when account is configured
            String::new(),
            call_event_tx,
        );

        Self {
            call_agent,
            media_sessions: HashMap::new(),
            local_media_addr,
            ice_config: IceConfig::default(),
            dtls_cert_chain: Vec::new(),
            dtls_private_key: Vec::new(),
            app_event_tx,
            contact_manager: None,
            account: None,
            active_call_id: None,
            is_muted: false,
        }
    }

    /// Configures the call manager with a SIP account.
    pub fn configure_account(&mut self, account: &SipAccount) {
        self.account = Some(account.clone());
        info!(account_id = %account.id, "Call manager configured with account");
    }

    /// Sets the ICE configuration.
    pub fn set_ice_config(&mut self, config: IceConfig) {
        self.ice_config = config;
    }

    /// Sets the DTLS credentials.
    pub fn set_dtls_credentials(&mut self, cert_chain: Vec<Vec<u8>>, private_key: Vec<u8>) {
        self.dtls_cert_chain = cert_chain;
        self.dtls_private_key = private_key;
        info!("DTLS credentials configured");
    }

    /// Sets the contact manager for call history.
    pub fn set_contact_manager(&mut self, manager: Arc<RwLock<ContactManager>>) {
        self.contact_manager = Some(manager);
    }

    /// Makes an outbound call.
    ///
    /// # Arguments
    /// * `remote_uri` - SIP URI to call (e.g., "sips:bob@example.com")
    ///
    /// # Returns
    /// Call ID on success.
    pub async fn make_call(&mut self, remote_uri: &str) -> AppResult<String> {
        // Check if there's already an active call
        if let Some(call_id) = &self.active_call_id {
            return Err(AppError::Sip(format!(
                "Already have an active call: {call_id}"
            )));
        }

        // Verify we have an account configured
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account configured".to_string()))?;

        info!(remote_uri = %remote_uri, "Making outbound call");

        // Create media session channel
        let (media_tx, _media_rx) = mpsc::channel(32);

        // Create media session for this call
        let media_session = MediaSession::new(
            self.local_media_addr,
            true, // outbound = controlling
            self.ice_config.clone(),
            self.dtls_cert_chain.clone(),
            self.dtls_private_key.clone(),
            media_tx,
        );

        // Generate SDP offer from media session
        let sdp_offer = self.generate_sdp_offer(&media_session, account)?;

        // Make the call via SIP UA
        let call_id = self
            .call_agent
            .make_call(remote_uri, &sdp_offer)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Store media session
        self.media_sessions.insert(call_id.clone(), media_session);
        self.active_call_id = Some(call_id.clone());

        // Notify application
        let info = CallInfo {
            id: call_id.clone(),
            state: CallState::Dialing,
            direction: CallDirection::Outbound,
            remote_uri: remote_uri.to_string(),
            remote_display_name: None,
            start_time: Utc::now(),
            connect_time: None,
            is_muted: false,
            is_on_hold: false,
            failure_reason: None,
        };

        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.clone(),
                state: CallState::Dialing,
                info,
            })
            .await;

        Ok(call_id)
    }

    /// Hangs up the current call.
    pub async fn hangup(&mut self) -> AppResult<()> {
        let call_id = self
            .active_call_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No active call".to_string()))?
            .clone();

        self.hangup_call(&call_id).await
    }

    /// Hangs up a specific call.
    pub async fn hangup_call(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Hanging up call");

        // Get call info before hangup
        let call_info = self.call_agent.get_call_info(call_id);

        // Send hangup via SIP UA
        self.call_agent
            .hangup(call_id)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        // Close media session
        if let Some(mut session) = self.media_sessions.remove(call_id) {
            let _ = session.close().await;
        }

        // Record in call history
        if let Some(info) = call_info {
            self.record_call_history(&info, CallEndReason::LocalHangup)
                .await;
        }

        // Clear active call
        if self.active_call_id.as_ref() == Some(&call_id.to_string()) {
            self.active_call_id = None;
        }

        // Notify application
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallEnded {
                call_id: call_id.to_string(),
                reason: CallEndReason::LocalHangup,
                duration_secs: None,
            })
            .await;

        Ok(())
    }

    /// Handles a call event from the SIP UA.
    pub async fn handle_call_event(&mut self, event: CallEvent) -> AppResult<()> {
        match event {
            CallEvent::StateChanged {
                call_id,
                state,
                info,
            } => {
                self.handle_state_changed(&call_id, state, info).await?;
            }
            CallEvent::SdpAnswerReceived { call_id, sdp } => {
                self.handle_sdp_answer(&call_id, &sdp).await?;
            }
            CallEvent::SendRequest { .. } => {
                // Transport layer handles this
            }
            CallEvent::SendResponse { .. } => {
                // Transport layer handles this
            }
            CallEvent::SdpOfferReceived { call_id, sdp } => {
                self.handle_sdp_offer(&call_id, &sdp).await?;
            }
        }

        Ok(())
    }

    /// Handles a media session event.
    pub async fn handle_media_event(
        &mut self,
        call_id: &str,
        event: MediaSessionEvent,
    ) -> AppResult<()> {
        match event {
            MediaSessionEvent::StateChanged { state } => {
                debug!(call_id = %call_id, state = ?state, "Media session state changed");

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::MediaStateChanged {
                        call_id: call_id.to_string(),
                        state,
                    })
                    .await;
            }
            MediaSessionEvent::Ready {
                local_addr,
                remote_addr,
            } => {
                info!(
                    call_id = %call_id,
                    local = %local_addr,
                    remote = %remote_addr,
                    "Media session ready"
                );

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::CallConnected {
                        call_id: call_id.to_string(),
                        local_addr,
                        remote_addr,
                    })
                    .await;
            }
            MediaSessionEvent::Failed { reason } => {
                error!(call_id = %call_id, reason = %reason, "Media session failed");

                let _ = self
                    .app_event_tx
                    .send(CallManagerEvent::Error {
                        call_id: Some(call_id.to_string()),
                        message: reason,
                    })
                    .await;
            }
            MediaSessionEvent::LocalCandidate { .. }
            | MediaSessionEvent::LocalCredentials { .. }
            | MediaSessionEvent::LocalFingerprint { .. } => {
                // These are handled during SDP generation
            }
        }

        Ok(())
    }

    /// Toggles mute state.
    pub fn toggle_mute(&mut self) -> bool {
        self.is_muted = !self.is_muted;
        info!(muted = self.is_muted, "Mute toggled");
        self.is_muted
    }

    /// Returns whether currently muted.
    pub fn is_muted(&self) -> bool {
        self.is_muted
    }

    /// Returns the active call ID.
    pub fn active_call_id(&self) -> Option<&str> {
        self.active_call_id.as_deref()
    }

    /// Returns info for the active call.
    pub fn active_call_info(&self) -> Option<CallInfo> {
        self.active_call_id
            .as_ref()
            .and_then(|id| self.call_agent.get_call_info(id))
    }

    /// Returns the state of a specific call.
    pub fn get_call_state(&self, call_id: &str) -> Option<CallState> {
        self.call_agent.get_state(call_id)
    }

    /// Returns info for a specific call.
    pub fn get_call_info(&self, call_id: &str) -> Option<CallInfo> {
        self.call_agent.get_call_info(call_id)
    }

    /// Returns the media session for a call.
    pub fn get_media_session(&self, call_id: &str) -> Option<&MediaSession> {
        self.media_sessions.get(call_id)
    }

    /// Returns mutable reference to media session for a call.
    pub fn get_media_session_mut(&mut self, call_id: &str) -> Option<&mut MediaSession> {
        self.media_sessions.get_mut(call_id)
    }

    // --- Private methods ---

    async fn handle_state_changed(
        &mut self,
        call_id: &str,
        state: CallState,
        info: Option<CallInfo>,
    ) -> AppResult<()> {
        debug!(call_id = %call_id, state = ?state, "Call state changed");

        let call_info = info.unwrap_or_else(|| {
            self.call_agent
                .get_call_info(call_id)
                .unwrap_or_else(|| CallInfo {
                    id: call_id.to_string(),
                    state,
                    direction: CallDirection::Outbound,
                    remote_uri: String::new(),
                    remote_display_name: None,
                    start_time: Utc::now(),
                    connect_time: None,
                    is_muted: self.is_muted,
                    is_on_hold: false,
                    failure_reason: None,
                })
        });

        match state {
            CallState::Connected => {
                // Start media session
                if let Some(session) = self.media_sessions.get_mut(call_id) {
                    if let Err(e) = session.establish(None).await {
                        warn!(call_id = %call_id, error = %e, "Failed to establish media");
                    }
                }
            }
            CallState::Terminated => {
                // Clean up media session
                if let Some(mut session) = self.media_sessions.remove(call_id) {
                    let _ = session.close().await;
                }

                // Record in call history
                let end_reason = call_info
                    .failure_reason
                    .as_ref()
                    .map(|_| CallEndReason::Failed)
                    .unwrap_or(CallEndReason::RemoteHangup);

                self.record_call_history(&call_info, end_reason).await;

                // Clear active call
                if self.active_call_id.as_ref() == Some(&call_id.to_string()) {
                    self.active_call_id = None;
                }
            }
            _ => {}
        }

        // Notify application
        let _ = self
            .app_event_tx
            .send(CallManagerEvent::CallStateChanged {
                call_id: call_id.to_string(),
                state,
                info: call_info,
            })
            .await;

        Ok(())
    }

    async fn handle_sdp_answer(&mut self, call_id: &str, sdp: &str) -> AppResult<()> {
        debug!(call_id = %call_id, "Received SDP answer");

        // Parse SDP and configure media session
        if let Some(session) = self.media_sessions.get_mut(call_id) {
            // Extract ICE credentials from SDP
            if let Some(creds) = parse_ice_credentials_from_sdp(sdp) {
                session.set_remote_ice_credentials(creds);
            }

            // Extract ICE candidates from SDP
            for line in sdp.lines() {
                if line.starts_with("a=candidate:") {
                    if let Err(e) = session.add_remote_ice_candidate(line) {
                        warn!(error = %e, "Failed to add remote ICE candidate");
                    }
                }
            }

            // Start media session
            if let Err(e) = session.start().await {
                error!(call_id = %call_id, error = %e, "Failed to start media session");
            }
        }

        Ok(())
    }

    async fn handle_sdp_offer(&mut self, call_id: &str, sdp: &str) -> AppResult<()> {
        debug!(call_id = %call_id, "Received SDP offer");

        // For incoming calls, we'd create a media session here
        // and generate an answer
        let _ = (call_id, sdp);

        Ok(())
    }

    fn generate_sdp_offer(&self, session: &MediaSession, account: &SipAccount) -> AppResult<String> {
        let creds = session.local_ice_credentials();
        let fingerprint = session.local_dtls_fingerprint();
        let ssrc = session.local_ssrc();

        // Generate basic SDP offer
        // In production, this would use proto-sdp properly
        let sdp = format!(
            "v=0\r\n\
             o=- {session_id} {session_version} IN IP4 {ip}\r\n\
             s=USG SIP Client\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 111 0 8\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:sha-384 {fingerprint}\r\n\
             a=setup:actpass\r\n\
             a=mid:audio\r\n\
             a=sendrecv\r\n\
             a=rtcp-mux\r\n\
             a=ssrc:{ssrc} cname:{cname}\r\n",
            session_id = session_id(),
            session_version = 1,
            ip = self.local_media_addr.ip(),
            port = self.local_media_addr.port(),
            ufrag = creds.ufrag,
            pwd = creds.pwd,
            fingerprint = fingerprint,
            ssrc = ssrc,
            cname = account.id,
        );

        Ok(sdp)
    }

    async fn record_call_history(&self, info: &CallInfo, end_reason: CallEndReason) {
        if let Some(manager) = &self.contact_manager {
            let entry = CallHistoryEntry::from_call_info(info, end_reason);
            let mut guard = manager.write().await;
            guard.add_call_history(entry);
            if let Err(e) = guard.save_if_dirty() {
                warn!(error = %e, "Failed to save call history");
            }
        }
    }
}

/// Parses ICE credentials from SDP.
fn parse_ice_credentials_from_sdp(sdp: &str) -> Option<proto_ice::IceCredentials> {
    let mut ufrag = None;
    let mut pwd = None;

    for line in sdp.lines() {
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            pwd = Some(value.trim().to_string());
        }
    }

    match (ufrag, pwd) {
        (Some(ufrag), Some(pwd)) => Some(proto_ice::IceCredentials { ufrag, pwd }),
        _ => None,
    }
}

/// Generates a unique session ID for SDP.
fn session_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_call_manager_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let manager = CallManager::new(sip_addr, media_addr, tx);

        assert!(manager.active_call_id().is_none());
        assert!(!manager.is_muted());
    }

    #[tokio::test]
    async fn test_make_call_without_account() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager.make_call("sips:bob@example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_hangup_without_active_call() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager.hangup().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_toggle_mute() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let media_addr: SocketAddr = "192.168.1.100:16384".parse().unwrap();

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        assert!(!manager.is_muted());
        assert!(manager.toggle_mute());
        assert!(manager.is_muted());
        assert!(!manager.toggle_mute());
        assert!(!manager.is_muted());
    }

    #[test]
    fn test_parse_ice_credentials() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 0.0.0.0\r\n\
                   s=-\r\n\
                   c=IN IP4 0.0.0.0\r\n\
                   t=0 0\r\n\
                   m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                   a=ice-ufrag:testufrag\r\n\
                   a=ice-pwd:testpassword\r\n";

        let creds = parse_ice_credentials_from_sdp(sdp).unwrap();
        assert_eq!(creds.ufrag, "testufrag");
        assert_eq!(creds.pwd, "testpassword");
    }

    #[test]
    fn test_parse_ice_credentials_missing() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n";
        assert!(parse_ice_credentials_from_sdp(sdp).is_none());
    }
}
