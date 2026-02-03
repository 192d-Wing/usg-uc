//! WebRTC session management.

use crate::config::WebRtcConfig;
use crate::error::{WebRtcError, WebRtcResult};
use crate::trickle::TrickleCandidate;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// WebRTC session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSessionState {
    /// Session created, waiting for offer.
    New,
    /// Local offer/answer generated.
    HaveLocalDescription,
    /// Remote offer/answer received.
    HaveRemoteDescription,
    /// Both descriptions set, ICE gathering.
    Connecting,
    /// ICE connected, DTLS handshaking.
    DtlsHandshaking,
    /// DTLS complete, media flowing.
    Connected,
    /// Session disconnected.
    Disconnected,
    /// Session failed.
    Failed,
    /// Session closed.
    Closed,
}

impl std::fmt::Display for WebRtcSessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::HaveLocalDescription => write!(f, "have-local-description"),
            Self::HaveRemoteDescription => write!(f, "have-remote-description"),
            Self::Connecting => write!(f, "connecting"),
            Self::DtlsHandshaking => write!(f, "dtls-handshaking"),
            Self::Connected => write!(f, "connected"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Failed => write!(f, "failed"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// WebRTC session representing a browser-to-SBC connection.
#[derive(Debug)]
pub struct WebRtcSession {
    /// Session identifier.
    id: String,
    /// Current state.
    state: WebRtcSessionState,
    /// Local SDP.
    local_sdp: Option<String>,
    /// Remote SDP.
    remote_sdp: Option<String>,
    /// Local ICE candidates.
    local_candidates: Vec<TrickleCandidate>,
    /// Remote ICE candidates.
    remote_candidates: Vec<TrickleCandidate>,
    /// Session creation time.
    created_at: Instant,
    /// Last activity time.
    last_activity: Instant,
    /// Associated SIP call ID.
    sip_call_id: Option<String>,
    /// Local media address.
    local_media_addr: Option<SocketAddr>,
    /// Remote media address.
    remote_media_addr: Option<SocketAddr>,
    /// DTLS fingerprint.
    dtls_fingerprint: Option<String>,
    /// ICE username fragment.
    ice_ufrag: Option<String>,
    /// ICE password.
    ice_pwd: Option<String>,
}

impl WebRtcSession {
    /// Creates a new WebRTC session.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            state: WebRtcSessionState::New,
            local_sdp: None,
            remote_sdp: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            created_at: now,
            last_activity: now,
            sip_call_id: None,
            local_media_addr: None,
            remote_media_addr: None,
            dtls_fingerprint: None,
            ice_ufrag: None,
            ice_pwd: None,
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> WebRtcSessionState {
        self.state
    }

    /// Returns the local SDP.
    #[must_use]
    pub fn local_sdp(&self) -> Option<&str> {
        self.local_sdp.as_deref()
    }

    /// Returns the remote SDP.
    #[must_use]
    pub fn remote_sdp(&self) -> Option<&str> {
        self.remote_sdp.as_deref()
    }

    /// Sets the local SDP.
    pub fn set_local_sdp(&mut self, sdp: String) {
        self.local_sdp = Some(sdp);
        self.state = WebRtcSessionState::HaveLocalDescription;
        self.last_activity = Instant::now();
    }

    /// Sets the remote SDP.
    pub fn set_remote_sdp(&mut self, sdp: String) {
        self.remote_sdp = Some(sdp);
        self.state = if self.local_sdp.is_some() {
            WebRtcSessionState::Connecting
        } else {
            WebRtcSessionState::HaveRemoteDescription
        };
        self.last_activity = Instant::now();
    }

    /// Adds a local ICE candidate.
    pub fn add_local_candidate(&mut self, candidate: TrickleCandidate) {
        debug!(session = %self.id, candidate = %candidate.candidate, "Added local ICE candidate");
        self.local_candidates.push(candidate);
        self.last_activity = Instant::now();
    }

    /// Adds a remote ICE candidate.
    pub fn add_remote_candidate(&mut self, candidate: TrickleCandidate) {
        debug!(session = %self.id, candidate = %candidate.candidate, "Added remote ICE candidate");
        self.remote_candidates.push(candidate);
        self.last_activity = Instant::now();
    }

    /// Returns local ICE candidates.
    #[must_use]
    pub fn local_candidates(&self) -> &[TrickleCandidate] {
        &self.local_candidates
    }

    /// Returns remote ICE candidates.
    #[must_use]
    pub fn remote_candidates(&self) -> &[TrickleCandidate] {
        &self.remote_candidates
    }

    /// Associates this session with a SIP call.
    pub fn set_sip_call_id(&mut self, call_id: impl Into<String>) {
        self.sip_call_id = Some(call_id.into());
    }

    /// Returns the associated SIP call ID.
    #[must_use]
    pub fn sip_call_id(&self) -> Option<&str> {
        self.sip_call_id.as_deref()
    }

    /// Sets the DTLS fingerprint.
    pub fn set_dtls_fingerprint(&mut self, fingerprint: impl Into<String>) {
        self.dtls_fingerprint = Some(fingerprint.into());
    }

    /// Returns the DTLS fingerprint.
    #[must_use]
    pub fn dtls_fingerprint(&self) -> Option<&str> {
        self.dtls_fingerprint.as_deref()
    }

    /// Sets ICE credentials.
    pub fn set_ice_credentials(&mut self, ufrag: impl Into<String>, pwd: impl Into<String>) {
        self.ice_ufrag = Some(ufrag.into());
        self.ice_pwd = Some(pwd.into());
    }

    /// Returns ICE username fragment.
    #[must_use]
    pub fn ice_ufrag(&self) -> Option<&str> {
        self.ice_ufrag.as_deref()
    }

    /// Returns ICE password.
    #[must_use]
    pub fn ice_pwd(&self) -> Option<&str> {
        self.ice_pwd.as_deref()
    }

    /// Transitions to connected state.
    pub fn set_connected(&mut self) {
        self.state = WebRtcSessionState::Connected;
        self.last_activity = Instant::now();
        info!(session = %self.id, "WebRTC session connected");
    }

    /// Transitions to failed state.
    pub fn set_failed(&mut self, reason: &str) {
        self.state = WebRtcSessionState::Failed;
        self.last_activity = Instant::now();
        info!(session = %self.id, reason, "WebRTC session failed");
    }

    /// Closes the session.
    pub fn close(&mut self) {
        self.state = WebRtcSessionState::Closed;
        self.last_activity = Instant::now();
        info!(session = %self.id, "WebRTC session closed");
    }

    /// Returns true if the session is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            WebRtcSessionState::New
                | WebRtcSessionState::HaveLocalDescription
                | WebRtcSessionState::HaveRemoteDescription
                | WebRtcSessionState::Connecting
                | WebRtcSessionState::DtlsHandshaking
                | WebRtcSessionState::Connected
        )
    }

    /// Returns the session age.
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Returns time since last activity.
    #[must_use]
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }
}

/// WebRTC session manager.
pub struct SessionManager {
    /// Active sessions by ID.
    sessions: Arc<RwLock<HashMap<String, WebRtcSession>>>,
    /// Configuration.
    config: WebRtcConfig,
}

impl SessionManager {
    /// Creates a new session manager.
    #[must_use]
    pub fn new(config: WebRtcConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Creates a new WebRTC session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session limit is reached.
    pub async fn create_session(&self, id: impl Into<String>) -> WebRtcResult<String> {
        let id = id.into();
        let mut sessions = self.sessions.write().await;

        if sessions.len() >= self.config.session.max_sessions {
            return Err(WebRtcError::ConfigError {
                reason: format!(
                    "max sessions ({}) reached",
                    self.config.session.max_sessions
                ),
            });
        }

        if sessions.contains_key(&id) {
            return Err(WebRtcError::SessionExists {
                session_id: id.clone(),
            });
        }

        let session = WebRtcSession::new(id.clone());
        sessions.insert(id.clone(), session);

        info!(session_id = %id, "Created WebRTC session");
        Ok(id)
    }

    /// Gets a session by ID.
    pub async fn get_session(&self, id: &str) -> Option<WebRtcSession> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }

    /// Updates a session with a closure.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub async fn update_session<F>(&self, id: &str, f: F) -> WebRtcResult<()>
    where
        F: FnOnce(&mut WebRtcSession),
    {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(id) {
            f(session);
            Ok(())
        } else {
            Err(WebRtcError::SessionNotFound {
                session_id: id.to_string(),
            })
        }
    }

    /// Removes a session.
    pub async fn remove_session(&self, id: &str) -> Option<WebRtcSession> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.remove(id);
        if session.is_some() {
            info!(session_id = %id, "Removed WebRTC session");
        }
        session
    }

    /// Returns the number of active sessions.
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Cleans up expired sessions.
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let idle_timeout = self.config.session.idle_timeout;

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.idle_time() > idle_timeout)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            sessions.remove(&id);
            debug!(session_id = %id, "Cleaned up expired WebRTC session");
        }

        if count > 0 {
            info!(count, "Cleaned up expired WebRTC sessions");
        }

        count
    }
}

impl Clone for WebRtcSession {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            state: self.state,
            local_sdp: self.local_sdp.clone(),
            remote_sdp: self.remote_sdp.clone(),
            local_candidates: self.local_candidates.clone(),
            remote_candidates: self.remote_candidates.clone(),
            created_at: self.created_at,
            last_activity: self.last_activity,
            sip_call_id: self.sip_call_id.clone(),
            local_media_addr: self.local_media_addr,
            remote_media_addr: self.remote_media_addr,
            dtls_fingerprint: self.dtls_fingerprint.clone(),
            ice_ufrag: self.ice_ufrag.clone(),
            ice_pwd: self.ice_pwd.clone(),
        }
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("max_sessions", &self.config.session.max_sessions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_display() {
        assert_eq!(WebRtcSessionState::New.to_string(), "new");
        assert_eq!(WebRtcSessionState::Connected.to_string(), "connected");
    }

    #[test]
    fn test_session_creation() {
        let session = WebRtcSession::new("test-session");
        assert_eq!(session.id(), "test-session");
        assert_eq!(session.state(), WebRtcSessionState::New);
        assert!(session.is_active());
    }

    #[test]
    fn test_session_sdp() {
        let mut session = WebRtcSession::new("test");
        session.set_local_sdp("v=0\r\n".to_string());
        assert_eq!(session.state(), WebRtcSessionState::HaveLocalDescription);

        session.set_remote_sdp("v=0\r\n".to_string());
        assert_eq!(session.state(), WebRtcSessionState::Connecting);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let config = WebRtcConfig::default();
        let manager = SessionManager::new(config);

        let id = manager.create_session("session-1").await.unwrap();
        assert_eq!(id, "session-1");
        assert_eq!(manager.session_count().await, 1);

        manager.remove_session("session-1").await;
        assert_eq!(manager.session_count().await, 0);
    }
}
