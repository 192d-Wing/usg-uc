//! ICE trickling support for WebRTC.
//!
//! This module implements ICE candidate trickling per RFC 8838,
//! enabling incremental exchange of ICE candidates.

use crate::error::{WebRtcError, WebRtcResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info};

/// Trickle ICE candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrickleCandidate {
    /// ICE candidate string (RFC 5245 format).
    pub candidate: String,

    /// SDP media line index (m-line).
    pub sdp_m_line_index: Option<u32>,

    /// SDP media ID.
    pub sdp_mid: Option<String>,

    /// Username fragment.
    pub username_fragment: Option<String>,
}

impl TrickleCandidate {
    /// Creates a new trickle candidate.
    #[must_use]
    pub fn new(candidate: impl Into<String>) -> Self {
        Self {
            candidate: candidate.into(),
            sdp_m_line_index: None,
            sdp_mid: None,
            username_fragment: None,
        }
    }

    /// Sets the SDP m-line index.
    #[must_use]
    pub const fn with_m_line_index(mut self, index: u32) -> Self {
        self.sdp_m_line_index = Some(index);
        self
    }

    /// Sets the SDP mid.
    #[must_use]
    pub fn with_mid(mut self, mid: impl Into<String>) -> Self {
        self.sdp_mid = Some(mid.into());
        self
    }

    /// Sets the username fragment.
    #[must_use]
    pub fn with_ufrag(mut self, ufrag: impl Into<String>) -> Self {
        self.username_fragment = Some(ufrag.into());
        self
    }

    /// Returns true if this is an end-of-candidates indicator.
    #[must_use]
    pub fn is_end_of_candidates(&self) -> bool {
        self.candidate.is_empty() || self.candidate == "end-of-candidates"
    }

    /// Parses from an ICE candidate attribute line.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(line: &str) -> WebRtcResult<Self> {
        // Format: a=candidate:foundation component-id transport priority address port type [extensions]
        let candidate = if let Some(stripped) = line.strip_prefix("a=candidate:") {
            format!("candidate:{stripped}")
        } else if line.starts_with("candidate:") {
            line.to_string()
        } else {
            return Err(WebRtcError::IceError {
                reason: format!("invalid candidate format: {line}"),
            });
        };

        Ok(Self::new(candidate))
    }

    /// Formats as an SDP attribute line.
    #[must_use]
    pub fn to_sdp_attribute(&self) -> String {
        format!("a={}", self.candidate)
    }
}

impl std::fmt::Display for TrickleCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.candidate)?;
        if let Some(mid) = &self.sdp_mid {
            write!(f, " (mid={mid})")?;
        }
        if let Some(idx) = self.sdp_m_line_index {
            write!(f, " (m-line={idx})")?;
        }
        Ok(())
    }
}

/// Trickle ICE state for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrickleState {
    /// Trickling not started.
    Idle,
    /// Gathering candidates locally.
    Gathering,
    /// Receiving remote candidates.
    Receiving,
    /// All candidates gathered/received.
    Complete,
}

/// Trickle ICE handler for a single session.
#[derive(Debug)]
pub struct TrickleIce {
    /// Session ID.
    session_id: String,
    /// Current state.
    state: TrickleState,
    /// Local candidates.
    local_candidates: Vec<TrickleCandidate>,
    /// Remote candidates.
    remote_candidates: Vec<TrickleCandidate>,
    /// Local gathering complete.
    local_complete: bool,
    /// Remote gathering complete.
    remote_complete: bool,
    /// Broadcast sender for new candidates.
    candidate_tx: broadcast::Sender<TrickleCandidate>,
}

impl TrickleIce {
    /// Creates a new trickle ICE handler.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        let (candidate_tx, _) = broadcast::channel(64);
        Self {
            session_id: session_id.into(),
            state: TrickleState::Idle,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            local_complete: false,
            remote_complete: false,
            candidate_tx,
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> TrickleState {
        self.state
    }

    /// Starts local candidate gathering.
    pub fn start_gathering(&mut self) {
        self.state = TrickleState::Gathering;
        debug!(session = %self.session_id, "Started ICE candidate gathering");
    }

    /// Adds a local candidate.
    pub fn add_local_candidate(&mut self, candidate: TrickleCandidate) {
        if candidate.is_end_of_candidates() {
            self.local_complete = true;
            self.update_state();
            info!(session = %self.session_id, "Local ICE gathering complete");
        } else {
            debug!(
                session = %self.session_id,
                candidate = %candidate.candidate,
                "Added local ICE candidate"
            );
            self.local_candidates.push(candidate.clone());
            let _ = self.candidate_tx.send(candidate);
        }
    }

    /// Adds a remote candidate.
    pub fn add_remote_candidate(&mut self, candidate: TrickleCandidate) {
        if candidate.is_end_of_candidates() {
            self.remote_complete = true;
            self.update_state();
            info!(session = %self.session_id, "Remote ICE gathering complete");
        } else {
            if self.state == TrickleState::Idle {
                self.state = TrickleState::Receiving;
            }
            debug!(
                session = %self.session_id,
                candidate = %candidate.candidate,
                "Added remote ICE candidate"
            );
            self.remote_candidates.push(candidate);
        }
    }

    /// Updates state based on completion flags.
    fn update_state(&mut self) {
        if self.local_complete && self.remote_complete {
            self.state = TrickleState::Complete;
            info!(session = %self.session_id, "ICE trickling complete");
        }
    }

    /// Returns local candidates.
    #[must_use]
    pub fn local_candidates(&self) -> &[TrickleCandidate] {
        &self.local_candidates
    }

    /// Returns remote candidates.
    #[must_use]
    pub fn remote_candidates(&self) -> &[TrickleCandidate] {
        &self.remote_candidates
    }

    /// Returns true if local gathering is complete.
    #[must_use]
    pub fn is_local_complete(&self) -> bool {
        self.local_complete
    }

    /// Returns true if remote gathering is complete.
    #[must_use]
    pub fn is_remote_complete(&self) -> bool {
        self.remote_complete
    }

    /// Subscribes to new local candidates.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<TrickleCandidate> {
        self.candidate_tx.subscribe()
    }

    /// Creates an end-of-candidates indicator.
    #[must_use]
    pub fn end_of_candidates() -> TrickleCandidate {
        TrickleCandidate::new("")
    }
}

/// Manages trickle ICE for multiple sessions.
pub struct TrickleManager {
    /// Trickle handlers by session ID.
    handlers: Arc<RwLock<HashMap<String, TrickleIce>>>,
}

impl TrickleManager {
    /// Creates a new trickle manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a trickle handler for a session.
    pub async fn create(&self, session_id: impl Into<String>) -> TrickleIce {
        let session_id = session_id.into();
        let handler = TrickleIce::new(session_id.clone());

        let mut handlers = self.handlers.write().await;
        handlers.insert(session_id, handler.clone());

        handler
    }

    /// Gets the trickle handler for a session.
    pub async fn get(&self, session_id: &str) -> Option<TrickleIce> {
        let handlers = self.handlers.read().await;
        handlers.get(session_id).cloned()
    }

    /// Removes the trickle handler for a session.
    pub async fn remove(&self, session_id: &str) {
        let mut handlers = self.handlers.write().await;
        handlers.remove(session_id);
    }
}

impl Default for TrickleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TrickleIce {
    fn clone(&self) -> Self {
        let (candidate_tx, _) = broadcast::channel(64);
        Self {
            session_id: self.session_id.clone(),
            state: self.state,
            local_candidates: self.local_candidates.clone(),
            remote_candidates: self.remote_candidates.clone(),
            local_complete: self.local_complete,
            remote_complete: self.remote_complete,
            candidate_tx,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_trickle_candidate() {
        let candidate =
            TrickleCandidate::new("candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host")
                .with_m_line_index(0)
                .with_mid("audio");

        assert_eq!(candidate.sdp_m_line_index, Some(0));
        assert_eq!(candidate.sdp_mid.as_deref(), Some("audio"));
        assert!(!candidate.is_end_of_candidates());
    }

    #[test]
    fn test_end_of_candidates() {
        let eoc = TrickleCandidate::new("");
        assert!(eoc.is_end_of_candidates());

        let eoc2 = TrickleCandidate::new("end-of-candidates");
        assert!(eoc2.is_end_of_candidates());
    }

    #[test]
    fn test_parse_candidate() {
        let candidate =
            TrickleCandidate::parse("a=candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host")
                .unwrap();
        assert!(candidate.candidate.starts_with("candidate:"));
    }

    #[test]
    fn test_trickle_ice() {
        let mut trickle = TrickleIce::new("session-1");
        assert_eq!(trickle.state(), TrickleState::Idle);

        trickle.start_gathering();
        assert_eq!(trickle.state(), TrickleState::Gathering);

        trickle.add_local_candidate(TrickleCandidate::new(
            "candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host",
        ));
        assert_eq!(trickle.local_candidates().len(), 1);

        trickle.add_local_candidate(TrickleIce::end_of_candidates());
        assert!(trickle.is_local_complete());
    }

    #[tokio::test]
    async fn test_trickle_manager() {
        let manager = TrickleManager::new();

        let trickle = manager.create("session-1").await;
        assert_eq!(trickle.session_id(), "session-1");

        let retrieved = manager.get("session-1").await;
        assert!(retrieved.is_some());

        manager.remove("session-1").await;
        assert!(manager.get("session-1").await.is_none());
    }
}
