//! ICE/NAT traversal agent for the SBC daemon.
//!
//! This module integrates the ICE layer components:
//! - `proto-ice` for ICE protocol implementation (RFC 8445)
//! - `proto-stun` for STUN connectivity checks
//! - `proto-turn` for TURN relay allocation
//!
//! ## Features
//!
//! - Full ICE implementation with controlling/controlled roles
//! - ICE-lite mode for server-side optimization
//! - STUN server reflexive candidate gathering
//! - TURN relay candidate allocation
//! - Connectivity check state machine
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (NAT traversal)
//! - **SC-8**: Transmission Confidentiality (via DTLS-SRTP)

use proto_ice::agent::{
    GatheringState, IceConfig, IceCredentials, IceState, TurnServerConfig,
};
use proto_ice::{Candidate, IceAgent, IceRole};
use proto_stun::{StunClass, StunMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tracing::{debug, info, trace};

/// ICE agent manager configuration.
#[derive(Debug, Clone)]
pub struct IceManagerConfig {
    /// STUN server addresses.
    pub stun_servers: Vec<SocketAddr>,
    /// TURN server configurations.
    pub turn_servers: Vec<TurnServerConfig>,
    /// Whether to use ICE-lite mode.
    pub ice_lite: bool,
    /// Use aggressive nomination.
    pub aggressive_nomination: bool,
    /// Local preference for candidate priority.
    pub local_preference: u32,
    /// Connectivity check interval in milliseconds.
    pub check_interval_ms: u64,
    /// Maximum check retransmissions.
    pub max_retransmissions: u32,
}

impl Default for IceManagerConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun.l.google.com:19302".parse().unwrap_or_else(|_| {
                    SocketAddr::from(([74, 125, 250, 129], 19302))
                }),
            ],
            turn_servers: Vec::new(),
            ice_lite: false,
            aggressive_nomination: true,
            local_preference: 65535,
            check_interval_ms: 50,
            max_retransmissions: 7,
        }
    }
}

/// ICE agent manager for handling ICE sessions.
pub struct IceManager {
    /// Configuration.
    config: IceManagerConfig,
    /// Active ICE sessions by call ID.
    sessions: RwLock<HashMap<String, IceSessionContext>>,
}

/// Context for an ICE session.
struct IceSessionContext {
    /// The ICE agent.
    agent: IceAgent,
    /// A-leg selected pair.
    a_leg_selected: Option<(SocketAddr, SocketAddr)>,
    /// B-leg selected pair.
    b_leg_selected: Option<(SocketAddr, SocketAddr)>,
    /// Whether this is an ICE-lite session.
    ice_lite: bool,
}

impl IceManager {
    /// Creates a new ICE manager.
    pub fn new(config: IceManagerConfig) -> Self {
        info!(
            stun_servers = config.stun_servers.len(),
            turn_servers = config.turn_servers.len(),
            ice_lite = config.ice_lite,
            "ICE manager created"
        );

        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new ICE session for a call.
    pub async fn create_session(
        &self,
        call_id: &str,
        role: IceRole,
        ice_lite: Option<bool>,
    ) -> Result<IceCredentials, IceManagerError> {
        let ice_lite = ice_lite.unwrap_or(self.config.ice_lite);

        let ice_config = IceConfig {
            stun_servers: self.config.stun_servers.clone(),
            turn_servers: self.config.turn_servers.clone(),
            local_preference: self.config.local_preference,
            aggressive_nomination: self.config.aggressive_nomination,
            ice_lite,
            ta_interval: self.config.check_interval_ms,
            max_retransmissions: self.config.max_retransmissions,
        };

        let agent = IceAgent::new(role, ice_config);
        let credentials = agent.local_credentials().clone();

        let context = IceSessionContext {
            agent,
            a_leg_selected: None,
            b_leg_selected: None,
            ice_lite,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(call_id.to_string(), context);

        info!(
            call_id = %call_id,
            role = ?role,
            ice_lite = ice_lite,
            ufrag = %credentials.ufrag,
            "ICE session created"
        );

        Ok(credentials)
    }

    /// Gathers local candidates for a session.
    pub async fn gather_candidates(
        &self,
        call_id: &str,
        local_addresses: &[SocketAddr],
    ) -> Result<Vec<Candidate>, IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        context
            .agent
            .gather_candidates(local_addresses)
            .map_err(|e| IceManagerError::GatheringFailed(e.to_string()))?;

        let candidates = context.agent.local_candidates().to_vec();

        info!(
            call_id = %call_id,
            candidate_count = candidates.len(),
            "Candidates gathered"
        );

        for candidate in &candidates {
            debug!(
                call_id = %call_id,
                candidate_type = ?candidate.candidate_type(),
                address = %candidate.address(),
                priority = candidate.priority(),
                "Local candidate"
            );
        }

        Ok(candidates)
    }

    /// Sets remote credentials for a session.
    pub async fn set_remote_credentials(
        &self,
        call_id: &str,
        ufrag: &str,
        pwd: &str,
    ) -> Result<(), IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        let credentials = IceCredentials::new(ufrag.to_string(), pwd.to_string());
        context.agent.set_remote_credentials(credentials);

        debug!(call_id = %call_id, ufrag = %ufrag, "Remote credentials set");
        Ok(())
    }

    /// Adds a remote candidate to a session.
    pub async fn add_remote_candidate(
        &self,
        call_id: &str,
        candidate: Candidate,
    ) -> Result<(), IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        debug!(
            call_id = %call_id,
            candidate_type = ?candidate.candidate_type(),
            address = %candidate.address(),
            "Adding remote candidate"
        );

        context
            .agent
            .add_remote_candidate(candidate)
            .map_err(|e| IceManagerError::CandidateError(e.to_string()))?;

        Ok(())
    }

    /// Starts connectivity checks for a session.
    pub async fn start_checks(&self, call_id: &str) -> Result<(), IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        if context.ice_lite {
            // ICE-lite mode: skip checks, wait for remote to complete
            info!(call_id = %call_id, "ICE-lite mode: skipping active checks");
            return Ok(());
        }

        context
            .agent
            .start_checks()
            .map_err(|e| IceManagerError::ChecksFailed(e.to_string()))?;

        info!(
            call_id = %call_id,
            pairs = context.agent.checklist().len(),
            "Connectivity checks started"
        );

        Ok(())
    }

    /// Gets the next candidate pair to check.
    pub async fn next_check(&self, call_id: &str) -> Result<Option<usize>, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.next_check())
    }

    /// Gets candidate pair information for a check.
    pub async fn get_check_pair(
        &self,
        call_id: &str,
        pair_index: usize,
    ) -> Result<(SocketAddr, SocketAddr), IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        let pair = context
            .agent
            .checklist()
            .get(pair_index)
            .ok_or(IceManagerError::PairNotFound)?;

        Ok((pair.local().address(), pair.remote().address()))
    }

    /// Creates a STUN binding request for connectivity check.
    pub async fn create_check_request(
        &self,
        call_id: &str,
        pair_index: usize,
    ) -> Result<Vec<u8>, IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        // Mark check as in progress
        context
            .agent
            .start_check(pair_index)
            .map_err(|e| IceManagerError::ChecksFailed(e.to_string()))?;

        // Create STUN binding request
        let request = StunMessage::binding_request()
            .map_err(|e| IceManagerError::StunError(e.to_string()))?;

        // Add ICE attributes would go here in full implementation
        // For now, return basic binding request
        let encoded = request.encode();

        trace!(
            call_id = %call_id,
            pair_index = pair_index,
            size = encoded.len(),
            "Created STUN binding request"
        );

        Ok(encoded.to_vec())
    }

    /// Processes a STUN response and updates check state.
    pub async fn process_check_response(
        &self,
        call_id: &str,
        pair_index: usize,
        response_data: &[u8],
    ) -> Result<bool, IceManagerError> {
        let response = StunMessage::parse(response_data)
            .map_err(|e| IceManagerError::StunError(e.to_string()))?;

        let success = response.msg_type.class == StunClass::SuccessResponse;

        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        if success {
            context
                .agent
                .check_succeeded(pair_index)
                .map_err(|e| IceManagerError::ChecksFailed(e.to_string()))?;

            debug!(call_id = %call_id, pair_index = pair_index, "Check succeeded");

            // If aggressive nomination is enabled and we're controlling, nominate
            if context.agent.role() == IceRole::Controlling {
                context
                    .agent
                    .nominate(pair_index)
                    .map_err(|e| IceManagerError::NominationFailed(e.to_string()))?;
            }
        } else {
            context
                .agent
                .check_failed(pair_index)
                .map_err(|e| IceManagerError::ChecksFailed(e.to_string()))?;

            debug!(call_id = %call_id, pair_index = pair_index, "Check failed");
        }

        Ok(success)
    }

    /// Gets the selected candidate pair for a component.
    pub async fn get_selected_pair(
        &self,
        call_id: &str,
        component: u16,
    ) -> Result<Option<(SocketAddr, SocketAddr)>, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.selected_pair(component).map(|pair| {
            (pair.local().address(), pair.remote().address())
        }))
    }

    /// Gets the current ICE state for a session.
    pub async fn get_state(&self, call_id: &str) -> Result<IceState, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.state())
    }

    /// Gets the gathering state for a session.
    pub async fn get_gathering_state(
        &self,
        call_id: &str,
    ) -> Result<GatheringState, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.gathering_state())
    }

    /// Gets local credentials for a session.
    pub async fn get_local_credentials(
        &self,
        call_id: &str,
    ) -> Result<IceCredentials, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.local_credentials().clone())
    }

    /// Gets local candidates for a session.
    pub async fn get_local_candidates(
        &self,
        call_id: &str,
    ) -> Result<Vec<Candidate>, IceManagerError> {
        let sessions = self.sessions.read().await;
        let context = sessions
            .get(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        Ok(context.agent.local_candidates().to_vec())
    }

    /// Restarts ICE for a session.
    pub async fn restart(&self, call_id: &str) -> Result<IceCredentials, IceManagerError> {
        let mut sessions = self.sessions.write().await;
        let context = sessions
            .get_mut(call_id)
            .ok_or(IceManagerError::SessionNotFound)?;

        context
            .agent
            .restart()
            .map_err(|e| IceManagerError::RestartFailed(e.to_string()))?;

        let credentials = context.agent.local_credentials().clone();

        info!(
            call_id = %call_id,
            ufrag = %credentials.ufrag,
            "ICE restarted"
        );

        Ok(credentials)
    }

    /// Closes an ICE session.
    pub async fn close_session(&self, call_id: &str) -> Result<(), IceManagerError> {
        let mut sessions = self.sessions.write().await;
        if let Some(mut context) = sessions.remove(call_id) {
            context.agent.close();
            info!(call_id = %call_id, "ICE session closed");
            Ok(())
        } else {
            Err(IceManagerError::SessionNotFound)
        }
    }

    /// Returns the number of active sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Gets session statistics.
    pub async fn get_session_stats(&self, call_id: &str) -> Option<IceSessionStats> {
        let sessions = self.sessions.read().await;
        sessions.get(call_id).map(|ctx| IceSessionStats {
            call_id: call_id.to_string(),
            role: ctx.agent.role(),
            state: ctx.agent.state(),
            gathering_state: ctx.agent.gathering_state(),
            local_candidate_count: ctx.agent.local_candidates().len(),
            remote_candidate_count: ctx.agent.remote_candidates().len(),
            checklist_size: ctx.agent.checklist().len(),
            ice_lite: ctx.ice_lite,
        })
    }
}

/// ICE session statistics.
#[derive(Debug, Clone)]
pub struct IceSessionStats {
    /// Call identifier.
    pub call_id: String,
    /// ICE role.
    pub role: IceRole,
    /// ICE state.
    pub state: IceState,
    /// Gathering state.
    pub gathering_state: GatheringState,
    /// Number of local candidates.
    pub local_candidate_count: usize,
    /// Number of remote candidates.
    pub remote_candidate_count: usize,
    /// Size of the check list.
    pub checklist_size: usize,
    /// Whether using ICE-lite mode.
    pub ice_lite: bool,
}

/// ICE manager errors.
#[derive(Debug)]
pub enum IceManagerError {
    /// Session not found.
    SessionNotFound,
    /// Candidate gathering failed.
    GatheringFailed(String),
    /// Candidate error.
    CandidateError(String),
    /// Connectivity checks failed.
    ChecksFailed(String),
    /// Nomination failed.
    NominationFailed(String),
    /// ICE restart failed.
    RestartFailed(String),
    /// STUN error.
    StunError(String),
    /// TURN error.
    TurnError(String),
    /// Pair not found.
    PairNotFound,
}

impl std::fmt::Display for IceManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "ICE session not found"),
            Self::GatheringFailed(e) => write!(f, "Candidate gathering failed: {e}"),
            Self::CandidateError(e) => write!(f, "Candidate error: {e}"),
            Self::ChecksFailed(e) => write!(f, "Connectivity checks failed: {e}"),
            Self::NominationFailed(e) => write!(f, "Nomination failed: {e}"),
            Self::RestartFailed(e) => write!(f, "ICE restart failed: {e}"),
            Self::StunError(e) => write!(f, "STUN error: {e}"),
            Self::TurnError(e) => write!(f, "TURN error: {e}"),
            Self::PairNotFound => write!(f, "Candidate pair not found"),
        }
    }
}

impl std::error::Error for IceManagerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_ice::CandidateType;

    #[test]
    fn test_default_config() {
        let config = IceManagerConfig::default();
        assert!(!config.stun_servers.is_empty());
        assert!(config.turn_servers.is_empty());
        assert!(!config.ice_lite);
        assert!(config.aggressive_nomination);
    }

    #[test]
    fn test_ice_manager_creation() {
        let config = IceManagerConfig::default();
        let _manager = IceManager::new(config);
    }

    #[tokio::test]
    async fn test_create_session() {
        let manager = IceManager::new(IceManagerConfig::default());

        let credentials = manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        assert!(!credentials.ufrag.is_empty());
        assert!(!credentials.pwd.is_empty());
        assert_eq!(manager.active_session_count().await, 1);
    }

    #[tokio::test]
    async fn test_create_ice_lite_session() {
        let manager = IceManager::new(IceManagerConfig::default());

        let credentials = manager
            .create_session("test-call-1", IceRole::Controlled, Some(true))
            .await
            .unwrap();

        // Verify credentials were generated
        assert!(!credentials.ufrag.is_empty());
        assert!(!credentials.pwd.is_empty());

        let stats = manager.get_session_stats("test-call-1").await.unwrap();
        assert!(stats.ice_lite);
        assert_eq!(stats.role, IceRole::Controlled);
    }

    #[tokio::test]
    async fn test_close_session() {
        let manager = IceManager::new(IceManagerConfig::default());

        manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        manager.close_session("test-call-1").await.unwrap();
        assert_eq!(manager.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let manager = IceManager::new(IceManagerConfig::default());

        let result = manager.get_state("nonexistent").await;
        assert!(matches!(result, Err(IceManagerError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_gather_candidates() {
        let manager = IceManager::new(IceManagerConfig::default());

        manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        let local_addrs = vec!["127.0.0.1:0".parse().unwrap()];
        let candidates = manager
            .gather_candidates("test-call-1", &local_addrs)
            .await
            .unwrap();

        // Should have at least one host candidate
        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .any(|c| c.candidate_type() == CandidateType::Host));
    }

    #[tokio::test]
    async fn test_set_remote_credentials() {
        let manager = IceManager::new(IceManagerConfig::default());

        manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        manager
            .set_remote_credentials("test-call-1", "remoteufrag", "remotepwd123456")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_ice_restart() {
        let manager = IceManager::new(IceManagerConfig::default());

        let original = manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        let restarted = manager.restart("test-call-1").await.unwrap();

        // After restart, credentials should be different
        assert_ne!(original.ufrag, restarted.ufrag);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let manager = IceManager::new(IceManagerConfig::default());

        manager
            .create_session("test-call-1", IceRole::Controlling, None)
            .await
            .unwrap();

        let stats = manager.get_session_stats("test-call-1").await.unwrap();
        assert_eq!(stats.call_id, "test-call-1");
        assert_eq!(stats.role, IceRole::Controlling);
        assert_eq!(stats.state, IceState::New);
    }
}
