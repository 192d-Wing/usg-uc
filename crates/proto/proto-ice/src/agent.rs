//! ICE agent for managing connectivity establishment.

use crate::candidate::{Candidate, CandidateType};
use crate::checklist::{CheckList, CheckListState, PairState};
use crate::error::{IceError, IceResult};
use proto_stun::StunClient;
use proto_turn::{TurnClient, TurnCredentials};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// ICE agent role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (typically the offerer).
    Controlling,
    /// Controlled agent (typically the answerer).
    Controlled,
}

impl std::fmt::Display for IceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Controlling => write!(f, "controlling"),
            Self::Controlled => write!(f, "controlled"),
        }
    }
}

/// ICE agent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Initial state, not started.
    New,
    /// Gathering candidates.
    Gathering,
    /// Checking connectivity.
    Checking,
    /// Connected (at least one pair succeeded).
    Connected,
    /// Completed (all components have selected pairs).
    Completed,
    /// Failed (all pairs failed).
    Failed,
    /// Closed.
    Closed,
}

impl std::fmt::Display for IceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Gathering => write!(f, "gathering"),
            Self::Checking => write!(f, "checking"),
            Self::Connected => write!(f, "connected"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// ICE gathering state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringState {
    /// Not started.
    New,
    /// Gathering in progress.
    Gathering,
    /// Gathering complete.
    Complete,
}

impl std::fmt::Display for GatheringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Gathering => write!(f, "gathering"),
            Self::Complete => write!(f, "complete"),
        }
    }
}

/// ICE agent configuration.
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN server addresses.
    pub stun_servers: Vec<SocketAddr>,
    /// TURN server addresses.
    pub turn_servers: Vec<TurnServerConfig>,
    /// Local preference for candidates.
    pub local_preference: u32,
    /// Enable aggressive nomination.
    pub aggressive_nomination: bool,
    /// ICE-lite mode (only host candidates).
    pub ice_lite: bool,
    /// Connectivity check interval in milliseconds.
    pub ta_interval: u64,
    /// Maximum check retransmissions.
    pub max_retransmissions: u32,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            local_preference: 65535,
            aggressive_nomination: false,
            ice_lite: false,
            ta_interval: 50,
            max_retransmissions: 7,
        }
    }
}

/// TURN server configuration.
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// Server address.
    pub address: SocketAddr,
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Realm.
    pub realm: String,
}

/// ICE credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    /// Username fragment.
    pub ufrag: String,
    /// Password.
    pub pwd: String,
}

impl IceCredentials {
    /// Creates new credentials with random values.
    pub fn generate() -> Self {
        // Generate random ufrag (4-256 chars) and pwd (22-256 chars)
        // Using simple random for now
        let ufrag = Self::random_string(8);
        let pwd = Self::random_string(24);

        Self { ufrag, pwd }
    }

    /// Creates credentials with specified values.
    pub fn new(ufrag: String, pwd: String) -> Self {
        Self { ufrag, pwd }
    }

    fn random_string(len: usize) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0) as u64;

        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();

        let mut result = String::with_capacity(len);
        let mut state = seed;

        for _ in 0..len {
            // Simple LCG
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            let idx = (state >> 16) as usize % chars.len();
            result.push(chars[idx]);
        }

        result
    }
}

/// ICE agent.
#[derive(Debug)]
pub struct IceAgent {
    /// Agent role.
    role: IceRole,
    /// Agent state.
    state: IceState,
    /// Gathering state.
    gathering_state: GatheringState,
    /// Configuration.
    config: IceConfig,
    /// Local credentials.
    local_credentials: IceCredentials,
    /// Remote credentials.
    remote_credentials: Option<IceCredentials>,
    /// Local candidates.
    local_candidates: Vec<Candidate>,
    /// Remote candidates.
    remote_candidates: Vec<Candidate>,
    /// Check list.
    checklist: CheckList,
    /// Tie-breaker for role conflicts.
    tie_breaker: u64,
}

impl IceAgent {
    /// Creates a new ICE agent.
    pub fn new(role: IceRole, config: IceConfig) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let tie_breaker = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            role,
            state: IceState::New,
            gathering_state: GatheringState::New,
            config,
            local_credentials: IceCredentials::generate(),
            remote_credentials: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            checklist: CheckList::new(),
            tie_breaker,
        }
    }

    /// Creates a new controlling agent.
    pub fn controlling(config: IceConfig) -> Self {
        Self::new(IceRole::Controlling, config)
    }

    /// Creates a new controlled agent.
    pub fn controlled(config: IceConfig) -> Self {
        Self::new(IceRole::Controlled, config)
    }

    /// Returns the agent role.
    pub fn role(&self) -> IceRole {
        self.role
    }

    /// Sets the agent role.
    pub fn set_role(&mut self, role: IceRole) {
        if self.role != role {
            self.role = role;
            // Recompute pair priorities
            for pair in self.checklist.pairs_mut() {
                pair.recompute_priority(role);
            }
        }
    }

    /// Returns the agent state.
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Returns the gathering state.
    pub fn gathering_state(&self) -> GatheringState {
        self.gathering_state
    }

    /// Returns the local credentials.
    pub fn local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Returns the remote credentials.
    pub fn remote_credentials(&self) -> Option<&IceCredentials> {
        self.remote_credentials.as_ref()
    }

    /// Sets remote credentials.
    pub fn set_remote_credentials(&mut self, credentials: IceCredentials) {
        self.remote_credentials = Some(credentials);
    }

    /// Returns local candidates.
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    /// Returns remote candidates.
    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    /// Returns the check list.
    pub fn checklist(&self) -> &CheckList {
        &self.checklist
    }

    /// Returns the tie-breaker value.
    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    /// Adds a local candidate.
    pub fn add_local_candidate(&mut self, candidate: Candidate) {
        self.local_candidates.push(candidate);
    }

    /// Adds a remote candidate.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn add_remote_candidate(&mut self, candidate: &Candidate) -> IceResult<()> {
        // Add to remote candidates
        self.remote_candidates.push(candidate.clone());

        // Form pairs with existing local candidates
        for local in &self.local_candidates {
            if Self::can_pair(local, candidate) {
                let pair = crate::checklist::CandidatePair::new(
                    local.clone(),
                    candidate.clone(),
                    self.role,
                );
                self.checklist.add_pair(pair);
            }
        }

        Ok(())
    }

    /// Starts candidate gathering.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn gather_candidates(&mut self, local_addresses: &[SocketAddr]) -> IceResult<()> {
        if self.state != IceState::New {
            return Err(IceError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "gathering".to_string(),
            });
        }

        self.state = IceState::Gathering;
        self.gathering_state = GatheringState::Gathering;

        // Gather host candidates
        for (i, addr) in local_addresses.iter().enumerate() {
            // RTP candidate
            let mut rtp_candidate = Candidate::host(*addr, 1);
            // Adjust priority based on interface preference
            let priority = Candidate::compute_priority(
                crate::candidate::CandidateType::Host,
                1,
                (self.config.local_preference as usize - i) as u32,
            );
            rtp_candidate = Candidate::new(
                rtp_candidate.foundation().to_string(),
                1,
                rtp_candidate.transport(),
                priority,
                *addr,
                rtp_candidate.candidate_type(),
            );
            self.local_candidates.push(rtp_candidate);
        }

        self.gathering_state = GatheringState::Complete;

        Ok(())
    }

    /// Gathers server-reflexive and relay candidates asynchronously.
    ///
    /// This method should be called after `gather_candidates()` to add
    /// srflx and relay candidates using configured STUN/TURN servers.
    ///
    /// ## RFC 8445 Candidate Gathering
    ///
    /// - Server-reflexive (srflx): Discovered via STUN Binding requests
    /// - Relay: Allocated via TURN Allocate requests
    ///
    /// ## Example
    ///
    /// ```ignore
    /// agent.gather_candidates(&local_addrs)?;
    /// agent.gather_async_candidates().await?;
    /// ```
    pub async fn gather_async_candidates(&mut self) -> IceResult<()> {
        // Gather server-reflexive candidates from STUN servers
        for stun_server in &self.config.stun_servers.clone() {
            if let Err(e) = self.gather_srflx_from_server(*stun_server).await {
                warn!(server = %stun_server, error = %e, "Failed to gather srflx candidate");
            }
        }

        // Gather relay candidates from TURN servers
        for turn_config in &self.config.turn_servers.clone() {
            if let Err(e) = self.gather_relay_from_server(turn_config.clone()).await {
                warn!(server = %turn_config.address, error = %e, "Failed to gather relay candidate");
            }
        }

        Ok(())
    }

    /// Gathers a server-reflexive candidate from a STUN server.
    async fn gather_srflx_from_server(&mut self, stun_server: SocketAddr) -> IceResult<()> {
        // Find a host candidate to use as the base
        let host_candidate = self
            .local_candidates
            .iter()
            .find(|c| c.candidate_type() == CandidateType::Host)
            .ok_or(IceError::NoCandidates)?
            .clone();

        let base_addr = host_candidate.address();

        // Create UDP socket bound to an ephemeral port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| IceError::NetworkError {
                reason: format!("failed to bind socket: {e}"),
            })?;

        let local_addr = socket.local_addr().map_err(|e| IceError::NetworkError {
            reason: format!("failed to get local addr: {e}"),
        })?;

        debug!(
            stun_server = %stun_server,
            local_addr = %local_addr,
            "Discovering server-reflexive address"
        );

        // Create STUN client and discover srflx address
        let client = StunClient::new(Arc::new(socket), stun_server);
        let srflx_addr = client
            .discover_srflx()
            .await
            .map_err(|e| IceError::NetworkError {
                reason: format!("STUN discovery failed: {e}"),
            })?;

        debug!(
            srflx_addr = %srflx_addr,
            base_addr = %base_addr,
            "Discovered server-reflexive address"
        );

        // Create srflx candidate
        let component = host_candidate.component();
        let srflx_candidate = Candidate::server_reflexive(srflx_addr, base_addr, component);

        // Add to local candidates
        self.local_candidates.push(srflx_candidate);

        Ok(())
    }

    /// Gathers a relay candidate from a TURN server.
    async fn gather_relay_from_server(&mut self, turn_config: TurnServerConfig) -> IceResult<()> {
        // Find a host candidate to use as the base
        let host_candidate = self
            .local_candidates
            .iter()
            .find(|c| c.candidate_type() == CandidateType::Host)
            .ok_or(IceError::NoCandidates)?
            .clone();

        let base_addr = host_candidate.address();

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| IceError::NetworkError {
                reason: format!("failed to bind socket: {e}"),
            })?;

        debug!(
            turn_server = %turn_config.address,
            "Allocating relay address"
        );

        // Create TURN credentials
        let credentials = TurnCredentials::new(&turn_config.username, &turn_config.password)
            .with_realm(&turn_config.realm);

        // Create TURN client and allocate relay address
        let client = TurnClient::new(Arc::new(socket), turn_config.address, credentials);
        let relay_addr = client
            .allocate()
            .await
            .map_err(|e| IceError::NetworkError {
                reason: format!("TURN allocation failed: {e}"),
            })?;

        debug!(
            relay_addr = %relay_addr,
            base_addr = %base_addr,
            "Allocated relay address"
        );

        // Create relay candidate
        let component = host_candidate.component();
        let relay_candidate = Candidate::relay(relay_addr, base_addr, component);

        // Add to local candidates
        self.local_candidates.push(relay_candidate);

        Ok(())
    }

    /// Starts connectivity checks.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start_checks(&mut self) -> IceResult<()> {
        if self.local_candidates.is_empty() {
            return Err(IceError::NoCandidates);
        }

        if self.remote_candidates.is_empty() {
            return Err(IceError::NoCandidates);
        }

        // Form the check list
        self.checklist =
            CheckList::form_pairs(&self.local_candidates, &self.remote_candidates, self.role);

        if self.checklist.is_empty() {
            return Err(IceError::NoCandidates);
        }

        self.state = IceState::Checking;

        Ok(())
    }

    /// Gets the next pair to check.
    pub fn next_check(&self) -> Option<usize> {
        self.checklist.next_pair_to_check()
    }

    /// Marks a connectivity check as started.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start_check(&mut self, pair_index: usize) -> IceResult<()> {
        let pair = self
            .checklist
            .get_mut(pair_index)
            .ok_or_else(|| IceError::InvalidCandidate {
                reason: "invalid pair index".to_string(),
            })?;

        pair.set_state(PairState::InProgress);
        pair.increment_check_attempts();

        Ok(())
    }

    /// Handles a successful connectivity check.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn check_succeeded(&mut self, pair_index: usize) -> IceResult<()> {
        self.checklist.mark_succeeded(pair_index)?;

        // Update state to Connected if this is first success
        if self.state == IceState::Checking {
            self.state = IceState::Connected;
        }

        // Check if we should select this pair
        let pair = self
            .checklist
            .get(pair_index)
            .ok_or_else(|| IceError::InvalidCandidate {
                reason: "invalid pair index".to_string(),
            })?;
        let component = pair.local().component();

        // If no pair selected for this component, select this one
        if self.checklist.selected_pair(component).is_none() {
            self.checklist.select_pair(component, pair_index)?;
        }

        // Check if all components are complete
        self.update_completion_state();

        Ok(())
    }

    /// Handles a failed connectivity check.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn check_failed(&mut self, pair_index: usize) -> IceResult<()> {
        self.checklist.mark_failed(pair_index)?;

        // Check if all pairs have failed
        if self.checklist.all_failed() {
            self.state = IceState::Failed;
            self.checklist.set_state(CheckListState::Failed);
        }

        Ok(())
    }

    /// Nominates a candidate pair (controlling agent only).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn nominate(&mut self, pair_index: usize) -> IceResult<()> {
        if self.role != IceRole::Controlling {
            return Err(IceError::InvalidStateTransition {
                from: "controlled".to_string(),
                to: "nominating".to_string(),
            });
        }

        let pair = self
            .checklist
            .get_mut(pair_index)
            .ok_or_else(|| IceError::InvalidCandidate {
                reason: "invalid pair index".to_string(),
            })?;

        if pair.state() != PairState::Succeeded {
            return Err(IceError::InvalidStateTransition {
                from: pair.state().to_string(),
                to: "nominated".to_string(),
            });
        }

        pair.nominate();

        Ok(())
    }

    /// Gets the selected pair for a component.
    pub fn selected_pair(&self, component: u16) -> Option<&crate::checklist::CandidatePair> {
        self.checklist.selected_pair(component)
    }

    /// Returns whether aggressive nomination is enabled.
    ///
    /// Per RFC 8445 §7.2.2, with aggressive nomination the controlling agent
    /// includes the USE-CANDIDATE attribute in every connectivity check.
    pub fn aggressive_nomination(&self) -> bool {
        self.config.aggressive_nomination
    }

    /// Returns the configuration.
    pub fn config(&self) -> &IceConfig {
        &self.config
    }

    /// Returns whether this check should include nomination (USE-CANDIDATE).
    ///
    /// ## RFC 8445 §7.2.2 Aggressive Nomination
    ///
    /// With aggressive nomination, the controlling agent includes the
    /// USE-CANDIDATE attribute in every check it sends. This is faster
    /// but may result in suboptimal pair selection.
    ///
    /// With regular nomination, the controlling agent first performs
    /// checks without USE-CANDIDATE, then sends a separate check with
    /// USE-CANDIDATE for the selected pair.
    ///
    /// ## Returns
    ///
    /// `true` if nomination should be included, `false` otherwise.
    /// For controlled agents, always returns `false` since only the
    /// controlling agent can nominate pairs.
    pub fn should_nominate_check(&self) -> bool {
        // Only the controlling agent can nominate
        if self.role != IceRole::Controlling {
            return false;
        }

        // With aggressive nomination, every check includes USE-CANDIDATE
        self.config.aggressive_nomination
    }

    /// Creates a connectivity check for a candidate pair.
    ///
    /// This is a convenience method that properly configures nomination
    /// based on the agent's role and nomination strategy.
    ///
    /// ## RFC 8445 §7.2.2 Aggressive Nomination
    ///
    /// When aggressive nomination is enabled for a controlling agent,
    /// the USE-CANDIDATE attribute is automatically included in the check.
    pub fn create_connectivity_check(
        &self,
        local: &Candidate,
        remote: &Candidate,
    ) -> Option<crate::connectivity::ConnectivityCheck> {
        let remote_credentials = self.remote_credentials.as_ref()?;

        let check = crate::connectivity::ConnectivityCheck::new(
            local.clone(),
            remote.clone(),
            self.local_credentials.clone(),
            remote_credentials.clone(),
            self.role,
            self.tie_breaker,
        );

        // Apply aggressive nomination if enabled and we're controlling
        Some(check.with_nomination(self.should_nominate_check()))
    }

    /// Creates a connectivity check with explicit nomination control.
    ///
    /// Use this method when you need to override the automatic nomination
    /// behavior, such as when performing regular nomination for a specific
    /// pair after initial checks.
    pub fn create_connectivity_check_with_nomination(
        &self,
        local: &Candidate,
        remote: &Candidate,
        nominate: bool,
    ) -> Option<crate::connectivity::ConnectivityCheck> {
        let remote_credentials = self.remote_credentials.as_ref()?;

        // Only controlling agent can actually nominate
        let effective_nominate = nominate && self.role == IceRole::Controlling;

        let check = crate::connectivity::ConnectivityCheck::new(
            local.clone(),
            remote.clone(),
            self.local_credentials.clone(),
            remote_credentials.clone(),
            self.role,
            self.tie_breaker,
        );

        Some(check.with_nomination(effective_nominate))
    }

    /// Handles an ICE restart.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn restart(&mut self) -> IceResult<()> {
        // Generate new credentials
        self.local_credentials = IceCredentials::generate();
        self.remote_credentials = None;

        // Clear candidates and checklist
        self.local_candidates.clear();
        self.remote_candidates.clear();
        self.checklist = CheckList::new();

        // Reset states
        self.state = IceState::New;
        self.gathering_state = GatheringState::New;

        Ok(())
    }

    /// Closes the agent.
    pub fn close(&mut self) {
        self.state = IceState::Closed;
    }

    /// Checks if two candidates can be paired.
    fn can_pair(local: &Candidate, remote: &Candidate) -> bool {
        // Same component
        if local.component() != remote.component() {
            return false;
        }

        // Same transport
        if local.transport() != remote.transport() {
            return false;
        }

        // Same address family
        if local.address().is_ipv4() != remote.address().is_ipv4() {
            return false;
        }

        true
    }

    /// Updates completion state based on check list.
    fn update_completion_state(&mut self) {
        if self.checklist.is_complete() {
            self.state = IceState::Completed;
            self.checklist.set_state(CheckListState::Completed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_ice_role_display() {
        assert_eq!(IceRole::Controlling.to_string(), "controlling");
        assert_eq!(IceRole::Controlled.to_string(), "controlled");
    }

    #[test]
    fn test_ice_state_display() {
        assert_eq!(IceState::New.to_string(), "new");
        assert_eq!(IceState::Checking.to_string(), "checking");
        assert_eq!(IceState::Completed.to_string(), "completed");
    }

    #[test]
    fn test_credentials_generation() {
        let creds = IceCredentials::generate();

        assert!(!creds.ufrag.is_empty());
        assert!(!creds.pwd.is_empty());
        assert!(creds.ufrag.len() >= 4);
        assert!(creds.pwd.len() >= 22);
    }

    #[test]
    fn test_agent_creation() {
        let config = IceConfig::default();
        let agent = IceAgent::controlling(config);

        assert_eq!(agent.role(), IceRole::Controlling);
        assert_eq!(agent.state(), IceState::New);
        assert_eq!(agent.gathering_state(), GatheringState::New);
    }

    #[test]
    fn test_gather_candidates() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        let local_addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            5060,
        )];

        agent.gather_candidates(&local_addrs).unwrap();

        assert_eq!(agent.gathering_state(), GatheringState::Complete);
        assert!(!agent.local_candidates().is_empty());
    }

    #[test]
    fn test_add_remote_candidate() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );
        agent.add_remote_candidate(remote).unwrap();

        assert!(!agent.remote_candidates().is_empty());
    }

    #[test]
    fn test_start_checks() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );
        agent.add_remote_candidate(remote).unwrap();

        agent.set_remote_credentials(IceCredentials::generate());
        agent.start_checks().unwrap();

        assert_eq!(agent.state(), IceState::Checking);
        assert!(!agent.checklist().is_empty());
    }

    #[test]
    fn test_role_change() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        agent.set_role(IceRole::Controlled);
        assert_eq!(agent.role(), IceRole::Controlled);
    }

    #[test]
    fn test_restart() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        let old_creds = agent.local_credentials().clone();

        agent.restart().unwrap();

        assert_eq!(agent.state(), IceState::New);
        assert!(agent.local_candidates().is_empty());
        assert_ne!(agent.local_credentials(), &old_creds);
    }

    #[test]
    fn test_close() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlling(config);

        agent.close();
        assert_eq!(agent.state(), IceState::Closed);
    }

    #[test]
    fn test_aggressive_nomination_disabled_by_default() {
        let config = IceConfig::default();
        let agent = IceAgent::controlling(config);

        assert!(!agent.aggressive_nomination());
        // Controlling agent without aggressive nomination should not nominate
        assert!(!agent.should_nominate_check());
    }

    #[test]
    fn test_aggressive_nomination_enabled() {
        let config = IceConfig {
            aggressive_nomination: true,
            ..Default::default()
        };
        let agent = IceAgent::controlling(config);

        assert!(agent.aggressive_nomination());
        // Controlling agent with aggressive nomination should nominate every check
        assert!(agent.should_nominate_check());
    }

    #[test]
    fn test_controlled_agent_never_nominates() {
        // Even with aggressive nomination enabled, controlled agent cannot nominate
        let config = IceConfig {
            aggressive_nomination: true,
            ..Default::default()
        };
        let agent = IceAgent::controlled(config);

        assert!(agent.aggressive_nomination()); // Config is set
        assert!(!agent.should_nominate_check()); // But controlled agent can't nominate
    }

    #[test]
    fn test_create_connectivity_check_with_aggressive_nomination() {
        let config = IceConfig {
            aggressive_nomination: true,
            ..Default::default()
        };
        let mut agent = IceAgent::controlling(config);

        // Gather local candidates
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        // Set remote credentials (required for check creation)
        agent.set_remote_credentials(IceCredentials::generate());

        // Create a remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );

        let local = &agent.local_candidates()[0];
        let check = agent.create_connectivity_check(local, &remote).unwrap();

        // The check should have nomination enabled due to aggressive nomination
        let request = check.create_request().unwrap();
        let has_use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, proto_stun::StunAttribute::UseCandidate));
        assert!(
            has_use_candidate,
            "Aggressive nomination should set USE-CANDIDATE"
        );
    }

    #[test]
    fn test_create_connectivity_check_without_aggressive_nomination() {
        let config = IceConfig::default(); // aggressive_nomination = false
        let mut agent = IceAgent::controlling(config);

        // Gather local candidates
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        // Set remote credentials
        agent.set_remote_credentials(IceCredentials::generate());

        // Create a remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );

        let local = &agent.local_candidates()[0];
        let check = agent.create_connectivity_check(local, &remote).unwrap();

        // The check should NOT have nomination (regular nomination mode)
        let request = check.create_request().unwrap();
        let has_use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, proto_stun::StunAttribute::UseCandidate));
        assert!(
            !has_use_candidate,
            "Regular nomination should not set USE-CANDIDATE initially"
        );
    }

    #[test]
    fn test_create_connectivity_check_with_explicit_nomination() {
        let config = IceConfig::default(); // aggressive_nomination = false
        let mut agent = IceAgent::controlling(config);

        // Gather local candidates
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        // Set remote credentials
        agent.set_remote_credentials(IceCredentials::generate());

        // Create a remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );

        let local = &agent.local_candidates()[0];

        // Explicitly request nomination (for regular nomination after check succeeds)
        let check = agent
            .create_connectivity_check_with_nomination(local, &remote, true)
            .unwrap();

        let request = check.create_request().unwrap();
        let has_use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, proto_stun::StunAttribute::UseCandidate));
        assert!(
            has_use_candidate,
            "Explicit nomination should set USE-CANDIDATE"
        );
    }

    #[test]
    fn test_controlled_cannot_nominate_even_with_explicit_request() {
        let config = IceConfig::default();
        let mut agent = IceAgent::controlled(config);

        // Gather local candidates
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        agent.gather_candidates(&[local_addr]).unwrap();

        // Set remote credentials
        agent.set_remote_credentials(IceCredentials::generate());

        // Create a remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            1,
        );

        let local = &agent.local_candidates()[0];

        // Try to explicitly request nomination as controlled agent
        let check = agent
            .create_connectivity_check_with_nomination(local, &remote, true)
            .unwrap();

        let request = check.create_request().unwrap();
        let has_use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, proto_stun::StunAttribute::UseCandidate));
        assert!(!has_use_candidate, "Controlled agent cannot nominate");
    }
}
