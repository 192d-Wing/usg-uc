//! ICE check list and candidate pair management.

use crate::IceRole;
use crate::candidate::Candidate;
use crate::error::{IceError, IceResult};
use std::collections::HashMap;

/// State of a candidate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Pair is waiting to be checked.
    Waiting,
    /// Check is in progress.
    InProgress,
    /// Check succeeded.
    Succeeded,
    /// Check failed.
    Failed,
    /// Pair is frozen (waiting for another pair to complete).
    Frozen,
}

impl std::fmt::Display for PairState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waiting => write!(f, "Waiting"),
            Self::InProgress => write!(f, "In-Progress"),
            Self::Succeeded => write!(f, "Succeeded"),
            Self::Failed => write!(f, "Failed"),
            Self::Frozen => write!(f, "Frozen"),
        }
    }
}

/// A candidate pair for connectivity checking.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate.
    local: Candidate,
    /// Remote candidate.
    remote: Candidate,
    /// Pair priority.
    priority: u64,
    /// Current state.
    state: PairState,
    /// Whether this is the nominated pair.
    nominated: bool,
    /// Number of check attempts.
    check_attempts: u32,
    /// Foundation string (local foundation + remote foundation).
    foundation: String,
}

impl CandidatePair {
    /// Creates a new candidate pair.
    pub fn new(local: Candidate, remote: Candidate, role: IceRole) -> Self {
        let priority = Self::compute_priority(&local, &remote, role);
        let foundation = format!("{}:{}", local.foundation(), remote.foundation());

        Self {
            local,
            remote,
            priority,
            state: PairState::Frozen,
            nominated: false,
            check_attempts: 0,
            foundation,
        }
    }

    /// Returns the local candidate.
    pub fn local(&self) -> &Candidate {
        &self.local
    }

    /// Returns the remote candidate.
    pub fn remote(&self) -> &Candidate {
        &self.remote
    }

    /// Returns the pair priority.
    pub fn priority(&self) -> u64 {
        self.priority
    }

    /// Returns the current state.
    pub fn state(&self) -> PairState {
        self.state
    }

    /// Sets the state.
    pub fn set_state(&mut self, state: PairState) {
        self.state = state;
    }

    /// Returns whether this pair is nominated.
    pub fn is_nominated(&self) -> bool {
        self.nominated
    }

    /// Nominates this pair.
    pub fn nominate(&mut self) {
        self.nominated = true;
    }

    /// Returns the foundation.
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// Returns the check attempt count.
    pub fn check_attempts(&self) -> u32 {
        self.check_attempts
    }

    /// Increments the check attempt count.
    pub fn increment_check_attempts(&mut self) {
        self.check_attempts += 1;
    }

    /// Computes pair priority per RFC 8445 Section 6.1.2.3.
    ///
    /// pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    ///
    /// Where G is controlling agent's candidate priority and D is controlled.
    fn compute_priority(local: &Candidate, remote: &Candidate, role: IceRole) -> u64 {
        let (g, d) = match role {
            IceRole::Controlling => (local.priority() as u64, remote.priority() as u64),
            IceRole::Controlled => (remote.priority() as u64, local.priority() as u64),
        };

        let min = g.min(d);
        let max = g.max(d);
        let tie_breaker = if g > d { 1u64 } else { 0u64 };

        (min << 32) + (max << 1) + tie_breaker
    }

    /// Recomputes priority (e.g., after role change).
    pub fn recompute_priority(&mut self, role: IceRole) {
        self.priority = Self::compute_priority(&self.local, &self.remote, role);
    }
}

/// Check list for ICE connectivity checks.
#[derive(Debug)]
pub struct CheckList {
    /// Candidate pairs sorted by priority.
    pairs: Vec<CandidatePair>,
    /// Component to pairs mapping.
    by_component: HashMap<u16, Vec<usize>>,
    /// Foundation to pairs mapping (for freezing logic).
    by_foundation: HashMap<String, Vec<usize>>,
    /// Check list state.
    state: CheckListState,
    /// Selected pair per component.
    selected: HashMap<u16, usize>,
}

/// Check list state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckListState {
    /// Check list is running.
    Running,
    /// Check list completed successfully.
    Completed,
    /// Check list failed.
    Failed,
}

impl CheckList {
    /// Creates a new check list.
    pub fn new() -> Self {
        Self {
            pairs: Vec::new(),
            by_component: HashMap::new(),
            by_foundation: HashMap::new(),
            state: CheckListState::Running,
            selected: HashMap::new(),
        }
    }

    /// Adds a candidate pair to the list.
    pub fn add_pair(&mut self, pair: CandidatePair) {
        let index = self.pairs.len();
        let component = pair.local().component();
        let foundation = pair.foundation().to_string();

        self.pairs.push(pair);

        self.by_component.entry(component).or_default().push(index);

        self.by_foundation
            .entry(foundation)
            .or_default()
            .push(index);
    }

    /// Forms pairs from local and remote candidates.
    pub fn form_pairs(
        local_candidates: &[Candidate],
        remote_candidates: &[Candidate],
        role: IceRole,
    ) -> Self {
        let mut checklist = CheckList::new();

        for local in local_candidates {
            for remote in remote_candidates {
                // Only pair candidates with same component and transport
                if local.component() != remote.component() {
                    continue;
                }
                if local.transport() != remote.transport() {
                    continue;
                }
                // Only pair IPv4 with IPv4, IPv6 with IPv6
                if local.address().is_ipv4() != remote.address().is_ipv4() {
                    continue;
                }

                let pair = CandidatePair::new(local.clone(), remote.clone(), role);
                checklist.add_pair(pair);
            }
        }

        // Sort by priority (highest first)
        checklist.sort_by_priority();

        // Initialize states - unfreeze highest priority pair per foundation
        checklist.initialize_states();

        checklist
    }

    /// Returns all pairs.
    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

    /// Returns mutable reference to pairs.
    pub fn pairs_mut(&mut self) -> &mut [CandidatePair] {
        &mut self.pairs
    }

    /// Returns the check list state.
    pub fn state(&self) -> CheckListState {
        self.state
    }

    /// Sets the check list state.
    pub fn set_state(&mut self, state: CheckListState) {
        self.state = state;
    }

    /// Returns pairs for a specific component.
    pub fn pairs_for_component(&self, component: u16) -> Vec<&CandidatePair> {
        self.by_component
            .get(&component)
            .map(|indices| indices.iter().map(|&i| &self.pairs[i]).collect())
            .unwrap_or_default()
    }

    /// Returns the number of pairs.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Returns true if there are no pairs.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Returns the next pair to check (Waiting state, highest priority).
    pub fn next_pair_to_check(&self) -> Option<usize> {
        self.pairs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state() == PairState::Waiting)
            .max_by_key(|(_, p)| p.priority())
            .map(|(i, _)| i)
    }

    /// Gets a pair by index.
    pub fn get(&self, index: usize) -> Option<&CandidatePair> {
        self.pairs.get(index)
    }

    /// Gets a mutable pair by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut CandidatePair> {
        self.pairs.get_mut(index)
    }

    /// Marks a pair as succeeded and handles nomination.
    pub fn mark_succeeded(&mut self, index: usize) -> IceResult<()> {
        let pair = self
            .pairs
            .get_mut(index)
            .ok_or(IceError::InvalidCandidate {
                reason: "pair index out of bounds".to_string(),
            })?;

        pair.set_state(PairState::Succeeded);

        // Unfreeze pairs with same foundation
        let foundation = pair.foundation().to_string();
        self.unfreeze_foundation(&foundation);

        Ok(())
    }

    /// Marks a pair as failed.
    pub fn mark_failed(&mut self, index: usize) -> IceResult<()> {
        let pair = self
            .pairs
            .get_mut(index)
            .ok_or(IceError::InvalidCandidate {
                reason: "pair index out of bounds".to_string(),
            })?;

        pair.set_state(PairState::Failed);

        Ok(())
    }

    /// Selects a pair for a component.
    pub fn select_pair(&mut self, component: u16, index: usize) -> IceResult<()> {
        if index >= self.pairs.len() {
            return Err(IceError::InvalidCandidate {
                reason: "pair index out of bounds".to_string(),
            });
        }

        let pair = &self.pairs[index];
        if pair.local().component() != component {
            return Err(IceError::InvalidCandidate {
                reason: "pair component mismatch".to_string(),
            });
        }

        self.selected.insert(component, index);
        Ok(())
    }

    /// Returns the selected pair for a component.
    pub fn selected_pair(&self, component: u16) -> Option<&CandidatePair> {
        self.selected
            .get(&component)
            .and_then(|&i| self.pairs.get(i))
    }

    /// Checks if all components have a selected pair.
    pub fn is_complete(&self) -> bool {
        let components: std::collections::HashSet<u16> =
            self.pairs.iter().map(|p| p.local().component()).collect();

        components.iter().all(|c| self.selected.contains_key(c))
    }

    /// Checks if all pairs have failed.
    pub fn all_failed(&self) -> bool {
        self.pairs.iter().all(|p| p.state() == PairState::Failed)
    }

    /// Sorts pairs by priority (highest first).
    fn sort_by_priority(&mut self) {
        // We need to rebuild indices after sorting
        self.pairs.sort_by(|a, b| b.priority().cmp(&a.priority()));

        // Rebuild component and foundation indices
        self.by_component.clear();
        self.by_foundation.clear();

        for (index, pair) in self.pairs.iter().enumerate() {
            let component = pair.local().component();
            let foundation = pair.foundation().to_string();

            self.by_component.entry(component).or_default().push(index);

            self.by_foundation
                .entry(foundation)
                .or_default()
                .push(index);
        }
    }

    /// Initializes pair states per RFC 8445 Section 6.1.2.6.
    fn initialize_states(&mut self) {
        // Unfreeze the first pair for each foundation
        let mut seen_foundations = std::collections::HashSet::new();

        for pair in &mut self.pairs {
            if seen_foundations.insert(pair.foundation().to_string()) {
                pair.set_state(PairState::Waiting);
            }
        }
    }

    /// Unfreezes pairs with the given foundation.
    fn unfreeze_foundation(&mut self, foundation: &str) {
        if let Some(indices) = self.by_foundation.get(foundation) {
            for &i in indices {
                if let Some(pair) = self.pairs.get_mut(i) {
                    if pair.state() == PairState::Frozen {
                        pair.set_state(PairState::Waiting);
                    }
                }
            }
        }
    }
}

impl Default for CheckList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{CandidateType, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_candidate(ip: [u8; 4], port: u16, component: u16) -> Candidate {
        Candidate::new(
            "test".to_string(),
            component,
            TransportProtocol::Udp,
            2130706431,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port),
            CandidateType::Host,
        )
    }

    #[test]
    fn test_pair_creation() {
        let local = test_candidate([192, 168, 1, 100], 5060, 1);
        let remote = test_candidate([10, 0, 0, 1], 5060, 1);

        let pair = CandidatePair::new(local, remote, IceRole::Controlling);

        assert_eq!(pair.state(), PairState::Frozen);
        assert!(!pair.is_nominated());
        assert!(pair.priority() > 0);
    }

    #[test]
    fn test_pair_priority() {
        // Create candidates with DIFFERENT priorities
        let local = Candidate::new(
            "local".to_string(),
            1,
            TransportProtocol::Udp,
            2130706431, // High priority (host)
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060),
            CandidateType::Host,
        );
        let remote = Candidate::new(
            "remote".to_string(),
            1,
            TransportProtocol::Udp,
            1694498815, // Lower priority (server reflexive)
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            CandidateType::ServerReflexive,
        );

        let pair_controlling =
            CandidatePair::new(local.clone(), remote.clone(), IceRole::Controlling);
        let pair_controlled = CandidatePair::new(local, remote, IceRole::Controlled);

        // Priority should differ based on role when G != D
        // When G != D, the (G>D?1:0) tie-breaker matters
        assert_ne!(pair_controlling.priority(), pair_controlled.priority());
    }

    #[test]
    fn test_checklist_form_pairs() {
        let local = vec![
            test_candidate([192, 168, 1, 100], 5060, 1),
            test_candidate([192, 168, 1, 100], 5061, 2),
        ];
        let remote = vec![
            test_candidate([10, 0, 0, 1], 5060, 1),
            test_candidate([10, 0, 0, 1], 5061, 2),
        ];

        let checklist = CheckList::form_pairs(&local, &remote, IceRole::Controlling);

        // Should have 2 pairs (one per component)
        assert_eq!(checklist.len(), 2);
    }

    #[test]
    fn test_checklist_next_pair() {
        let local = vec![test_candidate([192, 168, 1, 100], 5060, 1)];
        let remote = vec![test_candidate([10, 0, 0, 1], 5060, 1)];

        let checklist = CheckList::form_pairs(&local, &remote, IceRole::Controlling);

        // First pair should be in Waiting state
        let next = checklist.next_pair_to_check();
        assert!(next.is_some());
    }

    #[test]
    fn test_checklist_mark_succeeded() {
        let local = vec![test_candidate([192, 168, 1, 100], 5060, 1)];
        let remote = vec![test_candidate([10, 0, 0, 1], 5060, 1)];

        let mut checklist = CheckList::form_pairs(&local, &remote, IceRole::Controlling);

        checklist.mark_succeeded(0).unwrap();
        assert_eq!(checklist.pairs()[0].state(), PairState::Succeeded);
    }

    #[test]
    fn test_checklist_select_pair() {
        let local = vec![test_candidate([192, 168, 1, 100], 5060, 1)];
        let remote = vec![test_candidate([10, 0, 0, 1], 5060, 1)];

        let mut checklist = CheckList::form_pairs(&local, &remote, IceRole::Controlling);

        checklist.select_pair(1, 0).unwrap();
        assert!(checklist.selected_pair(1).is_some());
        assert!(checklist.is_complete());
    }

    #[test]
    fn test_pair_state_display() {
        assert_eq!(PairState::Waiting.to_string(), "Waiting");
        assert_eq!(PairState::InProgress.to_string(), "In-Progress");
        assert_eq!(PairState::Succeeded.to_string(), "Succeeded");
    }
}
