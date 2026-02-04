//! SCTP path management for multi-homing (RFC 9260 Section 5.4 and 8).
//!
//! This module implements:
//! - Path state tracking (active, inactive, pending reachability)
//! - Per-path congestion control
//! - Path selection and failover
//! - Heartbeat-based path monitoring

use super::congestion::CongestionController;
use super::timer::RtoCalculator;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// =============================================================================
// Path State
// =============================================================================

/// Path state for multi-homing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is active and available for data transmission.
    Active,
    /// Path is inactive (failed heartbeats or errors).
    Inactive,
    /// Path reachability is being verified.
    PendingReachability,
}

impl std::fmt::Display for PathState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Inactive => write!(f, "Inactive"),
            Self::PendingReachability => write!(f, "PendingReachability"),
        }
    }
}

// =============================================================================
// Path ID
// =============================================================================

/// Unique identifier for a path (local addr, remote addr pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId {
    /// Local address.
    pub local: SocketAddr,
    /// Remote address.
    pub remote: SocketAddr,
}

impl PathId {
    /// Creates a new path ID.
    #[must_use]
    pub const fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self { local, remote }
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}→{}", self.local, self.remote)
    }
}

// =============================================================================
// Path
// =============================================================================

/// A single network path for SCTP multi-homing.
///
/// Per RFC 9260 Section 5.4, each path maintains:
/// - Congestion control state (cwnd, ssthresh)
/// - RTO calculation
/// - Error counter
/// - Heartbeat state
#[derive(Debug)]
pub struct Path {
    /// Path identifier.
    id: PathId,
    /// Path state.
    state: PathState,
    /// Per-path congestion controller.
    congestion: CongestionController,
    /// Per-path RTO calculator.
    rto: RtoCalculator,
    /// Consecutive error count.
    error_count: u32,
    /// Maximum error count before marking path inactive.
    max_path_retransmissions: u32,
    /// Whether this path is confirmed (received data or HB-ACK).
    confirmed: bool,
    /// Last time data was sent on this path.
    last_data_sent: Option<Instant>,
    /// Last time data was received on this path.
    last_data_received: Option<Instant>,
    /// Time of last heartbeat sent.
    last_heartbeat_sent: Option<Instant>,
    /// Time of last heartbeat acknowledged.
    last_heartbeat_acked: Option<Instant>,
    /// Heartbeat interval.
    heartbeat_interval: Duration,
    /// Whether heartbeat is enabled for this path.
    heartbeat_enabled: bool,
    /// Path MTU.
    pmtu: u32,
    /// Whether PMTU discovery is in progress.
    pmtu_discovery_in_progress: bool,
}

impl Path {
    /// Default max path retransmissions (RFC 9260 suggests 5).
    pub const DEFAULT_MAX_PATH_RETRANSMISSIONS: u32 = 5;
    /// Default heartbeat interval (30 seconds).
    pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    /// Default path MTU.
    pub const DEFAULT_PMTU: u32 = 1280;

    /// Creates a new path.
    #[must_use]
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            id: PathId::new(local, remote),
            state: PathState::PendingReachability,
            congestion: CongestionController::new(),
            rto: RtoCalculator::new(),
            error_count: 0,
            max_path_retransmissions: Self::DEFAULT_MAX_PATH_RETRANSMISSIONS,
            confirmed: false,
            last_data_sent: None,
            last_data_received: None,
            last_heartbeat_sent: None,
            last_heartbeat_acked: None,
            heartbeat_interval: Self::DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_enabled: true,
            pmtu: Self::DEFAULT_PMTU,
            pmtu_discovery_in_progress: false,
        }
    }

    /// Creates a new path with custom MTU.
    #[must_use]
    pub fn with_mtu(local: SocketAddr, remote: SocketAddr, mtu: u32) -> Self {
        let mut path = Self::new(local, remote);
        path.pmtu = mtu;
        path.congestion = CongestionController::with_mtu(mtu);
        path
    }

    /// Returns the path ID.
    #[must_use]
    pub const fn id(&self) -> PathId {
        self.id
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.id.local
    }

    /// Returns the remote address.
    #[must_use]
    pub const fn remote_addr(&self) -> SocketAddr {
        self.id.remote
    }

    /// Returns the path state.
    #[must_use]
    pub const fn state(&self) -> PathState {
        self.state
    }

    /// Returns true if the path is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, PathState::Active)
    }

    /// Returns true if the path is confirmed reachable.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Returns the congestion controller.
    #[must_use]
    pub const fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    /// Returns a mutable reference to the congestion controller.
    pub fn congestion_mut(&mut self) -> &mut CongestionController {
        &mut self.congestion
    }

    /// Returns the RTO calculator.
    #[must_use]
    pub const fn rto(&self) -> &RtoCalculator {
        &self.rto
    }

    /// Returns a mutable reference to the RTO calculator.
    pub fn rto_mut(&mut self) -> &mut RtoCalculator {
        &mut self.rto
    }

    /// Returns the current RTO.
    #[must_use]
    pub fn current_rto(&self) -> Duration {
        self.rto.rto()
    }

    /// Returns the error count.
    #[must_use]
    pub const fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Returns the path MTU.
    #[must_use]
    pub const fn pmtu(&self) -> u32 {
        self.pmtu
    }

    /// Returns true if heartbeat is due on this path.
    #[must_use]
    pub fn heartbeat_due(&self) -> bool {
        if !self.heartbeat_enabled {
            return false;
        }

        self.last_heartbeat_sent
            .is_none_or(|last| last.elapsed() >= self.heartbeat_interval)
    }

    /// Confirms the path is reachable.
    ///
    /// Called when data is received or HB-ACK is received on this path.
    pub fn confirm(&mut self) {
        self.confirmed = true;
        if self.state == PathState::PendingReachability {
            self.state = PathState::Active;
            tracing::debug!(path = %self.id, "Path confirmed and activated");
        }
    }

    /// Records that data was sent on this path.
    pub fn on_data_sent(&mut self, bytes: u32) {
        self.last_data_sent = Some(Instant::now());
        self.congestion.on_data_sent(bytes);
    }

    /// Records that data was received on this path.
    pub fn on_data_received(&mut self) {
        self.last_data_received = Some(Instant::now());
        self.confirm();
        self.error_count = 0;
    }

    /// Records that a SACK was received for data sent on this path.
    pub fn on_sack_received(&mut self, bytes_acked: u32, is_new_ack: bool, rtt: Option<Duration>) {
        self.congestion.on_sack(bytes_acked, is_new_ack);

        if let Some(rtt) = rtt {
            self.rto.update(rtt);
        }

        if is_new_ack {
            self.error_count = 0;
        }
    }

    /// Records that a heartbeat was sent on this path.
    pub fn on_heartbeat_sent(&mut self) {
        self.last_heartbeat_sent = Some(Instant::now());
    }

    /// Records that a heartbeat acknowledgment was received.
    pub fn on_heartbeat_ack(&mut self, rtt: Duration) {
        self.last_heartbeat_acked = Some(Instant::now());
        self.rto.update(rtt);
        self.confirm();
        self.error_count = 0;

        tracing::trace!(
            path = %self.id,
            rtt_ms = rtt.as_millis(),
            "Heartbeat acknowledged"
        );
    }

    /// Records a transmission error (timeout, etc.) on this path.
    ///
    /// Returns true if the path should be marked as failed.
    pub fn on_error(&mut self) -> bool {
        self.error_count += 1;
        self.rto.backoff();

        tracing::debug!(
            path = %self.id,
            error_count = self.error_count,
            max = self.max_path_retransmissions,
            "Path error recorded"
        );

        if self.error_count >= self.max_path_retransmissions {
            self.state = PathState::Inactive;
            tracing::warn!(path = %self.id, "Path marked inactive due to errors");
            true
        } else {
            false
        }
    }

    /// Reactivates the path (e.g., after receiving data).
    pub fn reactivate(&mut self) {
        if self.state == PathState::Inactive {
            self.state = PathState::PendingReachability;
            self.error_count = 0;
            self.rto.reset();
            self.congestion.reset();
            tracing::debug!(path = %self.id, "Path reactivation initiated");
        }
    }

    /// Sets the heartbeat interval.
    pub fn set_heartbeat_interval(&mut self, interval: Duration) {
        self.heartbeat_interval = interval;
    }

    /// Enables or disables heartbeats.
    pub fn set_heartbeat_enabled(&mut self, enabled: bool) {
        self.heartbeat_enabled = enabled;
    }

    /// Updates the path MTU.
    pub fn update_pmtu(&mut self, pmtu: u32) {
        self.pmtu = pmtu;
        self.congestion.update_mtu(pmtu);
        self.pmtu_discovery_in_progress = false;
    }

    /// Returns true if PMTU discovery is in progress.
    #[must_use]
    pub const fn pmtu_discovery_in_progress(&self) -> bool {
        self.pmtu_discovery_in_progress
    }

    /// Starts PMTU discovery on this path.
    pub fn start_pmtu_discovery(&mut self) {
        self.pmtu_discovery_in_progress = true;
    }

    /// Cancels PMTU discovery on this path.
    pub fn cancel_pmtu_discovery(&mut self) {
        self.pmtu_discovery_in_progress = false;
    }

    /// Returns the available congestion window.
    #[must_use]
    pub fn available_window(&self) -> u32 {
        self.congestion.available_window()
    }
}

// =============================================================================
// Path Manager
// =============================================================================

/// Manages all paths for an SCTP association.
///
/// Implements RFC 9260 Section 5.4 (Multi-homed SCTP Endpoints) and
/// Section 8 (Path Management).
#[derive(Debug)]
pub struct PathManager {
    /// All known paths.
    paths: HashMap<PathId, Path>,
    /// Primary path ID.
    primary_path: Option<PathId>,
    /// Default heartbeat interval for new paths.
    default_heartbeat_interval: Duration,
    /// Default max path retransmissions.
    default_max_retransmissions: u32,
}

impl PathManager {
    /// Creates a new path manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            primary_path: None,
            default_heartbeat_interval: Path::DEFAULT_HEARTBEAT_INTERVAL,
            default_max_retransmissions: Path::DEFAULT_MAX_PATH_RETRANSMISSIONS,
        }
    }

    /// Returns the number of paths.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Returns true if there are no paths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Returns the primary path ID.
    #[must_use]
    pub fn primary_path_id(&self) -> Option<PathId> {
        self.primary_path
    }

    /// Returns a reference to the primary path.
    #[must_use]
    pub fn primary_path(&self) -> Option<&Path> {
        self.primary_path.and_then(|id| self.paths.get(&id))
    }

    /// Returns a mutable reference to the primary path.
    pub fn primary_path_mut(&mut self) -> Option<&mut Path> {
        self.primary_path.and_then(|id| self.paths.get_mut(&id))
    }

    /// Returns a reference to a path by ID.
    #[must_use]
    pub fn get_path(&self, id: PathId) -> Option<&Path> {
        self.paths.get(&id)
    }

    /// Returns a mutable reference to a path by ID.
    pub fn get_path_mut(&mut self, id: PathId) -> Option<&mut Path> {
        self.paths.get_mut(&id)
    }

    /// Returns a path by remote address (any local).
    #[must_use]
    pub fn get_path_by_remote(&self, remote: SocketAddr) -> Option<&Path> {
        self.paths.values().find(|p| p.remote_addr() == remote)
    }

    /// Adds a new path.
    ///
    /// If this is the first path, it becomes the primary path.
    pub fn add_path(&mut self, local: SocketAddr, remote: SocketAddr) -> PathId {
        let id = PathId::new(local, remote);

        if self.paths.contains_key(&id) {
            return id;
        }

        let mut path = Path::new(local, remote);
        path.set_heartbeat_interval(self.default_heartbeat_interval);
        path.max_path_retransmissions = self.default_max_retransmissions;

        self.paths.insert(id, path);

        // Set as primary if it's the first path
        if self.primary_path.is_none() {
            self.primary_path = Some(id);
            tracing::debug!(path = %id, "Set as primary path");
        }

        tracing::debug!(path = %id, total_paths = self.paths.len(), "Path added");

        id
    }

    /// Removes a path.
    ///
    /// If the removed path was primary, a new primary is selected.
    pub fn remove_path(&mut self, id: PathId) -> Option<Path> {
        let path = self.paths.remove(&id)?;

        // If we removed the primary, select a new one
        if self.primary_path == Some(id) {
            self.primary_path = self.select_best_path();
            if let Some(new_primary) = self.primary_path {
                tracing::debug!(path = %new_primary, "New primary path selected");
            }
        }

        tracing::debug!(path = %id, total_paths = self.paths.len(), "Path removed");

        Some(path)
    }

    /// Sets the primary path.
    ///
    /// Returns true if the path exists and was set as primary.
    pub fn set_primary_path(&mut self, id: PathId) -> bool {
        if self.paths.contains_key(&id) {
            self.primary_path = Some(id);
            tracing::debug!(path = %id, "Primary path changed");
            true
        } else {
            false
        }
    }

    /// Selects the best available path.
    ///
    /// Prefers active, confirmed paths with the lowest error count.
    fn select_best_path(&self) -> Option<PathId> {
        self.paths
            .values()
            .filter(|p| p.is_active())
            .min_by_key(|p| (p.error_count(), !p.is_confirmed()))
            .map(Path::id)
            .or_else(|| {
                // Fallback to any path if no active paths
                self.paths.values().next().map(Path::id)
            })
    }

    /// Returns an active path for transmission.
    ///
    /// Returns the primary path if active, otherwise fails over to an alternate.
    #[must_use]
    pub fn get_active_path(&self) -> Option<&Path> {
        // Try primary first
        if let Some(primary) = self.primary_path()
            && primary.is_active()
        {
            return Some(primary);
        }

        // Failover to another active path
        self.paths.values().find(|p| p.is_active())
    }

    /// Returns a mutable reference to an active path for transmission.
    pub fn get_active_path_mut(&mut self) -> Option<&mut Path> {
        // Check if primary is active
        let primary_active = self
            .primary_path
            .and_then(|id| self.paths.get(&id))
            .is_some_and(Path::is_active);

        if primary_active {
            // Safe because we just checked it exists and is active
            let primary_id = self.primary_path?;
            return self.paths.get_mut(&primary_id);
        }

        // Failover: find any active path
        self.paths.values_mut().find(|p| p.is_active())
    }

    /// Performs path failover from the current primary to the next best path.
    ///
    /// Returns the new primary path ID if failover succeeded.
    pub fn failover(&mut self) -> Option<PathId> {
        let current_primary = self.primary_path?;

        // Find the best alternate path
        let new_primary = self
            .paths
            .values()
            .filter(|p| p.id() != current_primary && p.is_active())
            .min_by_key(|p| p.error_count())
            .map(Path::id)?;

        self.primary_path = Some(new_primary);

        tracing::info!(
            old_primary = %current_primary,
            new_primary = %new_primary,
            "Path failover performed"
        );

        Some(new_primary)
    }

    /// Returns all paths that need heartbeats.
    pub fn paths_needing_heartbeat(&self) -> Vec<PathId> {
        self.paths
            .values()
            .filter(|p| p.heartbeat_due())
            .map(Path::id)
            .collect()
    }

    /// Returns all active paths.
    pub fn active_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths.values().filter(|p| p.is_active())
    }

    /// Returns all inactive paths.
    pub fn inactive_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths
            .values()
            .filter(|p| matches!(p.state(), PathState::Inactive))
    }

    /// Returns an iterator over all paths.
    pub fn all_paths(&self) -> impl Iterator<Item = &Path> {
        self.paths.values()
    }

    /// Returns an iterator over all path IDs.
    pub fn all_path_ids(&self) -> impl Iterator<Item = PathId> + '_ {
        self.paths.keys().copied()
    }

    /// Sets the default heartbeat interval for new paths.
    pub fn set_default_heartbeat_interval(&mut self, interval: Duration) {
        self.default_heartbeat_interval = interval;
    }

    /// Sets the default max retransmissions for new paths.
    pub fn set_default_max_retransmissions(&mut self, max: u32) {
        self.default_max_retransmissions = max;
    }

    /// Resets all paths.
    pub fn reset(&mut self) {
        self.paths.clear();
        self.primary_path = None;
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn test_path_creation() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let path = Path::new(local, remote);

        assert_eq!(path.local_addr(), local);
        assert_eq!(path.remote_addr(), remote);
        assert_eq!(path.state(), PathState::PendingReachability);
        assert!(!path.is_confirmed());
        assert_eq!(path.error_count(), 0);
    }

    #[test]
    fn test_path_confirmation() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);

        assert!(!path.is_confirmed());
        assert_eq!(path.state(), PathState::PendingReachability);

        path.confirm();

        assert!(path.is_confirmed());
        assert_eq!(path.state(), PathState::Active);
    }

    #[test]
    fn test_path_error_tracking() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);
        path.max_path_retransmissions = 3;
        path.confirm();

        // First few errors shouldn't fail the path
        assert!(!path.on_error());
        assert_eq!(path.error_count(), 1);
        assert!(path.is_active());

        assert!(!path.on_error());
        assert_eq!(path.error_count(), 2);

        // Third error should mark path inactive
        assert!(path.on_error());
        assert_eq!(path.error_count(), 3);
        assert!(!path.is_active());
        assert_eq!(path.state(), PathState::Inactive);
    }

    #[test]
    fn test_path_reactivation() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);
        path.max_path_retransmissions = 1;
        path.confirm();

        // Fail the path
        path.on_error();
        assert_eq!(path.state(), PathState::Inactive);

        // Reactivate
        path.reactivate();
        assert_eq!(path.state(), PathState::PendingReachability);
        assert_eq!(path.error_count(), 0);
    }

    #[test]
    fn test_path_data_tracking() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);

        path.on_data_sent(1000);
        assert!(path.last_data_sent.is_some());

        path.on_data_received();
        assert!(path.last_data_received.is_some());
        assert!(path.is_confirmed());
    }

    #[test]
    fn test_path_manager_creation() {
        let manager = PathManager::new();
        assert!(manager.is_empty());
        assert!(manager.primary_path_id().is_none());
    }

    #[test]
    fn test_path_manager_add_path() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote = test_addr(5061);

        let id = manager.add_path(local, remote);

        assert_eq!(manager.path_count(), 1);
        assert_eq!(manager.primary_path_id(), Some(id));
        assert!(manager.get_path(id).is_some());
    }

    #[test]
    fn test_path_manager_multiple_paths() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote1 = test_addr(5061);
        let remote2 = test_addr(5062);

        let id1 = manager.add_path(local, remote1);
        let id2 = manager.add_path(local, remote2);

        assert_eq!(manager.path_count(), 2);
        // First path should be primary
        assert_eq!(manager.primary_path_id(), Some(id1));
        assert!(manager.get_path(id2).is_some());
    }

    #[test]
    fn test_path_manager_remove_primary() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote1 = test_addr(5061);
        let remote2 = test_addr(5062);

        let id1 = manager.add_path(local, remote1);
        let id2 = manager.add_path(local, remote2);

        // Confirm second path so it can become primary
        manager.get_path_mut(id2).unwrap().confirm();

        // Remove primary
        manager.remove_path(id1);

        assert_eq!(manager.path_count(), 1);
        // Second path should become primary
        assert_eq!(manager.primary_path_id(), Some(id2));
    }

    #[test]
    fn test_path_manager_failover() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote1 = test_addr(5061);
        let remote2 = test_addr(5062);

        let id1 = manager.add_path(local, remote1);
        let id2 = manager.add_path(local, remote2);

        // Confirm and activate both paths
        manager.get_path_mut(id1).unwrap().confirm();
        manager.get_path_mut(id2).unwrap().confirm();

        assert_eq!(manager.primary_path_id(), Some(id1));

        // Perform failover
        let new_primary = manager.failover();

        assert_eq!(new_primary, Some(id2));
        assert_eq!(manager.primary_path_id(), Some(id2));
    }

    #[test]
    fn test_path_manager_get_active_path() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote1 = test_addr(5061);
        let remote2 = test_addr(5062);

        let id1 = manager.add_path(local, remote1);
        let id2 = manager.add_path(local, remote2);

        // Neither path is active yet
        assert!(manager.get_active_path().is_none());

        // Activate second path
        manager.get_path_mut(id2).unwrap().confirm();

        // Should return the active path
        let active = manager.get_active_path().unwrap();
        assert_eq!(active.id(), id2);

        // Activate primary
        manager.get_path_mut(id1).unwrap().confirm();

        // Should prefer primary
        let active = manager.get_active_path().unwrap();
        assert_eq!(active.id(), id1);
    }

    #[test]
    fn test_path_manager_set_primary() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);
        let remote1 = test_addr(5061);
        let remote2 = test_addr(5062);

        let id1 = manager.add_path(local, remote1);
        let id2 = manager.add_path(local, remote2);

        assert_eq!(manager.primary_path_id(), Some(id1));

        assert!(manager.set_primary_path(id2));
        assert_eq!(manager.primary_path_id(), Some(id2));
    }

    #[test]
    fn test_path_heartbeat_due() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);
        path.set_heartbeat_interval(Duration::from_millis(10));

        // Should be due initially
        assert!(path.heartbeat_due());

        // Send heartbeat
        path.on_heartbeat_sent();
        assert!(!path.heartbeat_due());

        // Wait for interval
        std::thread::sleep(Duration::from_millis(15));
        assert!(path.heartbeat_due());
    }

    #[test]
    fn test_path_heartbeat_disabled() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);

        path.set_heartbeat_enabled(false);
        assert!(!path.heartbeat_due());
    }

    #[test]
    fn test_path_manager_paths_needing_heartbeat() {
        let mut manager = PathManager::new();
        let local = test_addr(5060);

        let id1 = manager.add_path(local, test_addr(5061));
        let id2 = manager.add_path(local, test_addr(5062));

        // Both should need heartbeat initially
        let needing = manager.paths_needing_heartbeat();
        assert_eq!(needing.len(), 2);

        // Send heartbeat on one
        manager.get_path_mut(id1).unwrap().on_heartbeat_sent();

        let needing = manager.paths_needing_heartbeat();
        assert_eq!(needing.len(), 1);
        assert!(needing.contains(&id2));
    }

    #[test]
    fn test_path_rtt_update() {
        let local = test_addr(5060);
        let remote = test_addr(5061);
        let mut path = Path::new(local, remote);

        let rtt = Duration::from_millis(50);
        path.on_heartbeat_ack(rtt);

        assert!(path.rto().srtt().is_some());
        assert!(path.is_confirmed());
    }

    #[test]
    fn test_path_id_display() {
        let id = PathId::new(test_addr(5060), test_addr(5061));
        let display = format!("{id}");
        assert!(display.contains("5060"));
        assert!(display.contains("5061"));
    }
}
