//! Failover coordination for cluster high availability.

use crate::config::{ClusterConfig, FailoverStrategy};
use crate::error::{ClusterError, ClusterResult};
use crate::membership::ClusterMembership;
use crate::node::{ClusterNode, NodeId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, error, info};

/// Result of a session takeover operation.
#[derive(Debug, Clone)]
pub struct TakeoverResult {
    /// Node that took over the sessions.
    pub target_node: NodeId,
    /// Number of sessions transferred.
    pub sessions_transferred: u64,
    /// Number of sessions that failed to transfer.
    pub sessions_failed: u64,
    /// Duration of the takeover operation.
    pub duration_ms: u64,
}

/// State of an ongoing failover operation.
#[derive(Debug, Clone)]
pub struct FailoverState {
    /// Node that failed.
    pub failed_node: NodeId,
    /// Node taking over.
    pub target_node: NodeId,
    /// When failover started.
    pub started_at: Instant,
    /// Current phase of failover.
    pub phase: FailoverPhase,
}

/// Phases of a failover operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverPhase {
    /// Detecting and confirming failure.
    Detecting,
    /// Selecting target node.
    SelectingTarget,
    /// Transferring sessions.
    TransferringSessions,
    /// Updating routing tables.
    UpdatingRoutes,
    /// Notifying cluster members.
    Notifying,
    /// Failover complete.
    Complete,
    /// Failover failed.
    Failed,
}

impl std::fmt::Display for FailoverPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detecting => write!(f, "detecting"),
            Self::SelectingTarget => write!(f, "selecting_target"),
            Self::TransferringSessions => write!(f, "transferring_sessions"),
            Self::UpdatingRoutes => write!(f, "updating_routes"),
            Self::Notifying => write!(f, "notifying"),
            Self::Complete => write!(f, "complete"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Coordinates failover operations in the cluster.
pub struct FailoverCoordinator {
    /// Cluster configuration.
    config: ClusterConfig,
    /// Cluster membership reference.
    membership: Arc<ClusterMembership>,
    /// Whether a failover is in progress.
    failover_in_progress: AtomicBool,
    /// Current failover state.
    current_failover: RwLock<Option<FailoverState>>,
    /// Session takeover handlers.
    takeover_handlers: RwLock<Vec<Box<dyn SessionTakeoverHandler>>>,
}

/// Handler for session takeover during failover.
pub trait SessionTakeoverHandler: Send + Sync + 'static {
    /// Takes over sessions from a failed node.
    fn takeover_sessions(
        &self,
        failed_node: &NodeId,
        target_node: &NodeId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ClusterResult<(u64, u64)>> + Send + '_>>;

    /// Returns the type of sessions this handler manages.
    fn session_type(&self) -> &'static str;
}

impl FailoverCoordinator {
    /// Creates a new failover coordinator.
    #[must_use]
    pub fn new(config: ClusterConfig, membership: Arc<ClusterMembership>) -> Self {
        Self {
            config,
            membership,
            failover_in_progress: AtomicBool::new(false),
            current_failover: RwLock::new(None),
            takeover_handlers: RwLock::new(Vec::new()),
        }
    }

    /// Registers a session takeover handler.
    pub async fn register_handler(&self, handler: Box<dyn SessionTakeoverHandler>) {
        let mut handlers = self.takeover_handlers.write().await;
        info!(
            handler_type = handler.session_type(),
            "Registered takeover handler"
        );
        handlers.push(handler);
    }

    /// Checks if a failover is currently in progress.
    #[must_use]
    pub fn is_failover_in_progress(&self) -> bool {
        self.failover_in_progress.load(Ordering::Acquire)
    }

    /// Returns the current failover state if any.
    pub async fn current_state(&self) -> Option<FailoverState> {
        self.current_failover.read().await.clone()
    }

    /// Initiates failover for a failed node.
    pub async fn initiate_failover(&self, failed_node: &NodeId) -> ClusterResult<TakeoverResult> {
        // Check if failover already in progress
        if self
            .failover_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ClusterError::FailoverInProgress);
        }

        let started_at = Instant::now();
        info!(failed_node = %failed_node, "Initiating failover");

        // Initialize failover state
        {
            let mut state = self.current_failover.write().await;
            *state = Some(FailoverState {
                failed_node: failed_node.clone(),
                target_node: NodeId::new("pending"),
                started_at,
                phase: FailoverPhase::Detecting,
            });
        }

        let result = self.execute_failover(failed_node, started_at).await;

        // Clean up failover state
        self.failover_in_progress.store(false, Ordering::Release);
        {
            let mut state = self.current_failover.write().await;
            if let Some(ref mut s) = *state {
                s.phase = if result.is_ok() {
                    FailoverPhase::Complete
                } else {
                    FailoverPhase::Failed
                };
            }
        }

        result
    }

    /// Executes the failover process.
    async fn execute_failover(
        &self,
        failed_node: &NodeId,
        started_at: Instant,
    ) -> ClusterResult<TakeoverResult> {
        // Phase 1: Mark failed node
        self.update_phase(FailoverPhase::Detecting).await;
        self.membership.mark_failed(failed_node).await?;

        // Phase 2: Select target node
        self.update_phase(FailoverPhase::SelectingTarget).await;
        let local_node = self.create_local_node_for_selection();
        let target_node = self
            .membership
            .select_failover_target(&local_node)
            .await
            .ok_or_else(|| ClusterError::FailoverFailed {
                reason: format!("No available failover target for node {failed_node}"),
            })?;

        info!(
            failed_node = %failed_node,
            target_node = %target_node,
            "Selected failover target"
        );

        // Update state with target
        {
            let mut state = self.current_failover.write().await;
            if let Some(ref mut s) = *state {
                s.target_node = target_node.clone();
            }
        }

        // Phase 3: Transfer sessions
        self.update_phase(FailoverPhase::TransferringSessions).await;
        let (sessions_transferred, sessions_failed) =
            self.transfer_sessions(failed_node, &target_node).await?;

        // Phase 4: Update routes
        self.update_phase(FailoverPhase::UpdatingRoutes).await;
        // Routes would be updated by the routing layer listening to membership changes

        // Phase 5: Notify cluster
        self.update_phase(FailoverPhase::Notifying).await;
        debug!(
            failed_node = %failed_node,
            target_node = %target_node,
            "Failover complete, notifying cluster"
        );

        let duration = started_at.elapsed();

        Ok(TakeoverResult {
            target_node,
            sessions_transferred,
            sessions_failed,
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Updates the current failover phase.
    async fn update_phase(&self, phase: FailoverPhase) {
        let mut state = self.current_failover.write().await;
        if let Some(ref mut s) = *state {
            debug!(phase = %phase, "Failover phase update");
            s.phase = phase;
        }
    }

    /// Transfers sessions from failed node to target.
    async fn transfer_sessions(
        &self,
        failed_node: &NodeId,
        target_node: &NodeId,
    ) -> ClusterResult<(u64, u64)> {
        let handlers = self.takeover_handlers.read().await;

        let mut total_transferred: u64 = 0;
        let mut total_failed: u64 = 0;

        for handler in handlers.iter() {
            match handler.takeover_sessions(failed_node, target_node).await {
                Ok((transferred, failed)) => {
                    info!(
                        handler_type = handler.session_type(),
                        transferred = transferred,
                        failed = failed,
                        "Session takeover complete"
                    );
                    total_transferred += transferred;
                    total_failed += failed;
                }
                Err(e) => {
                    error!(
                        handler_type = handler.session_type(),
                        error = %e,
                        "Session takeover failed"
                    );
                    // Continue with other handlers
                }
            }
        }

        Ok((total_transferred, total_failed))
    }

    /// Creates a minimal local node for failover target selection.
    fn create_local_node_for_selection(&self) -> ClusterNode {
        use crate::node::NodeEndpoints;
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};
        use uc_types::SbcSocketAddr;

        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
        ClusterNode::new(
            self.membership.local_node_id().clone(),
            self.config.role,
            self.config.region.clone(),
            self.config.zone.clone(),
            NodeEndpoints::new(
                SbcSocketAddr::from(addr),
                addr,
                addr,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
            ),
        )
    }

    /// Returns the configured failover timeout.
    #[must_use]
    pub fn failover_timeout(&self) -> Duration {
        Duration::from_millis(self.config.failover.failure_detection_timeout_ms)
    }

    /// Returns the configured failover strategy.
    #[must_use]
    pub fn strategy(&self) -> FailoverStrategy {
        self.config.failover.strategy
    }

    /// Checks if automatic failover is enabled.
    #[must_use]
    pub fn auto_failover_enabled(&self) -> bool {
        self.config.failover.auto_failover
    }

    /// Performs a manual failover to a specific target node.
    pub async fn manual_failover(
        &self,
        failed_node: &NodeId,
        target_node: &NodeId,
    ) -> ClusterResult<TakeoverResult> {
        // Check if failover already in progress
        if self
            .failover_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ClusterError::FailoverInProgress);
        }

        let started_at = Instant::now();
        info!(
            failed_node = %failed_node,
            target_node = %target_node,
            "Initiating manual failover"
        );

        // Initialize failover state
        {
            let mut state = self.current_failover.write().await;
            *state = Some(FailoverState {
                failed_node: failed_node.clone(),
                target_node: target_node.clone(),
                started_at,
                phase: FailoverPhase::Detecting,
            });
        }

        let result = self
            .execute_manual_failover(failed_node, target_node, started_at)
            .await;

        // Clean up failover state
        self.failover_in_progress.store(false, Ordering::Release);
        {
            let mut state = self.current_failover.write().await;
            if let Some(ref mut s) = *state {
                s.phase = if result.is_ok() {
                    FailoverPhase::Complete
                } else {
                    FailoverPhase::Failed
                };
            }
        }

        result
    }

    /// Executes a manual failover to a specific target.
    async fn execute_manual_failover(
        &self,
        failed_node: &NodeId,
        target_node: &NodeId,
        started_at: Instant,
    ) -> ClusterResult<TakeoverResult> {
        // Phase 1: Mark failed node
        self.update_phase(FailoverPhase::Detecting).await;
        self.membership.mark_failed(failed_node).await?;

        // Verify target is available
        let target_info = self.membership.get_node(target_node).await.ok_or_else(|| {
            ClusterError::NodeNotFound {
                node_id: target_node.to_string(),
            }
        })?;

        if !target_info.state.is_healthy() {
            return Err(ClusterError::FailoverFailed {
                reason: format!(
                    "Target node {target_node} is not healthy for failover of {failed_node}"
                ),
            });
        }

        // Phase 2: Transfer sessions
        self.update_phase(FailoverPhase::TransferringSessions).await;
        let (sessions_transferred, sessions_failed) =
            self.transfer_sessions(failed_node, target_node).await?;

        // Phase 3: Update routes
        self.update_phase(FailoverPhase::UpdatingRoutes).await;

        // Phase 4: Notify cluster
        self.update_phase(FailoverPhase::Notifying).await;

        let duration = started_at.elapsed();

        Ok(TakeoverResult {
            target_node: target_node.clone(),
            sessions_transferred,
            sessions_failed,
            duration_ms: duration.as_millis() as u64,
        })
    }
}

impl std::fmt::Debug for FailoverCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailoverCoordinator")
            .field("config", &"<config>")
            .field("membership", &"<membership>")
            .field("failover_in_progress", &self.is_failover_in_progress())
            .field("current_failover", &"<state>")
            .field("takeover_handlers", &"<handlers>")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn create_test_config() -> ClusterConfig {
        ClusterConfig::builder()
            .cluster_id("test-cluster")
            .node_id("local-node")
            .region("us-east-1")
            .zone("us-east-1a")
            .build()
    }

    #[test]
    fn test_takeover_result() {
        let result = TakeoverResult {
            target_node: NodeId::new("node-02"),
            sessions_transferred: 100,
            sessions_failed: 2,
            duration_ms: 1500,
        };

        assert_eq!(result.target_node.as_str(), "node-02");
        assert_eq!(result.sessions_transferred, 100);
        assert_eq!(result.sessions_failed, 2);
        assert_eq!(result.duration_ms, 1500);
    }

    #[test]
    fn test_failover_phase_display() {
        assert_eq!(format!("{}", FailoverPhase::Detecting), "detecting");
        assert_eq!(
            format!("{}", FailoverPhase::SelectingTarget),
            "selecting_target"
        );
        assert_eq!(
            format!("{}", FailoverPhase::TransferringSessions),
            "transferring_sessions"
        );
        assert_eq!(format!("{}", FailoverPhase::Complete), "complete");
    }

    #[tokio::test]
    async fn test_failover_coordinator_creation() {
        let config = create_test_config();
        let membership = Arc::new(ClusterMembership::new(config.clone()));
        let coordinator = FailoverCoordinator::new(config, membership);

        assert!(!coordinator.is_failover_in_progress());
        assert!(coordinator.auto_failover_enabled());
    }

    #[tokio::test]
    async fn test_failover_coordinator_no_target() {
        let config = create_test_config();
        let membership = Arc::new(ClusterMembership::new(config.clone()));
        let coordinator = FailoverCoordinator::new(config, membership);

        // Failover with no other nodes should fail
        let result = coordinator
            .initiate_failover(&NodeId::new("failed-node"))
            .await;
        assert!(result.is_err());
    }
}
