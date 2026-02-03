//! Graceful shutdown handling with async signal support.
//!
//! This module provides production-grade shutdown coordination with:
//! - Connection draining with configurable timeout
//! - Active connection tracking
//! - Shutdown phases for orderly teardown
//!
//! ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
//!
//! Shutdown events are logged for audit trail.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Shutdown signal handler with tokio signal support.
#[derive(Clone)]
pub struct ShutdownSignal {
    /// Whether shutdown has been requested.
    shutdown_requested: Arc<AtomicBool>,
    /// Whether reload has been requested (SIGHUP).
    reload_requested: Arc<AtomicBool>,
    /// Broadcast sender for shutdown notification.
    shutdown_tx: broadcast::Sender<()>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    /// Creates a new shutdown signal handler.
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            reload_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    /// Checks if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Checks if reload has been requested.
    pub fn is_reload_requested(&self) -> bool {
        self.reload_requested.load(Ordering::SeqCst)
    }

    /// Clears the reload flag after handling.
    pub fn clear_reload(&self) {
        self.reload_requested.store(false, Ordering::SeqCst);
    }

    /// Requests shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        // Notify all waiters
        let _ = self.shutdown_tx.send(());
    }

    /// Requests reload.
    pub fn request_reload(&self) {
        self.reload_requested.store(true, Ordering::SeqCst);
    }

    /// Returns a receiver for shutdown notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Waits for a shutdown signal.
    ///
    /// This can be used in select! to wait for shutdown alongside other operations.
    pub async fn wait_for_shutdown(&self) {
        let mut rx = self.shutdown_tx.subscribe();
        // If already shutdown, return immediately
        if self.is_shutdown_requested() {
            return;
        }
        // Wait for shutdown signal
        let _ = rx.recv().await;
    }

    /// Installs signal handlers for graceful shutdown.
    ///
    /// On Unix, this installs handlers for SIGTERM, SIGINT, and SIGHUP.
    /// On other platforms, only Ctrl+C is handled.
    pub async fn install_handlers(&self) -> Result<(), ShutdownError> {
        let shutdown = self.clone();

        // Spawn signal handler task
        tokio::spawn(async move {
            shutdown.signal_handler_loop().await;
        });

        Ok(())
    }

    /// Internal signal handler loop.
    #[cfg(unix)]
    async fn signal_handler_loop(&self) {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to install SIGTERM handler: {e}");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to install SIGINT handler: {e}");
                return;
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to install SIGHUP handler: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating shutdown");
                    self.request_shutdown();
                    break;
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating shutdown");
                    self.request_shutdown();
                    break;
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP, requesting configuration reload");
                    self.request_reload();
                }
            }
        }
    }

    /// Internal signal handler loop for non-Unix platforms.
    #[cfg(not(unix))]
    async fn signal_handler_loop(&self) {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Received Ctrl+C, initiating shutdown");
                self.request_shutdown();
            }
            Err(e) => {
                warn!("Failed to listen for Ctrl+C: {e}");
            }
        }
    }
}

/// Shutdown error.
#[derive(Debug)]
pub struct ShutdownError {
    /// Error message.
    pub message: String,
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Shutdown error: {}", self.message)
    }
}

impl std::error::Error for ShutdownError {}

/// Connection tracker for graceful shutdown draining.
#[derive(Clone)]
pub struct ConnectionTracker {
    /// Active call count.
    active_calls: Arc<AtomicU32>,
    /// Active SIP transactions.
    active_transactions: Arc<AtomicU32>,
    /// Active registrations being processed.
    pending_registrations: Arc<AtomicU32>,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    /// Creates a new connection tracker.
    pub fn new() -> Self {
        Self {
            active_calls: Arc::new(AtomicU32::new(0)),
            active_transactions: Arc::new(AtomicU32::new(0)),
            pending_registrations: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Increments the active call count.
    pub fn call_started(&self) {
        self.active_calls.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active call count.
    pub fn call_ended(&self) {
        self.active_calls.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the active call count.
    pub fn active_calls(&self) -> u32 {
        self.active_calls.load(Ordering::SeqCst)
    }

    /// Increments the active transaction count.
    pub fn transaction_started(&self) {
        self.active_transactions.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active transaction count.
    pub fn transaction_ended(&self) {
        self.active_transactions.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the active transaction count.
    pub fn active_transactions(&self) -> u32 {
        self.active_transactions.load(Ordering::SeqCst)
    }

    /// Increments the pending registration count.
    pub fn registration_started(&self) {
        self.pending_registrations.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the pending registration count.
    pub fn registration_ended(&self) {
        self.pending_registrations.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the pending registration count.
    pub fn pending_registrations(&self) -> u32 {
        self.pending_registrations.load(Ordering::SeqCst)
    }

    /// Returns the total number of active connections/operations.
    pub fn total_active(&self) -> u32 {
        self.active_calls() + self.active_transactions() + self.pending_registrations()
    }

    /// Returns true if all connections have drained.
    pub fn is_drained(&self) -> bool {
        self.total_active() == 0
    }
}

/// Shutdown coordinator for graceful shutdown.
pub struct ShutdownCoordinator {
    /// Shutdown signal.
    signal: ShutdownSignal,
    /// Shutdown timeout in seconds.
    timeout_secs: u64,
    /// Whether shutdown is in progress.
    in_progress: AtomicBool,
    /// Connection tracker for draining.
    connections: ConnectionTracker,
    /// Drain poll interval in milliseconds.
    drain_poll_ms: u64,
}

impl ShutdownCoordinator {
    /// Creates a new shutdown coordinator.
    pub fn new(signal: ShutdownSignal) -> Self {
        Self {
            signal,
            timeout_secs: 30,
            in_progress: AtomicBool::new(false),
            connections: ConnectionTracker::new(),
            drain_poll_ms: 100,
        }
    }

    /// Sets the shutdown timeout.
    pub const fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Sets the drain poll interval.
    pub const fn with_drain_poll_interval(mut self, poll_ms: u64) -> Self {
        self.drain_poll_ms = poll_ms;
        self
    }

    /// Returns the shutdown signal.
    pub const fn signal(&self) -> &ShutdownSignal {
        &self.signal
    }

    /// Returns the connection tracker.
    pub const fn connections(&self) -> &ConnectionTracker {
        &self.connections
    }

    /// Initiates graceful shutdown.
    ///
    /// This will:
    /// 1. Stop accepting new connections
    /// 2. Wait for active calls to complete (up to timeout)
    /// 3. Force-terminate remaining connections
    pub fn initiate_shutdown(&self) -> ShutdownPhase {
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return ShutdownPhase::AlreadyInProgress;
        }

        self.signal.request_shutdown();
        ShutdownPhase::Started {
            timeout_secs: self.timeout_secs,
        }
    }

    /// Performs graceful shutdown with connection draining.
    ///
    /// This method:
    /// 1. Signals shutdown to stop accepting new connections
    /// 2. Polls active connections until drained or timeout
    /// 3. Returns the final shutdown phase with statistics
    #[allow(clippy::cast_possible_truncation)]
    pub async fn shutdown_gracefully(&self) -> DrainResult {
        let phase = self.initiate_shutdown();
        if matches!(phase, ShutdownPhase::AlreadyInProgress) {
            return DrainResult {
                phase,
                drained: false,
                remaining_calls: self.connections.active_calls(),
                remaining_transactions: self.connections.active_transactions(),
                drain_duration_ms: 0,
            };
        }

        let active = self.connections.total_active();
        info!(
            timeout_secs = self.timeout_secs,
            active_calls = self.connections.active_calls(),
            active_transactions = self.connections.active_transactions(),
            pending_registrations = self.connections.pending_registrations(),
            total_active = active,
            "Starting graceful shutdown with connection draining"
        );

        if active == 0 {
            info!("No active connections, shutdown immediate");
            return DrainResult {
                phase: ShutdownPhase::Complete,
                drained: true,
                remaining_calls: 0,
                remaining_transactions: 0,
                drain_duration_ms: 0,
            };
        }

        // Poll for connection drain with timeout
        let timeout = Duration::from_secs(self.timeout_secs);
        let poll_interval = Duration::from_millis(self.drain_poll_ms);
        let start = Instant::now();
        let deadline = start + timeout;

        let mut last_logged = start;
        let log_interval = Duration::from_secs(5);

        loop {
            if self.connections.is_drained() {
                let duration_ms = start.elapsed().as_millis() as u64;
                info!(duration_ms, "All connections drained successfully");
                return DrainResult {
                    phase: ShutdownPhase::Complete,
                    drained: true,
                    remaining_calls: 0,
                    remaining_transactions: 0,
                    drain_duration_ms: duration_ms,
                };
            }

            let now = Instant::now();
            if now >= deadline {
                let remaining_calls = self.connections.active_calls();
                let remaining_transactions = self.connections.active_transactions();
                warn!(
                    remaining_calls,
                    remaining_transactions,
                    timeout_secs = self.timeout_secs,
                    "Drain timeout exceeded, forcing shutdown"
                );
                return DrainResult {
                    phase: ShutdownPhase::ForcedShutdown {
                        remaining_calls,
                        remaining_transactions,
                    },
                    drained: false,
                    remaining_calls,
                    remaining_transactions,
                    drain_duration_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Log progress periodically
            if now.duration_since(last_logged) >= log_interval {
                let remaining = self.connections.total_active();
                let elapsed = start.elapsed().as_secs();
                debug!(remaining, elapsed_secs = elapsed, "Draining connections...");
                last_logged = now;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Performs graceful shutdown with the given active connection count.
    ///
    /// This is a convenience method for simpler shutdown scenarios where
    /// connection tracking is managed externally.
    pub async fn shutdown_gracefully_with_count(&self, active_connections: u32) -> ShutdownPhase {
        let phase = self.initiate_shutdown();
        if matches!(phase, ShutdownPhase::AlreadyInProgress) {
            return phase;
        }

        info!(
            timeout_secs = self.timeout_secs,
            active_connections, "Starting graceful shutdown"
        );

        if active_connections > 0 {
            // Wait for connections to drain with timeout
            let drain_timeout = tokio::time::Duration::from_secs(self.timeout_secs);
            info!(
                "Waiting up to {} seconds for {} active connections to drain",
                self.timeout_secs, active_connections
            );

            // In production, would poll connection count until 0 or timeout
            tokio::time::sleep(drain_timeout).await;
        }

        ShutdownPhase::Complete
    }

    /// Checks if shutdown is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.in_progress.load(Ordering::SeqCst)
    }
}

/// Result of a graceful shutdown drain operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainResult {
    /// Final shutdown phase.
    pub phase: ShutdownPhase,
    /// Whether all connections were successfully drained.
    pub drained: bool,
    /// Number of calls that remained active.
    pub remaining_calls: u32,
    /// Number of transactions that remained active.
    pub remaining_transactions: u32,
    /// Total drain duration in milliseconds.
    pub drain_duration_ms: u64,
}

/// Shutdown phase indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Shutdown has started.
    Started {
        /// Timeout before forced shutdown.
        timeout_secs: u64,
    },
    /// Shutdown was already in progress.
    AlreadyInProgress,
    /// Draining active connections.
    Draining {
        /// Remaining active connections.
        active_connections: u32,
    },
    /// Forced shutdown after timeout.
    ForcedShutdown {
        /// Calls that were forcibly terminated.
        remaining_calls: u32,
        /// Transactions that were forcibly terminated.
        remaining_transactions: u32,
    },
    /// Shutdown complete.
    Complete,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_signal() {
        let signal = ShutdownSignal::new();
        assert!(!signal.is_shutdown_requested());
        assert!(!signal.is_reload_requested());

        signal.request_shutdown();
        assert!(signal.is_shutdown_requested());

        signal.request_reload();
        assert!(signal.is_reload_requested());

        signal.clear_reload();
        assert!(!signal.is_reload_requested());
    }

    #[test]
    fn test_shutdown_coordinator() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal).with_timeout(60);

        assert!(!coordinator.is_in_progress());

        let phase = coordinator.initiate_shutdown();
        assert!(matches!(phase, ShutdownPhase::Started { timeout_secs: 60 }));
        assert!(coordinator.is_in_progress());

        // Second initiate should return AlreadyInProgress
        let phase2 = coordinator.initiate_shutdown();
        assert_eq!(phase2, ShutdownPhase::AlreadyInProgress);
    }

    #[tokio::test]
    async fn test_shutdown_wait() {
        let signal = ShutdownSignal::new();
        let signal_clone = signal.clone();

        // Spawn a task that will trigger shutdown
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            signal_clone.request_shutdown();
        });

        // Wait for shutdown - should complete when signal is sent
        tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            signal.wait_for_shutdown(),
        )
        .await
        .expect("Shutdown wait timed out");

        assert!(signal.is_shutdown_requested());
    }

    #[tokio::test]
    async fn test_graceful_shutdown_no_connections() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal).with_timeout(1);

        let result = coordinator.shutdown_gracefully().await;
        assert!(result.drained);
        assert_eq!(result.remaining_calls, 0);
        assert_eq!(result.phase, ShutdownPhase::Complete);
    }

    #[tokio::test]
    async fn test_graceful_shutdown_with_count() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal).with_timeout(1);

        let phase = coordinator.shutdown_gracefully_with_count(0).await;
        assert_eq!(phase, ShutdownPhase::Complete);
    }

    #[test]
    fn test_connection_tracker() {
        let tracker = ConnectionTracker::new();

        // Initially empty
        assert_eq!(tracker.total_active(), 0);
        assert!(tracker.is_drained());

        // Add some calls
        tracker.call_started();
        tracker.call_started();
        assert_eq!(tracker.active_calls(), 2);
        assert_eq!(tracker.total_active(), 2);
        assert!(!tracker.is_drained());

        // Add a transaction
        tracker.transaction_started();
        assert_eq!(tracker.active_transactions(), 1);
        assert_eq!(tracker.total_active(), 3);

        // End a call
        tracker.call_ended();
        assert_eq!(tracker.active_calls(), 1);
        assert_eq!(tracker.total_active(), 2);

        // End remaining
        tracker.call_ended();
        tracker.transaction_ended();
        assert!(tracker.is_drained());
    }

    #[test]
    fn test_connection_tracker_registrations() {
        let tracker = ConnectionTracker::new();

        tracker.registration_started();
        tracker.registration_started();
        assert_eq!(tracker.pending_registrations(), 2);
        assert_eq!(tracker.total_active(), 2);

        tracker.registration_ended();
        assert_eq!(tracker.pending_registrations(), 1);

        tracker.registration_ended();
        assert!(tracker.is_drained());
    }

    #[tokio::test]
    async fn test_graceful_shutdown_with_draining() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal)
            .with_timeout(2)
            .with_drain_poll_interval(10);

        // Add an active call
        coordinator.connections().call_started();

        // Spawn a task to end the call after a short delay
        let tracker = coordinator.connections().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tracker.call_ended();
        });

        let result = coordinator.shutdown_gracefully().await;
        assert!(result.drained);
        assert_eq!(result.remaining_calls, 0);
        assert_eq!(result.phase, ShutdownPhase::Complete);
        assert!(result.drain_duration_ms >= 50);
    }

    #[tokio::test]
    async fn test_graceful_shutdown_timeout() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal)
            .with_timeout(1) // 1 second timeout
            .with_drain_poll_interval(10);

        // Add active connections that won't be drained
        coordinator.connections().call_started();
        coordinator.connections().transaction_started();

        let result = coordinator.shutdown_gracefully().await;
        assert!(!result.drained);
        assert_eq!(result.remaining_calls, 1);
        assert_eq!(result.remaining_transactions, 1);
        assert!(matches!(result.phase, ShutdownPhase::ForcedShutdown { .. }));
    }

    #[test]
    fn test_drain_result() {
        let result = DrainResult {
            phase: ShutdownPhase::Complete,
            drained: true,
            remaining_calls: 0,
            remaining_transactions: 0,
            drain_duration_ms: 100,
        };

        assert!(result.drained);
        assert_eq!(result.phase, ShutdownPhase::Complete);
    }
}
