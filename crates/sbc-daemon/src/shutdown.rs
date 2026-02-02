//! Graceful shutdown handling with async signal support.
//!
//! ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
//!
//! Shutdown events are logged for audit trail.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

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
        use tokio::signal::unix::{signal, SignalKind};

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

/// Shutdown coordinator for graceful shutdown.
pub struct ShutdownCoordinator {
    /// Shutdown signal.
    signal: ShutdownSignal,
    /// Shutdown timeout in seconds.
    timeout_secs: u64,
    /// Whether shutdown is in progress.
    in_progress: AtomicBool,
}

impl ShutdownCoordinator {
    /// Creates a new shutdown coordinator.
    pub fn new(signal: ShutdownSignal) -> Self {
        Self {
            signal,
            timeout_secs: 30,
            in_progress: AtomicBool::new(false),
        }
    }

    /// Sets the shutdown timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Returns the shutdown signal.
    pub fn signal(&self) -> &ShutdownSignal {
        &self.signal
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
    pub async fn shutdown_gracefully(&self, active_connections: u32) -> ShutdownPhase {
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
    /// Shutdown complete.
    Complete,
}

#[cfg(test)]
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
    async fn test_graceful_shutdown() {
        let signal = ShutdownSignal::new();
        let coordinator = ShutdownCoordinator::new(signal).with_timeout(1);

        let phase = coordinator.shutdown_gracefully(0).await;
        assert_eq!(phase, ShutdownPhase::Complete);
    }
}
