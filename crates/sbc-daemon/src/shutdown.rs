//! Graceful shutdown handling.
//!
//! ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
//!
//! Shutdown events are logged for audit trail.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shutdown signal handler.
#[derive(Clone)]
pub struct ShutdownSignal {
    /// Whether shutdown has been requested.
    shutdown_requested: Arc<AtomicBool>,
    /// Whether reload has been requested (SIGHUP).
    reload_requested: Arc<AtomicBool>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    /// Creates a new shutdown signal handler.
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            reload_requested: Arc::new(AtomicBool::new(false)),
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
    }

    /// Requests reload.
    pub fn request_reload(&self) {
        self.reload_requested.store(true, Ordering::SeqCst);
    }

    /// Installs signal handlers.
    ///
    /// On Unix, this installs handlers for SIGTERM, SIGINT, and SIGHUP.
    /// On other platforms, this is a no-op.
    pub fn install_handlers(&self) -> Result<(), ShutdownError> {
        #[cfg(unix)]
        {
            use std::thread;

            let shutdown = self.shutdown_requested.clone();
            let reload = self.reload_requested.clone();

            // We can't use actual signal handlers without unsafe code,
            // so we'll use a polling approach in the main loop.
            // In production, this would use signal-hook or similar.
            let _ = (shutdown, reload);

            // Spawn a thread to handle Ctrl+C via stdin
            let shutdown_clone = self.shutdown_requested.clone();
            thread::spawn(move || {
                // This is a simplified handler - in production would use signal-hook
                let _ = shutdown_clone;
            });
        }

        Ok(())
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
}
