//! SBC server components.
//!
//! This module contains the server components that handle SIP signaling
//! and media processing.

use crate::shutdown::ShutdownSignal;
use sbc_config::SbcConfig;
use sbc_health::{HealthChecker, HealthCheckerConfig};
use sbc_metrics::{MetricRegistry, SbcMetrics};
use std::sync::atomic::{AtomicU64, Ordering};

/// SBC server state.
pub struct Server {
    /// Configuration.
    config: SbcConfig,
    /// Shutdown signal.
    shutdown: ShutdownSignal,
    /// Health checker.
    health: HealthChecker,
    /// Metrics registry.
    metrics: MetricRegistry,
    /// Server statistics.
    stats: ServerStats,
}

impl Server {
    /// Creates a new server.
    pub fn new(config: SbcConfig, shutdown: ShutdownSignal) -> Self {
        // Use standard SBC metrics
        let metrics = SbcMetrics::standard();

        let mut health = HealthChecker::new(HealthCheckerConfig::default())
            .with_version(env!("CARGO_PKG_VERSION"));

        // Register health checks
        health.register(Box::new(sbc_health::check::AlwaysHealthyCheck::new(
            "sbc_core",
        )));
        health.register(Box::new(sbc_health::check::MemoryCheck::new()));

        Self {
            config,
            shutdown,
            health,
            metrics,
            stats: ServerStats::default(),
        }
    }

    /// Returns the server configuration.
    pub fn config(&self) -> &SbcConfig {
        &self.config
    }

    /// Returns the health checker.
    pub fn health(&mut self) -> &mut HealthChecker {
        &mut self.health
    }

    /// Returns the metrics registry.
    pub fn metrics(&self) -> &MetricRegistry {
        &self.metrics
    }

    /// Returns server statistics.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Starts the server.
    pub fn start(&mut self) -> Result<(), ServerError> {
        // Log startup
        println!(
            "[INFO] Starting SBC daemon v{} (instance: {})",
            env!("CARGO_PKG_VERSION"),
            self.config.general.instance_name
        );
        println!(
            "[INFO] Max calls: {}, Max registrations: {}",
            self.config.general.max_calls, self.config.general.max_registrations
        );
        println!(
            "[INFO] Media mode: {:?}, SRTP required: {}",
            self.config.media.default_mode, self.config.media.srtp.required
        );

        // In production, would bind to transport addresses here
        // For now, just log the configured addresses
        for addr in &self.config.transport.udp_listen {
            println!("[INFO] UDP listener configured: {addr}");
        }
        for addr in &self.config.transport.tcp_listen {
            println!("[INFO] TCP listener configured: {addr}");
        }
        for addr in &self.config.transport.tls_listen {
            println!("[INFO] TLS listener configured: {addr}");
        }

        Ok(())
    }

    /// Runs the main event loop.
    pub fn run(&mut self) -> Result<(), ServerError> {
        println!("[INFO] Entering main event loop");

        // Main loop - in production would handle events
        while !self.shutdown.is_shutdown_requested() {
            // Check for reload
            if self.shutdown.is_reload_requested() {
                println!("[INFO] Reload requested");
                self.shutdown.clear_reload();
            }

            // Update stats
            self.stats.loops_completed.fetch_add(1, Ordering::Relaxed);

            // Sleep to prevent busy loop in this placeholder
            std::thread::sleep(std::time::Duration::from_millis(100));

            // In production, would process SIP messages, media, etc.
            // For now, just break after one iteration for testing
            #[cfg(test)]
            break;
        }

        Ok(())
    }

    /// Stops the server gracefully.
    pub fn stop(&mut self) -> Result<(), ServerError> {
        println!("[INFO] Stopping SBC daemon");

        // In production, would:
        // 1. Stop accepting new connections
        // 2. Drain active calls
        // 3. Close listeners

        println!("[INFO] SBC daemon stopped");
        Ok(())
    }

    /// Performs a health check.
    pub fn check_health(&mut self) -> sbc_health::SystemHealth {
        self.health.check()
    }

    /// Returns whether the server is ready to accept traffic.
    pub fn is_ready(&mut self) -> bool {
        self.health.is_ready()
    }

    /// Returns whether the server is alive.
    pub fn is_alive(&self) -> bool {
        self.health.is_alive()
    }
}

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Total calls processed.
    pub calls_total: AtomicU64,
    /// Currently active calls.
    pub calls_active: AtomicU64,
    /// Total registrations.
    pub registrations_total: AtomicU64,
    /// Active registrations.
    pub registrations_active: AtomicU64,
    /// Main loop iterations.
    pub loops_completed: AtomicU64,
}

/// Server error.
#[derive(Debug)]
pub enum ServerError {
    /// Failed to bind to address.
    BindFailed {
        /// Address that failed.
        address: String,
        /// Error reason.
        reason: String,
    },
    /// Configuration error.
    ConfigError {
        /// Error message.
        message: String,
    },
    /// Transport error.
    TransportError {
        /// Error message.
        message: String,
    },
    /// Internal error.
    InternalError {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed { address, reason } => {
                write!(f, "Failed to bind to {address}: {reason}")
            }
            Self::ConfigError { message } => {
                write!(f, "Configuration error: {message}")
            }
            Self::TransportError { message } => {
                write!(f, "Transport error: {message}")
            }
            Self::InternalError { message } => {
                write!(f, "Internal error: {message}")
            }
        }
    }
}

impl std::error::Error for ServerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown);

        assert_eq!(
            server.config().general.instance_name,
            "sbc-01"
        );
    }

    #[test]
    fn test_server_health() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let mut server = Server::new(config, shutdown);

        assert!(server.is_alive());
        assert!(server.is_ready());

        let health = server.check_health();
        assert!(health.is_healthy());
    }

    #[test]
    fn test_server_lifecycle() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let mut server = Server::new(config, shutdown);

        // Start server
        server.start().unwrap();

        // Run (will exit immediately in test mode)
        server.run().unwrap();

        // Stop server
        server.stop().unwrap();
    }

    #[test]
    fn test_server_stats() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown);

        assert_eq!(server.stats().calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(server.stats().calls_active.load(Ordering::Relaxed), 0);

        server.stats().calls_total.fetch_add(1, Ordering::Relaxed);
        assert_eq!(server.stats().calls_total.load(Ordering::Relaxed), 1);
    }
}
