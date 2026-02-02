//! SBC server components with async I/O.
//!
//! This module contains the server components that handle SIP signaling
//! and media processing using async/await patterns.

use crate::shutdown::ShutdownSignal;
use crate::sip_stack::{ProcessResult, SipStack, SipStackConfig};
use sbc_config::SbcConfig;
use sbc_health::{HealthChecker, HealthCheckerConfig};
use sbc_metrics::{MetricRegistry, SbcMetrics};
use sbc_registrar::RegistrarMode;
use sbc_transport::udp::UdpTransport;
use sbc_transport::Transport;
use sbc_types::address::SbcSocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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
    stats: Arc<ServerStats>,
    /// UDP transports for SIP signaling.
    udp_transports: RwLock<Vec<Arc<UdpTransport>>>,
    /// SIP stack for message processing.
    sip_stack: Arc<SipStack>,
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

        // Create SIP stack configuration
        let sip_config = SipStackConfig {
            instance_name: config.general.instance_name.clone(),
            domain: config
                .general
                .instance_name
                .clone(), // Use instance name as domain for now
            registrar_mode: RegistrarMode::B2bua,
            b2bua_enabled: true,
        };
        let sip_stack = Arc::new(SipStack::new(sip_config));

        Self {
            config,
            shutdown,
            health,
            metrics,
            stats: Arc::new(ServerStats::default()),
            udp_transports: RwLock::new(Vec::new()),
            sip_stack,
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

    /// Starts the server and binds to transport addresses.
    pub async fn start(&mut self) -> Result<(), ServerError> {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            instance = %self.config.general.instance_name,
            "Starting SBC daemon"
        );
        info!(
            max_calls = self.config.general.max_calls,
            max_registrations = self.config.general.max_registrations,
            "Call limits configured"
        );
        info!(
            media_mode = ?self.config.media.default_mode,
            srtp_required = self.config.media.srtp.required,
            "Media settings configured"
        );

        // Bind UDP listeners
        self.bind_udp_listeners().await?;

        Ok(())
    }

    /// Binds UDP transport listeners.
    async fn bind_udp_listeners(&mut self) -> Result<(), ServerError> {
        let mut transports = self.udp_transports.write().await;

        for socket_addr in &self.config.transport.udp_listen {
            let addr = SbcSocketAddr::from(*socket_addr);

            match UdpTransport::bind(addr.clone()).await {
                Ok(transport) => {
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound"
                    );
                    transports.push(Arc::new(transport));
                }
                Err(e) => {
                    error!(address = %addr, error = %e, "Failed to bind UDP listener");
                    return Err(ServerError::BindFailed {
                        address: addr.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // If no UDP listeners configured, bind to default ports
        if transports.is_empty() {
            let default_addr = SbcSocketAddr::new_v6(Ipv6Addr::UNSPECIFIED, 5060);
            match UdpTransport::bind(default_addr.clone()).await {
                Ok(transport) => {
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound (default)"
                    );
                    transports.push(Arc::new(transport));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to bind default UDP listener on IPv6, trying IPv4");
                    // Try IPv4 fallback
                    let ipv4_addr = SbcSocketAddr::new_v4(Ipv4Addr::UNSPECIFIED, 5060);
                    let transport = UdpTransport::bind(ipv4_addr).await.map_err(|e| {
                        ServerError::BindFailed {
                            address: "0.0.0.0:5060".to_string(),
                            reason: e.to_string(),
                        }
                    })?;
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound (IPv4 fallback)"
                    );
                    transports.push(Arc::new(transport));
                }
            }
        }

        Ok(())
    }

    /// Runs the main event loop.
    pub async fn run(&mut self) -> Result<(), ServerError> {
        info!("Entering async event loop");

        // Get transport handles for spawning receive tasks
        let transports = self.udp_transports.read().await;
        let transport_count = transports.len();

        if transport_count == 0 {
            warn!("No transports bound, exiting event loop");
            return Ok(());
        }

        // Spawn receive tasks for each transport
        let mut handles = Vec::new();
        for (idx, transport) in transports.iter().enumerate() {
            let transport = Arc::clone(transport);
            let shutdown = self.shutdown.clone();
            let stats = Arc::clone(&self.stats);
            let sip_stack = Arc::clone(&self.sip_stack);

            let handle = tokio::spawn(async move {
                Self::transport_receive_loop(idx, transport, shutdown, stats, sip_stack).await
            });
            handles.push(handle);
        }
        drop(transports);

        // Spawn health check polling task
        let shutdown = self.shutdown.clone();
        let health_interval = tokio::time::Duration::from_secs(30);
        let health_handle = tokio::spawn(async move {
            Self::health_poll_loop(shutdown, health_interval).await;
        });

        // Wait for shutdown or all tasks to complete
        self.shutdown.wait_for_shutdown().await;
        info!("Shutdown signal received, stopping event loop");

        // Cancel all tasks
        for handle in handles {
            handle.abort();
        }
        health_handle.abort();

        Ok(())
    }

    /// Receive loop for a single transport.
    async fn transport_receive_loop(
        idx: usize,
        transport: Arc<UdpTransport>,
        shutdown: ShutdownSignal,
        stats: Arc<ServerStats>,
        sip_stack: Arc<SipStack>,
    ) {
        debug!(transport_idx = idx, "Starting transport receive loop");

        loop {
            tokio::select! {
                result = transport.recv() => {
                    match result {
                        Ok(msg) => {
                            stats.messages_received.fetch_add(1, Ordering::Relaxed);
                            debug!(
                                source = %msg.source,
                                size = msg.data.len(),
                                transport = ?msg.transport,
                                "Received message"
                            );

                            // Process through SIP stack
                            let result = sip_stack.process_message(&msg.data, msg.source.clone()).await;

                            // Handle the processing result
                            match result {
                                ProcessResult::Response { message, destination } => {
                                    let response_bytes = message.to_bytes();
                                    if let Err(e) = transport.send(&response_bytes, &destination).await {
                                        warn!(error = %e, "Failed to send response");
                                    } else {
                                        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                                        debug!(destination = %destination, "Response sent");
                                    }
                                }
                                ProcessResult::Forward { message, destination } => {
                                    let request_bytes = message.to_bytes();
                                    if let Err(e) = transport.send(&request_bytes, &destination).await {
                                        warn!(error = %e, "Failed to forward request");
                                    } else {
                                        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                                        debug!(destination = %destination, "Request forwarded");
                                    }
                                }
                                ProcessResult::NoAction => {
                                    debug!("No action required for message");
                                }
                                ProcessResult::Error { reason } => {
                                    warn!(reason = %reason, "Error processing message");
                                }
                            }
                        }
                        Err(e) => {
                            if shutdown.is_shutdown_requested() {
                                break;
                            }
                            warn!(error = %e, "Transport receive error");
                        }
                    }
                }
                _ = shutdown.wait_for_shutdown() => {
                    debug!(transport_idx = idx, "Transport receive loop shutting down");
                    break;
                }
            }
        }
    }

    /// Health check polling loop.
    async fn health_poll_loop(shutdown: ShutdownSignal, interval: tokio::time::Duration) {
        let mut interval_timer = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    debug!("Health check poll");
                    // In production, would run actual health checks here
                }
                _ = shutdown.wait_for_shutdown() => {
                    debug!("Health poll loop shutting down");
                    break;
                }
            }
        }
    }

    /// Stops the server gracefully.
    pub async fn stop(&mut self) -> Result<(), ServerError> {
        info!("Stopping SBC daemon");

        // Close all transports
        let transports = self.udp_transports.read().await;
        for transport in transports.iter() {
            if let Err(e) = transport.close().await {
                warn!(error = %e, "Error closing transport");
            }
        }

        info!(
            messages_received = self.stats.messages_received.load(Ordering::Relaxed),
            messages_sent = self.stats.messages_sent.load(Ordering::Relaxed),
            "SBC daemon stopped"
        );
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
    /// Messages received.
    pub messages_received: AtomicU64,
    /// Messages sent.
    pub messages_sent: AtomicU64,
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

        assert_eq!(server.config().general.instance_name, "sbc-01");
    }

    #[tokio::test]
    async fn test_server_health() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let mut server = Server::new(config, shutdown);

        assert!(server.is_alive());
        assert!(server.is_ready());

        let health = server.check_health();
        assert!(health.is_healthy());
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown);

        assert_eq!(server.stats().calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(server.stats().messages_received.load(Ordering::Relaxed), 0);

        server.stats().messages_received.fetch_add(1, Ordering::Relaxed);
        assert_eq!(server.stats().messages_received.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_sbc_socket_addr_conversion() {
        // Test that SocketAddr converts to SbcSocketAddr correctly
        let socket_addr: std::net::SocketAddr = "[::]:5060".parse().unwrap();
        let sbc_addr = SbcSocketAddr::from(socket_addr);
        assert_eq!(sbc_addr.port(), 5060);

        let socket_addr: std::net::SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let sbc_addr = SbcSocketAddr::from(socket_addr);
        assert_eq!(sbc_addr.port(), 5060);
    }
}
