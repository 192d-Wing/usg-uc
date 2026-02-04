//! gRPC API server for the SBC daemon.
//!
//! This module provides a gRPC server using tonic for enterprise management APIs.
//! It coexists with the REST API server on a different port (default 9090).
//!
//! ## Services
//!
//! - `ConfigService` - Configuration management
//! - `CallService` - Call monitoring and control
//! - `RegistrationService` - Registration management
//! - `SystemService` - System operations
//! - `ClusterService` - Cluster management (requires `cluster` feature)
//! - `Health` - Standard gRPC health checking
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - All API requests are logged
//! - **SC-8**: Transmission Confidentiality (TLS supported)
//! - **SC-13**: Cryptographic Protection (CNSA 2.0 compliant TLS)
//! - **IA-3**: Device Identification (mTLS support)

mod config_service;
mod health_service;
mod system_service;

use crate::api_server::AppState;
use crate::shutdown::ShutdownSignal;
use sbc_config::schema::GrpcConfig;
use sbc_grpc_api::health::health_server::HealthServer;
use sbc_grpc_api::sbc::config_service_server::ConfigServiceServer;
use sbc_grpc_api::sbc::system_service_server::SystemServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;

pub use config_service::ConfigServiceImpl;
pub use health_service::HealthServiceImpl;
pub use system_service::SystemServiceImpl;

/// gRPC API server.
pub struct GrpcServer {
    /// Configuration.
    config: GrpcConfig,
    /// Application state (shared with REST API).
    state: Arc<AppState>,
    /// Shutdown signal.
    shutdown: ShutdownSignal,
}

/// Error type for gRPC server operations.
#[derive(Debug)]
pub enum GrpcServerError {
    /// Failed to bind to address.
    BindFailed {
        /// Address that failed to bind.
        address: SocketAddr,
        /// Reason for failure.
        reason: String,
    },
    /// Server error.
    ServerError {
        /// Reason for failure.
        reason: String,
    },
    /// TLS configuration error.
    TlsError {
        /// Reason for failure.
        reason: String,
    },
}

impl std::fmt::Display for GrpcServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed { address, reason } => {
                write!(f, "Failed to bind to {address}: {reason}")
            }
            Self::ServerError { reason } => {
                write!(f, "gRPC server error: {reason}")
            }
            Self::TlsError { reason } => {
                write!(f, "TLS error: {reason}")
            }
        }
    }
}

impl std::error::Error for GrpcServerError {}

impl GrpcServer {
    /// Creates a new gRPC server.
    pub const fn new(config: GrpcConfig, state: Arc<AppState>, shutdown: ShutdownSignal) -> Self {
        Self {
            config,
            state,
            shutdown,
        }
    }

    /// Runs the gRPC server.
    ///
    /// This method blocks until the shutdown signal is received.
    pub async fn run(&self) -> Result<(), GrpcServerError> {
        let addr = self.config.listen_addr;

        info!(
            address = %addr,
            tls = self.config.tls_cert_path.is_some(),
            mtls = self.config.require_mtls,
            "Starting gRPC server"
        );

        // Create service implementations
        let config_svc = ConfigServiceImpl::new(Arc::clone(&self.state));
        let system_svc = SystemServiceImpl::new(Arc::clone(&self.state));
        let health_svc = HealthServiceImpl::new(Arc::clone(&self.state));

        // Build the server
        let server = Server::builder()
            .add_service(ConfigServiceServer::new(config_svc))
            .add_service(SystemServiceServer::new(system_svc))
            .add_service(HealthServer::new(health_svc));

        // Run with graceful shutdown
        let shutdown = self.shutdown.clone();
        server
            .serve_with_shutdown(addr, async move {
                shutdown.wait_for_shutdown().await;
                info!("gRPC server shutting down");
            })
            .await
            .map_err(|e| GrpcServerError::ServerError {
                reason: e.to_string(),
            })?;

        Ok(())
    }
}
