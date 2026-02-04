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

mod call_service;
#[cfg(feature = "cluster")]
mod cluster_service;
mod config_service;
mod health_service;
mod registration_service;
mod system_service;

#[cfg(feature = "cluster")]
use crate::cluster::ClusterManager;
use crate::api_server::AppState;
use crate::shutdown::ShutdownSignal;
use sbc_config::schema::GrpcConfig;
use sbc_grpc_api::health::health_server::HealthServer;
use sbc_grpc_api::sbc::call_service_server::CallServiceServer;
use sbc_grpc_api::sbc::config_service_server::ConfigServiceServer;
use sbc_grpc_api::sbc::registration_service_server::RegistrationServiceServer;
use sbc_grpc_api::sbc::system_service_server::SystemServiceServer;
#[cfg(feature = "cluster")]
use sbc_grpc_api::sbc::cluster_service_server::ClusterServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tracing::{info, warn};

pub use call_service::CallServiceImpl;
#[cfg(feature = "cluster")]
pub use cluster_service::ClusterServiceImpl;
pub use config_service::ConfigServiceImpl;
pub use health_service::HealthServiceImpl;
pub use registration_service::RegistrationServiceImpl;
pub use system_service::SystemServiceImpl;

/// gRPC API server.
pub struct GrpcServer {
    /// Configuration.
    config: GrpcConfig,
    /// Application state (shared with REST API).
    state: Arc<AppState>,
    /// Shutdown signal.
    shutdown: ShutdownSignal,
    /// Cluster manager (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<ClusterManager>>,
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
    #[cfg(not(feature = "cluster"))]
    pub const fn new(config: GrpcConfig, state: Arc<AppState>, shutdown: ShutdownSignal) -> Self {
        Self {
            config,
            state,
            shutdown,
        }
    }

    /// Creates a new gRPC server with optional cluster support.
    #[cfg(feature = "cluster")]
    pub const fn new(
        config: GrpcConfig,
        state: Arc<AppState>,
        shutdown: ShutdownSignal,
        cluster: Option<Arc<ClusterManager>>,
    ) -> Self {
        Self {
            config,
            state,
            shutdown,
            cluster,
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
        let call_svc = CallServiceImpl::new(Arc::clone(&self.state));
        let registration_svc = RegistrationServiceImpl::new(Arc::clone(&self.state));

        // Configure TLS if enabled
        let tls_config = self.configure_tls()?;

        // Build the server with or without TLS
        let mut server = if let Some(tls) = tls_config {
            info!("gRPC server TLS enabled");
            Server::builder()
                .tls_config(tls)
                .map_err(|e| GrpcServerError::TlsError {
                    reason: e.to_string(),
                })?
        } else {
            warn!("gRPC server running WITHOUT TLS - not recommended for production");
            Server::builder()
        };

        // Build router with core services
        #[cfg(not(feature = "cluster"))]
        let router = server
            .add_service(ConfigServiceServer::new(config_svc))
            .add_service(SystemServiceServer::new(system_svc))
            .add_service(HealthServer::new(health_svc))
            .add_service(CallServiceServer::new(call_svc))
            .add_service(RegistrationServiceServer::new(registration_svc));

        // Build router with core services and optional cluster service
        #[cfg(feature = "cluster")]
        let router = {
            let base = server
                .add_service(ConfigServiceServer::new(config_svc))
                .add_service(SystemServiceServer::new(system_svc))
                .add_service(HealthServer::new(health_svc))
                .add_service(CallServiceServer::new(call_svc))
                .add_service(RegistrationServiceServer::new(registration_svc));

            // Add ClusterService if cluster manager is available
            if let Some(cluster) = &self.cluster {
                let cluster_svc = ClusterServiceImpl::new(Arc::clone(&self.state), Arc::clone(cluster));
                info!("ClusterService enabled");
                base.add_service(ClusterServiceServer::new(cluster_svc))
            } else {
                base
            }
        };

        // Run with graceful shutdown
        let shutdown = self.shutdown.clone();
        router
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

    /// Configures TLS for the gRPC server.
    ///
    /// Returns `None` if TLS is not configured, or a `ServerTlsConfig` if it is.
    fn configure_tls(&self) -> Result<Option<ServerTlsConfig>, GrpcServerError> {
        let (cert_path, key_path) = match (&self.config.tls_cert_path, &self.config.tls_key_path) {
            (Some(cert), Some(key)) => (cert, key),
            (None, None) => return Ok(None),
            _ => {
                return Err(GrpcServerError::TlsError {
                    reason: "Both tls_cert_path and tls_key_path must be specified".to_string(),
                });
            }
        };

        // Load server certificate and key
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| GrpcServerError::TlsError {
            reason: format!("Failed to read certificate file: {e}"),
        })?;

        let key_pem = std::fs::read_to_string(key_path).map_err(|e| GrpcServerError::TlsError {
            reason: format!("Failed to read key file: {e}"),
        })?;

        let identity = Identity::from_pem(&cert_pem, &key_pem);

        let mut tls_config = ServerTlsConfig::new().identity(identity);

        // Configure mTLS if CA certificate is provided
        if let Some(ca_path) = &self.config.tls_ca_path {
            let ca_pem = std::fs::read_to_string(ca_path).map_err(|e| GrpcServerError::TlsError {
                reason: format!("Failed to read CA certificate file: {e}"),
            })?;

            let ca_cert = Certificate::from_pem(&ca_pem);
            tls_config = tls_config.client_ca_root(ca_cert);

            if self.config.require_mtls {
                info!("gRPC server mTLS required - clients must present valid certificates");
            }
        } else if self.config.require_mtls {
            return Err(GrpcServerError::TlsError {
                reason: "require_mtls is true but tls_ca_path is not set".to_string(),
            });
        }

        Ok(Some(tls_config))
    }
}
