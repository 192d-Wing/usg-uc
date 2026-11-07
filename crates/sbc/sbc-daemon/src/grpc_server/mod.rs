//! gRPC API server for the SBC daemon.
//!
//! This module provides a gRPC server using tonic for enterprise management APIs.
//! It coexists with the REST API server on a different port (default 9090).
//!
//! ## Services
//!
//! - `ConfigService` - Configuration management
//! - `CallService` - Call monitoring and control
//! - `CdrService` - Recent Call Detail Records (read-only ring)
//! - `RegistrationService` - Registration management
//! - `SystemService` - System operations
//! - `TrunkSyncService` - "Trunk group X changed in Postgres; please re-sync"
//!   notification API used by sbc-api (PR5+). Returns FailedPrecondition
//!   when SBC_POSTGRES_URL is unset.
//! - `DialPlanSyncService` - Same shape as TrunkSyncService, for dial plans.
//! - `DidMappingSyncService` - Same shape, for DID→user mappings.
//! - `SbcSyncService` - Same shape, for partitions / CSS / route patterns /
//!   route lists (PR11).
//! - `ClusterService` - Cluster management (requires `cluster` feature)
//! - `Health` - Standard gRPC health checking
//! - `ServerReflection` - gRPC reflection service (requires `grpc-reflection` feature)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - All API requests are logged
//! - **SC-8**: Transmission Confidentiality (TLS supported)
//! - **SC-13**: Cryptographic Protection (CNSA 2.0 compliant TLS)
//! - **IA-3**: Device Identification (mTLS support)

mod call_service;
mod cdr_service;
#[cfg(feature = "cluster")]
mod cluster_service;
mod config_service;
mod dial_plan_sync_service;
mod did_mapping_sync_service;
mod health_service;
#[cfg(test)]
mod mtls_handshake_tests;
mod peer_identity;
mod registration_service;
mod sbc_sync_service;
mod system_service;
mod trunk_health_service;
mod trunk_status_publish_service;
mod trunk_sync_service;

use crate::api_server::AppState;
#[cfg(feature = "cluster")]
use crate::cluster::ClusterManager;
use crate::shutdown::ShutdownSignal;
use sbc_config::schema::GrpcConfig;
use sbc_grpc_api::health::health_server::HealthServer;
use sbc_grpc_api::sbc::call_service_server::CallServiceServer;
use sbc_grpc_api::sbc::cdr_service_server::CdrServiceServer;
#[cfg(feature = "cluster")]
use sbc_grpc_api::sbc::cluster_service_server::ClusterServiceServer;
use sbc_grpc_api::sbc::config_service_server::ConfigServiceServer;
use sbc_grpc_api::sbc::dial_plan_sync_service_server::DialPlanSyncServiceServer;
use sbc_grpc_api::sbc::did_mapping_sync_service_server::DidMappingSyncServiceServer;
use sbc_grpc_api::sbc::registration_service_server::RegistrationServiceServer;
use sbc_grpc_api::sbc::sbc_sync_service_server::SbcSyncServiceServer;
use sbc_grpc_api::sbc::system_service_server::SystemServiceServer;
use sbc_grpc_api::sbc::trunk_health_service_server::TrunkHealthServiceServer;
use sbc_grpc_api::sbc::trunk_status_publish_service_server::TrunkStatusPublishServiceServer;
use sbc_grpc_api::sbc::trunk_sync_service_server::TrunkSyncServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tracing::{info, warn};

pub use call_service::CallServiceImpl;
pub use cdr_service::CdrServiceImpl;
#[cfg(feature = "cluster")]
pub use cluster_service::ClusterServiceImpl;
pub use config_service::ConfigServiceImpl;
pub use dial_plan_sync_service::DialPlanSyncServiceImpl;
pub use did_mapping_sync_service::DidMappingSyncServiceImpl;
pub use health_service::HealthServiceImpl;
pub use peer_identity::{ClientCertGate, PeerPrincipal};
pub use registration_service::RegistrationServiceImpl;
pub use sbc_sync_service::SbcSyncServiceImpl;
pub use system_service::SystemServiceImpl;
pub use trunk_health_service::TrunkHealthServiceImpl;
pub use trunk_status_publish_service::TrunkStatusPublishServiceImpl;
pub use trunk_sync_service::TrunkSyncServiceImpl;

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
            reflection = self.config.enable_reflection,
            "Starting gRPC server"
        );

        // Create service implementations
        let config_svc = ConfigServiceImpl::new(Arc::clone(&self.state));
        let system_svc = SystemServiceImpl::new(Arc::clone(&self.state));
        let health_svc = HealthServiceImpl::new(Arc::clone(&self.state));
        let call_svc = CallServiceImpl::new(Arc::clone(&self.state));
        let registration_svc = RegistrationServiceImpl::new(Arc::clone(&self.state));
        // Sync services used by sbc-api (and other Postgres-aware
        // writers) to push "I changed entity X" notifications back to
        // the daemon so it can re-read from Postgres and refresh the
        // SIP router. Always mounted; each service returns
        // FailedPrecondition when no Postgres DSN is configured.
        let trunk_sync_svc = TrunkSyncServiceImpl::new(Arc::clone(&self.state));
        let dial_plan_sync_svc = DialPlanSyncServiceImpl::new(Arc::clone(&self.state));
        let did_mapping_sync_svc = DidMappingSyncServiceImpl::new(Arc::clone(&self.state));
        let trunk_health_svc = TrunkHealthServiceImpl::new(Arc::clone(&self.state));
        // Write-side: the sbc-trunk-agent pod pushes trunk status
        // snapshots here when trunk services run externally.
        let trunk_status_publish_svc = TrunkStatusPublishServiceImpl::new(Arc::clone(&self.state));
        let sbc_sync_svc = SbcSyncServiceImpl::new(Arc::clone(&self.state));
        // Read-only CDR ring queries. CDRs carry PII and this listener has
        // no per-RPC authorization, so the service is mounted only when
        // every caller is authenticated (mTLS) or local (loopback).
        let cdr_svc = cdr_service_permitted(&self.config)
            .then(|| CdrServiceServer::new(CdrServiceImpl::new(Arc::clone(&self.state))));

        // Configure TLS if enabled
        let tls_config = self.configure_tls()?;

        // NIST 800-53 Rev5: AC-3, IA-3 — under mTLS every RPC (all services)
        // must come from a certificate on grpc.allowed_client_names.
        let gate = client_cert_gate(&self.config);

        // Build the server with or without TLS
        let mut server = if let Some(tls) = tls_config {
            info!("gRPC server TLS enabled");
            Server::builder()
                .tls_config(tls)
                .map_err(|e| GrpcServerError::TlsError {
                    reason: e.to_string(),
                })?
                .layer(tonic::service::InterceptorLayer::new(gate))
        } else {
            warn!("gRPC server running WITHOUT TLS - not recommended for production");
            Server::builder().layer(tonic::service::InterceptorLayer::new(gate))
        };

        // Build router with core services (no cluster, no reflection)
        #[cfg(all(not(feature = "cluster"), not(feature = "grpc-reflection")))]
        let router = server
            .add_service(ConfigServiceServer::new(config_svc))
            .add_service(SystemServiceServer::new(system_svc))
            .add_service(HealthServer::new(health_svc))
            .add_service(CallServiceServer::new(call_svc))
            .add_service(RegistrationServiceServer::new(registration_svc))
            .add_service(TrunkSyncServiceServer::new(trunk_sync_svc))
            .add_service(DialPlanSyncServiceServer::new(dial_plan_sync_svc))
            .add_service(DidMappingSyncServiceServer::new(did_mapping_sync_svc))
            .add_service(TrunkHealthServiceServer::new(trunk_health_svc))
            .add_service(TrunkStatusPublishServiceServer::new(
                trunk_status_publish_svc,
            ))
            .add_service(SbcSyncServiceServer::new(sbc_sync_svc))
            .add_optional_service(cdr_svc);

        // Build router with reflection but no cluster
        #[cfg(all(not(feature = "cluster"), feature = "grpc-reflection"))]
        let router = {
            let base = server
                .add_service(ConfigServiceServer::new(config_svc))
                .add_service(SystemServiceServer::new(system_svc))
                .add_service(HealthServer::new(health_svc))
                .add_service(CallServiceServer::new(call_svc))
                .add_service(RegistrationServiceServer::new(registration_svc))
                .add_service(TrunkSyncServiceServer::new(trunk_sync_svc))
                .add_service(DialPlanSyncServiceServer::new(dial_plan_sync_svc))
                .add_service(DidMappingSyncServiceServer::new(did_mapping_sync_svc))
                .add_service(TrunkHealthServiceServer::new(trunk_health_svc))
                .add_service(SbcSyncServiceServer::new(sbc_sync_svc))
                .add_optional_service(cdr_svc);

            // Add reflection service if enabled in config
            if self.config.enable_reflection {
                let reflection_svc = tonic_reflection::server::Builder::configure()
                    .register_encoded_file_descriptor_set(sbc_grpc_api::FILE_DESCRIPTOR_SET)
                    .build_v1()
                    .map_err(|e| GrpcServerError::ServerError {
                        reason: format!("Failed to build reflection service: {e}"),
                    })?;
                info!("gRPC reflection service enabled");
                base.add_service(reflection_svc)
            } else {
                base
            }
        };

        // Build router with cluster but no reflection
        #[cfg(all(feature = "cluster", not(feature = "grpc-reflection")))]
        let router = {
            let base = server
                .add_service(ConfigServiceServer::new(config_svc))
                .add_service(SystemServiceServer::new(system_svc))
                .add_service(HealthServer::new(health_svc))
                .add_service(CallServiceServer::new(call_svc))
                .add_service(RegistrationServiceServer::new(registration_svc))
                .add_service(TrunkSyncServiceServer::new(trunk_sync_svc))
                .add_service(DialPlanSyncServiceServer::new(dial_plan_sync_svc))
                .add_service(DidMappingSyncServiceServer::new(did_mapping_sync_svc))
                .add_service(TrunkHealthServiceServer::new(trunk_health_svc))
                .add_service(SbcSyncServiceServer::new(sbc_sync_svc))
                .add_optional_service(cdr_svc);

            // Add ClusterService if cluster manager is available
            if let Some(cluster) = &self.cluster {
                let cluster_svc =
                    ClusterServiceImpl::new(Arc::clone(&self.state), Arc::clone(cluster));
                info!("ClusterService enabled");
                base.add_service(ClusterServiceServer::new(cluster_svc))
            } else {
                base
            }
        };

        // Build router with both cluster and reflection
        #[cfg(all(feature = "cluster", feature = "grpc-reflection"))]
        let router = {
            let base = server
                .add_service(ConfigServiceServer::new(config_svc))
                .add_service(SystemServiceServer::new(system_svc))
                .add_service(HealthServer::new(health_svc))
                .add_service(CallServiceServer::new(call_svc))
                .add_service(RegistrationServiceServer::new(registration_svc))
                .add_service(TrunkSyncServiceServer::new(trunk_sync_svc))
                .add_service(DialPlanSyncServiceServer::new(dial_plan_sync_svc))
                .add_service(DidMappingSyncServiceServer::new(did_mapping_sync_svc))
                .add_service(TrunkHealthServiceServer::new(trunk_health_svc))
                .add_service(SbcSyncServiceServer::new(sbc_sync_svc))
                .add_optional_service(cdr_svc);

            // Add ClusterService if cluster manager is available
            let with_cluster = if let Some(cluster) = &self.cluster {
                let cluster_svc =
                    ClusterServiceImpl::new(Arc::clone(&self.state), Arc::clone(cluster));
                info!("ClusterService enabled");
                base.add_service(ClusterServiceServer::new(cluster_svc))
            } else {
                base
            };

            // Add reflection service if enabled in config
            if self.config.enable_reflection {
                let reflection_svc = tonic_reflection::server::Builder::configure()
                    .register_encoded_file_descriptor_set(sbc_grpc_api::FILE_DESCRIPTOR_SET)
                    .build_v1()
                    .map_err(|e| GrpcServerError::ServerError {
                        reason: format!("Failed to build reflection service: {e}"),
                    })?;
                info!("gRPC reflection service enabled");
                with_cluster.add_service(reflection_svc)
            } else {
                with_cluster
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
            // mTLS cannot be satisfied without a server certificate: refuse
            // to start rather than serve in plaintext.
            (None, None) if self.config.require_mtls => {
                return Err(GrpcServerError::TlsError {
                    reason: "require_mtls is true but tls_cert_path and tls_key_path are not set"
                        .to_string(),
                });
            }
            (None, None) => return Ok(None),
            _ => {
                return Err(GrpcServerError::TlsError {
                    reason: "Both tls_cert_path and tls_key_path must be specified".to_string(),
                });
            }
        };

        // Load server certificate and key
        let cert_pem =
            std::fs::read_to_string(cert_path).map_err(|e| GrpcServerError::TlsError {
                reason: format!("Failed to read certificate file: {e}"),
            })?;

        let key_pem = std::fs::read_to_string(key_path).map_err(|e| GrpcServerError::TlsError {
            reason: format!("Failed to read key file: {e}"),
        })?;

        let identity = Identity::from_pem(&cert_pem, &key_pem);

        let mut tls_config = ServerTlsConfig::new().identity(identity);

        // Configure mTLS if CA certificate is provided
        if let Some(ca_path) = &self.config.tls_ca_path {
            let ca_pem =
                std::fs::read_to_string(ca_path).map_err(|e| GrpcServerError::TlsError {
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

/// Builds the per-RPC client-certificate gate, warning at startup when mTLS
/// admits any certificate from the CA (empty `grpc.allowed_client_names`).
// POAM: SEC-9 (SC-13) the gRPC server and the sbc-api client use tonic's
// default rustls provider and suites (TLS 1.2/1.3, AES-128, X25519 allowed),
// not the uc-transport CNSA 2.0 profile; the P-384 keys alone do not make
// the negotiated suite CNSA compliant.
fn client_cert_gate(config: &GrpcConfig) -> ClientCertGate {
    if config.require_mtls && config.allowed_client_names.is_empty() {
        warn!(
            "grpc.require_mtls is set but grpc.allowed_client_names is empty: any client \
             certificate issued by grpc.tls_ca_path may call every gRPC service; set \
             grpc.allowed_client_names and use a dedicated issuer for this CA"
        );
    }
    ClientCertGate::new(config.require_mtls, &config.allowed_client_names)
}

/// Whether `CdrService` may be mounted on this listener: only when every
/// client is authenticated by certificate (`grpc.require_mtls`) or the
/// listener is bound to loopback. Otherwise it is not registered (clients
/// get `Unimplemented`) and a warning names the keys to change.
///
/// ## NIST 800-53 Rev5: AC-3 (Access Enforcement), SC-8, SI-12
fn cdr_service_permitted(config: &GrpcConfig) -> bool {
    if config.require_mtls || config.listen_addr.ip().is_loopback() {
        return true;
    }
    warn!(
        listen_addr = %config.listen_addr,
        "CdrService NOT mounted: CDRs carry PII and this gRPC listener is neither \
         mTLS-authenticated nor loopback. Set grpc.require_mtls = true (with \
         grpc.tls_cert_path, grpc.tls_key_path, grpc.tls_ca_path) or bind \
         grpc.listen_addr to 127.0.0.1/::1"
    );
    false
}

// Runs under every feature set (the module below is no-cluster only).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cdr_gate_tests {
    use super::*;

    #[test]
    fn cdr_service_only_on_mtls_or_loopback_listener() {
        // SEC-1: the default listener (0.0.0.0, no mTLS) must not serve PII.
        let default = GrpcConfig::default();
        assert!(!default.require_mtls && !default.listen_addr.ip().is_loopback());
        assert!(!cdr_service_permitted(&default));
        let public_v6 = GrpcConfig {
            listen_addr: "[::]:9091".parse().unwrap(),
            ..GrpcConfig::default()
        };
        assert!(!cdr_service_permitted(&public_v6));
        for addr in ["127.0.0.1:9091", "[::1]:9091"] {
            let local = GrpcConfig {
                listen_addr: addr.parse().unwrap(),
                ..GrpcConfig::default()
            };
            assert!(cdr_service_permitted(&local), "{addr}");
        }
        let mtls = GrpcConfig {
            require_mtls: true,
            ..GrpcConfig::default()
        };
        assert!(cdr_service_permitted(&mtls));
    }
}

#[cfg(all(test, not(feature = "cluster")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::server::ServerStats;
    use uc_metrics::SbcMetrics;

    fn server_with(config: GrpcConfig) -> GrpcServer {
        let state = Arc::new(AppState::new(
            SbcMetrics::standard(),
            Arc::new(ServerStats::default()),
        ));
        GrpcServer::new(config, state, ShutdownSignal::new())
    }

    #[test]
    fn require_mtls_without_certificate_is_an_error() {
        let config = GrpcConfig {
            require_mtls: true,
            ..GrpcConfig::default()
        };
        assert!(matches!(
            server_with(config).configure_tls(),
            Err(GrpcServerError::TlsError { .. })
        ));
    }

    #[test]
    fn no_tls_and_no_mtls_requirement_stays_plaintext() {
        let config = GrpcConfig::default();
        assert!(matches!(server_with(config).configure_tls(), Ok(None)));
    }
}
