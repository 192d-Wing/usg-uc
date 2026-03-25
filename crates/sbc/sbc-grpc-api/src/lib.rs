//! # SBC gRPC API
//!
//! gRPC API protocol definitions for SBC management.
//!
//! This crate provides generated Rust types and gRPC service traits
//! for the SBC management API, enabling enterprise-level control
//! of the Session Border Controller via gRPC.
//!
//! ## Services
//!
//! - [`ConfigService`](sbc::config_service_server::ConfigService) - Configuration management
//! - [`CallService`](sbc::call_service_server::CallService) - Call monitoring and control
//! - [`RegistrationService`](sbc::registration_service_server::RegistrationService) - Registration management
//! - [`SystemService`](sbc::system_service_server::SystemService) - System operations
//! - [`ClusterService`](sbc::cluster_service_server::ClusterService) - Cluster management (feature-gated)
//! - [`Health`](health::health_server::Health) - Standard gRPC health checking
//!
//! ## Usage
//!
//! ### Server Implementation
//!
//! ```ignore
//! use sbc_grpc_api::sbc::config_service_server::{ConfigService, ConfigServiceServer};
//! use sbc_grpc_api::sbc::{GetConfigRequest, GetConfigResponse};
//! use tonic::{Request, Response, Status};
//!
//! #[derive(Debug, Default)]
//! pub struct MyConfigService;
//!
//! #[tonic::async_trait]
//! impl ConfigService for MyConfigService {
//!     async fn get_config(
//!         &self,
//!         request: Request<GetConfigRequest>,
//!     ) -> Result<Response<GetConfigResponse>, Status> {
//!         // Implementation
//!         todo!()
//!     }
//!     // ... other methods
//! }
//! ```
//!
//! ### Client Usage
//!
//! ```ignore
//! use sbc_grpc_api::sbc::config_service_client::ConfigServiceClient;
//! use sbc_grpc_api::sbc::GetConfigRequest;
//!
//! async fn get_config() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = ConfigServiceClient::connect("http://[::1]:9090").await?;
//!     let response = client.get_config(GetConfigRequest::default()).await?;
//!     println!("Config: {}", response.into_inner().config);
//!     Ok(())
//! }
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CM-2**: Baseline Configuration (ConfigService)
//! - **CM-6**: Configuration Settings (ConfigService)
//! - **AU-2**: Event Logging (CallService)
//! - **AC-2**: Account Management (RegistrationService)
//! - **SC-12**: Cryptographic Key Management (SystemService TLS operations)
//! - **SC-24**: Fail in Known State (ClusterService)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
// Allow clippy warnings in generated code
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]

/// SBC management API service definitions.
///
/// This module contains all SBC-specific services:
/// - `ConfigService` - Configuration CRUD operations
/// - `CallService` - Call monitoring and termination
/// - `RegistrationService` - SIP registration management
/// - `SystemService` - System-level operations (version, stats, TLS)
/// - `ClusterService` - Cluster management (requires `cluster` feature)
///
/// File descriptor set for gRPC reflection service.
///
/// This constant contains the serialized protobuf file descriptors for all
/// SBC services. It is used by the gRPC reflection service to allow clients
/// to discover available services and methods at runtime.
///
/// # Usage
///
/// ```ignore
/// use sbc_grpc_api::FILE_DESCRIPTOR_SET;
/// use tonic_reflection::server::Builder;
///
/// let reflection_service = Builder::configure()
///     .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
///     .build_v1()?;
/// ```
#[cfg(feature = "reflection")]
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("sbc_descriptor");

#[allow(
    missing_docs,
    clippy::default_trait_access,
    clippy::missing_const_for_fn,
    clippy::too_many_lines,
    clippy::too_long_first_doc_paragraph,
    clippy::struct_excessive_bools
)]
pub mod sbc {
    tonic::include_proto!("sbc.api.v1");
}

/// Standard gRPC health checking protocol.
///
/// This module implements the standard gRPC health checking protocol
/// as defined in <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>.
///
/// The health service is used by:
/// - Load balancers to route traffic
/// - Kubernetes for liveness/readiness probes
/// - Monitoring systems to track service health
#[allow(
    missing_docs,
    clippy::default_trait_access,
    clippy::missing_const_for_fn,
    clippy::too_many_lines,
    clippy::too_long_first_doc_paragraph,
    clippy::struct_excessive_bools
)]
pub mod health {
    tonic::include_proto!("grpc.health.v1");
}

/// Re-export commonly used types for convenience.
pub mod prelude {
    // Config service
    pub use super::sbc::config_service_client::ConfigServiceClient;
    pub use super::sbc::config_service_server::{ConfigService, ConfigServiceServer};
    pub use super::sbc::{
        GetConfigRequest, GetConfigResponse, ReloadConfigRequest, ReloadConfigResponse,
        UpdateConfigRequest, UpdateConfigResponse, ValidateConfigRequest, ValidateConfigResponse,
        ValidationError,
    };

    // Call service
    pub use super::sbc::call_service_client::CallServiceClient;
    pub use super::sbc::call_service_server::{CallService, CallServiceServer};
    pub use super::sbc::{
        CallEvent, CallInfo, CallLegInfo, CallState, GetCallRequest, GetCallResponse,
        GetCallStatsRequest, GetCallStatsResponse, ListCallsRequest, ListCallsResponse,
        TerminateCallRequest, TerminateCallResponse, WatchCallsRequest,
    };

    // Registration service
    pub use super::sbc::registration_service_client::RegistrationServiceClient;
    pub use super::sbc::registration_service_server::{
        RegistrationService, RegistrationServiceServer,
    };
    pub use super::sbc::{
        ContactInfo, DeleteRegistrationRequest, DeleteRegistrationResponse, GetRegistrationRequest,
        GetRegistrationResponse, GetRegistrationStatsRequest, GetRegistrationStatsResponse,
        ListRegistrationsRequest, ListRegistrationsResponse, RegistrationInfo,
    };

    // System service
    pub use super::sbc::system_service_client::SystemServiceClient;
    pub use super::sbc::system_service_server::{SystemService, SystemServiceServer};
    pub use super::sbc::{
        GetMetricsRequest, GetMetricsResponse, GetStatsRequest, GetStatsResponse,
        GetTlsStatusRequest, GetTlsStatusResponse, GetVersionRequest, GetVersionResponse,
        ReloadTlsRequest, ReloadTlsResponse, ShutdownRequest, ShutdownResponse, TlsStatus,
    };

    // Cluster service (feature-gated)
    #[cfg(feature = "cluster")]
    pub use super::sbc::cluster_service_client::ClusterServiceClient;
    #[cfg(feature = "cluster")]
    pub use super::sbc::cluster_service_server::{ClusterService, ClusterServiceServer};
    #[cfg(feature = "cluster")]
    pub use super::sbc::{
        ClusterEvent, ClusterHealth, DrainNodeRequest, DrainNodeResponse, GetClusterStatusRequest,
        GetClusterStatusResponse, GetNodeStatusRequest, GetNodeStatusResponse, HealthCheckDetail,
        InitiateFailoverRequest, InitiateFailoverResponse, ListNodesRequest, ListNodesResponse,
        NodeInfo, NodeMetrics, NodeRole, NodeState, UndoFailoverRequest, UndoFailoverResponse,
        WatchClusterRequest,
    };

    // Health service
    pub use super::health::health_check_response::ServingStatus;
    pub use super::health::health_client::HealthClient;
    pub use super::health::health_server::{Health, HealthServer};
    pub use super::health::{HealthCheckRequest, HealthCheckResponse};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbc_module_exists() {
        // Verify that the sbc module compiles and basic types exist
        let _ = sbc::GetConfigRequest::default();
        let _ = sbc::GetVersionRequest::default();
        let _ = sbc::ListCallsRequest::default();
        let _ = sbc::ListRegistrationsRequest::default();
    }

    #[test]
    fn test_health_module_exists() {
        // Verify that the health module compiles
        let _ = health::HealthCheckRequest::default();
        let req = health::HealthCheckRequest {
            service: "test".to_string(),
        };
        assert_eq!(req.service, "test");
    }

    #[test]
    fn test_call_state_enum() {
        assert_eq!(sbc::CallState::Unspecified as i32, 0);
        assert_eq!(sbc::CallState::Initial as i32, 1);
        assert_eq!(sbc::CallState::Early as i32, 2);
        assert_eq!(sbc::CallState::Confirmed as i32, 3);
        assert_eq!(sbc::CallState::Terminated as i32, 4);
    }

    #[test]
    fn test_serving_status_enum() {
        use health::health_check_response::ServingStatus;
        assert_eq!(ServingStatus::Unknown as i32, 0);
        assert_eq!(ServingStatus::Serving as i32, 1);
        assert_eq!(ServingStatus::NotServing as i32, 2);
        assert_eq!(ServingStatus::ServiceUnknown as i32, 3);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn test_cluster_module_exists() {
        let _ = sbc::GetClusterStatusRequest::default();
        let _ = sbc::ListNodesRequest::default();
        assert_eq!(sbc::NodeRole::Unspecified as i32, 0);
        assert_eq!(sbc::NodeRole::Primary as i32, 1);
        assert_eq!(sbc::NodeState::Active as i32, 2);
    }
}
