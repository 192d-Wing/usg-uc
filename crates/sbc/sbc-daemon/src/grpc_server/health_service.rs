//! Standard gRPC health checking service implementation.
//!
//! Implements the standard gRPC health checking protocol as defined in:
//! <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>

use crate::api_server::AppState;
use sbc_grpc_api::health::health_check_response::ServingStatus;
use sbc_grpc_api::health::health_server::Health;
use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::debug;

/// Health service implementation.
pub struct HealthServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for HealthServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthServiceImpl").finish_non_exhaustive()
    }
}

impl HealthServiceImpl {
    /// Creates a new Health service implementation.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Gets the serving status for a service.
    fn get_status(&self, service: &str) -> ServingStatus {
        if service.is_empty() {
            // Empty service name means overall server health
            if self.state.is_ready() {
                ServingStatus::Serving
            } else {
                ServingStatus::NotServing
            }
        } else {
            // Check specific service
            match service {
                "sbc.api.v1.ConfigService"
                | "sbc.api.v1.SystemService"
                | "sbc.api.v1.CallService"
                | "sbc.api.v1.RegistrationService" => {
                    if self.state.is_ready() {
                        ServingStatus::Serving
                    } else {
                        ServingStatus::NotServing
                    }
                }
                "sbc.api.v1.ClusterService" => {
                    // Cluster service only available if cluster feature is enabled
                    #[cfg(feature = "cluster")]
                    {
                        if self.state.is_ready() {
                            ServingStatus::Serving
                        } else {
                            ServingStatus::NotServing
                        }
                    }
                    #[cfg(not(feature = "cluster"))]
                    {
                        ServingStatus::ServiceUnknown
                    }
                }
                _ => ServingStatus::ServiceUnknown,
            }
        }
    }
}

#[tonic::async_trait]
impl Health for HealthServiceImpl {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let req = request.into_inner();
        debug!(service = %req.service, "gRPC Health Check");

        let status = self.get_status(&req.service);
        let response = HealthCheckResponse {
            status: status.into(),
        };

        Ok(Response::new(response))
    }

    type WatchStream =
        Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send + 'static>>;

    async fn watch(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        debug!(service = %req.service, "gRPC Health Watch");

        // For now, return a stream that sends the current status once
        // A full implementation would monitor for status changes
        let status = self.get_status(&req.service);

        let stream = tokio_stream::once(Ok(HealthCheckResponse {
            status: status.into(),
        }));

        Ok(Response::new(Box::pin(stream)))
    }
}
