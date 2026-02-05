//! ConfigService gRPC implementation.
//!
//! Provides configuration management operations via gRPC.

use crate::api_server::AppState;
use sbc_grpc_api::sbc::config_service_server::ConfigService;
use sbc_grpc_api::sbc::{
    GetConfigRequest, GetConfigResponse, ReloadConfigRequest, ReloadConfigResponse,
    UpdateConfigRequest, UpdateConfigResponse, ValidateConfigRequest, ValidateConfigResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

/// ConfigService implementation.
pub struct ConfigServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for ConfigServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigServiceImpl").finish_non_exhaustive()
    }
}

impl ConfigServiceImpl {
    /// Creates a new ConfigService implementation.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ConfigService for ConfigServiceImpl {
    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let req = request.into_inner();
        info!(sections = ?req.sections, format = %req.format, "gRPC GetConfig");

        // TODO: Implement actual config retrieval
        // For now, return a placeholder response
        let response = GetConfigResponse {
            config: String::new(),
            format: if req.format.is_empty() {
                "json".to_string()
            } else {
                req.format
            },
            version: "1".to_string(),
            last_modified: 0,
        };

        Ok(Response::new(response))
    }

    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let req = request.into_inner();
        info!(
            format = %req.format,
            sections = ?req.sections,
            dry_run = req.dry_run,
            "gRPC UpdateConfig"
        );

        // TODO: Implement actual config update
        // For now, return not implemented
        Err(Status::unimplemented("UpdateConfig not yet implemented"))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let req = request.into_inner();
        info!(format = %req.format, "gRPC ValidateConfig");

        // TODO: Implement actual config validation using sbc_config::validate
        let response = ValidateConfigResponse {
            valid: true,
            errors: vec![],
            warnings: vec![],
        };

        Ok(Response::new(response))
    }

    async fn reload_config(
        &self,
        request: Request<ReloadConfigRequest>,
    ) -> Result<Response<ReloadConfigResponse>, Status> {
        let req = request.into_inner();
        info!(path = %req.path, "gRPC ReloadConfig");

        // TODO: Implement actual config reload
        // This would trigger the same reload logic as SIGHUP
        Err(Status::unimplemented("ReloadConfig not yet implemented"))
    }
}
