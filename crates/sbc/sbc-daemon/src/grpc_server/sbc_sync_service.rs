//! SbcSyncService gRPC implementation (PR11).
//!
//! Receives "partition / CSS / route-pattern / route-list X changed in
//! Postgres" notifications from sbc-api and re-applies the row to the
//! live [`uc_routing::SbcRouter`]. Same shape as `TrunkSyncService` and
//! `DialPlanSyncService`: ID-only RPC, daemon re-reads from Postgres,
//! calls the relevant `apply_*_to_router` helper in [`api_server`].
//!
//! Returns `FailedPrecondition` when the matching store is `None`
//! (no Postgres DSN — legacy single-pod path) so callers see a clear
//! reason rather than a silent no-op.

use std::sync::Arc;

use sbc_grpc_api::sbc::sbc_sync_service_server::SbcSyncService;
use sbc_grpc_api::sbc::{
    RemoveCallingSearchSpaceRequest, RemovePartitionRequest, RemoveRouteListRequest,
    RemoveRoutePatternRequest, SyncCallingSearchSpaceRequest, SyncSbcResponse,
    SyncPartitionRequest, SyncRouteListRequest, SyncRoutePatternRequest,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::api_server::{
    AppState, apply_css_to_router, apply_partition_to_router, apply_route_list_to_router,
    apply_route_pattern_to_router,
};

pub struct SbcSyncServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for SbcSyncServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SbcSyncServiceImpl")
            .finish_non_exhaustive()
    }
}

impl SbcSyncServiceImpl {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

fn precondition(svc: &str) -> Status {
    Status::failed_precondition(format!("{svc} requires Postgres (SBC_POSTGRES_URL unset)"))
}

#[tonic::async_trait]
impl SbcSyncService for SbcSyncServiceImpl {
    async fn sync_partition(
        &self,
        request: Request<SyncPartitionRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().partition_id;
        info!(partition_id = %id, "gRPC SyncPartition");
        let store = self
            .state
            .partition_store
            .as_ref()
            .ok_or_else(|| precondition("SbcSyncService"))?;
        match store.get(&id).await {
            Ok(body) => {
                apply_partition_to_router(&self.state, &body).await;
                Ok(Response::new(SyncSbcResponse {
                    synced: true,
                    message: "partition applied to SbcRouter".to_string(),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncSbcResponse {
                    synced: false,
                    message: format!("no such partition: {id}"),
                }))
            }
            Err(e) => {
                warn!(partition_id = %id, error = %e, "partition_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_partition(
        &self,
        request: Request<RemovePartitionRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().partition_id;
        info!(partition_id = %id, "gRPC RemovePartition");
        if let Some(ref router) = self.state.sbc_router {
            router.write().await.remove_partition(&id);
        }
        Ok(Response::new(SyncSbcResponse {
            synced: true,
            message: "partition removed from SbcRouter".to_string(),
        }))
    }

    async fn sync_calling_search_space(
        &self,
        request: Request<SyncCallingSearchSpaceRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().css_id;
        info!(css_id = %id, "gRPC SyncCallingSearchSpace");
        let store = self
            .state
            .css_store
            .as_ref()
            .ok_or_else(|| precondition("SbcSyncService"))?;
        match store.get(&id).await {
            Ok(body) => {
                apply_css_to_router(&self.state, &body).await;
                Ok(Response::new(SyncSbcResponse {
                    synced: true,
                    message: "CSS applied to SbcRouter".to_string(),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncSbcResponse {
                    synced: false,
                    message: format!("no such CSS: {id}"),
                }))
            }
            Err(e) => {
                warn!(css_id = %id, error = %e, "css_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_calling_search_space(
        &self,
        request: Request<RemoveCallingSearchSpaceRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().css_id;
        info!(css_id = %id, "gRPC RemoveCallingSearchSpace");
        if let Some(ref router) = self.state.sbc_router {
            router.write().await.remove_css(&id);
        }
        Ok(Response::new(SyncSbcResponse {
            synced: true,
            message: "CSS removed from SbcRouter".to_string(),
        }))
    }

    async fn sync_route_pattern(
        &self,
        request: Request<SyncRoutePatternRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().pattern_id;
        info!(pattern_id = %id, "gRPC SyncRoutePattern");
        let store = self
            .state
            .route_pattern_store
            .as_ref()
            .ok_or_else(|| precondition("SbcSyncService"))?;
        match store.get(&id).await {
            Ok(body) => {
                apply_route_pattern_to_router(&self.state, &body).await;
                Ok(Response::new(SyncSbcResponse {
                    synced: true,
                    message: "route pattern applied to SbcRouter".to_string(),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncSbcResponse {
                    synced: false,
                    message: format!("no such route pattern: {id}"),
                }))
            }
            Err(e) => {
                warn!(pattern_id = %id, error = %e, "route_pattern_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_route_pattern(
        &self,
        request: Request<RemoveRoutePatternRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().pattern_id;
        info!(pattern_id = %id, "gRPC RemoveRoutePattern");
        if let Some(ref router) = self.state.sbc_router {
            router.write().await.remove_route_pattern(&id);
        }
        Ok(Response::new(SyncSbcResponse {
            synced: true,
            message: "route pattern removed from SbcRouter".to_string(),
        }))
    }

    async fn sync_route_list(
        &self,
        request: Request<SyncRouteListRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().list_id;
        info!(list_id = %id, "gRPC SyncRouteList");
        let store = self
            .state
            .route_list_store
            .as_ref()
            .ok_or_else(|| precondition("SbcSyncService"))?;
        match store.get(&id).await {
            Ok(body) => {
                apply_route_list_to_router(&self.state, &body).await;
                Ok(Response::new(SyncSbcResponse {
                    synced: true,
                    message: "route list applied to SbcRouter".to_string(),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncSbcResponse {
                    synced: false,
                    message: format!("no such route list: {id}"),
                }))
            }
            Err(e) => {
                warn!(list_id = %id, error = %e, "route_list_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_route_list(
        &self,
        request: Request<RemoveRouteListRequest>,
    ) -> Result<Response<SyncSbcResponse>, Status> {
        let id = request.into_inner().list_id;
        info!(list_id = %id, "gRPC RemoveRouteList");
        if let Some(ref router) = self.state.sbc_router {
            router.write().await.remove_route_list(&id);
        }
        Ok(Response::new(SyncSbcResponse {
            synced: true,
            message: "route list removed from SbcRouter".to_string(),
        }))
    }
}
