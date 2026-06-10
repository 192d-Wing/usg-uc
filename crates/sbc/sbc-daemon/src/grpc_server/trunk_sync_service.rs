//! TrunkSyncService gRPC implementation.
//!
//! Receives "trunk group X changed in Postgres" notifications from
//! sbc-api (or any other writer) and re-runs the same sync helper the
//! REST handlers use, so the SIP router ends up with the current state.
//!
//! The whole point of this service is to keep sbc-api out of the
//! daemon's process — there's nothing here the daemon couldn't do
//! itself. When `trunk_group_store` is unset (legacy single-pod /
//! JSON-only deploys), every method returns `FailedPrecondition`: the
//! sync contract doesn't make sense without a shared Postgres.

use std::sync::Arc;

use sbc_grpc_api::sbc::trunk_sync_service_server::TrunkSyncService;
use sbc_grpc_api::sbc::{
    RemoveTrunkGroupRequest, RemoveTrunkGroupResponse, SyncTrunkGroupRequest,
    SyncTrunkGroupResponse,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::api_server::AppState;

/// TrunkSyncService implementation.
pub struct TrunkSyncServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for TrunkSyncServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrunkSyncServiceImpl")
            .finish_non_exhaustive()
    }
}

impl TrunkSyncServiceImpl {
    /// Create a new TrunkSyncService backed by the daemon's AppState.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl TrunkSyncService for TrunkSyncServiceImpl {
    async fn sync_trunk_group(
        &self,
        request: Request<SyncTrunkGroupRequest>,
    ) -> Result<Response<SyncTrunkGroupResponse>, Status> {
        let req = request.into_inner();
        let group_id = req.group_id;
        info!(group_id, "gRPC SyncTrunkGroup");

        let store = self.state.trunk_group_store.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "TrunkSyncService requires Postgres (SBC_POSTGRES_URL unset)",
            )
        })?;

        match store.get(&group_id).await {
            Ok(group_json) => {
                crate::api_server::sync_trunk_group_to_router(&self.state, &group_json).await;
                Ok(Response::new(SyncTrunkGroupResponse {
                    synced: true,
                    message: "synced to SIP router".to_string(),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncTrunkGroupResponse {
                    synced: false,
                    message: format!("no such trunk group: {group_id}"),
                }))
            }
            Err(e) => {
                warn!(group_id, error = %e, "trunk_group_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_trunk_group(
        &self,
        request: Request<RemoveTrunkGroupRequest>,
    ) -> Result<Response<RemoveTrunkGroupResponse>, Status> {
        let req = request.into_inner();
        let group_id = req.group_id;
        info!(group_id, "gRPC RemoveTrunkGroup");

        // Also clear from the CucmRouter for symmetry with the REST
        // delete handler — keeps both internal routers in step even
        // when only the SIP-stack sync was requested.
        if let Some(ref cucm) = self.state.cucm_router {
            cucm.write().await.remove_route_group(&group_id);
        }
        if let Some(ref sip_stack) = self.state.sip_stack {
            sip_stack.remove_trunk_group_from_router(&group_id).await;
        }
        Ok(Response::new(RemoveTrunkGroupResponse {
            success: true,
            message: "removed from SIP router".to_string(),
        }))
    }
}
