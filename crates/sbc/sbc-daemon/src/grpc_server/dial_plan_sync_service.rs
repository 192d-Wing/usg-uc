//! DialPlanSyncService gRPC implementation.
//!
//! Same shape as TrunkSyncService: pulls the current plan body from
//! Postgres and calls `sync_dial_plan_to_router` so the router ends up
//! in sync. Removal clears the plan from `SbcRouter` directly via the
//! same path the REST `delete_dial_plan_entry` handler uses when a plan
//! goes empty.

use std::sync::Arc;

use sbc_grpc_api::sbc::dial_plan_sync_service_server::DialPlanSyncService;
use sbc_grpc_api::sbc::{
    RemoveDialPlanRequest, RemoveDialPlanResponse, SyncDialPlanRequest, SyncDialPlanResponse,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::api_server::AppState;

pub struct DialPlanSyncServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for DialPlanSyncServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialPlanSyncServiceImpl")
            .finish_non_exhaustive()
    }
}

impl DialPlanSyncServiceImpl {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl DialPlanSyncService for DialPlanSyncServiceImpl {
    async fn sync_dial_plan(
        &self,
        request: Request<SyncDialPlanRequest>,
    ) -> Result<Response<SyncDialPlanResponse>, Status> {
        let req = request.into_inner();
        let plan_id = req.plan_id;
        info!(plan_id, "gRPC SyncDialPlan");

        let store = self.state.dial_plan_store.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "DialPlanSyncService requires Postgres (SBC_POSTGRES_URL unset)",
            )
        })?;

        match store.get(&plan_id).await {
            Ok(doc) => {
                let entries: Vec<serde_json::Value> = doc
                    .get("entries")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let entry_count = entries.len();
                crate::api_server::sync_dial_plan_to_router(&self.state, &plan_id, &entries).await;
                Ok(Response::new(SyncDialPlanResponse {
                    synced: true,
                    message: format!("synced {entry_count} entries to SIP router"),
                }))
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => {
                Ok(Response::new(SyncDialPlanResponse {
                    synced: false,
                    message: format!("no such dial plan: {plan_id}"),
                }))
            }
            Err(e) => {
                warn!(plan_id, error = %e, "dial_plan_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_dial_plan(
        &self,
        request: Request<RemoveDialPlanRequest>,
    ) -> Result<Response<RemoveDialPlanResponse>, Status> {
        let req = request.into_inner();
        let plan_id = req.plan_id;
        info!(plan_id, "gRPC RemoveDialPlan");

        if let Some(ref sip_stack) = self.state.sip_stack
            && let Some(router_lock) = sip_stack.router()
        {
            let mut router = router_lock.write().await;
            router.remove_dial_plan(&plan_id);
        }
        Ok(Response::new(RemoveDialPlanResponse {
            success: true,
            message: "removed from SIP router".to_string(),
        }))
    }
}
