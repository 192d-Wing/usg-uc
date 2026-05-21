//! DidMappingSyncService gRPC implementation.
//!
//! Pulls the current DID record from Postgres and pushes the user
//! binding into the SIP stack's DID→user routing map. The REST handler
//! `add_directory_number` did this inline; gRPC does the same thing but
//! lets sbc-api (which writes Postgres) ask the daemon to re-sync
//! without going through HTTP.

use std::sync::Arc;

use sbc_grpc_api::sbc::did_mapping_sync_service_server::DidMappingSyncService;
use sbc_grpc_api::sbc::{
    RemoveDirectoryNumberRequest, RemoveDirectoryNumberResponse, SyncDirectoryNumberRequest,
    SyncDirectoryNumberResponse,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::api_server::AppState;

pub struct DidMappingSyncServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for DidMappingSyncServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidMappingSyncServiceImpl")
            .finish_non_exhaustive()
    }
}

impl DidMappingSyncServiceImpl {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl DidMappingSyncService for DidMappingSyncServiceImpl {
    async fn sync_directory_number(
        &self,
        request: Request<SyncDirectoryNumberRequest>,
    ) -> Result<Response<SyncDirectoryNumberResponse>, Status> {
        let req = request.into_inner();
        let did = req.did;
        info!(did, "gRPC SyncDirectoryNumber");

        let store = self.state.directory_store.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "DidMappingSyncService requires Postgres (SBC_POSTGRES_URL unset)",
            )
        })?;

        match store.get(&did).await {
            Ok(dn) => {
                let Some(sip_stack) = self.state.sip_stack.as_ref() else {
                    return Ok(Response::new(SyncDirectoryNumberResponse {
                        synced: false,
                        message: "SIP stack not initialized".to_string(),
                    }));
                };
                // Clear any prior mapping first — the same belt-and-
                // suspenders dance the REST update_directory_number
                // handler does, so a DID whose user changed lands on
                // the new user (not duplicated to both).
                sip_stack.remove_did_mapping(&did).await;
                if let Some(user) = dn.user.as_deref() {
                    sip_stack.add_did_mapping(&did, user).await;
                    Ok(Response::new(SyncDirectoryNumberResponse {
                        synced: true,
                        message: format!("DID → {user}"),
                    }))
                } else {
                    Ok(Response::new(SyncDirectoryNumberResponse {
                        synced: false,
                        message: "DID has no user binding".to_string(),
                    }))
                }
            }
            Err(sbc_config_store::ConfigStoreError::NotFound) => Ok(Response::new(
                SyncDirectoryNumberResponse {
                    synced: false,
                    message: format!("no such DID: {did}"),
                },
            )),
            Err(e) => {
                warn!(did, error = %e, "directory_store get failed");
                Err(Status::internal(format!("storage error: {e}")))
            }
        }
    }

    async fn remove_directory_number(
        &self,
        request: Request<RemoveDirectoryNumberRequest>,
    ) -> Result<Response<RemoveDirectoryNumberResponse>, Status> {
        let req = request.into_inner();
        let did = req.did;
        info!(did, "gRPC RemoveDirectoryNumber");

        if let Some(ref sip_stack) = self.state.sip_stack {
            sip_stack.remove_did_mapping(&did).await;
        }
        Ok(Response::new(RemoveDirectoryNumberResponse {
            success: true,
            message: "removed from SIP routing map".to_string(),
        }))
    }
}
