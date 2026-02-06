//! RegistrationService gRPC implementation.
//!
//! Provides registration management and monitoring operations via gRPC.

use crate::api_server::AppState;
use sbc_grpc_api::sbc::registration_service_server::RegistrationService;
use sbc_grpc_api::sbc::{
    DeleteRegistrationRequest, DeleteRegistrationResponse, GetRegistrationRequest,
    GetRegistrationResponse, GetRegistrationStatsRequest, GetRegistrationStatsResponse,
    ListRegistrationsRequest, ListRegistrationsResponse,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tonic::{Request, Response, Status};
use tracing::info;

/// RegistrationService implementation.
pub struct RegistrationServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for RegistrationServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationServiceImpl")
            .finish_non_exhaustive()
    }
}

impl RegistrationServiceImpl {
    /// Creates a new RegistrationService implementation.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl RegistrationService for RegistrationServiceImpl {
    async fn list_registrations(
        &self,
        request: Request<ListRegistrationsRequest>,
    ) -> Result<Response<ListRegistrationsResponse>, Status> {
        let req = request.into_inner();
        info!(
            limit = req.limit,
            offset = req.offset,
            aor_filter = %req.aor_filter,
            realm_filter = %req.realm_filter,
            "gRPC ListRegistrations"
        );

        // Get registration counts from stats
        let active = self
            .state
            .stats
            .registrations_active
            .load(Ordering::Relaxed);
        let total = self.state.stats.registrations_total.load(Ordering::Relaxed);

        // TODO: Implement actual registration listing from registrar
        #[allow(clippy::cast_possible_wrap)]
        let response = ListRegistrationsResponse {
            registrations: vec![], // Would be populated from registrar
            total: total as i64,
            active: active as i64,
        };

        Ok(Response::new(response))
    }

    async fn get_registration(
        &self,
        request: Request<GetRegistrationRequest>,
    ) -> Result<Response<GetRegistrationResponse>, Status> {
        let req = request.into_inner();
        info!(aor = %req.aor, "gRPC GetRegistration");

        // TODO: Implement actual registration lookup from registrar
        Err(Status::not_found(format!(
            "Registration not found: {}",
            req.aor
        )))
    }

    async fn delete_registration(
        &self,
        request: Request<DeleteRegistrationRequest>,
    ) -> Result<Response<DeleteRegistrationResponse>, Status> {
        let req = request.into_inner();
        info!(
            aor = %req.aor,
            contact_uri = %req.contact_uri,
            reason = %req.reason,
            "gRPC DeleteRegistration"
        );

        // TODO: Implement actual registration deletion via registrar
        // This would send a NOTIFY with expires=0 or update the registration store
        Err(Status::unimplemented(
            "DeleteRegistration not yet implemented",
        ))
    }

    async fn get_registration_stats(
        &self,
        request: Request<GetRegistrationStatsRequest>,
    ) -> Result<Response<GetRegistrationStatsResponse>, Status> {
        let req = request.into_inner();
        info!(realm = %req.realm, "gRPC GetRegistrationStats");

        let stats = &self.state.stats;
        #[allow(clippy::cast_possible_wrap)]
        let response = GetRegistrationStatsResponse {
            registrations_total: stats.registrations_total.load(Ordering::Relaxed) as i64,
            registrations_active: stats.registrations_active.load(Ordering::Relaxed) as i64,
            unique_aors: 0,    // TODO: Track unique AORs
            total_contacts: 0, // TODO: Track total contacts
            expiring_soon: 0,  // TODO: Track expiring registrations
            avg_contacts_per_aor: 0.0,
            registrations_per_minute: 0.0,
            reregistrations_per_minute: 0.0,
            auth_failures_per_minute: 0.0,
        };

        Ok(Response::new(response))
    }
}
