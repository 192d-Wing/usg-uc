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

        // Get live data from SIP stack if available
        let (regs_proto, active, total) = if let Some(ref stack) = self.state.sip_stack {
            let summaries = stack.list_registrations().await;
            let active = summaries.len() as u64;
            let total = self.state.stats.registrations_total.load(Ordering::Relaxed);

            let regs: Vec<_> = summaries
                .iter()
                .map(|s| sbc_grpc_api::sbc::RegistrationInfo {
                    aor: s.aor.clone(),
                    contacts: s
                        .contacts
                        .iter()
                        .map(|c| sbc_grpc_api::sbc::ContactInfo {
                            uri: c.clone(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                })
                .collect();
            (regs, active, total)
        } else {
            (vec![], active, total)
        };

        #[allow(clippy::cast_possible_wrap)]
        let response = ListRegistrationsResponse {
            registrations: regs_proto,
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

        if let Some(ref stack) = self.state.sip_stack {
            match stack.delete_registration(&req.aor, &req.contact_uri).await {
                Ok(()) => {
                    info!(aor = %req.aor, contact = %req.contact_uri, "Registration deleted");
                    Ok(Response::new(DeleteRegistrationResponse {
                        success: true,
                        message: "Registration deleted".to_string(),
                        contacts_removed: 1,
                    }))
                }
                Err(e) => Err(Status::not_found(e)),
            }
        } else {
            Err(Status::unavailable("SIP stack not available"))
        }
    }

    async fn get_registration_stats(
        &self,
        request: Request<GetRegistrationStatsRequest>,
    ) -> Result<Response<GetRegistrationStatsResponse>, Status> {
        let req = request.into_inner();
        info!(realm = %req.realm, "gRPC GetRegistrationStats");

        let stats = &self.state.stats;
        let (unique_aors, total_contacts) = if let Some(ref stack) = self.state.sip_stack {
            (
                stack.registration_aor_count().await as i64,
                stack.registration_binding_count().await as i64,
            )
        } else {
            (0, 0)
        };
        #[allow(clippy::cast_possible_wrap)]
        let response = GetRegistrationStatsResponse {
            registrations_total: stats.registrations_total.load(Ordering::Relaxed) as i64,
            registrations_active: stats.registrations_active.load(Ordering::Relaxed) as i64,
            unique_aors,
            total_contacts,
            expiring_soon: 0,
            avg_contacts_per_aor: if unique_aors > 0 {
                total_contacts as f64 / unique_aors as f64
            } else {
                0.0
            },
            registrations_per_minute: 0.0,
            reregistrations_per_minute: 0.0,
            auth_failures_per_minute: 0.0,
        };

        Ok(Response::new(response))
    }
}
