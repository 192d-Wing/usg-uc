//! TrunkHealthService gRPC implementation.
//!
//! Read-side view of runtime trunk state — OPTIONS-ping health monitor
//! and outbound carrier-registration status — plus a Register trigger
//! for manually kicking a re-registration. Replaces the daemon's REST
//! routes `/api/v1/trunk-health`, `/api/v1/trunk-registration`, and
//! `/api/v1/trunk-registration/{trunk_id}/register` so sbc-api can stop
//! HTTP-proxying these and the daemon's REST surface can shrink.

use std::sync::Arc;

use sbc_grpc_api::sbc::trunk_health_service_server::TrunkHealthService;
use sbc_grpc_api::sbc::{
    ListTrunkHealthRequest, ListTrunkHealthResponse, ListTrunkRegistrationsRequest,
    ListTrunkRegistrationsResponse, RegisterTrunkRequest, RegisterTrunkResponse, TrunkHealthInfo,
    TrunkRegistrationInfo,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::api_server::AppState;
use crate::trunk_registrar::TrunkRegConfig;

pub struct TrunkHealthServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for TrunkHealthServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrunkHealthServiceImpl")
            .finish_non_exhaustive()
    }
}

impl TrunkHealthServiceImpl {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl TrunkHealthService for TrunkHealthServiceImpl {
    async fn list_trunk_health(
        &self,
        _request: Request<ListTrunkHealthRequest>,
    ) -> Result<Response<ListTrunkHealthResponse>, Status> {
        info!("gRPC ListTrunkHealth");
        let external = self.state.trunk_monitor.is_none();
        let (statuses, snapshot_age_secs) = if let Some(ref monitor) = self.state.trunk_monitor {
            (monitor.get_all_status().await, 0u32)
        } else {
            let remote = self.state.remote_trunk_status.read().await;
            let age = remote.received_at.map_or(0u32, |t| {
                t.elapsed().as_secs().min(u32::MAX as u64) as u32
            });
            (remote.health.clone(), age)
        };
        let trunks: Vec<TrunkHealthInfo> = statuses
            .into_iter()
            .map(|s| TrunkHealthInfo {
                trunk_id: s.trunk_id,
                reachable: s.reachable,
                last_response_ms: s.last_response_ms.unwrap_or(0) as i64,
                last_success_epoch: s.last_success.unwrap_or(0),
                last_failure_epoch: s.last_failure.unwrap_or(0),
                consecutive_success: s.consecutive_success,
                consecutive_failures: s.consecutive_failures,
                total_pings: s.total_pings,
                total_success: s.total_success,
                uptime_pct: s.uptime_pct,
                in_service_since_epoch: s.in_service_since.unwrap_or(0),
            })
            .collect();
        Ok(Response::new(ListTrunkHealthResponse {
            trunks,
            trunk_services_external: external,
            snapshot_age_secs,
        }))
    }

    async fn list_trunk_registrations(
        &self,
        _request: Request<ListTrunkRegistrationsRequest>,
    ) -> Result<Response<ListTrunkRegistrationsResponse>, Status> {
        info!("gRPC ListTrunkRegistrations");
        let external = self.state.trunk_registrar.is_none();
        let (statuses, snapshot_age_secs) = if let Some(ref reg) = self.state.trunk_registrar {
            (reg.get_all_status().await, 0u32)
        } else {
            let remote = self.state.remote_trunk_status.read().await;
            let age = remote.received_at.map_or(0u32, |t| {
                t.elapsed().as_secs().min(u32::MAX as u64) as u32
            });
            (remote.registrations.clone(), age)
        };
        let trunks: Vec<TrunkRegistrationInfo> = statuses
            .into_iter()
            .map(|s| TrunkRegistrationInfo {
                trunk_id: s.trunk_id,
                registered: s.registered,
                state: s.state,
                registrar: s.registrar,
                username: s.username,
                last_registered_epoch: s.last_registered.unwrap_or(0),
                last_error: s.last_error.unwrap_or_default(),
                expires_secs: s.expires,
                attempts: s.attempts,
                successes: s.successes,
            })
            .collect();
        Ok(Response::new(ListTrunkRegistrationsResponse {
            trunks,
            trunk_services_external: external,
            snapshot_age_secs,
        }))
    }

    async fn register_trunk(
        &self,
        request: Request<RegisterTrunkRequest>,
    ) -> Result<Response<RegisterTrunkResponse>, Status> {
        let req = request.into_inner();
        let trunk_id = req.trunk_id;
        info!(trunk_id, "gRPC RegisterTrunk");

        // Look up the trunk's credentials. Same fall-through logic the
        // REST handler used: Postgres first, MemStore fallback.
        let groups: Vec<serde_json::Value> = if let Some(ref store) = self.state.trunk_group_store {
            store.list().await.unwrap_or_default()
        } else {
            let mem = self.state.mem_store.read().await;
            mem.trunk_groups.values().cloned().collect()
        };
        let mut found_trunk = None;
        for group in &groups {
            if let Some(trunks) = group.get("trunks").and_then(|v| v.as_array()) {
                for t in trunks {
                    if t.get("id").and_then(|v| v.as_str()) == Some(&trunk_id) {
                        found_trunk = Some(t.clone());
                        break;
                    }
                }
            }
            if found_trunk.is_some() {
                break;
            }
        }
        let Some(trunk) = found_trunk else {
            return Ok(Response::new(RegisterTrunkResponse {
                success: false,
                message: format!("Trunk not found: {trunk_id}"),
            }));
        };

        let username = trunk
            .get("sip_username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let password = trunk
            .get("sip_password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let host = trunk
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port = trunk.get("port").and_then(|v| v.as_u64()).unwrap_or(5060) as u16;

        if username.is_empty() || host.is_empty() {
            return Ok(Response::new(RegisterTrunkResponse {
                success: false,
                message: "Trunk missing SIP credentials or host".to_string(),
            }));
        }

        let Some(ref registrar) = self.state.trunk_registrar else {
            warn!(trunk_id, "Trunk registrar not configured");
            return Ok(Response::new(RegisterTrunkResponse {
                success: false,
                message: "trunk registration runs in the sbc-trunk-agent pod \
                          (SBC_TRUNK_SERVICES=external); it re-registers \
                          automatically on its next config poll"
                    .to_string(),
            }));
        };

        registrar.register_trunk(TrunkRegConfig {
            trunk_id: trunk_id.clone(),
            host: host.clone(),
            port,
            username,
            password,
            domain: host,
            expires: 3600,
            bind_ip: None,
            external_ip: None,
        });
        Ok(Response::new(RegisterTrunkResponse {
            success: true,
            message: format!("Registration started for {trunk_id}"),
        }))
    }
}
