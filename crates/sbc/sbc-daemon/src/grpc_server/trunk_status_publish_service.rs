//! TrunkStatusPublishService gRPC implementation.
//!
//! Write-side companion to `TrunkHealthService`: the sbc-trunk-agent
//! pod pushes periodic snapshots of OPTIONS-ping health and carrier-
//! registration status here when trunk services run externally
//! (`SBC_TRUNK_SERVICES=external`). The daemon stores the latest
//! snapshot in `AppState::remote_trunk_status`, where the
//! `TrunkHealthService` read RPCs serve it to sbc-api and the dashboard.
//!
//! Publishes are rejected while the daemon runs its own in-process
//! trunk loops — two concurrent writers would make trunk status flap
//! between sources.

use std::sync::Arc;
use std::time::Instant;

use sbc_grpc_api::sbc::trunk_status_publish_service_server::TrunkStatusPublishService;
use sbc_grpc_api::sbc::{PublishTrunkStatusRequest, PublishTrunkStatusResponse};
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use crate::api_server::AppState;
use crate::trunk_monitor::TrunkHealthStatus;
use crate::trunk_registrar::TrunkRegistrationStatus;

pub struct TrunkStatusPublishServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for TrunkStatusPublishServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrunkStatusPublishServiceImpl")
            .finish_non_exhaustive()
    }
}

impl TrunkStatusPublishServiceImpl {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

/// 0 means "absent" on the wire (proto3 scalar defaults).
const fn opt_nonzero_i64(v: i64) -> Option<i64> {
    if v == 0 { None } else { Some(v) }
}

#[tonic::async_trait]
impl TrunkStatusPublishService for TrunkStatusPublishServiceImpl {
    async fn publish_trunk_status(
        &self,
        request: Request<PublishTrunkStatusRequest>,
    ) -> Result<Response<PublishTrunkStatusResponse>, Status> {
        let req = request.into_inner();

        if self.state.trunk_monitor.is_some() || self.state.trunk_registrar.is_some() {
            warn!(
                agent_id = %req.agent_id,
                "Rejecting trunk status publish: daemon runs local trunk services"
            );
            return Ok(Response::new(PublishTrunkStatusResponse {
                accepted: false,
                message: "daemon runs in-process trunk services; \
                          set SBC_TRUNK_SERVICES=external to delegate them"
                    .to_string(),
            }));
        }

        let health: Vec<TrunkHealthStatus> = req
            .health
            .into_iter()
            .map(|h| TrunkHealthStatus {
                trunk_id: h.trunk_id,
                reachable: h.reachable,
                last_response_ms: u64::try_from(h.last_response_ms).ok().filter(|&v| v != 0),
                last_success: opt_nonzero_i64(h.last_success_epoch),
                last_failure: opt_nonzero_i64(h.last_failure_epoch),
                consecutive_success: h.consecutive_success,
                consecutive_failures: h.consecutive_failures,
                total_pings: h.total_pings,
                total_success: h.total_success,
                uptime_pct: h.uptime_pct,
                in_service_since: opt_nonzero_i64(h.in_service_since_epoch),
            })
            .collect();

        let registrations: Vec<TrunkRegistrationStatus> = req
            .registrations
            .into_iter()
            .map(|r| TrunkRegistrationStatus {
                trunk_id: r.trunk_id,
                registered: r.registered,
                state: r.state,
                registrar: r.registrar,
                username: r.username,
                last_registered: opt_nonzero_i64(r.last_registered_epoch),
                last_error: if r.last_error.is_empty() {
                    None
                } else {
                    Some(r.last_error)
                },
                expires: r.expires_secs,
                attempts: r.attempts,
                successes: r.successes,
            })
            .collect();

        let mut snapshot = self.state.remote_trunk_status.write().await;
        if !snapshot.agent_id.is_empty() && snapshot.agent_id != req.agent_id {
            // Pod replacement during a rollout is expected; two agents
            // alternating here is the misconfiguration to watch for.
            warn!(
                previous = %snapshot.agent_id,
                current = %req.agent_id,
                "Trunk status publisher changed"
            );
        }
        debug!(
            agent_id = %req.agent_id,
            health = health.len(),
            registrations = registrations.len(),
            "Stored trunk status snapshot"
        );
        snapshot.agent_id = req.agent_id;
        snapshot.health = health;
        snapshot.registrations = registrations;
        snapshot.received_at = Some(Instant::now());

        Ok(Response::new(PublishTrunkStatusResponse {
            accepted: true,
            message: String::new(),
        }))
    }
}
