//! HTTP route surface for sbc-api-server.
//!
//! The route map mirrors the daemon's REST surface so the frontend
//! dashboard (and any external operator tooling) can flip from
//! daemon-API to sbc-api by swapping nothing more than the nginx
//! upstream. Handlers sbc-api owns are wired here; everything else
//! falls through to the [`proxy`] catch-all which reverse-proxies to
//! the daemon.

use std::sync::Arc;

use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

mod calls;
mod dial_plans;
mod directory;
mod phones;
mod proxy;
mod registrations;
mod system;
mod trunk_groups;

pub fn router(state: Arc<AppState>) -> Router {
    let api_v1 = Router::new()
        // Phones
        .route("/phones", get(phones::list).post(phones::create))
        .route(
            "/phones/{id}",
            get(phones::get).put(phones::update).delete(phones::delete),
        )
        .route("/phones/{id}/reboot", post(phones::reboot))
        // Directory numbers (DIDs)
        .route("/directory", get(directory::list).post(directory::create))
        .route(
            "/directory/{did}",
            put(directory::update).delete(directory::delete),
        )
        // Trunk groups + nested trunks
        .route(
            "/trunkgroups",
            get(trunk_groups::list_groups).post(trunk_groups::add_group),
        )
        .route(
            "/trunkgroups/{group_id}",
            get(trunk_groups::get_group)
                .put(trunk_groups::update_group)
                .delete(trunk_groups::delete_group),
        )
        .route("/trunkgroups/{group_id}/trunks", post(trunk_groups::add_trunk))
        .route(
            "/trunkgroups/{group_id}/trunks/{trunk_id}",
            put(trunk_groups::update_trunk).delete(trunk_groups::delete_trunk),
        )
        // Dial plan writes (reads stay on the daemon — they read SIP-
        // stack state, not Postgres).
        .route(
            "/dialplans/{plan_id}/entries",
            post(dial_plans::add_entry),
        )
        .route(
            "/dialplans/{plan_id}/entries/{entry_id}",
            delete(dial_plans::delete_entry),
        )
        // SIP-state reads — these used to fall through to the HTTP
        // proxy back to the daemon. PR7 wires them directly to the
        // daemon's gRPC CallService / RegistrationService / System
        // Service so the daemon's REST surface can be deleted.
        .route("/calls", get(calls::list))
        .route("/calls/{call_id}/ladder", get(calls::ladder))
        .route("/calls/{call_id}/terminate", post(calls::terminate))
        .route("/registrations", get(registrations::list))
        .route("/registrations/{aor}", delete(registrations::delete))
        // System endpoints. /system/version stays local (sbc-api's
        // own identity); /system/daemon-version exposes the daemon's
        // version via gRPC. The rest passthrough to SystemService.
        .route("/system/daemon-version", get(system::daemon_version))
        .route("/system/stats", get(system::stats))
        .route("/system/metrics", get(system::metrics))
        .route("/system/tls", get(system::tls_status))
        .route("/system/tls/reload", post(system::tls_reload))
        .with_state(Arc::clone(&state));

    // Catch-all for /api/v1/* paths we don't handle locally. Matches
    // *path so it captures arbitrary depth (e.g., /api/v1/system/stats,
    // /api/v1/users/123, /api/v1/registrations).
    let api_proxy = Router::new()
        .route("/api/v1/{*path}", get(proxy::proxy_get)
            .post(proxy::proxy_post)
            .put(proxy::proxy_put)
            .delete(proxy::proxy_delete))
        .with_state(Arc::clone(&state));

    Router::new()
        .route("/healthz", get(system::liveness))
        .route("/readyz", get(system::readiness))
        .route("/api/v1/system/version", get(system::version))
        .nest("/api/v1", api_v1)
        .merge(api_proxy)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
