//! Write audit for the sbc-api route surface.
//!
//! Every owned write handler records one `ConfigurationChange` (entity, id,
//! op, real outcome, actor) through [`audited`], which also marks the
//! response [`WriteAudited`]. The [`write_audit_backstop`] middleware
//! records any other non-GET request whose response is unmarked (a route
//! without handler-level audit, a body the extractor rejected, the proxy
//! catch-all, logout, a handler that panicked), so no write goes
//! unrecorded and none is recorded twice. `/api/v1/auth/login` is audited
//! by the login path instead.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5

use axum::extract::{MatchedPath, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sbc_http_util::mgmt_audit::{self, Actor, Op, Outcome};

use crate::authmw::Principal;

/// Response extension: the handler has already audited this write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAudited;

/// The one write audited by the login path, not as a config change.
const LOGIN_PATH: &str = "/api/v1/auth/login";

/// Actor for a request that reached a handler without a principal (not
/// possible behind `require_auth`; recorded rather than dropped).
fn anonymous() -> Actor {
    Actor {
        id: "anonymous".to_string(),
        issuer: None,
        display: None,
        source_ip: None,
    }
}

/// The audit actor for `p`.
pub fn actor_of(p: Option<&Principal>) -> Actor {
    p.map_or_else(anonymous, Principal::actor)
}

/// The principal recorded in the store's `updated_by` for `p`.
pub fn store_actor(p: Option<&Principal>) -> String {
    p.map_or_else(|| "anonymous".to_string(), Principal::actor_id)
}

/// Reason token for a failed store call.
pub const fn store_reason(e: &sbc_config_store::ConfigStoreError) -> &'static str {
    use sbc_config_store::ConfigStoreError as E;
    match e {
        E::NotFound => "not_found",
        E::Invalid { .. } | E::Serialization(_) => "invalid",
        E::Storage(_) | E::Io(_) => "storage",
    }
}

/// Reason token for a failed daemon gRPC call.
pub fn grpc_reason(status: &tonic::Status) -> &'static str {
    use tonic::Code;
    match status.code() {
        Code::NotFound => "not_found",
        Code::InvalidArgument | Code::OutOfRange => "invalid",
        Code::PermissionDenied | Code::Unauthenticated => "forbidden",
        Code::AlreadyExists | Code::Aborted | Code::FailedPrecondition => "conflict",
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::Cancelled
        | Code::Unknown
        | Code::ResourceExhausted => "daemon_unavailable",
        _ => "rejected",
    }
}

/// Outcome of a daemon call that answered with a `success` flag.
pub const fn daemon_outcome(success: bool) -> Outcome {
    if success {
        Outcome::Ok
    } else {
        Outcome::Failed("rejected")
    }
}

/// Response extension: a delete found no live row. The response stays the
/// idempotent 200; the record says `outcome=failed reason=not_found`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Absent;

/// Marks `resp` [`Absent`] when `absent`.
pub fn mark_absent(mut resp: Response, absent: bool) -> Response {
    if absent {
        resp.extensions_mut().insert(Absent);
    }
    resp
}

/// Outcome of a handler response: `not_found` for an [`Absent`] delete,
/// else from the status.
pub fn outcome_of(resp: &Response) -> Outcome {
    if resp.extensions().get::<Absent>().is_some() {
        Outcome::Failed("not_found")
    } else {
        Outcome::from_status(resp.status())
    }
}

/// Audited 400 for a body that is not a JSON object (handlers index into
/// it, which would panic on an array or scalar).
///
/// ## NIST 800-53 Rev5: SI-10, AU-2
pub fn non_object(p: Option<&Principal>, entity: &'static str, id: &str, op: Op) -> Response {
    audited(
        p,
        entity,
        id,
        op,
        Outcome::Failed("invalid"),
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(
                serde_json::json!({"success": false, "error": "request body must be a JSON object"}),
            ),
        ),
    )
}

/// Records one config change by `p` and marks `resp` as audited.
pub fn audited(
    p: Option<&Principal>,
    entity: &'static str,
    id: &str,
    op: Op,
    outcome: Outcome,
    resp: impl IntoResponse,
) -> Response {
    mgmt_audit::config_change(&actor_of(p), entity, id, op, outcome, None);
    let mut resp = resp.into_response();
    resp.extensions_mut().insert(WriteAudited);
    resp
}

/// Static method token for the backstop record.
const fn method_token(m: &Method) -> Option<&'static str> {
    Some(match *m {
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE => return None,
        _ => "OTHER",
    })
}

/// Router backstop: audits a non-GET request whose response no handler
/// marked [`WriteAudited`], as `entity=route id=<matched route>
/// op=<METHOD>` with the response status. Runs inside the auth layer, so
/// the principal is known.
///
/// ## NIST 800-53 Rev5: AU-2, AU-12, CM-3
pub async fn write_audit_backstop(req: Request, next: Next) -> Response {
    let Some(method) = method_token(req.method()) else {
        return next.run(req).await;
    };
    if req.uri().path() == LOGIN_PATH {
        return next.run(req).await;
    }
    // Cheap copies only; the actor and route strings are built when no
    // handler audited the write.
    let route = req.extensions().get::<MatchedPath>().cloned();
    let principal = req.extensions().get::<Principal>().cloned();
    let resp = next.run(req).await;
    if resp.extensions().get::<WriteAudited>().is_none() {
        let route = route.as_ref().map_or("-", MatchedPath::as_str);
        mgmt_audit::route_write(&actor_of(principal.as_ref()), route, method, resp.status());
    }
    resp
}
