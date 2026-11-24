//! Write audit for the operator surface, plus the request-scoped client IP.
//!
//! [`layer`] wraps every route. It resolves the client IP (trusted-proxy
//! aware) into [`crate::auth::PEER_IP`] and, for an operator write, scopes a
//! small context that [`crate::auth::authorize_action`] fills with the
//! validated actor and the handler fills with the body's entity id
//! ([`target`]). When the handler returns, one `ConfigurationChange` is
//! emitted with entity, id, op and the outcome of the response status. Every
//! exit path after authorization is covered, including validation and
//! secret re-entry refusals; nothing from the request body other than the id
//! is recorded.
//!
//! A write refused before authorization has no actor: a bad or missing
//! token is audited by the token-reject path, and a body the extractor
//! refused is recorded as `unauthenticated` (aggregated per client /64). `/v1/sync/*` uploads are
//! audited per change by the handler.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use axum::extract::{ConnectInfo, FromRequestParts, MatchedPath, RawPathParams, Request};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;
use proto_jwt::{Claims, Validator};
use sbc_http_util::mgmt_audit::{self, Actor, Op, Outcome};

use crate::auth::PEER_IP;

/// Proxies whose `X-Real-IP` is honored (`CENTRAL_API_TRUSTED_PROXIES`).
/// Set once at startup; empty (the default) means the TCP peer is used.
static TRUSTED_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();

/// Installs the trusted-proxy list. Later calls are ignored.
pub fn set_trusted_proxies(nets: Vec<IpNet>) {
    let _ = TRUSTED_PROXIES.set(nets);
}

#[derive(Debug, Default)]
struct WriteCtx {
    actor: Option<Actor>,
    id: Option<String>,
}

tokio::task_local! {
    static WRITE: Arc<Mutex<WriteCtx>>;
}

fn with_ctx(f: impl FnOnce(&mut WriteCtx)) {
    let _ = WRITE.try_with(|c| f(&mut c.lock().unwrap_or_else(PoisonError::into_inner)));
}

/// Records the validated operator for the current write (called by
/// `authorize_action` on success; a no-op outside a write).
pub fn set_actor(claims: &Claims, validator: &Validator) {
    let actor = Actor {
        id: crate::auth::actor_id(claims, validator),
        issuer: Some(validator.issuer().to_string()),
        display: claims.preferred_username.clone(),
        source_ip: Some(crate::auth::peer_ip()),
    };
    with_ctx(|c| c.actor = Some(actor));
}

/// Names the entity a body-addressed write targets (upserts).
pub fn target(id: &str) {
    with_ctx(|c| c.id = Some(id.to_string()));
}

/// Where a route's audit id comes from.
#[derive(Clone, Copy)]
enum IdFrom {
    /// Set by the handler with [`target`].
    Body,
    /// A path parameter.
    Param(&'static str),
}

/// Entity, op and id source of an operator write route; `None` for reads,
/// probes and the sync surface.
fn classify(method: &Method, route: &str) -> Option<(&'static str, Op, IdFrom)> {
    use IdFrom::{Body, Param};
    let w = match (method.as_str(), route) {
        ("POST", "/v1/sites") => ("site", Op::Create, Body),
        ("POST", "/v1/sites/{site_code}/phones") => ("phone", Op::Update, Body),
        ("DELETE", "/v1/sites/{site_code}/phones/{id}") => ("phone", Op::Delete, Param("id")),
        ("POST", "/v1/sites/{site_code}/directory") => ("directory_number", Op::Update, Body),
        ("DELETE", "/v1/sites/{site_code}/directory/{did}") => {
            ("directory_number", Op::Delete, Param("did"))
        }
        ("POST", "/v1/sites/{site_code}/trunkgroups") => ("trunk_group", Op::Update, Body),
        ("DELETE", "/v1/sites/{site_code}/trunkgroups/{id}") => {
            ("trunk_group", Op::Delete, Param("id"))
        }
        ("POST", "/v1/sites/{site_code}/dialplans") => ("dial_plan", Op::Update, Body),
        ("DELETE", "/v1/sites/{site_code}/dialplans/{id}") => {
            ("dial_plan", Op::Delete, Param("id"))
        }
        ("PUT", "/v1/sites/{site_code}/config") => ("site_config", Op::Update, Param("site_code")),
        ("POST", "/v1/sites/{site_code}/routing/{kind}") => ("routing", Op::Update, Body),
        ("DELETE", "/v1/sites/{site_code}/routing/{kind}/{id}") => {
            ("routing", Op::Delete, Param("id"))
        }
        ("PUT", "/v1/templates/{kind}/{id}") => ("template", Op::Update, Param("id")),
        ("DELETE", "/v1/templates/{kind}/{id}") => ("template", Op::Delete, Param("id")),
        ("PUT", "/v1/templates/{kind}/{id}/sites/{site_code}") => {
            ("template_assignment", Op::Action("assign"), Param("id"))
        }
        ("POST", "/v1/templates/{kind}/{id}/materialize") => {
            ("template", Op::Action("materialize"), Param("id"))
        }
        _ => return None,
    };
    Some(w)
}

/// Statuses axum's extractors answer for a refused body or path.
fn is_extractor_reject(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::UNPROCESSABLE_ENTITY
    )
}

/// Router middleware: client IP scope for every request, write audit for
/// operator writes.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3
pub async fn layer(req: Request, next: Next) -> Response {
    let ip: Option<IpAddr> =
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| {
                let trusted = TRUSTED_PROXIES.get().map_or(&[][..], Vec::as_slice);
                sbc_http_util::resolve_client_ip(req.headers(), peer.ip(), trusted)
            });
    let class = req
        .extensions()
        .get::<MatchedPath>()
        .and_then(|m| classify(req.method(), m.as_str()));

    let Some((entity, op, id_from)) = class else {
        return match ip {
            Some(ip) => PEER_IP.scope(ip, next.run(req)).await,
            None => next.run(req).await,
        };
    };

    let (mut parts, body) = req.into_parts();
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .ok();
    let param = |name: &str| {
        params.as_ref().and_then(|p| {
            p.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        })
    };
    let site = param("site_code");
    let kind = param("kind");
    let path_id = match id_from {
        IdFrom::Param(name) => param(name),
        IdFrom::Body => None,
    };
    let req = Request::from_parts(parts, body);

    let ctx = Arc::new(Mutex::new(WriteCtx::default()));
    let fut = WRITE.scope(Arc::clone(&ctx), next.run(req));
    let resp = match ip {
        Some(ip) => PEER_IP.scope(ip, fut).await,
        None => fut.await,
    };

    let (actor, body_id) = {
        let mut c = ctx.lock().unwrap_or_else(PoisonError::into_inner);
        (c.actor.take(), c.id.take())
    };
    // No actor and a body/format refusal: the JSON extractor refused the
    // write before authorization ran. Recorded as `unauthenticated`,
    // aggregated per client /64. Other refusals without an actor (401/403)
    // are audited as token rejects.
    if actor.is_none() && is_extractor_reject(resp.status()) {
        let ip = ip.unwrap_or_else(crate::auth::peer_ip);
        mgmt_audit::rejected_write(ip, entity, op, site.as_deref(), resp.status());
    }
    if let Some(actor) = actor {
        let id = path_id.or(body_id).unwrap_or_default();
        let detail: Vec<(&'static str, &str)> =
            kind.as_deref().map(|k| ("kind", k)).into_iter().collect();
        mgmt_audit::config_change_detail(
            &actor,
            entity,
            &id,
            op,
            Outcome::from_status(resp.status()),
            site.as_deref(),
            &detail,
        );
    }
    resp
}
