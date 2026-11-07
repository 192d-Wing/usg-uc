//! CDR handlers — recent Call Detail Records from the daemon's in-memory
//! ring over the gRPC `CdrService`. Replaces the HTTP-proxy fallback to
//! the daemon's former `/cdrs` stub.
//!
//! Records are returned in schema v1 (`uc_cdr::CallRecord` field names).
//! The durable record is the daemon's rotated file sink; there is no
//! delete or purge endpoint (retention is config-driven).
//!
//! Permissions are enforced by route layers in `handlers::router`:
//! `cdr:read` for list/show/stats and `cdr:export` for export.
//!
//! ## NIST 800-53 Rev5: AC-3, AC-6, AU-6, AU-9, SI-12

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use sbc_grpc_api::prelude::{GetCdrRequest, GetCdrStatsRequest, ListCdrsRequest};
use tonic::Code;
use tracing::warn;

use crate::authmw::Principal;
use crate::state::AppState;

/// Longest query value accepted (matches the record field cap).
const MAX_PARAM_LEN: usize = 256;

/// Most records one export returns (paged from the ring at 500 a time).
pub const MAX_EXPORT_RECORDS: usize = 50_000;

/// One export at a time per sbc-api replica (plan §7: export is
/// rate-limited; each export reads up to the whole ring).
static EXPORT_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Wraps a `CdrService` request with the end user, which the daemon records
/// in its `CdrExport` audit event (NIST 800-53 Rev5: AU-3).
fn as_user<T>(msg: T, user: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    if let Ok(v) = format!("api:{user}").parse() {
        req.metadata_mut().insert("x-sbc-user", v);
    }
    req
}

fn grpc_error(op: &str, status: &tonic::Status) -> Response {
    warn!(error = %status, "CdrService.{op} failed");
    match status.code() {
        // The daemon does not mount CdrService on a listener that is
        // neither mTLS nor loopback.
        Code::Unimplemented => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon CDR service not exposed: it needs grpc.require_mtls (and \
             SBC_DAEMON_GRPC_TLS_* here) or a loopback gRPC listener",
        ),
        Code::NotFound => error(StatusCode::NOT_FOUND, "CDR not found"),
        Code::InvalidArgument => error(StatusCode::BAD_REQUEST, status.message()),
        Code::FailedPrecondition => error(StatusCode::SERVICE_UNAVAILABLE, status.message()),
        _ => error(StatusCode::BAD_GATEWAY, "daemon CDR service unavailable"),
    }
}

/// Parses `/cdrs` query parameters into a `ListCdrsRequest`. `start` and
/// `end` are epoch milliseconds (UTC).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
pub fn list_request(q: &HashMap<String, String>) -> Result<ListCdrsRequest, String> {
    let mut req = ListCdrsRequest::default();
    for (k, v) in q {
        if v.len() > MAX_PARAM_LEN {
            return Err(format!("{k} too long"));
        }
        let ms = || {
            v.parse::<u64>()
                .map_err(|_| format!("{k} must be epoch milliseconds"))
        };
        match k.as_str() {
            "start" => req.start_ms = ms()?,
            "end" => req.end_ms = ms()?,
            "caller" => req.caller.clone_from(v),
            "callee" => req.callee.clone_from(v),
            "disposition" => {
                if uc_cdr::Disposition::parse(v).is_none() {
                    return Err(format!("unknown disposition {v:?}"));
                }
                req.disposition.clone_from(v);
            }
            "trunk" => req.trunk.clone_from(v),
            "page_token" => {
                if !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid page_token".to_string());
                }
                req.page_token.clone_from(v);
            }
            "page_size" => {
                req.page_size = v
                    .parse::<u32>()
                    .map_err(|_| "page_size must be a number".to_string())?
                    .min(500);
            }
            // Export format is read by the export handler.
            "format" => {}
            other => return Err(format!("unknown parameter {other:?}")),
        }
    }
    if req.start_ms != 0 && req.end_ms != 0 && req.end_ms <= req.start_ms {
        return Err("end must be after start".to_string());
    }
    Ok(req)
}

fn to_json(p: &sbc_grpc_api::prelude::CdrRecord) -> Result<serde_json::Value, String> {
    let r = sbc_grpc_api::cdr::from_proto(p)?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

/// `GET /api/v1/cdrs` — `{cdrs, next_page_token, total, node_id}`.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let req = match list_request(&q) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let mut client = state.cdrs.clone();
    match client.list_cdrs(as_user(req, &principal.user)).await {
        Ok(resp) => {
            let r = resp.into_inner();
            let cdrs: Result<Vec<_>, _> = r.cdrs.iter().map(to_json).collect();
            match cdrs {
                Ok(cdrs) => Json(serde_json::json!({
                    "cdrs": cdrs,
                    "next_page_token": (!r.next_page_token.is_empty()).then_some(r.next_page_token),
                    "total": r.total_in_ring,
                    "node_id": r.node_id,
                }))
                .into_response(),
                Err(e) => {
                    warn!(error = %e, "daemon returned an invalid CDR");
                    error(StatusCode::BAD_GATEWAY, "daemon returned an invalid CDR")
                }
            }
        }
        Err(status) => grpc_error("ListCdrs", &status),
    }
}

/// `GET /api/v1/cdrs/{record_id}`.
pub async fn get(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(record_id): Path<String>,
) -> Response {
    if record_id.is_empty() || record_id.len() > MAX_PARAM_LEN {
        return error(StatusCode::BAD_REQUEST, "invalid record_id");
    }
    let mut client = state.cdrs.clone();
    match client
        .get_cdr(as_user(GetCdrRequest { record_id }, &principal.user))
        .await
    {
        Ok(resp) => match resp.into_inner().cdr.as_ref().map(to_json) {
            Some(Ok(v)) => Json(v).into_response(),
            Some(Err(e)) => {
                warn!(error = %e, "daemon returned an invalid CDR");
                error(StatusCode::BAD_GATEWAY, "daemon returned an invalid CDR")
            }
            None => error(StatusCode::NOT_FOUND, "CDR not found"),
        },
        Err(status) => grpc_error("GetCdr", &status),
    }
}

/// `GET /api/v1/cdrs/stats`.
pub async fn stats(State(state): State<Arc<AppState>>) -> Response {
    let mut client = state.cdrs.clone();
    match client.get_cdr_stats(GetCdrStatsRequest {}).await {
        Ok(resp) => {
            let s = resp.into_inner();
            Json(serde_json::json!({
                "emitted": s.emitted,
                "dropped": s.dropped,
                "write_errors": s.write_errors,
                "queue_depth": s.queue_depth,
                "ring_size": s.ring_size,
                "last_write_ms": s.last_write_ms,
                "chain_ok": s.chain_ok,
                "writer_alive": s.writer_alive,
                "rotations": s.rotations,
                "health": s.health,
                "node_id": s.node_id,
            }))
            .into_response()
        }
        Err(status) => grpc_error("GetCdrStats", &status),
    }
}

/// Filter keys whose values are subscriber numbers (PII).
const PII_FILTER_KEYS: &[&str] = &["caller", "callee"];

/// The export filter in query-string form for the audit record, with
/// caller/callee values redacted: sbc-api does not hold the daemon's PII
/// policy (hash key), so it never writes the raw number to the audit log.
///
/// ## NIST 800-53 Rev5: SI-12 (Information Management and Retention)
fn audit_filter(q: &HashMap<String, String>) -> String {
    let mut filter: Vec<_> = q
        .iter()
        .filter(|(k, _)| k.as_str() != "page_token")
        .map(|(k, v)| {
            if PII_FILTER_KEYS.contains(&k.as_str()) {
                format!("{k}=<redacted>")
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    filter.sort();
    filter.join("&")
}

/// Writes the `CdrExport` audit record. Called on every exit after the
/// format and filter are valid, including busy and failed exports.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3 (outcome), AC-3
fn audit_export(user: &str, filter: &str, count: usize, format: &str, outcome: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::CdrExport(
        uc_audit::event::CdrExport {
            user: user.to_string(),
            on_behalf_of: String::new(),
            filter: filter.to_string(),
            count: count as u64,
            format: format.to_string(),
            outcome: outcome.to_string(),
        },
    ));
}

/// `GET /api/v1/cdrs/export?format=jsonl|csv&...filters` — the matching
/// ring records (newest first), at most [`MAX_EXPORT_RECORDS`]. Audited
/// (`CdrExport`): a bulk read of PII.
///
/// ## NIST 800-53 Rev5: AU-2, AC-3, SI-12
// POAM: SEC-7 the body (up to MAX_EXPORT_RECORDS) is buffered in memory
// before sending; stream it with `Body::from_stream`.
pub async fn export(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let format = match q.get("format").map_or("jsonl", String::as_str) {
        "jsonl" => uc_cdr::CdrFormat::Jsonl,
        "csv" => uc_cdr::CdrFormat::Csv,
        other => return error(StatusCode::BAD_REQUEST, format!("unknown format {other:?}")),
    };
    let mut req = match list_request(&q) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let filter = audit_filter(&q);
    let audit = |outcome: &str, count: usize| {
        audit_export(&principal.user, &filter, count, format.extension(), outcome);
    };
    let Ok(_permit) = EXPORT_GATE.try_acquire() else {
        audit("busy", 0);
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "another CDR export is in progress",
        );
    };
    req.page_size = 500;
    let mut body = String::new();
    if format == uc_cdr::CdrFormat::Csv {
        body.push_str(&uc_cdr::format::csv_header());
    }
    let mut count = 0usize;
    let mut truncated = false;
    let mut client = state.cdrs.clone();
    loop {
        let page = match client
            .list_cdrs(as_user(req.clone(), &principal.user))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(status) => {
                audit("failed", count);
                return grpc_error("ListCdrs", &status);
            }
        };
        for p in &page.cdrs {
            let line = sbc_grpc_api::cdr::from_proto(p).and_then(|r| match format {
                uc_cdr::CdrFormat::Csv => uc_cdr::format::to_csv_row(&r).map_err(|e| e.to_string()),
                uc_cdr::CdrFormat::Jsonl => {
                    uc_cdr::format::to_json_line(&r).map_err(|e| e.to_string())
                }
            });
            match line {
                Ok(l) => {
                    body.push_str(&l);
                    if !l.ends_with('\n') {
                        body.push('\n');
                    }
                }
                Err(e) => {
                    warn!(error = %e, "daemon returned an invalid CDR");
                    audit("failed", count);
                    return error(StatusCode::BAD_GATEWAY, "daemon returned an invalid CDR");
                }
            }
            count += 1;
            if count >= MAX_EXPORT_RECORDS {
                truncated = true;
                break;
            }
        }
        if truncated || page.next_page_token.is_empty() {
            break;
        }
        req.page_token = page.next_page_token;
    }
    audit(if truncated { "truncated" } else { "success" }, count);
    let content_type = match format {
        uc_cdr::CdrFormat::Csv => "text/csv; charset=utf-8",
        uc_cdr::CdrFormat::Jsonl => "application/x-ndjson",
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"cdrs.{}\"", format.extension()),
            ),
            (
                header::HeaderName::from_static("x-cdr-truncated"),
                truncated.to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn export_audit_redacts_numbers_and_records_outcome() {
        let capture = uc_audit::capture::start();
        let f = audit_filter(&q(&[
            ("caller", "+15550100"),
            ("callee", "+15550199"),
            ("trunk", "t1"),
            ("page_token", "7"),
        ]));
        assert_eq!(f, "callee=<redacted>&caller=<redacted>&trunk=t1");
        audit_export("op1", &f, 3, "csv", "failed");
        let ev = capture.events();
        let got: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CdrExport(x) => {
                    Some((x.user.as_str(), x.count, x.outcome.as_str()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(got, vec![("op1", 3, "failed")]);
        assert!(!format!("{ev:?}").contains("5550"));
    }

    #[test]
    fn list_request_parses_and_validates() {
        let r = list_request(&q(&[
            ("start", "1000"),
            ("end", "2000"),
            ("caller", "alice"),
            ("disposition", "busy"),
            ("page_size", "9999"),
        ]))
        .unwrap();
        assert_eq!((r.start_ms, r.end_ms, r.page_size), (1000, 2000, 500));
        assert_eq!(r.disposition, "busy");
        for bad in [
            q(&[("start", "yesterday")]),
            q(&[("disposition", "exploded")]),
            q(&[("page_token", "1;DROP")]),
            q(&[("start", "5"), ("end", "5")]),
            q(&[("bogus", "1")]),
            q(&[("caller", &"x".repeat(1000))]),
        ] {
            assert!(list_request(&bad).is_err(), "{bad:?}");
        }
    }
}
