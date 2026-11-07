//! CdrService gRPC implementation: read-only queries over the node's
//! in-memory ring of recent CDRs.
//!
//! The durable record is the rotated CDR file sink; this service has no
//! delete or purge RPC.
//!
//! The service is mounted only when the gRPC listener requires mTLS or is
//! bound to loopback (`grpc_server::cdr_service_permitted`): it has no
//! per-RPC authorization of its own. Role checks (`cdr:read`,
//! `cdr:export`) are enforced by sbc-api for REST users.
//!
//! Under mTLS the caller is authenticated by its client certificate, which
//! must be on `grpc.allowed_client_names` (`peer_identity::ClientCertGate`);
//! the audit principal is that certificate name. On a loopback listener
//! without mTLS there is no authentication at all: being local is not an
//! identity, and the principal is recorded as `unauthenticated`. In both
//! cases `x-sbc-user` is recorded only as `on_behalf_of`. Every list/get
//! is audited here as `CdrExport`, so CLI reads are audited too.
//!
// POAM: NIST-R2-01 (IA-2, AC-3) loopback CdrService access is
// unauthenticated and relies on host / pod network-namespace isolation;
// any local process can read CDRs and assert any x-sbc-user.
//! ## NIST 800-53 Rev5: AC-3, AU-2, AU-6 (Audit Review), AU-9 (no
//! modification path), SI-12 (PII is returned as stored, after the PII policy)

use crate::api_server::AppState;
use sbc_grpc_api::cdr::to_proto;
use sbc_grpc_api::sbc::cdr_service_server::CdrService;
use sbc_grpc_api::sbc::{
    GetCdrRequest, GetCdrResponse, GetCdrStatsRequest, GetCdrStatsResponse, ListCdrsRequest,
    ListCdrsResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::debug;
use uc_cdr::{CdrFilter, Disposition};

/// Longest filter string accepted (matches the record field cap).
const MAX_FILTER_LEN: usize = uc_cdr::record::MAX_FIELD_LEN;

/// CdrService implementation.
pub struct CdrServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for CdrServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdrServiceImpl").finish_non_exhaustive()
    }
}

impl CdrServiceImpl {
    /// Creates the service.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    fn emitter(&self) -> Result<&Arc<uc_cdr::CdrEmitter>, Status> {
        self.state
            .sip_stack
            .as_ref()
            .and_then(|s| s.cdr())
            .map(|c| c.emitter())
            .ok_or_else(|| Status::failed_precondition("CDRs are disabled (cdr.enabled = false)"))
    }
}

/// Metadata key carrying the end user the caller acts for (set by sbc-api
/// and sbc-cli). Caller-asserted: recorded as `on_behalf_of`, never as the
/// principal.
pub const USER_METADATA: &str = "x-sbc-user";

/// Longest `x-sbc-user` value recorded.
const MAX_USER_LEN: usize = 128;

/// Audit identity for a gRPC CDR read.
struct Caller {
    /// `cert:<name>@peer` under mTLS, else `unauthenticated@peer`.
    principal: String,
    /// [`USER_METADATA`] (printable ASCII, capped), or empty.
    on_behalf_of: String,
}

/// Reads the authenticated principal (set by the client-certificate gate)
/// and the asserted end user from a request.
///
/// ## NIST 800-53 Rev5: AU-3, IA-3
fn caller_identity<T>(req: &Request<T>) -> Caller {
    let on_behalf_of: String = req
        .metadata()
        .get(USER_METADATA)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.bytes()
                .filter(|b| (0x21..=0x7e).contains(b))
                .take(MAX_USER_LEN)
                .map(char::from)
                .collect()
        })
        .unwrap_or_default();
    let who = req
        .extensions()
        .get::<super::PeerPrincipal>()
        .map_or("unauthenticated", |p| p.0.as_str());
    let peer = req
        .remote_addr()
        .map_or_else(|| "local".to_string(), |a| a.to_string());
    Caller {
        principal: format!("{who}@{peer}"),
        on_behalf_of,
    }
}

/// Filter in query-string form for the audit record. Caller/callee terms
/// are subscriber numbers (PII): only their presence is recorded.
///
/// ## NIST 800-53 Rev5: SI-12
fn audit_filter(f: &CdrFilter, page_token: &str) -> String {
    let mut parts = Vec::new();
    if let Some(v) = f.start_ms {
        parts.push(format!("start={v}"));
    }
    if let Some(v) = f.end_ms {
        parts.push(format!("end={v}"));
    }
    if f.caller.is_some() {
        parts.push("caller=<redacted>".to_string());
    }
    if f.callee.is_some() {
        parts.push("callee=<redacted>".to_string());
    }
    if let Some(d) = f.disposition {
        parts.push(format!("disposition={}", d.as_str()));
    }
    if let Some(t) = &f.trunk {
        parts.push(format!("trunk={t}"));
    }
    if !page_token.is_empty() {
        parts.push(format!("page_token={page_token}"));
    }
    parts.join("&")
}

/// Records one gRPC CDR read (including refused and failed ones).
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AC-3
fn audit_read(user: &Caller, filter: &str, count: usize, op: &str, outcome: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::CdrExport(
        uc_audit::event::CdrExport {
            user: user.principal.clone(),
            on_behalf_of: user.on_behalf_of.clone(),
            filter: filter.to_string(),
            count: count as u64,
            format: op.to_string(),
            outcome: outcome.to_string(),
        },
    ));
}

/// Bounded optional filter string (empty = unset).
fn opt(field: &str, v: String) -> Result<Option<String>, Status> {
    if v.len() > MAX_FILTER_LEN {
        return Err(Status::invalid_argument(format!("{field} too long")));
    }
    Ok((!v.is_empty()).then_some(v))
}

/// Validates a ListCdrs request into a ring filter.
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
pub fn filter_from(req: &mut ListCdrsRequest) -> Result<CdrFilter, Status> {
    let disposition = match opt("disposition", std::mem::take(&mut req.disposition))? {
        Some(d) => Some(
            Disposition::parse(&d)
                .ok_or_else(|| Status::invalid_argument(format!("unknown disposition {d:?}")))?,
        ),
        None => None,
    };
    if req.start_ms != 0 && req.end_ms != 0 && req.end_ms <= req.start_ms {
        return Err(Status::invalid_argument("end_ms must be after start_ms"));
    }
    Ok(CdrFilter {
        start_ms: (req.start_ms != 0).then_some(req.start_ms),
        end_ms: (req.end_ms != 0).then_some(req.end_ms),
        caller: opt("caller", std::mem::take(&mut req.caller))?,
        callee: opt("callee", std::mem::take(&mut req.callee))?,
        disposition,
        trunk: opt("trunk", std::mem::take(&mut req.trunk))?,
    })
}

#[tonic::async_trait]
impl CdrService for CdrServiceImpl {
    async fn list_cdrs(
        &self,
        request: Request<ListCdrsRequest>,
    ) -> Result<Response<ListCdrsResponse>, Status> {
        let user = caller_identity(&request);
        let emitter = match self.emitter() {
            Ok(e) => Arc::clone(e),
            Err(s) => {
                audit_read(&user, "", 0, "grpc-list", "failed");
                return Err(s);
            }
        };
        let mut req = request.into_inner();
        let filter = match filter_from(&mut req) {
            Ok(f) => f,
            Err(s) => {
                audit_read(&user, "", 0, "grpc-list", "invalid");
                return Err(s);
            }
        };
        let audit_f = audit_filter(&filter, &req.page_token);
        if req.page_token.len() > 32 || !req.page_token.bytes().all(|b| b.is_ascii_digit()) {
            audit_read(&user, "", 0, "grpc-list", "invalid");
            return Err(Status::invalid_argument("invalid page_token"));
        }
        let page_size = if req.page_size == 0 {
            uc_cdr::ring::DEFAULT_PAGE_SIZE
        } else {
            (req.page_size as usize).min(uc_cdr::ring::MAX_PAGE_SIZE)
        };
        // The scan copies up to the whole ring: keep it off async workers.
        let token = req.page_token;
        let ring_emitter = Arc::clone(&emitter);
        let page = tokio::task::spawn_blocking(move || {
            let token = (!token.is_empty()).then_some(token.as_str());
            ring_emitter.ring().query(&filter, token, page_size)
        })
        .await
        .map_err(|e| {
            audit_read(&user, &audit_f, 0, "grpc-list", "failed");
            Status::internal(format!("CDR query failed: {e}"))
        })?;
        debug!(returned = page.records.len(), "gRPC ListCdrs");
        audit_read(&user, &audit_f, page.records.len(), "grpc-list", "success");
        Ok(Response::new(ListCdrsResponse {
            cdrs: page.records.iter().map(|r| to_proto(r)).collect(),
            next_page_token: page.next_page_token.unwrap_or_default(),
            total_in_ring: page.total_in_ring as u64,
            node_id: emitter.node_id().to_string(),
        }))
    }

    async fn get_cdr(
        &self,
        request: Request<GetCdrRequest>,
    ) -> Result<Response<GetCdrResponse>, Status> {
        let user = caller_identity(&request);
        let emitter = match self.emitter() {
            Ok(e) => e,
            Err(s) => {
                audit_read(&user, "", 0, "grpc-get", "failed");
                return Err(s);
            }
        };
        let id = request.into_inner().record_id;
        if id.is_empty() || id.len() > MAX_FILTER_LEN {
            audit_read(&user, "", 0, "grpc-get", "invalid");
            return Err(Status::invalid_argument("invalid record_id"));
        }
        let filter = format!("record_id={id}");
        let Some(rec) = emitter.ring().get(&id) else {
            audit_read(&user, &filter, 0, "grpc-get", "not_found");
            return Err(Status::not_found("CDR not in this node's ring"));
        };
        audit_read(&user, &filter, 1, "grpc-get", "success");
        Ok(Response::new(GetCdrResponse {
            cdr: Some(to_proto(&rec)),
        }))
    }

    async fn get_cdr_stats(
        &self,
        _request: Request<GetCdrStatsRequest>,
    ) -> Result<Response<GetCdrStatsResponse>, Status> {
        let emitter = self.emitter()?;
        let s = emitter.stats();
        Ok(Response::new(GetCdrStatsResponse {
            emitted: s.emitted,
            dropped: s.dropped(),
            write_errors: s.write_errors,
            queue_depth: s.queue_depth,
            ring_size: s.ring_size,
            last_write_ms: s.last_write_ms,
            chain_ok: s.chain_ok,
            writer_alive: s.writer_alive,
            rotations: s.rotations,
            health: emitter.health().as_str().to_string(),
            node_id: emitter.node_id().to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::AppState;
    use crate::sip_stack::{SipStack, SipStackConfig};
    use std::time::Duration;
    use uc_cdr::CallRecord;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn state_with_ring() -> Result<(Arc<AppState>, Arc<uc_cdr::CdrEmitter>), uc_cdr::CdrError> {
        let emitter = uc_cdr::CdrEmitter::start(
            uc_cdr::CdrEmitterConfig {
                node_id: "n1".into(),
                file: None,
                ..Default::default()
            },
            Vec::new(),
            None,
        )?;
        let ctx = Arc::new(crate::cdr::CdrContext::new(
            Arc::clone(&emitter),
            &sbc_config::schema::CdrConfig::default(),
        ));
        let mut stack = SipStack::new(SipStackConfig::default());
        stack.set_cdr(ctx);
        let mut state = AppState::new(
            uc_metrics::SbcMetrics::standard(),
            Arc::new(crate::server::ServerStats::default()),
        );
        state.sip_stack = Some(Arc::new(stack));
        Ok((Arc::new(state), emitter))
    }

    #[tokio::test]
    async fn list_and_get_cdrs() -> TestResult {
        let (state, emitter) = state_with_ring()?;
        for (i, d) in [
            Disposition::Answered,
            Disposition::Busy,
            Disposition::Answered,
        ]
        .into_iter()
        .enumerate()
        {
            emitter.emit(CallRecord {
                caller: format!("100{i}"),
                disposition: d,
                setup_ms: 1000 + i as u64,
                ..Default::default()
            });
        }
        assert!(emitter.flush(Duration::from_secs(5)));
        let svc = CdrServiceImpl::new(state);

        let all = svc
            .list_cdrs(Request::new(ListCdrsRequest::default()))
            .await?
            .into_inner();
        assert_eq!(all.cdrs.len(), 3);
        assert_eq!(all.total_in_ring, 3);
        assert_eq!(all.node_id, "n1");

        let answered = svc
            .list_cdrs(Request::new(ListCdrsRequest {
                disposition: "answered".into(),
                page_size: 1,
                ..Default::default()
            }))
            .await?
            .into_inner();
        assert_eq!(answered.cdrs.len(), 1);
        assert_ne!(answered.next_page_token, "");
        let page2 = svc
            .list_cdrs(Request::new(ListCdrsRequest {
                disposition: "answered".into(),
                page_size: 1,
                page_token: answered.next_page_token.clone(),
                ..Default::default()
            }))
            .await?
            .into_inner();
        assert_eq!(page2.cdrs.len(), 1);
        assert_ne!(page2.cdrs[0].record_id, answered.cdrs[0].record_id);

        let id = all.cdrs[0].record_id.clone();
        let one = svc
            .get_cdr(Request::new(GetCdrRequest {
                record_id: id.clone(),
            }))
            .await?
            .into_inner();
        assert_eq!(one.cdr.ok_or("cdr missing")?.record_id, id);
        let missing = svc
            .get_cdr(Request::new(GetCdrRequest {
                record_id: "n1-999".into(),
            }))
            .await;
        assert_eq!(code(missing), Some(tonic::Code::NotFound));

        let counters = svc
            .get_cdr_stats(Request::new(GetCdrStatsRequest {}))
            .await?
            .into_inner();
        assert_eq!(counters.emitted, 3);
        assert!(counters.writer_alive);
        Ok(())
    }

    /// SEC-1/SEC-6: gRPC reads (sbc-cli, sbc-api) are audited in the daemon
    /// with the asserted user, outcome, and caller/callee redacted.
    #[tokio::test]
    async fn grpc_reads_are_audited_without_numbers() -> TestResult {
        let (state, emitter) = state_with_ring()?;
        emitter.emit(CallRecord {
            caller: "+12025550100".into(),
            ..Default::default()
        });
        assert!(emitter.flush(Duration::from_secs(5)));
        let svc = CdrServiceImpl::new(state);
        let capture = uc_audit::capture::start();
        let mut req = Request::new(ListCdrsRequest {
            caller: "+12025550100".into(),
            ..Default::default()
        });
        req.metadata_mut().insert(USER_METADATA, "cli:op1".parse()?);
        let got = svc.list_cdrs(req).await?.into_inner();
        assert_eq!(got.cdrs.len(), 1);
        let bad = svc
            .get_cdr(Request::new(GetCdrRequest {
                record_id: String::new(),
            }))
            .await;
        assert_eq!(code(bad), Some(tonic::Code::InvalidArgument));
        let ev: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CdrExport(x) => Some(x),
                _ => None,
            })
            .collect();
        assert_eq!(ev.len(), 2, "{ev:?}");
        assert_eq!(ev[0].user, "unauthenticated@local");
        assert_eq!(ev[0].on_behalf_of, "cli:op1");
        assert_eq!((ev[0].count, ev[0].outcome.as_str()), (1, "success"));
        assert_eq!(ev[0].filter, "caller=<redacted>");
        assert_eq!(ev[1].outcome, "invalid");
        assert_eq!(ev[1].user, "unauthenticated@local");
        assert_eq!(ev[1].on_behalf_of, "");
        assert!(!format!("{ev:?}").contains("5550100"));
        Ok(())
    }

    /// SEC-8 / NIST-R2-01: under mTLS the audit principal is the client
    /// certificate name from the gate; x-sbc-user is only on_behalf_of.
    #[tokio::test]
    async fn audit_principal_is_the_client_certificate() -> TestResult {
        let (state, _emitter) = state_with_ring()?;
        let svc = CdrServiceImpl::new(state);
        let capture = uc_audit::capture::start();
        let mut req = Request::new(ListCdrsRequest::default());
        req.metadata_mut()
            .insert(USER_METADATA, "api:admin".parse()?);
        req.extensions_mut()
            .insert(super::super::PeerPrincipal("cert:rel-sbc-api".into()));
        svc.list_cdrs(req).await?;
        let ev: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CdrExport(x) => Some(x),
                _ => None,
            })
            .collect();
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].user, "cert:rel-sbc-api@local");
        assert_eq!(ev[0].on_behalf_of, "api:admin");
        Ok(())
    }

    fn code<T>(r: Result<T, Status>) -> Option<tonic::Code> {
        r.err().map(|e| e.code())
    }

    #[tokio::test]
    async fn list_rejects_bad_input() -> TestResult {
        let (state, _e) = state_with_ring()?;
        let svc = CdrServiceImpl::new(state);
        for req in [
            ListCdrsRequest {
                disposition: "bogus".into(),
                ..Default::default()
            },
            ListCdrsRequest {
                page_token: "12x".into(),
                ..Default::default()
            },
            ListCdrsRequest {
                caller: "x".repeat(1000),
                ..Default::default()
            },
            ListCdrsRequest {
                start_ms: 10,
                end_ms: 5,
                ..Default::default()
            },
        ] {
            let r = svc.list_cdrs(Request::new(req)).await;
            assert_eq!(code(r), Some(tonic::Code::InvalidArgument));
        }
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cdrs_fail_precondition() {
        let mut state = AppState::new(
            uc_metrics::SbcMetrics::standard(),
            Arc::new(crate::server::ServerStats::default()),
        );
        state.sip_stack = Some(Arc::new(SipStack::new(SipStackConfig::default())));
        let svc = CdrServiceImpl::new(Arc::new(state));
        let r = svc
            .list_cdrs(Request::new(ListCdrsRequest::default()))
            .await;
        assert_eq!(code(r), Some(tonic::Code::FailedPrecondition));
    }
}
