//! SystemService gRPC implementation.
//!
//! Provides system-level management operations via gRPC.

use crate::api_server::AppState;
use sbc_grpc_api::sbc::system_service_server::SystemService;
use sbc_grpc_api::sbc::{
    GetMetricsRequest, GetMetricsResponse, GetStatsRequest, GetStatsResponse, GetTlsStatusRequest,
    GetTlsStatusResponse, GetVersionRequest, GetVersionResponse, ReloadTlsRequest,
    ReloadTlsResponse, ShutdownRequest, ShutdownResponse, TlsStatus,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tonic::{Request, Response, Status};
use tracing::info;

/// Audits a management-plane TLS certificate/key reload: `Rotated` with
/// success on `Ok(true)`, failure on `Err`, nothing on `Ok(false)` (TLS not
/// configured, no key touched).
///
/// The API acceptor accepts P-384 or P-521 keys (its curve is not pinned to
/// `security.curve`; POA&M-193), so the algorithm label is the family.
/// Filesystem paths in the failure reason (uc-transport cert-load errors
/// embed them) are reduced to the file name before auditing.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, SC-12, SI-11 (POA&M-166)
// POAM: POA&M-193, the API TLS acceptor (sbc-api-server api_server.rs) does
// not pin its key curve to `security.curve`, and REST-triggered TLS reloads
// are not audited; only this gRPC ReloadTls path emits a key event.
fn audit_tls_reload(result: &Result<bool, String>, key_path: Option<&std::path::Path>) {
    use uc_audit::event::{CryptoKeyOperation, KeyOperationType};
    const ROLE: &str = "api-tls";
    const ALGORITHM: &str = "ECDSA-P384/P521";
    let key_id = key_path.map_or_else(|| ROLE.to_string(), |p| crate::server::tls_key_id(ROLE, p));
    let event = match result {
        Ok(false) => return,
        Ok(true) => CryptoKeyOperation::success(key_id, KeyOperationType::Rotated, ALGORITHM),
        Err(e) => CryptoKeyOperation::failure(
            key_id,
            KeyOperationType::Rotated,
            ALGORITHM,
            &redact_paths(e),
        ),
    };
    uc_audit::log_event(uc_audit::AuditEvent::CryptoKeyOperation(event));
}

/// Replaces every whitespace-separated token that looks like a filesystem
/// path (contains `/` or `\\`) with its final component, keeping a trailing
/// `:` so `"/etc/sbc/tls/api.crt: bad"` becomes `"api.crt: bad"`.
///
/// ## NIST 800-53 Rev5: SI-11 (no internal paths in audit records)
fn redact_paths(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len());
    for (i, tok) in reason.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if tok.contains(['/', '\\']) {
            let (body, colon) = tok.strip_suffix(':').map_or((tok, ""), |b| (b, ":"));
            let name = body.rsplit(['/', '\\']).next().unwrap_or_default();
            out.push_str(name);
            out.push_str(colon);
        } else {
            out.push_str(tok);
        }
    }
    out
}

/// SystemService implementation.
pub struct SystemServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for SystemServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemServiceImpl").finish_non_exhaustive()
    }
}

impl SystemServiceImpl {
    /// Creates a new SystemService implementation.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl SystemService for SystemServiceImpl {
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        info!("gRPC GetVersion");

        let response = GetVersionResponse {
            version: self.state.version.clone(),
            name: "sbc-daemon".to_string(),
            build_time: String::new(),
            rust_version: String::new(),
            git_commit: String::new(),
            git_branch: String::new(),
            release_build: cfg!(not(debug_assertions)),
            target: std::env::consts::ARCH.to_string(),
            features: vec![],
        };

        Ok(Response::new(response))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        info!("gRPC GetStats");

        let stats = &self.state.stats;
        #[allow(clippy::cast_possible_wrap)]
        let response = GetStatsResponse {
            calls_total: stats.calls_total.load(Ordering::Relaxed) as i64,
            calls_active: stats.calls_active.load(Ordering::Relaxed) as i64,
            registrations_total: stats.registrations_total.load(Ordering::Relaxed) as i64,
            registrations_active: stats.registrations_active.load(Ordering::Relaxed) as i64,
            messages_received: stats.messages_received.load(Ordering::Relaxed) as i64,
            messages_sent: stats.messages_sent.load(Ordering::Relaxed) as i64,
            rate_limited: stats.rate_limited.load(Ordering::Relaxed) as i64,
            uptime_secs: self.state.uptime_secs() as i64,
            start_time: None, // TODO: Convert to protobuf timestamp
            memory_usage_bytes: 0,
            peak_memory_bytes: 0,
            active_connections: 0,
            active_transactions: 0,
            active_dialogs: 0,
        };

        Ok(Response::new(response))
    }

    async fn get_metrics(
        &self,
        request: Request<GetMetricsRequest>,
    ) -> Result<Response<GetMetricsResponse>, Status> {
        let req = request.into_inner();
        info!(prefix = %req.prefix, "gRPC GetMetrics");

        self.state.refresh_daemon_metrics();
        let metrics_text = self.state.metrics.export();
        let response = GetMetricsResponse {
            metrics: metrics_text,
            content_type: "text/plain; version=0.0.4; charset=utf-8".to_string(),
        };

        Ok(Response::new(response))
    }

    async fn reload_tls(
        &self,
        _request: Request<ReloadTlsRequest>,
    ) -> Result<Response<ReloadTlsResponse>, Status> {
        info!("gRPC ReloadTls");

        let result = self.state.reload_tls_certificates();
        let key_path = self
            .state
            .tls_acceptor
            .as_ref()
            .map(|a| a.key_path().clone());
        audit_tls_reload(&result, key_path.as_deref());
        match result {
            Ok(true) => {
                let tls_stats = self.state.tls_stats();
                let response = ReloadTlsResponse {
                    success: true,
                    message: "TLS certificates reloaded successfully".to_string(),
                    status: tls_stats.map(|s| TlsStatus {
                        reload_count: s.reload_count as i64,
                        last_reload: None,
                        cert_path: s.cert_path,
                        key_path: s.key_path,
                        cert_expiry: None,
                        cert_subject: String::new(),
                        cert_issuer: String::new(),
                        cert_serial: String::new(),
                        days_until_expiry: 0,
                        cnsa_compliant: true,
                        tls_version: "1.3".to_string(),
                        cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
                    }),
                };
                Ok(Response::new(response))
            }
            Ok(false) => {
                let response = ReloadTlsResponse {
                    success: false,
                    message: "TLS is not enabled".to_string(),
                    status: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => Err(Status::internal(format!(
                "Failed to reload TLS certificates: {e}"
            ))),
        }
    }

    async fn get_tls_status(
        &self,
        _request: Request<GetTlsStatusRequest>,
    ) -> Result<Response<GetTlsStatusResponse>, Status> {
        info!("gRPC GetTlsStatus");

        let tls_stats = self.state.tls_stats();
        let response = GetTlsStatusResponse {
            enabled: tls_stats.is_some(),
            status: tls_stats.map(|s| TlsStatus {
                reload_count: s.reload_count as i64,
                last_reload: None,
                cert_path: s.cert_path,
                key_path: s.key_path,
                cert_expiry: None,
                cert_subject: String::new(),
                cert_issuer: String::new(),
                cert_serial: String::new(),
                days_until_expiry: 0,
                cnsa_compliant: true,
                tls_version: "1.3".to_string(),
                cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            }),
        };

        Ok(Response::new(response))
    }

    async fn shutdown(
        &self,
        request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        let req = request.into_inner();
        info!(
            timeout_secs = req.timeout_secs,
            reason = %req.reason,
            drain_only = req.drain_only,
            "gRPC Shutdown"
        );

        // TODO: Implement actual shutdown initiation
        // This would need access to the ShutdownCoordinator
        Err(Status::unimplemented("Shutdown not yet implemented"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{audit_tls_reload, redact_paths};
    use uc_audit::event::{KeyOperationOutcome, KeyOperationType};

    fn key_ops(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::CryptoKeyOperation> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CryptoKeyOperation(k) => Some(k.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn reload_ok_audits_rotated_success() {
        let capture = uc_audit::capture::start();
        audit_tls_reload(
            &Ok(true),
            Some(std::path::Path::new("/etc/sbc/tls/api.key")),
        );
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].operation, KeyOperationType::Rotated);
        assert_eq!(ops[0].outcome, KeyOperationOutcome::Success);
        assert_eq!(ops[0].key_id, "api-tls:api.key");
    }

    #[test]
    fn reload_err_audits_failure_and_not_enabled_is_silent() {
        let capture = uc_audit::capture::start();
        audit_tls_reload(&Ok(false), None);
        assert!(key_ops(&capture.events()).is_empty());
        audit_tls_reload(&Err("private key curve mismatch\r\nX".to_string()), None);
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].outcome, KeyOperationOutcome::Failure);
        assert_eq!(ops[0].key_id, "api-tls");
        assert!(!ops[0].reason.as_deref().unwrap().contains('\n'));
    }

    #[test]
    fn reload_err_reason_has_no_cert_path() {
        let capture = uc_audit::capture::start();
        audit_tls_reload(
            &Err("/etc/sbc/secret-dir/api.crt: invalid PEM".to_string()),
            None,
        );
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 1);
        let reason = ops[0].reason.as_deref().unwrap();
        assert!(!reason.contains("secret-dir"), "{reason}");
        assert!(reason.contains("api.crt: invalid PEM"), "{reason}");
        assert_eq!(
            redact_paths("C:\\tls\\a.crt contains no certificates"),
            "a.crt contains no certificates"
        );
        assert_eq!(redact_paths("curve mismatch"), "curve mismatch");
    }
}
