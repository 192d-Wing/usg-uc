//! SystemService gRPC implementation.
//!
//! Provides system-level management operations via gRPC.

use crate::api_server::AppState;
use sbc_grpc_api::sbc::system_service_server::SystemService;
use sbc_grpc_api::sbc::{
    GetMetricsRequest, GetMetricsResponse, GetStatsRequest, GetStatsResponse,
    GetTlsStatusRequest, GetTlsStatusResponse, GetVersionRequest, GetVersionResponse,
    ReloadTlsRequest, ReloadTlsResponse, ShutdownRequest, ShutdownResponse, TlsStatus,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

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

        match self.state.reload_tls_certificates() {
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
