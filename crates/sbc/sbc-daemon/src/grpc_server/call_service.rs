//! CallService gRPC implementation.
//!
//! Provides call management and monitoring operations via gRPC.

use crate::api_server::AppState;
use sbc_grpc_api::sbc::call_service_server::CallService;
use sbc_grpc_api::sbc::{
    CallEvent, GetCallRequest, GetCallResponse, GetCallStatsRequest, GetCallStatsResponse,
    ListCallsRequest, ListCallsResponse, TerminateCallRequest, TerminateCallResponse,
    WatchCallsRequest,
};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::info;

/// CallService implementation.
pub struct CallServiceImpl {
    state: Arc<AppState>,
}

impl std::fmt::Debug for CallServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallServiceImpl").finish_non_exhaustive()
    }
}

impl CallServiceImpl {
    /// Creates a new CallService implementation.
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl CallService for CallServiceImpl {
    async fn list_calls(
        &self,
        request: Request<ListCallsRequest>,
    ) -> Result<Response<ListCallsResponse>, Status> {
        let req = request.into_inner();
        info!(
            limit = req.limit,
            offset = req.offset,
            state_filter = ?req.state_filter,
            "gRPC ListCalls"
        );

        // Get active calls count from stats
        let active = self.state.stats.calls_active.load(Ordering::Relaxed);
        let total = self.state.stats.calls_total.load(Ordering::Relaxed);

        // TODO: Implement actual call listing from dialog manager
        // For now, return stats-based response
        #[allow(clippy::cast_possible_wrap)]
        let response = ListCallsResponse {
            calls: vec![], // Would be populated from dialog manager
            total: total as i64,
            active: active as i64,
        };

        Ok(Response::new(response))
    }

    async fn get_call(
        &self,
        request: Request<GetCallRequest>,
    ) -> Result<Response<GetCallResponse>, Status> {
        let req = request.into_inner();
        info!(call_id = %req.call_id, "gRPC GetCall");

        // TODO: Implement actual call lookup from dialog manager
        // For now, return not found
        Err(Status::not_found(format!(
            "Call not found: {}",
            req.call_id
        )))
    }

    async fn terminate_call(
        &self,
        request: Request<TerminateCallRequest>,
    ) -> Result<Response<TerminateCallResponse>, Status> {
        let req = request.into_inner();
        info!(
            call_id = %req.call_id,
            reason = %req.reason,
            cause_code = req.cause_code,
            "gRPC TerminateCall"
        );

        // TODO: Implement actual call termination via B2BUA
        // This would send BYE to both legs
        Err(Status::unimplemented("TerminateCall not yet implemented"))
    }

    async fn get_call_stats(
        &self,
        request: Request<GetCallStatsRequest>,
    ) -> Result<Response<GetCallStatsResponse>, Status> {
        let req = request.into_inner();
        info!(time_range_secs = req.time_range_secs, "gRPC GetCallStats");

        let stats = &self.state.stats;
        #[allow(clippy::cast_possible_wrap)]
        let response = GetCallStatsResponse {
            calls_total: stats.calls_total.load(Ordering::Relaxed) as i64,
            calls_active: stats.calls_active.load(Ordering::Relaxed) as i64,
            calls_completed: 0, // TODO: Track completed calls
            calls_failed: 0,    // TODO: Track failed calls
            average_duration_secs: 0.0,
            peak_concurrent: 0, // TODO: Track peak concurrent
            calls_per_second: 0.0,
            window_start: None,
            window_end: None,
        };

        Ok(Response::new(response))
    }

    type WatchCallsStream = Pin<Box<dyn Stream<Item = Result<CallEvent, Status>> + Send + 'static>>;

    async fn watch_calls(
        &self,
        request: Request<WatchCallsRequest>,
    ) -> Result<Response<Self::WatchCallsStream>, Status> {
        let req = request.into_inner();
        info!(
            state_filter = ?req.state_filter,
            include_leg_info = req.include_leg_info,
            "gRPC WatchCalls"
        );

        // TODO: Implement actual call event streaming
        // For now, return empty stream
        let stream = tokio_stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }
}
