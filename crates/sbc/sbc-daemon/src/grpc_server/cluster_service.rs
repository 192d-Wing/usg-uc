//! ClusterService gRPC implementation.
//!
//! Provides cluster management operations via gRPC.
//! This service is only available when the `cluster` feature is enabled.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-24**: Fail in Known State - Graceful failover
//! - **CP-10**: System Recovery - Automatic failover and rejoin

use crate::api_server::AppState;
use crate::cluster::ClusterManager;
use sbc_grpc_api::sbc::cluster_service_server::ClusterService;
use sbc_grpc_api::sbc::{
    ClusterEvent, ClusterHealth as ProtoClusterHealth, DrainNodeRequest, DrainNodeResponse,
    GetClusterStatusRequest, GetClusterStatusResponse, GetNodeStatusRequest, GetNodeStatusResponse,
    InitiateFailoverRequest, InitiateFailoverResponse, ListNodesRequest, ListNodesResponse,
    NodeInfo, NodeMetrics, NodeRole as ProtoNodeRole, NodeState as ProtoNodeState,
    UndoFailoverRequest, UndoFailoverResponse, WatchClusterRequest,
};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::info;
use uc_cluster::node::{NodeRole, NodeState, NodeSummary};

/// ClusterService implementation.
pub struct ClusterServiceImpl {
    state: Arc<AppState>,
    cluster: Arc<ClusterManager>,
}

impl std::fmt::Debug for ClusterServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterServiceImpl").finish_non_exhaustive()
    }
}

impl ClusterServiceImpl {
    /// Creates a new ClusterService implementation.
    pub fn new(state: Arc<AppState>, cluster: Arc<ClusterManager>) -> Self {
        Self { state, cluster }
    }

    /// Converts internal NodeRole to protobuf NodeRole.
    fn to_proto_role(role: NodeRole) -> i32 {
        match role {
            NodeRole::Primary => ProtoNodeRole::Primary as i32,
            NodeRole::Secondary => ProtoNodeRole::Secondary as i32,
            NodeRole::Witness => ProtoNodeRole::Witness as i32,
        }
    }

    /// Converts internal NodeState to protobuf NodeState.
    fn to_proto_state(state: NodeState) -> i32 {
        match state {
            NodeState::Starting => ProtoNodeState::Initializing as i32,
            NodeState::Syncing => ProtoNodeState::Initializing as i32,
            NodeState::Ready => ProtoNodeState::Standby as i32,
            NodeState::Active => ProtoNodeState::Active as i32,
            NodeState::Draining => ProtoNodeState::Draining as i32,
            NodeState::Unhealthy => ProtoNodeState::Failed as i32,
            NodeState::ShuttingDown => ProtoNodeState::Maintenance as i32,
        }
    }

    /// Converts a NodeSummary to protobuf NodeInfo.
    fn node_summary_to_info(&self, summary: &NodeSummary) -> NodeInfo {
        let stats = &self.state.stats;

        NodeInfo {
            node_id: summary.node_id.clone(),
            role: Self::to_proto_role(summary.role),
            state: Self::to_proto_state(summary.state),
            address: String::new(), // Would be populated from endpoints
            sip_address: String::new(),
            api_address: String::new(),
            last_seen: None, // Would calculate from ms_since_heartbeat
            uptime_secs: 0,  // TODO: Track node uptime
            metrics: Some(NodeMetrics {
                active_calls: i64::from(summary.active_calls),
                active_registrations: i64::from(summary.active_registrations),
                cpu_usage: 0.0,    // TODO: Track CPU usage
                memory_usage: 0.0, // TODO: Track memory usage
                network_in_bps: 0,
                network_out_bps: 0,
                disk_usage: 0.0,
                load_score: summary.health_score,
                calls_per_second: 0.0,
                messages_per_second: stats.messages_received.load(Ordering::Relaxed) as f64 / 60.0,
            }),
            version: env!("CARGO_PKG_VERSION").to_string(),
            region: summary.region.clone(),
            zone: summary.zone.clone(),
            labels: std::collections::HashMap::new(),
        }
    }
}

#[tonic::async_trait]
impl ClusterService for ClusterServiceImpl {
    async fn get_cluster_status(
        &self,
        _request: Request<GetClusterStatusRequest>,
    ) -> Result<Response<GetClusterStatusResponse>, Status> {
        info!("gRPC GetClusterStatus");

        let status = self.cluster.status().await;
        let quorum_status = self.cluster.membership().quorum_status().await;

        // Convert internal health to proto health
        let health = ProtoClusterHealth {
            healthy: status.health.healthy,
            storage_healthy: status.health.storage_healthy,
            discovery_healthy: status.health.discovery_healthy,
            location_healthy: status.health.location_healthy,
            sync_healthy: true, // TODO: Track sync health
            healthy_nodes: quorum_status.active_voters as i32,
            quorum_size: quorum_status.required as i32,
            quorum_met: quorum_status.has_quorum,
            checks: vec![], // TODO: Add detailed health checks
        };

        // Parse role from status string
        let role = match status.role.to_lowercase().as_str() {
            "primary" => ProtoNodeRole::Primary as i32,
            "secondary" => ProtoNodeRole::Secondary as i32,
            "witness" => ProtoNodeRole::Witness as i32,
            _ => ProtoNodeRole::Unspecified as i32,
        };

        // Parse state from status string
        let state = match status.state.to_lowercase().as_str() {
            "starting" | "syncing" => ProtoNodeState::Initializing as i32,
            "ready" => ProtoNodeState::Standby as i32,
            "active" => ProtoNodeState::Active as i32,
            "draining" => ProtoNodeState::Draining as i32,
            "unhealthy" => ProtoNodeState::Failed as i32,
            "shuttingdown" => ProtoNodeState::Maintenance as i32,
            _ => ProtoNodeState::Unspecified as i32,
        };

        let response = GetClusterStatusResponse {
            node_id: status.node_id,
            role,
            state,
            health: Some(health),
            member_count: status.member_count as i32,
            storage_backend: status.storage_backend,
            cluster_id: String::new(), // TODO: Add cluster ID to ClusterStatus
            leader_id: String::new(),  // TODO: Track leader
            last_sync: None,           // TODO: Track last sync time
            replication_lag_ms: 0,     // TODO: Track replication lag
        };

        Ok(Response::new(response))
    }

    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let req = request.into_inner();
        info!(
            role_filter = req.role_filter,
            state_filter = req.state_filter,
            include_offline = req.include_offline,
            "gRPC ListNodes"
        );

        let members = self.cluster.membership().all_members().await;

        // Apply filters
        let filtered: Vec<NodeInfo> = members
            .iter()
            .filter(|m| {
                // Role filter
                if req.role_filter != ProtoNodeRole::Unspecified as i32 {
                    let member_role = Self::to_proto_role(m.role);
                    if member_role != req.role_filter {
                        return false;
                    }
                }

                // State filter
                if req.state_filter != ProtoNodeState::Unspecified as i32 {
                    let member_state = Self::to_proto_state(m.state);
                    if member_state != req.state_filter {
                        return false;
                    }
                }

                // Include offline filter
                if !req.include_offline && !m.state.is_healthy() {
                    return false;
                }

                true
            })
            .map(|m| self.node_summary_to_info(m))
            .collect();

        let response = ListNodesResponse {
            nodes: filtered.clone(),
            total: filtered.len() as i32,
        };

        Ok(Response::new(response))
    }

    async fn get_node_status(
        &self,
        request: Request<GetNodeStatusRequest>,
    ) -> Result<Response<GetNodeStatusResponse>, Status> {
        let req = request.into_inner();
        info!(node_id = %req.node_id, "gRPC GetNodeStatus");

        let node_id = uc_cluster::NodeId::new(&req.node_id);
        let node = self.cluster.membership().get_node(&node_id).await;

        match node {
            Some(summary) => {
                let node_info = self.node_summary_to_info(&summary);
                Ok(Response::new(GetNodeStatusResponse {
                    node: Some(node_info),
                }))
            }
            None => Err(Status::not_found(format!(
                "Node not found: {}",
                req.node_id
            ))),
        }
    }

    async fn initiate_failover(
        &self,
        request: Request<InitiateFailoverRequest>,
    ) -> Result<Response<InitiateFailoverResponse>, Status> {
        let req = request.into_inner();
        info!(
            target_node_id = %req.target_node_id,
            reason = %req.reason,
            force = req.force,
            "gRPC InitiateFailover"
        );

        // TODO: Implement actual failover via FailoverCoordinator
        // For now, return unimplemented
        Err(Status::unimplemented(
            "InitiateFailover not yet implemented - requires FailoverCoordinator integration",
        ))
    }

    async fn drain_node(
        &self,
        request: Request<DrainNodeRequest>,
    ) -> Result<Response<DrainNodeResponse>, Status> {
        let req = request.into_inner();
        info!(
            node_id = %req.node_id,
            timeout_secs = req.timeout_secs,
            reason = %req.reason,
            "gRPC DrainNode"
        );

        let node_id = uc_cluster::NodeId::new(&req.node_id);

        // Check if node exists
        let node = self.cluster.membership().get_node(&node_id).await;
        if node.is_none() {
            return Err(Status::not_found(format!(
                "Node not found: {}",
                req.node_id
            )));
        }

        // Mark node as draining
        // Note: This would normally trigger call migration
        match self.cluster.membership().mark_failed(&node_id).await {
            Ok(()) => {
                let response = DrainNodeResponse {
                    success: true,
                    message: format!("Node {} marked for draining", req.node_id),
                    calls_draining: 0,          // TODO: Track actual calls
                    registrations_migrating: 0, // TODO: Track registrations
                };
                Ok(Response::new(response))
            }
            Err(e) => Err(Status::internal(format!("Failed to drain node: {e}"))),
        }
    }

    async fn undo_failover(
        &self,
        request: Request<UndoFailoverRequest>,
    ) -> Result<Response<UndoFailoverResponse>, Status> {
        let req = request.into_inner();
        info!(
            operation_id = %req.operation_id,
            reason = %req.reason,
            "gRPC UndoFailover"
        );

        // TODO: Implement failover undo
        Err(Status::unimplemented(
            "UndoFailover not yet implemented - requires FailoverCoordinator integration",
        ))
    }

    type WatchClusterStream =
        Pin<Box<dyn Stream<Item = Result<ClusterEvent, Status>> + Send + 'static>>;

    async fn watch_cluster(
        &self,
        request: Request<WatchClusterRequest>,
    ) -> Result<Response<Self::WatchClusterStream>, Status> {
        let req = request.into_inner();
        info!(
            include_membership = req.include_membership,
            include_role_changes = req.include_role_changes,
            include_health = req.include_health,
            "gRPC WatchCluster"
        );

        // TODO: Implement actual cluster event streaming
        // For now, return empty stream
        let stream = tokio_stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_role_conversion() {
        assert_eq!(
            ClusterServiceImpl::to_proto_role(NodeRole::Primary),
            ProtoNodeRole::Primary as i32
        );
        assert_eq!(
            ClusterServiceImpl::to_proto_role(NodeRole::Secondary),
            ProtoNodeRole::Secondary as i32
        );
        assert_eq!(
            ClusterServiceImpl::to_proto_role(NodeRole::Witness),
            ProtoNodeRole::Witness as i32
        );
    }

    #[test]
    fn test_proto_state_conversion() {
        assert_eq!(
            ClusterServiceImpl::to_proto_state(NodeState::Active),
            ProtoNodeState::Active as i32
        );
        assert_eq!(
            ClusterServiceImpl::to_proto_state(NodeState::Draining),
            ProtoNodeState::Draining as i32
        );
        assert_eq!(
            ClusterServiceImpl::to_proto_state(NodeState::Unhealthy),
            ProtoNodeState::Failed as i32
        );
    }
}
