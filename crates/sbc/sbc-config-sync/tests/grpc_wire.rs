//! gRPC wire test for the daemon refresh: boot a mock daemon implementing
//! the four sync services, point a real `GrpcRefresher` at it over a real
//! tonic channel, and assert each `RefreshItem` lands on the correct
//! `Sync`/`Remove` RPC with the right id. This exercises the wire dispatch
//! the in-process recording-refresher test can't (entity → RPC mapping,
//! request field names, channel transport).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use central_config_store::{ChangeOp, ConfigTable};
use sbc_config_sync::refresh::{GrpcRefresher, RefreshItem, Refresher};
use sbc_grpc_api::prelude as p;
use tonic::{Request, Response, Status};

/// Records `"service.method:id"` for every RPC the refresher fires.
#[derive(Clone, Default)]
struct MockDaemon {
    calls: Arc<Mutex<Vec<String>>>,
}

impl MockDaemon {
    fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.to_string());
    }
}

#[tonic::async_trait]
impl p::TrunkSyncService for MockDaemon {
    async fn sync_trunk_group(
        &self,
        req: Request<p::SyncTrunkGroupRequest>,
    ) -> Result<Response<p::SyncTrunkGroupResponse>, Status> {
        self.note(&format!("trunk.sync:{}", req.into_inner().group_id));
        Ok(Response::new(p::SyncTrunkGroupResponse::default()))
    }
    async fn remove_trunk_group(
        &self,
        req: Request<p::RemoveTrunkGroupRequest>,
    ) -> Result<Response<p::RemoveTrunkGroupResponse>, Status> {
        self.note(&format!("trunk.remove:{}", req.into_inner().group_id));
        Ok(Response::new(p::RemoveTrunkGroupResponse::default()))
    }
}

#[tonic::async_trait]
impl p::DialPlanSyncService for MockDaemon {
    async fn sync_dial_plan(
        &self,
        req: Request<p::SyncDialPlanRequest>,
    ) -> Result<Response<p::SyncDialPlanResponse>, Status> {
        self.note(&format!("dialplan.sync:{}", req.into_inner().plan_id));
        Ok(Response::new(p::SyncDialPlanResponse::default()))
    }
    async fn remove_dial_plan(
        &self,
        req: Request<p::RemoveDialPlanRequest>,
    ) -> Result<Response<p::RemoveDialPlanResponse>, Status> {
        self.note(&format!("dialplan.remove:{}", req.into_inner().plan_id));
        Ok(Response::new(p::RemoveDialPlanResponse::default()))
    }
}

#[tonic::async_trait]
impl p::DidMappingSyncService for MockDaemon {
    async fn sync_directory_number(
        &self,
        req: Request<p::SyncDirectoryNumberRequest>,
    ) -> Result<Response<p::SyncDirectoryNumberResponse>, Status> {
        self.note(&format!("did.sync:{}", req.into_inner().did));
        Ok(Response::new(p::SyncDirectoryNumberResponse::default()))
    }
    async fn remove_directory_number(
        &self,
        req: Request<p::RemoveDirectoryNumberRequest>,
    ) -> Result<Response<p::RemoveDirectoryNumberResponse>, Status> {
        self.note(&format!("did.remove:{}", req.into_inner().did));
        Ok(Response::new(p::RemoveDirectoryNumberResponse::default()))
    }
}

#[tonic::async_trait]
impl p::SbcSyncService for MockDaemon {
    async fn sync_partition(
        &self,
        req: Request<p::SyncPartitionRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!(
            "sbc.sync_partition:{}",
            req.into_inner().partition_id
        ));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn remove_partition(
        &self,
        req: Request<p::RemovePartitionRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!(
            "sbc.remove_partition:{}",
            req.into_inner().partition_id
        ));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn sync_calling_search_space(
        &self,
        req: Request<p::SyncCallingSearchSpaceRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!("sbc.sync_css:{}", req.into_inner().css_id));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn remove_calling_search_space(
        &self,
        req: Request<p::RemoveCallingSearchSpaceRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!("sbc.remove_css:{}", req.into_inner().css_id));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn sync_route_pattern(
        &self,
        req: Request<p::SyncRoutePatternRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!("sbc.sync_pattern:{}", req.into_inner().pattern_id));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn remove_route_pattern(
        &self,
        req: Request<p::RemoveRoutePatternRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!(
            "sbc.remove_pattern:{}",
            req.into_inner().pattern_id
        ));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn sync_route_list(
        &self,
        req: Request<p::SyncRouteListRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!("sbc.sync_list:{}", req.into_inner().list_id));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
    async fn remove_route_list(
        &self,
        req: Request<p::RemoveRouteListRequest>,
    ) -> Result<Response<p::SyncSbcResponse>, Status> {
        self.note(&format!("sbc.remove_list:{}", req.into_inner().list_id));
        Ok(Response::new(p::SyncSbcResponse::default()))
    }
}

#[tokio::test]
async fn refresh_dispatches_to_the_right_rpc_over_the_wire() {
    let mock = MockDaemon::default();
    let calls = mock.calls.clone();

    // Bind an ephemeral port and serve all four sync services.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(p::TrunkSyncServiceServer::new(mock.clone()))
            .add_service(p::DialPlanSyncServiceServer::new(mock.clone()))
            .add_service(p::DidMappingSyncServiceServer::new(mock.clone()))
            .add_service(p::SbcSyncServiceServer::new(mock.clone()))
            .serve_with_incoming(incoming)
            .await
    });

    let refresher = GrpcRefresher::connect(&format!("http://{addr}")).expect("connect");

    // One item per dispatch arm we care about, mixing upsert/delete.
    let up = ChangeOp::Upsert;
    let del = ChangeOp::Delete;
    let items = vec![
        RefreshItem {
            table: ConfigTable::TrunkGroups,
            id: "us".into(),
            op: up,
        },
        RefreshItem {
            table: ConfigTable::DialPlans,
            id: "main".into(),
            op: del,
        },
        RefreshItem {
            table: ConfigTable::DirectoryNumbers,
            id: "5551234".into(),
            op: up,
        },
        RefreshItem {
            table: ConfigTable::SbcPartitions,
            id: "internal".into(),
            op: up,
        },
        RefreshItem {
            table: ConfigTable::SbcRouteLists,
            id: "rl1".into(),
            op: del,
        },
        // No live router for these — must NOT produce any RPC.
        RefreshItem {
            table: ConfigTable::Phones,
            id: "p1".into(),
            op: up,
        },
        RefreshItem {
            table: ConfigTable::SiteTelephonyConfig,
            id: "default".into(),
            op: up,
        },
    ];
    refresher.refresh(&items).await;

    let mut got = calls.lock().unwrap().clone();
    got.sort();
    let mut want = vec![
        "trunk.sync:us".to_string(),
        "dialplan.remove:main".to_string(),
        "did.sync:5551234".to_string(),
        "sbc.sync_partition:internal".to_string(),
        "sbc.remove_list:rl1".to_string(),
    ];
    want.sort();
    assert_eq!(
        got, want,
        "exactly the routable items hit their RPCs; phones/site-config skipped"
    );
}
