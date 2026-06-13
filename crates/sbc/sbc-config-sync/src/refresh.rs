//! Best-effort daemon refresh after an apply.
//!
//! Applied config is already durable in the site-local Postgres, and the
//! daemon replays it on startup — so the live SIP router eventually
//! converges regardless. To make a change take effect *without* waiting
//! for a restart, the agent pokes the daemon's per-entity sync RPCs (the
//! same ones `sbc-api-server` calls) after each apply. These calls are
//! best-effort: a failure is logged and the cycle still succeeds, because
//! the source of truth is the database, not the RPC.
//!
//! Phones and site-telephony-config have no live daemon router (phones are
//! served by `sbc-provision-server` reading Postgres on boot), so they are
//! not refreshed.

use central_config_store::{ChangeOp, ConfigTable};
use sbc_grpc_api::prelude as p;
use tonic::transport::Channel;
use tracing::{debug, warn};

/// One entity the daemon should re-read after an apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshItem {
    /// Which config table changed.
    pub table: ConfigTable,
    /// The row id (`id` or `did`).
    pub id: String,
    /// Whether the row was upserted or deleted.
    pub op: ChangeOp,
}

/// Pokes the daemon to re-read changed entities. Best-effort by contract:
/// implementations must not fail the reconcile cycle.
pub trait Refresher {
    /// Notify the daemon of `items` (no-op if empty).
    fn refresh(&self, items: &[RefreshItem]) -> impl std::future::Future<Output = ()> + Send;
}

/// Refresher that does nothing — used when no daemon gRPC URL is
/// configured (the daemon will pick changes up on its next restart).
pub struct NoopRefresher;

impl Refresher for NoopRefresher {
    async fn refresh(&self, _items: &[RefreshItem]) {}
}

/// Runtime choice of refresher.
///
/// The [`Refresher`] trait has an async method (so it isn't
/// `dyn`-compatible); this enum lets the agent pick a backend at startup
/// and still pass a concrete type to `reconcile`.
pub enum AnyRefresher {
    /// Poke the daemon over gRPC (boxed — it holds four gRPC clients).
    Grpc(Box<GrpcRefresher>),
    /// Do nothing.
    Noop,
}

impl Refresher for AnyRefresher {
    async fn refresh(&self, items: &[RefreshItem]) {
        match self {
            Self::Grpc(r) => r.refresh(items).await,
            Self::Noop => {}
        }
    }
}

/// gRPC refresher: dispatches each item to the daemon's matching
/// `Sync`/`Remove` RPC. Clients are cheaply cloneable (the channel is an
/// `Arc`), so each call clones rather than locking.
pub struct GrpcRefresher {
    trunk: p::TrunkSyncServiceClient<Channel>,
    dial_plan: p::DialPlanSyncServiceClient<Channel>,
    did: p::DidMappingSyncServiceClient<Channel>,
    sbc: p::SbcSyncServiceClient<Channel>,
}

impl GrpcRefresher {
    /// Connect (lazily) to the daemon's gRPC endpoint (`http://host:port`).
    ///
    /// # Errors
    /// Returns the URI parse error string if `daemon_grpc_url` is malformed.
    /// The connection itself is lazy and never fails here.
    pub fn connect(daemon_grpc_url: &str) -> Result<Self, String> {
        let channel = Channel::from_shared(daemon_grpc_url.to_string())
            .map_err(|e| e.to_string())?
            .connect_lazy();
        Ok(Self {
            trunk: p::TrunkSyncServiceClient::new(channel.clone()),
            dial_plan: p::DialPlanSyncServiceClient::new(channel.clone()),
            did: p::DidMappingSyncServiceClient::new(channel.clone()),
            sbc: p::SbcSyncServiceClient::new(channel),
        })
    }
}

impl Refresher for GrpcRefresher {
    async fn refresh(&self, items: &[RefreshItem]) {
        for item in items {
            let id = item.id.clone();
            let upsert = item.op == ChangeOp::Upsert;
            // Each arm clones the relevant client (cheap) and fires the
            // matching RPC; errors are logged, never propagated.
            let result: Result<(), tonic::Status> = match item.table {
                ConfigTable::TrunkGroups => {
                    let mut c = self.trunk.clone();
                    if upsert {
                        c.sync_trunk_group(p::SyncTrunkGroupRequest { group_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_trunk_group(p::RemoveTrunkGroupRequest { group_id: id })
                            .await
                            .map(drop)
                    }
                }
                ConfigTable::DialPlans => {
                    let mut c = self.dial_plan.clone();
                    if upsert {
                        c.sync_dial_plan(p::SyncDialPlanRequest { plan_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_dial_plan(p::RemoveDialPlanRequest { plan_id: id })
                            .await
                            .map(drop)
                    }
                }
                ConfigTable::DirectoryNumbers => {
                    let mut c = self.did.clone();
                    if upsert {
                        c.sync_directory_number(p::SyncDirectoryNumberRequest { did: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_directory_number(p::RemoveDirectoryNumberRequest { did: id })
                            .await
                            .map(drop)
                    }
                }
                ConfigTable::SbcPartitions => {
                    let mut c = self.sbc.clone();
                    if upsert {
                        c.sync_partition(p::SyncPartitionRequest { partition_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_partition(p::RemovePartitionRequest { partition_id: id })
                            .await
                            .map(drop)
                    }
                }
                ConfigTable::SbcCallingSearchSpaces => {
                    let mut c = self.sbc.clone();
                    if upsert {
                        c.sync_calling_search_space(p::SyncCallingSearchSpaceRequest { css_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_calling_search_space(p::RemoveCallingSearchSpaceRequest {
                            css_id: id,
                        })
                        .await
                        .map(drop)
                    }
                }
                ConfigTable::SbcRoutePatterns => {
                    let mut c = self.sbc.clone();
                    if upsert {
                        c.sync_route_pattern(p::SyncRoutePatternRequest { pattern_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_route_pattern(p::RemoveRoutePatternRequest { pattern_id: id })
                            .await
                            .map(drop)
                    }
                }
                ConfigTable::SbcRouteLists => {
                    let mut c = self.sbc.clone();
                    if upsert {
                        c.sync_route_list(p::SyncRouteListRequest { list_id: id })
                            .await
                            .map(drop)
                    } else {
                        c.remove_route_list(p::RemoveRouteListRequest { list_id: id })
                            .await
                            .map(drop)
                    }
                }
                // No live daemon router for these — provisioning reads
                // Postgres directly; site config isn't consumed live yet.
                ConfigTable::Phones | ConfigTable::SiteTelephonyConfig => continue,
            };
            match result {
                Ok(()) => debug!(table = item.table.name(), id = %item.id, "daemon refresh ok"),
                Err(e) => warn!(table = item.table.name(), id = %item.id, error = %e,
                    "daemon refresh RPC failed (config is in Postgres; daemon catches up on restart)"),
            }
        }
    }
}
