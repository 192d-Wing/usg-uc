//! Application state shared across all sbc-api handlers.
//!
//! Holds the Postgres stores (one per config entity), the three gRPC
//! clients to the daemon's sync services, and a reqwest client used by
//! the reverse-proxy fallback.

use std::sync::Arc;
use std::time::Duration;

use sbc_config_store::{
    PostgresDialPlanStore, PostgresDirectoryNumberStore, PostgresPhoneStore,
    PostgresTrunkGroupStore,
};
use sbc_grpc_api::prelude::{
    DialPlanSyncServiceClient, DidMappingSyncServiceClient, TrunkSyncServiceClient,
};
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::info;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("postgres init failed: {0}")]
    Postgres(String),
    #[error("daemon grpc channel build failed: {0}")]
    Grpc(String),
    #[error("daemon http client build failed: {0}")]
    Http(String),
}

#[derive(Clone)]
pub struct AppState {
    pub phones: Arc<PostgresPhoneStore>,
    pub directory: Arc<PostgresDirectoryNumberStore>,
    pub trunk_groups: Arc<PostgresTrunkGroupStore>,
    pub dial_plans: Arc<PostgresDialPlanStore>,

    /// gRPC clients into the daemon's sync services. Cloning a tonic
    /// client is cheap (Arc<Channel> underneath) so handlers take
    /// `&self.state` and clone on use.
    pub trunk_sync: TrunkSyncServiceClient<Channel>,
    pub dial_plan_sync: DialPlanSyncServiceClient<Channel>,
    pub did_sync: DidMappingSyncServiceClient<Channel>,

    /// HTTP client + base URL used by the reverse-proxy fallback for
    /// endpoints sbc-api doesn't own.
    pub http_client: reqwest::Client,
    pub daemon_http_base: String,

    /// Process start instant, for /system/version uptime reporting.
    pub start_time: std::time::Instant,
}

impl AppState {
    pub async fn build(cfg: &Config) -> Result<Arc<Self>, StateError> {
        info!(database_url = %scrub_dsn(&cfg.database_url), "connecting to postgres");
        let phones = Arc::new(
            PostgresPhoneStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let directory = Arc::new(
            PostgresDirectoryNumberStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let trunk_groups = Arc::new(
            PostgresTrunkGroupStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let dial_plans = Arc::new(
            PostgresDialPlanStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );

        info!(grpc = %cfg.daemon_grpc_url, "dialing daemon gRPC");
        // Lazy connect: tonic doesn't actually open the TCP socket
        // until the first RPC, which is what we want — sbc-api should
        // come up even if the daemon is briefly unavailable (e.g.,
        // mid-restart) and recover when the daemon comes back.
        let endpoint = Endpoint::from_shared(cfg.daemon_grpc_url.clone())
            .map_err(|e| StateError::Grpc(e.to_string()))?
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));
        let channel = endpoint.connect_lazy();
        let trunk_sync = TrunkSyncServiceClient::new(channel.clone());
        let dial_plan_sync = DialPlanSyncServiceClient::new(channel.clone());
        let did_sync = DidMappingSyncServiceClient::new(channel);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| StateError::Http(e.to_string()))?;

        Ok(Arc::new(Self {
            phones,
            directory,
            trunk_groups,
            dial_plans,
            trunk_sync,
            dial_plan_sync,
            did_sync,
            http_client,
            daemon_http_base: cfg.daemon_http_url.trim_end_matches('/').to_string(),
            start_time: std::time::Instant::now(),
        }))
    }
}

/// Strip the password from a Postgres DSN so it can be safely logged.
fn scrub_dsn(dsn: &str) -> String {
    // Naive: replace `user:pass@host` with `user:***@host`. Doesn't
    // handle every DSN form (e.g., URL-encoded creds) but catches the
    // typical postgres://user:pass@host/db shape we emit from Helm.
    if let Some(at) = dsn.find('@') {
        if let Some(scheme_end) = dsn.find("://") {
            let after_scheme = scheme_end + 3;
            if let Some(colon) = dsn[after_scheme..at].find(':') {
                let mut out = String::with_capacity(dsn.len());
                out.push_str(&dsn[..after_scheme + colon + 1]);
                out.push_str("***");
                out.push_str(&dsn[at..]);
                return out;
            }
        }
    }
    dsn.to_string()
}
