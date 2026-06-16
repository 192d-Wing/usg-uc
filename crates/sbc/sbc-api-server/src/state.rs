//! Application state shared across all sbc-api handlers.
//!
//! Holds the Postgres stores (one per config entity), the three gRPC
//! clients to the daemon's sync services, and a reqwest client used by
//! the reverse-proxy fallback.

use std::sync::Arc;
use std::time::Duration;

use sbc_config_store::{
    PostgresCallingSearchSpaceStore, PostgresDialPlanStore, PostgresDirectoryNumberStore,
    PostgresPartitionStore, PostgresPhoneStore, PostgresRouteListStore, PostgresRoutePatternStore,
    PostgresTrunkGroupStore,
};
use sbc_grpc_api::prelude::{
    CallServiceClient, DialPlanSyncServiceClient, DidMappingSyncServiceClient,
    RegistrationServiceClient, SbcSyncServiceClient, SystemServiceClient, TrunkHealthServiceClient,
    TrunkSyncServiceClient,
};
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::info;
use uc_user_mgmt::postgres::PostgresUserStore;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("postgres init failed: {0}")]
    Postgres(String),
    #[error("daemon grpc channel build failed: {0}")]
    Grpc(String),
    #[error("daemon http client build failed: {0}")]
    Http(String),
    #[error("authentication setup failed: {0}")]
    Auth(String),
}

#[derive(Clone)]
pub struct AppState {
    pub phones: Arc<PostgresPhoneStore>,
    pub directory: Arc<PostgresDirectoryNumberStore>,
    pub trunk_groups: Arc<PostgresTrunkGroupStore>,
    pub dial_plans: Arc<PostgresDialPlanStore>,
    /// Postgres-backed user store. Moves /users CRUD off the daemon as
    /// of PR10. SIP digest auth still happens in the daemon, but it
    /// reads through the same `users` table via its own pool.
    pub users: Arc<PostgresUserStore>,
    /// Postgres-backed SBC-routing stores (PR11). sbc-api owns CRUD;
    /// after each write it notifies the daemon via `sbc_sync` so the
    /// live router catches up without a daemon restart.
    pub partitions: Arc<PostgresPartitionStore>,
    /// See [`Self::partitions`].
    pub css: Arc<PostgresCallingSearchSpaceStore>,
    /// See [`Self::partitions`].
    pub route_patterns: Arc<PostgresRoutePatternStore>,
    /// See [`Self::partitions`].
    pub route_lists: Arc<PostgresRouteListStore>,

    /// gRPC clients into the daemon's sync services. Cloning a tonic
    /// client is cheap (Arc<Channel> underneath) so handlers take
    /// `&self.state` and clone on use.
    pub trunk_sync: TrunkSyncServiceClient<Channel>,
    pub dial_plan_sync: DialPlanSyncServiceClient<Channel>,
    pub did_sync: DidMappingSyncServiceClient<Channel>,
    /// gRPC clients for SIP-state reads. These replace the HTTP-proxy
    /// fallback path for `/calls`, `/registrations`, and `/system/*`
    /// reads — sbc-api now talks gRPC directly to the daemon instead
    /// of reverse-proxying HTTP, which lets us delete the daemon's
    /// REST API entirely.
    pub calls: CallServiceClient<Channel>,
    pub registrations: RegistrationServiceClient<Channel>,
    pub system: SystemServiceClient<Channel>,
    /// Runtime trunk-state reads + `RegisterTrunk` trigger. Replaces the
    /// daemon's REST `/trunk-health`, `/trunk-registration`, and
    /// `/trunk-registration/{id}/register` endpoints (PR9).
    pub trunk_health: TrunkHealthServiceClient<Channel>,
    /// SBC-routing sync client (PR11) — sbc-api notifies the daemon
    /// "I changed partition / CSS / route-pattern / route-list X,
    /// please re-apply from Postgres to the live `SbcRouter`".
    pub sbc_sync: SbcSyncServiceClient<Channel>,

    /// HTTP client + base URL used by the reverse-proxy fallback for
    /// endpoints sbc-api doesn't own.
    pub http_client: reqwest::Client,
    pub daemon_http_base: String,

    /// Process start instant, for /system/version uptime reporting.
    pub start_time: std::time::Instant,

    /// Management-plane authenticator (admin login + stateless tokens).
    /// Shared, replica-safe via a common signing key.
    pub auth: Arc<uc_auth::Authenticator>,

    /// Optional operator OIDC validator. When configured, the auth
    /// middleware also accepts `config-admin` bearer tokens, so the
    /// dashboard authenticates once for both the central and per-site APIs.
    pub oidc: Option<Arc<proto_jwt::Validator>>,
}

impl AppState {
    #[allow(clippy::too_many_lines)] // flat wiring of all stores + clients
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
        let users = Arc::new(
            PostgresUserStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let partitions = Arc::new(
            PostgresPartitionStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let css = Arc::new(
            PostgresCallingSearchSpaceStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let route_patterns = Arc::new(
            PostgresRoutePatternStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
        );
        let route_lists = Arc::new(
            PostgresRouteListStore::new(&cfg.database_url)
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
        let did_sync = DidMappingSyncServiceClient::new(channel.clone());
        let calls = CallServiceClient::new(channel.clone());
        let registrations = RegistrationServiceClient::new(channel.clone());
        let system = SystemServiceClient::new(channel.clone());
        let trunk_health = TrunkHealthServiceClient::new(channel.clone());
        let sbc_sync = SbcSyncServiceClient::new(channel);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| StateError::Http(e.to_string()))?;

        // Fail closed: without admin credentials the management plane
        // cannot authenticate anyone, so refuse to start (forces the Helm
        // chart to mount SBC_ADMIN_PASSWORD[_HASH] + SBC_AUTH_SIGNING_KEY).
        let auth = Arc::new(
            uc_auth::Authenticator::from_env().map_err(|e| StateError::Auth(e.to_string()))?,
        );
        info!("management-plane authentication enabled");

        // Optional operator OIDC: accept the same config-admin tokens the
        // central config API takes, so the dashboard signs in once.
        let oidc = match (&cfg.oidc_issuer, &cfg.oidc_audience) {
            (Some(issuer), Some(audience)) => {
                // Trust an extra CA for the JWKS fetch when the IdP is
                // fronted by an internal CA (SBC_OIDC_EXTRA_CA_CERT_FILE),
                // mirroring the daemon. Without it the rustls webpki roots
                // can't verify e.g. icam.oopl.dev.mil and every bearer 401s.
                let mut http_builder = reqwest::Client::builder();
                if let Ok(path) = std::env::var("SBC_OIDC_EXTRA_CA_CERT_FILE")
                    && !path.trim().is_empty()
                {
                    match std::fs::read(&path) {
                        Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                            Ok(cert) => {
                                info!(path, "loaded extra CA certificate for OIDC JWKS fetch");
                                http_builder = http_builder.add_root_certificate(cert);
                            }
                            Err(e) => {
                                tracing::error!(path, error = %e, "failed to parse SBC_OIDC_EXTRA_CA_CERT_FILE");
                            }
                        },
                        Err(e) => {
                            tracing::error!(path, error = %e, "failed to read SBC_OIDC_EXTRA_CA_CERT_FILE");
                        }
                    }
                }
                let http = http_builder
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());
                let jwks = Arc::new(proto_jwt::JwksCache::new(http, issuer.clone()));
                let validator = proto_jwt::Validator::new(
                    jwks,
                    proto_jwt::ValidatorConfig {
                        issuer: issuer.clone(),
                        audiences: vec![audience.clone()],
                        required_scope: crate::authmw::ADMIN_SCOPE,
                        leeway_secs: 30,
                    },
                );
                info!(issuer = %issuer, "operator OIDC bearer auth enabled");
                Some(Arc::new(validator))
            }
            _ => None,
        };

        Ok(Arc::new(Self {
            phones,
            directory,
            trunk_groups,
            dial_plans,
            users,
            partitions,
            css,
            route_patterns,
            route_lists,
            trunk_sync,
            dial_plan_sync,
            did_sync,
            calls,
            registrations,
            system,
            trunk_health,
            sbc_sync,
            http_client,
            daemon_http_base: cfg.daemon_http_url.trim_end_matches('/').to_string(),
            start_time: std::time::Instant::now(),
            auth,
            oidc,
        }))
    }
}

/// Strip the password from a Postgres DSN so it can be safely logged.
fn scrub_dsn(dsn: &str) -> String {
    // Naive: replace `user:pass@host` with `user:***@host`. Doesn't
    // handle every DSN form (e.g., URL-encoded creds) but catches the
    // typical postgres://user:pass@host/db shape we emit from Helm.
    if let Some(at) = dsn.find('@')
        && let Some(scheme_end) = dsn.find("://")
    {
        let after_scheme = scheme_end + 3;
        if let Some(colon) = dsn[after_scheme..at].find(':') {
            let mut out = String::with_capacity(dsn.len());
            out.push_str(&dsn[..=(after_scheme + colon)]);
            out.push_str("***");
            out.push_str(&dsn[at..]);
            return out;
        }
    }
    dsn.to_string()
}
