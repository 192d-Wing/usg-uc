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
    CallServiceClient, CdrServiceClient, DialPlanSyncServiceClient, DidMappingSyncServiceClient,
    RegistrationServiceClient, SbcSyncServiceClient, SystemServiceClient, TrunkHealthServiceClient,
    TrunkSyncServiceClient,
};
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::info;
use uc_user_mgmt::encrypt::EncryptedUserStore;
use uc_user_mgmt::postgres::PostgresUserStore;

/// The users store: Postgres with HA1 sealed at rest.
pub type UserStoreImpl = EncryptedUserStore<PostgresUserStore>;

/// Advisory-lock name serializing the HA1 re-encrypt job across replicas.
const HA1_REENCRYPT_LOCK: &str = "uc_user_mgmt.ha1_reencrypt";
/// Give up waiting for a peer replica's re-encrypt lock after this long and
/// exit non-zero (the orchestrator restarts us). NIST 800-53 Rev5: CP-10
const HA1_REENCRYPT_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
    #[error("HA1 encryption key: {0}")]
    Ha1Key(String),
    #[error("HA1 re-encryption failed: {0}")]
    Ha1Reencrypt(String),
}

#[derive(Clone)]
pub struct AppState {
    pub phones: Arc<PostgresPhoneStore>,
    pub directory: Arc<PostgresDirectoryNumberStore>,
    pub trunk_groups: Arc<PostgresTrunkGroupStore>,
    pub dial_plans: Arc<PostgresDialPlanStore>,
    /// Postgres-backed user store with `digest_ha1` AES-256-GCM sealed at
    /// rest. sbc-api is the only consumer of the `users` table: sbc-daemon
    /// SIP digest auth does not read it today. If it ever does, the daemon
    /// must also load `SBC_USER_HA1_KEY_FILE` and wrap its store in
    /// `EncryptedUserStore`.
    ///
    /// ## NIST 800-53 Rev5: SC-28(1), IA-5(1)(c)
    pub users: Arc<UserStoreImpl>,
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
    /// Read-only CDR ring queries (`/cdrs`). Replaces the HTTP-proxy
    /// fallback to the daemon's former `/cdrs` stub.
    pub cdrs: CdrServiceClient<Channel>,

    /// HTTP client + base URL used by the reverse-proxy fallback for
    /// endpoints sbc-api doesn't own.
    pub http_client: reqwest::Client,
    pub daemon_http_base: String,
    /// Bearer token for authenticating proxied requests to the daemon's
    /// `/api/v1` routes.  Read from `SBC_API_TOKEN` at startup.
    pub daemon_api_token: Option<String>,

    /// Process start instant, for /system/version uptime reporting.
    pub start_time: std::time::Instant,

    /// Management-plane authenticator (admin login + stateless tokens).
    /// Shared, replica-safe via a common signing key.
    pub auth: Arc<uc_auth::Authenticator>,

    /// Optional operator OIDC validator. When configured, the auth
    /// middleware also accepts `config-admin` bearer tokens, so the
    /// dashboard authenticates once for both the central and per-site APIs.
    pub oidc: Option<Arc<proto_jwt::Validator>>,

    /// In-memory rate limiter for login attempts, keyed by client IP.
    /// Maps to (`attempt_count`, `window_start`).
    pub login_rate_limiter: Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    >,

    /// Networks from which the `X-Real-IP` header is trusted (the nginx
    /// pod range). Used to resolve the real client IP for the login rate
    /// limiter without letting a direct caller spoof it. Empty = trust
    /// the header unconditionally.
    pub trusted_proxies: Arc<Vec<ipnet::IpNet>>,
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
        // HA1 at rest: key is mandatory (fail closed), then seal any
        // legacy plaintext rows before serving. A startup job, not a SQL
        // migration, because the key never enters the database. Serialized
        // across replicas by a Postgres advisory lock; idempotent.
        // NIST 800-53 Rev5: SC-28(1), SC-12, IA-5(1)(c)
        let ha1_key = crate::ha1_key::load_ha1_key(&cfg.user_ha1_key_file)?;
        uc_audit::log_event(uc_audit::AuditEvent::CryptoKeyOperation(
            uc_audit::event::CryptoKeyOperation::success(
                "sbc-user-ha1",
                uc_audit::event::KeyOperationType::Loaded,
                "AES-256-GCM",
            ),
        ));
        let users = Arc::new(EncryptedUserStore::new(
            PostgresUserStore::new(&cfg.database_url)
                .await
                .map_err(|e| StateError::Postgres(e.to_string()))?,
            ha1_key,
        ));
        let report = users
            .inner()
            .with_advisory_lock(
                HA1_REENCRYPT_LOCK,
                HA1_REENCRYPT_LOCK_TIMEOUT,
                users.reencrypt_plaintext_rows(),
            )
            .await
            .map_err(|e| StateError::Ha1Reencrypt(e.to_string()))?;
        info!(
            scanned = report.scanned,
            encrypted = report.encrypted,
            already = report.already,
            raced = report.raced,
            "HA1 at-rest re-encryption check complete"
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
        let mut endpoint = Endpoint::from_shared(cfg.daemon_grpc_url.clone())
            .map_err(|e| StateError::Grpc(e.to_string()))?
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));
        if let Some(tls) = &cfg.daemon_grpc_tls {
            // mTLS to the daemon (required for CdrService off loopback).
            // NIST 800-53 Rev5: IA-3, SC-8
            // POAM: tonic's rustls defaults are used (TLS 1.2+1.3, default
            // suites) on both ends of this channel, not the uc-transport CNSA
            // 2.0 config; the chart's certificates are ECDSA P-384.
            async fn read(p: &std::path::Path) -> Result<String, StateError> {
                tokio::fs::read_to_string(p)
                    .await
                    .map_err(|e| StateError::Grpc(format!("{}: {e}", p.display())))
            }
            let tls_cfg = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(
                    read(&tls.ca).await?,
                ))
                .identity(tonic::transport::Identity::from_pem(
                    read(&tls.cert).await?,
                    read(&tls.key).await?,
                ));
            endpoint = endpoint
                .tls_config(tls_cfg)
                .map_err(|e| StateError::Grpc(e.to_string()))?;
            info!("daemon gRPC uses mTLS");
        }
        let channel = endpoint.connect_lazy();
        let trunk_sync = TrunkSyncServiceClient::new(channel.clone());
        let dial_plan_sync = DialPlanSyncServiceClient::new(channel.clone());
        let did_sync = DidMappingSyncServiceClient::new(channel.clone());
        let calls = CallServiceClient::new(channel.clone());
        let registrations = RegistrationServiceClient::new(channel.clone());
        let system = SystemServiceClient::new(channel.clone());
        let trunk_health = TrunkHealthServiceClient::new(channel.clone());
        let cdrs = CdrServiceClient::new(channel.clone());
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

        if cfg.trusted_proxies.is_empty() {
            tracing::warn!(
                "SBC_TRUSTED_PROXIES unset — X-Real-IP is trusted unconditionally; a caller \
                 reaching this pod directly (bypassing nginx) can forge its source IP and evade \
                 the login rate limiter. Set it to the frontend nginx pod network."
            );
        } else {
            info!(trusted_proxies = ?cfg.trusted_proxies, "X-Real-IP trusted only from these networks");
        }

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
            cdrs,
            http_client,
            daemon_http_base: cfg.daemon_http_url.trim_end_matches('/').to_string(),
            daemon_api_token: std::env::var("SBC_API_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            start_time: std::time::Instant::now(),
            auth,
            oidc,
            login_rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            trusted_proxies: Arc::new(cfg.trusted_proxies.clone()),
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
