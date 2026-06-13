//! Shared application state and its construction.

use std::sync::Arc;
use std::time::Instant;

use proto_jwt::{JwksCache, Validator, ValidatorConfig};
use thiserror::Error;

use central_config_store::CentralConfigStore;

use crate::config::Config;

/// The OAuth scope a site's `config-sync` service-account token must
/// carry. A protocol constant, not operator-tunable.
pub const SYNC_SCOPE: &str = "config-sync";

/// The base OAuth scope every operator token must carry to reach the
/// operator surface (the dashboard / admin tooling). This is only the
/// coarse "may use the operator API" gate; *what* an operator may do is
/// decided per-request by ABAC ([`crate::policy`]) from the token's `roles`
/// and `sites` claims. Distinct from [`SYNC_SCOPE`]: a site's pull
/// credential can never reach this surface, and an operator credential can
/// never masquerade as a site's sync agent.
pub const OPERATOR_SCOPE: &str = "config";

/// Legacy full-fleet operator scope. A token carrying this is treated by
/// ABAC as a fleet admin (`*:*` on every site), so existing `config-admin`
/// credentials keep working without `roles`/`sites` claims.
pub const ADMIN_SCOPE: &str = "config-admin";

/// State init errors.
#[derive(Debug, Error)]
pub enum StateError {
    /// The central store could not be opened or migrated.
    #[error("central store: {0}")]
    Store(String),
    /// The configured extra OIDC CA cert could not be read or parsed. Fatal:
    /// without it, JWKS fetches fail and every token is rejected, so the API
    /// would be uselessly up. Fail fast instead.
    #[error("oidc CA cert: {0}")]
    OidcCa(String),
}

/// Handler-shared state: the store and the two scope-specific validators.
pub struct AppState {
    /// The central config store (writes + sync reads).
    pub store: CentralConfigStore,
    /// Validates site service-account tokens (requires [`SYNC_SCOPE`]) for
    /// the `/v1/sync` surface.
    pub sync_validator: Arc<Validator>,
    /// Validates operator tokens (requires [`OPERATOR_SCOPE`]) for the
    /// operator surface. Shares the same issuer/audience/JWKS as
    /// `sync_validator`; only the required scope differs. Per-action
    /// authorization is then applied by [`crate::policy`].
    pub admin_validator: Arc<Validator>,
    /// Process start, for uptime in the health endpoint.
    pub start_time: Instant,
}

impl AppState {
    /// Connect the store and build the scope-specific validators.
    ///
    /// # Errors
    /// [`StateError::Store`] if the database can't be reached or migrated.
    pub async fn build(cfg: &Config) -> Result<Arc<Self>, StateError> {
        let store = CentralConfigStore::connect_with(central_config_store::StoreConfig {
            primary_url: &cfg.database_url,
            replica_url: cfg.database_ro_url.as_deref(),
            max_connections: cfg.db_max_connections,
            application_name: "central-config-api",
        })
        .await
        .map_err(|e| StateError::Store(e.to_string()))?;

        // rustls-only HTTP client for JWKS fetches; one cache, two validators.
        // An extra CA cert is trusted when the IdP is fronted by an internal
        // CA the bundled webpki roots don't include.
        let mut http_builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10));
        if let Some(path) = cfg.oidc_extra_ca_cert_file.as_deref() {
            let pem =
                std::fs::read(path).map_err(|e| StateError::OidcCa(format!("read {path}: {e}")))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| StateError::OidcCa(format!("parse {path}: {e}")))?;
            tracing::info!(path, "loaded extra CA certificate for IdP JWKS fetch");
            http_builder = http_builder.add_root_certificate(cert);
        }
        let http = http_builder
            .build()
            .map_err(|e| StateError::OidcCa(format!("build HTTP client: {e}")))?;
        let jwks = Arc::new(JwksCache::new(http, cfg.oidc_issuer.clone()));
        let validator_for = |scope: &'static str| {
            Arc::new(Validator::new(
                Arc::clone(&jwks),
                ValidatorConfig {
                    issuer: cfg.oidc_issuer.clone(),
                    audiences: vec![cfg.oidc_audience.clone()],
                    required_scope: scope,
                    leeway_secs: 30,
                },
            ))
        };

        Ok(Arc::new(Self {
            store,
            sync_validator: validator_for(SYNC_SCOPE),
            admin_validator: validator_for(OPERATOR_SCOPE),
            start_time: Instant::now(),
        }))
    }
}
