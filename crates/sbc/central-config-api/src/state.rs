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

/// The OAuth scope an operator token must carry to write config (the
/// dashboard / admin tooling). Distinct from [`SYNC_SCOPE`]: a site's
/// pull credential can never write, and an operator credential can never
/// masquerade as a site's sync agent.
pub const ADMIN_SCOPE: &str = "config-admin";

/// State init errors.
#[derive(Debug, Error)]
pub enum StateError {
    /// The central store could not be opened or migrated.
    #[error("central store: {0}")]
    Store(String),
}

/// Handler-shared state: the store and the two scope-specific validators.
pub struct AppState {
    /// The central config store (writes + sync reads).
    pub store: CentralConfigStore,
    /// Validates site service-account tokens (requires [`SYNC_SCOPE`]) for
    /// the `/v1/sync` surface.
    pub sync_validator: Arc<Validator>,
    /// Validates operator tokens (requires [`ADMIN_SCOPE`]) for the write
    /// surface. Shares the same issuer/audience/JWKS as `sync_validator`;
    /// only the required scope differs.
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
        let store = CentralConfigStore::connect(&cfg.database_url)
            .await
            .map_err(|e| StateError::Store(e.to_string()))?;

        // rustls-only HTTP client for JWKS fetches; one cache, two validators.
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
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
            admin_validator: validator_for(ADMIN_SCOPE),
            start_time: Instant::now(),
        }))
    }
}
