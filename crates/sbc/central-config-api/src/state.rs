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

/// State init errors.
#[derive(Debug, Error)]
pub enum StateError {
    /// The central store could not be opened or migrated.
    #[error("central store: {0}")]
    Store(String),
}

/// Handler-shared state: the store and the token validator.
pub struct AppState {
    /// The central config store (writes + sync reads).
    pub store: CentralConfigStore,
    /// OIDC validator for site service-account tokens.
    pub validator: Arc<Validator>,
    /// Process start, for uptime in the health endpoint.
    pub start_time: Instant,
}

impl AppState {
    /// Connect the store and build the token validator.
    ///
    /// # Errors
    /// [`StateError::Store`] if the database can't be reached or migrated.
    pub async fn build(cfg: &Config) -> Result<Arc<Self>, StateError> {
        let store = CentralConfigStore::connect(&cfg.database_url)
            .await
            .map_err(|e| StateError::Store(e.to_string()))?;

        // rustls-only HTTP client for JWKS fetches.
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let jwks = Arc::new(JwksCache::new(http, cfg.oidc_issuer.clone()));
        let validator = Arc::new(Validator::new(
            jwks,
            ValidatorConfig {
                issuer: cfg.oidc_issuer.clone(),
                audiences: vec![cfg.oidc_audience.clone()],
                required_scope: SYNC_SCOPE,
                leeway_secs: 30,
            },
        ));

        Ok(Arc::new(Self { store, validator, start_time: Instant::now() }))
    }
}
