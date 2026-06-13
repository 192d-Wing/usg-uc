//! Env-only config for the sync agent.

use std::time::Duration;

use thiserror::Error;

/// Config load errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required env var was unset.
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    /// A var was set but could not be parsed.
    #[error("invalid {var}: {reason}")]
    Invalid {
        /// The offending env var.
        var: &'static str,
        /// Why it failed to parse.
        reason: String,
    },
}

/// Resolved agent configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Canonical site code this agent syncs (its shard).
    pub site_code: String,
    /// Site-local Postgres DSN (the shard replica the agent writes).
    pub local_database_url: String,
    /// Central config API base URL (no trailing slash).
    pub central_url: String,
    /// How the agent obtains its central-API bearer token.
    pub auth: AuthConfig,
    /// Base poll interval. A per-site jitter is added so 184 agents don't
    /// stampede the central API in lockstep.
    pub interval: Duration,
    /// Listen address for the metrics/health HTTP server.
    pub metrics_addr: std::net::SocketAddr,
}

/// Token-acquisition configuration.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// A pre-issued static token (`SYNC_BEARER_TOKEN`). Break-glass / tests.
    Static(String),
    /// `OAuth2` client-credentials (`SYNC_OIDC_*`). The production path.
    Oidc {
        /// Token endpoint URL.
        token_url: String,
        /// Client id (the per-site service account).
        client_id: String,
        /// Client secret.
        client_secret: String,
        /// Requested scope (default `config-sync`).
        scope: String,
    },
}

impl Config {
    /// Load from the process environment.
    ///
    /// # Errors
    /// [`ConfigError`] if a required var is missing or unparseable.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Load from an arbitrary lookup (used by tests).
    ///
    /// # Errors
    /// [`ConfigError`] if a required var is missing or unparseable.
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let site_code =
            lookup("SYNC_SITE_CODE").ok_or(ConfigError::Missing("SYNC_SITE_CODE"))?;
        let local_database_url = lookup("SYNC_LOCAL_POSTGRES_URL")
            .ok_or(ConfigError::Missing("SYNC_LOCAL_POSTGRES_URL"))?;
        let central_url =
            lookup("SYNC_CENTRAL_URL").ok_or(ConfigError::Missing("SYNC_CENTRAL_URL"))?;
        // Static token wins if present (break-glass / tests); otherwise
        // require the OIDC client-credentials set.
        let auth = if let Some(token) = lookup("SYNC_BEARER_TOKEN") {
            AuthConfig::Static(token)
        } else {
            AuthConfig::Oidc {
                token_url: lookup("SYNC_OIDC_TOKEN_URL")
                    .ok_or(ConfigError::Missing("SYNC_OIDC_TOKEN_URL"))?,
                client_id: lookup("SYNC_OIDC_CLIENT_ID")
                    .ok_or(ConfigError::Missing("SYNC_OIDC_CLIENT_ID"))?,
                client_secret: lookup("SYNC_OIDC_CLIENT_SECRET")
                    .ok_or(ConfigError::Missing("SYNC_OIDC_CLIENT_SECRET"))?,
                scope: lookup("SYNC_OIDC_SCOPE").unwrap_or_else(|| "config-sync".to_string()),
            }
        };
        let interval_secs = lookup("SYNC_INTERVAL_SECS")
            .map(|s| {
                s.parse::<u64>().map_err(|e| ConfigError::Invalid {
                    var: "SYNC_INTERVAL_SECS",
                    reason: e.to_string(),
                })
            })
            .transpose()?
            .unwrap_or(60);
        let metrics_addr = lookup("SYNC_METRICS_ADDR")
            .unwrap_or_else(|| "0.0.0.0:9090".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                var: "SYNC_METRICS_ADDR",
                reason: e.to_string(),
            })?;
        Ok(Self {
            site_code,
            local_database_url,
            central_url,
            auth,
            interval: Duration::from_secs(interval_secs),
            metrics_addr,
        })
    }

    /// A per-site jittered interval: base ± up to ~12% derived from the
    /// site code, so agents desynchronize without an RNG dependency.
    #[must_use]
    pub fn jittered_interval(&self) -> Duration {
        let base = self.interval.as_secs().max(1);
        let span = (base / 8).max(1);
        let hash: u64 = self.site_code.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
        let offset = hash % (span * 2 + 1); // 0..=2*span
        Duration::from_secs(base + offset - span)
    }
}
