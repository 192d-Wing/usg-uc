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
    /// OIDC service-account access token presented to the central API.
    pub bearer_token: String,
    /// Base poll interval. A per-site jitter is added so 184 agents don't
    /// stampede the central API in lockstep.
    pub interval: Duration,
    /// Listen address for the metrics/health HTTP server.
    pub metrics_addr: std::net::SocketAddr,
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
        let bearer_token =
            lookup("SYNC_BEARER_TOKEN").ok_or(ConfigError::Missing("SYNC_BEARER_TOKEN"))?;
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
            bearer_token,
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
