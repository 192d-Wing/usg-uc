//! Env-only config for central-config-api. Supplied by Helm via the
//! Deployment's env / envFrom — no TOML, no flags.

use std::net::SocketAddr;

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

/// Resolved service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen address. Defaults to `0.0.0.0:80`.
    pub listen_addr: SocketAddr,
    /// Central config database DSN.
    pub database_url: String,
    /// OIDC issuer the site service-account tokens are minted by (must
    /// round-trip exactly with the `IdP` discovery doc).
    pub oidc_issuer: String,
    /// Accepted token audience for this API (e.g. `usg-uc-config-sync`).
    pub oidc_audience: String,
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
        let listen_addr = lookup("CENTRAL_API_LISTEN_ADDR")
            .unwrap_or_else(|| "0.0.0.0:80".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                var: "CENTRAL_API_LISTEN_ADDR",
                reason: e.to_string(),
            })?;
        let database_url =
            lookup("CENTRAL_POSTGRES_URL").ok_or(ConfigError::Missing("CENTRAL_POSTGRES_URL"))?;
        let oidc_issuer =
            lookup("CENTRAL_OIDC_ISSUER").ok_or(ConfigError::Missing("CENTRAL_OIDC_ISSUER"))?;
        let oidc_audience =
            lookup("CENTRAL_OIDC_AUDIENCE").ok_or(ConfigError::Missing("CENTRAL_OIDC_AUDIENCE"))?;
        Ok(Self {
            listen_addr,
            database_url,
            oidc_issuer,
            oidc_audience,
        })
    }
}
