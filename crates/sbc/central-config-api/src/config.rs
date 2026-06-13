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
    /// Central config database DSN (the read-write primary).
    pub database_url: String,
    /// Optional read-only replica DSN (e.g. a `CloudNativePG` `-ro` service).
    /// When set, the heavy sync `snapshot` read is served from it; unset
    /// routes every read at the primary.
    pub database_ro_url: Option<String>,
    /// Max connections per database pool. Defaults to 10.
    pub db_max_connections: u32,
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
        // Optional read replica; an empty value is treated as unset so an
        // always-present-but-blank Helm env var doesn't wire a bad DSN.
        let database_ro_url = lookup("CENTRAL_POSTGRES_RO_URL").filter(|s| !s.trim().is_empty());
        let db_max_connections = match lookup("CENTRAL_PG_MAX_CONNS") {
            Some(v) => v
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Invalid {
                    var: "CENTRAL_PG_MAX_CONNS",
                    reason: e.to_string(),
                })?,
            None => 10,
        };
        let oidc_issuer =
            lookup("CENTRAL_OIDC_ISSUER").ok_or(ConfigError::Missing("CENTRAL_OIDC_ISSUER"))?;
        let oidc_audience =
            lookup("CENTRAL_OIDC_AUDIENCE").ok_or(ConfigError::Missing("CENTRAL_OIDC_AUDIENCE"))?;
        Ok(Self {
            listen_addr,
            database_url,
            database_ro_url,
            db_max_connections,
            oidc_issuer,
            oidc_audience,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over the required vars plus any `extra` overrides.
    fn lookup_with(extra: &[(&'static str, &str)]) -> impl Fn(&'static str) -> Option<String> {
        let mut map: std::collections::HashMap<&'static str, String> = [
            ("CENTRAL_POSTGRES_URL", "postgres://primary/db"),
            ("CENTRAL_OIDC_ISSUER", "https://idp/realms/x"),
            ("CENTRAL_OIDC_AUDIENCE", "usg-uc-config"),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();
        for (k, v) in extra {
            map.insert(k, (*v).to_string());
        }
        move |var| map.get(var).cloned()
    }

    #[test]
    fn defaults_no_replica_and_ten_conns() {
        let cfg = Config::from_lookup(lookup_with(&[])).expect("config");
        assert_eq!(cfg.database_ro_url, None);
        assert_eq!(cfg.db_max_connections, 10);
    }

    #[test]
    fn replica_url_and_max_conns_parsed() {
        let cfg = Config::from_lookup(lookup_with(&[
            ("CENTRAL_POSTGRES_RO_URL", "postgres://replica/db"),
            ("CENTRAL_PG_MAX_CONNS", "25"),
        ]))
        .expect("config");
        assert_eq!(
            cfg.database_ro_url.as_deref(),
            Some("postgres://replica/db")
        );
        assert_eq!(cfg.db_max_connections, 25);
    }

    #[test]
    fn blank_replica_url_is_treated_as_unset() {
        let cfg =
            Config::from_lookup(lookup_with(&[("CENTRAL_POSTGRES_RO_URL", "  ")])).expect("config");
        assert_eq!(
            cfg.database_ro_url, None,
            "blank RO url must not wire a bad DSN"
        );
    }

    #[test]
    fn non_numeric_max_conns_is_an_error() {
        let err = Config::from_lookup(lookup_with(&[("CENTRAL_PG_MAX_CONNS", "lots")]))
            .expect_err("should reject");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "CENTRAL_PG_MAX_CONNS",
                ..
            }
        ));
    }
}
