//! Env-only config. Same approach as sbc-api-server — Helm sets
//! everything via Deployment env / envFrom.

use std::net::SocketAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("invalid {var}: {reason}")]
    Invalid { var: &'static str, reason: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Where the provisioning HTTP server listens. Defaults to `:80` so
    /// the frontend nginx upstream stays the same shape post-cutover.
    pub listen_addr: SocketAddr,

    /// Postgres DSN — same env var the daemon and sbc-api read.
    pub database_url: String,

    /// FQDN baked into rendered phone configs as the next-fetch URL.
    /// Phones come back here for refresh checks after first boot.
    pub provision_host: String,

    /// Port baked alongside `provision_host`.
    pub provision_port: u16,

    /// Source networks allowed to fetch provisioning configs (defense in
    /// depth behind the Cilium `NetworkPolicy`). Parsed from
    /// `SBC_PROVISION_ALLOWED_CIDRS` (comma-separated CIDRs). Empty =
    /// unrestricted at the app layer. The client IP is read from
    /// `X-Forwarded-For` (set by the frontend nginx).
    pub allowed_cidrs: Vec<ipnet::IpNet>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = std::env::var("SBC_PROVISION_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:80".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                var: "SBC_PROVISION_LISTEN_ADDR",
                reason: e.to_string(),
            })?;

        let database_url = std::env::var("SBC_POSTGRES_URL")
            .map_err(|_| ConfigError::Missing("SBC_POSTGRES_URL"))?;

        let provision_host = std::env::var("SBC_PROVISION_HOST")
            .map_err(|_| ConfigError::Missing("SBC_PROVISION_HOST"))?;

        let provision_port = std::env::var("SBC_PROVISION_PORT")
            .unwrap_or_else(|_| "80".to_string())
            .parse::<u16>()
            .map_err(|e| ConfigError::Invalid {
                var: "SBC_PROVISION_PORT",
                reason: e.to_string(),
            })?;

        let allowed_cidrs = std::env::var("SBC_PROVISION_ALLOWED_CIDRS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<ipnet::IpNet>().map_err(|e| ConfigError::Invalid {
                    var: "SBC_PROVISION_ALLOWED_CIDRS",
                    reason: format!("{s}: {e}"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            listen_addr,
            database_url,
            provision_host,
            provision_port,
            allowed_cidrs,
        })
    }
}
