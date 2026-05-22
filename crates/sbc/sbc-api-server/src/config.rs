//! Env-only config for sbc-api-server.
//!
//! No TOML, no flags — everything sbc-api needs is supplied by Helm via
//! the Deployment's env / envFrom. Keeps the binary small and removes a
//! config-precedence story we'd otherwise have to document.

use std::net::SocketAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("invalid {var}: {reason}")]
    Invalid {
        var: &'static str,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Where to listen for HTTP requests. Defaults to `0.0.0.0:80` to
    /// match the daemon's old API port — the frontend nginx upstream
    /// can stay the same shape after the cutover.
    pub listen_addr: SocketAddr,

    /// Postgres DSN. Same env var the daemon uses; in Helm both pods
    /// mount the same Secret.
    pub database_url: String,

    /// Daemon's gRPC endpoint (`http://host:port`). Used for the three
    /// sync services. No default — sbc-api refuses to start without it
    /// because every write handler needs a working gRPC channel.
    pub daemon_grpc_url: String,

    /// Daemon's REST endpoint (`http://host:port`). Used by the
    /// reverse-proxy fallback for the few read-only endpoints sbc-api
    /// doesn't own (CDRs and dial-plan reads).
    pub daemon_http_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = std::env::var("SBC_API_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:80".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                var: "SBC_API_LISTEN_ADDR",
                reason: e.to_string(),
            })?;

        let database_url =
            std::env::var("SBC_POSTGRES_URL").map_err(|_| ConfigError::Missing("SBC_POSTGRES_URL"))?;

        let daemon_grpc_url = std::env::var("SBC_DAEMON_GRPC_URL")
            .map_err(|_| ConfigError::Missing("SBC_DAEMON_GRPC_URL"))?;

        let daemon_http_url = std::env::var("SBC_DAEMON_HTTP_URL")
            .map_err(|_| ConfigError::Missing("SBC_DAEMON_HTTP_URL"))?;

        Ok(Self {
            listen_addr,
            database_url,
            daemon_grpc_url,
            daemon_http_url,
        })
    }
}
