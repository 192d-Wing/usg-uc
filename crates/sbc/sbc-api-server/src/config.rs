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
    Invalid { var: &'static str, reason: String },
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

    /// Optional OIDC issuer. When set (with `oidc_audience`), the auth
    /// middleware *also* accepts operator OIDC bearer tokens (scope
    /// `config-admin`) — so the dashboard uses one token for both the
    /// central config API and this per-site API. The legacy cookie/HMAC
    /// admin login keeps working alongside it.
    pub oidc_issuer: Option<String>,
    /// Accepted OIDC audience (required iff `oidc_issuer` is set).
    pub oidc_audience: Option<String>,

    /// Networks (CIDRs) from which an `X-Real-IP` header is trusted —
    /// the frontend nginx pod range. Parsed from `SBC_TRUSTED_PROXIES`
    /// (comma-separated). The login rate limiter keys on the real
    /// client IP only when the request's TCP peer is one of these; a
    /// caller connecting directly to this pod (bypassing nginx) can't
    /// forge its address. Empty = trust `X-Real-IP` unconditionally
    /// (a startup warning is logged).
    pub trusted_proxies: Vec<ipnet::IpNet>,

    /// Client certificate for mTLS to the daemon's gRPC listener
    /// (`SBC_DAEMON_GRPC_TLS_{CA,CERT,KEY}_FILE`, all three or none). The
    /// daemon serves `CdrService` (PII) only over mTLS or loopback.
    ///
    /// ## NIST 800-53 Rev5: IA-3 (Device Identification and Authentication), SC-8
    pub daemon_grpc_tls: Option<GrpcClientTls>,

    /// File holding the AES-256-GCM key (64 hex chars) that seals SIP
    /// digest HA1 values at rest (`SBC_USER_HA1_KEY_FILE`, required).
    /// Must be owner-only and owned by the sbc-api uid.
    ///
    /// ## NIST 800-53 Rev5: SC-28(1), SC-12
    pub user_ha1_key_file: std::path::PathBuf,
}

/// PEM file paths for the daemon gRPC mTLS client.
#[derive(Debug, Clone)]
pub struct GrpcClientTls {
    /// CA that signed the daemon's server certificate.
    pub ca: std::path::PathBuf,
    /// Client certificate chain.
    pub cert: std::path::PathBuf,
    /// Client private key.
    pub key: std::path::PathBuf,
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

        let database_url = std::env::var("SBC_POSTGRES_URL")
            .map_err(|_| ConfigError::Missing("SBC_POSTGRES_URL"))?;

        let daemon_grpc_url = std::env::var("SBC_DAEMON_GRPC_URL")
            .map_err(|_| ConfigError::Missing("SBC_DAEMON_GRPC_URL"))?;

        let daemon_http_url = std::env::var("SBC_DAEMON_HTTP_URL")
            .map_err(|_| ConfigError::Missing("SBC_DAEMON_HTTP_URL"))?;

        // OIDC is optional but issuer+audience must come as a pair.
        let oidc_issuer = std::env::var("SBC_OIDC_ISSUER")
            .ok()
            .filter(|s| !s.is_empty());
        let oidc_audience = std::env::var("SBC_OIDC_AUDIENCE")
            .ok()
            .filter(|s| !s.is_empty());
        if oidc_issuer.is_some() != oidc_audience.is_some() {
            return Err(ConfigError::Invalid {
                var: "SBC_OIDC_ISSUER/SBC_OIDC_AUDIENCE",
                reason: "set both or neither".to_string(),
            });
        }

        let trusted_proxies = sbc_http_util::parse_cidr_list(
            &std::env::var("SBC_TRUSTED_PROXIES").unwrap_or_default(),
        )
        .map_err(|reason| ConfigError::Invalid {
            var: "SBC_TRUSTED_PROXIES",
            reason,
        })?;

        let tls_var = |k: &'static str| std::env::var(k).ok().filter(|s| !s.is_empty());
        let daemon_grpc_tls = match (
            tls_var("SBC_DAEMON_GRPC_TLS_CA_FILE"),
            tls_var("SBC_DAEMON_GRPC_TLS_CERT_FILE"),
            tls_var("SBC_DAEMON_GRPC_TLS_KEY_FILE"),
        ) {
            (None, None, None) => None,
            (Some(ca), Some(cert), Some(key)) => Some(GrpcClientTls {
                ca: ca.into(),
                cert: cert.into(),
                key: key.into(),
            }),
            _ => {
                return Err(ConfigError::Invalid {
                    var: "SBC_DAEMON_GRPC_TLS_{CA,CERT,KEY}_FILE",
                    reason: "set all three or none".to_string(),
                });
            }
        };

        let user_ha1_key_file = std::env::var("SBC_USER_HA1_KEY_FILE")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(ConfigError::Missing("SBC_USER_HA1_KEY_FILE"))?
            .into();

        Ok(Self {
            listen_addr,
            database_url,
            daemon_grpc_url,
            daemon_http_url,
            oidc_issuer,
            oidc_audience,
            trusted_proxies,
            daemon_grpc_tls,
            user_ha1_key_file,
        })
    }
}
