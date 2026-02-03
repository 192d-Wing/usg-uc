//! AAA configuration types.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// AAA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AaaConfig {
    /// Enable AAA.
    pub enabled: bool,
    /// AAA provider type.
    pub provider: AaaProviderType,
    /// RADIUS configuration.
    pub radius: Option<RadiusConfig>,
    /// Local authentication database (for testing/fallback).
    pub local: Option<LocalConfig>,
    /// Failover configuration.
    pub failover: FailoverConfig,
}

impl Default for AaaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AaaProviderType::Local,
            radius: None,
            local: Some(LocalConfig::default()),
            failover: FailoverConfig::default(),
        }
    }
}

impl AaaConfig {
    /// Creates a RADIUS configuration.
    #[must_use]
    pub fn radius(server: SocketAddr, secret: impl Into<String>) -> Self {
        Self {
            enabled: true,
            provider: AaaProviderType::Radius,
            radius: Some(RadiusConfig::new(server, secret)),
            local: None,
            failover: FailoverConfig::default(),
        }
    }

    /// Creates a local-only configuration.
    #[must_use]
    pub fn local_only() -> Self {
        Self {
            enabled: true,
            provider: AaaProviderType::Local,
            radius: None,
            local: Some(LocalConfig::default()),
            failover: FailoverConfig::default(),
        }
    }
}

/// AAA provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AaaProviderType {
    /// Local authentication only.
    #[default]
    Local,
    /// RADIUS authentication.
    Radius,
    /// Diameter authentication (planned).
    Diameter,
}

impl std::fmt::Display for AaaProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Radius => write!(f, "radius"),
            Self::Diameter => write!(f, "diameter"),
        }
    }
}

/// RADIUS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RadiusConfig {
    /// Primary RADIUS server.
    pub server: SocketAddr,
    /// Backup RADIUS servers.
    #[serde(default)]
    pub backup_servers: Vec<SocketAddr>,
    /// Shared secret.
    #[serde(skip_serializing)]
    pub secret: String,
    /// Authentication port (default 1812).
    pub auth_port: u16,
    /// Accounting port (default 1813).
    pub acct_port: u16,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum retries.
    pub max_retries: u32,
    /// NAS identifier.
    pub nas_identifier: String,
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:1812".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1812)
            }),
            backup_servers: Vec::new(),
            secret: String::new(),
            auth_port: 1812,
            acct_port: 1813,
            timeout_ms: 3000,
            max_retries: 3,
            nas_identifier: "sbc".to_string(),
        }
    }
}

impl RadiusConfig {
    /// Creates a new RADIUS configuration.
    #[must_use]
    pub fn new(server: SocketAddr, secret: impl Into<String>) -> Self {
        Self {
            server,
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Returns the timeout as a Duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Adds a backup server.
    #[must_use]
    pub fn with_backup(mut self, server: SocketAddr) -> Self {
        self.backup_servers.push(server);
        self
    }
}

/// Local authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LocalConfig {
    /// Whether to allow any credentials (for testing).
    pub allow_any: bool,
    /// Static credentials file path.
    pub credentials_file: Option<String>,
}

/// Failover configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FailoverConfig {
    /// Enable failover to backup servers.
    pub enabled: bool,
    /// Time to wait before retrying failed server (seconds).
    pub retry_after_secs: u64,
    /// Maximum consecutive failures before failover.
    pub max_failures: u32,
    /// Fallback to local auth if all servers fail.
    pub fallback_to_local: bool,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retry_after_secs: 60,
            max_failures: 3,
            fallback_to_local: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AaaConfig::default();
        assert!(!config.enabled);
        assert!(matches!(config.provider, AaaProviderType::Local));
    }

    #[test]
    fn test_radius_config() {
        let server: SocketAddr = "192.168.1.100:1812".parse().unwrap();
        let config = AaaConfig::radius(server, "secret123");

        assert!(config.enabled);
        assert!(matches!(config.provider, AaaProviderType::Radius));
        assert!(config.radius.is_some());
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(format!("{}", AaaProviderType::Local), "local");
        assert_eq!(format!("{}", AaaProviderType::Radius), "radius");
        assert_eq!(format!("{}", AaaProviderType::Diameter), "diameter");
    }

    #[test]
    fn test_radius_timeout() {
        let config = RadiusConfig::default();
        assert_eq!(config.timeout(), Duration::from_secs(3));
    }
}
