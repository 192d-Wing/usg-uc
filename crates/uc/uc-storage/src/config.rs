//! Storage configuration types.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Storage configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Storage backend type.
    pub backend: StorageBackendType,
    /// Key prefix for namespacing.
    pub key_prefix: String,
    /// Default TTL for entries (in seconds, 0 = no expiry).
    pub default_ttl_secs: u64,
    /// Redis configuration (if using Redis).
    pub redis: Option<RedisConfig>,
    /// PostgreSQL configuration (if using PostgreSQL).
    pub postgres: Option<PostgresConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackendType::InMemory,
            key_prefix: "sbc:".to_string(),
            default_ttl_secs: 0,
            redis: None,
            postgres: None,
        }
    }
}

impl StorageConfig {
    /// Creates an in-memory storage configuration.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Creates a Redis storage configuration.
    #[must_use]
    pub fn redis(url: impl Into<String>) -> Self {
        Self {
            backend: StorageBackendType::Redis,
            redis: Some(RedisConfig::new(url)),
            ..Default::default()
        }
    }

    /// Creates a PostgreSQL storage configuration.
    #[must_use]
    pub fn postgres(url: impl Into<String>) -> Self {
        Self {
            backend: StorageBackendType::Postgres,
            postgres: Some(PostgresConfig::new(url)),
            ..Default::default()
        }
    }

    /// Returns the default TTL as a Duration.
    #[must_use]
    pub fn default_ttl(&self) -> Option<Duration> {
        if self.default_ttl_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.default_ttl_secs))
        }
    }
}

/// Storage backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendType {
    /// In-memory storage (single node only).
    #[default]
    InMemory,
    /// Redis distributed cache.
    Redis,
    /// PostgreSQL persistent storage.
    Postgres,
}

impl std::fmt::Display for StorageBackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InMemory => write!(f, "in_memory"),
            Self::Redis => write!(f, "redis"),
            Self::Postgres => write!(f, "postgres"),
        }
    }
}

/// Redis configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    /// Redis connection URL.
    pub url: String,
    /// Connection pool size.
    pub pool_size: u32,
    /// Connection timeout in milliseconds.
    pub connection_timeout_ms: u64,
    /// Command timeout in milliseconds.
    pub command_timeout_ms: u64,
    /// Whether to use Redis cluster mode.
    pub cluster_mode: bool,
    /// TLS configuration.
    pub tls: Option<RedisTlsConfig>,
    /// Retry configuration.
    pub retry: RetryConfig,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout_ms: 5000,
            command_timeout_ms: 1000,
            cluster_mode: false,
            tls: None,
            retry: RetryConfig::default(),
        }
    }
}

impl RedisConfig {
    /// Creates a new Redis configuration with the given URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Returns the connection timeout as a Duration.
    #[must_use]
    pub const fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.connection_timeout_ms)
    }

    /// Returns the command timeout as a Duration.
    #[must_use]
    pub const fn command_timeout(&self) -> Duration {
        Duration::from_millis(self.command_timeout_ms)
    }
}

/// Redis TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisTlsConfig {
    /// Path to CA certificate.
    pub ca_cert_path: Option<String>,
    /// Path to client certificate.
    pub client_cert_path: Option<String>,
    /// Path to client key.
    pub client_key_path: Option<String>,
    /// Whether to verify server certificate.
    pub verify_certificate: bool,
}

impl Default for RedisTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_certificate: true,
        }
    }
}

/// PostgreSQL configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PostgresConfig {
    /// Connection URL or DSN.
    pub url: String,
    /// Database name.
    pub database: String,
    /// Connection pool minimum size.
    pub pool_min_size: u32,
    /// Connection pool maximum size.
    pub pool_max_size: u32,
    /// Connection timeout in milliseconds.
    pub connection_timeout_ms: u64,
    /// Query timeout in milliseconds.
    pub query_timeout_ms: u64,
    /// Whether to run migrations on startup.
    pub run_migrations: bool,
    /// SSL mode.
    pub ssl_mode: PostgresSslMode,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/sbc".to_string(),
            database: "sbc".to_string(),
            pool_min_size: 2,
            pool_max_size: 10,
            connection_timeout_ms: 5000,
            query_timeout_ms: 30000,
            run_migrations: true,
            ssl_mode: PostgresSslMode::Prefer,
        }
    }
}

impl PostgresConfig {
    /// Creates a new PostgreSQL configuration with the given URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Returns the connection timeout as a Duration.
    #[must_use]
    pub const fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.connection_timeout_ms)
    }

    /// Returns the query timeout as a Duration.
    #[must_use]
    pub const fn query_timeout(&self) -> Duration {
        Duration::from_millis(self.query_timeout_ms)
    }
}

/// PostgreSQL SSL mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    /// Disable SSL.
    Disable,
    /// Prefer SSL but allow unencrypted.
    #[default]
    Prefer,
    /// Require SSL.
    Require,
    /// Require SSL with CA verification.
    VerifyCa,
    /// Require SSL with full verification.
    VerifyFull,
}

impl std::fmt::Display for PostgresSslMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disable => write!(f, "disable"),
            Self::Prefer => write!(f, "prefer"),
            Self::Require => write!(f, "require"),
            Self::VerifyCa => write!(f, "verify-ca"),
            Self::VerifyFull => write!(f, "verify-full"),
        }
    }
}

/// Retry configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_attempts: u32,
    /// Initial backoff duration in milliseconds.
    pub initial_backoff_ms: u64,
    /// Maximum backoff duration in milliseconds.
    pub max_backoff_ms: u64,
    /// Backoff multiplier.
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Returns the initial backoff as a Duration.
    #[must_use]
    pub const fn initial_backoff(&self) -> Duration {
        Duration::from_millis(self.initial_backoff_ms)
    }

    /// Returns the max backoff as a Duration.
    #[must_use]
    pub const fn max_backoff(&self) -> Duration {
        Duration::from_millis(self.max_backoff_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = StorageConfig::default();
        assert!(matches!(config.backend, StorageBackendType::InMemory));
        assert_eq!(config.key_prefix, "sbc:");
        assert_eq!(config.default_ttl_secs, 0);
    }

    #[test]
    fn test_in_memory_config() {
        let config = StorageConfig::in_memory();
        assert!(matches!(config.backend, StorageBackendType::InMemory));
    }

    #[test]
    fn test_redis_config() {
        let config = StorageConfig::redis("redis://localhost:6379");
        assert!(matches!(config.backend, StorageBackendType::Redis));
        assert!(config.redis.is_some());
        assert_eq!(config.redis.unwrap().url, "redis://localhost:6379");
    }

    #[test]
    fn test_postgres_config() {
        let config = StorageConfig::postgres("postgres://localhost/sbc");
        assert!(matches!(config.backend, StorageBackendType::Postgres));
        assert!(config.postgres.is_some());
        assert_eq!(config.postgres.unwrap().url, "postgres://localhost/sbc");
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(format!("{}", StorageBackendType::InMemory), "in_memory");
        assert_eq!(format!("{}", StorageBackendType::Redis), "redis");
        assert_eq!(format!("{}", StorageBackendType::Postgres), "postgres");
    }

    #[test]
    fn test_default_ttl() {
        let mut config = StorageConfig::default();
        assert!(config.default_ttl().is_none());

        config.default_ttl_secs = 3600;
        assert_eq!(config.default_ttl(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_redis_timeouts() {
        let config = RedisConfig::default();
        assert_eq!(config.connection_timeout(), Duration::from_secs(5));
        assert_eq!(config.command_timeout(), Duration::from_secs(1));
    }

    #[test]
    fn test_postgres_timeouts() {
        let config = PostgresConfig::default();
        assert_eq!(config.connection_timeout(), Duration::from_secs(5));
        assert_eq!(config.query_timeout(), Duration::from_secs(30));
    }
}
