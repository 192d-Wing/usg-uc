//! Storage configuration types.

use crate::error::{StorageError, StorageResult};
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
///
/// `Debug` redacts the password in `url`. `Serialize` does not: serialized
/// configs still carry the secret (POA&M-247).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
    /// Allow a plaintext (`redis://`, `unix://`) connection. Insecure; for
    /// development only. Default `false`: plaintext URLs are rejected.
    pub allow_insecure_transport: bool,
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &redact_url(&self.url))
            .field("pool_size", &self.pool_size)
            .field("connection_timeout_ms", &self.connection_timeout_ms)
            .field("command_timeout_ms", &self.command_timeout_ms)
            .field("cluster_mode", &self.cluster_mode)
            .field("tls", &self.tls)
            .field("retry", &self.retry)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .finish()
    }
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
            allow_insecure_transport: false,
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

    /// Checks that the configured transport is authenticated and encrypted.
    ///
    /// Fails closed:
    /// - `redis://` / `unix://` without TLS needs `allow_insecure_transport`;
    /// - a `tls` block with a non-`rediss://` URL is rejected (TLS would
    ///   otherwise be silently ignored);
    /// - `verify_certificate = false` and the `#insecure` URL fragment are
    ///   always rejected, with or without the opt-in;
    /// - `cluster_mode = true` is rejected because it is not implemented.
    ///
    /// Returns `Ok(true)` when the insecure opt-in is in effect, so the
    /// caller can log a warning.
    ///
    /// NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity),
    /// CM-6 (Configuration Settings)
    ///
    /// # Errors
    /// Returns [`StorageError::InsecureTransport`] or
    /// [`StorageError::ConfigError`] when the policy is violated.
    pub fn validate_transport_security(&self) -> StorageResult<bool> {
        if self.cluster_mode {
            return Err(StorageError::ConfigError {
                reason: "redis cluster_mode is not supported".to_string(),
            });
        }
        let scheme = url_scheme(&self.url).to_ascii_lowercase();
        let is_tls = scheme == "rediss";
        if url_fragment(&self.url).is_some_and(|f| f.eq_ignore_ascii_case("insecure")) {
            return Err(StorageError::InsecureTransport {
                reason: "the #insecure redis URL fragment disables certificate checks".to_string(),
            });
        }
        if let Some(tls) = &self.tls {
            if !tls.verify_certificate {
                return Err(StorageError::InsecureTransport {
                    reason: "redis tls.verify_certificate = false is not allowed".to_string(),
                });
            }
            if !is_tls {
                return Err(StorageError::InsecureTransport {
                    reason: "redis tls is configured but the URL scheme is not rediss://"
                        .to_string(),
                });
            }
            if tls.client_cert_path.is_some() != tls.client_key_path.is_some() {
                return Err(StorageError::ConfigError {
                    reason: "redis tls client_cert_path and client_key_path must be set together"
                        .to_string(),
                });
            }
        }
        if is_tls {
            return Ok(false);
        }
        if self.allow_insecure_transport {
            Ok(true)
        } else {
            Err(StorageError::InsecureTransport {
                reason: format!(
                    "redis URL scheme '{scheme}' is not TLS; use rediss:// or set \
                     allow_insecure_transport"
                ),
            })
        }
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
///
/// `Debug` redacts the password in `url`. `Serialize` does not: serialized
/// configs still carry the secret (POA&M-247).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// SSL mode. Overrides any `sslmode=` in `url`.
    pub ssl_mode: PostgresSslMode,
    /// PEM file of trust anchors for the server certificate. `None` uses
    /// the `sslrootcert` URL parameter, if any, else the built-in roots.
    pub ssl_root_cert: Option<String>,
    /// Allow `disable`, `prefer` or `require` SSL modes (no server
    /// authentication). Insecure; for development only. Default `false`.
    pub allow_insecure_transport: bool,
}

impl std::fmt::Debug for PostgresConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresConfig")
            .field("url", &redact_url(&self.url))
            .field("database", &self.database)
            .field("pool_min_size", &self.pool_min_size)
            .field("pool_max_size", &self.pool_max_size)
            .field("connection_timeout_ms", &self.connection_timeout_ms)
            .field("query_timeout_ms", &self.query_timeout_ms)
            .field("run_migrations", &self.run_migrations)
            .field("ssl_mode", &self.ssl_mode)
            .field("ssl_root_cert", &self.ssl_root_cert)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .finish()
    }
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
            ssl_mode: PostgresSslMode::VerifyFull,
            ssl_root_cert: None,
            allow_insecure_transport: false,
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

    /// Checks that the SSL mode authenticates the server.
    ///
    /// `disable`, `prefer` (silent plaintext fallback) and `require`
    /// (encryption without server authentication) need
    /// `allow_insecure_transport`. `verify-ca` and `verify-full` are
    /// accepted. Returns `Ok(true)` when the insecure opt-in is in effect.
    ///
    /// NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity),
    /// CM-6 (Configuration Settings)
    ///
    /// # Errors
    /// Returns [`StorageError::InsecureTransport`] when the policy is violated.
    pub fn validate_transport_security(&self) -> StorageResult<bool> {
        match self.ssl_mode {
            PostgresSslMode::VerifyCa | PostgresSslMode::VerifyFull => Ok(false),
            PostgresSslMode::Disable | PostgresSslMode::Prefer | PostgresSslMode::Require => {
                if self.allow_insecure_transport {
                    Ok(true)
                } else {
                    Err(StorageError::InsecureTransport {
                        reason: format!(
                            "postgres ssl_mode '{}' does not authenticate the server; use \
                             verify-full or set allow_insecure_transport",
                            self.ssl_mode
                        ),
                    })
                }
            }
        }
    }
}

/// PostgreSQL SSL mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    /// Disable SSL. Needs `allow_insecure_transport`.
    Disable,
    /// Prefer SSL but allow unencrypted. Needs `allow_insecure_transport`.
    Prefer,
    /// Require SSL without server verification. Needs
    /// `allow_insecure_transport`.
    Require,
    /// Require SSL with CA verification.
    VerifyCa,
    /// Require SSL with full verification (default).
    #[default]
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

/// Query parameter / DSN keys whose values are secrets.
const SECRET_KEYS: &[&str] = &["password", "pass", "passwd", "sslpassword"];

/// Returns the URL scheme (text before `://`), or `""`.
fn url_scheme(url: &str) -> &str {
    url.find("://").map_or("", |i| &url[..i])
}

/// Returns the URL fragment (text after `#`), if any.
fn url_fragment(url: &str) -> Option<&str> {
    url.find('#').map(|i| &url[i + 1..])
}

/// Redacts secrets in a connection URL or key/value DSN for logging.
///
/// Replaces the userinfo password (`scheme://user:SECRET@host`) and the
/// value of `password`-like query or DSN parameters with `***`. Never
/// panics on malformed input; all slicing is at ASCII delimiters.
///
/// NIST 800-53 Rev5: SI-11 (Error Handling), IA-5(1) (protection of
/// authenticators), AU-9
#[must_use]
pub fn redact_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return redact_dsn(url);
    };
    out.push_str(&url[..scheme_end]);
    let rest = &url[scheme_end..];
    let auth_end = authority_end(rest);
    let authority = &rest[..auth_end];
    // rfind: an unescaped '@' inside the password still ends at the host.
    match authority.rfind('@') {
        Some(at) => {
            let userinfo = &authority[..at];
            match userinfo.find(':') {
                Some(colon) => {
                    out.push_str(&userinfo[..colon]);
                    out.push_str(":***");
                }
                None => out.push_str(userinfo),
            }
            out.push_str(&authority[at..]);
        }
        None => out.push_str(authority),
    }
    // SEC-5: the authority heuristic can swallow a '?' (an '@' in the
    // query looks like userinfo), so secret pairs are redacted in every
    // `?`/`&`/`#`-separated segment of the tail, not only after a '?'.
    for (seg, delim) in tail_segments(&rest[auth_end..]) {
        push_redacted_pair(&mut out, seg);
        if let Some(d) = delim {
            out.push(d);
        }
    }
    out
}

/// Splits a URL tail at `?`, `&` and `#`, yielding each segment and the
/// delimiter that follows it.
fn tail_segments(tail: &str) -> impl Iterator<Item = (&str, Option<char>)> {
    let mut rest = Some(tail);
    std::iter::from_fn(move || {
        let r = rest?;
        if let Some(i) = r.find(['?', '&', '#']) {
            rest = Some(&r[i + 1..]);
            Some((&r[..i], r[i..].chars().next()))
        } else {
            rest = None;
            Some((r, None))
        }
    })
}

/// Values of secret `key=value` pairs in a URL tail or DSN.
fn secret_values(url: &str) -> Vec<&str> {
    let tail = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            &rest[authority_end(rest)..]
        }
        None => {
            return dsn_pairs(url)
                .filter_map(|(k, v)| is_secret(k).then_some(v))
                .collect();
        }
    };
    tail_segments(tail)
        .filter_map(|(seg, _)| seg.split_once('='))
        .filter_map(|(k, v)| is_secret(k).then_some(v))
        .collect()
}

fn is_secret(key: &str) -> bool {
    SECRET_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k))
}

/// Byte offset in `rest` (text after `://`) where the authority ends.
///
/// An unescaped `/`, `?` or `#` may appear inside the password, so the
/// search for the end starts after the last `@` when one exists. If the
/// `@` was really in the path or query, more than the password is
/// redacted, which errs on the safe side.
fn authority_end(rest: &str) -> usize {
    let from = rest.rfind('@').unwrap_or(0);
    // '&' cannot occur in a host, so it also ends the authority (SEC-5:
    // `?user=u@srv&password=pw`).
    rest[from..]
        .find(['/', '?', '#', '&'])
        .map_or(rest.len(), |i| from + i)
}

/// Redacts a libpq key/value DSN (`host=h user=u password='a b'`).
///
/// Follows libpq parsing: any ASCII whitespace separates pairs, spaces are
/// allowed around `=`, and single-quoted values honour `\'` and `\\`
/// escapes, so a quoted password containing whitespace is fully replaced.
fn redact_dsn(dsn: &str) -> String {
    let mut out = String::with_capacity(dsn.len());
    let mut copied = 0;
    for (key, value) in dsn_pairs(dsn) {
        if !is_secret(key) {
            continue;
        }
        // `value` is a subslice of `dsn`; replace it in place.
        let start = value.as_ptr() as usize - dsn.as_ptr() as usize;
        out.push_str(&dsn[copied..start]);
        out.push_str("***");
        copied = start + value.len();
    }
    out.push_str(&dsn[copied..]);
    out
}

/// Parses a libpq key/value DSN into `(key, raw value)` subslices.
///
/// Values keep their quotes. Malformed input ends parsing; never panics.
fn dsn_pairs(dsn: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut rest = dsn;
    std::iter::from_fn(move || {
        let r = rest.trim_start();
        let key_end = r.find(|c: char| c == '=' || c.is_ascii_whitespace())?;
        let key = &r[..key_end];
        let after_key = r[key_end..].trim_start();
        let Some(after_eq) = after_key.strip_prefix('=') else {
            // Bare word: skip it and continue.
            rest = after_key;
            return Some((key, ""));
        };
        let v = after_eq.trim_start();
        let end = dsn_value_end(v);
        rest = &v[end..];
        Some((key, &v[..end]))
    })
    .filter(|(k, _)| !k.is_empty())
}

/// Length of the value at the start of `s`, honouring libpq quotes.
fn dsn_value_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\\' if quoted => i += 1,
            b'\'' => quoted = !quoted,
            b if !quoted && b.is_ascii_whitespace() => return i,
            _ => {}
        }
        i += 1;
    }
    // An unterminated quote runs to the end; `min` keeps a trailing
    // backslash from stepping past it.
    i.min(s.len())
}

/// Appends `key=value`, replacing the value with `***` for secret keys.
fn push_redacted_pair(out: &mut String, pair: &str) {
    match pair.split_once('=') {
        Some((key, _)) if is_secret(key) => {
            out.push_str(key);
            out.push_str("=***");
        }
        _ => out.push_str(pair),
    }
}

/// Redacts the password of `url` wherever it appears in `message`.
///
/// Driver errors (sqlx, redis) can echo the connection string or parts of
/// it; this removes the raw and percent-decoded password, then any URL.
///
/// NIST 800-53 Rev5: SI-11 (Error Handling)
#[must_use]
pub fn redact_error(message: &str, url: &str) -> String {
    let mut msg = message.to_string();
    if let Some(pw) = url_password(url) {
        if !pw.is_empty() {
            msg = msg.replace(pw, "***");
            let decoded = percent_decode(pw);
            if !decoded.is_empty() && decoded != pw {
                msg = msg.replace(&decoded, "***");
            }
        }
    }
    for v in secret_values(url) {
        let v = v.trim_matches('\'');
        if !v.is_empty() {
            msg = msg.replace(v, "***");
        }
    }
    if msg.contains(url) && !url.is_empty() {
        msg = msg.replace(url, &redact_url(url));
    }
    msg
}

/// Returns the userinfo password of a URL, if present.
fn url_password(url: &str) -> Option<&str> {
    let rest = &url[url.find("://")? + 3..];
    let authority = &rest[..authority_end(rest)];
    let userinfo = &authority[..authority.rfind('@')?];
    userinfo.find(':').map(|c| &userinfo[c + 1..])
}

/// Lossy percent-decoding (invalid escapes are kept literally).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |c: Option<&u8>| c.and_then(|c| char::from(*c).to_digit(16));
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            if let (Some(h), Some(l)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                // h, l < 16 so the value always fits a u8.
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        assert_eq!(config.default_ttl(), Some(Duration::from_hours(1)));
    }

    #[test]
    fn test_redis_timeouts() {
        let config = RedisConfig::default();
        assert_eq!(config.connection_timeout(), Duration::from_secs(5));
        assert_eq!(config.command_timeout(), Duration::from_secs(1));
    }

    #[test]
    fn default_ssl_mode_is_verify_full() {
        assert_eq!(PostgresSslMode::default(), PostgresSslMode::VerifyFull);
        let cfg = PostgresConfig::default();
        assert_eq!(cfg.ssl_mode, PostgresSslMode::VerifyFull);
        assert!(!cfg.allow_insecure_transport);
        assert!(!cfg.validate_transport_security().unwrap());
    }

    #[test]
    fn prefer_and_disable_rejected_without_opt_in() {
        for mode in [
            PostgresSslMode::Disable,
            PostgresSslMode::Prefer,
            PostgresSslMode::Require,
        ] {
            let cfg = PostgresConfig {
                ssl_mode: mode,
                ..Default::default()
            };
            assert!(matches!(
                cfg.validate_transport_security(),
                Err(StorageError::InsecureTransport { .. })
            ));
        }
        let cfg = PostgresConfig {
            ssl_mode: PostgresSslMode::VerifyCa,
            ..Default::default()
        };
        assert!(!cfg.validate_transport_security().unwrap());
    }

    #[test]
    fn serde_prefer_still_rejected_at_runtime() {
        let cfg: PostgresConfig = serde_json::from_str(r#"{"ssl_mode":"prefer"}"#).unwrap();
        assert!(cfg.validate_transport_security().is_err());
    }

    #[test]
    fn redis_plain_url_rejected_without_tls() {
        assert!(matches!(
            RedisConfig::default().validate_transport_security(),
            Err(StorageError::InsecureTransport { .. })
        ));
        for url in ["unix:///tmp/redis.sock", "redis+unix:///tmp/r.sock"] {
            assert!(RedisConfig::new(url).validate_transport_security().is_err());
        }
        let mut cfg = RedisConfig::new("redis://cache.example.invalid:6379");
        cfg.tls = Some(RedisTlsConfig::default());
        assert!(matches!(
            cfg.validate_transport_security(),
            Err(StorageError::InsecureTransport { .. })
        ));
        assert!(
            !RedisConfig::new("rediss://cache.example.invalid:6379")
                .validate_transport_security()
                .unwrap()
        );
    }

    #[test]
    fn verify_certificate_false_always_rejected() {
        let mut cfg = RedisConfig::new("rediss://cache.example.invalid:6379");
        cfg.allow_insecure_transport = true;
        cfg.tls = Some(RedisTlsConfig {
            verify_certificate: false,
            ..Default::default()
        });
        assert!(cfg.validate_transport_security().is_err());

        let mut cfg = RedisConfig::new("rediss://cache.example.invalid:6379/#insecure");
        cfg.allow_insecure_transport = true;
        assert!(cfg.validate_transport_security().is_err());
    }

    #[test]
    fn redis_half_client_cert_rejected() {
        let mut cfg = RedisConfig::new("rediss://cache.example.invalid:6379");
        cfg.tls = Some(RedisTlsConfig {
            client_cert_path: Some("/x.pem".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            cfg.validate_transport_security(),
            Err(StorageError::ConfigError { .. })
        ));
    }

    #[test]
    fn redis_cluster_mode_rejected() {
        let mut cfg = RedisConfig::new("rediss://cache.example.invalid:6379");
        cfg.cluster_mode = true;
        assert!(cfg.validate_transport_security().is_err());
    }

    #[test]
    fn opt_in_allows_insecure_with_warning() {
        let r = RedisConfig {
            allow_insecure_transport: true,
            ..Default::default()
        };
        assert!(r.validate_transport_security().unwrap());
        let p = PostgresConfig {
            ssl_mode: PostgresSslMode::Prefer,
            allow_insecure_transport: true,
            ..Default::default()
        };
        assert!(p.validate_transport_security().unwrap());
    }

    #[test]
    fn redact_url_userinfo_password() {
        assert_eq!(
            redact_url("redis://user:hunter2@cache:6379/0"),
            "redis://user:***@cache:6379/0"
        );
        assert_eq!(redact_url("redis://:hunter2@cache"), "redis://:***@cache");
    }

    #[test]
    fn redact_url_without_password_unchanged() {
        for u in [
            "redis://cache:6379",
            "postgres://user@db/sbc",
            "rediss://cache/#insecure",
        ] {
            assert_eq!(redact_url(u), u);
        }
    }

    #[test]
    fn redact_url_unescaped_delimiters_in_password() {
        // SEC-1: '/', '?', '#' inside the password must not end the authority.
        for (u, want) in [
            ("postgres://u:pa/ss@db/sbc", "postgres://u:***@db/sbc"),
            ("postgres://u:pa?ss@db", "postgres://u:***@db"),
            (
                concat!("redis", "://u:p#a/s?s@cache:6379/0"),
                "redis://u:***@cache:6379/0",
            ),
        ] {
            assert_eq!(redact_url(u), want);
            assert!(!redact_error(u, u).contains("pa"), "{u}");
        }
    }

    #[test]
    fn redact_url_at_in_query_does_not_leak_query_password() {
        // SEC-5: an '@' in the query must not hide `password=` from redaction.
        let u = "postgres://db:5432/sbc?user=u@srv&password=pw";
        let r = redact_url(u);
        assert!(!r.contains("pw"), "{r}");
        assert!(r.contains("password=***"), "{r}");
        assert!(!redact_error(&format!("bad pw for {u}"), u).contains("pw"));
        // SEC-1 cases still hold.
        assert_eq!(
            redact_url("postgres://u:pa/ss@db/sbc"),
            "postgres://u:***@db/sbc"
        );
    }

    #[test]
    fn redact_dsn_whitespace_and_spaced_equals() {
        // SEC-6: libpq allows any whitespace and spaces around '='.
        assert_eq!(
            redact_url("host=db\tpassword = 'a b'\nuser=u"),
            "host=db\tpassword = ***\nuser=u"
        );
        assert_eq!(redact_url("password =\tsecret"), "password =\t***");
        assert!(!redact_error("x a b y", "password = 'a b'").contains("a b"));
    }

    #[test]
    fn redact_dsn_quoted_password() {
        // SEC-2: libpq single-quoted values may contain spaces and escapes.
        assert_eq!(
            redact_url("host=db password='a b' dbname=sbc"),
            "host=db password=*** dbname=sbc"
        );
        assert_eq!(
            redact_url(r"password='x\' y' user=u"),
            "password=*** user=u"
        );
        assert_eq!(redact_url("password='open ended"), "password=***");
        assert_eq!(redact_url("password=\\"), "password=***");
    }

    #[test]
    fn redact_url_at_and_escapes_in_password() {
        assert_eq!(
            redact_url(concat!("postgres", "://u:p%40ss@db/sbc")),
            "postgres://u:***@db/sbc"
        );
        assert_eq!(
            redact_url("postgres://u:p@ss@db/sbc"),
            "postgres://u:***@db/sbc"
        );
    }

    #[test]
    fn redact_url_ipv6_host() {
        assert_eq!(
            redact_url("postgres://u:pw@[2001:db8::1]:5432/sbc"),
            "postgres://u:***@[2001:db8::1]:5432/sbc"
        );
        assert_eq!(redact_url("redis://[::1]:6379"), "redis://[::1]:6379");
    }

    #[test]
    fn redact_url_query_and_dsn_password() {
        assert_eq!(
            redact_url("postgres://db/sbc?user=u&password=pw&sslmode=verify-full#f"),
            "postgres://db/sbc?user=u&password=***&sslmode=verify-full#f"
        );
        assert_eq!(
            redact_url("host=db user=u PASSWORD=pw dbname=sbc"),
            "host=db user=u PASSWORD=*** dbname=sbc"
        );
    }

    #[test]
    fn redact_url_garbage_does_not_panic() {
        for u in [
            "",
            "://",
            "@",
            ":@",
            "a://@",
            "a://:",
            "?password",
            "%",
            "%4",
            "é://ü:ß@ñ/?password=€",
            "redis://u:pw@",
            "x://?&&=#",
        ] {
            let r = redact_url(u);
            assert!(!r.contains("pw@"));
            let _ = redact_error(u, u);
        }
    }

    #[test]
    fn debug_output_has_no_password() {
        let r = RedisConfig::new("redis://u:hunter2@cache:6379");
        let p = PostgresConfig::new("postgres://u:hunter2@db/sbc?password=hunter2");
        let mut s = StorageConfig::redis("redis://u:hunter2@cache");
        s.postgres = Some(p.clone());
        for out in [format!("{r:?}"), format!("{p:?}"), format!("{s:?}")] {
            assert!(!out.contains("hunter2"), "{out}");
        }
    }

    #[test]
    fn connection_error_reason_redacted() {
        let url = concat!("postgres", "://u:p%40ss@db/sbc");
        let msg = concat!(
            "error connecting to postgres",
            "://u:p%40ss@db/sbc: auth failed for p@ss"
        );
        let out = redact_error(msg, url);
        assert!(!out.contains("p%40ss"), "{out}");
        assert!(!out.contains("p@ss"), "{out}");
    }

    #[test]
    fn test_postgres_timeouts() {
        let config = PostgresConfig::default();
        assert_eq!(config.connection_timeout(), Duration::from_secs(5));
        assert_eq!(config.query_timeout(), Duration::from_secs(30));
    }
}
