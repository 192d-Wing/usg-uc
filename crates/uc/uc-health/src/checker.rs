//! Health checker service.

use crate::check::{HealthCheck, HealthCheckResult};
use crate::status::{HealthStatus, SystemHealth};
use crate::{DEFAULT_CHECK_INTERVAL_SECS, DEFAULT_CHECK_TIMEOUT_MS};
use std::time::Instant;

/// Health checker configuration.
#[derive(Debug, Clone)]
pub struct HealthCheckerConfig {
    /// Check timeout in milliseconds.
    pub timeout_ms: u64,
    /// Check interval in seconds.
    pub interval_secs: u64,
    /// Whether to include details in responses.
    pub include_details: bool,
    /// Whether to fail on any unhealthy component.
    pub fail_on_unhealthy: bool,
}

impl Default for HealthCheckerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_CHECK_TIMEOUT_MS,
            interval_secs: DEFAULT_CHECK_INTERVAL_SECS,
            include_details: true,
            fail_on_unhealthy: true,
        }
    }
}

impl HealthCheckerConfig {
    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets the interval.
    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    /// Sets whether to include details.
    pub fn with_details(mut self, include: bool) -> Self {
        self.include_details = include;
        self
    }
}

/// Health checker statistics.
#[derive(Debug, Clone, Default)]
pub struct HealthCheckerStats {
    /// Total checks performed.
    pub checks_performed: u64,
    /// Failed checks.
    pub checks_failed: u64,
    /// Last check time.
    pub last_check: Option<Instant>,
    /// Last check duration in milliseconds.
    pub last_check_duration_ms: Option<u64>,
}

/// Health checker service.
pub struct HealthChecker {
    /// Configuration.
    config: HealthCheckerConfig,
    /// Registered checks.
    checks: Vec<Box<dyn HealthCheck>>,
    /// Last health status.
    last_status: Option<SystemHealth>,
    /// Statistics.
    stats: HealthCheckerStats,
    /// Start time (for uptime).
    start_time: Instant,
    /// Version string.
    version: Option<String>,
}

impl HealthChecker {
    /// Creates a new health checker.
    pub fn new(config: HealthCheckerConfig) -> Self {
        Self {
            config,
            checks: Vec::new(),
            last_status: None,
            stats: HealthCheckerStats::default(),
            start_time: Instant::now(),
            version: None,
        }
    }

    /// Creates a health checker with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HealthCheckerConfig::default())
    }

    /// Sets the version string.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Returns the configuration.
    pub fn config(&self) -> &HealthCheckerConfig {
        &self.config
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &HealthCheckerStats {
        &self.stats
    }

    /// Returns the uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Registers a health check.
    pub fn register(&mut self, check: Box<dyn HealthCheck>) {
        self.checks.push(check);
    }

    /// Returns the number of registered checks.
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Performs all health checks and returns the system health.
    pub fn check(&mut self) -> SystemHealth {
        let start = Instant::now();
        let mut components = Vec::new();

        for check in &self.checks {
            let result = check.check();
            components.push(result.to_component_status(check.name()));
        }

        let duration = start.elapsed();

        // Update stats
        self.stats.checks_performed += 1;
        self.stats.last_check = Some(start);
        self.stats.last_check_duration_ms = Some(duration.as_millis() as u64);

        // Build system health
        let mut health = SystemHealth::from_components(components)
            .with_uptime(self.uptime_secs())
            .with_timestamp(self.current_timestamp());

        if let Some(ref version) = self.version {
            health = health.with_version(version.clone());
        }

        // Check if any critical checks failed
        if !health.is_healthy() {
            self.stats.checks_failed += 1;
        }

        self.last_status = Some(health.clone());
        health
    }

    /// Performs a liveness check.
    /// Returns true if the service is alive (can respond to requests).
    pub fn is_alive(&self) -> bool {
        // Liveness = service is running and can respond
        true
    }

    /// Performs a readiness check.
    /// Returns true if the service is ready to accept traffic.
    pub fn is_ready(&mut self) -> bool {
        // Readiness = all critical components are operational
        let health = self.check();
        health.is_operational()
    }

    /// Returns the last health status without performing a new check.
    pub fn last_status(&self) -> Option<&SystemHealth> {
        self.last_status.as_ref()
    }

    /// Returns the current timestamp in milliseconds.
    fn current_timestamp(&self) -> u64 {
        // In production, would use proper time
        0
    }

    /// Performs a single check by name.
    pub fn check_by_name(&self, name: &str) -> Option<HealthCheckResult> {
        self.checks
            .iter()
            .find(|c| c.name() == name)
            .map(|c| c.check())
    }

    /// Returns the names of all registered checks.
    pub fn check_names(&self) -> Vec<&str> {
        self.checks.iter().map(|c| c.name()).collect()
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Liveness probe response.
#[derive(Debug, Clone)]
pub struct LivenessResponse {
    /// Whether alive.
    pub alive: bool,
    /// Timestamp.
    pub timestamp: u64,
}

impl LivenessResponse {
    /// Creates a new liveness response.
    pub fn new(alive: bool) -> Self {
        Self {
            alive,
            timestamp: 0,
        }
    }
}

/// Readiness probe response.
#[derive(Debug, Clone)]
pub struct ReadinessResponse {
    /// Whether ready.
    pub ready: bool,
    /// Status.
    pub status: HealthStatus,
    /// Reason if not ready.
    pub reason: Option<String>,
}

impl ReadinessResponse {
    /// Creates a new readiness response.
    pub fn new(ready: bool, status: HealthStatus) -> Self {
        Self {
            ready,
            status,
            reason: None,
        }
    }

    /// Sets the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{AlwaysHealthyCheck, FnHealthCheck};

    #[test]
    fn test_config_default() {
        let config = HealthCheckerConfig::default();
        assert_eq!(config.timeout_ms, DEFAULT_CHECK_TIMEOUT_MS);
        assert!(config.include_details);
    }

    #[test]
    fn test_config_builder() {
        let config = HealthCheckerConfig::default()
            .with_timeout(10000)
            .with_interval(60)
            .with_details(false);

        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.interval_secs, 60);
        assert!(!config.include_details);
    }

    #[test]
    fn test_checker_creation() {
        let checker = HealthChecker::with_defaults();
        assert_eq!(checker.check_count(), 0);
    }

    #[test]
    fn test_checker_register() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("test")));

        assert_eq!(checker.check_count(), 1);
        assert_eq!(checker.check_names(), vec!["test"]);
    }

    #[test]
    fn test_checker_check() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("component1")));
        checker.register(Box::new(AlwaysHealthyCheck::new("component2")));

        let health = checker.check();

        assert!(health.is_healthy());
        assert_eq!(health.components.len(), 2);
        assert_eq!(checker.stats().checks_performed, 1);
    }

    #[test]
    fn test_checker_unhealthy() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("healthy")));
        checker.register(Box::new(FnHealthCheck::new("unhealthy", || {
            HealthCheckResult::unhealthy("Simulated failure")
        })));

        let health = checker.check();

        assert!(!health.is_healthy());
        assert_eq!(health.unhealthy_count(), 1);
    }

    #[test]
    fn test_checker_is_alive() {
        let checker = HealthChecker::with_defaults();
        assert!(checker.is_alive());
    }

    #[test]
    fn test_checker_is_ready() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("test")));

        assert!(checker.is_ready());
    }

    #[test]
    fn test_checker_is_ready_degraded() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(FnHealthCheck::new("degraded", || {
            HealthCheckResult::degraded("High latency")
        })));

        // Degraded is still operational
        assert!(checker.is_ready());
    }

    #[test]
    fn test_checker_is_ready_unhealthy() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(FnHealthCheck::new("unhealthy", || {
            HealthCheckResult::unhealthy("Down")
        })));

        assert!(!checker.is_ready());
    }

    #[test]
    fn test_checker_with_version() {
        let mut checker = HealthChecker::with_defaults().with_version("1.0.0");
        checker.register(Box::new(AlwaysHealthyCheck::new("test")));

        let health = checker.check();
        assert_eq!(health.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_checker_check_by_name() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("database")));

        let result = checker.check_by_name("database");
        assert!(result.is_some());
        assert_eq!(result.unwrap().status, HealthStatus::Healthy);

        let result = checker.check_by_name("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_checker_last_status() {
        let mut checker = HealthChecker::with_defaults();
        checker.register(Box::new(AlwaysHealthyCheck::new("test")));

        assert!(checker.last_status().is_none());

        checker.check();

        assert!(checker.last_status().is_some());
    }

    #[test]
    fn test_checker_uptime() {
        let checker = HealthChecker::with_defaults();
        // Just verify it returns something
        let _ = checker.uptime_secs();
    }

    #[test]
    fn test_liveness_response() {
        let response = LivenessResponse::new(true);
        assert!(response.alive);
    }

    #[test]
    fn test_readiness_response() {
        let response =
            ReadinessResponse::new(false, HealthStatus::Unhealthy).with_reason("Database down");

        assert!(!response.ready);
        assert_eq!(response.reason, Some("Database down".to_string()));
    }
}
