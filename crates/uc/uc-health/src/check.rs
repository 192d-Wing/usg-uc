//! Health check definitions.

use crate::status::{ComponentStatus, HealthStatus};
use std::time::{Duration, Instant};

/// Result of a health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Status.
    pub status: HealthStatus,
    /// Optional message.
    pub message: Option<String>,
    /// Check duration.
    pub duration: Duration,
    /// Additional data.
    pub data: Option<String>,
}

impl HealthCheckResult {
    /// Creates a healthy result.
    pub fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
            duration: Duration::ZERO,
            data: None,
        }
    }

    /// Creates a degraded result.
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            duration: Duration::ZERO,
            data: None,
        }
    }

    /// Creates an unhealthy result.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            duration: Duration::ZERO,
            data: None,
        }
    }

    /// Sets the duration.
    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Sets additional data.
    #[must_use]
    pub fn with_data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Converts to a component status.
    pub fn to_component_status(self, name: &str) -> ComponentStatus {
        let mut status = ComponentStatus::new(name, self.status);
        status.message = self.message;
        status.check_duration_ms = Some(self.duration.as_millis() as u64);
        status.last_check = Some(Instant::now());
        status
    }
}

/// Health check trait.
pub trait HealthCheck {
    /// Returns the check name.
    fn name(&self) -> &str;

    /// Performs the health check.
    fn check(&self) -> HealthCheckResult;

    /// Returns whether this check is critical.
    fn is_critical(&self) -> bool {
        true
    }
}

/// Simple function-based health check.
pub struct FnHealthCheck<F>
where
    F: Fn() -> HealthCheckResult,
{
    /// Check name.
    name: String,
    /// Check function.
    check_fn: F,
    /// Whether critical.
    critical: bool,
}

impl<F> FnHealthCheck<F>
where
    F: Fn() -> HealthCheckResult,
{
    /// Creates a new function-based health check.
    pub fn new(name: impl Into<String>, check_fn: F) -> Self {
        Self {
            name: name.into(),
            check_fn,
            critical: true,
        }
    }

    /// Sets whether this check is critical.
    #[must_use]
    pub fn with_critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }
}

impl<F> HealthCheck for FnHealthCheck<F>
where
    F: Fn() -> HealthCheckResult,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let mut result = (self.check_fn)();
        result.duration = start.elapsed();
        result
    }

    fn is_critical(&self) -> bool {
        self.critical
    }
}

/// Always healthy check (useful for testing).
pub struct AlwaysHealthyCheck {
    /// Check name.
    name: String,
}

impl AlwaysHealthyCheck {
    /// Creates a new always-healthy check.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl HealthCheck for AlwaysHealthyCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> HealthCheckResult {
        HealthCheckResult::healthy()
    }
}

/// Memory usage check.
pub struct MemoryCheck {
    /// Check name.
    name: String,
    /// Warning threshold (percentage).
    warn_threshold: f64,
    /// Critical threshold (percentage).
    critical_threshold: f64,
}

impl MemoryCheck {
    /// Creates a new memory check with default thresholds.
    pub fn new() -> Self {
        Self {
            name: "memory".to_string(),
            warn_threshold: 80.0,
            critical_threshold: 95.0,
        }
    }

    /// Sets the warning threshold.
    #[must_use]
    pub fn with_warn_threshold(mut self, threshold: f64) -> Self {
        self.warn_threshold = threshold;
        self
    }

    /// Sets the critical threshold.
    #[must_use]
    pub fn with_critical_threshold(mut self, threshold: f64) -> Self {
        self.critical_threshold = threshold;
        self
    }
}

impl Default for MemoryCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheck for MemoryCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> HealthCheckResult {
        // Simulated memory check - in production would query system
        let usage_percent = 50.0; // Simulated

        if usage_percent >= self.critical_threshold {
            HealthCheckResult::unhealthy(format!("Memory usage critical: {usage_percent:.1}%"))
        } else if usage_percent >= self.warn_threshold {
            HealthCheckResult::degraded(format!("Memory usage high: {usage_percent:.1}%"))
        } else {
            HealthCheckResult::healthy().with_data(format!("Memory usage: {usage_percent:.1}%"))
        }
    }
}

/// Disk usage check.
pub struct DiskCheck {
    /// Check name.
    name: String,
    /// Path to check.
    path: String,
    /// Warning threshold (percentage).
    warn_threshold: f64,
    /// Critical threshold (percentage).
    critical_threshold: f64,
}

impl DiskCheck {
    /// Creates a new disk check.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            name: "disk".to_string(),
            path: path.into(),
            warn_threshold: 80.0,
            critical_threshold: 95.0,
        }
    }

    /// Sets the warning threshold.
    #[must_use]
    pub fn with_warn_threshold(mut self, threshold: f64) -> Self {
        self.warn_threshold = threshold;
        self
    }

    /// Sets the critical threshold.
    #[must_use]
    pub fn with_critical_threshold(mut self, threshold: f64) -> Self {
        self.critical_threshold = threshold;
        self
    }
}

impl HealthCheck for DiskCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> HealthCheckResult {
        // Simulated disk check - in production would query filesystem
        let usage_percent = 40.0; // Simulated

        if usage_percent >= self.critical_threshold {
            HealthCheckResult::unhealthy(format!(
                "Disk usage critical on {}: {:.1}%",
                self.path, usage_percent
            ))
        } else if usage_percent >= self.warn_threshold {
            HealthCheckResult::degraded(format!(
                "Disk usage high on {}: {:.1}%",
                self.path, usage_percent
            ))
        } else {
            HealthCheckResult::healthy().with_data(format!(
                "Disk usage on {}: {:.1}%",
                self.path, usage_percent
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_result_healthy() {
        let result = HealthCheckResult::healthy();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.message.is_none());
    }

    #[test]
    fn test_health_check_result_unhealthy() {
        let result = HealthCheckResult::unhealthy("Connection failed");
        assert_eq!(result.status, HealthStatus::Unhealthy);
        assert_eq!(result.message, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_health_check_result_with_data() {
        let result = HealthCheckResult::healthy()
            .with_data("latency: 5ms")
            .with_duration(Duration::from_millis(10));

        assert_eq!(result.data, Some("latency: 5ms".to_string()));
        assert_eq!(result.duration, Duration::from_millis(10));
    }

    #[test]
    fn test_health_check_result_to_component() {
        let result = HealthCheckResult::healthy().with_duration(Duration::from_millis(50));

        let component = result.to_component_status("database");
        assert_eq!(component.name, "database");
        assert_eq!(component.status, HealthStatus::Healthy);
        assert_eq!(component.check_duration_ms, Some(50));
    }

    #[test]
    fn test_fn_health_check() {
        let check = FnHealthCheck::new("test_check", HealthCheckResult::healthy);

        assert_eq!(check.name(), "test_check");
        assert!(check.is_critical());

        let result = check.check();
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_fn_health_check_non_critical() {
        let check = FnHealthCheck::new("optional_check", HealthCheckResult::healthy)
            .with_critical(false);

        assert!(!check.is_critical());
    }

    #[test]
    fn test_always_healthy_check() {
        let check = AlwaysHealthyCheck::new("test");
        let result = check.check();
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_memory_check() {
        let check = MemoryCheck::new()
            .with_warn_threshold(80.0)
            .with_critical_threshold(95.0);

        let result = check.check();
        // With simulated 50% usage, should be healthy
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_disk_check() {
        let check = DiskCheck::new("/")
            .with_warn_threshold(80.0)
            .with_critical_threshold(95.0);

        let result = check.check();
        // With simulated 40% usage, should be healthy
        assert_eq!(result.status, HealthStatus::Healthy);
    }
}
