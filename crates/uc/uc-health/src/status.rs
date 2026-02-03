//! Health status types.

use std::collections::HashMap;
use std::time::Instant;

/// Overall health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// System is healthy and operational.
    Healthy,
    /// System is degraded but functional.
    Degraded,
    /// System is unhealthy.
    Unhealthy,
    /// Health status is unknown.
    Unknown,
}

impl HealthStatus {
    /// Returns whether the status indicates the system is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// Returns whether the system is fully healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns a string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }

    /// Combines two statuses (takes the worse one).
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unhealthy, _) | (_, Self::Unhealthy) => Self::Unhealthy,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Degraded, _) | (_, Self::Degraded) => Self::Degraded,
            (Self::Healthy, Self::Healthy) => Self::Healthy,
        }
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Individual component status.
#[derive(Debug, Clone)]
pub struct ComponentStatus {
    /// Component name.
    pub name: String,
    /// Health status.
    pub status: HealthStatus,
    /// Optional message.
    pub message: Option<String>,
    /// Last check time.
    pub last_check: Option<Instant>,
    /// Check duration in milliseconds.
    pub check_duration_ms: Option<u64>,
    /// Additional details.
    pub details: HashMap<String, String>,
}

impl ComponentStatus {
    /// Creates a new component status.
    pub fn new(name: impl Into<String>, status: HealthStatus) -> Self {
        Self {
            name: name.into(),
            status,
            message: None,
            last_check: None,
            check_duration_ms: None,
            details: HashMap::new(),
        }
    }

    /// Creates a healthy status.
    pub fn healthy(name: impl Into<String>) -> Self {
        Self::new(name, HealthStatus::Healthy)
    }

    /// Creates a degraded status.
    pub fn degraded(name: impl Into<String>, message: impl Into<String>) -> Self {
        let mut status = Self::new(name, HealthStatus::Degraded);
        status.message = Some(message.into());
        status
    }

    /// Creates an unhealthy status.
    pub fn unhealthy(name: impl Into<String>, message: impl Into<String>) -> Self {
        let mut status = Self::new(name, HealthStatus::Unhealthy);
        status.message = Some(message.into());
        status
    }

    /// Sets the message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Sets the last check time.
    pub fn with_last_check(mut self, instant: Instant) -> Self {
        self.last_check = Some(instant);
        self
    }

    /// Sets the check duration.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.check_duration_ms = Some(duration_ms);
        self
    }

    /// Adds a detail.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Returns whether the component is healthy.
    pub fn is_healthy(&self) -> bool {
        self.status.is_healthy()
    }

    /// Returns whether the component is operational.
    pub fn is_operational(&self) -> bool {
        self.status.is_operational()
    }
}

/// System-wide health report.
#[derive(Debug, Clone)]
pub struct SystemHealth {
    /// Overall status.
    pub status: HealthStatus,
    /// Component statuses.
    pub components: Vec<ComponentStatus>,
    /// System uptime in seconds.
    pub uptime_secs: Option<u64>,
    /// Version info.
    pub version: Option<String>,
    /// Timestamp.
    pub timestamp: u64,
}

impl SystemHealth {
    /// Creates a new system health report.
    pub fn new(status: HealthStatus) -> Self {
        Self {
            status,
            components: Vec::new(),
            uptime_secs: None,
            version: None,
            timestamp: 0,
        }
    }

    /// Creates from component statuses.
    pub fn from_components(components: Vec<ComponentStatus>) -> Self {
        let status = components
            .iter()
            .map(|c| c.status)
            .fold(HealthStatus::Healthy, HealthStatus::combine);

        Self {
            status,
            components,
            uptime_secs: None,
            version: None,
            timestamp: 0,
        }
    }

    /// Sets the uptime.
    pub fn with_uptime(mut self, secs: u64) -> Self {
        self.uptime_secs = Some(secs);
        self
    }

    /// Sets the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the timestamp.
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Adds a component status.
    pub fn add_component(&mut self, component: ComponentStatus) {
        self.status = self.status.combine(component.status);
        self.components.push(component);
    }

    /// Returns whether the system is healthy.
    pub fn is_healthy(&self) -> bool {
        self.status.is_healthy()
    }

    /// Returns whether the system is operational.
    pub fn is_operational(&self) -> bool {
        self.status.is_operational()
    }

    /// Returns the number of healthy components.
    pub fn healthy_count(&self) -> usize {
        self.components.iter().filter(|c| c.is_healthy()).count()
    }

    /// Returns the number of unhealthy components.
    pub fn unhealthy_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count()
    }

    /// Returns component by name.
    pub fn get_component(&self, name: &str) -> Option<&ComponentStatus> {
        self.components.iter().find(|c| c.name == name)
    }
}

impl Default for SystemHealth {
    fn default() -> Self {
        Self::new(HealthStatus::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(HealthStatus::Healthy.is_operational());
        assert!(!HealthStatus::Unhealthy.is_operational());
        assert!(HealthStatus::Degraded.is_operational());
    }

    #[test]
    fn test_health_status_combine() {
        assert_eq!(
            HealthStatus::Healthy.combine(HealthStatus::Healthy),
            HealthStatus::Healthy
        );
        assert_eq!(
            HealthStatus::Healthy.combine(HealthStatus::Degraded),
            HealthStatus::Degraded
        );
        assert_eq!(
            HealthStatus::Degraded.combine(HealthStatus::Unhealthy),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn test_component_status_healthy() {
        let status = ComponentStatus::healthy("database");
        assert!(status.is_healthy());
        assert_eq!(status.name, "database");
    }

    #[test]
    fn test_component_status_unhealthy() {
        let status = ComponentStatus::unhealthy("cache", "Connection refused");
        assert!(!status.is_healthy());
        assert_eq!(status.message, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_component_status_with_details() {
        let status = ComponentStatus::healthy("database")
            .with_detail("connections", "10")
            .with_detail("latency_ms", "5");

        assert_eq!(status.details.len(), 2);
        assert_eq!(status.details.get("connections"), Some(&"10".to_string()));
    }

    #[test]
    fn test_system_health_from_components() {
        let components = vec![
            ComponentStatus::healthy("db"),
            ComponentStatus::healthy("cache"),
        ];
        let health = SystemHealth::from_components(components);

        assert!(health.is_healthy());
        assert_eq!(health.healthy_count(), 2);
    }

    #[test]
    fn test_system_health_degraded() {
        let components = vec![
            ComponentStatus::healthy("db"),
            ComponentStatus::degraded("cache", "High latency"),
        ];
        let health = SystemHealth::from_components(components);

        assert!(!health.is_healthy());
        assert!(health.is_operational());
        assert_eq!(health.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_system_health_unhealthy() {
        let components = vec![
            ComponentStatus::healthy("db"),
            ComponentStatus::unhealthy("cache", "Down"),
        ];
        let health = SystemHealth::from_components(components);

        assert!(!health.is_healthy());
        assert!(!health.is_operational());
        assert_eq!(health.unhealthy_count(), 1);
    }

    #[test]
    fn test_system_health_add_component() {
        let mut health = SystemHealth::new(HealthStatus::Healthy);
        health.add_component(ComponentStatus::healthy("db"));
        health.add_component(ComponentStatus::unhealthy("cache", "Error"));

        assert_eq!(health.components.len(), 2);
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_system_health_get_component() {
        let components = vec![
            ComponentStatus::healthy("db"),
            ComponentStatus::healthy("cache"),
        ];
        let health = SystemHealth::from_components(components);

        assert!(health.get_component("db").is_some());
        assert!(health.get_component("nonexistent").is_none());
    }

    #[test]
    fn test_system_health_with_metadata() {
        let health = SystemHealth::new(HealthStatus::Healthy)
            .with_uptime(3600)
            .with_version("1.0.0")
            .with_timestamp(1704067200);

        assert_eq!(health.uptime_secs, Some(3600));
        assert_eq!(health.version, Some("1.0.0".to_string()));
    }
}
