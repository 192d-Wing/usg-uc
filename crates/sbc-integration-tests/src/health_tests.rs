//! Health check integration tests.

use sbc_health::{
    check::{AlwaysHealthyCheck, FnHealthCheck, HealthCheck, HealthCheckResult, MemoryCheck},
    HealthChecker, HealthCheckerConfig, HealthStatus,
};

#[test]
fn test_health_checker_all_healthy() {
    let mut checker = HealthChecker::new(HealthCheckerConfig::default());

    checker.register(Box::new(AlwaysHealthyCheck::new("database")));
    checker.register(Box::new(AlwaysHealthyCheck::new("cache")));

    let health = checker.check();

    assert!(health.is_healthy());
    assert_eq!(health.healthy_count(), 2);
}

#[test]
fn test_health_checker_degraded() {
    let mut checker = HealthChecker::new(HealthCheckerConfig::default());

    checker.register(Box::new(AlwaysHealthyCheck::new("database")));
    checker.register(Box::new(FnHealthCheck::new("cache", || {
        HealthCheckResult::degraded("High latency")
    })));

    let health = checker.check();

    assert!(!health.is_healthy());
    assert!(health.is_operational());
    assert_eq!(health.status, HealthStatus::Degraded);
}

#[test]
fn test_health_checker_unhealthy() {
    let mut checker = HealthChecker::new(HealthCheckerConfig::default());

    checker.register(Box::new(FnHealthCheck::new("critical", || {
        HealthCheckResult::unhealthy("Connection refused")
    })));

    let health = checker.check();

    assert!(!health.is_healthy());
    assert!(!health.is_operational());
}

#[test]
fn test_liveness_and_readiness() {
    let mut checker = HealthChecker::with_defaults();
    checker.register(Box::new(AlwaysHealthyCheck::new("test")));

    assert!(checker.is_alive());
    assert!(checker.is_ready());
}

#[test]
fn test_health_status_combine() {
    assert_eq!(
        HealthStatus::Healthy.combine(HealthStatus::Healthy),
        HealthStatus::Healthy
    );
    assert_eq!(
        HealthStatus::Healthy.combine(HealthStatus::Unhealthy),
        HealthStatus::Unhealthy
    );
}

#[test]
fn test_memory_check() {
    let check = MemoryCheck::new();
    let result = check.check();
    assert_eq!(result.status, HealthStatus::Healthy);
}
