//! Metrics integration tests.

use uc_metrics::{Counter, Gauge, Histogram, MetricRegistry, SbcMetrics};

#[test]
fn test_counter_operations() {
    let counter = Counter::new("test_counter", "A test counter");

    assert_eq!(counter.get(), 0);
    counter.inc();
    assert_eq!(counter.get(), 1);
    counter.inc_by(5);
    assert_eq!(counter.get(), 6);
}

#[test]
fn test_gauge_operations() {
    let gauge = Gauge::new("test_gauge", "A test gauge");

    gauge.set(100);
    assert_eq!(gauge.get(), 100);
    gauge.inc();
    assert_eq!(gauge.get(), 101);
    gauge.dec();
    assert_eq!(gauge.get(), 100);
}

#[test]
fn test_histogram_observations() {
    let histogram = Histogram::new("latency", "Request latency");

    histogram.observe(10.0);
    histogram.observe(20.0);
    histogram.observe(30.0);

    assert_eq!(histogram.count(), 3);
    assert_eq!(histogram.sum(), 60.0);
}

#[test]
fn test_registry_operations() {
    let mut registry = MetricRegistry::new();

    let counter = registry.register_counter("requests_total", "Total requests");
    counter.inc_by(100);

    let retrieved = registry.counter("requests_total");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().get(), 100);
}

#[test]
fn test_registry_namespace() {
    let mut registry = MetricRegistry::with_namespace("myapp");

    let counter = registry.register_counter("requests", "Total requests");
    assert_eq!(counter.name(), "myapp_requests");
}

#[test]
fn test_uc_metrics_standard() {
    let registry = SbcMetrics::standard();

    assert!(registry.counter("calls_total").is_some());
    assert!(registry.gauge("calls_active").is_some());
    assert!(registry.histogram("call_setup_duration_seconds").is_some());
}

#[test]
fn test_registry_export() {
    let mut registry = MetricRegistry::new();

    let counter = registry.register_counter("requests", "Total requests");
    counter.inc_by(100);

    let output = registry.export();
    assert!(output.contains("requests 100"));
}
