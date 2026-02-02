//! Metric registry.

use crate::counter::Counter;
use crate::gauge::Gauge;
use crate::histogram::Histogram;
use std::collections::HashMap;

/// Metric type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// Counter (monotonically increasing).
    Counter,
    /// Gauge (can go up or down).
    Gauge,
    /// Histogram (distribution of values).
    Histogram,
}

impl MetricType {
    /// Returns the Prometheus type string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Metric info.
#[derive(Debug, Clone)]
pub struct MetricInfo {
    /// Metric name.
    pub name: String,
    /// Metric type.
    pub metric_type: MetricType,
    /// Help text.
    pub help: String,
    /// Label names.
    pub label_names: Vec<String>,
}

/// Metric registry for managing all metrics.
#[derive(Debug, Default)]
pub struct MetricRegistry {
    /// Registered counters.
    counters: HashMap<String, Counter>,
    /// Registered gauges.
    gauges: HashMap<String, Gauge>,
    /// Registered histograms.
    histograms: HashMap<String, Histogram>,
    /// Namespace prefix.
    namespace: Option<String>,
    /// Subsystem prefix.
    subsystem: Option<String>,
}

impl MetricRegistry {
    /// Creates a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry with a namespace.
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self {
            namespace: Some(namespace.into()),
            ..Default::default()
        }
    }

    /// Sets the subsystem.
    pub fn with_subsystem(mut self, subsystem: impl Into<String>) -> Self {
        self.subsystem = Some(subsystem.into());
        self
    }

    /// Builds a full metric name with namespace/subsystem.
    fn full_name(&self, name: &str) -> String {
        let mut parts = Vec::new();
        if let Some(ref ns) = self.namespace {
            parts.push(ns.as_str());
        }
        if let Some(ref sub) = self.subsystem {
            parts.push(sub.as_str());
        }
        parts.push(name);
        parts.join("_")
    }

    /// Registers a counter.
    pub fn register_counter(
        &mut self,
        name: impl Into<String>,
        help: impl Into<String>,
    ) -> &Counter {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.counters
            .entry(full_name.clone())
            .or_insert_with(|| Counter::new(full_name, help.into()))
    }

    /// Registers a counter with labels.
    pub fn register_counter_with_labels(
        &mut self,
        name: impl Into<String>,
        help: impl Into<String>,
        labels: Vec<String>,
    ) -> &mut Counter {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.counters
            .entry(full_name.clone())
            .or_insert_with(|| Counter::with_labels(full_name, help.into(), labels))
    }

    /// Gets a counter by name.
    pub fn counter(&self, name: &str) -> Option<&Counter> {
        let full_name = self.full_name(name);
        self.counters.get(&full_name)
    }

    /// Gets a mutable counter by name.
    pub fn counter_mut(&mut self, name: &str) -> Option<&mut Counter> {
        let full_name = self.full_name(name);
        self.counters.get_mut(&full_name)
    }

    /// Registers a gauge.
    pub fn register_gauge(&mut self, name: impl Into<String>, help: impl Into<String>) -> &Gauge {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.gauges
            .entry(full_name.clone())
            .or_insert_with(|| Gauge::new(full_name, help.into()))
    }

    /// Registers a gauge with labels.
    pub fn register_gauge_with_labels(
        &mut self,
        name: impl Into<String>,
        help: impl Into<String>,
        labels: Vec<String>,
    ) -> &mut Gauge {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.gauges
            .entry(full_name.clone())
            .or_insert_with(|| Gauge::with_labels(full_name, help.into(), labels))
    }

    /// Gets a gauge by name.
    pub fn gauge(&self, name: &str) -> Option<&Gauge> {
        let full_name = self.full_name(name);
        self.gauges.get(&full_name)
    }

    /// Gets a mutable gauge by name.
    pub fn gauge_mut(&mut self, name: &str) -> Option<&mut Gauge> {
        let full_name = self.full_name(name);
        self.gauges.get_mut(&full_name)
    }

    /// Registers a histogram.
    pub fn register_histogram(
        &mut self,
        name: impl Into<String>,
        help: impl Into<String>,
    ) -> &Histogram {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.histograms
            .entry(full_name.clone())
            .or_insert_with(|| Histogram::new(full_name, help.into()))
    }

    /// Registers a histogram with custom buckets.
    pub fn register_histogram_with_buckets(
        &mut self,
        name: impl Into<String>,
        help: impl Into<String>,
        buckets: Vec<f64>,
    ) -> &Histogram {
        let name = name.into();
        let full_name = self.full_name(&name);
        self.histograms
            .entry(full_name.clone())
            .or_insert_with(|| Histogram::with_buckets(full_name, help.into(), buckets))
    }

    /// Gets a histogram by name.
    pub fn histogram(&self, name: &str) -> Option<&Histogram> {
        let full_name = self.full_name(name);
        self.histograms.get(&full_name)
    }

    /// Returns the total number of registered metrics.
    pub fn metric_count(&self) -> usize {
        self.counters.len() + self.gauges.len() + self.histograms.len()
    }

    /// Lists all registered metrics.
    pub fn list_metrics(&self) -> Vec<MetricInfo> {
        let mut metrics = Vec::new();

        for counter in self.counters.values() {
            metrics.push(MetricInfo {
                name: counter.name().to_string(),
                metric_type: MetricType::Counter,
                help: counter.help().to_string(),
                label_names: counter.label_names().to_vec(),
            });
        }

        for gauge in self.gauges.values() {
            metrics.push(MetricInfo {
                name: gauge.name().to_string(),
                metric_type: MetricType::Gauge,
                help: gauge.help().to_string(),
                label_names: gauge.label_names().to_vec(),
            });
        }

        for histogram in self.histograms.values() {
            metrics.push(MetricInfo {
                name: histogram.name().to_string(),
                metric_type: MetricType::Histogram,
                help: histogram.help().to_string(),
                label_names: Vec::new(),
            });
        }

        metrics
    }

    /// Exports all metrics in Prometheus format.
    pub fn export(&self) -> String {
        let mut output = String::new();

        for counter in self.counters.values() {
            output.push_str(&counter.export());
            output.push('\n');
        }

        for gauge in self.gauges.values() {
            output.push_str(&gauge.export());
            output.push('\n');
        }

        for histogram in self.histograms.values() {
            output.push_str(&histogram.export());
            output.push('\n');
        }

        output
    }

    /// Unregisters a counter.
    pub fn unregister_counter(&mut self, name: &str) -> Option<Counter> {
        let full_name = self.full_name(name);
        self.counters.remove(&full_name)
    }

    /// Unregisters a gauge.
    pub fn unregister_gauge(&mut self, name: &str) -> Option<Gauge> {
        let full_name = self.full_name(name);
        self.gauges.remove(&full_name)
    }

    /// Unregisters a histogram.
    pub fn unregister_histogram(&mut self, name: &str) -> Option<Histogram> {
        let full_name = self.full_name(name);
        self.histograms.remove(&full_name)
    }
}

/// Standard SBC metrics.
pub struct SbcMetrics;

impl SbcMetrics {
    /// Creates a registry with standard SBC metrics.
    pub fn standard() -> MetricRegistry {
        let mut registry = MetricRegistry::with_namespace("sbc");

        // Call metrics
        registry.register_counter("calls_total", "Total number of calls");
        registry.register_counter("calls_failed_total", "Total number of failed calls");
        registry.register_gauge("calls_active", "Number of active calls");

        // SIP metrics
        registry.register_counter("sip_requests_total", "Total SIP requests");
        registry.register_counter("sip_responses_total", "Total SIP responses");

        // Media metrics
        registry.register_gauge("rtp_streams_active", "Number of active RTP streams");

        // Performance metrics
        registry.register_histogram(
            "call_setup_duration_seconds",
            "Call setup duration in seconds",
        );
        registry.register_histogram("sip_request_duration_seconds", "SIP request processing time");

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = MetricRegistry::new();
        assert_eq!(registry.metric_count(), 0);
    }

    #[test]
    fn test_registry_with_namespace() {
        let mut registry = MetricRegistry::with_namespace("myapp");
        registry.register_counter("requests", "Total requests");

        assert!(registry.counter("requests").is_some());
        let counter = registry.counter("requests").unwrap();
        assert_eq!(counter.name(), "myapp_requests");
    }

    #[test]
    fn test_registry_with_subsystem() {
        let mut registry = MetricRegistry::with_namespace("myapp").with_subsystem("http");
        registry.register_counter("requests", "Total requests");

        let counter = registry.counter("requests").unwrap();
        assert_eq!(counter.name(), "myapp_http_requests");
    }

    #[test]
    fn test_register_counter() {
        let mut registry = MetricRegistry::new();
        registry.register_counter("test_counter", "A test counter");

        assert_eq!(registry.metric_count(), 1);
        assert!(registry.counter("test_counter").is_some());
    }

    #[test]
    fn test_register_gauge() {
        let mut registry = MetricRegistry::new();
        registry.register_gauge("test_gauge", "A test gauge");

        assert!(registry.gauge("test_gauge").is_some());
    }

    #[test]
    fn test_register_histogram() {
        let mut registry = MetricRegistry::new();
        registry.register_histogram("test_histogram", "A test histogram");

        assert!(registry.histogram("test_histogram").is_some());
    }

    #[test]
    fn test_counter_operations() {
        let mut registry = MetricRegistry::new();
        let counter = registry.register_counter("requests_total", "Total requests");

        counter.inc();
        counter.inc_by(5);

        assert_eq!(registry.counter("requests_total").unwrap().get(), 6);
    }

    #[test]
    fn test_gauge_operations() {
        let mut registry = MetricRegistry::new();
        let gauge = registry.register_gauge("temperature", "Current temperature");

        gauge.set(25);

        assert_eq!(registry.gauge("temperature").unwrap().get(), 25);
    }

    #[test]
    fn test_histogram_operations() {
        let mut registry = MetricRegistry::new();
        let histogram = registry.register_histogram("latency", "Request latency");

        histogram.observe(100.0);
        histogram.observe(200.0);

        assert_eq!(registry.histogram("latency").unwrap().count(), 2);
    }

    #[test]
    fn test_list_metrics() {
        let mut registry = MetricRegistry::new();
        registry.register_counter("counter1", "Counter 1");
        registry.register_gauge("gauge1", "Gauge 1");
        registry.register_histogram("histogram1", "Histogram 1");

        let metrics = registry.list_metrics();
        assert_eq!(metrics.len(), 3);
    }

    #[test]
    fn test_export() {
        let mut registry = MetricRegistry::new();
        let counter = registry.register_counter("requests_total", "Total requests");
        counter.inc_by(100);

        let gauge = registry.register_gauge("connections", "Active connections");
        gauge.set(50);

        let output = registry.export();
        assert!(output.contains("requests_total 100"));
        assert!(output.contains("connections 50"));
    }

    #[test]
    fn test_unregister() {
        let mut registry = MetricRegistry::new();
        registry.register_counter("test_counter", "Test");

        assert!(registry.counter("test_counter").is_some());

        let removed = registry.unregister_counter("test_counter");
        assert!(removed.is_some());
        assert!(registry.counter("test_counter").is_none());
    }

    #[test]
    fn test_metric_type() {
        assert_eq!(MetricType::Counter.as_str(), "counter");
        assert_eq!(MetricType::Gauge.as_str(), "gauge");
        assert_eq!(MetricType::Histogram.as_str(), "histogram");
    }

    #[test]
    fn test_sbc_metrics() {
        let registry = SbcMetrics::standard();
        assert!(registry.counter("calls_total").is_some());
        assert!(registry.gauge("calls_active").is_some());
        assert!(registry.histogram("call_setup_duration_seconds").is_some());
    }
}
