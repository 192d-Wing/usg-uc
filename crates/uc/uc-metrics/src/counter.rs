//! Counter metric type.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing counter.
#[derive(Debug)]
pub struct Counter {
    /// Metric name.
    name: String,
    /// Metric help text.
    help: String,
    /// Label names.
    label_names: Vec<String>,
    /// Values by label combination.
    values: HashMap<Vec<String>, AtomicU64>,
    /// Default value (no labels).
    default_value: AtomicU64,
}

impl Counter {
    /// Creates a new counter.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            label_names: Vec::new(),
            values: HashMap::new(),
            default_value: AtomicU64::new(0),
        }
    }

    /// Creates a counter with labels.
    pub fn with_labels(
        name: impl Into<String>,
        help: impl Into<String>,
        label_names: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            label_names,
            values: HashMap::new(),
            default_value: AtomicU64::new(0),
        }
    }

    /// Returns the metric name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the help text.
    pub fn help(&self) -> &str {
        &self.help
    }

    /// Returns the label names.
    pub fn label_names(&self) -> &[String] {
        &self.label_names
    }

    /// Increments the counter by 1.
    pub fn inc(&self) {
        self.default_value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the counter by the given amount.
    pub fn inc_by(&self, n: u64) {
        self.default_value.fetch_add(n, Ordering::Relaxed);
    }

    /// Increments the counter with labels.
    pub fn inc_with_labels(&mut self, labels: &[&str]) {
        self.inc_by_with_labels(labels, 1);
    }

    /// Increments the counter by the given amount with labels.
    pub fn inc_by_with_labels(&mut self, labels: &[&str], n: u64) {
        let key: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
        self.values
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Gets the current value.
    pub fn get(&self) -> u64 {
        self.default_value.load(Ordering::Relaxed)
    }

    /// Gets the value for specific labels.
    pub fn get_with_labels(&self, labels: &[&str]) -> u64 {
        let key: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
        self.values
            .get(&key)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Resets the counter.
    pub fn reset(&self) {
        self.default_value.store(0, Ordering::Relaxed);
    }

    /// Exports in Prometheus format.
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Help line
        let _ = writeln!(output, "# HELP {} {}", self.name, self.help);
        // Type line
        let _ = writeln!(output, "# TYPE {} counter", self.name);

        // Default value
        if self.label_names.is_empty() {
            let _ = writeln!(output, "{} {}", self.name, self.get());
        }

        // Labeled values
        for (labels, value) in &self.values {
            let label_str = self.format_labels(labels);
            let _ = writeln!(
                output,
                "{}{} {}",
                self.name,
                label_str,
                value.load(Ordering::Relaxed)
            );
        }

        output
    }

    /// Formats labels for Prometheus export.
    fn format_labels(&self, labels: &[String]) -> String {
        if labels.is_empty() || self.label_names.is_empty() {
            return String::new();
        }

        let pairs: Vec<String> = self
            .label_names
            .iter()
            .zip(labels.iter())
            .map(|(name, value)| format!("{}=\"{}\"", name, Self::escape_label_value(value)))
            .collect();

        format!("{{{}}}", pairs.join(","))
    }

    /// Escapes a label value for Prometheus format.
    fn escape_label_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_creation() {
        let counter = Counter::new("test_counter", "A test counter");
        assert_eq!(counter.name(), "test_counter");
        assert_eq!(counter.help(), "A test counter");
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_counter_inc() {
        let counter = Counter::new("test_counter", "Test");
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc();
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_counter_inc_by() {
        let counter = Counter::new("test_counter", "Test");
        counter.inc_by(5);
        assert_eq!(counter.get(), 5);
        counter.inc_by(10);
        assert_eq!(counter.get(), 15);
    }

    #[test]
    fn test_counter_reset() {
        let counter = Counter::new("test_counter", "Test");
        counter.inc_by(100);
        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_counter_with_labels() {
        let mut counter = Counter::with_labels(
            "http_requests_total",
            "Total HTTP requests",
            vec!["method".to_string(), "status".to_string()],
        );

        counter.inc_with_labels(&["GET", "200"]);
        counter.inc_with_labels(&["GET", "200"]);
        counter.inc_with_labels(&["POST", "201"]);

        assert_eq!(counter.get_with_labels(&["GET", "200"]), 2);
        assert_eq!(counter.get_with_labels(&["POST", "201"]), 1);
        assert_eq!(counter.get_with_labels(&["PUT", "200"]), 0);
    }

    #[test]
    fn test_counter_export() {
        let counter = Counter::new("test_counter_total", "A test counter");
        counter.inc_by(42);

        let output = counter.export();
        assert!(output.contains("# HELP test_counter_total A test counter"));
        assert!(output.contains("# TYPE test_counter_total counter"));
        assert!(output.contains("test_counter_total 42"));
    }

    #[test]
    fn test_counter_export_with_labels() {
        let mut counter = Counter::with_labels(
            "http_requests_total",
            "Total HTTP requests",
            vec!["method".to_string()],
        );

        counter.inc_by_with_labels(&["GET"], 10);
        counter.inc_by_with_labels(&["POST"], 5);

        let output = counter.export();
        assert!(output.contains("http_requests_total{method=\"GET\"} 10"));
        assert!(output.contains("http_requests_total{method=\"POST\"} 5"));
    }

    #[test]
    fn test_label_escaping() {
        let escaped = Counter::escape_label_value("test\"value\\with\nnewline");
        assert_eq!(escaped, "test\\\"value\\\\with\\nnewline");
    }
}
