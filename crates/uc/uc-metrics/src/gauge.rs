//! Gauge metric type.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::labels::{self, MAX_LABEL_SERIES};

/// A gauge that can go up and down.
#[derive(Debug)]
pub struct Gauge {
    /// Metric name.
    name: String,
    /// Metric help text.
    help: String,
    /// Label names.
    label_names: Vec<String>,
    /// Values by label combination.
    values: HashMap<Vec<String>, AtomicI64>,
    /// Default value (no labels).
    default_value: AtomicI64,
    /// Maximum distinct labelled series (SC-5).
    max_series: usize,
    /// Updates redirected to the overflow series.
    overflowed: AtomicU64,
}

impl Gauge {
    /// Creates a new gauge.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            label_names: Vec::new(),
            values: HashMap::new(),
            default_value: AtomicI64::new(0),
            max_series: MAX_LABEL_SERIES,
            overflowed: AtomicU64::new(0),
        }
    }

    /// Creates a gauge with labels.
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
            default_value: AtomicI64::new(0),
            max_series: MAX_LABEL_SERIES,
            overflowed: AtomicU64::new(0),
        }
    }

    /// Creates a gauge with labels and an explicit series cap.
    ///
    /// Once `max_series` distinct label tuples exist, further new tuples
    /// update a single series whose labels are all `"__overflow__"`.
    pub fn with_labels_capped(
        name: impl Into<String>,
        help: impl Into<String>,
        label_names: Vec<String>,
        max_series: usize,
    ) -> Self {
        let mut m = Self::with_labels(name, help, label_names);
        m.max_series = max_series;
        m
    }

    /// Returns how many labelled updates were redirected to the overflow
    /// series (cap reached or label arity mismatch).
    pub fn overflowed(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// Resolves the bounded series for `labels`, creating it if needed.
    fn series(&mut self, labels: &[&str]) -> &AtomicI64 {
        let (key, overflow) = labels::series_key(
            &self.values,
            self.label_names.len(),
            self.max_series,
            labels,
        );
        if overflow {
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
        self.values.entry(key).or_insert_with(|| AtomicI64::new(0))
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

    /// Sets the gauge to the given value.
    pub fn set(&self, value: i64) {
        self.default_value.store(value, Ordering::Relaxed);
    }

    /// Sets the gauge with labels.
    pub fn set_with_labels(&mut self, labels: &[&str], value: i64) {
        self.series(labels).store(value, Ordering::Relaxed);
    }

    /// Increments the gauge by 1.
    pub fn inc(&self) {
        self.default_value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the gauge by 1.
    pub fn dec(&self) {
        self.default_value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increments the gauge by the given amount.
    pub fn add(&self, n: i64) {
        self.default_value.fetch_add(n, Ordering::Relaxed);
    }

    /// Decrements the gauge by the given amount.
    pub fn sub(&self, n: i64) {
        self.default_value.fetch_sub(n, Ordering::Relaxed);
    }

    /// Increments the gauge with labels.
    pub fn inc_with_labels(&mut self, labels: &[&str]) {
        self.add_with_labels(labels, 1);
    }

    /// Decrements the gauge with labels.
    pub fn dec_with_labels(&mut self, labels: &[&str]) {
        self.add_with_labels(labels, -1);
    }

    /// Adds to the gauge with labels.
    pub fn add_with_labels(&mut self, labels: &[&str], n: i64) {
        self.series(labels).fetch_add(n, Ordering::Relaxed);
    }

    /// Gets the current value.
    pub fn get(&self) -> i64 {
        self.default_value.load(Ordering::Relaxed)
    }

    /// Gets the value for specific labels.
    pub fn get_with_labels(&self, labels: &[&str]) -> i64 {
        let key = if labels.len() == self.label_names.len() {
            labels::lookup_key(labels)
        } else {
            labels::overflow_key(self.label_names.len())
        };
        self.values
            .get(&key)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Exports in Prometheus format.
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Help line
        let _ = writeln!(output, "# HELP {} {}", self.name, self.help);
        // Type line
        let _ = writeln!(output, "# TYPE {} gauge", self.name);

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
    fn test_gauge_creation() {
        let gauge = Gauge::new("test_gauge", "A test gauge");
        assert_eq!(gauge.name(), "test_gauge");
        assert_eq!(gauge.get(), 0);
    }

    #[test]
    fn test_gauge_set() {
        let gauge = Gauge::new("test_gauge", "Test");
        gauge.set(100);
        assert_eq!(gauge.get(), 100);
        gauge.set(50);
        assert_eq!(gauge.get(), 50);
    }

    #[test]
    fn test_gauge_inc_dec() {
        let gauge = Gauge::new("test_gauge", "Test");
        gauge.inc();
        assert_eq!(gauge.get(), 1);
        gauge.inc();
        assert_eq!(gauge.get(), 2);
        gauge.dec();
        assert_eq!(gauge.get(), 1);
    }

    #[test]
    fn test_gauge_add_sub() {
        let gauge = Gauge::new("test_gauge", "Test");
        gauge.add(10);
        assert_eq!(gauge.get(), 10);
        gauge.sub(3);
        assert_eq!(gauge.get(), 7);
    }

    #[test]
    fn test_gauge_negative() {
        let gauge = Gauge::new("test_gauge", "Test");
        gauge.sub(5);
        assert_eq!(gauge.get(), -5);
    }

    #[test]
    fn test_gauge_with_labels() {
        let mut gauge = Gauge::with_labels(
            "active_connections",
            "Active connections",
            vec!["protocol".to_string()],
        );

        gauge.set_with_labels(&["tcp"], 100);
        gauge.set_with_labels(&["udp"], 50);

        assert_eq!(gauge.get_with_labels(&["tcp"]), 100);
        assert_eq!(gauge.get_with_labels(&["udp"]), 50);
    }

    #[test]
    fn test_gauge_inc_dec_with_labels() {
        let mut gauge = Gauge::with_labels(
            "active_calls",
            "Active calls",
            vec!["direction".to_string()],
        );

        gauge.inc_with_labels(&["inbound"]);
        gauge.inc_with_labels(&["inbound"]);
        gauge.inc_with_labels(&["outbound"]);
        gauge.dec_with_labels(&["inbound"]);

        assert_eq!(gauge.get_with_labels(&["inbound"]), 1);
        assert_eq!(gauge.get_with_labels(&["outbound"]), 1);
    }

    #[test]
    fn test_gauge_export() {
        let gauge = Gauge::new("cpu_usage", "Current CPU usage");
        gauge.set(75);

        let output = gauge.export();
        assert!(output.contains("# HELP cpu_usage Current CPU usage"));
        assert!(output.contains("# TYPE cpu_usage gauge"));
        assert!(output.contains("cpu_usage 75"));
    }

    #[test]
    fn test_gauge_export_with_labels() {
        let mut gauge = Gauge::with_labels(
            "temperature",
            "Temperature in Celsius",
            vec!["location".to_string()],
        );

        gauge.set_with_labels(&["server_room"], 22);
        gauge.set_with_labels(&["office"], 24);

        let output = gauge.export();
        assert!(output.contains("temperature{location=\"server_room\"} 22"));
        assert!(output.contains("temperature{location=\"office\"} 24"));
    }

    #[test]
    fn test_series_cap_overflows() {
        let mut g = Gauge::with_labels_capped("g", "g", vec!["peer".to_string()], 1);
        g.set_with_labels(&["a"], 5);
        g.inc_with_labels(&["b"]);
        g.inc_with_labels(&["c"]);
        g.set_with_labels(&["a"], 7);
        assert_eq!(g.get_with_labels(&["a"]), 7);
        assert_eq!(g.get_with_labels(&["__overflow__"]), 2);
        assert_eq!(g.overflowed(), 2);
        assert!(g.export().contains("g{peer=\"__overflow__\"} 2"));
    }

    #[test]
    fn qa_gauge_cap_boundary_and_arity() {
        let mut g = Gauge::with_labels_capped("g", "g", vec!["p".to_string()], 1);
        g.set_with_labels(&["a"], 7);
        assert_eq!(g.overflowed(), 0);
        g.inc_with_labels(&["b"]);
        g.dec_with_labels(&["c"]);
        g.add_with_labels(&["x", "y"], 3);
        assert_eq!(g.get_with_labels(&["a"]), 7);
        assert_eq!(g.get_with_labels(&["__overflow__"]), 3);
        assert_eq!(g.overflowed(), 3);
    }
}
