//! Counter metric type.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::labels::{self, MAX_LABEL_SERIES};

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
    /// Maximum distinct labelled series (SC-5).
    max_series: usize,
    /// Updates redirected to the overflow series.
    overflowed: AtomicU64,
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
            max_series: MAX_LABEL_SERIES,
            overflowed: AtomicU64::new(0),
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
            max_series: MAX_LABEL_SERIES,
            overflowed: AtomicU64::new(0),
        }
    }

    /// Creates a counter with labels and an explicit series cap.
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
    fn series(&mut self, labels: &[&str]) -> &AtomicU64 {
        let (key, overflow) = labels::series_key(
            &self.values,
            self.label_names.len(),
            self.max_series,
            labels,
        );
        if overflow {
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
        self.values.entry(key).or_insert_with(|| AtomicU64::new(0))
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
        self.series(labels).fetch_add(n, Ordering::Relaxed);
    }

    /// Gets the current value.
    pub fn get(&self) -> u64 {
        self.default_value.load(Ordering::Relaxed)
    }

    /// Gets the value for specific labels.
    pub fn get_with_labels(&self, labels: &[&str]) -> u64 {
        let key = if labels.len() == self.label_names.len() {
            labels::lookup_key(labels)
        } else {
            labels::overflow_key(self.label_names.len())
        };
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

    #[test]
    fn test_series_cap_overflows() {
        let mut c = Counter::with_labels_capped("c_total", "c", vec!["peer".to_string()], 2);
        c.inc_with_labels(&["a"]);
        c.inc_with_labels(&["b"]);
        c.inc_with_labels(&["c"]);
        c.inc_with_labels(&["d"]);
        c.inc_with_labels(&["a"]);
        assert_eq!(c.get_with_labels(&["a"]), 2);
        assert_eq!(c.get_with_labels(&["b"]), 1);
        assert_eq!(c.get_with_labels(&["c"]), 0);
        assert_eq!(c.get_with_labels(&["__overflow__"]), 2);
        assert_eq!(c.overflowed(), 2);
        assert_eq!(c.values.len(), 3);
        let out = c.export();
        assert!(out.contains("c_total{peer=\"__overflow__\"} 2"));
    }

    #[test]
    fn test_arity_mismatch_overflows() {
        let mut c = Counter::with_labels("c_total", "c", vec!["a".to_string(), "b".to_string()]);
        c.inc_with_labels(&["only-one"]);
        assert_eq!(c.overflowed(), 1);
        assert_eq!(c.get_with_labels(&["__overflow__", "__overflow__"]), 1);
        assert!(
            c.export()
                .contains("c_total{a=\"__overflow__\",b=\"__overflow__\"} 1")
        );
    }

    #[test]
    fn test_long_label_value_truncated() {
        let mut c = Counter::with_labels("c_total", "c", vec!["peer".to_string()]);
        let long = "x".repeat(1000);
        c.inc_with_labels(&[&long]);
        assert_eq!(c.get_with_labels(&[&long]), 1);
        let key = c.values.keys().next().unwrap();
        assert_eq!(key[0].len(), crate::labels::MAX_LABEL_VALUE_LEN);
    }

    #[test]
    fn test_default_cap() {
        let mut c = Counter::with_labels("c_total", "c", vec!["n".to_string()]);
        for i in 0..(MAX_LABEL_SERIES + 10) {
            c.inc_with_labels(&[&i.to_string()]);
        }
        assert_eq!(c.values.len(), MAX_LABEL_SERIES + 1);
        assert_eq!(c.overflowed(), 10);
    }

    // QA: exact cap boundary -- the Nth distinct series is admitted, N+1 folds.
    #[test]
    fn qa_cap_boundary_exact() {
        let mut c = Counter::with_labels_capped("c_total", "c", vec!["p".to_string()], 3);
        for v in ["a", "b", "c"] {
            c.inc_with_labels(&[v]);
        }
        assert_eq!(c.overflowed(), 0);
        assert_eq!(c.values.len(), 3);
        c.inc_with_labels(&["d"]);
        assert_eq!(c.overflowed(), 1);
        assert_eq!(c.values.len(), 4);
        // overflow series does not consume a real slot; more new keys keep folding
        c.inc_with_labels(&["e"]);
        assert_eq!(c.values.len(), 4);
        assert_eq!(c.get_with_labels(&["__overflow__"]), 2);
    }

    #[test]
    fn qa_cap_zero_all_overflow() {
        let mut c = Counter::with_labels_capped("c_total", "c", vec!["p".to_string()], 0);
        c.inc_by_with_labels(&["a"], 5);
        assert_eq!(c.get_with_labels(&["a"]), 0);
        assert_eq!(c.get_with_labels(&["__overflow__"]), 5);
        assert_eq!(c.overflowed(), 1);
    }

    #[test]
    fn qa_truncated_values_share_series_and_bound_export() {
        let mut c = Counter::with_labels_capped("c_total", "c", vec!["p".to_string()], 4);
        let a = format!("{}A", "x".repeat(200));
        let b = format!("{}B", "x".repeat(200));
        c.inc_with_labels(&[&a]);
        c.inc_with_labels(&[&b]);
        assert_eq!(c.values.len(), 1);
        assert_eq!(c.overflowed(), 0);
        let out = c.export();
        assert!(out.lines().all(|l| l.len() < 128 + 64));
    }

    #[test]
    fn qa_totals_preserved_across_overflow() {
        let mut c = Counter::with_labels_capped("c_total", "c", vec!["p".to_string()], 2);
        for i in 0..50u64 {
            c.inc_by_with_labels(&[&format!("peer{i}")], i);
        }
        let total: u64 = c.values.values().map(|v| v.load(Ordering::Relaxed)).sum();
        assert_eq!(total, (0..50u64).sum::<u64>());
        assert_eq!(c.overflowed(), 48);
    }

    #[test]
    fn qa_too_many_labels_overflow() {
        let mut c = Counter::with_labels("c_total", "c", vec!["a".to_string()]);
        c.inc_with_labels(&["x", "y"]);
        c.inc_with_labels(&[]);
        assert_eq!(c.overflowed(), 2);
        assert_eq!(c.get_with_labels(&["__overflow__"]), 2);
    }
}
