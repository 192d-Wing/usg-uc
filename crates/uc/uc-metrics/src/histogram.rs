//! Histogram metric type.

use crate::DEFAULT_LATENCY_BUCKETS;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// A histogram for tracking value distributions.
#[derive(Debug)]
pub struct Histogram {
    /// Metric name.
    name: String,
    /// Metric help text.
    help: String,
    /// Bucket boundaries.
    buckets: Vec<f64>,
    /// Bucket counts.
    bucket_counts: Vec<AtomicU64>,
    /// Sum of all observations.
    sum: AtomicU64,
    /// Total count of observations.
    count: AtomicU64,
}

impl Histogram {
    /// Creates a new histogram with default buckets.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self::with_buckets(name, help, DEFAULT_LATENCY_BUCKETS.to_vec())
    }

    /// Creates a histogram with custom buckets.
    pub fn with_buckets(
        name: impl Into<String>,
        help: impl Into<String>,
        buckets: Vec<f64>,
    ) -> Self {
        let bucket_counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();

        Self {
            name: name.into(),
            help: help.into(),
            buckets,
            bucket_counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
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

    /// Returns the bucket boundaries.
    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    /// Observes a value.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn observe(&self, value: f64) {
        // Increment appropriate bucket(s)
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }

        // Update sum and count
        // Note: This is a simplified implementation using u64 for sum
        // In production, you'd want proper f64 atomic handling
        let sum_bits = (value * 1000.0) as u64; // Store as millis for precision
        self.sum.fetch_add(sum_bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Gets the sum of all observations.
    #[allow(clippy::cast_precision_loss)]
    pub fn sum(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Gets the count of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Gets the bucket counts.
    pub fn bucket_counts(&self) -> Vec<u64> {
        self.bucket_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }

    /// Calculates the mean.
    #[allow(clippy::cast_precision_loss)]
    pub fn mean(&self) -> f64 {
        let count = self.count();
        if count == 0 {
            0.0
        } else {
            self.sum() / count as f64
        }
    }

    /// Exports in Prometheus format.
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Help line
        let _ = writeln!(output, "# HELP {} {}", self.name, self.help);
        // Type line
        let _ = writeln!(output, "# TYPE {} histogram", self.name);

        // Bucket values (already cumulative from observe())
        for (i, bucket) in self.buckets.iter().enumerate() {
            let count = self.bucket_counts[i].load(Ordering::Relaxed);
            let _ = writeln!(
                output,
                "{}_bucket{{le=\"{}\"}} {count}",
                self.name,
                Self::format_bucket_le(*bucket),
            );
        }

        // +Inf bucket
        let _ = writeln!(
            output,
            "{}_bucket{{le=\"+Inf\"}} {}",
            self.name,
            self.count()
        );

        // Sum and count
        let _ = writeln!(output, "{}_sum {}", self.name, self.sum());
        let _ = write!(output, "{}_count {}", self.name, self.count());

        output
    }

    /// Formats a bucket le value.
    #[allow(clippy::cast_possible_truncation)]
    fn format_bucket_le(value: f64) -> String {
        if value == f64::INFINITY {
            "+Inf".to_string()
        } else if (value - value.floor()).abs() < f64::EPSILON {
            format!("{}", value as i64)
        } else {
            format!("{value}")
        }
    }
}

/// Helper to create linear bucket boundaries.
#[allow(clippy::cast_precision_loss)]
pub fn linear_buckets(start: f64, width: f64, count: usize) -> Vec<f64> {
    (0..count).map(|i| (i as f64).mul_add(width, start)).collect()
}

/// Helper to create exponential bucket boundaries.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
pub fn exponential_buckets(start: f64, factor: f64, count: usize) -> Vec<f64> {
    (0..count).map(|i| start * factor.powi(i as i32)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_creation() {
        let histogram = Histogram::new("request_latency", "Request latency in ms");
        assert_eq!(histogram.name(), "request_latency");
        assert_eq!(histogram.count(), 0);
    }

    #[test]
    fn test_histogram_observe() {
        let histogram =
            Histogram::with_buckets("test_histogram", "Test", vec![10.0, 50.0, 100.0, 500.0]);

        histogram.observe(25.0);
        histogram.observe(75.0);
        histogram.observe(200.0);

        assert_eq!(histogram.count(), 3);
        assert!((histogram.sum() - 300.0).abs() < 0.01);
    }

    #[test]
    fn test_histogram_buckets() {
        let histogram = Histogram::with_buckets("test_histogram", "Test", vec![10.0, 50.0, 100.0]);

        histogram.observe(5.0); // <= 10, <= 50, <= 100
        histogram.observe(25.0); // <= 50, <= 100
        histogram.observe(75.0); // <= 100
        histogram.observe(150.0); // none

        let counts = histogram.bucket_counts();
        assert_eq!(counts[0], 1); // <= 10
        assert_eq!(counts[1], 2); // <= 50
        assert_eq!(counts[2], 3); // <= 100
    }

    #[test]
    fn test_histogram_mean() {
        let histogram =
            Histogram::with_buckets("test_histogram", "Test", vec![100.0, 200.0, 300.0]);

        histogram.observe(100.0);
        histogram.observe(200.0);
        histogram.observe(300.0);

        assert!((histogram.mean() - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_histogram_mean_empty() {
        let histogram = Histogram::new("test_histogram", "Test");
        assert!((histogram.mean() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_export() {
        let histogram = Histogram::with_buckets(
            "request_duration_seconds",
            "Request duration in seconds",
            vec![0.1, 0.5, 1.0],
        );

        histogram.observe(0.05);
        histogram.observe(0.3);
        histogram.observe(0.8);

        let output = histogram.export();
        assert!(output.contains("# TYPE request_duration_seconds histogram"));
        assert!(output.contains("request_duration_seconds_bucket{le=\"0.1\"} 1"));
        assert!(output.contains("request_duration_seconds_bucket{le=\"0.5\"} 2"));
        assert!(output.contains("request_duration_seconds_bucket{le=\"1\"} 3"));
        assert!(output.contains("request_duration_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(output.contains("request_duration_seconds_count 3"));
    }

    #[test]
    fn test_linear_buckets() {
        let buckets = linear_buckets(0.0, 10.0, 5);
        assert_eq!(buckets, vec![0.0, 10.0, 20.0, 30.0, 40.0]);
    }

    #[test]
    fn test_exponential_buckets() {
        let buckets = exponential_buckets(1.0, 2.0, 5);
        assert_eq!(buckets, vec![1.0, 2.0, 4.0, 8.0, 16.0]);
    }
}
