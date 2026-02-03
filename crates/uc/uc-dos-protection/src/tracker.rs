//! Request tracker for monitoring traffic patterns.

use crate::DEFAULT_WINDOW_SECS;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Source statistics.
#[derive(Debug, Clone)]
pub struct SourceStats {
    /// Total requests in window.
    pub total_requests: u64,
    /// Requests per second (average).
    pub requests_per_second: f64,
    /// First request time in window.
    pub first_seen: Instant,
    /// Last request time.
    pub last_seen: Instant,
    /// Peak requests per second observed.
    pub peak_rps: f64,
    /// Number of rejected requests.
    pub rejected_count: u64,
}

impl SourceStats {
    /// Returns the duration since first seen.
    pub fn age(&self) -> Duration {
        self.first_seen.elapsed()
    }

    /// Returns the duration since last seen.
    pub fn idle_time(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

/// Tracking entry for a source.
#[derive(Debug)]
struct TrackingEntry {
    /// Request timestamps in current window.
    timestamps: Vec<Instant>,
    /// First seen time.
    first_seen: Instant,
    /// Peak RPS observed.
    peak_rps: f64,
    /// Rejected count.
    rejected_count: u64,
}

impl TrackingEntry {
    /// Creates a new tracking entry.
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            first_seen: Instant::now(),
            peak_rps: 0.0,
            rejected_count: 0,
        }
    }

    /// Records a request.
    fn record(&mut self, window: Duration) {
        let now = Instant::now();
        self.timestamps.push(now);

        // Clean up old timestamps
        let cutoff = now.checked_sub(window).unwrap_or(now);
        self.timestamps.retain(|&t| t > cutoff);

        // Update peak RPS
        let rps = self.calculate_rps(window);
        if rps > self.peak_rps {
            self.peak_rps = rps;
        }
    }

    /// Records a rejected request.
    fn record_rejection(&mut self) {
        self.rejected_count += 1;
    }

    /// Calculates current RPS.
    fn calculate_rps(&self, window: Duration) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }

        let window_secs = window.as_secs_f64();
        if window_secs > 0.0 {
            // Allow precision loss for rate calculation
            #[allow(clippy::cast_precision_loss)]
            let rate = self.timestamps.len() as f64 / window_secs;
            rate
        } else {
            0.0
        }
    }

    /// Returns statistics.
    fn stats(&self, window: Duration) -> SourceStats {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        // Count requests in window
        let requests_in_window: Vec<_> = self
            .timestamps
            .iter()
            .filter(|&&t| t > cutoff)
            .copied()
            .collect();

        let total_requests = requests_in_window.len() as u64;
        let requests_per_second = self.calculate_rps(window);
        let last_seen = requests_in_window
            .last()
            .copied()
            .unwrap_or(self.first_seen);

        SourceStats {
            total_requests,
            requests_per_second,
            first_seen: self.first_seen,
            last_seen,
            peak_rps: self.peak_rps,
            rejected_count: self.rejected_count,
        }
    }
}

/// Request tracker for monitoring traffic.
#[derive(Debug)]
pub struct RequestTracker {
    /// Tracking window duration.
    window: Duration,
    /// Per-source entries.
    entries: HashMap<IpAddr, TrackingEntry>,
    /// Global stats.
    global: TrackingEntry,
}

impl RequestTracker {
    /// Creates a new tracker.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            entries: HashMap::new(),
            global: TrackingEntry::new(),
        }
    }

    /// Creates a tracker with default window.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_WINDOW_SECS)
    }

    /// Returns the tracking window duration.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Records a request.
    pub fn record(&mut self, source: IpAddr) {
        // Update per-source entry
        let entry = self
            .entries
            .entry(source)
            .or_insert_with(TrackingEntry::new);
        entry.record(self.window);

        // Update global stats
        self.global.record(self.window);
    }

    /// Records a rejected request.
    pub fn record_rejection(&mut self, source: IpAddr) {
        if let Some(entry) = self.entries.get_mut(&source) {
            entry.record_rejection();
        }
    }

    /// Returns stats for a source.
    pub fn stats(&self, source: IpAddr) -> Option<SourceStats> {
        self.entries.get(&source).map(|e| e.stats(self.window))
    }

    /// Returns global stats.
    pub fn global_stats(&self) -> SourceStats {
        self.global.stats(self.window)
    }

    /// Returns the number of tracked sources.
    pub fn tracked_sources(&self) -> usize {
        self.entries.len()
    }

    /// Returns all tracked source IPs.
    pub fn sources(&self) -> impl Iterator<Item = &IpAddr> {
        self.entries.keys()
    }

    /// Returns top sources by RPS.
    pub fn top_sources(&self, limit: usize) -> Vec<(IpAddr, SourceStats)> {
        let mut sources: Vec<_> = self
            .entries
            .iter()
            .map(|(&ip, entry)| (ip, entry.stats(self.window)))
            .collect();

        sources.sort_by(|a, b| {
            b.1.requests_per_second
                .partial_cmp(&a.1.requests_per_second)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sources.truncate(limit);
        sources
    }

    /// Cleans up stale entries.
    ///
    /// Removes entries with no requests in the window.
    pub fn cleanup(&mut self) {
        let window = self.window;
        self.entries.retain(|_, entry| {
            let stats = entry.stats(window);
            stats.total_requests > 0
        });
    }

    /// Removes all tracking data for a source.
    pub fn remove(&mut self, source: IpAddr) {
        self.entries.remove(&source);
    }

    /// Clears all tracking data.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.global = TrackingEntry::new();
    }
}

impl Default for RequestTracker {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    fn test_ip2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn test_tracker_creation() {
        let tracker = RequestTracker::with_defaults();
        assert_eq!(tracker.window(), Duration::from_secs(DEFAULT_WINDOW_SECS));
        assert_eq!(tracker.tracked_sources(), 0);
    }

    #[test]
    fn test_tracker_record() {
        let mut tracker = RequestTracker::new(60);
        let ip = test_ip();

        tracker.record(ip);
        tracker.record(ip);
        tracker.record(ip);

        let stats = tracker.stats(ip).unwrap();
        assert_eq!(stats.total_requests, 3);
        assert!(stats.requests_per_second > 0.0);
    }

    #[test]
    fn test_tracker_global_stats() {
        let mut tracker = RequestTracker::new(60);

        tracker.record(test_ip());
        tracker.record(test_ip2());
        tracker.record(test_ip());

        let stats = tracker.global_stats();
        assert_eq!(stats.total_requests, 3);
    }

    #[test]
    fn test_tracker_multiple_sources() {
        let mut tracker = RequestTracker::new(60);

        tracker.record(test_ip());
        tracker.record(test_ip2());

        assert_eq!(tracker.tracked_sources(), 2);
    }

    #[test]
    fn test_tracker_rejection() {
        let mut tracker = RequestTracker::new(60);
        let ip = test_ip();

        tracker.record(ip);
        tracker.record_rejection(ip);
        tracker.record_rejection(ip);

        let stats = tracker.stats(ip).unwrap();
        assert_eq!(stats.rejected_count, 2);
    }

    #[test]
    fn test_tracker_top_sources() {
        let mut tracker = RequestTracker::new(60);

        // Make ip1 have more requests
        for _ in 0..10 {
            tracker.record(test_ip());
        }
        for _ in 0..5 {
            tracker.record(test_ip2());
        }

        let top = tracker.top_sources(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, test_ip()); // ip1 should be first
    }

    #[test]
    fn test_tracker_remove() {
        let mut tracker = RequestTracker::new(60);
        let ip = test_ip();

        tracker.record(ip);
        assert!(tracker.stats(ip).is_some());

        tracker.remove(ip);
        assert!(tracker.stats(ip).is_none());
    }

    #[test]
    fn test_tracker_clear() {
        let mut tracker = RequestTracker::new(60);

        tracker.record(test_ip());
        tracker.record(test_ip2());

        tracker.clear();
        assert_eq!(tracker.tracked_sources(), 0);
    }

    #[test]
    fn test_source_stats_age() {
        let mut tracker = RequestTracker::new(60);
        let ip = test_ip();

        tracker.record(ip);

        let stats = tracker.stats(ip).unwrap();
        assert!(stats.age() < Duration::from_secs(1));
        assert!(stats.idle_time() < Duration::from_secs(1));
    }

    #[test]
    fn test_tracker_peak_rps() {
        let mut tracker = RequestTracker::new(60);
        let ip = test_ip();

        // Record many requests quickly
        for _ in 0..100 {
            tracker.record(ip);
        }

        let stats = tracker.stats(ip).unwrap();
        assert!(stats.peak_rps > 0.0);
    }

    #[test]
    fn test_tracker_sources_iterator() {
        let mut tracker = RequestTracker::new(60);

        tracker.record(test_ip());
        tracker.record(test_ip2());

        assert_eq!(tracker.sources().count(), 2);
    }
}
