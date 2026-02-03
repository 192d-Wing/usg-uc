//! Health checking and heartbeat protocol.

use crate::config::HeartbeatConfig;
use crate::node::{NodeId, NodeState};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Heartbeat message sent between cluster nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Sending node ID.
    pub node_id: NodeId,
    /// Current node state.
    pub state: NodeState,
    /// Health score (0.0 to 1.0).
    pub health_score: f64,
    /// Number of active calls.
    pub active_calls: u32,
    /// Number of active registrations.
    pub active_registrations: u32,
    /// CPU utilization (0.0 to 1.0).
    pub cpu_percent: f32,
    /// Memory utilization (0.0 to 1.0).
    pub memory_percent: f32,
    /// Heartbeat sequence number.
    pub sequence: u64,
    /// Cluster view version.
    pub view_version: u64,
    /// Node generation (incremented on restart).
    pub generation: u64,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
}

impl Heartbeat {
    /// Creates a new heartbeat message.
    #[must_use]
    pub fn new(node_id: NodeId, state: NodeState, sequence: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            node_id,
            state,
            health_score: 1.0,
            active_calls: 0,
            active_registrations: 0,
            cpu_percent: 0.0,
            memory_percent: 0.0,
            sequence,
            view_version: 0,
            generation: 1,
            timestamp_ms: now,
        }
    }

    /// Sets the health metrics.
    #[must_use]
    pub const fn with_metrics(
        mut self,
        active_calls: u32,
        active_registrations: u32,
        cpu_percent: f32,
        memory_percent: f32,
    ) -> Self {
        self.active_calls = active_calls;
        self.active_registrations = active_registrations;
        self.cpu_percent = cpu_percent;
        self.memory_percent = memory_percent;
        self
    }

    /// Sets the health score.
    #[must_use]
    pub fn with_health_score(mut self, score: f64) -> Self {
        self.health_score = score.clamp(0.0, 1.0);
        self
    }

    /// Sets the view version.
    #[must_use]
    pub const fn with_view_version(mut self, version: u64) -> Self {
        self.view_version = version;
        self
    }

    /// Sets the generation.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }
}

/// Health status of a node based on heartbeat monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Node is healthy and responding.
    Healthy,
    /// Node has missed some heartbeats but not yet considered dead.
    Suspect,
    /// Node has missed too many heartbeats and is considered dead.
    Dead,
    /// Node status is unknown (no heartbeats received yet).
    Unknown,
}

impl HealthStatus {
    /// Returns true if the node should be considered available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Suspect)
    }
}

/// Tracks health status based on heartbeats.
#[derive(Debug)]
pub struct HealthChecker {
    config: HeartbeatConfig,
    last_heartbeat: Option<Instant>,
    last_sequence: u64,
    missed_count: u32,
}

impl HealthChecker {
    /// Creates a new health checker.
    #[must_use]
    pub const fn new(config: HeartbeatConfig) -> Self {
        Self {
            config,
            last_heartbeat: None,
            last_sequence: 0,
            missed_count: 0,
        }
    }

    /// Records a heartbeat reception.
    pub fn record_heartbeat(&mut self, sequence: u64) {
        self.last_heartbeat = Some(Instant::now());
        self.last_sequence = sequence;
        self.missed_count = 0;
    }

    /// Records a missed heartbeat.
    pub fn record_missed(&mut self) {
        self.missed_count = self.missed_count.saturating_add(1);
    }

    /// Returns the current health status.
    #[must_use]
    pub fn status(&self) -> HealthStatus {
        let Some(last) = self.last_heartbeat else {
            return HealthStatus::Unknown;
        };

        let elapsed = last.elapsed();

        if elapsed > self.config.dead_timeout() {
            HealthStatus::Dead
        } else if elapsed > self.config.suspect_timeout() {
            HealthStatus::Suspect
        } else {
            HealthStatus::Healthy
        }
    }

    /// Returns the time since the last heartbeat.
    #[must_use]
    pub fn time_since_heartbeat(&self) -> Option<Duration> {
        self.last_heartbeat.map(|last| last.elapsed())
    }

    /// Returns the last heartbeat sequence number.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the number of missed heartbeats.
    #[must_use]
    pub const fn missed_count(&self) -> u32 {
        self.missed_count
    }

    /// Resets the health checker state.
    pub fn reset(&mut self) {
        self.last_heartbeat = None;
        self.last_sequence = 0;
        self.missed_count = 0;
    }
}

/// Health metrics for a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// CPU utilization (0.0 to 1.0).
    pub cpu_percent: f32,
    /// Memory utilization (0.0 to 1.0).
    pub memory_percent: f32,
    /// Active call count.
    pub active_calls: u32,
    /// Active registration count.
    pub active_registrations: u32,
    /// Network latency to peers in milliseconds.
    pub peer_latency_ms: Vec<(String, u32)>,
}

impl Default for HealthMetrics {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            memory_percent: 0.0,
            active_calls: 0,
            active_registrations: 0,
            peer_latency_ms: Vec::new(),
        }
    }
}

impl HealthMetrics {
    /// Calculates an overall health score based on metrics.
    #[must_use]
    pub fn health_score(&self) -> f64 {
        // Simple weighted average
        let cpu_score = 1.0 - f64::from(self.cpu_percent);
        let mem_score = 1.0 - f64::from(self.memory_percent);

        // Weight: 40% CPU, 40% memory, 20% other factors
        (cpu_score * 0.4 + mem_score * 0.4 + 0.2).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_creation() {
        let hb = Heartbeat::new(NodeId::new("node-01"), NodeState::Active, 1);
        assert_eq!(hb.node_id.as_str(), "node-01");
        assert_eq!(hb.state, NodeState::Active);
        assert_eq!(hb.sequence, 1);
        assert!((hb.health_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_heartbeat_builder_methods() {
        let hb = Heartbeat::new(NodeId::new("node-01"), NodeState::Active, 1)
            .with_metrics(100, 500, 0.5, 0.3)
            .with_health_score(0.8)
            .with_view_version(5)
            .with_generation(2);

        assert_eq!(hb.active_calls, 100);
        assert_eq!(hb.active_registrations, 500);
        assert!((hb.cpu_percent - 0.5).abs() < f32::EPSILON);
        assert!((hb.memory_percent - 0.3).abs() < f32::EPSILON);
        assert!((hb.health_score - 0.8).abs() < f64::EPSILON);
        assert_eq!(hb.view_version, 5);
        assert_eq!(hb.generation, 2);
    }

    #[test]
    fn test_health_checker_initial_state() {
        let config = HeartbeatConfig::default();
        let checker = HealthChecker::new(config);
        assert_eq!(checker.status(), HealthStatus::Unknown);
        assert!(checker.time_since_heartbeat().is_none());
    }

    #[test]
    fn test_health_checker_record_heartbeat() {
        let config = HeartbeatConfig::default();
        let mut checker = HealthChecker::new(config);

        checker.record_heartbeat(1);
        assert_eq!(checker.status(), HealthStatus::Healthy);
        assert!(checker.time_since_heartbeat().is_some());
        assert_eq!(checker.last_sequence(), 1);
    }

    #[test]
    fn test_health_status_availability() {
        assert!(HealthStatus::Healthy.is_available());
        assert!(HealthStatus::Suspect.is_available());
        assert!(!HealthStatus::Dead.is_available());
        assert!(!HealthStatus::Unknown.is_available());
    }

    #[test]
    fn test_health_metrics_score() {
        let metrics = HealthMetrics {
            cpu_percent: 0.5,
            memory_percent: 0.5,
            active_calls: 100,
            active_registrations: 500,
            peer_latency_ms: vec![],
        };

        let score = metrics.health_score();
        // (0.5 * 0.4) + (0.5 * 0.4) + 0.2 = 0.6
        assert!((score - 0.6).abs() < 0.01);
    }
}
