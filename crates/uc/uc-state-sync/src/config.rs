//! State synchronization configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// State synchronization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StateSyncConfig {
    /// Replication mode.
    pub mode: ReplicationMode,
    /// Batch size for replication.
    pub batch_size: usize,
    /// Replication interval in milliseconds.
    pub replication_interval_ms: u64,
    /// Snapshot interval in seconds.
    pub snapshot_interval_secs: u64,
    /// Maximum lag before triggering catch-up sync (milliseconds).
    pub max_lag_ms: u64,
    /// Maximum pending operations before applying backpressure.
    pub max_pending_ops: usize,
    /// Compression enabled.
    pub compression_enabled: bool,
    /// Snapshot compression level (0-9).
    pub snapshot_compression_level: u32,
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            mode: ReplicationMode::SemiSynchronous,
            batch_size: 100,
            replication_interval_ms: 100,
            snapshot_interval_secs: 300,
            max_lag_ms: 5000,
            max_pending_ops: 10000,
            compression_enabled: true,
            snapshot_compression_level: 6,
        }
    }
}

impl StateSyncConfig {
    /// Creates a synchronous replication configuration.
    #[must_use]
    pub fn synchronous(min_acks: usize) -> Self {
        Self {
            mode: ReplicationMode::Synchronous { min_acks },
            ..Default::default()
        }
    }

    /// Creates an asynchronous replication configuration.
    #[must_use]
    pub fn asynchronous() -> Self {
        Self {
            mode: ReplicationMode::Asynchronous,
            ..Default::default()
        }
    }

    /// Returns the replication interval as a Duration.
    #[must_use]
    pub const fn replication_interval(&self) -> Duration {
        Duration::from_millis(self.replication_interval_ms)
    }

    /// Returns the snapshot interval as a Duration.
    #[must_use]
    pub const fn snapshot_interval(&self) -> Duration {
        Duration::from_secs(self.snapshot_interval_secs)
    }

    /// Returns the max lag as a Duration.
    #[must_use]
    pub const fn max_lag(&self) -> Duration {
        Duration::from_millis(self.max_lag_ms)
    }
}

/// Replication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    /// Synchronous - wait for N nodes to acknowledge.
    Synchronous {
        /// Minimum acknowledgments required.
        min_acks: usize,
    },
    /// Asynchronous - fire and forget.
    Asynchronous,
    /// Semi-synchronous - ack from at least one peer.
    #[default]
    SemiSynchronous,
}

impl std::fmt::Display for ReplicationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synchronous { min_acks } => write!(f, "synchronous({min_acks})"),
            Self::Asynchronous => write!(f, "asynchronous"),
            Self::SemiSynchronous => write!(f, "semi_synchronous"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = StateSyncConfig::default();
        assert!(matches!(config.mode, ReplicationMode::SemiSynchronous));
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.replication_interval_ms, 100);
    }

    #[test]
    fn test_synchronous_config() {
        let config = StateSyncConfig::synchronous(2);
        assert!(matches!(
            config.mode,
            ReplicationMode::Synchronous { min_acks: 2 }
        ));
    }

    #[test]
    fn test_asynchronous_config() {
        let config = StateSyncConfig::asynchronous();
        assert!(matches!(config.mode, ReplicationMode::Asynchronous));
    }

    #[test]
    fn test_durations() {
        let config = StateSyncConfig::default();
        assert_eq!(config.replication_interval(), Duration::from_millis(100));
        assert_eq!(config.snapshot_interval(), Duration::from_secs(300));
        assert_eq!(config.max_lag(), Duration::from_secs(5));
    }

    #[test]
    fn test_replication_mode_display() {
        assert_eq!(
            format!("{}", ReplicationMode::Synchronous { min_acks: 2 }),
            "synchronous(2)"
        );
        assert_eq!(format!("{}", ReplicationMode::Asynchronous), "asynchronous");
        assert_eq!(
            format!("{}", ReplicationMode::SemiSynchronous),
            "semi_synchronous"
        );
    }
}
