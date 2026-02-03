//! Conflict-free Replicated Data Types (CRDTs).
//!
//! Provides CRDT implementations for eventually consistent distributed state:
//! - `GCounter`: Grow-only counter
//! - `PNCounter`: Positive-negative counter (supports increment and decrement)
//! - `LWWRegister`: Last-writer-wins register

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A grow-only counter CRDT.
///
/// Each node maintains its own counter that can only be incremented.
/// The global value is the sum of all node counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCounter {
    /// Node ID for this counter instance.
    node_id: String,
    /// Per-node counter values.
    counts: HashMap<String, u64>,
}

impl GCounter {
    /// Creates a new grow-only counter for the given node.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            counts: HashMap::new(),
        }
    }

    /// Increments the counter for this node.
    pub fn increment(&mut self) {
        self.increment_by(1);
    }

    /// Increments the counter by a specified amount.
    pub fn increment_by(&mut self, amount: u64) {
        *self.counts.entry(self.node_id.clone()).or_insert(0) += amount;
    }

    /// Returns the current value (sum of all node counters).
    #[must_use]
    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Returns the local node's contribution.
    #[must_use]
    pub fn local_value(&self) -> u64 {
        self.counts.get(&self.node_id).copied().unwrap_or(0)
    }

    /// Merges another `GCounter` into this one.
    ///
    /// Takes the maximum value for each node.
    pub fn merge(&mut self, other: &GCounter) {
        for (node, &count) in &other.counts {
            let entry = self.counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
    }
}

/// A positive-negative counter CRDT.
///
/// Supports both increment and decrement operations while maintaining
/// eventual consistency across nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PNCounter {
    /// Positive counter (increments).
    positive: GCounter,
    /// Negative counter (decrements).
    negative: GCounter,
}

impl PNCounter {
    /// Creates a new positive-negative counter for the given node.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            positive: GCounter::new(node_id.clone()),
            negative: GCounter::new(node_id),
        }
    }

    /// Increments the counter.
    pub fn increment(&mut self) {
        self.increment_by(1);
    }

    /// Increments the counter by a specified amount.
    pub fn increment_by(&mut self, amount: u64) {
        self.positive.increment_by(amount);
    }

    /// Decrements the counter.
    pub fn decrement(&mut self) {
        self.decrement_by(1);
    }

    /// Decrements the counter by a specified amount.
    pub fn decrement_by(&mut self, amount: u64) {
        self.negative.increment_by(amount);
    }

    /// Returns the current value.
    #[must_use]
    pub fn value(&self) -> i64 {
        self.positive.value() as i64 - self.negative.value() as i64
    }

    /// Merges another `PNCounter` into this one.
    pub fn merge(&mut self, other: &PNCounter) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

/// A last-writer-wins register CRDT.
///
/// Stores a single value with a timestamp. When merging, the value with
/// the highest timestamp wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWWRegister<T: Clone> {
    /// The stored value.
    value: Option<T>,
    /// Timestamp of the last update (microseconds since epoch).
    timestamp: u64,
    /// Node ID that made the last update.
    node_id: String,
}

impl<T: Clone> LWWRegister<T> {
    /// Creates a new empty register for the given node.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            value: None,
            timestamp: 0,
            node_id: node_id.into(),
        }
    }

    /// Creates a register with an initial value.
    #[must_use]
    pub fn with_value(node_id: impl Into<String>, value: T) -> Self {
        Self {
            value: Some(value),
            timestamp: Self::current_timestamp(),
            node_id: node_id.into(),
        }
    }

    /// Sets the value.
    pub fn set(&mut self, value: T) {
        self.value = Some(value);
        self.timestamp = Self::current_timestamp();
    }

    /// Clears the value.
    pub fn clear(&mut self) {
        self.value = None;
        self.timestamp = Self::current_timestamp();
    }

    /// Returns the current value.
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Returns the timestamp of the last update.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Merges another register into this one.
    ///
    /// The value with the higher timestamp wins. If timestamps are equal,
    /// uses lexicographic node ID comparison as a tiebreaker.
    pub fn merge(&mut self, other: &LWWRegister<T>) {
        let should_update = match self.timestamp.cmp(&other.timestamp) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => other.node_id > self.node_id,
        };

        if should_update {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node_id = other.node_id.clone();
        }
    }

    /// Returns the current timestamp in microseconds.
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcounter_increment() {
        let mut counter = GCounter::new("node1");

        assert_eq!(counter.value(), 0);

        counter.increment();
        assert_eq!(counter.value(), 1);

        counter.increment_by(5);
        assert_eq!(counter.value(), 6);
    }

    #[test]
    fn test_gcounter_merge() {
        let mut counter1 = GCounter::new("node1");
        let mut counter2 = GCounter::new("node2");

        counter1.increment_by(3);
        counter2.increment_by(5);

        counter1.merge(&counter2);
        assert_eq!(counter1.value(), 8); // 3 + 5

        // Merging again should be idempotent
        counter1.merge(&counter2);
        assert_eq!(counter1.value(), 8);
    }

    #[test]
    fn test_pncounter_operations() {
        let mut counter = PNCounter::new("node1");

        assert_eq!(counter.value(), 0);

        counter.increment_by(10);
        assert_eq!(counter.value(), 10);

        counter.decrement_by(3);
        assert_eq!(counter.value(), 7);

        counter.decrement_by(10);
        assert_eq!(counter.value(), -3);
    }

    #[test]
    fn test_pncounter_merge() {
        let mut counter1 = PNCounter::new("node1");
        let mut counter2 = PNCounter::new("node2");

        counter1.increment_by(10);
        counter1.decrement_by(2);

        counter2.increment_by(5);
        counter2.decrement_by(1);

        counter1.merge(&counter2);
        // node1: +10, -2 = 8
        // node2: +5, -1 = 4
        // total: 12
        assert_eq!(counter1.value(), 12);
    }

    #[test]
    fn test_lww_register_set_get() {
        let mut register: LWWRegister<String> = LWWRegister::new("node1");

        assert!(register.get().is_none());

        register.set("hello".to_string());
        assert_eq!(register.get(), Some(&"hello".to_string()));

        register.set("world".to_string());
        assert_eq!(register.get(), Some(&"world".to_string()));
    }

    #[test]
    fn test_lww_register_merge() {
        let mut register1: LWWRegister<String> = LWWRegister::new("node1");
        let mut register2: LWWRegister<String> = LWWRegister::new("node2");

        register1.set("first".to_string());

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(1));

        register2.set("second".to_string());

        // register2 should have a later timestamp
        register1.merge(&register2);
        assert_eq!(register1.get(), Some(&"second".to_string()));
    }

    #[test]
    fn test_lww_register_clear() {
        let mut register: LWWRegister<i32> = LWWRegister::with_value("node1", 42);

        assert_eq!(register.get(), Some(&42));

        register.clear();
        assert!(register.get().is_none());
    }
}
