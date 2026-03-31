//! Calling Search Space — an ordered list of partitions.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Calling Search Space is an ordered list of partitions.
///
/// It determines which route patterns a user or device can reach.
/// Partition order matters: the first matching pattern wins when the same
/// dialed digits match patterns in multiple partitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingSearchSpace {
    /// Unique identifier.
    id: String,
    /// Human-readable name.
    name: String,
    /// Optional description.
    description: Option<String>,
    /// Ordered partition IDs.
    partitions: Vec<String>,
}

impl CallingSearchSpace {
    /// Creates a new CSS with no partitions.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            partitions: Vec::new(),
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Returns the CSS ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the CSS name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description, if any.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the ordered partition IDs.
    pub fn partitions(&self) -> &[String] {
        &self.partitions
    }

    /// Adds a partition ID to the end of the list (lowest precedence).
    ///
    /// Does nothing if the partition is already present.
    pub fn add_partition(&mut self, partition_id: impl Into<String>) {
        let id = partition_id.into();
        if !self.partitions.contains(&id) {
            self.partitions.push(id);
        }
    }

    /// Removes a partition ID from the list.
    ///
    /// Returns `true` if the partition was present.
    pub fn remove_partition(&mut self, partition_id: &str) -> bool {
        let before = self.partitions.len();
        self.partitions.retain(|p| p != partition_id);
        self.partitions.len() < before
    }

    /// Returns whether the CSS contains the given partition.
    pub fn contains_partition(&self, partition_id: &str) -> bool {
        self.partitions.iter().any(|p| p == partition_id)
    }

    /// Replaces the partition list with a new ordering.
    pub fn reorder_partitions(&mut self, partition_ids: Vec<String>) {
        self.partitions = partition_ids;
    }

    /// Returns the number of partitions.
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }
}

impl fmt::Display for CallingSearchSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CSS({}: {} [{} partitions])",
            self.id,
            self.name,
            self.partitions.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_create() {
        let css = CallingSearchSpace::new("css-phone", "Phone CSS")
            .with_description("Standard phone CSS");
        assert_eq!(css.id(), "css-phone");
        assert_eq!(css.name(), "Phone CSS");
        assert_eq!(css.description(), Some("Standard phone CSS"));
        assert_eq!(css.partition_count(), 0);
    }

    #[test]
    fn test_css_add_partition() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        css.add_partition("pt-internal");
        css.add_partition("pt-local");
        css.add_partition("pt-ld");
        assert_eq!(css.partition_count(), 3);
        assert_eq!(css.partitions(), &["pt-internal", "pt-local", "pt-ld"]);
    }

    #[test]
    fn test_css_add_partition_no_duplicate() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        css.add_partition("pt-internal");
        css.add_partition("pt-internal");
        assert_eq!(css.partition_count(), 1);
    }

    #[test]
    fn test_css_remove_partition() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        css.add_partition("pt-internal");
        css.add_partition("pt-pstn");

        assert!(css.remove_partition("pt-internal"));
        assert_eq!(css.partition_count(), 1);
        assert!(!css.contains_partition("pt-internal"));
    }

    #[test]
    fn test_css_remove_nonexistent() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        assert!(!css.remove_partition("nope"));
    }

    #[test]
    fn test_css_contains() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        css.add_partition("pt-internal");
        assert!(css.contains_partition("pt-internal"));
        assert!(!css.contains_partition("pt-pstn"));
    }

    #[test]
    fn test_css_reorder() {
        let mut css = CallingSearchSpace::new("css-1", "Test");
        css.add_partition("pt-a");
        css.add_partition("pt-b");
        css.add_partition("pt-c");

        css.reorder_partitions(vec![
            "pt-c".to_string(),
            "pt-a".to_string(),
            "pt-b".to_string(),
        ]);
        assert_eq!(css.partitions(), &["pt-c", "pt-a", "pt-b"]);
    }

    #[test]
    fn test_css_display() {
        let mut css = CallingSearchSpace::new("css-phone", "Phone");
        css.add_partition("pt-1");
        css.add_partition("pt-2");
        assert_eq!(css.to_string(), "CSS(css-phone: Phone [2 partitions])");
    }
}
