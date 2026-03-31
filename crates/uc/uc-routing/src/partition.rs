//! Partition — a namespace for grouping route patterns.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Partition groups route patterns into a namespace.
///
/// In CUCM, partitions isolate dialing scopes so that the same pattern can
/// exist in multiple partitions without conflict.  A Calling Search Space
/// (CSS) selects which partitions a device or user can reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    /// Unique identifier.
    id: String,
    /// Human-readable name.
    name: String,
    /// Optional description.
    description: Option<String>,
}

impl Partition {
    /// Creates a new partition.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Returns the partition ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the partition name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description, if any.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Partition({}: {})", self.id, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_create() {
        let p = Partition::new("pt-internal", "Internal")
            .with_description("Internal extensions");
        assert_eq!(p.id(), "pt-internal");
        assert_eq!(p.name(), "Internal");
        assert_eq!(p.description(), Some("Internal extensions"));
    }

    #[test]
    fn test_partition_display() {
        let p = Partition::new("pt-pstn", "PSTN");
        assert_eq!(p.to_string(), "Partition(pt-pstn: PSTN)");
    }

    #[test]
    fn test_partition_no_description() {
        let p = Partition::new("pt-test", "Test");
        assert!(p.description().is_none());
    }
}
