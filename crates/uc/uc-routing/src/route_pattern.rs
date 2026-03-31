//! Route Pattern — a pattern that belongs to a partition and matches dialed digits.

use crate::dialplan::{DialPattern, NumberTransform};
use crate::DEFAULT_PRIORITY;

/// A Route Pattern belongs to a partition and matches dialed digits.
///
/// CUCM equivalent: a route pattern with partition membership, optional
/// route list or route group destination, digit manipulation, and blocking.
#[derive(Debug, Clone)]
pub struct RoutePattern {
    /// Unique identifier.
    id: String,
    /// The dial pattern to match.
    pattern: DialPattern,
    /// Which partition this pattern belongs to.
    partition_id: String,
    /// Route via a Route List (ordered groups with failover).
    route_list_id: Option<String>,
    /// Route directly via a Route Group (`TrunkGroup`).
    route_group_id: Option<String>,
    /// Digit manipulation applied before routing.
    transform: NumberTransform,
    /// Optional description.
    description: Option<String>,
    /// If `true`, route immediately on match without waiting for inter-digit timeout.
    urgent: bool,
    /// If `true`, calls matching this pattern are blocked.
    block_enabled: bool,
    /// Priority (lower = preferred when multiple patterns match).
    priority: u32,
}

impl RoutePattern {
    /// Creates a new route pattern in the given partition.
    pub fn new(
        id: impl Into<String>,
        pattern: DialPattern,
        partition_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            pattern,
            partition_id: partition_id.into(),
            route_list_id: None,
            route_group_id: None,
            transform: NumberTransform::None,
            description: None,
            urgent: false,
            block_enabled: false,
            priority: DEFAULT_PRIORITY,
        }
    }

    /// Sets the route list ID.
    #[must_use]
    pub fn with_route_list(mut self, route_list_id: impl Into<String>) -> Self {
        self.route_list_id = Some(route_list_id.into());
        self
    }

    /// Sets the route group ID (direct trunk group routing).
    #[must_use]
    pub fn with_route_group(mut self, route_group_id: impl Into<String>) -> Self {
        self.route_group_id = Some(route_group_id.into());
        self
    }

    /// Sets the number transform.
    #[must_use]
    pub fn with_transform(mut self, transform: NumberTransform) -> Self {
        self.transform = transform;
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the urgent flag.
    #[must_use]
    pub fn with_urgent(mut self, urgent: bool) -> Self {
        self.urgent = urgent;
        self
    }

    /// Sets the block flag.
    #[must_use]
    pub fn with_block(mut self, block: bool) -> Self {
        self.block_enabled = block;
        self
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    // -- Getters --

    /// Returns the pattern ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the dial pattern.
    pub fn pattern(&self) -> &DialPattern {
        &self.pattern
    }

    /// Returns the partition ID.
    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    /// Returns the route list ID, if any.
    pub fn route_list_id(&self) -> Option<&str> {
        self.route_list_id.as_deref()
    }

    /// Returns the route group ID, if any.
    pub fn route_group_id(&self) -> Option<&str> {
        self.route_group_id.as_deref()
    }

    /// Returns the number transform.
    pub fn transform(&self) -> &NumberTransform {
        &self.transform
    }

    /// Returns the description, if any.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns whether this pattern is urgent.
    pub fn is_urgent(&self) -> bool {
        self.urgent
    }

    /// Returns whether this pattern blocks calls.
    pub fn is_blocked(&self) -> bool {
        self.block_enabled
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Checks if `number` matches the underlying dial pattern.
    pub fn matches(&self, number: &str) -> bool {
        self.pattern.matches(number)
    }

    /// Applies the transform to `number` and returns the result.
    pub fn transform_number(&self, number: &str) -> String {
        self.transform.apply(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_pattern_create() {
        let rp = RoutePattern::new("rp-911", DialPattern::exact("911"), "pt-emergency")
            .with_route_group("emergency-tg")
            .with_urgent(true)
            .with_priority(1)
            .with_description("Emergency pattern");

        assert_eq!(rp.id(), "rp-911");
        assert_eq!(rp.partition_id(), "pt-emergency");
        assert_eq!(rp.route_group_id(), Some("emergency-tg"));
        assert!(rp.is_urgent());
        assert!(!rp.is_blocked());
        assert_eq!(rp.priority(), 1);
        assert_eq!(rp.description(), Some("Emergency pattern"));
    }

    #[test]
    fn test_route_pattern_match() {
        let rp = RoutePattern::new("rp-us", DialPattern::prefix("+1"), "pt-ld");
        assert!(rp.matches("+15551234567"));
        assert!(!rp.matches("+445551234567"));
    }

    #[test]
    fn test_route_pattern_transform() {
        let rp = RoutePattern::new("rp-us", DialPattern::prefix("+1"), "pt-ld")
            .with_transform(NumberTransform::strip_prefix(2));
        assert_eq!(rp.transform_number("+15551234567"), "5551234567");
    }

    #[test]
    fn test_route_pattern_blocked() {
        let rp = RoutePattern::new("rp-900", DialPattern::prefix("1900"), "pt-ld")
            .with_block(true);
        assert!(rp.is_blocked());
    }

    #[test]
    fn test_route_pattern_with_route_list() {
        let rp = RoutePattern::new("rp-intl", DialPattern::prefix("+"), "pt-intl")
            .with_route_list("rl-international");
        assert_eq!(rp.route_list_id(), Some("rl-international"));
        assert!(rp.route_group_id().is_none());
    }
}
