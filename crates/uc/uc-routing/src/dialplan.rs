//! Dial plan and number manipulation.

use crate::DEFAULT_PRIORITY;
use std::collections::HashMap;

/// Number transformation operation.
#[derive(Debug, Clone, Default)]
pub enum NumberTransform {
    /// No transformation.
    #[default]
    None,
    /// Strip leading digits.
    StripPrefix {
        /// Number of digits to strip.
        count: usize,
    },
    /// Add prefix.
    AddPrefix {
        /// Prefix to add.
        prefix: String,
    },
    /// Replace prefix.
    ReplacePrefix {
        /// Prefix to match.
        from: String,
        /// Replacement.
        to: String,
    },
    /// Full number replacement.
    Replace {
        /// Replacement number.
        number: String,
    },
    /// Multiple transformations.
    Chain(Vec<NumberTransform>),
}

impl NumberTransform {
    /// Applies the transformation to a number.
    pub fn apply(&self, number: &str) -> String {
        match self {
            Self::None => number.to_string(),
            Self::StripPrefix { count } => {
                if number.len() > *count {
                    number[*count..].to_string()
                } else {
                    number.to_string()
                }
            }
            Self::AddPrefix { prefix } => format!("{prefix}{number}"),
            Self::ReplacePrefix { from, to } => {
                if number.starts_with(from) {
                    format!("{}{}", to, &number[from.len()..])
                } else {
                    number.to_string()
                }
            }
            Self::Replace {
                number: replacement,
            } => replacement.clone(),
            Self::Chain(transforms) => {
                let mut result = number.to_string();
                for transform in transforms {
                    result = transform.apply(&result);
                }
                result
            }
        }
    }

    /// Creates a strip prefix transformation.
    pub fn strip_prefix(count: usize) -> Self {
        Self::StripPrefix { count }
    }

    /// Creates an add prefix transformation.
    pub fn add_prefix(prefix: impl Into<String>) -> Self {
        Self::AddPrefix {
            prefix: prefix.into(),
        }
    }

    /// Creates a replace prefix transformation.
    pub fn replace_prefix(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::ReplacePrefix {
            from: from.into(),
            to: to.into(),
        }
    }
}

/// Dial pattern type.
#[derive(Debug, Clone)]
pub enum DialPattern {
    /// Exact match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Wildcard pattern (X = any digit, . = any remaining).
    Wildcard(String),
    /// Regex pattern.
    Regex(String),
    /// Match any number.
    Any,
}

impl DialPattern {
    /// Checks if a number matches this pattern.
    pub fn matches(&self, number: &str) -> bool {
        match self {
            Self::Exact(pattern) => number == pattern,
            Self::Prefix(prefix) => number.starts_with(prefix),
            Self::Wildcard(pattern) => Self::match_wildcard(pattern, number),
            Self::Regex(_pattern) => {
                // Would use regex crate in production
                true
            }
            Self::Any => true,
        }
    }

    /// Matches a wildcard pattern.
    /// X = single digit (0-9)
    /// . = any remaining digits
    fn match_wildcard(pattern: &str, number: &str) -> bool {
        let pattern_chars = pattern.chars();
        let mut number_chars = number.chars();

        for p in pattern_chars {
            match p {
                'X' => {
                    // Match any single digit
                    match number_chars.next() {
                        Some(c) if c.is_ascii_digit() => {}
                        _ => return false,
                    }
                }
                '.' => {
                    // Match any remaining
                    return true;
                }
                c => {
                    // Match literal character
                    if number_chars.next() != Some(c) {
                        return false;
                    }
                }
            }
        }

        // Pattern exhausted, number should also be exhausted
        number_chars.next().is_none()
    }

    /// Creates a prefix pattern.
    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self::Prefix(prefix.into())
    }

    /// Creates an exact match pattern.
    pub fn exact(number: impl Into<String>) -> Self {
        Self::Exact(number.into())
    }

    /// Creates a wildcard pattern.
    pub fn wildcard(pattern: impl Into<String>) -> Self {
        Self::Wildcard(pattern.into())
    }
}

/// Call direction for dial plan matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Inbound: trunk → SBC → target (registered user or downstream trunk).
    Inbound,
    /// Outbound: registered user → SBC → trunk.
    #[default]
    Outbound,
    /// Both: matches in either direction.
    Both,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Destination type for a dial plan entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DestinationType {
    /// Route to a trunk group (default).
    #[default]
    TrunkGroup,
    /// Route to a registered user via LocationService.
    RegisteredUser,
    /// Route to a static SIP URI.
    StaticUri,
}

/// Dial plan entry.
#[derive(Debug, Clone)]
pub struct DialPlanEntry {
    /// Entry ID.
    id: String,
    /// Entry name.
    name: String,
    /// Pattern to match (user part of Request-URI).
    pattern: DialPattern,
    /// Number transformation.
    transform: NumberTransform,
    /// Trunk group to route to (for `DestinationType::TrunkGroup`).
    trunk_group: String,
    /// Priority (lower = higher priority).
    priority: u32,
    /// Whether this entry is enabled.
    enabled: bool,
    /// Tags for categorization.
    tags: Vec<String>,
    /// Call direction filter.
    direction: Direction,
    /// Domain pattern to match (host part of Request-URI).
    /// Suffix match: `"uc.mil"` matches `"sip.uc.mil"` and `"uc.mil"`.
    /// Wildcard: `"*.mil"` matches any `.mil` domain.
    domain_pattern: Option<String>,
    /// Source trunk ID filter (only match if call came from this trunk).
    source_trunk: Option<String>,
    /// Where to route the call.
    destination_type: DestinationType,
    /// Static destination URI (for `DestinationType::StaticUri`).
    static_destination: Option<String>,
}

impl DialPlanEntry {
    /// Creates a new dial plan entry.
    pub fn new(
        id: impl Into<String>,
        pattern: DialPattern,
        trunk_group: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            pattern,
            transform: NumberTransform::None,
            trunk_group: trunk_group.into(),
            priority: DEFAULT_PRIORITY,
            enabled: true,
            tags: Vec::new(),
            direction: Direction::default(),
            domain_pattern: None,
            source_trunk: None,
            destination_type: DestinationType::default(),
            static_destination: None,
        }
    }

    /// Sets the entry name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the transformation.
    #[must_use]
    pub fn with_transform(mut self, transform: NumberTransform) -> Self {
        self.transform = transform;
        self
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets whether enabled.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Sets the call direction filter.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Sets the domain pattern to match against the Request-URI host.
    #[must_use]
    pub fn with_domain_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.domain_pattern = Some(pattern.into());
        self
    }

    /// Sets the source trunk filter.
    #[must_use]
    pub fn with_source_trunk(mut self, trunk_id: impl Into<String>) -> Self {
        self.source_trunk = Some(trunk_id.into());
        self
    }

    /// Sets the destination type.
    #[must_use]
    pub fn with_destination_type(mut self, dest_type: DestinationType) -> Self {
        self.destination_type = dest_type;
        self
    }

    /// Sets the static destination URI.
    #[must_use]
    pub fn with_static_destination(mut self, uri: impl Into<String>) -> Self {
        self.destination_type = DestinationType::StaticUri;
        self.static_destination = Some(uri.into());
        self
    }

    /// Returns the entry ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the entry name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the pattern.
    pub fn pattern(&self) -> &DialPattern {
        &self.pattern
    }

    /// Returns the transformation.
    pub fn transform(&self) -> &NumberTransform {
        &self.transform
    }

    /// Returns the trunk group.
    pub fn trunk_group(&self) -> &str {
        &self.trunk_group
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Returns whether enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the tags.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns the direction filter.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the domain pattern.
    pub fn domain_pattern(&self) -> Option<&str> {
        self.domain_pattern.as_deref()
    }

    /// Returns the source trunk filter.
    pub fn source_trunk(&self) -> Option<&str> {
        self.source_trunk.as_deref()
    }

    /// Returns the destination type.
    pub fn destination_type(&self) -> DestinationType {
        self.destination_type
    }

    /// Returns the static destination URI.
    pub fn static_destination(&self) -> Option<&str> {
        self.static_destination.as_deref()
    }

    /// Checks if this entry matches a number (user part only, legacy).
    pub fn matches(&self, number: &str) -> bool {
        self.enabled && self.pattern.matches(number)
    }

    /// Checks if this entry matches with full URI context.
    pub fn matches_extended(
        &self,
        user: &str,
        domain: &str,
        direction: Direction,
        source_trunk: Option<&str>,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Direction filter
        if self.direction != Direction::Both && self.direction != direction {
            return false;
        }

        // Source trunk filter
        if let Some(ref required_trunk) = self.source_trunk {
            match source_trunk {
                Some(actual) if actual == required_trunk => {}
                _ => return false,
            }
        }

        // Domain pattern filter
        if let Some(ref domain_pat) = self.domain_pattern {
            if !match_domain(domain_pat, domain) {
                return false;
            }
        }

        // User/number pattern match
        self.pattern.matches(user)
    }

    /// Transforms a number according to this entry.
    pub fn transform_number(&self, number: &str) -> String {
        self.transform.apply(number)
    }
}

/// Matches a domain pattern against a domain.
///
/// - `"uc.mil"` matches `"uc.mil"` and `"sip.uc.mil"` (suffix match)
/// - `"*.mil"` matches any `.mil` domain
/// - `""` or empty matches everything
fn match_domain(pattern: &str, domain: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    // Wildcard prefix: "*.mil" matches "anything.mil"
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain.ends_with(suffix)
            || domain == suffix;
    }

    // Exact or suffix match: "uc.mil" matches "uc.mil" and "sip.uc.mil"
    domain == pattern || domain.ends_with(&format!(".{pattern}"))
}

/// Dial plan result.
#[derive(Debug, Clone)]
pub struct DialPlanResult {
    /// Entry that matched.
    pub entry_id: String,
    /// Original number.
    pub original_number: String,
    /// Transformed number.
    pub transformed_number: String,
    /// Trunk group to use.
    pub trunk_group: String,
    /// Destination type.
    pub destination_type: DestinationType,
    /// Static destination URI (if `DestinationType::StaticUri`).
    pub static_destination: Option<String>,
}

/// A complete dial plan.
#[derive(Debug, Default)]
pub struct DialPlan {
    /// Plan ID.
    id: String,
    /// Plan name.
    name: String,
    /// Entries indexed by ID.
    entries: HashMap<String, DialPlanEntry>,
    /// Sorted entry IDs by priority.
    sorted_ids: Vec<String>,
}

impl DialPlan {
    /// Creates a new dial plan.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            entries: HashMap::new(),
            sorted_ids: Vec::new(),
        }
    }

    /// Returns the plan ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the plan name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds an entry to the plan.
    pub fn add_entry(&mut self, entry: DialPlanEntry) {
        let id = entry.id().to_string();
        self.entries.insert(id.clone(), entry);

        // Re-sort entries by priority
        self.sorted_ids.push(id);
        self.sorted_ids.sort_by(|a, b| {
            let pa = self
                .entries
                .get(a)
                .map_or(u32::MAX, DialPlanEntry::priority);
            let pb = self
                .entries
                .get(b)
                .map_or(u32::MAX, DialPlanEntry::priority);
            pa.cmp(&pb)
        });
    }

    /// Removes an entry.
    pub fn remove_entry(&mut self, id: &str) -> Option<DialPlanEntry> {
        self.sorted_ids.retain(|i| i != id);
        self.entries.remove(id)
    }

    /// Gets an entry by ID.
    pub fn get_entry(&self, id: &str) -> Option<&DialPlanEntry> {
        self.entries.get(id)
    }

    /// Returns the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Matches a number against the dial plan (legacy, user-part only).
    pub fn match_number(&self, number: &str) -> Option<DialPlanResult> {
        for id in &self.sorted_ids {
            if let Some(entry) = self.entries.get(id)
                && entry.matches(number)
            {
                return Some(DialPlanResult {
                    entry_id: entry.id().to_string(),
                    original_number: number.to_string(),
                    transformed_number: entry.transform_number(number),
                    trunk_group: entry.trunk_group().to_string(),
                    destination_type: entry.destination_type(),
                    static_destination: entry.static_destination().map(String::from),
                });
            }
        }
        None
    }

    /// Matches with full URI context (user, domain, direction, source trunk).
    pub fn match_extended(
        &self,
        user: &str,
        domain: &str,
        direction: Direction,
        source_trunk: Option<&str>,
    ) -> Option<DialPlanResult> {
        for id in &self.sorted_ids {
            if let Some(entry) = self.entries.get(id)
                && entry.matches_extended(user, domain, direction, source_trunk)
            {
                return Some(DialPlanResult {
                    entry_id: entry.id().to_string(),
                    original_number: user.to_string(),
                    transformed_number: entry.transform_number(user),
                    trunk_group: entry.trunk_group().to_string(),
                    destination_type: entry.destination_type(),
                    static_destination: entry.static_destination().map(String::from),
                });
            }
        }
        None
    }

    /// Returns all entries with a specific tag.
    pub fn entries_with_tag(&self, tag: &str) -> Vec<&DialPlanEntry> {
        self.entries
            .values()
            .filter(|e| e.tags().contains(&tag.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_transform_none() {
        let transform = NumberTransform::None;
        assert_eq!(transform.apply("+15551234567"), "+15551234567");
    }

    #[test]
    fn test_number_transform_strip_prefix() {
        let transform = NumberTransform::strip_prefix(2);
        assert_eq!(transform.apply("+15551234567"), "5551234567");
    }

    #[test]
    fn test_number_transform_add_prefix() {
        let transform = NumberTransform::add_prefix("9");
        assert_eq!(transform.apply("5551234567"), "95551234567");
    }

    #[test]
    fn test_number_transform_replace_prefix() {
        let transform = NumberTransform::replace_prefix("+1", "011-1-");
        assert_eq!(transform.apply("+15551234567"), "011-1-5551234567");
    }

    #[test]
    fn test_number_transform_chain() {
        let transform = NumberTransform::Chain(vec![
            NumberTransform::strip_prefix(1), // Remove +
            NumberTransform::add_prefix("011-"),
        ]);
        assert_eq!(transform.apply("+15551234567"), "011-15551234567");
    }

    #[test]
    fn test_dial_pattern_exact() {
        let pattern = DialPattern::exact("911");
        assert!(pattern.matches("911"));
        assert!(!pattern.matches("9111"));
    }

    #[test]
    fn test_dial_pattern_prefix() {
        let pattern = DialPattern::prefix("+1555");
        assert!(pattern.matches("+15551234567"));
        assert!(!pattern.matches("+445551234567"));
    }

    #[test]
    fn test_dial_pattern_wildcard() {
        // 10-digit US number pattern
        let pattern = DialPattern::wildcard("1XXXXXXXXXX");
        assert!(pattern.matches("15551234567"));
        assert!(!pattern.matches("15551234")); // Too short

        // Any number after prefix
        let pattern = DialPattern::wildcard("+1.");
        assert!(pattern.matches("+15551234567"));
        assert!(pattern.matches("+1"));
    }

    #[test]
    fn test_dial_pattern_any() {
        let pattern = DialPattern::Any;
        assert!(pattern.matches("anything"));
        assert!(pattern.matches(""));
    }

    #[test]
    fn test_dial_plan_entry() {
        let entry = DialPlanEntry::new("us-toll-free", DialPattern::prefix("+1800"), "toll-free")
            .with_name("US Toll Free")
            .with_transform(NumberTransform::strip_prefix(2))
            .with_priority(50)
            .with_tag("inbound");

        assert_eq!(entry.id(), "us-toll-free");
        assert_eq!(entry.priority(), 50);
        assert!(entry.matches("+18001234567"));
        assert_eq!(entry.transform_number("+18001234567"), "8001234567");
    }

    #[test]
    fn test_dial_plan_entry_disabled() {
        let entry = DialPlanEntry::new("test", DialPattern::Any, "trunk").with_enabled(false);

        assert!(!entry.matches("+15551234567"));
    }

    #[test]
    fn test_dial_plan_creation() {
        let plan = DialPlan::new("default", "Default Plan");
        assert_eq!(plan.id(), "default");
        assert_eq!(plan.entry_count(), 0);
    }

    #[test]
    fn test_dial_plan_add_entry() {
        let mut plan = DialPlan::new("default", "Default Plan");

        plan.add_entry(
            DialPlanEntry::new("entry-1", DialPattern::prefix("+1"), "us-trunk").with_priority(100),
        );
        plan.add_entry(
            DialPlanEntry::new("entry-2", DialPattern::prefix("+44"), "uk-trunk")
                .with_priority(100),
        );

        assert_eq!(plan.entry_count(), 2);
    }

    #[test]
    fn test_dial_plan_match() {
        let mut plan = DialPlan::new("default", "Default Plan");

        plan.add_entry(DialPlanEntry::new(
            "us",
            DialPattern::prefix("+1"),
            "us-trunk",
        ));
        plan.add_entry(DialPlanEntry::new(
            "uk",
            DialPattern::prefix("+44"),
            "uk-trunk",
        ));

        let result = plan.match_number("+15551234567");
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.entry_id, "us");
        assert_eq!(result.trunk_group, "us-trunk");
    }

    #[test]
    fn test_dial_plan_no_match() {
        let mut plan = DialPlan::new("default", "Default Plan");

        plan.add_entry(DialPlanEntry::new(
            "us",
            DialPattern::prefix("+1"),
            "us-trunk",
        ));

        let result = plan.match_number("+445551234567");
        assert!(result.is_none());
    }

    #[test]
    fn test_dial_plan_priority_ordering() {
        let mut plan = DialPlan::new("default", "Default Plan");

        // Add low priority first
        plan.add_entry(
            DialPlanEntry::new("low", DialPattern::prefix("+1"), "low-priority-trunk")
                .with_priority(200),
        );
        // Add high priority
        plan.add_entry(
            DialPlanEntry::new("high", DialPattern::prefix("+1"), "high-priority-trunk")
                .with_priority(50),
        );

        let result = plan.match_number("+15551234567");
        assert!(result.is_some());
        assert_eq!(result.unwrap().entry_id, "high");
    }

    #[test]
    fn test_dial_plan_with_transform() {
        let mut plan = DialPlan::new("default", "Default Plan");

        plan.add_entry(
            DialPlanEntry::new("us", DialPattern::prefix("+1"), "us-trunk")
                .with_transform(NumberTransform::replace_prefix("+1", "1")),
        );

        let result = plan.match_number("+15551234567");
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.original_number, "+15551234567");
        assert_eq!(result.transformed_number, "15551234567");
    }

    #[test]
    fn test_direction_filtering() {
        let mut plan = DialPlan::new("test", "Test");

        plan.add_entry(
            DialPlanEntry::new("outbound-us", DialPattern::prefix("+1"), "us-trunk")
                .with_direction(Direction::Outbound)
                .with_priority(10),
        );
        plan.add_entry(
            DialPlanEntry::new("inbound-did", DialPattern::prefix("+1555"), "internal")
                .with_direction(Direction::Inbound)
                .with_destination_type(DestinationType::RegisteredUser)
                .with_priority(5),
        );

        // Outbound call should match outbound entry
        let result = plan.match_extended("+15551234567", "sbc.local", Direction::Outbound, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().entry_id, "outbound-us");

        // Inbound call should match inbound entry (higher priority)
        let result = plan.match_extended("+15551234567", "sbc.local", Direction::Inbound, None);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.entry_id, "inbound-did");
        assert_eq!(r.destination_type, DestinationType::RegisteredUser);
    }

    #[test]
    fn test_domain_pattern_matching() {
        let mut plan = DialPlan::new("test", "Test");

        plan.add_entry(
            DialPlanEntry::new("mil-calls", DialPattern::Any, "mil-trunk")
                .with_domain_pattern("uc.mil")
                .with_direction(Direction::Inbound)
                .with_priority(1),
        );

        // Match: domain is uc.mil
        let result = plan.match_extended("bob", "uc.mil", Direction::Inbound, None);
        assert!(result.is_some());

        // Match: subdomain of uc.mil
        let result = plan.match_extended("bob", "sip.uc.mil", Direction::Inbound, None);
        assert!(result.is_some());

        // No match: different domain
        let result = plan.match_extended("bob", "example.com", Direction::Inbound, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_wildcard_domain_matching() {
        let mut plan = DialPlan::new("test", "Test");

        plan.add_entry(
            DialPlanEntry::new("all-mil", DialPattern::Any, "mil-trunk")
                .with_domain_pattern("*.mil")
                .with_direction(Direction::Both)
                .with_priority(1),
        );

        assert!(plan.match_extended("bob", "army.mil", Direction::Inbound, None).is_some());
        assert!(plan.match_extended("bob", "navy.mil", Direction::Outbound, None).is_some());
        assert!(plan.match_extended("bob", "example.com", Direction::Inbound, None).is_none());
    }

    #[test]
    fn test_source_trunk_filtering() {
        let mut plan = DialPlan::new("test", "Test");

        plan.add_entry(
            DialPlanEntry::new("from-bulkvs", DialPattern::Any, "downstream")
                .with_direction(Direction::Inbound)
                .with_source_trunk("bulkvs-1")
                .with_priority(1),
        );

        // Match: correct source trunk
        let result = plan.match_extended("12345", "sbc.local", Direction::Inbound, Some("bulkvs-1"));
        assert!(result.is_some());

        // No match: wrong source trunk
        let result = plan.match_extended("12345", "sbc.local", Direction::Inbound, Some("other-trunk"));
        assert!(result.is_none());

        // No match: no source trunk
        let result = plan.match_extended("12345", "sbc.local", Direction::Inbound, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_static_destination() {
        let mut plan = DialPlan::new("test", "Test");

        plan.add_entry(
            DialPlanEntry::new("voicemail", DialPattern::exact("*86"), "")
                .with_static_destination("sip:voicemail@vm.uc.mil:5060")
                .with_direction(Direction::Both)
                .with_priority(1),
        );

        let result = plan.match_extended("*86", "sbc.local", Direction::Outbound, None);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.destination_type, DestinationType::StaticUri);
        assert_eq!(r.static_destination.as_deref(), Some("sip:voicemail@vm.uc.mil:5060"));
    }

    #[test]
    fn test_combined_filters() {
        let mut plan = DialPlan::new("test", "Test");

        // Inbound from BulkVS to @uc.mil with +1 prefix → strip and route to downstream
        plan.add_entry(
            DialPlanEntry::new("bulkvs-to-cm", DialPattern::prefix("+1"), "downstream-cm")
                .with_direction(Direction::Inbound)
                .with_source_trunk("bulkvs-1")
                .with_domain_pattern("uc.mil")
                .with_transform(NumberTransform::strip_prefix(2))
                .with_priority(1),
        );

        let result = plan.match_extended("+15551234567", "sip.uc.mil", Direction::Inbound, Some("bulkvs-1"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.trunk_group, "downstream-cm");
        assert_eq!(r.transformed_number, "5551234567");

        // Same number but outbound direction — should NOT match
        let result = plan.match_extended("+15551234567", "sip.uc.mil", Direction::Outbound, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_domain_helper() {
        // Exact match
        assert!(match_domain("uc.mil", "uc.mil"));
        // Suffix match
        assert!(match_domain("uc.mil", "sip.uc.mil"));
        // Wildcard
        assert!(match_domain("*.mil", "army.mil"));
        assert!(match_domain("*.mil", "uc.mil"));
        // No match
        assert!(!match_domain("uc.mil", "example.com"));
        assert!(!match_domain("*.mil", "example.com"));
        // Empty pattern matches everything
        assert!(match_domain("", "anything.com"));
    }

    #[test]
    fn test_dial_plan_entries_with_tag() {
        let mut plan = DialPlan::new("default", "Default Plan");

        plan.add_entry(
            DialPlanEntry::new("toll-free", DialPattern::prefix("+1800"), "tf-trunk")
                .with_tag("inbound"),
        );
        plan.add_entry(
            DialPlanEntry::new("local", DialPattern::prefix("+1"), "local-trunk")
                .with_tag("outbound"),
        );

        let inbound = plan.entries_with_tag("inbound");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].id(), "toll-free");
    }
}
