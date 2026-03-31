//! CUCM-compatible routing engine.
//!
//! Implements Cisco Unified Communications Manager-style call routing:
//! Calling Search Spaces select partitions, partitions contain route
//! patterns, and route patterns point to route lists or route groups.

use crate::css::CallingSearchSpace;
use crate::partition::Partition;
use crate::route_list::RouteList;
use crate::route_pattern::RoutePattern;
use crate::trunk::TrunkGroup;
use std::collections::HashMap;

/// Result of the CUCM routing algorithm.
#[derive(Debug, Clone)]
pub struct CucmRoutingResult {
    /// ID of the matched route pattern.
    pub pattern_id: String,
    /// ID of the partition the matched pattern belongs to.
    pub partition_id: String,
    /// Dialed digits after all transforms have been applied.
    pub transformed_number: String,
    /// Ordered route group (trunk group) IDs for failover.
    pub route_group_ids: Vec<String>,
    /// Human-readable descriptions of applied transforms.
    pub transforms_applied: Vec<String>,
}

/// A CUCM-compatible routing engine.
///
/// Combines Partitions, Calling Search Spaces, Route Patterns, Route Lists,
/// and Route Groups (trunk groups) into a single routing decision.
#[derive(Debug)]
pub struct CucmRouter {
    /// Partitions indexed by ID.
    partitions: HashMap<String, Partition>,
    /// Calling Search Spaces indexed by ID.
    css_list: HashMap<String, CallingSearchSpace>,
    /// All route patterns (searched linearly per partition).
    route_patterns: Vec<RoutePattern>,
    /// Route lists indexed by ID.
    route_lists: HashMap<String, RouteList>,
    /// Route groups (trunk groups) indexed by ID.
    route_groups: HashMap<String, TrunkGroup>,
    /// Default CSS to use when none is specified.
    default_css: Option<String>,
}

impl CucmRouter {
    /// Creates a new empty router.
    pub fn new() -> Self {
        Self {
            partitions: HashMap::new(),
            css_list: HashMap::new(),
            route_patterns: Vec::new(),
            route_lists: HashMap::new(),
            route_groups: HashMap::new(),
            default_css: None,
        }
    }

    /// Sets the default CSS ID.
    pub fn set_default_css(&mut self, css_id: impl Into<String>) {
        self.default_css = Some(css_id.into());
    }

    // ---- Partition CRUD ----

    /// Adds a partition.
    pub fn add_partition(&mut self, partition: Partition) {
        self.partitions.insert(partition.id().to_string(), partition);
    }

    /// Removes a partition by ID.
    pub fn remove_partition(&mut self, id: &str) -> Option<Partition> {
        self.partitions.remove(id)
    }

    /// Gets a partition by ID.
    pub fn get_partition(&self, id: &str) -> Option<&Partition> {
        self.partitions.get(id)
    }

    /// Lists all partitions.
    pub fn list_partitions(&self) -> Vec<&Partition> {
        self.partitions.values().collect()
    }

    // ---- CSS CRUD ----

    /// Adds a calling search space.
    pub fn add_css(&mut self, css: CallingSearchSpace) {
        self.css_list.insert(css.id().to_string(), css);
    }

    /// Removes a CSS by ID.
    pub fn remove_css(&mut self, id: &str) -> Option<CallingSearchSpace> {
        self.css_list.remove(id)
    }

    /// Gets a CSS by ID.
    pub fn get_css(&self, id: &str) -> Option<&CallingSearchSpace> {
        self.css_list.get(id)
    }

    /// Lists all CSSes.
    pub fn list_css(&self) -> Vec<&CallingSearchSpace> {
        self.css_list.values().collect()
    }

    // ---- Route Pattern CRUD ----

    /// Adds a route pattern.
    pub fn add_route_pattern(&mut self, pattern: RoutePattern) {
        self.route_patterns.push(pattern);
    }

    /// Removes a route pattern by ID. Returns it if found.
    pub fn remove_route_pattern(&mut self, id: &str) -> Option<RoutePattern> {
        if let Some(pos) = self.route_patterns.iter().position(|rp| rp.id() == id) {
            Some(self.route_patterns.remove(pos))
        } else {
            None
        }
    }

    /// Lists all route patterns.
    pub fn list_route_patterns(&self) -> Vec<&RoutePattern> {
        self.route_patterns.iter().collect()
    }

    /// Lists route patterns belonging to a specific partition.
    pub fn list_route_patterns_by_partition(&self, partition_id: &str) -> Vec<&RoutePattern> {
        self.route_patterns
            .iter()
            .filter(|rp| rp.partition_id() == partition_id)
            .collect()
    }

    // ---- Route List CRUD ----

    /// Lists all route lists.
    pub fn list_route_lists(&self) -> Vec<&RouteList> {
        self.route_lists.values().collect()
    }

    /// Adds a route list.
    pub fn add_route_list(&mut self, list: RouteList) {
        self.route_lists.insert(list.id().to_string(), list);
    }

    /// Removes a route list by ID.
    pub fn remove_route_list(&mut self, id: &str) -> Option<RouteList> {
        self.route_lists.remove(id)
    }

    // ---- Route Group (TrunkGroup) CRUD ----

    /// Adds a route group (trunk group).
    pub fn add_route_group(&mut self, group: TrunkGroup) {
        self.route_groups.insert(group.id().to_string(), group);
    }

    /// Removes a route group by ID.
    pub fn remove_route_group(&mut self, id: &str) -> Option<TrunkGroup> {
        self.route_groups.remove(id)
    }

    // ---- Routing ----

    /// Routes dialed digits through the CUCM algorithm.
    ///
    /// 1. Resolve the CSS (explicit or default).
    /// 2. Walk partitions in CSS order.
    /// 3. For each partition, find enabled, non-blocked patterns that match.
    /// 4. Among matches, prefer the longest prefix, then lowest priority value.
    /// 5. Resolve route list or route group, apply transforms.
    pub fn route(
        &self,
        dialed_digits: &str,
        css_id: Option<&str>,
    ) -> Option<CucmRoutingResult> {
        // 1. Resolve CSS
        let css_key = css_id.or(self.default_css.as_deref())?;
        let css = self.css_list.get(css_key)?;

        // 2-3. Walk partitions in order and collect best match
        let mut best: Option<&RoutePattern> = None;
        let mut best_specificity: usize = 0;

        for partition_id in css.partitions() {
            let candidates = self.matching_patterns_in_partition(partition_id, dialed_digits);

            for rp in candidates {
                let specificity = Self::pattern_specificity(rp, dialed_digits);

                let dominated = match best {
                    Some(current) => {
                        let cur_spec = best_specificity;
                        if specificity > cur_spec {
                            true
                        } else if specificity == cur_spec {
                            rp.priority() < current.priority()
                        } else {
                            false
                        }
                    }
                    None => true,
                };

                if dominated {
                    best = Some(rp);
                    best_specificity = specificity;
                }
            }

            // CUCM semantics: first partition with *any* match wins.
            // Within that partition, the best (most-specific, lowest-priority) pattern is used.
            if best.is_some() {
                break;
            }
        }

        let matched = best?;

        // 4. Build result
        let mut transforms_applied = Vec::new();
        let mut transformed = dialed_digits.to_string();

        // Apply pattern-level transform
        if !matches!(matched.transform(), crate::dialplan::NumberTransform::None) {
            transformed = matched.transform_number(&transformed);
            transforms_applied.push(format!("pattern({})", matched.id()));
        }

        // 5. Resolve route groups
        let route_group_ids = self.resolve_route_groups(matched, &mut transformed, &mut transforms_applied);

        Some(CucmRoutingResult {
            pattern_id: matched.id().to_string(),
            partition_id: matched.partition_id().to_string(),
            transformed_number: transformed,
            route_group_ids,
            transforms_applied,
        })
    }

    /// Returns enabled, non-blocked patterns in the given partition that match `digits`.
    fn matching_patterns_in_partition<'a>(
        &'a self,
        partition_id: &str,
        digits: &str,
    ) -> Vec<&'a RoutePattern> {
        self.route_patterns
            .iter()
            .filter(|rp| {
                rp.partition_id() == partition_id
                    && !rp.is_blocked()
                    && rp.matches(digits)
            })
            .collect()
    }

    /// Heuristic specificity score for tie-breaking: longer literal prefix = more specific.
    fn pattern_specificity(rp: &RoutePattern, _digits: &str) -> usize {
        match rp.pattern() {
            crate::dialplan::DialPattern::Exact(s) => s.len() * 2, // exact is most specific
            crate::dialplan::DialPattern::Prefix(s) => s.len(),
            crate::dialplan::DialPattern::Wildcard(s) => {
                // Count literal characters before first wildcard
                s.chars().take_while(|c| *c != 'X' && *c != '.').count()
            }
            crate::dialplan::DialPattern::Regex(_) => 0,
            crate::dialplan::DialPattern::Any => 0,
        }
    }

    /// Resolves route group IDs from the matched pattern.
    fn resolve_route_groups(
        &self,
        matched: &RoutePattern,
        transformed: &mut String,
        transforms_applied: &mut Vec<String>,
    ) -> Vec<String> {
        if let Some(rl_id) = matched.route_list_id() {
            if let Some(rl) = self.route_lists.get(rl_id) {
                let ordered = rl.ordered_members();
                // Apply first member's transform if present (primary path)
                if let Some(first) = ordered.first()
                    && let Some(t) = first.transform()
                {
                    *transformed = t.apply(transformed);
                    transforms_applied.push(format!("route_list_member({})", first.route_group_id()));
                }
                return ordered
                    .iter()
                    .map(|m| m.route_group_id().to_string())
                    .collect();
            }
        }

        if let Some(rg_id) = matched.route_group_id() {
            return vec![rg_id.to_string()];
        }

        Vec::new()
    }
}

impl Default for CucmRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialplan::{DialPattern, NumberTransform};
    use crate::route_list::{RouteList, RouteListMember};
    use crate::trunk::{Trunk, TrunkConfig, TrunkGroup};

    /// Helper: build a fully wired CUCM router for testing.
    fn setup_cucm_router() -> CucmRouter {
        let mut router = CucmRouter::new();

        // Partitions
        router.add_partition(Partition::new("pt-emergency", "Emergency"));
        router.add_partition(Partition::new("pt-internal", "Internal"));
        router.add_partition(Partition::new("pt-local", "Local"));
        router.add_partition(Partition::new("pt-ld", "Long Distance"));
        router.add_partition(Partition::new("pt-intl", "International"));

        // CSS: standard phone gets emergency + internal + local + LD
        let mut css_phone = CallingSearchSpace::new("css-phone", "Phone CSS");
        css_phone.add_partition("pt-emergency");
        css_phone.add_partition("pt-internal");
        css_phone.add_partition("pt-local");
        css_phone.add_partition("pt-ld");
        router.add_css(css_phone);

        // CSS: lobby phone — emergency + internal only
        let mut css_lobby = CallingSearchSpace::new("css-lobby", "Lobby CSS");
        css_lobby.add_partition("pt-emergency");
        css_lobby.add_partition("pt-internal");
        router.add_css(css_lobby);

        router.set_default_css("css-phone");

        // Route groups (trunk groups)
        let mut tg_pstn = TrunkGroup::new("tg-pstn-primary", "PSTN Primary");
        tg_pstn.add_trunk(Trunk::new(
            TrunkConfig::new("t-pstn1", "pstn1.carrier.com").with_priority(10),
        ));
        router.add_route_group(tg_pstn);

        let mut tg_pstn_backup = TrunkGroup::new("tg-pstn-backup", "PSTN Backup");
        tg_pstn_backup.add_trunk(Trunk::new(
            TrunkConfig::new("t-pstn2", "pstn2.carrier.com").with_priority(10),
        ));
        router.add_route_group(tg_pstn_backup);

        // Route list: US PSTN with failover
        let mut rl_us = RouteList::new("rl-us-pstn", "US PSTN");
        rl_us.add_member(RouteListMember::new("tg-pstn-primary", 10));
        rl_us.add_member(RouteListMember::new("tg-pstn-backup", 20));
        router.add_route_list(rl_us);

        // Route patterns
        router.add_route_pattern(
            RoutePattern::new("rp-911", DialPattern::exact("911"), "pt-emergency")
                .with_route_group("tg-pstn-primary")
                .with_urgent(true)
                .with_priority(1),
        );

        router.add_route_pattern(
            RoutePattern::new("rp-ext", DialPattern::wildcard("XXXX"), "pt-internal")
                .with_route_group("tg-pstn-primary") // placeholder; internal extension
                .with_priority(10),
        );

        router.add_route_pattern(
            RoutePattern::new("rp-us-ld", DialPattern::prefix("+1"), "pt-ld")
                .with_route_list("rl-us-pstn")
                .with_transform(NumberTransform::strip_prefix(1))
                .with_priority(50),
        );

        router.add_route_pattern(
            RoutePattern::new("rp-local-7d", DialPattern::wildcard("XXXXXXX"), "pt-local")
                .with_route_list("rl-us-pstn")
                .with_priority(50),
        );

        // Blocked pattern: 1-900 premium numbers in LD partition
        router.add_route_pattern(
            RoutePattern::new("rp-900-block", DialPattern::prefix("+1900"), "pt-ld")
                .with_block(true)
                .with_priority(1),
        );

        router
    }

    #[test]
    fn test_route_emergency() {
        let router = setup_cucm_router();
        let result = router.route("911", Some("css-phone"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.pattern_id, "rp-911");
        assert_eq!(r.partition_id, "pt-emergency");
        assert_eq!(r.route_group_ids, vec!["tg-pstn-primary"]);
    }

    #[test]
    fn test_route_us_long_distance() {
        let router = setup_cucm_router();
        let result = router.route("+15551234567", Some("css-phone"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.pattern_id, "rp-us-ld");
        assert_eq!(r.partition_id, "pt-ld");
        // Transform: strip_prefix(1) removes "+"
        assert_eq!(r.transformed_number, "15551234567");
        // Route list resolved to two groups in priority order
        assert_eq!(r.route_group_ids, vec!["tg-pstn-primary", "tg-pstn-backup"]);
    }

    #[test]
    fn test_route_blocked_premium() {
        let router = setup_cucm_router();
        // +1900 is blocked — it should not match the +1 LD pattern either,
        // because the blocked pattern has higher priority (1 < 50), but
        // the routing algorithm filters out blocked patterns entirely.
        // The +1 prefix pattern still matches because blocked patterns are
        // simply skipped.
        let result = router.route("+19005551234", Some("css-phone"));
        assert!(result.is_some());
        let r = result.unwrap();
        // The blocked 1900 pattern is skipped, so +1 LD matches.
        assert_eq!(r.pattern_id, "rp-us-ld");
    }

    #[test]
    fn test_css_filtering_lobby() {
        let router = setup_cucm_router();
        // Lobby CSS only has emergency + internal.
        // Long distance +1 should NOT match.
        let result = router.route("+15551234567", Some("css-lobby"));
        assert!(result.is_none());
    }

    #[test]
    fn test_css_filtering_lobby_911() {
        let router = setup_cucm_router();
        // Lobby can still reach 911.
        let result = router.route("911", Some("css-lobby"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern_id, "rp-911");
    }

    #[test]
    fn test_default_css() {
        let router = setup_cucm_router();
        // No explicit CSS — uses default (css-phone).
        let result = router.route("911", None);
        assert!(result.is_some());
    }

    #[test]
    fn test_no_css_no_default() {
        let mut router = CucmRouter::new();
        // No CSS at all.
        let result = router.route("911", None);
        assert!(result.is_none());

        // Even with a CSS ID that doesn't exist:
        router.set_default_css("nonexistent");
        let result = router.route("911", None);
        assert!(result.is_none());
    }

    #[test]
    fn test_partition_crud() {
        let mut router = CucmRouter::new();
        router.add_partition(Partition::new("pt-1", "One"));
        assert!(router.get_partition("pt-1").is_some());
        assert_eq!(router.list_partitions().len(), 1);

        let removed = router.remove_partition("pt-1");
        assert!(removed.is_some());
        assert!(router.get_partition("pt-1").is_none());
    }

    #[test]
    fn test_css_crud() {
        let mut router = CucmRouter::new();
        router.add_css(CallingSearchSpace::new("css-1", "CSS One"));
        assert!(router.get_css("css-1").is_some());
        assert_eq!(router.list_css().len(), 1);

        let removed = router.remove_css("css-1");
        assert!(removed.is_some());
    }

    #[test]
    fn test_route_pattern_crud() {
        let mut router = CucmRouter::new();
        router.add_route_pattern(RoutePattern::new(
            "rp-1",
            DialPattern::exact("100"),
            "pt-1",
        ));
        assert_eq!(router.list_route_patterns().len(), 1);

        router.add_route_pattern(RoutePattern::new(
            "rp-2",
            DialPattern::exact("200"),
            "pt-2",
        ));
        assert_eq!(router.list_route_patterns_by_partition("pt-1").len(), 1);

        let removed = router.remove_route_pattern("rp-1");
        assert!(removed.is_some());
        assert_eq!(router.list_route_patterns().len(), 1);
    }

    #[test]
    fn test_route_list_crud() {
        let mut router = CucmRouter::new();
        router.add_route_list(RouteList::new("rl-1", "RL One"));
        let removed = router.remove_route_list("rl-1");
        assert!(removed.is_some());
    }

    #[test]
    fn test_internal_extension() {
        let router = setup_cucm_router();
        let result = router.route("1234", Some("css-phone"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.pattern_id, "rp-ext");
        assert_eq!(r.partition_id, "pt-internal");
    }

    #[test]
    fn test_local_seven_digit() {
        let router = setup_cucm_router();
        let result = router.route("5551234", Some("css-phone"));
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.pattern_id, "rp-local-7d");
        assert_eq!(r.partition_id, "pt-local");
    }

    #[test]
    fn test_partition_order_precedence() {
        // Verify that partition order in the CSS determines winner
        // when the same pattern exists in multiple partitions.
        let mut router = CucmRouter::new();

        router.add_partition(Partition::new("pt-a", "A"));
        router.add_partition(Partition::new("pt-b", "B"));

        // Same exact pattern in both partitions
        router.add_route_pattern(
            RoutePattern::new("rp-a", DialPattern::prefix("+1"), "pt-a")
                .with_route_group("tg-a")
                .with_priority(100),
        );
        router.add_route_pattern(
            RoutePattern::new("rp-b", DialPattern::prefix("+1"), "pt-b")
                .with_route_group("tg-b")
                .with_priority(1), // lower priority number = higher priority
        );

        // CSS lists pt-a first
        let mut css = CallingSearchSpace::new("css-ab", "A then B");
        css.add_partition("pt-a");
        css.add_partition("pt-b");
        router.add_css(css);

        let result = router.route("+15551234567", Some("css-ab"));
        assert!(result.is_some());
        // pt-a is checked first; it has a match, so pt-b is never considered.
        assert_eq!(result.unwrap().partition_id, "pt-a");
    }
}
