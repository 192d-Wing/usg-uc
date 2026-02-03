//! Call router.

use crate::dialplan::{DialPlan, DialPlanResult};
use crate::error::{RoutingError, RoutingResult};
use crate::trunk::{Trunk, TrunkGroup};
use std::collections::HashMap;

/// Routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Dial plan result.
    pub dial_plan_result: Option<DialPlanResult>,
    /// Selected trunk ID.
    pub trunk_id: String,
    /// Trunk SIP URI.
    pub trunk_uri: String,
    /// Transformed destination number.
    pub destination: String,
    /// Failover trunk IDs in order.
    pub failover_trunks: Vec<String>,
}

impl RoutingDecision {
    /// Returns whether there are failover options.
    pub fn has_failover(&self) -> bool {
        !self.failover_trunks.is_empty()
    }
}

/// Router configuration.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum failover attempts.
    pub max_failover_attempts: usize,
    /// Whether to use dial plan.
    pub use_dial_plan: bool,
    /// Default trunk group.
    pub default_trunk_group: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            max_failover_attempts: 3,
            use_dial_plan: true,
            default_trunk_group: None,
        }
    }
}

impl RouterConfig {
    /// Sets the maximum failover attempts.
    pub fn with_max_failover(mut self, max: usize) -> Self {
        self.max_failover_attempts = max;
        self
    }

    /// Sets whether to use dial plan.
    pub fn with_dial_plan(mut self, use_dp: bool) -> Self {
        self.use_dial_plan = use_dp;
        self
    }

    /// Sets the default trunk group.
    pub fn with_default_trunk_group(mut self, group: impl Into<String>) -> Self {
        self.default_trunk_group = Some(group.into());
        self
    }
}

/// Router statistics.
#[derive(Debug, Clone, Default)]
pub struct RouterStats {
    /// Total routing requests.
    pub requests: u64,
    /// Successful routes.
    pub successes: u64,
    /// Failed routes (no route found).
    pub no_route: u64,
    /// Routes requiring failover.
    pub failovers: u64,
}

/// Call router.
#[derive(Debug)]
pub struct Router {
    /// Configuration.
    config: RouterConfig,
    /// Dial plans.
    dial_plans: HashMap<String, DialPlan>,
    /// Active dial plan ID.
    active_dial_plan: Option<String>,
    /// Trunk groups.
    trunk_groups: HashMap<String, TrunkGroup>,
    /// Statistics.
    stats: RouterStats,
}

impl Router {
    /// Creates a new router.
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config,
            dial_plans: HashMap::new(),
            active_dial_plan: None,
            trunk_groups: HashMap::new(),
            stats: RouterStats::default(),
        }
    }

    /// Creates a router with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RouterConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &RouterStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats = RouterStats::default();
    }

    /// Adds a dial plan.
    pub fn add_dial_plan(&mut self, plan: DialPlan) {
        let id = plan.id().to_string();
        if self.active_dial_plan.is_none() {
            self.active_dial_plan = Some(id.clone());
        }
        self.dial_plans.insert(id, plan);
    }

    /// Removes a dial plan.
    pub fn remove_dial_plan(&mut self, id: &str) -> Option<DialPlan> {
        let plan = self.dial_plans.remove(id);
        if self.active_dial_plan.as_deref() == Some(id) {
            self.active_dial_plan = self.dial_plans.keys().next().cloned();
        }
        plan
    }

    /// Gets a dial plan.
    pub fn get_dial_plan(&self, id: &str) -> Option<&DialPlan> {
        self.dial_plans.get(id)
    }

    /// Sets the active dial plan.
    pub fn set_active_dial_plan(&mut self, id: &str) -> RoutingResult<()> {
        if self.dial_plans.contains_key(id) {
            self.active_dial_plan = Some(id.to_string());
            Ok(())
        } else {
            Err(RoutingError::DialPlanNotFound {
                plan_id: id.to_string(),
            })
        }
    }

    /// Returns the active dial plan.
    pub fn active_dial_plan(&self) -> Option<&DialPlan> {
        self.active_dial_plan
            .as_ref()
            .and_then(|id| self.dial_plans.get(id))
    }

    /// Adds a trunk group.
    pub fn add_trunk_group(&mut self, group: TrunkGroup) {
        self.trunk_groups.insert(group.id().to_string(), group);
    }

    /// Removes a trunk group.
    pub fn remove_trunk_group(&mut self, id: &str) -> Option<TrunkGroup> {
        self.trunk_groups.remove(id)
    }

    /// Gets a trunk group.
    pub fn get_trunk_group(&self, id: &str) -> Option<&TrunkGroup> {
        self.trunk_groups.get(id)
    }

    /// Gets a mutable trunk group.
    pub fn get_trunk_group_mut(&mut self, id: &str) -> Option<&mut TrunkGroup> {
        self.trunk_groups.get_mut(id)
    }

    /// Routes a call to the given destination.
    pub fn route(&mut self, destination: &str) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        // First, try dial plan if enabled
        let dial_plan_result = if self.config.use_dial_plan {
            self.match_dial_plan(destination)
        } else {
            None
        };

        // Determine trunk group
        let trunk_group_id = dial_plan_result
            .as_ref()
            .map(|r| r.trunk_group.as_str())
            .or(self.config.default_trunk_group.as_deref())
            .ok_or_else(|| RoutingError::NoRoute {
                destination: destination.to_string(),
            })?
            .to_string();

        // Get trunk count for error message before mutable borrow
        let trunk_count = self
            .trunk_groups
            .get(&trunk_group_id)
            .map(|g| g.trunk_count())
            .unwrap_or(0);

        // Get the trunk group
        let trunk_group = self.trunk_groups.get_mut(&trunk_group_id).ok_or_else(|| {
            RoutingError::TrunkGroupNotFound {
                group_id: trunk_group_id.clone(),
            }
        })?;

        // Select a trunk
        let trunk_id =
            trunk_group
                .select_trunk()
                .map(String::from)
                .ok_or(RoutingError::AllTrunksFailed {
                    trunks_tried: trunk_count,
                })?;

        // Get failover trunks
        let failover_trunks: Vec<String> = trunk_group
            .failover_order()
            .into_iter()
            .filter(|id| *id != trunk_id)
            .take(self.config.max_failover_attempts)
            .map(String::from)
            .collect();

        // Get trunk details
        let trunk =
            trunk_group
                .get_trunk(&trunk_id)
                .ok_or_else(|| RoutingError::TrunkNotFound {
                    trunk_id: trunk_id.clone(),
                })?;

        let trunk_uri = trunk.sip_uri();

        // Determine final destination
        let final_destination = dial_plan_result
            .as_ref()
            .map(|r| r.transformed_number.clone())
            .unwrap_or_else(|| destination.to_string());

        self.stats.successes += 1;
        if !failover_trunks.is_empty() {
            self.stats.failovers += 1;
        }

        Ok(RoutingDecision {
            dial_plan_result,
            trunk_id,
            trunk_uri,
            destination: final_destination,
            failover_trunks,
        })
    }

    /// Routes directly to a specific trunk group.
    pub fn route_to_group(
        &mut self,
        destination: &str,
        group_id: &str,
    ) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        // Get trunk count for error message before mutable borrow
        let trunk_count = self
            .trunk_groups
            .get(group_id)
            .map(|g| g.trunk_count())
            .unwrap_or(0);

        let trunk_group = self.trunk_groups.get_mut(group_id).ok_or_else(|| {
            RoutingError::TrunkGroupNotFound {
                group_id: group_id.to_string(),
            }
        })?;

        let trunk_id =
            trunk_group
                .select_trunk()
                .map(String::from)
                .ok_or(RoutingError::AllTrunksFailed {
                    trunks_tried: trunk_count,
                })?;

        let failover_trunks: Vec<String> = trunk_group
            .failover_order()
            .into_iter()
            .filter(|id| *id != trunk_id)
            .take(self.config.max_failover_attempts)
            .map(String::from)
            .collect();

        let trunk =
            trunk_group
                .get_trunk(&trunk_id)
                .ok_or_else(|| RoutingError::TrunkNotFound {
                    trunk_id: trunk_id.clone(),
                })?;

        let trunk_uri = trunk.sip_uri();

        self.stats.successes += 1;

        Ok(RoutingDecision {
            dial_plan_result: None,
            trunk_id,
            trunk_uri,
            destination: destination.to_string(),
            failover_trunks,
        })
    }

    /// Matches against the active dial plan.
    fn match_dial_plan(&self, destination: &str) -> Option<DialPlanResult> {
        self.active_dial_plan()
            .and_then(|plan| plan.match_number(destination))
    }

    /// Records a successful call on a trunk.
    pub fn record_success(&mut self, group_id: &str, trunk_id: &str, setup_time_ms: u64) {
        if let Some(group) = self.trunk_groups.get_mut(group_id) {
            if let Some(trunk) = group.get_trunk_mut(trunk_id) {
                trunk.complete_call(setup_time_ms);
            }
        }
    }

    /// Records a failed call on a trunk.
    pub fn record_failure(&mut self, group_id: &str, trunk_id: &str) {
        if let Some(group) = self.trunk_groups.get_mut(group_id) {
            if let Some(trunk) = group.get_trunk_mut(trunk_id) {
                trunk.fail_call();
            }
        }
    }

    /// Returns a trunk for a failover attempt.
    pub fn get_failover_trunk(&self, group_id: &str, trunk_id: &str) -> Option<&Trunk> {
        self.trunk_groups
            .get(group_id)
            .and_then(|g| g.get_trunk(trunk_id))
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialplan::{DialPattern, DialPlanEntry, NumberTransform};
    use crate::trunk::{Trunk, TrunkConfig};

    fn setup_test_router() -> Router {
        let mut router = Router::with_defaults();

        // Create dial plan
        let mut plan = DialPlan::new("default", "Default Plan");
        plan.add_entry(DialPlanEntry::new(
            "us",
            DialPattern::prefix("+1"),
            "us-trunks",
        ));
        plan.add_entry(DialPlanEntry::new(
            "uk",
            DialPattern::prefix("+44"),
            "uk-trunks",
        ));
        router.add_dial_plan(plan);

        // Create trunk groups
        let mut us_group = TrunkGroup::new("us-trunks", "US Trunks");
        us_group.add_trunk(Trunk::new(
            TrunkConfig::new("us-1", "us1.example.com").with_priority(100),
        ));
        us_group.add_trunk(Trunk::new(
            TrunkConfig::new("us-2", "us2.example.com").with_priority(200),
        ));
        router.add_trunk_group(us_group);

        let mut uk_group = TrunkGroup::new("uk-trunks", "UK Trunks");
        uk_group.add_trunk(Trunk::new(TrunkConfig::new("uk-1", "uk1.example.com")));
        router.add_trunk_group(uk_group);

        router
    }

    #[test]
    fn test_router_creation() {
        let router = Router::with_defaults();
        assert!(router.active_dial_plan().is_none());
    }

    #[test]
    fn test_router_add_dial_plan() {
        let mut router = Router::with_defaults();
        let plan = DialPlan::new("test", "Test Plan");
        router.add_dial_plan(plan);

        assert!(router.active_dial_plan().is_some());
        assert_eq!(router.active_dial_plan().unwrap().id(), "test");
    }

    #[test]
    fn test_router_route_us() {
        let mut router = setup_test_router();

        let decision = router.route("+15551234567").unwrap();
        assert_eq!(decision.trunk_id, "us-1"); // Highest priority
        assert!(decision.dial_plan_result.is_some());
        assert_eq!(decision.destination, "+15551234567");
    }

    #[test]
    fn test_router_route_uk() {
        let mut router = setup_test_router();

        let decision = router.route("+445551234567").unwrap();
        assert_eq!(decision.trunk_id, "uk-1");
    }

    #[test]
    fn test_router_failover() {
        let mut router = setup_test_router();

        let decision = router.route("+15551234567").unwrap();
        assert!(decision.has_failover());
        assert!(!decision.failover_trunks.is_empty());
        // us-2 should be in failover list
        assert!(decision.failover_trunks.contains(&"us-2".to_string()));
    }

    #[test]
    fn test_router_no_route() {
        let mut router = setup_test_router();

        let result = router.route("+335551234567"); // French number
        assert!(result.is_err());
    }

    #[test]
    fn test_router_with_default_trunk() {
        let config = RouterConfig::default()
            .with_dial_plan(false)
            .with_default_trunk_group("us-trunks");
        let mut router = Router::new(config);

        let mut group = TrunkGroup::new("us-trunks", "US Trunks");
        group.add_trunk(Trunk::new(TrunkConfig::new("trunk-1", "example.com")));
        router.add_trunk_group(group);

        let decision = router.route("anything").unwrap();
        assert_eq!(decision.trunk_id, "trunk-1");
    }

    #[test]
    fn test_router_route_to_group() {
        let mut router = setup_test_router();

        let decision = router.route_to_group("+15551234567", "uk-trunks").unwrap();
        assert_eq!(decision.trunk_id, "uk-1"); // Routes to UK despite US prefix
    }

    #[test]
    fn test_router_record_success() {
        let mut router = setup_test_router();

        router.record_success("us-trunks", "us-1", 100);

        let trunk = router
            .get_trunk_group("us-trunks")
            .unwrap()
            .get_trunk("us-1")
            .unwrap();
        assert_eq!(trunk.stats().calls_succeeded, 1);
    }

    #[test]
    fn test_router_record_failure() {
        let mut router = setup_test_router();

        router.record_failure("us-trunks", "us-1");

        let trunk = router
            .get_trunk_group("us-trunks")
            .unwrap()
            .get_trunk("us-1")
            .unwrap();
        assert_eq!(trunk.stats().calls_failed, 1);
    }

    #[test]
    fn test_router_stats() {
        let mut router = setup_test_router();

        router.route("+15551234567").unwrap();
        router.route("+445551234567").unwrap();

        assert_eq!(router.stats().requests, 2);
        assert_eq!(router.stats().successes, 2);
    }

    #[test]
    fn test_router_set_active_dial_plan() {
        let mut router = Router::with_defaults();

        router.add_dial_plan(DialPlan::new("plan-1", "Plan 1"));
        router.add_dial_plan(DialPlan::new("plan-2", "Plan 2"));

        router.set_active_dial_plan("plan-2").unwrap();
        assert_eq!(router.active_dial_plan().unwrap().id(), "plan-2");
    }

    #[test]
    fn test_router_dial_plan_not_found() {
        let mut router = Router::with_defaults();

        let result = router.set_active_dial_plan("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_routing_decision() {
        let decision = RoutingDecision {
            dial_plan_result: None,
            trunk_id: "trunk-1".to_string(),
            trunk_uri: "sips:example.com:5061".to_string(),
            destination: "+15551234567".to_string(),
            failover_trunks: vec!["trunk-2".to_string()],
        };

        assert!(decision.has_failover());
    }

    #[test]
    fn test_router_with_transform() {
        let mut router = Router::with_defaults();

        let mut plan = DialPlan::new("default", "Default");
        plan.add_entry(
            DialPlanEntry::new("us", DialPattern::prefix("+1"), "us-trunks")
                .with_transform(NumberTransform::replace_prefix("+1", "1")),
        );
        router.add_dial_plan(plan);

        let mut group = TrunkGroup::new("us-trunks", "US");
        group.add_trunk(Trunk::new(TrunkConfig::new("t1", "example.com")));
        router.add_trunk_group(group);

        let decision = router.route("+15551234567").unwrap();
        assert_eq!(decision.destination, "15551234567"); // + stripped
    }
}
