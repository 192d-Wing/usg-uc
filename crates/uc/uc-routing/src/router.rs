//! Call router.

use crate::dialplan::{DialPlan, DialPlanResult};
use crate::error::{RoutingError, RoutingResult};
use crate::trunk::{Admission, Trunk, TrunkGroup, TrunkOutcome};
use std::collections::HashMap;
use std::time::Duration;

/// Routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Dial plan result.
    pub dial_plan_result: Option<DialPlanResult>,
    /// Trunk group the selected trunk belongs to.
    pub trunk_group_id: String,
    /// Selected trunk ID. One call slot on this trunk is already reserved;
    /// release it with [`Router::release_trunk`].
    pub trunk_id: String,
    /// Trunk SIP URI.
    pub trunk_uri: String,
    /// Transformed destination number.
    pub destination: String,
    /// Failover trunk IDs in order (same trunk group as `trunk_id`).
    pub failover_trunks: Vec<String>,
    /// Failover targets as `(trunk_group_id, trunk_id)` in try order,
    /// capped at `max_failover_attempts`. Includes `failover_trunks` and,
    /// for [`Router::route_to_groups`], trunks of the later groups. Nothing
    /// is reserved on these; take one with [`Router::acquire_trunk`].
    pub failover_targets: Vec<(String, String)>,
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
    #[must_use]
    pub fn with_max_failover(mut self, max: usize) -> Self {
        self.max_failover_attempts = max;
        self
    }

    /// Sets whether to use dial plan.
    #[must_use]
    pub fn with_dial_plan(mut self, use_dp: bool) -> Self {
        self.use_dial_plan = use_dp;
        self
    }

    /// Sets the default trunk group.
    #[must_use]
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
    ///
    /// # Errors
    /// Returns an error if the operation fails.
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
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn route(&mut self, destination: &str) -> RoutingResult<RoutingDecision> {
        self.route_for(destination, Admission::Normal)
    }

    /// [`Self::route`] for a call admitted as `admission`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn route_for(
        &mut self,
        destination: &str,
        admission: Admission,
    ) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        let dial_plan_result = if self.config.use_dial_plan {
            self.match_dial_plan(destination)
        } else {
            None
        };

        let trunk_group_id = self.resolve_trunk_group(dial_plan_result.as_ref(), destination)?;
        let (trunk_id, trunk_uri, failover_trunks) =
            self.select_trunk_from_group(&trunk_group_id, admission)?;
        let failover_targets = failover_trunks
            .iter()
            .map(|t| (trunk_group_id.clone(), t.clone()))
            .collect();

        let final_destination = dial_plan_result
            .as_ref()
            .map_or_else(|| destination.to_string(), |r| r.transformed_number.clone());

        self.stats.successes += 1;
        if !failover_trunks.is_empty() {
            self.stats.failovers += 1;
        }

        Ok(RoutingDecision {
            dial_plan_result,
            trunk_group_id,
            trunk_id,
            trunk_uri,
            destination: final_destination,
            failover_trunks,
            failover_targets,
        })
    }

    /// Resolves the trunk group ID from dial plan result or default config.
    fn resolve_trunk_group(
        &self,
        dial_plan_result: Option<&DialPlanResult>,
        destination: &str,
    ) -> RoutingResult<String> {
        dial_plan_result
            .map(|r| r.trunk_group.as_str())
            .or(self.config.default_trunk_group.as_deref())
            .ok_or_else(|| RoutingError::NoRoute {
                destination: destination.to_string(),
            })
            .map(String::from)
    }

    /// Selects a trunk from the specified trunk group.
    /// Returns (trunk_id, trunk_uri, failover_trunks).
    fn select_trunk_from_group(
        &mut self,
        trunk_group_id: &str,
        admission: Admission,
    ) -> RoutingResult<(String, String, Vec<String>)> {
        let trunk_count = self
            .trunk_groups
            .get(trunk_group_id)
            .map_or(0, super::trunk::TrunkGroup::trunk_count);

        let trunk_group = self.trunk_groups.get_mut(trunk_group_id).ok_or_else(|| {
            RoutingError::TrunkGroupNotFound {
                group_id: trunk_group_id.to_string(),
            }
        })?;

        let trunk_id = trunk_group
            .select_trunk_for(admission)
            .map(String::from)
            .ok_or(RoutingError::AllTrunksFailed {
                trunks_tried: trunk_count,
            })?;

        let failover_trunks: Vec<String> = trunk_group
            .failover_order_for(admission)
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

        // Reserve the slot in the same `&mut self` as the selection so two
        // concurrent routes cannot both take the last slot (SC-5).
        // POAM: the trunk `max_calls` reservation is counted per node only; in a cluster of N nodes the
        // effective limit is N x the configured cap. Cluster-wide accounting is a
        // follow-up via uc-state-sync.
        if let Some(t) = trunk_group.get_trunk_mut(&trunk_id) {
            t.start_call();
        }

        Ok((trunk_id, trunk_uri, failover_trunks))
    }

    /// Routes directly to a specific trunk group. Reserves a call slot on
    /// the selected trunk (see [`RoutingDecision::trunk_id`]).
    ///
    /// # Errors
    /// Returns an error if the group does not exist or has no usable trunk.
    pub fn route_to_group(
        &mut self,
        destination: &str,
        group_id: &str,
    ) -> RoutingResult<RoutingDecision> {
        self.route_to_group_for(destination, group_id, Admission::Normal)
    }

    /// [`Self::route_to_group`] for a call admitted as `admission`.
    ///
    /// # Errors
    /// Returns an error if the group does not exist or has no usable trunk.
    pub fn route_to_group_for(
        &mut self,
        destination: &str,
        group_id: &str,
        admission: Admission,
    ) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        let (trunk_id, trunk_uri, failover_trunks) =
            self.select_trunk_from_group(group_id, admission)?;
        let failover_targets = failover_trunks
            .iter()
            .map(|t| (group_id.to_string(), t.clone()))
            .collect();

        self.stats.successes += 1;

        Ok(RoutingDecision {
            dial_plan_result: None,
            trunk_group_id: group_id.to_string(),
            trunk_id,
            trunk_uri,
            destination: destination.to_string(),
            failover_trunks,
            failover_targets,
        })
    }

    /// Routes to the first of an ordered list of trunk groups (an SBC route
    /// list's route groups) that has a usable trunk, reserving a slot on it.
    /// Usable trunks of the remaining groups follow the selected group's
    /// own failover trunks in `failover_targets`.
    ///
    /// # Errors
    /// Returns [`RoutingError::NoRoute`] for an empty list and
    /// [`RoutingError::AllTrunksFailed`] when no group has a usable trunk.
    pub fn route_to_groups(
        &mut self,
        destination: &str,
        group_ids: &[String],
    ) -> RoutingResult<RoutingDecision> {
        self.route_to_groups_for(destination, group_ids, Admission::Normal)
    }

    /// [`Self::route_to_groups`] for a call admitted as `admission`.
    ///
    /// # Errors
    /// As [`Self::route_to_groups`].
    pub fn route_to_groups_for(
        &mut self,
        destination: &str,
        group_ids: &[String],
        admission: Admission,
    ) -> RoutingResult<RoutingDecision> {
        if group_ids.is_empty() {
            return Err(RoutingError::NoRoute {
                destination: destination.to_string(),
            });
        }
        let mut tried = 0usize;
        for (idx, group_id) in group_ids.iter().enumerate() {
            tried += self
                .trunk_groups
                .get(group_id.as_str())
                .map_or(0, TrunkGroup::trunk_count);
            let Ok(mut decision) = self.route_to_group_for(destination, group_id, admission) else {
                continue;
            };
            let max = self.config.max_failover_attempts;
            for later in group_ids.iter().skip(idx + 1) {
                if decision.failover_targets.len() >= max {
                    break;
                }
                if later == group_id {
                    continue;
                }
                if let Some(group) = self.trunk_groups.get(later.as_str()) {
                    for t in group.failover_order_for(admission) {
                        if decision.failover_targets.len() >= max {
                            break;
                        }
                        decision
                            .failover_targets
                            .push((later.clone(), t.to_string()));
                    }
                }
            }
            return Ok(decision);
        }
        Err(RoutingError::AllTrunksFailed {
            trunks_tried: tried,
        })
    }

    /// Reserves a call slot on a specific trunk if it is still usable
    /// (enabled, reachable, not in cooldown, below `max_calls`). Returns the
    /// trunk's SIP URI, or `None` when it cannot take the call.
    pub fn acquire_trunk(&mut self, group_id: &str, trunk_id: &str) -> Option<String> {
        self.acquire_trunk_for(group_id, trunk_id, Admission::Normal)
    }

    /// [`Self::acquire_trunk`] for a call admitted as `admission`.
    pub fn acquire_trunk_for(
        &mut self,
        group_id: &str,
        trunk_id: &str,
        admission: Admission,
    ) -> Option<String> {
        let trunk = self
            .trunk_groups
            .get_mut(group_id)
            .and_then(|g| g.get_trunk_mut(trunk_id))?;
        if !trunk.is_usable_for(admission) {
            return None;
        }
        // POAM: the trunk `max_calls` reservation is counted per node only; in a cluster of N nodes the
        // effective limit is N x the configured cap. Cluster-wide accounting is a
        // follow-up via uc-state-sync.
        trunk.start_call();
        Some(trunk.sip_uri())
    }

    /// Releases a slot taken by routing or [`Self::acquire_trunk`]. Call
    /// exactly once per reservation. Unknown group/trunk IDs (removed at
    /// runtime) are ignored.
    pub fn release_trunk(&mut self, group_id: &str, trunk_id: &str, outcome: TrunkOutcome) {
        if let Some(trunk) = self
            .trunk_groups
            .get_mut(group_id)
            .and_then(|g| g.get_trunk_mut(trunk_id))
        {
            trunk.end_call(outcome);
        }
    }

    /// Puts a trunk into cooldown immediately (e.g. it answered 503), for
    /// `duration` (the trunk's `Retry-After`, RFC 3261 §21.5.4) or the
    /// trunk's `cooldown_secs` when `None`. The caller bounds `duration`.
    pub fn cooldown_trunk(&mut self, group_id: &str, trunk_id: &str, duration: Option<Duration>) {
        if let Some(trunk) = self
            .trunk_groups
            .get_mut(group_id)
            .and_then(|g| g.get_trunk_mut(trunk_id))
        {
            match duration {
                Some(d) => trunk.start_cooldown_for(d),
                None => trunk.start_cooldown(),
            }
        }
    }

    /// Whether any trunk group holds a trunk with this ID.
    pub fn has_trunk(&self, trunk_id: &str) -> bool {
        self.trunk_groups
            .values()
            .any(|g| g.get_trunk(trunk_id).is_some())
    }

    /// Applies an OPTIONS-ping reachability result to every trunk with this
    /// ID, in every group. Returns how many trunks were updated.
    pub fn set_trunk_reachable(&mut self, trunk_id: &str, reachable: bool) -> usize {
        let mut n = 0;
        for group in self.trunk_groups.values_mut() {
            if let Some(trunk) = group.get_trunk_mut(trunk_id) {
                trunk.set_reachable(reachable);
                n += 1;
            }
        }
        n
    }

    /// Active (reserved) call count on a trunk, if it exists.
    pub fn trunk_active_calls(&self, group_id: &str, trunk_id: &str) -> Option<u32> {
        self.trunk_groups
            .get(group_id)
            .and_then(|g| g.get_trunk(trunk_id))
            .map(|t| t.stats().active_calls)
    }

    /// Matches against the active dial plan.
    fn match_dial_plan(&self, destination: &str) -> Option<DialPlanResult> {
        self.active_dial_plan()
            .and_then(|plan| plan.match_number(destination))
    }

    /// Records a successful call on a trunk.
    pub fn record_success(&mut self, group_id: &str, trunk_id: &str, setup_time_ms: u64) {
        if let Some(group) = self.trunk_groups.get_mut(group_id)
            && let Some(trunk) = group.get_trunk_mut(trunk_id)
        {
            trunk.complete_call(setup_time_ms);
        }
    }

    /// Records a failed call on a trunk.
    pub fn record_failure(&mut self, group_id: &str, trunk_id: &str) {
        if let Some(group) = self.trunk_groups.get_mut(group_id)
            && let Some(trunk) = group.get_trunk_mut(trunk_id)
        {
            trunk.fail_call();
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
#[allow(clippy::similar_names)]
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
        assert_ne!(decision.failover_trunks, Vec::<String>::new());
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
            trunk_group_id: "g".to_string(),
            trunk_id: "trunk-1".to_string(),
            trunk_uri: "sips:example.com:5061".to_string(),
            destination: "+15551234567".to_string(),
            failover_trunks: vec!["trunk-2".to_string()],
            failover_targets: vec![("g".to_string(), "trunk-2".to_string())],
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

    #[test]
    fn test_route_reserves_and_release_returns_to_zero() {
        let mut router = setup_test_router();
        let d = router.route("+15551234567").unwrap();
        assert_eq!(d.trunk_group_id, "us-trunks");
        assert_eq!(router.trunk_active_calls("us-trunks", "us-1"), Some(1));
        assert_eq!(
            d.failover_targets,
            vec![("us-trunks".to_string(), "us-2".to_string())]
        );
        for outcome in [
            TrunkOutcome::Completed { setup_ms: 10 },
            TrunkOutcome::Failed,
            TrunkOutcome::Abandoned,
        ] {
            assert_eq!(router.trunk_active_calls("us-trunks", "us-1"), Some(1));
            router.release_trunk("us-trunks", "us-1", outcome);
            assert_eq!(router.trunk_active_calls("us-trunks", "us-1"), Some(0));
            router.route("+15551234567").unwrap();
        }
        router.release_trunk("us-trunks", "us-1", TrunkOutcome::Abandoned);
        router.release_trunk("us-trunks", "us-1", TrunkOutcome::Abandoned);
        assert_eq!(router.trunk_active_calls("us-trunks", "us-1"), Some(0));
    }

    #[test]
    fn test_route_skips_full_trunk_then_errors_when_all_full() {
        let mut router = Router::new(
            RouterConfig::default()
                .with_dial_plan(false)
                .with_default_trunk_group("g"),
        );
        let mut group = TrunkGroup::new("g", "G");
        group.add_trunk(Trunk::new(
            TrunkConfig::new("a", "a.example.com")
                .with_priority(1)
                .with_max_calls(1),
        ));
        group.add_trunk(Trunk::new(
            TrunkConfig::new("b", "b.example.com")
                .with_priority(2)
                .with_max_calls(1),
        ));
        router.add_trunk_group(group);

        assert_eq!(router.route("1").unwrap().trunk_id, "a");
        assert_eq!(router.route("1").unwrap().trunk_id, "b");
        assert!(matches!(
            router.route("1"),
            Err(RoutingError::AllTrunksFailed { .. })
        ));
        router.release_trunk("g", "a", TrunkOutcome::Abandoned);
        assert_eq!(router.route("1").unwrap().trunk_id, "a");
    }

    #[test]
    fn test_acquire_trunk_respects_usability() {
        let mut router = setup_test_router();
        assert!(router.acquire_trunk("us-trunks", "us-2").is_some());
        assert_eq!(router.trunk_active_calls("us-trunks", "us-2"), Some(1));
        router.set_trunk_reachable("us-2", false);
        assert!(router.acquire_trunk("us-trunks", "us-2").is_none());
        assert!(router.acquire_trunk("us-trunks", "missing").is_none());
        assert!(router.acquire_trunk("missing", "us-2").is_none());
    }

    #[test]
    fn test_set_trunk_reachable_excludes_trunk_from_selection() {
        let mut router = setup_test_router();
        assert!(router.has_trunk("us-1"));
        assert!(!router.has_trunk("no-such-trunk"));
        assert_eq!(router.set_trunk_reachable("no-such-trunk", false), 0);
        assert_eq!(router.set_trunk_reachable("us-1", false), 1);
        let d = router.route("+15551234567").unwrap();
        assert_eq!(d.trunk_id, "us-2");
        assert_eq!(d.failover_trunks, Vec::<String>::new());
        router.release_trunk("us-trunks", "us-2", TrunkOutcome::Abandoned);

        router.set_trunk_reachable("us-1", true);
        assert_eq!(router.route("+15551234567").unwrap().trunk_id, "us-1");
    }

    #[test]
    fn test_route_to_groups_falls_through_and_lists_later_groups() {
        let mut router = setup_test_router();
        router.set_trunk_reachable("uk-1", false);
        let groups = vec!["uk-trunks".to_string(), "us-trunks".to_string()];
        let d = router.route_to_groups("+15551234567", &groups).unwrap();
        assert_eq!(d.trunk_group_id, "us-trunks");
        assert_eq!(d.trunk_id, "us-1");

        router.set_trunk_reachable("uk-1", true);
        let d = router.route_to_groups("+15551234567", &groups).unwrap();
        assert_eq!(d.trunk_id, "uk-1");
        assert_eq!(
            d.failover_targets,
            vec![
                ("us-trunks".to_string(), "us-1".to_string()),
                ("us-trunks".to_string(), "us-2".to_string()),
            ]
        );

        assert!(router.route_to_groups("x", &[]).is_err());
        router.set_trunk_reachable("uk-1", false);
        router.set_trunk_reachable("us-1", false);
        router.set_trunk_reachable("us-2", false);
        assert!(matches!(
            router.route_to_groups("x", &groups),
            Err(RoutingError::AllTrunksFailed { .. })
        ));
    }

    #[test]
    fn test_cooldown_trunk() {
        let mut router = setup_test_router();
        router.cooldown_trunk("us-trunks", "us-1", None);
        assert_eq!(router.route("+15551234567").unwrap().trunk_id, "us-2");
    }

    #[test]
    fn cooldown_trunk_override_duration() {
        let mut router = setup_test_router();
        let before = std::time::Instant::now();
        router.cooldown_trunk("us-trunks", "us-1", Some(Duration::from_secs(120)));
        let trunk = router
            .get_trunk_group("us-trunks")
            .and_then(|g| g.get_trunk("us-1"))
            .unwrap();
        let until = trunk.cooldown_until().unwrap();
        assert!(until >= before + Duration::from_secs(120));
        assert!(until < before + Duration::from_secs(121));
        assert_eq!(router.route("+15551234567").unwrap().trunk_id, "us-2");
        // Unknown IDs are ignored.
        router.cooldown_trunk("missing", "us-1", Some(Duration::from_secs(1)));
    }

    #[test]
    fn emergency_admission_routes_past_max_calls_but_not_cooldown() {
        let mut router = Router::new(
            RouterConfig::default()
                .with_dial_plan(false)
                .with_default_trunk_group("g"),
        );
        let mut group = TrunkGroup::new("g", "G");
        group.add_trunk(Trunk::new(
            TrunkConfig::new("a", "a.example.com")
                .with_priority(1)
                .with_max_calls(1)
                .with_emergency_reserve_calls(3),
        ));
        group.add_trunk(Trunk::new(
            TrunkConfig::new("b", "b.example.com")
                .with_priority(2)
                .with_max_calls(1)
                .with_emergency_reserve_calls(3),
        ));
        router.add_trunk_group(group);
        router.route("1").unwrap();
        router.route("1").unwrap();
        assert!(router.route("1").is_err());

        let d = router.route_for("911", Admission::Emergency).unwrap();
        assert_eq!(d.trunk_id, "a");
        assert_eq!(d.failover_targets, vec![("g".to_string(), "b".to_string())]);
        assert_eq!(router.trunk_active_calls("g", "a"), Some(2));
        assert!(router.acquire_trunk("g", "b").is_none());
        assert!(
            router
                .acquire_trunk_for("g", "b", Admission::Emergency)
                .is_some()
        );
        let groups = vec!["g".to_string()];
        assert!(router.route_to_groups("911", &groups).is_err());
        assert!(
            router
                .route_to_groups_for("911", &groups, Admission::Emergency)
                .is_ok()
        );

        router.cooldown_trunk("g", "a", None);
        router.cooldown_trunk("g", "b", None);
        assert!(matches!(
            router.route_for("911", Admission::Emergency),
            Err(RoutingError::AllTrunksFailed { .. })
        ));
    }
}
