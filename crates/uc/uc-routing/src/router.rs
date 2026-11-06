//! Call router.

use crate::dialplan::{DialPlan, DialPlanResult, Direction};
use crate::error::{RoutingError, RoutingResult};
use crate::trunk::{Admission, Trunk, TrunkGroup, TrunkOutcome};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Per-call routing context for [`Router::route_call`].
#[derive(Debug, Clone, Copy)]
pub struct CallRouteContext<'a> {
    /// Canonical dialled number (routing key).
    pub destination: &'a str,
    /// Request-URI host, matched against entry `domain_pattern`
    /// (case-insensitive, RFC 3261 §19.1.4).
    pub domain: &'a str,
    /// Call direction: [`Direction::Inbound`] when the call came from a
    /// configured trunk, else [`Direction::Outbound`].
    pub direction: Direction,
    /// Trunk-group id the call arrived on, matched against entry
    /// `source_trunk`.
    pub source_trunk_group: Option<&'a str>,
}

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

/// `require_tls` policy counters (NIST 800-53 Rev5: SI-4, SC-8).
///
/// Shared through an [`Arc`] so a metrics scrape never takes the router lock.
/// Unlabelled counters: no cardinality from attacker-controlled data (SC-5).
#[derive(Debug, Default)]
pub struct TlsPolicyCounters {
    /// Non-TLS trunks excluded by policy (summed per routing decision and per
    /// refused failover acquisition).
    skips: AtomicU64,
    /// Calls refused because a `require_tls` group had no usable TLS trunk
    /// while a usable non-TLS trunk existed.
    rejects: AtomicU64,
}

impl TlsPolicyCounters {
    /// `routing_tls_required_skips`.
    pub fn skips(&self) -> u64 {
        self.skips.load(Ordering::Relaxed)
    }

    /// `routing_tls_required_rejects`.
    pub fn rejects(&self) -> u64 {
        self.rejects.load(Ordering::Relaxed)
    }
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
    /// Global `security.require_tls_trunks`: ORed into every group added.
    require_tls_default: bool,
    /// `require_tls` policy counters.
    tls_counters: Arc<TlsPolicyCounters>,
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
            require_tls_default: false,
            tls_counters: Arc::new(TlsPolicyCounters::default()),
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

    /// Sets the global TLS-only default (`security.require_tls_trunks`).
    ///
    /// NIST 800-53 Rev5: SC-8 — applies to groups added after the call and to
    /// groups already present. A group cannot opt out while it is set.
    pub fn set_require_tls_default(&mut self, require_tls: bool) {
        self.require_tls_default = require_tls;
        if require_tls {
            for group in self.trunk_groups.values_mut() {
                group.set_require_tls(true);
            }
        }
    }

    /// Returns the global TLS-only default.
    pub fn require_tls_default(&self) -> bool {
        self.require_tls_default
    }

    /// `(skips, rejects)` snapshot of the `require_tls` policy counters.
    pub fn tls_policy_counters(&self) -> (u64, u64) {
        (self.tls_counters.skips(), self.tls_counters.rejects())
    }

    /// Replaces the counter handle so a router rebuilt by its owner keeps
    /// counting into the same (already exported) counters.
    pub fn set_tls_policy_counters(&mut self, counters: Arc<TlsPolicyCounters>) {
        self.tls_counters = counters;
    }

    /// Shared handle to the `require_tls` counters (for lock-free scrapes).
    pub fn tls_policy_counters_handle(&self) -> Arc<TlsPolicyCounters> {
        Arc::clone(&self.tls_counters)
    }

    /// Adds a trunk group. The effective `require_tls` policy is the group's
    /// own flag ORed with the global default.
    pub fn add_trunk_group(&mut self, mut group: TrunkGroup) {
        if self.require_tls_default {
            group.set_require_tls(true);
        }
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

    /// Routes a call with its full context: the active dial plan is
    /// matched with [`DialPlan::match_extended`] (direction, source trunk
    /// group and Request-URI host filters enforced), then
    /// `default_trunk_group` — for [`Direction::Outbound`] calls only, so a
    /// trunk-originated call cannot be relayed out another trunk by the
    /// default group.
    ///
    /// ## NIST 800-53 Rev5: AC-4 (Information Flow Enforcement), SC-8
    ///
    /// # Errors
    /// As [`Self::route_for_tls`].
    pub fn route_call(
        &mut self,
        ctx: &CallRouteContext<'_>,
        admission: Admission,
        tls_only: bool,
    ) -> RoutingResult<RoutingDecision> {
        let dial_plan_result = if self.config.use_dial_plan {
            self.active_dial_plan().and_then(|plan| {
                plan.match_extended(
                    ctx.destination,
                    ctx.domain,
                    ctx.direction,
                    ctx.source_trunk_group,
                )
            })
        } else {
            None
        };
        let allow_default = ctx.direction != Direction::Inbound;
        self.route_with_dial_plan_result(
            ctx.destination,
            dial_plan_result,
            allow_default,
            admission,
            tls_only,
        )
    }

    /// Routes a call to the given destination.
    ///
    /// Legacy library entry point: the dial plan is matched on the number
    /// only (`DialPlan::match_number`, entry direction / source trunk /
    /// domain filters ignored). The SBC daemon uses [`Self::route_call`].
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
        self.route_for_tls(destination, admission, false)
    }

    /// [`Self::route_for`] for a call that itself requires TLS egress when
    /// `tls_only` (RFC 3261 §26.2.2: `sips:` Request-URI). The group's
    /// `require_tls` predicate is applied as if the group had it set.
    ///
    /// # Errors
    /// As [`Self::route_for`]; `tls_required` is set when the TLS
    /// requirement is what refused the call.
    pub fn route_for_tls(
        &mut self,
        destination: &str,
        admission: Admission,
        tls_only: bool,
    ) -> RoutingResult<RoutingDecision> {
        let dial_plan_result = if self.config.use_dial_plan {
            self.match_dial_plan(destination)
        } else {
            None
        };
        self.route_with_dial_plan_result(destination, dial_plan_result, true, admission, tls_only)
    }

    /// Shared tail of [`Self::route_for_tls`] / [`Self::route_call`].
    fn route_with_dial_plan_result(
        &mut self,
        destination: &str,
        dial_plan_result: Option<DialPlanResult>,
        allow_default: bool,
        admission: Admission,
        tls_only: bool,
    ) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        let trunk_group_id =
            self.resolve_trunk_group(dial_plan_result.as_ref(), destination, allow_default)?;
        let (trunk_id, trunk_uri, failover_trunks) =
            self.select_trunk_from_group(&trunk_group_id, admission, tls_only)?;
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
        allow_default: bool,
    ) -> RoutingResult<String> {
        dial_plan_result
            .map(|r| r.trunk_group.as_str())
            .or_else(|| {
                self.config
                    .default_trunk_group
                    .as_deref()
                    .filter(|_| allow_default)
            })
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
        tls_only: bool,
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

        // NIST 800-53 Rev5: SC-8 — the group's `require_tls` predicate is
        // applied inside selection and failover ordering (POA&M-48).
        let Some(trunk_id) = trunk_group
            .select_trunk_with(admission, tls_only)
            .map(String::from)
        else {
            // Failure path only: tell a policy refusal from "all down".
            let tls_required = trunk_group.tls_blocked_with(admission, tls_only);
            if tls_required {
                self.tls_counters.rejects.fetch_add(1, Ordering::Relaxed);
                self.tls_counters
                    .skips
                    .fetch_add(u64::from(trunk_group.non_tls_count()), Ordering::Relaxed);
            }
            return Err(RoutingError::AllTrunksFailed {
                trunks_tried: trunk_count,
                tls_required,
            });
        };
        if (trunk_group.require_tls() || tls_only) && trunk_group.non_tls_count() > 0 {
            self.tls_counters
                .skips
                .fetch_add(u64::from(trunk_group.non_tls_count()), Ordering::Relaxed);
        }

        let failover_trunks: Vec<String> = trunk_group
            .failover_order_with(admission, tls_only)
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
        // POAM: POA&M-1 — `max_calls` here is per node. sbc-daemon passes this node's
        // share under `cluster.admission.split = "divide"` (static); dynamic
        // cluster-wide leasing is POA&M-80.
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
        self.route_to_group_for_tls(destination, group_id, admission, false)
    }

    /// [`Self::route_to_group_for`]; `tls_only` as in [`Self::route_for_tls`].
    ///
    /// # Errors
    /// As [`Self::route_to_group_for`].
    pub fn route_to_group_for_tls(
        &mut self,
        destination: &str,
        group_id: &str,
        admission: Admission,
        tls_only: bool,
    ) -> RoutingResult<RoutingDecision> {
        self.stats.requests += 1;

        let (trunk_id, trunk_uri, failover_trunks) =
            self.select_trunk_from_group(group_id, admission, tls_only)?;
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
        self.route_to_groups_for_tls(destination, group_ids, admission, false)
    }

    /// [`Self::route_to_groups_for`]; `tls_only` as in [`Self::route_for_tls`].
    /// The call's TLS requirement applies to every group in the list,
    /// including cross-group failover targets.
    ///
    /// # Errors
    /// As [`Self::route_to_groups`].
    // POAM: POA&M-57 — `require_tls` is per group: a route list naming a
    // TLS-only group then a plain group can fall back to the plain group's
    // UDP/TCP trunks (accepted scope; mitigated by
    // `security.require_tls_trunks` and by `tls_only` for `sips:` calls).
    pub fn route_to_groups_for_tls(
        &mut self,
        destination: &str,
        group_ids: &[String],
        admission: Admission,
        tls_only: bool,
    ) -> RoutingResult<RoutingDecision> {
        if group_ids.is_empty() {
            return Err(RoutingError::NoRoute {
                destination: destination.to_string(),
            });
        }
        let mut tried = 0usize;
        let mut tls_required = false;
        for (idx, group_id) in group_ids.iter().enumerate() {
            tried += self
                .trunk_groups
                .get(group_id.as_str())
                .map_or(0, TrunkGroup::trunk_count);
            let mut decision =
                match self.route_to_group_for_tls(destination, group_id, admission, tls_only) {
                    Ok(d) => d,
                    Err(RoutingError::AllTrunksFailed {
                        tls_required: tls, ..
                    }) => {
                        tls_required |= tls;
                        continue;
                    }
                    Err(_) => continue,
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
                    for t in group.failover_order_with(admission, tls_only) {
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
            tls_required,
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
        self.acquire_trunk_for_tls(group_id, trunk_id, admission, false)
    }

    /// [`Self::acquire_trunk_for`]; `tls_only` refuses a non-TLS trunk for a
    /// call that requires TLS (`sips:` Request-URI) in any group.
    pub fn acquire_trunk_for_tls(
        &mut self,
        group_id: &str,
        trunk_id: &str,
        admission: Admission,
        tls_only: bool,
    ) -> Option<String> {
        let group = self.trunk_groups.get_mut(group_id)?;
        // NIST 800-53 Rev5: SC-8 — defence in depth: a failover target list
        // built before a re-sync that turned `require_tls` on must not reach a
        // clear-text trunk (RFC 5630 §3.1.3: no TLS-to-clear downgrade).
        let allowed = group
            .get_trunk(trunk_id)
            .map(|t| group.transport_allowed_with(t, tls_only))?;
        if !allowed {
            self.tls_counters.skips.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let trunk = group.get_trunk_mut(trunk_id)?;
        if !trunk.is_usable_for(admission) {
            return None;
        }
        // POAM: POA&M-1 — `max_calls` here is per node. sbc-daemon passes this node's
        // share under `cluster.admission.split = "divide"` (static); dynamic
        // cluster-wide leasing is POA&M-80.
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

    // --- POA&M-48 (SC-8): require_tls ---

    use crate::trunk::{SelectionStrategy, TrunkProtocol};

    fn mixed_group(id: &str, require_tls: bool) -> TrunkGroup {
        let mut g = TrunkGroup::new(id, id).with_require_tls(require_tls);
        g.add_trunk(Trunk::new(
            TrunkConfig::new("udp", "udp.example.com")
                .with_protocol(TrunkProtocol::Udp)
                .with_priority(1),
        ));
        g.add_trunk(Trunk::new(
            TrunkConfig::new("tcp", "tcp.example.com")
                .with_protocol(TrunkProtocol::Tcp)
                .with_priority(2),
        ));
        g.add_trunk(Trunk::new(
            TrunkConfig::new("tls1", "tls1.example.com")
                .with_protocol(TrunkProtocol::Tls)
                .with_priority(3),
        ));
        g.add_trunk(Trunk::new(
            TrunkConfig::new("tls2", "tls2.example.com")
                .with_protocol(TrunkProtocol::Tls)
                .with_priority(4),
        ));
        g
    }

    #[test]
    fn require_tls_skips_non_tls_on_primary_and_failover() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("g", true));
        let d = router.route_to_group("1", "g").unwrap();
        assert_eq!(d.trunk_id, "tls1");
        assert_eq!(d.failover_trunks, vec!["tls2".to_string()]);
        assert!(d.failover_targets.iter().all(|(_, t)| t.starts_with("tls")));
        assert_eq!(router.tls_policy_counters(), (2, 0));
    }

    #[test]
    fn require_tls_false_is_unchanged() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("g", false));
        let d = router.route_to_group("1", "g").unwrap();
        assert_eq!(d.trunk_id, "udp");
        assert_eq!(
            d.failover_trunks,
            vec!["tcp".to_string(), "tls1".to_string(), "tls2".to_string()]
        );
        assert_eq!(router.tls_policy_counters(), (0, 0));
    }

    #[test]
    fn require_tls_all_non_tls_reports_tls_required() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        let mut g = mixed_group("g", true);
        g.remove_trunk("tls1");
        g.remove_trunk("tls2");
        assert_eq!(g.non_tls_count(), 2);
        router.add_trunk_group(g);
        assert!(matches!(
            router.route_to_group("1", "g"),
            Err(RoutingError::AllTrunksFailed {
                trunks_tried: 2,
                tls_required: true
            })
        ));
        assert!(matches!(
            router.route_to_groups("1", &["g".to_string()]),
            Err(RoutingError::AllTrunksFailed {
                tls_required: true,
                ..
            })
        ));
        assert_eq!(router.tls_policy_counters().1, 2);
    }

    #[test]
    fn require_tls_tls_down_is_not_a_policy_reject() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        let mut g = mixed_group("g", true);
        for id in ["udp", "tcp", "tls1", "tls2"] {
            g.get_trunk_mut(id).unwrap().disable();
        }
        router.add_trunk_group(g);
        assert!(matches!(
            router.route_to_group("1", "g"),
            Err(RoutingError::AllTrunksFailed {
                tls_required: false,
                ..
            })
        ));
        assert_eq!(router.tls_policy_counters(), (0, 0));
    }

    #[test]
    fn acquire_refuses_non_tls_after_policy_turned_on() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("g", false));
        let d = router.route_to_group("1", "g").unwrap();
        assert!(d.failover_targets.iter().any(|(_, t)| t == "tcp"));
        router
            .get_trunk_group_mut("g")
            .unwrap()
            .set_require_tls(true);
        assert!(router.acquire_trunk("g", "tcp").is_none());
        assert_eq!(router.tls_policy_counters().0, 1);
        assert!(router.acquire_trunk("g", "tls2").is_some());
    }

    #[test]
    fn global_require_tls_default_applies_and_cannot_be_opted_out() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("early", false));
        router.set_require_tls_default(true);
        router.add_trunk_group(mixed_group("late", false));
        assert!(router.get_trunk_group("early").unwrap().require_tls());
        assert!(router.get_trunk_group("late").unwrap().require_tls());
        assert_eq!(router.route_to_group("1", "late").unwrap().trunk_id, "tls1");
    }

    #[test]
    fn require_tls_every_strategy_selects_only_tls() {
        for strategy in [
            SelectionStrategy::Priority,
            SelectionStrategy::RoundRobin,
            SelectionStrategy::WeightedRandom,
            SelectionStrategy::LeastConnections,
            SelectionStrategy::BestSuccessRate,
        ] {
            let mut g = mixed_group("g", true).with_strategy(strategy);
            for _ in 0..8 {
                let id = g.select_trunk().unwrap().to_string();
                assert!(id.starts_with("tls"), "{strategy:?} picked {id}");
            }
            assert!(g.failover_order().iter().all(|t| t.starts_with("tls")));
            assert_eq!(g.usable_trunk_count(), 2);
        }
    }

    // --- QA (POA&M-48): cross-group fallback and global toggle ---

    fn plain_udp_group(id: &str) -> TrunkGroup {
        let mut g = TrunkGroup::new(id, id);
        g.add_trunk(Trunk::new(
            TrunkConfig::new("b-udp", "b-udp.example.com")
                .with_protocol(TrunkProtocol::Udp)
                .with_priority(1),
        ));
        g
    }

    // Documents current behaviour (plan Q4, user decision: policy is per
    // group). A route listing a require_tls group A then a plain group B
    // appends B's clear-text trunks to the failover targets after A's TLS
    // trunks. Operators must set require_tls on every group of the route or
    // use security.require_tls_trunks.
    #[test]
    fn qa_cross_group_failover_reaches_plain_group_after_tls_group() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("a", true));
        router.add_trunk_group(plain_udp_group("b"));
        let d = router
            .route_to_groups("1", &["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(d.trunk_id, "tls1");
        assert_eq!(
            d.failover_targets,
            vec![
                ("a".to_string(), "tls2".to_string()),
                ("b".to_string(), "b-udp".to_string()),
            ],
            "A's non-TLS trunks are skipped; B's UDP trunk is still a target"
        );
        // Acquiring B's UDP trunk is allowed: B has no policy.
        assert!(
            router
                .acquire_trunk_for("b", "b-udp", Admission::Normal)
                .is_some()
        );
        // Acquiring A's UDP trunk is refused.
        assert!(
            router
                .acquire_trunk_for("a", "udp", Admission::Normal)
                .is_none()
        );
    }

    // Current behaviour: a require_tls group with no TLS trunk at all is
    // skipped and the call routes to the next (plain) group in clear.
    #[test]
    fn qa_cross_group_primary_falls_through_to_plain_group() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        let mut a = mixed_group("a", true);
        a.remove_trunk("tls1");
        a.remove_trunk("tls2");
        router.add_trunk_group(a);
        router.add_trunk_group(plain_udp_group("b"));
        let d = router
            .route_to_groups("1", &["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(d.trunk_id, "b-udp");
        let (_, rejects) = router.tls_policy_counters();
        // Recorded: the reject counter counts group-level refusals, even
        // when a later group carried the call (no 503 sent).
        assert_eq!(rejects, 1);
    }

    // With the global default on, the cross-group fallback is closed.
    #[test]
    fn qa_global_default_closes_cross_group_fallback() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.set_require_tls_default(true);
        router.add_trunk_group(mixed_group("a", false));
        router.add_trunk_group(plain_udp_group("b"));
        let d = router
            .route_to_groups("1", &["a".to_string(), "b".to_string()])
            .unwrap();
        assert!(d.failover_targets.iter().all(|(_, t)| t.starts_with("tls")));
        assert!(
            router
                .acquire_trunk_for("b", "b-udp", Admission::Normal)
                .is_none()
        );
    }

    // Runtime toggle: turning the global default on flips loaded groups.
    // Turning it off again does NOT restore their own flag (stays strict
    // until the group is re-added); groups added later use their own flag.
    #[test]
    fn qa_global_default_toggle_at_runtime() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("a", false));
        assert_eq!(router.route_to_group("1", "a").unwrap().trunk_id, "udp");
        router.set_require_tls_default(true);
        assert_eq!(router.route_to_group("1", "a").unwrap().trunk_id, "tls1");
        router.set_require_tls_default(false);
        assert!(!router.require_tls_default());
        assert!(router.get_trunk_group("a").unwrap().require_tls());
        router.add_trunk_group(plain_udp_group("b"));
        assert!(!router.get_trunk_group("b").unwrap().require_tls());
        router.add_trunk_group(mixed_group("a", false));
        assert_eq!(router.route_to_group("1", "a").unwrap().trunk_id, "udp");
    }

    // RFC 3261 §26.2.2 (RFC-002): a sips: call is TLS-only in every group,
    // including cross-group failover, even without `require_tls`.
    #[test]
    fn tls_only_call_skips_non_tls_without_group_flag() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(mixed_group("a", false));
        router.add_trunk_group(plain_udp_group("b"));
        let d = router
            .route_to_groups_for_tls(
                "1",
                &["a".to_string(), "b".to_string()],
                Admission::Normal,
                true,
            )
            .unwrap();
        assert_eq!(d.trunk_id, "tls1");
        assert!(d.failover_targets.iter().all(|(_, t)| t.starts_with("tls")));
        assert!(
            router
                .acquire_trunk_for_tls("a", "udp", Admission::Normal, true)
                .is_none()
        );
        assert!(
            router
                .acquire_trunk_for_tls("a", "udp", Admission::Normal, false)
                .is_some()
        );
        // Only clear trunks: the call is refused as a TLS policy failure.
        assert!(matches!(
            router.route_to_group_for_tls("1", "b", Admission::Normal, true),
            Err(RoutingError::AllTrunksFailed {
                tls_required: true,
                ..
            })
        ));
        // Same group, sip: call: unchanged.
        assert_eq!(
            router
                .route_to_group_for_tls("1", "a", Admission::Normal, false)
                .unwrap()
                .trunk_id,
            "udp"
        );
    }

    // QA-4: a require_tls group with no trunk left is a policy refusal.
    #[test]
    fn empty_require_tls_group_reports_tls_required() {
        let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
        router.add_trunk_group(TrunkGroup::new("e", "e").with_require_tls(true));
        router.add_trunk_group(TrunkGroup::new("p", "p"));
        assert!(matches!(
            router.route_to_groups("1", &["e".to_string()]),
            Err(RoutingError::AllTrunksFailed {
                trunks_tried: 0,
                tls_required: true
            })
        ));
        assert!(matches!(
            router.route_to_group("1", "p"),
            Err(RoutingError::AllTrunksFailed {
                tls_required: false,
                ..
            })
        ));
    }

    fn ctx_router() -> Router {
        let config = RouterConfig::default().with_default_trunk_group("default-tg");
        let mut router = Router::new(config);
        let mut plan = DialPlan::new("p", "P");
        plan.add_entry(
            DialPlanEntry::new("out", DialPattern::prefix("1"), "out-tg")
                .with_direction(Direction::Outbound)
                .with_priority(10),
        );
        plan.add_entry(
            DialPlanEntry::new("in-a", DialPattern::prefix("1"), "in-tg")
                .with_direction(Direction::Inbound)
                .with_source_trunk("carrier-a")
                .with_priority(20),
        );
        plan.add_entry(
            DialPlanEntry::new("dom", DialPattern::prefix("2"), "dom-tg")
                .with_direction(Direction::Both)
                .with_domain_pattern("*.mil")
                .with_priority(30),
        );
        router.add_dial_plan(plan);
        for id in ["default-tg", "out-tg", "in-tg", "dom-tg"] {
            let mut g = TrunkGroup::new(id, id);
            g.add_trunk(Trunk::new(TrunkConfig::new(
                format!("{id}-t"),
                "example.com",
            )));
            router.add_trunk_group(g);
        }
        router
    }

    fn ctx<'a>(
        destination: &'a str,
        domain: &'a str,
        direction: Direction,
        source: Option<&'a str>,
    ) -> CallRouteContext<'a> {
        CallRouteContext {
            destination,
            domain,
            direction,
            source_trunk_group: source,
        }
    }

    #[test]
    fn route_call_enforces_direction_source_trunk_and_domain() {
        let mut r = ctx_router();
        let d = r
            .route_call(
                &ctx("1555", "h", Direction::Outbound, None),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "out-tg");

        // Inbound from carrier-a: the outbound entry is skipped.
        let d = r
            .route_call(
                &ctx("1555", "h", Direction::Inbound, Some("carrier-a")),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "in-tg");

        // Inbound from another trunk: no entry and no default group.
        assert!(
            r.route_call(
                &ctx("1555", "h", Direction::Inbound, Some("carrier-b")),
                Admission::Normal,
                false,
            )
            .is_err()
        );

        // Domain filter, label boundary and case.
        let d = r
            .route_call(
                &ctx("2000", "SIP.Army.MIL", Direction::Outbound, None),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "dom-tg");
        let d = r
            .route_call(
                &ctx("2000", "evilmil", Direction::Outbound, None),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "default-tg");
    }

    #[test]
    fn qa_default_trunk_group_is_outbound_only_and_both_matches_inbound() {
        let mut r = ctx_router();
        // Outbound miss falls to the default group.
        let d = r
            .route_call(
                &ctx("9999", "h", Direction::Outbound, None),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "default-tg");
        // Inbound miss: no default fallback, with or without a source group.
        for src in [None, Some("carrier-a"), Some("default-tg")] {
            assert!(
                r.route_call(
                    &ctx("9999", "h", Direction::Inbound, src),
                    Admission::Normal,
                    false
                )
                .is_err(),
                "{src:?}"
            );
        }
        // Inbound without a source group does not satisfy a source_trunk filter.
        assert!(
            r.route_call(
                &ctx("1555", "h", Direction::Inbound, None),
                Admission::Normal,
                false
            )
            .is_err()
        );
        // Direction::Both entry matches inbound when the domain matches.
        let d = r
            .route_call(
                &ctx("2000", "uc.army.mil", Direction::Inbound, Some("x")),
                Admission::Normal,
                false,
            )
            .unwrap();
        assert_eq!(d.trunk_group_id, "dom-tg");
        // Label boundary for inbound too: evilmil / mil.evil.com miss and
        // there is no default fallback.
        for dom in ["evilmil", "army.mil.evil.com", "xmil", ""] {
            assert!(
                r.route_call(
                    &ctx("2000", dom, Direction::Inbound, None),
                    Admission::Normal,
                    false
                )
                .is_err(),
                "{dom}"
            );
        }
    }

    #[test]
    fn legacy_route_ignores_entry_filters() {
        let mut r = ctx_router();
        // match_number semantics: first enabled entry by priority wins.
        assert_eq!(r.route("1555").unwrap().trunk_group_id, "out-tg");
        assert_eq!(r.route("2000").unwrap().trunk_group_id, "dom-tg");
    }
}
