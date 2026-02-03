//! Trunk and carrier management.

use crate::{DEFAULT_PRIORITY, DEFAULT_WEIGHT};
use std::collections::HashMap;
use std::time::Instant;

/// Trunk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrunkState {
    /// Trunk is available.
    #[default]
    Available,
    /// Trunk is busy (at capacity).
    Busy,
    /// Trunk is disabled.
    Disabled,
    /// Trunk has failed.
    Failed,
    /// Trunk is in cooldown after failure.
    Cooldown,
}

impl TrunkState {
    /// Returns whether the trunk is usable.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Trunk protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrunkProtocol {
    /// UDP transport.
    Udp,
    /// TCP transport.
    Tcp,
    /// TLS transport.
    #[default]
    Tls,
}

/// Trunk statistics.
#[derive(Debug, Clone, Default)]
pub struct TrunkStats {
    /// Total calls attempted.
    pub calls_attempted: u64,
    /// Successful calls.
    pub calls_succeeded: u64,
    /// Failed calls.
    pub calls_failed: u64,
    /// Current active calls.
    pub active_calls: u32,
    /// Average call setup time in milliseconds.
    pub avg_setup_time_ms: u64,
    /// Last failure time.
    pub last_failure: Option<Instant>,
    /// Consecutive failures.
    pub consecutive_failures: u32,
}

impl TrunkStats {
    /// Returns the success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        if self.calls_attempted == 0 {
            1.0
        } else {
            // Allow precision loss for statistics calculation
            #[allow(clippy::cast_precision_loss)]
            let rate = self.calls_succeeded as f64 / self.calls_attempted as f64;
            rate
        }
    }

    /// Records a successful call.
    pub fn record_success(&mut self, setup_time_ms: u64) {
        self.calls_attempted += 1;
        self.calls_succeeded += 1;
        self.consecutive_failures = 0;

        // Update average setup time
        if self.calls_succeeded == 1 {
            self.avg_setup_time_ms = setup_time_ms;
        } else {
            self.avg_setup_time_ms = (self.avg_setup_time_ms * (self.calls_succeeded - 1)
                + setup_time_ms)
                / self.calls_succeeded;
        }
    }

    /// Records a failed call.
    pub fn record_failure(&mut self) {
        self.calls_attempted += 1;
        self.calls_failed += 1;
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());
    }
}

/// Trunk configuration.
#[derive(Debug, Clone)]
pub struct TrunkConfig {
    /// Trunk ID.
    pub id: String,
    /// Trunk name.
    pub name: String,
    /// Host address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Protocol.
    pub protocol: TrunkProtocol,
    /// Priority (lower = preferred).
    pub priority: u32,
    /// Weight for load balancing.
    pub weight: u32,
    /// Maximum concurrent calls.
    pub max_calls: u32,
    /// Cooldown period after failure (seconds).
    pub cooldown_secs: u64,
    /// Maximum consecutive failures before cooldown.
    pub max_failures: u32,
    /// Whether outbound calling is enabled.
    pub outbound_enabled: bool,
    /// Whether inbound calling is enabled.
    pub inbound_enabled: bool,
}

impl Default for TrunkConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            host: String::new(),
            port: 5061,
            protocol: TrunkProtocol::Tls,
            priority: DEFAULT_PRIORITY,
            weight: DEFAULT_WEIGHT,
            max_calls: 100,
            cooldown_secs: 60,
            max_failures: 3,
            outbound_enabled: true,
            inbound_enabled: true,
        }
    }
}

impl TrunkConfig {
    /// Creates a new trunk configuration.
    pub fn new(id: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            host: host.into(),
            ..Default::default()
        }
    }

    /// Sets the name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the protocol.
    #[must_use]
    pub fn with_protocol(mut self, protocol: TrunkProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the weight.
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Sets the maximum calls.
    #[must_use]
    pub fn with_max_calls(mut self, max: u32) -> Self {
        self.max_calls = max;
        self
    }
}

/// A SIP trunk/carrier.
#[derive(Debug)]
pub struct Trunk {
    /// Configuration.
    config: TrunkConfig,
    /// Current state.
    state: TrunkState,
    /// Statistics.
    stats: TrunkStats,
    /// Cooldown expiry time.
    cooldown_until: Option<Instant>,
}

impl Trunk {
    /// Creates a new trunk.
    pub fn new(config: TrunkConfig) -> Self {
        Self {
            config,
            state: TrunkState::Available,
            stats: TrunkStats::default(),
            cooldown_until: None,
        }
    }

    /// Returns the trunk ID.
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Returns the trunk name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Returns the configuration.
    pub fn config(&self) -> &TrunkConfig {
        &self.config
    }

    /// Returns the current state.
    pub fn state(&self) -> TrunkState {
        // Check if cooldown has expired
        if self.state == TrunkState::Cooldown
            && let Some(until) = self.cooldown_until
            && Instant::now() >= until
        {
            return TrunkState::Available;
        }
        self.state
    }

    /// Returns whether the trunk is usable for outbound calls.
    pub fn is_usable(&self) -> bool {
        self.state().is_usable() && self.config.outbound_enabled && !self.is_at_capacity()
    }

    /// Returns whether the trunk is at capacity.
    pub fn is_at_capacity(&self) -> bool {
        self.stats.active_calls >= self.config.max_calls
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &TrunkStats {
        &self.stats
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.config.priority
    }

    /// Returns the weight.
    pub fn weight(&self) -> u32 {
        self.config.weight
    }

    /// Returns the SIP URI for this trunk.
    pub fn sip_uri(&self) -> String {
        let scheme = match self.config.protocol {
            TrunkProtocol::Udp | TrunkProtocol::Tcp => "sip",
            TrunkProtocol::Tls => "sips",
        };
        format!("{}:{}:{}", scheme, self.config.host, self.config.port)
    }

    /// Enables the trunk.
    pub fn enable(&mut self) {
        if self.state == TrunkState::Disabled {
            self.state = TrunkState::Available;
        }
    }

    /// Disables the trunk.
    pub fn disable(&mut self) {
        self.state = TrunkState::Disabled;
    }

    /// Records a call attempt.
    pub fn start_call(&mut self) {
        self.stats.active_calls += 1;
    }

    /// Records a successful call completion.
    pub fn complete_call(&mut self, setup_time_ms: u64) {
        if self.stats.active_calls > 0 {
            self.stats.active_calls -= 1;
        }
        self.stats.record_success(setup_time_ms);
    }

    /// Records a failed call.
    pub fn fail_call(&mut self) {
        if self.stats.active_calls > 0 {
            self.stats.active_calls -= 1;
        }
        self.stats.record_failure();

        // Check if we need to enter cooldown
        if self.stats.consecutive_failures >= self.config.max_failures {
            self.enter_cooldown();
        }
    }

    /// Enters cooldown state.
    fn enter_cooldown(&mut self) {
        self.state = TrunkState::Cooldown;
        self.cooldown_until =
            Some(Instant::now() + std::time::Duration::from_secs(self.config.cooldown_secs));
    }

    /// Resets the trunk state.
    pub fn reset(&mut self) {
        self.state = TrunkState::Available;
        self.cooldown_until = None;
        self.stats.consecutive_failures = 0;
    }
}

/// Trunk selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    /// Select by priority (lowest first).
    #[default]
    Priority,
    /// Round-robin selection.
    RoundRobin,
    /// Weighted random selection.
    WeightedRandom,
    /// Least connections.
    LeastConnections,
    /// Best success rate.
    BestSuccessRate,
}

/// A group of trunks for failover and load balancing.
#[derive(Debug)]
pub struct TrunkGroup {
    /// Group ID.
    id: String,
    /// Group name.
    name: String,
    /// Trunks in the group.
    trunks: HashMap<String, Trunk>,
    /// Selection strategy.
    strategy: SelectionStrategy,
    /// Round-robin index.
    round_robin_idx: usize,
}

impl TrunkGroup {
    /// Creates a new trunk group.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            trunks: HashMap::new(),
            strategy: SelectionStrategy::Priority,
            round_robin_idx: 0,
        }
    }

    /// Returns the group ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the selection strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: SelectionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Adds a trunk to the group.
    pub fn add_trunk(&mut self, trunk: Trunk) {
        self.trunks.insert(trunk.id().to_string(), trunk);
    }

    /// Removes a trunk from the group.
    pub fn remove_trunk(&mut self, id: &str) -> Option<Trunk> {
        self.trunks.remove(id)
    }

    /// Gets a trunk by ID.
    pub fn get_trunk(&self, id: &str) -> Option<&Trunk> {
        self.trunks.get(id)
    }

    /// Gets a mutable trunk by ID.
    pub fn get_trunk_mut(&mut self, id: &str) -> Option<&mut Trunk> {
        self.trunks.get_mut(id)
    }

    /// Returns the number of trunks.
    pub fn trunk_count(&self) -> usize {
        self.trunks.len()
    }

    /// Returns the number of usable trunks.
    pub fn usable_trunk_count(&self) -> usize {
        self.trunks.values().filter(|t| t.is_usable()).count()
    }

    /// Selects a trunk for routing.
    pub fn select_trunk(&mut self) -> Option<&str> {
        let usable: Vec<_> = self.trunks.iter().filter(|(_, t)| t.is_usable()).collect();

        if usable.is_empty() {
            return None;
        }

        match self.strategy {
            SelectionStrategy::Priority => usable
                .iter()
                .min_by_key(|(_, t)| t.priority())
                .map(|(id, _)| id.as_str()),
            SelectionStrategy::RoundRobin => {
                let idx = self.round_robin_idx % usable.len();
                self.round_robin_idx = self.round_robin_idx.wrapping_add(1);
                usable.get(idx).map(|(id, _)| id.as_str())
            }
            SelectionStrategy::WeightedRandom => {
                // Simple implementation: select by weight proportion
                let total_weight: u32 = usable.iter().map(|(_, t)| t.weight()).sum();
                if total_weight == 0 {
                    return usable.first().map(|(id, _)| id.as_str());
                }
                // Use simple pseudo-random based on round-robin index
                let target = (self.round_robin_idx as u32 * 31) % total_weight;
                self.round_robin_idx = self.round_robin_idx.wrapping_add(1);
                let mut acc = 0;
                for (id, trunk) in &usable {
                    acc += trunk.weight();
                    if acc > target {
                        return Some(id.as_str());
                    }
                }
                usable.last().map(|(id, _)| id.as_str())
            }
            SelectionStrategy::LeastConnections => usable
                .iter()
                .min_by_key(|(_, t)| t.stats().active_calls)
                .map(|(id, _)| id.as_str()),
            SelectionStrategy::BestSuccessRate => usable
                .iter()
                .max_by(|(_, a), (_, b)| {
                    a.stats()
                        .success_rate()
                        .partial_cmp(&b.stats().success_rate())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(id, _)| id.as_str()),
        }
    }

    /// Returns an ordered list of trunk IDs for failover.
    pub fn failover_order(&self) -> Vec<&str> {
        let mut usable: Vec<_> = self.trunks.iter().filter(|(_, t)| t.is_usable()).collect();

        usable.sort_by_key(|(_, t)| t.priority());
        usable.into_iter().map(|(id, _)| id.as_str()).collect()
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn test_trunk_state() {
        assert!(TrunkState::Available.is_usable());
        assert!(!TrunkState::Failed.is_usable());
        assert!(!TrunkState::Disabled.is_usable());
    }

    #[test]
    fn test_trunk_stats_success_rate() {
        let mut stats = TrunkStats::default();
        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);

        stats.record_success(100);
        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);

        stats.record_failure();
        assert!((stats.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trunk_config() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com")
            .with_name("Example Trunk")
            .with_port(5060)
            .with_protocol(TrunkProtocol::Tcp)
            .with_priority(50)
            .with_max_calls(200);

        assert_eq!(config.id, "trunk-1");
        assert_eq!(config.host, "sip.example.com");
        assert_eq!(config.port, 5060);
        assert_eq!(config.priority, 50);
    }

    #[test]
    fn test_trunk_creation() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com");
        let trunk = Trunk::new(config);

        assert_eq!(trunk.id(), "trunk-1");
        assert!(trunk.is_usable());
        assert_eq!(trunk.state(), TrunkState::Available);
    }

    #[test]
    fn test_trunk_sip_uri() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com")
            .with_port(5061)
            .with_protocol(TrunkProtocol::Tls);
        let trunk = Trunk::new(config);

        assert_eq!(trunk.sip_uri(), "sips:sip.example.com:5061");
    }

    #[test]
    fn test_trunk_call_tracking() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com").with_max_calls(2);
        let mut trunk = Trunk::new(config);

        trunk.start_call();
        assert_eq!(trunk.stats().active_calls, 1);

        trunk.start_call();
        assert!(trunk.is_at_capacity());

        trunk.complete_call(100);
        assert!(!trunk.is_at_capacity());
    }

    #[test]
    fn test_trunk_cooldown() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com").with_max_calls(10);
        let mut trunk = Trunk::new(config);

        // Fail 3 times (default max_failures)
        for _ in 0..3 {
            trunk.start_call();
            trunk.fail_call();
        }

        assert_eq!(trunk.state(), TrunkState::Cooldown);
        assert!(!trunk.is_usable());
    }

    #[test]
    fn test_trunk_disable_enable() {
        let config = TrunkConfig::new("trunk-1", "sip.example.com");
        let mut trunk = Trunk::new(config);

        trunk.disable();
        assert!(!trunk.is_usable());

        trunk.enable();
        assert!(trunk.is_usable());
    }

    #[test]
    fn test_trunk_group_creation() {
        let group = TrunkGroup::new("group-1", "Primary Trunks");
        assert_eq!(group.id(), "group-1");
        assert_eq!(group.trunk_count(), 0);
    }

    #[test]
    fn test_trunk_group_add_remove() {
        let mut group = TrunkGroup::new("group-1", "Test Group");

        let trunk = Trunk::new(TrunkConfig::new("trunk-1", "sip.example.com"));
        group.add_trunk(trunk);

        assert_eq!(group.trunk_count(), 1);
        assert!(group.get_trunk("trunk-1").is_some());

        group.remove_trunk("trunk-1");
        assert_eq!(group.trunk_count(), 0);
    }

    #[test]
    fn test_trunk_group_select_priority() {
        let mut group =
            TrunkGroup::new("group-1", "Test Group").with_strategy(SelectionStrategy::Priority);

        let low_priority =
            Trunk::new(TrunkConfig::new("low", "low.example.com").with_priority(200));
        let high_priority =
            Trunk::new(TrunkConfig::new("high", "high.example.com").with_priority(50));

        group.add_trunk(low_priority);
        group.add_trunk(high_priority);

        let selected = group.select_trunk();
        assert_eq!(selected, Some("high"));
    }

    #[test]
    fn test_trunk_group_select_least_connections() {
        let mut group = TrunkGroup::new("group-1", "Test Group")
            .with_strategy(SelectionStrategy::LeastConnections);

        let mut busy = Trunk::new(TrunkConfig::new("busy", "busy.example.com"));
        busy.start_call();
        busy.start_call();

        let idle = Trunk::new(TrunkConfig::new("idle", "idle.example.com"));

        group.add_trunk(busy);
        group.add_trunk(idle);

        let selected = group.select_trunk();
        assert_eq!(selected, Some("idle"));
    }

    #[test]
    fn test_trunk_group_failover_order() {
        let mut group = TrunkGroup::new("group-1", "Test Group");

        group.add_trunk(Trunk::new(
            TrunkConfig::new("third", "third.example.com").with_priority(300),
        ));
        group.add_trunk(Trunk::new(
            TrunkConfig::new("first", "first.example.com").with_priority(100),
        ));
        group.add_trunk(Trunk::new(
            TrunkConfig::new("second", "second.example.com").with_priority(200),
        ));

        let order = group.failover_order();
        assert_eq!(order, vec!["first", "second", "third"]);
    }

    #[test]
    fn test_trunk_group_usable_count() {
        let mut group = TrunkGroup::new("group-1", "Test Group");

        let mut disabled = Trunk::new(TrunkConfig::new("disabled", "disabled.example.com"));
        disabled.disable();

        let available = Trunk::new(TrunkConfig::new("available", "available.example.com"));

        group.add_trunk(disabled);
        group.add_trunk(available);

        assert_eq!(group.trunk_count(), 2);
        assert_eq!(group.usable_trunk_count(), 1);
    }
}
