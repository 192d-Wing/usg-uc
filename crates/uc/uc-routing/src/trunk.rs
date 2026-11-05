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

/// Default emergency headroom for a limit of `max_calls`: 10%, at least 1.
///
/// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
pub const fn default_emergency_reserve(max_calls: u32) -> u32 {
    let tenth = max_calls / 10;
    if tenth == 0 { 1 } else { tenth }
}

/// How a call is admitted to trunk capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Admission {
    /// Normal call: a trunk at `max_calls` is skipped.
    #[default]
    Normal,
    /// Emergency call (47 CFR 9.16): may use the trunk's emergency reserve
    /// on top of `max_calls`, so held normal calls never block an emergency
    /// call. The reserve is bounded (SC-5); reachability, enable state and
    /// cooldown still apply; the slot is still counted and released.
    Emergency,
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
    /// Extra calls above `max_calls` that only emergency calls may use.
    /// `None` uses [`default_emergency_reserve`] of `max_calls`.
    pub emergency_reserve_calls: Option<u32>,
    /// Cooldown period after failure (seconds).
    pub cooldown_secs: u64,
    /// Maximum consecutive failures before cooldown.
    pub max_failures: u32,
    /// Whether outbound calling is enabled.
    pub outbound_enabled: bool,
    /// Whether inbound calling is enabled.
    pub inbound_enabled: bool,
    /// TLS server name to verify the trunk certificate against when
    /// `protocol` is TLS. `None` verifies against `host` (DNS name or, for
    /// an IP literal, an IP SAN).
    ///
    /// ## NIST 800-53 Rev5: SC-23 (Session Authenticity)
    pub tls_server_name: Option<String>,
    /// Present the SBC certificate to this trunk (mutual TLS).
    ///
    /// ## NIST 800-53 Rev5: IA-3 (Device Identification and Authentication)
    pub tls_client_cert: bool,
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
            emergency_reserve_calls: None,
            cooldown_secs: 60,
            max_failures: 3,
            outbound_enabled: true,
            inbound_enabled: true,
            tls_server_name: None,
            tls_client_cert: false,
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

    /// Sets the emergency-only headroom above `max_calls`.
    #[must_use]
    pub const fn with_emergency_reserve_calls(mut self, reserve: u32) -> Self {
        self.emergency_reserve_calls = Some(reserve);
        self
    }

    /// Emergency-only headroom above `max_calls` in effect for this trunk.
    pub fn emergency_reserve(&self) -> u32 {
        self.emergency_reserve_calls
            .unwrap_or_else(|| default_emergency_reserve(self.max_calls))
    }

    /// Sets the cooldown period after `max_failures` consecutive failures.
    #[must_use]
    pub fn with_cooldown_secs(mut self, secs: u64) -> Self {
        self.cooldown_secs = secs;
        self
    }

    /// Sets the TLS server name verified on the trunk certificate.
    #[must_use]
    pub fn with_tls_server_name(mut self, name: impl Into<String>) -> Self {
        self.tls_server_name = Some(name.into());
        self
    }

    /// Presents the SBC certificate to this trunk (mutual TLS).
    #[must_use]
    pub const fn with_tls_client_cert(mut self, on: bool) -> Self {
        self.tls_client_cert = on;
        self
    }

    /// Name the trunk's TLS certificate is verified against.
    pub fn tls_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.host)
    }

    /// Sets the consecutive-failure count that puts the trunk into cooldown.
    #[must_use]
    pub fn with_max_failures(mut self, max: u32) -> Self {
        self.max_failures = max;
        self
    }
}

/// How a call that held a trunk slot ended, for [`Trunk`] accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrunkOutcome {
    /// The trunk answered the call; `setup_ms` is INVITE-to-answer time.
    Completed {
        /// Call setup time in milliseconds.
        setup_ms: u64,
    },
    /// The trunk failed the call (timeout, transport error, 5xx). Counts
    /// toward `max_failures` / cooldown.
    Failed,
    /// The call went away for a reason that is not the trunk's fault
    /// (CANCEL, callee reject, local failure). Releases the slot only.
    Abandoned,
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
    /// `config.host`, shared: built once so a per-call endpoint read is an
    /// `Arc` clone, not an allocation.
    host_shared: std::sync::Arc<str>,
    /// `config.tls_name()`, shared (see `host_shared`).
    tls_name_shared: std::sync::Arc<str>,
}

impl Trunk {
    /// Creates a new trunk.
    pub fn new(config: TrunkConfig) -> Self {
        let host_shared = std::sync::Arc::from(config.host.as_str());
        let tls_name_shared = std::sync::Arc::from(config.tls_name());
        Self {
            config,
            state: TrunkState::Available,
            stats: TrunkStats::default(),
            cooldown_until: None,
            host_shared,
            tls_name_shared,
        }
    }

    /// The configured host, shared (no allocation per call).
    pub fn host_shared(&self) -> &std::sync::Arc<str> {
        &self.host_shared
    }

    /// The TLS server name ([`TrunkConfig::tls_name`]), shared.
    pub fn tls_name_shared(&self) -> &std::sync::Arc<str> {
        &self.tls_name_shared
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
        self.is_usable_for(Admission::Normal)
    }

    /// Whether the trunk can take a call admitted as `admission`.
    pub fn is_usable_for(&self, admission: Admission) -> bool {
        self.state().is_usable()
            && self.config.outbound_enabled
            && match admission {
                Admission::Normal => !self.is_at_capacity(),
                // Bounded headroom: emergency calls may use the reserve,
                // never more (SC-5); normal calls never reach it.
                Admission::Emergency => {
                    self.stats.active_calls
                        < self
                            .config
                            .max_calls
                            .saturating_add(self.config.emergency_reserve())
                }
            }
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

    /// Records a call attempt (takes one of the `max_calls` slots).
    pub fn start_call(&mut self) {
        self.stats.active_calls = self.stats.active_calls.saturating_add(1);
    }

    /// Releases a call slot without counting a success or a failure.
    pub fn abandon_call(&mut self) {
        self.stats.active_calls = self.stats.active_calls.saturating_sub(1);
    }

    /// Releases a call slot with the given outcome.
    pub fn end_call(&mut self, outcome: TrunkOutcome) {
        match outcome {
            TrunkOutcome::Completed { setup_ms } => self.complete_call(setup_ms),
            TrunkOutcome::Failed => self.fail_call(),
            TrunkOutcome::Abandoned => self.abandon_call(),
        }
    }

    /// Applies an out-of-band reachability probe result (SIP OPTIONS ping).
    ///
    /// Unreachable marks the trunk `Failed` so selection skips it; reachable
    /// returns a `Failed` trunk to `Available`. An operator `Disabled` trunk
    /// and a trunk in `Cooldown` are left alone.
    pub fn set_reachable(&mut self, reachable: bool) {
        match (reachable, self.state) {
            (false, TrunkState::Available | TrunkState::Busy) => {
                self.state = TrunkState::Failed;
            }
            (false, TrunkState::Cooldown) => {
                // Keep the cooldown timer but stay unusable once it lapses.
                self.state = TrunkState::Failed;
                self.cooldown_until = None;
            }
            (true, TrunkState::Failed) => self.state = TrunkState::Available,
            _ => {}
        }
    }

    /// Puts the trunk into cooldown now, regardless of the failure count
    /// (e.g. the trunk answered 503, RFC 3261 §21.5.4). A disabled or
    /// probe-failed trunk keeps its state.
    pub fn start_cooldown(&mut self) {
        self.start_cooldown_for(std::time::Duration::from_secs(self.config.cooldown_secs));
    }

    /// Like [`Self::start_cooldown`] but for `duration` instead of
    /// `cooldown_secs` (e.g. the trunk's `Retry-After`, RFC 3261 §21.5.4).
    pub fn start_cooldown_for(&mut self, duration: std::time::Duration) {
        if matches!(self.state, TrunkState::Available | TrunkState::Busy) {
            self.state = TrunkState::Cooldown;
            self.cooldown_until = Some(Instant::now() + duration);
        }
    }

    /// When the current cooldown ends, if the trunk is cooling down.
    pub fn cooldown_until(&self) -> Option<Instant> {
        if self.state == TrunkState::Cooldown {
            self.cooldown_until
        } else {
            None
        }
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

        // Check if we need to enter cooldown. A disabled or probe-failed
        // trunk stays in that state (cooldown would expire it to Available).
        if self.stats.consecutive_failures >= self.config.max_failures
            && matches!(self.state, TrunkState::Available | TrunkState::Busy)
        {
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
        self.select_trunk_for(Admission::Normal)
    }

    /// Selects a trunk for a call admitted as `admission`.
    pub fn select_trunk_for(&mut self, admission: Admission) -> Option<&str> {
        let usable: Vec<_> = self
            .trunks
            .iter()
            .filter(|(_, t)| t.is_usable_for(admission))
            .collect();

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
        self.failover_order_for(Admission::Normal)
    }

    /// Failover order for a call admitted as `admission`.
    pub fn failover_order_for(&self, admission: Admission) -> Vec<&str> {
        let mut usable: Vec<_> = self
            .trunks
            .iter()
            .filter(|(_, t)| t.is_usable_for(admission))
            .collect();

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
    fn test_trunk_end_call_outcomes_never_underflow() {
        let mut trunk = Trunk::new(TrunkConfig::new("t", "t.example.com").with_max_calls(1));
        trunk.start_call();
        assert!(trunk.is_at_capacity());
        assert!(!trunk.is_usable());
        trunk.end_call(TrunkOutcome::Abandoned);
        assert_eq!(trunk.stats().active_calls, 0);
        assert_eq!(trunk.stats().calls_attempted, 0);

        trunk.start_call();
        trunk.end_call(TrunkOutcome::Completed { setup_ms: 50 });
        assert_eq!(trunk.stats().active_calls, 0);
        assert_eq!(trunk.stats().calls_succeeded, 1);

        trunk.start_call();
        trunk.end_call(TrunkOutcome::Failed);
        assert_eq!(trunk.stats().active_calls, 0);
        assert_eq!(trunk.stats().calls_failed, 1);

        // Extra releases are clamped at zero.
        trunk.end_call(TrunkOutcome::Abandoned);
        trunk.end_call(TrunkOutcome::Failed);
        assert_eq!(trunk.stats().active_calls, 0);
    }

    #[test]
    fn test_trunk_max_failures_and_cooldown_config() {
        let config = TrunkConfig::new("t", "t.example.com")
            .with_max_failures(1)
            .with_cooldown_secs(3600);
        assert_eq!(config.cooldown_secs, 3600);
        let mut trunk = Trunk::new(config);
        trunk.start_call();
        trunk.fail_call();
        assert_eq!(trunk.state(), TrunkState::Cooldown);
    }

    #[test]
    fn test_trunk_start_cooldown() {
        let mut trunk = Trunk::new(TrunkConfig::new("t", "t.example.com"));
        trunk.start_cooldown();
        assert_eq!(trunk.state(), TrunkState::Cooldown);
        assert!(!trunk.is_usable());

        let mut disabled = Trunk::new(TrunkConfig::new("d", "d.example.com"));
        disabled.disable();
        disabled.start_cooldown();
        assert_eq!(disabled.state(), TrunkState::Disabled);
    }

    #[test]
    fn test_trunk_set_reachable() {
        let mut trunk = Trunk::new(TrunkConfig::new("t", "t.example.com"));
        trunk.set_reachable(false);
        assert_eq!(trunk.state(), TrunkState::Failed);
        assert!(!trunk.is_usable());
        trunk.set_reachable(true);
        assert!(trunk.is_usable());

        // Never overrides an operator disable.
        trunk.disable();
        trunk.set_reachable(true);
        assert_eq!(trunk.state(), TrunkState::Disabled);
        trunk.set_reachable(false);
        assert_eq!(trunk.state(), TrunkState::Disabled);

        // Up does not cut a cooldown short.
        let mut cooling = Trunk::new(TrunkConfig::new("c", "c.example.com"));
        cooling.start_cooldown();
        cooling.set_reachable(true);
        assert_eq!(cooling.state(), TrunkState::Cooldown);
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

    #[test]
    fn emergency_admission_ignores_max_calls_only() {
        let mut trunk = Trunk::new(TrunkConfig::new("t", "t.example.com").with_max_calls(1));
        trunk.start_call();
        assert!(!trunk.is_usable());
        assert!(trunk.is_usable_for(Admission::Emergency));
        // Default reserve for max_calls=1 is 1: the second slot is the last.
        trunk.start_call();
        assert!(!trunk.is_usable_for(Admission::Emergency));
        trunk.end_call(TrunkOutcome::Abandoned);
        trunk.start_cooldown();
        assert!(!trunk.is_usable_for(Admission::Emergency));
        trunk.reset();
        trunk.set_reachable(false);
        assert!(!trunk.is_usable_for(Admission::Emergency));
        trunk.set_reachable(true);
        trunk.disable();
        assert!(!trunk.is_usable_for(Admission::Emergency));

        let mut group = TrunkGroup::new("g", "g");
        let mut full = Trunk::new(TrunkConfig::new("full", "f.example.com").with_max_calls(1));
        full.start_call();
        group.add_trunk(full);
        assert!(group.select_trunk().is_none());
        assert_eq!(group.failover_order(), Vec::<&str>::new());
        assert_eq!(group.select_trunk_for(Admission::Emergency), Some("full"));
        assert_eq!(group.failover_order_for(Admission::Emergency), vec!["full"]);
    }

    #[test]
    fn emergency_reserve_is_bounded_and_configurable() {
        assert_eq!(default_emergency_reserve(0), 1);
        assert_eq!(default_emergency_reserve(9), 1);
        assert_eq!(default_emergency_reserve(100), 10);
        let mut trunk = Trunk::new(
            TrunkConfig::new("t", "t.example.com")
                .with_max_calls(2)
                .with_emergency_reserve_calls(2),
        );
        for _ in 0..2 {
            trunk.start_call();
        }
        // Normal calls never use the reserve.
        assert!(!trunk.is_usable());
        assert!(trunk.is_usable_for(Admission::Emergency));
        trunk.start_call();
        assert!(!trunk.is_usable());
        assert!(trunk.is_usable_for(Admission::Emergency));
        trunk.start_call();
        // max_calls + reserve reached: emergency skipped too.
        assert!(!trunk.is_usable_for(Admission::Emergency));
    }

    #[test]
    fn start_cooldown_for_uses_given_duration() {
        let mut trunk = Trunk::new(TrunkConfig::new("t", "t.example.com").with_cooldown_secs(30));
        let before = Instant::now();
        trunk.start_cooldown_for(std::time::Duration::from_secs(120));
        let until = trunk.cooldown_until().unwrap();
        assert!(until >= before + std::time::Duration::from_secs(120));
        assert!(until < before + std::time::Duration::from_secs(121));
        assert!(!trunk.is_usable());

        let mut short = Trunk::new(TrunkConfig::new("s", "s.example.com"));
        short.start_cooldown_for(std::time::Duration::ZERO);
        assert!(short.is_usable(), "an elapsed cooldown lapses to Available");

        let mut dflt = Trunk::new(TrunkConfig::new("d", "d.example.com").with_cooldown_secs(30));
        let before = Instant::now();
        dflt.start_cooldown();
        let until = dflt.cooldown_until().unwrap();
        assert!(until >= before + std::time::Duration::from_secs(30));
        assert!(until < before + std::time::Duration::from_secs(31));
    }
}
