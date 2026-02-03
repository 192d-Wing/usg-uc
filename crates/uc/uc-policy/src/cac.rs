//! Call Admission Control (CAC) and bandwidth management.
//!
//! Provides call admission control and bandwidth management for enterprise
//! SBC deployments. Ensures SLA compliance and prevents resource exhaustion.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP rejection with 503 Service Unavailable
//! - **RFC 4412**: Communications Resource Priority for SIP
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial of Service Protection
//! - **SC-6**: Resource Availability
//!
//! ## Features
//!
//! - Maximum concurrent sessions per trunk
//! - Bandwidth limits per trunk/system
//! - Call rate limiting (CPS)
//! - Emergency call bypass
//! - Priority-based admission

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Reason for rejecting call admission.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectionReason {
    /// Maximum concurrent sessions exceeded.
    MaxSessionsExceeded {
        /// Current session count.
        current: u32,
        /// Maximum allowed.
        max: u32,
    },
    /// Bandwidth limit exceeded.
    BandwidthExceeded {
        /// Current bandwidth in kbps.
        current_kbps: u64,
        /// Maximum bandwidth in kbps.
        max_kbps: u64,
    },
    /// Call rate limit exceeded.
    RateLimitExceeded {
        /// Current CPS.
        current_cps: f64,
        /// Maximum CPS.
        max_cps: f64,
    },
    /// Trunk is disabled.
    TrunkDisabled,
    /// Trunk not found.
    TrunkNotFound {
        /// Trunk identifier.
        trunk_id: String,
    },
    /// Codec bandwidth not allowed.
    CodecNotAllowed {
        /// Requested codec.
        codec: String,
    },
    /// Custom rejection reason.
    Custom(String),
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxSessionsExceeded { current, max } => {
                write!(f, "max sessions exceeded ({current}/{max})")
            }
            Self::BandwidthExceeded {
                current_kbps,
                max_kbps,
            } => write!(f, "bandwidth exceeded ({current_kbps}/{max_kbps} kbps)"),
            Self::RateLimitExceeded {
                current_cps,
                max_cps,
            } => {
                write!(f, "rate limit exceeded ({current_cps:.1}/{max_cps:.1} CPS)")
            }
            Self::TrunkDisabled => write!(f, "trunk disabled"),
            Self::TrunkNotFound { trunk_id } => write!(f, "trunk not found: {trunk_id}"),
            Self::CodecNotAllowed { codec } => write!(f, "codec not allowed: {codec}"),
            Self::Custom(reason) => write!(f, "{reason}"),
        }
    }
}

/// Result of call admission decision.
#[derive(Debug, Clone)]
pub enum AdmissionDecision {
    /// Call is admitted.
    Admitted {
        /// Estimated bandwidth consumed (kbps).
        estimated_bandwidth_kbps: u32,
    },
    /// Call is rejected.
    Rejected {
        /// Reason for rejection.
        reason: RejectionReason,
        /// Suggested retry time (seconds).
        retry_after_secs: Option<u32>,
    },
    /// Call is queued (for future implementation).
    Queued {
        /// Position in queue.
        queue_position: u32,
    },
}

impl AdmissionDecision {
    /// Returns true if call is admitted.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// Returns true if call is rejected.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }
}

/// Call priority levels per RFC 4412.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum CallPriority {
    /// Emergency calls (highest priority, bypass CAC).
    Emergency = 5,
    /// Critical infrastructure.
    Critical = 4,
    /// Priority calls.
    Priority = 3,
    /// Normal calls.
    #[default]
    Normal = 2,
    /// Non-urgent calls.
    NonUrgent = 1,
    /// Best effort (lowest priority).
    BestEffort = 0,
}

impl CallPriority {
    /// Returns true if this priority bypasses normal CAC limits.
    #[must_use]
    pub fn bypasses_cac(&self) -> bool {
        *self == Self::Emergency
    }

    /// Returns true if this is higher than or equal to critical.
    #[must_use]
    pub fn is_critical_or_higher(&self) -> bool {
        *self >= Self::Critical
    }
}

impl fmt::Display for CallPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emergency => write!(f, "emergency"),
            Self::Critical => write!(f, "critical"),
            Self::Priority => write!(f, "priority"),
            Self::Normal => write!(f, "normal"),
            Self::NonUrgent => write!(f, "non-urgent"),
            Self::BestEffort => write!(f, "best-effort"),
        }
    }
}

/// Common codec bandwidth estimates (kbps).
#[derive(Debug, Clone, Copy)]
pub struct CodecBandwidth {
    /// G.711 u-law/a-law (64 kbps + overhead).
    pub g711: u32,
    /// G.729 (8 kbps + overhead).
    pub g729: u32,
    /// G.722 wideband (64 kbps + overhead).
    pub g722: u32,
    /// Opus voice (variable, average).
    pub opus: u32,
    /// Default for unknown codecs.
    pub default: u32,
}

impl Default for CodecBandwidth {
    fn default() -> Self {
        Self {
            g711: 90,     // 64 kbps + ~26 kbps overhead
            g729: 32,     // 8 kbps + ~24 kbps overhead
            g722: 90,     // 64 kbps + overhead
            opus: 50,     // Variable, assume mid-range
            default: 100, // Conservative default
        }
    }
}

impl CodecBandwidth {
    /// Estimates bandwidth for a codec name.
    #[must_use]
    pub fn estimate(&self, codec: &str) -> u32 {
        let codec_lower = codec.to_lowercase();
        if codec_lower.contains("g711")
            || codec_lower.contains("pcmu")
            || codec_lower.contains("pcma")
        {
            self.g711
        } else if codec_lower.contains("g729") {
            self.g729
        } else if codec_lower.contains("g722") {
            self.g722
        } else if codec_lower.contains("opus") {
            self.opus
        } else {
            self.default
        }
    }
}

/// Per-trunk CAC limits.
#[derive(Debug, Clone)]
pub struct TrunkCacLimits {
    /// Maximum concurrent sessions.
    pub max_sessions: u32,
    /// Maximum bandwidth in kbps.
    pub max_bandwidth_kbps: u64,
    /// Maximum calls per second.
    pub max_cps: f64,
    /// Whether trunk is enabled.
    pub enabled: bool,
    /// Reserved capacity for emergency calls (percentage).
    pub emergency_reserve_percent: u8,
    /// Allowed codecs (empty = all allowed).
    pub allowed_codecs: Vec<String>,
}

impl Default for TrunkCacLimits {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            max_bandwidth_kbps: 100_000, // 100 Mbps
            max_cps: 100.0,
            enabled: true,
            emergency_reserve_percent: 10,
            allowed_codecs: Vec::new(),
        }
    }
}

impl TrunkCacLimits {
    /// Creates new limits with the given max sessions.
    #[must_use]
    pub fn new(max_sessions: u32) -> Self {
        Self {
            max_sessions,
            ..Default::default()
        }
    }

    /// Sets max bandwidth.
    #[must_use]
    pub fn with_max_bandwidth_kbps(mut self, kbps: u64) -> Self {
        self.max_bandwidth_kbps = kbps;
        self
    }

    /// Sets max CPS.
    #[must_use]
    pub fn with_max_cps(mut self, cps: f64) -> Self {
        self.max_cps = cps;
        self
    }

    /// Sets emergency reserve percentage.
    #[must_use]
    pub fn with_emergency_reserve(mut self, percent: u8) -> Self {
        self.emergency_reserve_percent = percent.min(50);
        self
    }

    /// Adds an allowed codec.
    #[must_use]
    pub fn with_allowed_codec(mut self, codec: impl Into<String>) -> Self {
        self.allowed_codecs.push(codec.into());
        self
    }

    /// Disables the trunk.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Returns effective max sessions accounting for emergency reserve.
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Percentage calculation always yields non-negative result
    pub fn effective_max_sessions(&self, priority: CallPriority) -> u32 {
        if priority.is_critical_or_higher() {
            self.max_sessions
        } else {
            let reserve =
                (self.max_sessions as f64 * (self.emergency_reserve_percent as f64 / 100.0)) as u32;
            self.max_sessions.saturating_sub(reserve)
        }
    }
}

/// Trunk CAC state (runtime counters).
#[derive(Debug)]
pub struct TrunkCacState {
    /// Trunk identifier.
    trunk_id: String,
    /// Current session count.
    current_sessions: AtomicU32,
    /// Current bandwidth usage (kbps).
    current_bandwidth_kbps: AtomicU64,
    /// Call counter for CPS calculation.
    call_counter: AtomicU32,
    /// Last CPS reset time.
    last_cps_reset: std::sync::Mutex<Instant>,
}

impl TrunkCacState {
    /// Creates new trunk state.
    fn new(trunk_id: impl Into<String>) -> Self {
        Self {
            trunk_id: trunk_id.into(),
            current_sessions: AtomicU32::new(0),
            current_bandwidth_kbps: AtomicU64::new(0),
            call_counter: AtomicU32::new(0),
            last_cps_reset: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Returns trunk ID.
    #[must_use]
    pub fn trunk_id(&self) -> &str {
        &self.trunk_id
    }

    /// Returns current session count.
    #[must_use]
    pub fn current_sessions(&self) -> u32 {
        self.current_sessions.load(Ordering::Relaxed)
    }

    /// Returns current bandwidth usage.
    #[must_use]
    pub fn current_bandwidth_kbps(&self) -> u64 {
        self.current_bandwidth_kbps.load(Ordering::Relaxed)
    }

    /// Calculates current CPS.
    fn calculate_cps(&self) -> f64 {
        let guard = self.last_cps_reset.lock();
        guard.map_or(0.0, |last_reset| {
            let elapsed = last_reset.elapsed().as_secs_f64();
            let count = self.call_counter.load(Ordering::Relaxed) as f64;
            // Use at least 1 second for calculation to avoid division by near-zero
            // If we just reset, the count will be 0 or very low anyway
            let effective_elapsed = elapsed.max(1.0);
            count / effective_elapsed
        })
    }

    /// Resets CPS counter if enough time has passed.
    fn maybe_reset_cps(&self) {
        if let Ok(mut last_reset) = self.last_cps_reset.lock()
            && last_reset.elapsed() >= Duration::from_secs(1) {
                *last_reset = Instant::now();
                self.call_counter.store(0, Ordering::Relaxed);
            }
    }

    /// Increments session and bandwidth counters.
    fn admit_call(&self, bandwidth_kbps: u32) {
        self.current_sessions.fetch_add(1, Ordering::Relaxed);
        self.current_bandwidth_kbps
            .fetch_add(bandwidth_kbps as u64, Ordering::Relaxed);
        self.call_counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements session and bandwidth counters.
    fn release_call(&self, bandwidth_kbps: u32) {
        self.current_sessions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
        self.current_bandwidth_kbps
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(bandwidth_kbps as u64))
            })
            .ok();
    }
}

/// Call Admission Controller.
#[derive(Debug)]
pub struct CallAdmissionController {
    /// Per-trunk limits configuration.
    limits: HashMap<String, TrunkCacLimits>,
    /// Per-trunk runtime state.
    state: HashMap<String, Arc<TrunkCacState>>,
    /// Global system limits.
    global_limits: TrunkCacLimits,
    /// Global state.
    global_state: Arc<TrunkCacState>,
    /// Codec bandwidth estimates.
    codec_bandwidth: CodecBandwidth,
}

impl Default for CallAdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

impl CallAdmissionController {
    /// Creates a new CAC with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            state: HashMap::new(),
            global_limits: TrunkCacLimits::default(),
            global_state: Arc::new(TrunkCacState::new("__global__")),
            codec_bandwidth: CodecBandwidth::default(),
        }
    }

    /// Sets global system limits.
    pub fn set_global_limits(&mut self, limits: TrunkCacLimits) {
        self.global_limits = limits;
    }

    /// Adds or updates trunk limits.
    pub fn set_trunk_limits(&mut self, trunk_id: impl Into<String>, limits: TrunkCacLimits) {
        let trunk_id = trunk_id.into();
        self.limits.insert(trunk_id.clone(), limits);
        self.state
            .entry(trunk_id.clone())
            .or_insert_with(|| Arc::new(TrunkCacState::new(trunk_id)));
    }

    /// Removes trunk limits (falls back to global).
    pub fn remove_trunk_limits(&mut self, trunk_id: &str) {
        self.limits.remove(trunk_id);
    }

    /// Gets trunk limits (returns global if trunk not found).
    #[must_use]
    pub fn get_trunk_limits(&self, trunk_id: &str) -> &TrunkCacLimits {
        self.limits.get(trunk_id).unwrap_or(&self.global_limits)
    }

    /// Gets trunk state.
    fn get_or_create_state(&mut self, trunk_id: &str) -> Arc<TrunkCacState> {
        self.state
            .entry(trunk_id.to_string())
            .or_insert_with(|| Arc::new(TrunkCacState::new(trunk_id)))
            .clone()
    }

    /// Evaluates call admission for a trunk.
    ///
    /// # Arguments
    ///
    /// * `trunk_id` - Trunk identifier
    /// * `codec` - Codec name for bandwidth estimation
    /// * `priority` - Call priority
    ///
    /// # Returns
    ///
    /// Admission decision indicating whether call is admitted or rejected.
    pub fn evaluate(
        &mut self,
        trunk_id: &str,
        codec: Option<&str>,
        priority: CallPriority,
    ) -> AdmissionDecision {
        // Extract limits values to avoid borrow conflicts
        let limits = self
            .limits
            .get(trunk_id)
            .cloned()
            .unwrap_or_else(|| self.global_limits.clone());

        // Check if trunk is enabled
        if !limits.enabled {
            return AdmissionDecision::Rejected {
                reason: RejectionReason::TrunkDisabled,
                retry_after_secs: None,
            };
        }

        // Estimate bandwidth
        let estimated_bandwidth = codec
            .map_or(self.codec_bandwidth.default, |c| self.codec_bandwidth.estimate(c));

        // Emergency calls bypass CAC (unless trunk is disabled)
        if priority.bypasses_cac() {
            return AdmissionDecision::Admitted {
                estimated_bandwidth_kbps: estimated_bandwidth,
            };
        }

        // Check codec allowlist
        if let Some(codec_name) = codec
            && !limits.allowed_codecs.is_empty()
                && !limits
                    .allowed_codecs
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(codec_name))
            {
                return AdmissionDecision::Rejected {
                    reason: RejectionReason::CodecNotAllowed {
                        codec: codec_name.to_string(),
                    },
                    retry_after_secs: None,
                };
            }

        // Get state for this trunk
        let state = self.get_or_create_state(trunk_id);

        // Maybe reset CPS counter
        state.maybe_reset_cps();

        // Check session limit
        let effective_max = limits.effective_max_sessions(priority);
        let current_sessions = state.current_sessions();
        if current_sessions >= effective_max {
            return AdmissionDecision::Rejected {
                reason: RejectionReason::MaxSessionsExceeded {
                    current: current_sessions,
                    max: effective_max,
                },
                retry_after_secs: Some(5),
            };
        }

        // Check bandwidth limit
        let current_bandwidth = state.current_bandwidth_kbps();
        let new_bandwidth = current_bandwidth + estimated_bandwidth as u64;
        if new_bandwidth > limits.max_bandwidth_kbps {
            return AdmissionDecision::Rejected {
                reason: RejectionReason::BandwidthExceeded {
                    current_kbps: current_bandwidth,
                    max_kbps: limits.max_bandwidth_kbps,
                },
                retry_after_secs: Some(1),
            };
        }

        // Check CPS limit
        let current_cps = state.calculate_cps();
        if current_cps >= limits.max_cps {
            return AdmissionDecision::Rejected {
                reason: RejectionReason::RateLimitExceeded {
                    current_cps,
                    max_cps: limits.max_cps,
                },
                retry_after_secs: Some(1),
            };
        }

        // Also check global limits
        let global_sessions = self.global_state.current_sessions();
        let global_max = self.global_limits.effective_max_sessions(priority);
        if global_sessions >= global_max {
            return AdmissionDecision::Rejected {
                reason: RejectionReason::MaxSessionsExceeded {
                    current: global_sessions,
                    max: global_max,
                },
                retry_after_secs: Some(5),
            };
        }

        AdmissionDecision::Admitted {
            estimated_bandwidth_kbps: estimated_bandwidth,
        }
    }

    /// Commits call admission (increments counters).
    ///
    /// Call this after successfully setting up a call.
    pub fn commit(&mut self, trunk_id: &str, bandwidth_kbps: u32) {
        if let Some(state) = self.state.get(trunk_id) {
            state.admit_call(bandwidth_kbps);
        }
        self.global_state.admit_call(bandwidth_kbps);

        tracing::debug!(
            trunk_id = trunk_id,
            bandwidth_kbps = bandwidth_kbps,
            "call admitted"
        );
    }

    /// Releases call (decrements counters).
    ///
    /// Call this when a call ends.
    pub fn release(&mut self, trunk_id: &str, bandwidth_kbps: u32) {
        if let Some(state) = self.state.get(trunk_id) {
            state.release_call(bandwidth_kbps);
        }
        self.global_state.release_call(bandwidth_kbps);

        tracing::debug!(
            trunk_id = trunk_id,
            bandwidth_kbps = bandwidth_kbps,
            "call released"
        );
    }

    /// Gets statistics for a trunk.
    #[must_use]
    pub fn trunk_stats(&self, trunk_id: &str) -> Option<TrunkStats> {
        let state = self.state.get(trunk_id)?;
        let limits = self.limits.get(trunk_id).unwrap_or(&self.global_limits);

        Some(TrunkStats {
            trunk_id: trunk_id.to_string(),
            current_sessions: state.current_sessions(),
            max_sessions: limits.max_sessions,
            current_bandwidth_kbps: state.current_bandwidth_kbps(),
            max_bandwidth_kbps: limits.max_bandwidth_kbps,
            current_cps: state.calculate_cps(),
            max_cps: limits.max_cps,
            enabled: limits.enabled,
        })
    }

    /// Gets global system statistics.
    #[must_use]
    pub fn global_stats(&self) -> TrunkStats {
        TrunkStats {
            trunk_id: "__global__".to_string(),
            current_sessions: self.global_state.current_sessions(),
            max_sessions: self.global_limits.max_sessions,
            current_bandwidth_kbps: self.global_state.current_bandwidth_kbps(),
            max_bandwidth_kbps: self.global_limits.max_bandwidth_kbps,
            current_cps: self.global_state.calculate_cps(),
            max_cps: self.global_limits.max_cps,
            enabled: self.global_limits.enabled,
        }
    }
}

/// Statistics for a trunk.
#[derive(Debug, Clone)]
pub struct TrunkStats {
    /// Trunk identifier.
    pub trunk_id: String,
    /// Current session count.
    pub current_sessions: u32,
    /// Maximum sessions allowed.
    pub max_sessions: u32,
    /// Current bandwidth in kbps.
    pub current_bandwidth_kbps: u64,
    /// Maximum bandwidth in kbps.
    pub max_bandwidth_kbps: u64,
    /// Current calls per second.
    pub current_cps: f64,
    /// Maximum CPS.
    pub max_cps: f64,
    /// Whether trunk is enabled.
    pub enabled: bool,
}

impl TrunkStats {
    /// Returns session utilization (0.0 - 1.0).
    #[must_use]
    pub fn session_utilization(&self) -> f64 {
        if self.max_sessions == 0 {
            0.0
        } else {
            self.current_sessions as f64 / self.max_sessions as f64
        }
    }

    /// Returns bandwidth utilization (0.0 - 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss is acceptable for utilization calculation
    pub fn bandwidth_utilization(&self) -> f64 {
        if self.max_bandwidth_kbps == 0 {
            0.0
        } else {
            self.current_bandwidth_kbps as f64 / self.max_bandwidth_kbps as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_bandwidth_estimates() {
        let estimates = CodecBandwidth::default();

        assert_eq!(estimates.estimate("PCMU"), estimates.g711);
        assert_eq!(estimates.estimate("pcma"), estimates.g711);
        assert_eq!(estimates.estimate("G729"), estimates.g729);
        assert_eq!(estimates.estimate("opus"), estimates.opus);
        assert_eq!(estimates.estimate("unknown"), estimates.default);
    }

    #[test]
    fn test_trunk_cac_limits() {
        let limits = TrunkCacLimits::new(100)
            .with_max_bandwidth_kbps(50_000)
            .with_max_cps(10.0)
            .with_emergency_reserve(20);

        assert_eq!(limits.max_sessions, 100);
        assert_eq!(limits.max_bandwidth_kbps, 50_000);
        assert!((limits.max_cps - 10.0).abs() < f64::EPSILON);
        assert_eq!(limits.emergency_reserve_percent, 20);

        // Effective max for normal calls
        assert_eq!(limits.effective_max_sessions(CallPriority::Normal), 80);
        // Emergency calls get full capacity
        assert_eq!(limits.effective_max_sessions(CallPriority::Emergency), 100);
    }

    #[test]
    fn test_call_priority() {
        assert!(CallPriority::Emergency.bypasses_cac());
        assert!(!CallPriority::Normal.bypasses_cac());

        assert!(CallPriority::Emergency.is_critical_or_higher());
        assert!(CallPriority::Critical.is_critical_or_higher());
        assert!(!CallPriority::Normal.is_critical_or_higher());
    }

    #[test]
    fn test_admission_basic() {
        let mut cac = CallAdmissionController::new();
        cac.set_trunk_limits("trunk-1", TrunkCacLimits::new(10));

        // First call should be admitted
        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        assert!(decision.is_admitted());

        // Commit the call
        if let AdmissionDecision::Admitted {
            estimated_bandwidth_kbps,
        } = decision
        {
            cac.commit("trunk-1", estimated_bandwidth_kbps);
        }

        // Check stats
        let stats = cac.trunk_stats("trunk-1").unwrap();
        assert_eq!(stats.current_sessions, 1);
    }

    #[test]
    fn test_admission_max_sessions() {
        let mut cac = CallAdmissionController::new();
        // Set high global limits to not interfere with trunk test
        cac.set_global_limits(
            TrunkCacLimits::new(1000)
                .with_emergency_reserve(0)
                .with_max_cps(1000.0),
        );
        cac.set_trunk_limits(
            "trunk-1",
            TrunkCacLimits::new(2)
                .with_emergency_reserve(0)
                .with_max_cps(1000.0),
        );

        // Admit 2 calls
        for i in 0..2 {
            let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
            assert!(
                decision.is_admitted(),
                "call {i} should be admitted: {decision:?}"
            );
            if let AdmissionDecision::Admitted {
                estimated_bandwidth_kbps,
            } = decision
            {
                cac.commit("trunk-1", estimated_bandwidth_kbps);
            }
        }

        // Third call should be rejected
        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        assert!(decision.is_rejected(), "third call should be rejected");
        match decision {
            AdmissionDecision::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    RejectionReason::MaxSessionsExceeded { .. }
                ));
            }
            _ => panic!("expected rejection"),
        }
    }

    #[test]
    fn test_emergency_bypass() {
        let mut cac = CallAdmissionController::new();
        cac.set_trunk_limits("trunk-1", TrunkCacLimits::new(1).with_emergency_reserve(0));

        // Fill the trunk
        let _first = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        cac.commit("trunk-1", 90);

        // Emergency call should still be admitted
        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Emergency);
        assert!(decision.is_admitted());
    }

    #[test]
    fn test_disabled_trunk() {
        let mut cac = CallAdmissionController::new();
        cac.set_trunk_limits("trunk-1", TrunkCacLimits::new(100).disabled());

        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        assert!(decision.is_rejected());
        match decision {
            AdmissionDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::TrunkDisabled);
            }
            _ => panic!("expected rejection"),
        }
    }

    #[test]
    fn test_codec_allowlist() {
        let mut cac = CallAdmissionController::new();
        cac.set_trunk_limits(
            "trunk-1",
            TrunkCacLimits::new(100)
                .with_allowed_codec("PCMU")
                .with_allowed_codec("G729"),
        );

        // Allowed codec
        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        assert!(decision.is_admitted());

        // Disallowed codec
        let decision = cac.evaluate("trunk-1", Some("opus"), CallPriority::Normal);
        assert!(decision.is_rejected());
    }

    #[test]
    fn test_release_call() {
        let mut cac = CallAdmissionController::new();
        cac.set_trunk_limits("trunk-1", TrunkCacLimits::new(10));

        // Admit and commit
        let decision = cac.evaluate("trunk-1", Some("PCMU"), CallPriority::Normal);
        if let AdmissionDecision::Admitted {
            estimated_bandwidth_kbps,
        } = decision
        {
            cac.commit("trunk-1", estimated_bandwidth_kbps);
            assert_eq!(cac.trunk_stats("trunk-1").unwrap().current_sessions, 1);

            // Release
            cac.release("trunk-1", estimated_bandwidth_kbps);
            assert_eq!(cac.trunk_stats("trunk-1").unwrap().current_sessions, 0);
        }
    }

    #[test]
    fn test_trunk_stats_utilization() {
        let stats = TrunkStats {
            trunk_id: "test".to_string(),
            current_sessions: 50,
            max_sessions: 100,
            current_bandwidth_kbps: 25_000,
            max_bandwidth_kbps: 100_000,
            current_cps: 5.0,
            max_cps: 10.0,
            enabled: true,
        };

        assert!((stats.session_utilization() - 0.5).abs() < f64::EPSILON);
        assert!((stats.bandwidth_utilization() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rejection_reason_display() {
        let reason = RejectionReason::MaxSessionsExceeded {
            current: 100,
            max: 100,
        };
        assert_eq!(format!("{reason}"), "max sessions exceeded (100/100)");

        let reason = RejectionReason::TrunkDisabled;
        assert_eq!(format!("{reason}"), "trunk disabled");
    }
}
