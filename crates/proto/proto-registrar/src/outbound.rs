//! RFC 5626 Outbound Flow Maintenance.
//!
//! This module implements flow maintenance for SIP Outbound connections
//! to keep NAT bindings alive and detect connection failures.
//!
//! ## RFC 5626 Section 5.2 Compliance
//!
//! The edge proxy MUST maintain flows to registered clients by sending
//! periodic keepalives. This ensures:
//!
//! 1. NAT bindings remain open
//! 2. Connection failures are detected quickly
//! 3. Flows can be recovered when detected as failed
//!
//! ## Keepalive Mechanisms
//!
//! - **STUN**: For UDP flows, use STUN Binding Request/Response
//! - **CRLF**: For TCP/TLS flows, send double-CRLF keepalive
//! - **WebSocket Ping**: For WebSocket flows, use WS ping frames
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (connection monitoring)
//! - **SC-10**: Network Disconnect (failure detection)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Default keepalive interval (RFC 5626 recommends <= 120 seconds).
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Default failure threshold (consecutive failures before marking flow dead).
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Default response timeout for keepalive probes.
pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum keepalive interval.
pub const MIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum keepalive interval (should be less than typical NAT timeout).
pub const MAX_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

/// Flow transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowTransport {
    /// UDP flow (use STUN keepalives).
    Udp,
    /// TCP flow (use CRLF keepalives).
    Tcp,
    /// TLS flow (use CRLF keepalives over TLS).
    Tls,
    /// WebSocket flow (use WS ping frames).
    WebSocket,
    /// Secure WebSocket flow (use WS ping frames over TLS).
    WebSocketSecure,
}

impl FlowTransport {
    /// Returns the appropriate keepalive mechanism description.
    #[must_use]
    pub fn keepalive_mechanism(&self) -> &'static str {
        match self {
            Self::Udp => "STUN Binding",
            Self::Tcp | Self::Tls => "CRLF ping",
            Self::WebSocket | Self::WebSocketSecure => "WebSocket ping",
        }
    }

    /// Returns true if this is a connection-oriented transport.
    #[must_use]
    pub fn is_connection_oriented(&self) -> bool {
        !matches!(self, Self::Udp)
    }
}

impl std::fmt::Display for FlowTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Tls => write!(f, "TLS"),
            Self::WebSocket => write!(f, "WS"),
            Self::WebSocketSecure => write!(f, "WSS"),
        }
    }
}

/// Flow state per RFC 5626.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Flow is active and healthy.
    Active,
    /// Keepalive pending response.
    Probing,
    /// Flow suspected to be failing (some keepalives failed).
    Suspect,
    /// Flow has failed (consecutive keepalive failures).
    Failed,
    /// Flow is being recovered.
    Recovering,
}

impl std::fmt::Display for FlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Probing => write!(f, "probing"),
            Self::Suspect => write!(f, "suspect"),
            Self::Failed => write!(f, "failed"),
            Self::Recovering => write!(f, "recovering"),
        }
    }
}

/// Unique flow identifier.
///
/// Per RFC 5626, a flow is identified by the tuple of:
/// - Local address
/// - Remote address
/// - Transport protocol
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowId {
    /// Local endpoint address.
    pub local_addr: SocketAddr,
    /// Remote endpoint address.
    pub remote_addr: SocketAddr,
    /// Transport protocol.
    pub transport: FlowTransport,
}

impl FlowId {
    /// Creates a new flow ID.
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr, transport: FlowTransport) -> Self {
        Self {
            local_addr,
            remote_addr,
            transport,
        }
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}->{}",
            self.transport, self.local_addr, self.remote_addr
        )
    }
}

/// Token for identifying a flow in messages.
///
/// This is a compact token that can be included in SIP messages
/// to correlate requests with specific flows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowToken(String);

impl FlowToken {
    /// Creates a new flow token from the flow ID.
    pub fn from_flow_id(flow_id: &FlowId) -> Self {
        // Generate a deterministic but compact token
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        flow_id.hash(&mut hasher);
        let hash = hasher.finish();

        Self(format!("f-{:016x}", hash))
    }

    /// Creates a flow token from a string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the token as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FlowToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single outbound flow.
#[derive(Debug)]
pub struct Flow {
    /// Flow identifier.
    id: FlowId,
    /// Flow token for SIP routing.
    token: FlowToken,
    /// Current state.
    state: FlowState,
    /// When the flow was created.
    created_at: Instant,
    /// When the last successful keepalive was received.
    last_success: Instant,
    /// When the last keepalive was sent.
    last_probe: Option<Instant>,
    /// Consecutive failure count.
    failure_count: u32,
    /// Associated instance ID (RFC 5626).
    instance_id: Option<String>,
    /// Associated reg-ID (RFC 5626).
    reg_id: Option<u32>,
    /// Keepalive interval for this flow.
    keepalive_interval: Duration,
}

impl Flow {
    /// Creates a new flow.
    pub fn new(id: FlowId) -> Self {
        let token = FlowToken::from_flow_id(&id);
        let now = Instant::now();

        Self {
            id,
            token,
            state: FlowState::Active,
            created_at: now,
            last_success: now,
            last_probe: None,
            failure_count: 0,
            instance_id: None,
            reg_id: None,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        }
    }

    /// Returns the flow ID.
    #[must_use]
    pub fn id(&self) -> &FlowId {
        &self.id
    }

    /// Returns the flow token.
    #[must_use]
    pub fn token(&self) -> &FlowToken {
        &self.token
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> FlowState {
        self.state
    }

    /// Returns when the flow was created.
    #[must_use]
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when the last successful keepalive was received.
    #[must_use]
    pub fn last_success(&self) -> Instant {
        self.last_success
    }

    /// Returns the instance ID if set.
    #[must_use]
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    /// Returns the reg-ID if set.
    #[must_use]
    pub fn reg_id(&self) -> Option<u32> {
        self.reg_id
    }

    /// Returns the consecutive failure count.
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Sets the instance ID.
    pub fn set_instance_id(&mut self, id: impl Into<String>) {
        self.instance_id = Some(id.into());
    }

    /// Sets the reg-ID.
    pub fn set_reg_id(&mut self, reg_id: u32) {
        self.reg_id = Some(reg_id);
    }

    /// Sets the keepalive interval.
    pub fn set_keepalive_interval(&mut self, interval: Duration) {
        self.keepalive_interval = interval.clamp(MIN_KEEPALIVE_INTERVAL, MAX_KEEPALIVE_INTERVAL);
    }

    /// Returns true if a keepalive should be sent now.
    #[must_use]
    pub fn needs_keepalive(&self) -> bool {
        if self.state == FlowState::Failed {
            return false;
        }

        // Don't send if we're already probing and waiting for response
        if self.state == FlowState::Probing {
            return false;
        }

        self.last_success.elapsed() >= self.keepalive_interval
    }

    /// Returns time until next keepalive is needed.
    #[must_use]
    pub fn time_until_keepalive(&self) -> Duration {
        let elapsed = self.last_success.elapsed();
        if elapsed >= self.keepalive_interval {
            Duration::ZERO
        } else {
            self.keepalive_interval - elapsed
        }
    }

    /// Records that a keepalive probe was sent.
    pub fn mark_probe_sent(&mut self) {
        self.last_probe = Some(Instant::now());
        self.state = FlowState::Probing;
    }

    /// Records a successful keepalive response.
    pub fn mark_success(&mut self) {
        self.last_success = Instant::now();
        self.last_probe = None;
        self.failure_count = 0;
        self.state = FlowState::Active;
    }

    /// Records a keepalive failure.
    pub fn mark_failure(&mut self, threshold: u32) {
        self.failure_count += 1;
        self.last_probe = None;

        if self.failure_count >= threshold {
            self.state = FlowState::Failed;
        } else {
            self.state = FlowState::Suspect;
        }
    }

    /// Checks if a pending probe has timed out.
    #[must_use]
    pub fn probe_timed_out(&self, timeout: Duration) -> bool {
        if self.state != FlowState::Probing {
            return false;
        }

        self.last_probe
            .map(|t| t.elapsed() >= timeout)
            .unwrap_or(false)
    }

    /// Returns true if the flow has failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.state == FlowState::Failed
    }

    /// Returns true if the flow is healthy (active).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.state == FlowState::Active
    }

    /// Attempts to recover the flow.
    pub fn start_recovery(&mut self) {
        self.state = FlowState::Recovering;
        self.failure_count = 0;
    }
}

/// Action to take for flow maintenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    /// Send a STUN Binding Request keepalive.
    SendStunKeepalive {
        /// Remote address.
        remote_addr: SocketAddr,
        /// Transaction ID for the request.
        transaction_id: [u8; 12],
    },
    /// Send a CRLF keepalive (double-CRLF for TCP/TLS).
    SendCrlfKeepalive {
        /// Remote address.
        remote_addr: SocketAddr,
    },
    /// Send a WebSocket ping frame.
    SendWebSocketPing {
        /// Remote address.
        remote_addr: SocketAddr,
    },
    /// Flow has failed - notify registrar to remove bindings.
    FlowFailed {
        /// Flow token.
        token: FlowToken,
        /// Instance ID if available.
        instance_id: Option<String>,
        /// Reg-ID if available.
        reg_id: Option<u32>,
    },
    /// No action needed.
    None,
}

/// Outbound flow manager per RFC 5626 §5.2.
///
/// Manages keepalives for all active outbound flows to ensure
/// NAT bindings remain open and connections stay alive.
#[derive(Debug)]
pub struct OutboundFlowManager {
    /// Active flows indexed by flow ID.
    flows: HashMap<FlowId, Flow>,
    /// Flow token to flow ID mapping.
    token_index: HashMap<FlowToken, FlowId>,
    /// Keepalive interval.
    keepalive_interval: Duration,
    /// Keepalive timeout.
    keepalive_timeout: Duration,
    /// Failure threshold.
    failure_threshold: u32,
}

impl OutboundFlowManager {
    /// Creates a new flow manager with default settings.
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            token_index: HashMap::new(),
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
        }
    }

    /// Creates a flow manager with custom settings.
    pub fn with_config(
        keepalive_interval: Duration,
        keepalive_timeout: Duration,
        failure_threshold: u32,
    ) -> Self {
        Self {
            flows: HashMap::new(),
            token_index: HashMap::new(),
            keepalive_interval: keepalive_interval.clamp(MIN_KEEPALIVE_INTERVAL, MAX_KEEPALIVE_INTERVAL),
            keepalive_timeout,
            failure_threshold: failure_threshold.max(1),
        }
    }

    /// Returns the number of active flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Returns the number of healthy flows.
    #[must_use]
    pub fn healthy_flow_count(&self) -> usize {
        self.flows.values().filter(|f| f.is_healthy()).count()
    }

    /// Returns the number of failed flows.
    #[must_use]
    pub fn failed_flow_count(&self) -> usize {
        self.flows.values().filter(|f| f.is_failed()).count()
    }

    /// Adds or updates a flow.
    ///
    /// Called when a registration is received to track the flow.
    pub fn add_flow(&mut self, flow_id: FlowId) -> &Flow {
        let token = FlowToken::from_flow_id(&flow_id);
        self.token_index.insert(token.clone(), flow_id.clone());

        self.flows.entry(flow_id.clone()).or_insert_with(|| {
            let mut flow = Flow::new(flow_id);
            flow.set_keepalive_interval(self.keepalive_interval);
            flow
        })
    }

    /// Adds a flow with instance-id and reg-id (RFC 5626).
    pub fn add_outbound_flow(
        &mut self,
        flow_id: FlowId,
        instance_id: impl Into<String>,
        reg_id: u32,
    ) -> &Flow {
        let token = FlowToken::from_flow_id(&flow_id);
        self.token_index.insert(token.clone(), flow_id.clone());

        self.flows.entry(flow_id.clone()).or_insert_with(|| {
            let mut flow = Flow::new(flow_id);
            flow.set_instance_id(instance_id);
            flow.set_reg_id(reg_id);
            flow.set_keepalive_interval(self.keepalive_interval);
            flow
        })
    }

    /// Removes a flow.
    pub fn remove_flow(&mut self, flow_id: &FlowId) -> Option<Flow> {
        if let Some(flow) = self.flows.remove(flow_id) {
            self.token_index.remove(&flow.token);
            Some(flow)
        } else {
            None
        }
    }

    /// Gets a flow by ID.
    #[must_use]
    pub fn get_flow(&self, flow_id: &FlowId) -> Option<&Flow> {
        self.flows.get(flow_id)
    }

    /// Gets a flow by token.
    #[must_use]
    pub fn get_flow_by_token(&self, token: &FlowToken) -> Option<&Flow> {
        self.token_index
            .get(token)
            .and_then(|id| self.flows.get(id))
    }

    /// Records a successful keepalive response for a flow.
    pub fn record_success(&mut self, flow_id: &FlowId) {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.mark_success();
        }
    }

    /// Records a keepalive failure for a flow.
    pub fn record_failure(&mut self, flow_id: &FlowId) -> Option<FlowAction> {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.mark_failure(self.failure_threshold);

            if flow.is_failed() {
                return Some(FlowAction::FlowFailed {
                    token: flow.token.clone(),
                    instance_id: flow.instance_id.clone(),
                    reg_id: flow.reg_id,
                });
            }
        }
        None
    }

    /// Processes a tick and returns actions for flows needing maintenance.
    ///
    /// ## RFC 5626 §5.2
    ///
    /// The edge proxy MUST send periodic keepalives on each flow.
    /// This method should be called periodically to check all flows.
    pub fn tick(&mut self) -> Vec<FlowAction> {
        let mut actions = Vec::new();

        for flow in self.flows.values_mut() {
            // Check for probe timeout
            if flow.probe_timed_out(self.keepalive_timeout) {
                flow.mark_failure(self.failure_threshold);

                if flow.is_failed() {
                    actions.push(FlowAction::FlowFailed {
                        token: flow.token.clone(),
                        instance_id: flow.instance_id.clone(),
                        reg_id: flow.reg_id,
                    });
                }
                continue;
            }

            // Check if keepalive is needed
            if flow.needs_keepalive() {
                let action = match flow.id.transport {
                    FlowTransport::Udp => {
                        let mut transaction_id = [0u8; 12];
                        // Generate a simple transaction ID
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        transaction_id[..8].copy_from_slice(&now.to_le_bytes()[..8]);

                        FlowAction::SendStunKeepalive {
                            remote_addr: flow.id.remote_addr,
                            transaction_id,
                        }
                    }
                    FlowTransport::Tcp | FlowTransport::Tls => {
                        FlowAction::SendCrlfKeepalive {
                            remote_addr: flow.id.remote_addr,
                        }
                    }
                    FlowTransport::WebSocket | FlowTransport::WebSocketSecure => {
                        FlowAction::SendWebSocketPing {
                            remote_addr: flow.id.remote_addr,
                        }
                    }
                };

                flow.mark_probe_sent();
                actions.push(action);
            }
        }

        actions
    }

    /// Removes all failed flows and returns their tokens.
    pub fn remove_failed_flows(&mut self) -> Vec<FlowToken> {
        let failed_ids: Vec<FlowId> = self
            .flows
            .iter()
            .filter(|(_, f)| f.is_failed())
            .map(|(id, _)| id.clone())
            .collect();

        let mut tokens = Vec::new();
        for id in failed_ids {
            if let Some(flow) = self.remove_flow(&id) {
                tokens.push(flow.token);
            }
        }

        tokens
    }

    /// Returns an iterator over all flows.
    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Returns time until next action is needed.
    #[must_use]
    pub fn time_until_next_action(&self) -> Duration {
        self.flows
            .values()
            .filter(|f| !f.is_failed())
            .map(|f| {
                if f.state == FlowState::Probing {
                    // Waiting for probe response
                    f.last_probe
                        .map(|t| {
                            let elapsed = t.elapsed();
                            if elapsed >= self.keepalive_timeout {
                                Duration::ZERO
                            } else {
                                self.keepalive_timeout - elapsed
                            }
                        })
                        .unwrap_or(Duration::ZERO)
                } else {
                    f.time_until_keepalive()
                }
            })
            .min()
            .unwrap_or(self.keepalive_interval)
    }
}

impl Default for OutboundFlowManager {
    fn default() -> Self {
        Self::new()
    }
}

/// CRLF keepalive bytes for TCP/TLS flows.
///
/// Per RFC 5626 §3.5.1, the keepalive is a double CRLF.
pub const CRLF_KEEPALIVE: &[u8] = b"\r\n\r\n";

/// Pong response for CRLF keepalive.
pub const CRLF_PONG: &[u8] = b"\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_flow_id() -> FlowId {
        FlowId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            FlowTransport::Udp,
        )
    }

    #[test]
    fn test_flow_creation() {
        let flow_id = test_flow_id();
        let flow = Flow::new(flow_id.clone());

        assert_eq!(flow.id(), &flow_id);
        assert_eq!(flow.state(), FlowState::Active);
        assert!(!flow.is_failed());
        assert!(flow.is_healthy());
    }

    #[test]
    fn test_flow_token_generation() {
        let flow_id = test_flow_id();
        let token = FlowToken::from_flow_id(&flow_id);

        assert!(token.as_str().starts_with("f-"));
        assert!(!token.as_str().is_empty());
    }

    #[test]
    fn test_flow_manager_add_flow() {
        let mut manager = OutboundFlowManager::new();
        let flow_id = test_flow_id();

        manager.add_flow(flow_id.clone());
        assert_eq!(manager.flow_count(), 1);

        let flow = manager.get_flow(&flow_id).unwrap();
        assert!(flow.is_healthy());
    }

    #[test]
    fn test_flow_manager_outbound_flow() {
        let mut manager = OutboundFlowManager::new();
        let flow_id = test_flow_id();

        manager.add_outbound_flow(flow_id.clone(), "<urn:uuid:test>", 1);

        let flow = manager.get_flow(&flow_id).unwrap();
        assert_eq!(flow.instance_id(), Some("<urn:uuid:test>"));
        assert_eq!(flow.reg_id(), Some(1));
    }

    #[test]
    fn test_flow_keepalive_needed() {
        let flow_id = test_flow_id();
        let flow = Flow::new(flow_id);

        // New flow should not need keepalive immediately
        // (keepalive interval is >= 10 seconds)
        assert!(!flow.needs_keepalive());

        // Test that time_until_keepalive returns something > 0
        assert!(flow.time_until_keepalive() > Duration::ZERO);
    }

    #[test]
    fn test_flow_probe_success() {
        let flow_id = test_flow_id();
        let mut flow = Flow::new(flow_id);

        flow.mark_probe_sent();
        assert_eq!(flow.state(), FlowState::Probing);

        flow.mark_success();
        assert_eq!(flow.state(), FlowState::Active);
        assert_eq!(flow.failure_count(), 0);
    }

    #[test]
    fn test_flow_probe_failure() {
        let flow_id = test_flow_id();
        let mut flow = Flow::new(flow_id);

        // First failure - should become suspect
        flow.mark_failure(3);
        assert_eq!(flow.state(), FlowState::Suspect);
        assert_eq!(flow.failure_count(), 1);

        // Second failure - still suspect
        flow.mark_failure(3);
        assert_eq!(flow.state(), FlowState::Suspect);
        assert_eq!(flow.failure_count(), 2);

        // Third failure - should fail
        flow.mark_failure(3);
        assert_eq!(flow.state(), FlowState::Failed);
        assert!(flow.is_failed());
    }

    #[test]
    fn test_flow_manager_record_failure() {
        let mut manager = OutboundFlowManager::with_config(
            DEFAULT_KEEPALIVE_INTERVAL,
            DEFAULT_KEEPALIVE_TIMEOUT,
            2, // Lower threshold for testing
        );

        let flow_id = test_flow_id();
        manager.add_flow(flow_id.clone());

        // First failure - no action
        let action = manager.record_failure(&flow_id);
        assert!(action.is_none());

        // Second failure - should trigger FlowFailed
        let action = manager.record_failure(&flow_id);
        assert!(matches!(action, Some(FlowAction::FlowFailed { .. })));
    }

    #[test]
    fn test_flow_transport_display() {
        assert_eq!(FlowTransport::Udp.to_string(), "UDP");
        assert_eq!(FlowTransport::Tls.to_string(), "TLS");
        assert_eq!(FlowTransport::WebSocket.to_string(), "WS");
    }

    #[test]
    fn test_flow_transport_properties() {
        assert!(!FlowTransport::Udp.is_connection_oriented());
        assert!(FlowTransport::Tcp.is_connection_oriented());
        assert!(FlowTransport::Tls.is_connection_oriented());

        assert_eq!(FlowTransport::Udp.keepalive_mechanism(), "STUN Binding");
        assert_eq!(FlowTransport::Tcp.keepalive_mechanism(), "CRLF ping");
    }

    #[test]
    fn test_flow_state_display() {
        assert_eq!(FlowState::Active.to_string(), "active");
        assert_eq!(FlowState::Probing.to_string(), "probing");
        assert_eq!(FlowState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_flow_manager_remove_failed() {
        let mut manager = OutboundFlowManager::with_config(
            DEFAULT_KEEPALIVE_INTERVAL,
            DEFAULT_KEEPALIVE_TIMEOUT,
            1, // Fail immediately
        );

        let flow_id = test_flow_id();
        manager.add_flow(flow_id.clone());

        // Make flow fail
        manager.record_failure(&flow_id);

        assert_eq!(manager.failed_flow_count(), 1);

        let removed = manager.remove_failed_flows();
        assert_eq!(removed.len(), 1);
        assert_eq!(manager.flow_count(), 0);
    }

    #[test]
    fn test_flow_id_display() {
        let flow_id = test_flow_id();
        let display = flow_id.to_string();
        assert!(display.contains("UDP"));
        assert!(display.contains("192.168.1.1:5060"));
        assert!(display.contains("10.0.0.1:5060"));
    }

    #[test]
    fn test_flow_manager_tick_udp() {
        let mut manager = OutboundFlowManager::new();
        let flow_id = FlowId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            FlowTransport::Udp,
        );

        manager.add_flow(flow_id.clone());

        // Tick should not generate actions immediately (flow just created)
        let actions = manager.tick();
        assert!(actions.is_empty());

        // Verify flow is tracked
        assert_eq!(manager.flow_count(), 1);
        assert!(manager.get_flow(&flow_id).is_some());
    }

    #[test]
    fn test_flow_manager_tick_tcp() {
        let mut manager = OutboundFlowManager::new();
        let flow_id = FlowId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            FlowTransport::Tcp,
        );

        manager.add_flow(flow_id.clone());

        // Tick should not generate actions immediately (flow just created)
        let actions = manager.tick();
        assert!(actions.is_empty());

        // Verify flow is tracked with correct transport
        let flow = manager.get_flow(&flow_id).unwrap();
        assert_eq!(flow.id().transport, FlowTransport::Tcp);
    }

    #[test]
    fn test_flow_recovery() {
        let flow_id = test_flow_id();
        let mut flow = Flow::new(flow_id);

        // Fail the flow
        flow.mark_failure(1);
        assert!(flow.is_failed());

        // Start recovery
        flow.start_recovery();
        assert_eq!(flow.state(), FlowState::Recovering);
        assert_eq!(flow.failure_count(), 0);
    }
}
