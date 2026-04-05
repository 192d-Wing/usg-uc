//! SIP stack integration layer.
//!
//! This module coordinates all SIP components into a working call flow:
//! - Message parsing via `proto-sip`
//! - Transaction handling via `sbc-transaction`
//! - Dialog management via `sbc-dialog`
//! - B2BUA call control via `sbc-b2bua`
//! - Registration handling via `sbc-registrar`
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - SIP events are logged
//! - **IA-2**: Identification and Authentication - REGISTER handling
//! - **SC-8**: Transmission Confidentiality and Integrity

use bytes::Bytes;
use proto_b2bua::{B2buaMode, Call, CallConfig, CallId, MediaAddress, SdpRewriter, extract_media_address};
use proto_dialog::{Dialog, DialogId};
#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
use proto_registrar::{
    AuthenticatedRegistrar, ContactInfo, LocationService, RegisterRequest, RegistrarConfig,
    RegistrarMode,
};
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id};
use proto_sip::uri::SipUri;
use proto_sip::{Header, HeaderName, Method, SipMessage, StatusCode};
use proto_transaction::{
    ClientInviteTransaction, ClientNonInviteTransaction, ServerInviteTransaction,
    ServerNonInviteTransaction, TransactionKey, TransportType,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use proto_sip::manipulation::{
    HeaderManipulator, ManipulationAction, ManipulationContext, ManipulationDirection,
    ManipulationPolicy, ManipulationRule,
};
use proto_sip::{TopologyHider, TopologyHidingConfig as SipTopologyConfig, TopologyHidingMode};
use tracing::{debug, error, info, warn};
use uc_routing::{
    DestinationType, DialPattern, DialPlan, DialPlanEntry, Direction, NumberTransform, Router,
    RouterConfig, SelectionStrategy, Trunk, TrunkConfig, TrunkGroup, TrunkProtocol,
};
use uc_types::address::SbcSocketAddr;

/// SIP stack for processing SIP messages.
pub struct SipStack {
    /// Transaction store.
    transactions: RwLock<TransactionStore>,
    /// Dialog store.
    dialogs: RwLock<DialogStore>,
    /// Call store (B2BUA).
    calls: RwLock<CallStore>,
    /// Authenticated registrar for REGISTER handling with digest auth.
    registrar: RwLock<AuthenticatedRegistrar>,
    /// Location service for routing (in-memory, shared with registrar).
    location_service: Arc<RwLock<LocationService>>,
    /// Async location service for routing (storage-backed, when cluster enabled).
    #[cfg(feature = "cluster")]
    async_location_service: Option<Arc<AsyncLocationService>>,
    /// Call correlation: maps A-leg/B-leg SIP Call-IDs to internal CallIds.
    call_correlation: RwLock<CallCorrelation>,
    /// SDP rewriter for media anchoring.
    sdp_rewriter: SdpRewriter,
    /// Media pipeline for RTP relay (optional, set after construction).
    media_pipeline: Option<Arc<crate::media_pipeline::MediaPipeline>>,
    /// Call router for dial plan matching and trunk selection.
    router: Option<RwLock<Router>>,
    /// CUCM-compatible router for CSS/Partition-based routing.
    cucm_router: Option<Arc<RwLock<uc_routing::CucmRouter>>>,
    /// SIP header manipulator for per-trunk/global header rules.
    header_manipulator: Option<HeaderManipulator>,
    /// Topology hider for Via/Contact/Call-ID anonymization.
    topology_hider: Option<RwLock<TopologyHider>>,
    /// Stack configuration.
    config: SipStackConfig,
    /// Resolved zone registry for interface-based binding.
    zone_registry: Option<Arc<crate::zone::ResolvedZoneRegistry>>,
    /// Inbound trunk identification: maps source IP → (trunk_group_id, css_id).
    /// Used to resolve which CSS to use for routing inbound calls from trunks.
    inbound_trunk_map: RwLock<std::collections::HashMap<std::net::IpAddr, (String, Option<String>)>>,
    /// Directory number mapping: DID → username for inbound call routing.
    did_map: RwLock<std::collections::HashMap<String, String>>,
    /// Registration statistics.
    registrations_active: AtomicU64,
    registrations_total: AtomicU64,
}

/// SIP stack configuration.
#[derive(Debug, Clone)]
pub struct SipStackConfig {
    /// Instance name for Via headers.
    pub instance_name: String,
    /// Local SIP domain.
    pub domain: String,
    /// Registrar mode.
    pub registrar_mode: RegistrarMode,
    /// Enable B2BUA mode.
    pub b2bua_enabled: bool,
    /// Authentication realm for digest auth.
    pub auth_realm: String,
    /// Whether authentication is required for REGISTER.
    pub require_auth: bool,
    /// Static credentials: username → password (for standalone deployment).
    pub auth_credentials: HashMap<String, String>,
}

impl Default for SipStackConfig {
    fn default() -> Self {
        Self {
            instance_name: "sbc-01".to_string(),
            domain: "sbc.local".to_string(),
            registrar_mode: RegistrarMode::B2bua,
            b2bua_enabled: true,
            auth_realm: "sbc.local".to_string(),
            require_auth: false,
            auth_credentials: HashMap::new(),
        }
    }
}

/// Store for active transactions.
#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct TransactionStore {
    /// Server INVITE transactions.
    server_invite: HashMap<TransactionKey, ServerInviteState>,
    /// Server non-INVITE transactions.
    server_non_invite: HashMap<TransactionKey, ServerNonInviteState>,
    /// Client INVITE transactions.
    client_invite: HashMap<TransactionKey, ClientInviteState>,
    /// Client non-INVITE transactions.
    client_non_invite: HashMap<TransactionKey, ClientNonInviteState>,
}

/// State for server INVITE transaction.
struct ServerInviteState {
    transaction: ServerInviteTransaction,
    source: SbcSocketAddr,
}

/// State for server non-INVITE transaction.
struct ServerNonInviteState {
    transaction: ServerNonInviteTransaction,
    source: SbcSocketAddr,
}

/// State for client INVITE transaction.
struct ClientInviteState {
    transaction: ClientInviteTransaction,
    destination: SbcSocketAddr,
}

/// State for client non-INVITE transaction.
struct ClientNonInviteState {
    transaction: ClientNonInviteTransaction,
    destination: SbcSocketAddr,
}

/// Store for active dialogs.
#[derive(Default)]
struct DialogStore {
    /// Dialogs indexed by dialog ID.
    dialogs: HashMap<DialogId, Dialog>,
}

/// Store for active calls (B2BUA).
#[derive(Default)]
struct CallStore {
    /// Calls indexed by call ID.
    calls: HashMap<CallId, Call>,
}

/// Correlates A-leg and B-leg SIP Call-IDs with internal B2BUA CallIds.
#[derive(Default)]
struct CallCorrelation {
    /// Maps A-leg SIP Call-ID → internal CallId.
    a_leg: HashMap<String, CallId>,
    /// Maps B-leg SIP Call-ID → internal CallId.
    b_leg: HashMap<String, CallId>,
    /// Maps internal CallId → call addressing info.
    addresses: HashMap<CallId, CallAddresses>,
    /// Call-IDs currently being handled by announcement playback (dedup retransmits).
    announcement_calls: std::collections::HashSet<String>,
}

/// Addressing info for both legs of a B2BUA call.
#[derive(Clone)]
struct CallAddresses {
    /// A-leg source address (where to send responses).
    a_leg_source: SbcSocketAddr,
    /// B-leg destination address (where to forward requests).
    b_leg_destination: SbcSocketAddr,
    /// A-leg SIP Call-ID.
    a_leg_sip_call_id: String,
    /// B-leg SIP Call-ID.
    b_leg_sip_call_id: String,
    /// SBC's local SIP address for Via/Contact headers.
    local_addr: String,
    /// Failover trunk IDs for retry on B-leg failure.
    failover_trunks: Vec<String>,
}

/// Result of processing a SIP message.
#[derive(Debug)]
pub enum ProcessResult {
    /// Message was processed, send response.
    Response {
        /// Response message.
        message: SipMessage,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Forward request to another destination.
    Forward {
        /// Request message.
        message: SipMessage,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Multiple actions (e.g., 100 Trying + forward INVITE, or BYE + 200 OK).
    Multiple(Vec<Self>),
    /// No action required (e.g., ACK for 2xx).
    NoAction,
    /// Error processing message.
    Error {
        /// Error description.
        reason: String,
    },
}

impl SipStack {
    /// Creates a new SIP stack.
    pub fn new(config: SipStackConfig) -> Self {
        let location_service = Arc::new(RwLock::new(LocationService::new()));

        let registrar_config = RegistrarConfig {
            mode: config.registrar_mode,
            realm: config.auth_realm.clone(),
            require_auth: config.require_auth,
            ..RegistrarConfig::default()
        };

        // Build authenticated registrar with password lookup from config
        let credentials = config.auth_credentials.clone();
        let registrar =
            AuthenticatedRegistrar::new(registrar_config).with_password_lookup(move |user, _| {
                credentials.get(user).cloned()
            });

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            location_service,
            #[cfg(feature = "cluster")]
            async_location_service: None,
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
            router: None,
            cucm_router: None,
            header_manipulator: None,
            topology_hider: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Creates a new SIP stack with a storage-backed async location service.
    #[cfg(feature = "cluster")]
    pub fn new_with_location_service(
        config: SipStackConfig,
        async_location_service: Arc<AsyncLocationService>,
    ) -> Self {
        let location_service = Arc::new(RwLock::new(LocationService::new()));

        let registrar_config = RegistrarConfig {
            mode: config.registrar_mode,
            realm: config.auth_realm.clone(),
            require_auth: config.require_auth,
            ..RegistrarConfig::default()
        };

        let credentials = config.auth_credentials.clone();
        let registrar =
            AuthenticatedRegistrar::new(registrar_config).with_password_lookup(move |user, _| {
                credentials.get(user).cloned()
            });

        info!("SIP stack initialized with storage-backed location service");

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            location_service,
            async_location_service: Some(async_location_service),
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
            router: None,
            cucm_router: None,
            header_manipulator: None,
            topology_hider: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Sets the media pipeline for RTP relay.
    pub fn set_media_pipeline(&mut self, pipeline: Arc<crate::media_pipeline::MediaPipeline>) {
        self.media_pipeline = Some(pipeline);
    }

    /// Sets the zone registry for zone-aware SIP processing.
    pub fn set_zone_registry(&mut self, registry: Arc<crate::zone::ResolvedZoneRegistry>) {
        self.zone_registry = Some(registry);
    }

    /// Returns the effective signaling IP for a zone, falling back to source IP.
    fn zone_signaling_ip(&self, zone: Option<&str>, fallback: std::net::IpAddr) -> String {
        if let (Some(name), Some(reg)) = (zone, &self.zone_registry) {
            reg.signaling_ip(name)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| fallback.to_string())
        } else {
            fallback.to_string()
        }
    }

    /// Returns the effective media IP for a zone, falling back to source IP.
    fn zone_media_ip(&self, zone: Option<&str>, fallback: std::net::IpAddr) -> String {
        if let (Some(name), Some(reg)) = (zone, &self.zone_registry) {
            reg.media_ip(name)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| fallback.to_string())
        } else {
            fallback.to_string()
        }
    }

    /// Sets the CUCM router for CSS/Partition-based call routing.
    pub fn set_cucm_router(&mut self, router: Arc<RwLock<uc_routing::CucmRouter>>) {
        self.cucm_router = Some(router);
    }

    /// Initializes the call router from SBC config sections.
    ///
    /// Builds dial plans and trunk groups from the config, then creates
    /// a Router instance for call routing.
    pub fn init_router_from_config(
        &mut self,
        routing_config: &sbc_config::RoutingConfig,
        dial_plan_configs: &[sbc_config::DialPlanConfig],
        trunk_group_configs: &[sbc_config::TrunkGroupConfig],
    ) {
        let router_config = RouterConfig {
            use_dial_plan: routing_config.use_dial_plan,
            max_failover_attempts: routing_config.max_failover_attempts as usize,
            default_trunk_group: Some(routing_config.default_trunk_group.clone()),
        };

        let mut router = Router::new(router_config);

        // Load trunk groups first (dial plan entries reference them)
        for tg_config in trunk_group_configs {
            let strategy = match tg_config.strategy.as_str() {
                "round_robin" => SelectionStrategy::RoundRobin,
                "weighted_random" => SelectionStrategy::WeightedRandom,
                "least_connections" => SelectionStrategy::LeastConnections,
                "best_success_rate" => SelectionStrategy::BestSuccessRate,
                _ => SelectionStrategy::Priority,
            };

            let mut group = TrunkGroup::new(&tg_config.id, &tg_config.name)
                .with_strategy(strategy);

            for t_config in &tg_config.trunks {
                let protocol = match t_config.protocol.as_str() {
                    "tcp" => TrunkProtocol::Tcp,
                    "tls" => TrunkProtocol::Tls,
                    _ => TrunkProtocol::Udp,
                };

                let trunk_config = TrunkConfig::new(&t_config.id, &t_config.host)
                    .with_port(t_config.port)
                    .with_protocol(protocol)
                    .with_priority(t_config.priority)
                    .with_weight(t_config.weight)
                    .with_max_calls(t_config.max_calls);

                group.add_trunk(Trunk::new(trunk_config));
            }

            router.add_trunk_group(group);
        }

        // Load dial plans
        for dp_config in dial_plan_configs {
            if !dp_config.active {
                continue;
            }

            let mut plan = DialPlan::new(&dp_config.id, &dp_config.name);

            for (idx, entry_config) in dp_config.entries.iter().enumerate() {
                let pattern = match entry_config.pattern_type.as_str() {
                    "exact" => DialPattern::exact(&entry_config.pattern_value),
                    "wildcard" => DialPattern::wildcard(&entry_config.pattern_value),
                    "any" => DialPattern::Any,
                    _ => DialPattern::prefix(&entry_config.pattern_value),
                };

                let direction = match entry_config.direction.as_str() {
                    "inbound" => Direction::Inbound,
                    "both" => Direction::Both,
                    _ => Direction::Outbound,
                };

                let dest_type = match entry_config.destination_type.as_str() {
                    "registered_user" => DestinationType::RegisteredUser,
                    "static_uri" => DestinationType::StaticUri,
                    _ => DestinationType::TrunkGroup,
                };

                let transform = match entry_config.transform_type.as_str() {
                    "strip_prefix" => {
                        let count = entry_config.transform_value.parse().unwrap_or(0);
                        NumberTransform::strip_prefix(count)
                    }
                    "add_prefix" => {
                        NumberTransform::add_prefix(&entry_config.transform_value)
                    }
                    "replace_prefix" => {
                        let parts: Vec<&str> = entry_config.transform_value.splitn(2, '|').collect();
                        if parts.len() == 2 {
                            NumberTransform::replace_prefix(parts[0], parts[1])
                        } else {
                            NumberTransform::None
                        }
                    }
                    _ => NumberTransform::None,
                };

                let entry_id = format!("{}-{idx}", dp_config.id);
                let mut entry = DialPlanEntry::new(entry_id, pattern, &entry_config.trunk_group)
                    .with_transform(transform)
                    .with_priority(entry_config.priority)
                    .with_direction(direction)
                    .with_destination_type(dest_type);

                if let Some(ref domain) = entry_config.domain_pattern {
                    entry = entry.with_domain_pattern(domain);
                }
                if let Some(ref trunk) = entry_config.source_trunk {
                    entry = entry.with_source_trunk(trunk);
                }
                if let Some(ref dest) = entry_config.static_destination {
                    entry = entry.with_static_destination(dest);
                }

                plan.add_entry(entry);
            }

            router.add_dial_plan(plan);
        }

        let plan_count = dial_plan_configs.iter().filter(|p| p.active).count();
        let trunk_count: usize = trunk_group_configs.iter().map(|g| g.trunks.len()).sum();

        info!(
            dial_plans = plan_count,
            trunk_groups = trunk_group_configs.len(),
            trunks = trunk_count,
            "Router initialized from config"
        );

        self.router = Some(RwLock::new(router));
    }

    /// Initializes the header manipulator from config.
    pub fn init_manipulator_from_config(
        &mut self,
        config: &sbc_config::HeaderManipulationConfig,
    ) {
        let mut manipulator = HeaderManipulator::new();

        for rule_config in &config.global_rules {
            let direction = match rule_config.direction.as_str() {
                "inbound" => Some(ManipulationDirection::Inbound),
                "outbound" => Some(ManipulationDirection::Outbound),
                _ => None, // "both" or default
            };

            let action = parse_manipulation_action(&rule_config.action, &rule_config.header, &rule_config.value);

            let mut policy = ManipulationPolicy::new(&rule_config.name);
            if let Some(dir) = direction {
                policy = policy.with_direction(dir);
            }
            policy.add_rule(ManipulationRule::new(
                &rule_config.name,
                proto_sip::manipulation::ManipulationCondition::Always,
                action,
            ));
            manipulator.add_global_policy(policy);
        }

        for rule_config in &config.trunk_rules {
            let action = parse_manipulation_action(&rule_config.action, &rule_config.header, &rule_config.value);
            let mut policy = ManipulationPolicy::new(&rule_config.name);
            policy.add_rule(ManipulationRule::new(
                &rule_config.name,
                proto_sip::manipulation::ManipulationCondition::Always,
                action,
            ));
            manipulator.add_trunk_policy(&rule_config.trunk_id, policy);
        }

        let global_count = config.global_rules.len();
        let trunk_count = config.trunk_rules.len();

        info!(
            global_rules = global_count,
            trunk_rules = trunk_count,
            "Header manipulator initialized"
        );

        self.header_manipulator = Some(manipulator);
    }

    /// Initializes the topology hider from config.
    pub fn init_topology_hider_from_config(
        &mut self,
        config: &sbc_config::TopologyHidingConfig,
    ) {
        if !config.enabled {
            return;
        }

        let mode = match config.mode.as_str() {
            "signaling_only" => TopologyHidingMode::Basic,
            "full" => TopologyHidingMode::Aggressive,
            _ => return, // "none"
        };

        let topo_config = SipTopologyConfig::new(&config.external_host)
            .with_port(config.external_port)
            .with_mode(mode)
            .with_call_id_obfuscation(config.obfuscate_call_id);

        let hider = TopologyHider::new(topo_config);

        info!(
            mode = %config.mode,
            external_host = %config.external_host,
            obfuscate_call_id = config.obfuscate_call_id,
            "Topology hider initialized"
        );

        self.topology_hider = Some(RwLock::new(hider));
    }

    /// Returns whether the stack has a storage-backed location service.
    #[cfg(feature = "cluster")]
    pub fn has_async_location_service(&self) -> bool {
        self.async_location_service.is_some()
    }

    /// Processes an incoming SIP message.
    ///
    /// `receiving_zone` is the zone name this message arrived on (if zones configured).
    pub async fn process_message(&self, data: &Bytes, source: SbcSocketAddr, _receiving_zone: Option<&str>) -> ProcessResult {
        // Parse the SIP message
        let message = match SipMessage::parse(data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!(error = %e, "Failed to parse SIP message");
                return ProcessResult::Error {
                    reason: format!("Parse error: {e}"),
                };
            }
        };

        debug!(
            message_type = if message.is_request() {
                "request"
            } else {
                "response"
            },
            source = %source,
            "Processing SIP message"
        );

        match message {
            SipMessage::Request(_) => self.process_request(message, source).await,
            SipMessage::Response(_) => self.process_response(message, source).await,
        }
    }

    /// Processes a SIP request.
    async fn process_request(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let method = req.method.clone();
        let call_id = req.headers.call_id().map(String::from);

        info!(
            method = %method,
            call_id = call_id.as_deref().unwrap_or("none"),
            source = %source,
            "Received SIP request"
        );

        match method {
            Method::Register => self.handle_register(message, source).await,
            Method::Invite => self.handle_invite(message, source).await,
            Method::Ack => self.handle_ack(message).await,
            Method::Bye => self.handle_bye(message, source).await,
            Method::Cancel => self.handle_cancel(message, source).await,
            Method::Options => self.handle_options(message, source).await,
            _ => self.handle_other_request(message, source).await,
        }
    }

    /// Processes a SIP response.
    ///
    /// In B2BUA mode, matches the response to the B-leg client transaction,
    /// then forwards an appropriate response to the A-leg.
    async fn process_response(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Response(ref resp) = message else {
            return ProcessResult::Error {
                reason: "Expected response".to_string(),
            };
        };

        let status_code = resp.status.code();
        let sip_call_id = resp
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(
            status = status_code,
            call_id = %sip_call_id,
            source = %source,
            "Received SIP response"
        );

        // Look up the B-leg Call-ID in correlation map
        let corr = self.call_correlation.read().await;
        let Some(id) = corr.b_leg.get(&sip_call_id) else {
            debug!(call_id = %sip_call_id, "Response for unknown B-leg Call-ID, ignoring");
            return ProcessResult::NoAction;
        };
        let internal_id = id.clone();

        let Some(a) = corr.addresses.get(&internal_id) else {
            warn!(call_id = %sip_call_id, "No addresses for call");
            return ProcessResult::NoAction;
        };
        let addrs = a.clone();
        drop(corr);

        // Handle based on status code class
        if status_code == 100 {
            // 100 Trying — absorb, do not forward to A-leg (RFC 3261 §16.7)
            debug!("Absorbing 100 Trying from B-leg");
            return ProcessResult::NoAction;
        }

        if (101..200).contains(&status_code) {
            // 1xx provisional (180 Ringing, 183 Session Progress)
            return self
                .handle_provisional_response(resp, &internal_id, &addrs)
                .await;
        }

        if (200..300).contains(&status_code) {
            // 2xx success (200 OK)
            return self
                .handle_success_response(resp, &internal_id, &addrs)
                .await;
        }

        // 4xx/5xx/6xx error — forward to A-leg, cleanup
        self.handle_error_response(resp, status_code, &internal_id, &addrs)
            .await
    }

    /// Handles 1xx provisional response from B-leg (180 Ringing, 183 Session Progress).
    async fn handle_provisional_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        let status_code = resp.status.code();

        // Update call state
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.receive_provisional(status_code);
            }
        }

        // Build provisional response for A-leg with A-leg's Call-ID
        let mut a_response = proto_sip::message::SipResponse::new(resp.status);

        // Copy Via from A-leg (original request's Via, not B-leg's)
        // For now, copy from B-leg response and trust the headers
        copy_response_headers(resp, &mut a_response);

        // Replace Call-ID with A-leg's
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // If 183 with SDP, rewrite SDP for A-leg
        if status_code == 183
            && let Some(ref body) = resp.body {
                let sdp_str = String::from_utf8_lossy(body);
                let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
                let local_media = MediaAddress::new(local_ip, 20_002);
                let result = self
                    .sdp_rewriter
                    .rewrite_answer_for_a_leg(&sdp_str, &local_media);
                a_response.body = Some(Bytes::from(result.rewritten));
                a_response
                    .headers
                    .set(HeaderName::ContentType, "application/sdp");
            }

        info!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Forwarding provisional response to A-leg"
        );

        ProcessResult::Response {
            message: SipMessage::Response(a_response),
            destination: addrs.a_leg_source,
        }
    }

    /// Handles 200 OK from B-leg: activate call, rewrite SDP, send ACK to B-leg.
    async fn handle_success_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        // Activate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.activate();
            }
        }

        // Extract B-leg's RTP address from SDP
        if let Some(ref body) = resp.body {
            let sdp_str = String::from_utf8_lossy(body);
            if let Some(_remote_media) = extract_media_address(&sdp_str) {
                // Phase 4 will use this to set_remote_address on MediaPipeline
                debug!(
                    call_id = %addrs.a_leg_sip_call_id,
                    "B-leg RTP address extracted from SDP"
                );
            }
        }

        // Build 200 OK for A-leg with rewritten SDP
        let mut a_response = proto_sip::message::SipResponse::new(StatusCode::OK);
        copy_response_headers(resp, &mut a_response);
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // Rewrite SDP for A-leg
        if let Some(ref body) = resp.body {
            let sdp_str = String::from_utf8_lossy(body);
            let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
            let local_media = MediaAddress::new(local_ip, 20_002);
            let result = self
                .sdp_rewriter
                .rewrite_answer_for_a_leg(&sdp_str, &local_media);
            a_response.body = Some(Bytes::from(result.rewritten));
            a_response
                .headers
                .set(HeaderName::ContentType, "application/sdp");
            // Update Content-Length
            if let Some(ref body) = a_response.body {
                a_response
                    .headers
                    .set(HeaderName::ContentLength, body.len().to_string());
            }
        }

        // Build ACK for B-leg
        let b_leg_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut ack_request = proto_sip::message::SipRequest::new(Method::Ack, b_leg_uri);
        ack_request.headers.set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        ack_request.headers.set(HeaderName::CSeq, "1 ACK");
        let _local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");
        let branch = generate_branch();
        ack_request.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        ack_request.headers.set(HeaderName::ContentLength, "0");

        info!(
            call_id = %addrs.a_leg_sip_call_id,
            "Call connected: 200 OK → A-leg, ACK → B-leg"
        );

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(a_response),
                destination: addrs.a_leg_source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(ack_request),
                destination: addrs.b_leg_destination,
            },
        ])
    }

    /// Handles 4xx/5xx/6xx error response from B-leg.
    async fn handle_error_response(
        &self,
        resp: &proto_sip::message::SipResponse,
        status_code: u16,
        internal_id: &CallId,
        addrs: &CallAddresses,
    ) -> ProcessResult {
        // Check for failover trunks before giving up
        if !addrs.failover_trunks.is_empty()
            && let Some(ref router_lock) = self.router
        {
            let mut remaining = addrs.failover_trunks.clone();
            let next_trunk_id = remaining.remove(0);

            // Look up trunk URI from router
            let router = router_lock.read().await;
            let trunk_addr = router
                .get_trunk_group(
                    addrs.failover_trunks.first().map_or("default", |_| "default"),
                )
                .and_then(|_| resolve_sip_uri_to_addr(&format!("sip:{next_trunk_id}")));
            drop(router);

            if let Some(new_dest) = trunk_addr {
                let new_call_id = generate_call_id(&self.config.domain);
                let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");

                let new_uri = SipUri::new(new_dest.ip().to_string())
                    .with_port(new_dest.port());
                let builder = RequestBuilder::invite(new_uri)
                    .via_auto("UDP", local_ip, Some(new_dest.port()))
                    .call_id(&new_call_id)
                    .cseq(1)
                    .max_forwards(70);

                if let Ok(new_request) = builder.build_with_defaults() {
                    {
                        let mut corr = self.call_correlation.write().await;
                        corr.b_leg.remove(&addrs.b_leg_sip_call_id);
                        corr.b_leg.insert(new_call_id.clone(), internal_id.clone());
                        if let Some(addr_entry) = corr.addresses.get_mut(internal_id) {
                            addr_entry.b_leg_destination = new_dest;
                            addr_entry.b_leg_sip_call_id.clone_from(&new_call_id);
                            addr_entry.failover_trunks = remaining;
                        }
                    }

                    info!(
                        failed_trunk = %addrs.b_leg_sip_call_id,
                        next_trunk = %next_trunk_id,
                        call_id = %addrs.a_leg_sip_call_id,
                        "Trunk failover: retrying with next trunk"
                    );

                    return ProcessResult::Forward {
                        message: SipMessage::Request(new_request),
                        destination: new_dest,
                    };
                }
            }
        }

        // No failover available — fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                call.fail(status_code, resp.reason_phrase());
            }
        }

        // Build error response for A-leg
        let mut a_response = proto_sip::message::SipResponse::new(resp.status);
        copy_response_headers(resp, &mut a_response);
        a_response
            .headers
            .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);

        // Cleanup call state
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(internal_id);
        }

        warn!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Call failed, forwarding error to A-leg"
        );

        ProcessResult::Response {
            message: SipMessage::Response(a_response),
            destination: addrs.a_leg_source,
        }
    }

    /// Handles REGISTER request.
    ///
    /// Processes registration through `AuthenticatedRegistrar` which handles:
    /// - Digest authentication challenge/response (RFC 3261 §22)
    /// - Binding storage in `LocationService`
    /// - Expiration enforcement (min/max/default)
    /// - Wildcard removal (Contact: *)
    async fn handle_register(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing REGISTER");

        // Parse AOR from To header
        let aor = match req.headers.get_value(&HeaderName::To) {
            Some(to) => extract_uri_from_header(to),
            None => {
                return ProcessResult::Response {
                    message: SipMessage::Response(create_response_from_request(
                        req,
                        StatusCode::BAD_REQUEST,
                    )),
                    destination: source,
                };
            }
        };

        // Parse Contact headers into ContactInfo list
        let contacts = parse_contacts_from_request(req);

        // Parse Expires header
        let expires: Option<u32> = req
            .headers
            .get_value(&HeaderName::Expires)
            .and_then(|v| v.parse().ok());

        // Parse Call-ID and CSeq
        let call_id = req
            .headers
            .call_id()
            .unwrap_or("unknown")
            .to_string();
        let cseq: u32 = req
            .headers
            .cseq()
            .and_then(|c| c.split_whitespace().next()?.parse().ok())
            .unwrap_or(1);

        // Build RegisterRequest
        let register_req = RegisterRequest::new(&aor)
            .with_contacts(contacts)
            .with_call_id(&call_id)
            .with_cseq(cseq);
        let register_req = if let Some(exp) = expires {
            RegisterRequest { expires: Some(exp), ..register_req }
        } else {
            register_req
        };
        let register_req = if let Some(auth) = req.headers.get_value(&HeaderName::Authorization) {
            register_req.with_authorization(auth)
        } else {
            register_req
        };
        let register_req = RegisterRequest {
            source_address: Some(source.to_string()),
            ..register_req
        };

        // Process through AuthenticatedRegistrar
        let reg_response = {
            let mut registrar = self.registrar.write().await;
            match registrar.process_register(&register_req) {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(error = %e, aor = %aor, "Registration processing failed");
                    return ProcessResult::Response {
                        message: SipMessage::Response(create_response_from_request(
                            req,
                            StatusCode::SERVER_INTERNAL_ERROR,
                        )),
                        destination: source,
                    };
                }
            }
        };

        // Build SIP response from RegisterResponse
        let status = StatusCode::new(reg_response.status_code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR);
        let mut response = create_response_from_request(req, status);

        match reg_response.status_code {
            200 => {
                // Add Contact headers for all current bindings
                for contact_str in reg_response.format_contacts() {
                    response.add_header(Header::new(HeaderName::Contact, contact_str));
                }

                // Sync bindings to shared location service for routing
                let binding_count = reg_response.contacts.len();
                {
                    let mut loc = self.location_service.write().await;
                    // Remove existing bindings for this AOR and re-add current ones
                    let _ = loc.remove_all_bindings(&aor);
                    for binding in &reg_response.contacts {
                        // If Contact has 0.0.0.0, substitute the actual source IP
                        // so the SBC can route calls back to the phone
                        let contact = binding.contact_uri();
                        let fixed_contact = if contact.contains("0.0.0.0") {
                            let src_ip = match source.ip() {
                                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped()
                                    .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
                                std::net::IpAddr::V4(v4) => v4.to_string(),
                            };
                            contact.replace("0.0.0.0", &src_ip)
                        } else {
                            contact.to_string()
                        };
                        let new_binding = proto_registrar::Binding::new(
                            &aor,
                            &fixed_contact,
                            &call_id,
                            cseq,
                        );
                        let _ = loc.add_binding(new_binding);
                    }
                }

                self.registrations_total.fetch_add(1, Ordering::Relaxed);
                // Update active count based on location service
                self.registrations_active.store(
                    {
                        let loc = self.location_service.read().await;
                        loc.total_bindings() as u64
                    },
                    Ordering::Relaxed,
                );

                info!(
                    aor = %aor,
                    bindings = binding_count,
                    "Registration successful"
                );
            }
            401 => {
                // Add WWW-Authenticate challenge header
                if let Some(ref www_auth) = reg_response.www_authenticate {
                    response.add_header(Header::new(
                        HeaderName::WwwAuthenticate,
                        www_auth.as_str(),
                    ));
                }
                debug!(aor = %aor, "Registration challenged (401)");
            }
            423 => {
                // Add Min-Expires header
                if let Some(min_exp) = reg_response.min_expires {
                    response.add_header(Header::new(
                        HeaderName::Custom("Min-Expires".to_string()),
                        min_exp.to_string(),
                    ));
                }
                debug!(aor = %aor, "Registration interval too brief (423)");
            }
            _ => {
                warn!(
                    aor = %aor,
                    status = reg_response.status_code,
                    reason = %reg_response.reason,
                    "Registration failed"
                );
            }
        }

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles INVITE request.
    ///
    /// B2BUA call flow:
    /// 1. Send 100 Trying to A-leg
    /// 2. Look up destination in LocationService (registered users) or resolve directly
    /// 3. Create B2BUA Call with A-leg/B-leg config
    /// 4. Rewrite SDP with SBC's address for media anchoring
    /// 5. Build B-leg INVITE with new headers
    /// 6. Return Multiple(100 Trying + Forward B-leg INVITE)
    async fn handle_invite(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let a_leg_call_id = req
            .headers
            .call_id()
            .unwrap_or("unknown")
            .to_string();

        debug!(uri = %req.uri, call_id = %a_leg_call_id, "Processing INVITE");

        // Check for INVITE retransmit — if we already know this Call-ID, absorb it
        {
            let corr = self.call_correlation.read().await;
            if corr.a_leg.contains_key(&a_leg_call_id)
                || corr.announcement_calls.contains(&a_leg_call_id)
            {
                debug!(call_id = %a_leg_call_id, "INVITE retransmit, absorbing");
                return ProcessResult::NoAction;
            }
        }

        // 1. Build 100 Trying for A-leg
        let trying = create_response_from_request(req, StatusCode::TRYING);

        // 2. Extract destination from Request-URI
        let dest_user = req.uri.user.as_deref().unwrap_or("").to_string();
        let dest_host = req.uri.host.clone();
        let dest_aor = format!("sip:{dest_user}@{dest_host}");

        // 3. Look up destination:
        //    a) Check DID → user mapping, then LocationService
        //    b) Check LocationService directly for registered users
        //    c) Try CUCM router (CSS/Partition)
        //    d) Try dial plan router
        //    e) Fall back to announcement
        let failover_trunks: Vec<String> = Vec::new();
        let b_leg_destination = {
            // Check DID → user mapping first (e.g., +12139160002 → jwillman)
            let mapped_user = self.lookup_did(&dest_user).await;

            // Build AOR candidates for location service lookup
            let loc = self.location_service.read().await;
            let mut found_contact = None;

            if let Some(ref user) = mapped_user {
                info!(did = %dest_user, user = %user, "DID mapped to registered user");
                // Try the mapped user with the dest host first, then with known zone IPs
                let candidates = [
                    format!("sip:{user}@{dest_host}"),
                ];
                for aor in &candidates {
                    let bindings = loc.lookup(aor);
                    if let Some(binding) = bindings.first() {
                        let contact = binding.contact_uri().to_string();
                        info!(aor = %aor, contact = %contact, "Routing to registered user");
                        found_contact = Some(contact);
                        break;
                    }
                }
                // If not found with dest_host, try with zone IPs
                if found_contact.is_none() {
                    if let Some(ref zr) = self.zone_registry {
                        for zone_name in &["inside", "outside", "oobm"] {
                            if let Some(ip) = zr.signaling_ip(zone_name) {
                                let aor = format!("sip:{user}@{ip}");
                                let bindings = loc.lookup(&aor);
                                if let Some(binding) = bindings.first() {
                                    let contact = binding.contact_uri().to_string();
                                    info!(aor = %aor, contact = %contact, zone = zone_name, "Routing to registered user via zone lookup");
                                    found_contact = Some(contact);
                                    break;
                                }
                            }
                        }
                    }
                }
                if found_contact.is_none() {
                    warn!(user = %user, "DID mapped but user not registered on any zone");
                }
            } else {
                // Direct AOR lookup (no DID mapping)
                let bindings = loc.lookup(&dest_aor);
                if let Some(binding) = bindings.first() {
                    let contact = binding.contact_uri().to_string();
                    info!(aor = %dest_aor, contact = %contact, "Routing to registered user");
                    found_contact = Some(contact);
                }
            }
            drop(loc);

            if let Some(contact) = found_contact {
                resolve_sip_uri_to_addr(&contact)
            } else {
                // Not registered — try CUCM router (CSS-based), then dial plan, then direct
                let mut routed = None;

                // Identify which trunk group this inbound call came from (by source IP)
                // and get its assigned CSS for routing
                let source_ip = match source.ip() {
                    std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped()
                        .map(std::net::IpAddr::V4)
                        .unwrap_or(std::net::IpAddr::V6(v6)),
                    ip => ip,
                };
                let inbound_trunk = self.lookup_inbound_trunk(source_ip).await;
                let css_id_owned = inbound_trunk.as_ref().and_then(|(_, css)| css.clone());

                if let Some((ref tg_id, ref css)) = inbound_trunk {
                    info!(
                        trunk_group = %tg_id,
                        css = ?css,
                        source = %source_ip,
                        dest = %dest_user,
                        "Identified inbound trunk for CSS routing"
                    );
                }

                // 1. Route via CUCM router (CSS/Partition → Route Pattern → Route List → Route Group)
                if let Some(ref cucm) = self.cucm_router {
                    let cucm_r = cucm.read().await;
                    let css_ref = css_id_owned.as_deref();
                    if let Some(result) = cucm_r.route(&dest_user, css_ref) {
                        info!(
                            pattern = %result.pattern_id,
                            partition = %result.partition_id,
                            destination = %result.transformed_number,
                            css = ?css_ref,
                            "Routed via CUCM CSS/Partition"
                        );
                        if let Some(rg_id) = result.route_group_ids.first() {
                            routed = resolve_sip_uri_to_addr(&format!("sip:{rg_id}"));
                        }
                    }
                }

                // 2. Route via dial plan → trunk group → trunk
                if routed.is_none() {
                    if let Some(ref router_lock) = self.router {
                        let mut router = router_lock.write().await;
                        info!(dest = %dest_user, "Attempting dial plan routing");
                        match router.route(&dest_user) {
                            Ok(decision) => {
                                info!(
                                    trunk_id = %decision.trunk_id,
                                    trunk_uri = %decision.trunk_uri,
                                    destination = %decision.destination,
                                    "Routed via dial plan"
                                );
                                routed = resolve_sip_uri_to_addr(&decision.trunk_uri);
                                if routed.is_none() {
                                    warn!(trunk_uri = %decision.trunk_uri, "Could not resolve trunk URI to address");
                                }
                            }
                            Err(e) => {
                                warn!(dest = %dest_user, error = %e, "Dial plan routing failed");
                            }
                        }
                    } else {
                        warn!("No router configured on SIP stack");
                    }
                }

                if routed.is_none() {
                    warn!(dest = %dest_aor, "No route found — playing announcement");
                    return self.play_announcement_to_caller(
                        req,
                        source,
                        crate::announcement::AnnouncementType::NumberNotInService,
                    ).await;
                }

                routed
            }
        };

        let Some(b_leg_destination) = b_leg_destination else {
            warn!(dest = %dest_aor, "Cannot resolve destination — playing announcement");
            return self.play_announcement_to_caller(
                req,
                source,
                crate::announcement::AnnouncementType::NumberNotInService,
            ).await;
        };

        // 4. Create B2BUA call
        let internal_call_id = CallId::generate();
        let a_leg_from = req
            .headers
            .get_value(&HeaderName::From)
            .map(extract_uri_from_header)
            .unwrap_or_default();

        let call_config = CallConfig::new(
            format!("sip:{}@{}", self.config.instance_name, self.config.domain),
            a_leg_from,
            format!("sip:{}@{}", self.config.instance_name, self.config.domain),
            dest_aor.clone(),
        )
        .with_call_id(internal_call_id.clone());

        let mut call = Call::new(call_config);
        if let Err(e) = call.receive() {
            error!(error = %e, "Failed to transition call to Received");
        }
        if let Err(e) = call.start_routing() {
            error!(error = %e, "Failed to transition call to Routing");
        }

        // 5. Determine SBC's local address for SDP rewriting
        let local_ip = source.ip().to_string(); // Use the address we received on
        let local_sip_addr = format!("{}:{}", local_ip, source.port());

        // 6. Rewrite SDP for B-leg (replace A-leg's address with SBC's)
        let b_leg_sdp = req.body.as_ref().map(|body| {
            let sdp_str = String::from_utf8_lossy(body);
            // For now, use a placeholder port -- Phase 4 will allocate real RTP ports
            let local_media = MediaAddress::new(&local_ip, 20_000);
            let result = self
                .sdp_rewriter
                .rewrite_offer_for_b_leg(&sdp_str, &local_media);
            result.rewritten
        });

        // 7. Build B-leg INVITE
        let b_leg_sip_call_id = generate_call_id(&self.config.domain);
        let b_leg_branch = generate_branch();

        let mut b_leg_uri = SipUri::new(&dest_host).with_user(&dest_user);
        if let Some(port) = req.uri.port {
            b_leg_uri.port = Some(port);
        }

        let mut builder = RequestBuilder::invite(b_leg_uri)
            .via_auto("UDP", &local_ip, Some(source.port()))
            .from_auto(
                SipUri::new(&self.config.domain).with_user(&self.config.instance_name),
                None,
            )
            .to_uri(
                SipUri::new(&dest_host).with_user(&dest_user),
                None,
            )
            .call_id(&b_leg_sip_call_id)
            .cseq(1)
            .max_forwards(70)
            .contact_uri(
                SipUri::new(&local_ip).with_port(source.port()),
            );

        if let Some(ref sdp) = b_leg_sdp {
            builder = builder.body_sdp(sdp.as_bytes().to_vec());
        }

        let mut b_leg_request = match builder.build_with_defaults() {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build B-leg INVITE");
                let server_err = create_response_from_request(
                    req,
                    StatusCode::SERVER_INTERNAL_ERROR,
                );
                return ProcessResult::Response {
                    message: SipMessage::Response(server_err),
                    destination: source,
                };
            }
        };

        // 7b. Apply header manipulation to B-leg INVITE
        if let Some(ref manipulator) = self.header_manipulator {
            let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
            if let Ok(count) = manipulator.apply(&mut b_leg_request.headers, &context)
                && count > 0
            {
                debug!(rules_applied = count, "Header manipulation applied to B-leg INVITE");
            }
        }

        // 7c. Apply topology hiding to B-leg INVITE
        // (strip internal Via headers, anonymize Contact)
        // TopologyHider modifies headers in-place — will be fully wired in Phase 4

        // 8. Store call state and correlation
        {
            let mut calls = self.calls.write().await;
            calls.calls.insert(internal_call_id.clone(), call);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.insert(a_leg_call_id.clone(), internal_call_id.clone());
            corr.b_leg.insert(b_leg_sip_call_id.clone(), internal_call_id.clone());
            corr.addresses.insert(
                internal_call_id.clone(),
                CallAddresses {
                    a_leg_source: source,
                    b_leg_destination,
                    a_leg_sip_call_id: a_leg_call_id.clone(),
                    b_leg_sip_call_id: b_leg_sip_call_id.clone(),
                    local_addr: local_sip_addr,
                    failover_trunks,
                },
            );
        }

        // 9. Create transactions
        {
            let a_branch = req
                .headers
                .get_value(&HeaderName::Via)
                .and_then(|v| extract_param(v, "branch").map(String::from))
                .unwrap_or_else(generate_branch);

            let mut txns = self.transactions.write().await;
            let server_key = TransactionKey::server(&a_branch, "INVITE");
            txns.server_invite.insert(
                server_key,
                ServerInviteState {
                    transaction: ServerInviteTransaction::new(
                        TransactionKey::server(&a_branch, "INVITE"),
                        TransportType::Unreliable,
                    ),
                    source,
                },
            );

            let client_key = TransactionKey::client(&b_leg_branch, "INVITE");
            txns.client_invite.insert(
                client_key,
                ClientInviteState {
                    transaction: ClientInviteTransaction::new(
                        TransactionKey::client(&b_leg_branch, "INVITE"),
                        TransportType::Unreliable,
                    ),
                    destination: b_leg_destination,
                },
            );
        }

        info!(
            call_id = %a_leg_call_id,
            b_leg_call_id = %b_leg_sip_call_id,
            destination = %b_leg_destination,
            "INVITE routed: A-leg → SBC → B-leg"
        );

        // 10. Return 100 Trying to A-leg + forward INVITE to B-leg
        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(trying),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_leg_request),
                destination: b_leg_destination,
            },
        ])
    }

    /// Handles ACK request.
    async fn handle_ack(&self, message: SipMessage) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing ACK");

        // ACK for 2xx completes dialog establishment
        // ACK for non-2xx is absorbed by transaction layer
        ProcessResult::NoAction
    }

    /// Handles BYE request.
    ///
    /// B2BUA BYE flow:
    /// 1. Look up Call-ID → find internal call (could be A-leg or B-leg)
    /// 2. Send 200 OK to BYE sender
    /// 3. Build BYE for the other leg
    /// 4. Stop media relay and clean up call state
    async fn handle_bye(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let sip_call_id = req
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(call_id = %sip_call_id, "Processing BYE");

        // Look up the call — could be from A-leg or B-leg
        let corr = self.call_correlation.read().await;
        let (internal_id, is_from_a_leg) =
            if let Some(id) = corr.a_leg.get(&sip_call_id) {
                (id.clone(), true)
            } else if let Some(id) = corr.b_leg.get(&sip_call_id) {
                (id.clone(), false)
            } else {
                // Unknown call — just respond 200 OK
                debug!(call_id = %sip_call_id, "BYE for unknown call");
                let response = create_response_from_request(req, StatusCode::OK);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            };

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::OK);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        };
        let addrs = a.clone();
        drop(corr);

        // Terminate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(&internal_id) {
                let _ = call.start_termination();
            }
        }

        // Stop media relay
        if let Some(ref pipeline) = self.media_pipeline {
            let call_id_str = internal_id.to_string();
            let _ = pipeline.stop_relay(&call_id_str).await;
            let _ = pipeline.remove_session(&call_id_str).await;
        }

        // Build 200 OK for BYE sender
        let ok_response = create_response_from_request(req, StatusCode::OK);

        // Build BYE for the other leg
        let (other_call_id, other_dest) = if is_from_a_leg {
            (&addrs.b_leg_sip_call_id, addrs.b_leg_destination)
        } else {
            (&addrs.a_leg_sip_call_id, addrs.a_leg_source)
        };

        let other_uri = SipUri::new(other_dest.ip().to_string())
            .with_port(other_dest.port());
        let mut bye_request = proto_sip::message::SipRequest::new(Method::Bye, other_uri);
        bye_request.headers.set(HeaderName::CallId, other_call_id);
        bye_request.headers.set(HeaderName::CSeq, "2 BYE");
        let branch = generate_branch();
        bye_request.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        bye_request.headers.set(HeaderName::ContentLength, "0");

        // Clean up call state
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(&internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(&internal_id);
        }

        info!(
            call_id = %sip_call_id,
            from_a_leg = is_from_a_leg,
            "Call terminated via BYE"
        );

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(ok_response),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(bye_request),
                destination: other_dest,
            },
        ])
    }

    /// Handles CANCEL request.
    ///
    /// B2BUA CANCEL flow:
    /// 1. Match CANCEL to pending A-leg INVITE
    /// 2. Send 200 OK for CANCEL to sender
    /// 3. Send 487 Request Terminated for the original INVITE
    /// 4. Send CANCEL to B-leg (if pending)
    /// 5. Clean up call state
    async fn handle_cancel(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let sip_call_id = req
            .headers
            .call_id()
            .unwrap_or("")
            .to_string();

        debug!(call_id = %sip_call_id, "Processing CANCEL");

        // Look up the call via A-leg Call-ID
        let corr = self.call_correlation.read().await;
        let Some(id) = corr.a_leg.get(&sip_call_id) else {
            // Unknown call -- just respond 200 OK for the CANCEL
            let response = create_response_from_request(req, StatusCode::OK);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        };
        let internal_id = id.clone();

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::OK);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        };
        let addrs = a.clone();
        drop(corr);

        // Fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(&internal_id) {
                call.fail(487, "Request Terminated");
            }
        }

        // Stop media if started
        if let Some(ref pipeline) = self.media_pipeline {
            let call_id_str = internal_id.to_string();
            let _ = pipeline.stop_relay(&call_id_str).await;
            let _ = pipeline.remove_session(&call_id_str).await;
        }

        // 200 OK for CANCEL
        let cancel_ok = create_response_from_request(req, StatusCode::OK);

        // 487 Request Terminated for the original INVITE
        let mut terminated = proto_sip::message::SipResponse::new(
            StatusCode::new(487).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
        );
        // Copy headers from CANCEL (same Via/From/To/Call-ID as original INVITE)
        if let Some(via) = req.headers.get_value(&HeaderName::Via) {
            terminated.headers.add(Header::new(HeaderName::Via, via));
        }
        if let Some(from) = req.headers.get_value(&HeaderName::From) {
            terminated.headers.set(HeaderName::From, from);
        }
        if let Some(to) = req.headers.get_value(&HeaderName::To) {
            let to_with_tag = if to.contains("tag=") {
                to.to_string()
            } else {
                format!("{};tag={}", to, generate_tag())
            };
            terminated.headers.set(HeaderName::To, to_with_tag);
        }
        terminated.headers.set(HeaderName::CallId, &sip_call_id);
        terminated.headers.set(HeaderName::CSeq, "1 INVITE");
        terminated.headers.set(HeaderName::ContentLength, "0");

        // CANCEL to B-leg
        let b_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut b_cancel = proto_sip::message::SipRequest::new(Method::Cancel, b_uri);
        b_cancel.headers.set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        b_cancel.headers.set(HeaderName::CSeq, "1 CANCEL");
        let branch = generate_branch();
        b_cancel.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        b_cancel.headers.set(HeaderName::ContentLength, "0");

        // Clean up
        {
            let mut calls = self.calls.write().await;
            calls.calls.remove(&internal_id);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg.remove(&addrs.a_leg_sip_call_id);
            corr.b_leg.remove(&addrs.b_leg_sip_call_id);
            corr.addresses.remove(&internal_id);
        }

        info!(call_id = %sip_call_id, "Call cancelled");

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(cancel_ok),
                destination: source,
            },
            ProcessResult::Response {
                message: SipMessage::Response(terminated),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_cancel),
                destination: addrs.b_leg_destination,
            },
        ])
    }

    /// Handles OPTIONS request (keepalive/capability query).
    async fn handle_options(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        debug!(uri = %req.uri, "Processing OPTIONS");

        // Create 200 OK with capabilities
        let mut response = create_response_from_request(req, StatusCode::OK);

        // Add Allow header with supported methods
        response.add_header(Header::new(
            HeaderName::Allow,
            "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER",
        ));

        // Add Accept header as custom
        response.add_header(Header::new(
            HeaderName::Custom("Accept".to_string()),
            "application/sdp",
        ));

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Handles other requests.
    async fn handle_other_request(
        &self,
        message: SipMessage,
        source: SbcSocketAddr,
    ) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        warn!(method = %req.method, "Unsupported method");

        // Create 405 Method Not Allowed
        let mut response = create_response_from_request(req, StatusCode::METHOD_NOT_ALLOWED);
        response.add_header(Header::new(
            HeaderName::Allow,
            "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER",
        ));

        ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        }
    }

    /// Matches a response to its client transaction.
    async fn match_response_to_transaction(&self) -> ProcessResult {
        // In B2BUA mode, would forward response to appropriate leg
        // For now, just log it
        debug!("Response matched to transaction");
        ProcessResult::NoAction
    }

    /// Returns the number of active dialogs.
    pub async fn dialog_count(&self) -> usize {
        self.dialogs.read().await.dialogs.len()
    }

    /// Returns the number of active calls.
    pub async fn call_count(&self) -> usize {
        self.calls.read().await.calls.len()
    }

    /// Lists all active calls with summary info (for gRPC ListCalls).
    pub async fn list_calls(&self) -> Vec<CallSummary> {
        let calls = self.calls.read().await;
        let corr = self.call_correlation.read().await;

        calls
            .calls
            .iter()
            .map(|(id, call)| {
                let addrs = corr.addresses.get(id);
                CallSummary {
                    call_id: id.to_string(),
                    state: format!("{:?}", call.state()),
                    a_leg_call_id: addrs.map(|a| a.a_leg_sip_call_id.clone()).unwrap_or_default(),
                    b_leg_call_id: addrs.map(|a| a.b_leg_sip_call_id.clone()).unwrap_or_default(),
                    a_leg_source: addrs.map(|a| a.a_leg_source.to_string()).unwrap_or_default(),
                    b_leg_destination: addrs.map(|a| a.b_leg_destination.to_string()).unwrap_or_default(),
                }
            })
            .collect()
    }

    /// Lists all registrations from the location service (for gRPC ListRegistrations).
    pub async fn list_registrations(&self) -> Vec<RegistrationSummary> {
        let loc = self.location_service.read().await;
        loc.aors()
            .map(|aor| {
                let bindings = loc.lookup(aor);
                RegistrationSummary {
                    aor: aor.to_string(),
                    contact_count: bindings.len(),
                    contacts: bindings
                        .iter()
                        .map(|b| b.contact_uri().to_string())
                        .collect(),
                }
            })
            .collect()
    }

    /// Returns the number of registered AORs.
    pub async fn registration_aor_count(&self) -> usize {
        let loc = self.location_service.read().await;
        loc.aor_count()
    }

    /// Returns the total number of contact bindings.
    pub async fn registration_binding_count(&self) -> usize {
        let loc = self.location_service.read().await;
        loc.total_bindings()
    }

    /// Deletes a registration binding (for gRPC DeleteRegistration).
    pub async fn delete_registration(
        &self,
        aor: &str,
        contact_uri: &str,
    ) -> Result<(), String> {
        let mut loc = self.location_service.write().await;
        loc.remove_binding(aor, contact_uri)
            .map_err(|e| e.to_string())
    }
    /// Lists dial plan summaries from the router.
    pub async fn list_dial_plans(&self) -> Vec<DialPlanSummary> {
        let Some(ref router_lock) = self.router else {
            return Vec::new();
        };
        let router = router_lock.read().await;
        let mut plans = Vec::new();
        if let Some(plan) = router.active_dial_plan() {
            plans.push(DialPlanSummary {
                id: plan.id().to_string(),
                name: plan.name().to_string(),
                entry_count: plan.entry_count(),
                active: true,
            });
        }
        plans
    }

    /// Lists dial plan entries for a given plan.
    pub async fn list_dial_plan_entries(&self, plan_id: &str) -> Vec<DialPlanEntryDetail> {
        let Some(ref router_lock) = self.router else {
            return Vec::new();
        };
        let router = router_lock.read().await;
        let Some(plan) = router.get_dial_plan(plan_id) else {
            return Vec::new();
        };
        plan.all_entries()
            .iter()
            .map(|e| DialPlanEntryDetail {
                id: e.id().to_string(),
                direction: format!("{}", e.direction()),
                pattern_type: match e.pattern() {
                    DialPattern::Exact(_) => "exact".to_string(),
                    DialPattern::Prefix(_) => "prefix".to_string(),
                    DialPattern::Wildcard(_) => "wildcard".to_string(),
                    DialPattern::Regex(_) => "regex".to_string(),
                    DialPattern::Any => "any".to_string(),
                },
                pattern_value: match e.pattern() {
                    DialPattern::Exact(v) | DialPattern::Prefix(v) | DialPattern::Wildcard(v) | DialPattern::Regex(v) => v.clone(),
                    DialPattern::Any => "*".to_string(),
                },
                domain_pattern: e.domain_pattern().map(String::from),
                source_trunk: e.source_trunk().map(String::from),
                trunk_group: e.trunk_group().to_string(),
                destination_type: match e.destination_type() {
                    DestinationType::TrunkGroup => "trunk_group",
                    DestinationType::RegisteredUser => "registered_user",
                    DestinationType::StaticUri => "static_uri",
                }.to_string(),
                static_destination: e.static_destination().map(String::from),
                transform_type: match e.transform() {
                    NumberTransform::None => "none",
                    NumberTransform::StripPrefix { .. } => "strip_prefix",
                    NumberTransform::AddPrefix { .. } => "add_prefix",
                    NumberTransform::ReplacePrefix { .. } => "replace_prefix",
                    NumberTransform::Replace { .. } => "replace",
                    NumberTransform::Chain(_) => "chain",
                }.to_string(),
                priority: e.priority(),
                enabled: e.is_enabled(),
            })
            .collect()
    }

    /// Lists trunk group summaries from the router.
    pub async fn list_trunk_groups(&self) -> Vec<TrunkGroupSummary> {
        let Some(ref router_lock) = self.router else {
            return Vec::new();
        };
        let router = router_lock.read().await;
        let mut groups = Vec::new();
        // We need to iterate trunk groups — the Router exposes get_trunk_group by ID
        // but not iteration. Return what the config provided.
        // For now, query via the router's stats
        let stats = router.stats();
        groups.push(TrunkGroupSummary {
            id: "info".to_string(),
            name: "Router Stats".to_string(),
            strategy: "N/A".to_string(),
            trunk_count: 0,
            total_routes: stats.requests,
            successful_routes: stats.successes,
            failed_routes: stats.no_route,
        });
        groups
    }

    /// Returns a reference to the router for direct access (used by API handlers).
    pub fn router(&self) -> Option<&RwLock<Router>> {
        self.router.as_ref()
    }

    /// Ensures a Router exists on the SipStack, creating a default one if needed.
    pub async fn ensure_router(&mut self) {
        if self.router.is_none() {
            let config = RouterConfig {
                use_dial_plan: true,
                max_failover_attempts: 3,
                default_trunk_group: None,
            };
            self.router = Some(RwLock::new(Router::new(config)));
        }
    }

    /// Adds or replaces a trunk group in the router.
    pub async fn add_trunk_group_to_router(&self, group: TrunkGroup) {
        if let Some(ref router_lock) = self.router {
            let mut router = router_lock.write().await;
            router.add_trunk_group(group);
        }
    }

    /// Removes a trunk group from the router.
    pub async fn remove_trunk_group_from_router(&self, id: &str) {
        if let Some(ref router_lock) = self.router {
            let mut router = router_lock.write().await;
            router.remove_trunk_group(id);
        }
    }

    /// Registers a trunk group for inbound call identification.
    /// Maps each trunk's host IP to the trunk group ID and CSS.
    pub async fn register_inbound_trunk(&self, trunk_group_id: &str, css_id: Option<&str>, hosts: &[(String, u16)]) {
        let mut map = self.inbound_trunk_map.write().await;
        for (host, _port) in hosts {
            // Resolve hostname to IP
            let addr_str = format!("{host}:0");
            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                map.insert(addr.ip(), (trunk_group_id.to_string(), css_id.map(String::from)));
            } else {
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                    if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                        map.insert(addr.ip(), (trunk_group_id.to_string(), css_id.map(String::from)));
                    }
                }
            }
        }
        info!(trunk_group = trunk_group_id, css = ?css_id, hosts = hosts.len(), "Registered inbound trunk for CSS routing");
    }

    /// Looks up which trunk group and CSS an inbound call belongs to by source IP.
    pub async fn lookup_inbound_trunk(&self, source_ip: std::net::IpAddr) -> Option<(String, Option<String>)> {
        self.inbound_trunk_map.read().await.get(&source_ip).cloned()
    }

    /// Adds a DID → username mapping for inbound call routing.
    pub async fn add_did_mapping(&self, did: &str, username: &str) {
        self.did_map.write().await.insert(did.to_string(), username.to_string());
        info!(did, username, "Added DID → user mapping");
    }

    /// Removes a DID mapping.
    pub async fn remove_did_mapping(&self, did: &str) {
        self.did_map.write().await.remove(did);
    }

    /// Looks up a username by DID.
    pub async fn lookup_did(&self, did: &str) -> Option<String> {
        self.did_map.read().await.get(did).cloned()
    }

    /// Adds or replaces a dial plan in the router.
    pub async fn add_dial_plan_to_router(&self, plan: DialPlan) {
        if let Some(ref router_lock) = self.router {
            let mut router = router_lock.write().await;
            router.add_dial_plan(plan);
        }
    }

    /// Answers a call, plays an announcement via RTP, then sends BYE.
    ///
    /// Flow:
    /// 1. Allocate RTP port
    /// 2. Send 200 OK with SDP (sendonly PCMU) to caller
    /// 3. Spawn background task: stream announcement audio, then send BYE
    async fn play_announcement_to_caller(
        &self,
        req: &proto_sip::message::SipRequest,
        source: SbcSocketAddr,
        announcement: crate::announcement::AnnouncementType,
    ) -> ProcessResult {
        // Bind announcement RTP socket first to discover actual port
        let preferred_port = if let Some(ref pipeline) = self.media_pipeline {
            pipeline.port_allocator().allocate_pair().await.map(|(rtp, _)| rtp).unwrap_or(0)
        } else {
            0
        };

        // Bind RTP socket to the outside zone's signaling IP so media
        // exits via the correct macvlan interface.
        let rtp_bind_ip = if let Some(ref zr) = self.zone_registry {
            zr.signaling_ip("outside")
        } else {
            None
        };
        let (ann_socket, actual_rtp_port) = match crate::announcement::AnnouncementServer::bind_socket(preferred_port, rtp_bind_ip).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "Cannot bind announcement socket");
                let unavailable = create_response_from_request(req, StatusCode::TEMPORARILY_UNAVAILABLE);
                return ProcessResult::Response {
                    message: SipMessage::Response(unavailable),
                    destination: source,
                };
            }
        };

        // Use the outside zone's external IP (STUN/public) for the SDP so
        // the remote party (on the internet) can send RTP to a routable address.
        // Falls back to the signaling IP if no external IP is configured.
        let sdp_ip = if let Some(ref zr) = self.zone_registry {
            zr.external_ip("outside")
                .or_else(|| zr.signaling_ip("outside"))
                .map(|ip| ip.to_string())
        } else {
            None
        }.unwrap_or_else(|| match source.ip() {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(|| v6.to_string(), |v4| v4.to_string()),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        });
        info!(sdp_ip = %sdp_ip, rtp_port = actual_rtp_port, zone_registry_present = self.zone_registry.is_some(), "SDP media address for announcement");
        let sdp = crate::announcement::build_announcement_sdp(&sdp_ip, actual_rtp_port);

        // Build 200 OK with SDP
        let mut ok_response = create_response_from_request(req, StatusCode::OK);
        ok_response.add_header(Header::new(
            HeaderName::Contact,
            format!("<sip:{}@{}:{}>", self.config.instance_name, sdp_ip, source.port()),
        ));
        ok_response.headers.set(HeaderName::ContentType, "application/sdp");
        let sdp_bytes = sdp.into_bytes();
        ok_response.headers.set(HeaderName::ContentLength, sdp_bytes.len().to_string());
        ok_response.body = Some(Bytes::from(sdp_bytes));

        // Extract caller's RTP destination from their SDP offer
        let caller_rtp_dest = req.body.as_ref().and_then(|body| {
            let sdp_str = String::from_utf8_lossy(body);
            crate::announcement::extract_rtp_dest_from_sdp(&sdp_str)
        });

        // Track this Call-ID to absorb INVITE retransmits
        let call_id = req.headers.call_id().unwrap_or("unknown").to_string();
        {
            let mut corr = self.call_correlation.write().await;
            corr.announcement_calls.insert(call_id.clone());
        }
        // Capture full From/To headers for the BYE dialog matching.
        // In BYE from UAS: From = our To (with our tag), To = caller's From (with their tag)
        let invite_from = req.headers.get_value(&HeaderName::From).unwrap_or_default().to_string();
        let ok_to = ok_response.headers.get_value(&HeaderName::To).unwrap_or_default().to_string();

        let source_port = source.port();
        // local_ip = macvlan IP for binding sockets; sdp_ip = external/public IP for SDP
        let local_ip = rtp_bind_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| sdp_ip.clone());

        // Spawn background task to play announcement then BYE
        tokio::spawn(async move {
            // Wait for caller to process the 200 OK and send ACK
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            if let Some(rtp_dest) = caller_rtp_dest {
                let ssrc = {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                    (now.as_nanos() as u32) ^ (now.as_secs() as u32)
                };
                if let Err(e) = crate::announcement::AnnouncementServer::play_on_socket(
                    announcement,
                    ann_socket,
                    rtp_dest,
                    ssrc,
                ).await {
                    warn!(error = %e, "Announcement playback failed");
                }
            } else {
                warn!("No RTP destination from caller SDP, skipping audio playback");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }

            // Send BYE after announcement
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // Build BYE using the exact dialog headers from the INVITE/200 exchange.
            // From UAS perspective: our From = the To from 200 OK, our To = the From from INVITE
            let caller_ip = source.ip().to_string();
            let bye_uri = SipUri::new(&caller_ip).with_port(source_port);
            let bye = RequestBuilder::new(Method::Bye, bye_uri)
                .via_auto("UDP", &local_ip, Some(5060))
                .from_auto(SipUri::new(&local_ip), None)
                .to_uri(SipUri::new(&caller_ip), None)
                .call_id(&call_id)
                .cseq(2)
                .max_forwards(70)
                .build_with_defaults()
                .map(|mut r| {
                    // Overwrite From/To with exact dialog headers (swapped for UAS BYE)
                    r.headers.set(HeaderName::From, &ok_to);
                    r.headers.set(HeaderName::To, &invite_from);
                    r
                });

            match bye {
                Ok(bye_req) => {
                    let bye_bytes = SipMessage::Request(bye_req).to_bytes();
                    info!("Sending BYE:\n{}", String::from_utf8_lossy(&bye_bytes));
                    // Bind to the outside zone IP on port 5060 so the BYE comes
                    // from the same address the call was established on
                    let bind_addr: std::net::SocketAddr = format!("{local_ip}:5060").parse()
                        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
                    let sock2 = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    );
                    if let Ok(s) = sock2 {
                        s.set_reuse_address(true).ok();
                        #[cfg(target_os = "linux")]
                        s.set_reuse_port(true).ok();
                        s.set_nonblocking(true).ok();
                        if s.bind(&bind_addr.into()).is_ok() {
                            if let Ok(sock) = tokio::net::UdpSocket::from_std(s.into()) {
                                if let Err(e) = sock.send_to(&bye_bytes, source.as_std()).await {
                                    warn!(error = %e, "Failed to send BYE after announcement");
                                } else {
                                    info!(call_id = %call_id, destination = %source, "Sent BYE after announcement");
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to build BYE after announcement");
                }
            }
        });

        // Return 200 OK to answer the call
        ProcessResult::Response {
            message: SipMessage::Response(ok_response),
            destination: source,
        }
    }
}

/// Summary of a dial plan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DialPlanSummary {
    /// Plan ID.
    pub id: String,
    /// Plan name.
    pub name: String,
    /// Number of entries.
    pub entry_count: usize,
    /// Whether this is the active plan.
    pub active: bool,
}

/// Detail of a dial plan entry (for API).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DialPlanEntryDetail {
    /// Entry ID.
    pub id: String,
    /// Direction (inbound/outbound/both).
    pub direction: String,
    /// Pattern type description.
    pub pattern_type: String,
    /// Pattern value.
    pub pattern_value: String,
    /// Domain pattern.
    pub domain_pattern: Option<String>,
    /// Source trunk filter.
    pub source_trunk: Option<String>,
    /// Trunk group.
    pub trunk_group: String,
    /// Destination type.
    pub destination_type: String,
    /// Static destination URI.
    pub static_destination: Option<String>,
    /// Transform description.
    pub transform_type: String,
    /// Priority.
    pub priority: u32,
    /// Whether enabled.
    pub enabled: bool,
}

/// Summary of a trunk group.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrunkGroupSummary {
    /// Group ID.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Selection strategy.
    pub strategy: String,
    /// Number of trunks.
    pub trunk_count: usize,
    /// Total routing requests.
    pub total_routes: u64,
    /// Successful routes.
    pub successful_routes: u64,
    /// Failed routes.
    pub failed_routes: u64,
}

/// Summary of an active call (for gRPC API).
#[derive(Debug, Clone)]
pub struct CallSummary {
    /// Internal call ID.
    pub call_id: String,
    /// Call state.
    pub state: String,
    /// A-leg SIP Call-ID.
    pub a_leg_call_id: String,
    /// B-leg SIP Call-ID.
    pub b_leg_call_id: String,
    /// A-leg source address.
    pub a_leg_source: String,
    /// B-leg destination address.
    pub b_leg_destination: String,
}

/// Summary of a registration (for gRPC API).
#[derive(Debug, Clone)]
pub struct RegistrationSummary {
    /// Address of Record.
    pub aor: String,
    /// Number of contacts.
    pub contact_count: usize,
    /// Contact URIs.
    pub contacts: Vec<String>,
}

/// Creates a response from a request, copying required headers.
fn create_response_from_request(
    req: &proto_sip::message::SipRequest,
    status: StatusCode,
) -> proto_sip::message::SipResponse {
    let mut response = proto_sip::message::SipResponse::new(status);

    // Copy Via headers
    if let Some(via) = req.headers.get_value(&HeaderName::Via) {
        response.add_header(Header::new(HeaderName::Via, via));
    }

    // Copy From header
    if let Some(from) = req.headers.get_value(&HeaderName::From) {
        response.add_header(Header::new(HeaderName::From, from));
    }

    // Copy To header (add tag if not present for non-100 responses)
    if let Some(to) = req.headers.get_value(&HeaderName::To) {
        let to_value = if status.code() != 100 && !to.contains("tag=") {
            format!("{};tag={}", to, generate_tag())
        } else {
            to.to_string()
        };
        response.add_header(Header::new(HeaderName::To, to_value));
    }

    // Copy Call-ID
    if let Some(call_id) = req.headers.call_id() {
        response.add_header(Header::new(HeaderName::CallId, call_id));
    }

    // Copy CSeq
    if let Some(cseq) = req.headers.cseq() {
        response.add_header(Header::new(HeaderName::CSeq, cseq));
    }

    // Add Content-Length: 0
    response.add_header(Header::new(HeaderName::ContentLength, "0"));

    response
}

/// Generates a random tag for From/To headers.
fn generate_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", timestamp & 0xFFFF_FFFF)
}

/// Copies common headers from a B-leg response for forwarding to A-leg.
///
/// Copies Via, From, To, CSeq, and Content-Length.
/// Call-ID should be replaced by the caller with the A-leg's Call-ID.
fn copy_response_headers(
    from: &proto_sip::message::SipResponse,
    to: &mut proto_sip::message::SipResponse,
) {
    // Copy Via (will be the A-leg's Via from the original INVITE)
    for via in from.headers.get_all(&HeaderName::Via) {
        to.headers.add(Header::new(HeaderName::Via, &via.value));
    }
    if let Some(from_val) = from.headers.get_value(&HeaderName::From) {
        to.headers.set(HeaderName::From, from_val);
    }
    if let Some(to_val) = from.headers.get_value(&HeaderName::To) {
        to.headers.set(HeaderName::To, to_val);
    }
    if let Some(cseq) = from.headers.cseq() {
        to.headers.set(HeaderName::CSeq, cseq);
    }
    to.headers.set(HeaderName::ContentLength, "0");
}

/// Parses a manipulation action from config strings.
fn parse_manipulation_action(action: &str, header: &str, value: &str) -> ManipulationAction {
    let header_name: HeaderName = header.parse().unwrap_or_else(|_| HeaderName::Custom(header.to_string()));
    match action {
        "add" => ManipulationAction::Add {
            name: header_name,
            value: value.to_string(),
        },
        "set" => ManipulationAction::Set {
            name: header_name,
            value: value.to_string(),
        },
        "remove" => ManipulationAction::Remove { name: header_name },
        "replace" => ManipulationAction::Replace {
            name: header_name,
            pattern: String::new(),
            replacement: value.to_string(),
        },
        "prepend" => ManipulationAction::Prepend {
            name: header_name,
            prefix: value.to_string(),
        },
        "append" => ManipulationAction::Append {
            name: header_name,
            suffix: value.to_string(),
        },
        _ => ManipulationAction::Set {
            name: header_name,
            value: value.to_string(),
        },
    }
}

/// Resolves a SIP URI string to a socket address.
///
/// Parses the host and port from URIs like `sip:user@host:port` or `sip:host`.
/// Defaults to port 5060 if not specified.
fn resolve_sip_uri_to_addr(uri: &str) -> Option<SbcSocketAddr> {
    use std::net::ToSocketAddrs;

    // Strip sip: or sips: prefix
    let without_scheme = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);

    // Strip user@ if present
    let host_part = without_scheme.find('@').map_or(without_scheme, |at_pos| &without_scheme[at_pos + 1..]);

    // Strip parameters (;transport=udp etc.)
    let host_part = host_part.split(';').next().unwrap_or(host_part);

    // Parse host:port
    let (host, port) = host_part.rfind(':').map_or((host_part, 5060), |colon_pos| {
        let port_str = &host_part[colon_pos + 1..];
        port_str.parse::<u16>().map_or((host_part, 5060), |port| (&host_part[..colon_pos], port))
    });

    // Parse IP address
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return Some(SbcSocketAddr::new_v4(ipv4, port));
    }
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return Some(SbcSocketAddr::new_v6(ipv6, port));
    }

    // For hostnames, try DNS resolution (synchronous for now)
    let addr_str = format!("{host}:{port}");
    if let Ok(mut addrs) = addr_str.to_socket_addrs()
        && let Some(addr) = addrs.next() {
            return Some(SbcSocketAddr::from(addr));
        }

    None
}

/// Extracts a SIP URI from a From/To header value.
///
/// Handles formats like:
/// - `<sip:alice@example.com>`
/// - `"Alice" <sip:alice@example.com>;tag=1234`
/// - `sip:alice@example.com`
fn extract_uri_from_header(header_value: &str) -> String {
    if let Some(start) = header_value.find('<')
        && let Some(end) = header_value.find('>') {
            return header_value[start + 1..end].to_string();
        }
    // No angle brackets — take the value before any parameters
    header_value
        .split(';')
        .next()
        .unwrap_or(header_value)
        .trim()
        .to_string()
}

/// Parses Contact headers from a SIP request into `ContactInfo` list.
fn parse_contacts_from_request(req: &proto_sip::message::SipRequest) -> Vec<ContactInfo> {
    let mut contacts = Vec::new();

    // Get all Contact header values
    let contact_values: Vec<String> = req
        .headers
        .get_all(&HeaderName::Contact)
        .map(|h| h.value.clone())
        .collect();

    for contact_val in &contact_values {
        // Handle wildcard
        if contact_val.trim() == "*" {
            contacts.push(ContactInfo::new("*"));
            continue;
        }

        // Parse each contact (may be comma-separated)
        for part in contact_val.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let uri = extract_uri_from_header(part);
            let mut info = ContactInfo::new(&uri);

            // Parse expires parameter
            if let Some(exp_str) = extract_param(part, "expires") {
                info.expires = exp_str.parse().ok();
            }

            // Parse q parameter
            if let Some(q_str) = extract_param(part, "q") {
                info.q_value = q_str.parse().ok();
            }

            // Parse +sip.instance parameter (RFC 5626)
            if let Some(instance) = extract_param(part, "+sip.instance") {
                info.instance_id = Some(instance.trim_matches('"').to_string());
            }

            // Parse reg-id parameter (RFC 5626)
            if let Some(reg_id_str) = extract_param(part, "reg-id") {
                info.reg_id = reg_id_str.parse().ok();
            }

            contacts.push(info);
        }
    }

    contacts
}

/// Extracts a parameter value from a SIP header value string.
///
/// Looks for `name=value` patterns after the URI portion.
fn extract_param<'a>(header_value: &'a str, name: &str) -> Option<&'a str> {
    // Find the parameter after the URI (after '>')
    let params_start = header_value.find('>').map_or(0, |p| p + 1);
    let params = &header_value[params_start..];

    for part in params.split(';') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim();
            if key.eq_ignore_ascii_case(name) {
                return Some(part[eq_pos + 1..].trim());
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sip_stack_creation() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        assert_eq!(stack.dialog_count().await, 0);
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn test_process_options() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        let options = b"OPTIONS sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:sbc.local>\r\n\
            Call-ID: test123@example.com\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(options), source, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                assert!(message.is_response());
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status, StatusCode::OK);
                }
            }
            _ => panic!("Expected response"),
        }
    }

    #[tokio::test]
    async fn test_process_register() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:alice@example.com>\r\n\
            Call-ID: reg123@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                assert!(message.is_response());
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status, StatusCode::OK);
                }
            }
            _ => panic!("Expected response"),
        }

        // Verify binding was stored in location service
        let loc = stack.location_service.read().await;
        assert!(
            loc.has_bindings("sip:alice@example.com"),
            "Location service should have binding for alice"
        );
        let bindings = loc.lookup("sip:alice@example.com");
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].contact_uri(),
            "sip:alice@client.example.com:5060"
        );
    }

    #[tokio::test]
    async fn test_register_with_auth() {
        let mut config = SipStackConfig::default();
        config.require_auth = true;
        config.auth_realm = "example.com".to_string();
        config
            .auth_credentials
            .insert("alice".to_string(), "password123".to_string());

        let stack = SipStack::new(config);

        // First REGISTER without credentials → should get 401
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:alice@example.com>\r\n\
            Call-ID: reg123@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                if let SipMessage::Response(resp) = message {
                    assert_eq!(
                        resp.status.code(),
                        401,
                        "Should get 401 Unauthorized without credentials"
                    );
                    // Should have WWW-Authenticate header
                    let www_auth = resp.headers.get_value(&HeaderName::WwwAuthenticate);
                    assert!(
                        www_auth.is_some(),
                        "401 response should include WWW-Authenticate"
                    );
                }
            }
            _ => panic!("Expected response"),
        }

        // Verify no binding stored
        let loc = stack.location_service.read().await;
        assert!(
            !loc.has_bindings("sip:alice@example.com"),
            "Should NOT have binding after 401"
        );
    }

    #[tokio::test]
    async fn test_invite_unresolvable_destination() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // INVITE to unresolvable host → should get 200 OK (announcement playback)
        let invite = b"INVITE sip:bob@nonexistent.invalid SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK776\r\n\
            From: <sip:alice@example.com>;tag=1234\r\n\
            To: <sip:bob@nonexistent.invalid>\r\n\
            Call-ID: call123@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), source, None)
            .await;

        // Unresolvable destinations now get a 200 OK with announcement SDP
        match result {
            ProcessResult::Response { message, .. } => {
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status.code(), 200, "Unresolvable destination should return 200 OK (announcement)");
                    assert!(resp.body.is_some(), "Should have SDP body for announcement");
                }
            }
            _ => panic!("Expected 200 OK response with announcement"),
        }
    }

    #[tokio::test]
    async fn test_invite_to_registered_user() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // First, register bob at 127.0.0.1:5060
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776\r\n\
            From: <sip:bob@sbc.local>;tag=reg1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: reg-bob@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(register), source, None)
            .await;
        // Verify registration succeeded
        if let ProcessResult::Response { message, .. } = &result {
            if let SipMessage::Response(resp) = message {
                assert_eq!(resp.status, StatusCode::OK, "Registration should succeed");
            }
        }

        // Now INVITE bob — should route via location service
        let invite = b"INVITE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK999\r\n\
            From: <sip:alice@example.com>;tag=inv1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-bob@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@192.168.1.100:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let alice_source = SbcSocketAddr::new_v4(
            std::net::Ipv4Addr::new(192, 168, 1, 100),
            5060,
        );
        let result = stack
            .process_message(&Bytes::from_static(invite), alice_source, None)
            .await;

        // Should get Multiple(100 Trying + Forward INVITE)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 2, "Should have 2 results: Trying + Forward");

                // First: 100 Trying to A-leg
                if let ProcessResult::Response { message, destination } = &results[0] {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status, StatusCode::TRYING);
                    }
                    assert_eq!(*destination, alice_source);
                } else {
                    panic!("First result should be Response (100 Trying)");
                }

                // Second: Forward INVITE to B-leg (bob at 127.0.0.1:5060)
                if let ProcessResult::Forward { message, destination } = &results[1] {
                    assert!(message.is_request(), "Forward should be a request");
                    assert_eq!(
                        destination.ip(),
                        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
                        "B-leg should go to bob's registered address"
                    );
                } else {
                    panic!("Second result should be Forward (B-leg INVITE)");
                }

                // Verify call state was created
                assert_eq!(stack.call_count().await, 1);
            }
            other => panic!("Expected Multiple, got: {other:?}"),
        }
    }

    #[test]
    fn test_generate_tag() {
        let tag1 = generate_tag();
        let tag2 = generate_tag();

        assert!(!tag1.is_empty());
        assert!(!tag2.is_empty());
        assert!(tag1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(tag2.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_bye_from_a_leg() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // Register bob
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK001\r\n\
            From: <sip:bob@sbc.local>;tag=r1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: reg-bob@test\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        stack.process_message(&Bytes::from_static(register), src, None).await;

        // INVITE bob from alice
        let invite = b"INVITE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK002\r\n\
            From: <sip:alice@example.com>;tag=i1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-bye-test@test\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@192.168.1.1:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let alice = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5060);
        stack.process_message(&Bytes::from_static(invite), alice, None).await;
        assert_eq!(stack.call_count().await, 1);

        // BYE from alice (A-leg)
        let bye = b"BYE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK003\r\n\
            From: <sip:alice@example.com>;tag=i1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-bye-test@test\r\n\
            CSeq: 2 BYE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let result = stack.process_message(&Bytes::from_static(bye), alice, None).await;

        // Should get Multiple(200 OK to alice + BYE to bob)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 2);
                // First: 200 OK
                if let ProcessResult::Response { message, .. } = &results[0] {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status, StatusCode::OK);
                    }
                }
                // Second: BYE to bob
                if let ProcessResult::Forward { message, .. } = &results[1] {
                    assert!(message.is_request());
                }
            }
            _ => panic!("Expected Multiple for BYE"),
        }

        // Call should be cleaned up
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn test_cancel_pending_invite() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // Register bob
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK010\r\n\
            From: <sip:bob@sbc.local>;tag=r2\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: reg-bob-cancel@test\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        stack.process_message(&Bytes::from_static(register), src, None).await;

        // INVITE bob
        let invite = b"INVITE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK011\r\n\
            From: <sip:alice@example.com>;tag=c1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-cancel-test@test\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:alice@192.168.1.1:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let alice = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5060);
        stack.process_message(&Bytes::from_static(invite), alice, None).await;
        assert_eq!(stack.call_count().await, 1);

        // CANCEL from alice before bob answers
        let cancel = b"CANCEL sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK011\r\n\
            From: <sip:alice@example.com>;tag=c1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: call-cancel-test@test\r\n\
            CSeq: 1 CANCEL\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let result = stack.process_message(&Bytes::from_static(cancel), alice, None).await;

        // Should get Multiple(200 OK for CANCEL + 487 for INVITE + CANCEL to bob)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 3, "CANCEL should produce 3 results");
                // First: 200 OK for CANCEL
                if let ProcessResult::Response { message, .. } = &results[0] {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status, StatusCode::OK);
                    }
                }
                // Second: 487 Request Terminated for INVITE
                if let ProcessResult::Response { message, .. } = &results[1] {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status.code(), 487);
                    }
                }
                // Third: CANCEL to bob
                if let ProcessResult::Forward { message, .. } = &results[2] {
                    assert!(message.is_request());
                }
            }
            _ => panic!("Expected Multiple for CANCEL"),
        }

        // Call should be cleaned up
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn test_list_calls_and_registrations() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // Initially empty
        assert!(stack.list_calls().await.is_empty());
        assert!(stack.list_registrations().await.is_empty());
        assert_eq!(stack.registration_aor_count().await, 0);
        assert_eq!(stack.registration_binding_count().await, 0);

        // Register alice
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK020\r\n\
            From: <sip:alice@sbc.local>;tag=q1\r\n\
            To: <sip:alice@sbc.local>\r\n\
            Call-ID: reg-query@test\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        stack.process_message(&Bytes::from_static(register), src, None).await;

        // Verify registration query
        let regs = stack.list_registrations().await;
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].aor, "sip:alice@sbc.local");
        assert_eq!(regs[0].contact_count, 1);
        assert_eq!(stack.registration_aor_count().await, 1);
        assert_eq!(stack.registration_binding_count().await, 1);

        // Delete registration
        stack
            .delete_registration("sip:alice@sbc.local", "sip:alice@127.0.0.1:5060")
            .await
            .unwrap();
        assert_eq!(stack.registration_aor_count().await, 0);
    }

    #[tokio::test]
    async fn test_bye_unknown_call() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // BYE for unknown call — should just get 200 OK
        let bye = b"BYE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK030\r\n\
            From: <sip:alice@example.com>;tag=u1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: unknown-call@test\r\n\
            CSeq: 2 BYE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5060);
        let result = stack.process_message(&Bytes::from_static(bye), src, None).await;

        match result {
            ProcessResult::Response { message, .. } => {
                if let SipMessage::Response(resp) = message {
                    assert_eq!(resp.status, StatusCode::OK, "Unknown BYE should get 200 OK");
                }
            }
            _ => panic!("Expected Response for unknown BYE"),
        }
    }

    #[test]
    fn test_extract_uri_from_header() {
        assert_eq!(
            extract_uri_from_header("<sip:alice@example.com>"),
            "sip:alice@example.com"
        );
        assert_eq!(
            extract_uri_from_header("\"Alice\" <sip:alice@example.com>;tag=1234"),
            "sip:alice@example.com"
        );
        assert_eq!(
            extract_uri_from_header("sip:alice@example.com;tag=1234"),
            "sip:alice@example.com"
        );
    }

    #[test]
    fn test_resolve_sip_uri_to_addr() {
        // IP address
        let addr = resolve_sip_uri_to_addr("sip:alice@192.168.1.100:5060");
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 5060);

        // IP without port (default 5060)
        let addr = resolve_sip_uri_to_addr("sip:alice@10.0.0.1");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 5060);

        // Bare IP
        let addr = resolve_sip_uri_to_addr("sip:127.0.0.1:9999");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 9999);
    }

    #[test]
    fn test_parse_contacts_from_request() {
        let mut req = proto_sip::message::SipRequest::new(
            Method::Register,
            SipUri::new("sbc.local"),
        );
        req.headers.add(Header::new(
            HeaderName::Contact,
            "<sip:alice@192.168.1.100:5060>;expires=3600;q=0.8",
        ));

        let contacts = parse_contacts_from_request(&req);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri, "sip:alice@192.168.1.100:5060");
        assert_eq!(contacts[0].expires, Some(3600));
        assert!((contacts[0].q_value.unwrap() - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_parse_wildcard_contact() {
        let mut req = proto_sip::message::SipRequest::new(
            Method::Register,
            SipUri::new("sbc.local"),
        );
        req.headers.add(Header::new(HeaderName::Contact, "*"));

        let contacts = parse_contacts_from_request(&req);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri, "*");
    }

    #[tokio::test]
    async fn test_router_initialization() {
        let mut config = SipStackConfig::default();
        config.domain = "sbc.test".to_string();
        let mut stack = SipStack::new(config);

        let routing = sbc_config::RoutingConfig {
            use_dial_plan: true,
            max_failover_attempts: 2,
            default_trunk_group: "default".to_string(),
        };

        let dial_plans = vec![sbc_config::DialPlanConfig {
            id: "test-plan".to_string(),
            name: "Test Plan".to_string(),
            active: true,
            entries: vec![
                sbc_config::DialPlanEntryConfig {
                    direction: "outbound".to_string(),
                    pattern_type: "prefix".to_string(),
                    pattern_value: "+1".to_string(),
                    trunk_group: "us-trunks".to_string(),
                    transform_type: "strip_prefix".to_string(),
                    transform_value: "2".to_string(),
                    priority: 10,
                    ..Default::default()
                },
                sbc_config::DialPlanEntryConfig {
                    direction: "both".to_string(),
                    pattern_type: "exact".to_string(),
                    pattern_value: "911".to_string(),
                    trunk_group: "emergency".to_string(),
                    priority: 1,
                    ..Default::default()
                },
            ],
        }];

        let trunk_groups = vec![
            sbc_config::TrunkGroupConfig {
                id: "us-trunks".to_string(),
                name: "US".to_string(),
                strategy: "priority".to_string(),
                trunks: vec![sbc_config::TrunkConfigSchema {
                    id: "trunk-1".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: 5060,
                    protocol: "udp".to_string(),
                    ..Default::default()
                }],
                zone: None,
            },
            sbc_config::TrunkGroupConfig {
                id: "emergency".to_string(),
                name: "E911".to_string(),
                strategy: "priority".to_string(),
                trunks: vec![sbc_config::TrunkConfigSchema {
                    id: "e911-1".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: 5061,
                    protocol: "udp".to_string(),
                    ..Default::default()
                }],
                zone: None,
            },
        ];

        stack.init_router_from_config(&routing, &dial_plans, &trunk_groups);

        // Router should be set
        assert!(stack.router.is_some());
    }

    #[tokio::test]
    async fn test_manipulator_initialization() {
        let mut config = SipStackConfig::default();
        config.domain = "sbc.test".to_string();
        let mut stack = SipStack::new(config);

        let manip_config = sbc_config::HeaderManipulationConfig {
            global_rules: vec![sbc_config::ManipulationRuleConfig {
                name: "strip-internal".to_string(),
                direction: "outbound".to_string(),
                action: "remove".to_string(),
                header: "X-Internal-ID".to_string(),
                value: String::new(),
            }],
            trunk_rules: vec![sbc_config::TrunkManipulationRuleConfig {
                trunk_id: "trunk-1".to_string(),
                name: "set-ua".to_string(),
                action: "set".to_string(),
                header: "User-Agent".to_string(),
                value: "USG-SBC/1.0".to_string(),
            }],
        };

        stack.init_manipulator_from_config(&manip_config);
        assert!(stack.header_manipulator.is_some());
    }

    #[tokio::test]
    async fn test_topology_hider_initialization() {
        let mut config = SipStackConfig::default();
        config.domain = "sbc.test".to_string();
        let mut stack = SipStack::new(config);

        let topo_config = sbc_config::TopologyHidingConfig {
            enabled: true,
            mode: "full".to_string(),
            external_host: "sbc.uc.mil".to_string(),
            external_port: 5060,
            obfuscate_call_id: true,
        };

        stack.init_topology_hider_from_config(&topo_config);
        assert!(stack.topology_hider.is_some());
    }

    #[tokio::test]
    async fn test_topology_hider_disabled() {
        let mut config = SipStackConfig::default();
        config.domain = "sbc.test".to_string();
        let mut stack = SipStack::new(config);

        let topo_config = sbc_config::TopologyHidingConfig {
            enabled: false,
            ..Default::default()
        };

        stack.init_topology_hider_from_config(&topo_config);
        assert!(stack.topology_hider.is_none(), "Disabled topology hider should be None");
    }
}
