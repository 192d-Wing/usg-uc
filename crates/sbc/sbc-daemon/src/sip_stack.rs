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
use proto_b2bua::{
    B2buaMode, Call, CallConfig, CallId, MediaAddress, SdpRewriter, extract_media_address,
};
use proto_dialog::{Dialog, DialogId};
#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
use proto_registrar::{
    AuthenticatedRegistrar, BearerAuthenticator, BearerResult, ContactInfo, LocationService,
    RegisterRequest, RegistrarConfig, RegistrarMode,
};
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id};
use proto_sip::manipulation::{
    HeaderManipulator, ManipulationAction, ManipulationContext, ManipulationDirection,
    ManipulationPolicy, ManipulationRule,
};
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::uri::SipUri;
use proto_sip::{Header, HeaderName, Method, SipMessage, StatusCode};
use proto_sip::{TopologyHider, TopologyHidingConfig as SipTopologyConfig, TopologyHidingMode};
use proto_transaction::timer::TimerType;
use proto_transaction::{
    ClientInviteTransaction, ClientNonInviteTransaction, ServerInviteTransaction,
    ServerNonInviteTransaction, TransactionKey, TransportType,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
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
    /// RFC 8898 Bearer-token REGISTER authorizer (OIDC JWT). When `Some`,
    /// REGISTER is authorized against the IdP's JWKS and the `dn` claim must
    /// match the AOR user part, instead of (or alongside) digest auth.
    bearer: Option<Arc<BearerAuthenticator>>,
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
    media_pipeline: Option<Arc<dyn sbc_media_core::media_pipeline::MediaController>>,
    /// The SBC's DTLS-SRTP identity. `Some` only when `srtp.mode = terminate`;
    /// its presence gates advertising the SBC fingerprint in rewritten SDP.
    dtls_fingerprint_source: Option<Arc<sbc_media_core::dtls_identity::DtlsFingerprintSource>>,
    /// Call router for dial plan matching and trunk selection.
    router: Option<RwLock<Router>>,
    /// SBC-compatible router for CSS/Partition-based routing.
    sbc_router: Option<Arc<RwLock<uc_routing::SbcRouter>>>,
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
    inbound_trunk_map:
        RwLock<std::collections::HashMap<std::net::IpAddr, (String, Option<String>)>>,
    /// Directory number mapping: DID → username for inbound call routing.
    did_map: RwLock<std::collections::HashMap<String, String>>,
    /// Call-IDs currently being played an announcement (dedup retransmits).
    /// Arc so the spawned playback task can remove its entry when done —
    /// previously entries were never removed (unbounded growth from
    /// unroutable INVITEs).
    announcement_calls: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
    /// Voice Protection System engine for pre-routing call screening
    /// (see docs/VPS-ARCHITECTURE.md). Mutex: screening mutates rate
    /// counters and stats.
    vps: Option<tokio::sync::Mutex<uc_vps::VpsEngine>>,
    /// Registration statistics.
    registrations_active: AtomicU64,
    registrations_total: AtomicU64,
    /// Draining: reject new INVITEs (503) while existing calls finish.
    draining: std::sync::atomic::AtomicBool,
    /// RTP port allocator: hands out even-numbered ports in a range.
    next_rtp_port: std::sync::atomic::AtomicU16,
    /// Set of currently allocated RTP ports for deallocation tracking.
    allocated_ports: Arc<std::sync::Mutex<HashSet<u16>>>,
    /// In-flight INVITE Call-IDs: prevents TOCTOU race between the
    /// retransmit check and the correlation insert.
    in_flight_invites: RwLock<HashSet<String>>,
    /// 2xx responses to INVITEs the SBC answered as UAS, retransmitted until
    /// ACKed (RFC 3261 §13.3.1.4). Keyed by the SIP Call-ID of that leg.
    pending_2xx: RwLock<HashMap<String, Pending2xx>>,
    /// Per-user request limiter (`rate_limit.per_user_rps`), keyed by the
    /// From user. `None` when disabled.
    user_limiter: Option<tokio::sync::Mutex<uc_dos_protection::KeyedRateLimiter>>,
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
    /// Maximum concurrent calls — INVITEs beyond this are rejected with
    /// 503 (admission control, `general.max_calls`).
    pub max_calls: u32,
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
            max_calls: 1000,
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
    created_at: Instant,
    /// Last response sent on this transaction: re-sent on an INVITE
    /// retransmission (RFC 3261 §17.2.1) and, for a non-2xx final, on
    /// Timer G until the ACK arrives.
    last_response: Option<SipMessage>,
}

/// State for server non-INVITE transaction.
struct ServerNonInviteState {
    transaction: ServerNonInviteTransaction,
    source: SbcSocketAddr,
    created_at: Instant,
    /// Last response sent; re-sent on a request retransmission (§17.2.2).
    last_response: Option<SipMessage>,
}

/// State for client INVITE transaction.
struct ClientInviteState {
    transaction: ClientInviteTransaction,
    destination: SbcSocketAddr,
    created_at: Instant,
    /// The INVITE on the wire, retransmitted on Timer A (§17.1.1.2).
    request: SipMessage,
    /// ACK for a non-2xx final (§17.1.1.3), re-sent when that final is
    /// retransmitted.
    ack: Option<SipMessage>,
    /// Call this INVITE belongs to (Timer B fails it).
    call: CallId,
}

/// State for client non-INVITE transaction.
struct ClientNonInviteState {
    transaction: ClientNonInviteTransaction,
    destination: SbcSocketAddr,
    created_at: Instant,
    /// The request on the wire, retransmitted on Timer E (§17.1.2.2).
    request: SipMessage,
    /// Call this request belongs to, when it is a relayed in-dialog request
    /// (Timer F fails it toward the originator).
    call: Option<CallId>,
}

impl TransactionStore {
    /// Sweep threshold: once any map exceeds this, stale entries are purged
    /// on the next insert. Bounds memory against INVITE floods.
    const SWEEP_THRESHOLD: usize = 1024;

    /// Backstop lifetime for a transaction that never reached Terminated.
    /// Terminated ones are pruned by `poll_timers` as their RFC 3261 timers
    /// fire; this only catches state machines that stalled. It must exceed
    /// any legitimate transaction — a server INVITE stays in Proceeding for
    /// as long as the callee rings — so it is minutes, not 64*T1.
    const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

    /// Removes transactions older than [`Self::MAX_AGE`] once any map has
    /// grown past [`Self::SWEEP_THRESHOLD`]. Amortized O(1) per insert.
    fn sweep_if_needed(&mut self) {
        let over = self
            .server_invite
            .len()
            .max(self.client_invite.len())
            .max(self.server_non_invite.len())
            .max(self.client_non_invite.len())
            > Self::SWEEP_THRESHOLD;
        if !over {
            return;
        }
        let now = std::time::Instant::now();
        let young = |created: std::time::Instant| now.duration_since(created) < Self::MAX_AGE;
        self.server_invite.retain(|_, s| young(s.created_at));
        self.server_non_invite.retain(|_, s| young(s.created_at));
        self.client_invite.retain(|_, s| young(s.created_at));
        self.client_non_invite.retain(|_, s| young(s.created_at));
    }

    /// Drops transactions whose state machine has reached Terminated.
    fn prune_terminated(&mut self) {
        self.server_invite
            .retain(|_, s| !s.transaction.is_terminated());
        self.server_non_invite
            .retain(|_, s| !s.transaction.is_terminated());
        self.client_invite
            .retain(|_, s| !s.transaction.is_terminated());
        self.client_non_invite
            .retain(|_, s| !s.transaction.is_terminated());
    }
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
    /// Via header values from the original A-leg INVITE (responses to the
    /// A-leg must carry these, not the B-leg's Via).
    a_leg_via: Vec<String>,
    /// From header of the original A-leg INVITE (caller, with tag).
    a_leg_from: String,
    /// To header of the original A-leg INVITE (no tag until answered).
    a_leg_to: String,
    /// CSeq value of the original A-leg INVITE (e.g. "314 INVITE").
    a_leg_cseq: String,
    /// From header sent on the B-leg INVITE (includes our from-tag).
    b_leg_from: String,
    /// To header sent on the B-leg INVITE (no tag until answered).
    b_leg_to: String,
    /// Top Via branch of the B-leg INVITE (CANCEL must mirror it; also
    /// used to validate that responses belong to our client transaction).
    b_leg_branch: String,
    /// Remote (callee) tag learned from the first tagged B-leg response.
    /// Completes the dialog identity on both legs.
    dialog_to_tag: Option<String>,
    /// RTP ports allocated for this call (released on teardown).
    rtp_ports: Vec<u16>,
    /// Media-relay A-leg (caller-facing) RTP port, when the pipeline anchored
    /// this call. Advertised to the caller in the A-leg answer SDP so both the
    /// offer (B-leg port) and answer (A-leg port) point at the relay's sockets.
    /// `None` when no relay is attached (bare-port fallback).
    media_a_leg_port: Option<u16>,
    /// SBC-owned media IP advertised to the **caller** in the A-leg answer SDP
    /// (183/200) — the ingress zone's media interface, where the relay's
    /// caller-facing socket is bound. Resolved once at INVITE so the answer
    /// handlers advertise the same host the relay listens on. The callee-facing
    /// (egress zone) media IP is only needed when building the B-leg offer, so
    /// it is used inline at INVITE and not stored here.
    media_a_leg_ip: String,
    /// The caller's offered DTLS `a=setup` role (from the A-leg INVITE offer),
    /// used to pick the SBC's answering role in the A-leg 183/200 SDP when
    /// terminating DTLS-SRTP. `None` for non-DTLS offers or pass-through.
    dtls_caller_setup: Option<crate::sdp_dtls::SetupRole>,
    /// The caller's DTLS `a=fingerprint` (from the A-leg INVITE offer). Persisted
    /// from INVITE because the A-leg DTLS handshake is driven at answer time
    /// (200 OK), when the original offer is no longer in hand. `None` for
    /// non-DTLS offers or pass-through.
    dtls_caller_fingerprint: Option<String>,
    /// SBC-owned media IP and port advertised to the **callee** in the B-leg
    /// offer; re-used when the caller re-offers mid-dialog.
    media_b_leg_ip: String,
    media_b_leg_port: u16,
    /// Set once the B-leg answered (first 2xx seen). A later 2xx is a
    /// retransmission: re-ACK only, do not restart media.
    b_leg_answered: bool,
    /// Next CSeq for SBC-originated requests toward each leg. The B-leg
    /// INVITE used 1; the SBC→caller direction has its own sequence space.
    a_leg_local_cseq: u32,
    b_leg_local_cseq: u32,
    /// Last SDP the SBC sent to each leg (the answer to the caller, the offer
    /// to the callee); replayed to answer a body-less session refresh.
    a_leg_last_sdp: Option<Bytes>,
    b_leg_last_sdp: Option<Bytes>,
    /// Mid-dialog re-INVITE/UPDATE currently being relayed across the legs.
    pending_reinvite: Option<PendingReinvite>,
    /// ACK sent for the last relayed re-INVITE's 2xx (keyed by that
    /// re-INVITE's client branch) — re-sent if the 2xx is retransmitted.
    last_reinvite_ack: Option<(String, SipMessage, SbcSocketAddr)>,
    /// When the B-leg answered (for the audit trail's call duration).
    established_at: Option<Instant>,
}

/// Records a call-lifecycle event on the audit trail (NIST AU-2); a no-op
/// when `logging.audit_enabled` is off.
fn audit(event: uc_audit::AuditEvent) {
    uc_audit::log_event(event);
}

/// `CallTerminated` for a call, with its duration since answer (0 when it
/// never got answered).
fn audit_call_terminated(addrs: &CallAddresses, reason: uc_audit::event::TerminationReason) {
    audit(uc_audit::AuditEvent::CallTerminated(
        uc_audit::event::CallTerminated {
            call_id: uc_types::identifier::CallId::new(addrs.a_leg_sip_call_id.clone()),
            duration_secs: addrs.established_at.map_or(0, |t| t.elapsed().as_secs()),
            reason,
        },
    ));
}

/// `AuthorizationDecision` for a rejected INVITE (admission or VPS policy).
fn audit_invite_denied(req: &SipRequest, source: SbcSocketAddr, policy: &str) {
    audit(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity: req
                .headers
                .get_value(&HeaderName::From)
                .map_or_else(|| source.to_string(), extract_uri_from_header),
            resource: req.uri.to_string(),
            action: "INVITE".to_string(),
            granted: false,
            policy: policy.to_string(),
        },
    ));
}

/// `AuthenticationAttempt` for a REGISTER outcome.
fn audit_register_auth(
    aor: &str,
    source: SbcSocketAddr,
    method: uc_audit::event::AuthMethod,
    failure_reason: Option<String>,
) {
    audit(uc_audit::AuditEvent::AuthenticationAttempt(
        uc_audit::event::AuthenticationAttempt {
            identity: aor.to_string(),
            source_ip: source.ip(),
            success: failure_reason.is_none(),
            failure_reason,
            method,
        },
    ));
}

/// A mid-dialog re-INVITE (RFC 3261 §14) or UPDATE (RFC 3311) received on one
/// leg and forwarded to the other; the originator is answered when the far
/// leg answers.
#[derive(Clone)]
struct PendingReinvite {
    /// `true` when the caller (A-leg) originated it.
    from_a_leg: bool,
    /// INVITE or UPDATE.
    method: Method,
    /// The originator's Via stack, From, To and CSeq — its response must
    /// carry these verbatim.
    orig_via: Vec<String>,
    orig_from: String,
    orig_to: String,
    orig_cseq: String,
    /// Top Via branch of the forwarded request (client transaction key).
    fwd_branch: String,
    /// CSeq number of the forwarded request (its ACK carries it).
    fwd_cseq: u32,
    /// The originator's offered DTLS `a=setup`; picks the SBC's answering
    /// role when terminating DTLS-SRTP.
    offer_setup: Option<crate::sdp_dtls::SetupRole>,
}

/// A 2xx the SBC sent as UAS for an INVITE, retransmitted until the ACK
/// arrives: 2xx reliability is the TU's job, not the transaction layer's
/// (RFC 3261 §13.3.1.4).
struct Pending2xx {
    response: SipMessage,
    destination: SbcSocketAddr,
    /// CSeq number of the INVITE answered (the ACK must carry it).
    cseq: u32,
    call: CallId,
    interval: std::time::Duration,
    next_at: Instant,
    deadline: Instant,
}

/// Methods the SBC accepts (OPTIONS `Allow` and 405 responses).
const ALLOWED_METHODS: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, UPDATE";

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

/// Where announcement media for a failed call is produced: a locally
/// bound RTP socket (in-process engine, pre-split behavior) or a session
/// on the sbc-announcement-server pod (`SBC_ANNOUNCEMENT_URL`).
enum AnnouncementPlayback {
    /// In-process playback on this bound socket.
    Local(tokio::net::UdpSocket),
    /// Remote playback; resolves when the pod reports Completed.
    /// Boxed: `RemoteAnnouncement` is far larger than the `Local` socket,
    /// so inlining it would bloat every `AnnouncementPlayback` value.
    #[cfg(feature = "grpc")]
    Remote(Box<crate::announcement_client::RemoteAnnouncement>),
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
        let registrar = AuthenticatedRegistrar::new(registrar_config)
            .with_password_lookup(move |user, _| credentials.get(user).cloned());

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            bearer: None,
            location_service,
            #[cfg(feature = "cluster")]
            async_location_service: None,
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
            dtls_fingerprint_source: None,
            router: None,
            sbc_router: None,
            header_manipulator: None,
            topology_hider: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            draining: std::sync::atomic::AtomicBool::new(false),
            next_rtp_port: std::sync::atomic::AtomicU16::new(32_770),
            allocated_ports: Arc::new(std::sync::Mutex::new(HashSet::new())),
            in_flight_invites: RwLock::new(HashSet::new()),
            pending_2xx: RwLock::new(HashMap::new()),
            user_limiter: None,
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(std::collections::HashMap::new()),
            announcement_calls: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashSet::new()),
            ),
            vps: None,
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
        let registrar = AuthenticatedRegistrar::new(registrar_config)
            .with_password_lookup(move |user, _| credentials.get(user).cloned());

        info!("SIP stack initialized with storage-backed location service");

        Self {
            transactions: RwLock::new(TransactionStore::default()),
            dialogs: RwLock::new(DialogStore::default()),
            calls: RwLock::new(CallStore::default()),
            registrar: RwLock::new(registrar),
            bearer: None,
            location_service,
            async_location_service: Some(async_location_service),
            call_correlation: RwLock::new(CallCorrelation::default()),
            sdp_rewriter: SdpRewriter::new(B2buaMode::MediaRelay),
            media_pipeline: None,
            dtls_fingerprint_source: None,
            router: None,
            sbc_router: None,
            header_manipulator: None,
            topology_hider: None,
            registrations_active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            draining: std::sync::atomic::AtomicBool::new(false),
            next_rtp_port: std::sync::atomic::AtomicU16::new(32_770),
            allocated_ports: Arc::new(std::sync::Mutex::new(HashSet::new())),
            in_flight_invites: RwLock::new(HashSet::new()),
            pending_2xx: RwLock::new(HashMap::new()),
            user_limiter: None,
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(std::collections::HashMap::new()),
            announcement_calls: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashSet::new()),
            ),
            vps: None,
        }
    }

    /// Allocates the next even-numbered RTP port in the 32770-49998 range,
    /// skipping any port currently in use.  Range starts above the media
    /// pipeline's RTP allocator (16384-32768) to avoid port collisions.
    fn allocate_rtp_port(&self) -> u16 {
        const MIN_PORT: u16 = 32_770;
        const MAX_PORT: u16 = 49_998;
        const PAIR_COUNT: u16 = (MAX_PORT - MIN_PORT) / 2 + 1;
        let mut ports = self
            .allocated_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut candidate = self.next_rtp_port.load(Ordering::Relaxed);
        for _ in 0..PAIR_COUNT {
            if candidate > MAX_PORT {
                candidate = MIN_PORT;
            }
            if !ports.contains(&candidate) {
                ports.insert(candidate);
                let next = if candidate + 2 > MAX_PORT {
                    MIN_PORT
                } else {
                    candidate + 2
                };
                self.next_rtp_port.store(next, Ordering::Relaxed);
                return candidate;
            }
            candidate += 2;
        }
        let fallback = self.next_rtp_port.load(Ordering::Relaxed);
        ports.insert(fallback);
        fallback
    }

    /// Releases a previously allocated RTP port so it can be reused.
    fn release_rtp_port(&self, port: u16) {
        let mut ports = self
            .allocated_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ports.remove(&port);
    }

    /// Sets the media controller (RTP/SRTP relay). Takes `dyn MediaController`
    /// so the signaling layer is decoupled from the concrete in-process pipeline
    /// (an out-of-process implementation can be injected here later).
    pub fn set_media_pipeline(
        &mut self,
        pipeline: Arc<dyn sbc_media_core::media_pipeline::MediaController>,
    ) {
        self.media_pipeline = Some(pipeline);
    }

    /// Sets the SBC's DTLS-SRTP fingerprint source, enabling DTLS-SRTP
    /// termination (advertising the SBC's own fingerprint in rewritten SDP). A
    /// file-backed source re-reads on demand so a sidecar restart is picked up.
    /// Set only when `srtp.mode = terminate`.
    pub fn set_dtls_fingerprint_source(
        &mut self,
        source: Arc<sbc_media_core::dtls_identity::DtlsFingerprintSource>,
    ) {
        self.dtls_fingerprint_source = Some(source);
    }

    /// Applies DTLS-SRTP termination rewriting to an A-leg answer SDP: when the
    /// SBC terminates DTLS (fingerprint source set), advertise the SBC's own
    /// fingerprint with the answering `a=setup` role derived from the caller's
    /// offer (RFC 5763). A no-op for pass-through or non-DTLS answers.
    fn rewrite_answer_dtls(&self, sdp: String, addrs: &CallAddresses) -> String {
        if let Some(source) = &self.dtls_fingerprint_source {
            let role = addrs.dtls_caller_setup.map_or(
                crate::sdp_dtls::SetupRole::Passive,
                super::sdp_dtls::SetupRole::answer_role,
            );
            crate::sdp_dtls::rewrite_local_dtls(&sdp, &source.current(), role)
        } else {
            sdp
        }
    }

    /// The SBC's DTLS role for a leg whose peer offered `peer_setup`. The SBC
    /// answers each terminated leg (RFC 5763), so the answering `a=setup`
    /// decides: a `passive` answer makes the SBC the DTLS server, an `active`
    /// answer the client. A peer that omitted `a=setup` is treated as `actpass`
    /// (the offerer default) → the SBC answers `passive` (server), matching
    /// [`Self::rewrite_answer_dtls`]. Used to drive the per-leg handshake.
    fn sbc_dtls_role(
        peer_setup: Option<crate::sdp_dtls::SetupRole>,
    ) -> sbc_media_core::dtls_sidecar::Role {
        use crate::sdp_dtls::SetupRole;
        match peer_setup.map_or(SetupRole::Passive, SetupRole::answer_role) {
            SetupRole::Active => sbc_media_core::dtls_sidecar::Role::Client,
            // answer_role() yields only Active/Passive; Passive (and, defensively,
            // ActPass) means the SBC is the DTLS server.
            SetupRole::Passive | SetupRole::ActPass => sbc_media_core::dtls_sidecar::Role::Server,
        }
    }

    /// Derives the per-leg DTLS-SRTP terminate params for a call, or `None` to
    /// relay opaquely. Termination requires the SBC to terminate
    /// (`has_dtls_identity`) **and both legs to offer DTLS**: the caller's
    /// fingerprint captured at INVITE, the callee's parsed from its answer.
    /// Pure so the terminate/opaque decision is unit-testable.
    fn terminate_params(
        has_dtls_identity: bool,
        caller_fingerprint: Option<&String>,
        caller_setup: Option<crate::sdp_dtls::SetupRole>,
        answer_sdp: &str,
    ) -> Option<(
        sbc_media_core::media_pipeline::LegDtlsParams,
        sbc_media_core::media_pipeline::LegDtlsParams,
    )> {
        if !has_dtls_identity {
            return None;
        }
        let caller_fp = caller_fingerprint?;
        let callee = crate::sdp_dtls::parse_peer_dtls(answer_sdp)?;
        Some((
            sbc_media_core::media_pipeline::LegDtlsParams {
                peer_fingerprint: caller_fp.clone(),
                role: Self::sbc_dtls_role(caller_setup),
            },
            sbc_media_core::media_pipeline::LegDtlsParams {
                peer_fingerprint: callee.fingerprint,
                role: Self::sbc_dtls_role(callee.setup),
            },
        ))
    }

    /// Starts the media relay for a call at 200-OK time: DTLS-SRTP termination
    /// when [`Self::terminate_params`] applies, else the opaque forwarding relay
    /// (plain RTP or SRTP pass-through). Errors are logged, not propagated —
    /// media failure must not fail call setup.
    async fn start_media_relay(
        &self,
        pipeline: &dyn sbc_media_core::media_pipeline::MediaController,
        session_key: &str,
        addrs: &CallAddresses,
        answer_sdp: &str,
    ) {
        let params = Self::terminate_params(
            self.dtls_fingerprint_source.is_some(),
            addrs.dtls_caller_fingerprint.as_ref(),
            addrs.dtls_caller_setup,
            answer_sdp,
        );
        if let Some((a_leg, b_leg)) = params {
            if let Err(e) = pipeline
                .start_relay_terminate(session_key, a_leg, b_leg)
                .await
            {
                warn!(error = %e, call_id = %addrs.a_leg_sip_call_id, "start_relay_terminate failed");
            }
            return;
        }
        if self.dtls_fingerprint_source.is_some() {
            // Terminate configured but a leg offered no fingerprint; SRTP↔RTP
            // interworking is not yet supported, so relay opaquely.
            warn!(
                call_id = %addrs.a_leg_sip_call_id,
                "DTLS termination configured but a leg offered no fingerprint; relaying opaquely"
            );
        }
        if let Err(e) = pipeline.start_relay(session_key).await {
            warn!(error = %e, call_id = %addrs.a_leg_sip_call_id, "start_relay failed");
        }
    }

    /// Builds a BYE for one leg of a confirmed dialog from stored dialog state.
    /// `target_b_leg` sends to the callee (SBC as UAC on the B-leg); otherwise to
    /// the caller (SBC as UAS on the A-leg). Mirrors the BYE construction in
    /// [`Self::handle_bye`] so an SBC-initiated teardown is dialog-correct.
    fn build_leg_bye(addrs: &CallAddresses, target_b_leg: bool) -> proto_sip::message::SipRequest {
        let (dest, other_call_id) = if target_b_leg {
            (&addrs.b_leg_destination, &addrs.b_leg_sip_call_id)
        } else {
            (&addrs.a_leg_source, &addrs.a_leg_sip_call_id)
        };
        let uri = SipUri::new(dest.ip().to_string()).with_port(dest.port());
        let mut bye = proto_sip::message::SipRequest::new(Method::Bye, uri);
        bye.headers.set(HeaderName::CallId, other_call_id);
        if target_b_leg {
            // SBC is the UAC on the B-leg: From = our INVITE From, To = the callee
            // with their tag; next CSeq after the INVITE (1).
            bye.headers.set(HeaderName::From, &addrs.b_leg_from);
            bye.headers.set(
                HeaderName::To,
                with_tag(&addrs.b_leg_to, addrs.dialog_to_tag.as_deref()),
            );
            bye.headers
                .set(HeaderName::CSeq, format!("{} BYE", addrs.b_leg_local_cseq));
        } else {
            // SBC is the UAS on the A-leg: From = the To we answered with (+tag),
            // To = the caller's From. The SBC→A direction has its own CSeq space.
            bye.headers.set(
                HeaderName::From,
                with_tag(&addrs.a_leg_to, addrs.dialog_to_tag.as_deref()),
            );
            bye.headers.set(HeaderName::To, &addrs.a_leg_from);
            bye.headers
                .set(HeaderName::CSeq, format!("{} BYE", addrs.a_leg_local_cseq));
        }
        bye.headers.set(HeaderName::MaxForwards, "70");
        let branch = generate_branch();
        bye.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        bye.headers.set(HeaderName::ContentLength, "0");
        bye
    }

    /// Builds an in-dialog request (re-INVITE, UPDATE or ACK) toward one leg,
    /// optionally carrying an SDP body. Mirrors [`Self::build_leg_bye`]'s
    /// dialog addressing (To/From/Call-ID per leg); INVITE/UPDATE also carry a
    /// `Contact` refreshing the SBC's dialog target. `cseq` is the sequence
    /// number in the SBC's request stream toward that leg (for ACK, the
    /// INVITE's). Used to relay mid-dialog session changes (RFC 3261 §14,
    /// RFC 3311) and by media re-anchor (RFC 3264 re-offer).
    fn build_leg_in_dialog_request(
        addrs: &CallAddresses,
        target_b_leg: bool,
        method: &Method,
        cseq: u32,
        body: Option<&[u8]>,
    ) -> proto_sip::message::SipRequest {
        let (dest, other_call_id) = if target_b_leg {
            (&addrs.b_leg_destination, &addrs.b_leg_sip_call_id)
        } else {
            (&addrs.a_leg_source, &addrs.a_leg_sip_call_id)
        };
        let uri = SipUri::new(dest.ip().to_string()).with_port(dest.port());
        let method_name = method.to_string();
        let mut inv = proto_sip::message::SipRequest::new(method.clone(), uri);
        inv.headers.set(HeaderName::CallId, other_call_id);
        if target_b_leg {
            // SBC is the UAC on the B-leg: From = our INVITE From, To = the callee
            // with their tag (same dialog as the original INVITE).
            inv.headers.set(HeaderName::From, &addrs.b_leg_from);
            inv.headers.set(
                HeaderName::To,
                with_tag(&addrs.b_leg_to, addrs.dialog_to_tag.as_deref()),
            );
        } else {
            // SBC is the UAS on the A-leg: From = the To we answered with (+tag),
            // To = the caller's From.
            inv.headers.set(
                HeaderName::From,
                with_tag(&addrs.a_leg_to, addrs.dialog_to_tag.as_deref()),
            );
            inv.headers.set(HeaderName::To, &addrs.a_leg_from);
        }
        inv.headers
            .set(HeaderName::CSeq, format!("{cseq} {method_name}"));
        inv.headers.set(HeaderName::MaxForwards, "70");
        let branch = generate_branch();
        inv.headers.add(Header::new(
            HeaderName::Via,
            format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
        ));
        if *method != Method::Ack {
            // Target-refresh Contact: subsequent in-dialog requests come back to us.
            inv.headers
                .set(HeaderName::Contact, format!("<sip:{}>", addrs.local_addr));
        }
        match body {
            Some(sdp) if !sdp.is_empty() => {
                inv.headers.set(HeaderName::ContentType, "application/sdp");
                inv.headers
                    .set(HeaderName::ContentLength, sdp.len().to_string());
                inv.body = Some(Bytes::copy_from_slice(sdp));
            }
            _ => {
                inv.headers.set(HeaderName::ContentLength, "0");
            }
        }
        inv
    }

    // ------------------------------------------------------------------
    // Transaction layer (RFC 3261 §17) and 2xx reliability (§13.3.1.4).
    //
    // The state machines live in `proto-transaction`; this stack opens one
    // per request it receives or sends, feeds it every message and timer
    // tick, and re-sends from the copies kept alongside.
    // ------------------------------------------------------------------

    /// If `req` retransmits a request already in the server transaction store
    /// (RFC 3261 §17.2.3: top Via branch + CSeq method), returns what to do
    /// about it — re-send the last response, or nothing while the first copy
    /// is still being processed. `None` means the request is new.
    async fn answer_request_retransmit(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
    ) -> Option<ProcessResult> {
        let branch = req.headers.via_branch()?;
        let key = TransactionKey::server(&branch, req.method.to_string());
        let mut txns = self.transactions.write().await;
        let (resend, last) = if req.method == Method::Invite {
            let st = txns.server_invite.get_mut(&key)?;
            (
                st.transaction.receive_request().unwrap_or(false),
                st.last_response.clone(),
            )
        } else {
            let st = txns.server_non_invite.get_mut(&key)?;
            (
                st.transaction.receive_request().unwrap_or(false),
                st.last_response.clone(),
            )
        };
        drop(txns);
        debug!(method = %req.method, branch = %branch, resend, "Request retransmission");
        match (resend, last) {
            (true, Some(message)) => Some(ProcessResult::Response {
                message,
                destination: source,
            }),
            _ => Some(ProcessResult::NoAction),
        }
    }

    /// Opens a server transaction for a newly received request so later
    /// retransmissions are answered from the stored response and a non-2xx
    /// INVITE final is retransmitted on Timer G until ACKed.
    async fn open_server_transaction(&self, req: &SipRequest, source: SbcSocketAddr) {
        let Some(branch) = req.headers.via_branch() else {
            return;
        };
        let key = TransactionKey::server(&branch, req.method.to_string());
        let now = Instant::now();
        let mut txns = self.transactions.write().await;
        txns.sweep_if_needed();
        if req.method == Method::Invite {
            txns.server_invite
                .entry(key.clone())
                .or_insert_with(|| ServerInviteState {
                    transaction: ServerInviteTransaction::new(key, TransportType::Unreliable),
                    source,
                    created_at: now,
                    last_response: None,
                });
        } else {
            txns.server_non_invite
                .entry(key.clone())
                .or_insert_with(|| ServerNonInviteState {
                    transaction: ServerNonInviteTransaction::new(key, TransportType::Unreliable),
                    source,
                    created_at: now,
                    last_response: None,
                });
        }
    }

    /// Bookkeeping for everything a handler puts on the wire: responses are
    /// recorded on their server transaction, forwarded requests open a client
    /// transaction that retransmits and times them out.
    async fn track_result(&self, result: &ProcessResult) {
        match result {
            ProcessResult::Response { message, .. } => self.record_server_response(message).await,
            ProcessResult::Forward {
                message,
                destination,
            } => self.open_client_transaction(message, *destination).await,
            ProcessResult::Multiple(results) => {
                for r in results {
                    Box::pin(self.track_result(r)).await;
                }
            }
            ProcessResult::NoAction | ProcessResult::Error { .. } => {}
        }
    }

    /// Feeds a response the TU is sending to its server transaction (matched
    /// by the response's top Via branch + CSeq method, which mirror the
    /// request's) and keeps a copy for retransmission.
    async fn record_server_response(&self, message: &SipMessage) {
        let SipMessage::Response(resp) = message else {
            return;
        };
        let Some(branch) = resp.headers.via_branch() else {
            return;
        };
        let Some(cseq) = resp.headers.cseq_parsed() else {
            return;
        };
        let code = resp.status.code();
        let key = TransactionKey::server(&branch, cseq.method.to_string());
        let mut txns = self.transactions.write().await;
        if cseq.method == Method::Invite {
            if let Some(st) = txns.server_invite.get_mut(&key) {
                let _ = st.transaction.send_response(code);
                st.last_response = Some(message.clone());
            }
        } else if let Some(st) = txns.server_non_invite.get_mut(&key) {
            let _ = st.transaction.send_response(code);
            st.last_response = Some(message.clone());
        }
    }

    /// Opens a client transaction for a request the SBC is sending. ACK has
    /// none (§17.1.1.3). The stored copy is retransmitted on Timer A/E; Timer
    /// B/F fails the call or relayed request it belongs to.
    async fn open_client_transaction(&self, message: &SipMessage, destination: SbcSocketAddr) {
        let SipMessage::Request(req) = message else {
            return;
        };
        if req.method == Method::Ack {
            return;
        }
        let Some(branch) = req.headers.via_branch() else {
            return;
        };
        let call = {
            let corr = self.call_correlation.read().await;
            let id = req.headers.call_id().unwrap_or("");
            corr.b_leg.get(id).or_else(|| corr.a_leg.get(id)).cloned()
        };
        let key = TransactionKey::client(&branch, req.method.to_string());
        let now = Instant::now();
        let mut txns = self.transactions.write().await;
        txns.sweep_if_needed();
        if req.method == Method::Invite {
            let Some(call) = call else {
                return;
            };
            txns.client_invite
                .entry(key.clone())
                .or_insert_with(|| ClientInviteState {
                    transaction: ClientInviteTransaction::new(key, TransportType::Unreliable),
                    destination,
                    created_at: now,
                    request: message.clone(),
                    ack: None,
                    call,
                });
        } else {
            txns.client_non_invite
                .entry(key.clone())
                .or_insert_with(|| ClientNonInviteState {
                    transaction: ClientNonInviteTransaction::new(key, TransportType::Unreliable),
                    destination,
                    created_at: now,
                    request: message.clone(),
                    call,
                });
        }
    }

    /// Builds the ACK for a non-2xx final to a client INVITE (RFC 3261
    /// §17.1.1.3): the INVITE's Request-URI, Call-ID, From and CSeq number,
    /// the To from the response, and a single Via equal to the INVITE's top
    /// Via — same branch, since this ACK belongs to that transaction.
    fn build_non2xx_ack(invite: &SipRequest, resp: &SipResponse) -> SipMessage {
        let mut ack = SipRequest::new(Method::Ack, invite.uri.clone());
        if let Some(via) = invite.headers.get_value(&HeaderName::Via) {
            ack.headers.add(Header::new(HeaderName::Via, via));
        }
        for name in [
            HeaderName::From,
            HeaderName::CallId,
            HeaderName::MaxForwards,
        ] {
            if let Some(v) = invite.headers.get_value(&name) {
                ack.headers.set(name, v);
            }
        }
        let to = resp
            .headers
            .get_value(&HeaderName::To)
            .or_else(|| invite.headers.get_value(&HeaderName::To))
            .unwrap_or_default();
        ack.headers.set(HeaderName::To, to);
        let seq = invite.headers.cseq_parsed().map_or(1, |c| c.sequence);
        ack.headers.set(HeaderName::CSeq, format!("{seq} ACK"));
        ack.headers.set(HeaderName::ContentLength, "0");
        SipMessage::Request(ack)
    }

    /// Starts retransmitting a 2xx the SBC sent for an INVITE until the ACK
    /// arrives (RFC 3261 §13.3.1.4: every T1, doubling up to T2, giving up
    /// after 64*T1). Keyed by the SIP Call-ID of the leg it was sent on.
    async fn arm_2xx_retransmit(
        &self,
        leg_call_id: &str,
        call: &CallId,
        response: &SipMessage,
        destination: SbcSocketAddr,
        cseq: u32,
    ) {
        let now = Instant::now();
        let t1 = proto_transaction::DEFAULT_T1;
        self.pending_2xx.write().await.insert(
            leg_call_id.to_string(),
            Pending2xx {
                response: response.clone(),
                destination,
                cseq,
                call: call.clone(),
                interval: t1,
                next_at: now + t1,
                deadline: now + t1 * 64,
            },
        );
    }

    /// Drives every transaction's timers (RFC 3261 §17) plus the TU-level 2xx
    /// retransmission (§13.3.1.4), returning what must go on the wire: Timer
    /// A/E/G re-sends, Timer B/F timeouts turned into 408s, and BYEs for 2xx
    /// responses that were never ACKed. The daemon calls this every ~100 ms
    /// (a fraction of T1).
    pub async fn poll_timers(&self) -> Vec<ProcessResult> {
        let mut out = Vec::new();
        let mut timed_out: Vec<(String, CallId)> = Vec::new();
        {
            let mut txns = self.transactions.write().await;
            for (key, st) in &mut txns.client_invite {
                match st.transaction.check_timers() {
                    Some(TimerType::TimerA) => out.push(ProcessResult::Forward {
                        message: st.request.clone(),
                        destination: st.destination,
                    }),
                    Some(TimerType::TimerB) => {
                        timed_out.push((key.branch.clone(), st.call.clone()));
                    }
                    _ => {}
                }
            }
            for (key, st) in &mut txns.client_non_invite {
                match st.transaction.check_timers() {
                    Some(TimerType::TimerE) => out.push(ProcessResult::Forward {
                        message: st.request.clone(),
                        destination: st.destination,
                    }),
                    Some(TimerType::TimerF) => {
                        if let Some(call) = &st.call {
                            timed_out.push((key.branch.clone(), call.clone()));
                        }
                    }
                    _ => {}
                }
            }
            for (key, st) in &mut txns.server_invite {
                match st.transaction.check_timers() {
                    Some(TimerType::TimerG) => {
                        if let Some(r) = &st.last_response {
                            out.push(ProcessResult::Response {
                                message: r.clone(),
                                destination: st.source,
                            });
                        }
                    }
                    Some(TimerType::TimerH) => warn!(
                        branch = %key.branch,
                        "No ACK for non-2xx final; INVITE server transaction timed out"
                    ),
                    _ => {}
                }
            }
            for st in txns.server_non_invite.values_mut() {
                let _ = st.transaction.check_timers();
            }
            txns.prune_terminated();
        }

        let mut timeouts = Vec::new();
        for (branch, call) in timed_out {
            timeouts.extend(self.fail_timed_out_request(&branch, &call).await);
        }
        // The 408s ride their server transactions; the BYEs get client ones.
        for r in &timeouts {
            self.track_result(r).await;
        }
        out.extend(timeouts);
        out.extend(self.retransmit_pending_2xx().await);
        out
    }

    /// A request the SBC forwarded got no final response (Timer B/F). For the
    /// initial INVITE the call fails with 408 toward the caller. For a relayed
    /// re-INVITE/UPDATE the originator gets the 408 — which ends the dialog at
    /// its end (RFC 5057 §5.2) — the silent leg is BYEd and the call released.
    async fn fail_timed_out_request(&self, branch: &str, call: &CallId) -> Vec<ProcessResult> {
        let addrs = {
            let corr = self.call_correlation.read().await;
            match corr.addresses.get(call) {
                Some(a) => a.clone(),
                None => return Vec::new(),
            }
        };
        let timeout = StatusCode::REQUEST_TIMEOUT;

        if let Some(p) = addrs
            .pending_reinvite
            .as_ref()
            .filter(|p| p.fwd_branch == branch)
        {
            warn!(
                call_id = %addrs.a_leg_sip_call_id,
                method = %p.method,
                "Relayed in-dialog request got no response; releasing call"
            );
            let (resp, dest) = Self::build_reinvite_response(timeout, p, &addrs);
            let bye = Self::build_leg_bye(&addrs, p.from_a_leg);
            let bye_dest = if p.from_a_leg {
                addrs.b_leg_destination
            } else {
                addrs.a_leg_source
            };
            self.cleanup_terminated_call(call, &addrs).await;
            return vec![
                ProcessResult::Response {
                    message: resp,
                    destination: dest,
                },
                ProcessResult::Forward {
                    message: SipMessage::Request(bye),
                    destination: bye_dest,
                },
            ];
        }

        if branch == addrs.b_leg_branch {
            warn!(
                call_id = %addrs.a_leg_sip_call_id,
                "No final response from B-leg (Timer B); failing call with 408"
            );
            audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Timeout);
            {
                let mut calls = self.calls.write().await;
                if let Some(c) = calls.calls.get_mut(call) {
                    c.fail(timeout.code(), timeout.reason_phrase());
                }
            }
            let resp = build_a_leg_response(timeout, &addrs);
            self.cleanup_terminated_call(call, &addrs).await;
            return vec![ProcessResult::Response {
                message: SipMessage::Response(resp),
                destination: addrs.a_leg_source,
            }];
        }

        Vec::new()
    }

    /// Re-sends 2xx responses whose ACK has not arrived; a 2xx still
    /// un-ACKed after 64*T1 ends the call with a BYE to both legs (RFC 3261
    /// §13.3.1.4).
    async fn retransmit_pending_2xx(&self) -> Vec<ProcessResult> {
        let now = Instant::now();
        let t2 = proto_transaction::DEFAULT_T2;
        let mut out = Vec::new();
        let mut expired = Vec::new();
        {
            let mut pending = self.pending_2xx.write().await;
            for (leg_call_id, p) in pending.iter_mut() {
                if now >= p.deadline {
                    expired.push((leg_call_id.clone(), p.call.clone()));
                } else if now >= p.next_at {
                    out.push(ProcessResult::Response {
                        message: p.response.clone(),
                        destination: p.destination,
                    });
                    p.interval = (p.interval * 2).min(t2);
                    p.next_at = now + p.interval;
                }
            }
            for (id, _) in &expired {
                pending.remove(id);
            }
        }
        for (leg_call_id, call) in expired {
            let addrs = {
                let corr = self.call_correlation.read().await;
                match corr.addresses.get(&call) {
                    Some(a) => a.clone(),
                    None => continue,
                }
            };
            warn!(
                call_id = %leg_call_id,
                "2xx never ACKed; terminating call (RFC 3261 §13.3.1.4)"
            );
            audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Failed);
            if addrs.dialog_to_tag.is_some() {
                out.push(ProcessResult::Forward {
                    message: SipMessage::Request(Self::build_leg_bye(&addrs, false)),
                    destination: addrs.a_leg_source,
                });
                out.push(ProcessResult::Forward {
                    message: SipMessage::Request(Self::build_leg_bye(&addrs, true)),
                    destination: addrs.b_leg_destination,
                });
            }
            self.cleanup_terminated_call(&call, &addrs).await;
        }
        out
    }

    // ------------------------------------------------------------------
    // Mid-dialog session changes: re-INVITE (RFC 3261 §14), UPDATE (RFC
    // 3311), session refresh (RFC 4028).
    // ------------------------------------------------------------------

    /// Handles UPDATE (RFC 3311). Only in-dialog UPDATEs are meaningful to a
    /// B2BUA; one without a To tag matches no dialog (481).
    async fn handle_update(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };
        if req.headers.to_tag().is_none() {
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        }
        self.handle_in_dialog_request(req, source).await
    }

    /// Relays a mid-dialog re-INVITE or UPDATE from one leg to the other. The
    /// originator's new offer is re-anchored at the SBC's media address toward
    /// the far leg; the far leg's answer comes back re-anchored toward the
    /// originator, and the relay's remote addresses follow both — so
    /// hold/resume, codec changes and RFC 4028 refreshes work end to end. A
    /// body-less refresh is answered locally with the SDP last sent to that
    /// leg. One re-INVITE at a time crosses the B2BUA (491 otherwise, §14.2).
    async fn handle_in_dialog_request(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
    ) -> ProcessResult {
        let method = req.method.clone();
        let sip_call_id = req.headers.call_id().unwrap_or("").to_string();
        let respond = |status: StatusCode| ProcessResult::Response {
            message: SipMessage::Response(create_response_from_request(req, status)),
            destination: source,
        };

        // 1. Match the dialog: Call-ID on either leg, and the request's From
        //    tag must be that leg's remote tag (a forged request with a
        //    guessed Call-ID gets 481, not a relayed session change).
        let (internal_id, from_a_leg, addrs) = {
            let corr = self.call_correlation.read().await;
            let found = corr
                .a_leg
                .get(&sip_call_id)
                .map(|id| (id.clone(), true))
                .or_else(|| corr.b_leg.get(&sip_call_id).map(|id| (id.clone(), false)));
            let Some(found) =
                found.and_then(|(id, a)| corr.addresses.get(&id).map(|ad| (id, a, ad.clone())))
            else {
                debug!(method = %method, call_id = %sip_call_id, "In-dialog request for unknown dialog, 481");
                return respond(StatusCode::CALL_DOES_NOT_EXIST);
            };
            found
        };
        let remote_tag = if from_a_leg {
            extract_param(&addrs.a_leg_from, "tag").map(String::from)
        } else {
            addrs.dialog_to_tag.clone()
        };
        if addrs.dialog_to_tag.is_none()
            || remote_tag.is_none()
            || req.headers.from_tag() != remote_tag
        {
            warn!(method = %method, call_id = %sip_call_id, "In-dialog request does not match the dialog's tags, 481");
            return respond(StatusCode::CALL_DOES_NOT_EXIST);
        }

        // 2. Glare (§14.2): a second session change while one is in flight.
        if addrs.pending_reinvite.is_some() {
            info!(method = %method, call_id = %sip_call_id, "Session change already pending, 491");
            return respond(StatusCode::REQUEST_PENDING);
        }

        // 3. Body-less refresh (RFC 4028 §7.4): answer locally. A 200 to an
        //    INVITE must carry an offer (§14.2), so replay the SDP this leg
        //    last got from us; the ACK's answer is not needed by the relay.
        let Some(body) = req.body.as_ref().filter(|b| !b.is_empty()) else {
            let mut ok = create_response_from_request(req, StatusCode::OK);
            // RFC 4028 §9: the 2xx names the refresher — the requester keeps
            // refreshing — and requires `timer` when the requester supports it.
            if let Some(se) = req.headers.get_value(&HeaderName::SessionExpires) {
                let se = if se.contains("refresher=") {
                    se.to_string()
                } else {
                    format!("{se};refresher=uac")
                };
                ok.headers.set(HeaderName::SessionExpires, se);
                if lists_timer_option(&req.headers, &HeaderName::Supported) {
                    ok.headers.set(HeaderName::Require, "timer");
                }
            }
            if method == Method::Invite {
                ok.headers
                    .set(HeaderName::Contact, format!("<sip:{}>", addrs.local_addr));
                let last = if from_a_leg {
                    &addrs.a_leg_last_sdp
                } else {
                    &addrs.b_leg_last_sdp
                };
                if let Some(sdp) = last {
                    ok.headers.set(HeaderName::ContentType, "application/sdp");
                    ok.headers
                        .set(HeaderName::ContentLength, sdp.len().to_string());
                    ok.body = Some(sdp.clone());
                }
            }
            let ok = SipMessage::Response(ok);
            if method == Method::Invite {
                self.arm_2xx_retransmit(
                    &sip_call_id,
                    &internal_id,
                    &ok,
                    source,
                    req.headers.cseq_parsed().map_or(1, |c| c.sequence),
                )
                .await;
            }
            info!(method = %method, call_id = %sip_call_id, "Session refresh answered locally");
            return ProcessResult::Response {
                message: ok,
                destination: source,
            };
        };

        // 4. The originator's new offer: follow its media address (a hold
        //    with c=0.0.0.0 is not an address and leaves the relay as is),
        //    then re-anchor the offer at the SBC's address facing the far leg.
        let sdp_str = String::from_utf8_lossy(body);
        let session_key = internal_id.to_string();
        if let Some(ref pipeline) = self.media_pipeline
            && let Some(media) = extract_media_address(&sdp_str)
            && let Some(addr) = admitted_media_addr(&media)
        {
            let _ = pipeline
                .set_remote_address(&session_key, from_a_leg, addr)
                .await;
        }
        let local_media = if from_a_leg {
            MediaAddress::new(&addrs.media_b_leg_ip, addrs.media_b_leg_port)
        } else {
            MediaAddress::new(&addrs.media_a_leg_ip, a_leg_media_port(&addrs))
        };
        let mut offer = self
            .sdp_rewriter
            .rewrite_reinvite(&sdp_str, &local_media)
            .rewritten;
        if let Some(fp) = &self.dtls_fingerprint_source {
            offer = crate::sdp_dtls::rewrite_local_dtls(
                &offer,
                &fp.current(),
                crate::sdp_dtls::SetupRole::ActPass,
            );
        }
        let offer_setup = crate::sdp_dtls::parse_peer_dtls(&sdp_str).and_then(|d| d.setup);

        // 5. Forward on the other leg as the next request in the SBC's own
        //    sequence space there.
        let (dest, fwd_cseq) = if from_a_leg {
            (addrs.b_leg_destination, addrs.b_leg_local_cseq)
        } else {
            (addrs.a_leg_source, addrs.a_leg_local_cseq)
        };
        let mut fwd = Self::build_leg_in_dialog_request(
            &addrs,
            from_a_leg,
            &method,
            fwd_cseq,
            Some(offer.as_bytes()),
        );
        relay_session_timer_request_headers(&req.headers, &mut fwd.headers);
        let fwd_branch = fwd.headers.via_branch().unwrap_or_default();

        // 6. Remember what is in flight.
        {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(&internal_id) {
                if from_a_leg {
                    a.b_leg_local_cseq += 1;
                    a.b_leg_last_sdp = Some(Bytes::from(offer));
                } else {
                    a.a_leg_local_cseq += 1;
                    a.a_leg_last_sdp = Some(Bytes::from(offer));
                }
                a.pending_reinvite = Some(PendingReinvite {
                    from_a_leg,
                    method: method.clone(),
                    orig_via: req
                        .headers
                        .get_all(&HeaderName::Via)
                        .map(|h| h.value.clone())
                        .collect(),
                    orig_from: req
                        .headers
                        .get_value(&HeaderName::From)
                        .unwrap_or_default()
                        .to_string(),
                    orig_to: req
                        .headers
                        .get_value(&HeaderName::To)
                        .unwrap_or_default()
                        .to_string(),
                    orig_cseq: req.headers.cseq().unwrap_or_default().to_string(),
                    fwd_branch,
                    fwd_cseq,
                    offer_setup,
                });
            }
        }

        info!(
            method = %method,
            call_id = %sip_call_id,
            from_a_leg,
            "Relaying mid-dialog session change to the other leg"
        );

        let mut results = Vec::with_capacity(2);
        if method == Method::Invite {
            results.push(ProcessResult::Response {
                message: SipMessage::Response(create_response_from_request(
                    req,
                    StatusCode::TRYING,
                )),
                destination: source,
            });
        }
        results.push(ProcessResult::Forward {
            message: SipMessage::Request(fwd),
            destination: dest,
        });
        ProcessResult::Multiple(results)
    }

    /// Handles the far leg's response to a relayed re-INVITE/UPDATE: the
    /// answer is re-anchored toward the originator and the relay learns the
    /// answerer's new media address; a relayed re-INVITE's 2xx is ACKed on
    /// the far leg and the originator's 2xx retransmitted until it ACKs. A
    /// 408/481 means the far leg's dialog is gone (RFC 5057 §5.2): the
    /// originator gets it and the call is released.
    async fn handle_reinvite_response(
        &self,
        resp: &SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
        pending: &PendingReinvite,
    ) -> ProcessResult {
        let code = resp.status.code();
        if code == 100 {
            return ProcessResult::NoAction;
        }
        let (mut relayed, orig_dest) = Self::build_reinvite_response(resp.status, pending, addrs);
        if code < 200 {
            return ProcessResult::Response {
                message: relayed,
                destination: orig_dest,
            };
        }

        // Final response: the session change is no longer pending.
        {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(internal_id) {
                a.pending_reinvite = None;
            }
        }

        if code >= 300 {
            if code == 408 || code == 481 {
                warn!(
                    call_id = %addrs.a_leg_sip_call_id,
                    status = code,
                    "Far leg's dialog is gone; releasing call"
                );
                self.cleanup_terminated_call(internal_id, addrs).await;
            } else {
                info!(
                    call_id = %addrs.a_leg_sip_call_id,
                    status = code,
                    "Session change rejected by far leg; relaying to originator"
                );
            }
            return ProcessResult::Response {
                message: relayed,
                destination: orig_dest,
            };
        }

        // 2xx: re-anchor the answer toward the originator.
        let SipMessage::Response(ok) = &mut relayed else {
            unreachable!("build_reinvite_response builds a response")
        };
        relay_session_timer_response_headers(&resp.headers, &mut ok.headers);
        ok.headers
            .set(HeaderName::Contact, format!("<sip:{}>", addrs.local_addr));
        let mut answer_sdp = None;
        if let Some(body) = resp.body.as_ref().filter(|b| !b.is_empty()) {
            let sdp_str = String::from_utf8_lossy(body);
            let session_key = internal_id.to_string();
            if let Some(ref pipeline) = self.media_pipeline
                && let Some(media) = extract_media_address(&sdp_str)
                && let Some(addr) = admitted_media_addr(&media)
            {
                let _ = pipeline
                    .set_remote_address(&session_key, !pending.from_a_leg, addr)
                    .await;
            }
            let local_media = if pending.from_a_leg {
                MediaAddress::new(&addrs.media_a_leg_ip, a_leg_media_port(addrs))
            } else {
                MediaAddress::new(&addrs.media_b_leg_ip, addrs.media_b_leg_port)
            };
            let mut answer = self
                .sdp_rewriter
                .rewrite_answer_for_a_leg(&sdp_str, &local_media)
                .rewritten;
            if let Some(fp) = &self.dtls_fingerprint_source {
                let role = pending.offer_setup.map_or(
                    crate::sdp_dtls::SetupRole::Passive,
                    crate::sdp_dtls::SetupRole::answer_role,
                );
                answer = crate::sdp_dtls::rewrite_local_dtls(&answer, &fp.current(), role);
            }
            let answer = Bytes::from(answer);
            ok.headers.set(HeaderName::ContentType, "application/sdp");
            ok.headers
                .set(HeaderName::ContentLength, answer.len().to_string());
            ok.body = Some(answer.clone());
            answer_sdp = Some(answer);
        }

        let mut results = vec![ProcessResult::Response {
            message: relayed.clone(),
            destination: orig_dest,
        }];
        let mut ack_record = None;
        if pending.method == Method::Invite {
            // ACK the far leg's 2xx (same CSeq number as the re-INVITE) and
            // keep it for the far leg's retransmissions; retransmit our own
            // 2xx to the originator until it ACKs.
            let ack = Self::build_leg_in_dialog_request(
                addrs,
                pending.from_a_leg,
                &Method::Ack,
                pending.fwd_cseq,
                None,
            );
            let ack_dest = if pending.from_a_leg {
                addrs.b_leg_destination
            } else {
                addrs.a_leg_source
            };
            let ack = SipMessage::Request(ack);
            ack_record = Some((pending.fwd_branch.clone(), ack.clone(), ack_dest));
            results.push(ProcessResult::Forward {
                message: ack,
                destination: ack_dest,
            });
            let orig_call_id = if pending.from_a_leg {
                &addrs.a_leg_sip_call_id
            } else {
                &addrs.b_leg_sip_call_id
            };
            self.arm_2xx_retransmit(
                orig_call_id,
                internal_id,
                &relayed,
                orig_dest,
                cseq_number(&pending.orig_cseq),
            )
            .await;
        }
        {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(internal_id) {
                if let Some(sdp) = answer_sdp {
                    if pending.from_a_leg {
                        a.a_leg_last_sdp = Some(sdp);
                    } else {
                        a.b_leg_last_sdp = Some(sdp);
                    }
                }
                if ack_record.is_some() {
                    a.last_reinvite_ack = ack_record;
                }
            }
        }

        info!(
            call_id = %addrs.a_leg_sip_call_id,
            method = %pending.method,
            from_a_leg = pending.from_a_leg,
            "Session change completed across both legs"
        );
        ProcessResult::Multiple(results)
    }

    /// Builds the response toward the originator of a relayed re-INVITE/UPDATE,
    /// carrying its own Via stack, From, To, Call-ID and CSeq (the far leg's
    /// headers belong to the other dialog). Returns it with its destination.
    fn build_reinvite_response(
        status: StatusCode,
        pending: &PendingReinvite,
        addrs: &CallAddresses,
    ) -> (SipMessage, SbcSocketAddr) {
        let mut r = SipResponse::new(status);
        for via in &pending.orig_via {
            r.headers.add(Header::new(HeaderName::Via, via));
        }
        r.headers.set(HeaderName::From, &pending.orig_from);
        r.headers.set(HeaderName::To, &pending.orig_to);
        let (call_id, dest) = if pending.from_a_leg {
            (&addrs.a_leg_sip_call_id, addrs.a_leg_source)
        } else {
            (&addrs.b_leg_sip_call_id, addrs.b_leg_destination)
        };
        r.headers.set(HeaderName::CallId, call_id);
        r.headers.set(HeaderName::CSeq, &pending.orig_cseq);
        r.headers.set(HeaderName::ContentLength, "0");
        (SipMessage::Response(r), dest)
    }

    /// Removes all state for a call the SBC is tearing down (dialog correlation,
    /// call record, INVITE transactions, RTP ports, media session).
    async fn cleanup_terminated_call(&self, internal_id: &CallId, addrs: &CallAddresses) {
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
        // INVITE transactions are left to run out (Timer D/H/I) so late
        // retransmissions are still absorbed; `poll_timers` prunes them.
        self.pending_2xx
            .write()
            .await
            .retain(|_, p| &p.call != internal_id);
        for port in &addrs.rtp_ports {
            self.release_rtp_port(*port);
        }
        if let Some(ref pipeline) = self.media_pipeline {
            let key = internal_id.to_string();
            let _ = pipeline.stop_relay(&key).await;
            let _ = pipeline.remove_session(&key).await;
        }
    }

    /// Tears down a call whose DTLS-SRTP media handshake failed at runtime (after
    /// the 200 OK): the SBC initiated the teardown, so it BYEs **both** legs
    /// (neither peer sends one). Returns the serialized BYEs paired with their
    /// destinations for the caller to send; the call state is removed here.
    /// Empty if the call is already gone or the dialog never confirmed.
    pub async fn terminate_call_on_media_failure(
        &self,
        call_id: &str,
    ) -> Vec<(bytes::Bytes, SbcSocketAddr)> {
        let internal_id = CallId::from(call_id);
        let addrs = {
            let corr = self.call_correlation.read().await;
            match corr.addresses.get(&internal_id) {
                Some(a) => a.clone(),
                None => return Vec::new(),
            }
        };

        // A clean BYE needs the confirmed dialog's remote tag. Media only starts
        // after the 200 OK (which learns it), so this normally holds; if it does
        // not, tear the state down without emitting an invalid BYE.
        if addrs.dialog_to_tag.is_none() {
            warn!(
                call_id,
                "media failure before dialog confirmed; cleaning up without BYE"
            );
            self.cleanup_terminated_call(&internal_id, &addrs).await;
            return Vec::new();
        }

        let a_bye = Self::build_leg_bye(&addrs, false);
        let b_bye = Self::build_leg_bye(&addrs, true);
        self.cleanup_terminated_call(&internal_id, &addrs).await;

        warn!(
            call_id,
            "DTLS-SRTP media failed after answer; tearing down call (BYE both legs)"
        );
        audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Failed);

        vec![
            (SipMessage::Request(a_bye).to_bytes(), addrs.a_leg_source),
            (
                SipMessage::Request(b_bye).to_bytes(),
                addrs.b_leg_destination,
            ),
        ]
    }

    /// Enables RFC 8898 Bearer-token REGISTER authorization. When set,
    /// `handle_register` validates the OIDC access token and binds the `dn`
    /// claim to the AOR before accepting the registration.
    pub fn set_bearer_authenticator(&mut self, bearer: Arc<BearerAuthenticator>) {
        self.bearer = Some(bearer);
    }

    /// Whether REGISTER requests are authenticated at all (bearer token or
    /// digest). When false, any peer can bind any address-of-record.
    pub fn register_auth_enabled(&self) -> bool {
        self.bearer.is_some() || self.config.require_auth
    }

    /// Enables per-user request limiting (`rate_limit.per_user_rps`).
    pub fn set_user_rate_limiter(&mut self, limiter: uc_dos_protection::KeyedRateLimiter) {
        self.user_limiter = Some(tokio::sync::Mutex::new(limiter));
    }

    /// Applies the per-user limiter to a request: `Some(503)` when the From
    /// user is over its rate (RFC 3261 §21.5.4 with `Retry-After`), `None`
    /// to proceed. ACK is never limited (it completes a transaction already
    /// admitted). Requests without a From user are not keyed.
    async fn user_rate_limit(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
    ) -> Option<ProcessResult> {
        let limiter = self.user_limiter.as_ref()?;
        if req.method == Method::Ack {
            return None;
        }
        let user = req.headers.from_parsed().and_then(|f| f.uri.user)?;
        let (action, threshold) = {
            let mut l = limiter.lock().await;
            (l.check(&user), l.rps())
        };
        if action.is_allowed() {
            return None;
        }
        warn!(%user, source = %source, method = %req.method, "Per-user rate limit exceeded, 503");
        uc_audit::log_event(uc_audit::AuditEvent::RateLimitTriggered(
            uc_audit::event::RateLimitTriggered {
                source_ip: source.ip(),
                limit_name: format!("per_user_rps:{user}"),
                request_count: u64::from(threshold),
                threshold: u64::from(threshold),
            },
        ));
        let mut response = create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
        response.headers.set(HeaderName::RetryAfter, "1");
        Some(ProcessResult::Response {
            message: SipMessage::Response(response),
            destination: source,
        })
    }

    /// Sets the Voice Protection System engine for call screening.
    pub fn set_vps_engine(&mut self, engine: uc_vps::VpsEngine) {
        self.vps = Some(tokio::sync::Mutex::new(engine));
    }

    /// Enters draining mode: new INVITEs are rejected with 503 while
    /// existing dialogs continue (graceful shutdown).
    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    /// Number of active B2BUA calls (drain progress).
    pub async fn active_call_count(&self) -> usize {
        self.calls.read().await.calls.len()
    }

    /// Sets the zone registry for zone-aware SIP processing.
    pub fn set_zone_registry(&mut self, registry: Arc<crate::zone::ResolvedZoneRegistry>) {
        self.zone_registry = Some(registry);
    }

    /// The host and port the SBC advertises as itself (Via sent-by and
    /// Contact) on an outbound leg: the egress zone's external IP when it has
    /// one, else that zone's signaling IP, else the configured domain. The
    /// port is the standard SIP port; the zone registry carries no port.
    fn b_leg_signaling_addr(&self, ingress: Option<&str>, b_leg_external: bool) -> (String, u16) {
        const SIP_PORT: u16 = 5060;
        let host = self.zone_registry.as_ref().and_then(|reg| {
            let zone = self
                .egress_media_zone(ingress, b_leg_external)
                .or_else(|| reg.zone_names().into_iter().next())?;
            reg.external_ip(&zone)
                .or_else(|| reg.signaling_ip(&zone))
                .map(|ip| ip.to_string())
        });
        (host.unwrap_or_else(|| self.config.domain.clone()), SIP_PORT)
    }

    /// Returns the effective signaling IP for a zone, falling back to source IP.
    fn zone_signaling_ip(&self, zone: Option<&str>, fallback: std::net::IpAddr) -> String {
        if let (Some(name), Some(reg)) = (zone, &self.zone_registry) {
            reg.signaling_ip(name)
                .map_or_else(|| fallback.to_string(), |ip| ip.to_string())
        } else {
            fallback.to_string()
        }
    }

    /// Returns the effective media IP for a zone, falling back to source IP.
    fn zone_media_ip(&self, zone: Option<&str>, fallback: std::net::IpAddr) -> String {
        if let (Some(name), Some(reg)) = (zone, &self.zone_registry) {
            reg.media_ip(name)
                .map_or_else(|| fallback.to_string(), |ip| ip.to_string())
        } else {
            fallback.to_string()
        }
    }

    /// Resolves the SBC's own media IP for one leg of a call — the address to
    /// bind that leg's RTP relay socket to AND advertise in its rewritten SDP.
    /// Endpoints send RTP straight to this address, so it MUST be SBC-owned: the
    /// peer's source IP is only correct for signaling (where the Via `received=`
    /// param repairs response routing), never for media.
    ///
    /// Prefers the named `zone`'s media interface (so the caller-facing leg
    /// advertises the ingress zone and the trunk-facing leg advertises the
    /// egress zone); falls back to the first configured zone, then to `fallback`
    /// (relay binds `0.0.0.0`) when no zone media IP is available. Returns
    /// `(bind_ip, advertise_string)`.
    fn zone_media_bind(
        &self,
        zone: Option<&str>,
        fallback: std::net::IpAddr,
    ) -> (Option<std::net::IpAddr>, String) {
        if let Some(reg) = &self.zone_registry {
            if let Some(name) = zone
                && let Some(ip) = reg.media_ip(name)
            {
                return (Some(ip), ip.to_string());
            }
            for name in reg.zone_names() {
                if let Some(ip) = reg.media_ip(&name) {
                    return (Some(ip), ip.to_string());
                }
            }
        }
        (None, fallback.to_string())
    }

    /// Picks the zone whose media interface faces the **callee** (B-leg). On an
    /// outbound leg that crosses to a trunk/carrier (`b_leg_external`), that is
    /// the carrier-facing zone (the one with an external IP configured) so the
    /// SBC advertises its outside media address to the carrier; otherwise the
    /// call stays inside and the callee is reached from the same (ingress) zone
    /// as the caller. Falls back to the ingress zone when no external-facing
    /// zone is configured.
    fn egress_media_zone(&self, ingress: Option<&str>, b_leg_external: bool) -> Option<String> {
        if b_leg_external {
            self.zone_registry
                .as_ref()
                .and_then(|reg| reg.external_facing_zone())
                .or_else(|| ingress.map(String::from))
        } else {
            ingress.map(String::from)
        }
    }

    /// Sets the SBC router for CSS/Partition-based call routing.
    pub fn set_sbc_router(&mut self, router: Arc<RwLock<uc_routing::SbcRouter>>) {
        self.sbc_router = Some(router);
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

            let mut group = TrunkGroup::new(&tg_config.id, &tg_config.name).with_strategy(strategy);

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

            // Config-file trunks are admitted INVITE sources too (the API
            // path does this in register_inbound_trunk). No CSS for these.
            let map = self.inbound_trunk_map.get_mut();
            for t_config in &tg_config.trunks {
                for ip in resolve_trunk_host_ips(&t_config.host) {
                    map.insert(ip, (tg_config.id.clone(), None));
                }
            }
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
                    "add_prefix" => NumberTransform::add_prefix(&entry_config.transform_value),
                    "replace_prefix" => {
                        let parts: Vec<&str> =
                            entry_config.transform_value.splitn(2, '|').collect();
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
    pub fn init_manipulator_from_config(&mut self, config: &sbc_config::HeaderManipulationConfig) {
        let mut manipulator = HeaderManipulator::new();

        for rule_config in &config.global_rules {
            let direction = match rule_config.direction.as_str() {
                "inbound" => Some(ManipulationDirection::Inbound),
                "outbound" => Some(ManipulationDirection::Outbound),
                _ => None, // "both" or default
            };

            let action = parse_manipulation_action(
                &rule_config.action,
                &rule_config.header,
                &rule_config.value,
            );

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
            let action = parse_manipulation_action(
                &rule_config.action,
                &rule_config.header,
                &rule_config.value,
            );
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
    pub fn init_topology_hider_from_config(&mut self, config: &sbc_config::TopologyHidingConfig) {
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
    pub async fn process_message(
        &self,
        data: &Bytes,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
    ) -> ProcessResult {
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

        let result = match message {
            SipMessage::Request(_) => self.process_request(message, source, receiving_zone).await,
            SipMessage::Response(_) => self.process_response(message, source).await,
        };
        // Everything a handler puts on the wire rides a transaction: responses
        // are recorded for retransmission, forwarded requests get a client
        // transaction that retransmits and times them out (RFC 3261 §17).
        self.track_result(&result).await;
        result
    }

    /// Processes a SIP request. `receiving_zone` is the zone the request arrived
    /// on (used by INVITE to pick the caller-facing media interface).
    async fn process_request(
        &self,
        message: SipMessage,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
    ) -> ProcessResult {
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

        // Transaction layer (RFC 3261 §17.2): a retransmitted request is
        // answered from its server transaction, never re-processed. ACK has
        // no server transaction of its own.
        if method != Method::Ack {
            if let Some(answer) = self.answer_request_retransmit(req, source).await {
                return answer;
            }
            if let Some(rejected) = self.user_rate_limit(req, source).await {
                return rejected;
            }
            self.open_server_transaction(req, source).await;
        }

        match method {
            Method::Register => self.handle_register(message, source).await,
            Method::Invite => self.handle_invite(message, source, receiving_zone).await,
            Method::Ack => self.handle_ack(message).await,
            Method::Bye => self.handle_bye(message, source).await,
            Method::Cancel => self.handle_cancel(message, source).await,
            Method::Options => self.handle_options(message, source).await,
            Method::Update => self.handle_update(message, source).await,
            _ => self.handle_other_request(message, source).await,
        }
    }

    /// Processes a SIP response.
    ///
    /// The response is first matched to the client transaction that sent the
    /// request (RFC 3261 §17.1.3: top Via branch + CSeq method). The
    /// transaction absorbs retransmitted finals and ACKs non-2xx INVITE
    /// finals (§17.1.1.3). What passes is handed to the B2BUA: the initial
    /// INVITE's responses are relayed to the A-leg; responses to a relayed
    /// re-INVITE/UPDATE go back to whichever leg originated it.
    async fn process_response(&self, message: SipMessage, source: SbcSocketAddr) -> ProcessResult {
        let SipMessage::Response(ref resp) = message else {
            return ProcessResult::Error {
                reason: "Expected response".to_string(),
            };
        };

        let status_code = resp.status.code();
        let sip_call_id = resp.headers.call_id().unwrap_or("").to_string();

        debug!(
            status = status_code,
            call_id = %sip_call_id,
            source = %source,
            "Received SIP response"
        );

        let Some(branch) = resp.headers.via_branch() else {
            debug!(call_id = %sip_call_id, "Response without Via branch, ignoring");
            return ProcessResult::NoAction;
        };
        let Some(cseq) = resp.headers.cseq_parsed() else {
            debug!(call_id = %sip_call_id, "Response without CSeq, ignoring");
            return ProcessResult::NoAction;
        };

        // 1. Transaction layer. Matching on Call-ID alone would let anyone who
        //    learned a Call-ID inject a forged 200 OK; the branch must match a
        //    request this SBC actually sent.
        let mut ack_action = None;
        {
            let mut txns = self.transactions.write().await;
            let key = TransactionKey::client(&branch, cseq.method.to_string());
            if cseq.method == Method::Invite {
                match txns.client_invite.get_mut(&key) {
                    Some(st) => {
                        let passed = st
                            .transaction
                            .receive_response(status_code)
                            .unwrap_or(false);
                        if status_code >= 300 {
                            // ACK every non-2xx final, and again for each
                            // retransmission of it (§17.1.1.3).
                            let SipMessage::Request(ref invite) = st.request else {
                                unreachable!("client INVITE transaction stores a request")
                            };
                            let ack = st
                                .ack
                                .get_or_insert_with(|| Self::build_non2xx_ack(invite, resp))
                                .clone();
                            ack_action = Some(ProcessResult::Forward {
                                message: ack,
                                destination: st.destination,
                            });
                        }
                        // 2xx always reaches the TU: their retransmissions
                        // are the dialog layer's to re-ACK (§13.2.2.4).
                        if !passed && !(200..300).contains(&status_code) {
                            debug!(call_id = %sip_call_id, status = status_code, "Retransmitted final response absorbed");
                            return ack_action.unwrap_or(ProcessResult::NoAction);
                        }
                    }
                    None if (200..300).contains(&status_code) => {
                        // Transaction already gone (2xx terminates it): a
                        // late 200 retransmission, handled by the TU below.
                    }
                    None => {
                        debug!(call_id = %sip_call_id, branch = %branch, "Response matches no client INVITE transaction, ignoring");
                        return ProcessResult::NoAction;
                    }
                }
            } else {
                let Some(st) = txns.client_non_invite.get_mut(&key) else {
                    debug!(call_id = %sip_call_id, method = %cseq.method, "Response matches no client transaction, ignoring");
                    return ProcessResult::NoAction;
                };
                if !st
                    .transaction
                    .receive_response(status_code)
                    .unwrap_or(false)
                {
                    return ProcessResult::NoAction;
                }
            }
        }

        // 2. Transaction user: find the call this leg belongs to.
        let corr = self.call_correlation.read().await;
        let (internal_id, is_b_leg) = if let Some(id) = corr.b_leg.get(&sip_call_id) {
            (id.clone(), true)
        } else if let Some(id) = corr.a_leg.get(&sip_call_id) {
            (id.clone(), false)
        } else {
            debug!(call_id = %sip_call_id, "Response for unknown dialog (e.g. 200 to our BYE)");
            drop(corr);
            return ack_action.unwrap_or(ProcessResult::NoAction);
        };
        let Some(a) = corr.addresses.get(&internal_id) else {
            warn!(call_id = %sip_call_id, "No addresses for call");
            drop(corr);
            return ack_action.unwrap_or(ProcessResult::NoAction);
        };
        let mut addrs = a.clone();
        drop(corr);

        // 2a. Response to a relayed mid-dialog re-INVITE/UPDATE.
        if let Some(pending) = addrs
            .pending_reinvite
            .clone()
            .filter(|p| p.fwd_branch == branch)
        {
            let tu = self
                .handle_reinvite_response(resp, &internal_id, &addrs, &pending)
                .await;
            return match ack_action {
                Some(ack) => ProcessResult::Multiple(vec![ack, tu]),
                None => tu,
            };
        }

        // 2b. Retransmitted 2xx to a relayed re-INVITE: re-ACK it (§13.2.2.4).
        if cseq.method == Method::Invite
            && (200..300).contains(&status_code)
            && let Some((ack_branch, ack, dest)) = addrs.last_reinvite_ack.as_ref()
            && *ack_branch == branch
        {
            return ProcessResult::Forward {
                message: ack.clone(),
                destination: *dest,
            };
        }

        // 2c. Anything else must be a response to the initial B-leg INVITE.
        if !is_b_leg || cseq.method != Method::Invite || branch != addrs.b_leg_branch {
            debug!(call_id = %sip_call_id, "Response not for the initial INVITE, ignoring");
            return ack_action.unwrap_or(ProcessResult::NoAction);
        }

        // Learn the remote (callee) tag from the first tagged response —
        // it completes the dialog identity used by in-dialog BYE/ACK.
        if addrs.dialog_to_tag.is_none()
            && let Some(tag) = resp
                .headers
                .get_value(&HeaderName::To)
                .and_then(|to| extract_param(to, "tag"))
                .map(String::from)
        {
            addrs.dialog_to_tag = Some(tag.clone());
            let mut corr = self.call_correlation.write().await;
            if let Some(entry) = corr.addresses.get_mut(&internal_id) {
                entry.dialog_to_tag = Some(tag);
            }
        }

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

        // 4xx/5xx/6xx error — forward to A-leg (the ACK toward the B-leg was
        // produced by the transaction layer above), cleanup
        let tu = self
            .handle_error_response(resp, status_code, &internal_id, &addrs)
            .await;
        match ack_action {
            Some(ack) => ProcessResult::Multiple(vec![ack, tu]),
            None => tu,
        }
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

        // Build provisional response for A-leg with the A-leg dialog's
        // own Via/From/To/CSeq.
        let mut a_response = build_a_leg_response(resp.status, addrs);

        // If 183 with SDP, rewrite SDP for A-leg (early media / ringback)
        if status_code == 183
            && let Some(ref body) = resp.body
        {
            let sdp_str = String::from_utf8_lossy(body);
            // Advertise the relay's caller-facing port (allocated at INVITE) when
            // anchored, so the early-media answer matches the eventual 200. The
            // relay itself starts on the 200 OK. Bare-port fallback otherwise.
            let rtp_port = if let Some(a_port) = addrs.media_a_leg_port {
                a_port
            } else {
                let p = self.allocate_rtp_port();
                let mut corr = self.call_correlation.write().await;
                if let Some(a) = corr.addresses.get_mut(internal_id) {
                    a.rtp_ports.push(p);
                }
                p
            };
            let local_media = MediaAddress::new(&addrs.media_a_leg_ip, rtp_port);
            let result = self
                .sdp_rewriter
                .rewrite_answer_for_a_leg(&sdp_str, &local_media);
            let rewritten = Bytes::from(self.rewrite_answer_dtls(result.rewritten, addrs));
            // build_a_leg_response set Content-Length: 0; correct it to
            // the attached body length or the A-leg UA truncates the SDP
            // and the caller gets no early media.
            a_response
                .headers
                .set(HeaderName::ContentLength, rewritten.len().to_string());
            a_response.body = Some(rewritten);
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
        // A retransmitted 200 (our ACK was lost): re-ACK only (RFC 3261
        // §13.2.2.4). The A-leg 200 is retransmitted by the 2xx timer, and
        // the media relay must not be started twice.
        if addrs.b_leg_answered {
            debug!(call_id = %addrs.a_leg_sip_call_id, "Retransmitted 200 OK from B-leg, re-sending ACK");
            let ack = Self::build_leg_in_dialog_request(addrs, true, &Method::Ack, 1, None);
            return ProcessResult::Forward {
                message: SipMessage::Request(ack),
                destination: addrs.b_leg_destination,
            };
        }

        // Activate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.calls.get_mut(internal_id) {
                let _ = call.activate();
            }
        }

        // Build 200 OK for A-leg with rewritten SDP, carrying the A-leg
        // dialog's own Via/From/To/CSeq.
        let mut a_response = build_a_leg_response(StatusCode::OK, addrs);
        // RFC 4028: the session-timer outcome the callee negotiated travels
        // back to the caller, who may become the refresher.
        relay_session_timer_response_headers(&resp.headers, &mut a_response.headers);

        // Rewrite the A-leg answer SDP and, when a relay anchored this call,
        // learn the callee's remote from the answer and start forwarding RTP in
        // both directions. The advertised A-leg port is the relay's
        // caller-facing port allocated at INVITE time.
        if let Some(ref body) = resp.body {
            let sdp_str = String::from_utf8_lossy(body);
            let rtp_port = if let (Some(pipeline), Some(a_port)) =
                (&self.media_pipeline, addrs.media_a_leg_port)
            {
                let session_key = internal_id.to_string();
                if let Some(callee_media) = extract_media_address(&sdp_str)
                    && let Some(callee_addr) = admitted_media_addr(&callee_media)
                {
                    let _ = pipeline
                        .set_remote_address(&session_key, false, callee_addr)
                        .await;
                }
                self.start_media_relay(&**pipeline, &session_key, addrs, &sdp_str)
                    .await;
                a_port
            } else {
                // No relay attached: bare port (SDP rewritten, media not relayed).
                let p = self.allocate_rtp_port();
                let mut corr = self.call_correlation.write().await;
                if let Some(a) = corr.addresses.get_mut(internal_id) {
                    a.rtp_ports.push(p);
                }
                p
            };
            let local_media = MediaAddress::new(&addrs.media_a_leg_ip, rtp_port);
            let result = self
                .sdp_rewriter
                .rewrite_answer_for_a_leg(&sdp_str, &local_media);
            a_response.body = Some(Bytes::from(
                self.rewrite_answer_dtls(result.rewritten, addrs),
            ));
            a_response
                .headers
                .set(HeaderName::ContentType, "application/sdp");
            if let Some(ref body) = a_response.body {
                a_response
                    .headers
                    .set(HeaderName::ContentLength, body.len().to_string());
            }
        }

        // Remember the answer for body-less refreshes, and that the B-leg
        // has answered (later 2xx are retransmissions).
        {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(internal_id) {
                a.b_leg_answered = true;
                a.a_leg_last_sdp.clone_from(&a_response.body);
                a.established_at = Some(Instant::now());
            }
        }
        audit(uc_audit::AuditEvent::CallEstablished(
            uc_audit::event::CallEstablished {
                call_id: uc_types::identifier::CallId::new(addrs.a_leg_sip_call_id.clone()),
                established_at: chrono::Utc::now(),
            },
        ));

        // Build ACK for B-leg. The ACK belongs to the B-leg dialog: it
        // must carry the INVITE's From (our tag), the To with the callee's
        // tag, and the INVITE's CSeq number with method ACK (RFC 3261
        // §13.2.2.4). The previous bare ACK (Call-ID + "1 ACK" only) was
        // unmatchable, so far ends kept retransmitting their 200 OK.
        let b_leg_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut ack_request = proto_sip::message::SipRequest::new(Method::Ack, b_leg_uri);
        ack_request
            .headers
            .set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        ack_request.headers.set(HeaderName::CSeq, "1 ACK");
        ack_request.headers.set(HeaderName::From, &addrs.b_leg_from);
        ack_request.headers.set(
            HeaderName::To,
            resp.headers.get_value(&HeaderName::To).map_or_else(
                || with_tag(&addrs.b_leg_to, addrs.dialog_to_tag.as_deref()),
                String::from,
            ),
        );
        ack_request.headers.set(HeaderName::MaxForwards, "70");
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

        // The 200 toward the caller is retransmitted until ACKed (§13.3.1.4).
        let a_message = SipMessage::Response(a_response);
        self.arm_2xx_retransmit(
            &addrs.a_leg_sip_call_id,
            internal_id,
            &a_message,
            addrs.a_leg_source,
            cseq_number(&addrs.a_leg_cseq),
        )
        .await;

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: a_message,
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
                    addrs
                        .failover_trunks
                        .first()
                        .map_or("default", |t| t.as_str()),
                )
                .and_then(|_| resolve_sip_uri_to_addr(&format!("sip:{next_trunk_id}")));
            drop(router);

            if let Some(new_dest) = trunk_addr {
                let new_call_id = generate_call_id(&self.config.domain);
                let local_ip = addrs.local_addr.split(':').next().unwrap_or("0.0.0.0");

                let new_uri = SipUri::new(new_dest.ip().to_string()).with_port(new_dest.port());
                let builder = RequestBuilder::invite(new_uri)
                    .via_auto("UDP", local_ip, Some(new_dest.port()))
                    .call_id(&new_call_id)
                    .cseq(1)
                    .max_forwards(70);

                if let Ok(new_request) = builder.build_with_defaults() {
                    // The retry INVITE carries a fresh Via branch and From
                    // tag generated by the builder; capture them so the
                    // stored dialog state matches what went on the wire.
                    // Without this, process_response's branch validation
                    // (it matches the top Via branch against b_leg_branch)
                    // would silently drop every response to the failover
                    // INVITE, and a CANCEL would mirror the stale branch.
                    let new_branch = new_request
                        .headers
                        .get_value(&HeaderName::Via)
                        .and_then(|v| extract_param(v, "branch").map(String::from))
                        .unwrap_or_else(generate_branch);
                    let new_from = new_request
                        .headers
                        .get_value(&HeaderName::From)
                        .unwrap_or_default()
                        .to_string();
                    let new_to = new_request
                        .headers
                        .get_value(&HeaderName::To)
                        .unwrap_or_default()
                        .to_string();
                    {
                        let mut corr = self.call_correlation.write().await;
                        corr.b_leg.remove(&addrs.b_leg_sip_call_id);
                        corr.b_leg.insert(new_call_id.clone(), internal_id.clone());
                        if let Some(addr_entry) = corr.addresses.get_mut(internal_id) {
                            addr_entry.b_leg_destination = new_dest;
                            addr_entry.b_leg_sip_call_id.clone_from(&new_call_id);
                            addr_entry.failover_trunks = remaining;
                            addr_entry.b_leg_branch = new_branch;
                            addr_entry.b_leg_from = new_from;
                            addr_entry.b_leg_to = new_to;
                            // New transaction: a tagged response will be
                            // re-learned for the dialog.
                            addr_entry.dialog_to_tag = None;
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

        // Build error response for A-leg with the A-leg dialog's headers
        let a_response = build_a_leg_response(resp.status, addrs);

        // Release any media resources allocated for this call — the BYE/
        // CANCEL paths do this, but the error path leaked relay tasks and
        // their bound ports.
        if let Some(ref pipeline) = self.media_pipeline {
            let call_id_str = internal_id.to_string();
            let _ = pipeline.stop_relay(&call_id_str).await;
            let _ = pipeline.remove_session(&call_id_str).await;
        }

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
        // Release allocated RTP ports (C12).
        for port in &addrs.rtp_ports {
            self.release_rtp_port(*port);
        }

        warn!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Call failed, forwarding error to A-leg"
        );
        audit_call_terminated(addrs, uc_audit::event::TerminationReason::Rejected);

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

        // RFC 8898 Bearer-token authorization (when enabled). Validate the
        // OIDC access token and bind its `dn` claim to the AOR *before* any
        // binding work. Digest auth (if configured) still runs in the
        // registrar below; bearer is an alternative, not a replacement.
        if let Some(bearer) = &self.bearer {
            let auth_hdr = req.headers.get_value(&HeaderName::Authorization);
            let aor_user = aor_user_part(&aor);
            match bearer.authorize(auth_hdr, aor_user).await {
                BearerResult::Authorized { dn, .. } => {
                    debug!(%dn, aor = %aor, "REGISTER bearer-authorized (RFC 8898)");
                    audit_register_auth(&aor, source, uc_audit::event::AuthMethod::Jwt, None);
                }
                BearerResult::Challenge { error } => {
                    // A challenge to a request that carried credentials is a
                    // failed attempt; without credentials it is just the
                    // initial challenge.
                    if auth_hdr.is_some() {
                        audit_register_auth(
                            &aor,
                            source,
                            uc_audit::event::AuthMethod::Jwt,
                            Some(format!("{error:?}")),
                        );
                    }
                    let mut response = create_response_from_request(req, StatusCode::UNAUTHORIZED);
                    response.add_header(Header::new(
                        HeaderName::WwwAuthenticate,
                        bearer.challenge_header(error),
                    ));
                    return ProcessResult::Response {
                        message: SipMessage::Response(response),
                        destination: source,
                    };
                }
                BearerResult::Forbidden { reason } => {
                    warn!(aor = %aor, %reason, "REGISTER bearer authorization denied");
                    audit_register_auth(
                        &aor,
                        source,
                        uc_audit::event::AuthMethod::Jwt,
                        Some(reason),
                    );
                    return ProcessResult::Response {
                        message: SipMessage::Response(create_response_from_request(
                            req,
                            StatusCode::FORBIDDEN,
                        )),
                        destination: source,
                    };
                }
            }
        }

        // Parse Contact headers into ContactInfo list, then latch any
        // unroutable contact host (an unspecified address such as "[::]"
        // from clients advertising their wildcard bind) to the request
        // source, so the stored binding is actually dialable.
        let mut contacts = parse_contacts_from_request(req);
        for contact in &mut contacts {
            latch_unspecified_contact(contact, &source);
        }

        // Parse Expires header
        let expires: Option<u32> = req
            .headers
            .get_value(&HeaderName::Expires)
            .and_then(|v| v.parse().ok());

        // Parse Call-ID and CSeq
        let call_id = req.headers.call_id().unwrap_or("unknown").to_string();
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
            RegisterRequest {
                expires: Some(exp),
                ..register_req
            }
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

        // Process through AuthenticatedRegistrar — hold the registrar
        // write lock through the location_service sync so both stores are
        // updated atomically (H5).
        let mut registrar_guard = self.registrar.write().await;
        let reg_response = match registrar_guard.process_register(&register_req) {
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
        };

        // Build SIP response from RegisterResponse
        let status =
            StatusCode::new(reg_response.status_code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR);
        let mut response = create_response_from_request(req, status);

        match reg_response.status_code {
            200 => {
                // Add Contact headers for all current bindings
                for contact_str in reg_response.format_contacts() {
                    response.add_header(Header::new(HeaderName::Contact, contact_str));
                }

                // Sync bindings to the shared location service from the
                // registrar's authoritative contact set. This honors
                // multi-device registration and de-registration
                // (Expires: 0 yields an empty set).
                //
                // NAT handling: a phone behind NAT advertises its own
                // (private, unroutable) address in Contact, so the binding
                // for the device that just registered is rewritten to the
                // packet source — its NAT pinhole — keyed by Call-ID. Other
                // devices' bindings (different Call-IDs) are left as the
                // registrar stored them; each was NAT-fixed to its own
                // source when it registered. Skipping this rewrite (the
                // regression) sent every inbound INVITE for a NAT'd phone to
                // its private address.
                let binding_count = reg_response.contacts.len();
                {
                    let mut loc = self.location_service.write().await;
                    let _ = loc.remove_all_bindings(&aor);
                    let src_ip = match source.ip() {
                        std::net::IpAddr::V6(v6) => v6
                            .to_ipv4_mapped()
                            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
                        std::net::IpAddr::V4(v4) => v4.to_string(),
                    };
                    let src_port = source.port();
                    let aor_user = aor
                        .split(':')
                        .nth(1)
                        .and_then(|s| s.split('@').next())
                        .unwrap_or("unknown");
                    // The pinhole is only reachable over the transport the
                    // REGISTER used — take it from the top Via
                    // ("SIP/2.0/TLS ..."), not a hardcoded udp.
                    let via_transport = req
                        .headers
                        .get_value(&HeaderName::Via)
                        .and_then(|v| {
                            v.split_whitespace()
                                .next()
                                .and_then(|proto| proto.rsplit('/').next())
                                .map(str::to_ascii_lowercase)
                        })
                        .unwrap_or_else(|| "udp".to_string());
                    for binding in &reg_response.contacts {
                        // The binding created/refreshed by *this* REGISTER
                        // (same Call-ID) is reachable via the source pinhole;
                        // also fix any wildcard host that can never be routed.
                        let is_this_device = binding.call_id() == call_id;
                        if is_this_device || binding.contact_uri().contains("0.0.0.0") {
                            // SipUri's display brackets IPv6 hosts.
                            let contact_uri = proto_sip::uri::SipUri::new(src_ip.clone())
                                .with_user(aor_user)
                                .with_port(src_port)
                                .with_param("transport", Some(via_transport.clone()))
                                .to_string();
                            let mut latched = proto_registrar::Binding::new(
                                &aor,
                                &contact_uri,
                                binding.call_id(),
                                binding.cseq(),
                            );
                            // Keep the negotiated expiry instead of resetting
                            // the binding to the default lifetime.
                            let _ = latched.set_expires(binding.remaining_seconds());
                            let _ = loc.add_binding(latched);
                        } else {
                            let _ = loc.add_binding(binding.clone());
                        }
                    }
                    // Update active count while holding the loc lock.
                    self.registrations_active
                        .store(loc.total_bindings() as u64, Ordering::Relaxed);
                }
                // Both registrar and location_service are now consistent;
                // release the registrar guard.
                drop(registrar_guard);

                self.registrations_total.fetch_add(1, Ordering::Relaxed);

                info!(
                    aor = %aor,
                    bindings = binding_count,
                    "Registration successful"
                );
                if self.config.require_auth {
                    audit_register_auth(&aor, source, uc_audit::event::AuthMethod::Digest, None);
                }
            }
            401 => {
                drop(registrar_guard);
                if req.headers.get_value(&HeaderName::Authorization).is_some() {
                    audit_register_auth(
                        &aor,
                        source,
                        uc_audit::event::AuthMethod::Digest,
                        Some("digest credentials rejected".to_string()),
                    );
                }
                // Add WWW-Authenticate challenge header
                if let Some(ref www_auth) = reg_response.www_authenticate {
                    response
                        .add_header(Header::new(HeaderName::WwwAuthenticate, www_auth.as_str()));
                }
                debug!(aor = %aor, "Registration challenged (401)");
            }
            423 => {
                drop(registrar_guard);
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
                drop(registrar_guard);
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
    async fn handle_invite(
        &self,
        message: SipMessage,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
    ) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let a_leg_call_id = req.headers.call_id().unwrap_or("unknown").to_string();

        debug!(uri = %req.uri, call_id = %a_leg_call_id, "Processing INVITE");

        // Mid-dialog INVITE (To carries a tag): a re-INVITE on an established
        // dialog (RFC 3261 §14), relayed to the other leg — or 481 when no
        // dialog matches (§12.2.2). Admission is the dialog match itself.
        if req.headers.to_tag().is_some() {
            return self.handle_in_dialog_request(req, source).await;
        }

        // Source admission: only configured trunks and currently registered
        // endpoints may place calls. Checked before any per-call state exists.
        //
        // ## NIST 800-53 Rev5: AC-3 (Access Enforcement)
        if !self.is_admitted_source(source.ip()).await {
            warn!(
                call_id = %a_leg_call_id,
                source = %source,
                "INVITE from a source that is neither a trunk nor registered, rejecting"
            );
            audit_invite_denied(req, source, "source-admission");
            let forbidden = create_response_from_request(req, StatusCode::FORBIDDEN);
            return ProcessResult::Response {
                message: SipMessage::Response(forbidden),
                destination: source,
            };
        }

        // Check for INVITE retransmit — if we already know this Call-ID,
        // or it is already being processed (in-flight), absorb it.
        {
            let corr = self.call_correlation.read().await;
            if corr.a_leg.contains_key(&a_leg_call_id) {
                debug!(call_id = %a_leg_call_id, "INVITE retransmit, absorbing");
                return ProcessResult::NoAction;
            }
        }
        if self
            .announcement_calls
            .read()
            .await
            .contains(&a_leg_call_id)
        {
            debug!(call_id = %a_leg_call_id, "INVITE retransmit (announcement), absorbing");
            return ProcessResult::NoAction;
        }
        // Mark this Call-ID as in-flight under a write lock so a second
        // copy arriving before the correlation insert is also absorbed
        // (TOCTOU fix — H4).
        {
            let mut in_flight = self.in_flight_invites.write().await;
            if !in_flight.insert(a_leg_call_id.clone()) {
                debug!(call_id = %a_leg_call_id, "INVITE retransmit (in-flight), absorbing");
                return ProcessResult::NoAction;
            }
        }

        // Draining (graceful shutdown): refuse new calls, let existing ones
        // finish.
        if self.draining.load(Ordering::Relaxed) {
            info!(call_id = %a_leg_call_id, "Draining — rejecting new INVITE");
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            let unavailable = create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
            return ProcessResult::Response {
                message: SipMessage::Response(unavailable),
                destination: source,
            };
        }

        // Admission control: reject new calls beyond the configured ceiling
        // (general.max_calls) instead of allocating unbounded state.
        //
        // ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
        {
            let calls = self.calls.read().await;
            if calls.calls.len() >= self.config.max_calls as usize {
                warn!(
                    call_id = %a_leg_call_id,
                    max_calls = self.config.max_calls,
                    "Maximum concurrent calls reached, rejecting INVITE"
                );
                drop(calls);
                self.in_flight_invites.write().await.remove(&a_leg_call_id);
                let unavailable =
                    create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
                return ProcessResult::Response {
                    message: SipMessage::Response(unavailable),
                    destination: source,
                };
            }
        }

        // Loop protection (RFC 3261 §16.3): honor the incoming Max-Forwards
        // and propagate it decremented — previously every hop reset it to
        // 70, so two SBCs could forward in a loop forever.
        let incoming_max_forwards: u8 = req
            .headers
            .get_value(&HeaderName::MaxForwards)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(70);
        if incoming_max_forwards == 0 {
            warn!(call_id = %a_leg_call_id, "Max-Forwards exhausted, rejecting INVITE");
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            let too_many_hops = create_response_from_request(
                req,
                StatusCode::new(483).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
            );
            return ProcessResult::Response {
                message: SipMessage::Response(too_many_hops),
                destination: source,
            };
        }
        let b_leg_max_forwards = incoming_max_forwards - 1;

        // 1. Build 100 Trying for A-leg
        let trying = create_response_from_request(req, StatusCode::TRYING);

        // 2. Extract destination from Request-URI
        let dest_user = req.uri.user.as_deref().unwrap_or("").to_string();
        let dest_host = req.uri.host.clone();
        let dest_aor = format!("sip:{dest_user}@{dest_host}");

        // Voice Protection System: pre-routing call screening (blocklist,
        // call-level rate limits, concurrency caps, policy rules). See
        // docs/VPS-ARCHITECTURE.md.
        //
        // ## NIST 800-53 Rev5: AC-3 (Access Enforcement), SC-5 (DoS Protection)
        if let Some(ref vps) = self.vps {
            let direction = if self
                .inbound_trunk_map
                .read()
                .await
                .contains_key(&source.ip())
            {
                uc_vps::CallDirection::Inbound
            } else {
                uc_vps::CallDirection::Unknown
            };
            let mut attempt = uc_vps::CallAttempt::new(source.ip())
                .with_callee(dest_user.clone())
                .with_request_uri(req.uri.to_string())
                .with_direction(direction);
            if let Some(from) = req.headers.get_value(&HeaderName::From) {
                attempt = attempt.with_from_uri(extract_uri_from_header(from));
            }
            let verdict = vps.lock().await.screen_call(&attempt);
            match verdict.action() {
                uc_vps::VpsAction::Allow => {}
                uc_vps::VpsAction::Reject {
                    status_code,
                    reason,
                } => {
                    warn!(
                        call_id = %a_leg_call_id,
                        status_code,
                        reason = %reason,
                        stage = ?verdict.source(),
                        rule = verdict.matched_rule().unwrap_or("-"),
                        "VPS rejected INVITE"
                    );
                    audit_invite_denied(
                        req,
                        source,
                        &format!("vps:{}", verdict.matched_rule().unwrap_or("rate-limit")),
                    );
                    self.in_flight_invites.write().await.remove(&a_leg_call_id);
                    let rejection = create_response_from_request(
                        req,
                        StatusCode::new(*status_code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
                    );
                    return ProcessResult::Response {
                        message: SipMessage::Response(rejection),
                        destination: source,
                    };
                }
                uc_vps::VpsAction::Drop => {
                    warn!(
                        call_id = %a_leg_call_id,
                        stage = ?verdict.source(),
                        "VPS dropped INVITE (blocked source)"
                    );
                    self.in_flight_invites.write().await.remove(&a_leg_call_id);
                    return ProcessResult::NoAction;
                }
            }
        }

        // 3. Look up destination:
        //    a) Check DID → user mapping, then LocationService
        //    b) Check LocationService directly for registered users
        //    c) Try SBC router (CSS/Partition)
        //    d) Try dial plan router
        //    e) Fall back to announcement
        let failover_trunks: Vec<String> = Vec::new();
        // Direction of the outbound leg: true when it crosses to an untrusted
        // (trunk/carrier) destination, false for a registered internal user.
        // Gates topology hiding so only outside-facing legs are anonymized
        // (rewriting an inside-facing leg's Via/Contact would misroute it).
        let mut b_leg_external = false;
        let b_leg_destination = {
            // Check DID → user mapping first (e.g., +12139160002 → jwillman)
            let mapped_user = self.lookup_did(&dest_user).await;

            // Build AOR candidates for location service lookup
            let loc = self.location_service.read().await;
            let mut found_contact = None;

            if let Some(ref user) = mapped_user {
                info!(did = %dest_user, user = %user, "DID mapped to registered user");
                // Try the mapped user with the dest host first, then with known zone IPs
                let candidates = [format!("sip:{user}@{dest_host}")];
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
                if found_contact.is_none()
                    && let Some(ref zr) = self.zone_registry
                {
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
                // Not registered — try SBC router (CSS-based), then dial plan, then direct
                let mut routed = None;

                // Identify which trunk group this inbound call came from (by source IP)
                // and get its assigned CSS for routing
                let source_ip = match source.ip() {
                    std::net::IpAddr::V6(v6) => v6
                        .to_ipv4_mapped()
                        .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
                    ip @ std::net::IpAddr::V4(_) => ip,
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

                // 1. Route via SBC router (CSS/Partition → Route Pattern → Route List → Route Group)
                if let Some(ref sbc) = self.sbc_router {
                    let sbc_r = sbc.read().await;
                    let css_ref = css_id_owned.as_deref();
                    if let Some(result) = sbc_r.route(&dest_user, css_ref) {
                        info!(
                            pattern = %result.pattern_id,
                            partition = %result.partition_id,
                            destination = %result.transformed_number,
                            css = ?css_ref,
                            "Routed via SBC CSS/Partition"
                        );
                        if let Some(rg_id) = result.route_group_ids.first() {
                            routed = resolve_sip_uri_to_addr(&format!("sip:{rg_id}"));
                        }
                    }
                }

                // 2. Route via dial plan → trunk group → trunk
                if routed.is_none() {
                    if let Some(ref router_lock) = self.router {
                        let mut dial_router = router_lock.write().await;
                        info!(dest = %dest_user, "Attempting dial plan routing");
                        match dial_router.route(&dest_user) {
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
                    self.in_flight_invites.write().await.remove(&a_leg_call_id);
                    return self
                        .play_announcement_to_caller(
                            req,
                            source,
                            crate::announcement::AnnouncementType::NumberNotInService,
                        )
                        .await;
                }

                // Routed to a trunk/carrier — this outbound leg faces an
                // untrusted zone, so topology hiding (if enabled) applies.
                b_leg_external = true;
                routed
            }
        };

        let Some(b_leg_destination) = b_leg_destination else {
            warn!(dest = %dest_aor, "Cannot resolve destination — playing announcement");
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            return self
                .play_announcement_to_caller(
                    req,
                    source,
                    crate::announcement::AnnouncementType::NumberNotInService,
                )
                .await;
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

        // 5. The SBC's own signaling address for the B-leg Via/Contact (and
        // for every later in-dialog request on that leg).
        let (local_ip, local_port) = self.b_leg_signaling_addr(receiving_zone, b_leg_external);
        let local_sip_addr = format!("{local_ip}:{local_port}");

        // 6. Media session + B-leg SDP rewrite. With the media pipeline present,
        // allocate the relay's A/B ports (backed by real sockets), advertise the
        // B-leg port to the callee, and set the A-leg (caller) remote from the
        // caller's offer so RTP forwards once the callee answers. Without a
        // pipeline, fall back to a bare port (SDP rewritten but no relay).
        let session_key = internal_call_id.to_string();
        // Advertise + bind the SBC's own media IP per leg (never the peer's
        // source IP, which is only valid for signaling). The caller-facing
        // (A-leg) socket uses the ingress zone's media interface; the
        // callee-facing (B-leg) socket uses the egress zone's — the carrier zone
        // on outbound trunk legs, else the same ingress zone. In a single-zone
        // deployment both collapse to that zone's media IP (unchanged behavior).
        let egress_zone = self.egress_media_zone(receiving_zone, b_leg_external);
        let (a_media_bind, mut a_media_ip_str) = self.zone_media_bind(receiving_zone, source.ip());
        let (b_media_bind, mut b_media_ip_str) =
            self.zone_media_bind(egress_zone.as_deref(), source.ip());
        let (b_leg_rtp_port, media_a_leg_port) = if let Some(ref pipeline) = self.media_pipeline {
            match pipeline
                .create_session_with_zones(&session_key, None, a_media_bind, b_media_bind)
                .await
            {
                Ok(ports) => {
                    // Phase 3 media steering: when the media node reports its own
                    // advertised IP (a standalone media-node pool), advertise THAT
                    // to both legs — the relay lives on the node, not here. Absent
                    // (monolith / co-located split), keep our zone media IP.
                    if let Some(node_ip) = ports.media_ip {
                        a_media_ip_str = node_ip.to_string();
                        b_media_ip_str.clone_from(&a_media_ip_str);
                    }
                    if let Some(ref body) = req.body
                        && let Some(caller_media) =
                            extract_media_address(&String::from_utf8_lossy(body))
                        && let Some(caller_addr) = admitted_media_addr(&caller_media)
                    {
                        let _ = pipeline
                            .set_remote_address(&session_key, true, caller_addr)
                            .await;
                    }
                    (ports.b_leg_rtp_port, Some(ports.a_leg_rtp_port))
                }
                Err(e) => {
                    warn!(error = %e, "media create_session failed; RTP relay disabled for this call");
                    (self.allocate_rtp_port(), None)
                }
            }
        } else {
            (self.allocate_rtp_port(), None)
        };
        // DTLS-SRTP termination (when `srtp.mode = terminate`, i.e.
        // `dtls_identity` is set): learn the caller's offered DTLS params (its
        // `a=setup` picks the SBC's answering role for the A-leg 183/200), and
        // on the B-leg offer advertise the SBC's own fingerprint with actpass
        // (the SBC is the offerer toward the callee). Otherwise SDP is untouched.
        let caller_dtls = req
            .body
            .as_ref()
            .and_then(|body| crate::sdp_dtls::parse_peer_dtls(&String::from_utf8_lossy(body)));
        let dtls_caller_setup = caller_dtls.as_ref().and_then(|d| d.setup);
        let dtls_caller_fingerprint = caller_dtls.map(|d| d.fingerprint);

        let b_leg_sdp = req.body.as_ref().map(|body| {
            let sdp_str = String::from_utf8_lossy(body);
            let local_media = MediaAddress::new(&b_media_ip_str, b_leg_rtp_port);
            let mut rewritten = self
                .sdp_rewriter
                .rewrite_offer_for_b_leg(&sdp_str, &local_media)
                .rewritten;
            if let Some(source) = &self.dtls_fingerprint_source {
                rewritten = crate::sdp_dtls::rewrite_local_dtls(
                    &rewritten,
                    &source.current(),
                    crate::sdp_dtls::SetupRole::ActPass,
                );
            }
            rewritten
        });

        // 7. Build B-leg INVITE
        let b_leg_sip_call_id = generate_call_id(&self.config.domain);
        let b_leg_branch = generate_branch();

        let mut b_leg_uri = SipUri::new(&dest_host).with_user(&dest_user);
        if let Some(port) = req.uri.port {
            b_leg_uri.port = Some(port);
        }

        let mut builder = RequestBuilder::invite(b_leg_uri)
            .via_auto("UDP", &local_ip, Some(local_port))
            .from_auto(
                SipUri::new(&self.config.domain).with_user(&self.config.instance_name),
                None,
            )
            .to_uri(SipUri::new(&dest_host).with_user(&dest_user), None)
            .call_id(&b_leg_sip_call_id)
            .cseq(1)
            .max_forwards(b_leg_max_forwards)
            .contact_uri(SipUri::new(&local_ip).with_port(local_port));

        if let Some(ref sdp) = b_leg_sdp {
            builder = builder.body_sdp(sdp.as_bytes().to_vec());
        }

        let mut b_leg_request = match builder.build_with_defaults() {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build B-leg INVITE");
                self.in_flight_invites.write().await.remove(&a_leg_call_id);
                self.release_rtp_port(b_leg_rtp_port);
                if let Some(ref pipeline) = self.media_pipeline {
                    let _ = pipeline.remove_session(&session_key).await;
                }
                let server_err =
                    create_response_from_request(req, StatusCode::SERVER_INTERNAL_ERROR);
                return ProcessResult::Response {
                    message: SipMessage::Response(server_err),
                    destination: source,
                };
            }
        };

        // RFC 4028 session timers negotiate end to end through the B2BUA:
        // carry the caller's timer support and Session-Expires/Min-SE so the
        // callee can pick the refresher; the SBC relays the refreshes.
        relay_session_timer_request_headers(&req.headers, &mut b_leg_request.headers);

        // 7b. Apply header manipulation to B-leg INVITE
        if let Some(ref manipulator) = self.header_manipulator {
            let context =
                ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
            if let Ok(count) = manipulator.apply(&mut b_leg_request.headers, &context)
                && count > 0
            {
                debug!(
                    rules_applied = count,
                    "Header manipulation applied to B-leg INVITE"
                );
            }
        }

        // 7c. Apply topology hiding to the B-leg INVITE when it faces an
        // untrusted (trunk/carrier) zone: anonymize the SBC's internal
        // signaling host in the Via/Contact so internal topology is not
        // disclosed to carriers. Opt-in via config (default disabled) and
        // scoped to outside-facing legs so inside routing is unaffected. The
        // B2BUA already emits a fresh per-leg Call-ID, so no Call-ID rewrite is
        // needed (and it must not change — it is the correlation key).
        if b_leg_external && let Some(ref hider) = self.topology_hider {
            hider
                .read()
                .await
                .hide_b2bua_request(&mut b_leg_request.headers);
        }

        // 8. Store call state and correlation
        {
            let mut calls = self.calls.write().await;
            calls.calls.insert(internal_call_id.clone(), call);
        }
        {
            let mut corr = self.call_correlation.write().await;
            corr.a_leg
                .insert(a_leg_call_id.clone(), internal_call_id.clone());
            corr.b_leg
                .insert(b_leg_sip_call_id.clone(), internal_call_id.clone());
            // Dialog state for in-dialog requests and forwarded responses:
            // both legs' From/To/Via/CSeq must be carried exactly, not
            // reconstructed (a BYE without dialog tags is unmatchable).
            let a_leg_via: Vec<String> = req
                .headers
                .get_all(&HeaderName::Via)
                .map(|h| h.value.clone())
                .collect();
            let a_leg_from = req
                .headers
                .get_value(&HeaderName::From)
                .unwrap_or_default()
                .to_string();
            let a_leg_to = req
                .headers
                .get_value(&HeaderName::To)
                .unwrap_or_default()
                .to_string();
            let a_leg_cseq = req.headers.cseq().unwrap_or("1 INVITE").to_string();
            let b_leg_from = b_leg_request
                .headers
                .get_value(&HeaderName::From)
                .unwrap_or_default()
                .to_string();
            let b_leg_to = b_leg_request
                .headers
                .get_value(&HeaderName::To)
                .unwrap_or_default()
                .to_string();
            // The transaction branch is the one actually on the wire (the
            // builder generates its own), so capture it from the built
            // request.
            let b_leg_wire_branch = b_leg_request
                .headers
                .get_value(&HeaderName::Via)
                .and_then(|v| extract_param(v, "branch").map(String::from))
                .unwrap_or_else(|| b_leg_branch.clone());
            corr.addresses.insert(
                internal_call_id.clone(),
                CallAddresses {
                    a_leg_source: source,
                    b_leg_destination,
                    a_leg_sip_call_id: a_leg_call_id.clone(),
                    b_leg_sip_call_id: b_leg_sip_call_id.clone(),
                    local_addr: local_sip_addr,
                    failover_trunks,
                    a_leg_via,
                    a_leg_from,
                    a_leg_to,
                    a_leg_cseq,
                    b_leg_from,
                    b_leg_to,
                    b_leg_branch: b_leg_wire_branch,
                    dialog_to_tag: None,
                    rtp_ports: vec![b_leg_rtp_port],
                    media_a_leg_port,
                    media_a_leg_ip: a_media_ip_str,
                    dtls_caller_setup,
                    dtls_caller_fingerprint,
                    media_b_leg_ip: b_media_ip_str,
                    media_b_leg_port: b_leg_rtp_port,
                    b_leg_answered: false,
                    a_leg_local_cseq: 1,
                    b_leg_local_cseq: 2,
                    a_leg_last_sdp: None,
                    b_leg_last_sdp: b_leg_sdp.map(Bytes::from),
                    pending_reinvite: None,
                    last_reinvite_ack: None,
                    established_at: None,
                },
            );
        }
        // INVITE correlation is stored — remove from in-flight set (H4).
        {
            let mut in_flight = self.in_flight_invites.write().await;
            in_flight.remove(&a_leg_call_id);
        }

        // 9. Transactions: the server INVITE transaction was opened in
        //    `process_request`; the B-leg client transaction opens when the
        //    forwarded INVITE below is tracked by `process_message`.

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
    ///
    /// An ACK for a non-2xx final shares the INVITE's branch and completes
    /// that server transaction (RFC 3261 §17.2.1). An ACK for a 2xx is its
    /// own transaction and stops the TU's 2xx retransmission (§13.3.1.4).
    async fn handle_ack(&self, message: SipMessage) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let call_id = req.headers.call_id().unwrap_or("").to_string();
        debug!(uri = %req.uri, call_id = %call_id, "Processing ACK");

        if let Some(branch) = req.headers.via_branch() {
            let mut txns = self.transactions.write().await;
            if let Some(st) = txns
                .server_invite
                .get_mut(&TransactionKey::server(&branch, "INVITE"))
            {
                let _ = st.transaction.receive_ack();
                debug!(call_id = %call_id, "ACK completed non-2xx INVITE transaction");
                return ProcessResult::NoAction;
            }
        }

        let cseq = req.headers.cseq_parsed().map(|c| c.sequence);
        let mut pending = self.pending_2xx.write().await;
        if pending
            .get(&call_id)
            .is_some_and(|p| cseq.is_none_or(|n| n == p.cseq))
        {
            pending.remove(&call_id);
            debug!(call_id = %call_id, "ACK received for 2xx; retransmission stopped");
        }
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

        let sip_call_id = req.headers.call_id().unwrap_or("").to_string();

        debug!(call_id = %sip_call_id, "Processing BYE");

        // Look up the call — could be from A-leg or B-leg
        let corr = self.call_correlation.read().await;
        let (internal_id, is_from_a_leg) = if let Some(id) = corr.a_leg.get(&sip_call_id) {
            (id.clone(), true)
        } else if let Some(id) = corr.b_leg.get(&sip_call_id) {
            (id.clone(), false)
        } else {
            // No dialog matches: 481 Call/Transaction Does Not Exist
            // (RFC 3261 §15.1.2). A 200 here would hide a stale dialog from
            // the far end and let a forged BYE look successful.
            debug!(call_id = %sip_call_id, "BYE for unknown dialog, 481");
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        };

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
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

        // Build the forwarded request for the other leg. If the B-leg
        // dialog has no To-tag yet (early dialog — no final response
        // received), send CANCEL instead of BYE (H6). A BYE in an early
        // dialog is invalid per RFC 3261 §15 and will be rejected by
        // conformant UAs.
        let (other_call_id, other_dest) = if is_from_a_leg {
            (&addrs.b_leg_sip_call_id, addrs.b_leg_destination)
        } else {
            (&addrs.a_leg_sip_call_id, addrs.a_leg_source)
        };

        let use_cancel = is_from_a_leg && addrs.dialog_to_tag.is_none();

        let other_uri = SipUri::new(other_dest.ip().to_string()).with_port(other_dest.port());
        let forward_request = if use_cancel {
            // Early dialog: send CANCEL mirroring the original INVITE
            // (same Via branch, From, To without tag).
            let mut cancel_req = proto_sip::message::SipRequest::new(Method::Cancel, other_uri);
            cancel_req.headers.set(HeaderName::CallId, other_call_id);
            cancel_req.headers.set(HeaderName::CSeq, "1 CANCEL");
            cancel_req.headers.set(HeaderName::From, &addrs.b_leg_from);
            cancel_req.headers.set(HeaderName::To, &addrs.b_leg_to);
            cancel_req.headers.set(HeaderName::MaxForwards, "70");
            cancel_req.headers.add(Header::new(
                HeaderName::Via,
                format!(
                    "SIP/2.0/UDP {};branch={}",
                    addrs.local_addr, addrs.b_leg_branch
                ),
            ));
            cancel_req.headers.set(HeaderName::ContentLength, "0");
            cancel_req
        } else {
            // Confirmed dialog: send BYE with dialog identity.
            let mut bye_request = proto_sip::message::SipRequest::new(Method::Bye, other_uri);
            bye_request.headers.set(HeaderName::CallId, other_call_id);
            if is_from_a_leg {
                // SBC is the UAC on the B-leg: From = our INVITE From, To = the
                // callee with their tag; next CSeq after the INVITE (1).
                bye_request.headers.set(HeaderName::From, &addrs.b_leg_from);
                bye_request.headers.set(
                    HeaderName::To,
                    with_tag(&addrs.b_leg_to, addrs.dialog_to_tag.as_deref()),
                );
                bye_request
                    .headers
                    .set(HeaderName::CSeq, format!("{} BYE", addrs.b_leg_local_cseq));
            } else {
                // SBC is the UAS on the A-leg: swap the A-leg dialog headers
                // (our From = the To we answered with, our To = the caller's
                // From). The SBC→A direction has its own CSeq space.
                bye_request.headers.set(
                    HeaderName::From,
                    with_tag(&addrs.a_leg_to, addrs.dialog_to_tag.as_deref()),
                );
                bye_request.headers.set(HeaderName::To, &addrs.a_leg_from);
                bye_request
                    .headers
                    .set(HeaderName::CSeq, format!("{} BYE", addrs.a_leg_local_cseq));
            }
            bye_request.headers.set(HeaderName::MaxForwards, "70");
            let branch = generate_branch();
            bye_request.headers.add(Header::new(
                HeaderName::Via,
                format!("SIP/2.0/UDP {};branch={}", addrs.local_addr, branch),
            ));
            bye_request.headers.set(HeaderName::ContentLength, "0");
            bye_request
        };

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
        // Release allocated RTP ports (C12).
        for port in &addrs.rtp_ports {
            self.release_rtp_port(*port);
        }

        info!(
            call_id = %sip_call_id,
            from_a_leg = is_from_a_leg,
            early_dialog = use_cancel,
            "Call terminated via BYE"
        );
        audit_call_terminated(
            &addrs,
            if is_from_a_leg {
                uc_audit::event::TerminationReason::CallerHangup
            } else {
                uc_audit::event::TerminationReason::CalleeHangup
            },
        );

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(ok_response),
                destination: source,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(forward_request),
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

        let sip_call_id = req.headers.call_id().unwrap_or("").to_string();

        debug!(call_id = %sip_call_id, "Processing CANCEL");

        // Look up the call via A-leg Call-ID.  When messages are spawned
        // as independent tasks, a CANCEL can arrive before the INVITE's
        // correlation entry is stored.  If the Call-ID is currently
        // in-flight (INVITE processing), wait for it to finish before
        // giving up.
        let mut corr = self.call_correlation.read().await;
        if !corr.a_leg.contains_key(&sip_call_id)
            && self.in_flight_invites.read().await.contains(&sip_call_id)
        {
            drop(corr);
            for _ in 0..20 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if !self.in_flight_invites.read().await.contains(&sip_call_id) {
                    break;
                }
            }
            corr = self.call_correlation.read().await;
        }
        let Some(id) = corr.a_leg.get(&sip_call_id) else {
            // No INVITE transaction to cancel: 481 (RFC 3261 §9.2).
            debug!(call_id = %sip_call_id, "CANCEL matches no pending INVITE, 481");
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
            };
        };
        let internal_id = id.clone();

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
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
        terminated.headers.set(HeaderName::CSeq, &addrs.a_leg_cseq);
        terminated.headers.set(HeaderName::ContentLength, "0");

        // CANCEL to B-leg. RFC 3261 §9.1: a CANCEL must mirror the INVITE
        // it cancels — same Via branch, From, To (no tag), and CSeq number
        // with method CANCEL. A fresh branch made it unmatchable.
        let b_uri = SipUri::new(addrs.b_leg_destination.ip().to_string())
            .with_port(addrs.b_leg_destination.port());
        let mut b_cancel = proto_sip::message::SipRequest::new(Method::Cancel, b_uri);
        b_cancel
            .headers
            .set(HeaderName::CallId, &addrs.b_leg_sip_call_id);
        b_cancel.headers.set(HeaderName::CSeq, "1 CANCEL");
        b_cancel.headers.set(HeaderName::From, &addrs.b_leg_from);
        b_cancel.headers.set(HeaderName::To, &addrs.b_leg_to);
        b_cancel.headers.set(HeaderName::MaxForwards, "70");
        b_cancel.headers.add(Header::new(
            HeaderName::Via,
            format!(
                "SIP/2.0/UDP {};branch={}",
                addrs.local_addr, addrs.b_leg_branch
            ),
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
        // Release allocated RTP ports (C12).
        for port in &addrs.rtp_ports {
            self.release_rtp_port(*port);
        }

        info!(call_id = %sip_call_id, "Call cancelled");
        audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Canceled);

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
        response.add_header(Header::new(HeaderName::Allow, ALLOWED_METHODS));

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

        // An in-dialog request (tagged To) for a dialog this SBC does not
        // have gets 481, not 405 (RFC 3261 §12.2.2).
        if req.headers.to_tag().is_some() {
            let call_id = req.headers.call_id().unwrap_or("");
            let corr = self.call_correlation.read().await;
            let known = corr.a_leg.contains_key(call_id) || corr.b_leg.contains_key(call_id);
            drop(corr);
            if !known {
                debug!(method = %req.method, call_id, "In-dialog request for unknown dialog, 481");
                let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
                return ProcessResult::Response {
                    message: SipMessage::Response(response),
                    destination: source,
                };
            }
        }

        warn!(method = %req.method, "Unsupported method");

        // Create 405 Method Not Allowed
        let mut response = create_response_from_request(req, StatusCode::METHOD_NOT_ALLOWED);
        response.add_header(Header::new(HeaderName::Allow, ALLOWED_METHODS));

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
                    a_leg_call_id: addrs
                        .map(|a| a.a_leg_sip_call_id.clone())
                        .unwrap_or_default(),
                    b_leg_call_id: addrs
                        .map(|a| a.b_leg_sip_call_id.clone())
                        .unwrap_or_default(),
                    a_leg_source: addrs
                        .map(|a| a.a_leg_source.to_string())
                        .unwrap_or_default(),
                    b_leg_destination: addrs
                        .map(|a| a.b_leg_destination.to_string())
                        .unwrap_or_default(),
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
                        .map(|b| ContactSummary {
                            uri: b.contact_uri().to_string(),
                            expires_secs: b.remaining_seconds(),
                            q_value: b.q_value(),
                        })
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
    pub async fn delete_registration(&self, aor: &str, contact_uri: &str) -> Result<(), String> {
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
                    DialPattern::Exact(v)
                    | DialPattern::Prefix(v)
                    | DialPattern::Wildcard(v)
                    | DialPattern::Regex(v) => v.clone(),
                    DialPattern::Any => "*".to_string(),
                },
                domain_pattern: e.domain_pattern().map(String::from),
                source_trunk: e.source_trunk().map(String::from),
                trunk_group: e.trunk_group().to_string(),
                destination_type: match e.destination_type() {
                    DestinationType::TrunkGroup => "trunk_group",
                    DestinationType::RegisteredUser => "registered_user",
                    DestinationType::StaticUri => "static_uri",
                }
                .to_string(),
                static_destination: e.static_destination().map(String::from),
                transform_type: match e.transform() {
                    NumberTransform::None => "none",
                    NumberTransform::StripPrefix { .. } => "strip_prefix",
                    NumberTransform::AddPrefix { .. } => "add_prefix",
                    NumberTransform::ReplacePrefix { .. } => "replace_prefix",
                    NumberTransform::Replace { .. } => "replace",
                    NumberTransform::Chain(_) => "chain",
                }
                .to_string(),
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
    pub async fn register_inbound_trunk(
        &self,
        trunk_group_id: &str,
        css_id: Option<&str>,
        hosts: &[(String, u16)],
    ) {
        let mut map = self.inbound_trunk_map.write().await;
        for (host, _port) in hosts {
            for ip in resolve_trunk_host_ips(host) {
                map.insert(ip, (trunk_group_id.to_string(), css_id.map(String::from)));
            }
        }
        info!(trunk_group = trunk_group_id, css = ?css_id, hosts = hosts.len(), "Registered inbound trunk for CSS routing");
    }

    /// Looks up which trunk group and CSS an inbound call belongs to by source IP.
    pub async fn lookup_inbound_trunk(
        &self,
        source_ip: std::net::IpAddr,
    ) -> Option<(String, Option<String>)> {
        self.inbound_trunk_map.read().await.get(&source_ip).cloned()
    }

    /// Whether an INVITE from `source_ip` may be admitted: the address must
    /// belong to a configured trunk or to a current (unexpired) registration.
    async fn is_admitted_source(&self, source_ip: std::net::IpAddr) -> bool {
        let ip = source_ip.to_canonical();
        if self.inbound_trunk_map.read().await.contains_key(&ip) {
            return true;
        }
        let loc = self.location_service.read().await;
        loc.aors().any(|aor| {
            loc.lookup(aor).iter().any(|binding| {
                binding
                    .contact_uri()
                    .parse::<SipUri>()
                    .ok()
                    .and_then(|uri| uri.host.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|contact_ip| contact_ip.to_canonical() == ip)
            })
        })
    }

    /// Adds a DID → username mapping for inbound call routing.
    pub async fn add_did_mapping(&self, did: &str, username: &str) {
        self.did_map
            .write()
            .await
            .insert(did.to_string(), username.to_string());
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
    /// 1. Set up media: delegate to the sbc-announcement-server pod when
    ///    `SBC_ANNOUNCEMENT_URL` is configured (it binds the RTP socket
    ///    and reports the IP/port for our SDP), otherwise bind a local
    ///    RTP socket (in-process fallback, pre-split behavior)
    /// 2. Send 200 OK with SDP (sendonly PCMU) to caller
    /// 3. Spawn background task: stream announcement audio (or wait for
    ///    the pod to finish streaming), then send BYE
    async fn play_announcement_to_caller(
        &self,
        req: &proto_sip::message::SipRequest,
        source: SbcSocketAddr,
        announcement: crate::announcement::AnnouncementType,
    ) -> ProcessResult {
        // Extract the caller's RTP destination from their SDP offer up
        // front: the remote announcement pod needs it before we can
        // build our 200 OK.
        let caller_rtp_dest = req
            .body
            .as_ref()
            .and_then(|body| {
                let sdp_str = String::from_utf8_lossy(body);
                crate::announcement::extract_rtp_dest_from_sdp(&sdp_str)
            })
            .filter(|dest| {
                let allowed = !sbc_announcement::is_disallowed_media_ip(dest.ip())
                    && !dest.ip().is_unspecified();
                if !allowed {
                    warn!(destination = %dest, "Ignoring disallowed media address in SDP");
                }
                allowed
            });

        let call_id = req.headers.call_id().unwrap_or("unknown").to_string();

        let ssrc = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            (now.as_nanos() as u32) ^ (now.as_secs() as u32)
        };

        // Bind RTP socket to the outside zone's signaling IP so media
        // exits via the correct macvlan interface (in-process mode).
        let rtp_bind_ip = self
            .zone_registry
            .as_ref()
            .and_then(|zr| zr.signaling_ip("outside"));

        // The daemon's own externally reachable IP: the outside zone's
        // external IP (STUN/public), falling back to the signaling IP,
        // then to the address the INVITE arrived on. Used for the SIP
        // Contact and the BYE, and as the SDP media address when
        // playback runs in-process.
        let daemon_ip = self
            .zone_registry
            .as_ref()
            .and_then(|zr| {
                zr.external_ip("outside")
                    .or_else(|| zr.signaling_ip("outside"))
                    .map(|ip| ip.to_string())
            })
            .unwrap_or_else(|| match source.ip() {
                std::net::IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
                std::net::IpAddr::V4(v4) => v4.to_string(),
            });

        // Prefer the external announcement pod when configured. Any
        // failure here falls back to in-process playback so a missing
        // or crashed pod degrades to pre-split behavior.
        #[cfg(feature = "grpc")]
        let remote_media: Option<(String, u16, AnnouncementPlayback)> = match (
            std::env::var(crate::announcement_client::ANNOUNCEMENT_URL_ENV),
            caller_rtp_dest,
        ) {
            (Ok(url), Some(dest)) => crate::announcement_client::start_remote_announcement(
                &url,
                announcement,
                dest,
                ssrc,
                &call_id,
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "Remote announcement unavailable; using in-process playback");
            })
            .ok()
            .map(|session| {
                (
                    session.advertised_ip.clone(),
                    session.rtp_port,
                    AnnouncementPlayback::Remote(Box::new(session)),
                )
            }),
            _ => None,
        };
        #[cfg(not(feature = "grpc"))]
        let remote_media: Option<(String, u16, AnnouncementPlayback)> = None;

        let (sdp_ip, actual_rtp_port, playback) = if let Some(remote) = remote_media {
            remote
        } else {
            // In-process playback: bind the announcement RTP socket now
            // to discover the actual port before building the SDP.
            let preferred_port = if let Some(ref pipeline) = self.media_pipeline {
                pipeline.allocate_ports().await.map_or(0, |(rtp, _)| rtp)
            } else {
                0
            };
            match crate::announcement::AnnouncementServer::bind_socket(preferred_port, rtp_bind_ip)
                .await
            {
                Ok((socket, port)) => {
                    (daemon_ip.clone(), port, AnnouncementPlayback::Local(socket))
                }
                Err(e) => {
                    warn!(error = %e, "Cannot bind announcement socket");
                    let unavailable =
                        create_response_from_request(req, StatusCode::TEMPORARILY_UNAVAILABLE);
                    return ProcessResult::Response {
                        message: SipMessage::Response(unavailable),
                        destination: source,
                    };
                }
            }
        };

        info!(sdp_ip = %sdp_ip, rtp_port = actual_rtp_port, zone_registry_present = self.zone_registry.is_some(), "SDP media address for announcement");
        let sdp = crate::announcement::build_announcement_sdp(&sdp_ip, actual_rtp_port);

        // Build 200 OK with SDP
        let mut ok_response = create_response_from_request(req, StatusCode::OK);
        // Contact is the daemon's SIP address — not sdp_ip, which is the
        // announcement pod's media IP when playback runs remotely.
        ok_response.add_header(Header::new(
            HeaderName::Contact,
            format!(
                "<sip:{}@{}:{}>",
                self.config.instance_name,
                daemon_ip,
                source.port()
            ),
        ));
        ok_response
            .headers
            .set(HeaderName::ContentType, "application/sdp");
        let sdp_bytes = sdp.into_bytes();
        ok_response
            .headers
            .set(HeaderName::ContentLength, sdp_bytes.len().to_string());
        ok_response.body = Some(Bytes::from(sdp_bytes));

        // Track this Call-ID to absorb INVITE retransmits
        let announcement_calls = Arc::clone(&self.announcement_calls);
        announcement_calls.write().await.insert(call_id.clone());
        // Capture full From/To headers for the BYE dialog matching.
        // In BYE from UAS: From = our To (with our tag), To = caller's From (with their tag)
        let invite_from = req
            .headers
            .get_value(&HeaderName::From)
            .unwrap_or_default()
            .to_string();
        let ok_to = ok_response
            .headers
            .get_value(&HeaderName::To)
            .unwrap_or_default()
            .to_string();

        let source_port = source.port();
        // local_ip = macvlan IP for binding sockets; daemon_ip = the
        // daemon's external/public IP (sdp_ip may be the announcement
        // pod's address and must not be used for the BYE)
        let local_ip = rtp_bind_ip.map_or_else(|| daemon_ip.clone(), |ip| ip.to_string());

        // Spawn background task to play announcement then BYE
        tokio::spawn(async move {
            match playback {
                AnnouncementPlayback::Local(ann_socket) => {
                    // Wait for caller to process the 200 OK and send ACK
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                    if let Some(rtp_dest) = caller_rtp_dest {
                        if let Err(e) = crate::announcement::AnnouncementServer::play_on_socket(
                            announcement,
                            ann_socket,
                            rtp_dest,
                            ssrc,
                        )
                        .await
                        {
                            warn!(error = %e, "Announcement playback failed");
                        }
                    } else {
                        warn!("No RTP destination from caller SDP, skipping audio playback");
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
                #[cfg(feature = "grpc")]
                AnnouncementPlayback::Remote(session) => {
                    // The pod paces the audio; this resolves when its
                    // Completed event arrives (or the stream breaks —
                    // we still BYE so the call is not left hanging).
                    if let Err(e) = session.wait_complete().await {
                        warn!(error = %e, "Remote announcement playback failed");
                    }
                }
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
                    let bind_addr: std::net::SocketAddr = format!("{local_ip}:5060")
                        .parse()
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
                        if s.bind(&bind_addr.into()).is_ok()
                            && let Ok(sock) = tokio::net::UdpSocket::from_std(s.into())
                        {
                            if let Err(e) = sock.send_to(&bye_bytes, source.as_std()).await {
                                warn!(error = %e, "Failed to send BYE after announcement");
                            } else {
                                info!(call_id = %call_id, destination = %source, "Sent BYE after announcement");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to build BYE after announcement");
                }
            }

            // Playback finished — drop the retransmit-dedup entry so the
            // set stays bounded (it previously grew forever).
            announcement_calls.write().await.remove(&call_id);
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
    /// Contact bindings.
    pub contacts: Vec<ContactSummary>,
}

/// One contact binding within a [`RegistrationSummary`].
#[derive(Debug, Clone)]
pub struct ContactSummary {
    /// Contact URI.
    pub uri: String,
    /// Seconds until the binding expires.
    pub expires_secs: u32,
    /// Q-value priority.
    pub q_value: f32,
}

/// Creates a response from a request, copying required headers.
fn create_response_from_request(
    req: &proto_sip::message::SipRequest,
    status: StatusCode,
) -> proto_sip::message::SipResponse {
    let mut response = proto_sip::message::SipResponse::new(status);

    // Copy all Via headers (RFC 3261 requires every Via from the request)
    for via in req.headers.get_all(&HeaderName::Via) {
        response.add_header(Header::new(HeaderName::Via, &via.value));
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
///
/// Cryptographically random — predictable tags weaken protection against
/// off-path forged in-dialog requests (e.g. a spoofed BYE).
fn generate_tag() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// Copies common headers from a B-leg response for forwarding to A-leg.
///
/// Copies Via, From, To, CSeq, and Content-Length.
/// Call-ID should be replaced by the caller with the A-leg's Call-ID.
/// Appends a tag parameter to a From/To header value if not present.
fn with_tag(header_value: &str, tag: Option<&str>) -> String {
    match tag {
        Some(t) if !header_value.contains("tag=") => format!("{header_value};tag={t}"),
        _ => header_value.to_string(),
    }
}

/// The SBC's caller-facing RTP port: the relay's A-leg port when the media
/// pipeline anchored the call, else the bare port allocated at answer time
/// (second entry of `rtp_ports`), else the B-leg port (nothing is relayed in
/// that fallback, so the value only needs to be a port the SBC owns).
fn a_leg_media_port(addrs: &CallAddresses) -> u16 {
    addrs
        .media_a_leg_port
        .or_else(|| addrs.rtp_ports.get(1).copied())
        .unwrap_or(addrs.media_b_leg_port)
}

/// The sequence number of a `CSeq` header value such as `"314 INVITE"`.
fn cseq_number(cseq: &str) -> u32 {
    cseq.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1)
}

/// True when a `Supported`/`Require` header value lists the `timer` option
/// tag (RFC 4028 §7.1).
fn lists_timer_option(headers: &proto_sip::header::Headers, name: &HeaderName) -> bool {
    headers.get_all(name).any(|h| {
        h.value
            .split(',')
            .any(|tag| tag.trim().eq_ignore_ascii_case("timer"))
    })
}

/// Copies the RFC 4028 negotiation headers of a request across the B2BUA:
/// `Session-Expires`/`Min-SE` verbatim and `Supported: timer` when the
/// originator listed it. Only the `timer` option tag is relayed — other
/// capabilities (e.g. `100rel`) are not implemented end to end by this SBC
/// and must not be advertised on its behalf.
fn relay_session_timer_request_headers(
    from: &proto_sip::header::Headers,
    to: &mut proto_sip::header::Headers,
) {
    for name in [HeaderName::SessionExpires, HeaderName::MinSe] {
        if let Some(v) = from.get_value(&name) {
            to.set(name, v);
        }
    }
    if lists_timer_option(from, &HeaderName::Supported) {
        to.set(HeaderName::Supported, "timer");
    }
}

/// Copies the RFC 4028 outcome of a 2xx across the B2BUA: `Session-Expires`
/// (with the chosen refresher) and `Require: timer` when the answerer set it.
fn relay_session_timer_response_headers(
    from: &proto_sip::header::Headers,
    to: &mut proto_sip::header::Headers,
) {
    if let Some(v) = from.get_value(&HeaderName::SessionExpires) {
        to.set(HeaderName::SessionExpires, v);
    }
    if lists_timer_option(from, &HeaderName::Require) {
        to.set(HeaderName::Require, "timer");
    }
}

/// Builds a response toward the A-leg carrying the A-leg dialog's own
/// Via/From/To/CSeq/Call-ID (forwarding the B-leg's headers verbatim makes
/// the response unmatchable for the A-leg UA).
fn build_a_leg_response(
    status: StatusCode,
    addrs: &CallAddresses,
) -> proto_sip::message::SipResponse {
    let mut response = proto_sip::message::SipResponse::new(status);
    for via in &addrs.a_leg_via {
        response.headers.add(Header::new(HeaderName::Via, via));
    }
    response.headers.set(HeaderName::From, &addrs.a_leg_from);
    // A UAS tags To on every non-100 response (RFC 3261 §8.2.6.2). Before the
    // callee answered there is no learned tag, e.g. a 408 on Timer B.
    let local_tag = addrs
        .dialog_to_tag
        .clone()
        .or_else(|| (status.code() != 100).then(generate_tag));
    response.headers.set(
        HeaderName::To,
        with_tag(&addrs.a_leg_to, local_tag.as_deref()),
    );
    response
        .headers
        .set(HeaderName::CallId, &addrs.a_leg_sip_call_id);
    response.headers.set(HeaderName::CSeq, &addrs.a_leg_cseq);
    response.headers.set(HeaderName::ContentLength, "0");
    response
}

/// Parses a manipulation action from config strings.
fn parse_manipulation_action(action: &str, header: &str, value: &str) -> ManipulationAction {
    let header_name: HeaderName = header
        .parse()
        .unwrap_or_else(|_| HeaderName::Custom(header.to_string()));
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
/// Turns an SDP `c=`/`m=` address into a relay target, refusing addresses a
/// peer must not be able to make the SBC send to: loopback, link-local,
/// multicast and unspecified. Hostnames are not resolved.
fn admitted_media_addr(media: &MediaAddress) -> Option<SbcSocketAddr> {
    let ip: std::net::IpAddr = media.address.parse().ok()?;
    if sbc_announcement::is_disallowed_media_ip(ip) || ip.is_unspecified() {
        warn!(address = %media.address, port = media.port, "Ignoring disallowed media address in SDP");
        return None;
    }
    Some(SbcSocketAddr::from(std::net::SocketAddr::new(
        ip, media.port,
    )))
}

/// Resolves a trunk host (IP literal or hostname) to every address it names.
/// A hostname is resolved synchronously; failures yield an empty list.
fn resolve_trunk_host_ips(host: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip.to_canonical()];
    }
    format!("{host}:0")
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip().to_canonical()).collect())
        .unwrap_or_default()
}

fn resolve_sip_uri_to_addr(uri: &str) -> Option<SbcSocketAddr> {
    use std::net::ToSocketAddrs;

    // Strip sip: or sips: prefix
    let without_scheme = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);

    // Strip user@ if present
    let host_part = without_scheme
        .find('@')
        .map_or(without_scheme, |at_pos| &without_scheme[at_pos + 1..]);

    // Strip parameters (;transport=udp etc.)
    let host_part = host_part.split(';').next().unwrap_or(host_part);

    // Parse host:port
    let (host, port) = host_part.rfind(':').map_or((host_part, 5060), |colon_pos| {
        let port_str = &host_part[colon_pos + 1..];
        port_str
            .parse::<u16>()
            .map_or((host_part, 5060), |port| (&host_part[..colon_pos], port))
    });

    // Parse IP address
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return Some(SbcSocketAddr::new_v4(ipv4, port));
    }
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return Some(SbcSocketAddr::new_v6(ipv6, port));
    }

    // For hostnames, resolve via DNS off the async executor.
    let addr_str = format!("{host}:{port}");
    let resolved = tokio::task::block_in_place(|| addr_str.to_socket_addrs());
    if let Ok(mut addrs) = resolved
        && let Some(addr) = addrs.next()
    {
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
    // Search for '>' only after the '<': a display name may itself contain '>'.
    if let Some(start) = header_value.find('<')
        && let Some(len) = header_value[start + 1..].find('>')
    {
        return header_value[start + 1..start + 1 + len].to_string();
    }
    // No angle brackets — take the value before any parameters
    header_value
        .split(';')
        .next()
        .unwrap_or(header_value)
        .trim()
        .to_string()
}

/// Extracts the user part of an AOR URI for RFC 8898 `dn`-to-AOR binding.
///
/// `aor` is a SIP/SIPS URI like `sip:1455550100@example.mil`; this returns
/// the user part (`1455550100`), tolerating a missing scheme or host.
fn aor_user_part(aor: &str) -> &str {
    // Strip the scheme (`sip:` / `sips:`) if present, then take the part
    // before `@`. URI parameters after the host are irrelevant here.
    let after_scheme = aor.split_once(':').map_or(aor, |(_, rest)| rest);
    after_scheme
        .split('@')
        .next()
        .unwrap_or(after_scheme)
        .trim()
}

/// Parses Contact headers from a SIP request into `ContactInfo` list.
/// Rewrites a contact whose host is an unspecified address (`[::]` /
/// `0.0.0.0` — clients that advertise their wildcard bind address) to the
/// request's source IP and port. `SipUri`'s display re-brackets IPv6
/// hosts, so latched URIs come out well-formed.
fn latch_unspecified_contact(contact: &mut ContactInfo, source: &SbcSocketAddr) {
    if contact.uri == "*" {
        return;
    }
    let Ok(mut uri) = contact.uri.parse::<proto_sip::uri::SipUri>() else {
        return;
    };
    let is_unspecified = uri
        .host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified());
    if !is_unspecified {
        return;
    }
    let latched_from = contact.uri.clone();
    uri.host = source.ip().to_string();
    uri.port = Some(source.port());
    contact.uri = uri.to_string();
    debug!(from = %latched_from, to = %contact.uri, "Latched unspecified contact host to request source");
}

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

    #[test]
    fn latch_rewrites_unspecified_v6_host_with_brackets() {
        let source = SbcSocketAddr::from(
            "[2601:443:c200:570::1]:55748"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        );
        let mut contact = ContactInfo::new("sip:1209@[::]:61676;transport=tls");
        latch_unspecified_contact(&mut contact, &source);
        assert_eq!(
            contact.uri,
            "sip:1209@[2601:443:c200:570::1]:55748;transport=tls"
        );
    }

    #[test]
    fn latch_rewrites_unspecified_v4_host() {
        let source =
            SbcSocketAddr::from("198.51.100.7:5060".parse::<std::net::SocketAddr>().unwrap());
        let mut contact = ContactInfo::new("sip:alice@0.0.0.0:5080");
        latch_unspecified_contact(&mut contact, &source);
        assert_eq!(contact.uri, "sip:alice@198.51.100.7:5060");
    }

    #[test]
    fn latch_leaves_routable_and_wildcard_contacts_alone() {
        let source =
            SbcSocketAddr::from("198.51.100.7:5060".parse::<std::net::SocketAddr>().unwrap());
        let mut routable = ContactInfo::new("sip:alice@203.0.113.9:5080;transport=tls");
        latch_unspecified_contact(&mut routable, &source);
        assert_eq!(routable.uri, "sip:alice@203.0.113.9:5080;transport=tls");

        let mut wildcard = ContactInfo::new("*");
        latch_unspecified_contact(&mut wildcard, &source);
        assert_eq!(wildcard.uri, "*");

        let mut hostname = ContactInfo::new("sip:alice@phone.example.mil");
        latch_unspecified_contact(&mut hostname, &source);
        assert_eq!(hostname.uri, "sip:alice@phone.example.mil");
    }

    #[tokio::test]
    async fn test_sip_stack_creation() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        assert_eq!(stack.dialog_count().await, 0);
        assert_eq!(stack.call_count().await, 0);
    }

    #[test]
    fn per_zone_media_ip_selects_ingress_and_egress() {
        use crate::zone::ResolvedZoneRegistry;
        use sbc_config::interface::ResolvedZone;

        let mut stack = SipStack::new(SipStackConfig::default());
        stack.set_zone_registry(Arc::new(ResolvedZoneRegistry::from_resolved(vec![
            ResolvedZone {
                name: "inside".to_string(),
                signaling_ip: "10.0.1.10".parse().unwrap(),
                media_ip: "10.0.1.20".parse().unwrap(),
                external_ip: None,
                external_ip_source: None,
            },
            ResolvedZone {
                name: "outside".to_string(),
                signaling_ip: "203.0.113.5".parse().unwrap(),
                media_ip: "203.0.113.6".parse().unwrap(),
                external_ip: Some("203.0.113.6".parse().unwrap()),
                external_ip_source: Some("203.0.113.6".to_string()),
            },
        ])));

        let fallback: std::net::IpAddr = "192.0.2.1".parse().unwrap();

        // B-leg Via/Contact: trunk legs advertise the external zone's public
        // IP; internal legs the ingress zone's signaling IP.
        assert_eq!(
            stack.b_leg_signaling_addr(Some("inside"), true),
            ("203.0.113.6".to_string(), 5060)
        );
        assert_eq!(
            stack.b_leg_signaling_addr(Some("inside"), false),
            ("10.0.1.10".to_string(), 5060)
        );

        // A-leg (caller) advertises + binds the INGRESS zone's media interface.
        let (a_bind, a_adv) = stack.zone_media_bind(Some("inside"), fallback);
        assert_eq!(a_adv, "10.0.1.20");
        assert_eq!(a_bind, "10.0.1.20".parse::<std::net::IpAddr>().ok());

        // Outbound trunk leg → egress zone is the carrier-facing (external) zone,
        // so the B-leg advertises the outside media interface.
        let egress = stack.egress_media_zone(Some("inside"), true);
        assert_eq!(egress.as_deref(), Some("outside"));
        let (_, b_adv) = stack.zone_media_bind(egress.as_deref(), fallback);
        assert_eq!(b_adv, "203.0.113.6");

        // Internal (non-external) call → egress stays on the ingress zone.
        assert_eq!(
            stack.egress_media_zone(Some("inside"), false).as_deref(),
            Some("inside")
        );

        // No zone registry → bind None (relay binds 0.0.0.0), advertise fallback,
        // and egress falls back to the ingress zone name.
        let bare = SipStack::new(SipStackConfig::default());
        let (bind, adv) = bare.zone_media_bind(Some("inside"), fallback);
        assert_eq!(bind, None);
        assert_eq!(adv, "192.0.2.1");
        assert_eq!(
            bare.egress_media_zone(Some("inside"), true).as_deref(),
            Some("inside")
        );
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

    #[test]
    fn test_with_tag() {
        assert_eq!(with_tag("<sip:a@b>", Some("xyz")), "<sip:a@b>;tag=xyz");
        // Existing tag is preserved, not duplicated
        assert_eq!(
            with_tag("<sip:a@b>;tag=abc", Some("xyz")),
            "<sip:a@b>;tag=abc"
        );
        assert_eq!(with_tag("<sip:a@b>", None), "<sip:a@b>");
    }

    /// An INVITE arriving with Max-Forwards: 0 must be rejected with 483,
    /// not forwarded with a fresh Max-Forwards (loop protection).
    #[tokio::test]
    async fn test_invite_max_forwards_exhausted() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);
        // The caller is a configured trunk, so the INVITE passes source admission.
        stack
            .register_inbound_trunk("test-trunk", None, &[("127.0.0.1".to_string(), 5060)])
            .await;

        let invite = b"INVITE sip:9999@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKmf0\r\n\
            From: <sip:alice@example.com>;tag=mf0\r\n\
            To: <sip:9999@sbc.local>\r\n\
            Call-ID: maxfwd0@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Max-Forwards: 0\r\n\
            Contact: <sip:alice@client.example.com:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), source, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                let SipMessage::Response(resp) = message else {
                    panic!("Expected response message");
                };
                assert_eq!(
                    resp.status.code(),
                    483,
                    "must reject with 483 Too Many Hops"
                );
            }
            other => panic!("Expected 483 response, got {other:?}"),
        }
    }

    #[test]
    fn register_auth_enabled_reflects_config() {
        assert!(!SipStack::new(SipStackConfig::default()).register_auth_enabled());
        let digest = SipStackConfig {
            require_auth: true,
            ..SipStackConfig::default()
        };
        assert!(SipStack::new(digest).register_auth_enabled());
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
        // The binding is NAT-fixed to the packet source (127.0.0.1:5060),
        // not the phone's advertised Contact host — a phone behind NAT
        // advertises an unroutable private address, so the location binding
        // must point at the source pinhole for inbound calls to reach it.
        assert_eq!(
            bindings[0].contact_uri(),
            "sip:alice@127.0.0.1:5060;transport=udp"
        );
    }

    #[tokio::test]
    async fn test_register_with_auth() {
        let mut config = SipStackConfig {
            require_auth: true,
            auth_realm: "example.com".to_string(),
            ..Default::default()
        };
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

    /// An INVITE from an address that is neither a configured trunk nor a
    /// current registration must be refused, not routed or answered.
    #[tokio::test]
    async fn test_invite_from_unknown_source_is_forbidden() {
        let stack = SipStack::new(SipStackConfig::default());

        let invite = b"INVITE sip:0119005551234@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKadm1\r\n\
            From: <sip:mallory@example.com>;tag=adm1\r\n\
            To: <sip:0119005551234@sbc.local>\r\n\
            Call-ID: admission1@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:mallory@203.0.113.9:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 9), 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), source, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                let SipMessage::Response(resp) = message else {
                    panic!("Expected response message");
                };
                assert_eq!(resp.status.code(), 403, "unknown source must get 403");
            }
            other => panic!("Expected a single 403 response, got {other:?}"),
        }
        assert!(stack.in_flight_invites.read().await.is_empty());
    }

    /// The same INVITE is admitted once its source is a configured trunk.
    #[tokio::test]
    async fn test_invite_from_trunk_source_is_admitted() {
        let stack = SipStack::new(SipStackConfig::default());
        stack
            .register_inbound_trunk("carrier", None, &[("203.0.113.9".to_string(), 5060)])
            .await;

        let invite = b"INVITE sip:9999@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKadm2\r\n\
            From: <sip:carrier@example.com>;tag=adm2\r\n\
            To: <sip:9999@sbc.local>\r\n\
            Call-ID: admission2@example.com\r\n\
            CSeq: 1 INVITE\r\n\
            Contact: <sip:carrier@203.0.113.9:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 9), 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), source, None)
            .await;

        if let ProcessResult::Response { message, .. } = &result
            && let SipMessage::Response(resp) = message
        {
            assert_ne!(resp.status.code(), 403, "trunk source must be admitted");
        }
    }

    /// A currently registered endpoint is admitted from its registered
    /// address, and refused from a different one.
    #[tokio::test]
    async fn test_invite_from_registered_source_is_admitted() {
        let stack = SipStack::new(SipStackConfig::default());

        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKadm3\r\n\
            From: <sip:bob@sbc.local>;tag=adm3\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: admission3-reg@example.com\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@198.51.100.7:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let bob = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
        stack
            .process_message(&Bytes::from_static(register), bob, None)
            .await;

        assert!(stack.is_admitted_source(bob.ip()).await);
        assert!(
            !stack
                .is_admitted_source(std::net::Ipv4Addr::new(198, 51, 100, 8).into())
                .await
        );
    }

    #[tokio::test]
    async fn test_invite_unresolvable_destination() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);
        // The caller is a configured trunk, so the INVITE passes source admission.
        stack
            .register_inbound_trunk("test-trunk", None, &[("127.0.0.1".to_string(), 5060)])
            .await;

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
                    assert_eq!(
                        resp.status.code(),
                        200,
                        "Unresolvable destination should return 200 OK (announcement)"
                    );
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
        // The caller is a configured trunk, so the INVITE passes source admission.
        stack
            .register_inbound_trunk("test-trunk", None, &[("192.168.1.100".to_string(), 5060)])
            .await;

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
        if let ProcessResult::Response { message, .. } = &result
            && let SipMessage::Response(resp) = message
        {
            assert_eq!(resp.status, StatusCode::OK, "Registration should succeed");
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

        let alice_source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 100), 5060);
        let result = stack
            .process_message(&Bytes::from_static(invite), alice_source, None)
            .await;

        // Should get Multiple(100 Trying + Forward INVITE)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 2, "Should have 2 results: Trying + Forward");

                // First: 100 Trying to A-leg
                if let ProcessResult::Response {
                    message,
                    destination,
                } = &results[0]
                {
                    if let SipMessage::Response(resp) = message {
                        assert_eq!(resp.status, StatusCode::TRYING);
                    }
                    assert_eq!(*destination, alice_source);
                } else {
                    panic!("First result should be Response (100 Trying)");
                }

                // Second: Forward INVITE to B-leg (bob at 127.0.0.1:5060)
                if let ProcessResult::Forward {
                    message,
                    destination,
                } = &results[1]
                {
                    assert!(message.is_request(), "Forward should be a request");
                    assert_eq!(
                        destination.ip(),
                        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
                        "B-leg should go to bob's registered address"
                    );
                    // The B-leg must advertise the SBC, never the caller's address.
                    let SipMessage::Request(b_leg) = message else {
                        panic!("Forward should be a request");
                    };
                    let via = b_leg.headers.get_value(&HeaderName::Via).unwrap();
                    let contact = b_leg.headers.get_value(&HeaderName::Contact).unwrap();
                    for (name, value) in [("Via", via), ("Contact", contact)] {
                        assert!(
                            !value.contains("192.168.1.100"),
                            "{name} leaks the caller's address: {value}"
                        );
                        assert!(value.contains("sbc.local:5060"), "{name}: {value}");
                    }
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
        // The caller is a configured trunk, so the INVITE passes source admission.
        stack
            .register_inbound_trunk("test-trunk", None, &[("192.168.1.1".to_string(), 5060)])
            .await;

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
        stack
            .process_message(&Bytes::from_static(register), src, None)
            .await;

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
        stack
            .process_message(&Bytes::from_static(invite), alice, None)
            .await;
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
        let result = stack
            .process_message(&Bytes::from_static(bye), alice, None)
            .await;

        // Should get Multiple(200 OK to alice + BYE to bob)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 2);
                // First: 200 OK
                if let ProcessResult::Response { message, .. } = &results[0]
                    && let SipMessage::Response(resp) = message
                {
                    assert_eq!(resp.status, StatusCode::OK);
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
        // The caller is a configured trunk, so the INVITE passes source admission.
        stack
            .register_inbound_trunk("test-trunk", None, &[("192.168.1.1".to_string(), 5060)])
            .await;

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
        stack
            .process_message(&Bytes::from_static(register), src, None)
            .await;

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
        stack
            .process_message(&Bytes::from_static(invite), alice, None)
            .await;
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
        let result = stack
            .process_message(&Bytes::from_static(cancel), alice, None)
            .await;

        // Should get Multiple(200 OK for CANCEL + 487 for INVITE + CANCEL to bob)
        match result {
            ProcessResult::Multiple(results) => {
                assert_eq!(results.len(), 3, "CANCEL should produce 3 results");
                // First: 200 OK for CANCEL
                if let ProcessResult::Response { message, .. } = &results[0]
                    && let SipMessage::Response(resp) = message
                {
                    assert_eq!(resp.status, StatusCode::OK);
                }
                // Second: 487 Request Terminated for INVITE
                if let ProcessResult::Response { message, .. } = &results[1]
                    && let SipMessage::Response(resp) = message
                {
                    assert_eq!(resp.status.code(), 487);
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
        stack
            .process_message(&Bytes::from_static(register), src, None)
            .await;

        // Verify registration query
        let regs = stack.list_registrations().await;
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].aor, "sip:alice@sbc.local");
        assert_eq!(regs[0].contact_count, 1);
        assert_eq!(stack.registration_aor_count().await, 1);
        assert_eq!(stack.registration_binding_count().await, 1);

        // Delete registration (binding is NAT-fixed to the source pinhole
        // with an explicit transport param).
        stack
            .delete_registration(
                "sip:alice@sbc.local",
                "sip:alice@127.0.0.1:5060;transport=udp",
            )
            .await
            .unwrap();
        assert_eq!(stack.registration_aor_count().await, 0);
    }

    #[tokio::test]
    async fn test_bye_unknown_call() {
        let config = SipStackConfig::default();
        let stack = SipStack::new(config);

        // BYE for a dialog this SBC does not have: 481 (RFC 3261 §15.1.2)
        let bye = b"BYE sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK030\r\n\
            From: <sip:alice@example.com>;tag=u1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: unknown-call@test\r\n\
            CSeq: 2 BYE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5060);
        let result = stack
            .process_message(&Bytes::from_static(bye), src, None)
            .await;

        match result {
            ProcessResult::Response { message, .. } => {
                if let SipMessage::Response(resp) = message {
                    assert_eq!(
                        resp.status,
                        StatusCode::CALL_DOES_NOT_EXIST,
                        "Unknown BYE should get 481"
                    );
                }
            }
            _ => panic!("Expected Response for unknown BYE"),
        }
    }

    #[test]
    fn admitted_media_addr_rejects_local_and_group_addresses() {
        let m = |a: &str| MediaAddress::new(a.to_string(), 4000);
        assert_eq!(
            admitted_media_addr(&m("203.0.113.5")),
            Some(SbcSocketAddr::from(
                "203.0.113.5:4000".parse::<std::net::SocketAddr>().unwrap()
            ))
        );
        assert_eq!(
            admitted_media_addr(&m("2001:db8::7")),
            Some(SbcSocketAddr::from(
                "[2001:db8::7]:4000"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
            ))
        );
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.9.9",
            "::1",
            "::",
            "ff02::1",
        ] {
            assert!(
                admitted_media_addr(&m(bad)).is_none(),
                "{bad} must be refused"
            );
        }
        // Hostnames are not resolved.
        assert!(admitted_media_addr(&m("media.example.com")).is_none());
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
    fn extract_uri_from_header_tolerates_close_bracket_before_open() {
        // A '>' inside the display name precedes the '<' of the name-addr.
        assert_eq!(
            extract_uri_from_header("\">\" <sip:alice@example.com>;tag=1234"),
            "sip:alice@example.com"
        );
        // Unbalanced brackets must not panic.
        assert_eq!(extract_uri_from_header(">x<"), ">x<");
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
        let mut req =
            proto_sip::message::SipRequest::new(Method::Register, SipUri::new("sbc.local"));
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
        let mut req =
            proto_sip::message::SipRequest::new(Method::Register, SipUri::new("sbc.local"));
        req.headers.add(Header::new(HeaderName::Contact, "*"));

        let contacts = parse_contacts_from_request(&req);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri, "*");
    }

    #[tokio::test]
    async fn test_router_initialization() {
        let config = SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        };
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
        // Config-file trunks are admitted sources for INVITE.
        assert!(
            stack
                .is_admitted_source(std::net::Ipv4Addr::LOCALHOST.into())
                .await
        );
        assert!(
            !stack
                .is_admitted_source(std::net::Ipv4Addr::new(10, 9, 9, 9).into())
                .await
        );
    }

    #[tokio::test]
    async fn test_manipulator_initialization() {
        let config = SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        };
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
        let config = SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        };
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
        let config = SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        };
        let mut stack = SipStack::new(config);

        let topo_config = sbc_config::TopologyHidingConfig {
            enabled: false,
            ..Default::default()
        };

        stack.init_topology_hider_from_config(&topo_config);
        assert!(
            stack.topology_hider.is_none(),
            "Disabled topology hider should be None"
        );
    }

    #[test]
    fn sbc_dtls_role_answers_the_peer() {
        use crate::sdp_dtls::SetupRole;
        use sbc_media_core::dtls_sidecar::Role;
        // Caller offered actpass → SBC answers passive → DTLS server.
        assert!(matches!(
            SipStack::sbc_dtls_role(Some(SetupRole::ActPass)),
            Role::Server
        ));
        // Peer active → SBC passive → server.
        assert!(matches!(
            SipStack::sbc_dtls_role(Some(SetupRole::Active)),
            Role::Server
        ));
        // Peer passive → SBC active → client.
        assert!(matches!(
            SipStack::sbc_dtls_role(Some(SetupRole::Passive)),
            Role::Client
        ));
        // No a=setup → treated as actpass (offerer default) → server.
        assert!(matches!(SipStack::sbc_dtls_role(None), Role::Server));
    }

    #[test]
    fn terminate_params_requires_identity_and_both_fingerprints() {
        use crate::sdp_dtls::SetupRole;
        use sbc_media_core::dtls_sidecar::Role;
        let answer_dtls = "v=0\r\nm=audio 5004 UDP/TLS/RTP/SAVP 8\r\n\
            a=setup:active\r\na=fingerprint:sha-384 BB:CC\r\n";
        let answer_plain = "v=0\r\nm=audio 5004 RTP/AVP 8\r\n";
        let caller_fp = "sha-384 AA".to_string();

        // Terminate + both legs offered DTLS → Some, with roles derived from each
        // peer's setup (caller actpass → SBC server; callee active → SBC server).
        let (a, b) = SipStack::terminate_params(
            true,
            Some(&caller_fp),
            Some(SetupRole::ActPass),
            answer_dtls,
        )
        .expect("both legs DTLS → terminate");
        assert_eq!(a.peer_fingerprint, "sha-384 AA");
        assert!(matches!(a.role, Role::Server));
        assert_eq!(b.peer_fingerprint, "sha-384 BB:CC");
        assert!(matches!(b.role, Role::Server));

        // Not terminating (no SBC identity) → opaque.
        assert!(SipStack::terminate_params(false, Some(&caller_fp), None, answer_dtls).is_none());
        // Caller never offered DTLS → opaque.
        assert!(SipStack::terminate_params(true, None, None, answer_dtls).is_none());
        // Callee's answer carries no fingerprint → opaque (interworking unsupported).
        assert!(SipStack::terminate_params(true, Some(&caller_fp), None, answer_plain).is_none());
    }

    // A confirmed B2BUA dialog (remote tag learned), for the media-failure
    // teardown tests.
    fn confirmed_call_addresses() -> CallAddresses {
        CallAddresses {
            a_leg_source: SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(10, 0, 0, 1), 5060),
            b_leg_destination: SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(10, 0, 0, 2), 5060),
            a_leg_sip_call_id: "aleg-callid".to_string(),
            b_leg_sip_call_id: "bleg-callid".to_string(),
            local_addr: "10.0.0.9:5060".to_string(),
            failover_trunks: vec![],
            a_leg_via: vec!["SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK-a".to_string()],
            a_leg_from: "<sip:caller@10.0.0.1>;tag=callertag".to_string(),
            a_leg_to: "<sip:callee@sbc>".to_string(),
            a_leg_cseq: "1 INVITE".to_string(),
            b_leg_from: "<sip:sbc@10.0.0.9>;tag=sbctag".to_string(),
            b_leg_to: "<sip:callee@10.0.0.2>".to_string(),
            b_leg_branch: "z9hG4bK-b".to_string(),
            dialog_to_tag: Some("calleetag".to_string()),
            rtp_ports: vec![16_384, 16_385],
            media_a_leg_port: Some(16_384),
            media_a_leg_ip: "10.0.0.9".to_string(),
            dtls_caller_setup: None,
            dtls_caller_fingerprint: None,
            media_b_leg_ip: "10.0.0.9".to_string(),
            media_b_leg_port: 16_386,
            b_leg_answered: true,
            a_leg_local_cseq: 1,
            b_leg_local_cseq: 2,
            a_leg_last_sdp: None,
            b_leg_last_sdp: None,
            pending_reinvite: None,
            last_reinvite_ack: None,
            established_at: None,
        }
    }

    #[test]
    fn build_leg_bye_is_dialog_correct_for_both_legs() {
        let addrs = confirmed_call_addresses();

        // A-leg BYE: SBC as UAS toward the caller. From = our answered To + our
        // (callee) tag, To = the caller's From, CSeq in the A-leg space.
        let a = String::from_utf8(
            SipMessage::Request(SipStack::build_leg_bye(&addrs, false))
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(a.starts_with("BYE "), "{a}");
        assert!(a.contains("10.0.0.1"), "A-leg BYE targets the caller: {a}");
        assert!(a.contains("aleg-callid"));
        assert!(a.contains("1 BYE"));
        assert!(a.contains("tag=calleetag")); // our From tag
        assert!(a.contains("callertag")); // caller's tag in To

        // B-leg BYE: SBC as UAC toward the callee. From = our INVITE From, To =
        // the callee + their tag, CSeq 2 (after the INVITE).
        let b = String::from_utf8(
            SipMessage::Request(SipStack::build_leg_bye(&addrs, true))
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(b.contains("10.0.0.2"), "B-leg BYE targets the callee: {b}");
        assert!(b.contains("bleg-callid"));
        assert!(b.contains("2 BYE"));
        assert!(b.contains("tag=sbctag")); // our From tag
        assert!(b.contains("tag=calleetag")); // callee's tag in To
    }

    #[test]
    fn build_leg_reinvite_is_in_dialog_and_carries_the_offer() {
        let addrs = confirmed_call_addresses();
        let sdp = b"v=0\r\no=- 1 1 IN IP4 172.28.2.12\r\nc=IN IP4 172.28.2.12\r\nm=audio 16400 RTP/AVP 0\r\n";

        // A-leg re-INVITE: SBC as UAS toward the caller, same dialog as the BYE,
        // carrying the new media offer.
        let a_req =
            SipStack::build_leg_in_dialog_request(&addrs, false, &Method::Invite, 2, Some(sdp));
        assert_eq!(a_req.method, Method::Invite);
        let a = String::from_utf8(SipMessage::Request(a_req).to_bytes().to_vec()).unwrap();
        assert!(a.starts_with("INVITE "), "{a}");
        assert!(
            a.contains("10.0.0.1"),
            "A-leg re-INVITE targets the caller: {a}"
        );
        assert!(a.contains("aleg-callid"));
        assert!(a.contains("2 INVITE"));
        assert!(a.contains("tag=calleetag")); // our From tag (same dialog)
        assert!(a.contains("callertag")); // caller's tag in To
        assert!(a.contains("application/sdp"));
        assert!(a.contains("Contact:"));
        assert!(
            a.contains("172.28.2.12"),
            "carries the new node's media offer: {a}"
        );

        // B-leg re-INVITE: SBC as UAC toward the callee.
        let b = String::from_utf8(
            SipMessage::Request(SipStack::build_leg_in_dialog_request(
                &addrs,
                true,
                &Method::Invite,
                3,
                Some(sdp),
            ))
            .to_bytes()
            .to_vec(),
        )
        .unwrap();
        assert!(b.starts_with("INVITE "));
        assert!(
            b.contains("10.0.0.2"),
            "B-leg re-INVITE targets the callee: {b}"
        );
        assert!(b.contains("bleg-callid"));
        assert!(b.contains("3 INVITE"));
        assert!(b.contains("tag=calleetag")); // callee's tag in To
        assert!(b.contains("172.28.2.12"));
    }

    // ------------------------------------------------------------------
    // Transaction driving and mid-dialog relay (issue #117)
    // ------------------------------------------------------------------

    use std::fmt::Write as _;

    const ALICE_SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n";
    const BOB_SDP: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\na=sendrecv\r\n";

    fn alice() -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5060)
    }

    fn bob() -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060)
    }

    /// A request from alice (A-leg) on the test call's dialog.
    fn alice_request(method: &str, cseq: u32, to_tag: Option<&str>, body: Option<&str>) -> Bytes {
        let to = to_tag.map_or_else(
            || "<sip:bob@sbc.local>".to_string(),
            |t| format!("<sip:bob@sbc.local>;tag={t}"),
        );
        let mut msg = format!(
            "{method} sip:bob@sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-alice-{cseq}-{method}\r\n\
             From: <sip:alice@example.com>;tag=i1\r\n\
             To: {to}\r\n\
             Call-ID: call-relay@test\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@192.168.1.1:5060>\r\n\
             Supported: timer\r\n\
             Session-Expires: 1800\r\n"
        );
        match body {
            Some(b) => drop(write!(
                msg,
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )),
            None => msg.push_str("Content-Length: 0\r\n\r\n"),
        }
        Bytes::from(msg)
    }

    /// A response from the far end to a request the SBC forwarded it,
    /// mirroring that request's Via/From/To/Call-ID/CSeq (what a UAS does).
    fn response_to(
        req: &proto_sip::message::SipRequest,
        status: u16,
        to_tag: Option<&str>,
        body: Option<&str>,
    ) -> Bytes {
        let mut msg = format!("SIP/2.0 {status} Whatever\r\n");
        for via in req.headers.get_all(&HeaderName::Via) {
            let _ = write!(msg, "Via: {}\r\n", via.value);
        }
        let to = req.headers.get_value(&HeaderName::To).unwrap();
        let to = match to_tag {
            Some(t) if !to.contains("tag=") => format!("{to};tag={t}"),
            _ => to.to_string(),
        };
        let _ = write!(
            msg,
            "From: {}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: {}\r\n",
            req.headers.get_value(&HeaderName::From).unwrap(),
            req.headers.call_id().unwrap(),
            req.headers.cseq().unwrap(),
        );
        match body {
            Some(b) => drop(write!(
                msg,
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )),
            None => msg.push_str("Content-Length: 0\r\n\r\n"),
        }
        Bytes::from(msg)
    }

    /// An in-dialog request from bob (B-leg) toward the SBC, built from the
    /// dialog the forwarded INVITE established (bob's tag is `bobtag`).
    fn bob_request(
        b_invite: &proto_sip::message::SipRequest,
        method: &str,
        cseq: u32,
        body: Option<&str>,
    ) -> Bytes {
        let from = format!(
            "{};tag=bobtag",
            b_invite.headers.get_value(&HeaderName::To).unwrap()
        );
        let to = b_invite.headers.get_value(&HeaderName::From).unwrap();
        let mut msg = format!(
            "{method} sip:sbc@sbc.local:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-bob-{cseq}-{method}\r\n\
             From: {from}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: {cseq} {method}\r\n\
             Contact: <sip:bob@127.0.0.1:5060>\r\n",
            b_invite.headers.call_id().unwrap()
        );
        match body {
            Some(b) => drop(write!(
                msg,
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )),
            None => msg.push_str("Content-Length: 0\r\n\r\n"),
        }
        Bytes::from(msg)
    }

    fn flatten(result: ProcessResult) -> Vec<ProcessResult> {
        match result {
            ProcessResult::Multiple(v) => v.into_iter().flat_map(flatten).collect(),
            ProcessResult::NoAction => Vec::new(),
            other => vec![other],
        }
    }

    fn forwarded<'a>(
        results: &'a [ProcessResult],
        method: &Method,
    ) -> Option<(&'a proto_sip::message::SipRequest, SbcSocketAddr)> {
        results.iter().find_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                destination,
            } if req.method == *method => Some((req, *destination)),
            _ => None,
        })
    }

    fn responded(
        results: &[ProcessResult],
        status: u16,
    ) -> Option<(&proto_sip::message::SipResponse, SbcSocketAddr)> {
        results.iter().find_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                destination,
            } if resp.status.code() == status => Some((resp, *destination)),
            _ => None,
        })
    }

    /// Registers bob, admits alice's trunk, and sends alice's INVITE; returns
    /// the stack and the INVITE the SBC forwarded to bob.
    async fn ringing_call() -> (SipStack, proto_sip::message::SipRequest) {
        let stack = SipStack::new(SipStackConfig::default());
        stack
            .register_inbound_trunk("test-trunk", None, &[("192.168.1.1".to_string(), 5060)])
            .await;
        let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reg\r\n\
            From: <sip:bob@sbc.local>;tag=r1\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: reg-bob@relay\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:bob@127.0.0.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\
            \r\n";
        stack
            .process_message(&Bytes::from_static(register), bob(), None)
            .await;

        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 100).is_some(), "100 Trying to alice");
        let (b_invite, dest) = forwarded(&results, &Method::Invite).expect("INVITE forwarded");
        assert_eq!(dest, bob());
        assert!(
            b_invite
                .headers
                .get_value(&HeaderName::Supported)
                .is_some_and(|s| s.contains("timer")),
            "RFC 4028 support relayed on the B-leg INVITE"
        );
        assert_eq!(
            b_invite.headers.get_value(&HeaderName::SessionExpires),
            Some("1800")
        );
        (stack, b_invite.clone())
    }

    /// `ringing_call` answered by bob (200 with SDP, tag `bobtag`) and ACKed
    /// by alice: a confirmed dialog on both legs.
    async fn established_call() -> (SipStack, proto_sip::message::SipRequest) {
        let (stack, b_invite) = ringing_call().await;
        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        let (ok, dest) = responded(&results, 200).expect("200 relayed to alice");
        assert_eq!(dest, alice());
        assert_eq!(ok.headers.call_id(), Some("call-relay@test"));
        assert_eq!(ok.headers.cseq(), Some("1 INVITE"));
        assert_eq!(ok.headers.to_tag().as_deref(), Some("bobtag"));
        let (ack, dest) = forwarded(&results, &Method::Ack).expect("ACK to bob");
        assert_eq!(dest, bob());
        assert_eq!(ack.headers.cseq(), Some("1 ACK"));
        assert_eq!(
            stack.pending_2xx.read().await.len(),
            1,
            "200 awaits alice's ACK"
        );

        let ack = alice_request("ACK", 1, Some("bobtag"), None);
        assert!(matches!(
            stack.process_message(&ack, alice(), None).await,
            ProcessResult::NoAction
        ));
        assert!(
            stack.pending_2xx.read().await.is_empty(),
            "ACK stops 2xx retransmission"
        );
        (stack, b_invite)
    }

    #[tokio::test]
    async fn reinvite_from_caller_round_trips_hold_and_resume() {
        let (stack, b_invite) = established_call().await;
        let hold_sdp = ALICE_SDP.replace("a=sendrecv", "a=sendonly");

        // Hold: alice re-INVITEs with sendonly → 100 to alice, re-INVITE to bob
        // in the B-leg dialog with the SBC's next CSeq there.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 2, Some("bobtag"), Some(&hold_sdp)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 100).is_some());
        let (b_reinvite, dest) = forwarded(&results, &Method::Invite).expect("re-INVITE to bob");
        assert_eq!(dest, bob());
        assert_eq!(b_reinvite.headers.call_id(), b_invite.headers.call_id());
        assert_eq!(b_reinvite.headers.cseq(), Some("2 INVITE"));
        assert_eq!(b_reinvite.headers.to_tag().as_deref(), Some("bobtag"));
        assert_eq!(
            b_reinvite.headers.get_value(&HeaderName::From),
            b_invite.headers.get_value(&HeaderName::From),
            "same B-leg dialog"
        );
        let body = String::from_utf8_lossy(b_reinvite.body.as_ref().unwrap()).to_string();
        assert!(
            body.contains("a=sendonly"),
            "hold survives the rewrite: {body}"
        );
        assert!(
            !body.contains("m=audio 4000 "),
            "media re-anchored at the SBC's B-leg port: {body}"
        );
        assert!(b_reinvite.headers.get_value(&HeaderName::Contact).is_some());

        // Bob answers the re-INVITE → 200 to alice (her dialog's headers), ACK to bob.
        let results = flatten(
            stack
                .process_message(
                    &response_to(b_reinvite, 200, None, Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        let (ok, dest) = responded(&results, 200).expect("200 relayed to alice");
        assert_eq!(dest, alice());
        assert_eq!(ok.headers.cseq(), Some("2 INVITE"));
        assert_eq!(ok.headers.call_id(), Some("call-relay@test"));
        assert!(
            ok.headers
                .get_value(&HeaderName::Via)
                .unwrap()
                .contains("z9hG4bK-alice-2-INVITE"),
            "alice's own Via"
        );
        assert!(ok.body.is_some(), "answer SDP relayed");
        let (ack, dest) = forwarded(&results, &Method::Ack).expect("ACK to bob");
        assert_eq!(dest, bob());
        assert_eq!(ack.headers.cseq(), Some("2 ACK"));
        assert_eq!(ack.headers.call_id(), b_invite.headers.call_id());

        // Alice ACKs; the pending change is cleared.
        stack
            .process_message(
                &alice_request("ACK", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        assert!(stack.pending_2xx.read().await.is_empty());

        // Resume: next re-INVITE uses the next B-leg CSeq.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        let (b_reinvite, _) = forwarded(&results, &Method::Invite).expect("resume re-INVITE");
        assert_eq!(b_reinvite.headers.cseq(), Some("3 INVITE"));
        let results = flatten(
            stack
                .process_message(
                    &response_to(b_reinvite, 200, None, Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 200).is_some());
        assert_eq!(
            forwarded(&results, &Method::Ack).unwrap().0.headers.cseq(),
            Some("3 ACK")
        );

        // A later BYE from alice continues the B-leg sequence.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("BYE", 4, Some("bobtag"), None),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 200).is_some());
        let (bye, _) = forwarded(&results, &Method::Bye).expect("BYE to bob");
        assert_eq!(bye.headers.cseq(), Some("4 BYE"));
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn reinvite_from_callee_is_relayed_to_caller() {
        let (stack, b_invite) = established_call().await;
        let hold_sdp = BOB_SDP.replace("a=sendrecv", "a=sendonly");

        let results = flatten(
            stack
                .process_message(
                    &bob_request(&b_invite, "INVITE", 7, Some(&hold_sdp)),
                    bob(),
                    None,
                )
                .await,
        );
        let (_, dest) = responded(&results, 100).expect("100 to bob");
        assert_eq!(dest, bob());
        let (a_reinvite, dest) = forwarded(&results, &Method::Invite).expect("re-INVITE to alice");
        assert_eq!(dest, alice());
        assert_eq!(a_reinvite.headers.call_id(), Some("call-relay@test"));
        assert_eq!(
            a_reinvite.headers.cseq(),
            Some("1 INVITE"),
            "SBC's first request toward alice"
        );
        assert_eq!(
            a_reinvite.headers.to_tag().as_deref(),
            Some("i1"),
            "alice's tag in To"
        );
        assert_eq!(
            a_reinvite.headers.from_tag().as_deref(),
            Some("bobtag"),
            "SBC's A-leg tag in From"
        );
        let body = String::from_utf8_lossy(a_reinvite.body.as_ref().unwrap()).to_string();
        assert!(body.contains("a=sendonly"));

        // Alice answers → 200 to bob in his dialog, ACK to alice.
        let results = flatten(
            stack
                .process_message(
                    &response_to(a_reinvite, 200, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        let (ok, dest) = responded(&results, 200).expect("200 relayed to bob");
        assert_eq!(dest, bob());
        assert_eq!(ok.headers.cseq(), Some("7 INVITE"));
        assert_eq!(ok.headers.call_id(), b_invite.headers.call_id());
        let (ack, dest) = forwarded(&results, &Method::Ack).expect("ACK to alice");
        assert_eq!(dest, alice());
        assert_eq!(ack.headers.cseq(), Some("1 ACK"));
        assert_eq!(ack.headers.call_id(), Some("call-relay@test"));

        // Bob's ACK clears the 2xx retransmission on his leg.
        stack
            .process_message(&bob_request(&b_invite, "ACK", 7, None), bob(), None)
            .await;
        assert!(stack.pending_2xx.read().await.is_empty());

        // A BYE from alice afterwards continues the SBC→alice sequence (2).
        let results = flatten(
            stack
                .process_message(&bob_request(&b_invite, "BYE", 8, None), bob(), None)
                .await,
        );
        let (bye, dest) = forwarded(&results, &Method::Bye).expect("BYE to alice");
        assert_eq!(dest, alice());
        assert_eq!(bye.headers.cseq(), Some("2 BYE"));
    }

    #[tokio::test]
    async fn body_less_refresh_is_answered_locally() {
        let (stack, _) = established_call().await;

        // UPDATE without SDP (RFC 4028 refresh): 200 with Session-Expires, nothing forwarded.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("UPDATE", 2, Some("bobtag"), None),
                    alice(),
                    None,
                )
                .await,
        );
        assert_eq!(results.len(), 1);
        let (ok, dest) = responded(&results, 200).expect("200 to UPDATE");
        assert_eq!(dest, alice());
        assert_eq!(ok.headers.cseq(), Some("2 UPDATE"));
        assert_eq!(
            ok.headers.get_value(&HeaderName::SessionExpires),
            Some("1800;refresher=uac")
        );
        assert_eq!(ok.headers.get_value(&HeaderName::Require), Some("timer"));
        assert!(ok.body.is_none());

        // Body-less re-INVITE: 200 carries the SDP alice last got from us.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 3, Some("bobtag"), None),
                    alice(),
                    None,
                )
                .await,
        );
        assert_eq!(results.len(), 1, "no 100 Trying needed, nothing forwarded");
        let (ok, _) = responded(&results, 200).expect("200 to refresh INVITE");
        assert!(ok.body.is_some(), "200 to an INVITE carries an offer");
        assert_eq!(
            ok.headers.get_value(&HeaderName::ContentType),
            Some("application/sdp")
        );
        assert_eq!(stack.pending_2xx.read().await.len(), 1);
        stack
            .process_message(
                &alice_request("ACK", 3, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        assert!(stack.pending_2xx.read().await.is_empty());
    }

    #[tokio::test]
    async fn update_with_sdp_is_relayed_without_ack() {
        let (stack, b_invite) = established_call().await;
        let results = flatten(
            stack
                .process_message(
                    &alice_request("UPDATE", 2, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(
            responded(&results, 100).is_none(),
            "no provisional for UPDATE"
        );
        let (b_update, dest) = forwarded(&results, &Method::Update).expect("UPDATE to bob");
        assert_eq!(dest, bob());
        assert_eq!(b_update.headers.cseq(), Some("2 UPDATE"));
        assert_eq!(b_update.headers.call_id(), b_invite.headers.call_id());

        let results = flatten(
            stack
                .process_message(
                    &response_to(b_update, 200, None, Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        let (ok, dest) = responded(&results, 200).expect("200 to alice");
        assert_eq!(dest, alice());
        assert_eq!(ok.headers.cseq(), Some("2 UPDATE"));
        assert!(
            forwarded(&results, &Method::Ack).is_none(),
            "UPDATE has no ACK"
        );
        assert!(
            stack.pending_2xx.read().await.is_empty(),
            "non-INVITE 2xx is not retransmitted by the TU"
        );
    }

    #[tokio::test]
    async fn glare_reinvite_gets_491_and_rejection_is_relayed() {
        let (stack, _) = established_call().await;
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        let (b_reinvite, _) = forwarded(&results, &Method::Invite).unwrap();
        let b_reinvite = b_reinvite.clone();

        // A second change while the first is in flight: 491 Request Pending.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("UPDATE", 3, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 491).is_some(), "RFC 3261 §14.2 glare");

        // Bob rejects the re-INVITE: the SBC ACKs him and relays the 488 to
        // alice; the call stays up.
        let results = flatten(
            stack
                .process_message(&response_to(&b_reinvite, 488, None, None), bob(), None)
                .await,
        );
        let (ack, dest) = forwarded(&results, &Method::Ack).expect("ACK for non-2xx");
        assert_eq!(dest, bob());
        assert_eq!(ack.headers.cseq(), Some("2 ACK"));
        assert_eq!(
            ack.headers.via_branch(),
            b_reinvite.headers.via_branch(),
            "non-2xx ACK belongs to the INVITE transaction (same branch)"
        );
        let (rej, dest) = responded(&results, 488).expect("488 relayed");
        assert_eq!(dest, alice());
        assert_eq!(rej.headers.cseq(), Some("2 INVITE"));
        assert_eq!(stack.call_count().await, 1);

        // Now a new change is accepted again.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 4, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(forwarded(&results, &Method::Invite).is_some());
    }

    #[tokio::test]
    async fn in_dialog_requests_for_unknown_dialogs_get_481() {
        let (stack, _) = established_call().await;
        let src = alice();
        for (method, body) in [
            ("INVITE", Some(ALICE_SDP)),
            ("UPDATE", None),
            ("INFO", None),
            ("BYE", None),
        ] {
            let msg = format!(
                "{method} sip:bob@sbc.local SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-unk-{method}\r\n\
                 From: <sip:alice@example.com>;tag=zz\r\n\
                 To: <sip:bob@sbc.local>;tag=nope\r\n\
                 Call-ID: no-such-dialog@test\r\n\
                 CSeq: 9 {method}\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.map_or(0, str::len),
                body.unwrap_or("")
            );
            let results = flatten(stack.process_message(&Bytes::from(msg), src, None).await);
            assert!(
                responded(&results, 481).is_some(),
                "{method} for unknown dialog → 481"
            );
        }
        // CANCEL that matches no INVITE transaction (RFC 3261 §9.2).
        let cancel = b"CANCEL sip:bob@sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-unk-CANCEL\r\n\
            From: <sip:alice@example.com>;tag=zz\r\n\
            To: <sip:bob@sbc.local>\r\n\
            Call-ID: no-such-invite@test\r\n\
            CSeq: 1 CANCEL\r\n\
            Content-Length: 0\r\n\r\n";
        let results = flatten(
            stack
                .process_message(&Bytes::from_static(cancel), src, None)
                .await,
        );
        assert!(responded(&results, 481).is_some());

        // Right Call-ID, wrong From tag: not this dialog either.
        let forged = alice_request("INVITE", 5, Some("bobtag"), Some(ALICE_SDP));
        let forged = Bytes::from(String::from_utf8_lossy(&forged).replace("tag=i1", "tag=evil"));
        let results = flatten(stack.process_message(&forged, src, None).await);
        assert!(
            responded(&results, 481).is_some(),
            "forged in-dialog request → 481"
        );
        assert_eq!(stack.call_count().await, 1, "call untouched");
    }

    #[tokio::test]
    async fn non_2xx_final_from_callee_is_acked_and_its_retransmits_absorbed() {
        let (stack, b_invite) = ringing_call().await;

        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 486, Some("bobtag"), None),
                    bob(),
                    None,
                )
                .await,
        );
        let (ack, dest) = forwarded(&results, &Method::Ack).expect("486 is ACKed (§17.1.1.3)");
        assert_eq!(dest, bob());
        assert_eq!(ack.headers.cseq(), Some("1 ACK"));
        assert_eq!(ack.headers.via_branch(), b_invite.headers.via_branch());
        assert_eq!(ack.headers.to_tag().as_deref(), Some("bobtag"));
        let (busy, dest) = responded(&results, 486).expect("486 relayed to alice");
        assert_eq!(dest, alice());
        assert_eq!(busy.headers.call_id(), Some("call-relay@test"));
        assert_eq!(stack.call_count().await, 0);

        // Bob retransmits the 486 (our ACK was lost): ACK again, but alice
        // must not get a second 486 from the TU.
        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 486, Some("bobtag"), None),
                    bob(),
                    None,
                )
                .await,
        );
        assert!(forwarded(&results, &Method::Ack).is_some(), "re-ACK");
        assert!(responded(&results, 486).is_none(), "TU not re-driven");

        // Alice retransmits her INVITE before ACKing: the server transaction
        // answers with the stored 486 instead of starting a new call.
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 486).is_some(), "stored final re-sent");
        assert!(forwarded(&results, &Method::Invite).is_none());
        assert_eq!(stack.call_count().await, 0);

        // Alice's ACK (same branch as her INVITE) completes the transaction;
        // a further INVITE retransmit is then absorbed silently.
        let ack = alice_request("ACK", 1, Some("bobtag"), None);
        let ack = Bytes::from(
            String::from_utf8_lossy(&ack).replace("z9hG4bK-alice-1-ACK", "z9hG4bK-alice-1-INVITE"),
        );
        assert!(matches!(
            stack.process_message(&ack, alice(), None).await,
            ProcessResult::NoAction
        ));
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert!(results.is_empty(), "absorbed in Confirmed: {results:?}");
    }

    #[tokio::test]
    async fn invite_retransmit_while_proceeding_resends_100_trying() {
        let (stack, _) = ringing_call().await;
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        assert_eq!(results.len(), 1, "{results:?}");
        let (_, dest) = responded(&results, 100).expect("last provisional re-sent (§17.2.1)");
        assert_eq!(dest, alice());
        assert_eq!(stack.call_count().await, 1, "no second call");
    }

    #[tokio::test]
    async fn timers_retransmit_the_invite_and_a_lost_final_response() {
        let (stack, b_invite) = ringing_call().await;

        // Nothing fires before T1.
        assert!(stack.poll_timers().await.is_empty());

        // Timer A (T1 = 500 ms): the B-leg INVITE is retransmitted unchanged.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        let (again, dest) = forwarded(&results, &Method::Invite).expect("Timer A retransmit");
        assert_eq!(dest, bob());
        assert_eq!(again.headers.via_branch(), b_invite.headers.via_branch());
        assert_eq!(again.headers.cseq(), Some("1 INVITE"));

        // Bob answers 486; the 486 toward alice is retransmitted on Timer G
        // until she ACKs (a lost final response).
        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 486, Some("bobtag"), None),
                    bob(),
                    None,
                )
                .await,
        );
        let (first, _) = responded(&results, 486).unwrap();
        let first_to = first
            .headers
            .get_value(&HeaderName::To)
            .unwrap()
            .to_string();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        let (retrans, dest) = responded(&results, 486).expect("Timer G retransmit");
        assert_eq!(dest, alice());
        assert_eq!(
            retrans.headers.get_value(&HeaderName::To),
            Some(first_to.as_str()),
            "identical copy"
        );
        assert!(
            forwarded(&results, &Method::Invite).is_none(),
            "client transaction completed, no more Timer A"
        );

        // Alice ACKs → Confirmed → no further retransmission.
        let ack = alice_request("ACK", 1, Some("bobtag"), None);
        let ack = Bytes::from(
            String::from_utf8_lossy(&ack).replace("z9hG4bK-alice-1-ACK", "z9hG4bK-alice-1-INVITE"),
        );
        stack.process_message(&ack, alice(), None).await;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let results = stack.poll_timers().await;
        assert!(responded(&results, 486).is_none(), "{results:?}");
    }

    #[tokio::test]
    async fn two_hundred_is_retransmitted_until_acked() {
        let (stack, b_invite) = ringing_call().await;
        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        let (ok, _) = responded(&results, 200).unwrap();
        let ok_cl = ok
            .headers
            .get_value(&HeaderName::ContentLength)
            .unwrap()
            .to_string();

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        let (again, dest) = responded(&results, 200).expect("2xx retransmitted (§13.3.1.4)");
        assert_eq!(dest, alice());
        assert_eq!(
            again.headers.get_value(&HeaderName::ContentLength),
            Some(ok_cl.as_str())
        );
        assert!(again.body.is_some());

        // Bob also retransmits his 200 (our ACK lost): re-ACK only, no new 200
        // to alice and the call is activated once.
        let results = flatten(
            stack
                .process_message(
                    &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
                    bob(),
                    None,
                )
                .await,
        );
        assert!(forwarded(&results, &Method::Ack).is_some());
        assert!(responded(&results, 200).is_none());

        stack
            .process_message(
                &alice_request("ACK", 1, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(stack.poll_timers().await.is_empty());
        assert_eq!(stack.call_count().await, 1);
    }

    #[tokio::test]
    async fn per_user_rate_limit_answers_503_with_retry_after() {
        let mut stack = SipStack::new(SipStackConfig::default());
        stack.set_user_rate_limiter(uc_dos_protection::KeyedRateLimiter::new(1, 1));
        let options = |user: &str, n: u32| {
            Bytes::from(format!(
                "OPTIONS sip:sbc.local SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-rl-{user}-{n}\r\n\
                 From: <sip:{user}@example.com>;tag={n}\r\n\
                 To: <sip:sbc.local>\r\n\
                 Call-ID: rl-{user}-{n}@test\r\n\
                 CSeq: 1 OPTIONS\r\n\
                 Content-Length: 0\r\n\r\n"
            ))
        };
        let first = flatten(
            stack
                .process_message(&options("alice", 1), alice(), None)
                .await,
        );
        assert!(responded(&first, 200).is_some());
        let second = flatten(
            stack
                .process_message(&options("alice", 2), alice(), None)
                .await,
        );
        let (resp, dest) = responded(&second, 503).expect("over the per-user rate");
        assert_eq!(dest, alice());
        assert_eq!(resp.headers.get_value(&HeaderName::RetryAfter), Some("1"));
        // Another user from the same address is unaffected.
        let other = flatten(
            stack
                .process_message(&options("bob", 1), alice(), None)
                .await,
        );
        assert!(responded(&other, 200).is_some());
    }

    #[tokio::test]
    async fn options_allow_lists_update() {
        let stack = SipStack::new(SipStackConfig::default());
        let options = b"OPTIONS sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-opt\r\n\
            From: <sip:alice@example.com>;tag=1\r\n\
            To: <sip:sbc.local>\r\n\
            Call-ID: opt@test\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\r\n";
        let results = flatten(
            stack
                .process_message(&Bytes::from_static(options), alice(), None)
                .await,
        );
        let (ok, _) = responded(&results, 200).unwrap();
        assert!(
            ok.headers
                .get_value(&HeaderName::Allow)
                .unwrap()
                .contains("UPDATE")
        );
    }

    #[tokio::test]
    async fn terminate_call_on_media_failure_byes_both_legs_and_cleans_up() {
        let stack = SipStack::new(SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        });

        let internal = CallId::new("call-1");
        let addrs = confirmed_call_addresses();
        {
            let mut corr = stack.call_correlation.write().await;
            corr.a_leg
                .insert(addrs.a_leg_sip_call_id.clone(), internal.clone());
            corr.b_leg
                .insert(addrs.b_leg_sip_call_id.clone(), internal.clone());
            corr.addresses.insert(internal.clone(), addrs.clone());
        }

        let byes = stack.terminate_call_on_media_failure("call-1").await;
        assert_eq!(byes.len(), 2, "must BYE both legs");
        assert_eq!(byes[0].1.to_string(), addrs.a_leg_source.to_string());
        assert_eq!(byes[1].1.to_string(), addrs.b_leg_destination.to_string());

        // Call state is removed.
        let corr = stack.call_correlation.read().await;
        assert!(!corr.addresses.contains_key(&internal));
        assert!(!corr.a_leg.contains_key(&addrs.a_leg_sip_call_id));
        assert!(!corr.b_leg.contains_key(&addrs.b_leg_sip_call_id));
    }

    #[tokio::test]
    async fn terminate_call_on_media_failure_is_a_noop_for_unknown_call() {
        let stack = SipStack::new(SipStackConfig {
            domain: "sbc.test".to_string(),
            ..Default::default()
        });
        assert!(
            stack
                .terminate_call_on_media_failure("nope")
                .await
                .is_empty()
        );
    }
}
