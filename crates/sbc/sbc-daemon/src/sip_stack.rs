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

use crate::flow::{Flow, LegFlow};
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
use proto_transaction::client::ClientInviteState as ClientInvitePhase;
use proto_transaction::timer::TimerType;
use proto_transaction::{
    ClientInviteTransaction, ClientNonInviteTransaction, ServerInviteTransaction,
    ServerNonInviteTransaction, TransactionKey, TransportType,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uc_routing::{
    Admission, DestinationType, DialPattern, DialPlan, DialPlanEntry, Direction, NumberTransform,
    Router, RouterConfig, RoutingError, SelectionStrategy, Trunk, TrunkConfig, TrunkGroup,
    TrunkOutcome, TrunkProtocol,
};
use uc_types::address::SbcSocketAddr;
use uc_types::address::TransportType as AddrTransport;

/// SIP stack for processing SIP messages.
pub struct SipStack {
    /// Transaction store.
    transactions: RwLock<TransactionStore>,
    /// Dialog store.
    dialogs: RwLock<DialogStore>,
    /// Call store (B2BUA).
    calls: RwLock<CallStore>,
    /// `general.max_calls` slots held by stored calls plus INVITEs being
    /// admitted (see [`CallSlot`]). Always `>= calls.len()`.
    admitted_calls: Arc<AtomicUsize>,
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
    /// Directory number mapping: DID → username for inbound call routing,
    /// with the reverse user → TN index the STIR binding uses.
    did_map: RwLock<crate::stir_binding::DidMap>,
    /// Received REGISTER flow → AORs, so the STIR binding of an endpoint
    /// INVITE is O(1) (SEC-008). Bounded by `max_registrations`.
    stir_flows: RwLock<crate::stir_binding::StirFlows>,
    /// Call-IDs currently being played an announcement (dedup retransmits).
    /// Arc so the spawned playback task can remove its entry when done —
    /// previously entries were never removed (unbounded growth from
    /// unroutable INVITEs).
    announcement_calls: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
    /// Voice Protection System engine for pre-routing call screening
    /// (see docs/VPS-ARCHITECTURE.md). Mutex: screening mutates rate
    /// counters and stats.
    vps: Option<tokio::sync::Mutex<uc_vps::VpsEngine>>,
    /// STIR/SHAKEN signing and verification (None when both are disabled).
    stir: Option<Arc<crate::stir::StirService>>,
    /// Registration statistics.
    registrations_active: AtomicU64,
    registrations_total: AtomicU64,
    /// Draining: reject new INVITEs (503) while existing calls finish.
    draining: std::sync::atomic::AtomicBool,
    /// Emergency INVITEs admitted past screening (47 CFR 9.16 bypass).
    /// Exported as a metric so an emergency flood is visible (SI-4).
    emergency_admissions: AtomicU64,
    /// B-leg INVITE branches whose send succeeded (see `on_invite_sent`).
    first_send_ok: FirstSendLedger,
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
    /// CDR pipeline (`[cdr]`). `None` when CDRs are disabled.
    ///
    /// ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
    cdr: Option<Arc<crate::cdr::CdrContext>>,
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
    /// Maximum registration bindings held by this node
    /// (`general.max_registrations`). A REGISTER that would add bindings
    /// past it gets 503 + Retry-After; refreshes and de-registrations are
    /// always accepted.
    pub max_registrations: u32,
    /// Extra concurrent calls above `max_calls` that only emergency calls
    /// may use (`general.emergency_reserve_calls`). Emergency INVITEs past
    /// `max_calls + emergency_reserve_calls` get 503 (SC-5).
    pub emergency_reserve_calls: u32,
    /// Emergency numbers (`[vps] emergency_numbers`): may use the
    /// emergency reserve above `max_calls` and trunk `max_calls`, and skip
    /// VPS number/caller screening (47 CFR 9.16).
    pub emergency_numbers: uc_vps::EmergencyNumbers,
    /// Bound on a trunk's 503 `Retry-After` honoured as its cooldown
    /// (`general.trunk_retry_after_max_secs`, RFC 3261 §21.5.4).
    pub trunk_retry_after_max_secs: u32,
    /// SBC listener ports per transport, advertised in Via sent-by and
    /// Contact (`transport.udp_listen` / `tcp_listen` / `tls_listen`).
    pub udp_port: u16,
    /// TCP listener port.
    pub tcp_port: u16,
    /// TLS listener port.
    pub tls_port: u16,
    /// WebSocket listener port (`transport.ws_listen`, RFC 7118).
    pub ws_port: u16,
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
            emergency_reserve_calls: sbc_config::schema::default_emergency_reserve(1000),
            max_registrations: 50_000,
            emergency_numbers: uc_vps::EmergencyNumbers::new(&uc_vps::default_emergency_numbers()),
            trunk_retry_after_max_secs: sbc_config::schema::DEFAULT_TRUNK_RETRY_AFTER_MAX_SECS,
            udp_port: 5060,
            tcp_port: 5060,
            tls_port: 5061,
            ws_port: 5062,
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
    /// Transport the request arrived on; Timer G re-sends ride it.
    flow: LegFlow,
    created_at: Instant,
    /// Last response sent on this transaction: re-sent on an INVITE
    /// retransmission (RFC 3261 §17.2.1) and, for a non-2xx final, on
    /// Timer G until the ACK arrives.
    last_response: Option<SipMessage>,
    /// Call-ID of the request that opened the transaction; a later request
    /// with the same branch but another Call-ID is a new request.
    call_id: String,
}

/// State for server non-INVITE transaction.
struct ServerNonInviteState {
    transaction: ServerNonInviteTransaction,
    source: SbcSocketAddr,
    created_at: Instant,
    /// Last response sent; re-sent on a request retransmission (§17.2.2).
    last_response: Option<SipMessage>,
    /// Call-ID of the request that opened the transaction (see
    /// `ServerInviteState::call_id`).
    call_id: String,
}

/// State for client INVITE transaction.
struct ClientInviteState {
    transaction: ClientInviteTransaction,
    destination: SbcSocketAddr,
    /// Transport the INVITE is sent on; Timer A re-sends ride it and it
    /// selects the reliable/unreliable timers (RFC 3261 §17.1.1.2).
    flow: LegFlow,
    created_at: Instant,
    /// The INVITE on the wire, retransmitted on Timer A (§17.1.1.2).
    request: SipMessage,
    /// ACK for a non-2xx final (§17.1.1.3), re-sent when that final is
    /// retransmitted.
    ack: Option<SipMessage>,
    /// Call this INVITE belongs to (Timer B fails it).
    call: CallId,
    /// The first send's outcome has not been reported yet; only that send
    /// failing triggers failover (see `SipStack::on_invite_sent`).
    initial_send_pending: bool,
    /// Timer A has re-sent the INVITE, so a send failure may be the
    /// retransmission's rather than the first send's.
    retransmitted: bool,
}

/// Slots in [`FirstSendLedger`]; bounded (SC-5), independent of load.
const FIRST_SEND_SLOTS: usize = 1024;

/// Lock-free record of B-leg INVITE branches whose send succeeded, so a
/// failure reported after Timer A can be told apart: a retransmission
/// failure after a good first send stays log-only, a slow first send that
/// fails after Timer A still fails over (Decision 4).
///
/// Each branch hashes (keyed `RandomState`, attacker-chosen branches cannot
/// target a slot) to one `AtomicU64` slot holding the hash. A slot can be
/// overwritten by a later branch; the record is then lost and that branch's
/// failure is treated as a first-send failure (fails over), which is the
/// safe direction.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), CP-8
struct FirstSendLedger {
    hasher: std::collections::hash_map::RandomState,
    slots: Box<[AtomicU64]>,
}

impl FirstSendLedger {
    fn new() -> Self {
        Self {
            hasher: std::collections::hash_map::RandomState::new(),
            slots: (0..FIRST_SEND_SLOTS).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Non-zero keyed hash of `branch` and its slot index.
    fn locate(&self, branch: &str) -> (usize, u64) {
        use std::hash::BuildHasher;
        let h = self.hasher.hash_one(branch) | 1;
        // The remainder is < FIRST_SEND_SLOTS, so it always fits a usize.
        let idx = usize::try_from(h % FIRST_SEND_SLOTS as u64).unwrap_or(0);
        (idx, h)
    }

    fn record(&self, branch: &str) {
        let (idx, h) = self.locate(branch);
        if let Some(slot) = self.slots.get(idx) {
            slot.store(h, Ordering::Release);
        }
    }

    fn contains(&self, branch: &str) -> bool {
        let (idx, h) = self.locate(branch);
        self.slots
            .get(idx)
            .is_some_and(|slot| slot.load(Ordering::Acquire) == h)
    }
}

/// State for client non-INVITE transaction.
struct ClientNonInviteState {
    transaction: ClientNonInviteTransaction,
    destination: SbcSocketAddr,
    /// Transport the request is sent on (Timer E re-sends, §17.1.2.2).
    flow: LegFlow,
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
///
/// Each call holds the admission slot it was admitted with, so the slot is
/// released exactly when the call leaves the store (SC-5).
#[derive(Default)]
struct CallStore {
    /// Calls indexed by call ID.
    calls: HashMap<CallId, CallEntry>,
}

/// A stored call and the `general.max_calls` slot it holds.
struct CallEntry {
    call: Call,
    _slot: CallSlot,
}

impl CallStore {
    fn get_mut(&mut self, id: &CallId) -> Option<&mut Call> {
        self.calls.get_mut(id).map(|e| &mut e.call)
    }

    fn insert(&mut self, id: CallId, call: Call, slot: CallSlot) {
        self.calls.insert(id, CallEntry { call, _slot: slot });
    }

    /// Removes a call; dropping the entry releases its admission slot.
    fn remove(&mut self, id: &CallId) {
        self.calls.remove(id);
    }

    fn len(&self) -> usize {
        self.calls.len()
    }
}

/// One reserved `general.max_calls` admission slot. Taken atomically at
/// INVITE admission and released on drop, so every rejection or failure
/// path before the call is stored (and the call's removal afterwards)
/// frees it without per-path code.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
struct CallSlot(Arc<AtomicUsize>);

impl Drop for CallSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// Transaction timer mode for a SIP transport: connection-oriented
/// transports (TCP, TLS, WS, WSS, SCTP) are reliable, UDP is not.
///
/// ## RFC 3261 §17.1.1.2, §17.1.2.2, §17.2.1
const fn txn_transport(t: AddrTransport) -> TransportType {
    if t.is_connection_oriented() {
        TransportType::Reliable
    } else {
        TransportType::Unreliable
    }
}

/// Reserves one slot on `counter` if fewer than `ceiling` are held. The
/// check and the increment are one CAS, so concurrent INVITEs cannot
/// overshoot the ceiling.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
fn try_reserve_slot(counter: &Arc<AtomicUsize>, ceiling: usize) -> Option<CallSlot> {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
            (cur < ceiling).then_some(cur + 1)
        })
        .ok()
        .map(|_| CallSlot(Arc::clone(counter)))
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
    /// Transport of the A-leg: the one the INVITE arrived on. Everything
    /// toward the caller (responses, BYE, re-INVITE, timer 408) uses it.
    a_leg_flow: LegFlow,
    /// Transport of the B-leg: the trunk's configured protocol (or the
    /// registered contact's transport). Replaced with `b_leg_destination`
    /// on failover.
    ///
    /// ## NIST 800-53 Rev5: SC-8; RFC 3261 §18.1.1, §26.2
    b_leg_flow: LegFlow,
    /// SBC sent-by (`host:port`) for A-leg Via/Contact, the listener of the
    /// A-leg transport (RFC 3261 §18.1.1).
    a_leg_local_addr: String,
    /// A-leg SIP Call-ID.
    a_leg_sip_call_id: String,
    /// B-leg SIP Call-ID.
    b_leg_sip_call_id: String,
    /// SBC's local SIP address (`host:port` of the B-leg transport's
    /// listener) for B-leg Via/Contact headers.
    local_addr: String,
    /// Remaining failover targets `(trunk_group_id, trunk_id)`, in try
    /// order, for retrying the initial INVITE when the B-leg trunk fails.
    failover_targets: Vec<(String, String)>,
    /// Per-trunk `max_calls` slot this call holds. Released exactly once,
    /// by whoever removes this record from `call_correlation.addresses`.
    trunk_lease: Option<TrunkLease>,
    /// VPS per-callee concurrency slot (dialed number) this call holds;
    /// released with the record like `trunk_lease`.
    vps_callee: Option<String>,
    /// The initial B-leg INVITE as built (translated user, rewritten SDP,
    /// manipulated headers). Kept only when failover targets exist; a
    /// failover re-sends it with a fresh Call-ID, branch and From tag.
    b_leg_invite: Option<Arc<SipRequest>>,
    /// Request-URI of the current B-leg INVITE attempt (primary, or the
    /// failover that replaced it). RFC 3261 §9.1: a CANCEL's Request-URI
    /// MUST be identical to the INVITE it cancels.
    b_leg_ruri: Option<SipUri>,
    /// STIR facts to redo the B-leg STIR step on failover (kept with
    /// `b_leg_invite`, which is stored before that step).
    stir_egress: Option<Arc<crate::stir::StirEgress>>,
    /// A reliable (RSeq) 18x carrying SDP was relayed to the caller: the
    /// early media is committed to this trunk, so no more failover.
    early_media_committed: bool,
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
    last_reinvite_ack: Option<(String, SipMessage, SbcSocketAddr, LegFlow)>,
    /// When the B-leg answered (for the audit trail's call duration).
    established_at: Option<Instant>,
    /// CDR facts gathered over the call's life; emitted once by
    /// `finish_call_record`.
    ///
    /// ## NIST 800-53 Rev5: AU-3, AU-12
    cdr: crate::cdr::CdrDraft,
}

impl CallAddresses {
    /// Flow of one leg: the callee's (`target_b_leg`) or the caller's.
    fn leg_flow(&self, target_b_leg: bool) -> LegFlow {
        if target_b_leg {
            self.b_leg_flow.clone()
        } else {
            self.a_leg_flow.clone()
        }
    }

    /// Destination and flow of one leg.
    fn leg_target(&self, target_b_leg: bool) -> (SbcSocketAddr, LegFlow) {
        if target_b_leg {
            (self.b_leg_destination, self.b_leg_flow.clone())
        } else {
            (self.a_leg_source, self.a_leg_flow.clone())
        }
    }

    /// SBC sent-by for Via/Contact on one leg (RFC 3261 §18.1.1).
    fn leg_sent_by(&self, target_b_leg: bool) -> &str {
        if target_b_leg {
            &self.local_addr
        } else {
            &self.a_leg_local_addr
        }
    }
}

/// A per-trunk call slot (`trunk_groups[].trunks[].max_calls`) held by a
/// call.
#[derive(Clone, Debug)]
struct TrunkLease {
    group_id: String,
    trunk_id: String,
    /// When the slot was taken (INVITE sent), for setup-time statistics.
    started: Instant,
    /// Emergency calls take slots past `max_calls`, failover included.
    admission: Admission,
}

/// A call routed to a trunk: the reserved slot, where to send the INVITE,
/// what is left to fail over to and the number to put on the wire.
struct TrunkRoute {
    lease: TrunkLease,
    destination: SbcSocketAddr,
    /// The trunk's Request-URI host/port and flow.
    endpoint: TrunkEndpoint,
    failover: Vec<(String, String)>,
    /// Destination number after SBC-router / dial-plan transforms.
    translated: String,
}

/// Outcome of trunk routing for an INVITE no registered user answers.
enum TrunkRouting {
    Routed(Box<TrunkRoute>),
    /// No pattern / dial plan entry / trunk group matches the number.
    NoRoute,
    /// A route matched but every trunk is down, cooling down or at
    /// `max_calls`.
    Unavailable,
    /// The transformed number is unsafe to put in a Request-URI.
    InvalidTranslation,
}

/// `Retry-After` (seconds) on the 503 sent when every trunk of the matched
/// route is full or down (RFC 3261 §21.5.4).
const TRUNK_UNAVAILABLE_RETRY_AFTER_SECS: u32 = 5;

/// `Retry-After` (seconds) on the 503 sent when `general.max_registrations`
/// is reached (RFC 3261 §21.5.4).
const REGISTRATION_CAPACITY_RETRY_AFTER_SECS: u32 = 60;

/// Longest translated user part put on a B-leg Request-URI.
const MAX_B_LEG_USER_LEN: usize = 64;

/// Whether a translated number is safe as a B-leg Request-URI / To user.
///
/// Transforms (dial plan prefix rules, SBC route-pattern masks) run on the
/// attacker-controlled dialed digits, so the result is checked before it
/// goes on the wire. Accepts the RFC 3261 §25.1 `unreserved` set plus the
/// `user-unreserved` characters that cannot end the user part; `;`, `?` and
/// `/` (parameter/header delimiters downstream), `%` escapes, `@`, `<`, `>`,
/// whitespace and CR/LF are rejected.
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
fn is_safe_b_leg_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= MAX_B_LEG_USER_LEN
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.!~*'()&=+$,".contains(&b))
}

/// B-leg final statuses that fail the call over to the next trunk: the
/// trunk (not the callee) failed. Never 486/other 4xx/6xx — failing over
/// on a callee's reject would ring the callee through other carriers.
///
/// RFC 3263 §4.3 names only 503 and timeouts (408 / Timer B, which also
/// fails over) as next-server triggers. Failing over on 500, 502 and 504
/// is local B2BUA policy beyond RFC 3263; the B-leg retry is a new UAC
/// request, so it is permitted. A trunk URI that does not resolve also
/// moves to the next target, and so does a failed first send of the
/// INVITE (RFC 3261 §8.1.3.1, see `SipStack::on_invite_sent`).
const fn is_failover_status(status: u16) -> bool {
    matches!(status, 408 | 500 | 502 | 503 | 504)
}

/// Why the current B-leg attempt of a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailoverCause {
    /// A failover final status, with the trunk's bounded `Retry-After`
    /// (503 only).
    Status(u16, Option<std::time::Duration>),
    /// Timer B (RFC 3261 §17.1.1.2).
    Timeout,
    /// The first send of the INVITE failed (RFC 3261 §8.1.3.1).
    TransportError,
}

impl FailoverCause {
    /// The failed attempt's outcome for the CDR `trunks_tried` list.
    const fn cdr_outcome(self) -> uc_cdr::TrunkOutcome {
        match self {
            Self::Status(code, _) => uc_cdr::TrunkOutcome::Status(code),
            Self::Timeout => uc_cdr::TrunkOutcome::Timeout,
            Self::TransportError => uc_cdr::TrunkOutcome::TransportError,
        }
    }

    fn audit_reason(self) -> uc_audit::event::FailoverReason {
        match self {
            Self::Status(code, _) => uc_audit::event::FailoverReason::Status(code),
            Self::Timeout => uc_audit::event::FailoverReason::Timeout,
            Self::TransportError => uc_audit::event::FailoverReason::TransportError,
        }
    }
}

/// The cooldown a trunk's 503 asks for: its `Retry-After` delta-seconds
/// (RFC 3261 §20.33; a trailing comment or `;duration` is ignored), clamped
/// to `max_secs`. `None` (use `cooldown_secs`) when the header is absent,
/// not delta-seconds, or 0. After the digits and optional LWS, only the end
/// of the value, a balanced `( comment )` (then optional LWS and end or
/// `;params`), or `;params` may follow (RFC 3261 §25.1
/// `Retry-After = delta-seconds [ comment ] *( SEMI retry-param )`), so
/// `1e9`, `120 abc`, `120 )` or `120 (unclosed` are invalid rather than read
/// as a number.
///
/// RFC 3261 §21.5.4: a client SHOULD honour Retry-After on 503. The clamp
/// keeps a hostile or buggy trunk from taking itself out indefinitely.
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation), SC-5
fn retry_after_cooldown(resp: &SipResponse, max_secs: u32) -> Option<std::time::Duration> {
    let value = resp
        .headers
        .get_value(&HeaderName::RetryAfter)?
        .trim_start();
    let digits = value
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(value.len());
    let delta = value.get(..digits).filter(|d| !d.is_empty())?;
    if !retry_after_tail_ok(value.as_bytes().get(digits..).unwrap_or_default()) {
        return None;
    }
    // Leading digits only: anything longer than u64 saturates (and is
    // clamped below anyway).
    let secs = delta.parse::<u64>().unwrap_or(u64::MAX);
    if secs == 0 {
        return None;
    }
    Some(std::time::Duration::from_secs(
        secs.min(u64::from(max_secs.max(1))),
    ))
}

/// What may follow Retry-After's delta-seconds: `LWS [ comment LWS ]`, then
/// the end of the value or `;`. A comment nests and honours `\` quoted-pairs
/// (RFC 3261 §25.1); an unbalanced one is rejected.
fn retry_after_tail_ok(tail: &[u8]) -> bool {
    let is_lws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let skip_lws = |t: &[u8], from: usize| {
        t.get(from..)
            .and_then(|rest| rest.iter().position(|b| !is_lws(b)))
            .map_or(t.len(), |p| from + p)
    };
    let mut i = skip_lws(tail, 0);
    if tail.get(i) == Some(&b'(') {
        let mut depth = 0usize;
        let mut escaped = false;
        let mut closed = None;
        for (j, &b) in tail.iter().enumerate().skip(i) {
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' => escaped = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        closed = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = closed else {
            return false;
        };
        i = skip_lws(tail, end + 1);
    }
    matches!(tail.get(i), None | Some(&b';'))
}

/// Replaces (or appends) `;name=value` on a header value, outside any
/// `<...>` URI.
/// Splits a sent-by / hostport (`host`, `host:port`, `[v6]` or `[v6]:port`)
/// into host (brackets kept) and port.
fn split_sent_by(s: &str) -> (&str, Option<u16>) {
    let s = s.trim();
    if s.starts_with('[') {
        return match s.find(']') {
            Some(end) => (
                &s[..=end],
                s[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()),
            ),
            None => (s, None),
        };
    }
    match s.rsplit_once(':') {
        // A single ':' separates the port; more is a bare IPv6 literal.
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()),
        _ => (s, None),
    }
}

/// `host:port` with an IPv6 host bracketed.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Rewrites the top Via of an SBC-built request for another leg transport:
/// transport token, sent-by port (the listener of that transport) and
/// branch; the sent-by host (possibly topology-hidden) and other params
/// are kept.
///
/// ## RFC 3261 §18.1.1, §20.42
fn retarget_via(via: &str, flow: &LegFlow, port: u16, branch: &str) -> String {
    let rest = via
        .trim()
        .split_once(char::is_whitespace)
        .map_or(via, |(_, r)| r)
        .trim_start();
    let (sent_by, params) = rest.split_once(';').unwrap_or((rest, ""));
    let (host, _) = split_sent_by(sent_by);
    let mut out = format!("SIP/2.0/{} {}", flow.via_token(), host_port(host, port));
    if !params.is_empty() {
        out.push(';');
        out.push_str(params);
    }
    replace_header_param(&out, "branch", branch)
}

/// Rewrites the SBC Contact of a request for another leg transport
/// (`sips:` on TLS, RFC 3261 §8.1.1.8), keeping host and header params.
fn retarget_contact(contact: &str, flow: &LegFlow, port: u16) -> String {
    let (uri_part, trailing) = match (contact.find('<'), contact.find('>')) {
        (Some(a), Some(b)) if a < b => (&contact[a + 1..b], &contact[b + 1..]),
        _ => (contact.split(';').next().unwrap_or(contact), ""),
    };
    let host = uri_part.parse::<SipUri>().map_or_else(
        |_| {
            let hp = uri_part.split_once(':').map_or(uri_part, |(_, r)| r);
            let hp = hp.rsplit_once('@').map_or(hp, |(_, h)| h);
            split_sent_by(hp.split(';').next().unwrap_or(hp))
                .0
                .to_string()
        },
        |u| u.host,
    );
    let user = uri_part
        .parse::<SipUri>()
        .ok()
        .and_then(|u| u.user)
        .map(|u| format!("{u}@"))
        .unwrap_or_default();
    let sent_by = format!("{user}{}", host_port(&host, port));
    format!("{}{trailing}", leg_contact(&sent_by, flow))
}

fn replace_header_param(header_value: &str, name: &str, value: &str) -> String {
    let params_start = header_value.rfind('>').map_or(0, |p| p + 1);
    let (head, params) = header_value.split_at(params_start);
    let mut out = String::with_capacity(header_value.len() + value.len());
    out.push_str(head);
    let mut replaced = false;
    for (i, part) in params.split(';').enumerate() {
        if i == 0 {
            out.push_str(part);
            continue;
        }
        out.push(';');
        let key = part.split('=').next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case(name) {
            out.push_str(name);
            out.push('=');
            out.push_str(value);
            replaced = true;
        } else {
            out.push_str(part);
        }
    }
    if !replaced {
        out.push(';');
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// Takes a slot on the first still-usable failover target, dropping the
/// targets tried. Returns the lease and the trunk's SIP URI.
fn acquire_next_target(
    router: &mut Router,
    targets: &mut Vec<(String, String)>,
    admission: Admission,
) -> Option<(TrunkLease, String)> {
    let mut consumed = 0;
    let mut found = None;
    for (group_id, trunk_id) in targets.iter() {
        consumed += 1;
        if let Some(uri) = router.acquire_trunk_for(group_id, trunk_id, admission) {
            found = Some((
                TrunkLease {
                    group_id: group_id.clone(),
                    trunk_id: trunk_id.clone(),
                    started: Instant::now(),
                    admission,
                },
                uri,
            ));
            break;
        }
    }
    targets.drain(..consumed);
    found
}

/// Final status of a handler result sent to the A-leg (for a reject CDR);
/// 480 when the result carries no final response.
fn final_status(result: &ProcessResult) -> u16 {
    match result {
        ProcessResult::Response {
            message: SipMessage::Response(r),
            ..
        } if r.status.code() >= 200 => r.status.code(),
        ProcessResult::Multiple(v) => v
            .iter()
            .map(final_status)
            .find(|c| *c != 480)
            .unwrap_or(480),
        _ => 480,
    }
}

/// Every Reason header value (RFC 3326), for the CDR Q.850 cause.
fn reason_headers(headers: &proto_sip::header::Headers) -> impl Iterator<Item = &str> {
    // RFC 3326 §2: several Reason header fields may be present.
    headers
        .iter()
        .filter(|h| h.name.as_str().eq_ignore_ascii_case("Reason"))
        .map(|h| h.value.as_str())
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
            source_ip: Some(source.ip()),
        },
    ));
}

/// `AuthorizationDecision` (granted) for an emergency call admitted past
/// the capacity and VPS limits (47 CFR 9.16), so every bypass is on the
/// audit trail with its source.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, SC-5
fn audit_emergency_bypass(req: &SipRequest, source: SbcSocketAddr) {
    audit(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity: req
                .headers
                .get_value(&HeaderName::From)
                .map_or_else(|| source.to_string(), extract_uri_from_header),
            resource: req.uri.to_string(),
            action: "INVITE".to_string(),
            granted: true,
            policy: "emergency-bypass".to_string(),
            source_ip: Some(source.ip()),
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
    /// The A-leg transport the 2xx is retransmitted on.
    flow: LegFlow,
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
        /// Transport/connection it goes out on (RFC 3261 §18.2.2).
        flow: Flow,
    },
    /// Forward request to another destination.
    Forward {
        /// Request message.
        message: SipMessage,
        /// Destination address.
        destination: SbcSocketAddr,
        /// Transport/connection it goes out on: the target leg's, never
        /// the one the triggering message arrived on (RFC 3261 §18.1.1).
        ///
        /// ## NIST 800-53 Rev5: SC-8
        flow: Flow,
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
            admitted_calls: Arc::new(AtomicUsize::new(0)),
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
            emergency_admissions: AtomicU64::new(0),
            first_send_ok: FirstSendLedger::new(),
            next_rtp_port: std::sync::atomic::AtomicU16::new(32_770),
            allocated_ports: Arc::new(std::sync::Mutex::new(HashSet::new())),
            in_flight_invites: RwLock::new(HashSet::new()),
            pending_2xx: RwLock::new(HashMap::new()),
            user_limiter: None,
            cdr: None,
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(crate::stir_binding::DidMap::default()),
            stir_flows: RwLock::new(crate::stir_binding::StirFlows::default()),
            announcement_calls: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashSet::new()),
            ),
            vps: None,
            stir: None,
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
            admitted_calls: Arc::new(AtomicUsize::new(0)),
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
            emergency_admissions: AtomicU64::new(0),
            first_send_ok: FirstSendLedger::new(),
            next_rtp_port: std::sync::atomic::AtomicU16::new(32_770),
            allocated_ports: Arc::new(std::sync::Mutex::new(HashSet::new())),
            in_flight_invites: RwLock::new(HashSet::new()),
            pending_2xx: RwLock::new(HashMap::new()),
            user_limiter: None,
            cdr: None,
            config,
            zone_registry: None,
            inbound_trunk_map: RwLock::new(std::collections::HashMap::new()),
            did_map: RwLock::new(crate::stir_binding::DidMap::default()),
            stir_flows: RwLock::new(crate::stir_binding::StirFlows::default()),
            announcement_calls: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashSet::new()),
            ),
            vps: None,
            stir: None,
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
        let (dest, flow) = addrs.leg_target(target_b_leg);
        let other_call_id = if target_b_leg {
            &addrs.b_leg_sip_call_id
        } else {
            &addrs.a_leg_sip_call_id
        };
        let uri = leg_request_uri(None, &dest.ip().to_string(), dest.port(), &flow);
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
        // RFC 3261 §18.1.1: the Via names the leg's real transport.
        bye.headers.add(Header::new(
            HeaderName::Via,
            crate::flow::via_for(&flow, addrs.leg_sent_by(target_b_leg), &branch),
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
        let (dest, flow) = addrs.leg_target(target_b_leg);
        let other_call_id = if target_b_leg {
            &addrs.b_leg_sip_call_id
        } else {
            &addrs.a_leg_sip_call_id
        };
        let uri = leg_request_uri(None, &dest.ip().to_string(), dest.port(), &flow);
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
        let sent_by = addrs.leg_sent_by(target_b_leg);
        inv.headers.add(Header::new(
            HeaderName::Via,
            crate::flow::via_for(&flow, sent_by, &branch),
        ));
        if *method != Method::Ack {
            // Target-refresh Contact: subsequent in-dialog requests come back to us.
            inv.headers
                .set(HeaderName::Contact, leg_contact(sent_by, &flow));
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
    ///
    /// A retransmission is a copy of the same request, so a stored transaction
    /// whose Call-ID differs is a branch collision (a client that reuses
    /// branch values, or a forged one), not a retransmission: the request is
    /// treated as new instead of being swallowed or answered with another
    /// call's response.
    async fn answer_request_retransmit(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
    ) -> Option<ProcessResult> {
        let branch = req.headers.via_branch()?;
        let key = TransactionKey::server(&branch, req.method.to_string());
        let call_id = req.headers.call_id().unwrap_or("");
        let mut txns = self.transactions.write().await;
        let (resend, last) = if req.method == Method::Invite {
            let st = txns
                .server_invite
                .get_mut(&key)
                .filter(|st| st.call_id == call_id)?;
            (
                st.transaction.receive_request().unwrap_or(false),
                st.last_response.clone(),
            )
        } else {
            let st = txns
                .server_non_invite
                .get_mut(&key)
                .filter(|st| st.call_id == call_id)?;
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
                flow: Flow::Reply,
            }),
            _ => Some(ProcessResult::NoAction),
        }
    }

    /// Opens a server transaction for a newly received request so later
    /// retransmissions are answered from the stored response and a non-2xx
    /// INVITE final is retransmitted on Timer G until ACKed.
    async fn open_server_transaction(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        transport: AddrTransport,
    ) {
        let txn_transport = txn_transport(transport);
        let Some(branch) = req.headers.via_branch() else {
            return;
        };
        let key = TransactionKey::server(&branch, req.method.to_string());
        let call_id = req.headers.call_id().unwrap_or("").to_string();
        let now = Instant::now();
        let mut txns = self.transactions.write().await;
        txns.sweep_if_needed();
        // An entry with the same branch but another Call-ID belongs to an
        // earlier request (see `answer_request_retransmit`); replace it.
        if req.method == Method::Invite {
            if txns
                .server_invite
                .get(&key)
                .is_some_and(|st| st.call_id == call_id)
            {
                return;
            }
            txns.server_invite.insert(
                key.clone(),
                ServerInviteState {
                    // RFC 3261 §17.2.1: Timer G (final-response
                    // retransmission) runs only on unreliable transports.
                    transaction: ServerInviteTransaction::new(key, txn_transport),
                    source,
                    flow: LegFlow::inbound(transport),
                    created_at: now,
                    last_response: None,
                    call_id,
                },
            );
        } else {
            if txns
                .server_non_invite
                .get(&key)
                .is_some_and(|st| st.call_id == call_id)
            {
                return;
            }
            txns.server_non_invite.insert(
                key.clone(),
                ServerNonInviteState {
                    // RFC 3261 §17.2.2: Timer J is zero on reliable
                    // transports.
                    transaction: ServerNonInviteTransaction::new(key, txn_transport),
                    source,
                    created_at: now,
                    last_response: None,
                    call_id,
                },
            );
        }
    }

    /// Bookkeeping for everything a handler puts on the wire: responses are
    /// recorded on their server transaction, forwarded requests open a client
    /// transaction that retransmits and times them out.
    ///
    /// Each forward's own `flow` is the transport it is sent on; it selects
    /// reliable or unreliable transaction timers (RFC 3261 §17.1) and is
    /// kept for retransmissions. `Flow::Reply` must already be resolved
    /// (see [`resolve_reply`]).
    async fn track_result(&self, result: &ProcessResult) {
        match result {
            ProcessResult::Response { message, .. } => self.record_server_response(message).await,
            ProcessResult::Forward {
                message,
                destination,
                flow,
            } => {
                let Flow::Leg(flow) = flow else {
                    error!("Unresolved reply flow on a forwarded request; not tracked");
                    return;
                };
                self.open_client_transaction(message, *destination, flow.clone())
                    .await;
            }
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
    ///
    /// ## RFC 3261 §17.1.1.2, §17.1.2.2: Timers A and E run only on
    /// unreliable transports; Timers B and F run on all.
    async fn open_client_transaction(
        &self,
        message: &SipMessage,
        destination: SbcSocketAddr,
        flow: LegFlow,
    ) {
        let transport = flow.transport;
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
                    transaction: ClientInviteTransaction::new(key, txn_transport(transport)),
                    destination,
                    flow,
                    created_at: now,
                    request: message.clone(),
                    ack: None,
                    call,
                    initial_send_pending: true,
                    retransmitted: false,
                });
        } else {
            txns.client_non_invite
                .entry(key.clone())
                .or_insert_with(|| ClientNonInviteState {
                    transaction: ClientNonInviteTransaction::new(key, txn_transport(transport)),
                    destination,
                    flow,
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
        flow: LegFlow,
        cseq: u32,
    ) {
        let now = Instant::now();
        let t1 = proto_transaction::DEFAULT_T1;
        self.pending_2xx.write().await.insert(
            leg_call_id.to_string(),
            Pending2xx {
                response: response.clone(),
                destination,
                flow,
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
                    Some(TimerType::TimerA) => {
                        // A later failure may be this retransmission's; the
                        // first-send ledger decides (see on_invite_sent). The
                        // first-send flag stays set until that send reports.
                        st.retransmitted = true;
                        out.push(ProcessResult::Forward {
                            message: st.request.clone(),
                            destination: st.destination,
                            flow: st.flow.clone().into(),
                        });
                    }
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
                        flow: st.flow.clone().into(),
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
                                flow: st.flow.clone().into(),
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
        // The 408s ride their server transactions; the BYEs get client ones
        // on the leg's own flow (RFC 3261 §17.1.2.2: reliable timers on
        // TCP/TLS legs).
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
            let resp_flow = addrs.leg_flow(!p.from_a_leg);
            let bye = Self::build_leg_bye(&addrs, p.from_a_leg);
            let (bye_dest, bye_flow) = addrs.leg_target(p.from_a_leg);
            self.cleanup_terminated_call(
                call,
                false,
                crate::cdr::CdrEnd::dialog_lost(addrs.b_leg_answered, 408),
            )
            .await;
            return vec![
                ProcessResult::Response {
                    message: resp,
                    destination: dest,
                    flow: resp_flow.into(),
                },
                ProcessResult::Forward {
                    message: SipMessage::Request(bye),
                    destination: bye_dest,
                    flow: bye_flow.into(),
                },
            ];
        }

        if branch == addrs.b_leg_branch {
            // RFC 3261 §17.1.1.2: Timer B is a 408; the trunk failed the
            // call, so try the next one first.
            if let Some(retry) = self
                .try_failover(call, &addrs, FailoverCause::Timeout)
                .await
            {
                return vec![retry];
            }
            warn!(
                call_id = %addrs.a_leg_sip_call_id,
                "No final response from B-leg (Timer B); failing call with 408"
            );
            audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Timeout);
            {
                let mut calls = self.calls.write().await;
                if let Some(c) = calls.get_mut(call) {
                    c.fail(timeout.code(), timeout.reason_phrase());
                }
            }
            let resp = build_a_leg_response(timeout, &addrs);
            self.cleanup_terminated_call(call, true, crate::cdr::CdrEnd::timer_b())
                .await;
            return vec![ProcessResult::Response {
                message: SipMessage::Response(resp),
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            }];
        }

        Vec::new()
    }

    /// Reports the outcome of putting a forwarded request on the wire.
    /// Only the first send of a call's initial B-leg INVITE matters: if it
    /// failed (UDP send error, TCP/TLS connect, handshake or write failure,
    /// send timeout) the call fails over to the next trunk now instead of
    /// waiting 32 s for Timer B, or gets a 503 when none is left (RFC 3261
    /// §8.1.3.1: a transport error is a 503; RFC 3263 §4.3). The failed
    /// trunk counts a failure (`max_failures`) but is not cooled down.
    ///
    /// Retransmissions, ACK, CANCEL, in-dialog requests and re-INVITEs stay
    /// log-only. The dead attempt's client transaction is dropped so its
    /// Timer A/B cannot fire, and the attempt is current only while
    /// `b_leg_branch` names it, so it cannot fail over twice.
    ///
    /// Returned results are already tracked; the caller only sends them.
    ///
    /// ## NIST 800-53 Rev5: CP-8 (Telecommunications Services), SI-17
    pub async fn on_invite_sent(&self, message: &SipMessage, sent: bool) -> Vec<ProcessResult> {
        let SipMessage::Request(req) = message else {
            return Vec::new();
        };
        if req.method != Method::Invite {
            return Vec::new();
        }
        let Some(branch) = req.headers.via_branch() else {
            return Vec::new();
        };
        // A successful send only marks the branch in the lock-free ledger:
        // no transactions lock on the common path (PERF-001).
        if sent {
            self.first_send_ok.record(&branch);
            return Vec::new();
        }
        let key = TransactionKey::client(&branch, Method::Invite.to_string());
        let call = {
            let mut txns = self.transactions.write().await;
            let Some(st) = txns.client_invite.get_mut(&key) else {
                return Vec::new();
            };
            // After Timer A, a failure on a branch whose send already
            // succeeded is the retransmission's: log-only. Otherwise the
            // first send failed (possibly slowly, past Timer A on TCP/TLS).
            if st.retransmitted && self.first_send_ok.contains(&branch) {
                st.initial_send_pending = false;
                return Vec::new();
            }
            // The first failure report clears the flag: exactly once.
            if !std::mem::take(&mut st.initial_send_pending)
                || st.transaction.state() != ClientInvitePhase::Calling
            {
                return Vec::new();
            }
            st.call.clone()
        };
        let addrs = {
            let corr = self.call_correlation.read().await;
            match corr.addresses.get(&call) {
                Some(a) if a.b_leg_branch == branch && !a.b_leg_answered => a.clone(),
                _ => return Vec::new(),
            }
        };
        // Stop Timer A/B on the dead attempt.
        self.transactions.write().await.client_invite.remove(&key);
        warn!(
            call_id = %addrs.a_leg_sip_call_id,
            destination = %addrs.b_leg_destination,
            "B-leg INVITE could not be sent; failing over"
        );

        let out = if let Some(retry) = self
            .try_failover(&call, &addrs, FailoverCause::TransportError)
            .await
        {
            vec![retry]
        } else {
            let unavailable = StatusCode::SERVICE_UNAVAILABLE;
            audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Failed);
            {
                let mut calls = self.calls.write().await;
                if let Some(c) = calls.get_mut(&call) {
                    c.fail(unavailable.code(), unavailable.reason_phrase());
                }
            }
            let resp = build_a_leg_response(unavailable, &addrs);
            self.cleanup_terminated_call(&call, true, crate::cdr::CdrEnd::transport_error())
                .await;
            vec![ProcessResult::Response {
                message: SipMessage::Response(resp),
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            }]
        };
        // Each result carries its leg's flow: the failover INVITE the next
        // trunk's, the 503 the caller's (RFC 3261 §18.1.1, §18.2.2).
        for r in &out {
            self.track_result(r).await;
        }
        out
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
                        flow: p.flow.clone().into(),
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
                for target_b_leg in [false, true] {
                    let (destination, flow) = addrs.leg_target(target_b_leg);
                    out.push(ProcessResult::Forward {
                        message: SipMessage::Request(Self::build_leg_bye(&addrs, target_b_leg)),
                        destination,
                        flow: flow.into(),
                    });
                }
            }
            self.cleanup_terminated_call(&call, false, crate::cdr::CdrEnd::dialog_lost(true, 200))
                .await;
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
                flow: Flow::Reply,
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
            flow: Flow::Reply,
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
                // The Contact faces the requester's leg (RFC 3261 §12.1.1).
                let orig_flow = addrs.leg_flow(!from_a_leg);
                ok.headers.set(
                    HeaderName::Contact,
                    leg_contact(addrs.leg_sent_by(!from_a_leg), &orig_flow),
                );
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
                    addrs.leg_flow(!from_a_leg),
                    req.headers.cseq_parsed().map_or(1, |c| c.sequence),
                )
                .await;
            }
            info!(method = %method, call_id = %sip_call_id, "Session refresh answered locally");
            return ProcessResult::Response {
                message: ok,
                destination: source,
                flow: Flow::Reply,
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
                flow: Flow::Reply,
            });
        }
        results.push(ProcessResult::Forward {
            message: SipMessage::Request(fwd),
            destination: dest,
            flow: addrs.leg_flow(from_a_leg).into(),
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
        // The originator's leg: the response goes back on its transport.
        let orig_flow = addrs.leg_flow(!pending.from_a_leg);
        if code < 200 {
            return ProcessResult::Response {
                message: relayed,
                destination: orig_dest,
                flow: orig_flow.into(),
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
                self.cleanup_terminated_call(
                    internal_id,
                    false,
                    crate::cdr::CdrEnd::dialog_lost(addrs.b_leg_answered, code),
                )
                .await;
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
                flow: orig_flow.into(),
            };
        }

        // 2xx: re-anchor the answer toward the originator.
        let SipMessage::Response(ok) = &mut relayed else {
            unreachable!("build_reinvite_response builds a response")
        };
        relay_session_timer_response_headers(&resp.headers, &mut ok.headers);
        ok.headers.set(
            HeaderName::Contact,
            leg_contact(addrs.leg_sent_by(!pending.from_a_leg), &orig_flow),
        );
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
            flow: orig_flow.clone().into(),
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
            let (ack_dest, ack_flow) = addrs.leg_target(pending.from_a_leg);
            let ack = SipMessage::Request(ack);
            ack_record = Some((
                pending.fwd_branch.clone(),
                ack.clone(),
                ack_dest,
                ack_flow.clone(),
            ));
            results.push(ProcessResult::Forward {
                message: ack,
                destination: ack_dest,
                flow: ack_flow.into(),
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
                orig_flow,
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
    ///
    /// `trunk_failed` marks the B-leg trunk as having failed the call (Timer
    /// B), which counts toward its `max_failures` cooldown.
    async fn cleanup_terminated_call(
        &self,
        internal_id: &CallId,
        trunk_failed: bool,
        end: crate::cdr::CdrEnd,
    ) {
        {
            let mut calls = self.calls.write().await;
            calls.remove(internal_id);
        }
        self.finish_call_record(internal_id, trunk_failed, end)
            .await;
        // INVITE transactions are left to run out (Timer D/H/I) so late
        // retransmissions are still absorbed; `poll_timers` prunes them.
        self.pending_2xx
            .write()
            .await
            .retain(|_, p| &p.call != internal_id);
        if let Some(ref pipeline) = self.media_pipeline {
            let key = internal_id.to_string();
            let _ = pipeline.stop_relay(&key).await;
            let _ = pipeline.remove_session(&key).await;
        }
    }

    /// Removes a call's correlation record and releases what it held (RTP
    /// ports, trunk slot, VPS callee slot).
    ///
    /// Release is tied to the record actually removed from
    /// `call_correlation.addresses`, never to a caller's clone, so it happens
    /// exactly once however many teardown paths race (BYE crossing CANCEL,
    /// retransmitted BYE, Timer B during a BYE) and always for the trunk the
    /// call holds *now* (a failover swaps the lease in place).
    ///
    /// Lock order: `call_correlation` is released before `router` / `vps`
    /// are taken; neither is held across an `.await` on another lock.
    ///
    /// The same exactly-once removal emits the call's CDR (`end` describes
    /// how it ended), after `call_correlation` is released; emission is a
    /// non-blocking queue push.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), AU-12
    async fn finish_call_record(
        &self,
        internal_id: &CallId,
        trunk_failed: bool,
        end: crate::cdr::CdrEnd,
    ) -> bool {
        let mut removed = {
            let mut corr = self.call_correlation.write().await;
            let Some(removed) = corr.addresses.remove(internal_id) else {
                return false;
            };
            corr.a_leg.remove(&removed.a_leg_sip_call_id);
            corr.b_leg.remove(&removed.b_leg_sip_call_id);
            removed
        };
        for port in &removed.rtp_ports {
            self.release_rtp_port(*port);
        }
        let outcome = match (removed.established_at, removed.trunk_lease.as_ref()) {
            (Some(at), Some(lease)) => TrunkOutcome::Completed {
                setup_ms: u64::try_from(at.saturating_duration_since(lease.started).as_millis())
                    .unwrap_or(u64::MAX),
            },
            _ if trunk_failed => TrunkOutcome::Failed,
            _ => TrunkOutcome::Abandoned,
        };
        self.release_slots(
            removed.trunk_lease.as_ref(),
            removed.vps_callee.as_deref(),
            outcome,
        )
        .await;
        if let Some(cdr) = &self.cdr {
            cdr.emit_call(std::mem::take(&mut removed.cdr), &end);
        }
        true
    }

    /// Releases a trunk slot and/or a VPS callee slot.
    async fn release_slots(
        &self,
        lease: Option<&TrunkLease>,
        vps_callee: Option<&str>,
        outcome: TrunkOutcome,
    ) {
        if let (Some(lease), Some(router)) = (lease, self.router.as_ref()) {
            router
                .write()
                .await
                .release_trunk(&lease.group_id, &lease.trunk_id, outcome);
        }
        if let (Some(callee), Some(vps)) = (vps_callee, self.vps.as_ref()) {
            vps.lock().await.call_ended(callee);
        }
    }

    /// Whether the router knows a trunk with this ID (any group).
    pub async fn has_trunk(&self, trunk_id: &str) -> bool {
        match self.router.as_ref() {
            Some(router) => router.read().await.has_trunk(trunk_id),
            None => false,
        }
    }

    /// Applies an OPTIONS-ping reachability change to trunk selection: an
    /// unreachable trunk is skipped by routing and failover until it answers
    /// again. Returns how many router trunks matched `trunk_id`.
    ///
    /// ## NIST 800-53 Rev5: SC-5, CP-8 (alternate telecommunications)
    pub async fn set_trunk_reachable(&self, trunk_id: &str, reachable: bool) -> usize {
        let Some(router) = self.router.as_ref() else {
            return 0;
        };
        router
            .write()
            .await
            .set_trunk_reachable(trunk_id, reachable)
    }

    /// Applies a detected reachability change (OPTIONS monitor or agent
    /// publish) to trunk selection, logs it and records it on the audit
    /// trail. Returns how many router trunks matched `trunk_id`.
    ///
    /// ## NIST 800-53 Rev5: AU-2, CP-8 (Telecommunications Services)
    pub async fn apply_trunk_reachability_change(
        &self,
        trunk_id: &str,
        reachable: bool,
        source: uc_audit::event::ReachabilitySource,
    ) -> usize {
        let n = self.set_trunk_reachable(trunk_id, reachable).await;
        info!(
            trunk_id = %trunk_id,
            reachable,
            router_trunks = n,
            source = ?source,
            "Trunk reachability changed"
        );
        // The router lock is released; the audit hand-off does not block.
        audit(uc_audit::AuditEvent::TrunkReachabilityChanged(
            uc_audit::event::TrunkReachabilityChanged {
                trunk_id: trunk_id.to_string(),
                reachable,
                source,
            },
        ));
        n
    }

    /// Active (reserved) calls on a trunk, if the router knows it.
    pub async fn trunk_active_calls(&self, group_id: &str, trunk_id: &str) -> Option<u32> {
        let router = self.router.as_ref()?;
        router.read().await.trunk_active_calls(group_id, trunk_id)
    }

    /// Concurrent calls the VPS counts against a dialed number.
    pub async fn vps_callee_concurrent_calls(&self, callee: &str) -> Option<u32> {
        let vps = self.vps.as_ref()?;
        Some(vps.lock().await.callee_concurrent_calls(callee))
    }

    /// Routes a number no registered user answers to a trunk: the SBC
    /// router's route groups (CSS / partition / route pattern / route list)
    /// first, then the dial plan. Reserves a `max_calls` slot on the chosen
    /// trunk; a trunk whose URI does not resolve counts as failed and the
    /// next failover target is tried.
    async fn route_to_trunk(
        &self,
        dest_user: &str,
        css: Option<&str>,
        admission: Admission,
    ) -> TrunkRouting {
        let Some(router_lock) = self.router.as_ref() else {
            warn!("No router configured on SIP stack");
            return TrunkRouting::NoRoute;
        };

        let sbc_match = if let Some(ref sbc) = self.sbc_router {
            sbc.read().await.route(dest_user, css)
        } else {
            None
        };

        let mut matched_trunks = false;
        let decision = {
            let mut router = router_lock.write().await;
            let mut decision = None;
            if let Some(ref result) = sbc_match {
                info!(
                    pattern = %result.pattern_id,
                    partition = %result.partition_id,
                    destination = %result.transformed_number,
                    css = ?css,
                    "Routed via SBC CSS/Partition"
                );
                match router.route_to_groups_for(
                    &result.transformed_number,
                    &result.route_group_ids,
                    admission,
                ) {
                    Ok(d) => decision = Some(d),
                    Err(RoutingError::AllTrunksFailed { trunks_tried }) if trunks_tried > 0 => {
                        matched_trunks = true;
                    }
                    Err(e) => {
                        warn!(error = %e, "SBC route groups match no trunk group; trying dial plan");
                    }
                }
            }
            if decision.is_none() && !matched_trunks {
                debug!(dest = %dest_user, "Attempting dial plan routing");
                match router.route_for(dest_user, admission) {
                    Ok(d) => decision = Some(d),
                    Err(RoutingError::AllTrunksFailed { trunks_tried }) if trunks_tried > 0 => {
                        matched_trunks = true;
                    }
                    Err(e) => warn!(dest = %dest_user, error = %e, "Dial plan routing failed"),
                }
            }
            decision
        };

        let Some(decision) = decision else {
            return if matched_trunks {
                TrunkRouting::Unavailable
            } else {
                TrunkRouting::NoRoute
            };
        };

        let mut lease = TrunkLease {
            group_id: decision.trunk_group_id,
            trunk_id: decision.trunk_id,
            started: Instant::now(),
            admission,
        };
        let translated = decision.destination;
        let mut failover = decision.failover_targets;

        // The transformed number goes on the wire; the dialed number keeps
        // driving routing, VPS and audit (no partition bypass by dialing a
        // "translated-looking" number).
        if translated != dest_user && !is_safe_b_leg_user(&translated) {
            warn!(
                dest = %dest_user,
                translated = %translated.escape_default(),
                "Number transform produced an invalid Request-URI user; rejecting call"
            );
            router_lock.write().await.release_trunk(
                &lease.group_id,
                &lease.trunk_id,
                TrunkOutcome::Abandoned,
            );
            return TrunkRouting::InvalidTranslation;
        }

        let mut uri = decision.trunk_uri;
        loop {
            // Endpoint from the trunk's config (keeps the hostname as the TLS
            // server name); DNS runs outside the router lock.
            let endpoint =
                TrunkEndpoint::of(&*router_lock.read().await, &lease.group_id, &lease.trunk_id);
            if let Some((endpoint, destination)) =
                endpoint.and_then(|e| e.resolve().map(|d| (e, d)))
            {
                info!(
                    trunk_group = %lease.group_id,
                    trunk_id = %lease.trunk_id,
                    destination = %translated,
                    failover_targets = failover.len(),
                    "Routed to trunk"
                );
                return TrunkRouting::Routed(Box::new(TrunkRoute {
                    lease,
                    destination,
                    endpoint,
                    failover,
                    translated,
                }));
            }
            warn!(trunk_id = %lease.trunk_id, trunk_uri = %uri, "Could not resolve trunk URI; trying next trunk");
            let next = {
                let mut router = router_lock.write().await;
                router.release_trunk(&lease.group_id, &lease.trunk_id, TrunkOutcome::Failed);
                acquire_next_target(&mut router, &mut failover, admission)
            };
            match next {
                Some((l, u)) => {
                    lease = l;
                    uri = u;
                }
                None => return TrunkRouting::Unavailable,
            }
        }
    }

    /// Retries the initial INVITE on the next usable failover trunk after
    /// the current trunk failed it (`cause`: final status, Timer B, or a
    /// failed first send). Returns `None` when no failover applies, so the
    /// caller fails the call as before.
    ///
    /// Failover is skipped once the callee answered or a reliable 18x with
    /// SDP reached the caller (the early media is committed to this trunk).
    /// The old slot is released as failed and, on 503, the trunk goes into
    /// cooldown for its bounded `Retry-After`, else `cooldown_secs` (RFC
    /// 3261 §21.5.4, RFC 3263 §4.3). Each failover is audited
    /// (`TrunkFailover`).
    ///
    /// Only the attempt that is still current fails over: the swap below
    /// checks `b_leg_branch`, so a late Timer B or a second report for an
    /// attempt already failed over finds no match.
    ///
    /// ## NIST 800-53 Rev5: CP-8 (Telecommunications Services), SC-5
    ///
    /// The retried INVITE is addressed and sent per the next trunk's
    /// configured protocol (`sips:`/TLS, TCP, UDP), never downgraded to the
    /// failed attempt's transport (POA&M-5 closed).
    ///
    /// ## NIST 800-53 Rev5: SC-8; RFC 3261 §18.1.1, §26.2; RFC 3263 §4.3
    async fn try_failover(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        cause: FailoverCause,
    ) -> Option<ProcessResult> {
        if addrs.b_leg_answered || addrs.early_media_committed {
            return None;
        }
        let template = addrs.b_leg_invite.as_ref()?;
        let router_lock = self.router.as_ref()?;
        let old_lease = addrs.trunk_lease.as_ref()?;
        if addrs.failover_targets.is_empty() {
            return None;
        }

        let mut remaining = addrs.failover_targets.clone();
        let (lease, new_dest, endpoint) = loop {
            let (next, endpoint) = {
                let mut router = router_lock.write().await;
                let next = acquire_next_target(&mut router, &mut remaining, old_lease.admission)?;
                let endpoint = TrunkEndpoint::of(&router, &next.0.group_id, &next.0.trunk_id);
                (next, endpoint)
            };
            // DNS (if any) runs outside the router lock.
            if let Some((endpoint, dest)) = endpoint.and_then(|e| e.resolve().map(|d| (e, d))) {
                break (next.0, dest, endpoint);
            }
            warn!(trunk_id = %next.0.trunk_id, trunk_uri = %next.1, "Could not resolve failover trunk URI");
            router_lock.write().await.release_trunk(
                &next.0.group_id,
                &next.0.trunk_id,
                TrunkOutcome::Failed,
            );
        };

        // Same request (translated user, SDP, manipulated headers), new
        // client transaction and B-leg dialog: fresh Call-ID, branch, From tag.
        let mut request = SipRequest::clone(template);
        let new_call_id = generate_call_id(&self.config.domain);
        let new_branch = generate_branch();
        request.headers.set(HeaderName::CallId, &new_call_id);
        request.headers.set(HeaderName::CSeq, "1 INVITE");
        // The wire format follows the *next* trunk, not the template's:
        // Request-URI scheme/host/port/transport, Via transport and sent-by
        // port, Contact scheme (RFC 3261 §18.1.1, §19.1.1, §26.2; RFC 3263
        // §4.1). The user part (translated number) is kept.
        //
        // NIST 800-53 Rev5: SC-8 — a sips/TLS trunk is reached only over TLS.
        let new_flow = endpoint.flow.clone();
        let sent_by_port = self.signaling_port(new_flow.transport);
        request.uri = leg_request_uri(
            template.uri.user.as_deref(),
            &endpoint.host,
            endpoint.port,
            &new_flow,
        );
        if let Some(via) = request.headers.get_value(&HeaderName::Via) {
            let via = retarget_via(via, &new_flow, sent_by_port, &new_branch);
            request.headers.set(HeaderName::Via, via);
        }
        if let Some(contact) = request.headers.get_value(&HeaderName::Contact) {
            let contact = retarget_contact(contact, &new_flow, sent_by_port);
            request.headers.set(HeaderName::Contact, contact);
        }
        let new_local_addr = host_port(split_sent_by(&addrs.local_addr).0, sent_by_port);
        let new_from = request
            .headers
            .get_value(&HeaderName::From)
            .map(|f| replace_header_param(f, "tag", &generate_tag()))
            .unwrap_or_default();
        request.headers.set(HeaderName::From, &new_from);
        let new_to = request
            .headers
            .get_value(&HeaderName::To)
            .unwrap_or_default()
            .to_string();
        let new_template = Arc::new(request.clone());
        // STIR for this trunk on the wire copy only (the template stays
        // pre-STIR): fresh iat, or no Identity/PAI if it does not sign.
        let stir_signed = match (self.stir.as_ref(), addrs.stir_egress.as_deref()) {
            (Some(stir), Some(e)) => {
                stir.apply_egress(&mut request.headers, Some(&lease.trunk_id), e)
            }
            _ => None,
        };

        // Swap the lease in place only if the call is still on the attempt
        // that failed; otherwise (torn down, or another failover won) give
        // the new slot back.
        let swapped = {
            let mut corr = self.call_correlation.write().await;
            let current = corr
                .addresses
                .get(internal_id)
                .is_some_and(|e| e.b_leg_branch == addrs.b_leg_branch);
            if current {
                corr.b_leg.remove(&addrs.b_leg_sip_call_id);
                corr.b_leg.insert(new_call_id.clone(), internal_id.clone());
                corr.addresses.get_mut(internal_id).and_then(|entry| {
                    entry.b_leg_destination = new_dest;
                    entry.b_leg_flow = new_flow.clone();
                    entry.local_addr = new_local_addr;
                    entry.b_leg_sip_call_id.clone_from(&new_call_id);
                    entry.failover_targets = remaining;
                    entry.b_leg_branch.clone_from(&new_branch);
                    entry.b_leg_from = new_from;
                    entry.b_leg_to = new_to;
                    entry.dialog_to_tag = None;
                    entry.b_leg_ruri = Some(new_template.uri.clone());
                    entry.b_leg_invite = Some(new_template);
                    if addrs.stir_egress.is_some() {
                        entry.cdr.stir_attestation = stir_signed.map(crate::stir::cdr_attestation);
                    }
                    // POAM: POA&M-46 — CDR schema v1 records no per-attempt
                    // B-leg transport; the attempt's transport is in the
                    // warn log.
                    entry
                        .cdr
                        .record_failover(cause.cdr_outcome(), &lease.trunk_id, &new_call_id);
                    entry.trunk_lease.replace(lease.clone())
                })
            } else {
                None
            }
        };

        let Some(failed) = swapped else {
            router_lock.write().await.release_trunk(
                &lease.group_id,
                &lease.trunk_id,
                TrunkOutcome::Abandoned,
            );
            return Some(ProcessResult::NoAction);
        };
        {
            let mut router = router_lock.write().await;
            router.release_trunk(&failed.group_id, &failed.trunk_id, TrunkOutcome::Failed);
            if let FailoverCause::Status(503, retry_after) = cause {
                router.cooldown_trunk(&failed.group_id, &failed.trunk_id, retry_after);
            }
        }
        warn!(
            call_id = %addrs.a_leg_sip_call_id,
            failed_trunk = %old_lease.trunk_id,
            cause = ?cause,
            next_trunk = %lease.trunk_id,
            transport = new_flow.name(),
            "Trunk failover: retrying INVITE on next trunk"
        );
        // NIST 800-53 Rev5: AU-2, CP-8 — no lock is held here; the audit
        // hand-off is a non-blocking queue push.
        audit(uc_audit::AuditEvent::TrunkFailover(
            uc_audit::event::TrunkFailover {
                call_id: uc_types::identifier::CallId::new(addrs.a_leg_sip_call_id.clone()),
                group_id: failed.group_id.clone(),
                failed_trunk_id: failed.trunk_id.clone(),
                reason: cause.audit_reason(),
                next_trunk_id: lease.trunk_id.clone(),
            },
        ));
        Some(ProcessResult::Forward {
            message: SipMessage::Request(request),
            destination: new_dest,
            flow: new_flow.into(),
        })
    }

    /// Tears down a call whose DTLS-SRTP media handshake failed at runtime (after
    /// the 200 OK): the SBC initiated the teardown, so it BYEs **both** legs
    /// (neither peer sends one). Returns the BYEs, each on its leg's flow, for
    /// the caller to send; the call state is removed here.
    /// Empty if the call is already gone or the dialog never confirmed.
    pub async fn terminate_call_on_media_failure(&self, call_id: &str) -> Vec<ProcessResult> {
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
            self.cleanup_terminated_call(&internal_id, false, crate::cdr::CdrEnd::media_failure())
                .await;
            return Vec::new();
        }

        let a_bye = Self::build_leg_bye(&addrs, false);
        let b_bye = Self::build_leg_bye(&addrs, true);
        self.cleanup_terminated_call(&internal_id, false, crate::cdr::CdrEnd::media_failure())
            .await;

        warn!(
            call_id,
            "DTLS-SRTP media failed after answer; tearing down call (BYE both legs)"
        );
        audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Failed);

        // Each BYE on its own leg's flow (NIST 800-53 Rev5: SC-8).
        vec![
            ProcessResult::Forward {
                message: SipMessage::Request(a_bye),
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_bye),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
            },
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
            flow: Flow::Reply,
        })
    }

    /// Sets the STIR/SHAKEN service.
    pub fn set_stir(&mut self, stir: Arc<crate::stir::StirService>) {
        self.stir = Some(stir);
    }

    /// The STIR/SHAKEN service, if enabled.
    pub const fn stir(&self) -> Option<&Arc<crate::stir::StirService>> {
        self.stir.as_ref()
    }

    /// Sets the Voice Protection System engine for call screening.
    pub fn set_vps_engine(&mut self, engine: uc_vps::VpsEngine) {
        self.vps = Some(tokio::sync::Mutex::new(engine));
    }

    /// Emergency INVITEs admitted through the emergency bypass so far.
    ///
    /// ## NIST 800-53 Rev5: SI-4 (System Monitoring), SC-5
    pub fn emergency_admissions(&self) -> u64 {
        self.emergency_admissions.load(Ordering::Relaxed)
    }

    /// Attaches the CDR pipeline. Call before the stack is shared.
    pub fn set_cdr(&mut self, cdr: Arc<crate::cdr::CdrContext>) {
        self.cdr = Some(cdr);
    }

    /// The CDR pipeline, when enabled.
    pub fn cdr(&self) -> Option<&Arc<crate::cdr::CdrContext>> {
        self.cdr.as_ref()
    }

    /// Ends every call still up with a `shutdown` CDR (plan §5). Call
    /// after draining, before flushing the CDR writer.
    ///
    // POAM: no BYE is sent to either leg at shutdown; the far ends learn of
    // it from session timers / RTP loss. Plan §6 failover takeover CDRs
    // (`failover_takeover = true`) need a dialog takeover path, which the
    // daemon does not have (unknown-dialog requests get 481).
    ///
    /// ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
    pub async fn end_remaining_calls_for_shutdown(&self) -> usize {
        let remaining: Vec<(CallId, bool)> = self
            .call_correlation
            .read()
            .await
            .addresses
            .iter()
            .map(|(id, a)| (id.clone(), a.b_leg_answered))
            .collect();
        let n = remaining.len();
        for (id, answered) in remaining {
            self.cleanup_terminated_call(&id, false, crate::cdr::CdrEnd::shutdown(answered))
                .await;
        }
        n
    }

    /// Emits the CDR for an INVITE refused before a call was stored.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-12
    fn cdr_reject(&self, r: &crate::cdr::Rejection<'_>) {
        if let Some(cdr) = &self.cdr {
            cdr.emit_rejected(r);
        }
    }

    /// Enters draining mode: new INVITEs are rejected with 503 while
    /// existing dialogs continue (graceful shutdown).
    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    /// Number of active B2BUA calls (drain progress).
    pub async fn active_call_count(&self) -> usize {
        self.calls.read().await.len()
    }

    /// Sets the zone registry for zone-aware SIP processing.
    pub fn set_zone_registry(&mut self, registry: Arc<crate::zone::ResolvedZoneRegistry>) {
        self.zone_registry = Some(registry);
    }

    /// The SBC's listener port for `transport` (Via sent-by / Contact port,
    /// RFC 3261 §18.1.1: for TLS the TLS listener, not the UDP port).
    pub(crate) const fn signaling_port(&self, transport: AddrTransport) -> u16 {
        match transport {
            AddrTransport::Tls | AddrTransport::WebSocketSecure => self.config.tls_port,
            // RFC 7118 §5: a WS leg advertises the WebSocket listener.
            AddrTransport::WebSocket => self.config.ws_port,
            AddrTransport::Tcp | AddrTransport::Sctp => self.config.tcp_port,
            AddrTransport::Udp => self.config.udp_port,
        }
    }

    /// The host the SBC advertises as itself (Via sent-by and Contact) on an
    /// outbound leg: the egress zone's external IP when it has one, else
    /// that zone's signaling IP, else the configured domain. The port is
    /// the SBC listener for `transport` ([`Self::signaling_port`]).
    fn b_leg_signaling_addr(
        &self,
        ingress: Option<&str>,
        b_leg_external: bool,
        transport: AddrTransport,
    ) -> (String, u16) {
        let port = self.signaling_port(transport);
        let host = self.zone_registry.as_ref().and_then(|reg| {
            let zone = self
                .egress_media_zone(ingress, b_leg_external)
                .or_else(|| reg.zone_names().into_iter().next())?;
            reg.external_ip(&zone)
                .or_else(|| reg.signaling_ip(&zone))
                .map(|ip| ip.to_string())
        });
        (host.unwrap_or_else(|| self.config.domain.clone()), port)
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
                    .with_max_calls(t_config.max_calls)
                    .with_emergency_reserve_calls(t_config.effective_emergency_reserve_calls())
                    .with_cooldown_secs(u64::from(t_config.cooldown_secs))
                    .with_max_failures(t_config.max_failures)
                    .with_tls_client_cert(t_config.tls_client_cert);
                // NIST 800-53 Rev5: SC-23 — the name the trunk certificate
                // is verified against comes from config only.
                let trunk_config = match &t_config.tls_server_name {
                    Some(name) => trunk_config.with_tls_server_name(name),
                    None => trunk_config,
                };

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

    /// Processes an incoming SIP message received over UDP.
    ///
    /// `receiving_zone` is the zone name this message arrived on (if zones configured).
    pub async fn process_message(
        &self,
        data: &Bytes,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
    ) -> ProcessResult {
        self.process_message_on(data, source, receiving_zone, AddrTransport::Udp)
            .await
    }

    /// Processes an incoming SIP message received on `transport`. The
    /// result is sent back on the same transport, so the transactions it
    /// opens are reliable or unreliable to match (RFC 3261 §17).
    ///
    /// `receiving_zone` is the zone name this message arrived on (if zones configured).
    pub async fn process_message_on(
        &self,
        data: &Bytes,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
        transport: AddrTransport,
    ) -> ProcessResult {
        self.process_message_conn(data, source, receiving_zone, transport, None)
            .await
    }

    /// [`Self::process_message_on`] for a message read from stream
    /// connection `conn` (`None` for UDP). The id binds STIR endpoint
    /// attestation to the connection a REGISTER arrived on, not to its
    /// address (RFC 5626 §3.1, §5.2).
    ///
    /// ## NIST 800-53 Rev5: IA-3, SC-23 (Session Authenticity)
    pub async fn process_message_conn(
        &self,
        data: &Bytes,
        source: SbcSocketAddr,
        receiving_zone: Option<&str>,
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
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

        let mut result = match message {
            SipMessage::Request(_) => {
                self.process_request(message, source, receiving_zone, transport, conn)
                    .await
            }
            SipMessage::Response(_) => self.process_response(message, source).await,
        };
        // Everything a handler puts on the wire rides a transaction: responses
        // are recorded for retransmission, forwarded requests get a client
        // transaction that retransmits and times them out (RFC 3261 §17).
        // Replies are pinned to the receive transport first, so every
        // result leaves here with a concrete flow.
        resolve_reply(&mut result, transport);
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
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
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
            self.open_server_transaction(req, source, transport).await;
        }

        match method {
            Method::Register => self.handle_register(message, source, transport, conn).await,
            Method::Invite => {
                self.handle_invite(message, source, receiving_zone, transport, conn)
                    .await
            }
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
                            // §17.1.1.3: the ACK rides the INVITE's transport.
                            ack_action = Some(ProcessResult::Forward {
                                message: ack,
                                destination: st.destination,
                                flow: st.flow.clone().into(),
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
            && let Some((ack_branch, ack, dest, flow)) = addrs.last_reinvite_ack.as_ref()
            && *ack_branch == branch
        {
            return ProcessResult::Forward {
                message: ack.clone(),
                destination: *dest,
                flow: flow.clone().into(),
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
            if let Some(call) = calls.get_mut(internal_id) {
                let _ = call.receive_provisional(status_code);
            }
        }

        // First 18x: ring time / post-dial delay for the CDR (AU-3).
        if status_code > 100 && addrs.cdr.ring_ms.is_none() {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(internal_id) {
                a.cdr.record_ringing();
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

        // A reliable 18x (RFC 3262, RSeq) carrying SDP commits the caller to
        // this trunk's early media: no failover after it.
        if a_response.body.is_some()
            && resp
                .headers
                .iter()
                .any(|h| h.name.as_str().eq_ignore_ascii_case("RSeq"))
        {
            let mut corr = self.call_correlation.write().await;
            if let Some(a) = corr.addresses.get_mut(internal_id) {
                a.early_media_committed = true;
            }
        }

        info!(
            status = status_code,
            call_id = %addrs.a_leg_sip_call_id,
            "Forwarding provisional response to A-leg"
        );

        ProcessResult::Response {
            message: SipMessage::Response(a_response),
            destination: addrs.a_leg_source,
            flow: addrs.a_leg_flow.clone().into(),
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
                flow: addrs.b_leg_flow.clone().into(),
            };
        }

        // Activate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.get_mut(internal_id) {
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
                a.cdr.record_answer(resp.body.as_deref());
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
        let b_leg_uri = leg_request_uri(
            None,
            &addrs.b_leg_destination.ip().to_string(),
            addrs.b_leg_destination.port(),
            &addrs.b_leg_flow,
        );
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
            crate::flow::via_for(&addrs.b_leg_flow, &addrs.local_addr, &branch),
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
            addrs.a_leg_flow.clone(),
            cseq_number(&addrs.a_leg_cseq),
        )
        .await;

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: a_message,
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            },
            ProcessResult::Forward {
                message: SipMessage::Request(ack_request),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
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
        // A trunk failure (408/5xx, not a callee reject) fails over to the
        // next trunk of the route before the caller hears about it.
        let retry_after = if status_code == 503 {
            retry_after_cooldown(resp, self.config.trunk_retry_after_max_secs)
        } else {
            None
        };
        if is_failover_status(status_code)
            && let Some(retry) = self
                .try_failover(
                    internal_id,
                    addrs,
                    FailoverCause::Status(status_code, retry_after),
                )
                .await
        {
            return retry;
        }

        // No failover available — fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.get_mut(internal_id) {
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

        // Cleanup call state; RTP ports (C12), the trunk slot and the VPS
        // slot go with the correlation record.
        {
            let mut calls = self.calls.write().await;
            calls.remove(internal_id);
        }
        self.finish_call_record(
            internal_id,
            is_failover_status(status_code),
            crate::cdr::CdrEnd::trunk_final(status_code)
                .with_reasons(reason_headers(&resp.headers)),
        )
        .await;
        if status_code == 503
            && let (Some(lease), Some(router)) = (addrs.trunk_lease.as_ref(), self.router.as_ref())
        {
            router
                .write()
                .await
                .cooldown_trunk(&lease.group_id, &lease.trunk_id, retry_after);
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
            flow: addrs.a_leg_flow.clone().into(),
        }
    }

    /// Handles REGISTER request.
    ///
    /// Processes registration through `AuthenticatedRegistrar` which handles:
    /// - Digest authentication challenge/response (RFC 3261 §22)
    /// - Binding storage in `LocationService`
    /// - Expiration enforcement (min/max/default)
    /// - Wildcard removal (Contact: *)
    async fn handle_register(
        &self,
        message: SipMessage,
        source: SbcSocketAddr,
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
    ) -> ProcessResult {
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
                    flow: Flow::Reply,
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
                        flow: Flow::Reply,
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
                        flow: Flow::Reply,
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

        // general.max_registrations: refuse a REGISTER that would add
        // bindings past the node's cap. The registrar runs the check after
        // digest authentication succeeds (so an unauthenticated sender gets
        // 401, never a capacity signal) and before it stores anything, all
        // under the registrar write lock, so it is atomic with the insert.
        // New bindings are counted with the registrar's own de-dup: a
        // contact already bound for the AoR by contact URI or
        // +sip.instance/reg-id is an update whatever its Call-ID (RFC 3261
        // §10.3 step 7, e.g. a rebooted phone), repeated contacts count
        // once, and expires=0 / `Contact: *` / a query add nothing. Existing
        // phones can therefore always refresh or re-register at the cap.
        //
        // ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
        let max = self.config.max_registrations as usize;
        let mut over: Option<usize> = None;
        let admitted =
            registrar_guard.process_register_with_admission(&register_req, |total, new| {
                let fits = total.saturating_add(new) <= max;
                if !fits {
                    over = Some(total);
                }
                fits
            });
        let reg_response = match admitted {
            Ok(Some(resp)) => resp,
            Ok(None) => {
                let authenticated = registrar_guard.config().require_auth || self.bearer.is_some();
                drop(registrar_guard);
                warn!(
                    aor = %aor,
                    bindings = over.unwrap_or(0),
                    max_registrations = self.config.max_registrations,
                    "Registration capacity reached, rejecting REGISTER with 503"
                );
                // NIST 800-53 Rev5: AU-3 — the identity is only asserted as
                // authenticated when digest or bearer auth actually ran.
                let identity = if authenticated {
                    aor.clone()
                } else {
                    format!("unauthenticated:{aor}")
                };
                audit(uc_audit::AuditEvent::AuthorizationDecision(
                    uc_audit::event::AuthorizationDecision {
                        identity,
                        resource: req.uri.to_string(),
                        action: "REGISTER".to_string(),
                        granted: false,
                        policy: "max-registrations".to_string(),
                        source_ip: Some(source.ip()),
                    },
                ));
                let mut unavailable =
                    create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
                unavailable.headers.set(
                    HeaderName::RetryAfter,
                    REGISTRATION_CAPACITY_RETRY_AFTER_SECS.to_string(),
                );
                return ProcessResult::Response {
                    message: SipMessage::Response(unavailable),
                    destination: source,
                    flow: Flow::Reply,
                };
            }
            Err(e) => {
                warn!(error = %e, aor = %aor, "Registration processing failed");
                return ProcessResult::Response {
                    message: SipMessage::Response(create_response_from_request(
                        req,
                        StatusCode::SERVER_INTERNAL_ERROR,
                    )),
                    destination: source,
                    flow: Flow::Reply,
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
                    // Other devices' bindings keep the flow they were
                    // latched to when they registered (keyed by Call-ID).
                    let previous: Vec<proto_registrar::Binding> =
                        loc.lookup(&aor).into_iter().cloned().collect();
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
                    // REGISTER actually arrived on. That is the receiver's
                    // observation, not the (sender-asserted) Via token.
                    // NIST 800-53 Rev5: SC-8 — a binding learned over TLS is
                    // only ever reached over that TLS connection.
                    let recv_transport = LegFlow::inbound(transport).name();
                    for binding in &reg_response.contacts {
                        // Only the binding created/refreshed by *this*
                        // REGISTER (same Call-ID) is reachable via the source
                        // pinhole. Another device's wildcard Contact is not
                        // latched to this source (SEC-008: that would hand
                        // this peer's flow to the other device's AOR binding);
                        // it stays unroutable (see `binding_target`).
                        // NIST 800-53 Rev5: SC-8, AC-3
                        let is_this_device = binding.call_id() == call_id;
                        if is_this_device {
                            // SipUri's display brackets IPv6 hosts.
                            let contact_uri = proto_sip::uri::SipUri::new(src_ip.clone())
                                .with_user(aor_user)
                                .with_port(src_port)
                                .with_param("transport", Some(recv_transport.to_string()))
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
                            latched.set_source_addr(std::net::SocketAddr::from(source));
                            latched.set_source_transport(recv_transport);
                            let _ = loc.add_binding(latched);
                        } else if let Some(prev) = previous.iter().find(|p| {
                            p.call_id() == binding.call_id() && p.source_transport().is_some()
                        }) {
                            let mut kept = proto_registrar::Binding::new(
                                &aor,
                                prev.contact_uri(),
                                binding.call_id(),
                                binding.cseq(),
                            );
                            let _ = kept.set_expires(binding.remaining_seconds());
                            if let Some(a) = prev.source_addr() {
                                kept.set_source_addr(a);
                            }
                            if let Some(t) = prev.source_transport() {
                                kept.set_source_transport(t);
                            }
                            let _ = loc.add_binding(kept);
                        } else {
                            let _ = loc.add_binding(binding.clone());
                        }
                    }
                    // STIR flow index (SEC-008/SEC-009): the flow this
                    // REGISTER actually arrived on (received source and
                    // transport, not the declared Contact) now binds the
                    // AOR, or no longer does after a de-registration. For
                    // TCP/TLS the entry is also bound to the connection id,
                    // so a later connection on a reused address does not
                    // inherit it (RFC 5626 §3.1, §5.2; IA-3, SC-23).
                    {
                        let key = crate::stir_binding::flow_key(source.ip(), src_port, transport);
                        let this_bound =
                            reg_response.contacts.iter().any(|b| b.call_id() == call_id);
                        let mut flows = self.stir_flows.write().await;
                        if this_bound {
                            let cap = self.config.max_registrations as usize;
                            let indexed = flows.bind(key, conn, &aor, cap, |k, a| {
                                Self::flow_has_binding(&loc, a, k)
                            });
                            if !indexed {
                                debug!(aor = %aor, "STIR flow index full; flow not indexed");
                            }
                        } else {
                            flows.unbind(&key, conn, &aor);
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
            flow: Flow::Reply,
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
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
    ) -> ProcessResult {
        let SipMessage::Request(ref req) = message else {
            return ProcessResult::Error {
                reason: "Expected request".to_string(),
            };
        };

        let a_leg_call_id = req.headers.call_id().unwrap_or("unknown").to_string();
        let invite_received_ms = crate::cdr::now_ms();

        debug!(uri = %req.uri, call_id = %a_leg_call_id, "Processing INVITE");

        // Mid-dialog INVITE (To carries a tag): a re-INVITE on an established
        // dialog (RFC 3261 §14), relayed to the other leg — or 481 when no
        // dialog matches (§12.2.2). Admission is the dialog match itself.
        if req.headers.to_tag().is_some() {
            return self.handle_in_dialog_request(req, source).await;
        }

        // Emergency calls (dialed Request-URI user, before any translation);
        // see the admission bypass below.
        let emergency = self
            .config
            .emergency_numbers
            .matches(req.uri.user.as_deref().unwrap_or(""));

        // CDR for an INVITE refused before the call is stored (plan §0
        // reject sites). Rejections the RFC answers with a challenge
        // (401/407) and ACL/DoS drops never reach these sites, and the
        // source-admission 403 below is an ACL-layer reject (audited as an
        // AuthorizationDecision, no CDR) so a spoofed-source flood cannot
        // fill the CDR volume. Every reject site is after the retransmit
        // check, and `CdrContext::emit_rejected` drops repeats of a
        // Call-ID, so a retransmitted INVITE yields one CDR.
        //
        // ## NIST 800-53 Rev5: AU-2, AU-12
        let from_header = req.headers.get_value(&HeaderName::From).unwrap_or("");
        let from_uri = extract_uri_from_header(from_header);
        let reject_cdr = |status: u16, cause: uc_cdr::ReleaseCause| {
            self.cdr_reject(&crate::cdr::Rejection {
                a_call_id: &a_leg_call_id,
                from: &from_uri,
                callee: req.uri.user.as_deref().unwrap_or(""),
                source,
                transport,
                zone: receiving_zone,
                emergency,
                status,
                cause,
            });
        };

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
                flow: Flow::Reply,
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
            reject_cdr(503, uc_cdr::ReleaseCause::Draining);
            let unavailable = create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
            return ProcessResult::Response {
                message: SipMessage::Response(unavailable),
                destination: source,
                flow: Flow::Reply,
            };
        }

        // `cdr.on_failure = "reject_new_calls"`: while the CDR pipeline is
        // unhealthy, new calls that could not be accounted for are refused.
        // Emergency calls are never refused for an accounting failure.
        //
        // ## NIST 800-53 Rev5: AU-5(4); 47 CFR 9.16
        if !emergency && self.cdr.as_ref().is_some_and(|c| c.rejecting_new_calls()) {
            warn!(
                call_id = %a_leg_call_id,
                "CDR pipeline unhealthy (cdr.on_failure = reject_new_calls); rejecting INVITE"
            );
            audit_invite_denied(req, source, "cdr-unavailable");
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            reject_cdr(503, uc_cdr::ReleaseCause::PolicyDenied);
            let mut unavailable =
                create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
            unavailable.headers.set(
                HeaderName::RetryAfter,
                TRUNK_UNAVAILABLE_RETRY_AFTER_SECS.to_string(),
            );
            return ProcessResult::Response {
                message: SipMessage::Response(unavailable),
                destination: source,
                flow: Flow::Reply,
            };
        }

        // Emergency calls (dialed Request-URI user, before any translation)
        // are not refused while held normal calls fill `general.max_calls`
        // or trunk `max_calls`: they may use a bounded emergency reserve
        // above each, and skip VPS number/caller screening. Source
        // admission (above), authentication, operator source-IP blocks and
        // the transport flood limiter still apply; every bypass is audited.
        //
        // ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5, AU-2
        let admission = if emergency {
            Admission::Emergency
        } else {
            Admission::Normal
        };

        // Admission control: reject new calls beyond the configured ceiling
        // (general.max_calls) instead of allocating unbounded state.
        // Emergency calls may also use `emergency_reserve_calls` above it,
        // never more; normal calls never reach the reserve.
        //
        // The slot is reserved atomically here and held in `call_slot` until
        // the call is stored (step 8); every earlier return drops it, which
        // releases it. One shared counter keeps the reserve semantics: normal
        // calls stop at `max_calls`, emergency calls use ordinary slots first.
        //
        // ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection); 47 CFR 9.16
        let call_slot = {
            let ceiling = if emergency {
                self.config
                    .max_calls
                    .saturating_add(self.config.emergency_reserve_calls)
            } else {
                self.config.max_calls
            };
            let Some(slot) = try_reserve_slot(
                &self.admitted_calls,
                usize::try_from(ceiling).unwrap_or(usize::MAX),
            ) else {
                warn!(
                    call_id = %a_leg_call_id,
                    max_calls = self.config.max_calls,
                    ceiling,
                    emergency,
                    "Maximum concurrent calls reached, rejecting INVITE"
                );
                self.in_flight_invites.write().await.remove(&a_leg_call_id);
                reject_cdr(503, uc_cdr::ReleaseCause::AdmissionMaxCalls);
                let unavailable =
                    create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
                return ProcessResult::Response {
                    message: SipMessage::Response(unavailable),
                    destination: source,
                    flow: Flow::Reply,
                };
            };
            slot
        };

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
                flow: Flow::Reply,
            };
        }
        let b_leg_max_forwards = incoming_max_forwards - 1;

        // STIR/SHAKEN verification (RFC 8224 §6.2) on INVITEs from trunks
        // with `stir_shaken.verify`. Before VPS so `[vps.stir_shaken]`
        // screening sees the outcome. A certificate cache miss waits here
        // (bounded by cert_fetch_timeout_ms) on this INVITE's task only.
        //
        // ## NIST 800-53 Rev5: IA-9, SI-10, SC-5
        let stir_in = match self.stir.as_ref() {
            Some(stir) => stir.inbound(req, source.ip(), &a_leg_call_id).await,
            None => crate::stir::InboundStir::default(),
        };
        if let Some(reason) = stir_in.reject {
            let code = reason.sip_code();
            warn!(
                call_id = %a_leg_call_id,
                code,
                reason = reason.as_str(),
                "STIR/SHAKEN verification failed, rejecting INVITE"
            );
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            reject_cdr(code, uc_cdr::ReleaseCause::PolicyDenied);
            let mut rejection = create_response_from_request(
                req,
                StatusCode::new(code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
            );
            // RFC 8224 §6.2.2: the registered phrase on the status line
            // (403 "Stale Date" rather than "Forbidden") and a Reason header
            // carrying the failure code.
            rejection.reason = Some(reason.sip_reason_phrase().to_owned());
            rejection.headers.set(
                HeaderName::Reason,
                format!("SIP;cause={code};text=\"{}\"", reason.sip_reason_phrase()),
            );
            return ProcessResult::Response {
                message: SipMessage::Response(rejection),
                destination: source,
                flow: Flow::Reply,
            };
        }

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
        //
        // `per_callee_max_concurrent` is checked and the slot reserved in one
        // step, keyed on the dialed (pre-translation) number; the slot rides
        // the call record and is released with it.
        let mut vps_callee: Option<String> = None;
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
                .with_direction(direction)
                .with_stir_shaken(stir_in.vps_status);
            if let Some(from) = req.headers.get_value(&HeaderName::From) {
                attempt = attempt.with_from_uri(extract_uri_from_header(from));
            }
            let (verdict, reserved) = vps.lock().await.screen_and_reserve(&attempt);
            vps_callee = reserved;
            match verdict.action() {
                uc_vps::VpsAction::Allow => {
                    if verdict.source() == uc_vps::VerdictSource::EmergencyBypass {
                        info!(call_id = %a_leg_call_id, "Emergency call: VPS screening bypassed");
                    }
                }
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
                    reject_cdr(*status_code, uc_cdr::ReleaseCause::PolicyDenied);
                    let rejection = create_response_from_request(
                        req,
                        StatusCode::new(*status_code).unwrap_or(StatusCode::SERVER_INTERNAL_ERROR),
                    );
                    return ProcessResult::Response {
                        message: SipMessage::Response(rejection),
                        destination: source,
                        flow: Flow::Reply,
                    };
                }
                uc_vps::VpsAction::Drop => {
                    warn!(
                        call_id = %a_leg_call_id,
                        stage = ?verdict.source(),
                        emergency,
                        "VPS dropped INVITE (blocked source)"
                    );
                    // A dropped emergency call is always audited; other
                    // silent drops are not (flood amplification).
                    if emergency {
                        audit_invite_denied(req, source, "vps:blocklist");
                    }
                    self.in_flight_invites.write().await.remove(&a_leg_call_id);
                    return ProcessResult::NoAction;
                }
            }
        }

        // Audited (and counted) once the emergency call has passed the
        // bounded reserve and the operator source-IP blocklist.
        //
        // ## 47 CFR 9.16; NIST 800-53 Rev5: AU-2, SI-4
        if emergency {
            audit_emergency_bypass(req, source);
            self.emergency_admissions.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Look up destination:
        //    a) Check DID → user mapping, then LocationService
        //    b) Check LocationService directly for registered users
        //    c) Try SBC router (CSS/Partition)
        //    d) Try dial plan router
        //    e) Fall back to announcement
        // Direction of the outbound leg: true when it crosses to an untrusted
        // (trunk/carrier) destination, false for a registered internal user.
        // Gates topology hiding so only outside-facing legs are anonymized
        // (rewriting an inside-facing leg's Via/Contact would misroute it).
        let mut b_leg_external = false;
        // Trunk slot, failover targets and translated number when the call
        // is routed to a trunk.
        let mut trunk_route: Option<TrunkRoute> = None;
        // Transport toward the callee: the registered contact's, or the
        // trunk's configured protocol (set below). NIST 800-53 Rev5: SC-8.
        let b_leg_flow: LegFlow;
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
                        info!(aor = %aor, contact = %binding.contact_uri(), "Routing to registered user");
                        found_contact = Some((*binding).clone());
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
                                info!(aor = %aor, contact = %binding.contact_uri(), zone = zone_name, "Routing to registered user via zone lookup");
                                found_contact = Some((*binding).clone());
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
                    info!(aor = %dest_aor, contact = %binding.contact_uri(), "Routing to registered user");
                    found_contact = Some((*binding).clone());
                }
            }
            drop(loc);

            if let Some(binding) = found_contact {
                if let Some((flow, dest)) = binding_target(&binding) {
                    b_leg_flow = flow;
                    Some(dest)
                } else {
                    b_leg_flow = LegFlow::UDP;
                    None
                }
            } else {
                // Not registered — route to a trunk: SBC router (CSS-based),
                // then dial plan.
                //
                // Identify which trunk group this inbound call came from (by
                // source IP) and get its assigned CSS for routing
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

                match self
                    .route_to_trunk(&dest_user, css_id_owned.as_deref(), admission)
                    .await
                {
                    TrunkRouting::Routed(route) => {
                        // Routed to a trunk/carrier — this outbound leg faces
                        // an untrusted zone, so topology hiding (if enabled)
                        // applies.
                        b_leg_external = true;
                        let destination = route.destination;
                        b_leg_flow = route.endpoint.flow.clone();
                        trunk_route = Some(*route);
                        Some(destination)
                    }
                    TrunkRouting::NoRoute => {
                        warn!(dest = %dest_aor, "No route found — playing announcement");
                        self.in_flight_invites.write().await.remove(&a_leg_call_id);
                        self.release_slots(None, vps_callee.as_deref(), TrunkOutcome::Abandoned)
                            .await;
                        let result = self
                            .play_announcement_to_caller(
                                req,
                                source,
                                crate::announcement::AnnouncementType::NumberNotInService,
                            )
                            .await;
                        reject_cdr(final_status(&result), uc_cdr::ReleaseCause::NoRoute);
                        return result;
                    }
                    TrunkRouting::Unavailable => {
                        // Every trunk of the matched route is down, cooling
                        // down or at max_calls: 503 + Retry-After (RFC 3261
                        // §21.5.4), no queuing.
                        //
                        // ## NIST 800-53 Rev5: SC-5, SI-17 (Fail-Safe Procedures)
                        warn!(call_id = %a_leg_call_id, dest = %dest_user, "No usable trunk (all down or at capacity), rejecting INVITE with 503");
                        audit_invite_denied(req, source, "no-usable-trunk");
                        self.in_flight_invites.write().await.remove(&a_leg_call_id);
                        reject_cdr(503, uc_cdr::ReleaseCause::NoRoute);
                        self.release_slots(None, vps_callee.as_deref(), TrunkOutcome::Abandoned)
                            .await;
                        let mut unavailable =
                            create_response_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
                        unavailable.headers.set(
                            HeaderName::RetryAfter,
                            TRUNK_UNAVAILABLE_RETRY_AFTER_SECS.to_string(),
                        );
                        return ProcessResult::Response {
                            message: SipMessage::Response(unavailable),
                            destination: source,
                            flow: Flow::Reply,
                        };
                    }
                    TrunkRouting::InvalidTranslation => {
                        audit_invite_denied(req, source, "number-translation-invalid");
                        self.in_flight_invites.write().await.remove(&a_leg_call_id);
                        reject_cdr(500, uc_cdr::ReleaseCause::NoRoute);
                        self.release_slots(None, vps_callee.as_deref(), TrunkOutcome::Abandoned)
                            .await;
                        let server_err =
                            create_response_from_request(req, StatusCode::SERVER_INTERNAL_ERROR);
                        return ProcessResult::Response {
                            message: SipMessage::Response(server_err),
                            destination: source,
                            flow: Flow::Reply,
                        };
                    }
                }
            }
        };

        let Some(b_leg_destination) = b_leg_destination else {
            warn!(dest = %dest_aor, "Cannot resolve destination — playing announcement");
            self.in_flight_invites.write().await.remove(&a_leg_call_id);
            self.release_slots(None, vps_callee.as_deref(), TrunkOutcome::Abandoned)
                .await;
            let result = self
                .play_announcement_to_caller(
                    req,
                    source,
                    crate::announcement::AnnouncementType::NumberNotInService,
                )
                .await;
            reject_cdr(final_status(&result), uc_cdr::ReleaseCause::NoRoute);
            return result;
        };

        // Number translation (SBC route-pattern / dial-plan transforms): the
        // B-leg Request-URI and To carry the translated number; the dialed
        // number stays the key for VPS, audit and retransmit detection. A
        // B2BUA builds its own To as a new UAC (RFC 3261 §8.1.1.2).
        let (trunk_lease, failover_targets, b_leg_user, trunk_endpoint) = match trunk_route {
            Some(route) => (
                Some(route.lease),
                route.failover,
                route.translated,
                Some(route.endpoint),
            ),
            None => (None, Vec::new(), dest_user.clone(), None),
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
        // RFC 3261 §18.1.1: the sent-by port is the listener of the B-leg
        // transport; the A-leg's is the listener the INVITE arrived on.
        let (local_ip, local_port) =
            self.b_leg_signaling_addr(receiving_zone, b_leg_external, b_leg_flow.transport);
        let local_sip_addr = host_port(&local_ip, local_port);
        let a_leg_local_addr = {
            let (ip, port) = self.b_leg_signaling_addr(receiving_zone, false, transport);
            host_port(&ip, port)
        };

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
        let mut media_node: Option<String> = None;
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
                        media_node = Some(node_ip.to_string());
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

        // Toward a trunk the Request-URI is the trunk's own (scheme from its
        // protocol, its host/port), the same derivation failover uses
        // (RFC 3261 §19.1.1, §26.2; RFC 3263 §4.1). Toward a registered
        // user it keeps the dialed host.
        let b_leg_uri = trunk_endpoint.as_ref().map_or_else(
            || {
                let mut uri = SipUri::new(&dest_host).with_user(&b_leg_user);
                if let Some(port) = req.uri.port {
                    uri.port = Some(port);
                }
                uri
            },
            |e| leg_request_uri(Some(&b_leg_user), &e.host, e.port, &b_leg_flow),
        );
        let contact_uri = match b_leg_flow.transport {
            AddrTransport::Tls => SipUri::new_sips(&local_ip).with_port(local_port),
            AddrTransport::Udp => SipUri::new(&local_ip).with_port(local_port),
            _ => SipUri::new(&local_ip)
                .with_port(local_port)
                .with_param("transport", Some(b_leg_flow.name().to_string())),
        };

        let mut builder = RequestBuilder::invite(b_leg_uri)
            .via_auto(b_leg_flow.via_token(), &local_ip, Some(local_port))
            .from_auto(
                SipUri::new(&self.config.domain).with_user(&self.config.instance_name),
                None,
            )
            .to_uri(SipUri::new(&dest_host).with_user(&b_leg_user), None)
            .call_id(&b_leg_sip_call_id)
            .cseq(1)
            .max_forwards(b_leg_max_forwards)
            .contact_uri(contact_uri);

        if let Some(ref sdp) = b_leg_sdp {
            builder = builder.body_sdp(sdp.as_bytes().to_vec());
        }

        let mut b_leg_request = match builder.build_with_defaults() {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build B-leg INVITE");
                self.in_flight_invites.write().await.remove(&a_leg_call_id);
                self.release_slots(
                    trunk_lease.as_ref(),
                    vps_callee.as_deref(),
                    TrunkOutcome::Abandoned,
                )
                .await;
                self.release_rtp_port(b_leg_rtp_port);
                if let Some(ref pipeline) = self.media_pipeline {
                    let _ = pipeline.remove_session(&session_key).await;
                }
                let server_err =
                    create_response_from_request(req, StatusCode::SERVER_INTERNAL_ERROR);
                return ProcessResult::Response {
                    message: SipMessage::Response(server_err),
                    destination: source,
                    flow: Flow::Reply,
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

        // Failover re-sends this INVITE (fresh Call-ID/branch/tag), so keep
        // a copy only when there is somewhere to fail over to. It is taken
        // before the STIR step so each attempt redoes that step for its own
        // trunk (no stale Identity/iat, no PAI toward sign=false trunks).
        let b_leg_invite = (!failover_targets.is_empty()).then(|| Arc::new(b_leg_request.clone()));

        // 7d. STIR/SHAKEN on the B-leg: relay a trusted trunk's Identity
        // verbatim, otherwise on a `sign = true` egress trunk assert the
        // caller's number in P-Asserted-Identity (RFC 3325 trust domain:
        // A-leg PAI only from a trunk peer) and sign at egress (after
        // translation and header manipulation, so orig/dest match the
        // wire), then set (or strip) verstat (ATIS-1000074 §5.3.1).
        //
        // ## NIST 800-53 Rev5: IA-9; RFC 8224 §5; RFC 3325 §5
        let mut stir_signed: Option<proto_stir_shaken::Attestation> = None;
        let mut stir_egress: Option<Arc<crate::stir::StirEgress>> = None;
        if let Some(stir) = self.stir.as_ref() {
            let source_trunk = self
                .lookup_inbound_trunk(source.ip())
                .await
                .map(|(group, _)| group);
            // Endpoint callers are "authenticated" only when this INVITE is
            // bound to a registration from this flow and REGISTER auth is
            // on; the caller TN is then the one provisioned for that AOR,
            // never an arbitrary From (SEC-001). Only looked up when some
            // trunk this call may use signs (PERF-008): otherwise nothing
            // consumes it.
            let may_sign = trunk_lease
                .as_ref()
                .is_some_and(|l| stir.signs(&l.trunk_id))
                || failover_targets.iter().any(|(_, t)| stir.signs(t));
            let binding = if may_sign && source_trunk.is_none() && self.register_auth_enabled() {
                self.stir_endpoint_binding(source, transport, conn, &from_uri)
                    .await
            } else {
                None
            };
            let authenticated = binding.is_some();
            let assigned_tn = binding.flatten();
            // SEC-009: the flow match proves the provisioned TN only when the
            // source cannot be spoofed off-path. A UDP-bound caller is still
            // authenticated (its number is asserted) but is capped at B.
            // POAM: no per-INVITE digest challenge, so a UDP caller has no
            // path to A.
            let attest_tn = assigned_tn
                .as_deref()
                .filter(|_| crate::stir_binding::flow_is_connection_oriented(transport))
                .and_then(proto_stir_shaken::canonicalize_tn);
            let egress = crate::stir::StirEgress {
                caller_pai: crate::stir::caller_identity(
                    &req.headers,
                    source_trunk.is_some(),
                    assigned_tn.as_deref(),
                    &self.config.domain,
                ),
                source_trunk,
                source_realm: receiving_zone.map(str::to_owned),
                authenticated,
                assigned_tn: attest_tn,
                call_id: a_leg_call_id.clone(),
                dest_user: b_leg_user.clone(),
                passthrough_identity: stir_in.passthrough_identity.clone(),
                verstat: stir_in.egress_verstat,
            };
            stir_signed = stir.apply_egress(
                &mut b_leg_request.headers,
                trunk_lease.as_ref().map(|l| l.trunk_id.as_str()),
                &egress,
            );
            if b_leg_invite.is_some() {
                stir_egress = Some(Arc::new(egress));
            }
        }

        // CDR draft: the facts known at admission/routing (AU-3).
        let cdr_draft = if self.cdr.is_some() {
            // Caller translation: the B-leg From user after header
            // manipulation, when a rule changed it. The B2BUA's own default
            // From identity (`instance_name`) is not a translation.
            let caller = crate::cdr::uri_user(&from_uri).to_string();
            let caller_translated = b_leg_request
                .headers
                .get_value(&HeaderName::From)
                .map(extract_uri_from_header)
                .map(|u| crate::cdr::uri_user(&u).to_string())
                .filter(|u| !u.is_empty() && *u != caller && *u != self.config.instance_name);
            let from_trunk = self
                .inbound_trunk_map
                .read()
                .await
                .contains_key(&source.ip());
            crate::cdr::CdrDraft {
                setup_ms: invite_received_ms,
                a_call_id: a_leg_call_id.clone(),
                b_call_ids: vec![b_leg_sip_call_id.clone()],
                internal_call_id: internal_call_id.to_string(),
                direction: if from_trunk {
                    uc_cdr::Direction::Inbound
                } else if b_leg_external {
                    uc_cdr::Direction::Outbound
                } else {
                    uc_cdr::Direction::Internal
                },
                caller,
                caller_translated,
                callee_dialed: dest_user.clone(),
                callee_translated: (b_leg_user != dest_user).then(|| b_leg_user.clone()),
                source_ip: source.ip().to_string(),
                source_port: source.port(),
                transport: crate::cdr::transport_of(transport),
                ingress_zone: receiving_zone.map(str::to_string),
                egress_zone: egress_zone.clone(),
                trunk_group: trunk_lease.as_ref().map(|l| l.group_id.clone()),
                current_trunk: trunk_lease.as_ref().map(|l| l.trunk_id.clone()),
                media_anchored: media_a_leg_port.is_some(),
                media_node,
                emergency,
                stir_attestation: stir_signed.map(crate::stir::cdr_attestation),
                stir_verstat: stir_in.cdr_verstat.map(crate::stir::cdr_verstat),
                stir_verify_reason: stir_in.reason.map(|r| r.as_str().to_string()),
                stir_inbound_attestation: stir_in.inbound_attest.map(crate::stir::cdr_attestation),
                stir_x5u_host: stir_in.x5u_host.clone(),
                ..crate::cdr::CdrDraft::default()
            }
        } else {
            crate::cdr::CdrDraft::default()
        };

        // 8. Store call state and correlation
        {
            let mut calls = self.calls.write().await;
            calls.insert(internal_call_id.clone(), call, call_slot);
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
                    a_leg_flow: LegFlow::inbound(transport),
                    b_leg_flow: b_leg_flow.clone(),
                    a_leg_local_addr,
                    a_leg_sip_call_id: a_leg_call_id.clone(),
                    b_leg_sip_call_id: b_leg_sip_call_id.clone(),
                    local_addr: local_sip_addr,
                    failover_targets,
                    trunk_lease,
                    vps_callee,
                    b_leg_invite,
                    b_leg_ruri: Some(b_leg_request.uri.clone()),
                    stir_egress,
                    early_media_committed: false,
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
                    cdr: cdr_draft,
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
                flow: Flow::Reply,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_leg_request),
                destination: b_leg_destination,
                flow: b_leg_flow.into(),
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
                flow: Flow::Reply,
            };
        };

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
                flow: Flow::Reply,
            };
        };
        let addrs = a.clone();
        drop(corr);

        // Terminate the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.get_mut(&internal_id) {
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
        let other_call_id = if is_from_a_leg {
            &addrs.b_leg_sip_call_id
        } else {
            &addrs.a_leg_sip_call_id
        };
        // The other leg's own transport (NIST 800-53 Rev5: SC-8): a BYE from
        // the caller goes to the trunk over the trunk's flow, never back down
        // the caller's connection.
        let (other_dest, other_flow) = addrs.leg_target(is_from_a_leg);
        let other_sent_by = addrs.leg_sent_by(is_from_a_leg);

        let use_cancel = is_from_a_leg && addrs.dialog_to_tag.is_none();

        let other_uri = leg_request_uri(
            None,
            &other_dest.ip().to_string(),
            other_dest.port(),
            &other_flow,
        );
        let forward_request = if use_cancel {
            // Early dialog: send CANCEL mirroring the original INVITE
            // (same Via branch, From, To without tag).
            let mut cancel_req = proto_sip::message::SipRequest::new(Method::Cancel, other_uri);
            cancel_req.headers.set(HeaderName::CallId, other_call_id);
            cancel_req.headers.set(HeaderName::CSeq, "1 CANCEL");
            cancel_req.headers.set(HeaderName::From, &addrs.b_leg_from);
            cancel_req.headers.set(HeaderName::To, &addrs.b_leg_to);
            cancel_req.headers.set(HeaderName::MaxForwards, "70");
            // RFC 3261 §9.1: same Via (transport, sent-by, branch) as the
            // INVITE being cancelled.
            cancel_req.headers.add(Header::new(
                HeaderName::Via,
                crate::flow::via_for(&other_flow, other_sent_by, &addrs.b_leg_branch),
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
                crate::flow::via_for(&other_flow, other_sent_by, &branch),
            ));
            bye_request.headers.set(HeaderName::ContentLength, "0");
            bye_request
        };

        // Clean up call state; RTP ports (C12) and the trunk / VPS slots
        // are released with the correlation record, exactly once.
        {
            let mut calls = self.calls.write().await;
            calls.remove(&internal_id);
        }
        self.finish_call_record(
            &internal_id,
            false,
            crate::cdr::CdrEnd::bye(is_from_a_leg, addrs.b_leg_answered)
                .with_reasons(reason_headers(&req.headers)),
        )
        .await;

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
                flow: Flow::Reply,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(forward_request),
                destination: other_dest,
                flow: other_flow.into(),
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
                flow: Flow::Reply,
            };
        };
        let internal_id = id.clone();

        let Some(a) = corr.addresses.get(&internal_id) else {
            let response = create_response_from_request(req, StatusCode::CALL_DOES_NOT_EXIST);
            return ProcessResult::Response {
                message: SipMessage::Response(response),
                destination: source,
                flow: Flow::Reply,
            };
        };
        let addrs = a.clone();
        drop(corr);

        // Fail the call
        {
            let mut calls = self.calls.write().await;
            if let Some(call) = calls.get_mut(&internal_id) {
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
        // RFC 3261 §9.1: the Request-URI is the current attempt's INVITE
        // Request-URI (updated on failover); the socket-address form is only
        // a fallback for records that predate it.
        let b_uri = addrs.b_leg_ruri.clone().unwrap_or_else(|| {
            leg_request_uri(
                None,
                &addrs.b_leg_destination.ip().to_string(),
                addrs.b_leg_destination.port(),
                &addrs.b_leg_flow,
            )
        });
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
            crate::flow::via_for(&addrs.b_leg_flow, &addrs.local_addr, &addrs.b_leg_branch),
        ));
        b_cancel.headers.set(HeaderName::ContentLength, "0");

        // Clean up; RTP ports (C12) and the trunk / VPS slots are released
        // with the correlation record, exactly once.
        {
            let mut calls = self.calls.write().await;
            calls.remove(&internal_id);
        }
        self.finish_call_record(
            &internal_id,
            false,
            crate::cdr::CdrEnd::cancel().with_reasons(reason_headers(&req.headers)),
        )
        .await;

        info!(call_id = %sip_call_id, "Call cancelled");
        audit_call_terminated(&addrs, uc_audit::event::TerminationReason::Canceled);

        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(cancel_ok),
                destination: source,
                flow: Flow::Reply,
            },
            ProcessResult::Response {
                message: SipMessage::Response(terminated),
                destination: source,
                flow: Flow::Reply,
            },
            ProcessResult::Forward {
                message: SipMessage::Request(b_cancel),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
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
            flow: Flow::Reply,
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
                    flow: Flow::Reply,
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
            flow: Flow::Reply,
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

    /// `general.max_calls` slots currently held (stored calls plus INVITEs
    /// being admitted).
    #[cfg(test)]
    fn admitted_call_slots(&self) -> usize {
        self.admitted_calls.load(Ordering::Acquire)
    }

    /// Returns the number of active calls.
    pub async fn call_count(&self) -> usize {
        self.calls.read().await.len()
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
                    state: format!("{:?}", call.call.state()),
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
                    attestation: addrs
                        .and_then(|a| a.cdr.stir_attestation.or(a.cdr.stir_inbound_attestation))
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default(),
                    verstat: addrs
                        .and_then(|a| a.cdr.stir_verstat)
                        .map(|v| v.as_str().to_string())
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

    /// Whether `aor` still has a live binding whose contact is the flow
    /// `key` (IP, port and, when the contact says, transport). Looks at
    /// that one AOR's bindings only.
    fn flow_has_binding(
        loc: &LocationService,
        aor: &str,
        key: &crate::stir_binding::FlowKey,
    ) -> bool {
        let (ip, port, transport) = *key;
        let transport_name = transport.to_string();
        loc.lookup(aor).iter().any(|b| {
            b.contact_uri().parse::<SipUri>().is_ok_and(|c| {
                c.host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|h| h.to_canonical() == ip)
                    && c.port.unwrap_or_else(|| transport.default_sip_port()) == port
                    && c.params.iter().all(|(k, v)| {
                        !k.eq_ignore_ascii_case("transport")
                            || v.as_deref()
                                .is_none_or(|t| t.eq_ignore_ascii_case(&transport_name))
                    })
            })
        })
    }

    /// Records that `aor` registered from `source` over `transport` in the
    /// STIR flow index (tests that seed the location service directly).
    #[cfg(test)]
    async fn index_stir_flow(
        &self,
        aor: &str,
        source: SbcSocketAddr,
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
    ) {
        let key = crate::stir_binding::flow_key(source.ip(), source.port(), transport);
        let cap = self.config.max_registrations as usize;
        let _ = self
            .stir_flows
            .write()
            .await
            .bind(key, conn, aor, cap, |_, _| true);
    }

    /// Releases the STIR flow binding of stream connection `conn` when it
    /// closes, so a new connection that reuses the address (CGNAT) cannot
    /// inherit attestation A. Takes only the `stir_flows` lock (never the
    /// location lock), so it cannot invert the REGISTER lock order. A
    /// connection that never bound (the common case) costs only a read
    /// lock.
    ///
    /// ## NIST 800-53 Rev5: SC-23 (Session Authenticity), IA-3
    pub async fn connection_closed(&self, conn: crate::stir_binding::ConnId) {
        if !self.stir_flows.read().await.has_conn(conn) {
            return;
        }
        self.stir_flows.write().await.unbind_conn(conn);
    }

    /// STIR caller binding for an endpoint INVITE (RFC 8588 §4 attestation
    /// inputs). `None`: the INVITE is not bound to a registration from this
    /// flow (received IP, port and transport of the REGISTER, re-checked
    /// against the AOR's live binding, and for TCP/TLS the same connection
    /// `conn` the REGISTER arrived on), so the caller is not authenticated.
    /// A TCP/TLS connection-id mismatch is fail-secure: unauthenticated,
    /// never capped-at-B (local policy; ATIS-1000074 does not define
    /// connection binding).
    ///
    /// POAM: POA&M-70 TLS peer-certificate fingerprint is not bound to the entry;
    /// `Transport` does not expose peer certificates to the SIP stack. The
    /// unique connection id covers a single TLS session.
    /// `Some(tn)`: bound to a registered AOR; `tn` is the number provisioned
    /// for that AOR (the AOR user when it is a TN, else a DID mapped to it),
    /// or `None` when it has none.
    ///
    /// The From user must be the bound AOR user, or a DID mapped to it, so a
    /// registered endpoint cannot claim another subscriber's number.
    ///
    /// O(1) per INVITE (SEC-008): one flow-index lookup, the bindings of at
    /// most [`crate::stir_binding::MAX_AORS_PER_FLOW`] AORs, and keyed DID
    /// index lookups; no scan of the location service or DID map.
    ///
    /// The binding store is the in-process `location_service` in every
    /// mode: REGISTER always writes it, including when a cluster
    /// `AsyncLocationService` is attached (that store is not consulted by
    /// the SIP stack). POAM: a phone registered on another cluster node is
    /// unbound here, so its INVITEs are not attested A/B on this node.
    ///
    /// ## NIST 800-53 Rev5: IA-3 (Device Identification and Authentication), IA-9, SI-10
    async fn stir_endpoint_binding(
        &self,
        source: SbcSocketAddr,
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
        from_uri: &str,
    ) -> Option<Option<String>> {
        let from_user = from_uri.parse::<SipUri>().ok()?.user?;
        let key = crate::stir_binding::flow_key(source.ip(), source.port(), transport);
        let candidates: Vec<String> = self.stir_flows.read().await.get(&key, conn)?.to_vec();
        let bound_users: Vec<String> = {
            let loc = self.location_service.read().await;
            candidates
                .iter()
                .filter(|aor| Self::flow_has_binding(&loc, aor, &key))
                .filter_map(|aor| aor.parse::<SipUri>().ok().and_then(|u| u.user))
                .collect()
        };
        if bound_users.is_empty() {
            return None;
        }
        let from_tn = proto_stir_shaken::canonicalize_tn(&from_user);
        let dids = self.did_map.read().await;
        if bound_users.contains(&from_user) {
            if from_tn.is_some() {
                return Some(Some(from_user));
            }
            // Extension AOR: its provisioned DID (lowest, deterministic).
            return Some(dids.first_tn_of(&from_user).cloned());
        }
        // From is a DID: accepted only when mapped to a bound AOR user.
        let from_tn = from_tn?;
        bound_users
            .iter()
            .any(|u| dids.user_has_tn(u, from_tn.as_str()))
            .then_some(Some(from_user))
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
                        flow: Flow::Reply,
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
            flow: Flow::Reply,
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
    /// STIR/SHAKEN attestation: signed on the B-leg, else verified inbound
    /// (`"A"`/`"B"`/`"C"`, empty when none).
    pub attestation: String,
    /// Inbound verification status token (empty when not verified).
    pub verstat: String,
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
pub fn resolve_trunk_host_ips(host: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip.to_canonical()];
    }
    format!("{host}:0")
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip().to_canonical()).collect())
        .unwrap_or_default()
}

/// Pins every [`Flow::Reply`] in `result` to the transport the triggering
/// message arrived on (RFC 3261 §18.2.2).
fn resolve_reply(result: &mut ProcessResult, inbound: AddrTransport) {
    match result {
        ProcessResult::Response { flow, .. } | ProcessResult::Forward { flow, .. } => {
            if matches!(flow, Flow::Reply) {
                *flow = Flow::Leg(LegFlow::inbound(inbound));
            }
        }
        ProcessResult::Multiple(results) => {
            for r in results {
                resolve_reply(r, inbound);
            }
        }
        ProcessResult::NoAction | ProcessResult::Error { .. } => {}
    }
}

/// Where one trunk attempt goes on the wire, from the trunk's config only
/// (never from SIP headers): host and port for the Request-URI, the
/// resolved address, and the flow (protocol, TLS server name).
///
/// ## NIST 800-53 Rev5: SC-8, SC-23; RFC 3263 §4.1
#[derive(Debug, Clone)]
struct TrunkEndpoint {
    host: Arc<str>,
    port: u16,
    flow: LegFlow,
}

impl TrunkEndpoint {
    /// Reads the endpoint of a configured trunk. The host and TLS name are
    /// shared `Arc`s built at config load, so this does not allocate.
    fn of(router: &Router, group_id: &str, trunk_id: &str) -> Option<Self> {
        let trunk = router.get_trunk_group(group_id)?.get_trunk(trunk_id)?;
        let cfg = trunk.config();
        Some(Self {
            host: Arc::clone(trunk.host_shared()),
            port: cfg.port,
            flow: LegFlow::trunk_shared(cfg.protocol, trunk.tls_name_shared(), cfg.tls_client_cert),
        })
    }

    /// Resolves the trunk host. An IP literal is parsed in place; a
    /// hostname is resolved with a blocking lookup inside
    /// `tokio::task::block_in_place`, which keeps other tasks running but
    /// does hold this worker thread for the lookup.
    fn resolve(&self) -> Option<SbcSocketAddr> {
        resolve_host_port(&self.host, self.port)
    }
}

/// Request-URI toward a leg: `sips:` for TLS (RFC 3261 §26.2; the SBC never
/// puts a `sips` URI on a TCP/UDP hop), `;transport=tcp` for TCP, and no
/// `transport` parameter for UDP (§19.1.1, default). Built from config
/// and enum values only.
///
/// ## RFC 3261 §19.1.1, §26.2; RFC 5630 §3
fn leg_request_uri(user: Option<&str>, host: &str, port: u16, flow: &LegFlow) -> SipUri {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut uri = match flow.transport {
        AddrTransport::Tls => SipUri::new_sips(host),
        _ => SipUri::new(host),
    }
    .with_port(port);
    if let Some(user) = user {
        uri = uri.with_user(user);
    }
    match flow.transport {
        AddrTransport::Udp | AddrTransport::Tls => uri,
        AddrTransport::Tcp => uri.with_param("transport", Some("tcp".to_string())),
        AddrTransport::WebSocket | AddrTransport::WebSocketSecure => {
            uri.with_param("transport", Some("ws".to_string()))
        }
        AddrTransport::Sctp => uri.with_param("transport", Some("sctp".to_string())),
    }
}

/// Contact value for the SBC on a leg (`<sips:host:port>` on TLS,
/// RFC 3261 §8.1.1.8).
fn leg_contact(sent_by: &str, flow: &LegFlow) -> String {
    match flow.transport {
        AddrTransport::Udp => format!("<sip:{sent_by}>"),
        AddrTransport::Tls => format!("<sips:{sent_by}>"),
        AddrTransport::Tcp => format!("<sip:{sent_by};transport=tcp>"),
        AddrTransport::WebSocket | AddrTransport::WebSocketSecure => {
            format!("<sip:{sent_by};transport=ws>")
        }
        AddrTransport::Sctp => format!("<sip:{sent_by};transport=sctp>"),
    }
}

/// Flow toward a registered contact: its `transport` parameter (or `sips`
/// scheme) picks the accepted connection it registered over; the SBC never
/// dials a registered user (the parameter is attacker-chosen at REGISTER).
///
/// ## NIST 800-53 Rev5: SC-8, SI-10
fn contact_flow(contact: &str) -> LegFlow {
    let Ok(uri) = contact.parse::<SipUri>() else {
        return LegFlow::UDP;
    };
    let transport = match uri.transport().map(str::to_ascii_lowercase).as_deref() {
        Some("tls") => AddrTransport::Tls,
        Some("tcp") if uri.scheme.requires_tls() => AddrTransport::Tls,
        Some("tcp") => AddrTransport::Tcp,
        Some("ws") => AddrTransport::WebSocket,
        Some("wss") => AddrTransport::WebSocketSecure,
        _ if uri.scheme.requires_tls() => AddrTransport::Tls,
        _ => AddrTransport::Udp,
    };
    LegFlow::inbound(transport)
}

/// Flow and destination toward a registered binding.
///
/// A binding latched by REGISTER records the transport and source address
/// it arrived on: requests go back on that transport to that address only
/// (for TCP/TLS/WS, the accepted connection; it is never dialled), whatever
/// the Contact URI says. A binding without a recorded flow is only used
/// when its Contact names UDP: a stream Contact could otherwise point at
/// another peer's accepted connection and inject requests into it.
///
/// ## NIST 800-53 Rev5: SC-8, SC-23 (Session Authenticity)
///
/// ## RFC 3261 §18.2.2; RFC 5626 §5.3
fn binding_target(binding: &proto_registrar::Binding) -> Option<(LegFlow, SbcSocketAddr)> {
    if let (Some(t), Some(addr)) = (binding.source_transport(), binding.source_addr()) {
        let transport = match t {
            "udp" => AddrTransport::Udp,
            "tcp" => AddrTransport::Tcp,
            "tls" => AddrTransport::Tls,
            "ws" => AddrTransport::WebSocket,
            "wss" => AddrTransport::WebSocketSecure,
            other => {
                warn!(transport = %other, "Binding has an unknown source transport; not routable");
                return None;
            }
        };
        return Some((LegFlow::inbound(transport), SbcSocketAddr::from(addr)));
    }
    let flow = contact_flow(binding.contact_uri());
    if flow.transport != AddrTransport::Udp {
        warn!(
            contact = %binding.contact_uri(),
            "Stream Contact without a registered connection; not routable"
        );
        return None;
    }
    // A wildcard Contact (0.0.0.0 / [::]) with no recorded flow names no
    // reachable host (SEC-008).
    resolve_sip_uri_to_addr(binding.contact_uri())
        .filter(|d| !std::net::SocketAddr::from(*d).ip().is_unspecified())
        .map(|d| (flow, d))
}

/// Resolves `host:port` (IP literal, bracketed IPv6, or hostname).
fn resolve_host_port(host: &str, port: u16) -> Option<SbcSocketAddr> {
    use std::net::ToSocketAddrs;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ipv4) = bare.parse::<std::net::Ipv4Addr>() {
        return Some(SbcSocketAddr::new_v4(ipv4, port));
    }
    if let Ok(ipv6) = bare.parse::<std::net::Ipv6Addr>() {
        return Some(SbcSocketAddr::new_v6(ipv6, port));
    }
    let addr_str = format!("{host}:{port}");
    let resolved = tokio::task::block_in_place(|| addr_str.to_socket_addrs());
    resolved
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(SbcSocketAddr::from)
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
pub(crate) mod tests {
    use super::*;

    /// For server tests: a stack with trunks t1 (127.0.0.2:5061) and t2
    /// (127.0.0.3:5061), both TLS, and a placed call's primary B-leg INVITE
    /// result (to t1).
    pub(crate) async fn tls_failover_call(call_id: &str) -> (SipStack, ProcessResult) {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let primary = place_call(&stack, call_id)
            .await
            .into_iter()
            .find(|r| {
                matches!(r, ProcessResult::Forward { message: SipMessage::Request(q), .. }
                    if q.method == Method::Invite)
            })
            .expect("primary INVITE");
        (stack, primary)
    }

    /// Active calls on carrier trunk `trunk` (server tests).
    pub(crate) async fn carrier_active(stack: &SipStack, trunk: &str) -> u32 {
        active(stack, trunk).await
    }

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
            stack.b_leg_signaling_addr(Some("inside"), true, AddrTransport::Udp),
            ("203.0.113.6".to_string(), 5060)
        );
        assert_eq!(
            stack.b_leg_signaling_addr(Some("inside"), false, AddrTransport::Udp),
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
                    ..
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
                    ..
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
            a_leg_flow: LegFlow::UDP,
            b_leg_flow: LegFlow::UDP,
            a_leg_local_addr: "10.0.0.9:5060".to_string(),
            a_leg_sip_call_id: "aleg-callid".to_string(),
            b_leg_sip_call_id: "bleg-callid".to_string(),
            local_addr: "10.0.0.9:5060".to_string(),
            failover_targets: vec![],
            trunk_lease: None,
            vps_callee: None,
            b_leg_invite: None,
            b_leg_ruri: None,
            stir_egress: None,
            early_media_committed: false,
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
            cdr: crate::cdr::CdrDraft::default(),
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
                ..
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
                ..
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
    async fn reused_branch_with_new_call_id_is_a_new_request() {
        // A client that reuses branch values (SIPp restarted under the same
        // PID does) must not have its new request swallowed as a
        // retransmission of an earlier call's transaction.
        let (stack, _) = ringing_call().await;
        let first = alice_request("INVITE", 1, None, Some(ALICE_SDP));
        let second = String::from_utf8(first.to_vec())
            .unwrap()
            .replace("Call-ID: call-relay@test", "Call-ID: call-other@test");
        let results = flatten(
            stack
                .process_message(&Bytes::from(second), alice(), None)
                .await,
        );
        assert!(
            results
                .iter()
                .any(|r| matches!(r, ProcessResult::Forward { .. })),
            "new INVITE forwarded, not answered from the old transaction: {results:?}"
        );
        assert_eq!(stack.call_count().await, 2, "second call created");
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
        let dest = |r: &ProcessResult| match r {
            ProcessResult::Forward { destination, .. } => *destination,
            _ => panic!("BYE forward"),
        };
        assert_eq!(dest(&byes[0]), addrs.a_leg_source);
        assert_eq!(dest(&byes[1]), addrs.b_leg_destination);

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

    // ── Trunk routing: translation, failover, call limits ──────────────

    /// Trunk group "carriers": t1 (127.0.0.2, priority 1) and t2
    /// (127.0.0.3, priority 2), each `max_calls`. The dial plan sends `+1…`
    /// there and strips the `+1` (the translated number). Alice's address
    /// is an admitted trunk source.
    async fn trunk_stack(
        max_calls: u32,
        transform: (&str, &str),
        vps: Option<uc_vps::VpsEngine>,
    ) -> SipStack {
        trunk_stack_cfg(SipStackConfig::default(), max_calls, transform, vps).await
    }

    /// [`trunk_stack`] with a stack config. The dial plan also sends `9…`
    /// (emergency 911) to "carriers" untranslated.
    async fn trunk_stack_cfg(
        config: SipStackConfig,
        max_calls: u32,
        transform: (&str, &str),
        vps: Option<uc_vps::VpsEngine>,
    ) -> SipStack {
        trunk_stack_full(config, max_calls, transform, vps, ["udp", "udp"]).await
    }

    /// [`trunk_stack`] with trunk protocols for t1 / t2 (TLS trunks listen
    /// on 5061, `tls_server_name` unset so the host is verified).
    async fn trunk_stack_protos(protos: [&str; 2]) -> SipStack {
        trunk_stack_full(SipStackConfig::default(), 10, ("none", ""), None, protos).await
    }

    /// Routing, dial plan and the "carriers" group (t1 = 127.0.0.2,
    /// t2 = 127.0.0.3) used by [`trunk_stack`].
    fn carrier_routing(
        max_calls: u32,
        transform: (&str, &str),
        protos: [&str; 2],
    ) -> (
        sbc_config::RoutingConfig,
        Vec<sbc_config::DialPlanConfig>,
        Vec<sbc_config::TrunkGroupConfig>,
    ) {
        let routing = sbc_config::RoutingConfig {
            use_dial_plan: true,
            max_failover_attempts: 3,
            default_trunk_group: "carriers".to_string(),
        };
        let dial_plans = vec![sbc_config::DialPlanConfig {
            id: "plan".to_string(),
            name: "Plan".to_string(),
            active: true,
            entries: vec![
                sbc_config::DialPlanEntryConfig {
                    direction: "both".to_string(),
                    pattern_type: "prefix".to_string(),
                    pattern_value: "+1".to_string(),
                    trunk_group: "carriers".to_string(),
                    transform_type: transform.0.to_string(),
                    transform_value: transform.1.to_string(),
                    priority: 1,
                    ..Default::default()
                },
                sbc_config::DialPlanEntryConfig {
                    direction: "both".to_string(),
                    pattern_type: "prefix".to_string(),
                    pattern_value: "9".to_string(),
                    trunk_group: "carriers".to_string(),
                    transform_type: "none".to_string(),
                    transform_value: String::new(),
                    priority: 2,
                    ..Default::default()
                },
            ],
        }];
        let trunk =
            |id: &str, host: &str, priority: u32, proto: &str| sbc_config::TrunkConfigSchema {
                id: id.to_string(),
                host: host.to_string(),
                port: if proto == "tls" { 5061 } else { 5060 },
                protocol: proto.to_string(),
                priority,
                max_calls,
                max_failures: 3,
                ..Default::default()
            };
        let groups = vec![sbc_config::TrunkGroupConfig {
            id: "carriers".to_string(),
            name: "Carriers".to_string(),
            strategy: "priority".to_string(),
            trunks: vec![
                trunk("t1", "127.0.0.2", 1, protos[0]),
                trunk("t2", "127.0.0.3", 2, protos[1]),
            ],
            zone: None,
        }];
        (routing, dial_plans, groups)
    }

    async fn trunk_stack_full(
        config: SipStackConfig,
        max_calls: u32,
        transform: (&str, &str),
        vps: Option<uc_vps::VpsEngine>,
        protos: [&str; 2],
    ) -> SipStack {
        let mut stack = SipStack::new(config);
        let (routing, dial_plans, groups) = carrier_routing(max_calls, transform, protos);
        stack.init_router_from_config(&routing, &dial_plans, &groups);
        if let Some(engine) = vps {
            stack.set_vps_engine(engine);
        }
        stack
            .register_inbound_trunk("pbx", None, &[("192.168.1.1".to_string(), 5060)])
            .await;
        stack
    }

    fn t1() -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(127, 0, 0, 2), 5060)
    }

    fn t2() -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(127, 0, 0, 3), 5060)
    }

    const DIALED: &str = "+15551234567";

    /// A request from alice for call `call_id` to `user`. INVITE and CANCEL
    /// of one transaction share the branch.
    fn caller_request(
        method: &str,
        user: &str,
        call_id: &str,
        cseq: u32,
        to_tag: Option<&str>,
        body: Option<&str>,
    ) -> Bytes {
        let to = to_tag.map_or_else(
            || format!("<sip:{user}@sbc.local>"),
            |t| format!("<sip:{user}@sbc.local>;tag={t}"),
        );
        let mut msg = format!(
            "{method} sip:{user}@sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-{call_id}-{cseq}\r\n\
             From: <sip:alice@example.com>;tag=a-{call_id}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@192.168.1.1:5060>\r\n"
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

    async fn place_call(stack: &SipStack, call_id: &str) -> Vec<ProcessResult> {
        flatten(
            stack
                .process_message(
                    &caller_request("INVITE", DIALED, call_id, 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        )
    }

    async fn active(stack: &SipStack, trunk: &str) -> u32 {
        stack
            .trunk_active_calls("carriers", trunk)
            .await
            .expect("trunk exists")
    }

    async fn trunk_state(stack: &SipStack, trunk: &str) -> uc_routing::TrunkState {
        stack
            .router()
            .expect("router")
            .read()
            .await
            .get_trunk_group("carriers")
            .and_then(|g| g.get_trunk(trunk))
            .expect("trunk exists")
            .state()
    }

    async fn assert_all_released(stack: &SipStack) {
        assert_eq!(active(stack, "t1").await, 0, "t1 slots released");
        assert_eq!(active(stack, "t2").await, 0, "t2 slots released");
        if let Some(n) = stack.vps_callee_concurrent_calls(DIALED).await {
            assert_eq!(n, 0, "VPS callee slot released");
        }
        assert!(stack.call_correlation.read().await.addresses.is_empty());
        assert_eq!(stack.admitted_call_slots(), 0, "max_calls slots released");
        assert_eq!(stack.call_count().await, 0);
    }

    fn vps_with_callee_cap(cap: u32) -> uc_vps::VpsEngine {
        uc_vps::VpsEngine::new(&uc_vps::VpsConfig {
            enabled: true,
            tdos: uc_vps::TdosConfig {
                per_source_cps: 0,
                register_per_source_rps: 0,
                per_callee_max_concurrent: cap,
                ..uc_vps::TdosConfig::default()
            },
            ..uc_vps::VpsConfig::default()
        })
        .expect("valid VPS config")
    }

    #[tokio::test]
    async fn translated_number_is_on_b_leg_request_uri_and_to() {
        let stack = trunk_stack(10, ("strip_prefix", "2"), None).await;
        let results = place_call(&stack, "xlate@test").await;
        let (b_invite, dest) = forwarded(&results, &Method::Invite).expect("INVITE to trunk");
        assert_eq!(dest, t1());
        assert_eq!(b_invite.uri.user.as_deref(), Some("5551234567"));
        let to = b_invite.headers.get_value(&HeaderName::To).unwrap();
        assert!(
            to.contains("sip:5551234567@"),
            "To carries the translated number: {to}"
        );
        let wire =
            String::from_utf8_lossy(&SipMessage::Request(b_invite.clone()).to_bytes()).into_owned();
        assert!(wire.starts_with("INVITE sip:5551234567@"), "{wire}");
        assert_eq!(active(&stack, "t1").await, 1);

        // 200 then BYE from the caller releases the slot.
        let b_invite = b_invite.clone();
        stack
            .process_message(
                &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
                t1(),
                None,
            )
            .await;
        stack
            .process_message(
                &caller_request("BYE", DIALED, "xlate@test", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        assert_all_released(&stack).await;
        let stats = stack
            .router()
            .unwrap()
            .read()
            .await
            .get_trunk_group("carriers")
            .and_then(|g| g.get_trunk("t1"))
            .map(|t| t.stats().calls_succeeded);
        assert_eq!(stats, Some(1), "answered call counted as a success");
    }

    #[tokio::test]
    async fn unsafe_translation_is_rejected_with_500_and_nothing_sent() {
        for prefix in ["@evil.example;", "x\r\nX-Injected: 1"] {
            let stack = trunk_stack(10, ("add_prefix", prefix), None).await;
            let results = place_call(&stack, "inject@test").await;
            assert!(forwarded(&results, &Method::Invite).is_none());
            assert!(responded(&results, 500).is_some(), "500 for {prefix:?}");
            assert_all_released(&stack).await;
        }
    }

    #[test]
    fn safe_b_leg_user_charset() {
        for ok in [
            "5551234567",
            "+15551234567",
            "*67",
            "user.name",
            "a-b_c!~'()&=+$,",
        ] {
            assert!(is_safe_b_leg_user(ok), "{ok}");
        }
        for bad in [
            "",
            "a@b",
            "a;b",
            "a?b",
            "a/b",
            "a>b",
            "a<b",
            "a b",
            "a\r\nb",
            "a%40b",
            "#123",
            &"9".repeat(65),
        ] {
            assert!(!is_safe_b_leg_user(bad), "{bad:?}");
        }
    }

    #[test]
    fn replace_header_param_rewrites_or_appends() {
        assert_eq!(
            replace_header_param(
                "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKold;rport",
                "branch",
                "z9hG4bKnew"
            ),
            "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnew;rport"
        );
        assert_eq!(
            replace_header_param("<sip:sbc@d;tag=inuri>;tag=old", "tag", "new"),
            "<sip:sbc@d;tag=inuri>;tag=new"
        );
        assert_eq!(
            replace_header_param("<sip:sbc@d>", "tag", "t"),
            "<sip:sbc@d>;tag=t"
        );
    }

    #[tokio::test]
    async fn failover_on_503_retries_next_trunk_with_same_sdp() {
        let stack = trunk_stack(10, ("strip_prefix", "2"), None).await;
        let results = place_call(&stack, "fo@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).expect("INVITE to t1");
        let first = first.clone();

        let results = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (ack, ack_dest) = forwarded(&results, &Method::Ack).expect("503 ACKed");
        assert_eq!(ack_dest, t1());
        assert_eq!(ack.headers.call_id(), first.headers.call_id());
        assert!(
            responded(&results, 503).is_none(),
            "caller does not see the 503"
        );
        let (retry, dest) = forwarded(&results, &Method::Invite).expect("INVITE to t2");
        assert_eq!(dest, t2());
        assert_eq!(retry.body, first.body, "same SDP offer");
        assert_eq!(retry.uri.user.as_deref(), Some("5551234567"));
        assert_ne!(retry.headers.call_id(), first.headers.call_id());
        assert_ne!(retry.headers.via_branch(), first.headers.via_branch());
        assert_ne!(retry.headers.from_tag(), first.headers.from_tag());
        assert_eq!(retry.headers.cseq(), Some("1 INVITE"));
        assert_eq!(active(&stack, "t1").await, 0);
        assert_eq!(active(&stack, "t2").await, 1);
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Cooldown,
            "503 puts the trunk into cooldown"
        );

        // The new branch is accepted; 200 + BYE from the callee releases t2.
        let retry = retry.clone();
        let results = flatten(
            stack
                .process_message(
                    &response_to(&retry, 200, Some("bobtag"), Some(BOB_SDP)),
                    t2(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 200).is_some(), "200 from t2 relayed");
        stack
            .process_message(&bob_request(&retry, "BYE", 1, None), t2(), None)
            .await;
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn failover_exhausted_relays_last_error_and_releases() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "exhaust@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let results = flatten(
            stack
                .process_message(&response_to(&first, 500, Some("x"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&results, &Method::Invite).expect("failover to t2");
        let retry = retry.clone();
        let results = flatten(
            stack
                .process_message(&response_to(&retry, 502, Some("y"), None), t2(), None)
                .await,
        );
        let (_, dest) = responded(&results, 502).expect("last error relayed");
        assert_eq!(dest, alice());
        assert!(forwarded(&results, &Method::Invite).is_none());
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn callee_reject_does_not_fail_over() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "busy@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let results = flatten(
            stack
                .process_message(&response_to(&first, 486, Some("x"), None), t1(), None)
                .await,
        );
        assert!(responded(&results, 486).is_some());
        assert!(
            forwarded(&results, &Method::Invite).is_none(),
            "no failover on 486"
        );
        assert_all_released(&stack).await;
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Available
        );
    }

    #[tokio::test]
    async fn no_failover_after_reliable_early_media() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "early@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        // Reliable 183 with SDP (RFC 3262 RSeq).
        let mut early =
            String::from_utf8_lossy(&response_to(&first, 183, Some("x"), Some(BOB_SDP)))
                .into_owned();
        early = early.replacen(
            "Content-Type:",
            "Require: 100rel\r\nRSeq: 1\r\nContent-Type:",
            1,
        );
        stack.process_message(&Bytes::from(early), t1(), None).await;
        let results = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("x"), None), t1(), None)
                .await,
        );
        assert!(
            responded(&results, 503).is_some(),
            "503 relayed, no failover"
        );
        assert!(forwarded(&results, &Method::Invite).is_none());
        assert_all_released(&stack).await;
    }

    #[test]
    fn txn_transport_maps_connection_oriented_to_reliable() {
        // RFC 3261 §17.1.1.2 / §17.1.2.2: only UDP gets Timers A/E/G.
        assert_eq!(txn_transport(AddrTransport::Udp), TransportType::Unreliable);
        for t in [
            AddrTransport::Tcp,
            AddrTransport::Tls,
            AddrTransport::WebSocket,
            AddrTransport::WebSocketSecure,
            AddrTransport::Sctp,
        ] {
            assert_eq!(txn_transport(t), TransportType::Reliable, "{t:?}");
        }
    }

    async fn place_call_on(
        stack: &SipStack,
        call_id: &str,
        transport: AddrTransport,
    ) -> Vec<ProcessResult> {
        flatten(
            stack
                .process_message_on(
                    &caller_request("INVITE", DIALED, call_id, 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                    transport,
                )
                .await,
        )
    }

    #[tokio::test]
    async fn reliable_invite_client_txn_has_no_timer_a_but_times_out_on_timer_b() {
        // The B-leg transaction follows the trunk's transport (POA&M-5).
        let stack = trunk_stack_protos(["tcp", "tcp"]).await;
        let results = place_call_on(&stack, "tcp-a@test", AddrTransport::Tcp).await;
        assert!(forwarded(&results, &Method::Invite).is_some());
        {
            let txns = stack.transactions.read().await;
            let st = txns
                .client_invite
                .values()
                .next()
                .expect("client INVITE txn");
            assert_eq!(st.transaction.transport(), TransportType::Reliable);
            // Timer B (64*T1 = 32 s) is the only armed timer.
            let deadline = st.transaction.next_timer_deadline().expect("Timer B armed");
            let after = deadline.saturating_duration_since(st.transaction.created_at());
            assert!(
                after >= std::time::Duration::from_secs(31),
                "next timer is Timer B, not A: {after:?}"
            );
        }
        // Past T1 and 2*T1: no INVITE retransmission on TCP.
        tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
        let results = stack.poll_timers().await;
        assert!(
            forwarded(&results, &Method::Invite).is_none(),
            "Timer A ran on TCP: {results:?}"
        );
    }

    #[tokio::test]
    async fn reliable_server_invite_txn_has_no_timer_g() {
        // RFC 3261 §17.2.1: a final response is not retransmitted on TCP.
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call_on(&stack, "tcp-g@test", AddrTransport::Tcp).await;
        let (b_invite, dest) = forwarded(&results, &Method::Invite).unwrap();
        let (b_invite, dest) = (b_invite.clone(), dest);
        let out = flatten(
            stack
                .process_message(&response_to(&b_invite, 486, Some("t"), None), dest, None)
                .await,
        );
        assert!(responded(&out, 486).is_some(), "{out:?}");
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        assert!(responded(&results, 486).is_none(), "Timer G ran on TCP");
    }

    #[tokio::test]
    async fn udp_invite_client_txn_still_retransmits_timer_a() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call_on(&stack, "udp-a@test", AddrTransport::Udp).await;
        assert!(forwarded(&results, &Method::Invite).is_some());
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        assert!(
            forwarded(&results, &Method::Invite).is_some(),
            "Timer A retransmit on UDP"
        );
    }

    /// Places a call over `transport` then CANCELs it over the same
    /// transport; returns what the timers produce 600 ms later.
    async fn cancel_on(transport: AddrTransport) -> Vec<ProcessResult> {
        // The trunk uses the same transport as the caller here, so the
        // CANCEL's client transaction is reliable exactly when it is.
        let proto = if transport == AddrTransport::Udp {
            "udp"
        } else {
            "tls"
        };
        let stack = trunk_stack_protos([proto, proto]).await;
        let id = "nict@test";
        place_call_on(&stack, id, transport).await;
        let out = flatten(
            stack
                .process_message_on(
                    &caller_request("CANCEL", DIALED, id, 1, None, None),
                    alice(),
                    None,
                    transport,
                )
                .await,
        );
        assert!(forwarded(&out, &Method::Cancel).is_some(), "{out:?}");
        assert!(
            !stack.transactions.read().await.client_non_invite.is_empty(),
            "client CANCEL txn"
        );
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        stack.poll_timers().await
    }

    #[tokio::test]
    async fn reliable_non_invite_client_txn_has_no_timer_e() {
        let results = cancel_on(AddrTransport::Tls).await;
        assert!(
            forwarded(&results, &Method::Cancel).is_none(),
            "{results:?}"
        );
    }

    #[tokio::test]
    async fn udp_non_invite_client_txn_still_retransmits_timer_e() {
        let results = cancel_on(AddrTransport::Udp).await;
        assert!(
            forwarded(&results, &Method::Cancel).is_some(),
            "{results:?}"
        );
    }

    #[test]
    fn call_slot_reservation_is_bounded_and_released_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let a = try_reserve_slot(&counter, 2).expect("slot 1");
        let b = try_reserve_slot(&counter, 2).expect("slot 2");
        assert!(try_reserve_slot(&counter, 2).is_none(), "ceiling reached");
        // A higher (emergency) ceiling shares the same counter.
        let e = try_reserve_slot(&counter, 3).expect("reserve slot");
        assert_eq!(counter.load(Ordering::Acquire), 3);
        drop((a, b, e));
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(try_reserve_slot(&counter, 0).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admission_never_exceeds_max_calls() {
        const N: u32 = 3;
        let config = SipStackConfig {
            max_calls: N,
            emergency_reserve_calls: 0,
            ..SipStackConfig::default()
        };
        let stack = Arc::new(trunk_stack_cfg(config, 1000, ("none", ""), None).await);
        let tasks: Vec<_> = (0..4 * N)
            .map(|i| {
                let stack = Arc::clone(&stack);
                tokio::spawn(async move { place_call(&stack, &format!("cc-{i}@test")).await })
            })
            .collect();
        let mut admitted = 0;
        let mut rejected = 0;
        for t in tasks {
            let r = t.await.unwrap();
            if forwarded(&r, &Method::Invite).is_some() {
                admitted += 1;
            } else if responded(&r, 503).is_some() {
                rejected += 1;
            }
        }
        assert!(admitted <= N, "overshoot: {admitted} > {N}");
        assert_eq!(admitted + rejected, 4 * N);
        let calls = stack.call_count().await;
        assert!(calls <= N as usize);
        assert_eq!(stack.admitted_call_slots(), calls);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_emergency_admission_bounded_by_reserve() {
        const N: u32 = 2;
        const R: u32 = 2;
        let config = SipStackConfig {
            max_calls: N,
            emergency_reserve_calls: R,
            ..SipStackConfig::default()
        };
        let stack = Arc::new(trunk_stack_cfg(config, 1000, ("none", ""), None).await);
        let tasks: Vec<_> = (0..16u32)
            .map(|i| {
                let stack = Arc::clone(&stack);
                tokio::spawn(async move {
                    let emergency = i % 2 == 0;
                    let user = if emergency { "911" } else { DIALED };
                    let r = place_call_to(&stack, user, &format!("ce-{i}@test")).await;
                    (emergency, forwarded(&r, &Method::Invite).is_some())
                })
            })
            .collect();
        let (mut normal, mut total) = (0, 0);
        for t in tasks {
            let (emergency, ok) = t.await.unwrap();
            if ok {
                total += 1;
                if !emergency {
                    normal += 1;
                }
            }
        }
        assert!(normal <= N, "normal calls used the reserve: {normal}");
        assert!(total <= N + R, "overshoot: {total}");
        assert_eq!(stack.admitted_call_slots(), stack.call_count().await);
    }

    #[tokio::test]
    async fn slot_released_on_every_rejection_path() {
        let config = SipStackConfig {
            max_calls: 10,
            ..SipStackConfig::default()
        };
        let stack = trunk_stack_cfg(config, 1, ("none", ""), None).await;

        // 483: Max-Forwards exhausted (after admission).
        let mf0 = String::from_utf8_lossy(&caller_request(
            "INVITE",
            DIALED,
            "mf0@test",
            1,
            None,
            Some(ALICE_SDP),
        ))
        .replacen("CSeq:", "Max-Forwards: 0\r\nCSeq:", 1);
        let r = flatten(
            stack
                .process_message(&Bytes::from(mf0), alice(), None)
                .await,
        );
        assert!(responded(&r, 483).is_some(), "{r:?}");
        assert_eq!(stack.admitted_call_slots(), 0, "483 path");

        // All trunks full: 503 + Retry-After after routing.
        place_call(&stack, "f1@test").await;
        place_call(&stack, "f2@test").await;
        assert_eq!(stack.admitted_call_slots(), 2);
        let r = place_call(&stack, "f3@test").await;
        assert!(responded(&r, 503).is_some(), "{r:?}");
        assert_eq!(stack.admitted_call_slots(), 2, "trunk-full path");
        assert_eq!(stack.call_count().await, 2);
    }

    #[tokio::test]
    async fn slot_released_on_global_max_calls_rejection() {
        let config = SipStackConfig {
            max_calls: 1,
            emergency_reserve_calls: 0,
            ..SipStackConfig::default()
        };
        let stack = trunk_stack_cfg(config, 10, ("none", ""), None).await;
        place_call(&stack, "g1@test").await;
        for i in 0..3 {
            let r = place_call(&stack, &format!("g-over{i}@test")).await;
            assert!(responded(&r, 503).is_some());
        }
        assert_eq!(stack.admitted_call_slots(), 1);
        // CANCEL frees it and the next call is admitted.
        stack
            .process_message(
                &caller_request("CANCEL", DIALED, "g1@test", 1, None, None),
                alice(),
                None,
            )
            .await;
        assert_eq!(stack.admitted_call_slots(), 0);
        let r = place_call(&stack, "g2@test").await;
        assert!(forwarded(&r, &Method::Invite).is_some());
    }

    // ---- QA additions (POA&M-10/11) ----

    #[tokio::test]
    async fn qa_slot_released_on_vps_callee_cap_reject() {
        let stack = trunk_stack(10, ("none", ""), Some(vps_with_callee_cap(1))).await;
        let r1 = place_call(&stack, "qv1@test").await;
        assert!(forwarded(&r1, &Method::Invite).is_some());
        assert_eq!(stack.admitted_call_slots(), 1);
        for i in 0..3 {
            let r = place_call(&stack, &format!("qv-rej{i}@test")).await;
            assert!(
                responded(&r, uc_vps::CONCURRENCY_CAP_STATUS).is_some(),
                "{r:?}"
            );
            assert_eq!(stack.admitted_call_slots(), 1, "VPS reject leaked a slot");
        }
        assert_eq!(stack.call_count().await, 1);
    }

    #[tokio::test]
    async fn qa_slot_released_on_all_trunks_down_503() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        stack.set_trunk_reachable("t1", false).await;
        stack.set_trunk_reachable("t2", false).await;
        for i in 0..3 {
            let r = place_call(&stack, &format!("qd{i}@test")).await;
            assert!(responded(&r, 503).is_some(), "{r:?}");
        }
        assert_eq!(stack.admitted_call_slots(), 0, "routing-failure path");
        assert_eq!(stack.call_count().await, 0);
    }

    #[tokio::test]
    async fn qa_slot_invariant_holds_for_malformed_sdp_offer() {
        // Whatever the SDP path decides (reject or pass-through), the slot
        // counter must equal the stored calls afterwards.
        let stack = trunk_stack(10, ("none", ""), None).await;
        for (i, body) in [
            "garbage\r\n",
            "v=0\r\nm=audio notaport RTP/AVP 0\r\n",
            "v=0\r\nc=IN IP4\r\n",
        ]
        .iter()
        .enumerate()
        {
            let _ = flatten(
                stack
                    .process_message(
                        &caller_request(
                            "INVITE",
                            DIALED,
                            &format!("qs{i}@test"),
                            1,
                            None,
                            Some(body),
                        ),
                        alice(),
                        None,
                    )
                    .await,
            );
            assert_eq!(
                stack.admitted_call_slots(),
                stack.call_count().await,
                "body {i}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn qa_concurrent_emergency_only_burst_fills_exactly_to_ceiling() {
        const N: u32 = 2;
        const R: u32 = 3;
        let config = SipStackConfig {
            max_calls: N,
            emergency_reserve_calls: R,
            ..SipStackConfig::default()
        };
        let stack = Arc::new(trunk_stack_cfg(config, 1000, ("none", ""), None).await);
        for round in 0..5u32 {
            let tasks: Vec<_> = (0..24u32)
                .map(|i| {
                    let stack = Arc::clone(&stack);
                    tokio::spawn(async move {
                        let r = place_call_to(&stack, "911", &format!("qe-{round}-{i}@test")).await;
                        forwarded(&r, &Method::Invite).is_some()
                    })
                })
                .collect();
            let mut ok = 0u32;
            for t in tasks {
                if t.await.unwrap() {
                    ok += 1;
                }
            }
            let expected = if round == 0 { N + R } else { 0 };
            assert_eq!(ok, expected, "round {round}");
            assert_eq!(stack.call_count().await, (N + R) as usize);
            assert_eq!(stack.admitted_call_slots(), (N + R) as usize);
        }
        // Once the reserve is in use a normal call is still refused.
        let r = place_call(&stack, "qe-normal@test").await;
        assert!(responded(&r, 503).is_some());
    }

    fn qa_options(n: u32) -> Bytes {
        Bytes::from(format!(
            "OPTIONS sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/TCP 192.168.1.1:5060;branch=z9hG4bK-qopt-{n}\r\n\
             From: <sip:alice@example.com>;tag=q{n}\r\n\
             To: <sip:sbc.local>\r\n\
             Call-ID: qopt-{n}@test\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    }

    #[tokio::test]
    async fn qa_reliable_server_non_invite_txn_has_zero_timer_j() {
        // RFC 3261 §17.2.2: Timer J is 0 on reliable transports, so the
        // server NIT terminates right after the final response.
        let stack = SipStack::new(SipStackConfig::default());
        let out = flatten(
            stack
                .process_message_on(&qa_options(1), alice(), None, AddrTransport::Tcp)
                .await,
        );
        assert!(responded(&out, 200).is_some(), "{out:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let timers = stack.poll_timers().await;
        assert!(
            responded(&timers, 200).is_none(),
            "no NIT response retransmit on TCP"
        );
        assert!(
            stack.transactions.read().await.server_non_invite.is_empty(),
            "TCP server NIT should be gone (Timer J = 0)"
        );
    }

    #[tokio::test]
    async fn qa_udp_server_non_invite_txn_absorbs_retransmit_during_timer_j() {
        let stack = SipStack::new(SipStackConfig::default());
        let first = flatten(stack.process_message(&qa_options(2), alice(), None).await);
        assert!(responded(&first, 200).is_some());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        stack.poll_timers().await;
        assert!(
            !stack.transactions.read().await.server_non_invite.is_empty(),
            "UDP server NIT kept for Timer J"
        );
        // Retransmission is answered from the stored response.
        let again = flatten(stack.process_message(&qa_options(2), alice(), None).await);
        assert!(responded(&again, 200).is_some(), "{again:?}");
    }

    #[tokio::test]
    async fn timer_b_fails_over_then_408_when_exhausted() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "timerb@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let internal = stack
            .call_correlation
            .read()
            .await
            .a_leg
            .get("timerb@test")
            .cloned()
            .unwrap();

        let out = stack
            .fail_timed_out_request(&first.headers.via_branch().unwrap(), &internal)
            .await;
        let (retry, dest) = forwarded(&out, &Method::Invite).expect("Timer B fails over");
        assert_eq!(dest, t2());
        assert_eq!(active(&stack, "t1").await, 0);
        assert_eq!(active(&stack, "t2").await, 1);

        let out = stack
            .fail_timed_out_request(&retry.headers.via_branch().unwrap(), &internal)
            .await;
        assert!(responded(&out, 408).is_some(), "exhausted: 408 to caller");
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn options_down_trunk_is_skipped() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        assert_eq!(stack.set_trunk_reachable("t1", false).await, 1);
        let results = place_call(&stack, "down@test").await;
        let (_, dest) = forwarded(&results, &Method::Invite).unwrap();
        assert_eq!(dest, t2(), "down trunk skipped");

        stack.set_trunk_reachable("t1", true).await;
        let results = place_call(&stack, "up@test").await;
        let (_, dest) = forwarded(&results, &Method::Invite).unwrap();
        assert_eq!(dest, t1(), "trunk back in service");
    }

    #[tokio::test]
    async fn trunk_at_max_calls_is_skipped_then_503_when_all_full() {
        let stack = trunk_stack(1, ("none", ""), None).await;
        let r1 = place_call(&stack, "c1@test").await;
        assert_eq!(forwarded(&r1, &Method::Invite).unwrap().1, t1());
        let r2 = place_call(&stack, "c2@test").await;
        assert_eq!(forwarded(&r2, &Method::Invite).unwrap().1, t2());

        let r3 = place_call(&stack, "c3@test").await;
        assert!(forwarded(&r3, &Method::Invite).is_none());
        let (resp, _) = responded(&r3, 503).expect("503 when every trunk is full");
        assert_eq!(resp.headers.get_value(&HeaderName::RetryAfter), Some("5"));

        // CANCEL before answer and BYE from the callee both release.
        stack
            .process_message(
                &caller_request("CANCEL", DIALED, "c1@test", 1, None, None),
                alice(),
                None,
            )
            .await;
        assert_eq!(active(&stack, "t1").await, 0);
        let (b2, _) = forwarded(&r2, &Method::Invite).unwrap();
        let b2 = b2.clone();
        stack
            .process_message(
                &response_to(&b2, 200, Some("bobtag"), Some(BOB_SDP)),
                t2(),
                None,
            )
            .await;
        stack
            .process_message(&bob_request(&b2, "BYE", 1, None), t2(), None)
            .await;
        assert_all_released(&stack).await;

        // Retransmitted BYE / CANCEL after teardown do not double-release.
        stack
            .process_message(&bob_request(&b2, "BYE", 1, None), t2(), None)
            .await;
        stack
            .process_message(
                &caller_request("CANCEL", DIALED, "c1@test", 1, None, None),
                alice(),
                None,
            )
            .await;
        assert_all_released(&stack).await;
        let r4 = place_call(&stack, "c4@test").await;
        assert_eq!(forwarded(&r4, &Method::Invite).unwrap().1, t1());
    }

    #[tokio::test]
    async fn early_bye_from_caller_releases() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        place_call(&stack, "ebye@test").await;
        stack
            .process_message(
                &caller_request("BYE", DIALED, "ebye@test", 2, None, None),
                alice(),
                None,
            )
            .await;
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn per_callee_max_concurrent_rejects_the_next_call() {
        let stack = trunk_stack(10, ("none", ""), Some(vps_with_callee_cap(1))).await;
        let r1 = place_call(&stack, "v1@test").await;
        let (b1, _) = forwarded(&r1, &Method::Invite).expect("first call allowed");
        let b1 = b1.clone();
        assert_eq!(stack.vps_callee_concurrent_calls(DIALED).await, Some(1));

        let r2 = place_call(&stack, "v2@test").await;
        assert!(forwarded(&r2, &Method::Invite).is_none());
        assert!(
            responded(&r2, uc_vps::CONCURRENCY_CAP_STATUS).is_some(),
            "second concurrent call to the callee rejected"
        );
        assert_eq!(
            active(&stack, "t1").await,
            1,
            "rejected call took no trunk slot"
        );

        stack
            .process_message(
                &response_to(&b1, 200, Some("bobtag"), Some(BOB_SDP)),
                t1(),
                None,
            )
            .await;
        stack
            .process_message(
                &caller_request("BYE", DIALED, "v1@test", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        assert_all_released(&stack).await;
        let r3 = place_call(&stack, "v3@test").await;
        assert!(
            forwarded(&r3, &Method::Invite).is_some(),
            "slot freed by BYE"
        );
    }

    #[tokio::test]
    async fn all_trunks_down_503_releases_vps_slot() {
        let stack = trunk_stack(10, ("none", ""), Some(vps_with_callee_cap(1))).await;
        stack.set_trunk_reachable("t1", false).await;
        stack.set_trunk_reachable("t2", false).await;
        let r = place_call(&stack, "none@test").await;
        assert!(responded(&r, 503).is_some());
        assert_eq!(stack.vps_callee_concurrent_calls(DIALED).await, Some(0));
    }

    fn register_msg(user: &str, call_id: &str, cseq: u32, expires: u32) -> Bytes {
        Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-{call_id}-{cseq}\r\n\
             From: <sip:{user}@sbc.local>;tag=r{cseq}\r\n\
             To: <sip:{user}@sbc.local>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REGISTER\r\n\
             Contact: <sip:{user}@127.0.0.1:5060>\r\n\
             Expires: {expires}\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    }

    async fn register_status(stack: &SipStack, msg: &Bytes) -> (u16, Option<String>) {
        match stack.process_message(msg, bob(), None).await {
            ProcessResult::Response {
                message: SipMessage::Response(r),
                ..
            } => (
                r.status.code(),
                r.headers
                    .get_value(&HeaderName::RetryAfter)
                    .map(String::from),
            ),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn max_registrations_rejects_new_bindings_but_allows_refresh() {
        let stack = SipStack::new(SipStackConfig {
            max_registrations: 1,
            ..SipStackConfig::default()
        });
        assert_eq!(
            register_status(&stack, &register_msg("u1", "r-u1", 1, 3600))
                .await
                .0,
            200
        );

        let (code, retry) = register_status(&stack, &register_msg("u2", "r-u2", 1, 3600)).await;
        assert_eq!(code, 503, "second AoR over the cap");
        assert_eq!(retry.as_deref(), Some("60"));

        // Refresh of the existing binding is always allowed.
        assert_eq!(
            register_status(&stack, &register_msg("u1", "r-u1", 2, 3600))
                .await
                .0,
            200
        );
        // De-registration is always allowed and frees the slot.
        assert_eq!(
            register_status(&stack, &register_msg("u1", "r-u1", 3, 0))
                .await
                .0,
            200
        );
        assert_eq!(
            register_status(&stack, &register_msg("u2", "r-u2", 2, 3600))
                .await
                .0,
            200
        );
    }

    // ── QA additions (dead-config features) ─────────────────────────────

    /// Sends `status` from t1 for the first B-leg INVITE of a fresh call and
    /// returns the stack plus the resulting outputs.
    async fn first_trunk_answers(status: u16, call_id: &str) -> (SipStack, Vec<ProcessResult>) {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, call_id).await;
        let (first, dest) = forwarded(&results, &Method::Invite).expect("INVITE to t1");
        assert_eq!(dest, t1());
        let first = first.clone();
        let out = flatten(
            stack
                .process_message(
                    &response_to(&first, status, Some("t1tag"), None),
                    t1(),
                    None,
                )
                .await,
        );
        (stack, out)
    }

    #[tokio::test]
    async fn qa_every_failover_status_moves_call_to_second_trunk() {
        for status in [408_u16, 500, 502, 503, 504] {
            let (stack, out) = first_trunk_answers(status, &format!("fo{status}@qa")).await;
            let (retry, dest) =
                forwarded(&out, &Method::Invite).unwrap_or_else(|| panic!("{status} fails over"));
            assert_eq!(dest, t2(), "{status}: retry goes to t2");
            assert!(
                responded(&out, status).is_none(),
                "{status} hidden from caller"
            );
            assert_eq!(active(&stack, "t1").await, 0, "{status}: t1 released");
            assert_eq!(active(&stack, "t2").await, 1, "{status}: t2 reserved");
            let expect = if status == 503 {
                uc_routing::TrunkState::Cooldown
            } else {
                uc_routing::TrunkState::Available
            };
            assert_eq!(
                trunk_state(&stack, "t1").await,
                expect,
                "{status}: t1 state"
            );
            // Caller CANCEL during the failover attempt releases t2.
            let retry = retry.clone();
            stack
                .process_message(
                    &caller_request("CANCEL", DIALED, &format!("fo{status}@qa"), 1, None, None),
                    alice(),
                    None,
                )
                .await;
            stack
                .process_message(&response_to(&retry, 487, Some("t2tag"), None), t2(), None)
                .await;
            assert_all_released(&stack).await;
        }
    }

    #[tokio::test]
    async fn qa_client_and_global_errors_never_fail_over() {
        for status in [400_u16, 403, 404, 480, 484, 486, 488, 600, 603, 604, 606] {
            let (stack, out) = first_trunk_answers(status, &format!("nofo{status}@qa")).await;
            assert!(
                forwarded(&out, &Method::Invite).is_none(),
                "{status} must not fail over"
            );
            let (_, dest) =
                responded(&out, status).unwrap_or_else(|| panic!("{status} relayed to caller"));
            assert_eq!(dest, alice());
            assert_all_released(&stack).await;
            assert_eq!(
                trunk_state(&stack, "t1").await,
                uc_routing::TrunkState::Available,
                "{status}: no cooldown"
            );
        }
    }

    #[tokio::test]
    async fn qa_failover_still_happens_after_unreliable_or_sdp_less_18x() {
        // 180 without SDP, 183 with SDP but unreliable, reliable 180 without SDP.
        let cases: [(&str, u16, Option<&str>, bool); 3] = [
            ("p180", 180, None, false),
            ("p183", 183, Some(BOB_SDP), false),
            ("r180", 180, None, true),
        ];
        for (tag, code, body, reliable) in cases {
            let stack = trunk_stack(10, ("none", ""), None).await;
            let call_id = format!("{tag}@qa");
            let results = place_call(&stack, &call_id).await;
            let (first, _) = forwarded(&results, &Method::Invite).unwrap();
            let first = first.clone();
            let mut prov =
                String::from_utf8_lossy(&response_to(&first, code, Some("x"), body)).into_owned();
            if reliable {
                prov = prov.replacen(
                    "Content-Length:",
                    "Require: 100rel\r\nRSeq: 1\r\nContent-Length:",
                    1,
                );
            }
            stack.process_message(&Bytes::from(prov), t1(), None).await;
            let out = flatten(
                stack
                    .process_message(&response_to(&first, 503, Some("x"), None), t1(), None)
                    .await,
            );
            let (_, dest) = forwarded(&out, &Method::Invite)
                .unwrap_or_else(|| panic!("{tag}: failover after provisional"));
            assert_eq!(dest, t2());
            assert_eq!(active(&stack, "t2").await, 1);
        }
    }

    #[tokio::test]
    async fn qa_failover_then_caller_bye_releases() {
        let (stack, out) = first_trunk_answers(500, "fobye@qa").await;
        let (retry, _) = forwarded(&out, &Method::Invite).unwrap();
        let retry = retry.clone();
        stack
            .process_message(
                &response_to(&retry, 200, Some("bobtag"), Some(BOB_SDP)),
                t2(),
                None,
            )
            .await;
        stack
            .process_message(
                &caller_request("BYE", DIALED, "fobye@qa", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn qa_bye_cancel_race_releases_exactly_once() {
        let stack = trunk_stack(1, ("none", ""), Some(vps_with_callee_cap(5))).await;
        let results = place_call(&stack, "race@qa").await;
        let (b, _) = forwarded(&results, &Method::Invite).unwrap();
        let b = b.clone();
        let cancel = caller_request("CANCEL", DIALED, "race@qa", 1, None, None);
        let bye = caller_request("BYE", DIALED, "race@qa", 2, None, None);
        let bob_bye = bob_request(&b, "BYE", 1, None);
        let (_, _, _) = tokio::join!(
            stack.process_message(&cancel, alice(), None),
            stack.process_message(&bye, alice(), None),
            stack.process_message(&bob_bye, t1(), None),
        );
        assert_all_released(&stack).await;
        // Capacity is fully restored (no double-decrement hiding a leak):
        // max_calls=1 on each trunk, so two calls fit and a third is 503.
        let r1 = place_call(&stack, "race2@qa").await;
        assert_eq!(forwarded(&r1, &Method::Invite).unwrap().1, t1());
        let r2 = place_call(&stack, "race3@qa").await;
        assert_eq!(forwarded(&r2, &Method::Invite).unwrap().1, t2());
        let r3 = place_call(&stack, "race4@qa").await;
        assert!(responded(&r3, 503).is_some());
        assert_eq!(stack.vps_callee_concurrent_calls(DIALED).await, Some(2));
    }

    #[tokio::test]
    async fn qa_trunk_marked_down_mid_call_then_up() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "mid@qa").await;
        let (b, _) = forwarded(&results, &Method::Invite).unwrap();
        let b = b.clone();
        stack.set_trunk_reachable("t1", false).await;
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Failed
        );
        let r2 = place_call(&stack, "mid2@qa").await;
        assert_eq!(
            forwarded(&r2, &Method::Invite).unwrap().1,
            t2(),
            "down t1 skipped"
        );
        // The in-progress t1 call still tears down and releases its slot.
        stack
            .process_message(
                &response_to(&b, 200, Some("bobtag"), Some(BOB_SDP)),
                t1(),
                None,
            )
            .await;
        stack
            .process_message(&bob_request(&b, "BYE", 1, None), t1(), None)
            .await;
        assert_eq!(active(&stack, "t1").await, 0);
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Failed
        );
        stack.set_trunk_reachable("t1", true).await;
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Available
        );
        let r3 = place_call(&stack, "mid3@qa").await;
        assert_eq!(
            forwarded(&r3, &Method::Invite).unwrap().1,
            t1(),
            "t1 back up"
        );
        // Unknown trunk IDs touch nothing.
        assert_eq!(stack.set_trunk_reachable("nope", false).await, 0);
    }

    #[tokio::test]
    async fn qa_header_injection_in_translated_number_is_rejected() {
        let long = "9".repeat(60);
        for prefix in [
            ">",
            ";maddr=evil.example",
            "?X-Evil=1&",
            "\r\n",
            "\n",
            "\r",
            "a b",
            "%0d%0a",
            "<sip:evil@evil.example>",
            long.as_str(),
        ] {
            let stack = trunk_stack(10, ("add_prefix", prefix), None).await;
            let results = place_call(&stack, "inj@qa").await;
            assert!(
                forwarded(&results, &Method::Invite).is_none(),
                "nothing on the wire for {prefix:?}"
            );
            assert!(responded(&results, 500).is_some(), "500 for {prefix:?}");
            assert_all_released(&stack).await;
        }
    }

    #[tokio::test]
    async fn qa_translated_number_on_failover_invite_wire_bytes() {
        let stack = trunk_stack(10, ("strip_prefix", "2"), None).await;
        let results = place_call(&stack, "wire@qa").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&out, &Method::Invite).unwrap();
        let wire =
            String::from_utf8_lossy(&SipMessage::Request(retry.clone()).to_bytes()).into_owned();
        assert!(wire.starts_with("INVITE sip:5551234567@"), "{wire}");
        let to_line = wire
            .lines()
            .find(|l| l.starts_with("To:"))
            .expect("To header");
        assert!(to_line.contains("sip:5551234567@"), "{to_line}");
        assert!(
            !to_line.contains("tag="),
            "fresh B-leg To has no tag: {to_line}"
        );
        assert!(
            !wire.contains(DIALED),
            "dialed number not leaked in R-URI/To"
        );
    }

    #[tokio::test]
    async fn qa_config_cooldown_and_max_failures_reach_router() {
        let mut stack = SipStack::new(SipStackConfig::default());
        let groups = vec![sbc_config::TrunkGroupConfig {
            id: "g".to_string(),
            name: "G".to_string(),
            strategy: "priority".to_string(),
            trunks: vec![sbc_config::TrunkConfigSchema {
                id: "tx".to_string(),
                host: "127.0.0.9".to_string(),
                port: 5060,
                protocol: "udp".to_string(),
                priority: 1,
                max_calls: 7,
                max_failures: 2,
                cooldown_secs: 77,
                ..Default::default()
            }],
            zone: None,
        }];
        stack.init_router_from_config(&sbc_config::RoutingConfig::default(), &[], &groups);
        let router = stack.router().expect("router").read().await;
        let cfg = router
            .get_trunk_group("g")
            .and_then(|g| g.get_trunk("tx"))
            .expect("trunk")
            .config()
            .clone();
        drop(router);
        assert_eq!(cfg.max_calls, 7);
        assert_eq!(cfg.max_failures, 2);
        assert_eq!(cfg.cooldown_secs, 77);
    }

    fn register_raw(
        user: &str,
        call_id: &str,
        cseq: u32,
        contacts: &str,
        expires: Option<u32>,
    ) -> Bytes {
        let exp = expires.map_or_else(String::new, |e| format!("Expires: {e}\r\n"));
        Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-{call_id}-{cseq}\r\n\
             From: <sip:{user}@sbc.local>;tag=r{cseq}\r\n\
             To: <sip:{user}@sbc.local>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REGISTER\r\n\
             {contacts}{exp}\
             Content-Length: 0\r\n\r\n"
        ))
    }

    #[tokio::test]
    async fn qa_max_registrations_counts_bindings_and_allows_deregistration_forms() {
        let stack = SipStack::new(SipStackConfig {
            max_registrations: 2,
            ..SipStackConfig::default()
        });
        let ok = |code: (u16, Option<String>)| code.0;
        assert_eq!(
            ok(register_status(&stack, &register_msg("u1", "q-u1", 1, 3600)).await),
            200
        );
        assert_eq!(
            ok(register_status(&stack, &register_msg("u2", "q-u2", 1, 3600)).await),
            200
        );
        // A third binding (new AoR) is rejected with Retry-After.
        let (code, ra) = register_status(&stack, &register_msg("u3", "q-u3", 1, 3600)).await;
        assert_eq!((code, ra.as_deref()), (503, Some("60")));
        // A multi-contact REGISTER for a new AoR at the cap is rejected too.
        let three = "Contact: <sip:u5@127.0.0.1:1>\r\nContact: <sip:u5@127.0.0.1:2>\r\n";
        assert_eq!(
            ok(register_status(&stack, &register_raw("u5", "q-u5", 1, three, Some(3600))).await),
            503
        );
        // A query (no Contact) at the cap is allowed.
        assert_eq!(
            ok(register_status(&stack, &register_raw("u2", "q-u2", 2, "", None)).await),
            200
        );
        // Per-contact expires=0 de-registration at the cap is allowed and frees a slot.
        let off = "Contact: <sip:u1@127.0.0.1:5060>;expires=0\r\n";
        assert_eq!(
            ok(register_status(&stack, &register_raw("u1", "q-u1", 2, off, None)).await),
            200
        );
        assert_eq!(
            ok(register_status(&stack, &register_msg("u3", "q-u3", 2, 3600)).await),
            200
        );
        // Wildcard de-registration at the cap is allowed and frees a slot.
        assert_eq!(
            ok(register_status(
                &stack,
                &register_raw("u2", "q-u2", 3, "Contact: *\r\n", Some(0))
            )
            .await),
            200
        );
        assert_eq!(
            ok(register_status(&stack, &register_msg("u4", "q-u4", 1, 3600)).await),
            200
        );
    }

    /// RFC 3261 §10.3 step 7: a REGISTER for an existing contact with a new
    /// Call-ID (UA reboot) replaces that binding; it does not add one. At
    /// the cap this must not lock the phone out.
    #[tokio::test]
    async fn qa_max_registrations_allows_rebooted_phone_same_contact_new_call_id() {
        let stack = SipStack::new(SipStackConfig {
            max_registrations: 1,
            ..SipStackConfig::default()
        });
        assert_eq!(
            register_status(&stack, &register_msg("u1", "boot-1", 1, 3600))
                .await
                .0,
            200
        );
        let (code, _) = register_status(&stack, &register_msg("u1", "boot-2", 1, 3600)).await;
        assert_eq!(code, 200, "same contact, new Call-ID replaces the binding");
    }

    /// QA finding F2 / NIST-001: a multi-contact REGISTER is counted with the
    /// registrar's de-dup, so re-registering already-bound contacts under a
    /// new Call-ID does not over-count, and only the genuinely new contact
    /// of a mixed REGISTER counts.
    #[tokio::test]
    async fn max_registrations_counts_multi_contact_register_after_dedup() {
        let stack = SipStack::new(SipStackConfig {
            max_registrations: 2,
            ..SipStackConfig::default()
        });
        let two = "Contact: <sip:u1@127.0.0.1:1>\r\nContact: <sip:u1@127.0.0.1:2>\r\n";
        assert_eq!(
            register_status(&stack, &register_raw("u1", "mc-1", 1, two, Some(3600)))
                .await
                .0,
            200,
            "two contacts fit a cap of two"
        );
        // Same two contacts after a reboot (new Call-ID): 0 net-new.
        assert_eq!(
            register_status(&stack, &register_raw("u1", "mc-2", 1, two, Some(3600)))
                .await
                .0,
            200,
            "re-registering bound contacts adds nothing"
        );
        // One bound contact plus one new one is a single net-new binding,
        // which no longer fits.
        let plus = "Contact: <sip:u1@127.0.0.1:1>\r\nContact: <sip:u1@127.0.0.1:3>\r\n";
        assert_eq!(
            register_status(&stack, &register_raw("u1", "mc-2", 2, plus, Some(3600)))
                .await
                .0,
            503
        );
    }

    // ── POA&M quick wins: emergency bypass, Retry-After, send failover, audit ──

    fn authz_events(
        events: &[uc_audit::AuditEvent],
    ) -> Vec<uc_audit::event::AuthorizationDecision> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::AuthorizationDecision(d) => Some(d.clone()),
                _ => None,
            })
            .collect()
    }

    fn failover_events(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::TrunkFailover> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::TrunkFailover(f) => Some(f.clone()),
                _ => None,
            })
            .collect()
    }

    async fn place_call_to(stack: &SipStack, user: &str, call_id: &str) -> Vec<ProcessResult> {
        flatten(
            stack
                .process_message(
                    &caller_request("INVITE", user, call_id, 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        )
    }

    async fn cooldown_remaining(stack: &SipStack, trunk: &str) -> Option<std::time::Duration> {
        stack
            .router()
            .expect("router")
            .read()
            .await
            .get_trunk_group("carriers")
            .and_then(|g| g.get_trunk(trunk))
            .and_then(uc_routing::Trunk::cooldown_until)
            .map(|t| t.saturating_duration_since(Instant::now()))
    }

    fn with_retry_after(resp: &Bytes, value: &str) -> Bytes {
        Bytes::from(String::from_utf8_lossy(resp).replacen(
            "Content-Length:",
            &format!("Retry-After: {value}\r\nContent-Length:"),
            1,
        ))
    }

    #[tokio::test]
    async fn emergency_call_placed_while_callee_cap_max_calls_and_trunks_full() {
        let config = SipStackConfig {
            max_calls: 1,
            ..SipStackConfig::default()
        };
        let stack = trunk_stack_cfg(config, 1, ("none", ""), Some(vps_with_callee_cap(1))).await;
        // One ordinary call fills general.max_calls and t1's max_calls.
        let r1 = place_call(&stack, "normal@em").await;
        assert_eq!(forwarded(&r1, &Method::Invite).unwrap().1, t1());
        // The VPS cap for 911 is already full (held emergency call).
        stack.vps.as_ref().unwrap().lock().await.call_started("911");
        assert_eq!(stack.vps_callee_concurrent_calls("911").await, Some(1));

        // An ordinary call is refused by general.max_calls.
        let r2 = place_call(&stack, "normal2@em").await;
        assert!(responded(&r2, 503).is_some());

        let capture = uc_audit::capture::start();
        let r3 = place_call_to(&stack, "911", "e1@em").await;
        let (inv, dest) = forwarded(&r3, &Method::Invite).expect("911 placed");
        assert_eq!(dest, t1(), "trunk max_calls does not block 911");
        assert_eq!(inv.uri.user.as_deref(), Some("911"));
        assert_eq!(active(&stack, "t1").await, 2, "slot still counted");
        assert_eq!(
            stack.vps_callee_concurrent_calls("911").await,
            Some(1),
            "emergency call reserves no VPS slot"
        );
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1, "{authz:?}");
        assert!(authz[0].granted);
        assert_eq!(authz[0].policy, "emergency-bypass");
        assert_eq!(authz[0].source_ip, Some(alice().ip()));
        assert_eq!(authz[0].action, "INVITE");

        // A second 911 while the first is held also goes through; t1's
        // reserve (10% of 1, min 1) is used up, so it takes t2.
        let r4 = place_call_to(&stack, "911", "e2@em").await;
        assert_eq!(forwarded(&r4, &Method::Invite).unwrap().1, t2());

        // CANCEL releases the emergency trunk slot symmetrically.
        stack
            .process_message(
                &caller_request("CANCEL", "911", "e1@em", 1, None, None),
                alice(),
                None,
            )
            .await;
        assert_eq!(active(&stack, "t1").await, 1);
    }

    #[tokio::test]
    async fn emergency_reserve_bounds_global_max_calls() {
        // SEC-001 / Decision 6: max_calls=2 plus a reserve of 2.
        let config = SipStackConfig {
            max_calls: 2,
            emergency_reserve_calls: 2,
            ..SipStackConfig::default()
        };
        let stack = trunk_stack_cfg(config, 100, ("none", ""), None).await;
        // An emergency call below max_calls takes an ordinary slot.
        let e0 = place_call_to(&stack, "911", "g-e0@em").await;
        assert!(forwarded(&e0, &Method::Invite).is_some());
        let n1 = place_call(&stack, "g-n1@em").await;
        assert!(forwarded(&n1, &Method::Invite).is_some());
        // At max_calls: normal calls cannot consume the reserve.
        for i in 0..3 {
            let n = place_call(&stack, &format!("g-nx{i}@em")).await;
            assert!(
                responded(&n, 503).is_some(),
                "normal call {i} used the reserve"
            );
        }
        // Emergency calls fill the reserve exactly.
        for i in 0..2 {
            let e = place_call_to(&stack, "911", &format!("g-e{}@em", i + 1)).await;
            assert!(forwarded(&e, &Method::Invite).is_some(), "reserve slot {i}");
        }
        // max_calls + reserve reached: 503, and no bypass audited.
        let capture = uc_audit::capture::start();
        let over = place_call_to(&stack, "911", "g-over@em").await;
        assert!(forwarded(&over, &Method::Invite).is_none());
        assert!(responded(&over, 503).is_some());
        assert!(authz_events(&capture.events()).is_empty());
        assert_eq!(stack.emergency_admissions(), 3);
    }

    #[tokio::test]
    async fn emergency_reserve_bounds_trunk_max_calls() {
        // Trunks t1/t2 with max_calls=1 and the default reserve (1 each).
        let stack = trunk_stack(1, ("none", ""), None).await;
        let n1 = place_call(&stack, "t-n1@em").await;
        assert_eq!(forwarded(&n1, &Method::Invite).unwrap().1, t1());
        let n2 = place_call(&stack, "t-n2@em").await;
        assert_eq!(forwarded(&n2, &Method::Invite).unwrap().1, t2());
        // Both trunks at max_calls: a normal call cannot use the reserve.
        let n3 = place_call(&stack, "t-n3@em").await;
        assert!(responded(&n3, 503).is_some());
        // Emergency calls use each trunk's reserve, then skip to the next.
        let e1 = place_call_to(&stack, "911", "t-e1@em").await;
        assert_eq!(forwarded(&e1, &Method::Invite).unwrap().1, t1());
        let e2 = place_call_to(&stack, "911", "t-e2@em").await;
        assert_eq!(forwarded(&e2, &Method::Invite).unwrap().1, t2());
        // Every trunk at max_calls + reserve: 503.
        let e3 = place_call_to(&stack, "911", "t-e3@em").await;
        assert!(forwarded(&e3, &Method::Invite).is_none());
        assert!(responded(&e3, 503).is_some());
        assert_eq!(active(&stack, "t1").await, 2);
        assert_eq!(active(&stack, "t2").await, 2);
        // Still no room for a normal call.
        let n4 = place_call(&stack, "t-n4@em").await;
        assert!(responded(&n4, 503).is_some());
    }

    #[tokio::test]
    async fn emergency_bypasses_vps_deny_rules_only_for_emergency_numbers() {
        let vps = uc_vps::VpsEngine::new(&uc_vps::VpsConfig {
            enabled: true,
            default_action: uc_vps::VpsDefaultAction::Deny,
            tdos: uc_vps::TdosConfig {
                per_source_cps: 0,
                register_per_source_rps: 0,
                ..uc_vps::TdosConfig::default()
            },
            ..uc_vps::VpsConfig::default()
        })
        .unwrap();
        let stack = trunk_stack(10, ("none", ""), Some(vps)).await;
        // Caller-number block (number policy, bypassed for 911).
        stack
            .vps
            .as_ref()
            .unwrap()
            .lock()
            .await
            .block_caller_prefix("alice", None);
        let normal = place_call(&stack, "deny@em").await;
        assert!(forwarded(&normal, &Method::Invite).is_none());
        let em = place_call_to(&stack, "911", "deny-e@em").await;
        assert!(
            forwarded(&em, &Method::Invite).is_some(),
            "caller blocklist and default-deny do not stop 911"
        );
        // Not a prefix match.
        let not_em = place_call_to(&stack, "9111", "deny-9111@em").await;
        assert!(forwarded(&not_em, &Method::Invite).is_none());
    }

    #[tokio::test]
    async fn operator_source_ip_block_still_rejects_emergency_calls() {
        // Decision 7: an operator source-IP block applies to 911 too.
        let stack = trunk_stack(10, ("none", ""), Some(vps_with_callee_cap(10))).await;
        stack
            .vps
            .as_ref()
            .unwrap()
            .lock()
            .await
            .block_source(alice().ip(), None);
        let capture = uc_audit::capture::start();
        let em = place_call_to(&stack, "911", "blk-e@em").await;
        assert!(forwarded(&em, &Method::Invite).is_none());
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1, "{authz:?}");
        assert!(!authz[0].granted);
        assert_eq!(authz[0].policy, "vps:blocklist");
        assert_eq!(authz[0].source_ip, Some(alice().ip()));
        assert_eq!(stack.emergency_admissions(), 0);
    }

    #[tokio::test]
    async fn emergency_does_not_bypass_source_admission_or_trunk_reachability() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        // Source admission (ACL): an unknown source dialing 911 is refused.
        let capture = uc_audit::capture::start();
        let stranger = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 9), 5060);
        let r = flatten(
            stack
                .process_message(
                    &caller_request("INVITE", "911", "acl@em", 1, None, Some(ALICE_SDP)),
                    stranger,
                    None,
                )
                .await,
        );
        assert!(responded(&r, 403).is_some());
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1);
        assert_eq!(authz[0].policy, "source-admission");
        assert_eq!(authz[0].source_ip, Some(stranger.ip()));
        drop(capture);

        // Unreachable / cooling trunks are still skipped.
        stack.set_trunk_reachable("t1", false).await;
        stack.set_trunk_reachable("t2", false).await;
        let r = place_call_to(&stack, "911", "down@em").await;
        assert!(forwarded(&r, &Method::Invite).is_none());
        assert!(responded(&r, 503).is_some());
    }

    #[tokio::test]
    async fn empty_emergency_list_disables_the_bypass() {
        let config = SipStackConfig {
            max_calls: 1,
            emergency_numbers: uc_vps::EmergencyNumbers::default(),
            ..SipStackConfig::default()
        };
        let stack = trunk_stack_cfg(config, 10, ("none", ""), None).await;
        place_call(&stack, "fill@em").await;
        let r = place_call_to(&stack, "911", "nolist@em").await;
        assert!(responded(&r, 503).is_some());
    }

    fn response_with_retry_after(value: Option<&str>) -> SipResponse {
        let mut resp = SipResponse::new(StatusCode::SERVICE_UNAVAILABLE);
        if let Some(v) = value {
            resp.headers.set(HeaderName::RetryAfter, v);
        }
        resp
    }

    #[test]
    fn retry_after_cooldown_honoured_clamped_or_fallback() {
        let secs = |v: Option<&str>| {
            retry_after_cooldown(&response_with_retry_after(v), 300).map(|d| d.as_secs())
        };
        assert_eq!(secs(Some("120")), Some(120));
        assert_eq!(secs(Some("120(maintenance)")), Some(120));
        assert_eq!(secs(Some("120\t;duration=10")), Some(120));
        assert_eq!(secs(Some("1")), Some(1), "no cooldown_secs floor");
        assert_eq!(secs(Some(" 120 (maintenance);duration=10")), Some(120));
        assert_eq!(secs(Some("120;duration=10")), Some(120));
        assert_eq!(secs(Some("120 (a (nested) \\) ok)  ")), Some(120));
        assert_eq!(secs(Some("301")), Some(300));
        assert_eq!(secs(Some("4294967296")), Some(300));
        assert_eq!(secs(Some("99999999999999999999999999")), Some(300));
        for fallback in [
            None,
            Some("0"),
            Some("abc"),
            Some(""),
            Some("-5"),
            Some("(soon)"),
            Some("1e9"),
            Some("12abc"),
            Some("120x"),
            Some("18446744073709551616x"),
            Some("120 abc"),
            Some("120 1e9"),
            Some("120 )"),
            Some("120 (unclosed"),
            Some("120 (a) b"),
        ] {
            assert_eq!(secs(fallback), None, "{fallback:?}");
        }
        assert_eq!(
            retry_after_cooldown(&response_with_retry_after(Some("50")), 10).map(|d| d.as_secs()),
            Some(10)
        );
        // Hostile input never panics and never exceeds the clamp.
        for v in [
            "\u{0}",
            "9\u{301}",
            "１２",
            "1e9",
            "+1",
            "  ",
            "18446744073709551616x",
        ] {
            let d = retry_after_cooldown(&response_with_retry_after(Some(v)), 300);
            assert!(d.is_none_or(|d| d.as_secs() <= 300), "{v:?}");
        }
    }

    #[tokio::test]
    async fn failover_503_retry_after_sets_trunk_cooldown() {
        for (value, lo, hi) in [
            (Some("120"), 118, 120),
            (Some("4294967296"), 298, 300),
            (None, 28, 30),
            (Some("0"), 28, 30),
            (Some("garbage"), 28, 30),
        ] {
            let stack = trunk_stack(10, ("none", ""), None).await;
            let results = place_call(&stack, "ra@test").await;
            let (first, _) = forwarded(&results, &Method::Invite).unwrap();
            let first = first.clone();
            let mut resp = response_to(&first, 503, Some("t1tag"), None);
            if let Some(v) = value {
                resp = with_retry_after(&resp, v);
            }
            let out = flatten(stack.process_message(&resp, t1(), None).await);
            assert_eq!(forwarded(&out, &Method::Invite).unwrap().1, t2());
            let left = cooldown_remaining(&stack, "t1").await.expect("cooling");
            assert!(
                (lo..=hi).contains(&left.as_secs()),
                "{value:?}: cooldown {left:?} not in {lo}..={hi}"
            );
        }
    }

    #[tokio::test]
    async fn final_503_without_failover_honours_retry_after() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "ra-final@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&first, 500, Some("x"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&out, &Method::Invite).unwrap();
        let retry = retry.clone();
        let resp = with_retry_after(&response_to(&retry, 503, Some("y"), None), "45");
        let out = flatten(stack.process_message(&resp, t2(), None).await);
        assert!(responded(&out, 503).is_some(), "last error relayed");
        let left = cooldown_remaining(&stack, "t2").await.expect("t2 cooling");
        assert!((43..=45).contains(&left.as_secs()), "{left:?}");
    }

    #[tokio::test]
    async fn retransmission_send_failure_after_successful_first_send_is_log_only() {
        // PERF-001: a successful send returns before any lock, recording the
        // branch in the first-send ledger, so a retransmit failure is
        // log-only.
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "rtx@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = SipMessage::Request(first.clone());
        assert!(stack.on_invite_sent(&first, true).await.is_empty());
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let timers = stack.poll_timers().await;
        let (rtx, dest) = forwarded(&timers, &Method::Invite).expect("Timer A retransmit");
        assert_eq!(dest, t1());
        let rtx = SipMessage::Request(rtx.clone());
        assert!(stack.on_invite_sent(&rtx, false).await.is_empty());
        assert_eq!(active(&stack, "t1").await, 1);
        assert_eq!(active(&stack, "t2").await, 0);
    }

    #[tokio::test]
    async fn slow_first_send_failing_after_timer_a_still_fails_over_once() {
        // RFC-003: on TCP/TLS the first send can report after Timer A
        // (500 ms). Its failure is still a first-send failure.
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "slow@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = SipMessage::Request(first.clone());
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let timers = stack.poll_timers().await;
        assert!(
            forwarded(&timers, &Method::Invite).is_some(),
            "Timer A fired"
        );
        let out = flatten(ProcessResult::Multiple(
            stack.on_invite_sent(&first, false).await,
        ));
        let (_, dest) = forwarded(&out, &Method::Invite).expect("immediate failover");
        assert_eq!(dest, t2());
        assert_eq!(active(&stack, "t1").await, 0);
        assert_eq!(active(&stack, "t2").await, 1);
        // The retransmission's failure on the dead attempt is ignored.
        assert!(stack.on_invite_sent(&first, false).await.is_empty());
        assert_eq!(active(&stack, "t2").await, 1);
    }

    #[tokio::test]
    async fn send_failure_fails_over_once_without_waiting_for_timer_b() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "sf@test").await;
        let (first, dest) = forwarded(&results, &Method::Invite).unwrap();
        assert_eq!(dest, t1());
        let first = SipMessage::Request(first.clone());
        let old_branch = match &first {
            SipMessage::Request(r) => r.headers.via_branch().unwrap(),
            SipMessage::Response(_) => unreachable!(),
        };

        let capture = uc_audit::capture::start();
        let out = flatten(ProcessResult::Multiple(
            stack.on_invite_sent(&first, false).await,
        ));
        let (retry, dest) = forwarded(&out, &Method::Invite).expect("immediate failover");
        assert_eq!(dest, t2());
        let retry = SipMessage::Request(retry.clone());
        assert_eq!(active(&stack, "t1").await, 0);
        assert_eq!(active(&stack, "t2").await, 1);
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Available,
            "a transport error does not cool the trunk down"
        );
        let t1_failures = stack
            .router()
            .unwrap()
            .read()
            .await
            .get_trunk_group("carriers")
            .and_then(|g| g.get_trunk("t1"))
            .map(|t| t.stats().consecutive_failures);
        assert_eq!(t1_failures, Some(1), "counts as TrunkOutcome::Failed");
        let fo = failover_events(&capture.events());
        assert_eq!(fo.len(), 1);
        assert_eq!(fo[0].failed_trunk_id, "t1");
        assert_eq!(fo[0].next_trunk_id, "t2");
        assert_eq!(fo[0].group_id, "carriers");
        assert_eq!(
            fo[0].reason,
            uc_audit::event::FailoverReason::TransportError
        );

        // No double failover: a second report for the old attempt and its
        // Timer B are no-ops.
        assert!(stack.on_invite_sent(&first, false).await.is_empty());
        let call = stack
            .call_correlation
            .read()
            .await
            .addresses
            .keys()
            .next()
            .cloned()
            .unwrap();
        assert!(
            stack
                .fail_timed_out_request(&old_branch, &call)
                .await
                .is_empty()
        );
        // The dead attempt's transaction is gone: no Timer A toward t1.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let timers = stack.poll_timers().await;
        assert!(
            timers.iter().all(|r| !matches!(
                r,
                ProcessResult::Forward { destination, .. } if *destination == t1()
            )),
            "{timers:?}"
        );
        // The new attempt's first send succeeded; a later (retransmission)
        // failure is log-only.
        assert!(stack.on_invite_sent(&retry, true).await.is_empty());
        assert!(stack.on_invite_sent(&retry, false).await.is_empty());
        assert_eq!(failover_events(&capture.events()).len(), 1);
        assert_eq!(active(&stack, "t2").await, 1);
    }

    #[tokio::test]
    async fn send_failure_with_no_trunk_left_answers_503_and_releases() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "sf2@test").await;
        let first = SipMessage::Request(forwarded(&results, &Method::Invite).unwrap().0.clone());
        let out = flatten(ProcessResult::Multiple(
            stack.on_invite_sent(&first, false).await,
        ));
        let retry = SipMessage::Request(forwarded(&out, &Method::Invite).unwrap().0.clone());
        let out = flatten(ProcessResult::Multiple(
            stack.on_invite_sent(&retry, false).await,
        ));
        let (_, dest) = responded(&out, 503).expect("503 to the caller (RFC 3261 §8.1.3.1)");
        assert_eq!(dest, alice());
        assert!(forwarded(&out, &Method::Invite).is_none());
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn send_result_ignored_for_non_initial_invites() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        // Unknown branch.
        let stray = SipMessage::Request(
            SipMessage::parse(&caller_request("INVITE", DIALED, "x@t", 1, None, None))
                .ok()
                .and_then(|m| match m {
                    SipMessage::Request(r) => Some(r),
                    SipMessage::Response(_) => None,
                })
                .unwrap(),
        );
        assert!(stack.on_invite_sent(&stray, false).await.is_empty());
        // Non-INVITE (BYE) and responses.
        let bye =
            SipMessage::parse(&caller_request("BYE", DIALED, "x@t", 2, Some("t"), None)).unwrap();
        assert!(stack.on_invite_sent(&bye, false).await.is_empty());
        let results = place_call(&stack, "ok@test").await;
        let first = SipMessage::Request(forwarded(&results, &Method::Invite).unwrap().0.clone());
        // A response already arrived (Proceeding): no failover.
        let first_req = match &first {
            SipMessage::Request(r) => r.clone(),
            SipMessage::Response(_) => unreachable!(),
        };
        stack
            .process_message(
                &response_to(&first_req, 180, Some("t1tag"), None),
                t1(),
                None,
            )
            .await;
        assert!(stack.on_invite_sent(&first, false).await.is_empty());
        assert_eq!(active(&stack, "t1").await, 1);
    }

    #[tokio::test]
    async fn denials_carry_source_ip_in_audit() {
        // number-translation-invalid
        let stack = trunk_stack(10, ("add_prefix", "@evil;"), None).await;
        let capture = uc_audit::capture::start();
        place_call(&stack, "xl@audit").await;
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1);
        assert_eq!(authz[0].policy, "number-translation-invalid");
        assert_eq!(authz[0].source_ip, Some(alice().ip()));
        assert!(!authz[0].granted);
        drop(capture);

        // no-usable-trunk
        let stack = trunk_stack(10, ("none", ""), None).await;
        stack.set_trunk_reachable("t1", false).await;
        stack.set_trunk_reachable("t2", false).await;
        let capture = uc_audit::capture::start();
        place_call(&stack, "down@audit").await;
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1);
        assert_eq!(authz[0].policy, "no-usable-trunk");
        assert_eq!(authz[0].source_ip, Some(alice().ip()));
        drop(capture);

        // max-registrations
        let stack = SipStack::new(SipStackConfig {
            max_registrations: 1,
            ..SipStackConfig::default()
        });
        register_status(&stack, &register_msg("u1", "ra-u1", 1, 3600)).await;
        let capture = uc_audit::capture::start();
        let (code, _) = register_status(&stack, &register_msg("u2", "ra-u2", 1, 3600)).await;
        assert_eq!(code, 503);
        let authz = authz_events(&capture.events());
        assert_eq!(authz.len(), 1);
        assert_eq!(authz[0].policy, "max-registrations");
        assert_eq!(authz[0].source_ip, Some(bob().ip()));
    }

    #[tokio::test]
    async fn reachability_change_is_audited() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let capture = uc_audit::capture::start();
        let n = stack
            .apply_trunk_reachability_change(
                "t1",
                false,
                uc_audit::event::ReachabilitySource::Options,
            )
            .await;
        assert_eq!(n, 1);
        stack
            .apply_trunk_reachability_change("t1", true, uc_audit::event::ReachabilitySource::Agent)
            .await;
        let events: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::TrunkReachabilityChanged(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trunk_id, "t1");
        assert!(!events[0].reachable);
        assert_eq!(
            events[0].source,
            uc_audit::event::ReachabilitySource::Options
        );
        assert!(events[1].reachable);
        assert_eq!(events[1].source, uc_audit::event::ReachabilitySource::Agent);
        assert_eq!(
            trunk_state(&stack, "t1").await,
            uc_routing::TrunkState::Available
        );
    }

    #[tokio::test]
    async fn status_failover_is_audited_with_status_reason() {
        let capture = uc_audit::capture::start();
        let (_stack, out) = first_trunk_answers(503, "fo-audit@qa").await;
        assert!(forwarded(&out, &Method::Invite).is_some());
        let fo = failover_events(&capture.events());
        assert_eq!(fo.len(), 1);
        assert_eq!(fo[0].reason, uc_audit::event::FailoverReason::Status(503));
        assert_eq!(fo[0].call_id.as_str(), "fo-audit@qa");
    }

    // ── QA (poam-quick-wins): extra coverage ──

    /// `trunk_stack_cfg` with catch-all routes so 933/112/`+911`/`(911)`
    /// reach the trunk group (the base plan only routes `+1` and `9`).
    async fn qa_catchall_stack(
        config: SipStackConfig,
        max_calls: u32,
        vps: Option<uc_vps::VpsEngine>,
    ) -> SipStack {
        let mut stack = SipStack::new(config);
        let routing = sbc_config::RoutingConfig {
            use_dial_plan: true,
            max_failover_attempts: 3,
            default_trunk_group: "carriers".to_string(),
        };
        let entry = |prefix: &str, priority: u32| sbc_config::DialPlanEntryConfig {
            direction: "both".to_string(),
            pattern_type: "prefix".to_string(),
            pattern_value: prefix.to_string(),
            trunk_group: "carriers".to_string(),
            transform_type: "none".to_string(),
            transform_value: String::new(),
            priority,
            ..Default::default()
        };
        let dial_plans = vec![sbc_config::DialPlanConfig {
            id: "plan".to_string(),
            name: "Plan".to_string(),
            active: true,
            entries: vec![entry("+", 1), entry("9", 2), entry("1", 3), entry("(", 4)],
        }];
        let trunk = |id: &str, host: &str, priority: u32| sbc_config::TrunkConfigSchema {
            id: id.to_string(),
            host: host.to_string(),
            port: 5060,
            protocol: "udp".to_string(),
            priority,
            max_calls,
            max_failures: 3,
            ..Default::default()
        };
        let groups = vec![sbc_config::TrunkGroupConfig {
            id: "carriers".to_string(),
            name: "Carriers".to_string(),
            strategy: "priority".to_string(),
            trunks: vec![trunk("t1", "127.0.0.2", 1), trunk("t2", "127.0.0.3", 2)],
            zone: None,
        }];
        stack.init_router_from_config(&routing, &dial_plans, &groups);
        if let Some(engine) = vps {
            stack.set_vps_engine(engine);
        }
        stack
            .register_inbound_trunk("pbx", None, &[("192.168.1.1".to_string(), 5060)])
            .await;
        stack
    }

    /// Every default emergency number, and its separator/`+` spellings, is
    /// placed with the VPS per-callee cap full, `general.max_calls` full and
    /// every trunk at `max_calls`; each is audited with source_ip.
    #[tokio::test]
    async fn qa_each_default_emergency_number_placed_with_all_caps_full() {
        let spellings = [
            "911", "933", "112", "+911", "+933", "+112", "9-1-1", "9.1.1", "(911)", "9-3-3",
            "1-1-2",
        ];
        for (i, user) in spellings.iter().enumerate() {
            let config = SipStackConfig {
                max_calls: 2,
                ..SipStackConfig::default()
            };
            let stack = qa_catchall_stack(config, 1, Some(vps_with_callee_cap(1))).await;
            // Fill t1 and t2 max_calls and general.max_calls.
            assert!(
                forwarded(
                    &place_call_to(&stack, "+15550000001", &format!("f1-{i}@qa")).await,
                    &Method::Invite
                )
                .is_some()
            );
            assert!(
                forwarded(
                    &place_call_to(&stack, "+15550000002", &format!("f2-{i}@qa")).await,
                    &Method::Invite
                )
                .is_some()
            );
            assert!(
                responded(
                    &place_call_to(&stack, "+15550000003", &format!("f3-{i}@qa")).await,
                    503
                )
                .is_some()
            );
            // VPS per-callee cap full for the canonical numbers.
            for n in ["911", "933", "112"] {
                stack.vps.as_ref().unwrap().lock().await.call_started(n);
            }
            let capture = uc_audit::capture::start();
            let r = place_call_to(&stack, user, &format!("em-{i}@qa")).await;
            assert!(
                forwarded(&r, &Method::Invite).is_some(),
                "{user}: emergency call must be placed, got {r:?}"
            );
            let authz = authz_events(&capture.events());
            assert_eq!(authz.len(), 1, "{user}: {authz:?}");
            assert_eq!(authz[0].policy, "emergency-bypass");
            assert!(authz[0].granted);
            assert_eq!(authz[0].source_ip, Some(alice().ip()));
        }
    }

    /// Near-misses are not exempt: with capacity full they get 503 and no
    /// emergency-bypass audit.
    #[tokio::test]
    async fn qa_emergency_near_misses_are_not_exempt() {
        for (i, user) in [
            "9110", "91", "9-1-1-1", "9111", "1911", "+1911", "988", "11",
        ]
        .iter()
        .enumerate()
        {
            let config = SipStackConfig {
                max_calls: 1,
                ..SipStackConfig::default()
            };
            let stack = qa_catchall_stack(config, 1, None).await;
            assert!(
                forwarded(
                    &place_call(&stack, &format!("nf-{i}@qa")).await,
                    &Method::Invite
                )
                .is_some()
            );
            let capture = uc_audit::capture::start();
            let r = place_call_to(&stack, user, &format!("nm-{i}@qa")).await;
            assert!(
                forwarded(&r, &Method::Invite).is_none(),
                "{user} must not bypass"
            );
            assert!(responded(&r, 503).is_some(), "{user}: {r:?}");
            assert!(
                authz_events(&capture.events())
                    .iter()
                    .all(|d| d.policy != "emergency-bypass"),
                "{user}"
            );
        }
    }

    /// An emergency call still respects trunk cooldown (not only reachability).
    #[tokio::test]
    async fn qa_emergency_still_respects_trunk_cooldown() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        {
            let router = stack.router().unwrap();
            let mut r = router.write().await;
            r.cooldown_trunk("carriers", "t1", Some(std::time::Duration::from_secs(60)));
            r.cooldown_trunk("carriers", "t2", Some(std::time::Duration::from_secs(60)));
        }
        let r = place_call_to(&stack, "911", "cool@em").await;
        assert!(forwarded(&r, &Method::Invite).is_none());
        assert!(responded(&r, 503).is_some());
    }

    /// Retry-After of 1 s and with comment/params, end to end on failover.
    #[tokio::test]
    async fn qa_failover_503_retry_after_short_and_with_comment() {
        for (value, lo, hi) in [
            ("1", 0, 1),
            ("120 (maintenance);duration=10", 118, 120),
            ("3601", 298, 300),
            ("-1", 28, 30),
        ] {
            let stack = trunk_stack(10, ("none", ""), None).await;
            let results = place_call(&stack, "ra2@test").await;
            let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
            let resp = with_retry_after(&response_to(&first, 503, Some("t1tag"), None), value);
            let out = flatten(stack.process_message(&resp, t1(), None).await);
            assert_eq!(forwarded(&out, &Method::Invite).unwrap().1, t2());
            let left = cooldown_remaining(&stack, "t1").await.expect("cooling");
            assert!(
                (lo..=hi).contains(&left.as_secs()),
                "{value:?}: {left:?} not in {lo}..={hi}"
            );
        }
    }

    /// Timer B failover is audited with reason Timeout.
    #[tokio::test]
    async fn qa_timer_b_failover_is_audited_with_timeout_reason() {
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "tb@qa").await;
        let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let branch = first.headers.via_branch().unwrap();
        let call = stack
            .call_correlation
            .read()
            .await
            .addresses
            .keys()
            .next()
            .cloned()
            .unwrap();
        let capture = uc_audit::capture::start();
        let out = flatten(ProcessResult::Multiple(
            stack.fail_timed_out_request(&branch, &call).await,
        ));
        assert_eq!(forwarded(&out, &Method::Invite).unwrap().1, t2());
        let fo = failover_events(&capture.events());
        assert_eq!(fo.len(), 1);
        assert_eq!(fo[0].reason, uc_audit::event::FailoverReason::Timeout);
        assert_eq!(fo[0].failed_trunk_id, "t1");
        assert_eq!(fo[0].next_trunk_id, "t2");
    }

    /// Send failures of CANCEL, ACK and in-dialog requests are log-only.
    #[tokio::test]
    async fn qa_send_failure_of_cancel_ack_and_in_dialog_is_log_only() {
        // CANCEL toward the trunk.
        let stack = trunk_stack(10, ("none", ""), None).await;
        let results = place_call(&stack, "cx@qa").await;
        let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
        stack
            .process_message(&response_to(&first, 100, None, None), t1(), None)
            .await;
        let out = flatten(
            stack
                .process_message(
                    &caller_request("CANCEL", DIALED, "cx@qa", 1, None, None),
                    alice(),
                    None,
                )
                .await,
        );
        let capture = uc_audit::capture::start();
        if let Some((cancel, _)) = forwarded(&out, &Method::Cancel) {
            let cancel = SipMessage::Request(cancel.clone());
            assert!(stack.on_invite_sent(&cancel, false).await.is_empty());
        }
        // The INVITE's own (late) send failure after CANCEL: no new trunk.
        let r = stack
            .on_invite_sent(&SipMessage::Request(first.clone()), false)
            .await;
        assert!(forwarded(&flatten(ProcessResult::Multiple(r)), &Method::Invite).is_none());
        assert!(failover_events(&capture.events()).is_empty());
        drop(capture);

        // ACK and re-INVITE in an established dialog.
        let (stack, _b_invite) = established_call().await;
        let capture = uc_audit::capture::start();
        let results = flatten(
            stack
                .process_message(
                    &alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                )
                .await,
        );
        let (reinv, _) = forwarded(&results, &Method::Invite).expect("re-INVITE to bob");
        let reinv = SipMessage::Request(reinv.clone());
        assert!(stack.on_invite_sent(&reinv, false).await.is_empty());
        let ack = SipMessage::parse(&alice_request("ACK", 1, Some("bobtag"), None)).unwrap();
        assert!(stack.on_invite_sent(&ack, false).await.is_empty());
        assert!(failover_events(&capture.events()).is_empty());
        assert!(
            !stack.call_correlation.read().await.addresses.is_empty(),
            "dialog kept"
        );
    }

    // ------------------------------------------------------------------
    // CDR emission (plan §8): exactly one CDR per call on every teardown
    // path, reject-site CDRs, no CDR for auth challenges.
    // ------------------------------------------------------------------

    fn cdr_emitter() -> Arc<uc_cdr::CdrEmitter> {
        uc_cdr::CdrEmitter::start(
            uc_cdr::CdrEmitterConfig {
                node_id: "test".into(),
                file: None,
                ..Default::default()
            },
            Vec::new(),
            None,
        )
        .unwrap()
    }

    /// A trunk stack with a ring-only CDR pipeline.
    async fn cdr_stack_cfg(
        config: SipStackConfig,
        cdr: sbc_config::schema::CdrConfig,
    ) -> (SipStack, Arc<uc_cdr::CdrEmitter>) {
        let mut stack = trunk_stack_cfg(config, 10, ("none", ""), None).await;
        let emitter = cdr_emitter();
        stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
            Arc::clone(&emitter),
            &cdr,
        )));
        (stack, emitter)
    }

    async fn cdr_stack() -> (SipStack, Arc<uc_cdr::CdrEmitter>) {
        cdr_stack_cfg(
            SipStackConfig::default(),
            sbc_config::schema::CdrConfig::default(),
        )
        .await
    }

    /// Every CDR written so far, oldest first.
    fn cdrs(emitter: &uc_cdr::CdrEmitter) -> Vec<uc_cdr::CallRecord> {
        assert!(emitter.flush(std::time::Duration::from_secs(5)));
        let page = emitter
            .ring()
            .query(&uc_cdr::CdrFilter::default(), None, 500);
        page.records.iter().rev().map(|r| (**r).clone()).collect()
    }

    fn one_cdr(emitter: &uc_cdr::CdrEmitter) -> uc_cdr::CallRecord {
        let all = cdrs(emitter);
        assert_eq!(all.len(), 1, "exactly one CDR: {all:#?}");
        all.into_iter().next().unwrap()
    }

    fn attempts(r: &uc_cdr::CallRecord) -> Vec<(&str, uc_cdr::TrunkOutcome)> {
        r.trunks_tried
            .iter()
            .map(|t| (t.trunk_id.as_str(), t.status))
            .collect()
    }

    async fn answer(stack: &SipStack, inv: &SipRequest, from: SbcSocketAddr) {
        stack
            .process_message(&response_to(inv, 180, Some("bobtag"), None), from, None)
            .await;
        stack
            .process_message(
                &response_to(inv, 200, Some("bobtag"), Some(BOB_SDP)),
                from,
                None,
            )
            .await;
    }

    async fn internal_id(stack: &SipStack, a_call_id: &str) -> CallId {
        stack
            .call_correlation
            .read()
            .await
            .a_leg
            .get(a_call_id)
            .cloned()
            .expect("call stored")
    }

    #[tokio::test]
    async fn cdr_answered_then_caller_bye() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "ans@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        answer(&stack, &inv, t1()).await;
        let bye = caller_request("BYE", DIALED, "ans@cdr", 2, Some("bobtag"), None);
        stack.process_message(&bye, alice(), None).await;
        // A retransmitted BYE does not produce a second CDR.
        stack.process_message(&bye, alice(), None).await;
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::Normal);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Caller);
        assert_eq!(c.final_sip_status, 200);
        assert_eq!(c.a_call_id, "ans@cdr");
        assert_eq!(c.caller, "alice");
        assert_eq!(c.callee_dialed, DIALED);
        assert_eq!(c.source_ip, alice().ip().to_string());
        assert_eq!(c.direction, uc_cdr::Direction::Inbound);
        assert_eq!(c.trunk_group.as_deref(), Some("carriers"));
        assert_eq!(c.final_trunk.as_deref(), Some("t1"));
        assert_eq!(
            attempts(&c),
            vec![("t1", uc_cdr::TrunkOutcome::Status(200))]
        );
        assert_eq!(c.failover_count, 0);
        assert_eq!(c.codec.as_deref(), Some("PCMU"));
        assert!(c.ring_ms.is_some() && c.answer_ms.is_some() && c.pdd_ms.is_some());
        assert!(!c.emergency);
        assert_eq!(c.record_id, "test-0");
        assert_all_released(&stack).await;
    }

    /// QA: answered, translated call through a real file sink. Checks
    /// timestamp ordering, durations, pre/post translation and the on-disk
    /// chain.
    #[tokio::test]
    async fn qa_cdr_answered_translated_call_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut stack = trunk_stack(10, ("strip_prefix", "2"), None).await;
        let em = uc_cdr::CdrEmitter::start(
            uc_cdr::CdrEmitterConfig {
                node_id: "qa".into(),
                file: Some(uc_cdr::FileSinkConfig {
                    directory: dir.path().to_path_buf(),
                    rotate_interval: None,
                    fsync_interval: std::time::Duration::ZERO,
                    ..Default::default()
                }),
                ..Default::default()
            },
            Vec::new(),
            None,
        )
        .unwrap();
        stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
            Arc::clone(&em),
            &sbc_config::schema::CdrConfig::default(),
        )));
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let r = place_call(&stack, "qa-ans@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        answer(&stack, &inv, t1()).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let bye = caller_request("BYE", DIALED, "qa-ans@cdr", 2, Some("bobtag"), None);
        stack.process_message(&bye, alice(), None).await;
        assert!(em.shutdown(std::time::Duration::from_secs(5)));

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(uc_cdr::verify_file(&files[0]).unwrap().records, 1);
        let text = std::fs::read_to_string(&files[0]).unwrap();
        let c: uc_cdr::CallRecord = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
        assert!(c.setup_ms >= before);
        let ring = c.ring_ms.unwrap();
        let ans = c.answer_ms.unwrap();
        assert!(
            c.setup_ms <= ring && ring <= ans && ans <= c.end_ms,
            "{c:#?}"
        );
        assert_eq!(c.duration_ms, c.end_ms - ans);
        assert!(c.duration_ms >= 15, "BYE came >=20 ms after answer: {c:#?}");
        assert_eq!(c.pdd_ms, Some(ring - c.setup_ms));
        assert_eq!(c.callee_dialed, DIALED);
        assert_eq!(c.callee_translated.as_deref(), Some("5551234567"));
        assert_eq!(c.final_trunk.as_deref(), Some("t1"));
        assert_eq!(c.b_call_ids.len(), 1);
        assert_ne!(c.b_call_ids[0], c.a_call_id, "B-leg has its own Call-ID");
        assert!(!c.emergency);
    }

    /// Plan gap: a calling-number rewrite (header manipulation on the B-leg
    /// From) is recorded as `caller_translated`; untouched calls leave it
    /// unset.
    #[tokio::test]
    async fn cdr_caller_translated_from_b_leg_from() {
        let (mut stack, em) = cdr_stack().await;
        stack.init_manipulator_from_config(&sbc_config::HeaderManipulationConfig {
            global_rules: vec![sbc_config::ManipulationRuleConfig {
                name: "calling-number".to_string(),
                direction: "both".to_string(),
                action: "set".to_string(),
                header: "From".to_string(),
                value: "<sip:+12025550100@sbc.test>;tag=sbc1".to_string(),
            }],
            trunk_rules: Vec::new(),
        });
        let r = place_call(&stack, "xlate@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        assert!(
            inv.headers
                .get_value(&HeaderName::From)
                .is_some_and(|f| f.contains("+12025550100")),
            "manipulation applied to the B-leg From"
        );
        answer(&stack, &inv, t1()).await;
        let bye = caller_request("BYE", DIALED, "xlate@cdr", 2, Some("bobtag"), None);
        stack.process_message(&bye, alice(), None).await;
        let c = one_cdr(&em);
        assert_eq!(c.caller_translated.as_deref(), Some("+12025550100"));
        assert_ne!(c.caller, "+12025550100");
    }

    /// QA: an answered 911 call is flagged emergency and keeps the dialed
    /// number.
    #[tokio::test]
    async fn qa_cdr_answered_emergency_call_flagged() {
        let (stack, em) = cdr_stack().await;
        let r = place_call_to(&stack, "911", "qa-e911@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        answer(&stack, &inv, t1()).await;
        let bye = caller_request("BYE", "911", "qa-e911@cdr", 2, Some("bobtag"), None);
        stack.process_message(&bye, alice(), None).await;
        let c = one_cdr(&em);
        assert!(c.emergency);
        assert_eq!(c.callee_dialed, "911");
        assert_eq!(c.callee_translated, None);
        assert_eq!(c.caller_translated, None, "From not rewritten");
        assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
    }

    #[tokio::test]
    async fn cdr_answered_then_callee_bye_with_q850() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "cbye@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        answer(&stack, &inv, t1()).await;
        let bye = bob_request(&inv, "BYE", 2, None);
        let bye = String::from_utf8(bye.to_vec()).unwrap().replacen(
            "Content-Length",
            "Reason: Q.850;cause=16;text=\"Normal\"\r\nContent-Length",
            1,
        );
        stack.process_message(&Bytes::from(bye), t1(), None).await;
        let c = one_cdr(&em);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Callee);
        assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
        assert_eq!(c.q850_cause, Some(16));
    }

    #[tokio::test]
    async fn cdr_cancel_before_answer() {
        let (stack, em) = cdr_stack().await;
        place_call(&stack, "can@cdr").await;
        stack
            .process_message(
                &caller_request("CANCEL", DIALED, "can@cdr", 1, None, None),
                alice(),
                None,
            )
            .await;
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::Cancelled);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::Cancel);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Caller);
        assert_eq!(c.final_sip_status, 487);
        assert_eq!(c.duration_ms, 0);
        assert!(c.answer_ms.is_none());
    }

    #[tokio::test]
    async fn cdr_trunk_busy() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "busy@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        stack
            .process_message(&response_to(&inv, 486, Some("t1tag"), None), t1(), None)
            .await;
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::Busy);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::TrunkError);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Callee);
        assert_eq!(c.final_sip_status, 486);
        assert_eq!(
            attempts(&c),
            vec![("t1", uc_cdr::TrunkOutcome::Status(486))]
        );
    }

    #[tokio::test]
    async fn cdr_timer_b_on_last_trunk() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "tb@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        let id = internal_id(&stack, "tb@cdr").await;
        // t1 times out: fail over to t2, which times out too.
        let out = stack
            .fail_timed_out_request(&inv.headers.via_branch().unwrap(), &id)
            .await;
        let retry = flatten(ProcessResult::Multiple(out));
        let retry = forwarded(&retry, &Method::Invite).unwrap().0.clone();
        let out = stack
            .fail_timed_out_request(&retry.headers.via_branch().unwrap(), &id)
            .await;
        assert!(responded(&out, 408).is_some());
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::NoAnswer);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::TimerB);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Sbc);
        assert_eq!(c.final_sip_status, 408);
        assert_eq!(
            attempts(&c),
            vec![
                ("t1", uc_cdr::TrunkOutcome::Timeout),
                ("t2", uc_cdr::TrunkOutcome::Timeout)
            ]
        );
        assert_eq!(c.failover_count, 1);
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn cdr_media_failure_after_answer() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "mf@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        answer(&stack, &inv, t1()).await;
        let id = internal_id(&stack, "mf@cdr").await;
        let byes = stack.terminate_call_on_media_failure(&id.to_string()).await;
        assert_eq!(byes.len(), 2);
        assert_eq!(
            stack
                .terminate_call_on_media_failure(&id.to_string())
                .await
                .len(),
            0,
            "second media failure is a no-op"
        );
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::MediaFailure);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::MediaFailure);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Sbc);
        assert!(c.answer_ms.is_some());
    }

    #[tokio::test]
    async fn cdr_failover_then_answer_lists_trunk_attempts() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "fo@cdr").await;
        let first = forwarded(&r, &Method::Invite).unwrap().0.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (retry, dest) = forwarded(&out, &Method::Invite).unwrap();
        assert_eq!(dest, t2());
        let retry = retry.clone();
        answer(&stack, &retry, t2()).await;
        stack
            .process_message(
                &caller_request("BYE", DIALED, "fo@cdr", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
        assert_eq!(c.failover_count, 1);
        assert_eq!(c.b_call_ids.len(), 2);
        assert_eq!(c.b_call_ids[0], first.headers.call_id().unwrap());
        assert_eq!(c.b_call_ids[1], retry.headers.call_id().unwrap());
        assert_eq!(
            attempts(&c),
            vec![
                ("t1", uc_cdr::TrunkOutcome::Status(503)),
                ("t2", uc_cdr::TrunkOutcome::Status(200))
            ]
        );
        assert_eq!(c.final_trunk.as_deref(), Some("t2"));
    }

    #[tokio::test]
    async fn cdr_bye_cancel_race_emits_exactly_one() {
        let (stack, em) = cdr_stack().await;
        let results = place_call(&stack, "race@cdr").await;
        let b = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let cancel = caller_request("CANCEL", DIALED, "race@cdr", 1, None, None);
        let bye = caller_request("BYE", DIALED, "race@cdr", 2, None, None);
        let bob_bye = bob_request(&b, "BYE", 1, None);
        let _ = tokio::join!(
            stack.process_message(&cancel, alice(), None),
            stack.process_message(&bye, alice(), None),
            stack.process_message(&bob_bye, t1(), None),
        );
        one_cdr(&em);
        assert_eq!(em.stats().emitted, 1);
    }

    #[tokio::test]
    async fn cdr_trunk_407_is_not_recorded_unless_configured() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "auth@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&inv, 407, Some("t1tag"), None), t1(), None)
                .await,
        );
        assert!(responded(&out, 407).is_some(), "407 relayed to the caller");
        assert_eq!(cdrs(&em), Vec::new(), "no CDR for an auth challenge");
        assert_all_released(&stack).await;

        let (stack, em) = cdr_stack_cfg(
            SipStackConfig::default(),
            sbc_config::schema::CdrConfig {
                record_auth_challenges: true,
                ..Default::default()
            },
        )
        .await;
        let r = place_call(&stack, "auth2@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        stack
            .process_message(&response_to(&inv, 407, Some("t1tag"), None), t1(), None)
            .await;
        assert_eq!(one_cdr(&em).final_sip_status, 407);
    }

    #[tokio::test]
    async fn cdr_register_challenge_is_not_recorded() {
        let (stack, em) = cdr_stack_cfg(
            SipStackConfig {
                require_auth: true,
                ..SipStackConfig::default()
            },
            sbc_config::schema::CdrConfig::default(),
        )
        .await;
        let (status, _) = register_status(&stack, &register_msg("alice", "reg@cdr", 1, 3600)).await;
        assert_eq!(status, 401);
        assert_eq!(cdrs(&em), Vec::new());
    }

    #[tokio::test]
    async fn cdr_reject_sites() {
        let config = SipStackConfig {
            max_calls: 1,
            emergency_reserve_calls: 0,
            ..SipStackConfig::default()
        };
        let (stack, em) = cdr_stack_cfg(config, sbc_config::schema::CdrConfig::default()).await;

        // 403: source admission.
        let mallory = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 9), 5060);
        let r = flatten(
            stack
                .process_message(
                    &caller_request("INVITE", DIALED, "deny@cdr", 1, None, None),
                    mallory,
                    None,
                )
                .await,
        );
        assert!(responded(&r, 403).is_some());
        // SEC-2: the source-admission 403 is an ACL-layer reject (audited,
        // no CDR), so a spoofed-source flood cannot fill the CDR volume.
        assert_eq!(cdrs(&em), Vec::new());

        // 503: max_calls (one call held). The INVITE is retransmitted
        // twice and rejected each time; it still yields one CDR.
        place_call(&stack, "held@cdr").await;
        for _ in 0..3 {
            let r = place_call(&stack, "full@cdr").await;
            assert!(responded(&r, 503).is_some());
        }

        // 503: draining.
        stack.set_draining();
        let r = place_call(&stack, "drain@cdr").await;
        assert!(responded(&r, 503).is_some());

        let got: Vec<_> = cdrs(&em)
            .into_iter()
            .map(|c| {
                assert_eq!(c.release_side, uc_cdr::ReleaseSide::Sbc);
                assert_eq!(c.disposition, uc_cdr::Disposition::Rejected);
                (c.a_call_id, c.final_sip_status, c.release_cause)
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "full@cdr".to_string(),
                    503,
                    uc_cdr::ReleaseCause::AdmissionMaxCalls
                ),
                ("drain@cdr".to_string(), 503, uc_cdr::ReleaseCause::Draining),
            ]
        );
    }

    #[tokio::test]
    async fn cdr_no_route_announcement_is_a_reject() {
        // No router at all: every number is unroutable and gets the
        // announcement (200) or 480 when it cannot play.
        let mut stack = SipStack::new(SipStackConfig::default());
        let em = cdr_emitter();
        stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
            Arc::clone(&em),
            &sbc_config::schema::CdrConfig::default(),
        )));
        stack
            .register_inbound_trunk("pbx", None, &[("192.168.1.1".to_string(), 5060)])
            .await;
        let r = place_call(&stack, "noroute@cdr").await;
        let status = [200, 480]
            .into_iter()
            .find(|c| responded(&r, *c).is_some())
            .unwrap_or_else(|| panic!("announcement answer or 480: {r:?}"));
        let c = one_cdr(&em);
        assert_eq!(c.disposition, uc_cdr::Disposition::Rejected);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::NoRoute);
        assert_eq!(c.final_sip_status, status);
    }

    #[tokio::test]
    async fn cdr_no_usable_trunk_is_a_no_route_reject() {
        let (stack, em) = cdr_stack().await;
        stack.set_trunk_reachable("t1", false).await;
        stack.set_trunk_reachable("t2", false).await;
        let r = place_call(&stack, "down@cdr").await;
        assert!(responded(&r, 503).is_some());
        let c = one_cdr(&em);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::NoRoute);
        assert_eq!(c.final_sip_status, 503);
    }

    #[tokio::test]
    async fn cdr_record_unanswered_routed_skips_rejects() {
        let (stack, em) = cdr_stack_cfg(
            SipStackConfig::default(),
            sbc_config::schema::CdrConfig {
                record_unanswered: sbc_config::schema::CdrRecordUnanswered::Routed,
                ..Default::default()
            },
        )
        .await;
        stack.set_draining();
        place_call(&stack, "drain@cdr").await;
        assert_eq!(cdrs(&em), Vec::new());
    }

    #[tokio::test]
    async fn cdr_reject_new_calls_admits_emergency_only() {
        let (stack, em) = cdr_stack_cfg(
            SipStackConfig::default(),
            sbc_config::schema::CdrConfig {
                on_failure: sbc_config::schema::CdrOnFailure::RejectNewCalls,
                ..Default::default()
            },
        )
        .await;
        // Healthy pipeline: calls are admitted.
        let r = place_call(&stack, "ok@cdr").await;
        assert!(forwarded(&r, &Method::Invite).is_some());
        // Writer stopped: the pipeline is unhealthy.
        assert!(em.shutdown(std::time::Duration::from_secs(5)));
        assert_eq!(em.health(), uc_cdr::CdrHealth::Unhealthy);
        let r = place_call(&stack, "refused@cdr").await;
        assert!(responded(&r, 503).is_some(), "non-emergency refused");
        let r = place_call_to(&stack, "911", "e911@cdr").await;
        assert!(
            forwarded(&r, &Method::Invite).is_some(),
            "emergency always admitted"
        );
    }

    #[tokio::test]
    async fn cdr_continue_mode_admits_while_unhealthy() {
        let (stack, em) = cdr_stack().await;
        assert!(em.shutdown(std::time::Duration::from_secs(5)));
        let r = place_call(&stack, "cont@cdr").await;
        assert!(forwarded(&r, &Method::Invite).is_some());
    }

    #[tokio::test]
    async fn cdr_shutdown_ends_remaining_calls() {
        let (stack, em) = cdr_stack().await;
        let r = place_call(&stack, "up@cdr").await;
        let inv = forwarded(&r, &Method::Invite).unwrap().0.clone();
        answer(&stack, &inv, t1()).await;
        place_call(&stack, "ringing@cdr").await;
        assert_eq!(stack.end_remaining_calls_for_shutdown().await, 2);
        let all = cdrs(&em);
        assert_eq!(all.len(), 2);
        assert!(
            all.iter()
                .all(|c| c.release_cause == uc_cdr::ReleaseCause::Shutdown)
        );
        assert!(
            all.iter()
                .any(|c| c.disposition == uc_cdr::Disposition::Answered)
        );
        assert_all_released(&stack).await;
    }

    #[tokio::test]
    async fn cdr_hostile_from_is_capped_and_valid_json() {
        let (stack, em) = cdr_stack().await;
        let user = format!("a\"b{}", "x".repeat(10_000));
        let invite =
            String::from_utf8(caller_request("INVITE", DIALED, "evil@cdr", 1, None, None).to_vec())
                .unwrap()
                .replacen(
                    "sip:alice@example.com",
                    &format!("sip:{user}@example.com"),
                    1,
                );
        stack
            .process_message(&Bytes::from(invite), alice(), None)
            .await;
        stack
            .process_message(
                &caller_request("CANCEL", DIALED, "evil@cdr", 1, None, None),
                alice(),
                None,
            )
            .await;
        for c in cdrs(&em) {
            assert!(c.caller.len() <= uc_cdr::record::MAX_FIELD_LEN);
            let line = serde_json::to_string(&c).unwrap();
            let back: uc_cdr::CallRecord = serde_json::from_str(&line).unwrap();
            assert_eq!(back, c);
        }
    }

    // ── STIR/SHAKEN in the INVITE path ─────────────────────────────────

    /// [`trunk_stack`] plus a STIR service: alice (192.168.1.1) is a config
    /// trunk with `verify = true`; t1 has `sign = true`.
    async fn stir_stack(
        policy: sbc_config::StirFailurePolicy,
        require_identity: bool,
    ) -> (SipStack, crate::stir::test_support::StiFiles) {
        let mut stack = trunk_stack(10, ("none", ""), None).await;
        let f = crate::stir::test_support::sti_files();
        let mut c = sbc_config::SbcConfig::default();
        let ss = &mut c.stir_shaken;
        ss.signing_enabled = true;
        ss.signing.private_key_path = Some(f.key.clone());
        ss.signing.certificate_path = Some(f.cert.clone());
        ss.signing.certificate_url = Some("https://cert.example.com/a.pem".into());
        ss.verification_enabled = true;
        ss.verification.trust_anchors_path = Some(f.anchors.clone());
        ss.verification.failure_policy = policy;
        ss.verification.require_identity = require_identity;
        ss.verification.cert_fetch_timeout_ms = 200;
        let trunk = |id: &str, host: &str, stir| sbc_config::TrunkConfigSchema {
            id: id.into(),
            host: host.into(),
            stir_shaken: stir,
            ..Default::default()
        };
        c.trunk_groups.push(sbc_config::TrunkGroupConfig {
            id: "carriers".into(),
            name: String::new(),
            strategy: "priority".into(),
            trunks: vec![
                trunk(
                    "t1",
                    "127.0.0.2",
                    sbc_config::TrunkStirConfig {
                        sign: true,
                        ..Default::default()
                    },
                ),
                trunk(
                    "alice-trunk",
                    "192.168.1.1",
                    sbc_config::TrunkStirConfig {
                        verify: true,
                        ..Default::default()
                    },
                ),
            ],
            zone: None,
        });
        stack.set_stir(Arc::new(crate::stir::test_support::service(&c)));
        (stack, f)
    }

    fn invite_with_identity(call_id: &str, identity: Option<&str>) -> Bytes {
        let raw = caller_request("INVITE", DIALED, call_id, 1, None, Some(ALICE_SDP));
        let Some(id) = identity else {
            return raw;
        };
        let text = String::from_utf8_lossy(&raw).into_owned();
        Bytes::from(text.replacen("Contact:", &format!("Identity: {id}\r\nContact:"), 1))
    }

    fn response_status(results: &[ProcessResult]) -> Option<(u16, Option<String>)> {
        results.iter().find_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } if resp.status.code() >= 300 => Some((
                resp.status.code(),
                resp.headers
                    .get_value(&HeaderName::Reason)
                    .map(str::to_owned),
            )),
            _ => None,
        })
    }

    #[tokio::test]
    async fn stir_missing_identity_with_require_is_428() {
        let (stack, _f) = stir_stack(sbc_config::StirFailurePolicy::Mark, true).await;
        let results = flatten(
            stack
                .process_message(&invite_with_identity("stir-428@test", None), alice(), None)
                .await,
        );
        let (code, reason) = response_status(&results).expect("rejected");
        assert_eq!(code, 428);
        assert_eq!(
            reason.as_deref(),
            Some("SIP;cause=428;text=\"Use Identity Header\"")
        );
        assert!(forwarded(&results, &Method::Invite).is_none());
        assert_all_released(&stack).await;
    }

    /// RFC 8224 §6.2.2: an undecodable Identity is 438 under `reject`.
    #[tokio::test]
    async fn stir_malformed_identity_reject_is_438() {
        let (stack, _f) = stir_stack(sbc_config::StirFailurePolicy::Reject, false).await;
        let bad = "eyJh.eyJh.c2ln;info=<https://cert.example.com/a.pem>;ppt=\"shaken\"";
        let results = flatten(
            stack
                .process_message(
                    &invite_with_identity("stir-438@test", Some(bad)),
                    alice(),
                    None,
                )
                .await,
        );
        let (code, reason) = response_status(&results).expect("rejected");
        assert_eq!(code, 438);
        assert!(reason.unwrap().contains("cause=438"));
        assert_all_released(&stack).await;
    }

    /// Default `mark`: the call continues with verstat=TN-Validation-Failed
    /// on the B-leg From, no inbound Identity is relayed (untrusted ingress),
    /// and the B-leg From (SBC identity, not a TN) is not signed.
    #[tokio::test]
    async fn stir_failed_identity_mark_forwards_with_failed_verstat() {
        let (stack, _f) = stir_stack(sbc_config::StirFailurePolicy::Mark, false).await;
        // SSRF target in info/x5u: refused without a fetch (bad-info).
        let token = {
            let h = r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://169.254.169.254/c"}"#;
            let p = r#"{"attest":"A","dest":{"tn":["15551234567"]},"iat":1,"orig":{"tn":"12025550100"},"origid":"u"}"#;
            let mut t = String::new();
            proto_stir_shaken::jws::b64url_encode_into(h.as_bytes(), &mut t);
            t.push('.');
            proto_stir_shaken::jws::b64url_encode_into(p.as_bytes(), &mut t);
            t.push('.');
            proto_stir_shaken::jws::b64url_encode_into(&[7u8; 64], &mut t);
            t
        };
        let id = format!("{token};info=<https://169.254.169.254/c>;alg=ES256;ppt=\"shaken\"");
        let results = flatten(
            stack
                .process_message(
                    &invite_with_identity("stir-mark@test", Some(&id)),
                    alice(),
                    None,
                )
                .await,
        );
        let (b_invite, _) = forwarded(&results, &Method::Invite).expect("call continues");
        let from = b_invite.headers.get_value(&HeaderName::From).unwrap();
        assert!(from.contains(";verstat=TN-Validation-Failed>"), "{from}");
        assert!(!b_invite.headers.contains(&HeaderName::Identity));
        let stir = stack.stir().unwrap();
        assert_eq!(stir.metrics.verify_failed.load(Ordering::Relaxed), 1);
        assert_eq!(stir.metrics.sign_failed.load(Ordering::Relaxed), 1);
    }

    // ── QA: STIR/SHAKEN daemon paths (verified, parked+CANCEL, failover) ──

    const QA_X5U: &str = "https://cert.example.com/a.pem";
    const QA_ORIG: &str = "+12025550100";

    struct QaStir {
        stack: SipStack,
        files: crate::stir::test_support::StiFiles,
        source: Arc<crate::stir::test_support::FakeSource>,
        cdr: Arc<uc_cdr::CdrEmitter>,
    }

    /// CDR-enabled trunk stack with a STIR service whose x5u fetch is served
    /// by a [`crate::stir::test_support::FakeSource`] returning the real
    /// test end-entity certificate after `fetch_delay_ms`.
    async fn qa_stir_stack(
        policy: sbc_config::StirFailurePolicy,
        fetch_delay_ms: u64,
        fetch_timeout_ms: u64,
        t2_sign: bool,
        manip_pai: bool,
    ) -> QaStir {
        qa_stir_stack_with(
            policy,
            fetch_delay_ms,
            fetch_timeout_ms,
            t2_sign,
            manip_pai,
            |_| {},
        )
        .await
    }

    /// [`qa_stir_stack`] with a final tweak of the STIR config.
    async fn qa_stir_stack_with(
        policy: sbc_config::StirFailurePolicy,
        fetch_delay_ms: u64,
        fetch_timeout_ms: u64,
        t2_sign: bool,
        manip_pai: bool,
        tweak: impl FnOnce(&mut sbc_config::SbcConfig),
    ) -> QaStir {
        let (mut stack, cdr) = cdr_stack().await;
        if manip_pai {
            stack.init_manipulator_from_config(&sbc_config::HeaderManipulationConfig {
                global_rules: vec![sbc_config::ManipulationRuleConfig {
                    name: "qa-pai".into(),
                    direction: "outbound".into(),
                    action: "set".into(),
                    header: "P-Asserted-Identity".into(),
                    value: format!("<sip:{QA_ORIG}@sbc.test;user=phone>"),
                }],
                trunk_rules: vec![],
            });
        }
        let files = crate::stir::test_support::sti_files();
        let mut c = sbc_config::SbcConfig::default();
        let ss = &mut c.stir_shaken;
        ss.signing_enabled = true;
        ss.signing.private_key_path = Some(files.key.clone());
        ss.signing.certificate_path = Some(files.cert.clone());
        ss.signing.certificate_url = Some(QA_X5U.into());
        ss.verification_enabled = true;
        ss.verification.trust_anchors_path = Some(files.anchors.clone());
        ss.verification.failure_policy = policy;
        ss.verification.cert_fetch_timeout_ms = fetch_timeout_ms;
        let trunk = |id: &str, host: &str, stir| sbc_config::TrunkConfigSchema {
            id: id.into(),
            host: host.into(),
            stir_shaken: stir,
            ..Default::default()
        };
        c.trunk_groups.push(sbc_config::TrunkGroupConfig {
            id: "carriers".into(),
            name: String::new(),
            strategy: "priority".into(),
            trunks: vec![
                trunk(
                    "t1",
                    "127.0.0.2",
                    sbc_config::TrunkStirConfig {
                        sign: true,
                        ..Default::default()
                    },
                ),
                trunk(
                    "t2",
                    "127.0.0.3",
                    sbc_config::TrunkStirConfig {
                        sign: t2_sign,
                        ..Default::default()
                    },
                ),
                trunk(
                    "alice-trunk",
                    "192.168.1.1",
                    sbc_config::TrunkStirConfig {
                        verify: true,
                        strip_inbound_identity: true,
                        ..Default::default()
                    },
                ),
            ],
            zone: None,
        });
        tweak(&mut c);
        let source = Arc::new(crate::stir::test_support::FakeSource {
            body: std::fs::read_to_string(&files.cert).unwrap(),
            delay: std::time::Duration::from_millis(fetch_delay_ms),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let svc = crate::stir::test_support::service_with_source(
            &c,
            Arc::clone(&source) as Arc<dyn uc_sti::fetch::CertSource>,
        );
        stack.set_stir(Arc::new(svc));
        QaStir {
            stack,
            files,
            source,
            cdr,
        }
    }

    /// A real ES256 Identity for orig=QA_ORIG, dest=DIALED, signed by the
    /// test STI key (chains to the configured anchors).
    fn qa_identity(files: &crate::stir::test_support::StiFiles, iat_offset: i64) -> String {
        let now = uc_sti::cache::unix_now();
        let signer =
            uc_sti::signer::FileSigner::load(&files.key, &files.cert, QA_X5U, now).unwrap();
        let iat = u64::try_from(i64::try_from(now).unwrap() + iat_offset).unwrap();
        uc_sti::sign_identity(
            &signer,
            QA_X5U,
            proto_stir_shaken::Attestation::Full,
            proto_stir_shaken::canonicalize_tn(QA_ORIG).unwrap(),
            proto_stir_shaken::canonicalize_tn(DIALED).unwrap(),
            iat,
        )
        .unwrap()
    }

    fn qa_invite(call_id: &str, identity: Option<&str>) -> Bytes {
        let raw = invite_with_identity(call_id, identity);
        let text = String::from_utf8_lossy(&raw).into_owned();
        Bytes::from(text.replacen(
            "Contact:",
            &format!("P-Asserted-Identity: <sip:{QA_ORIG}@example.com;user=phone>\r\nContact:"),
            1,
        ))
    }

    /// Verified-passes path end to end in the daemon: cache miss → fetch →
    /// chain to anchors → ES256 verify → verstat Passed on the B-leg, VPS
    /// status VerifiedA, CDR v2 fields; a second call hits the cache.
    #[tokio::test]
    async fn qa_stir_valid_identity_passes_and_records_cdr() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Reject, 0, 1000, false, false).await;
        let id = qa_identity(&q.files, 0);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-pass@test", Some(&id)), alice(), None)
                .await,
        );
        assert!(response_status(&results).is_none(), "not rejected");
        let (b_invite, dest) = forwarded(&results, &Method::Invite).expect("forwarded");
        assert_eq!(dest, t1());
        // t1 signs, so the caller's PAI is on the B-leg and carries verstat.
        let pai = b_invite
            .headers
            .get_value(&HeaderName::PAssertedIdentity)
            .unwrap();
        assert!(pai.contains(";verstat=TN-Validation-Passed>"), "{pai}");
        let stir = q.stack.stir().unwrap();
        assert_eq!(stir.metrics.verify_passed.load(Ordering::Relaxed), 1);
        assert_eq!(stir.metrics.parked.load(Ordering::Relaxed), 0);
        assert_eq!(q.source.calls.load(Ordering::SeqCst), 1);

        q.stack
            .process_message(
                &caller_request("CANCEL", DIALED, "qa-pass@test", 1, None, None),
                alice(),
                None,
            )
            .await;
        let r = one_cdr(&q.cdr);
        assert_eq!(
            r.stir_verstat,
            Some(uc_cdr::record::Verstat::TnValidationPassed)
        );
        assert_eq!(
            r.stir_inbound_attestation,
            Some(uc_cdr::record::Attestation::A)
        );
        assert_eq!(r.stir_x5u_host.as_deref(), Some("cert.example.com"));
        assert_eq!(r.stir_verify_reason, None);

        // Second call: cache hit, no new fetch.
        let id2 = qa_identity(&q.files, 0);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-pass2@test", Some(&id2)), alice(), None)
                .await,
        );
        assert!(forwarded(&results, &Method::Invite).is_some());
        assert_eq!(q.source.calls.load(Ordering::SeqCst), 1, "cache hit");
        assert_eq!(stir.metrics.verify_passed.load(Ordering::Relaxed), 2);
    }

    /// Valid signature but stale iat → 438 under reject (RFC 8224 §6.2).
    #[tokio::test]
    async fn qa_stir_stale_iat_rejected_403_stale_date() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Reject, 0, 1000, false, false).await;
        let id = qa_identity(&q.files, -3600);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-stale@test", Some(&id)), alice(), None)
                .await,
        );
        // RFC 8224 §6.2.2: stale iat is 403 "Stale Date", not 438.
        let (code, reason) = response_status(&results).expect("rejected");
        assert_eq!(code, 403);
        let reason = reason.unwrap();
        assert!(reason.contains("cause=403"), "{reason}");
        assert!(reason.contains("Stale Date"), "{reason}");
        let phrase = results.iter().find_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } if resp.status.code() == 403 => resp.reason.clone(),
            _ => None,
        });
        assert_eq!(phrase.as_deref(), Some("Stale Date"));
        assert!(forwarded(&results, &Method::Invite).is_none());
        assert_all_released(&q.stack).await;
    }

    /// Valid token whose dest does not match the R-URI → 438 (dest binding).
    #[tokio::test]
    async fn qa_stir_dest_mismatch_rejected() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Reject, 0, 1000, false, false).await;
        let id = qa_identity(&q.files, 0);
        let raw = String::from_utf8_lossy(&qa_invite("qa-dest@test", Some(&id))).into_owned();
        let raw = raw.replace("+15551234567", "+15559990000");
        let results = flatten(
            q.stack
                .process_message(&Bytes::from(raw), alice(), None)
                .await,
        );
        let (code, _) = response_status(&results).expect("rejected");
        assert_eq!(code, 438);
        assert_all_released(&q.stack).await;
    }

    /// Fetch slower than cert_fetch_timeout_ms → 436 cert-fetch-timeout under
    /// reject, parked gauge returns to 0, and the cache still fills.
    #[tokio::test]
    async fn qa_stir_fetch_timeout_reject_436_then_cache_fills() {
        let q = qa_stir_stack(
            sbc_config::StirFailurePolicy::Reject,
            300,
            100,
            false,
            false,
        )
        .await;
        let id = qa_identity(&q.files, 0);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-to@test", Some(&id)), alice(), None)
                .await,
        );
        let (code, reason) = response_status(&results).expect("rejected");
        assert_eq!(code, 436, "{reason:?}");
        let stir = q.stack.stir().unwrap();
        assert_eq!(stir.metrics.parked.load(Ordering::Relaxed), 0);
        assert_all_released(&q.stack).await;
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(stir.cert_cache_entries(), 1, "fetch outlived the caller");
    }

    /// CANCEL arrives while the INVITE is parked on a cert fetch. The caller
    /// cancelled, so the B-leg INVITE must not be sent (or, if sent, the
    /// call must be torn down), and nothing may leak.
    #[tokio::test]
    async fn qa_stir_cancel_while_cert_fetch_pending() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 300, 1000, false, false).await;
        let id = qa_identity(&q.files, 0);
        let invite = qa_invite("qa-cancel@test", Some(&id));
        let cancel = caller_request("CANCEL", DIALED, "qa-cancel@test", 1, None, None);
        let (inv_res, cancel_res) =
            tokio::join!(q.stack.process_message(&invite, alice(), None), async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                q.stack.process_message(&cancel, alice(), None).await
            });
        let inv_res = flatten(inv_res);
        let cancel_res = flatten(cancel_res);
        let stir = q.stack.stir().unwrap();
        assert_eq!(stir.metrics.parked.load(Ordering::Relaxed), 0);
        let cancel_code = cancel_res.iter().find_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } => Some(resp.status.code()),
            _ => None,
        });
        let b_invite = forwarded(&inv_res, &Method::Invite).map(|(r, _)| r.clone());
        // Observed behaviour: CANCEL is serialised behind the parked INVITE,
        // so the B-leg INVITE goes out and is immediately CANCELled. Accept
        // that, but require the B-leg CANCEL to match the B-leg INVITE.
        if let Some(b_invite) = b_invite {
            let (b_cancel, dest) = forwarded(&cancel_res, &Method::Cancel).unwrap_or_else(|| {
                panic!("B-leg INVITE sent but never CANCELled ({cancel_code:?})")
            });
            assert_eq!(dest, t1());
            assert_eq!(b_cancel.headers.call_id(), b_invite.headers.call_id());
            assert_eq!(b_cancel.headers.via_branch(), b_invite.headers.via_branch());
        }
        assert!(responded(&cancel_res, 487).is_some() || responded(&inv_res, 487).is_some());
        assert_all_released(&q.stack).await;
    }

    /// RFC 8224 §6.2.2 at the daemon: malformed Identity values under
    /// `reject` are refused with 436/437/438 + Reason, never forwarded.
    #[tokio::test]
    async fn qa_stir_malformed_identity_table() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Reject, 0, 500, false, false).await;
        let good = qa_identity(&q.files, 0);
        let tok = good.split(';').next().unwrap().to_owned();
        let (h, rest) = tok.split_once('.').unwrap();
        let (p, sig) = rest.split_once('.').unwrap();
        let cases: Vec<(&str, String, &[u16])> = vec![
            ("no info", tok.clone(), &[436]),
            (
                "http info",
                format!("{tok};info=<http://cert.example.com/a.pem>"),
                &[436],
            ),
            (
                "alg none",
                format!("{tok};info=<{QA_X5U}>;alg=none"),
                &[437, 438],
            ),
            (
                "alg ES384",
                format!("{tok};info=<{QA_X5U}>;alg=ES384;ppt=\"shaken\""),
                &[437, 438],
            ),
            (
                "empty sig",
                format!("{h}.{p}.;info=<{QA_X5U}>;ppt=\"shaken\""),
                &[438],
            ),
            (
                "tampered sig",
                // Flip the last char to a different valid one (it ends in
                // 'A' about 1 in 16 runs, which would not tamper).
                format!(
                    "{h}.{p}.{}{};info=<{QA_X5U}>",
                    &sig[..sig.len() - 1],
                    if sig.ends_with('A') { 'Q' } else { 'A' }
                ),
                &[438],
            ),
            ("two parts", format!("{h}.{p};info=<{QA_X5U}>"), &[438]),
            (
                "oversized",
                format!("{};info=<{QA_X5U}>", "a".repeat(6000)),
                &[438],
            ),
            (
                "info mismatch",
                format!("{tok};info=<https://other.example.com/a.pem>"),
                &[436, 438],
            ),
            ("garbage", "%%%;;;<<>>".to_owned(), &[436, 438]),
        ];
        for (i, (name, value, codes)) in cases.iter().enumerate() {
            let cid = format!("qa-mal-{i}@test");
            let results = flatten(
                q.stack
                    .process_message(&qa_invite(&cid, Some(value)), alice(), None)
                    .await,
            );
            let got = response_status(&results);
            let (code, reason) = got
                .clone()
                .unwrap_or_else(|| panic!("{name}: not rejected"));
            assert!(codes.contains(&code), "{name}: got {code}, want {codes:?}");
            assert!(
                reason
                    .as_deref()
                    .is_some_and(|r| r.contains(&format!("cause={code}"))),
                "{name}: Reason {reason:?}"
            );
            assert!(forwarded(&results, &Method::Invite).is_none(), "{name}");
        }
        assert_all_released(&q.stack).await;
    }

    /// Duplicate Identity headers: one valid, one garbage. Must not crash;
    /// verification uses the SHAKEN one or fails, but never forwards an
    /// inbound Identity on an untrusted (strip) trunk.
    #[tokio::test]
    async fn qa_stir_duplicate_identity_headers() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 1000, false, false).await;
        let good = qa_identity(&q.files, 0);
        let both = format!("{good}\r\nIdentity: junk.junk.junk;info=<{QA_X5U}>");
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-dup@test", Some(&both)), alice(), None)
                .await,
        );
        let (b, _) = forwarded(&results, &Method::Invite).expect("mark continues");
        // Only the SBC's own signature (t1 signs), never an inbound value.
        let ids: Vec<&str> = b
            .headers
            .get_all(&HeaderName::Identity)
            .map(|h| h.value.as_str())
            .collect();
        assert!(ids.len() <= 1, "{ids:?}");
        assert!(
            ids.iter().all(|v| *v != good && !v.contains("junk")),
            "{ids:?}"
        );
        let pai = b.headers.get_value(&HeaderName::PAssertedIdentity).unwrap();
        assert!(pai.contains("verstat=TN-Validation-"), "{pai}");
    }

    /// Outbound signing on t1 (sign=true), then 503 → failover to t2 with
    /// sign=false. The retry must not carry t1's Identity.
    #[tokio::test]
    async fn qa_stir_failover_to_unsigned_trunk_drops_identity() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 500, false, true).await;
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-fo@test", None), alice(), None)
                .await,
        );
        let (first, dest) = forwarded(&results, &Method::Invite).expect("INVITE to t1");
        assert_eq!(dest, t1());
        assert!(first.headers.contains(&HeaderName::Identity), "t1 signed");
        let first = first.clone();
        let results = flatten(
            q.stack
                .process_message(&response_to(&first, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (retry, dest) = forwarded(&results, &Method::Invite).expect("failover");
        assert_eq!(dest, t2());
        assert!(
            !retry.headers.contains(&HeaderName::Identity),
            "t2 has sign=false but the failover INVITE carries t1's Identity"
        );
        // The QA stack's manipulation rule sets this PAI on every attempt.
        assert!(retry.headers.contains(&HeaderName::PAssertedIdentity));
    }

    /// Failover re-signs for the next trunk: a new token (fresh iat, new
    /// ES256 signature), not the first trunk's Identity re-sent.
    #[tokio::test]
    async fn qa_stir_failover_resigns_with_fresh_iat() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 500, true, false).await;
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-fo3@test", None), alice(), None)
                .await,
        );
        let (first, _) = forwarded(&results, &Method::Invite).expect("INVITE to t1");
        let first = first.clone();
        let first_id = first
            .headers
            .get_value(&HeaderName::Identity)
            .expect("t1 signed")
            .to_owned();
        let v = proto_stir_shaken::Verifier::default();
        let first_iat = v
            .prepare([first_id.as_str()])
            .unwrap()
            .unwrap()
            .passport
            .claims
            .iat;
        let results = flatten(
            q.stack
                .process_message(&response_to(&first, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (retry, dest) = forwarded(&results, &Method::Invite).expect("failover");
        assert_eq!(dest, t2());
        assert_eq!(retry.headers.get_all(&HeaderName::Identity).count(), 1);
        let retry_id = retry.headers.get_value(&HeaderName::Identity).unwrap();
        assert_ne!(retry_id, first_id, "re-signed, not re-sent");
        let p = v.prepare([retry_id]).unwrap().unwrap();
        assert!(p.passport.claims.iat >= first_iat);
        assert!(uc_sti::cache::unix_now().saturating_sub(p.passport.claims.iat) < 5);
        assert_eq!(p.passport.claims.orig.as_str(), "12025550100");
        // RFC-002: the re-signed retry's Date matches its fresh iat.
        let want =
            chrono::DateTime::from_timestamp(i64::try_from(p.passport.claims.iat).unwrap(), 0)
                .unwrap()
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string();
        assert_eq!(retry.headers.get_all(&HeaderName::Date).count(), 1);
        assert_eq!(
            retry.headers.get_value(&HeaderName::Date),
            Some(want.as_str())
        );
        assert_eq!(
            retry
                .headers
                .get_all(&HeaderName::PAssertedIdentity)
                .count(),
            1
        );
        let stir = q.stack.stir().unwrap();
        assert_eq!(stir.metrics.sign_ok.load(Ordering::Relaxed), 2);
    }

    /// Registered-endpoint INVITE from `src` with `from_user` (and an
    /// optional endpoint-supplied PAI) to DIALED.
    fn endpoint_invite(
        call_id: &str,
        src: SbcSocketAddr,
        from_user: &str,
        pai: Option<&str>,
    ) -> Bytes {
        let pai = pai.map_or_else(String::new, |p| format!("P-Asserted-Identity: {p}\r\n"));
        Bytes::from(format!(
            "INVITE sip:{DIALED}@sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP {src};branch=z9hG4bK-{call_id}\r\n\
             From: <sip:{from_user}@sbc.local>;tag=e-{call_id}\r\n\
             To: <sip:{DIALED}@sbc.local>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             {pai}Contact: <sip:{from_user}@{src}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{ALICE_SDP}",
            ALICE_SDP.len()
        ))
    }

    /// Attestation of the forwarded INVITE's Identity, if signed.
    fn forwarded_attest(
        results: &[ProcessResult],
    ) -> (Option<proto_stir_shaken::Attestation>, Option<String>) {
        let Some((b, _)) = forwarded(results, &Method::Invite) else {
            return (None, None);
        };
        let attest = b.headers.get_value(&HeaderName::Identity).map(|id| {
            let p = proto_stir_shaken::Verifier::default()
                .prepare([id])
                .unwrap()
                .unwrap();
            (
                p.passport.claims.attest,
                p.passport.claims.orig.as_str().to_owned(),
            )
        });
        (attest.as_ref().map(|a| a.0), attest.map(|a| a.1))
    }

    /// Sends an endpoint INVITE and flattens the results.
    async fn send(
        stack: &SipStack,
        call_id: &str,
        src: SbcSocketAddr,
        from: &str,
        pai: Option<&str>,
    ) -> Vec<ProcessResult> {
        send_on(stack, call_id, src, from, pai, AddrTransport::Tcp).await
    }

    /// The stream connection the STIR tests' endpoint REGISTERs and sends
    /// INVITEs on (one per test process; ids are never reused).
    static TEST_CONN: std::sync::LazyLock<crate::stir_binding::ConnId> =
        std::sync::LazyLock::new(crate::stir_binding::ConnId::next);

    /// [`send`] over `transport` (on [`TEST_CONN`]; ignored for UDP).
    async fn send_on(
        stack: &SipStack,
        call_id: &str,
        src: SbcSocketAddr,
        from: &str,
        pai: Option<&str>,
        transport: AddrTransport,
    ) -> Vec<ProcessResult> {
        send_conn(stack, call_id, src, from, transport, Some(*TEST_CONN), pai).await
    }

    /// [`send`] over `transport` on stream connection `conn`.
    async fn send_conn(
        stack: &SipStack,
        call_id: &str,
        src: SbcSocketAddr,
        from: &str,
        transport: AddrTransport,
        conn: Option<crate::stir_binding::ConnId>,
        pai: Option<&str>,
    ) -> Vec<ProcessResult> {
        flatten(
            stack
                .process_message_conn(
                    &endpoint_invite(call_id, src, from, pai),
                    src,
                    None,
                    transport,
                    conn,
                )
                .await,
        )
    }

    /// SEC-001: an endpoint is "authenticated" only when its INVITE is bound
    /// to a registration from the same source address, and only the number
    /// provisioned for that AOR is attested A. A registered user presenting
    /// another owned number, an unbound port, or its own PAI gets no A.
    #[tokio::test]
    async fn sec001_registered_user_other_owned_number_not_a() {
        let mut q = qa_stir_stack_with(
            sbc_config::StirFailurePolicy::Mark,
            0,
            500,
            false,
            false,
            |c| c.stir_shaken.attestation.owned_numbers = vec!["+1202555*".into()],
        )
        .await;
        q.stack.config.require_auth = true;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
        for (aor, user) in [
            ("sip:+12025550100@sbc.local", "+12025550100"),
            ("sip:bob@sbc.local", "bob"),
        ] {
            q.stack
                .location_service
                .write()
                .await
                .add_binding(proto_registrar::Binding::new(
                    aor,
                    format!("sip:{user}@198.51.100.7:5060;transport=tcp"),
                    "reg@test",
                    1,
                ))
                .unwrap();
            q.stack
                .index_stir_flow(aor, src, AddrTransport::Tcp, Some(*TEST_CONN))
                .await;
        }
        q.stack.add_did_mapping("+12025550142", "bob").await;

        // Own AOR number: A.
        let (a, orig) =
            forwarded_attest(&send(&q.stack, "sec1-own@test", src, "+12025550100", None).await);
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
        assert_eq!(orig.as_deref(), Some("12025550100"));

        // Another owned number from the same registered endpoint: never A
        // (the number is not asserted or signed at all).
        let r = send(&q.stack, "sec1-other@test", src, "+12025550199", None).await;
        let (a, orig) = forwarded_attest(&r);
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));
        assert_ne!(orig.as_deref(), Some("12025550199"));
        if let Some((b, _)) = forwarded(&r, &Method::Invite) {
            assert!(
                b.headers
                    .get_all(&HeaderName::PAssertedIdentity)
                    .all(|h| !h.value.contains("12025550199"))
            );
        }

        // Endpoint-supplied PAI is ignored: orig stays the AOR's number.
        let (a, orig) = forwarded_attest(
            &send(
                &q.stack,
                "sec1-pai@test",
                src,
                "+12025550100",
                Some("<sip:+12025550199@sbc.local;user=phone>"),
            )
            .await,
        );
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
        assert_eq!(orig.as_deref(), Some("12025550100"));

        // Same IP, different port: not bound to the registration, no A.
        let other_port = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5070);
        let (a, _) = forwarded_attest(
            &send(&q.stack, "sec1-port@test", other_port, "+12025550100", None).await,
        );
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));

        // Extension AOR: the DID provisioned for it is asserted and A.
        let (a, orig) = forwarded_attest(&send(&q.stack, "sec1-ext@test", src, "bob", None).await);
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
        assert_eq!(orig.as_deref(), Some("12025550142"));

        // Bound over TCP, INVITE over UDP from the same address: a different
        // flow, so unbound.
        let (a, _) = forwarded_attest(
            &send_on(
                &q.stack,
                "sec1-flow@test",
                src,
                "+12025550100",
                None,
                AddrTransport::Udp,
            )
            .await,
        );
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));

        // REGISTER auth off: nobody is "authenticated", so no A.
        q.stack.config.require_auth = false;
        let (a, _) =
            forwarded_attest(&send(&q.stack, "sec1-noauth@test", src, "+12025550100", None).await);
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));
    }

    /// SEC-008/SEC-009: the binding comes from the flow index, re-checked
    /// against the live location binding. A location binding the index never
    /// saw, or an index entry whose binding is gone, is unbound; a UDP-bound
    /// caller is authenticated (its own TN is asserted) but capped at B.
    #[tokio::test]
    async fn sec009_udp_flow_capped_at_b_and_index_rechecked() {
        let mut q = qa_stir_stack_with(
            sbc_config::StirFailurePolicy::Mark,
            0,
            500,
            false,
            false,
            |c| c.stir_shaken.attestation.owned_numbers = vec!["+1202555*".into()],
        )
        .await;
        q.stack.config.require_auth = true;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 8), 5060);
        let aor = "sip:+12025550100@sbc.local";
        let contact = "sip:+12025550100@198.51.100.8:5060;transport=udp";
        q.stack
            .location_service
            .write()
            .await
            .add_binding(proto_registrar::Binding::new(aor, contact, "reg@test", 1))
            .unwrap();

        // In the location service but never indexed (no REGISTER seen on
        // this flow): unbound, so not signed with this number.
        let udp = |id: &'static str| {
            let stack = &q.stack;
            async move { send_on(stack, id, src, "+12025550100", None, AddrTransport::Udp).await }
        };
        let (a, _) = forwarded_attest(&udp("sec9-unindexed@test").await);
        assert_eq!(a, None);

        // Indexed UDP flow: B with the caller's own TN, never A.
        q.stack
            .index_stir_flow(aor, src, AddrTransport::Udp, None)
            .await;
        let (a, orig) = forwarded_attest(&udp("sec9-udp@test").await);
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Partial));
        assert_eq!(orig.as_deref(), Some("12025550100"));

        // The binding is removed (expiry, API delete): the stale index entry
        // is not trusted.
        q.stack.delete_registration(aor, contact).await.unwrap();
        let (a, _) = forwarded_attest(&udp("sec9-stale@test").await);
        assert_eq!(a, None);
    }

    /// Item 2: with a cluster `AsyncLocationService` attached the REGISTER
    /// path still writes the in-process `location_service` and the flow
    /// index, so the STIR binding sees cluster-mode registrations (signing
    /// is not silently disabled).
    #[cfg(feature = "cluster")]
    #[tokio::test]
    async fn stir_binding_sees_registrations_with_async_location_service() {
        let storage = Arc::new(
            uc_storage::StorageManager::new(uc_storage::StorageConfig::in_memory())
                .await
                .unwrap(),
        );
        let stack = SipStack::new_with_location_service(
            SipStackConfig::default(),
            Arc::new(AsyncLocationService::new(storage)),
        );
        assert!(stack.has_async_location_service());
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 10), 40_001);
        let reg = Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/TLS {src};branch=z9hG4bK-c1\r\n\
             From: <sip:+12025550100@sbc.local>;tag=r\r\n\
             To: <sip:+12025550100@sbc.local>\r\n\
             Call-ID: reg-cluster@test\r\n\
             CSeq: 1 REGISTER\r\n\
             Contact: <sip:+12025550100@10.0.0.6:5061;transport=tls>\r\n\
             Expires: 300\r\n\
             Content-Length: 0\r\n\r\n"
        ));
        let conn = Some(crate::stir_binding::ConnId::next());
        let _ = stack
            .process_message_conn(&reg, src, None, AddrTransport::Tls, conn)
            .await;
        assert_eq!(
            stack
                .stir_endpoint_binding(src, AddrTransport::Tls, conn, "sip:+12025550100@sbc.local")
                .await,
            Some(Some("+12025550100".to_owned()))
        );
    }

    /// Item 2 / SEC-008: a real REGISTER (UDP and TCP) feeds the STIR flow
    /// index from the received source and transport, on the same
    /// `location_service` the binding check reads; de-registration removes
    /// it.
    #[tokio::test]
    async fn register_indexes_received_flow() {
        let stack = SipStack::new(SipStackConfig::default());
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 9), 40_000);
        let reg = |expires: u32| {
            Bytes::from(format!(
                "REGISTER sip:sbc.local SIP/2.0\r\n\
                 Via: SIP/2.0/TCP {src};branch=z9hG4bK-r{expires}\r\n\
                 From: <sip:alice@sbc.local>;tag=r\r\n\
                 To: <sip:alice@sbc.local>\r\n\
                 Call-ID: reg-flow@test\r\n\
                 CSeq: {} REGISTER\r\n\
                 Contact: <sip:alice@10.0.0.5:5060;transport=tcp>\r\n\
                 Expires: {expires}\r\n\
                 Content-Length: 0\r\n\r\n",
                if expires == 0 { 2 } else { 1 }
            ))
        };
        let conn = Some(crate::stir_binding::ConnId::next());
        let _ = stack
            .process_message_conn(&reg(300), src, None, AddrTransport::Tcp, conn)
            .await;
        let key = crate::stir_binding::flow_key(src.ip(), src.port(), AddrTransport::Tcp);
        assert_eq!(
            stack.stir_flows.read().await.get(&key, conn),
            Some(&["sip:alice@sbc.local".to_owned()][..])
        );
        // The declared (private) Contact is not the flow: the latched
        // binding is the received source, which the check accepts.
        assert!(SipStack::flow_has_binding(
            &*stack.location_service.read().await,
            "sip:alice@sbc.local",
            &key
        ));
        let other = crate::stir_binding::flow_key(src.ip(), src.port(), AddrTransport::Udp);
        assert!(stack.stir_flows.read().await.get(&other, None).is_none());
        let _ = stack
            .process_message_conn(&reg(0), src, None, AddrTransport::Tcp, conn)
            .await;
        assert!(stack.stir_flows.read().await.get(&key, conn).is_none());
    }

    /// REGISTER over TLS from `src` on connection `conn` (connection-binding tests).
    async fn poam36_register(
        stack: &SipStack,
        src: SbcSocketAddr,
        conn: Option<crate::stir_binding::ConnId>,
        transport: AddrTransport,
    ) {
        let t = if transport == AddrTransport::Udp {
            "udp"
        } else {
            "tls"
        };
        let reg = Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/{} {src};branch=z9hG4bK-p36-{}\r\n\
             From: <sip:+12025550100@sbc.local>;tag=r\r\n\
             To: <sip:+12025550100@sbc.local>\r\n\
             Call-ID: reg-p36-{}@test\r\n\
             CSeq: 1 REGISTER\r\n\
             Contact: <sip:+12025550100@10.0.0.7:5061;transport={t}>\r\n\
             Expires: 300\r\n\
             Content-Length: 0\r\n\r\n",
            t.to_ascii_uppercase(),
            conn.map_or(0, |_| 1),
            src.port(),
        ));
        let _ = stack
            .process_message_conn(&reg, src, None, transport, conn)
            .await;
    }

    /// A signing stack with REGISTER auth required (digest itself is not
    /// exercised: the registrar accepts the test REGISTER as is).
    async fn poam36_stack() -> QaStir {
        let mut q = qa_stir_stack_with(
            sbc_config::StirFailurePolicy::Mark,
            0,
            500,
            false,
            false,
            |c| c.stir_shaken.attestation.owned_numbers = vec!["+1202555*".into()],
        )
        .await;
        q.stack.config.require_auth = true;
        q
    }

    /// Connection binding (a): a new TLS connection on the same CGNAT address does
    /// not inherit attestation A, whether or not the old one closed.
    #[tokio::test]
    async fn poam36_new_connection_same_address_not_a() {
        use crate::stir_binding::ConnId;
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 20), 40_100);
        let (c1, c2) = (Some(ConnId::next()), Some(ConnId::next()));
        poam36_register(&q.stack, src, c1, AddrTransport::Tls).await;
        let from = "sip:+12025550100@sbc.local";
        // c1 still open, c2 reuses the address: unauthenticated.
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tls, c2, from)
                .await,
            None
        );
        let (a, _) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-open@test",
                src,
                "+12025550100",
                AddrTransport::Tls,
                c2,
                None,
            )
            .await,
        );
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));
        // c1 closes, c2 still has not registered: unauthenticated.
        if let Some(c) = c1 {
            q.stack.connection_closed(c).await;
        }
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tls, c2, from)
                .await,
            None
        );
        let (a, _) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-closed@test",
                src,
                "+12025550100",
                AddrTransport::Tls,
                c2,
                None,
            )
            .await,
        );
        assert_ne!(a, Some(proto_stir_shaken::Attestation::Full));
    }

    /// Connection binding (b): REGISTER and INVITE on the same connection attest A.
    #[tokio::test]
    async fn poam36_same_connection_attests_a() {
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 21), 40_101);
        let c1 = Some(crate::stir_binding::ConnId::next());
        poam36_register(&q.stack, src, c1, AddrTransport::Tls).await;
        let (a, orig) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-same@test",
                src,
                "+12025550100",
                AddrTransport::Tls,
                c1,
                None,
            )
            .await,
        );
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
        assert_eq!(orig.as_deref(), Some("12025550100"));
    }

    /// Connection binding (c): closing the connection drops its flow entry.
    #[tokio::test]
    async fn poam36_entry_removed_on_close() {
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 22), 40_102);
        let c1 = crate::stir_binding::ConnId::next();
        poam36_register(&q.stack, src, Some(c1), AddrTransport::Tls).await;
        assert_eq!(q.stack.stir_flows.read().await.len(), 1);
        q.stack.connection_closed(c1).await;
        assert_eq!(q.stack.stir_flows.read().await.len(), 0);
    }

    /// Connection binding (d): UDP keeps address matching (no connection id) and
    /// stays capped at B.
    #[tokio::test]
    async fn poam36_udp_unchanged() {
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 23), 40_103);
        poam36_register(&q.stack, src, None, AddrTransport::Udp).await;
        let (a, orig) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-udp@test",
                src,
                "+12025550100",
                AddrTransport::Udp,
                None,
                None,
            )
            .await,
        );
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Partial));
        assert_eq!(orig.as_deref(), Some("12025550100"));
    }

    /// QA: REGISTER from `src` on `conn` with an explicit CSeq/Expires (refresh,
    /// de-register) over TCP or TLS.
    async fn poam36_register_ex(
        stack: &SipStack,
        src: SbcSocketAddr,
        conn: Option<crate::stir_binding::ConnId>,
        transport: AddrTransport,
        cseq: u32,
        expires: u32,
    ) {
        let t = if transport == AddrTransport::Tcp {
            "tcp"
        } else {
            "tls"
        };
        let reg = Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/{} {src};branch=z9hG4bK-p36x-{cseq}-{}\r\n\
             From: <sip:+12025550100@sbc.local>;tag=r\r\n\
             To: <sip:+12025550100@sbc.local>\r\n\
             Call-ID: reg-p36x-{}@test\r\n\
             CSeq: {cseq} REGISTER\r\n\
             Contact: <sip:+12025550100@10.0.0.7:5061;transport={t}>\r\n\
             Expires: {expires}\r\n\
             Content-Length: 0\r\n\r\n",
            t.to_ascii_uppercase(),
            src.port(),
            src.port(),
        ));
        let _ = stack
            .process_message_conn(&reg, src, None, transport, conn)
            .await;
    }

    /// QA (POA&M-36): a REGISTER refresh on the same connection keeps one entry
    /// and attestation A.
    #[tokio::test]
    async fn poam36_qa_refresh_same_conn_keeps_a() {
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 30), 40_130);
        let c1 = Some(crate::stir_binding::ConnId::next());
        poam36_register_ex(&q.stack, src, c1, AddrTransport::Tls, 1, 300).await;
        poam36_register_ex(&q.stack, src, c1, AddrTransport::Tls, 2, 300).await;
        assert_eq!(q.stack.stir_flows.read().await.len(), 1);
        let (a, _) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-refresh@test",
                src,
                "+12025550100",
                AddrTransport::Tls,
                c1,
                None,
            )
            .await,
        );
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
    }

    /// QA (POA&M-36): after de-REGISTER (Expires: 0) on the connection, an
    /// INVITE on that same connection is no longer bound (live recheck).
    #[tokio::test]
    async fn poam36_qa_deregister_drops_a() {
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 31), 40_131);
        let c1 = Some(crate::stir_binding::ConnId::next());
        poam36_register_ex(&q.stack, src, c1, AddrTransport::Tls, 1, 300).await;
        poam36_register_ex(&q.stack, src, c1, AddrTransport::Tls, 2, 0).await;
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tls, c1, "sip:+12025550100@sbc.local")
                .await,
            None
        );
    }

    /// QA (POA&M-36): the binding moves to a new connection on the same address;
    /// the old connection's late close does not remove it, and the old
    /// connection no longer matches.
    #[tokio::test]
    async fn poam36_qa_binding_moves_old_close_keeps_new() {
        use crate::stir_binding::ConnId;
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 32), 40_132);
        let (c1, c2) = (ConnId::next(), ConnId::next());
        let from = "sip:+12025550100@sbc.local";
        poam36_register_ex(&q.stack, src, Some(c1), AddrTransport::Tls, 1, 300).await;
        poam36_register_ex(&q.stack, src, Some(c2), AddrTransport::Tls, 2, 300).await;
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tls, Some(c1), from)
                .await,
            None
        );
        q.stack.connection_closed(c1).await;
        assert_eq!(q.stack.stir_flows.read().await.len(), 1);
        let (a, _) = forwarded_attest(
            &send_conn(
                &q.stack,
                "p36-moved@test",
                src,
                "+12025550100",
                AddrTransport::Tls,
                Some(c2),
                None,
            )
            .await,
        );
        assert_eq!(a, Some(proto_stir_shaken::Attestation::Full));
        q.stack.connection_closed(c2).await;
        assert_eq!(q.stack.stir_flows.read().await.len(), 0);
    }

    /// QA (POA&M-36): plain TCP behaves like TLS: same conn A, other conn not A.
    #[tokio::test]
    async fn poam36_qa_tcp_variant() {
        use crate::stir_binding::ConnId;
        let q = poam36_stack().await;
        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 33), 40_133);
        let (c1, c2) = (Some(ConnId::next()), Some(ConnId::next()));
        poam36_register_ex(&q.stack, src, c1, AddrTransport::Tcp, 1, 300).await;
        let from = "sip:+12025550100@sbc.local";
        assert!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tcp, c1, from)
                .await
                .is_some()
        );
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tcp, c2, from)
                .await,
            None
        );
        // TLS lookup on the same address does not match a TCP entry.
        assert_eq!(
            q.stack
                .stir_endpoint_binding(src, AddrTransport::Tls, c1, from)
                .await,
            None
        );
    }

    /// NIST-009: verification failures are audited once per (trunk, reason)
    /// per window with a count, and the remainder is flushed.
    #[tokio::test]
    async fn stir_verify_failure_audit_is_aggregated() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 500, false, false).await;
        let cap = uc_audit::capture::start();
        for i in 0..3 {
            let _ = q
                .stack
                .process_message(
                    &qa_invite(&format!("agg-{i}@test"), Some("garbage")),
                    alice(),
                    None,
                )
                .await;
        }
        let counts = |events: &[uc_audit::AuditEvent]| -> Vec<u64> {
            events
                .iter()
                .filter_map(|e| match e {
                    uc_audit::AuditEvent::StirVerifyFailure(f) => {
                        assert_eq!(f.source_trunk, "alice-trunk");
                        Some(f.count)
                    }
                    _ => None,
                })
                .collect()
        };
        assert_eq!(counts(&cap.events()), vec![1]);
        q.stack
            .stir()
            .unwrap()
            .flush_audit(std::time::Instant::now() + std::time::Duration::from_secs(11));
        assert_eq!(counts(&cap.events()), vec![1, 2]);
    }

    /// User decision (POA&M-33): on a sign=true trunk the caller's number
    /// from a trust-domain peer's PAI goes into the B-leg PAI, is signed as
    /// `orig`, and carries verstat; From stays the SBC URI.
    #[tokio::test]
    async fn qa_stir_caller_pai_propagated_and_signed() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Reject, 0, 1000, false, false).await;
        let id = qa_identity(&q.files, 0);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-pai@test", Some(&id)), alice(), None)
                .await,
        );
        let (b, dest) = forwarded(&results, &Method::Invite).expect("forwarded");
        assert_eq!(dest, t1());
        let pai = b.headers.get_value(&HeaderName::PAssertedIdentity).unwrap();
        assert!(pai.starts_with(&format!("<sip:{QA_ORIG}@")), "{pai}");
        assert!(pai.contains(";verstat=TN-Validation-Passed>"), "{pai}");
        let from = b.headers.get_value(&HeaderName::From).unwrap();
        assert!(!from.contains("verstat"), "{from}");
        assert!(!from.contains(QA_ORIG), "{from}");
        let ident = b.headers.get_value(&HeaderName::Identity).expect("signed");
        let p = proto_stir_shaken::Verifier::default()
            .prepare([ident])
            .unwrap()
            .unwrap();
        assert_eq!(p.passport.claims.orig.as_str(), "12025550100");
    }

    /// Failover between two sign=true trunks: the retry carries a valid
    /// Identity whose dest matches the retry's R-URI.
    #[tokio::test]
    async fn qa_stir_failover_to_signed_trunk_keeps_valid_identity() {
        let q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 500, true, true).await;
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-fo2@test", None), alice(), None)
                .await,
        );
        let (first, _) = forwarded(&results, &Method::Invite).expect("INVITE to t1");
        let first = first.clone();
        let results = flatten(
            q.stack
                .process_message(&response_to(&first, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&results, &Method::Invite).expect("failover");
        let id = retry
            .headers
            .get_value(&HeaderName::Identity)
            .expect("signed");
        let p = proto_stir_shaken::Verifier::default()
            .prepare([id])
            .unwrap()
            .unwrap();
        let ruri_user = retry.uri.user.as_deref().unwrap();
        assert_eq!(
            p.passport.claims.dest[0].as_str(),
            proto_stir_shaken::canonicalize_tn(ruri_user)
                .unwrap()
                .as_str()
        );
    }

    // ------------------------------------------------------------------
    // POA&M-5 (SC-8): every emitted message carries its leg's flow; the
    // failover INVITE is addressed and sent per the next trunk.
    // ------------------------------------------------------------------

    fn flow_of<'a>(results: &'a [ProcessResult], method: &Method) -> &'a LegFlow {
        results
            .iter()
            .find_map(|r| match r {
                ProcessResult::Forward {
                    message: SipMessage::Request(req),
                    flow: Flow::Leg(f),
                    ..
                } if req.method == *method => Some(f),
                _ => None,
            })
            .expect("forward with a resolved flow")
    }

    fn response_flow(results: &[ProcessResult], status: u16) -> LegFlow {
        results
            .iter()
            .find_map(|r| match r {
                ProcessResult::Response {
                    message: SipMessage::Response(resp),
                    flow: Flow::Leg(f),
                    ..
                } if resp.status.code() == status => Some(f.clone()),
                _ => None,
            })
            .expect("response with a resolved flow")
    }

    async fn client_invite_mode(stack: &SipStack, branch: &str) -> TransportType {
        stack
            .transactions
            .read()
            .await
            .client_invite
            .get(&TransactionKey::client(branch, "INVITE"))
            .expect("client INVITE txn")
            .transaction
            .transport()
    }

    // RFC 3261 §18.1.1, §26.2; NIST 800-53 Rev5: SC-8.
    #[tokio::test]
    async fn failover_udp_to_tls_trunk_uses_sips_ruri_tls_via_and_tls_flow() {
        let stack = trunk_stack_protos(["udp", "tls"]).await;
        let results = place_call(&stack, "u2t@test").await;
        let (first, dest) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        assert_eq!(dest, t1());
        assert_eq!(flow_of(&results, &Method::Invite), &LegFlow::UDP);
        assert_eq!(
            first.uri.to_string(),
            format!("sip:{DIALED}@127.0.0.2:5060")
        );
        assert!(
            first
                .headers
                .get_value(&HeaderName::Via)
                .unwrap()
                .starts_with("SIP/2.0/UDP ")
        );

        let out = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t1"), None), t1(), None)
                .await,
        );
        let (retry, dest) = forwarded(&out, &Method::Invite).expect("failover");
        assert_eq!(dest.port(), 5061);
        assert_eq!(
            retry.uri.to_string(),
            format!("sips:{DIALED}@127.0.0.3:5061")
        );
        let via = retry.headers.get_value(&HeaderName::Via).unwrap();
        assert!(via.starts_with("SIP/2.0/TLS sbc.local:5061;"), "{via}");
        let contact = retry.headers.get_value(&HeaderName::Contact).unwrap();
        assert!(contact.starts_with("<sips:"), "{contact}");
        let flow = flow_of(&out, &Method::Invite);
        assert_eq!(flow.transport, AddrTransport::Tls);
        assert_eq!(flow.dial.as_deref(), Some("127.0.0.3"));
        let branch = retry.headers.via_branch().unwrap();
        assert_eq!(
            client_invite_mode(&stack, &branch).await,
            TransportType::Reliable
        );
    }

    #[tokio::test]
    async fn failover_tls_to_udp_trunk_uses_sip_ruri_udp_via_and_unreliable_txn() {
        let stack = trunk_stack_protos(["tls", "udp"]).await;
        let results = place_call(&stack, "t2u@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        assert_eq!(
            first.uri.to_string(),
            format!("sips:{DIALED}@127.0.0.2:5061")
        );
        assert_eq!(
            flow_of(&results, &Method::Invite).transport,
            AddrTransport::Tls
        );
        // The TLS attempt fails to send (connect/handshake/verify): the next
        // trunk's own flow is used, never a downgrade of this attempt.
        let out = flatten(ProcessResult::Multiple(
            stack
                .on_invite_sent(&SipMessage::Request(first), false)
                .await,
        ));
        let (retry, dest) = forwarded(&out, &Method::Invite).expect("failover");
        assert_eq!(dest, t2());
        assert_eq!(
            retry.uri.to_string(),
            format!("sip:{DIALED}@127.0.0.3:5060")
        );
        assert!(retry.uri.transport().is_none());
        let via = retry.headers.get_value(&HeaderName::Via).unwrap();
        assert!(via.starts_with("SIP/2.0/UDP sbc.local:5060;"), "{via}");
        assert_eq!(flow_of(&out, &Method::Invite), &LegFlow::UDP);
        let branch = retry.headers.via_branch().unwrap();
        assert_eq!(
            client_invite_mode(&stack, &branch).await,
            TransportType::Unreliable
        );
    }

    #[tokio::test]
    async fn failover_to_tcp_trunk_adds_transport_param() {
        let stack = trunk_stack_protos(["udp", "tcp"]).await;
        let results = place_call(&stack, "u2tcp@test").await;
        let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t1"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&out, &Method::Invite).expect("failover");
        assert_eq!(retry.uri.transport(), Some("tcp"));
        assert!(
            retry
                .headers
                .get_value(&HeaderName::Via)
                .unwrap()
                .starts_with("SIP/2.0/TCP ")
        );
        assert_eq!(flow_of(&out, &Method::Invite).transport, AddrTransport::Tcp);
    }

    // NIST 800-53 Rev5: SC-8 — all TLS targets dead: 503 to the caller on
    // its own connection, no plaintext attempt.
    #[tokio::test]
    async fn tls_trunks_all_dead_gives_503_on_caller_flow_without_plaintext_retry() {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_call_on(&stack, "dead@test", AddrTransport::Tcp).await;
        let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let out = flatten(ProcessResult::Multiple(
            stack
                .on_invite_sent(&SipMessage::Request(first), false)
                .await,
        ));
        let retry = forwarded(&out, &Method::Invite).unwrap().0.clone();
        assert_eq!(flow_of(&out, &Method::Invite).transport, AddrTransport::Tls);
        let out = flatten(ProcessResult::Multiple(
            stack
                .on_invite_sent(&SipMessage::Request(retry), false)
                .await,
        ));
        assert!(forwarded(&out, &Method::Invite).is_none(), "{out:?}");
        assert_eq!(
            response_flow(&out, 503),
            LegFlow::inbound(AddrTransport::Tcp)
        );
    }

    // RFC 3261 §17.1.1.2, §18.2.2: Timer B's 408 goes to the caller on its
    // stream connection, not the UDP socket.
    #[tokio::test]
    async fn timer_b_408_on_tcp_call_rides_the_caller_connection() {
        let stack = trunk_stack_protos(["tcp", "tcp"]).await;
        let results = place_call_on(&stack, "tb-tcp@test", AddrTransport::Tcp).await;
        let first = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let internal = internal_id(&stack, "tb-tcp@test").await;
        let out = stack
            .fail_timed_out_request(&first.headers.via_branch().unwrap(), &internal)
            .await;
        // Timer B -> failover result carries the next trunk's flow.
        let retry = forwarded(&out, &Method::Invite).unwrap().0.clone();
        assert_eq!(flow_of(&out, &Method::Invite).transport, AddrTransport::Tcp);
        assert!(flow_of(&out, &Method::Invite).dial.is_some());
        let out = stack
            .fail_timed_out_request(&retry.headers.via_branch().unwrap(), &internal)
            .await;
        assert_eq!(
            response_flow(&out, 408),
            LegFlow::inbound(AddrTransport::Tcp)
        );
    }

    // RFC 3261 §17.2.1: Timer G re-sends ride the server txn's flow.
    #[tokio::test]
    async fn timer_g_retransmission_carries_the_udp_flow_and_bye_the_leg_flows() {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_call_on(&stack, "g@test", AddrTransport::Udp).await;
        let (b_invite, dest) = forwarded(&results, &Method::Invite).unwrap();
        let (b_invite, dest) = (b_invite.clone(), dest);
        stack
            .process_message_on(
                &response_to(&b_invite, 486, Some("t"), None),
                dest,
                None,
                AddrTransport::Tls,
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let results = stack.poll_timers().await;
        assert_eq!(response_flow(&results, 486), LegFlow::UDP);
    }

    #[tokio::test]
    async fn bye_from_tls_caller_goes_to_trunk_on_trunk_flow() {
        let stack = trunk_stack_protos(["tls", "udp"]).await;
        let results = place_call_on(&stack, "bye@test", AddrTransport::Tls).await;
        let (inv, dest) = forwarded(&results, &Method::Invite).unwrap();
        let inv = inv.clone();
        answer(&stack, &inv, dest).await;
        let internal = internal_id(&stack, "bye@test").await;
        let addrs = stack
            .call_correlation
            .read()
            .await
            .addresses
            .get(&internal)
            .cloned()
            .unwrap();
        // SBC-initiated teardown: each BYE on its own leg's flow and Via.
        let byes = stack
            .terminate_call_on_media_failure(&internal.to_string())
            .await;
        assert_eq!(byes.len(), 2);
        let mut seen = Vec::new();
        for r in &byes {
            let ProcessResult::Forward {
                message: SipMessage::Request(b),
                destination,
                flow: Flow::Leg(f),
            } = r
            else {
                panic!("BYE forward");
            };
            let via = b.headers.get_value(&HeaderName::Via).unwrap().to_string();
            seen.push((*destination, f.transport, via));
        }
        assert_eq!(seen[0].0, addrs.a_leg_source);
        assert_eq!(seen[0].1, AddrTransport::Tls);
        assert!(
            seen[0].2.starts_with("SIP/2.0/TLS sbc.local:5061"),
            "{}",
            seen[0].2
        );
        assert_eq!(seen[1].0, addrs.b_leg_destination);
        assert_eq!(seen[1].1, AddrTransport::Tls);
        assert!(seen[1].2.starts_with("SIP/2.0/TLS "), "{}", seen[1].2);
    }

    // Regression for the primary-path misroute: a TLS caller's INVITE to a
    // TLS trunk is addressed to the trunk with the trunk's flow (dial), not
    // the caller's connection.
    #[tokio::test]
    async fn primary_invite_from_tls_caller_targets_tls_trunk_flow() {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_call_on(&stack, "prim@test", AddrTransport::Tls).await;
        let (inv, dest) = forwarded(&results, &Method::Invite).unwrap();
        assert_eq!(dest.port(), 5061);
        assert_ne!(dest, alice());
        let f = flow_of(&results, &Method::Invite);
        assert_eq!(f.transport, AddrTransport::Tls);
        assert_eq!(
            f.dial.as_deref(),
            Some("127.0.0.2"),
            "dial the trunk, not the caller"
        );
        assert!(inv.uri.scheme.requires_tls());
        // The 100 Trying replies on the caller's own TLS connection.
        assert_eq!(
            response_flow(&results, 100),
            LegFlow::inbound(AddrTransport::Tls)
        );
    }

    #[test]
    fn retarget_helpers_keep_host_and_params() {
        let via = retarget_via(
            "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKold;rport",
            &LegFlow::trunk(uc_routing::TrunkProtocol::Tls, "h", false),
            5061,
            "z9hG4bKnew",
        );
        assert_eq!(via, "SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bKnew;rport");
        let via = retarget_via(
            "SIP/2.0/TLS [2001:db8::1]:5061;branch=b",
            &LegFlow::UDP,
            5060,
            "c",
        );
        assert_eq!(via, "SIP/2.0/UDP [2001:db8::1]:5060;branch=c");
        assert_eq!(
            retarget_contact(
                "<sip:10.0.0.1:5060>",
                &LegFlow::inbound(AddrTransport::Tls),
                5061
            ),
            "<sips:10.0.0.1:5061>"
        );
        assert_eq!(
            retarget_contact("<sips:10.0.0.1:5061>;expires=60", &LegFlow::UDP, 5060),
            "<sip:10.0.0.1:5060>;expires=60"
        );
        assert_eq!(split_sent_by("[::1]:5"), ("[::1]", Some(5)));
        assert_eq!(split_sent_by("::1"), ("::1", None));
    }

    // NIST 800-53 Rev5: SC-8, SI-10 — a registered contact's transport picks
    // only an accepted connection; never a dial.
    #[test]
    fn contact_flow_never_dials() {
        assert_eq!(contact_flow("sip:a@192.0.2.1:5060"), LegFlow::UDP);
        assert_eq!(
            contact_flow("sip:a@192.0.2.1:5061;transport=tls"),
            LegFlow::inbound(AddrTransport::Tls)
        );
        assert_eq!(
            contact_flow("sips:a@192.0.2.1:5061"),
            LegFlow::inbound(AddrTransport::Tls)
        );
        assert_eq!(
            contact_flow("sip:a@192.0.2.1;transport=TCP"),
            LegFlow::inbound(AddrTransport::Tcp)
        );
        assert!(contact_flow("sips:a@h;transport=tcp").dial.is_none());
        assert_eq!(contact_flow("garbage"), LegFlow::UDP);
    }

    // ---------------- Fix round 1 (SEC-002/-003, RFC-002, RFC-004) --------

    fn tls_phone() -> SbcSocketAddr {
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 0, 2, 10), 40_000)
    }

    /// REGISTER for carol whose Contact names no transport and whose Via
    /// claims UDP; it arrives on `transport` from [`tls_phone`].
    async fn register_carol(stack: &SipStack, transport: AddrTransport) {
        let register = Bytes::from_static(
            b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.0.2.10:5061;branch=z9hG4bK-carol\r\n\
            From: <sip:carol@sbc.local>;tag=c1\r\n\
            To: <sip:carol@sbc.local>\r\n\
            Call-ID: reg-carol@test\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:carol@192.0.2.10:5061>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\r\n",
        );
        let r = stack
            .process_message_on(&register, tls_phone(), None, transport)
            .await;
        assert!(
            matches!(&r, ProcessResult::Response { message: SipMessage::Response(resp), .. }
                if resp.status == StatusCode::OK),
            "{r:?}"
        );
    }

    async fn call_carol(stack: &SipStack, id: &str) -> Vec<ProcessResult> {
        // Source admission (AC-3): alice is a registered endpoint.
        let register = Bytes::from_static(
            b"REGISTER sip:sbc.local SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-alice\r\n\
            From: <sip:alice@example.com>;tag=a1\r\n\
            To: <sip:alice@example.com>\r\n\
            Call-ID: reg-alice@test\r\n\
            CSeq: 1 REGISTER\r\n\
            Contact: <sip:alice@192.168.1.1:5060>\r\n\
            Expires: 3600\r\n\
            Content-Length: 0\r\n\r\n",
        );
        stack
            .process_message_on(&register, alice(), None, AddrTransport::Udp)
            .await;
        flatten(
            stack
                .process_message_on(
                    &caller_request("INVITE", "carol", id, 1, None, Some(ALICE_SDP)),
                    alice(),
                    None,
                    AddrTransport::Udp,
                )
                .await,
        )
    }

    // SEC-002 (NIST 800-53 Rev5: SC-8): a phone registered over TLS is
    // reached only on its TLS connection (the REGISTER's observed transport
    // and source), whatever its Contact or Via says; never UDP.
    #[tokio::test]
    async fn tls_registered_binding_is_reached_on_its_tls_connection() {
        let stack = SipStack::new(SipStackConfig::default());
        register_carol(&stack, AddrTransport::Tls).await;
        {
            let loc = stack.location_service.read().await;
            let b = loc.lookup("sip:carol@sbc.local");
            assert_eq!(b.len(), 1);
            assert_eq!(b[0].source_transport(), Some("tls"));
            assert_eq!(
                b[0].source_addr(),
                Some(std::net::SocketAddr::from(tls_phone()))
            );
            assert!(
                b[0].contact_uri().ends_with(";transport=tls"),
                "{}",
                b[0].contact_uri()
            );
        }
        let results = call_carol(&stack, "sec2-tls@test").await;
        let (_, dest) = forwarded(&results, &Method::Invite).expect("INVITE to carol");
        assert_eq!(dest, tls_phone(), "the registering connection's peer");
        let flow = flow_of(&results, &Method::Invite);
        assert_eq!(flow, &LegFlow::inbound(AddrTransport::Tls));
        assert!(flow.dial.is_none(), "a registered user is never dialled");
    }

    // The same REGISTER over UDP stays UDP (no upgrade from the Contact).
    #[tokio::test]
    async fn udp_registered_binding_stays_udp() {
        let stack = SipStack::new(SipStackConfig::default());
        register_carol(&stack, AddrTransport::Udp).await;
        let results = call_carol(&stack, "sec2-udp@test").await;
        let (_, dest) = forwarded(&results, &Method::Invite).expect("INVITE to carol");
        assert_eq!(dest, tls_phone());
        assert_eq!(flow_of(&results, &Method::Invite), &LegFlow::UDP);
    }

    // SEC-003: a binding with a stream Contact but no recorded connection
    // (not learned from a REGISTER on that connection) is not used: it
    // could name another peer's accepted connection.
    #[tokio::test]
    async fn stream_binding_without_its_own_connection_is_not_routed() {
        let stack = SipStack::new(SipStackConfig::default());
        stack
            .location_service
            .write()
            .await
            .add_binding(proto_registrar::Binding::new(
                "sip:carol@sbc.local",
                "sip:carol@192.0.2.99:5061;transport=tls",
                "reg@test",
                1,
            ))
            .unwrap();
        let results = call_carol(&stack, "sec3@test").await;
        assert!(
            forwarded(&results, &Method::Invite).is_none(),
            "{results:?}"
        );
    }

    // SEC-008: a REGISTER latches only its own binding; another device's
    // wildcard Contact for the same AOR is not pinned to this source/flow
    // and stays unroutable.
    #[tokio::test]
    async fn register_does_not_latch_another_devices_wildcard_contact() {
        let stack = SipStack::new(SipStackConfig::default());
        let mut other = proto_registrar::Binding::new(
            "sip:carol@sbc.local",
            "sip:carol@0.0.0.0:5070",
            "other-device@test",
            1,
        );
        let _ = other.set_expires(3600);
        // Seeded in the registrar (the authoritative store synced from).
        stack
            .registrar
            .write()
            .await
            .registrar_mut()
            .location_mut()
            .add_binding(other)
            .unwrap();
        register_carol(&stack, AddrTransport::Tls).await;
        let loc = stack.location_service.read().await;
        let bindings: Vec<_> = loc.lookup("sip:carol@sbc.local").into_iter().collect();
        let other = bindings
            .iter()
            .find(|b| b.call_id() == "other-device@test")
            .expect("other device's binding kept");
        assert!(other.source_transport().is_none(), "{other:?}");
        assert!(other.source_addr().is_none(), "{other:?}");
        assert!(other.contact_uri().contains("0.0.0.0"), "{other:?}");
        assert_eq!(binding_target(other), None);
        let own = bindings
            .iter()
            .find(|b| b.call_id() == "reg-carol@test")
            .expect("own binding");
        assert_eq!(own.source_transport(), Some("tls"));
    }

    #[test]
    fn binding_target_prefers_recorded_flow() {
        let mut b = proto_registrar::Binding::new("sip:c@x", "sip:c@192.0.2.1:5060", "id", 1);
        assert_eq!(
            binding_target(&b),
            Some((
                LegFlow::UDP,
                SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 0, 2, 1), 5060)
            ))
        );
        b.set_source_addr(std::net::SocketAddr::from(tls_phone()));
        b.set_source_transport("tls");
        assert_eq!(
            binding_target(&b),
            Some((LegFlow::inbound(AddrTransport::Tls), tls_phone()))
        );
        b.set_source_transport("bogus");
        assert_eq!(binding_target(&b), None);
    }

    /// CANCELs call `id` from alice and returns the B-leg CANCEL.
    async fn cancel_call(stack: &SipStack, id: &str) -> SipRequest {
        let out = flatten(
            stack
                .process_message(
                    &caller_request("CANCEL", DIALED, id, 1, None, None),
                    alice(),
                    None,
                )
                .await,
        );
        forwarded(&out, &Method::Cancel)
            .expect("B-leg CANCEL")
            .0
            .clone()
    }

    // RFC-002 (RFC 3261 §9.1): the CANCEL Request-URI equals the INVITE's,
    // on the primary attempt and after a failover changed it.
    #[tokio::test]
    async fn cancel_request_uri_matches_the_current_invite() {
        let stack = trunk_stack_protos(["udp", "tls"]).await;
        let results = place_call(&stack, "rfc2-primary@test").await;
        let (invite, _) = forwarded(&results, &Method::Invite).unwrap();
        let invite = invite.clone();
        let cancel = cancel_call(&stack, "rfc2-primary@test").await;
        assert_eq!(cancel.uri, invite.uri);

        let results = place_call(&stack, "rfc2-failover@test").await;
        let (first, _) = forwarded(&results, &Method::Invite).unwrap();
        let first = first.clone();
        let out = flatten(
            stack
                .process_message(&response_to(&first, 503, Some("t1"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&out, &Method::Invite).expect("failover");
        let retry = retry.clone();
        assert_ne!(retry.uri, first.uri);
        let cancel = cancel_call(&stack, "rfc2-failover@test").await;
        assert_eq!(cancel.uri, retry.uri, "CANCEL follows the failover attempt");
        assert_eq!(
            cancel.uri.to_string(),
            format!("sips:{DIALED}@127.0.0.3:5061")
        );
        assert!(
            cancel
                .headers
                .get_value(&HeaderName::Via)
                .unwrap()
                .starts_with("SIP/2.0/TLS ")
        );
    }

    // RFC-004 (RFC 7118 §5): a WS leg advertises the WebSocket listener.
    #[test]
    fn ws_leg_advertises_ws_listener_port() {
        let stack = SipStack::new(SipStackConfig {
            udp_port: 5060,
            tcp_port: 5070,
            tls_port: 5071,
            ws_port: 8080,
            ..SipStackConfig::default()
        });
        assert_eq!(stack.signaling_port(AddrTransport::WebSocket), 8080);
        assert_eq!(stack.signaling_port(AddrTransport::Tcp), 5070);
        assert_eq!(stack.signaling_port(AddrTransport::Tls), 5071);
    }

    // PR 160: STIR re-sign still works when failing over to a TLS trunk.
    #[tokio::test]
    async fn stir_resign_survives_failover_to_tls_trunk() {
        let mut q = qa_stir_stack(sbc_config::StirFailurePolicy::Mark, 0, 500, true, false).await;
        let (r, d, g) = carrier_routing(10, ("none", ""), ["udp", "tls"]);
        q.stack.init_router_from_config(&r, &d, &g);
        let results = flatten(
            q.stack
                .process_message(&qa_invite("qa-tls@test", None), alice(), None)
                .await,
        );
        let first = forwarded(&results, &Method::Invite).expect("t1").0.clone();
        let first_id = first
            .headers
            .get_value(&HeaderName::Identity)
            .expect("signed")
            .to_owned();
        let out = flatten(
            q.stack
                .process_message(&response_to(&first, 503, Some("t1"), None), t1(), None)
                .await,
        );
        let (retry, _) = forwarded(&out, &Method::Invite).expect("failover");
        assert!(retry.uri.scheme.requires_tls());
        assert_eq!(flow_of(&out, &Method::Invite).transport, AddrTransport::Tls);
        let id = retry
            .headers
            .get_value(&HeaderName::Identity)
            .expect("re-signed");
        assert_ne!(id, first_id);
    }

    // ---------------- QA additions (POA&M-5) ----------------

    // RFC 3261 §9.1, §18.1.1: the CANCEL follows the INVITE's B-leg flow —
    // the TLS trunk connection — not the caller's connection or UDP.
    #[tokio::test]
    async fn qa_cancel_on_tls_trunk_b_leg_rides_trunk_flow() {
        for caller in [AddrTransport::Udp, AddrTransport::Tls, AddrTransport::Tcp] {
            let stack = trunk_stack_protos(["tls", "udp"]).await;
            let id = format!("qa-cancel-{caller:?}@test");
            let results = place_call_on(&stack, &id, caller).await;
            let (inv, inv_dest) = forwarded(&results, &Method::Invite).unwrap();
            let inv_branch = inv.headers.via_branch().unwrap();
            let out = flatten(
                stack
                    .process_message_on(
                        &caller_request("CANCEL", DIALED, &id, 1, None, None),
                        alice(),
                        None,
                        caller,
                    )
                    .await,
            );
            let (cancel, dest) = forwarded(&out, &Method::Cancel).expect("CANCEL relayed");
            assert_eq!(dest, inv_dest, "{caller:?}");
            assert_eq!(dest.port(), 5061);
            let f = flow_of(&out, &Method::Cancel);
            assert_eq!(f.transport, AddrTransport::Tls, "{caller:?}");
            assert_eq!(
                f.dial.as_deref(),
                Some("127.0.0.2"),
                "trunk conn, not caller"
            );
            assert!(cancel.uri.scheme.requires_tls(), "{}", cancel.uri);
            let via = cancel.headers.get_value(&HeaderName::Via).unwrap();
            assert!(via.starts_with("SIP/2.0/TLS sbc.local:5061;"), "{via}");
            // §9.1: CANCEL carries the INVITE's branch.
            assert_eq!(cancel.headers.via_branch().unwrap(), inv_branch);
            // 200 OK to the CANCEL goes to the caller on its own flow.
            assert_eq!(response_flow(&out, 200), LegFlow::inbound(caller));
        }
    }

    // RFC 3261 §13.2.2.4, §18.1.1: the SBC's ACK for a trunk's 2xx (and the
    // re-ACK for a retransmitted 2xx) goes on the trunk's stream flow with a
    // matching Via; the 200 goes to the caller on the caller's connection.
    #[tokio::test]
    async fn qa_ack_for_2xx_on_stream_trunk_rides_trunk_flow() {
        for (proto, t, via_pfx) in [
            ("tls", AddrTransport::Tls, "SIP/2.0/TLS sbc.local:5061;"),
            ("tcp", AddrTransport::Tcp, "SIP/2.0/TCP "),
        ] {
            let stack = trunk_stack_protos([proto, "udp"]).await;
            let id = format!("qa-ack-{proto}@test");
            let results = place_call_on(&stack, &id, AddrTransport::Tls).await;
            let (inv, dest) = forwarded(&results, &Method::Invite).unwrap();
            let inv = inv.clone();
            stack
                .process_message_on(&response_to(&inv, 180, Some("bobtag"), None), dest, None, t)
                .await;
            let ok = response_to(&inv, 200, Some("bobtag"), Some(BOB_SDP));
            let out = flatten(stack.process_message_on(&ok, dest, None, t).await);
            let (ack, ack_dest) = forwarded(&out, &Method::Ack).expect("ACK to trunk");
            assert_eq!(ack_dest, dest);
            let f = flow_of(&out, &Method::Ack);
            assert_eq!(f.transport, t, "{proto}");
            assert!(f.dial.is_some(), "{proto}: ACK on the dialled trunk conn");
            let via = ack.headers.get_value(&HeaderName::Via).unwrap();
            assert!(via.starts_with(via_pfx), "{proto}: {via}");
            if t == AddrTransport::Tls {
                assert!(ack.uri.scheme.requires_tls(), "{}", ack.uri);
            } else {
                assert_eq!(ack.uri.transport(), Some("tcp"));
            }
            assert_eq!(
                response_flow(&out, 200),
                LegFlow::inbound(AddrTransport::Tls),
                "{proto}: 200 to the TLS caller on its connection"
            );
            // Retransmitted 200: re-ACK on the same trunk flow.
            let out = flatten(stack.process_message_on(&ok, dest, None, t).await);
            assert!(forwarded(&out, &Method::Ack).is_some(), "{proto}: re-ACK");
            assert_eq!(flow_of(&out, &Method::Ack), f);
        }
    }

    // Trunk connection closed mid-call: the SBC's media-failure BYE toward
    // a TLS trunk still names the dialled trunk flow (so the flow table
    // re-dials with verification); toward a TCP caller it names the
    // accepted connection only (never dialled, never UDP).
    #[tokio::test]
    async fn qa_teardown_bye_flows_after_trunk_conn_loss() {
        let stack = trunk_stack_protos(["tls", "udp"]).await;
        let results = place_call_on(&stack, "qa-bye@test", AddrTransport::Tcp).await;
        let (inv, dest) = forwarded(&results, &Method::Invite).unwrap();
        let inv = inv.clone();
        answer(&stack, &inv, dest).await;
        let internal = internal_id(&stack, "qa-bye@test").await;
        let byes = stack
            .terminate_call_on_media_failure(&internal.to_string())
            .await;
        let flows: Vec<LegFlow> = byes
            .iter()
            .map(|r| match r {
                ProcessResult::Forward {
                    flow: Flow::Leg(f), ..
                } => f.clone(),
                other => panic!("BYE forward expected: {other:?}"),
            })
            .collect();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0], LegFlow::inbound(AddrTransport::Tcp));
        assert!(flows[0].dial.is_none(), "caller leg is never dialled");
        assert_eq!(flows[1].transport, AddrTransport::Tls);
        assert_eq!(flows[1].dial.as_deref(), Some("127.0.0.2"));
    }
}
