//! SBC server components with async I/O.
//!
//! This module contains the server components that handle SIP signaling
//! and media processing using async/await patterns.
//!
//! ## Rate Limiting
//!
//! The server integrates with `sbc-dos-protection` to provide:
//! - Per-IP rate limiting for SIP requests
//! - Automatic blocking of abusive sources
//! - Configurable thresholds from `sbc-config`

#[cfg(feature = "cluster")]
use crate::cluster::ClusterManager;
use crate::digest_credentials::DigestCredentialStore;
use crate::flow::{Flow, LegFlow};
use crate::flows::{FlowKey, FlowTable};
use crate::shutdown::ShutdownSignal;
use crate::sip_stack::{ProcessResult, SipStack, SipStackConfig};
use proto_registrar::BearerAuthenticator;
use proto_sip::{Method, SipMessage};
use sbc_config::SbcConfig;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uc_dos_protection::{RateLimitAction, RateLimiter, RateLimiterConfig, SweepEvent};
use uc_health::{HealthChecker, HealthCheckerConfig};
use uc_metrics::{MetricRegistry, SbcMetrics};
use uc_transport::Transport;
use uc_transport::listener::ListenerConfig;
use uc_transport::tcp::TcpListener;
use uc_transport::tls::TlsListener;
use uc_transport::udp::UdpTransport;
use uc_transport::websocket::{WebSocketListener, WebSocketListenerOptions};
use uc_types::address::{SbcSocketAddr, TransportType};

/// Records a rate-limit event on the audit trail (no-op when auditing is
/// off). Called for block/unblock state changes and for the per-interval
/// aggregates, never per packet.
///
/// `limit_name` values: `per_ip_rps`, `per_ip_blocked_drops`, `global_rps`
/// (source `0.0.0.0`), `overflow_rps` (source `::`), `per_ip_conn`,
/// `per_prefix_conn`, `per_prefix_accept_rate`, `per_prefix_handshake_busy`
/// (source = IPv6 aggregate prefix or IPv4 /24 network),
/// `listener_conn` / `total_conn` (source `0.0.0.0`), `framing`,
/// `per_ip_block:/<prefix>:<secs>s` (source = blocked prefix),
/// `per_ip_unblock`, `per_ip_rps_suppressed`.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12
fn audit_rate_limit(
    source_ip: std::net::IpAddr,
    limit_name: &str,
    request_count: u64,
    threshold: u64,
) {
    uc_audit::log_event(uc_audit::AuditEvent::RateLimitTriggered(
        uc_audit::event::RateLimitTriggered {
            source_ip,
            limit_name: limit_name.to_string(),
            request_count,
            threshold,
        },
    ));
}

/// Maps the configured `security.curve` to the curve TLS private keys must
/// be on.
///
/// ## NIST 800-53 Rev5: SC-12, SC-13 (CNSA 2.0 curve consistency)
pub const fn required_key_curve(
    curve: uc_types::protocol::CnsaCurve,
) -> uc_transport::tls::RequiredKeyCurve {
    match curve {
        uc_types::protocol::CnsaCurve::P384 => uc_transport::tls::RequiredKeyCurve::P384,
        uc_types::protocol::CnsaCurve::P521 => uc_transport::tls::RequiredKeyCurve::P521,
    }
}

/// Audit algorithm label for `security.curve`.
pub const fn key_algorithm(curve: uc_types::protocol::CnsaCurve) -> &'static str {
    match curve {
        uc_types::protocol::CnsaCurve::P384 => "ECDSA-P384",
        uc_types::protocol::CnsaCurve::P521 => "ECDSA-P521",
    }
}

/// Audit key id: a fixed role plus the key file name only (never the full
/// path, never file contents).
pub fn tls_key_id(role: &str, path: &std::path::Path) -> String {
    path.file_name().map_or_else(
        || role.to_string(),
        |n| format!("{role}:{}", n.to_string_lossy()),
    )
}

/// Records a TLS key operation (pass or fail) on the audit trail. The
/// failure reason is the loader's error text, which carries no key
/// material or path; `CryptoKeyOperation::failure` strips CR/LF and caps it.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, SC-12
pub fn audit_tls_key<T, E: std::fmt::Display>(
    key_id: String,
    operation: uc_audit::event::KeyOperationType,
    curve: uc_types::protocol::CnsaCurve,
    result: &Result<T, E>,
) {
    let algorithm = key_algorithm(curve);
    let event = match result {
        Ok(_) => uc_audit::event::CryptoKeyOperation::success(key_id, operation, algorithm),
        Err(e) => uc_audit::event::CryptoKeyOperation::failure(
            key_id,
            operation,
            algorithm,
            &e.to_string(),
        ),
    };
    uc_audit::log_event(uc_audit::AuditEvent::CryptoKeyOperation(event));
}

/// Loads a TLS private key that must be on `security.curve`, auditing the
/// outcome either way.
///
/// ## NIST 800-53 Rev5: SC-12, SC-13, AU-12
fn load_tls_key_audited(
    role: &str,
    path: &std::path::Path,
    curve: uc_types::protocol::CnsaCurve,
) -> uc_transport::TransportResult<rustls_pki_types::PrivateKeyDer<'static>> {
    let result = uc_transport::tls::load_private_key_with(path, required_key_curve(curve));
    audit_tls_key(
        tls_key_id(role, path),
        uc_audit::event::KeyOperationType::Loaded,
        curve,
        &result,
    );
    result
}

/// Zeroizes the serialized form of a message that carried key material (a
/// recording session INVITE holds SDES SRTP keys). A buffer that is still
/// shared cannot be wiped and is left to its other owner.
///
/// ## NIST 800-53 Rev5: SC-12, SI-12
fn wipe_wire_bytes(bytes: bytes::Bytes) {
    use zeroize::Zeroize;
    if let Ok(mut owned) = bytes.try_into_mut() {
        owned[..].zeroize();
    }
}

/// Stream connection deadlines from `[transport]`.
#[derive(Clone, Copy, Debug)]
struct StreamTimeouts {
    /// TLS / WebSocket handshake deadline.
    handshake: std::time::Duration,
    /// Deadline for the first accepted SIP message.
    first_message: std::time::Duration,
    /// Idle limit once a message has been accepted.
    idle: std::time::Duration,
}

impl StreamTimeouts {
    fn from_config(config: &SbcConfig) -> Self {
        Self {
            handshake: std::time::Duration::from_secs(config.transport.handshake_timeout_secs),
            first_message: std::time::Duration::from_secs(
                config.transport.first_message_timeout_secs,
            ),
            idle: std::time::Duration::from_secs(config.transport.tcp_idle_timeout_secs),
        }
    }

    /// Longest wait for a node-wide TLS handshake slot once the client has
    /// sent its first bytes: a quarter of the handshake deadline, at most
    /// 1 s. A connection that gets no slot in time is dropped and counted
    /// (`handshake_slot_timeouts`), so a full pool sheds load quickly
    /// instead of queueing clients up to the whole deadline.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    fn handshake_slot_wait(&self) -> std::time::Duration {
        (self.handshake / 4).min(std::time::Duration::from_secs(1))
    }

    /// Longest a TLS handshake may hold a node-wide slot once it has one:
    /// half the handshake deadline, at most 2 s. A client that sends one
    /// byte and stalls loses the slot after this and is dropped and
    /// counted (`handshake_slot_hold_timeouts`), so each slot turns over
    /// at least every 2 s whatever `handshake_timeout_secs` is. A real
    /// handshake takes a few round trips, well inside the budget.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    // POAM: POA&M-440 — the pool can still be kept full by about
    // slots / hold one-byte connections per second spread over at least
    // slots / per-source-cap sources (defaults on 2 cores: 2,500 slots,
    // 16 per source, 2 s hold: 1,250 conn/s from 157 sources) (SC-5).
    fn handshake_slot_hold(&self) -> std::time::Duration {
        (self.handshake / 2).min(std::time::Duration::from_secs(2))
    }
}

/// Resources one admitted stream connection holds for its whole life
/// (handshake and receive loop). All RAII: released on return, panic or
/// abort.
struct ConnAdmission {
    _source: crate::conn_limit::ConnGuard,
    _listener: tokio::sync::OwnedSemaphorePermit,
    _total: tokio::sync::OwnedSemaphorePermit,
}

/// Which transport family a per-source rate limiter serves.
///
/// NIST 800-53 Rev5: SC-5 — UDP and stream sources are limited separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimiterKind {
    /// UDP signaling (spoofable source addresses).
    Udp,
    /// TCP, TLS and WebSocket signaling (handshake-proven addresses).
    Stream,
}

/// Shared handles a stream (TCP/TLS) accept loop and its per-connection
/// receive loops need for their lifetime.
#[derive(Clone)]
struct StreamLoopContext {
    shutdown: ShutdownSignal,
    stats: Arc<ServerStats>,
    sip_stack: Arc<SipStack>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    global_limiter: Arc<Mutex<RateLimiter>>,
    rate_limit_enabled: bool,
    zone_name: Option<String>,
    /// This listener's connection pool (`max_connections_per_listener`).
    conn_semaphore: Arc<tokio::sync::Semaphore>,
    /// Node-wide connection ceiling (`max_connections_total`).
    total_conns: Arc<tokio::sync::Semaphore>,
    /// Per-source connection cap, shared by all stream listeners.
    conn_limiter: Arc<crate::conn_limit::ConnLimiter>,
    /// Node-wide TLS handshakes in progress
    /// (`transport.max_handshakes_in_flight`). A permit is taken only once
    /// the client has sent data and held only for the handshake, never
    /// for the receive loop. WebSocket upgrades do not use it (no crypto).
    handshake_slots: Arc<tokio::sync::Semaphore>,
    timeouts: StreamTimeouts,
    flows: Arc<FlowTable>,
}

/// Accept-loop back-off for `accept()` errors.
///
/// Resource exhaustion (fd table full, no buffer space, out of memory)
/// backs off, 10 ms doubling to 1 s, so a full fd table does not spin the
/// loop. A per-connection error (peer aborted or reset, EPROTO, EPERM, ...;
/// [`uc_transport::is_accept_per_connection_error`]) never backs off and
/// never counts: the loop accepts again at once, so peers that reset
/// before accept cannot stall the listener. Listener-level or unknown
/// errors (EBADF, EINVAL, ENOTSOCK, EOPNOTSUPP, EFAULT, ...) also continue
/// at once until [`Self::PERSISTENT`] of them arrive with no successful
/// accept (a broken listener socket, not one peer); then they back off
/// the same way.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[derive(Debug)]
struct AcceptBackoff {
    /// Delay for the next backed-off error.
    next: std::time::Duration,
    /// Listener-level or unknown errors since the last successful accept.
    consecutive: u32,
    /// Last back-off warning, for one `warn!` per second at most.
    last_warn: Option<std::time::Instant>,
}

impl AcceptBackoff {
    const INITIAL: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX: std::time::Duration = std::time::Duration::from_secs(1);
    const WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    /// Listener-level or unknown errors, with no successful accept, after
    /// which those errors back off too.
    const PERSISTENT: u32 = 64;

    const fn new() -> Self {
        Self {
            next: Self::INITIAL,
            consecutive: 0,
            last_warn: None,
        }
    }

    /// The delay to sleep before the next accept, or `None` to continue at
    /// once.
    fn on_error(&mut self, err: &uc_transport::TransportError) -> Option<std::time::Duration> {
        if err.is_per_connection_accept_error() {
            return None;
        }
        if !err.is_resource_exhausted() {
            self.consecutive = self.consecutive.saturating_add(1);
            if self.consecutive < Self::PERSISTENT {
                return None;
            }
        }
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(Self::MAX);
        Some(delay)
    }

    /// Resets the delay and the error run after a successful accept.
    const fn on_success(&mut self) {
        self.next = Self::INITIAL;
        self.consecutive = 0;
    }

    /// Whether a back-off warning may be logged now (AU-4: bounded log
    /// volume while the fd table stays full or the listener stays broken).
    fn should_warn(&mut self) -> bool {
        let now = std::time::Instant::now();
        if self
            .last_warn
            .is_some_and(|t| now.duration_since(t) < Self::WARN_INTERVAL)
        {
            return false;
        }
        self.last_warn = Some(now);
        true
    }
}

/// What an accept loop does after an `accept()` error.
enum AcceptNext {
    /// Accept again (after any back-off sleep).
    Continue,
    /// Shutdown or closed listener: end the loop.
    Stop,
}

/// Node-wide handshake slots for `transport.max_handshakes_in_flight`; 0
/// sizes it as `max(64 x cores, max_connections_total / 8)`, at most
/// `max_connections_total` (defaults: 2,500 slots up to 39 cores).
// POAM: POA&M-440 — handshake admission is per source plus this node-wide
// concurrency bound and the per-slot hold budget
// (`StreamTimeouts::handshake_slot_hold`); there is no node-wide accept or
// handshake rate, so a flood spread over many sources is bounded only by
// rate x sources and by this pool (SC-5).
fn handshake_slot_count(tc: &sbc_config::schema::TransportConfig) -> usize {
    let total = (tc.max_connections_total as usize).max(1);
    if tc.max_handshakes_in_flight > 0 {
        return (tc.max_handshakes_in_flight as usize).min(total);
    }
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    cores.saturating_mul(64).max(total / 8).max(64).min(total)
}

/// Effective TLS handshake limits derived from `[transport]` at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HandshakeLimits {
    /// Node-wide slots ([`handshake_slot_count`]).
    slots: usize,
    /// Per-source cap ([`handshakes_per_source`]).
    per_source: u32,
}

impl HandshakeLimits {
    fn from_config(tc: &sbc_config::schema::TransportConfig) -> Self {
        let slots = handshake_slot_count(tc);
        Self {
            slots,
            per_source: handshakes_per_source(tc, slots),
        }
    }

    /// Whether the effective limits differ from the configured values
    /// (an auto-sized pool, or a clamped per-source cap), so the startup
    /// log must state the values in force.
    ///
    /// ## NIST 800-53 Rev5: AU-3, CM-6
    fn differ_from(&self, tc: &sbc_config::schema::TransportConfig) -> bool {
        self.per_source != tc.max_handshakes_per_source
            || self.slots != tc.max_handshakes_in_flight as usize
    }
}

/// Effective per-source TLS handshake cap: `transport.max_handshakes_per_source`,
/// at most `max_connections_per_source` (a source cannot hold more
/// handshakes than connections) and at most 1/32 of the node-wide pool
/// (`slots`), so at least 32 sources are needed to fill it.
///
/// ## NIST 800-53 Rev5: SC-5
fn handshakes_per_source(tc: &sbc_config::schema::TransportConfig, slots: usize) -> u32 {
    let pool_share = u32::try_from(slots / 32).unwrap_or(u32::MAX).max(1);
    tc.max_handshakes_per_source
        .min(tc.max_connections_per_source)
        .min(pool_share)
        .max(1)
}

/// Handshakes in progress allowed per aggregate (IPv6 aggregate prefix or
/// IPv4 /24, SR-58): 1/8 of the node-wide pool (`slots`), at least 1, so
/// one aggregate cannot hold the whole pool.
///
/// ## NIST 800-53 Rev5: SC-5
fn aggregate_handshake_cap(slots: usize) -> u32 {
    u32::try_from(slots / 8).unwrap_or(u32::MAX).max(1)
}

/// Logs and audits a startup clamp of `key` from `configured` to
/// `effective`.
///
/// ## NIST 800-53 Rev5: CM-6, AU-12
fn note_startup_clamp(key: &str, configured: u32, effective: u32, reason: &str) {
    warn!(
        key,
        configured, effective, reason, "connection limit clamped at startup"
    );
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "startup".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Modified,
            description: format!("{key} clamped from {configured} to {effective} ({reason})"),
        },
    ));
}

/// How a TLS handshake under a node-wide slot ended.
enum SlottedHandshake<T> {
    /// The handshake ran; its result.
    Done(uc_transport::TransportResult<T>),
    /// No node-wide slot within [`StreamTimeouts::handshake_slot_wait`].
    SlotWaitExpired,
    /// The handshake held a slot for [`StreamTimeouts::handshake_slot_hold`]
    /// without finishing.
    HoldExpired,
}

/// Where the message that produced a result arrived: replies to that peer
/// go straight back on it without a flow-table lookup.
#[derive(Clone)]
enum Origin {
    /// Timer loop / media teardown: no triggering message.
    None,
    /// A UDP socket.
    Udp(Arc<UdpTransport>),
    /// A stream connection, its peer and its flow-table key.
    Stream {
        conn: Arc<dyn Transport>,
        peer: SbcSocketAddr,
        key: FlowKey,
    },
}

/// Everything `handle_result` needs to put a result on the wire.
#[derive(Clone)]
struct SendCtx {
    flows: Arc<FlowTable>,
    stats: Arc<ServerStats>,
    sip_stack: Arc<SipStack>,
    origin: Origin,
}

/// SBC server state.
pub struct Server {
    /// Configuration.
    config: SbcConfig,
    /// Shutdown signal.
    shutdown: ShutdownSignal,
    /// Health checker.
    health: HealthChecker,
    /// Metrics registry.
    metrics: MetricRegistry,
    /// Server statistics.
    stats: Arc<ServerStats>,
    /// UDP transports for SIP signaling.
    udp_transports: RwLock<Vec<Arc<UdpTransport>>>,
    /// TCP listeners for SIP signaling (`transport.tcp_listen`).
    tcp_listeners: RwLock<Vec<Arc<TcpListener>>>,
    /// TLS listeners for SIP signaling (`transport.tls_listen`).
    tls_listeners: RwLock<Vec<Arc<TlsListener>>>,
    /// WebSocket listeners for SIP signaling (`transport.ws_listen`, RFC 7118).
    ws_listeners: RwLock<Vec<Arc<WebSocketListener>>>,
    /// SIP stack for message processing.
    sip_stack: Arc<SipStack>,
    /// Live transports per flow (UDP sockets, accepted and egress stream
    /// connections). NIST 800-53 Rev5: SC-8.
    flows: Arc<FlowTable>,
    /// Per-source rate limiter for UDP signaling. Source addresses are
    /// spoofable, so by default it rejects but does not block
    /// (`rate_limit.udp_auto_block`).
    udp_rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Per-source rate limiter for stream (TCP/TLS/WS) signaling. Separate
    /// from the UDP one so a UDP-earned block never reaches a peer that
    /// completed a handshake. NIST 800-53 Rev5: SC-5.
    stream_rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Global (all-sources) rate limiter — backstop against distributed
    /// floods that stay under the per-IP limit.
    global_limiter: Arc<Mutex<RateLimiter>>,
    /// Resolved zone registry (None if no zones configured).
    zone_registry: Option<Arc<crate::zone::ResolvedZoneRegistry>>,
    /// Receiver for DTLS-SRTP media-failure signals (terminate mode). Drained by
    /// a task spawned in `start` that tears down each failed call. `take`n once.
    media_failure_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
    /// The remote media-plane node clients, when the media plane runs out of
    /// process (`SBC_MEDIA_CONTROLLER_URL[S]` set). One per node (a single node,
    /// or the pool). Held so `start` can drain EACH node's `WatchMediaEvents`
    /// stream — the out-of-process equivalent of [`Self::media_failure_rx`].
    /// Empty in the in-process (monolith) mode.
    #[cfg(feature = "grpc")]
    remote_media: Vec<sbc_media_core::grpc_media_controller::GrpcMediaController>,
    /// The media-node pool when more than one node is configured, so a node
    /// whose event stream drops is marked down at once (see `start`).
    #[cfg(feature = "grpc")]
    media_pool: Option<Arc<sbc_media_core::grpc_media_pool::MediaPool>>,
    /// Cluster manager (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<ClusterManager>>,
}

/// Maps `digest_auth.algorithm` to the verifier's algorithm. Only the two
/// non-session SHA-2 algorithms exist in the config type, so no MD5 or
/// `-sess` value can reach the verifier. `SHA-512-256` is FIPS 180-4
/// SHA-512/256 (RFC 7616 §3.2), not a truncated SHA-512.
///
/// CNSA-EXCEPTION: RFC 7616 defines no SHA-384 digest (POA&M-110). What is
/// enforced here is "no MD5, no `-sess`"; a CNSA TLS transport under the
/// exchange is not enforced (see [`digest_cleartext_transports`]).
///
/// ## NIST 800-53 Rev5: IA-5(1) (no weaker algorithm than configured),
/// SC-13; RFC 7616 §3.7, RFC 8760 §2.1
pub const fn digest_algorithm(a: sbc_config::DigestAuthAlgorithm) -> proto_sip::DigestAlgorithm {
    match a {
        sbc_config::DigestAuthAlgorithm::Sha256 => proto_sip::DigestAlgorithm::Sha256,
        sbc_config::DigestAuthAlgorithm::Sha512_256 => proto_sip::DigestAlgorithm::Sha512_256,
    }
}

/// Whether `SBC_AUTH_MODE` (`auth_mode`) selects RFC 8898 bearer REGISTER
/// authorization. The one definition of "bearer mode is active": the
/// runtime's digest/bearer conflict check and the bearer authorizer setup
/// both use it, so they cannot disagree about a value such as `" Bearer "`.
///
/// ## NIST 800-53 Rev5: IA-2, CM-6
pub fn bearer_mode_active(auth_mode: &str) -> bool {
    auth_mode.trim().eq_ignore_ascii_case("bearer")
}

/// The configured SIP listener transports that carry REGISTER in cleartext
/// (`udp`, `tcp`, `ws`) while digest authentication is required; empty
/// when digest is off or every SIP listener is TLS / WSS.
///
/// Digest over a cleartext transport exposes the username, the realm and a
/// response an eavesdropper can attack offline (RFC 7616 §5.10, §5.11), and
/// is outside the "protected by CNSA TLS" condition of the POA&M-110
/// exception.
///
/// POAM: POA&M-314 - digest over a cleartext transport is warned about at
/// startup, not refused.
///
/// ## NIST 800-53 Rev5: IA-5(1) (protected channel, not enforced), SC-8
pub fn digest_cleartext_transports(config: &SbcConfig) -> Vec<&'static str> {
    if !config.digest_auth.require_auth {
        return Vec::new();
    }
    let t = &config.transport;
    [
        ("udp", !t.udp_listen.is_empty()),
        ("tcp", !t.tcp_listen.is_empty()),
        ("ws", !t.ws_listen.is_empty()),
    ]
    .into_iter()
    .filter_map(|(name, configured)| configured.then_some(name))
    .collect()
}

impl Server {
    /// Creates a new server. `digest_credentials` is the `[digest_auth]`
    /// credential store the runtime loaded (`None` when digest is off).
    pub fn new(
        config: SbcConfig,
        shutdown: ShutdownSignal,
        digest_credentials: Option<Arc<DigestCredentialStore>>,
    ) -> Self {
        // Use standard SBC metrics
        let metrics = SbcMetrics::standard();

        let mut health = HealthChecker::new(HealthCheckerConfig::default())
            .with_version(env!("CARGO_PKG_VERSION"));

        // Register health checks
        health.register(Box::new(uc_health::check::AlwaysHealthyCheck::new(
            "sbc_core",
        )));
        health.register(Box::new(uc_health::check::MemoryCheck::new()));

        let sip_config = Self::build_sip_config(&config, digest_credentials);
        let mut sip_stack = SipStack::new(sip_config);
        let media_failure_rx = Self::init_sip_stack_from_config(&mut sip_stack, &config);
        Self::init_user_rate_limiter(&mut sip_stack, &config);
        if let Some(bearer) = Self::build_bearer_authenticator(&config) {
            sip_stack.set_bearer_authenticator(bearer);
        }
        Self::warn_if_register_unauthenticated(&sip_stack);
        Self::warn_if_digest_over_cleartext(&config);
        let sip_stack = Arc::new(sip_stack);
        let udp_rate_limiter = Self::build_rate_limiter(&config, LimiterKind::Udp);
        let stream_rate_limiter = Self::build_rate_limiter(&config, LimiterKind::Stream);
        let global_limiter = Self::build_global_limiter(&config);

        Self {
            config,
            shutdown,
            health,
            metrics,
            stats: Arc::new(ServerStats::default()),
            udp_transports: RwLock::new(Vec::new()),
            tcp_listeners: RwLock::new(Vec::new()),
            tls_listeners: RwLock::new(Vec::new()),
            ws_listeners: RwLock::new(Vec::new()),
            sip_stack,
            flows: Arc::new(FlowTable::new(crate::flows::DEFAULT_MAX_EGRESS_CONNECTIONS)),
            udp_rate_limiter,
            stream_rate_limiter,
            global_limiter,
            zone_registry: None,
            media_failure_rx,
            #[cfg(feature = "grpc")]
            remote_media: Vec::new(),
            #[cfg(feature = "grpc")]
            media_pool: None,
            #[cfg(feature = "cluster")]
            cluster: None,
        }
    }

    /// Sets the zone registry for interface-based binding.
    pub fn set_zone_registry(&mut self, registry: Arc<crate::zone::ResolvedZoneRegistry>) {
        self.zone_registry = Some(Arc::clone(&registry));
        // Also set on the SIP stack so it can use zone IPs for SDP/Contact headers
        if let Some(stack) = Arc::get_mut(&mut self.sip_stack) {
            stack.set_zone_registry(registry);
            tracing::info!("Zone registry set on SIP stack");
        } else {
            tracing::error!("Cannot set zone registry on SIP stack — Arc has multiple references");
        }
    }

    /// Attaches the CDR pipeline to the SIP stack. Must run while the stack
    /// `Arc` is still uniquely held (before `start`).
    ///
    /// ## NIST 800-53 Rev5: AU-12 (Audit Record Generation)
    pub fn set_cdr(&mut self, cdr: Arc<crate::cdr::CdrContext>) -> bool {
        Arc::get_mut(&mut self.sip_stack).map_or_else(
            || {
                tracing::error!(
                    "Cannot set CDR pipeline on SIP stack — Arc has multiple references"
                );
                false
            },
            |stack| {
                stack.set_cdr(cdr);
                true
            },
        )
    }

    /// Attaches the STIR/SHAKEN service to the SIP stack. Returns false when
    /// the stack is already shared.
    pub fn set_stir(&mut self, stir: Arc<crate::stir::StirService>) -> bool {
        Arc::get_mut(&mut self.sip_stack).map_or_else(
            || {
                tracing::error!(
                    "Cannot set STIR/SHAKEN on SIP stack — Arc has multiple references"
                );
                false
            },
            |stack| {
                stack.set_stir(stir);
                true
            },
        )
    }

    /// Determines which zone a transport belongs to based on its local bind address.
    fn zone_for_transport(&self, transport: &UdpTransport) -> Option<String> {
        self.zone_for_local_ip(transport.local_addr().ip())
    }

    /// Determines which zone a local bind IP belongs to.
    fn zone_for_local_ip(&self, local_ip: std::net::IpAddr) -> Option<String> {
        self.zone_registry
            .as_ref()
            .and_then(|registry| registry.zone_for_signaling_ip(local_ip))
    }

    /// Creates a new server with cluster support.
    #[cfg(feature = "cluster")]
    pub fn new_with_cluster(
        config: SbcConfig,
        shutdown: ShutdownSignal,
        cluster: Option<Arc<ClusterManager>>,
        digest_credentials: Option<Arc<DigestCredentialStore>>,
    ) -> Self {
        let metrics = SbcMetrics::standard();

        let mut health = HealthChecker::new(HealthCheckerConfig::default())
            .with_version(env!("CARGO_PKG_VERSION"));
        health.register(Box::new(uc_health::check::AlwaysHealthyCheck::new(
            "sbc_core",
        )));
        health.register(Box::new(uc_health::check::MemoryCheck::new()));

        let sip_config = Self::build_sip_config(&config, digest_credentials);
        let mut sip_stack = if let Some(ref cluster_mgr) = cluster {
            SipStack::new_with_location_service(
                sip_config,
                Arc::clone(cluster_mgr.location_service()),
            )
        } else {
            SipStack::new(sip_config)
        };
        let media_failure_rx = Self::init_sip_stack_from_config(&mut sip_stack, &config);
        Self::init_user_rate_limiter(&mut sip_stack, &config);
        if let Some(bearer) = Self::build_bearer_authenticator(&config) {
            sip_stack.set_bearer_authenticator(bearer);
        }
        Self::warn_if_register_unauthenticated(&sip_stack);
        Self::warn_if_digest_over_cleartext(&config);
        let sip_stack = Arc::new(sip_stack);

        let udp_rate_limiter = Self::build_rate_limiter(&config, LimiterKind::Udp);
        let stream_rate_limiter = Self::build_rate_limiter(&config, LimiterKind::Stream);
        let global_limiter = Self::build_global_limiter(&config);

        Self {
            config,
            shutdown,
            health,
            metrics,
            stats: Arc::new(ServerStats::default()),
            udp_transports: RwLock::new(Vec::new()),
            tcp_listeners: RwLock::new(Vec::new()),
            tls_listeners: RwLock::new(Vec::new()),
            ws_listeners: RwLock::new(Vec::new()),
            sip_stack,
            flows: Arc::new(FlowTable::new(crate::flows::DEFAULT_MAX_EGRESS_CONNECTIONS)),
            udp_rate_limiter,
            stream_rate_limiter,
            global_limiter,
            zone_registry: None,
            media_failure_rx,
            #[cfg(feature = "grpc")]
            remote_media: Vec::new(),
            #[cfg(feature = "grpc")]
            media_pool: None,
            cluster,
        }
    }

    /// Builds `SipStackConfig` from `SbcConfig`. `digest_credentials` is
    /// the store loaded from `digest_auth.credentials_file`.
    fn build_sip_config(
        config: &SbcConfig,
        digest_credentials: Option<Arc<DigestCredentialStore>>,
    ) -> SipStackConfig {
        if config
            .vps
            .as_ref()
            .is_some_and(|v| v.emergency_numbers.is_empty())
        {
            // 47 CFR 9.16: with no list, emergency calls get no capacity reserve.
            warn!(
                "vps.emergency_numbers is empty: emergency calls are subject to every call limit"
            );
        }
        // NIST 800-53 Rev5: SC-8, CM-6 — plaintext storage transport passed
        // validation only via `allow_insecure_transport`; make it visible.
        #[cfg(feature = "cluster")]
        match sbc_config::validate::storage_insecure_transport(config) {
            Ok(Some(backend)) => {
                warn!(
                    event = "storage.insecure_transport_allowed",
                    backend,
                    "storage allow_insecure_transport is set: registrar state crosses the network without server-authenticated TLS"
                );
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    event = "storage.insecure_transport_check_failed",
                    error = %e,
                    "could not evaluate storage transport security"
                );
            }
        }
        #[cfg(feature = "cluster")]
        if config.cluster.as_ref().is_some_and(|c| {
            c.admission.split == sbc_config::schema::AdmissionSplit::Divide
                && c.admission.expected_nodes == 1
        }) {
            // CM-6 / CP-2(2): divide by 1 is per-node; likely a missed resize.
            warn!(
                "cluster.admission split = \"divide\" with expected_nodes = 1: caps are not divided"
            );
        }
        let divisor = config.admission_divisor();
        if divisor > 1 {
            // CP-2(2): a remainder is capacity no node can use.
            if !config.general.max_calls.is_multiple_of(divisor)
                || !config.general.max_registrations.is_multiple_of(divisor)
                || config
                    .trunk_groups
                    .iter()
                    .flat_map(|g| &g.trunks)
                    .any(|t| !t.max_calls.is_multiple_of(divisor))
            {
                warn!(
                    expected_nodes = divisor,
                    "cluster.admission divide: general or trunk caps are not multiples of expected_nodes; the remainder is unused"
                );
            }
            info!(
                expected_nodes = divisor,
                max_calls = config.effective_max_calls(),
                max_registrations = config.effective_max_registrations(),
                "cluster.admission divide: enforcing this node's share of cluster caps"
            );
        }
        SipStackConfig {
            instance_name: config.general.instance_name.clone(),
            domain: config.general.instance_name.clone(),
            // NIST 800-53 Rev5: SC-5 — `cluster.admission.split = "divide"`
            // enforces this node's share of the cluster-wide caps. The
            // emergency reserve is per node and undivided (47 CFR 9.16).
            max_calls: config.effective_max_calls(),
            emergency_reserve_calls: config.general.effective_emergency_reserve_calls(),
            max_registrations: config.effective_max_registrations(),
            admission_divisor: config.admission_divisor(),
            emergency_numbers: uc_vps::EmergencyNumbers::new(
                &config
                    .vps
                    .as_ref()
                    .map_or_else(uc_vps::default_emergency_numbers, |v| {
                        v.emergency_numbers.clone()
                    }),
            ),
            trunk_retry_after_max_secs: config.general.trunk_retry_after_max_secs,
            // RFC 3261 §18.1.1: Via sent-by / Contact name the listener of
            // the transport a request goes out on. No default port is
            // invented for a stream transport without a listener (RFC-001):
            // 0 means "none", and is never advertised because validation
            // rejects a trunk of that transport and no accepted or
            // registered flow of it can exist.
            udp_port: config
                .transport
                .udp_listen
                .first()
                .map_or(5060, std::net::SocketAddr::port),
            tcp_port: config
                .transport
                .tcp_listen
                .first()
                .map_or(0, std::net::SocketAddr::port),
            tls_port: config
                .transport
                .tls_listen
                .first()
                .map_or(0, std::net::SocketAddr::port),
            ws_port: config
                .transport
                .ws_listen
                .first()
                .map_or(0, std::net::SocketAddr::port),
            // NIST 800-53 Rev5: AU-4, AU-5 — the signaling audit aggregation
            // window shares the rate-limit audit interval (1..=3600 s).
            signaling_audit_window_secs: config.rate_limit.audit_interval_secs,
            // NIST 800-53 Rev5: IA-2, IA-5, CM-6 - `[digest_auth]`
            // (POA&M-270). RFC 7616 §3.7: the server picks the algorithm.
            require_auth: config.digest_auth.require_auth,
            auth_realm: config
                .digest_auth
                .realm
                .clone()
                .unwrap_or_else(|| SipStackConfig::default().auth_realm),
            digest_algorithm: digest_algorithm(config.digest_auth.algorithm()),
            digest_nonce_ttl_secs: config.digest_auth.nonce_ttl_secs(),
            digest_credentials,
            ..SipStackConfig::default()
        }
    }

    /// Logs a prominent warning when nothing authenticates REGISTER: in that
    /// state any peer can bind any address-of-record and receive its calls.
    fn warn_if_register_unauthenticated(sip_stack: &SipStack) {
        if !sip_stack.register_auth_enabled() {
            warn!(
                "REGISTER is UNAUTHENTICATED: any peer can register any user. \
                 Set [digest_auth] require_auth = true (with realm and credentials_file) \
                 to require digest, or SBC_AUTH_MODE=bearer (with SBC_OIDC_ISSUER) to \
                 require tokens."
            );
        }
    }

    /// Warns when digest REGISTER authentication is required and a SIP
    /// listener is not TLS (SEC-004 / NIST-002).
    ///
    /// POAM: POA&M-314 - warned, not refused.
    ///
    /// ## NIST 800-53 Rev5: IA-5(1), SC-8, CM-6
    fn warn_if_digest_over_cleartext(config: &SbcConfig) {
        let cleartext = digest_cleartext_transports(config);
        if !cleartext.is_empty() {
            warn!(
                transports = %cleartext.join(","),
                "[digest_auth] require_auth = true with cleartext SIP listeners: digest \
                 REGISTER on these transports exposes usernames and responses that can \
                 be attacked offline, and is outside the CNSA 2.0 exception for SIP \
                 digest. Use TLS (transport.tls_listen / wss_listen) only."
            );
        }
    }

    /// Builds the RFC 8898 Bearer-token REGISTER authorizer from environment,
    /// or `None` when bearer auth is not enabled (`SBC_AUTH_MODE` ≠ `bearer`).
    ///
    /// Mirrors `sbc-client-config-server`'s OIDC config: the JWKS is fetched
    /// over a rustls client that optionally trusts an extra CA (the internal
    /// IdP). The JWKS cache lazy-loads on the first REGISTER, so no async
    /// work is needed here.
    fn build_bearer_authenticator(config: &SbcConfig) -> Option<Arc<BearerAuthenticator>> {
        let mode = std::env::var("SBC_AUTH_MODE").unwrap_or_default();
        if !bearer_mode_active(&mode) {
            return None;
        }

        let issuer = match std::env::var("SBC_OIDC_ISSUER") {
            Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
            _ => {
                error!("SBC_AUTH_MODE=bearer but SBC_OIDC_ISSUER is unset — bearer auth disabled");
                return None;
            }
        };

        let audiences: Vec<String> = std::env::var("SBC_OIDC_AUDIENCE")
            .unwrap_or_else(|_| "sbc".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if audiences.is_empty() {
            error!("SBC_OIDC_AUDIENCE resolved to an empty set — bearer auth disabled");
            return None;
        }

        let realm = std::env::var("SBC_OIDC_REALM")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| config.general.instance_name.clone());

        let mut http_builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10));
        if let Ok(path) = std::env::var("SBC_OIDC_EXTRA_CA_CERT_FILE")
            && !path.trim().is_empty()
        {
            match std::fs::read(&path) {
                Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                    Ok(cert) => {
                        info!(path, "loaded extra CA certificate for IdP JWKS fetch");
                        http_builder = http_builder.add_root_certificate(cert);
                    }
                    Err(e) => {
                        error!(path, error = %e, "failed to parse SBC_OIDC_EXTRA_CA_CERT_FILE — bearer auth disabled");
                        return None;
                    }
                },
                Err(e) => {
                    error!(path, error = %e, "failed to read SBC_OIDC_EXTRA_CA_CERT_FILE — bearer auth disabled");
                    return None;
                }
            }
        }

        let http = match http_builder.build() {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to build IdP HTTP client — bearer auth disabled");
                return None;
            }
        };

        let jwks = Arc::new(proto_jwt::JwksCache::new(http, issuer.clone()));
        let validator = Arc::new(proto_jwt::Validator::new(
            jwks,
            proto_jwt::ValidatorConfig::new(issuer.clone(), audiences.clone()),
        ));
        info!(
            %issuer,
            ?audiences,
            %realm,
            "RFC 8898 Bearer-token REGISTER authorization enabled"
        );
        Some(Arc::new(BearerAuthenticator::new(validator, realm)))
    }

    /// Installs the per-user limiter (`rate_limit.per_user_rps`) on the SIP
    /// stack. It runs after parsing, keyed by the From user, so one identity
    /// cannot exhaust the per-IP allowance shared with other users behind
    /// the same NAT. `0` disables it.
    fn init_user_rate_limiter(sip_stack: &mut SipStack, config: &SbcConfig) {
        if !config.rate_limit.enabled || config.rate_limit.per_user_rps == 0 {
            return;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let burst = (f64::from(config.rate_limit.per_user_rps)
            * f64::from(config.rate_limit.burst_multiplier)) as u32;
        sip_stack.set_user_rate_limiter(uc_dos_protection::KeyedRateLimiter::new(
            config.rate_limit.per_user_rps,
            burst.max(1),
        ));
        info!(
            per_user_rps = config.rate_limit.per_user_rps,
            "Per-user rate limiting configured"
        );
    }

    /// Builds a per-source rate limiter from config. The UDP limiter blocks
    /// only with `rate_limit.udp_auto_block`; both give configured trunk
    /// addresses (see [`Self::apply_trusted_sources`]) their own
    /// `trunk_rps` bucket.
    fn build_rate_limiter(config: &SbcConfig, kind: LimiterKind) -> Arc<Mutex<RateLimiter>> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let burst_size = (f64::from(config.rate_limit.per_ip_rps)
            * f64::from(config.rate_limit.burst_multiplier)) as u32;
        let rl = &config.rate_limit;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let overflow_burst =
            (f64::from(rl.effective_overflow_rps()) * f64::from(rl.burst_multiplier)) as u32;
        // NIST 800-53 Rev5: SC-5 — keyed per /prefix, bounded maps, and an
        // overflow share for new sources instead of a hard reject.
        let rate_limit_config = RateLimiterConfig::new(rl.per_ip_rps, burst_size)
            .with_per_ip(true)
            .with_block_duration(rl.block_duration_secs)
            .with_ipv6_prefix_len(rl.ipv6_prefix_len)
            .with_max_tracked_sources(rl.max_tracked_sources as usize)
            .with_max_blocked_sources(rl.max_blocked_sources as usize)
            .with_overflow(rl.effective_overflow_rps(), overflow_burst.max(1));
        // NIST 800-53 Rev5: SC-5 — spoofable UDP sources are rejected, not
        // blocked, unless the operator opts in.
        let auto_block = match kind {
            LimiterKind::Udp => rl.udp_auto_block,
            LimiterKind::Stream => true,
        };
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let trunk_burst =
            (f64::from(rl.effective_trunk_rps()) * f64::from(rl.burst_multiplier)) as u32;
        // NIST 800-53 Rev5: SC-5, SC-5(2) — configured trunks get their own
        // bucket and are rejected over it, never auto-blocked.
        // POAM: POA&M-448 — spoofed UDP carrying a trunk's exact address can
        // still exhaust that trunk's bucket (reject only), and is admitted
        // at up to `trunk_rps` per trunk address instead of `per_ip_rps`,
        // bounded only by `global_rps`; edge uRPF/ACL or TLS trunks are
        // needed for full protection (SC-5).
        let rate_limit_config = rate_limit_config
            .with_auto_block(auto_block)
            .with_trusted_bucket(rl.effective_trunk_rps(), trunk_burst.max(1));

        info!(
            limiter = ?kind,
            auto_block,
            trunk_rps = rl.effective_trunk_rps(),
            enabled = config.rate_limit.enabled,
            per_ip_rps = config.rate_limit.per_ip_rps,
            global_rps = config.rate_limit.global_rps,
            burst_multiplier = config.rate_limit.burst_multiplier,
            "Rate limiting configured"
        );

        Arc::new(Mutex::new(RateLimiter::new(rate_limit_config)))
    }

    /// Applies the configured trunk address set (sorted and capped at
    /// [`uc_dos_protection::MAX_TRUSTED_SOURCES`] by the SIP stack) as
    /// trusted sources to both per-source limiters, one lock at a time.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    // POAM: POA&M-449 — registered endpoints and NAT addresses are not
    // trusted; a stream-earned block on their prefix still applies (SC-5).
    // POAM: POA&M-450 — the set holds addresses resolved when the trunk
    // group was loaded; a hostname trunk whose DNS changes is not
    // re-trusted until the group is re-synced. An address configured in
    // two trunk groups is held for the group that registered it last;
    // removing that group untrusts it while the other group still lists
    // it, until that group is re-synced (see POA&M-392) (SC-5, CM-3).
    async fn apply_trusted_sources(
        set: &[std::net::IpAddr],
        udp: &Mutex<RateLimiter>,
        stream: &Mutex<RateLimiter>,
    ) {
        let _ = udp.lock().await.set_trusted_sources(set.iter().copied());
        let _ = stream.lock().await.set_trusted_sources(set.iter().copied());
    }

    /// Re-applies the trunk address set to both limiters, and to the
    /// stream connection limiter's aggregate exemption (SR-58), on every
    /// change published by the SIP stack. Updates coalesce; the newest set
    /// wins.
    async fn trusted_source_sync(
        mut rx: tokio::sync::watch::Receiver<Arc<[std::net::IpAddr]>>,
        udp: Arc<Mutex<RateLimiter>>,
        stream: Arc<Mutex<RateLimiter>>,
        conns: Arc<crate::conn_limit::ConnLimiter>,
    ) {
        while rx.changed().await.is_ok() {
            // Clone the Arc so the watch borrow is released before locking.
            let set = Arc::clone(&rx.borrow_and_update());
            Self::apply_trusted_sources(&set, &udp, &stream).await;
            // SR-58: trunks skip the aggregate connection caps.
            let _ = conns.set_trusted_sources(set.iter().copied());
            debug!(trusted = set.len(), "Trusted rate-limit sources updated");
        }
    }

    /// Builds the global (all-sources) rate limiter from config.
    fn build_global_limiter(config: &SbcConfig) -> Arc<Mutex<RateLimiter>> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let burst_size = (f64::from(config.rate_limit.global_rps)
            * f64::from(config.rate_limit.burst_multiplier)) as u32;
        let rate_limit_config =
            RateLimiterConfig::new(config.rate_limit.global_rps, burst_size).with_per_ip(false);

        Arc::new(Mutex::new(RateLimiter::new(rate_limit_config)))
    }

    /// Initializes SipStack routing, manipulation, and topology hiding from config.
    fn init_sip_stack_from_config(
        sip_stack: &mut SipStack,
        config: &SbcConfig,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
        // NIST 800-53 Rev5: SC-8 — global TLS-only trunk policy (POA&M-48),
        // set before any router is built so every group inherits it.
        sip_stack.set_require_tls_trunks(config.security.require_tls_trunks);
        // NIST 800-53 Rev5: SC-8, SI-4 — lets the API/TrunkSync path flag a
        // TLS trunk that cannot connect (no trust anchors configured).
        sip_stack.set_trunk_tls_ca_configured(config.security.trunk_tls_ca_path.is_some());

        // CM-6: non-fatal routing/trust-domain configuration problems.
        for w in sbc_config::validate::routing_warnings(config) {
            warn!(event = "config.routing_warning", "{w}");
        }

        // NIST 800-53 Rev5: CM-6, CM-7 - `[media.t38]` fax relay policy
        // (fail-closed default; enforced per offer in the SIP stack).
        sip_stack.set_t38_config(config.media.t38.clone());
        // NIST 800-53 Rev5: SC-8, CM-6 - media.srtp.required on call legs.
        sip_stack.set_media_security_policy(&config.media.srtp);
        for w in sbc_config::validate::t38_warnings(config) {
            warn!(event = "config.t38_warning", "{w}");
        }
        // NIST 800-53 Rev5: CM-6, AU-14 - non-fatal `[recording]` problems
        // (e.g. SRTP passthrough: only cleartext-RTP calls can be recorded).
        // The settings themselves are attached in `start` (they need the
        // SRS address and CA; see `wire_recording`).
        for w in sbc_config::validate::recording_warnings(config) {
            warn!(event = "config.recording_warning", "{w}");
        }

        // Initialize router from config (if routing section present)
        if let Some(ref routing) = config.routing {
            sip_stack.init_router_from_config(routing, &config.dial_plans, &config.trunk_groups);
        } else if !config.dial_plans.is_empty() || !config.trunk_groups.is_empty() {
            // Dial plans or trunk groups defined but no [routing] section — use defaults
            let default_routing = sbc_config::RoutingConfig::default();
            sip_stack.init_router_from_config(
                &default_routing,
                &config.dial_plans,
                &config.trunk_groups,
            );
        }

        // Initialize header manipulation (if configured)
        if let Some(ref manip) = config.header_manipulation {
            sip_stack.init_manipulator_from_config(manip);
        }

        // Initialize topology hiding (if configured)
        if let Some(ref topo) = config.topology_hiding {
            // CM-6/SC-7: an invalid entry leaves the hider unset and
            // `start` refuses to run (fail closed, never warn-and-skip).
            if let Err(e) = sip_stack.init_topology_hider_from_config(topo) {
                error!(error = %e, "Invalid topology hiding config");
            }
        }

        // Media plane. When SBC_MEDIA_CONTROLLER_URL is set (grpc builds), the
        // media plane runs out of process: `wire_remote_media` connects the gRPC
        // controller (and fetches the fingerprint for SDP) before `start`, so the
        // in-process pipeline is skipped here and there is no in-process
        // media-failure channel — the gRPC WatchMediaEvents stream replaces it.
        // In the monolith (default) the in-process pipeline is attached below;
        // without it, allocated RTP ports are not backed by any socket (media
        // black-holes).
        let media_failure_rx = if Self::remote_media_urls().is_empty() {
            // Ports / mode / SRTP come from the [media] config; the codec list and
            // RTCP-mux keep the pipeline defaults. `validate_config` only admits
            // `media.default_mode = Relay`, an empty `media.realm_modes` and the
            // default `media.codecs` set: the live call path always anchors
            // media and nothing filters SDP codecs (CM-6), so other values would
            // be silently ignored.
            //
            // The config's mode is uc_types::MediaMode; the pipeline uses
            // uc_media_engine::MediaMode. The non-Relay arms below are
            // unreachable for a validated config and kept for exhaustiveness.
            let default_mode = match config.media.default_mode {
                uc_types::MediaMode::Relay => uc_media_engine::MediaMode::Relay,
                uc_types::MediaMode::PassThrough | uc_types::MediaMode::SignalingOnly => {
                    uc_media_engine::MediaMode::PassThrough
                }
            };
            // Terminate mode: build ONE DTLS fingerprint source shared by the SDP
            // advertisement (SipStack) and the sidecar-verify path (pipeline), so
            // both always reflect the same identity. A file-backed source re-reads
            // on demand, letting the daemon self-heal after a sidecar restart
            // instead of advertising a fingerprint cached once at startup (which
            // every handshake would then reject until the pod restarts).
            let terminate_dtls = config.media.srtp.mode == sbc_config::SrtpMode::Terminate;
            // Fail closed: the daemon terminates DTLS *only* via the sidecar (there
            // is no in-Rust handshake path), so both the socket and the sidecar-
            // published fingerprint file are mandatory in terminate mode. Refuse to
            // start rather than advertise the SBC fingerprint and accept secured
            // calls it can never relay — that would black-hole every such call.
            if terminate_dtls
                && (config.media.dtls.sidecar_socket.is_none()
                    || config.media.dtls.fingerprint_file.is_none())
            {
                tracing::error!(
                    "srtp.mode = Terminate requires [media.dtls] sidecar_socket and fingerprint_file — aborting startup"
                );
                #[allow(clippy::panic)]
                {
                    panic!(
                        "DTLS-SRTP termination configured but sidecar_socket/fingerprint_file missing"
                    );
                }
            }
            let dtls_fingerprint = if terminate_dtls {
                Some(Arc::new(build_dtls_fingerprint_source(&config.media.dtls)))
            } else {
                None
            };
            // Media-failure teardown channel (terminate mode only): the pipeline
            // signals a call id here when a leg's DTLS handshake fails at runtime;
            // the server's drain task (spawned in `start`) tears that call down.
            let (media_failure_tx, media_failure_rx) = if terminate_dtls {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
            let media_config = sbc_media_core::media_pipeline::MediaPipelineConfig {
                default_mode,
                srtp_required: config.media.srtp.required,
                rtp_port_min: config.media.rtp_port_min,
                rtp_port_max: config.media.rtp_port_max,
                terminate_dtls,
                dtls_sidecar_socket: config.media.dtls.sidecar_socket.clone(),
                dtls_fingerprint: dtls_fingerprint.clone(),
                media_failure_tx,
                // SIPREC: the fork tap exists only when recording is enabled
                // (CM-7: no tap at all by default).
                recording: sbc_media_core::media_pipeline::RecordingMode::from_enabled(
                    config.recording.enabled,
                ),
                ..Default::default()
            };
            sip_stack.set_media_pipeline(Arc::new(
                sbc_media_core::media_pipeline::MediaPipeline::new(media_config),
            ));

            if let Some(source) = dtls_fingerprint {
                tracing::info!(
                    fingerprint = %source.current(),
                    "DTLS-SRTP termination enabled"
                );
                sip_stack.set_dtls_fingerprint_source(source);
            }
            media_failure_rx
        } else {
            tracing::info!(
                "Remote media plane configured (SBC_MEDIA_CONTROLLER_URL); \
                 in-process pipeline skipped — wired via gRPC before start"
            );
            None
        };

        // Initialize Voice Protection System call screening (if configured).
        // The config was validated at load time, so a build failure here is
        // unreachable in practice; refuse to start half-protected if it
        // happens anyway.
        if let Some(ref vps) = config.vps
            && vps.enabled
        {
            match uc_vps::VpsEngine::new(vps) {
                Ok(engine) => {
                    sip_stack.set_vps_engine(engine);
                    tracing::info!(
                        rules = vps.rules.len(),
                        per_source_cps = vps.tdos.per_source_cps,
                        stir_shaken_mode = ?vps.stir_shaken.mode,
                        "VPS call screening enabled"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "Invalid VPS configuration — aborting startup");
                    // Fail closed: running without the configured call
                    // screening is worse than not starting.
                    #[allow(clippy::panic)]
                    {
                        panic!("invalid VPS configuration: {e}");
                    }
                }
            }
        }

        media_failure_rx
    }

    /// Builds the stream connection limiter from `[transport]`: the
    /// per-source cap keyed on `rate_limit.ipv6_prefix_len`; the IPv6
    /// aggregate and IPv4 /24 caps (SR-58); the per-source and aggregate
    /// accept buckets and handshake caps (SR-56, SR-58). An aggregate
    /// prefix longer than the per-source prefix, or an aggregate cap above
    /// the listener pool, is clamped; each clamp is logged and audited as a
    /// startup `ConfigurationChange`.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, CM-6, AU-12
    pub(crate) fn build_conn_limiter(config: &SbcConfig) -> crate::conn_limit::ConnLimiter {
        let tc = &config.transport;
        let per_source_prefix = config.rate_limit.ipv6_prefix_len;
        let v6_prefix = tc.effective_v6_aggregate_prefix_len(per_source_prefix);
        let v6_cap = tc.effective_max_connections_per_v6_aggregate();
        let v4_cap = tc.effective_max_connections_per_v4_24();
        for (key, configured, effective, reason) in [
            (
                "transport.v6_aggregate_prefix_len",
                u32::from(tc.v6_aggregate_prefix_len),
                u32::from(v6_prefix),
                "longer than rate_limit.ipv6_prefix_len",
            ),
            (
                "transport.max_connections_per_v6_aggregate",
                tc.max_connections_per_v6_aggregate,
                v6_cap,
                "above max_connections_per_listener",
            ),
            (
                "transport.max_connections_per_v4_24",
                tc.max_connections_per_v4_24,
                v4_cap,
                "above max_connections_per_listener",
            ),
        ] {
            if configured != effective {
                note_startup_clamp(key, configured, effective, reason);
            }
        }

        // NIST 800-53 Rev5: SC-5 — per-source and aggregate accept buckets
        // and handshake caps. Accept buckets are tracked for at most
        // `max_connections_total` keys per map; the rest share an overflow
        // bucket of 4x the rate.
        // POAM: POA&M-441 — accept admission is keyed per source and per
        // aggregate only, statically and per node; a flood spread over many
        // aggregates gets one aggregate allowance each (SC-5).
        let limits = HandshakeLimits::from_config(tc);
        let slot_count = limits.slots;
        let per_source_handshakes = limits.per_source;
        // NIST 800-53 Rev5: AU-3, CM-6 — the values in force are logged
        // whenever they differ from the configured ones.
        if per_source_handshakes < tc.max_handshakes_per_source {
            warn!(
                configured = tc.max_handshakes_per_source,
                max_connections_per_source = tc.max_connections_per_source,
                handshake_slots = slot_count,
                effective = per_source_handshakes,
                "transport.max_handshakes_per_source clamped to \
                 min(max_connections_per_source, handshake slots / 32)"
            );
        }
        if limits.differ_from(tc) {
            info!(
                configured_in_flight = tc.max_handshakes_in_flight,
                handshake_slots = slot_count,
                configured_per_source = tc.max_handshakes_per_source,
                per_source = per_source_handshakes,
                per_aggregate = aggregate_handshake_cap(slot_count),
                "Effective TLS handshake limits"
            );
        }
        let accept_tracked =
            (config.rate_limit.max_tracked_sources as usize).min(tc.max_connections_total as usize);
        crate::conn_limit::ConnLimiter::new(tc.max_connections_per_source, per_source_prefix)
            .with_aggregate_caps(v6_prefix, v6_cap, v4_cap)
            .with_accept_rate(
                tc.accept_rate_per_source,
                tc.accept_burst_per_source,
                accept_tracked,
            )
            .with_handshake_cap(per_source_handshakes)
            .with_aggregate_handshake_cap(aggregate_handshake_cap(slot_count))
    }

    /// The out-of-process media plane node URLs, empty for the in-process
    /// (monolith) media plane. `SBC_MEDIA_CONTROLLER_URLS` is a comma-separated
    /// list (a standalone media-node POOL); `SBC_MEDIA_CONTROLLER_URL` is the
    /// single-node form (co-located split), honored when the list is unset. Only
    /// read in `grpc` builds. One URL → a single node; many → a load-balanced pool.
    #[cfg(feature = "grpc")]
    fn remote_media_urls() -> Vec<String> {
        let parse = |raw: String| -> Vec<String> {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        };
        if let Ok(list) = std::env::var("SBC_MEDIA_CONTROLLER_URLS") {
            let urls = parse(list);
            if !urls.is_empty() {
                return urls;
            }
        }
        std::env::var("SBC_MEDIA_CONTROLLER_URL")
            .ok()
            .map(parse)
            .unwrap_or_default()
    }

    #[cfg(not(feature = "grpc"))]
    fn remote_media_urls() -> Vec<String> {
        Vec::new()
    }

    /// Connects the out-of-process media plane, if configured. Called between
    /// construction and [`Self::start`], while the `sip_stack` `Arc` is still
    /// uniquely held (so [`Arc::get_mut`] succeeds — same window as
    /// [`Self::set_zone_registry`]).
    ///
    /// Connects every configured node (`SBC_MEDIA_CONTROLLER_URL[S]`) and attaches
    /// the media plane: a single node's
    /// [`GrpcMediaController`](sbc_media_core::grpc_media_controller::GrpcMediaController),
    /// or a load-balanced [`MediaPool`](sbc_media_core::grpc_media_pool::MediaPool)
    /// when there are several — both `dyn MediaController`, so the SIP stack is
    /// unchanged. Fetches the fingerprint to advertise in SDP (terminate mode).
    /// Every node client is retained so [`Self::start`] can drain each node's
    /// `WatchMediaEvents` stream. A no-op (and no requirement) in the in-process
    /// mode.
    ///
    /// # Errors
    /// Fail-closed: returns an error if the configured media plane cannot be
    /// reached, so signaling does not start pointing at a dead media plane.
    #[cfg(feature = "grpc")]
    pub async fn wire_remote_media(&mut self) -> Result<(), ServerError> {
        use sbc_media_core::dtls_identity::DtlsFingerprintSource;
        use sbc_media_core::grpc_media_controller::{
            GrpcMediaController, MediaControllerTls, check_media_url,
        };
        use sbc_media_core::grpc_media_pool::MediaPool;

        let urls = Self::remote_media_urls();
        if urls.is_empty() {
            return Ok(());
        }

        // Connect every configured node, retrying each: media and signaling are
        // commonly brought up together, so a node may not be listening yet.
        // Fail-closed after the deadline — a configured node that never comes up
        // must stop signaling rather than run with a hole in the pool.
        const CONNECT_ATTEMPTS: u32 = 30;
        const CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
        // NIST 800-53 Rev5: IA-3, SC-8 — client mTLS to the media nodes
        // (SBC_MEDIA_CONTROLLER_TLS_*); with it every URL must be https://.
        // A media node off loopback accepts only an mTLS client.
        let tls = MediaControllerTls::from_env()
            .map_err(|message| ServerError::ConfigError { message })?;
        for url in &urls {
            check_media_url(url, tls.as_ref())
                .map_err(|message| ServerError::ConfigError { message })?;
        }
        if tls.is_some() {
            info!("remote media control channel uses mTLS");
        }
        info!(nodes = urls.len(), "Connecting to remote media plane");
        let mut clients: Vec<GrpcMediaController> = Vec::with_capacity(urls.len());
        for url in &urls {
            let mut attempt = 1;
            let client = loop {
                match GrpcMediaController::connect_with_tls(url.clone(), tls.as_ref()).await {
                    Ok(client) => break client,
                    Err(e) if attempt < CONNECT_ATTEMPTS => {
                        warn!(url, attempt, error = %e, "media node not ready; retrying");
                        attempt += 1;
                        tokio::time::sleep(CONNECT_BACKOFF).await;
                    }
                    Err(e) => {
                        return Err(ServerError::ConfigError {
                            message: format!(
                                "media node {url} unreachable after {attempt} attempts: {e}"
                            ),
                        });
                    }
                }
            };
            clients.push(client);
        }

        // Fetch the fingerprint to advertise in SDP from the first node (present
        // on every node in terminate mode). NOTE: for a multi-node terminate pool
        // this is approximate — distinct per-node identities need per-session
        // advertisement (already plumbed via AllocatedPorts.dtls_fingerprint;
        // daemon-side per-session consumption is a follow-on). Plain-RTP pools
        // and single nodes are exact.
        let fingerprint = match clients[0].fetch_dtls_fingerprint().await {
            Ok(fp) => {
                info!(fingerprint = %fp, "Remote media plane DTLS-SRTP termination enabled");
                Some(Arc::new(DtlsFingerprintSource::from_static(fp)))
            }
            // NIST 800-53 Rev5: SC-8, SC-24 - with media.srtp.mode =
            // Terminate the SIP stack refuses new calls without an identity
            // (fail closed); the operator must see why.
            Err(e) if self.config.media.srtp.mode == sbc_config::SrtpMode::Terminate => {
                error!(reason = %e, "Remote media plane has no DTLS fingerprint but media.srtp.mode = Terminate; new calls will be refused");
                None
            }
            Err(e) => {
                info!(reason = %e, "Remote media plane has no DTLS fingerprint (non-terminate mode)");
                None
            }
        };

        // One node → drive it directly; many → a load-balanced pool. Both are
        // `dyn MediaController`, so the SIP stack is unchanged either way.
        let controller: Arc<dyn sbc_media_core::media_pipeline::MediaController> =
            if clients.len() == 1 {
                Arc::new(clients[0].clone())
            } else {
                info!(nodes = clients.len(), "Media-node pool active");
                // A node crashing takes its in-flight calls with it: the pool
                // emits those call ids here, and start()'s drain BYEs them so the
                // endpoints redial onto a healthy node. (New calls route away
                // automatically.) Reuses the in-process media-failure drain.
                let (failure_tx, failure_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                self.media_failure_rx = Some(failure_rx);
                let pool = Arc::new(MediaPool::new(clients.clone(), Some(failure_tx)).map_err(
                    |e| ServerError::ConfigError {
                        message: format!("failed to build media pool: {e}"),
                    },
                )?);
                self.media_pool = Some(Arc::clone(&pool));
                pool
            };

        let stack =
            Arc::get_mut(&mut self.sip_stack).ok_or_else(|| ServerError::InternalError {
                message: "cannot attach remote media: sip_stack Arc already shared".to_string(),
            })?;
        stack.set_media_pipeline(controller);
        if let Some(source) = fingerprint {
            stack.set_dtls_fingerprint_source(source);
        }
        // Retain every node client so `start` can drain each node's event stream.
        self.remote_media = clients;
        Ok(())
    }

    /// No-op in non-grpc builds (the media plane is always in-process).
    #[cfg(not(feature = "grpc"))]
    #[allow(clippy::unused_async, clippy::missing_const_for_fn)]
    pub async fn wire_remote_media(&mut self) -> Result<(), ServerError> {
        Ok(())
    }

    /// Returns the cluster manager if available.
    #[cfg(feature = "cluster")]
    pub fn cluster(&self) -> Option<&Arc<ClusterManager>> {
        self.cluster.as_ref()
    }

    /// Returns the server configuration.
    pub const fn config(&self) -> &SbcConfig {
        &self.config
    }

    /// Returns the health checker.
    pub const fn health(&mut self) -> &mut HealthChecker {
        &mut self.health
    }

    /// Returns the metrics registry.
    pub const fn metrics(&self) -> &MetricRegistry {
        &self.metrics
    }

    /// Returns server statistics.
    pub const fn stats(&self) -> &Arc<ServerStats> {
        &self.stats
    }

    /// Returns the egress flow table.
    pub const fn flows(&self) -> &Arc<FlowTable> {
        &self.flows
    }

    /// Returns the SIP stack.
    pub fn sip_stack(&self) -> &Arc<SipStack> {
        &self.sip_stack
    }

    /// Starts the server and binds to transport addresses.
    pub async fn start(&mut self) -> Result<(), ServerError> {
        // NIST 800-53 Rev5: CM-6, SC-7 - refuse to start with an internal
        // network/domain entry that does not parse, even when the config
        // bypassed `validate_config` (SEC-001/NIST-002).
        if let Some(ref topo) = self.config.topology_hiding {
            SipStack::topology_config_from(topo)
                .map_err(|message| ServerError::ConfigError { message })?;
        }
        // NIST 800-53 Rev5: CM-6, SC-24 - `[recording]` either works or the
        // daemon does not start (remote media plane, no TLS certificate,
        // unresolvable SRS, unloadable SRS CA).
        Box::pin(self.wire_recording()).await?;
        info!(
            version = env!("CARGO_PKG_VERSION"),
            instance = %self.config.general.instance_name,
            "Starting SBC daemon"
        );
        // AU-3: log the caps this node enforces (cluster share under divide).
        info!(
            max_calls = self.config.effective_max_calls(),
            max_registrations = self.config.effective_max_registrations(),
            configured_max_calls = self.config.general.max_calls,
            configured_max_registrations = self.config.general.max_registrations,
            admission_divisor = self.config.admission_divisor(),
            "Call limits configured (per-node enforced)"
        );
        info!(
            media_mode = ?self.config.media.default_mode,
            srtp_required = self.config.media.srtp.required,
            "Media settings configured"
        );

        // Bind UDP listeners
        self.bind_udp_listeners().await?;

        // Bind stream listeners (SIP over TCP / TLS / WebSocket)
        self.bind_tcp_listeners().await?;
        self.bind_tls_listeners().await?;
        self.bind_ws_listeners().await?;

        // DTLS-SRTP media-failure teardown: drain call ids whose handshake failed
        // at runtime and BYE both legs (fail-closed). Needs a bound UDP transport
        // to send from; the SBC binds a single wildcard listener, so any works.
        if let Some(udp) = self.udp_transports.read().await.first() {
            self.flows.set_default_udp(Arc::clone(udp));
        }
        self.load_trunk_tls_clients()?;

        // Each BYE goes out on its leg's flow (NIST 800-53 Rev5: SC-8).
        if let Some(mut rx) = self.media_failure_rx.take() {
            let ctx = self.send_ctx(Origin::None);
            tokio::spawn(async move {
                while let Some(call_id) = rx.recv().await {
                    for bye in ctx
                        .sip_stack
                        .terminate_call_on_media_failure(&call_id)
                        .await
                    {
                        Self::dispatch(bye, &ctx).await;
                    }
                }
            });
        }

        // Out-of-process equivalent of the mpsc drain above: subscribe to EACH
        // media node's WatchMediaEvents stream and BYE the calls it reports as
        // failed. Best-effort — if a stream drops (node restart), teardown of
        // that node's subsequently-failed calls stops until the daemon restarts;
        // that mirrors the in-process channel's best-effort semantics.
        #[cfg(feature = "grpc")]
        if !self.remote_media.is_empty() {
            for (node, controller) in self.remote_media.iter().cloned().enumerate() {
                let ctx = self.send_ctx(Origin::None);
                let pool = self.media_pool.clone();
                tokio::spawn(async move {
                    use sbc_grpc_api::sbc::media_event::Event;
                    // A dropped event stream means the node is gone (or
                    // restarting): mark it down at once so new calls
                    // route away instead of queuing on its channel for a
                    // connect timeout each (NIST 800-53 Rev5: SC-5, CP-10).
                    let mark_down = || async {
                        if let Some(pool) = &pool {
                            pool.mark_node_down(node).await;
                        }
                    };
                    let mut stream = match controller.watch_media_events().await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(node, error = %e, "failed to open media node event stream");
                            mark_down().await;
                            return;
                        }
                    };
                    loop {
                        match stream.message().await {
                            Ok(Some(event)) => {
                                let Some(Event::Failure(f)) = event.event else {
                                    continue;
                                };
                                for bye in ctx
                                    .sip_stack
                                    .terminate_call_on_media_failure(&f.call_id)
                                    .await
                                {
                                    Self::dispatch(bye, &ctx).await;
                                }
                            }
                            Ok(None) => {
                                warn!(node, "media node event stream closed");
                                mark_down().await;
                                break;
                            }
                            Err(e) => {
                                warn!(node, error = %e, "media node event stream error");
                                mark_down().await;
                                break;
                            }
                        }
                    }
                });
            }
        }

        // Seed the live-transport count at bind time (before the API server
        // starts serving readiness), so the readiness probe never sees a
        // spurious 0 during the window before run() spawns the loops.
        let bound = self.udp_transports.read().await.len()
            + self.tcp_listeners.read().await.len()
            + self.tls_listeners.read().await.len()
            + self.ws_listeners.read().await.len();
        self.stats
            .live_transports
            .store(bound as u64, Ordering::SeqCst);

        Ok(())
    }

    /// Startup rules for `[recording]` that depend on the environment, so
    /// `sbc-config` validation cannot check them. `remote_media` is the
    /// configured remote media node list (`SBC_MEDIA_CONTROLLER_URL[S]`).
    ///
    /// - Remote media nodes cannot fork to a recorder: the media control
    ///   channel would have to carry SRTP master keys, which it does not
    ///   (POA&M-301; the channel can be mTLS, `SBC_MEDIA_CONTROLLER_TLS_*`).
    ///   A recorder that can never record is a misconfiguration, so the
    ///   daemon refuses to start rather than fail every matched call.
    /// - The RS Via / Contact advertise the TLS listener, and the daemon
    ///   binds it only with `security.tls_cert_path` / `tls_key_path`.
    ///
    /// # Errors
    ///
    /// The startup error message.
    ///
    /// ## NIST 800-53 Rev5: CM-6, SC-8, SC-12, SC-24
    fn recording_startup_check(config: &SbcConfig, remote_media: &[String]) -> Result<(), String> {
        if !config.recording.enabled {
            return Ok(());
        }
        if !remote_media.is_empty() {
            return Err(
                "recording.enabled = true cannot be used with a remote media plane \
                 (SBC_MEDIA_CONTROLLER_URL / SBC_MEDIA_CONTROLLER_URLS): the media control \
                 channel cannot carry SRTP keys (POA&M-301)"
                    .to_string(),
            );
        }
        if config.transport.tls_listen.is_empty()
            || config.security.tls_cert_path.is_none()
            || config.security.tls_key_path.is_none()
        {
            return Err(
                "recording.enabled = true requires a SIP TLS listener with a certificate \
                 (transport.tls_listen, security.tls_cert_path, security.tls_key_path): the \
                 recording session advertises it in Via and Contact"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Resolves and attaches `[recording]` (SIPREC SRC, RFC 7866). A no-op
    /// when recording is off. Runs at the top of [`Self::start`], while the
    /// `sip_stack` `Arc` is still uniquely held.
    ///
    /// The SRS host is resolved once, here, and pinned (the section is
    /// restart-required); the signaling path never does DNS for it. The
    /// recorder TLS client profile trusts `recording.srs_tls_ca_file` only,
    /// offers TLS 1.3 only whatever `security.min_tls_version` says, and
    /// presents the SBC certificate if the SRS asks for one.
    ///
    /// # Errors
    ///
    /// Fail-closed: [`Self::recording_startup_check`] failures, an SRS host
    /// that does not resolve, an SRS CA or SBC certificate that does not
    /// load, or no usable local media address toward the SRS.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-8(1), SC-13, SC-23, IA-3, CM-6, SC-24
    // POAM: POA&M-304 - no RFC 3263 NAPTR/SRV for the SRS (one A/AAAA
    // lookup at startup); ML-KEM hybrid key exchange is not offered.
    async fn wire_recording(&mut self) -> Result<(), ServerError> {
        let refuse = |message: String| ServerError::ConfigError { message };
        Self::recording_startup_check(&self.config, &Self::remote_media_urls()).map_err(refuse)?;
        let rec = &self.config.recording;
        if !rec.enabled {
            return Ok(());
        }
        let sec = &self.config.security;
        let srs_uri = crate::recording::parse_srs_uri(rec.srs_uri.as_deref()).map_err(refuse)?;
        let host = crate::recording::bare_host(&srs_uri.host).to_string();
        let port = srs_uri.effective_port();
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|mut addrs| addrs.next());
        let Some(srs) = resolved else {
            return Err(refuse(format!(
                "recording.srs_uri host {host:?} does not resolve"
            )));
        };
        let srs_addr = SbcSocketAddr::from(srs);

        let ca_path = rec
            .srs_tls_ca_file
            .as_deref()
            .map(std::path::Path::new)
            .ok_or_else(|| refuse("recording.srs_tls_ca_file is not set".to_string()))?;
        let roots = uc_transport::tls::load_root_store(ca_path).map_err(|e| {
            refuse(format!(
                "recording.srs_tls_ca_file {}: {e}",
                ca_path.display()
            ))
        })?;
        // Q4: the SBC certificate is presented only if the SRS requests one.
        let client_auth = match (&sec.tls_cert_path, &sec.tls_key_path) {
            (Some(cert), Some(key)) => {
                let chain = uc_transport::tls::load_certs(cert)
                    .map_err(|e| refuse(format!("loading {}: {e}", cert.display())))?;
                // POA&M-166: key must be on security.curve; outcome audited.
                let key = load_tls_key_audited("recorder-tls-client", key, sec.curve)
                    .map_err(|e| refuse(format!("loading {}: {e}", key.display())))?;
                Some((chain, key))
            }
            _ => None,
        };
        let tls =
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots,
                // CNSA 2.0: TLS 1.3 only toward the recorder.
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_auth,
            })
            .map_err(|e| refuse(format!("building the recorder TLS client config: {e}")))?;

        // The fork's address when no zone media address applies: the SBC's
        // source address toward the SRS, from the kernel's route lookup (a
        // connected UDP socket sends nothing).
        let zone_media = rec
            .srs_zone
            .as_deref()
            .zip(self.zone_registry.as_ref())
            .and_then(|(zone, reg)| reg.media_ip(zone));
        let local_media_ip = {
            let wildcard: std::net::SocketAddr = if srs.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            };
            std::net::UdpSocket::bind(wildcard)
                .and_then(|sock| sock.connect(srs).and_then(|()| sock.local_addr()))
                .ok()
                .map(|a| a.ip())
                .filter(|ip| !ip.is_unspecified())
        };
        if zone_media.is_none() && local_media_ip.is_none() {
            return Err(refuse(format!(
                "recording: no local media address toward the SRS {srs_addr} \
                 (no route, and recording.srs_zone has no media address)"
            )));
        }
        let mut settings =
            crate::recording::RecordingSettings::from_config(rec, srs_addr, local_media_ip)
                .map_err(refuse)?;
        // SC-7: the ports the SBC itself uses for RTP; an SRS answer must
        // not aim the fork at them.
        settings.media_ports = self.config.media.rtp_port_min..=self.config.media.rtp_port_max;
        // SC-7: an unzoned relay binds the wildcard address, so every local
        // interface address is one of the SBC's own. Enumerated once here
        // (one `getifaddrs`), never on the signaling task.
        settings.local_addrs = sbc_config::interface::local_addresses();
        if settings.local_addrs.is_empty() {
            warn!(
                "recording: local interface addresses could not be enumerated; \
                 SRS answer addresses are checked against configured addresses only"
            );
        }
        let tls_name = settings.flow.dial.clone().unwrap_or_default();
        let stack =
            Arc::get_mut(&mut self.sip_stack).ok_or_else(|| ServerError::InternalError {
                message: "cannot attach recording: sip_stack Arc already shared".to_string(),
            })?;
        stack.set_recording(settings);
        self.flows.set_recorder_tls_client(Arc::new(tls));
        info!(
            srs = %srs_addr,
            server_name = %tls_name,
            ca = %ca_path.display(),
            on_failure = ?rec.on_failure,
            max_sessions = rec.max_sessions,
            "SIPREC recording enabled (TLS 1.3 to the recorder, certificate verification on)"
        );
        Ok(())
    }

    /// A send context with this server's shared handles.
    fn send_ctx(&self, origin: Origin) -> SendCtx {
        SendCtx {
            flows: Arc::clone(&self.flows),
            stats: Arc::clone(&self.stats),
            sip_stack: Arc::clone(&self.sip_stack),
            origin,
        }
    }

    /// Loads the client TLS configs for `protocol = "tls"` trunks: trust
    /// anchors from `security.trunk_tls_ca_path` (never `tls_ca_path`, the
    /// client-issuing CA), `security.min_tls_version`, and for trunks with
    /// `tls_client_cert` the SBC certificate as the client certificate.
    /// Certificate verification cannot be turned off. Without the CA path
    /// (validation guarantees no TLS trunk then) no egress TLS is possible:
    /// a TLS flow fails closed.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-13, SC-23, IA-3
    fn load_trunk_tls_clients(&self) -> Result<(), ServerError> {
        let sec = &self.config.security;
        let Some(ca_path) = sec.trunk_tls_ca_path.as_ref() else {
            return Ok(());
        };
        let tls_error = |reason: String| ServerError::BindFailed {
            address: "trunk-tls".to_string(),
            reason,
        };
        let min_version = uc_transport::tls::MinTlsVersion::parse(&sec.min_tls_version)
            .ok_or_else(|| {
                tls_error(format!(
                    "unsupported security.min_tls_version {:?}",
                    sec.min_tls_version
                ))
            })?;
        let roots = || {
            uc_transport::tls::load_root_store(ca_path)
                .map_err(|e| tls_error(format!("loading {}: {e}", ca_path.display())))
        };
        let plain =
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots: roots()?,
                min_version,
                client_auth: None,
            })
            .map_err(|e| tls_error(format!("building trunk TLS client config: {e}")))?;
        let wants_mtls = self
            .config
            .trunk_groups
            .iter()
            .flat_map(|g| &g.trunks)
            .any(|t| t.tls_client_cert);
        let mtls = match (wants_mtls, &sec.tls_cert_path, &sec.tls_key_path) {
            (true, Some(cert), Some(key)) => {
                let chain = uc_transport::tls::load_certs(cert)
                    .map_err(|e| tls_error(format!("loading {}: {e}", cert.display())))?;
                // POA&M-166: key must be on security.curve; outcome audited.
                let key = load_tls_key_audited("trunk-mtls-client", key, sec.curve)
                    .map_err(|e| tls_error(format!("loading {}: {e}", key.display())))?;
                Some(Arc::new(
                    uc_transport::tls::create_client_config_with(
                        uc_transport::tls::TlsClientOptions {
                            roots: roots()?,
                            min_version,
                            client_auth: Some((chain, key)),
                        },
                    )
                    .map_err(|e| tls_error(format!("building trunk mTLS client config: {e}")))?,
                ))
            }
            (true, _, _) => {
                return Err(tls_error(
                    "trunk tls_client_cert needs security.tls_cert_path / tls_key_path".to_string(),
                ));
            }
            _ => None,
        };
        self.flows.set_tls_clients(Arc::new(plain), mtls);
        info!(
            ca = %ca_path.display(),
            min_tls_version = %sec.min_tls_version,
            mtls = wants_mtls,
            "Trunk TLS client credentials loaded (certificate verification on)"
        );
        Ok(())
    }

    /// Binds UDP transport listeners.
    async fn bind_udp_listeners(&mut self) -> Result<(), ServerError> {
        let mut transports = self.udp_transports.write().await;

        for socket_addr in &self.config.transport.udp_listen {
            let addr = SbcSocketAddr::from(*socket_addr);
            match UdpTransport::bind(addr).await {
                Ok(transport) => {
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound"
                    );
                    transports.push(Arc::new(transport));
                }
                Err(e) => {
                    error!(address = %addr, error = %e, "Failed to bind UDP listener");
                    return Err(ServerError::BindFailed {
                        address: addr.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // If no UDP listeners configured, bind to default ports
        if transports.is_empty() {
            let default_addr = SbcSocketAddr::new_v6(Ipv6Addr::UNSPECIFIED, 5060);
            match UdpTransport::bind(default_addr).await {
                Ok(transport) => {
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound (default)"
                    );
                    transports.push(Arc::new(transport));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to bind default UDP listener on IPv6, trying IPv4");
                    // Try IPv4 fallback
                    let ipv4_addr = SbcSocketAddr::new_v4(Ipv4Addr::UNSPECIFIED, 5060);
                    let transport = UdpTransport::bind(ipv4_addr).await.map_err(|e| {
                        ServerError::BindFailed {
                            address: "0.0.0.0:5060".to_string(),
                            reason: e.to_string(),
                        }
                    })?;
                    info!(
                        address = %transport.local_addr(),
                        "UDP listener bound (IPv4 fallback)"
                    );
                    transports.push(Arc::new(transport));
                }
            }
        }

        Ok(())
    }

    /// Binds SIP-over-TCP listeners from `transport.tcp_listen`.
    async fn bind_tcp_listeners(&mut self) -> Result<(), ServerError> {
        let mut listeners = self.tcp_listeners.write().await;

        for socket_addr in &self.config.transport.tcp_listen {
            let addr = SbcSocketAddr::from(*socket_addr);
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!(address = %listener.local_addr(), "TCP listener bound");
                    listeners.push(Arc::new(listener));
                }
                Err(e) => {
                    error!(address = %addr, error = %e, "Failed to bind TCP listener");
                    return Err(ServerError::BindFailed {
                        address: addr.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Binds SIP-over-TLS listeners from `transport.tls_listen`.
    ///
    /// TLS needs server credentials: `security.tls_cert_path` /
    /// `security.tls_key_path`. When the paths are not configured the
    /// listeners are skipped with a warning rather than failing startup, so
    /// UDP-only deployments keep working with the shipped default config
    /// (which declares a TLS listener but no certificate).
    async fn bind_tls_listeners(&mut self) -> Result<(), ServerError> {
        if self.config.transport.tls_listen.is_empty() {
            return Ok(());
        }

        let (Some(cert_path), Some(key_path)) = (
            self.config.security.tls_cert_path.as_ref(),
            self.config.security.tls_key_path.as_ref(),
        ) else {
            warn!(
                listeners = ?self.config.transport.tls_listen,
                "transport.tls_listen configured but security.tls_cert_path / \
                 tls_key_path are not set — SIP TLS listeners DISABLED"
            );
            return Ok(());
        };

        let tls_error = |reason: String| ServerError::BindFailed {
            address: "tls".to_string(),
            reason,
        };
        // POAM: POA&M-194, the SIP TLS cert/key are loaded once at bind;
        // they are not hot-reloadable (ReloadTls covers the API acceptor only).
        let cert_chain = uc_transport::tls::load_certs(cert_path)
            .map_err(|e| tls_error(format!("loading {}: {e}", cert_path.display())))?;
        // POA&M-166: key must be on security.curve; outcome audited.
        let private_key =
            load_tls_key_audited("sip-tls-listener", key_path, self.config.security.curve)
                .map_err(|e| tls_error(format!("loading {}: {e}", key_path.display())))?;
        // security.min_tls_version and security.require_mtls (with
        // security.tls_ca_path) are enforced here; validate_config already
        // guaranteed the combinations are coherent.
        let min_version =
            uc_transport::tls::MinTlsVersion::parse(&self.config.security.min_tls_version)
                .ok_or_else(|| {
                    tls_error(format!(
                        "unsupported security.min_tls_version {:?}",
                        self.config.security.min_tls_version
                    ))
                })?;
        let client_ca = if self.config.security.require_mtls {
            let ca_path = self.config.security.tls_ca_path.as_ref().ok_or_else(|| {
                tls_error("security.require_mtls needs security.tls_ca_path".to_string())
            })?;
            Some(
                uc_transport::tls::load_root_store(ca_path)
                    .map_err(|e| tls_error(format!("loading {}: {e}", ca_path.display())))?,
            )
        } else {
            None
        };
        let options = uc_transport::tls::TlsServerOptions {
            min_version,
            client_ca,
        };
        let server_config = Arc::new(
            uc_transport::tls::create_server_config_with(cert_chain, private_key, options)
                .map_err(|e| tls_error(format!("building TLS server config: {e}")))?,
        );
        info!(
            cert = %cert_path.display(),
            min_tls_version = %self.config.security.min_tls_version,
            mtls = self.config.security.require_mtls,
            "TLS server credentials loaded for SIP listeners"
        );

        let mut listeners = self.tls_listeners.write().await;
        for socket_addr in &self.config.transport.tls_listen {
            let addr = SbcSocketAddr::from(*socket_addr);
            let listener_config = ListenerConfig::new(addr, TransportType::Tls);
            match TlsListener::bind(listener_config, Arc::clone(&server_config)).await {
                Ok(listener) => {
                    info!(address = %listener.local_addr(), "TLS listener bound");
                    listeners.push(Arc::new(listener));
                }
                Err(e) => {
                    error!(address = %addr, error = %e, "Failed to bind TLS listener");
                    return Err(ServerError::BindFailed {
                        address: addr.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Binds SIP-over-WebSocket listeners from `transport.ws_listen`
    /// (RFC 7118). Plain `ws` only: the WebSocket transport does not
    /// terminate TLS, and `validate_config` rejects `wss_listen`.
    async fn bind_ws_listeners(&mut self) -> Result<(), ServerError> {
        let mut listeners = self.ws_listeners.write().await;
        for socket_addr in &self.config.transport.ws_listen {
            let addr = SbcSocketAddr::from(*socket_addr);
            match WebSocketListener::bind(&addr, false).await {
                Ok(listener) => {
                    // RFC 7118 §4; NIST 800-53 Rev5: SC-7.
                    let listener = listener.with_options(WebSocketListenerOptions {
                        require_sip_subprotocol: self.config.transport.ws_require_sip_subprotocol,
                    });
                    info!(address = %listener.local_addr(), "WebSocket listener bound");
                    listeners.push(Arc::new(listener));
                }
                Err(e) => {
                    error!(address = %addr, error = %e, "Failed to bind WebSocket listener");
                    return Err(ServerError::BindFailed {
                        address: addr.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Runs the main event loop.
    pub async fn run(&mut self) -> Result<(), ServerError> {
        info!("Entering async event loop");

        // Get transport handles for spawning receive tasks
        let transports = self.udp_transports.read().await;
        let tcp_listeners: Vec<_> = self.tcp_listeners.read().await.clone();
        let tls_listeners: Vec<_> = self.tls_listeners.read().await.clone();
        let ws_listeners: Vec<_> = self.ws_listeners.read().await.clone();
        let transport_count =
            transports.len() + tcp_listeners.len() + tls_listeners.len() + ws_listeners.len();

        if transport_count == 0 {
            warn!("No transports bound, exiting event loop");
            return Ok(());
        }

        // Configured trunks are trusted on both per-source limiters, and
        // exempt from the aggregate connection caps (SR-58), before any
        // receive or accept loop runs, then kept in step with trunk changes.
        // NIST 800-53 Rev5: SC-5
        let conn_limiter = Arc::new(Self::build_conn_limiter(&self.config));
        let mut handles = Vec::new();
        {
            let mut rx = self.sip_stack.trunk_sources();
            let set = Arc::clone(&rx.borrow_and_update());
            Self::apply_trusted_sources(&set, &self.udp_rate_limiter, &self.stream_rate_limiter)
                .await;
            let _ = conn_limiter.set_trusted_sources(set.iter().copied());
            let udp = Arc::clone(&self.udp_rate_limiter);
            let stream = Arc::clone(&self.stream_rate_limiter);
            let conns = Arc::clone(&conn_limiter);
            handles.push(tokio::spawn(Self::trusted_source_sync(
                rx, udp, stream, conns,
            )));
        }

        // Spawn receive tasks for each transport
        for (idx, transport) in transports.iter().enumerate() {
            let transport = Arc::clone(transport);
            let shutdown = self.shutdown.clone();
            let stats = Arc::clone(&self.stats);
            let sip_stack = Arc::clone(&self.sip_stack);
            let rate_limiter = Arc::clone(&self.udp_rate_limiter);
            let global_limiter = Arc::clone(&self.global_limiter);
            let rate_limit_enabled = self.config.rate_limit.enabled;
            let flows = Arc::clone(&self.flows);

            // Determine zone for this transport from its local bind address
            let zone_name = self.zone_for_transport(&transport);

            let handle = tokio::spawn(async move {
                Self::transport_receive_loop(
                    idx,
                    transport,
                    shutdown,
                    stats,
                    sip_stack,
                    rate_limiter,
                    global_limiter,
                    rate_limit_enabled,
                    zone_name,
                    flows,
                )
                .await;
            });
            handles.push(handle);
        }
        drop(transports);

        // Transaction timer loop: RFC 3261 §17 retransmissions and timeouts
        // plus §13.3.1.4 2xx retransmission. Re-sends go out the first UDP
        // socket (the one receive loops also answer from when zones share a
        // bind).
        // Every timer result carries its leg's flow, so the loop runs for
        // stream-only deployments too (RFC 3261 §17.1.2.2, §18).
        {
            let ctx = self.send_ctx(Origin::None);
            handles.push(tokio::spawn(async move {
                Self::transaction_timer_loop(ctx).await;
            }));
        }

        // Spawn accept loops for stream listeners (SIP over TCP / TLS).
        // Each accepted connection gets its own receive task; responses go
        // back over the connection the request arrived on (RFC 3261 §18).
        // NIST 800-53 Rev5: SC-5 — each listener has its own pool so a
        // flood on one (e.g. WS) cannot starve another (TLS); a node-wide
        // ceiling bounds the fd budget and a per-source cap stops one host
        // from taking a whole pool; aggregate caps stop one IPv6 /48 (or
        // IPv4 /24) from doing the same across many sources (SR-58).
        let tc = &self.config.transport;
        let per_listener = tc.max_connections_per_listener as usize;
        let total_conns = Arc::new(tokio::sync::Semaphore::new(
            tc.max_connections_total as usize,
        ));
        // NIST 800-53 Rev5: SC-5 — per-source and aggregate accept rate
        // (TCP and TLS) and TLS in-handshake caps, checked at accept before
        // any handshake; built (with the connection caps and the startup
        // handshake-limit logging) by `build_conn_limiter` before the trunk
        // sync above.
        let slot_count = HandshakeLimits::from_config(tc).slots;
        let handshake_slots = Arc::new(tokio::sync::Semaphore::new(slot_count));
        let timeouts = StreamTimeouts::from_config(&self.config);
        let stream_ctx = |zone_name: Option<String>| StreamLoopContext {
            shutdown: self.shutdown.clone(),
            stats: Arc::clone(&self.stats),
            sip_stack: Arc::clone(&self.sip_stack),
            rate_limiter: Arc::clone(&self.stream_rate_limiter),
            global_limiter: Arc::clone(&self.global_limiter),
            rate_limit_enabled: self.config.rate_limit.enabled,
            zone_name,
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(per_listener)),
            total_conns: Arc::clone(&total_conns),
            conn_limiter: Arc::clone(&conn_limiter),
            handshake_slots: Arc::clone(&handshake_slots),
            timeouts,
            flows: Arc::clone(&self.flows),
        };
        // Readers for SBC-dialled trunk connections: trunk responses and
        // in-dialog requests enter the SIP stack like any received message.
        {
            let ctx = stream_ctx(None);
            self.flows.set_reader(Arc::new(move |conn, peer, key| {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    Self::stream_connection_loop(conn, peer, ctx, Some(key)).await;
                });
            }));
        }
        for listener in tcp_listeners {
            let ctx = stream_ctx(self.zone_for_local_ip(listener.local_addr().ip()));
            handles.push(tokio::spawn(async move {
                Self::tcp_accept_loop(listener, ctx).await;
            }));
        }
        for listener in tls_listeners {
            let ctx = stream_ctx(self.zone_for_local_ip(listener.local_addr().ip()));
            handles.push(tokio::spawn(async move {
                Self::tls_accept_loop(listener, ctx).await;
            }));
        }
        for listener in ws_listeners {
            let ctx = stream_ctx(self.zone_for_local_ip(listener.local_addr().ip()));
            handles.push(tokio::spawn(async move {
                Self::ws_accept_loop(listener, ctx).await;
            }));
        }

        // Rate-limited signaling audit flush (digest, in-dialog, route and
        // loop rejections; POA&M-236/252). NIST 800-53 Rev5: AU-4, AU-5.
        handles.push(
            self.sip_stack
                .signaling_audit()
                .spawn_flush(self.shutdown.clone()),
        );

        // Limiter maintenance: expired blocks, idle buckets, aggregated
        // rate-limit audit (SC-5, AU-4).
        {
            let maint = RateLimitMaintenance::new(
                &self.config,
                self.shutdown.clone(),
                Arc::clone(&self.stream_rate_limiter),
                Arc::clone(&self.global_limiter),
                Arc::clone(&conn_limiter),
            )
            .with_per_ip_limiter(LimiterKind::Udp, Arc::clone(&self.udp_rate_limiter));
            handles.push(tokio::spawn(maint.run()));
        }

        // Spawn health check polling task
        let shutdown = self.shutdown.clone();
        let health_interval = tokio::time::Duration::from_secs(30);
        let health_handle = tokio::spawn(async move {
            Self::health_poll_loop(shutdown, health_interval).await;
        });

        // Wait for shutdown or all tasks to complete
        self.shutdown.wait_for_shutdown().await;
        info!("Shutdown signal received — draining active calls");

        // Drain: reject new INVITEs (503) but keep the receive loops alive
        // so in-dialog BYEs still tear calls down. Previously the loops were
        // aborted immediately, so "draining" could never complete and
        // active calls were killed on SIGTERM.
        self.sip_stack.set_draining();
        let drain_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
        loop {
            let active = self.sip_stack.active_call_count().await;
            if active == 0 {
                info!("All active calls drained");
                break;
            }
            if tokio::time::Instant::now() >= drain_deadline {
                warn!(
                    active,
                    "Drain timeout reached, terminating with active calls"
                );
                break;
            }
            debug!(active, "Waiting for calls to drain");
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }

        // Cancel all tasks
        for handle in handles {
            handle.abort();
        }
        health_handle.abort();

        Ok(())
    }

    /// Receive loop for a single transport.
    // Spawned-task entrypoint: each argument is a distinct shared handle the
    // loop needs for its lifetime; bundling them into a struct would only move
    // the same fields behind one name without improving clarity.
    #[allow(clippy::too_many_arguments)]
    async fn transport_receive_loop(
        idx: usize,
        transport: Arc<UdpTransport>,
        shutdown: ShutdownSignal,
        stats: Arc<ServerStats>,
        sip_stack: Arc<SipStack>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        global_limiter: Arc<Mutex<RateLimiter>>,
        rate_limit_enabled: bool,
        zone_name: Option<String>,
        flows: Arc<FlowTable>,
    ) {
        debug!(
            transport_idx = idx,
            zone = zone_name.as_deref().unwrap_or("default"),
            "Starting transport receive loop"
        );

        let mut consecutive_errors: u64 = 0;
        loop {
            // No shutdown arm here: during graceful shutdown the loop keeps
            // processing in-dialog requests (BYEs) so active calls can
            // drain; Server::run aborts the task once draining completes.
            tokio::select! {
                result = transport.recv() => {
                    match result {
                        Ok(msg) => {
                            consecutive_errors = 0;
                            stats.messages_received.fetch_add(1, Ordering::Relaxed);

                            // Extract source IP for rate limiting
                            let source_ip = msg.source.ip();

                            // Check rate limits: global backstop first
                            // (one bucket, catches distributed floods that
                            // stay under the per-IP limit), then per-source.
                            if rate_limit_enabled
                                && !Self::rate_limit_allows(
                                    source_ip,
                                    &rate_limiter,
                                    &global_limiter,
                                    &stats,
                                )
                                .await
                            {
                                continue;
                            }

                            debug!(
                                source = %msg.source,
                                size = msg.data.len(),
                                transport = ?msg.transport,
                                "Received message"
                            );

                            // Process through SIP stack in a separate task
                            // so slow operations (e.g. JWKS refresh) do not
                            // block the receive loop.
                            {
                                let ctx = SendCtx {
                                    flows: Arc::clone(&flows),
                                    stats: Arc::clone(&stats),
                                    sip_stack: Arc::clone(&sip_stack),
                                    origin: Origin::Udp(Arc::clone(&transport)),
                                };
                                let zone = zone_name.clone();
                                let data = msg.data;
                                let source = msg.source;
                                tokio::spawn(async move {
                                    let result = ctx
                                        .sip_stack
                                        .process_message_on(
                                            &data,
                                            source,
                                            zone.as_deref(),
                                            uc_types::address::TransportType::Udp,
                                        )
                                        .await;
                                    Self::dispatch(result, &ctx).await;
                                });
                            }
                        }
                        Err(e) => {
                            if shutdown.is_shutdown_requested() {
                                break;
                            }
                            warn!(error = %e, "Transport receive error");
                            // Persistent errors (closed fd, dead transport)
                            // return immediately — back off instead of
                            // busy-spinning at 100% CPU flooding the log.
                            consecutive_errors += 1;
                            if consecutive_errors >= 32 {
                                error!(
                                    transport_idx = idx,
                                    "Transport failing persistently, stopping receive loop"
                                );
                                // Mark this transport dead so readiness can
                                // reflect it (the daemon must not stay green
                                // while deaf on a listener).
                                stats.live_transports.try_update(
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                    |v| v.checked_sub(1),
                                ).ok();
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                50 * consecutive_errors.min(20),
                            ))
                            .await;
                        }
                    }
                }
            }
        }
    }

    /// Checks the per-source and global rate limits for one message.
    ///
    /// Per-source runs first: a source already over its own limit never
    /// spends shared global tokens, and a global rejection never blocks
    /// anyone (the global limiter cannot attribute a flood to a source).
    /// The limiters are locked one at a time, never together.
    ///
    /// Returns `true` when the message may be processed. Increments
    /// `stats.rate_limited` on every rejection. Rejections are counted
    /// inside the limiters and audited in aggregate by
    /// [`RateLimitMaintenance`]; only the transition into a block is
    /// audited here.
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-12
    async fn rate_limit_allows(
        source_ip: std::net::IpAddr,
        rate_limiter: &Mutex<RateLimiter>,
        global_limiter: &Mutex<RateLimiter>,
        stats: &ServerStats,
    ) -> bool {
        let (outcome, per_ip_rps, v6_prefix) = {
            let mut limiter = rate_limiter.lock().await;
            let config = limiter.config();
            let (rps, v6_prefix) = (config.rps, config.ipv6_prefix_len);
            (limiter.check_outcome(source_ip), rps, v6_prefix)
        };
        match outcome.action {
            RateLimitAction::Allow => {}
            RateLimitAction::Throttle { delay_ms } => {
                debug!(source = %source_ip, delay_ms, "Rate limit throttle suggested");
            }
            RateLimitAction::Reject => {
                stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                debug!(source = %source_ip, "Rate limit exceeded, rejecting message");
                return false;
            }
            RateLimitAction::Block { duration_secs } => {
                stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                if outcome.block_started {
                    warn!(
                        source = %source_ip,
                        duration_secs,
                        "Source blocked due to rate limit violation"
                    );
                    // AU-3: the record names what was blocked (the source
                    // key and its prefix length) and for how long;
                    // `request_count` is not overloaded with the duration.
                    let key = uc_dos_protection::source_key(source_ip, v6_prefix);
                    let prefix = if key.is_ipv4() { 32 } else { v6_prefix };
                    audit_rate_limit(
                        key,
                        &format!("per_ip_block:/{prefix}:{duration_secs}s"),
                        0,
                        u64::from(per_ip_rps),
                    );
                }
                return false;
            }
        }

        // POAM: POA&M-451 — trusted trunks are charged here too, so a
        // distributed flood at `global_rps` can reject trunk traffic (SC-5).
        let global_action = global_limiter.lock().await.check(source_ip);
        if global_action.is_rejected() {
            stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            debug!(source = %source_ip, "Global rate limit exceeded, rejecting message");
            return false;
        }
        true
    }

    /// Admits one accepted stream connection: per-source accept rate and
    /// cap, then this listener's pool, then the node-wide ceiling. `None`
    /// means the connection must be dropped (closing the socket).
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    fn admit_connection(
        ctx: &StreamLoopContext,
        peer: &SbcSocketAddr,
        kind: &str,
    ) -> Option<ConnAdmission> {
        Self::admit_with(ctx, peer, kind, true)
    }

    /// [`Self::admit_connection`]; `metered` false skips the per-source
    /// accept bucket (the caps still apply).
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    fn admit_with(
        ctx: &StreamLoopContext,
        peer: &SbcSocketAddr,
        kind: &str,
        metered: bool,
    ) -> Option<ConnAdmission> {
        let admitted = if metered {
            ctx.conn_limiter.try_admit(peer.ip())
        } else {
            ctx.conn_limiter.try_admit_unmetered(peer.ip())
        };
        let source = match admitted {
            Ok(source) => source,
            Err(crate::conn_limit::Rejection::AcceptRate) => {
                ctx.stats
                    .accept_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Per-source accept rate exceeded, dropping");
                return None;
            }
            Err(crate::conn_limit::Rejection::AggregateAcceptRate) => {
                ctx.stats
                    .accept_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Aggregate accept rate exceeded, dropping");
                return None;
            }
            Err(crate::conn_limit::Rejection::PerAggregate) => {
                ctx.stats
                    .conn_rejected_per_aggregate
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Aggregate connection limit reached, dropping");
                return None;
            }
            Err(_) => {
                ctx.stats
                    .conn_rejected_per_source
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Per-source connection limit reached, dropping");
                return None;
            }
        };
        // Pool-full drops are counted and audited in aggregate
        // (`listener_conn` / `total_conn`) by RateLimitMaintenance, which
        // also logs one warning per flush; a per-socket warn! would be an
        // unbounded log stream under a connection flood (AU-4, SC-5).
        let Ok(listener) = Arc::clone(&ctx.conn_semaphore).try_acquire_owned() else {
            ctx.conn_limiter.note_listener_full();
            debug!(peer = %peer, kind, "Listener connection limit reached, dropping");
            return None;
        };
        let Ok(total) = Arc::clone(&ctx.total_conns).try_acquire_owned() else {
            ctx.conn_limiter.note_total_full();
            debug!(peer = %peer, kind, "Total connection limit reached, dropping");
            return None;
        };
        Some(ConnAdmission {
            _source: source,
            _listener: listener,
            _total: total,
        })
    }

    /// Whether `peer`'s source is blocked by the stream per-source rate
    /// limiter (`ctx.rate_limiter` is `Server::stream_rate_limiter`, SR-55).
    /// A blocked source is dropped at accept, before admission and before
    /// any handshake; drops are counted and audited in aggregate
    /// (`accept_blocked`). Blocks earned on the UDP limiter do not apply,
    /// and `is_blocked` is trust-aware: a configured trunk is refused only
    /// for an explicit block of its exact address, never for a block on its
    /// IPv6 prefix.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    async fn accept_blocked(ctx: &StreamLoopContext, peer: &SbcSocketAddr, kind: &str) -> bool {
        // Lock held for the lookup only.
        let blocked = ctx.rate_limiter.lock().await.is_blocked(peer.ip());
        if blocked {
            ctx.stats.accept_blocked.fetch_add(1, Ordering::Relaxed);
            ctx.conn_limiter.note_accept_blocked(peer.ip());
            debug!(peer = %peer, kind, "Source blocked, dropping at accept");
        }
        blocked
    }

    /// Takes a per-source handshake slot (`max_handshakes_per_source`), or
    /// `None` when the source already has that many handshakes running.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    fn begin_handshake(
        ctx: &StreamLoopContext,
        peer: &SbcSocketAddr,
        kind: &str,
    ) -> Option<crate::conn_limit::HandshakeGuard> {
        match ctx.conn_limiter.try_handshake(peer.ip()) {
            Ok(guard) => Some(guard),
            Err(crate::conn_limit::Rejection::AggregateHandshakeBusy) => {
                ctx.stats
                    .handshake_busy_per_aggregate
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Aggregate handshake limit reached, dropping");
                None
            }
            Err(_) => {
                ctx.stats
                    .handshake_busy_per_source
                    .fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, kind, "Per-source handshake limit reached, dropping");
                None
            }
        }
    }

    /// Runs `handshake` on `stream` while holding a node-wide handshake
    /// slot.
    ///
    /// The slot is requested only once the client has sent data (peeked,
    /// not consumed), so a silent socket never holds one; it waits at most
    /// `slot_wait` for a slot, and the handshake then has at most `hold`
    /// to finish while holding it, so a client that sends one byte and
    /// stalls frees the slot after `hold`. The caller wraps this in the
    /// handshake deadline, which bounds the whole sequence. The slot and
    /// `guard` are released as soon as the handshake ends, before any
    /// receive loop.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    async fn with_handshake_slot<T, F, Fut>(
        slots: Arc<tokio::sync::Semaphore>,
        slot_wait: std::time::Duration,
        hold: std::time::Duration,
        guard: crate::conn_limit::HandshakeGuard,
        stream: tokio::net::TcpStream,
        handshake: F,
    ) -> SlottedHandshake<T>
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut,
        Fut: std::future::Future<Output = uc_transport::TransportResult<T>>,
    {
        // Wait for the first byte without consuming it. `readable()` alone
        // is not enough: it can report ready on a socket with no data
        // (seen with kqueue), which would let silent sockets take slots.
        let mut first = [0u8; 1];
        match stream.peek(&mut first).await {
            Ok(0) => {
                return SlottedHandshake::Done(Err(uc_transport::TransportError::ConnectionClosed));
            }
            Ok(_) => {}
            Err(e) => {
                return SlottedHandshake::Done(Err(uc_transport::TransportError::Io {
                    reason: e.to_string(),
                }));
            }
        }
        let slot = match tokio::time::timeout(slot_wait, slots.acquire_owned()).await {
            Ok(Ok(slot)) => slot,
            Ok(Err(_)) => {
                return SlottedHandshake::Done(Err(uc_transport::TransportError::ConnectionClosed));
            }
            Err(_) => return SlottedHandshake::SlotWaitExpired,
        };
        let result = tokio::time::timeout(hold, handshake(stream)).await;
        drop(slot);
        drop(guard);
        result.map_or(SlottedHandshake::HoldExpired, SlottedHandshake::Done)
    }

    /// Handles an `accept()` error: per-connection errors are counted and
    /// the loop continues at once; resource exhaustion, or a long run of
    /// errors with no successful accept, backs off.
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-4
    async fn on_accept_error(
        ctx: &StreamLoopContext,
        backoff: &mut AcceptBackoff,
        err: &uc_transport::TransportError,
        kind: &str,
    ) -> AcceptNext {
        if ctx.shutdown.is_shutdown_requested()
            || matches!(err, uc_transport::TransportError::AlreadyClosed)
        {
            return AcceptNext::Stop;
        }
        let resource_exhausted = err.is_resource_exhausted();
        if resource_exhausted {
            ctx.stats
                .accept_resource_errors
                .fetch_add(1, Ordering::Relaxed);
        } else {
            ctx.stats.accept_errors.fetch_add(1, Ordering::Relaxed);
        }
        match backoff.on_error(err) {
            None => {
                debug!(error = %err, kind, "Stream accept failed for one connection");
            }
            Some(delay) => {
                if backoff.should_warn() {
                    warn!(
                        error = %err,
                        kind,
                        resource_exhausted,
                        backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "Stream accept failing (resources exhausted or persistent errors); backing off"
                    );
                }
                tokio::time::sleep(delay).await;
            }
        }
        AcceptNext::Continue
    }

    /// Accept loop for a SIP-over-TCP listener.
    ///
    /// The connection is admitted (blocked check, accept rate, caps) before
    /// its transport is built, so a refused accept allocates nothing.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    // POAM: POA&M-442 — the listen backlog is fixed (`ListenerConfig`
    // default 128; tokio default for WS) and not configurable (SC-5).
    async fn tcp_accept_loop(listener: Arc<TcpListener>, ctx: StreamLoopContext) {
        info!(address = %listener.local_addr(), "SIP TCP accept loop started");
        let mut backoff = AcceptBackoff::new();
        loop {
            match listener.accept_tcp().await {
                Ok((stream, peer)) => {
                    backoff.on_success();
                    if Self::accept_blocked(&ctx, &peer, "tcp").await {
                        continue;
                    }
                    let Some(admission) = Self::admit_connection(&ctx, &peer, "tcp") else {
                        continue;
                    };
                    let transport = uc_transport::tcp::TcpTransport::from_accepted(
                        stream,
                        peer,
                        *listener.local_addr(),
                    );
                    debug!(peer = %peer, "Accepted SIP TCP connection");
                    let conn_ctx = ctx.clone();
                    tokio::spawn(async move {
                        Self::stream_connection_loop(Arc::new(transport), peer, conn_ctx, None)
                            .await;
                        drop(admission);
                    });
                }
                Err(e) => {
                    if matches!(
                        Self::on_accept_error(&ctx, &mut backoff, &e, "tcp").await,
                        AcceptNext::Stop
                    ) {
                        break;
                    }
                }
            }
        }
    }

    /// Accept loop for a SIP-over-WebSocket listener (RFC 7118). Each
    /// WebSocket message is a complete SIP message.
    ///
    /// The raw TCP accept and admission run inline; the HTTP upgrade runs
    /// in the spawned connection task under `transport.handshake_timeout_secs`,
    /// so a silent or slow client holds only its own connection slot and
    /// cannot stall the listener. The upgrade costs no crypto, so it takes
    /// no handshake slot.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, SC-10
    // POAM: POA&M-440 — the per-source accept bucket is off on WebSocket
    // listeners: behind the recommended WSS proxy the accept address is the
    // proxy's, so one bucket would be shared by every client. It is enabled
    // once SR-59 keys WS admission on the client address (SC-5).
    async fn ws_accept_loop(listener: Arc<WebSocketListener>, ctx: StreamLoopContext) {
        info!(address = %listener.local_addr(), "SIP WebSocket accept loop started");
        let mut backoff = AcceptBackoff::new();
        loop {
            match listener.accept_tcp().await {
                Ok((tcp_stream, peer)) => {
                    backoff.on_success();
                    if Self::accept_blocked(&ctx, &peer, "ws").await {
                        continue;
                    }
                    let Some(admission) = Self::admit_with(&ctx, &peer, "ws", false) else {
                        continue;
                    };
                    let conn_ctx = ctx.clone();
                    let listener = Arc::clone(&listener);
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            conn_ctx.timeouts.handshake,
                            listener.complete_handshake(tcp_stream, peer),
                        )
                        .await
                        {
                            Ok(Ok(transport)) => {
                                debug!(peer = %peer, "Accepted SIP WebSocket connection");
                                Self::stream_connection_loop(
                                    Arc::new(transport),
                                    peer,
                                    conn_ctx,
                                    None,
                                )
                                .await;
                            }
                            Ok(Err(e)) => {
                                conn_ctx
                                    .stats
                                    .ws_handshake_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                debug!(peer = %peer, error = %e, "WebSocket handshake failed");
                            }
                            Err(_) => {
                                conn_ctx
                                    .stats
                                    .handshake_timeouts
                                    .fetch_add(1, Ordering::Relaxed);
                                debug!(peer = %peer, "WebSocket handshake timed out, dropping");
                            }
                        }
                        drop(admission);
                    });
                }
                Err(e) => {
                    if matches!(
                        Self::on_accept_error(&ctx, &mut backoff, &e, "ws").await,
                        AcceptNext::Stop
                    ) {
                        break;
                    }
                }
            }
        }
    }

    /// Accept loop for a SIP-over-TLS listener.
    ///
    /// The raw TCP accept and admission run inline so the loop stays
    /// responsive and a refused source costs no crypto; the TLS handshake
    /// is spawned under `transport.handshake_timeout_secs`, so one slow
    /// client cannot stall new connections on this listener. The handshake
    /// takes a node-wide slot only after the client sends data, and waits
    /// for one at most [`StreamTimeouts::handshake_slot_wait`], then holds
    /// it at most [`StreamTimeouts::handshake_slot_hold`].
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    async fn tls_accept_loop(listener: Arc<TlsListener>, ctx: StreamLoopContext) {
        info!(address = %listener.local_addr(), "SIP TLS accept loop started");
        let mut backoff = AcceptBackoff::new();
        loop {
            // Step 1: accept the raw TCP connection (fast, no crypto).
            match listener.accept_tcp().await {
                Ok((tcp_stream, peer)) => {
                    backoff.on_success();
                    if Self::accept_blocked(&ctx, &peer, "tls").await {
                        continue;
                    }
                    let Some(admission) = Self::admit_connection(&ctx, &peer, "tls") else {
                        continue;
                    };
                    let Some(handshake) = Self::begin_handshake(&ctx, &peer, "tls") else {
                        continue;
                    };
                    // Step 2: spawn the TLS handshake so the accept loop
                    // continues immediately.
                    let conn_ctx = ctx.clone();
                    let listener_clone = listener.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            conn_ctx.timeouts.handshake,
                            Self::with_handshake_slot(
                                Arc::clone(&conn_ctx.handshake_slots),
                                conn_ctx.timeouts.handshake_slot_wait(),
                                conn_ctx.timeouts.handshake_slot_hold(),
                                handshake,
                                tcp_stream,
                                |tcp| listener_clone.complete_handshake(tcp, peer),
                            ),
                        )
                        .await
                        {
                            Ok(SlottedHandshake::Done(Ok(transport))) => {
                                debug!(peer = %peer, "TLS handshake completed");
                                Self::stream_connection_loop(
                                    Arc::new(transport),
                                    peer,
                                    conn_ctx,
                                    None,
                                )
                                .await;
                            }
                            Ok(SlottedHandshake::SlotWaitExpired) => {
                                conn_ctx
                                    .stats
                                    .handshake_slot_timeouts
                                    .fetch_add(1, Ordering::Relaxed);
                                debug!(peer = %peer, "No TLS handshake slot in time, dropping");
                            }
                            Ok(SlottedHandshake::HoldExpired) => {
                                conn_ctx
                                    .stats
                                    .handshake_slot_hold_timeouts
                                    .fetch_add(1, Ordering::Relaxed);
                                debug!(peer = %peer, "TLS handshake held its slot too long, dropping");
                            }
                            Ok(SlottedHandshake::Done(Err(e))) => {
                                // POAM: POA&M-443 — a failed TLS handshake
                                // is still a per-connection warn! (AU-4).
                                warn!(peer = %peer, error = %e, "TLS handshake failed");
                            }
                            Err(_) => {
                                conn_ctx
                                    .stats
                                    .handshake_timeouts
                                    .fetch_add(1, Ordering::Relaxed);
                                warn!(peer = %peer, "TLS handshake timed out, dropping");
                            }
                        }
                        drop(admission);
                    });
                }
                Err(e) => {
                    if matches!(
                        Self::on_accept_error(&ctx, &mut backoff, &e, "tls").await,
                        AcceptNext::Stop
                    ) {
                        break;
                    }
                }
            }
        }
    }

    /// Receive loop for one accepted stream connection (TCP, TLS or WS).
    ///
    /// Stream transports deliver byte chunks, not datagrams, so messages are
    /// re-framed here via Content-Length (RFC 3261 §18.3) before entering the
    /// SIP stack. Responses go back over this same connection.
    ///
    /// An accepted connection (`egress = None`) is registered in the flow
    /// table for its lifetime so timer re-sends, 408s and in-dialog requests
    /// toward this peer use it (RFC 3261 §18.2.2); a dialled trunk
    /// connection (`egress = Some(key)`) was registered by the table. Either
    /// is removed when the loop ends.
    ///
    /// Activity: only a SIP message that passed the rate limits resets the
    /// idle clock. Bare CRLF keep-alives count only after the connection has
    /// delivered one accepted message (RFC 5626 §4.4.1 flows); before that,
    /// `first_message` applies. Partial-message drips never count.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-10, SI-10
    async fn stream_connection_loop(
        transport: Arc<dyn Transport>,
        peer: SbcSocketAddr,
        ctx: StreamLoopContext,
        egress: Option<FlowKey>,
    ) {
        let mut buf = bytes::BytesMut::new();
        let dialled = egress.is_some();
        let key = egress.unwrap_or_else(|| {
            ctx.flows
                .register_accepted(transport.transport_type(), peer, Arc::clone(&transport));
            (
                transport.transport_type(),
                peer,
                None,
                crate::flow::FlowProfile::Plain,
            )
        });
        // NIST 800-53 Rev5: IA-3, SC-23 — a process-unique id for this
        // connection binds STIR endpoint attestation to it, not to the
        // (reusable, CGNAT) peer address (RFC 5626 §3.1, §5.2).
        let conn_id = crate::stir_binding::ConnId::next();
        // Releases the STIR binding even if this task panics or is aborted.
        let stir_guard = StirConnGuard {
            stack: Some(Arc::clone(&ctx.sip_stack)),
            conn: conn_id,
        };
        let send_ctx = SendCtx {
            flows: Arc::clone(&ctx.flows),
            stats: Arc::clone(&ctx.stats),
            sip_stack: Arc::clone(&ctx.sip_stack),
            origin: Origin::Stream {
                conn: Arc::clone(&transport),
                peer,
                key: key.clone(),
            },
        };
        // RFC 3261 §18.3 / RFC 7118 §5: message-framed WS may omit
        // Content-Length; TCP/TLS may not.
        let require_cl = !matches!(
            transport.transport_type(),
            TransportType::WebSocket | TransportType::WebSocketSecure
        );
        // The reader wakes this often to notice a connection the flow table
        // closed (stalled write, SC-5) and to enforce the deadlines below.
        let tick = std::time::Duration::from_secs(2);
        // A dialled trunk connection already carries our traffic; only an
        // accepted one must prove itself within `first_message`.
        let mut seen_message = dialled;
        let mut last_activity = tokio::time::Instant::now();

        'conn: loop {
            let limit = if seen_message {
                ctx.timeouts.idle
            } else {
                ctx.timeouts.first_message
            };
            if last_activity.elapsed() >= limit {
                warn!(
                    peer = %peer,
                    limit_secs = limit.as_secs(),
                    first_message = !seen_message,
                    "Stream connection idle timeout, closing"
                );
                break;
            }
            match tokio::time::timeout(tick, transport.recv()).await {
                Err(_elapsed) => {
                    if transport.is_closed() {
                        debug!(peer = %peer, "Stream connection closed by the flow table");
                        break;
                    }
                }
                Ok(Ok(chunk)) => {
                    // RFC 7118 §5: one WebSocket message carries exactly
                    // one SIP message, so nothing is carried between WS
                    // messages (the remainder of the previous one was
                    // discarded below).
                    buf.extend_from_slice(&chunk.data);
                    if buf.len() > uc_transport::MAX_STREAM_MESSAGE_SIZE {
                        warn!(
                            peer = %peer,
                            buffered = buf.len(),
                            "No complete SIP message within size limit, closing connection"
                        );
                        break;
                    }

                    loop {
                        let mut keepalive = KeepAlive::default();
                        let next = next_sip_frame(&mut buf, require_cl, &mut keepalive);
                        if keepalive.seen && seen_message {
                            // RFC 5626 §4.4.1: keep-alive on an established flow.
                            last_activity = tokio::time::Instant::now();
                        }
                        if keepalive.pings > 0 && require_cl {
                            // RFC 5626 §4.4.1: answer a double-CRLF ping with
                            // a single CRLF pong (TCP/TLS only; WS uses its
                            // own ping frames). One pong per run of pings,
                            // bounded by the stream write deadline.
                            let _ = tokio::time::timeout(
                                crate::flows::STREAM_WRITE_TIMEOUT,
                                transport.send(b"\r\n", &peer),
                            )
                            .await;
                        }
                        let frame = match next {
                            Ok(Some(frame)) => frame,
                            Ok(None) => {
                                if !require_cl && !buf.is_empty() && &buf[..] != b"\r\n" {
                                    // RFC 7118 §5: an incomplete SIP message
                                    // in a WS message is discarded, never
                                    // spliced onto the next WS message.
                                    Self::discard_partial_ws_message(&peer, &mut buf, &ctx);
                                }
                                break;
                            }
                            Err(e) => {
                                Self::reject_bad_framing(&*transport, &peer, &buf, &e, &ctx).await;
                                break 'conn;
                            }
                        };
                        // PERF-010: stop parsing once the flow table has
                        // closed this connection (stalled write, SC-5).
                        if transport.is_closed() {
                            break;
                        }
                        ctx.stats.messages_received.fetch_add(1, Ordering::Relaxed);

                        if ctx.rate_limit_enabled
                            && !Self::rate_limit_allows(
                                peer.ip(),
                                &ctx.rate_limiter,
                                &ctx.global_limiter,
                                &ctx.stats,
                            )
                            .await
                        {
                            continue;
                        }
                        debug!(
                            source = %peer,
                            size = frame.len(),
                            transport = ?transport.transport_type(),
                            "Received message"
                        );

                        let result = ctx
                            .sip_stack
                            // RFC 3261 §17: responses and forwards ride this
                            // stream, so its transactions use reliable timers.
                            .process_message_conn(
                                &frame,
                                peer,
                                ctx.zone_name.as_deref(),
                                transport.transport_type(),
                                Some(conn_id),
                            )
                            .await;
                        // NIST 800-53 Rev5: SC-10, SC-5 — only a message that
                        // parsed (and was processed) proves the peer speaks
                        // SIP; a well-framed junk frame earns no first-message
                        // or idle credit, so it cannot unlock CRLF keep-alive
                        // credit and hold the connection open.
                        // POAM: POA&M-94 — a request that parses but lacks
                        // mandatory headers still earns credit; closing this
                        // needs sip_stack.rs to report it as an error.
                        if !matches!(result, ProcessResult::Error { .. }) {
                            seen_message = true;
                            last_activity = tokio::time::Instant::now();
                        }
                        // NIST 800-53 Rev5: SC-5 — only a reply back on this
                        // connection is written inline (bounded by the write
                        // deadline); dials and sends to other peers go to
                        // their lanes so this reader keeps reading.
                        Self::dispatch(result, &send_ctx).await;
                    }
                }
                Ok(Err(uc_transport::TransportError::ConnectionClosed)) => {
                    debug!(peer = %peer, "Stream connection closed by peer");
                    break;
                }
                Ok(Err(e)) => {
                    if !ctx.shutdown.is_shutdown_requested() {
                        warn!(peer = %peer, error = %e, "Stream receive error, closing connection");
                    }
                    break;
                }
            }
        }

        // NIST 800-53 Rev5: SC-23, IA-3 — frames are processed inline, so
        // every REGISTER from this connection has finished; release its STIR
        // binding (before the flow is removed) so a later connection on the
        // same address cannot inherit it.
        stir_guard.release().await;
        ctx.flows.remove(&key, &transport);
        let _ = transport.close().await;
    }

    /// Drops the remainder of a WebSocket message that held no complete
    /// SIP message (RFC 7118 §5). The connection stays open: the WS
    /// message boundary resynchronises the stream.
    ///
    /// ## NIST 800-53 Rev5: SI-10, AU-12
    fn discard_partial_ws_message(
        peer: &SbcSocketAddr,
        buf: &mut bytes::BytesMut,
        ctx: &StreamLoopContext,
    ) {
        ctx.stats.framing_errors.fetch_add(1, Ordering::Relaxed);
        ctx.conn_limiter.note_framing_error(peer.ip());
        debug!(
            peer = %peer,
            discarded = buf.len(),
            "Incomplete SIP message in WebSocket message, discarding"
        );
        buf.clear();
    }

    /// Handles a stream framing error: the stream cannot be resynchronised,
    /// so the connection is closed. A request gets a minimal 400 first
    /// (RFC 3261 §21.4.1), written inline under the stream write deadline.
    ///
    /// ## NIST 800-53 Rev5: SI-10
    async fn reject_bad_framing(
        transport: &dyn Transport,
        peer: &SbcSocketAddr,
        buf: &[u8],
        err: &FramingError,
        ctx: &StreamLoopContext,
    ) {
        ctx.stats.framing_errors.fetch_add(1, Ordering::Relaxed);
        ctx.conn_limiter.note_framing_error(peer.ip());
        warn!(peer = %peer, error = %err, "Invalid stream framing, closing connection");
        if let Some(response) = framing_error_response(buf) {
            let _ = tokio::time::timeout(
                crate::flows::STREAM_WRITE_TIMEOUT,
                transport.send(&response, peer),
            )
            .await;
        }
    }

    /// Writes one message on its flow. A reply to the peer the triggering
    /// message came from goes straight back on that socket/connection;
    /// anything else is resolved by the flow table (UDP socket, accepted
    /// connection, or a dialled, certificate-verified trunk connection).
    /// Never retried on another transport.
    ///
    /// ## NIST 800-53 Rev5: SC-8; RFC 3261 §18.1.1, §18.2.2
    async fn send_on_flow(
        ctx: &SendCtx,
        flow: &Flow,
        dest: &SbcSocketAddr,
        bytes: &[u8],
    ) -> Result<(), String> {
        let Flow::Leg(flow) = flow else {
            // process_message_on resolves replies; reaching here is a bug.
            return Err("unresolved reply flow".to_string());
        };
        let udp = match &ctx.origin {
            Origin::Stream { conn, key, .. } if Self::is_origin_reply(&ctx.origin, flow, dest) => {
                return ctx
                    .flows
                    .write(key, conn, bytes, dest)
                    .await
                    .map_err(|e| e.to_string());
            }
            Origin::Udp(u) => Some(u),
            _ => None,
        };
        Self::send_flow_table(ctx, flow, dest, bytes, udp).await
    }

    /// True when `flow`/`dest` is the connection the triggering message
    /// arrived on (no lookup, no dial).
    fn is_origin_reply(origin: &Origin, flow: &LegFlow, dest: &SbcSocketAddr) -> bool {
        matches!(origin, Origin::Stream { conn, peer, .. }
            if flow.dial.is_none() && *peer == *dest && conn.transport_type() == flow.transport)
    }

    /// Puts a result on the wire without letting a stream dial or a slow
    /// stream peer hold the calling loop: UDP sends and replies back on the
    /// origin connection run inline (UDP does not block; the origin write
    /// has the flow table's write deadline), every other stream send is
    /// queued on its destination's lane ([`FlowTable::enqueue`]), which
    /// keeps per-connection order. An origin reply also queues when that
    /// connection's lane has a send queued or running, so it cannot
    /// overtake it (RFC-006). A forwarded INVITE dropped by a full lane is
    /// reported as a failed send so it fails over at once (PERF-007).
    ///
    /// ## NIST 800-53 Rev5: SC-5, CP-8; RFC 3261 §17.1.1.2, §17.2.1 (timer accuracy), §8.1.3.1
    fn dispatch<'a>(
        result: ProcessResult,
        ctx: &'a SendCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let lane = match &result {
                ProcessResult::Multiple(_) => {
                    let ProcessResult::Multiple(results) = result else {
                        return;
                    };
                    for r in results {
                        Self::dispatch(r, ctx).await;
                    }
                    return;
                }
                ProcessResult::Response {
                    destination, flow, ..
                }
                | ProcessResult::Forward {
                    destination, flow, ..
                } => match flow {
                    Flow::Leg(l) if l.transport != uc_types::address::TransportType::Udp => {
                        let key = (l.transport, *destination);
                        (!Self::is_origin_reply(&ctx.origin, l, destination)
                            || ctx.flows.lane_busy(&key))
                        .then_some(key)
                    }
                    _ => None,
                },
                _ => None,
            };
            match lane {
                None => Self::handle_result(result, ctx).await,
                Some(key) => {
                    // Kept only for INVITEs, to report a dropped send.
                    let invite = match &result {
                        ProcessResult::Forward {
                            message: m @ SipMessage::Request(r),
                            ..
                        } if r.method == Method::Invite => Some(m.clone()),
                        _ => None,
                    };
                    // A recording session request (BYE / CANCEL / ACK) lost
                    // to a full recorder lane is a recording drop: TLS has
                    // no retransmission, so the SRS keeps the session until
                    // its own timeout (NIST 800-53 Rev5: SC-5, AU-5).
                    let recorder = matches!(
                        &result,
                        ProcessResult::Forward { flow: Flow::Leg(l), .. } if l.recorder
                    );
                    let job_ctx = ctx.clone();
                    let queued = ctx.flows.enqueue(
                        key,
                        Box::pin(async move {
                            Self::handle_result(result, &job_ctx).await;
                        }),
                    );
                    if !queued && recorder && invite.is_none() {
                        ctx.sip_stack.recording_counters().note_rs_bye_dropped();
                    }
                    if !queued && let Some(invite) = invite {
                        for follow_up in ctx.sip_stack.on_invite_sent(&invite, false).await {
                            Self::dispatch(follow_up, ctx).await;
                        }
                    }
                }
            }
        })
    }

    async fn send_flow_table(
        ctx: &SendCtx,
        flow: &LegFlow,
        dest: &SbcSocketAddr,
        bytes: &[u8],
        udp: Option<&Arc<UdpTransport>>,
    ) -> Result<(), String> {
        ctx.flows
            .send(flow, dest, bytes, udp)
            .await
            .map_err(|e| e.to_string())
    }

    /// Handles a single `ProcessResult`, sending each message on its flow.
    ///
    /// A forwarded INVITE's send outcome goes back to the SIP stack so a
    /// failed first send (including a TLS connect, handshake or certificate
    /// failure) fails over at once (`SipStack::on_invite_sent`); whatever
    /// that yields goes through [`Self::dispatch`], so a stream failover
    /// target is sent on its lane (in order with a later CANCEL) and never
    /// stalls the caller's receive loop.
    fn handle_result<'a>(
        result: ProcessResult,
        ctx: &'a SendCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(Self::handle_result_inner(result, ctx))
    }

    async fn handle_result_inner(result: ProcessResult, ctx: &SendCtx) {
        match result {
            ProcessResult::Response {
                message,
                destination,
                flow,
            } => {
                let response_bytes = message.to_bytes();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    Self::send_on_flow(ctx, &flow, &destination, &response_bytes),
                )
                .await
                {
                    Ok(Ok(())) => {
                        ctx.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        debug!(destination = %destination, "Response sent");
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, destination = %destination, "Failed to send response");
                    }
                    Err(_) => {
                        warn!(destination = %destination, "Send response timed out (30s)");
                    }
                }
            }
            ProcessResult::Forward {
                message,
                destination,
                flow,
            } => {
                // A recording session request (it may carry SDES keys).
                let recorder = matches!(&flow, Flow::Leg(l) if l.recorder);
                let request_bytes = message.to_bytes();
                let sent = match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    Self::send_on_flow(ctx, &flow, &destination, &request_bytes),
                )
                .await
                {
                    Ok(Ok(())) => {
                        ctx.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        debug!(destination = %destination, "Request forwarded");
                        true
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, destination = %destination, "Failed to forward request");
                        false
                    }
                    Err(_) => {
                        warn!(destination = %destination, "Forward request timed out (30s)");
                        false
                    }
                };
                // NIST 800-53 Rev5: CP-8 — RFC 3261 §8.1.3.1 transport errors
                // are reported to the TU.
                //
                // NIST 800-53 Rev5: SC-5 — the failover follow-up (already
                // decided exactly once by on_invite_sent) goes to its lane.
                // NIST 800-53 Rev5: SC-12, SI-12 - the serialized RS request
                // is wiped once written (the TLS layer has its own copy).
                if recorder {
                    wipe_wire_bytes(request_bytes);
                }
                if matches!(&message, SipMessage::Request(r) if r.method == Method::Invite) {
                    // AU-5: a failed RS INVITE is audited as a TLS failure or
                    // an unreachable recorder.
                    let tls_failed = !sent
                        && matches!(&flow, Flow::Leg(l)
                            if l.recorder && ctx.flows.dial_failed_in_handshake(l, &destination));
                    let follow_ups = ctx
                        .sip_stack
                        .on_invite_sent_with(&message, sent, tls_failed)
                        .await;
                    for follow_up in follow_ups {
                        Self::dispatch(follow_up, ctx).await;
                    }
                }
            }
            ProcessResult::Multiple(results) => {
                for sub_result in results {
                    Self::handle_result(sub_result, ctx).await;
                }
            }
            ProcessResult::NoAction => {
                debug!("No action required for message");
            }
            ProcessResult::Error { reason } => {
                warn!(reason = %reason, "Error processing message");
            }
        }
    }

    /// Ticks the SIP stack's transaction timers every 100 ms (a fraction of
    /// T1 = 500 ms) and puts the resulting retransmissions, timeouts and
    /// teardowns on the wire, each on its leg's own flow (POA&M-5: no longer
    /// all on the UDP socket). Like the receive loops it has no shutdown arm:
    /// BYEs sent while draining still need their retransmissions, and
    /// `Server::run` aborts the task once draining completes.
    async fn transaction_timer_loop(ctx: SendCtx) {
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // NIST 800-53 Rev5: SC-5 — stream sends go to their lanes, so
            // a dial or a stalled peer never delays another call's timers.
            for result in ctx.sip_stack.poll_timers().await {
                Self::dispatch(result, &ctx).await;
            }
        }
    }

    /// Health check polling loop.
    async fn health_poll_loop(shutdown: ShutdownSignal, interval: tokio::time::Duration) {
        let mut interval_timer = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    debug!("Health check poll");
                    // In production, would run actual health checks here
                }
                () = shutdown.wait_for_shutdown() => {
                    debug!("Health poll loop shutting down");
                    break;
                }
            }
        }
    }

    /// Shutdown, after the remaining calls were ended: sends the RS BYE /
    /// CANCEL still on the recording wind-down queue on the recorder flow,
    /// for at most `bound`. The timer loop that normally paces them was
    /// aborted when [`Self::run`] returned, so without this they would
    /// never leave the queue. What is not handed to the recorder's lane in
    /// time is counted in `sbc_recording_rs_bye_dropped_total` and logged
    /// once. Returns the number dropped.
    ///
    /// ## NIST 800-53 Rev5: AU-5, SC-5; RFC 3261 §15
    pub async fn flush_recording_wind_down(&self, bound: std::time::Duration) -> usize {
        Self::flush_rs_wind_down(&self.send_ctx(Origin::None), bound).await
    }

    async fn flush_rs_wind_down(ctx: &SendCtx, bound: std::time::Duration) -> usize {
        let deadline = tokio::time::Instant::now() + bound;
        let poll = tokio::time::Duration::from_millis(10);
        let mut lane_stalled = false;
        loop {
            let batch = ctx.sip_stack.recording_shutdown_batch();
            if batch.is_empty() {
                break;
            }
            // The recorder flow is one TLS connection, so one lane.
            let lane = batch.iter().find_map(|r| match r {
                ProcessResult::Forward {
                    destination,
                    flow: Flow::Leg(l),
                    ..
                } => Some((l.transport, *destination)),
                _ => None,
            });
            for r in batch {
                // Queued on the lane (returns at once); a full lane counts
                // the drop itself.
                Self::dispatch(r, ctx).await;
            }
            // The lane sends in order; the next batch (and the return) waits
            // for it to empty so the lane depth is never exceeded.
            let Some(lane) = lane else { continue };
            while ctx.flows.lane_busy(&lane) {
                if tokio::time::Instant::now() >= deadline {
                    lane_stalled = true;
                    break;
                }
                tokio::time::sleep(poll).await;
            }
            if lane_stalled {
                break;
            }
        }
        if lane_stalled {
            warn!(
                bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
                "Recorder send lane still busy at shutdown; queued recording session BYEs may not be sent"
            );
        }
        ctx.sip_stack.recording_shutdown_abandon()
    }

    /// Stops the server gracefully.
    pub async fn stop(&mut self) -> Result<(), ServerError> {
        info!("Stopping SBC daemon");

        // Close all transports
        let transports = self.udp_transports.read().await;
        for transport in transports.iter() {
            if let Err(e) = transport.close().await {
                warn!(error = %e, "Error closing transport");
            }
        }
        drop(transports);

        // Close stream listeners (established connections wind down on
        // their own as peers disconnect or recv fails).
        for listener in self.tcp_listeners.read().await.iter() {
            if let Err(e) = listener.close() {
                warn!(error = %e, "Error closing TCP listener");
            }
        }
        for listener in self.tls_listeners.read().await.iter() {
            if let Err(e) = listener.close() {
                warn!(error = %e, "Error closing TLS listener");
            }
        }

        info!(
            messages_received = self.stats.messages_received.load(Ordering::Relaxed),
            messages_sent = self.stats.messages_sent.load(Ordering::Relaxed),
            "SBC daemon stopped"
        );
        Ok(())
    }

    /// Performs a health check.
    pub fn check_health(&mut self) -> uc_health::SystemHealth {
        self.health.check()
    }

    /// Returns whether the server is ready to accept traffic.
    pub fn is_ready(&mut self) -> bool {
        self.health.is_ready()
    }

    /// Returns whether the server is alive.
    pub fn is_alive(&self) -> bool {
        self.health.is_alive()
    }
}

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Total calls processed.
    pub calls_total: AtomicU64,
    /// Currently active calls.
    pub calls_active: AtomicU64,
    /// Total registrations.
    pub registrations_total: AtomicU64,
    /// Active registrations.
    pub registrations_active: AtomicU64,
    /// Messages received.
    pub messages_received: AtomicU64,
    /// Messages sent.
    pub messages_sent: AtomicU64,
    /// Messages rejected due to rate limiting.
    pub rate_limited: AtomicU64,
    /// Transport receive loops still running. Set to the bound-transport
    /// count at startup and decremented when a loop dies abnormally
    /// (persistent recv errors). Readiness flips to not-ready at 0 so a
    /// daemon deaf on all transports stops reporting healthy.
    pub live_transports: AtomicU64,
    /// Stream connections closed for invalid Content-Length framing
    /// (SI-10).
    pub framing_errors: AtomicU64,
    /// Stream accepts dropped by `transport.max_connections_per_source`.
    pub conn_rejected_per_source: AtomicU64,
    /// Stream accepts dropped by `transport.max_connections_per_v6_aggregate`
    /// or `transport.max_connections_per_v4_24` (SR-58).
    pub conn_rejected_per_aggregate: AtomicU64,
    /// WebSocket upgrades refused or failed (e.g. no `sip` subprotocol).
    pub ws_handshake_failures: AtomicU64,
    /// TLS / WebSocket handshakes that hit `handshake_timeout_secs`.
    // POAM: POA&M-93 — these counters and the accept counters below are
    // not yet exported on the REST/metrics API (api_server.rs is owned
    // elsewhere); visible via the stats Debug output only (SI-4).
    pub handshake_timeouts: AtomicU64,
    /// Stream `accept()` errors other than resource exhaustion (backed
    /// off only after a long run with no successful accept).
    pub accept_errors: AtomicU64,
    /// Stream `accept()` errors from resource exhaustion (backed off).
    pub accept_resource_errors: AtomicU64,
    /// Stream accepts dropped because the source is blocked.
    pub accept_blocked: AtomicU64,
    /// Stream accepts dropped by `transport.accept_rate_per_source`.
    pub accept_rate_limited: AtomicU64,
    /// TLS accepts dropped by `transport.max_handshakes_per_source`.
    pub handshake_busy_per_source: AtomicU64,
    /// TLS accepts dropped by the per-aggregate handshake cap (SR-58).
    pub handshake_busy_per_aggregate: AtomicU64,
    /// TLS connections dropped because no node-wide handshake slot
    /// (`transport.max_handshakes_in_flight`) freed within the slot wait.
    pub handshake_slot_timeouts: AtomicU64,
    /// TLS connections dropped because their handshake held a node-wide
    /// slot for the hold budget (`min(2 s, handshake_timeout_secs / 2)`)
    /// without finishing.
    pub handshake_slot_hold_timeouts: AtomicU64,
}

/// Server error.
#[derive(Debug)]
pub enum ServerError {
    /// Failed to bind to address.
    BindFailed {
        /// Address that failed.
        address: String,
        /// Error reason.
        reason: String,
    },
    /// Configuration error.
    ConfigError {
        /// Error message.
        message: String,
    },
    /// Transport error.
    TransportError {
        /// Error message.
        message: String,
    },
    /// Internal error.
    InternalError {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed { address, reason } => {
                write!(f, "Failed to bind to {address}: {reason}")
            }
            Self::ConfigError { message } => {
                write!(f, "Configuration error: {message}")
            }
            Self::TransportError { message } => {
                write!(f, "Transport error: {message}")
            }
            Self::InternalError { message } => {
                write!(f, "Internal error: {message}")
            }
        }
    }
}

impl std::error::Error for ServerError {}

/// Why a stream could not be framed. The connection is closed: once two
/// parties may disagree on a message boundary the stream cannot be
/// resynchronised (request smuggling).
#[derive(Debug)]
enum FramingError {
    /// No Content-Length on a stream transport (RFC 3261 §18.3, §20.14).
    Missing,
    /// Duplicate, malformed or oversized Content-Length, or a malformed
    /// header block (RFC 3261 §7.3.1, §20.14).
    Invalid(proto_sip::SipError),
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("missing Content-Length on a stream transport"),
            Self::Invalid(e) => write!(f, "{e}"),
        }
    }
}

/// Keep-alive CRLFs consumed by one [`next_sip_frame`] call.
#[derive(Debug, Default, Clone, Copy)]
struct KeepAlive {
    /// Any keep-alive CRLF was consumed.
    seen: bool,
    /// Double-CRLF pings consumed (RFC 5626 §4.4.1).
    pings: u32,
}

/// Extracts the next complete SIP message from a stream reassembly buffer.
///
/// SIP over stream transports is framed by Content-Length (RFC 3261 §18.3):
/// a message is complete at end-of-headers (`\r\n\r\n`) plus the declared
/// body length. The length comes from
/// [`SipMessage::stream_message_len`], so the framer and the parser apply
/// identical header rules (duplicates, compact `l`, `1*DIGIT`) and cannot
/// cut at different offsets.
///
/// Leading CRLFs (RFC 5626 keep-alive pings/pongs) are discarded and
/// reported through `keepalive`: each `CRLFCRLF` is a ping that the caller
/// answers on TCP/TLS; a lone CRLF (a pong) is discarded once more bytes
/// follow it, so a ping split across reads is still recognised. With `require_cl` false
/// (message-framed WebSocket, RFC 7118 §5) a missing Content-Length means
/// the body is the rest of the buffer; a duplicate or malformed one is
/// still an error.
///
/// Returns `Ok(None)` until a full message is buffered.
///
/// ## NIST 800-53 Rev5: SI-10
fn next_sip_frame(
    buf: &mut bytes::BytesMut,
    require_cl: bool,
    keepalive: &mut KeepAlive,
) -> Result<Option<bytes::Bytes>, FramingError> {
    // Discard keep-alive CRLFs between messages.
    loop {
        if buf.starts_with(b"\r\n\r\n") {
            let _ = buf.split_to(4);
            keepalive.seen = true;
            keepalive.pings = keepalive.pings.saturating_add(1);
        } else if buf.starts_with(b"\r\n") && buf.len() > 2 {
            let _ = buf.split_to(2);
            keepalive.seen = true;
        } else {
            break;
        }
    }
    if buf.is_empty() || &buf[..] == b"\r\n" {
        return Ok(None);
    }

    let Some(headers_end) = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|p| p.checked_add(4))
    else {
        return Ok(None);
    };
    let total = match SipMessage::stream_message_len(&buf[..headers_end]) {
        Ok(total) => total,
        Err(proto_sip::SipError::MissingHeader { name })
            if name.eq_ignore_ascii_case("content-length") =>
        {
            if require_cl {
                return Err(FramingError::Missing);
            }
            buf.len()
        }
        Err(e) => return Err(FramingError::Invalid(e)),
    };
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(buf.split_to(total).freeze()))
}

/// Builds a minimal `400 Bad Request` for a request whose framing failed,
/// or `None` for a response or an unparseable head (then the connection is
/// closed silently).
///
/// Only Via/From/To/Call-ID/CSeq are taken from the request, and only after
/// they pass the proto-sip parser, so nothing else from the hostile message
/// is echoed.
///
/// ## NIST 800-53 Rev5: SI-10; RFC 3261 §8.2.6.2, §21.4.1
fn framing_error_response(buf: &[u8]) -> Option<bytes::Bytes> {
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = buf.get(..head_end)?;
    let mut lines = head.split(|&b| b == b'\n');
    let start = lines.next()?;
    if start.starts_with(b"SIP/2.0") {
        return None;
    }
    let mut sanitized = Vec::with_capacity(head.len().min(4096) + 32);
    sanitized.extend_from_slice(start.strip_suffix(b"\r").unwrap_or(start));
    sanitized.extend_from_slice(b"\r\n");
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line.get(..colon)?.trim_ascii();
        let keep = [
            &b"via"[..],
            b"v",
            b"from",
            b"f",
            b"to",
            b"t",
            b"call-id",
            b"i",
            b"cseq",
        ]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n));
        if keep {
            sanitized.extend_from_slice(line);
            sanitized.extend_from_slice(b"\r\n");
        }
    }
    sanitized.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    let SipMessage::Request(req) =
        SipMessage::parse_with(&sanitized, proto_sip::message::Framing::Datagram).ok()?
    else {
        return None;
    };
    let mut resp = proto_sip::message::SipResponse::new(proto_sip::StatusCode::BAD_REQUEST);
    for via in req.headers.get_all(&proto_sip::HeaderName::Via) {
        resp.add_header(proto_sip::Header::new(
            proto_sip::HeaderName::Via,
            &via.value,
        ));
    }
    if let Some(from) = req.headers.get_value(&proto_sip::HeaderName::From) {
        resp.add_header(proto_sip::Header::new(proto_sip::HeaderName::From, from));
    }
    if let Some(to) = req.headers.get_value(&proto_sip::HeaderName::To) {
        let to = if to.contains("tag=") {
            to.to_string()
        } else {
            format!("{to};tag={}", proto_sip::builder::generate_tag())
        };
        resp.add_header(proto_sip::Header::new(proto_sip::HeaderName::To, to));
    }
    if let Some(call_id) = req.headers.call_id() {
        resp.add_header(proto_sip::Header::new(
            proto_sip::HeaderName::CallId,
            call_id,
        ));
    }
    if let Some(cseq) = req.headers.cseq() {
        resp.add_header(proto_sip::Header::new(proto_sip::HeaderName::CSeq, cseq));
    }
    resp.add_header(proto_sip::Header::new(
        proto_sip::HeaderName::ContentLength,
        "0",
    ));
    Some(resp.to_bytes())
}

/// Accumulates rate-limit rejections between audit flushes and emits them
/// as bounded, aggregated `RateLimitTriggered` records.
///
/// ## NIST 800-53 Rev5: AU-4, AU-12, SC-5
#[derive(Debug)]
struct RateLimitAudit {
    /// Per-source rejections (`per_ip_rps`, `per_ip_conn`), at most
    /// `max_records` keys.
    pending: std::collections::HashMap<(std::net::IpAddr, &'static str), u64>,
    /// Trusted-trunk rejections (`trunk_rps_udp`, `trunk_rps_stream`),
    /// kept apart from `pending` so a flood of per-source records across
    /// the sweeps of one audit interval cannot crowd them out. At most
    /// [`Self::MAX_TRUNK_RECORDS`] keys: one per trusted address per
    /// limiter.
    trunk_pending: std::collections::HashMap<(std::net::IpAddr, &'static str), u64>,
    /// Rejections whose source did not fit in `pending` (or, after a
    /// trusted-set change within the interval, `trunk_pending`).
    suppressed_count: u64,
    /// Number of drained (source, count) entries folded into
    /// `suppressed_count` (upper bound on distinct sources).
    suppressed_sources: u64,
    global: u64,
    overflow: u64,
    /// Accepts dropped on a full listener pool.
    listener_full: u64,
    /// Accepts dropped on the full node-wide pool.
    total_full: u64,
    max_records: usize,
    per_ip_rps: u64,
    global_rps: u64,
    overflow_rps: u64,
    per_source_conns: u64,
    /// Effective `trunk_rps` (threshold of `trunk_rps` records).
    trunk_rps: u64,
    accept_rate: u64,
    per_source_handshakes: u64,
    /// Threshold of `per_prefix_conn` records for IPv6 aggregates.
    v6_aggregate_conns: u64,
    /// Threshold of `per_prefix_conn` records for IPv4 /24s.
    v4_aggregate_conns: u64,
    /// Threshold of `per_prefix_accept_rate` records.
    aggregate_accept_rate: u64,
    /// Threshold of `per_prefix_handshake_busy` records.
    aggregate_handshakes: u64,
}

impl RateLimitAudit {
    /// Bound on `trunk_pending`: [`uc_dos_protection::MAX_TRUSTED_SOURCES`]
    /// addresses on each of the two per-source limiters (SC-5).
    const MAX_TRUNK_RECORDS: usize = 2 * uc_dos_protection::MAX_TRUSTED_SOURCES;

    fn new(config: &SbcConfig) -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            trunk_pending: std::collections::HashMap::new(),
            suppressed_count: 0,
            suppressed_sources: 0,
            global: 0,
            overflow: 0,
            listener_full: 0,
            total_full: 0,
            max_records: config.rate_limit.audit_max_records_per_interval as usize,
            per_ip_rps: u64::from(config.rate_limit.per_ip_rps),
            global_rps: u64::from(config.rate_limit.global_rps),
            overflow_rps: u64::from(config.rate_limit.effective_overflow_rps()),
            per_source_conns: u64::from(config.transport.max_connections_per_source),
            trunk_rps: u64::from(config.rate_limit.effective_trunk_rps()),
            accept_rate: u64::from(config.transport.accept_rate_per_source),
            // Effective cap (after the clamp), the limit actually enforced.
            per_source_handshakes: u64::from(
                HandshakeLimits::from_config(&config.transport).per_source,
            ),
            v6_aggregate_conns: u64::from(
                config
                    .transport
                    .effective_max_connections_per_v6_aggregate(),
            ),
            v4_aggregate_conns: u64::from(config.transport.effective_max_connections_per_v4_24()),
            aggregate_accept_rate: u64::from(
                config
                    .transport
                    .accept_rate_per_source
                    .saturating_mul(crate::conn_limit::AGGREGATE_ACCEPT_FACTOR),
            ),
            aggregate_handshakes: u64::from(aggregate_handshake_cap(
                HandshakeLimits::from_config(&config.transport).slots,
            )),
        }
    }

    /// Adds `count` rejections for `(source, limit)`.
    fn add(&mut self, source: std::net::IpAddr, limit: &'static str, count: u64) {
        if let Some(n) = self.pending.get_mut(&(source, limit)) {
            *n = n.saturating_add(count);
        } else if self.pending.len() < self.max_records {
            self.pending.insert((source, limit), count);
        } else {
            self.suppressed_count = self.suppressed_count.saturating_add(count);
            self.suppressed_sources = self.suppressed_sources.saturating_add(1);
        }
    }

    /// Adds `count` trusted-trunk rejections for `(source, limit)`. Not
    /// subject to `audit_max_records_per_interval`; bounded by
    /// [`Self::MAX_TRUNK_RECORDS`] instead.
    // NIST 800-53 Rev5: AU-12, SC-5 — trunk records always reach the log.
    fn add_trunk(&mut self, source: std::net::IpAddr, limit: &'static str, count: u64) {
        if let Some(n) = self.trunk_pending.get_mut(&(source, limit)) {
            *n = n.saturating_add(count);
        } else if self.trunk_pending.len() < Self::MAX_TRUNK_RECORDS {
            self.trunk_pending.insert((source, limit), count);
        } else {
            // Only reachable when the trusted set changed within the
            // interval; still counted in the suppressed summary.
            self.suppressed_count = self.suppressed_count.saturating_add(count);
            self.suppressed_sources = self.suppressed_sources.saturating_add(1);
        }
    }

    /// One pass over the `kind` per-source limiter: aggregates rejections
    /// and blocked drops, evicts idle buckets and expired blocks, and
    /// pushes each ended block onto `unblocked`.
    fn sweep_per_ip(
        &mut self,
        limiter: &mut RateLimiter,
        kind: LimiterKind,
        unblocked: &mut Vec<std::net::IpAddr>,
    ) {
        let trunk_label = match kind {
            LimiterKind::Udp => "trunk_rps_udp",
            LimiterKind::Stream => "trunk_rps_stream",
        };
        let _ = limiter.sweep_with(|event| match event {
            SweepEvent::Rejected(key, n) => self.add(key, "per_ip_rps", n),
            SweepEvent::BlockedDrops(key, n) => self.add(key, "per_ip_blocked_drops", n),
            SweepEvent::Unblocked(key) => unblocked.push(key),
            // NIST 800-53 Rev5: AU-12 — a trusted trunk over its own
            // bucket, by exact address and transport family.
            SweepEvent::TrustedRejected(ip, n) => self.add_trunk(ip, trunk_label, n),
        });
        self.overflow = self
            .overflow
            .saturating_add(limiter.take_overflow_rejections());
    }

    /// Drains the per-source limiter's counters without evicting.
    #[cfg(test)]
    fn collect_per_ip(&mut self, limiter: &mut RateLimiter) {
        limiter.drain_rejections(|key, n| self.add(key, "per_ip_rps", n));
        self.overflow = self
            .overflow
            .saturating_add(limiter.take_overflow_rejections());
    }

    /// Drains the global limiter's counter.
    fn collect_global(&mut self, limiter: &mut RateLimiter) {
        self.global = self.global.saturating_add(limiter.take_global_rejections());
    }

    /// Drains the connection limiter's counters.
    fn collect_conns(&mut self, limiter: &crate::conn_limit::ConnLimiter) {
        // Thresholds come from the limiter, which holds the effective caps.
        self.v6_aggregate_conns = u64::from(limiter.v6_aggregate_cap());
        self.v4_aggregate_conns = u64::from(limiter.v4_aggregate_cap());
        self.aggregate_accept_rate = u64::from(limiter.aggregate_accept_rate());
        self.aggregate_handshakes = u64::from(limiter.max_handshakes_per_aggregate());
        let totals = limiter.drain_rejections(|key, kind, n| {
            let limit = match kind {
                crate::conn_limit::Rejection::PerSource => "per_ip_conn",
                crate::conn_limit::Rejection::PerAggregate => "per_prefix_conn",
                crate::conn_limit::Rejection::Framing => "framing",
                crate::conn_limit::Rejection::AcceptRate => "per_ip_accept_rate",
                crate::conn_limit::Rejection::AggregateAcceptRate => "per_prefix_accept_rate",
                crate::conn_limit::Rejection::HandshakeBusy => "handshake_busy",
                crate::conn_limit::Rejection::AggregateHandshakeBusy => "per_prefix_handshake_busy",
                crate::conn_limit::Rejection::AcceptBlocked => "accept_blocked",
            };
            self.add(key, limit, n);
        });
        if totals.untracked > 0 {
            self.suppressed_count = self.suppressed_count.saturating_add(totals.untracked);
            self.suppressed_sources = self.suppressed_sources.saturating_add(1);
        }
        self.listener_full = self.listener_full.saturating_add(totals.listener_full);
        self.total_full = self.total_full.saturating_add(totals.total_full);
    }

    /// Drains the connection limiter's counters, then evicts idle accept
    /// buckets (picking up any accept-rate rejections counted in between).
    fn sweep_conns(&mut self, limiter: &crate::conn_limit::ConnLimiter) {
        self.collect_conns(limiter);
        limiter.sweep_accept(|key, kind, n| {
            let limit = if kind == crate::conn_limit::Rejection::AggregateAcceptRate {
                "per_prefix_accept_rate"
            } else {
                "per_ip_accept_rate"
            };
            self.add(key, limit, n);
        });
    }

    /// Emits one record per pending (source, limit), the global and
    /// overflow totals, and one summary for anything suppressed; then
    /// resets. At most `max_records + MAX_TRUNK_RECORDS + 5` records per
    /// flush; trunk records are emitted first.
    // POAM: POA&M-92 — global/overflow records carry the placeholder
    // sources 0.0.0.0 / :: because RateLimitTriggered requires a source
    // address; a dedicated aggregate event needs a uc-audit change (AU-3).
    fn flush(&mut self) {
        for ((source, limit), count) in self.trunk_pending.drain() {
            audit_rate_limit(source, limit, count, self.trunk_rps);
        }
        for ((source, limit), count) in self.pending.drain() {
            let threshold = match limit {
                "per_ip_conn" => self.per_source_conns,
                "per_ip_accept_rate" => self.accept_rate,
                "handshake_busy" => self.per_source_handshakes,
                "per_prefix_conn" if source.is_ipv4() => self.v4_aggregate_conns,
                "per_prefix_conn" => self.v6_aggregate_conns,
                "per_prefix_accept_rate" => self.aggregate_accept_rate,
                "per_prefix_handshake_busy" => self.aggregate_handshakes,
                "framing" | "accept_blocked" => 0,
                _ => self.per_ip_rps,
            };
            audit_rate_limit(source, limit, count, threshold);
        }
        if self.global > 0 {
            audit_rate_limit(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "global_rps",
                std::mem::take(&mut self.global),
                self.global_rps,
            );
        }
        if self.overflow > 0 {
            audit_rate_limit(
                std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                "overflow_rps",
                std::mem::take(&mut self.overflow),
                self.overflow_rps,
            );
        }
        for (name, count) in [
            ("listener_conn", std::mem::take(&mut self.listener_full)),
            ("total_conn", std::mem::take(&mut self.total_full)),
        ] {
            if count > 0 {
                warn!(
                    limit = name,
                    dropped = count,
                    "Stream connection pool full; accepts dropped this interval"
                );
                audit_rate_limit(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), name, count, 0);
            }
        }
        if self.suppressed_count > 0 {
            audit_rate_limit(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "per_ip_rps_suppressed",
                std::mem::take(&mut self.suppressed_count),
                std::mem::take(&mut self.suppressed_sources),
            );
        }
    }
}

/// Periodic limiter maintenance: expired blocks (audited as
/// `per_ip_unblock`), idle buckets, and the aggregated rate-limit audit.
///
/// Locks one limiter at a time and never holds a lock across an audit write.
///
/// ## NIST 800-53 Rev5: SC-5, AU-4, AU-12
struct RateLimitMaintenance {
    shutdown: ShutdownSignal,
    /// Per-source limiters (stream, then UDP) and the transport family
    /// each serves, swept one at a time.
    per_ip_limiters: Vec<(LimiterKind, Arc<Mutex<RateLimiter>>)>,
    global_limiter: Arc<Mutex<RateLimiter>>,
    conn_limiter: Arc<crate::conn_limit::ConnLimiter>,
    sweep_interval: std::time::Duration,
    audit_interval: std::time::Duration,
    audit: RateLimitAudit,
    /// Reused buffer of sources whose block ended this sweep.
    unblocked: Vec<std::net::IpAddr>,
}

impl RateLimitMaintenance {
    fn new(
        config: &SbcConfig,
        shutdown: ShutdownSignal,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        global_limiter: Arc<Mutex<RateLimiter>>,
        conn_limiter: Arc<crate::conn_limit::ConnLimiter>,
    ) -> Self {
        Self {
            shutdown,
            per_ip_limiters: vec![(LimiterKind::Stream, rate_limiter)],
            global_limiter,
            conn_limiter,
            sweep_interval: std::time::Duration::from_secs(config.rate_limit.sweep_interval_secs),
            audit_interval: std::time::Duration::from_secs(config.rate_limit.audit_interval_secs),
            audit: RateLimitAudit::new(config),
            unblocked: Vec::new(),
        }
    }

    /// Adds another per-source limiter, serving `kind`, to the sweep.
    fn with_per_ip_limiter(mut self, kind: LimiterKind, limiter: Arc<Mutex<RateLimiter>>) -> Self {
        self.per_ip_limiters.push((kind, limiter));
        self
    }

    /// One sweep; flushes the audit aggregate when `flush` is set.
    async fn sweep(&mut self, flush: bool) {
        for (kind, limiter) in &self.per_ip_limiters {
            let mut limiter = limiter.lock().await;
            // One pass: counts are reported before an idle bucket is evicted.
            self.audit
                .sweep_per_ip(&mut limiter, *kind, &mut self.unblocked);
        }
        {
            let mut global = self.global_limiter.lock().await;
            self.audit.collect_global(&mut global);
        }
        self.audit.sweep_conns(&self.conn_limiter);
        for key in self.unblocked.drain(..) {
            audit_rate_limit(key, "per_ip_unblock", 0, self.audit.per_ip_rps);
        }
        if flush {
            self.audit.flush();
        }
    }

    async fn run(mut self) {
        let mut tick = tokio::time::interval(self.sweep_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_flush = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let flush = last_flush.elapsed() >= self.audit_interval;
                    if flush {
                        last_flush = tokio::time::Instant::now();
                    }
                    self.sweep(flush).await;
                }
                () = self.shutdown.wait_for_shutdown() => {
                    self.sweep(true).await;
                    debug!("Rate-limit maintenance loop shutting down");
                    break;
                }
            }
        }
    }
}

/// Builds the DTLS-SRTP fingerprint source for terminate mode.
///
/// Sidecar architecture: the Go terminator publishes its fingerprint to a file,
/// which is re-read live so a sidecar restart is picked up. Falls back to an
/// operator cert/key or a self-signed cert (fixed fingerprint) only for the
/// legacy in-Rust DTLS path. **Fail-closed**: panics if termination is
/// configured but no valid identity is available — starting half-configured
/// would silently black-hole every secured call.
fn build_dtls_fingerprint_source(
    dtls: &sbc_config::schema::DtlsConfig,
) -> sbc_media_core::dtls_identity::DtlsFingerprintSource {
    use sbc_media_core::dtls_identity::{DtlsFingerprintSource, DtlsIdentity};

    // map_or_else with the nested cert/key match reads worse than this.
    #[allow(clippy::option_if_let_else)]
    let built = if let Some(fp_file) = &dtls.fingerprint_file {
        DtlsFingerprintSource::from_file(fp_file)
    } else {
        let identity = match (&dtls.cert_path, &dtls.key_path) {
            (Some(cert), Some(key)) => DtlsIdentity::from_pem_files(cert, key),
            _ => DtlsIdentity::generate(),
        };
        identity.map(|id| DtlsFingerprintSource::from_static(id.sdp_fingerprint().to_string()))
    };

    match built {
        Ok(source) => source,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build DTLS identity — aborting startup");
            #[allow(clippy::panic)]
            {
                panic!("DTLS-SRTP termination configured but identity unavailable: {e}");
            }
        }
    }
}

/// Releases a stream connection's STIR flow binding when its receive loop
/// ends. Normal exit awaits [`Self::release`] (ordered before the flow-table
/// removal); on panic or task abort, `Drop` spawns the release instead.
///
/// NIST 800-53 Rev5: SC-23 (Session Authenticity), IA-3
struct StirConnGuard {
    stack: Option<Arc<SipStack>>,
    conn: crate::stir_binding::ConnId,
}

impl StirConnGuard {
    async fn release(mut self) {
        if let Some(stack) = self.stack.take() {
            stack.connection_closed(self.conn).await;
        }
    }
}

impl Drop for StirConnGuard {
    fn drop(&mut self) {
        if let Some(stack) = self.stack.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let conn = self.conn;
            drop(rt.spawn(async move { stack.connection_closed(conn).await }));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// Writes a fresh PKCS#8 EC key with mode 0600 into `dir`.
    #[cfg(unix)]
    fn write_ec_key(
        dir: &std::path::Path,
        name: &str,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let kp = rcgen::KeyPair::generate_for(alg).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, kp.serialize_pem()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn key_ops(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::CryptoKeyOperation> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CryptoKeyOperation(k) => Some(k.clone()),
                _ => None,
            })
            .collect()
    }

    /// POA&M-166: the daemon TLS key loader enforces `security.curve` and
    /// audits success and failure.
    #[cfg(unix)]
    #[test]
    fn tls_key_load_enforces_curve_and_audits_outcome() {
        use uc_audit::event::{KeyOperationOutcome, KeyOperationType};
        use uc_types::protocol::CnsaCurve;
        let dir = tempfile::tempdir().unwrap();
        let p384 = write_ec_key(dir.path(), "p384.key", &rcgen::PKCS_ECDSA_P384_SHA384);
        let capture = uc_audit::capture::start();

        assert!(load_tls_key_audited("sip-tls-listener", &p384, CnsaCurve::P384).is_ok());
        let err = load_tls_key_audited("trunk-mtls-client", &p384, CnsaCurve::P521);
        assert!(
            err.is_err(),
            "P-384 key must be rejected under P-521 config"
        );

        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].key_id, "sip-tls-listener:p384.key");
        assert_eq!(ops[0].operation, KeyOperationType::Loaded);
        assert_eq!(ops[0].outcome, KeyOperationOutcome::Success);
        assert_eq!(ops[0].algorithm, "ECDSA-P384");
        assert_eq!(ops[1].key_id, "trunk-mtls-client:p384.key");
        assert_eq!(ops[1].outcome, KeyOperationOutcome::Failure);
        assert_eq!(ops[1].algorithm, "ECDSA-P521");
        let reason = ops[1].reason.as_deref().unwrap();
        assert!(reason.contains("curve"), "{reason}");
        assert!(
            !reason.contains(dir.path().to_string_lossy().as_ref()),
            "reason must not carry the key path"
        );
    }

    /// QA: reverse curve mismatch (P-521 key under P-384 baseline) also
    /// fails closed; P-521 key under P-521 config succeeds. One event each.
    #[test]
    fn qa_tls_key_load_p521_key_curve_matrix() {
        use uc_audit::event::KeyOperationOutcome;
        use uc_types::protocol::CnsaCurve;
        let dir = tempfile::tempdir().unwrap();
        let p521 = write_ec_key(dir.path(), "p521.key", &rcgen::PKCS_ECDSA_P521_SHA512);
        let capture = uc_audit::capture::start();
        assert!(load_tls_key_audited("sip-tls-listener", &p521, CnsaCurve::P384).is_err());
        assert!(load_tls_key_audited("sip-tls-listener", &p521, CnsaCurve::P521).is_ok());
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].outcome, KeyOperationOutcome::Failure);
        assert_eq!(ops[0].algorithm, "ECDSA-P384");
        assert_eq!(ops[1].outcome, KeyOperationOutcome::Success);
        assert_eq!(ops[1].algorithm, "ECDSA-P521");
        assert!(ops[1].reason.is_none());
    }

    /// QA: missing-file failure reason carries neither the directory path
    /// nor CR/LF.
    #[test]
    fn qa_tls_key_load_missing_file_reason_sanitized() {
        let capture = uc_audit::capture::start();
        let r = load_tls_key_audited(
            "trunk-mtls-client",
            std::path::Path::new("/qa-secret-dir/sub/client.key"),
            uc_types::protocol::CnsaCurve::P384,
        );
        assert!(r.is_err());
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].key_id, "trunk-mtls-client:client.key");
        let reason = ops[0].reason.as_deref().unwrap_or("");
        assert!(!reason.contains('\n') && !reason.contains('\r'));
        assert!(!reason.contains("/qa-secret-dir"), "{reason}");
    }

    /// A missing key file is a failure event too (fail closed, audited).
    #[test]
    fn tls_key_load_missing_file_audits_failure() {
        let capture = uc_audit::capture::start();
        let r = load_tls_key_audited(
            "sip-tls-listener",
            std::path::Path::new("/nonexistent/sbc-test.key"),
            uc_types::protocol::CnsaCurve::P384,
        );
        assert!(r.is_err());
        let ops = key_ops(&capture.events());
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0].outcome,
            uc_audit::event::KeyOperationOutcome::Failure
        );
    }
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown, None);

        assert_eq!(server.config().general.instance_name, "sbc-01");
    }

    #[tokio::test]
    async fn test_server_health() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let mut server = Server::new(config, shutdown, None);

        assert!(server.is_alive());
        assert!(server.is_ready());

        let health = server.check_health();
        assert!(health.is_healthy());
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown, None);

        assert_eq!(server.stats().calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(server.stats().messages_received.load(Ordering::Relaxed), 0);

        server
            .stats()
            .messages_received
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(server.stats().messages_received.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_sbc_socket_addr_conversion() {
        // Test that SocketAddr converts to SbcSocketAddr correctly
        let socket_addr: std::net::SocketAddr = "[::]:5060".parse().unwrap();
        let sbc_addr = SbcSocketAddr::from(socket_addr);
        assert_eq!(sbc_addr.port(), 5060);

        let socket_addr: std::net::SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let sbc_addr = SbcSocketAddr::from(socket_addr);
        assert_eq!(sbc_addr.port(), 5060);
    }

    const REGISTER: &[u8] = b"REGISTER sip:example.mil SIP/2.0\r\n\
        Via: SIP/2.0/TLS host:5061;branch=z9hG4bK1\r\n\
        Content-Length: 0\r\n\
        \r\n";

    /// Frames with stream (Content-Length required) rules.
    fn frame(buf: &mut bytes::BytesMut) -> Option<bytes::Bytes> {
        let mut ka = KeepAlive::default();
        next_sip_frame(buf, true, &mut ka).expect("valid framing")
    }

    fn frame_err(msg: &[u8], require_cl: bool) -> FramingError {
        let mut buf = bytes::BytesMut::from(msg);
        let mut ka = KeepAlive::default();
        next_sip_frame(&mut buf, require_cl, &mut ka).expect_err("framing error")
    }

    #[test]
    fn frame_complete_message() {
        let mut buf = bytes::BytesMut::from(REGISTER);
        let frame_bytes = frame(&mut buf).expect("complete message");
        assert_eq!(&frame_bytes[..], REGISTER);
        assert!(buf.is_empty());
        assert!(frame(&mut buf).is_none());
    }

    #[test]
    fn frame_waits_for_full_body() {
        let msg = b"MESSAGE sip:example.mil SIP/2.0\r\nContent-Length: 5\r\n\r\nhel";
        let mut buf = bytes::BytesMut::from(&msg[..]);
        assert!(frame(&mut buf).is_none());
        buf.extend_from_slice(b"lo");
        let f = frame(&mut buf).expect("complete after body");
        assert!(f.ends_with(b"hello"));
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_splits_pipelined_messages_and_skips_keepalives() {
        let mut buf = bytes::BytesMut::new();
        buf.extend_from_slice(b"\r\n\r\n"); // RFC 5626 keep-alive ping
        buf.extend_from_slice(REGISTER);
        buf.extend_from_slice(REGISTER);
        let mut ka = KeepAlive::default();
        let first = next_sip_frame(&mut buf, true, &mut ka).unwrap().unwrap();
        assert!(ka.seen);
        assert_eq!(first.len(), REGISTER.len());
        assert_eq!(frame(&mut buf).expect("second").len(), REGISTER.len());
        assert!(frame(&mut buf).is_none());
    }

    #[test]
    fn frame_partial_headers_returns_none() {
        let mut buf = bytes::BytesMut::from(&b"REGISTER sip:example.mil SIP/2.0\r\nVia: x"[..]);
        assert!(frame(&mut buf).is_none());
        assert!(!buf.is_empty()); // kept for the next chunk
    }

    #[test]
    fn content_length_compact_form() {
        let msg = b"MESSAGE sip:a SIP/2.0\r\nl: 7\r\n\r\n1234567";
        let mut buf = bytes::BytesMut::from(&msg[..]);
        assert_eq!(frame(&mut buf).unwrap().len(), msg.len());
    }

    #[test]
    fn duplicate_content_length_rejected() {
        let equal = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            frame_err(equal, true),
            FramingError::Invalid(proto_sip::SipError::DuplicateHeader { .. })
        ));
        let conflicting = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 5\r\nl: 7\r\n\r\n";
        assert!(matches!(
            frame_err(conflicting, true),
            FramingError::Invalid(proto_sip::SipError::DuplicateHeader { .. })
        ));
        // Still rejected on message-framed WS.
        assert!(matches!(
            frame_err(conflicting, false),
            FramingError::Invalid(_)
        ));
    }

    #[test]
    fn malformed_content_length_rejected() {
        for value in ["-1", "5x", "+5", "", "12345678901", "70000"] {
            let msg = format!("OPTIONS sip:a SIP/2.0\r\nContent-Length: {value}\r\n\r\n");
            assert!(
                matches!(frame_err(msg.as_bytes(), true), FramingError::Invalid(_)),
                "{value:?} accepted"
            );
        }
    }

    #[test]
    fn missing_content_length_rejected_on_stream_framed_on_ws() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nVia: SIP/2.0/WS h;branch=z9hG4bK1\r\n\r\nbody";
        assert!(matches!(frame_err(msg, true), FramingError::Missing));
        let mut buf = bytes::BytesMut::from(&msg[..]);
        let mut ka = KeepAlive::default();
        let f = next_sip_frame(&mut buf, false, &mut ka).unwrap().unwrap();
        assert_eq!(&f[..], &msg[..]);
    }

    // Round-trip: well-formed pipelined messages split at every offset
    // reframe to the identical bytes.
    #[test]
    fn reframing_any_split_is_identical() {
        let invite: &[u8] = b"INVITE sip:b@example.mil SIP/2.0\r\nl: 4\r\n\r\nv=0\n";
        let mut stream = Vec::new();
        stream.extend_from_slice(REGISTER);
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(invite);
        for split in 0..=stream.len() {
            let mut buf = bytes::BytesMut::new();
            let mut out = Vec::new();
            for part in [&stream[..split], &stream[split..]] {
                buf.extend_from_slice(part);
                while let Some(f) = frame(&mut buf) {
                    out.push(f);
                }
            }
            assert_eq!(out.len(), 2, "split {split}");
            assert_eq!(&out[0][..], REGISTER);
            assert_eq!(&out[1][..], invite);
        }
    }

    #[test]
    fn framing_error_response_is_minimal_400() {
        let msg = b"INVITE sip:b@example.mil SIP/2.0\r\n\
            Via: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bKx\r\n\
            From: <sip:a@example.mil>;tag=1\r\nTo: <sip:b@example.mil>\r\n\
            Call-ID: abc\r\nCSeq: 1 INVITE\r\nX-Evil: inject\r\n\
            Content-Length: 0\r\nContent-Length: 40\r\n\r\n";
        let resp = framing_error_response(msg).expect("400 for a request");
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.starts_with("SIP/2.0 400"));
        assert!(text.contains("Call-ID: abc"));
        assert!(text.contains("branch=z9hG4bKx"));
        assert!(!text.contains("X-Evil"));
        // A response, or garbage, gets no reply.
        assert!(framing_error_response(b"SIP/2.0 200 OK\r\nl: 1\r\nl: 2\r\n\r\n").is_none());
        assert!(framing_error_response(b"\x00\x01garbage\r\n\r\n").is_none());
    }

    /// In-memory stream transport for driving `stream_connection_loop`.
    struct FakeStream {
        local: SbcSocketAddr,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
        sent: std::sync::Mutex<Vec<bytes::Bytes>>,
        closed: std::sync::atomic::AtomicBool,
        kind: TransportType,
    }

    impl Transport for FakeStream {
        fn send<'a>(
            &'a self,
            data: &'a [u8],
            _dest: &'a SbcSocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = uc_transport::TransportResult<()>> + Send + 'a>,
        > {
            self.sent
                .lock()
                .unwrap()
                .push(bytes::Bytes::copy_from_slice(data));
            Box::pin(async { Ok(()) })
        }

        fn recv(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = uc_transport::TransportResult<uc_transport::ReceivedMessage>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                self.rx.lock().await.recv().await.map_or(
                    Err(uc_transport::TransportError::ConnectionClosed),
                    |data| {
                        Ok(uc_transport::ReceivedMessage {
                            data: data.into(),
                            source: self.local,
                            transport: self.kind,
                        })
                    },
                )
            })
        }

        fn local_addr(&self) -> &SbcSocketAddr {
            &self.local
        }

        fn transport_type(&self) -> TransportType {
            self.kind
        }

        fn close(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = uc_transport::TransportResult<()>> + Send + '_>,
        > {
            self.closed.store(true, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn stream_test_ctx(timeouts: StreamTimeouts) -> StreamLoopContext {
        let config = SbcConfig::default();
        StreamLoopContext {
            shutdown: ShutdownSignal::new(),
            stats: Arc::new(ServerStats::default()),
            sip_stack: Arc::new(SipStack::new(crate::sip_stack::SipStackConfig::default())),
            rate_limiter: Server::build_rate_limiter(&config, LimiterKind::Stream),
            global_limiter: Server::build_global_limiter(&config),
            rate_limit_enabled: true,
            zone_name: None,
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            total_conns: Arc::new(tokio::sync::Semaphore::new(4)),
            conn_limiter: Arc::new(crate::conn_limit::ConnLimiter::new(2, 64)),
            handshake_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            timeouts,
            flows: Arc::new(FlowTable::new(4)),
        }
    }

    /// Spawns the loop on a fake connection; returns the feed, the
    /// transport and the task.
    fn spawn_stream(
        ctx: StreamLoopContext,
    ) -> (
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        Arc<FakeStream>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_stream_kind(ctx, TransportType::Tcp)
    }

    fn spawn_stream_kind(
        ctx: StreamLoopContext,
        kind: TransportType,
    ) -> (
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        Arc<FakeStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let peer = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 20), 40000);
        spawn_stream_from(ctx, kind, peer)
    }

    /// [`spawn_stream_kind`] with the connection's peer address.
    fn spawn_stream_from(
        ctx: StreamLoopContext,
        kind: TransportType,
        peer: SbcSocketAddr,
    ) -> (
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        Arc<FakeStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let fake = Arc::new(FakeStream {
            local: SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 10), 5060),
            rx: tokio::sync::Mutex::new(rx),
            sent: std::sync::Mutex::new(Vec::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            kind,
        });
        let conn: Arc<dyn Transport> = Arc::clone(&fake) as Arc<dyn Transport>;
        let task = tokio::spawn(Server::stream_connection_loop(conn, peer, ctx, None));
        (tx, fake, task)
    }

    fn short_timeouts() -> StreamTimeouts {
        StreamTimeouts {
            handshake: std::time::Duration::from_secs(10),
            first_message: std::time::Duration::from_secs(30),
            idle: std::time::Duration::from_secs(300),
        }
    }

    // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4
    /// An IPv4 client on a dual-stack `[::]` TCP listener reaches the
    /// daemon's flow table as plain IPv4, the form trunk, blocklist and
    /// CDR lookups compare against. Skips without dual-stack unless
    /// `UC_REQUIRE_DUAL_STACK=1`.
    #[tokio::test]
    async fn dual_stack_tcp_accept_registers_plain_ipv4_peer() {
        use uc_types::address::TransportType as T;
        let required = std::env::var("UC_REQUIRE_DUAL_STACK").as_deref() == Ok("1");
        let skip = |why: &str| {
            assert!(!required, "UC_REQUIRE_DUAL_STACK=1 but {why}");
            eprintln!("skipping: {why}");
        };
        let Ok(listener) = TcpListener::bind(SbcSocketAddr::new_v6(Ipv6Addr::UNSPECIFIED, 0)).await
        else {
            return skip("cannot bind [::]:0 (no IPv6)");
        };
        let port = listener.local_addr().port();
        let ctx = stream_test_ctx(short_timeouts());
        let flows = Arc::clone(&ctx.flows);
        let accept = tokio::spawn(Server::tcp_accept_loop(Arc::new(listener), ctx));
        let Ok(mut client) = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
        else {
            accept.abort();
            return skip("127.0.0.1 cannot reach a [::] listener (no dual-stack)");
        };
        let local = client.local_addr().unwrap();
        let peer = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, local.port());
        let flow = LegFlow::inbound(T::Tcp);
        let mut sent = false;
        for _ in 0..200 {
            if flows.send(&flow, &peer, b"ping", None).await.is_ok() {
                sent = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sent, "accepted flow not registered under plain-IPv4 peer");
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ping");
        accept.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn crlf_only_connection_closed_at_first_message_timeout() {
        let (tx, fake, task) = spawn_stream(stream_test_ctx(short_timeouts()));
        let t0 = tokio::time::Instant::now();
        // CRLF pings every second never count before a first message.
        let pinger = tokio::spawn(async move {
            while tx.send(b"\r\n\r\n".to_vec()).is_ok() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(60), task)
            .await
            .expect("closed by the first-message deadline")
            .unwrap();
        assert!(t0.elapsed() >= std::time::Duration::from_secs(30));
        assert!(t0.elapsed() < std::time::Duration::from_secs(40));
        assert!(fake.closed.load(Ordering::Relaxed));
        pinger.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn byte_drip_does_not_reset_idle() {
        let (tx, _fake, task) = spawn_stream(stream_test_ctx(short_timeouts()));
        let t0 = tokio::time::Instant::now();
        let dripper = tokio::spawn(async move {
            for b in b"OPTIONS sip:a SIP/2.0\r\nVia: SIP/2.0/TCP h;branch=z9hG4bK1\r\n".repeat(10) {
                if tx.send(vec![b]).is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(60), task)
            .await
            .expect("slowloris closed")
            .unwrap();
        assert!(t0.elapsed() < std::time::Duration::from_secs(40));
        dripper.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn crlf_after_first_message_keeps_flow_alive() {
        let (tx, fake, task) = spawn_stream(stream_test_ctx(short_timeouts()));
        tx.send(
            b"OPTIONS sip:sbc@example.mil SIP/2.0\r\n\
              Via: SIP/2.0/TCP 192.0.2.20:40000;branch=z9hG4bKka1\r\n\
              From: <sip:a@example.mil>;tag=1\r\nTo: <sip:sbc@example.mil>\r\n\
              Call-ID: ka1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\
              Content-Length: 0\r\n\r\n"
                .to_vec(),
        )
        .unwrap();
        // RFC 5626 keep-alives every 100 s for 10 minutes: past both the
        // 30 s first-message and the 300 s idle limit.
        for _ in 0..6 {
            tokio::time::sleep(std::time::Duration::from_secs(100)).await;
            tx.send(b"\r\n\r\n".to_vec()).unwrap();
        }
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "flow closed despite keep-alives");
        assert!(!fake.closed.load(Ordering::Relaxed));
        task.abort();
    }

    const OPTIONS_KA: &[u8] = b"OPTIONS sip:sbc@example.mil SIP/2.0\r\n\
        Via: SIP/2.0/TCP 192.0.2.20:40000;branch=z9hG4bKka2\r\n\
        From: <sip:a@example.mil>;tag=1\r\nTo: <sip:sbc@example.mil>\r\n\
        Call-ID: ka2\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\
        Content-Length: 0\r\n\r\n";

    // SEC-001: a well-framed but unparseable frame is not a first message,
    // so CRLF keep-alives after it earn no credit and the connection closes
    // at the first-message deadline.
    #[tokio::test(start_paused = true)]
    async fn junk_frame_then_crlf_closed_at_first_message_timeout() {
        let (tx, fake, task) = spawn_stream(stream_test_ctx(short_timeouts()));
        let t0 = tokio::time::Instant::now();
        // Frames (valid start line and Content-Length) but fails the
        // parser's semantic validation (Max-Forwards is not 1*DIGIT).
        tx.send(
            b"OPTIONS sip:a@example.mil SIP/2.0\r\nMax-Forwards: junk\r\n\
              Content-Length: 0\r\n\r\n"
                .to_vec(),
        )
        .unwrap();
        let pinger = tokio::spawn(async move {
            while tx.send(b"\r\n\r\n".to_vec()).is_ok() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(60), task)
            .await
            .expect("closed by the first-message deadline")
            .unwrap();
        assert!(t0.elapsed() >= std::time::Duration::from_secs(30));
        assert!(t0.elapsed() < std::time::Duration::from_secs(40));
        assert!(fake.closed.load(Ordering::Relaxed));
        pinger.abort();
    }

    // RFC-001: RFC 5626 §4.4.1 double-CRLF ping gets a single-CRLF pong on
    // TCP/TLS, including a ping split across reads.
    #[tokio::test]
    async fn crlf_ping_gets_single_crlf_pong() {
        let (tx, fake, task) = spawn_stream(stream_test_ctx(short_timeouts()));
        tx.send(b"\r\n\r\n".to_vec()).unwrap();
        tx.send(b"\r\n".to_vec()).unwrap();
        tx.send(b"\r\n".to_vec()).unwrap();
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let sent = fake.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(sent.iter().all(|b| &b[..] == b"\r\n"));
        task.abort();
    }

    #[test]
    fn keepalive_counts_pings_and_waits_on_a_lone_crlf() {
        let mut buf = bytes::BytesMut::from(&b"\r\n\r\n\r\n\r\n\r\n"[..]);
        let mut ka = KeepAlive::default();
        assert!(next_sip_frame(&mut buf, true, &mut ka).unwrap().is_none());
        assert_eq!(ka.pings, 2);
        assert_eq!(&buf[..], b"\r\n");
        // A pong (lone CRLF) before a message is dropped, not a ping.
        buf.extend_from_slice(REGISTER);
        let mut ka = KeepAlive::default();
        assert!(next_sip_frame(&mut buf, true, &mut ka).unwrap().is_some());
        assert_eq!((ka.seen, ka.pings), (true, 0));
    }

    // RFC-002: an incomplete SIP message in one WebSocket message is
    // discarded on its own; the next WS message is framed alone.
    #[tokio::test]
    async fn ws_partial_message_is_not_spliced() {
        let ctx = stream_test_ctx(short_timeouts());
        let stats = Arc::clone(&ctx.stats);
        let (tx, fake, task) = spawn_stream_kind(ctx, TransportType::WebSocket);
        tx.send(b"OPTIONS sip:a@example.mil SIP/2.0\r\nVia: SIP/2.0/WS h".to_vec())
            .unwrap();
        tx.send(OPTIONS_KA.to_vec()).unwrap();
        for _ in 0..200 {
            tokio::task::yield_now().await;
            if !fake.sent.lock().unwrap().is_empty() {
                break;
            }
        }
        assert_eq!(stats.framing_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.messages_received.load(Ordering::Relaxed), 1);
        let sent = fake.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert!(sent[0].starts_with(b"SIP/2.0 "));
        assert!(!fake.closed.load(Ordering::Relaxed));
        task.abort();
    }

    #[tokio::test]
    async fn duplicate_cl_gets_400_and_close() {
        let ctx = stream_test_ctx(short_timeouts());
        let stats = Arc::clone(&ctx.stats);
        let (tx, fake, task) = spawn_stream(ctx);
        tx.send(
            b"OPTIONS sip:sbc@example.mil SIP/2.0\r\n\
              Via: SIP/2.0/TCP 192.0.2.20:40000;branch=z9hG4bKdup\r\n\
              From: <sip:a@example.mil>;tag=1\r\nTo: <sip:sbc@example.mil>\r\n\
              Call-ID: dup\r\nCSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\nContent-Length: 60\r\n\r\n"
                .to_vec(),
        )
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("connection closed")
            .unwrap();
        assert!(fake.closed.load(Ordering::Relaxed));
        assert_eq!(stats.framing_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.messages_received.load(Ordering::Relaxed), 0);
        let sent = fake.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].starts_with(b"SIP/2.0 400"));
    }

    // Item 1: a flooding source exhausts only its own bucket; the global
    // bucket is not charged for its rejected packets and an innocent
    // source is still served and never blocked.
    #[tokio::test]
    async fn rate_limit_allows_checks_per_ip_first() {
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 5;
        config.rate_limit.global_rps = 1_000;
        let per_ip = Server::build_rate_limiter(&config, LimiterKind::Stream);
        let global = Server::build_global_limiter(&config);
        let stats = ServerStats::default();
        let flooder: std::net::IpAddr = "192.0.2.66".parse().unwrap();
        let innocent: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        // Use the per-IP burst (5 * 2.0).
        for _ in 0..10 {
            assert!(Server::rate_limit_allows(flooder, &per_ip, &global, &stats).await);
        }
        let before = global
            .lock()
            .await
            .token_count(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .unwrap();
        for _ in 0..500 {
            assert!(!Server::rate_limit_allows(flooder, &per_ip, &global, &stats).await);
        }
        let after = global
            .lock()
            .await
            .token_count(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .unwrap();
        assert!(after >= before, "rejected packets charged global tokens");
        assert!(Server::rate_limit_allows(innocent, &per_ip, &global, &stats).await);
        assert!(!per_ip.lock().await.is_blocked(innocent));
        assert_eq!(global.lock().await.blocked_sources(), 0);
    }

    // A global flood rejects but never blocks the source that tripped it.
    #[tokio::test]
    async fn global_flood_does_not_block_a_source() {
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 1_000;
        config.rate_limit.global_rps = 5;
        let per_ip = Server::build_rate_limiter(&config, LimiterKind::Stream);
        let global = Server::build_global_limiter(&config);
        let stats = ServerStats::default();
        let trunk: std::net::IpAddr = "192.0.2.5".parse().unwrap();
        for _ in 0..200 {
            let _ = Server::rate_limit_allows(trunk, &per_ip, &global, &stats).await;
        }
        assert!(!per_ip.lock().await.is_blocked(trunk));
        assert_eq!(global.lock().await.blocked_sources(), 0);
    }

    fn rate_limit_records(
        events: &[uc_audit::AuditEvent],
    ) -> Vec<uc_audit::event::RateLimitTriggered> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::RateLimitTriggered(r) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn rejections_are_audited_in_aggregate() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 1;
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(1, 1).with_block_threshold(1e12));
        let src: std::net::IpAddr = "192.0.2.44".parse().unwrap();
        for _ in 0..1_001 {
            let _ = limiter.check(src);
        }
        let mut audit = RateLimitAudit::new(&config);
        audit.collect_per_ip(&mut limiter);
        assert!(rate_limit_records(&capture.events()).is_empty());
        audit.flush();
        let records = rate_limit_records(&capture.events());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].limit_name, "per_ip_rps");
        assert_eq!(records[0].request_count, 1_000);
        assert_eq!(records[0].source_ip, src);
    }

    #[test]
    fn audit_over_cap_emits_one_suppressed_summary() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.audit_max_records_per_interval = 2;
        let mut audit = RateLimitAudit::new(&config);
        for last in 1..=5u8 {
            audit.add(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
                "per_ip_rps",
                10,
            );
        }
        audit.flush();
        let records = rate_limit_records(&capture.events());
        assert_eq!(records.len(), 3);
        let suppressed: Vec<_> = records
            .iter()
            .filter(|r| r.limit_name == "per_ip_rps_suppressed")
            .collect();
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].request_count, 30);
        assert_eq!(suppressed[0].threshold, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_and_unblock_are_audited_once() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 2;
        config.rate_limit.block_duration_secs = 1;
        let per_ip = Server::build_rate_limiter(&config, LimiterKind::Stream);
        let global = Server::build_global_limiter(&config);
        let stats = ServerStats::default();
        let src: std::net::IpAddr = "192.0.2.99".parse().unwrap();
        for _ in 0..50 {
            let _ = Server::rate_limit_allows(src, &per_ip, &global, &stats).await;
        }
        let blocks: Vec<_> = rate_limit_records(&capture.events())
            .into_iter()
            .filter(|r| r.limit_name.starts_with("per_ip_block:"))
            .collect();
        assert_eq!(blocks.len(), 1);
        // NIST-002: names the blocked key and prefix, duration not in
        // request_count.
        assert_eq!(blocks[0].limit_name, "per_ip_block:/32:1s");
        assert_eq!(blocks[0].source_ip, src);
        assert_eq!(blocks[0].request_count, 0);

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let mut maint = RateLimitMaintenance::new(
            &config,
            ShutdownSignal::new(),
            Arc::clone(&per_ip),
            Arc::clone(&global),
            Arc::new(crate::conn_limit::ConnLimiter::new(1, 64)),
        );
        maint.sweep(true).await;
        let records = rate_limit_records(&capture.events());
        assert_eq!(
            records
                .iter()
                .filter(|r| r.limit_name == "per_ip_unblock")
                .count(),
            1
        );
        assert!(records.iter().any(|r| r.limit_name == "per_ip_rps"));
        // SEC-003 / NIST-004: drops while blocked are sized in the aggregate.
        let drops = records
            .iter()
            .find(|r| r.limit_name == "per_ip_blocked_drops")
            .expect("blocked drops aggregated");
        assert!(drops.request_count > 0);
    }

    // SEC-002 / NIST-003 / NIST-005: pool-full drops and framing rejections
    // are counted and audited in aggregate, one record per kind per flush.
    #[test]
    fn pool_full_and_framing_rejections_are_audited_in_aggregate() {
        let capture = uc_audit::capture::start();
        let mut ctx = stream_test_ctx(short_timeouts());
        ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let p = |last| SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, last), 1);
        let _held = Server::admit_connection(&ctx, &p(1), "tcp").unwrap();
        for last in 2..=4 {
            assert!(Server::admit_connection(&ctx, &p(last), "tcp").is_none());
        }
        ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        ctx.total_conns = Arc::new(tokio::sync::Semaphore::new(0));
        assert!(Server::admit_connection(&ctx, &p(5), "tcp").is_none());
        ctx.conn_limiter.note_framing_error(p(6).ip());
        ctx.conn_limiter.note_framing_error(p(6).ip());

        let mut audit = RateLimitAudit::new(&SbcConfig::default());
        audit.collect_conns(&ctx.conn_limiter);
        audit.flush();
        let records = rate_limit_records(&capture.events());
        let find = |name: &str| records.iter().find(|r| r.limit_name == name).unwrap();
        assert_eq!(find("listener_conn").request_count, 3);
        assert_eq!(find("total_conn").request_count, 1);
        let framing = find("framing");
        assert_eq!((framing.source_ip, framing.request_count), (p(6).ip(), 2));
        assert_eq!(records.len(), 3);
    }

    // Per-listener pools: exhausting one listener's pool does not affect
    // another listener; the per-source cap applies across listeners.
    #[test]
    fn admission_pools_are_per_listener_and_cap_is_per_source() {
        let ws = stream_test_ctx(short_timeouts());
        let mut tcp = ws.clone();
        tcp.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(4));
        let mut held = Vec::new();
        for last in 1..=4u8 {
            let p = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, last), 1);
            held.push(Server::admit_connection(&ws, &p, "ws").unwrap());
        }
        assert_eq!(held.len(), 4);
        let p5 = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 5), 1);
        assert!(Server::admit_connection(&ws, &p5, "ws").is_none());
        // The total ceiling (4 in this ctx) is shared: raise it for TCP.
        tcp.total_conns = Arc::new(tokio::sync::Semaphore::new(4));
        assert!(Server::admit_connection(&tcp, &p5, "tcp").is_some());
        // Source 192.0.2.1 already holds one; cap is 2 across listeners.
        let p1 = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 1), 2);
        let _second = Server::admit_connection(&tcp, &p1, "tcp").unwrap();
        assert!(Server::admit_connection(&tcp, &p1, "tcp").is_none());
        assert_eq!(
            tcp.stats.conn_rejected_per_source.load(Ordering::Relaxed),
            1
        );
    }

    // QA: the node-wide ceiling is enforced after the listener pool, and
    // every slot (source, listener, total) is released when the admission
    // drops.
    #[test]
    fn qa_admission_total_cap_and_slot_release() {
        let mut ctx = stream_test_ctx(short_timeouts());
        ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        ctx.total_conns = Arc::new(tokio::sync::Semaphore::new(2));
        let p = |last| SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, last), 1);
        let a1 = Server::admit_connection(&ctx, &p(1), "tcp").unwrap();
        let a2 = Server::admit_connection(&ctx, &p(2), "tcp").unwrap();
        assert!(Server::admit_connection(&ctx, &p(3), "tcp").is_none());
        // The refused accept released its per-source and listener slots.
        assert_eq!(ctx.conn_limiter.active(p(3).ip()), 0);
        assert_eq!(ctx.conn_semaphore.available_permits(), 8);
        drop(a1);
        assert_eq!(ctx.conn_limiter.active(p(1).ip()), 0);
        assert_eq!(ctx.total_conns.available_permits(), 1);
        assert_eq!(ctx.conn_semaphore.available_permits(), 9);
        let _a3 = Server::admit_connection(&ctx, &p(3), "tcp").unwrap();
        drop(a2);
    }

    async fn ws_upgrade_status(addr: std::net::SocketAddr) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    // QA (plan item 3): a silent client holds the only listener slot until
    // the handshake deadline, then the slot is released and a real client
    // upgrades.
    #[tokio::test]
    async fn qa_ws_handshake_timeout_releases_permit() {
        let mut ctx = stream_test_ctx(StreamTimeouts {
            handshake: std::time::Duration::from_millis(500),
            ..short_timeouts()
        });
        ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let stats = Arc::clone(&ctx.stats);
        let bind = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0);
        let listener = Arc::new(
            WebSocketListener::bind(&bind, false)
                .await
                .unwrap()
                .with_options(WebSocketListenerOptions {
                    require_sip_subprotocol: true,
                }),
        );
        let addr = listener.bound_addr().unwrap();
        let task = tokio::spawn(Server::ws_accept_loop(listener, ctx));
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Pool of one is held by the silent client: this accept is dropped.
        assert_eq!(ws_upgrade_status(addr).await, None);
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        assert_eq!(stats.handshake_timeouts.load(Ordering::Relaxed), 1);
        let reply = ws_upgrade_status(addr).await.expect("upgrade answered");
        assert!(reply.starts_with("HTTP/1.1 101"), "{reply}");
        task.abort();
    }

    // QA (plan item 5): records are emitted only on a flushing sweep, once
    // per aggregate, and an idle interval emits nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn qa_audit_flush_emits_once_per_interval() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 1;
        let per_ip = Server::build_rate_limiter(&config, LimiterKind::Stream);
        let global = Server::build_global_limiter(&config);
        let src: std::net::IpAddr = "192.0.2.45".parse().unwrap();
        {
            let mut l = per_ip.lock().await;
            for _ in 0..3 {
                let _ = l.check(src);
            }
        }
        let mut maint = RateLimitMaintenance::new(
            &config,
            ShutdownSignal::new(),
            Arc::clone(&per_ip),
            Arc::clone(&global),
            Arc::new(crate::conn_limit::ConnLimiter::new(1, 64)),
        );
        let count = || {
            rate_limit_records(&capture.events())
                .iter()
                .filter(|r| r.limit_name == "per_ip_rps")
                .count()
        };
        maint.sweep(false).await;
        maint.sweep(false).await;
        assert_eq!(count(), 0, "non-flushing sweep emitted");
        maint.sweep(true).await;
        assert_eq!(count(), 1);
        maint.sweep(true).await;
        assert_eq!(count(), 1, "idle interval emitted");
    }

    // QA (plan item 5): the run loop flushes on the audit interval, not on
    // every sweep tick.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn qa_maintenance_loop_flushes_on_audit_interval() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.per_ip_rps = 1;
        config.rate_limit.sweep_interval_secs = 10;
        config.rate_limit.audit_interval_secs = 60;
        let per_ip = Server::build_rate_limiter(&config, LimiterKind::Stream);
        let global = Server::build_global_limiter(&config);
        // Each batch uses a fresh source: packets dropped while a source is
        // blocked are not counted in the aggregate.
        let reject = |src: std::net::IpAddr, n| {
            let per_ip = Arc::clone(&per_ip);
            async move {
                let mut l = per_ip.lock().await;
                for _ in 0..n {
                    let _ = l.check(src);
                }
            }
        };
        reject("192.0.2.46".parse().unwrap(), 3).await;
        let shutdown = ShutdownSignal::new();
        let maint = RateLimitMaintenance::new(
            &config,
            shutdown.clone(),
            Arc::clone(&per_ip),
            Arc::clone(&global),
            Arc::new(crate::conn_limit::ConnLimiter::new(1, 64)),
        );
        let task = tokio::spawn(maint.run());
        let count = || {
            rate_limit_records(&capture.events())
                .iter()
                .filter(|r| r.limit_name == "per_ip_rps")
                .count()
        };
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
        assert_eq!(count(), 0);
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        assert_eq!(count(), 1);
        reject("192.0.2.47".parse().unwrap(), 5).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_eq!(count(), 1);
        tokio::time::sleep(std::time::Duration::from_secs(40)).await;
        assert_eq!(count(), 2);
        shutdown.request_shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    // QA (plan item 5): global, overflow and per-source connection
    // aggregates carry the documented placeholder sources and thresholds.
    #[test]
    fn qa_audit_record_fields_for_global_overflow_and_conn() {
        let capture = uc_audit::capture::start();
        let mut config = SbcConfig::default();
        config.rate_limit.global_rps = 7;
        config.transport.max_connections_per_source = 1;
        let mut audit = RateLimitAudit::new(&config);
        let mut global = RateLimiter::new(RateLimiterConfig::new(7, 1).with_per_ip(false));
        for _ in 0..4 {
            let _ = global.check(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        }
        audit.collect_global(&mut global);
        let conns = Arc::new(crate::conn_limit::ConnLimiter::new(1, 64));
        let src: std::net::IpAddr = "192.0.2.50".parse().unwrap();
        let _held = conns.try_acquire(src).unwrap();
        assert!(conns.try_acquire(src).is_none());
        assert!(conns.try_acquire(src).is_none());
        audit.collect_conns(&conns);
        audit.overflow = 9;
        audit.flush();
        let records = rate_limit_records(&capture.events());
        let find = |name: &str| records.iter().find(|r| r.limit_name == name).unwrap();
        let g = find("global_rps");
        assert_eq!(g.source_ip, std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!((g.request_count, g.threshold), (3, 7));
        let o = find("overflow_rps");
        assert_eq!(o.source_ip, std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(o.request_count, 9);
        let c = find("per_ip_conn");
        assert_eq!(c.source_ip, src);
        assert_eq!((c.request_count, c.threshold), (2, 1));
        assert_eq!(records.len(), 3);
    }

    // QA (plan item 6): a response with bad framing is closed silently,
    // and a request whose head cannot be parsed gets no echo.
    #[test]
    fn qa_framing_error_response_only_for_parseable_requests() {
        assert!(
            framing_error_response(b"SIP/2.0 200 OK\r\nContent-Length: 1\r\nl: 2\r\n\r\n")
                .is_none()
        );
        assert!(framing_error_response(b"\x00\x01garbage\r\n\r\n").is_none());
    }

    // QA (plan item 6): CRLF between pipelined messages is still a
    // keep-alive and never desynchronises framing; a whitespace or empty
    // Content-Length is malformed.
    #[test]
    fn qa_content_length_whitespace_variants() {
        for value in ["", " ", "1 2", "0x10"] {
            let msg = format!("OPTIONS sip:a SIP/2.0\r\nContent-Length:{value}\r\n\r\n");
            assert!(
                matches!(frame_err(msg.as_bytes(), true), FramingError::Invalid(_)),
                "{value:?} accepted"
            );
        }
        let ok = b"OPTIONS sip:a SIP/2.0\r\nContent-Length:   0  \r\n\r\n";
        let mut buf = bytes::BytesMut::from(&ok[..]);
        let mut ka = KeepAlive::default();
        assert!(next_sip_frame(&mut buf, true, &mut ka).unwrap().is_some());
    }

    // SEC-001/PERF-001 (fix round 1): a stream peer that stops reading does
    // not delay the timer loop's other sends (a UDP retransmission and a
    // healthy stream peer's message); its own send is evicted after the
    // write deadline.
    #[tokio::test]
    async fn dispatch_does_not_wait_on_a_stalled_stream_peer() {
        use crate::flow::{Flow, LegFlow};
        use std::net::Ipv4Addr;
        use uc_types::address::TransportType as T;

        let flows = Arc::new(FlowTable::new(4).with_timeouts(
            std::time::Duration::from_millis(300),
            crate::flows::DIAL_FAILURE_BACKOFF,
        ));
        let udp = Arc::new(
            UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let watcher = UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        flows.set_default_udp(udp);

        let listener = TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let laddr = *listener.local_addr();
        // Peer 1 never reads; peer 2 does.
        let _stalled_client = uc_transport::tcp::TcpTransport::connect(laddr)
            .await
            .unwrap();
        let (stalled, stalled_peer) = listener.accept().await.unwrap();
        let healthy_client = uc_transport::tcp::TcpTransport::connect(laddr)
            .await
            .unwrap();
        let (healthy, healthy_peer) = listener.accept().await.unwrap();
        let stalled: Arc<dyn Transport> = Arc::new(stalled);
        flows.register_accepted(T::Tcp, stalled_peer, Arc::clone(&stalled));
        flows.register_accepted(T::Tcp, healthy_peer, Arc::new(healthy));
        let chunk = vec![b'x'; 60_000];
        // Two stalls in a row: the window is really full, not a hiccup.
        let mut stalls = 0;
        while stalls < 2 {
            let r = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                stalled.send(&chunk, &stalled_peer),
            )
            .await;
            stalls = if r.is_err() { stalls + 1 } else { 0 };
        }

        let ctx = SendCtx {
            flows: Arc::clone(&flows),
            stats: Arc::new(ServerStats::default()),
            sip_stack: Arc::new(SipStack::new(crate::sip_stack::SipStackConfig::default())),
            origin: Origin::None,
        };
        let msg = || {
            SipMessage::parse(&bytes::Bytes::from_static(
                b"SIP/2.0 408 Request Timeout\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKt\r\n\
                  Call-ID: c\r\nCSeq: 1 INVITE\r\nFrom: <sip:a@x>;tag=1\r\n\
                  To: <sip:b@x>;tag=2\r\nContent-Length: 0\r\n\r\n",
            ))
            .unwrap()
        };
        let response = |destination, flow| ProcessResult::Response {
            message: msg(),
            destination,
            flow,
        };
        let batch = ProcessResult::Multiple(vec![
            response(stalled_peer, Flow::Leg(LegFlow::inbound(T::Tcp))),
            response(*watcher.local_addr(), Flow::UDP),
            response(healthy_peer, Flow::Leg(LegFlow::inbound(T::Tcp))),
        ]);
        let t0 = std::time::Instant::now();
        Server::dispatch(batch, &ctx).await;
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(100),
            "dispatch waited on a stream send: {:?}",
            t0.elapsed()
        );
        let secs = std::time::Duration::from_secs(1);
        let got = tokio::time::timeout(secs, watcher.recv())
            .await
            .expect("UDP send not delayed")
            .unwrap();
        assert!(got.data.starts_with(b"SIP/2.0 408"));
        let got = tokio::time::timeout(secs, healthy_client.recv())
            .await
            .expect("healthy stream peer not delayed")
            .unwrap();
        assert!(got.data.starts_with(b"SIP/2.0 408"));

        // The stalled peer's send hits the write deadline: closed, evicted.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while flows.stats.stream_write_timeouts.load(Ordering::Relaxed) == 0
                || !stalled.is_closed()
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("stalled connection evicted");
    }

    fn tls_lane(host: [u8; 4]) -> crate::flows::LaneKey {
        (
            uc_types::address::TransportType::Tls,
            SbcSocketAddr::new_v4(Ipv4Addr::from(host), 5061),
        )
    }

    fn none_ctx(stack: &Arc<SipStack>, flows: &Arc<FlowTable>) -> SendCtx {
        SendCtx {
            flows: Arc::clone(flows),
            stats: Arc::new(ServerStats::default()),
            sip_stack: Arc::clone(stack),
            origin: Origin::None,
        }
    }

    // PERF-008/SEC-006 (fix round 2): a failed INVITE's failover follow-up
    // goes through dispatch onto its destination's lane (here held by an
    // earlier send), not onto a free-running task.
    #[tokio::test]
    async fn invite_failover_follow_up_is_sent_on_its_lane() {
        use crate::sip_stack::tests::{carrier_active, tls_failover_call};
        let (stack, primary) = tls_failover_call("r2-follow@test").await;
        let stack = Arc::new(stack);
        // No TLS client config: the t1 send fails closed at once.
        let flows = Arc::new(FlowTable::new(4));
        assert!(flows.enqueue(tls_lane([127, 0, 0, 3]), Box::pin(std::future::pending())));
        let ctx = none_ctx(&stack, &flows);
        Server::dispatch(primary, &ctx).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while carrier_active(&stack, "t2").await != 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed over to t2");
        // Queued behind the t2 lane's earlier send: not attempted yet (a
        // fail-closed attempt would have released t2 again).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(carrier_active(&stack, "t1").await, 0);
        assert_eq!(carrier_active(&stack, "t2").await, 1);
        assert!(flows.lane_busy(&tls_lane([127, 0, 0, 3])));
    }

    // PERF-007 (fix round 2): an INVITE dropped by a full lane is reported
    // as a failed send and fails over at once, not on Timer B.
    #[tokio::test]
    async fn invite_dropped_by_a_full_lane_fails_over_at_once() {
        use crate::sip_stack::tests::{carrier_active, tls_failover_call};
        let (stack, primary) = tls_failover_call("r2-full@test").await;
        let stack = Arc::new(stack);
        let flows = Arc::new(FlowTable::new(4));
        while flows.enqueue(tls_lane([127, 0, 0, 2]), Box::pin(std::future::pending())) {}
        assert!(flows.enqueue(tls_lane([127, 0, 0, 3]), Box::pin(std::future::pending())));
        let dropped = flows.stats.lane_dropped.load(Ordering::Relaxed);
        let ctx = none_ctx(&stack, &flows);
        Server::dispatch(primary, &ctx).await;
        assert_eq!(
            flows.stats.lane_dropped.load(Ordering::Relaxed),
            dropped + 1
        );
        assert_eq!(carrier_active(&stack, "t1").await, 0);
        assert_eq!(carrier_active(&stack, "t2").await, 1);
    }

    // RFC-006 (fix round 2): a reply on the origin connection queues behind
    // a send already on that connection's lane instead of overtaking it.
    #[tokio::test]
    async fn origin_reply_waits_for_its_busy_lane() {
        use crate::flow::{Flow, LegFlow};
        use uc_types::address::TransportType as T;

        let flows = Arc::new(FlowTable::new(4));
        let listener = TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let client = uc_transport::tcp::TcpTransport::connect(*listener.local_addr())
            .await
            .unwrap();
        let (conn, peer) = listener.accept().await.unwrap();
        let conn: Arc<dyn Transport> = Arc::new(conn);
        flows.register_accepted(T::Tcp, peer, Arc::clone(&conn));
        let key: FlowKey = (T::Tcp, peer, None, crate::flow::FlowProfile::Plain);

        assert!(!flows.lane_busy(&(T::Tcp, peer)));
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        {
            let (flows, conn, key) = (Arc::clone(&flows), Arc::clone(&conn), key.clone());
            assert!(flows.clone().enqueue(
                (T::Tcp, peer),
                Box::pin(async move {
                    let _ = wait.await;
                    let _ = flows.write(&key, &conn, b"FIRST", &peer).await;
                }),
            ));
        }
        assert!(flows.lane_busy(&(T::Tcp, peer)));

        let ctx = SendCtx {
            flows: Arc::clone(&flows),
            stats: Arc::new(ServerStats::default()),
            sip_stack: Arc::new(SipStack::new(SipStackConfig::default())),
            origin: Origin::Stream {
                conn: Arc::clone(&conn),
                peer,
                key,
            },
        };
        let reply = SipMessage::parse(&bytes::Bytes::from_static(
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bKo\r\n\
              Call-ID: o\r\nCSeq: 1 OPTIONS\r\nFrom: <sip:a@x>;tag=1\r\n\
              To: <sip:b@x>;tag=2\r\nContent-Length: 0\r\n\r\n",
        ))
        .unwrap();
        Server::dispatch(
            ProcessResult::Response {
                message: reply,
                destination: peer,
                flow: Flow::Leg(LegFlow::inbound(T::Tcp)),
            },
            &ctx,
        )
        .await;
        let early =
            tokio::time::timeout(std::time::Duration::from_millis(200), client.recv()).await;
        assert!(early.is_err(), "reply overtook the queued send: {early:?}");

        go.send(()).unwrap();
        let mut got = Vec::new();
        while got.len() < 5 + 12 {
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(1), client.recv())
                .await
                .expect("both sends arrive")
                .unwrap();
            got.extend_from_slice(&chunk.data);
        }
        assert!(got.starts_with(b"FIRST"), "{got:?}");
        assert!(got[5..].starts_with(b"SIP/2.0 200 OK"), "{got:?}");
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cluster_divide_sets_node_share_and_keeps_emergency_reserve() {
        let config = sbc_config::load_from_str(
            "[general]\nmax_calls = 1000\nmax_registrations = 3000\n\
             [cluster]\nenabled = true\n\
             [cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 3\n\
             [cluster.auth]\nkey_file = \"/etc/sbc/cluster.key\"\nkey_id = 1\n",
        )
        .expect("config");
        let sip = Server::build_sip_config(&config, None);
        assert_eq!(sip.max_calls, 333);
        assert_eq!(sip.max_registrations, 1000);
        assert_eq!(sip.admission_divisor, 3);
        // 47 CFR 9.16: per-node reserve from the configured (undivided) cap.
        assert_eq!(sip.emergency_reserve_calls, 100);
    }

    // POA&M-270: `[digest_auth]` reaches the SIP stack config; absent, the
    // stack keeps REGISTER digest off.
    #[test]
    fn build_sip_config_maps_digest_auth() {
        let sip = Server::build_sip_config(&SbcConfig::default(), None);
        assert!(!sip.require_auth);
        assert!(sip.digest_credentials.is_none());
        assert_eq!(sip.digest_algorithm, proto_sip::DigestAlgorithm::Sha256);
        assert_eq!(sip.digest_nonce_ttl_secs, 300);

        let config = sbc_config::load_from_str(
            "[digest_auth]\nrequire_auth = true\nrealm = \"sip.example.test\"\n\
             algorithm = \"SHA-512-256\"\ncredentials_file = \"/etc/usg-sbc/digest.ha1\"\n\
             nonce_ttl_secs = 90\n",
        )
        .expect("config");
        let store = crate::sip_stack::tests::test_digest_store("sip.example.test", &[]);
        let sip = Server::build_sip_config(&config, Some(Arc::clone(&store)));
        assert!(sip.require_auth);
        assert_eq!(sip.auth_realm, "sip.example.test");
        assert_eq!(sip.digest_algorithm, proto_sip::DigestAlgorithm::Sha512_256);
        assert_eq!(sip.digest_nonce_ttl_secs, 90);
        assert!(
            sip.digest_credentials
                .is_some_and(|s| Arc::ptr_eq(&s, &store))
        );
        // No "UNAUTHENTICATED" state once configured.
        let server = Server::new(config, ShutdownSignal::new(), Some(store));
        assert!(server.sip_stack().register_auth_enabled());
        let off = Server::new(SbcConfig::default(), ShutdownSignal::new(), None);
        assert!(!off.sip_stack().register_auth_enabled());
    }

    // SEC-008: one rule for "bearer mode is active", shared with the
    // runtime's digest/bearer conflict check.
    #[test]
    fn bearer_mode_active_is_trimmed_and_case_insensitive() {
        for on in ["bearer", "Bearer", "BEARER", " bearer ", "\tbearer\n"] {
            assert!(bearer_mode_active(on), "{on:?}");
        }
        for off in [
            "",
            " ",
            "digest",
            "none",
            "bearer2",
            "be arer",
            "bearer,digest",
        ] {
            assert!(!bearer_mode_active(off), "{off:?}");
        }
    }

    // SEC-004 / NIST-002 (POA&M-314): digest with a non-TLS SIP listener is
    // reported; digest off, or TLS-only listeners, is not.
    #[test]
    fn digest_cleartext_transports_lists_non_tls_listeners() {
        let addr: std::net::SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let mut config = SbcConfig::default();
        config.transport.udp_listen = vec![addr];
        config.transport.tcp_listen = vec![addr];
        config.transport.ws_listen = vec![addr];
        config.transport.tls_listen = vec![addr];
        assert!(
            digest_cleartext_transports(&config).is_empty(),
            "digest off"
        );
        config.digest_auth.require_auth = true;
        assert_eq!(
            digest_cleartext_transports(&config),
            vec!["udp", "tcp", "ws"]
        );
        config.transport.tcp_listen.clear();
        assert_eq!(digest_cleartext_transports(&config), vec!["udp", "ws"]);
        config.transport.udp_listen.clear();
        config.transport.ws_listen.clear();
        config.transport.wss_listen = vec![addr];
        assert!(
            digest_cleartext_transports(&config).is_empty(),
            "TLS and WSS only"
        );
    }

    #[test]
    fn default_admission_is_per_node() {
        let config = SbcConfig::default();
        let sip = Server::build_sip_config(&config, None);
        assert_eq!(sip.max_calls, config.general.max_calls);
        assert_eq!(sip.max_registrations, config.general.max_registrations);
        assert_eq!(sip.admission_divisor, 1);
    }

    // ------------------------------------------------------------------
    // SIPREC recording startup (POA&M-300, -301, -304): it works or the
    // daemon does not start.
    // ------------------------------------------------------------------

    /// A self-signed P-384 certificate and its key (mode 0600) in `dir`.
    #[cfg(unix)]
    fn write_cert_and_key(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["sbc.example.test".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let cert_path = dir.join("sbc.crt");
        let key_path = dir.join("sbc.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, kp.serialize_pem()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (cert_path, key_path)
    }

    /// A config with recording enabled toward `srs_uri`, the SBC TLS
    /// certificate in place, and `ca` as the SRS CA bundle.
    #[cfg(unix)]
    fn recording_config(dir: &std::path::Path, srs_uri: &str, ca: &std::path::Path) -> SbcConfig {
        let (cert, key) = write_cert_and_key(dir);
        let mut config = SbcConfig::default();
        config.security.tls_cert_path = Some(cert);
        config.security.tls_key_path = Some(key);
        config.recording.enabled = true;
        config.recording.notice_acknowledged = true;
        config.recording.record_all = true;
        config.recording.srs_uri = Some(srs_uri.to_string());
        config.recording.srs_tls_ca_file = Some(ca.to_string_lossy().into_owned());
        config
    }

    /// The configuration error message of a refused startup (any other
    /// outcome yields a text no assertion matches).
    fn startup_error(r: Result<(), ServerError>) -> String {
        match r {
            Err(ServerError::ConfigError { message }) => message,
            other => format!("not a configuration error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn recording_off_wires_nothing() {
        let mut server = Server::new(SbcConfig::default(), ShutdownSignal::new(), None);
        server.wire_recording().await.unwrap();
        assert!(!server.sip_stack().recording_enabled());
        assert!(
            Server::recording_startup_check(
                &SbcConfig::default(),
                &["http://media-1:50051".to_string()]
            )
            .is_ok(),
            "remote media is fine while recording is off"
        );
    }

    // Q2 / POA&M-301: recording with remote media nodes refuses to start
    // (the media control channel would carry SRTP keys in the clear).
    #[cfg(unix)]
    #[test]
    fn recording_with_remote_media_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("sbc.crt");
        let config = recording_config(dir.path(), "sips:127.0.0.1:5061", &ca);
        assert!(Server::recording_startup_check(&config, &[]).is_ok());
        let err = Server::recording_startup_check(&config, &["http://media-1:50051".to_string()])
            .unwrap_err();
        assert!(err.contains("remote media plane"), "{err}");
    }

    // The RS Via / Contact advertise the TLS listener, which is bound only
    // with a certificate: recording without one refuses to start.
    #[cfg(unix)]
    #[tokio::test]
    async fn recording_without_tls_certificate_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("sbc.crt");
        let full = recording_config(dir.path(), "sips:127.0.0.1:5061", &ca);
        for strip in ["cert", "key", "listener"] {
            let mut config = full.clone();
            match strip {
                "cert" => config.security.tls_cert_path = None,
                "key" => config.security.tls_key_path = None,
                _ => config.transport.tls_listen.clear(),
            }
            let mut server = Server::new(config, ShutdownSignal::new(), None);
            let err = startup_error(server.start().await);
            assert!(
                err.contains("TLS listener with a certificate"),
                "{strip}: {err}"
            );
            assert!(!server.sip_stack().recording_enabled(), "{strip}");
        }
    }

    // The SRS host is resolved once at startup; failure is a startup error.
    #[cfg(unix)]
    #[tokio::test]
    async fn recording_with_unresolvable_srs_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("sbc.crt");
        let config = recording_config(dir.path(), "sips:srs.recorder.invalid:5061", &ca);
        let mut server = Server::new(config, ShutdownSignal::new(), None);
        let err = startup_error(server.wire_recording().await);
        assert!(err.contains("does not resolve"), "{err}");
        assert!(!server.sip_stack().recording_enabled());
        // Not a sips: URI (validation rejects it first; the daemon too).
        let config = recording_config(dir.path(), "sip:127.0.0.1:5060", &ca);
        let mut server = Server::new(config, ShutdownSignal::new(), None);
        let err = startup_error(server.wire_recording().await);
        assert!(err.contains("sips:"), "{err}");
    }

    // An SRS CA bundle that is missing or holds no certificate is a
    // startup error: the recorder is never dialled unverified.
    #[cfg(unix)]
    #[tokio::test]
    async fn recording_with_unloadable_srs_ca_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let missing = dir.path().join("missing.pem");
        for ca in [&empty, &missing] {
            let config = recording_config(dir.path(), "sips:127.0.0.1:5061", ca);
            let mut server = Server::new(config, ShutdownSignal::new(), None);
            let err = startup_error(server.wire_recording().await);
            assert!(err.contains("recording.srs_tls_ca_file"), "{err}");
            assert!(!server.sip_stack().recording_enabled());
        }
    }

    // With a resolvable SRS, a loadable CA and the SBC certificate, the
    // settings are attached and the recorder TLS profile is loaded (a
    // recorder flow no longer fails for want of a client config).
    #[cfg(unix)]
    #[tokio::test]
    async fn recording_wires_settings_and_the_recorder_tls_profile() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("sbc.crt");
        let config = recording_config(dir.path(), "sips:127.0.0.1:59", &ca);
        let mut server = Server::new(config, ShutdownSignal::new(), None);
        let capture = uc_audit::capture::start();
        server.wire_recording().await.unwrap();
        assert!(server.sip_stack().recording_enabled());
        // POA&M-166: the client key load is audited.
        assert!(
            key_ops(&capture.events())
                .iter()
                .any(|k| k.key_id == "recorder-tls-client:sbc.key"),
            "recorder client key load audited"
        );
        let name: Arc<str> = Arc::from("127.0.0.1");
        let flow = LegFlow::recorder(&name);
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 59);
        let err = server
            .flows()
            .send(&flow, &dest, b"x", None)
            .await
            .unwrap_err();
        assert_ne!(
            err,
            crate::flows::FlowError::NoTlsClient,
            "the recorder profile is loaded (the dial itself fails: nothing listens)"
        );
        // The trunk profiles were not loaded by this: a trunk TLS flow to
        // the same address still has no client config (separate profiles).
        let trunk = LegFlow::trunk_shared(uc_routing::TrunkProtocol::Tls, &name, false);
        assert_eq!(
            server
                .flows()
                .send(&trunk, &dest, b"x", None)
                .await
                .unwrap_err(),
            crate::flows::FlowError::NoTlsClient
        );
    }

    // AU-5: a failed RS INVITE send comes back to the stack with its cause:
    // a TLS / certificate failure is `srs_tls`, a refused connection is
    // `srs_unreachable`. Nothing is retried on another transport.
    #[tokio::test]
    async fn failed_rs_invite_send_reports_tls_or_unreachable() {
        use crate::sip_stack::tests::rs_invite_for_server;
        use sbc_config::schema::RecordingFailureAction;
        use uc_audit::event::RecordingFailReason;

        let self_signed = || {
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            let cert = rcgen::CertificateParams::new(vec!["srs.example.test".to_string()])
                .unwrap()
                .self_signed(&kp)
                .unwrap();
            (cert.der().clone(), kp.serialize_der())
        };
        // The recorder client trusts another certificate than the one the
        // "SRS" presents.
        let (trusted, _) = self_signed();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted).unwrap();
        let recorder_client = Arc::new(
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots,
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_auth: None,
            })
            .unwrap(),
        );
        let (presented, key) = self_signed();
        let server_cfg = uc_transport::tls::create_server_config(
            vec![presented],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
        let listener = TlsListener::bind(
            ListenerConfig::new(
                SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0),
                TransportType::Tls,
            ),
            Arc::new(server_cfg),
        )
        .await
        .unwrap();
        let untrusted_srs = *listener.local_addr();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        // A port nothing listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            SbcSocketAddr::from(l.local_addr().unwrap())
        };

        for (srs, reason) in [
            (untrusted_srs, RecordingFailReason::SrsTls),
            (closed, RecordingFailReason::SrsUnreachable),
        ] {
            let (stack, invite) =
                Box::pin(rs_invite_for_server(srs, RecordingFailureAction::Continue)).await;
            let stack = Arc::new(stack);
            let flows = Arc::new(FlowTable::new(4));
            flows.set_recorder_tls_client(Arc::clone(&recorder_client));
            let ctx = none_ctx(&stack, &flows);
            Server::dispatch(invite, &ctx).await;
            let reported = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while stack.recording_counters().failed(reason) != 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            assert!(
                reported,
                "{reason:?} not reported: {:?}",
                stack.recording_counters().metric_values()
            );
            assert_eq!(stack.recording_counters().slots_held(), 0);
            assert_eq!(
                flows.stats.egress_connections.load(Ordering::Relaxed),
                0,
                "no connection kept"
            );
        }
    }

    // PERF-001 (SC-5, AU-5): an RS BYE / CANCEL / ACK refused by a full
    // recorder lane is a recording drop and is counted as one (TLS has no
    // retransmission: the SRS keeps the session until its own timeout). A
    // dropped RS INVITE is not counted here; it is reported as a failed
    // send and goes through the failure policy.
    #[tokio::test]
    async fn rs_bye_dropped_by_a_full_recorder_lane_is_counted() {
        use crate::sip_stack::tests::rs_invite_for_server;
        use sbc_config::schema::RecordingFailureAction;
        use uc_audit::event::RecordingFailReason;

        let srs = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 50), 5061);
        let (stack, invite) =
            Box::pin(rs_invite_for_server(srs, RecordingFailureAction::Continue)).await;
        let stack = Arc::new(stack);
        let flows = Arc::new(FlowTable::new(4));
        let lane = (TransportType::Tls, srs);
        while flows.enqueue(lane, Box::pin(std::future::pending())) {}
        let lane_dropped = flows.stats.lane_dropped.load(Ordering::Relaxed);
        let ctx = none_ctx(&stack, &flows);
        let dropped = || {
            stack
                .recording_counters()
                .metric_values()
                .into_iter()
                .find(|(name, _)| *name == crate::recording::METRIC_RS_BYE_DROPPED)
                .map(|(_, v)| v)
        };
        assert_eq!(dropped(), Some(0));

        let forwarded = match invite {
            ProcessResult::Forward {
                message: SipMessage::Request(request),
                destination,
                flow,
            } => Some((request, destination, flow)),
            _ => None,
        };
        let (request, destination, flow) = forwarded.expect("RS INVITE is a forwarded request");
        for (n, method) in [Method::Bye, Method::Cancel, Method::Ack]
            .into_iter()
            .enumerate()
        {
            let mut wind_down = request.clone();
            wind_down.method = method;
            Server::dispatch(
                ProcessResult::Forward {
                    message: SipMessage::Request(wind_down),
                    destination,
                    flow: flow.clone(),
                },
                &ctx,
            )
            .await;
            assert_eq!(dropped(), Some(n as u64 + 1));
        }
        assert_eq!(
            flows.stats.lane_dropped.load(Ordering::Relaxed),
            lane_dropped + 3,
            "still counted as lane drops too"
        );

        // The INVITE itself: a failed send, not a BYE drop.
        Server::dispatch(
            ProcessResult::Forward {
                message: SipMessage::Request(request),
                destination,
                flow,
            },
            &ctx,
        )
        .await;
        assert_eq!(dropped(), Some(3));
        assert_eq!(
            stack
                .recording_counters()
                .failed(RecordingFailReason::SrsUnreachable),
            1
        );
    }

    // PERF-008 (fix round 2), AU-5 / SC-5: the RS BYEs of the calls ended
    // at shutdown are queued after the timer loop is gone. The shutdown
    // flush hands them to the recorder's lane in paced batches; what the
    // bound does not allow is counted as dropped, and the queue ends empty.
    #[tokio::test]
    async fn shutdown_flush_sends_queued_rs_byes_or_counts_them() {
        use crate::sip_stack::tests::rs_byes_queued_at_shutdown;
        use std::sync::atomic::AtomicUsize;

        let dropped = |stack: &SipStack| {
            stack
                .recording_counters()
                .metric_values()
                .into_iter()
                .find(|(name, _)| *name == crate::recording::METRIC_RS_BYE_DROPPED)
                .map(|(_, v)| v)
        };
        let bound = std::time::Duration::from_secs(5);

        // The lane is free: every BYE is handed to it (the send itself
        // fails here, no recorder TLS client is configured) and nothing is
        // counted as dropped.
        let (stack, srs) = Box::pin(rs_byes_queued_at_shutdown(2)).await;
        let stack = Arc::new(stack);
        let flows = Arc::new(FlowTable::new(4));
        let ctx = none_ctx(&stack, &flows);
        assert_eq!(Server::flush_rs_wind_down(&ctx, bound).await, 0);
        assert_eq!(dropped(&stack), Some(0));
        assert!(stack.recording_shutdown_batch().is_empty(), "queue empty");
        assert!(!flows.lane_busy(&(TransportType::Tls, srs)), "lane drained");
        assert_eq!(flows.stats.lane_dropped.load(Ordering::Relaxed), 0);

        // More BYEs than one batch, and a recorder lane that never drains:
        // the first batch is queued behind the stuck send, the bound
        // expires, and the BYEs still on the wind-down queue are counted.
        let per_batch = crate::flows::LANE_DEPTH / 4;
        let (stack, srs) = Box::pin(rs_byes_queued_at_shutdown(per_batch + 2)).await;
        let stack = Arc::new(stack);
        let flows = Arc::new(FlowTable::new(4));
        let ran = Arc::new(AtomicUsize::new(0));
        let started = Arc::clone(&ran);
        assert!(flows.enqueue(
            (TransportType::Tls, srs),
            Box::pin(async move {
                started.fetch_add(1, Ordering::Relaxed);
                std::future::pending::<()>().await;
            }),
        ));
        let ctx = none_ctx(&stack, &flows);
        let begun = tokio::time::Instant::now();
        let left = Server::flush_rs_wind_down(&ctx, std::time::Duration::from_millis(50)).await;
        assert!(begun.elapsed() < bound, "bounded");
        assert_eq!(left, 2, "the second batch never left the queue");
        assert_eq!(dropped(&stack), Some(2));
        assert!(stack.recording_shutdown_batch().is_empty(), "queue empty");
        assert_eq!(
            flows.stats.lane_dropped.load(Ordering::Relaxed),
            0,
            "the first batch fits the lane"
        );
        assert_eq!(ran.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn wire_bytes_are_wiped_when_uniquely_owned() {
        // A shared buffer is left alone (no panic); a unique one is consumed.
        let shared = bytes::Bytes::from(vec![7u8; 32]);
        let other = shared.clone();
        wipe_wire_bytes(shared);
        assert_eq!(&other[..], &[7u8; 32][..]);
        wipe_wire_bytes(other);
    }

    // SR-55: separate UDP and stream limiters, UDP reject-not-block, and
    // configured trunk IPs as trusted sources. Written against the planned
    // API (`LimiterKind`, `udp_rate_limiter` / `stream_rate_limiter`,
    // `SipStack::trunk_sources`, `Server::apply_trusted_sources`,
    // `rate_limit.udp_auto_block` / `trunk_rps`).
    mod sr55 {
        use super::*;
        use std::collections::HashSet;
        use std::net::IpAddr;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn trusted_set(ips: &[IpAddr]) -> HashSet<IpAddr> {
            ips.iter().copied().collect()
        }

        #[tokio::test]
        async fn udp_limiter_from_default_config_never_auto_blocks() {
            let config = SbcConfig::default();
            assert!(!config.rate_limit.udp_auto_block);
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let global = Server::build_global_limiter(&config);
            let stats = ServerStats::default();
            let src = ip("192.0.2.66");
            let mut rejected = 0;
            for _ in 0..1_000 {
                if !Server::rate_limit_allows(src, &udp, &global, &stats).await {
                    rejected += 1;
                }
            }
            assert!(rejected > 0);
            let l = udp.lock().await;
            assert_eq!(l.blocked_sources(), 0);
            assert!(!l.is_blocked(src));
        }

        #[tokio::test]
        async fn udp_auto_block_true_restores_blocking() {
            let mut config = SbcConfig::default();
            config.rate_limit.udp_auto_block = true;
            config.rate_limit.per_ip_rps = 2;
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let global = Server::build_global_limiter(&config);
            let stats = ServerStats::default();
            let src = ip("192.0.2.67");
            for _ in 0..50 {
                let _ = Server::rate_limit_allows(src, &udp, &global, &stats).await;
            }
            assert!(udp.lock().await.is_blocked(src));
        }

        #[tokio::test]
        async fn stream_limiter_still_auto_blocks() {
            let mut config = SbcConfig::default();
            config.rate_limit.per_ip_rps = 2;
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let global = Server::build_global_limiter(&config);
            let stats = ServerStats::default();
            let src = ip("192.0.2.68");
            for _ in 0..50 {
                let _ = Server::rate_limit_allows(src, &stream, &global, &stats).await;
            }
            assert!(stream.lock().await.is_blocked(src));
        }

        #[tokio::test]
        async fn udp_flood_does_not_reject_stream_frames() {
            let config = SbcConfig::default();
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let global = Server::build_global_limiter(&config);
            let stats = ServerStats::default();
            let src = ip("192.0.2.69");
            let mut rejected = 0;
            for _ in 0..1_000 {
                if !Server::rate_limit_allows(src, &udp, &global, &stats).await {
                    rejected += 1;
                }
            }
            assert!(rejected > 0);
            assert!(Server::rate_limit_allows(src, &stream, &global, &stats).await);
        }

        // The daemon wires two distinct limiters; a UDP-earned block does
        // not stop an established stream connection from that address.
        #[tokio::test]
        async fn stream_connection_ignores_udp_block() {
            let mut config = SbcConfig::default();
            config.rate_limit.udp_auto_block = true;
            config.rate_limit.per_ip_rps = 2;
            let server = Server::new(config, ShutdownSignal::new(), None);
            assert!(!Arc::ptr_eq(
                &server.udp_rate_limiter,
                &server.stream_rate_limiter
            ));
            // spawn_stream's peer address.
            let peer = ip("192.0.2.20");
            {
                let mut udp = server.udp_rate_limiter.lock().await;
                for _ in 0..50 {
                    let _ = udp.check(peer);
                }
                assert!(udp.is_blocked(peer), "UDP limiter did not block");
            }
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.rate_limiter = Arc::clone(&server.stream_rate_limiter);
            ctx.global_limiter = Arc::clone(&server.global_limiter);
            let stats = Arc::clone(&ctx.stats);
            let (tx, fake, task) = spawn_stream(ctx);
            tx.send(OPTIONS_KA.to_vec()).unwrap();
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if !fake.sent.lock().unwrap().is_empty() {
                    break;
                }
            }
            let sent = fake.sent.lock().unwrap().clone();
            assert_eq!(sent.len(), 1, "no response on the stream: {sent:?}");
            assert!(sent[0].starts_with(b"SIP/2.0 "));
            assert_eq!(stats.rate_limited.load(Ordering::Relaxed), 0);
            task.abort();
        }

        #[tokio::test]
        async fn trunk_ip_trusted_on_both_limiters_after_sync() {
            let config = SbcConfig::default();
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            let mut rx = stack.trunk_sources();
            let t = ip("203.0.113.9");
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[t]))
                .await;
            assert!(rx.has_changed().unwrap(), "no snapshot published");
            let set = rx.borrow_and_update().clone();
            assert!(set.contains(&t));
            Server::apply_trusted_sources(&set, &udp, &stream).await;
            assert!(udp.lock().await.is_trusted(t));
            assert!(stream.lock().await.is_trusted(t));
        }

        #[tokio::test]
        async fn trunk_removal_untrusts() {
            let config = SbcConfig::default();
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            let mut rx = stack.trunk_sources();
            let t = ip("203.0.113.10");
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[t]))
                .await;
            let set = rx.borrow_and_update().clone();
            Server::apply_trusted_sources(&set, &udp, &stream).await;
            assert!(udp.lock().await.is_trusted(t));

            stack.remove_trunk_group_from_router("g").await;
            assert!(rx.has_changed().unwrap(), "removal not published");
            let set = rx.borrow_and_update().clone();
            assert!(!set.contains(&t));
            Server::apply_trusted_sources(&set, &udp, &stream).await;
            assert!(!udp.lock().await.is_trusted(t));
            assert!(!stream.lock().await.is_trusted(t));
        }

        #[tokio::test]
        async fn config_file_trunks_trusted_at_start() {
            let config = sbc_config::load_from_str(
                r#"
                [[trunk_groups]]
                id = "g"
                name = "g"
                [[trunk_groups.trunks]]
                id = "a"
                host = "192.0.2.1"
            "#,
            )
            .unwrap();
            let server = Server::new(config, ShutdownSignal::new(), None);
            let t = ip("192.0.2.1");
            let set = server.sip_stack.trunk_sources().borrow().clone();
            assert!(set.contains(&t), "config trunk missing from snapshot");
            Server::apply_trusted_sources(
                &set,
                &server.udp_rate_limiter,
                &server.stream_rate_limiter,
            )
            .await;
            assert!(server.udp_rate_limiter.lock().await.is_trusted(t));
            assert!(server.stream_rate_limiter.lock().await.is_trusted(t));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn trunk_rps_rejections_audited_by_transport() {
            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.rate_limit.per_ip_rps = 1;
            config.rate_limit.trunk_rps = 2;
            let t = ip("203.0.113.11");
            let mut unblocked = Vec::new();
            let mut audit = RateLimitAudit::new(&config);
            for kind in [LimiterKind::Udp, LimiterKind::Stream] {
                let limiter = Server::build_rate_limiter(&config, kind);
                let mut l = limiter.lock().await;
                let _ = l.set_trusted_sources([t]);
                for _ in 0..100 {
                    let _ = l.check(t);
                }
                audit.sweep_per_ip(&mut l, kind, &mut unblocked);
            }
            audit.flush();
            let records = rate_limit_records(&capture.events());
            for label in ["trunk_rps_udp", "trunk_rps_stream"] {
                let trunk: Vec<_> = records.iter().filter(|r| r.limit_name == label).collect();
                assert_eq!(trunk.len(), 1, "{label}: {records:?}");
                assert_eq!(trunk[0].source_ip, t);
                assert!(trunk[0].request_count > 0);
                assert_eq!(
                    trunk[0].threshold,
                    u64::from(config.rate_limit.effective_trunk_rps())
                );
            }
            assert!(
                !records
                    .iter()
                    .any(|r| r.source_ip == t && r.limit_name.starts_with("per_ip")),
                "{records:?}"
            );
        }

        // NIST-004: with a record cap of 1, both the trunk record and one
        // per-source record are kept.
        #[tokio::test(flavor = "current_thread")]
        async fn trunk_record_survives_audit_cap() {
            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.rate_limit.per_ip_rps = 1;
            config.rate_limit.trunk_rps = 2;
            config.rate_limit.audit_max_records_per_interval = 1;
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let t = ip("203.0.113.14");
            let other = ip("198.51.100.7");
            let mut unblocked = Vec::new();
            {
                let mut l = udp.lock().await;
                let _ = l.set_trusted_sources([t]);
                for _ in 0..100 {
                    let _ = l.check(other);
                    let _ = l.check(t);
                }
                let mut audit = RateLimitAudit::new(&config);
                audit.sweep_per_ip(&mut l, LimiterKind::Udp, &mut unblocked);
                audit.flush();
            }
            let records = rate_limit_records(&capture.events());
            assert!(
                records
                    .iter()
                    .any(|r| r.source_ip == t && r.limit_name == "trunk_rps_udp"),
                "{records:?}"
            );
            // The trunk record does not take a per-source slot.
            assert!(
                records
                    .iter()
                    .any(|r| r.source_ip == other && r.limit_name == "per_ip_rps"),
                "{records:?}"
            );
        }

        // SEC-006: per-source records from an earlier sweep fill the cap;
        // trunk records reported by later sweeps of the same interval, on
        // either limiter, are still emitted.
        #[tokio::test(flavor = "current_thread")]
        async fn trunk_records_survive_cap_filled_by_earlier_sweep() {
            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.rate_limit.per_ip_rps = 1;
            config.rate_limit.trunk_rps = 2;
            config.rate_limit.audit_max_records_per_interval = 1;
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let t = ip("203.0.113.15");
            let others = [ip("198.51.100.8"), ip("198.51.100.9")];
            let mut unblocked = Vec::new();
            let mut audit = RateLimitAudit::new(&config);
            // Sweep 1: only untrusted sources reject; they fill the cap.
            for (kind, limiter) in [(LimiterKind::Udp, &udp), (LimiterKind::Stream, &stream)] {
                let mut l = limiter.lock().await;
                let _ = l.set_trusted_sources([t]);
                for other in others {
                    for _ in 0..100 {
                        let _ = l.check(other);
                    }
                }
                audit.sweep_per_ip(&mut l, kind, &mut unblocked);
            }
            // Sweep 2: the trunk rejects on both limiters.
            for (kind, limiter) in [(LimiterKind::Udp, &udp), (LimiterKind::Stream, &stream)] {
                let mut l = limiter.lock().await;
                for _ in 0..100 {
                    let _ = l.check(t);
                }
                audit.sweep_per_ip(&mut l, kind, &mut unblocked);
            }
            audit.flush();
            let records = rate_limit_records(&capture.events());
            let per_source = records
                .iter()
                .filter(|r| r.limit_name == "per_ip_rps")
                .count();
            assert_eq!(per_source, 1, "cap not filled first: {records:?}");
            assert!(
                records
                    .iter()
                    .any(|r| r.limit_name == "per_ip_rps_suppressed"),
                "{records:?}"
            );
            for label in ["trunk_rps_udp", "trunk_rps_stream"] {
                assert!(
                    records
                        .iter()
                        .any(|r| r.source_ip == t && r.limit_name == label),
                    "{label}: {records:?}"
                );
            }
        }

        // SEC-005: a stream-limiter flood from a /64 neighbour blocks the
        // prefix, but the trusted trunk's stream connection is still
        // answered.
        #[tokio::test]
        async fn trusted_trunk_stream_answered_under_prefix_block() {
            let trunk = ip("2001:db8::5");
            let neighbour = ip("2001:db8::66");
            let mut ctx = stream_test_ctx(short_timeouts());
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[trunk]))
                .await;
            let trunks = stack.trunk_sources().borrow().clone();
            let other = Server::build_rate_limiter(&SbcConfig::default(), LimiterKind::Udp);
            Server::apply_trusted_sources(&trunks, &other, &ctx.rate_limiter).await;
            {
                let mut l = ctx.rate_limiter.lock().await;
                assert!(l.is_trusted(trunk));
                let mut blocked = false;
                for _ in 0..10_000 {
                    if matches!(l.check(neighbour), RateLimitAction::Block { .. }) {
                        blocked = true;
                        break;
                    }
                }
                assert!(blocked, "/64 not blocked by the flood");
                assert!(l.is_blocked(ip("2001:db8::77")));
                assert!(!l.is_blocked(trunk));
            }
            ctx.global_limiter = Arc::new(Mutex::new(RateLimiter::new(
                RateLimiterConfig::new(1_000_000, 1_000_000).with_per_ip(false),
            )));
            let stats = Arc::clone(&ctx.stats);
            let peer = SbcSocketAddr::from(std::net::SocketAddr::new(trunk, 40000));
            let (tx, fake, task) = spawn_stream_from(ctx, TransportType::Tcp, peer);
            tx.send(OPTIONS_KA.to_vec()).unwrap();
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if !fake.sent.lock().unwrap().is_empty() {
                    break;
                }
            }
            let sent = fake.sent.lock().unwrap().clone();
            assert_eq!(sent.len(), 1, "trunk not answered: {sent:?}");
            assert!(sent[0].starts_with(b"SIP/2.0 "));
            assert_eq!(stats.rate_limited.load(Ordering::Relaxed), 0);
            task.abort();
        }

        // SEC-004 / PERF-004: an unchanged key set is not republished.
        #[tokio::test]
        async fn unchanged_trunk_set_not_republished() {
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            let mut rx = stack.trunk_sources();
            let t = ip("203.0.113.15");
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[t]))
                .await;
            assert!(rx.has_changed().unwrap());
            let _ = rx.borrow_and_update();
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[t]))
                .await;
            assert!(!rx.has_changed().unwrap(), "unchanged set republished");
        }

        // SEC-004: the published set is capped, keeping the lowest
        // addresses.
        #[tokio::test]
        async fn trunk_set_capped_deterministically() {
            let max = uc_dos_protection::MAX_TRUSTED_SOURCES;
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            let ips: HashSet<IpAddr> = (0..u32::try_from(max).unwrap() + 5)
                .map(|n| IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n)))
                .collect();
            stack.register_inbound_trunk_ips("g", None, &ips).await;
            let set = stack.trunk_sources().borrow().clone();
            assert_eq!(set.len(), max);
            assert!(set.is_sorted());
            assert_eq!(set[0], IpAddr::V4(Ipv4Addr::from(0x0A00_0000)));
            assert!(!set.contains(&IpAddr::V4(Ipv4Addr::from(
                0x0A00_0000 | u32::try_from(max).unwrap()
            ))));
        }

        // The sync task applies each published snapshot to both limiters.
        #[tokio::test]
        async fn trusted_source_sync_task_follows_trunk_changes() {
            let config = SbcConfig::default();
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let stream = Server::build_rate_limiter(&config, LimiterKind::Stream);
            let stack = SipStack::new(crate::sip_stack::SipStackConfig::default());
            let conns = Arc::new(Server::build_conn_limiter(&config));
            let task = tokio::spawn(Server::trusted_source_sync(
                stack.trunk_sources(),
                Arc::clone(&udp),
                Arc::clone(&stream),
                Arc::clone(&conns),
            ));
            let t = ip("203.0.113.13");
            stack
                .register_inbound_trunk_ips("g", None, &trusted_set(&[t]))
                .await;
            let mut synced = false;
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if udp.lock().await.is_trusted(t)
                    && stream.lock().await.is_trusted(t)
                    && conns.is_trusted(t)
                {
                    synced = true;
                    break;
                }
            }
            assert!(synced, "sync task did not apply the snapshot");
            stack.remove_trunk_group_from_router("g").await;
            let mut cleared = false;
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if !udp.lock().await.is_trusted(t)
                    && !stream.lock().await.is_trusted(t)
                    && !conns.is_trusted(t)
                {
                    cleared = true;
                    break;
                }
            }
            assert!(cleared, "sync task did not apply the removal");
            task.abort();
        }

        // POA&M-451: trusted sources still draw from the global bucket.
        #[tokio::test]
        async fn trusted_trunk_still_charged_to_global() {
            let mut config = SbcConfig::default();
            config.rate_limit.per_ip_rps = 1;
            config.rate_limit.trunk_rps = 1_000;
            let udp = Server::build_rate_limiter(&config, LimiterKind::Udp);
            let global = Arc::new(Mutex::new(RateLimiter::new(
                RateLimiterConfig::new(5, 5).with_per_ip(false),
            )));
            let stats = ServerStats::default();
            let t = ip("203.0.113.12");
            udp.lock().await.set_trusted_sources([t]);
            let mut allowed = 0;
            for _ in 0..100 {
                if Server::rate_limit_allows(t, &udp, &global, &stats).await {
                    allowed += 1;
                }
            }
            assert!(allowed < 100);
            assert!(global.lock().await.take_global_rejections() > 0);
            assert!(!udp.lock().await.is_blocked(t));
        }
    }

    // ---- SR-22 / SR-56 accept path (behaviour tests on existing APIs) ----

    const LOCALHOST_IP: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// Connects to `listen` and resets the connection (`SO_LINGER` 0)
    /// before the server accepts it. The kernel keeps it in the accept
    /// queue; `getpeername` on the accepted socket then fails.
    #[cfg(unix)]
    fn reset_before_accept(listen: std::net::SocketAddr) {
        use socket2::{Domain, Protocol, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        sock.connect(&listen.into()).unwrap();
        sock.set_linger(Some(std::time::Duration::ZERO)).unwrap();
        drop(sock);
    }

    /// Polls the flow table for an inbound TCP flow to `peer` for up to
    /// `within`; returns whether a `ping` could be sent on it.
    async fn tcp_flow_registered(
        flows: &FlowTable,
        peer: &SbcSocketAddr,
        within: std::time::Duration,
    ) -> bool {
        let flow = LegFlow::inbound(TransportType::Tcp);
        let t0 = std::time::Instant::now();
        while t0.elapsed() < within {
            if flows.send(&flow, peer, b"ping", None).await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    }

    async fn ws_test_listener() -> (Arc<WebSocketListener>, std::net::SocketAddr) {
        let bind = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0);
        let listener = WebSocketListener::bind(&bind, false)
            .await
            .unwrap()
            .with_options(WebSocketListenerOptions {
                require_sip_subprotocol: true,
            });
        let addr = listener.bound_addr().unwrap();
        (Arc::new(listener), addr)
    }

    /// A TLS listener on 127.0.0.1 with a fresh P-384 certificate for
    /// `sbc.example.test`, and a client config that trusts it.
    async fn tls_test_listener() -> (Arc<TlsListener>, Arc<rustls::ClientConfig>) {
        tls_test_listener_on(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0)).await
    }

    /// [`tls_test_listener`] bound to `bind`.
    async fn tls_test_listener_on(
        bind: SbcSocketAddr,
    ) -> (Arc<TlsListener>, Arc<rustls::ClientConfig>) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["sbc.example.test".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client =
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots,
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_auth: None,
            })
            .unwrap();
        let server = uc_transport::tls::create_server_config(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                kp.serialize_der(),
            )),
        )
        .unwrap();
        let listener = TlsListener::bind(
            ListenerConfig::new(bind, TransportType::Tls),
            Arc::new(server),
        )
        .await
        .unwrap();
        (Arc::new(listener), Arc::new(client))
    }

    /// Runs a TLS client handshake against `addr` (5 s bound); `true` when
    /// it completes.
    async fn tls_handshake_ok(addr: SbcSocketAddr, client: &Arc<rustls::ClientConfig>) -> bool {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client));
        let name = rustls_pki_types::ServerName::try_from("sbc.example.test").unwrap();
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(std::net::SocketAddr::from(addr)).await?;
            connector.connect(name, tcp).await
        };
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), attempt).await,
            Ok(Ok(_))
        )
    }

    // SR-22 (NIST 800-53 Rev5: SC-5): connections reset before accept must
    // not stall the listener. Before SR-22 each one made
    // `TcpListener::accept` fail (getpeername) and the loop slept 100 ms,
    // so 20 of them delayed a good client by about 2 s.
    #[cfg(unix)]
    #[tokio::test]
    async fn tcp_accept_loop_does_not_stall_on_reset_connections() {
        let listener = TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen: std::net::SocketAddr = (*listener.local_addr()).into();
        let mut ctx = stream_test_ctx(short_timeouts());
        // All clients share 127.0.0.1: give the source room so admission
        // caps do not interfere with what is measured.
        ctx.conn_limiter = Arc::new(crate::conn_limit::ConnLimiter::new(64, 64));
        ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(64));
        ctx.total_conns = Arc::new(tokio::sync::Semaphore::new(64));
        let flows = Arc::clone(&ctx.flows);
        for _ in 0..20 {
            reset_before_accept(listen);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let accept = tokio::spawn(Server::tcp_accept_loop(Arc::new(listener), ctx));
        let t0 = std::time::Instant::now();
        let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
        let peer = SbcSocketAddr::from(client.local_addr().unwrap());
        let served =
            tcp_flow_registered(&flows, &peer, std::time::Duration::from_millis(300)).await;
        let waited = t0.elapsed();
        accept.abort();
        assert!(
            served,
            "good client not registered within 300 ms behind 20 reset connections \
             (waited {waited:?}): accept errors stall the listener (SR-22)"
        );
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ping");
    }

    // SR-56 (NIST 800-53 Rev5: SC-5, SC-7): a blocked source is refused at
    // accept, before the HTTP upgrade. Before SR-56 the upgrade answered
    // 101.
    #[tokio::test]
    async fn blocked_source_dropped_at_ws_accept_before_upgrade() {
        let ctx = stream_test_ctx(short_timeouts());
        {
            let mut limiter = ctx.rate_limiter.lock().await;
            assert!(limiter.block(LOCALHOST_IP, std::time::Duration::from_secs(60)));
            assert!(limiter.is_blocked(LOCALHOST_IP));
        }
        let (listener, addr) = ws_test_listener().await;
        let task = tokio::spawn(Server::ws_accept_loop(listener, ctx));
        let reply = ws_upgrade_status(addr).await;
        task.abort();
        assert_eq!(
            reply, None,
            "blocked source got an upgrade reply: is_blocked not checked at accept (SR-56)"
        );
    }

    // SR-56 (NIST 800-53 Rev5: SC-5, SC-7): a blocked source is refused
    // before the TLS handshake, so it costs no crypto. Before SR-56 it
    // completed.
    #[tokio::test]
    async fn blocked_source_dropped_at_tls_accept_before_handshake() {
        let ctx = stream_test_ctx(short_timeouts());
        assert!(
            ctx.rate_limiter
                .lock()
                .await
                .block(LOCALHOST_IP, std::time::Duration::from_secs(60))
        );
        let (listener, client) = tls_test_listener().await;
        let addr = *listener.local_addr();
        let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
        let completed = tls_handshake_ok(addr, &client).await;
        task.abort();
        assert!(
            !completed,
            "blocked source completed a TLS handshake: is_blocked not checked at accept (SR-56)"
        );
    }

    // SR-56 / SR-55 (NIST 800-53 Rev5: SC-5): the accept check reads the
    // stream limiter. A block on the daemon's UDP limiter does not refuse a
    // TLS accept from the same address.
    #[tokio::test]
    async fn udp_block_does_not_refuse_tls_accept() {
        let mut config = SbcConfig::default();
        config.rate_limit.udp_auto_block = true;
        let server = Server::new(config, ShutdownSignal::new(), None);
        assert!(
            server
                .udp_rate_limiter
                .lock()
                .await
                .block(LOCALHOST_IP, std::time::Duration::from_secs(60))
        );
        assert!(
            server
                .udp_rate_limiter
                .lock()
                .await
                .is_blocked(LOCALHOST_IP)
        );
        let mut ctx = stream_test_ctx(short_timeouts());
        ctx.rate_limiter = Arc::clone(&server.stream_rate_limiter);
        let stats = Arc::clone(&ctx.stats);
        let (listener, client) = tls_test_listener().await;
        let addr = *listener.local_addr();
        let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
        let completed = tls_handshake_ok(addr, &client).await;
        task.abort();
        assert!(
            completed,
            "UDP-limiter block refused a TLS accept: accept_blocked must use the stream limiter"
        );
        assert_eq!(stats.accept_blocked.load(Ordering::Relaxed), 0);
    }

    // SR-56 / SR-55 (NIST 800-53 Rev5: SC-5): a stream block on a /64
    // refuses the neighbour but not the configured trunk inside it.
    #[tokio::test]
    async fn trusted_trunk_accepted_under_prefix_block() {
        let trunk = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let neighbour: std::net::IpAddr = "::2".parse().unwrap();
        let ctx = stream_test_ctx(short_timeouts());
        {
            let mut l = ctx.rate_limiter.lock().await;
            assert_eq!(l.set_trusted_sources([trunk]), 0);
            assert!(l.block(neighbour, std::time::Duration::from_secs(60)));
            assert!(l.is_blocked("::3".parse().unwrap()), "/64 not blocked");
            assert!(!l.is_blocked(trunk));
        }
        let stats = Arc::clone(&ctx.stats);
        let (listener, client) =
            tls_test_listener_on(SbcSocketAddr::from(std::net::SocketAddr::new(trunk, 0))).await;
        let addr = *listener.local_addr();
        let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
        let completed = tls_handshake_ok(addr, &client).await;
        task.abort();
        assert!(
            completed,
            "trusted trunk refused at accept for a prefix block"
        );
        assert_eq!(stats.accept_blocked.load(Ordering::Relaxed), 0);
    }

    // SR-56 (NIST 800-53 Rev5: SC-5, SC-7): a blocked source's plain TCP
    // connection is dropped at accept and never reaches the flow table.
    #[tokio::test]
    async fn blocked_source_dropped_at_tcp_accept() {
        let listener = TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen: std::net::SocketAddr = (*listener.local_addr()).into();
        let ctx = stream_test_ctx(short_timeouts());
        assert!(
            ctx.rate_limiter
                .lock()
                .await
                .block(LOCALHOST_IP, std::time::Duration::from_secs(60))
        );
        let flows = Arc::clone(&ctx.flows);
        let task = tokio::spawn(Server::tcp_accept_loop(Arc::new(listener), ctx));
        let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
        let peer = SbcSocketAddr::from(client.local_addr().unwrap());
        let registered =
            tcp_flow_registered(&flows, &peer, std::time::Duration::from_millis(300)).await;
        assert!(
            !registered,
            "blocked source's TCP connection was admitted (SR-56)"
        );
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut client, &mut buf),
        )
        .await;
        task.abort();
        assert!(
            matches!(read, Ok(Ok(0) | Err(_))),
            "blocked connection must be closed by the server, got {read:?}"
        );
    }

    /// SR-22 / SR-56 tests for the accept-path API (`AcceptBackoff`,
    /// `StreamLoopContext::handshake_slots`, `ConnLimiter::with_accept_rate`
    /// / `with_handshake_cap`, `ServerStats` counters and audit labels).
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-12
    mod sr56_accept_api {
        use super::*;
        use crate::conn_limit::ConnLimiter;
        use std::time::Duration as D;
        use tokio::sync::Semaphore;
        use uc_transport::TransportError as E;

        fn transient() -> E {
            E::AcceptFailed {
                reason: "Software caused connection abort".into(),
                resource_exhausted: false,
                per_connection: true,
            }
        }

        /// A listener-level error (EBADF-like): neither resource nor
        /// per-connection.
        fn listener_fault() -> E {
            E::AcceptFailed {
                reason: "Bad file descriptor".into(),
                resource_exhausted: false,
                per_connection: false,
            }
        }

        fn exhausted() -> E {
            E::AcceptFailed {
                reason: "Too many open files".into(),
                resource_exhausted: true,
                per_connection: false,
            }
        }

        /// Connects to `addr` and sends one byte: readable at the server,
        /// so the TLS handshake takes a node-wide slot and then stalls.
        async fn stalled_tls_client(addr: SbcSocketAddr) -> tokio::net::TcpStream {
            use tokio::io::AsyncWriteExt;
            let mut s = tokio::net::TcpStream::connect(std::net::SocketAddr::from(addr))
                .await
                .unwrap();
            s.write_all(&[0x16]).await.unwrap();
            s
        }

        /// A connected, silent TCP socket to `addr` from 127.0.0.1. The
        /// slot-pool tests raise the per-source caps above the pool size
        /// instead of binding loopback aliases (127.0.0.2+), which macOS
        /// does not configure by default, so they run the same everywhere.
        async fn silent_socket(addr: SbcSocketAddr) -> tokio::net::TcpStream {
            tokio::net::TcpStream::connect(std::net::SocketAddr::from(addr))
                .await
                .unwrap()
        }

        // SR-22: only process-wide resource errors back off (10 ms doubling
        // to 1 s); a per-connection error continues at once.
        #[test]
        fn accept_backoff_only_on_resource_exhaustion() {
            let mut b = AcceptBackoff::new();
            for e in [
                transient(),
                E::Io {
                    reason: "Too many open files".into(),
                },
                E::ReceiveFailed {
                    reason: "accept failed".into(),
                },
            ] {
                assert_eq!(b.on_error(&e), None, "{e:?} must not back off");
            }
            let seq: Vec<Option<D>> = (0..9).map(|_| b.on_error(&exhausted())).collect();
            let want: Vec<Option<D>> = [10, 20, 40, 80, 160, 320, 640, 1_000, 1_000]
                .into_iter()
                .map(|ms| Some(D::from_millis(ms)))
                .collect();
            assert_eq!(seq, want);
            assert_eq!(
                b.on_error(&transient()),
                None,
                "a per-connection error never sleeps, even mid-backoff"
            );
            b.on_success();
            assert_eq!(b.on_error(&exhausted()), Some(D::from_millis(10)));
        }

        // SR-22 (PERF-002, SEC-009): a broken listener socket fails every
        // accept with a listener-level error. After 64 in a row with no
        // successful accept those errors back off too; a success resets the
        // run. Per-connection errors (peer aborts) never count and never
        // back off, however many arrive.
        #[test]
        fn accept_backoff_after_consecutive_non_resource_errors() {
            let mut b = AcceptBackoff::new();
            for i in 0..10_000 {
                assert_eq!(b.on_error(&transient()), None, "per-connection {i}");
            }
            for i in 1..AcceptBackoff::PERSISTENT {
                assert_eq!(b.on_error(&listener_fault()), None, "error {i}");
                assert_eq!(b.on_error(&transient()), None, "interleaved abort");
            }
            assert_eq!(b.on_error(&listener_fault()), Some(D::from_millis(10)));
            assert_eq!(b.on_error(&listener_fault()), Some(D::from_millis(20)));
            assert_eq!(
                b.on_error(&transient()),
                None,
                "a per-connection error never sleeps, even mid-backoff"
            );
            let capped: Vec<_> = (0..10)
                .filter_map(|_| b.on_error(&listener_fault()))
                .collect();
            assert_eq!(capped.last(), Some(&D::from_secs(1)), "capped at 1 s");
            b.on_success();
            assert_eq!(b.on_error(&listener_fault()), None, "run reset on success");
        }

        // NIST-006: node-wide handshake pool sizing.
        #[test]
        fn handshake_slot_count_sizing() {
            let mut tc = sbc_config::schema::TransportConfig {
                max_connections_total: 10,
                max_handshakes_in_flight: 0,
                ..Default::default()
            };
            assert_eq!(
                handshake_slot_count(&tc),
                10,
                "auto never exceeds the total"
            );
            tc.max_handshakes_in_flight = 5;
            assert_eq!(handshake_slot_count(&tc), 5, "explicit value");
            tc.max_handshakes_in_flight = 50;
            assert_eq!(
                handshake_slot_count(&tc),
                10,
                "explicit above total is clamped"
            );
            tc.max_handshakes_in_flight = 0;
            let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
            for total in [1_000_u32, 20_000, 1_000_000] {
                tc.max_connections_total = total;
                let total = total as usize;
                assert_eq!(
                    handshake_slot_count(&tc),
                    (cores * 64).max(total / 8).max(64).min(total),
                    "max(64 per core, total / 8), at most the total"
                );
            }
            // SEC-001: the default total gives at least 2,500 slots on any
            // core count, so 157 sources are needed to fill the pool.
            let defaults = sbc_config::schema::TransportConfig::default();
            let limits = HandshakeLimits::from_config(&defaults);
            assert!(limits.slots >= 2_500, "{limits:?}");
            assert_eq!(limits.per_source, 16, "{limits:?}");
        }

        // SEC-001: a slot is held at most min(2 s, handshake / 2); the slot
        // wait stays min(1 s, handshake / 4).
        #[test]
        fn handshake_slot_hold_budget() {
            let t = |ms| StreamTimeouts {
                handshake: D::from_millis(ms),
                ..short_timeouts()
            };
            assert_eq!(t(10_000).handshake_slot_hold(), D::from_secs(2));
            assert_eq!(t(60_000).handshake_slot_hold(), D::from_secs(2));
            assert_eq!(t(1_000).handshake_slot_hold(), D::from_millis(500));
            assert_eq!(t(10_000).handshake_slot_wait(), D::from_secs(1));
            assert_eq!(t(1_000).handshake_slot_wait(), D::from_millis(250));
        }

        // SEC-008: the startup log states the values in force whenever they
        // differ from the configured ones (auto pool, clamped cap).
        #[test]
        fn handshake_limits_differ_from_config() {
            let mut tc = sbc_config::schema::TransportConfig {
                max_connections_total: 1_024,
                max_connections_per_source: 128,
                max_handshakes_in_flight: 512,
                max_handshakes_per_source: 16,
                ..Default::default()
            };
            let limits = HandshakeLimits::from_config(&tc);
            assert_eq!((limits.slots, limits.per_source), (512, 16));
            assert!(!limits.differ_from(&tc), "explicit and unclamped");
            tc.max_handshakes_in_flight = 64;
            let limits = HandshakeLimits::from_config(&tc);
            assert_eq!(limits.per_source, 2, "1/32 of 64 slots");
            assert!(limits.differ_from(&tc), "clamped per-source cap");
            tc.max_handshakes_in_flight = 0;
            assert!(
                HandshakeLimits::from_config(&tc).differ_from(&tc),
                "auto-sized pool"
            );
        }

        // NIST-002: the per-source handshake cap is clamped to
        // max_connections_per_source and to 1/32 of the node-wide pool.
        #[test]
        fn handshakes_per_source_clamped() {
            let mut tc = sbc_config::schema::TransportConfig::default();
            assert_eq!(handshakes_per_source(&tc, 512), 16, "defaults");
            tc.max_connections_per_source = 8;
            assert_eq!(handshakes_per_source(&tc, 512), 8, "per-source connections");
            tc.max_connections_per_source = 128;
            assert_eq!(handshakes_per_source(&tc, 64), 2, "1/32 of the pool");
            assert_eq!(handshakes_per_source(&tc, 10), 1, "at least 1");
        }

        // SR-56 (SEC-005): WebSocket accepts do not use the accept bucket
        // (behind a WSS proxy the accept address is the proxy's) until
        // SR-59 keys WS admission on the client address.
        #[tokio::test]
        async fn ws_accept_not_rate_limited_by_accept_bucket() {
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_accept_rate(1, 1, 1_024));
            let stats = Arc::clone(&ctx.stats);
            let (listener, addr) = ws_test_listener().await;
            let task = tokio::spawn(Server::ws_accept_loop(listener, ctx));
            for i in 0..3 {
                let reply = ws_upgrade_status(addr).await.expect("upgrade answered");
                assert!(reply.starts_with("HTTP/1.1 101"), "upgrade {i}: {reply}");
            }
            task.abort();
            assert_eq!(stats.accept_rate_limited.load(Ordering::Relaxed), 0);
        }

        // SR-56: the TLS listener applies the same bucket before the
        // handshake.
        #[tokio::test]
        async fn accept_rate_drops_excess_tls_connections_before_handshake() {
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_accept_rate(1, 1, 1_024));
            let stats = Arc::clone(&ctx.stats);
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            assert!(tls_handshake_ok(addr, &client).await, "first handshake");
            assert!(
                !tls_handshake_ok(addr, &client).await,
                "second over the bucket"
            );
            task.abort();
            assert_eq!(stats.accept_rate_limited.load(Ordering::Relaxed), 1);
            assert_eq!(stats.handshake_timeouts.load(Ordering::Relaxed), 0);
        }

        // SR-56: plain TCP is admitted (bucket included) before the
        // transport is built; a refused accept never reaches the flow table.
        #[tokio::test]
        async fn accept_rate_drops_excess_tcp_connections() {
            let listener = TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let listen: std::net::SocketAddr = (*listener.local_addr()).into();
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_accept_rate(1, 1, 1_024));
            let stats = Arc::clone(&ctx.stats);
            let flows = Arc::clone(&ctx.flows);
            let task = tokio::spawn(Server::tcp_accept_loop(Arc::new(listener), ctx));
            let first = tokio::net::TcpStream::connect(listen).await.unwrap();
            let p1 = SbcSocketAddr::from(first.local_addr().unwrap());
            assert!(tcp_flow_registered(&flows, &p1, D::from_secs(1)).await);
            let second = tokio::net::TcpStream::connect(listen).await.unwrap();
            let p2 = SbcSocketAddr::from(second.local_addr().unwrap());
            assert!(!tcp_flow_registered(&flows, &p2, D::from_millis(300)).await);
            task.abort();
            assert_eq!(stats.accept_rate_limited.load(Ordering::Relaxed), 1);
        }

        // SR-56: with the node-wide handshake pool full, a new TLS
        // connection waits for a slot (it is not dropped) and proceeds once
        // one frees within the slot wait (1 s here).
        #[tokio::test]
        async fn tls_handshake_slot_waits_then_proceeds() {
            let mut ctx = stream_test_ctx(StreamTimeouts {
                handshake: D::from_secs(4),
                ..short_timeouts()
            });
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_handshake_cap(8));
            ctx.handshake_slots = Arc::new(Semaphore::new(1));
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            let holder = stalled_tls_client(addr).await;
            tokio::time::sleep(D::from_millis(100)).await;
            let second = tokio::spawn(async move { tls_handshake_ok(addr, &client).await });
            tokio::time::sleep(D::from_millis(200)).await;
            assert!(
                !second.is_finished(),
                "second handshake finished while the only handshake slot was held"
            );
            drop(holder);
            let done = tokio::time::timeout(D::from_secs(3), second)
                .await
                .expect("second handshake proceeds once the slot frees")
                .unwrap();
            task.abort();
            assert!(done, "second handshake completes");
        }

        // SR-56: the handshake slot is released when the handshake ends,
        // not when the connection closes.
        #[tokio::test]
        async fn handshake_slot_released_before_receive_loop() {
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_handshake_cap(8));
            ctx.handshake_slots = Arc::new(Semaphore::new(2));
            let slots = Arc::clone(&ctx.handshake_slots);
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            let connector = tokio_rustls::TlsConnector::from(client);
            let name = rustls_pki_types::ServerName::try_from("sbc.example.test").unwrap();
            let tcp = tokio::net::TcpStream::connect(std::net::SocketAddr::from(addr))
                .await
                .unwrap();
            let mut open = tokio::time::timeout(D::from_secs(5), connector.connect(name, tcp))
                .await
                .unwrap()
                .unwrap();
            let t0 = std::time::Instant::now();
            while slots.available_permits() != 2 && t0.elapsed() < D::from_secs(1) {
                tokio::time::sleep(D::from_millis(5)).await;
            }
            assert_eq!(
                slots.available_permits(),
                2,
                "handshake slot still held by an established connection"
            );
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(
                D::from_millis(200),
                tokio::io::AsyncReadExt::read(&mut open, &mut buf),
            )
            .await;
            assert!(
                read.is_err(),
                "established connection must stay open: {read:?}"
            );
            task.abort();
        }

        // SR-56 (SEC-001, PERF-001): the slot wait and the slot hold have
        // their own budgets inside the handshake deadline (1 s here: wait
        // 250 ms, hold 500 ms). A sends a byte and holds the only slot; B
        // arrives 100 ms later and is dropped after its 250 ms slot wait
        // (about 350 ms), counted as a slot timeout. A loses the slot at
        // its 500 ms hold budget, counted as a hold timeout, long before
        // the handshake deadline. Real time: paused time auto-advances past
        // socket I/O.
        #[tokio::test]
        async fn qa_handshake_slot_wait_has_own_budget() {
            let mut ctx = stream_test_ctx(StreamTimeouts {
                handshake: D::from_secs(1),
                ..short_timeouts()
            });
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_handshake_cap(8));
            ctx.handshake_slots = Arc::new(Semaphore::new(1));
            let stats = Arc::clone(&ctx.stats);
            let listener_pool = Arc::clone(&ctx.conn_semaphore);
            let total = Arc::clone(&ctx.total_conns);
            let limiter = Arc::clone(&ctx.conn_limiter);
            let slots = Arc::clone(&ctx.handshake_slots);
            let (listener, _client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            let t0 = std::time::Instant::now();
            let _a = stalled_tls_client(addr).await;
            tokio::time::sleep(D::from_millis(100)).await;
            let _b = stalled_tls_client(addr).await;
            tokio::time::sleep(D::from_millis(440).saturating_sub(t0.elapsed())).await;
            assert_eq!(
                stats.handshake_slot_timeouts.load(Ordering::Relaxed),
                1,
                "B gives up on the slot after its own budget"
            );
            assert_eq!(
                stats.handshake_slot_hold_timeouts.load(Ordering::Relaxed),
                0
            );
            tokio::time::sleep(D::from_millis(800).saturating_sub(t0.elapsed())).await;
            assert_eq!(
                stats.handshake_slot_hold_timeouts.load(Ordering::Relaxed),
                1,
                "A loses the slot at its hold budget"
            );
            assert_eq!(
                stats.handshake_timeouts.load(Ordering::Relaxed),
                0,
                "the hold budget fires before the handshake deadline"
            );
            assert_eq!(listener_pool.available_permits(), 4);
            assert_eq!(total.available_permits(), 4);
            assert_eq!(limiter.active(LOCALHOST_IP), 0);
            assert_eq!(slots.available_permits(), 1);
            task.abort();
        }

        // SR-56 (SEC-001): one-byte clients cannot hold the node-wide pool.
        // Slot-count clients from 127.0.0.1 (per-source caps raised above
        // the pool so only the pool limits them) each send one byte and
        // stall, taking every slot. Each loses its slot at the hold budget
        // (500 ms with a 1 s handshake deadline), and a real TLS client,
        // retrying as a client would after a dropped attempt, completes
        // its handshake within hold budget + slot wait of the pool
        // filling. The real handshake can take the first freed slot and
        // finish before the other stalled clients' hold timers fire, so
        // the hold-timeout count is awaited, bounded by the handshake
        // deadline (a missed hold would count as a handshake timeout).
        #[tokio::test]
        async fn one_byte_tls_clients_do_not_starve_handshake_slots() {
            use tokio::io::AsyncWriteExt;
            const SLOTS: usize = 8;
            let timeouts = StreamTimeouts {
                handshake: D::from_secs(1),
                ..short_timeouts()
            };
            let mut ctx = stream_test_ctx(timeouts);
            ctx.conn_limiter = Arc::new(ConnLimiter::new(64, 64).with_handshake_cap(64));
            ctx.conn_semaphore = Arc::new(Semaphore::new(64));
            ctx.total_conns = Arc::new(Semaphore::new(64));
            ctx.handshake_slots = Arc::new(Semaphore::new(SLOTS));
            let slots = Arc::clone(&ctx.handshake_slots);
            let stats = Arc::clone(&ctx.stats);
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            let mut stalled = Vec::new();
            for _ in 0..SLOTS {
                let mut s = silent_socket(addr).await;
                s.write_all(&[0x16]).await.unwrap();
                stalled.push(s);
            }
            let t0 = std::time::Instant::now();
            while slots.available_permits() != 0 && t0.elapsed() < D::from_secs(1) {
                tokio::time::sleep(D::from_millis(2)).await;
            }
            assert_eq!(
                slots.available_permits(),
                0,
                "one-byte clients hold every slot"
            );
            let filled = std::time::Instant::now();
            let budget = timeouts.handshake_slot_hold() + timeouts.handshake_slot_wait();
            let mut ok = false;
            while !ok && filled.elapsed() < budget {
                ok = tls_handshake_ok(addr, &client).await;
            }
            let took = filled.elapsed();
            assert!(
                ok,
                "real TLS handshake behind {SLOTS} one-byte clients did not complete \
                 within {budget:?} (took {took:?})"
            );
            let deadline = timeouts.handshake + D::from_millis(250);
            while stats.handshake_slot_hold_timeouts.load(Ordering::Relaxed) < SLOTS as u64
                && filled.elapsed() < deadline
            {
                tokio::time::sleep(D::from_millis(5)).await;
            }
            task.abort();
            assert_eq!(
                stats.handshake_slot_hold_timeouts.load(Ordering::Relaxed),
                SLOTS as u64,
                "every one-byte client lost its slot at the hold budget"
            );
            assert_eq!(stats.handshake_timeouts.load(Ordering::Relaxed), 0);
            drop(stalled);
        }

        // SR-56 (SEC-001, PERF-001): silent sockets hold no node-wide
        // handshake slot. Slot-count silent TLS sockets from 127.0.0.1
        // (per-source caps raised above the pool) leave every slot free,
        // and a real TLS handshake completes within 1 s.
        #[tokio::test]
        async fn silent_tls_sockets_do_not_starve_handshake_slots() {
            const SLOTS: usize = 8;
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(64, 64).with_handshake_cap(64));
            ctx.conn_semaphore = Arc::new(Semaphore::new(64));
            ctx.total_conns = Arc::new(Semaphore::new(64));
            ctx.handshake_slots = Arc::new(Semaphore::new(SLOTS));
            let slots = Arc::clone(&ctx.handshake_slots);
            let listener_pool = Arc::clone(&ctx.conn_semaphore);
            let stats = Arc::clone(&ctx.stats);
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            let mut silent = Vec::new();
            for _ in 0..SLOTS {
                silent.push(silent_socket(addr).await);
            }
            let t0 = std::time::Instant::now();
            while listener_pool.available_permits() != 64 - SLOTS && t0.elapsed() < D::from_secs(1)
            {
                tokio::time::sleep(D::from_millis(5)).await;
            }
            assert_eq!(
                listener_pool.available_permits(),
                64 - SLOTS,
                "every silent socket admitted"
            );
            assert_eq!(
                slots.available_permits(),
                SLOTS,
                "silent sockets hold no slot"
            );
            let ok = tokio::time::timeout(D::from_secs(1), tls_handshake_ok(addr, &client)).await;
            task.abort();
            assert!(
                matches!(ok, Ok(true)),
                "real TLS handshake behind {SLOTS} silent sockets did not complete within 1 s"
            );
            assert_eq!(stats.handshake_slot_timeouts.load(Ordering::Relaxed), 0);
            drop(silent);
        }

        // SR-56 (AU-12): accept-rate and blocked-source drops are counted
        // and audited in aggregate, one record per source per flush.
        #[tokio::test]
        async fn accept_rate_and_blocked_are_audited_in_aggregate() {
            let capture = uc_audit::capture::start();
            let config = SbcConfig::default();
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(ConnLimiter::new(8, 64).with_accept_rate(1, 1, 1_024));
            let stats = Arc::clone(&ctx.stats);
            let per_ip = Arc::clone(&ctx.rate_limiter);
            let global = Arc::clone(&ctx.global_limiter);
            let conns = Arc::clone(&ctx.conn_limiter);
            let (listener, client) = tls_test_listener().await;
            let addr = *listener.local_addr();
            let task = tokio::spawn(Server::tls_accept_loop(listener, ctx));
            assert!(tls_handshake_ok(addr, &client).await, "first handshake");
            assert!(!tls_handshake_ok(addr, &client).await, "over the bucket");
            assert!(per_ip.lock().await.block(LOCALHOST_IP, D::from_secs(60)));
            assert!(!tls_handshake_ok(addr, &client).await, "blocked");
            assert!(!tls_handshake_ok(addr, &client).await, "blocked");
            task.abort();
            assert_eq!(stats.accept_rate_limited.load(Ordering::Relaxed), 1);
            assert_eq!(stats.accept_blocked.load(Ordering::Relaxed), 2);

            let mut maint = RateLimitMaintenance::new(
                &config,
                ShutdownSignal::new(),
                Arc::clone(&per_ip),
                global,
                conns,
            );
            maint.sweep(true).await;
            let records = rate_limit_records(&capture.events());
            let named = |name: &str| -> Vec<_> {
                records
                    .iter()
                    .filter(|r| r.limit_name == name)
                    .cloned()
                    .collect()
            };
            let rate = named("per_ip_accept_rate");
            assert_eq!(rate.len(), 1, "{records:?}");
            assert_eq!(rate[0].source_ip, LOCALHOST_IP);
            assert_eq!(rate[0].request_count, 1, "counted once, not per path");
            assert_eq!(
                rate[0].threshold,
                u64::from(config.transport.accept_rate_per_source)
            );
            let blocked = named("accept_blocked");
            assert_eq!(blocked.len(), 1, "{records:?}");
            assert_eq!(blocked[0].source_ip, LOCALHOST_IP);
            assert_eq!(blocked[0].request_count, 2);

            maint.sweep(true).await;
            let again = rate_limit_records(&capture.events());
            assert_eq!(
                again
                    .iter()
                    .filter(|r| r.limit_name == "per_ip_accept_rate"
                        || r.limit_name == "accept_blocked")
                    .count(),
                2,
                "an idle interval emits no new accept records"
            );
        }

        // SR-56 (AU-12): per-source handshake-cap rejections are audited as
        // `handshake_busy`.
        #[test]
        fn handshake_busy_is_audited_in_aggregate() {
            let capture = uc_audit::capture::start();
            let limiter = Arc::new(ConnLimiter::new(8, 64).with_handshake_cap(1));
            let src: std::net::IpAddr = "192.0.2.60".parse().unwrap();
            let _held = limiter.try_begin_handshake(src).unwrap();
            assert!(limiter.try_begin_handshake(src).is_none());
            assert!(limiter.try_begin_handshake(src).is_none());
            let mut audit = RateLimitAudit::new(&SbcConfig::default());
            audit.collect_conns(&limiter);
            audit.flush();
            let records = rate_limit_records(&capture.events());
            let busy: Vec<_> = records
                .iter()
                .filter(|r| r.limit_name == "handshake_busy")
                .collect();
            assert_eq!(busy.len(), 1, "{records:?}");
            assert_eq!((busy[0].source_ip, busy[0].request_count), (src, 2));
        }

        // SEC-008: the handshake_busy threshold is the effective per-source
        // cap enforced at accept, not the configured value.
        #[test]
        fn handshake_busy_audit_threshold_is_effective_cap() {
            let mut config = SbcConfig::default();
            config.transport.max_connections_total = 1_024;
            config.transport.max_handshakes_in_flight = 64;
            config.transport.max_handshakes_per_source = 16;
            let effective = HandshakeLimits::from_config(&config.transport).per_source;
            assert_eq!(effective, 2, "1/32 of 64 slots");
            let capture = uc_audit::capture::start();
            let limiter = Arc::new(ConnLimiter::new(8, 64).with_handshake_cap(effective));
            let src: std::net::IpAddr = "192.0.2.61".parse().unwrap();
            let _a = limiter.try_begin_handshake(src).unwrap();
            let _b = limiter.try_begin_handshake(src).unwrap();
            assert!(limiter.try_begin_handshake(src).is_none());
            let mut audit = RateLimitAudit::new(&config);
            audit.collect_conns(&limiter);
            audit.flush();
            let records = rate_limit_records(&capture.events());
            let busy: Vec<_> = records
                .iter()
                .filter(|r| r.limit_name == "handshake_busy" && r.source_ip == src)
                .collect();
            assert_eq!(busy.len(), 1, "{records:?}");
            assert_eq!(busy[0].threshold, u64::from(effective));
        }
    }

    /// SR-58: aggregate connection caps are wired from config and audited
    /// as `per_prefix_conn` with the aggregate key as source. Compile-red
    /// until `ConnLimiter::with_aggregate_caps`, `Rejection::PerAggregate`,
    /// `Server::build_conn_limiter` and the `[transport]` keys exist.
    mod sr58_aggregate_audit {
        use super::*;

        fn ip(s: &str) -> std::net::IpAddr {
            s.parse().unwrap()
        }

        #[test]
        fn per_prefix_conn_is_audited() {
            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.transport.max_connections_per_v6_aggregate = 4;
            config.transport.max_connections_per_v4_24 = 2;
            let conns = Arc::new(
                crate::conn_limit::ConnLimiter::new(128, 64).with_aggregate_caps(48, 4, 2),
            );
            let mut held = Vec::new();
            for n in 1..=4u16 {
                held.push(
                    conns
                        .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                        .unwrap(),
                );
            }
            assert!(conns.try_acquire(ip("2001:db8:1:5::1")).is_none());
            assert!(conns.try_acquire(ip("2001:db8:1:6::1")).is_none());
            held.push(conns.try_acquire(ip("192.0.2.1")).unwrap());
            held.push(conns.try_acquire(ip("192.0.2.2")).unwrap());
            assert!(conns.try_acquire(ip("192.0.2.3")).is_none());

            let mut audit = RateLimitAudit::new(&config);
            audit.collect_conns(&conns);
            audit.flush();
            let records = rate_limit_records(&capture.events());
            let prefix: Vec<_> = records
                .iter()
                .filter(|r| r.limit_name == "per_prefix_conn")
                .collect();
            assert_eq!(prefix.len(), 2, "{records:?}");
            let v6 = prefix
                .iter()
                .find(|r| r.source_ip == ip("2001:db8:1::"))
                .expect("v6 aggregate record keyed on the /48");
            assert_eq!((v6.request_count, v6.threshold), (2, 4));
            let v4 = prefix
                .iter()
                .find(|r| r.source_ip == ip("192.0.2.0"))
                .expect("v4 aggregate record keyed on the /24");
            assert_eq!((v4.request_count, v4.threshold), (1, 2));
            // No per-source record: no /64 or host was at its own cap.
            assert!(!records.iter().any(|r| r.limit_name == "per_ip_conn"));
            drop(held);
        }

        /// Decision 9 defaults through the daemon's construction path: one
        /// /56 with 128 connections per /64 gets exactly 1024.
        #[test]
        fn build_conn_limiter_defaults_bound_a_slash56() {
            // Accept buckets off: this checks the concurrent caps, not the
            // aggregate accept burst (800 at the defaults, tested below).
            let mut config = SbcConfig::default();
            config.transport.accept_rate_per_source = 0;
            let conns = Arc::new(Server::build_conn_limiter(&config));
            let mut held = Vec::new();
            for sub in 0..=255u16 {
                let a = ip(&format!("2001:db8:1:{:x}::1", 0xab00 | sub));
                for _ in 0..128 {
                    if let Some(g) = conns.try_acquire(a) {
                        held.push(g);
                    }
                }
            }
            assert_eq!(held.len(), 1024);
            let v4: Vec<_> = (0..=255u8)
                .flat_map(|h| {
                    let c = Arc::clone(&conns);
                    (0..8).filter_map(move |_| c.try_acquire(ip(&format!("198.51.100.{h}"))))
                })
                .collect();
            assert_eq!(v4.len(), 1024);
        }

        /// Every `[transport]` aggregate key reaches the limiter.
        #[test]
        fn build_conn_limiter_applies_aggregate_keys() {
            let mut config = SbcConfig::default();
            config.transport.max_connections_per_source = 1;
            config.transport.v6_aggregate_prefix_len = 56;
            config.transport.max_connections_per_v6_aggregate = 2;
            config.transport.max_connections_per_v4_24 = 3;
            let conns = Arc::new(Server::build_conn_limiter(&config));
            let _a = conns.try_acquire(ip("2001:db8:1:100::1")).unwrap();
            let _b = conns.try_acquire(ip("2001:db8:1:101::1")).unwrap();
            assert!(conns.try_acquire(ip("2001:db8:1:102::1")).is_none());
            // Next /56 in the same /48: the prefix key is /56, not /48.
            let _c = conns.try_acquire(ip("2001:db8:1:200::1")).unwrap();
            let v4: Vec<_> = (1..=4u8)
                .filter_map(|h| conns.try_acquire(ip(&format!("192.0.2.{h}"))))
                .collect();
            assert_eq!(v4.len(), 3);
            drop(v4);

            // 0 turns both aggregate levels off.
            config.transport.max_connections_per_v6_aggregate = 0;
            config.transport.max_connections_per_v4_24 = 0;
            let off = Arc::new(Server::build_conn_limiter(&config));
            let all: Vec<_> = (1..=200u8)
                .filter_map(|h| off.try_acquire(ip(&format!("192.0.2.{h}"))))
                .collect();
            assert_eq!(all.len(), 200);
            drop(all);
        }

        /// SEC-002: the default aggregate accept burst is 16 x the
        /// per-source burst (800), across the hosts of one /24.
        #[test]
        fn build_conn_limiter_wires_aggregate_accept_burst() {
            let conns = Arc::new(Server::build_conn_limiter(&SbcConfig::default()));
            let held: Vec<_> = (0..=255u8)
                .flat_map(|h| {
                    let c = Arc::clone(&conns);
                    (0..4).filter_map(move |_| c.try_acquire(ip(&format!("198.51.100.{h}"))))
                })
                .collect();
            assert_eq!(held.len(), 800);
            assert_eq!(conns.aggregate_accept_rate(), 20 * 16);
        }

        /// SEC-003 / NIST-003: each startup clamp is logged and audited as
        /// a `ConfigurationChange { Modified }` by `startup`; a stricter cap
        /// is not a clamp.
        #[test]
        fn aggregate_clamp_emits_configuration_change() {
            fn changes(
                capture: &uc_audit::capture::CaptureGuard,
            ) -> Vec<uc_audit::event::ConfigurationChange> {
                capture
                    .events()
                    .iter()
                    .filter_map(|e| match e {
                        uc_audit::AuditEvent::ConfigurationChange(c) => Some(c.clone()),
                        _ => None,
                    })
                    .collect()
            }
            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.rate_limit.ipv6_prefix_len = 48;
            config.transport.v6_aggregate_prefix_len = 56;
            config.transport.max_connections_per_v6_aggregate = 20_000;
            config.transport.max_connections_per_v4_24 = 20_001;
            let conns = Server::build_conn_limiter(&config);
            assert_eq!(
                (conns.v6_aggregate_cap(), conns.v4_aggregate_cap()),
                (10_000, 10_000)
            );
            let got = changes(&capture);
            assert_eq!(got.len(), 3, "{got:?}");
            for (key, from, to) in [
                ("transport.v6_aggregate_prefix_len", 56, 48),
                ("transport.max_connections_per_v6_aggregate", 20_000, 10_000),
                ("transport.max_connections_per_v4_24", 20_001, 10_000),
            ] {
                assert!(
                    got.iter().any(|c| c.admin == "startup"
                        && c.change_type == uc_audit::event::ConfigChangeType::Modified
                        && c.description.contains(key)
                        && c.description.contains(&format!("from {from} to {to}"))),
                    "{key}: {got:?}"
                );
            }
            drop(capture);

            let capture = uc_audit::capture::start();
            let mut config = SbcConfig::default();
            config.transport.max_connections_per_v6_aggregate = 4;
            config.transport.max_connections_per_v4_24 = 1;
            let conns = Server::build_conn_limiter(&config);
            assert_eq!((conns.v6_aggregate_cap(), conns.v4_aggregate_cap()), (4, 1));
            assert!(changes(&capture).is_empty());
        }

        /// SEC-006 / NIST-001: an aggregate rejection is counted and logged
        /// as one, not as a per-source rejection.
        #[test]
        fn aggregate_rejection_counted_per_aggregate() {
            let mut ctx = stream_test_ctx(short_timeouts());
            ctx.conn_limiter = Arc::new(
                crate::conn_limit::ConnLimiter::new(2, 64)
                    .with_aggregate_caps(48, 4, 1)
                    .with_aggregate_handshake_cap(1),
            );
            let v4 = |last| SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, last), 1);
            let v6 = SbcSocketAddr::new(ip("2001:db8:1:1::1"), 1);
            let _a = Server::admit_connection(&ctx, &v4(1), "tcp").unwrap();
            assert!(Server::admit_connection(&ctx, &v4(2), "tcp").is_none());
            let _b = Server::admit_connection(&ctx, &v6, "tcp").unwrap();
            let _c = Server::admit_connection(&ctx, &v6, "tcp").unwrap();
            assert!(Server::admit_connection(&ctx, &v6, "tcp").is_none());
            let s = &ctx.stats;
            assert_eq!(s.conn_rejected_per_aggregate.load(Ordering::Relaxed), 1);
            assert_eq!(s.conn_rejected_per_source.load(Ordering::Relaxed), 1);

            let _h = Server::begin_handshake(&ctx, &v4(3), "tls").unwrap();
            assert!(Server::begin_handshake(&ctx, &v4(4), "tls").is_none());
            assert_eq!(s.handshake_busy_per_aggregate.load(Ordering::Relaxed), 1);
            assert_eq!(s.handshake_busy_per_source.load(Ordering::Relaxed), 0);
        }

        /// SEC-002: aggregate accept-rate and handshake refusals are
        /// audited per aggregate key with the effective limit.
        #[test]
        fn per_prefix_accept_and_handshake_are_audited() {
            let capture = uc_audit::capture::start();
            let conns = Arc::new(
                crate::conn_limit::ConnLimiter::new(128, 64)
                    .with_aggregate_caps(48, 1024, 1024)
                    .with_accept_rate(1, 1, 1024)
                    .with_aggregate_handshake_cap(1),
            );
            let held: Vec<_> = (1..=17u8)
                .filter_map(|h| conns.try_acquire(ip(&format!("192.0.2.{h}"))))
                .collect();
            assert_eq!(held.len(), 16, "aggregate burst 16 x 1");
            let _h = conns.try_begin_handshake(ip("192.0.2.1")).unwrap();
            assert!(conns.try_begin_handshake(ip("192.0.2.2")).is_none());

            let mut audit = RateLimitAudit::new(&SbcConfig::default());
            audit.sweep_conns(&conns);
            audit.flush();
            let records = rate_limit_records(&capture.events());
            let find = |name: &str| {
                let found = records.iter().find(|r| r.limit_name == name);
                assert!(found.is_some(), "{name}: {records:?}");
                found.unwrap()
            };
            let rate = find("per_prefix_accept_rate");
            assert_eq!(
                (rate.source_ip, rate.request_count, rate.threshold),
                (ip("192.0.2.0"), 1, 16)
            );
            let busy = find("per_prefix_handshake_busy");
            assert_eq!(
                (busy.source_ip, busy.request_count, busy.threshold),
                (ip("192.0.2.0"), 1, 1)
            );
            assert!(!records.iter().any(|r| r.limit_name == "per_ip_accept_rate"));
            drop(held);
        }
    }
}
