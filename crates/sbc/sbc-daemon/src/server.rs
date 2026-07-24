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
use crate::shutdown::ShutdownSignal;
use crate::sip_stack::{ProcessResult, SipStack, SipStackConfig};
use proto_registrar::BearerAuthenticator;
use sbc_config::SbcConfig;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uc_dos_protection::{RateLimitAction, RateLimiter, RateLimiterConfig};
use uc_health::{HealthChecker, HealthCheckerConfig};
use uc_metrics::{MetricRegistry, SbcMetrics};
use uc_transport::Transport;
use uc_transport::listener::ListenerConfig;
use uc_transport::tcp::TcpListener;
use uc_transport::tls::TlsListener;
use uc_transport::udp::UdpTransport;
use uc_types::address::{SbcSocketAddr, TransportType};

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
    conn_semaphore: Arc<tokio::sync::Semaphore>,
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
    /// SIP stack for message processing.
    sip_stack: Arc<SipStack>,
    /// Per-source rate limiter for `DoS` protection.
    rate_limiter: Arc<Mutex<RateLimiter>>,
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
    /// Cluster manager (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<ClusterManager>>,
}

impl Server {
    /// Creates a new server.
    pub fn new(config: SbcConfig, shutdown: ShutdownSignal) -> Self {
        // Use standard SBC metrics
        let metrics = SbcMetrics::standard();

        let mut health = HealthChecker::new(HealthCheckerConfig::default())
            .with_version(env!("CARGO_PKG_VERSION"));

        // Register health checks
        health.register(Box::new(uc_health::check::AlwaysHealthyCheck::new(
            "sbc_core",
        )));
        health.register(Box::new(uc_health::check::MemoryCheck::new()));

        let sip_config = Self::build_sip_config(&config);
        let mut sip_stack = SipStack::new(sip_config);
        let media_failure_rx = Self::init_sip_stack_from_config(&mut sip_stack, &config);
        if let Some(bearer) = Self::build_bearer_authenticator(&config) {
            sip_stack.set_bearer_authenticator(bearer);
        }
        let sip_stack = Arc::new(sip_stack);
        let rate_limiter = Self::build_rate_limiter(&config);
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
            sip_stack,
            rate_limiter,
            global_limiter,
            zone_registry: None,
            media_failure_rx,
            #[cfg(feature = "grpc")]
            remote_media: Vec::new(),
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
    ) -> Self {
        let metrics = SbcMetrics::standard();

        let mut health = HealthChecker::new(HealthCheckerConfig::default())
            .with_version(env!("CARGO_PKG_VERSION"));
        health.register(Box::new(uc_health::check::AlwaysHealthyCheck::new(
            "sbc_core",
        )));
        health.register(Box::new(uc_health::check::MemoryCheck::new()));

        let sip_config = Self::build_sip_config(&config);
        let mut sip_stack = if let Some(ref cluster_mgr) = cluster {
            SipStack::new_with_location_service(
                sip_config,
                Arc::clone(cluster_mgr.location_service()),
            )
        } else {
            SipStack::new(sip_config)
        };
        let media_failure_rx = Self::init_sip_stack_from_config(&mut sip_stack, &config);
        if let Some(bearer) = Self::build_bearer_authenticator(&config) {
            sip_stack.set_bearer_authenticator(bearer);
        }
        let sip_stack = Arc::new(sip_stack);

        let rate_limiter = Self::build_rate_limiter(&config);
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
            sip_stack,
            rate_limiter,
            global_limiter,
            zone_registry: None,
            media_failure_rx,
            #[cfg(feature = "grpc")]
            remote_media: Vec::new(),
            cluster,
        }
    }

    /// Builds `SipStackConfig` from `SbcConfig`.
    fn build_sip_config(config: &SbcConfig) -> SipStackConfig {
        SipStackConfig {
            instance_name: config.general.instance_name.clone(),
            domain: config.general.instance_name.clone(),
            max_calls: config.general.max_calls,
            ..SipStackConfig::default()
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
        if !mode.eq_ignore_ascii_case("bearer") {
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

    /// Builds the per-source rate limiter from config.
    fn build_rate_limiter(config: &SbcConfig) -> Arc<Mutex<RateLimiter>> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let burst_size = (f64::from(config.rate_limit.per_ip_rps)
            * f64::from(config.rate_limit.burst_multiplier)) as u32;
        let rate_limit_config =
            RateLimiterConfig::new(config.rate_limit.per_ip_rps, burst_size).with_per_ip(true);

        info!(
            enabled = config.rate_limit.enabled,
            per_ip_rps = config.rate_limit.per_ip_rps,
            global_rps = config.rate_limit.global_rps,
            burst_multiplier = config.rate_limit.burst_multiplier,
            "Rate limiting configured"
        );

        Arc::new(Mutex::new(RateLimiter::new(rate_limit_config)))
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
            sip_stack.init_topology_hider_from_config(topo);
        }

        // Media plane. When SBC_MEDIA_CONTROLLER_URL is set (grpc builds), the
        // media plane runs out of process: `wire_remote_media` connects the gRPC
        // controller (and fetches the fingerprint for SDP) before `start`, so the
        // in-process pipeline is skipped here and there is no in-process
        // media-failure channel — the gRPC WatchMediaEvents stream replaces it.
        // In the monolith (default) the in-process pipeline is attached below;
        // without it, allocated RTP ports are not backed by any socket (media
        // black-holes).
        let media_failure_rx = if !Self::remote_media_urls().is_empty() {
            tracing::info!(
                "Remote media plane configured (SBC_MEDIA_CONTROLLER_URL); \
                 in-process pipeline skipped — wired via gRPC before start"
            );
            None
        } else {
            // Ports / mode / SRTP come from the [media] config; the codec list and
            // RTCP-mux keep the pipeline defaults.
            //
            // The config's mode is uc_types::MediaMode; the pipeline uses
            // uc_media_engine::MediaMode. They share Relay/PassThrough; the
            // config-only SignalingOnly has no relay-engine equivalent, so it maps
            // to the least-involved engine mode (PassThrough).
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
        let urls = Self::remote_media_urls();
        if urls.is_empty() {
            return Ok(());
        }
        use sbc_media_core::dtls_identity::DtlsFingerprintSource;
        use sbc_media_core::grpc_media_controller::GrpcMediaController;
        use sbc_media_core::grpc_media_pool::MediaPool;

        // Connect every configured node, retrying each: media and signaling are
        // commonly brought up together, so a node may not be listening yet.
        // Fail-closed after the deadline — a configured node that never comes up
        // must stop signaling rather than run with a hole in the pool.
        const CONNECT_ATTEMPTS: u32 = 30;
        const CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
        info!(nodes = urls.len(), "Connecting to remote media plane");
        let mut clients: Vec<GrpcMediaController> = Vec::with_capacity(urls.len());
        for url in &urls {
            let mut attempt = 1;
            let client = loop {
                match GrpcMediaController::connect(url.clone()).await {
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
                Arc::new(
                    MediaPool::new(clients.clone(), Some(failure_tx)).map_err(|e| {
                        ServerError::ConfigError {
                            message: format!("failed to build media pool: {e}"),
                        }
                    })?,
                )
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

    /// Returns the SIP stack.
    pub fn sip_stack(&self) -> &Arc<SipStack> {
        &self.sip_stack
    }

    /// Starts the server and binds to transport addresses.
    pub async fn start(&mut self) -> Result<(), ServerError> {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            instance = %self.config.general.instance_name,
            "Starting SBC daemon"
        );
        info!(
            max_calls = self.config.general.max_calls,
            max_registrations = self.config.general.max_registrations,
            "Call limits configured"
        );
        info!(
            media_mode = ?self.config.media.default_mode,
            srtp_required = self.config.media.srtp.required,
            "Media settings configured"
        );

        // Bind UDP listeners
        self.bind_udp_listeners().await?;

        // Bind stream listeners (SIP over TCP / TLS)
        self.bind_tcp_listeners().await?;
        self.bind_tls_listeners().await?;

        // DTLS-SRTP media-failure teardown: drain call ids whose handshake failed
        // at runtime and BYE both legs (fail-closed). Needs a bound UDP transport
        // to send from; the SBC binds a single wildcard listener, so any works.
        if let Some(mut rx) = self.media_failure_rx.take() {
            let sip_stack = Arc::clone(&self.sip_stack);
            let transport = self.udp_transports.read().await.first().map(Arc::clone);
            match transport {
                Some(transport) => {
                    tokio::spawn(async move {
                        while let Some(call_id) = rx.recv().await {
                            for (bytes, dest) in
                                sip_stack.terminate_call_on_media_failure(&call_id).await
                            {
                                if let Err(e) = transport.send(&bytes, &dest).await {
                                    warn!(error = %e, call_id, dest = %dest, "media-failure BYE send failed");
                                }
                            }
                        }
                    });
                }
                None => warn!("media-failure teardown disabled: no UDP transport bound"),
            }
        }

        // Out-of-process equivalent of the mpsc drain above: subscribe to EACH
        // media node's WatchMediaEvents stream and BYE the calls it reports as
        // failed. Best-effort — if a stream drops (node restart), teardown of
        // that node's subsequently-failed calls stops until the daemon restarts;
        // that mirrors the in-process channel's best-effort semantics.
        #[cfg(feature = "grpc")]
        if !self.remote_media.is_empty() {
            match self.udp_transports.read().await.first().map(Arc::clone) {
                Some(transport) => {
                    for (node, controller) in self.remote_media.iter().cloned().enumerate() {
                        let sip_stack = Arc::clone(&self.sip_stack);
                        let transport = Arc::clone(&transport);
                        tokio::spawn(async move {
                            use sbc_grpc_api::sbc::media_event::Event;
                            let mut stream = match controller.watch_media_events().await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(node, error = %e, "failed to open media node event stream");
                                    return;
                                }
                            };
                            loop {
                                match stream.message().await {
                                    Ok(Some(event)) => {
                                        let Some(Event::Failure(f)) = event.event else {
                                            continue;
                                        };
                                        for (bytes, dest) in sip_stack
                                            .terminate_call_on_media_failure(&f.call_id)
                                            .await
                                        {
                                            if let Err(e) = transport.send(&bytes, &dest).await {
                                                warn!(error = %e, call_id = f.call_id, dest = %dest, "media-failure BYE send failed");
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        warn!(node, "media node event stream closed");
                                        break;
                                    }
                                    Err(e) => {
                                        warn!(node, error = %e, "media node event stream error");
                                        break;
                                    }
                                }
                            }
                        });
                    }
                }
                None => warn!("media event drain disabled: no UDP transport bound"),
            }
        }

        // Seed the live-transport count at bind time (before the API server
        // starts serving readiness), so the readiness probe never sees a
        // spurious 0 during the window before run() spawns the loops.
        let bound = self.udp_transports.read().await.len()
            + self.tcp_listeners.read().await.len()
            + self.tls_listeners.read().await.len();
        self.stats
            .live_transports
            .store(bound as u64, Ordering::SeqCst);

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
        let cert_chain = uc_transport::tls::load_certs(cert_path)
            .map_err(|e| tls_error(format!("loading {}: {e}", cert_path.display())))?;
        let private_key = uc_transport::tls::load_private_key(key_path)
            .map_err(|e| tls_error(format!("loading {}: {e}", key_path.display())))?;
        let server_config = Arc::new(
            uc_transport::tls::create_server_config(cert_chain, private_key)
                .map_err(|e| tls_error(format!("building TLS server config: {e}")))?,
        );
        info!(
            cert = %cert_path.display(),
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

    /// Runs the main event loop.
    pub async fn run(&mut self) -> Result<(), ServerError> {
        info!("Entering async event loop");

        // Get transport handles for spawning receive tasks
        let transports = self.udp_transports.read().await;
        let tcp_listeners: Vec<_> = self.tcp_listeners.read().await.clone();
        let tls_listeners: Vec<_> = self.tls_listeners.read().await.clone();
        let transport_count = transports.len() + tcp_listeners.len() + tls_listeners.len();

        if transport_count == 0 {
            warn!("No transports bound, exiting event loop");
            return Ok(());
        }

        // Spawn receive tasks for each transport
        let mut handles = Vec::new();
        for (idx, transport) in transports.iter().enumerate() {
            let transport = Arc::clone(transport);
            let shutdown = self.shutdown.clone();
            let stats = Arc::clone(&self.stats);
            let sip_stack = Arc::clone(&self.sip_stack);
            let rate_limiter = Arc::clone(&self.rate_limiter);
            let global_limiter = Arc::clone(&self.global_limiter);
            let rate_limit_enabled = self.config.rate_limit.enabled;

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
                )
                .await;
            });
            handles.push(handle);
        }
        drop(transports);

        // Spawn accept loops for stream listeners (SIP over TCP / TLS).
        // Each accepted connection gets its own receive task; responses go
        // back over the connection the request arrived on (RFC 3261 §18).
        let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(10_000));
        for listener in tcp_listeners {
            let zone_name = self.zone_for_local_ip(listener.local_addr().ip());
            let ctx = StreamLoopContext {
                shutdown: self.shutdown.clone(),
                stats: Arc::clone(&self.stats),
                sip_stack: Arc::clone(&self.sip_stack),
                rate_limiter: Arc::clone(&self.rate_limiter),
                global_limiter: Arc::clone(&self.global_limiter),
                rate_limit_enabled: self.config.rate_limit.enabled,
                zone_name,
                conn_semaphore: Arc::clone(&conn_semaphore),
            };
            handles.push(tokio::spawn(async move {
                Self::tcp_accept_loop(listener, ctx).await;
            }));
        }
        for listener in tls_listeners {
            let zone_name = self.zone_for_local_ip(listener.local_addr().ip());
            let ctx = StreamLoopContext {
                shutdown: self.shutdown.clone(),
                stats: Arc::clone(&self.stats),
                sip_stack: Arc::clone(&self.sip_stack),
                rate_limiter: Arc::clone(&self.rate_limiter),
                global_limiter: Arc::clone(&self.global_limiter),
                rate_limit_enabled: self.config.rate_limit.enabled,
                zone_name,
                conn_semaphore: Arc::clone(&conn_semaphore),
            };
            handles.push(tokio::spawn(async move {
                Self::tls_accept_loop(listener, ctx).await;
            }));
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
                                let sip_stack = sip_stack.clone();
                                let transport = transport.clone();
                                let stats = stats.clone();
                                let zone = zone_name.clone();
                                let data = msg.data;
                                let source = msg.source;
                                tokio::spawn(async move {
                                    let result = sip_stack
                                        .process_message(&data, source, zone.as_deref())
                                        .await;
                                    Self::handle_result(result, transport.as_ref(), &stats).await;
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
                                stats.live_transports.fetch_update(
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

    /// Checks the global and per-source rate limits for one message.
    ///
    /// Returns `true` when the message may be processed. Increments
    /// `stats.rate_limited` on every rejection.
    async fn rate_limit_allows(
        source_ip: std::net::IpAddr,
        rate_limiter: &Mutex<RateLimiter>,
        global_limiter: &Mutex<RateLimiter>,
        stats: &ServerStats,
    ) -> bool {
        let global_action = {
            let mut limiter = global_limiter.lock().await;
            limiter.check(source_ip)
        };
        if matches!(
            global_action,
            RateLimitAction::Reject | RateLimitAction::Block { .. }
        ) {
            stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            debug!(
                source = %source_ip,
                "Global rate limit exceeded, rejecting message"
            );
            return false;
        }

        let action = {
            let mut limiter = rate_limiter.lock().await;
            limiter.check(source_ip)
        };

        match action {
            RateLimitAction::Allow => true,
            RateLimitAction::Throttle { delay_ms } => {
                // Log throttling but continue
                debug!(
                    source = %source_ip,
                    delay_ms,
                    "Rate limit throttle suggested"
                );
                true
            }
            RateLimitAction::Reject => {
                stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                debug!(
                    source = %source_ip,
                    "Rate limit exceeded, rejecting message"
                );
                false
            }
            RateLimitAction::Block { duration_secs } => {
                stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                warn!(
                    source = %source_ip,
                    duration_secs,
                    "Source blocked due to rate limit violation"
                );
                false
            }
        }
    }

    /// Accept loop for a SIP-over-TCP listener.
    async fn tcp_accept_loop(listener: Arc<TcpListener>, ctx: StreamLoopContext) {
        info!(address = %listener.local_addr(), "SIP TCP accept loop started");
        loop {
            match listener.accept().await {
                Ok((transport, peer)) => {
                    let permit = match ctx.conn_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!(peer = %peer, "TCP connection limit reached, dropping");
                            continue;
                        }
                    };
                    debug!(peer = %peer, "Accepted SIP TCP connection");
                    let conn_ctx = ctx.clone();
                    tokio::spawn(async move {
                        Self::stream_connection_loop(Arc::new(transport), peer, conn_ctx).await;
                        drop(permit);
                    });
                }
                Err(e) => {
                    if ctx.shutdown.is_shutdown_requested() {
                        break;
                    }
                    warn!(error = %e, "TCP accept failed");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Accept loop for a SIP-over-TLS listener.
    ///
    /// The raw TCP accept runs inline so the loop stays responsive; the TLS
    /// handshake is spawned with a 10-second timeout so one slow client
    /// cannot stall new connections on this listener.
    async fn tls_accept_loop(listener: Arc<TlsListener>, ctx: StreamLoopContext) {
        info!(address = %listener.local_addr(), "SIP TLS accept loop started");
        loop {
            // Step 1: accept the raw TCP connection (fast, no crypto).
            match listener.accept_tcp().await {
                Ok((tcp_stream, peer)) => {
                    let permit = match ctx.conn_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!(peer = %peer, "TLS connection limit reached, dropping");
                            continue;
                        }
                    };
                    // Step 2: spawn the TLS handshake so the accept loop
                    // continues immediately.
                    let conn_ctx = ctx.clone();
                    let listener_clone = listener.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            listener_clone.complete_handshake(tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(transport)) => {
                                debug!(peer = %peer, "TLS handshake completed");
                                Self::stream_connection_loop(Arc::new(transport), peer, conn_ctx)
                                    .await;
                            }
                            Ok(Err(e)) => {
                                warn!(peer = %peer, error = %e, "TLS handshake failed");
                            }
                            Err(_) => {
                                warn!(peer = %peer, "TLS handshake timed out (10s), dropping");
                            }
                        }
                        drop(permit);
                    });
                }
                Err(e) => {
                    if ctx.shutdown.is_shutdown_requested() {
                        break;
                    }
                    warn!(error = %e, "TLS TCP accept failed");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Receive loop for one accepted stream connection (TCP or TLS).
    ///
    /// Stream transports deliver byte chunks, not datagrams, so messages are
    /// re-framed here via Content-Length (RFC 3261 §18.3) before entering the
    /// SIP stack. Responses go back over this same connection.
    async fn stream_connection_loop<T: Transport + 'static>(
        transport: Arc<T>,
        peer: SbcSocketAddr,
        ctx: StreamLoopContext,
    ) {
        let mut buf = bytes::BytesMut::new();

        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(300), transport.recv()).await
            {
                Err(_elapsed) => {
                    warn!(peer = %peer, "Stream connection idle timeout (300s), closing");
                    break;
                }
                Ok(Ok(chunk)) => {
                    buf.extend_from_slice(&chunk.data);
                    if buf.len() > uc_transport::MAX_STREAM_MESSAGE_SIZE {
                        warn!(
                            peer = %peer,
                            buffered = buf.len(),
                            "No complete SIP message within size limit, closing connection"
                        );
                        break;
                    }

                    while let Some(frame) = next_sip_frame(&mut buf) {
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
                            .process_message(&frame, peer, ctx.zone_name.as_deref())
                            .await;
                        Self::handle_result(result, transport.as_ref(), &ctx.stats).await;
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

        let _ = transport.close().await;
    }

    /// Handles a single `ProcessResult`, sending responses/forwards via the transport.
    async fn handle_result(result: ProcessResult, transport: &dyn Transport, stats: &ServerStats) {
        match result {
            ProcessResult::Response {
                message,
                destination,
            } => {
                let response_bytes = message.to_bytes();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    transport.send(&response_bytes, &destination),
                )
                .await
                {
                    Ok(Ok(())) => {
                        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        debug!(destination = %destination, "Response sent");
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "Failed to send response");
                    }
                    Err(_) => {
                        warn!(destination = %destination, "Send response timed out (30s)");
                    }
                }
            }
            ProcessResult::Forward {
                message,
                destination,
            } => {
                let request_bytes = message.to_bytes();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    transport.send(&request_bytes, &destination),
                )
                .await
                {
                    Ok(Ok(())) => {
                        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        debug!(destination = %destination, "Request forwarded");
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "Failed to forward request");
                    }
                    Err(_) => {
                        warn!(destination = %destination, "Forward request timed out (30s)");
                    }
                }
            }
            ProcessResult::Multiple(results) => {
                for sub_result in results {
                    // Box::pin to allow recursive async call
                    Box::pin(Self::handle_result(sub_result, transport, stats)).await;
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

/// Extracts the next complete SIP message from a stream reassembly buffer.
///
/// SIP over stream transports is framed by Content-Length (RFC 3261 §18.3):
/// a message is complete at end-of-headers (`\r\n\r\n`) plus the declared
/// body length. Leading CRLFs (RFC 5626 keep-alive pings/pongs) are
/// discarded. Returns `None` until a full message is buffered.
fn next_sip_frame(buf: &mut bytes::BytesMut) -> Option<bytes::Bytes> {
    // Discard keep-alive CRLFs between messages.
    while buf.starts_with(b"\r\n") {
        let _ = buf.split_to(2);
    }
    if buf.is_empty() {
        return None;
    }

    let headers_end = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        .checked_add(4)?;
    let body_len = parse_content_length(&buf[..headers_end]);
    let total = headers_end.checked_add(body_len)?;
    if buf.len() < total {
        return None;
    }
    Some(buf.split_to(total).freeze())
}

/// Parses the Content-Length header (or its compact form `l`) from a SIP
/// header block. Absent or malformed values are treated as 0; the SIP
/// parser downstream rejects the message properly.
fn parse_content_length(headers: &[u8]) -> usize {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"l") {
            return std::str::from_utf8(line[colon + 1..].trim_ascii())
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown);

        assert_eq!(server.config().general.instance_name, "sbc-01");
    }

    #[tokio::test]
    async fn test_server_health() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let mut server = Server::new(config, shutdown);

        assert!(server.is_alive());
        assert!(server.is_ready());

        let health = server.check_health();
        assert!(health.is_healthy());
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = SbcConfig::default();
        let shutdown = ShutdownSignal::new();
        let server = Server::new(config, shutdown);

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

    #[test]
    fn frame_complete_message() {
        let mut buf = bytes::BytesMut::from(REGISTER);
        let frame = next_sip_frame(&mut buf).expect("complete message");
        assert_eq!(&frame[..], REGISTER);
        assert!(buf.is_empty());
        assert!(next_sip_frame(&mut buf).is_none());
    }

    #[test]
    fn frame_waits_for_full_body() {
        let msg = b"MESSAGE sip:example.mil SIP/2.0\r\nContent-Length: 5\r\n\r\nhel";
        let mut buf = bytes::BytesMut::from(&msg[..]);
        assert!(next_sip_frame(&mut buf).is_none());
        buf.extend_from_slice(b"lo");
        let frame = next_sip_frame(&mut buf).expect("complete after body");
        assert!(frame.ends_with(b"hello"));
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_splits_pipelined_messages_and_skips_keepalives() {
        let mut buf = bytes::BytesMut::new();
        buf.extend_from_slice(b"\r\n\r\n"); // RFC 5626 keep-alive ping
        buf.extend_from_slice(REGISTER);
        buf.extend_from_slice(REGISTER);
        assert_eq!(
            next_sip_frame(&mut buf).expect("first").len(),
            REGISTER.len()
        );
        assert_eq!(
            next_sip_frame(&mut buf).expect("second").len(),
            REGISTER.len()
        );
        assert!(next_sip_frame(&mut buf).is_none());
    }

    #[test]
    fn frame_partial_headers_returns_none() {
        let mut buf = bytes::BytesMut::from(&b"REGISTER sip:example.mil SIP/2.0\r\nVia: x"[..]);
        assert!(next_sip_frame(&mut buf).is_none());
        assert!(!buf.is_empty()); // kept for the next chunk
    }

    #[test]
    fn content_length_compact_form() {
        let headers = b"MESSAGE sip:a SIP/2.0\r\nl: 7\r\n\r\n";
        assert_eq!(parse_content_length(headers), 7);
    }

    #[test]
    fn content_length_request_line_colon_not_confused() {
        // The request-line contains ':' but is not a header.
        assert_eq!(parse_content_length(b"REGISTER sip:a SIP/2.0\r\n\r\n"), 0);
    }
}
