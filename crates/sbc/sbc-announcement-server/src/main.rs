//! sbc-announcement-server — announcement playback pod.
//!
//! Hosts the gRPC `AnnouncementService` (see
//! `sbc-grpc-api/proto/announcement.proto`). The SIP daemon stays the
//! SIP UAS for announcement calls (it sends the 200 OK and the BYE);
//! this pod only does the media work: bind an RTP socket, stream the
//! PCMU announcement to the caller, report completion. That keeps all
//! call/dialog state in the daemon, so this pod is stateless and can
//! roll, scale, and crash independently of signaling.
//!
//! Configuration (env; an invalid value stops startup with exit 2):
//! - `SBC_ANN_GRPC_LISTEN` — gRPC listen address (default `0.0.0.0:9095`).
//!   Off loopback the listener requires mTLS and a client allow-list:
//! - `SBC_ANN_GRPC_TLS_{CERT,KEY,CLIENT_CA}_FILE` — server certificate,
//!   key and the CA client certificates must chain to (all or none)
//! - `SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES` — comma-separated client SAN DNS
//!   names / URIs admitted on every RPC (the daemon's client certificate)
//! - `SBC_ANN_ADVERTISED_IP` — IP placed in the Bound event for the
//!   daemon's SDP `c=` line (the pod's externally reachable media IP).
//!   Falls back to `SBC_ANN_BIND_IP`; startup fails when neither is set.
//! - `SBC_ANN_BIND_IP` — local IP to bind RTP sockets to (default any)
//! - `SBC_ANN_RTP_PORT_MIN` / `SBC_ANN_RTP_PORT_MAX` — inclusive UDP port
//!   range for RTP sockets (default: kernel-assigned ephemeral ports).
//!   Set this when the pod's exposed UDP port range is constrained.
//! - `SBC_ANN_DEFAULT_DELAY_MS` — Bound→first-RTP-packet delay when the
//!   request leaves `initial_delay_ms` at 0 (default 200ms, matching the
//!   daemon's historical ACK-settle sleep; at most 2000).
//! - `SBC_ANN_MAX_PLAYS` (default 128, 1..=4096),
//!   `SBC_ANN_MAX_PLAYS_PER_DEST` (default 32, at most `SBC_ANN_MAX_PLAYS`)
//!   and `SBC_ANN_MAX_PLAY_SECS` (default 30, 1..=120) — concurrency and
//!   duration caps; over a cap Play returns `RESOURCE_EXHAUSTED`.
//! - `SBC_ANN_ALLOWED_DEST_CIDRS` — comma-separated media CIDRs RTP may be
//!   sent to (at most 256; empty = no CIDR restriction).
//! - `SBC_ANN_ALLOW_LOOPBACK_DEST` — `true` admits loopback destinations
//!   (lab and tests only; not exposed in Helm).
//!
//! Unspecified, broadcast, multicast, link-local and (without the lab flag)
//! loopback destinations and port 0 are always refused. Playback stops when
//! the daemon drops the stream or the connection dies, and at
//! `SBC_ANN_MAX_PLAY_SECS` (`DEADLINE_EXCEEDED`).
//!
//! The listener serves TLS 1.3 with the CNSA 2.0 suite and groups only
//! (`sbc_grpc_api::mtls::cnsa_provider`). It reads its certificate once at
//! start and exits (code 3) when the certificate, key or client CA file
//! changes, so the orchestrator restarts it with the renewed files. There is
//! no gRPC Health service: probes are TCP checks, and every RPC on this
//! listener is name-checked.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3, SC-5, SC-7, SI-10, CM-6, CM-7, SC-13

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use sbc_grpc_api::mtls::{
    ClientNameGate, ServerTls, TlsFingerprint, cnsa_provider, load_server_tls_fingerprinted,
    wait_for_tls_change,
};
use sbc_grpc_api::sbc::announcement_service_server::{
    AnnouncementService, AnnouncementServiceServer,
};
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{
    AnnouncementBound, AnnouncementCompleted, AnnouncementKind, PlayAnnouncementEvent,
    PlayAnnouncementRequest,
};

use sbc_announcement::{AnnouncementServer as Engine, AnnouncementType};

mod config;
mod limits;

use config::{Config, MAX_INITIAL_DELAY_MS};
use limits::PlayLimits;

// SR-41 QA (config, limits, Play lifetime, mTLS handshake).
#[cfg(test)]
mod config_tests;
// SR-41 fix round 1.
#[cfg(test)]
mod fix_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod mtls_handshake_tests;
#[cfg(test)]
mod play_tests;

/// Longest `call_id` written to the log (the field is caller-supplied).
const MAX_LOGGED_CALL_ID: usize = 128;

/// HTTP/2 PING interval and timeout, and TCP keepalive, so a dead daemon
/// connection is noticed and its plays stop (NIST 800-53 Rev5: SC-5).
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// HTTP/2 streams per connection above the Play cap, so a daemon's shared
/// connection reaches the cap check (`RESOURCE_EXHAUSTED`) instead of an
/// HTTP/2 stream refusal.
const STREAM_HEADROOM: usize = 16;

/// How often the listener's certificate files are checked for renewal.
const TLS_CHANGE_CHECK: Duration = Duration::from_secs(30);

/// Exit code when the certificate files changed (restart to reload them).
const EXIT_TLS_CHANGED: u8 = 3;

/// `call_id` cut to [`MAX_LOGGED_CALL_ID`] characters for logging.
fn log_call_id(call_id: &str) -> &str {
    call_id
        .char_indices()
        .nth(MAX_LOGGED_CALL_ID)
        .map_or(call_id, |(i, _)| call_id.get(..i).unwrap_or(call_id))
}

/// gRPC `AnnouncementService` implementation backed by the shared
/// `sbc-announcement` playback engine.
#[derive(Debug)]
struct AnnouncementServiceImpl {
    config: Config,
    limits: PlayLimits,
}

impl AnnouncementServiceImpl {
    fn new(config: Config) -> Self {
        let limits = PlayLimits::new(config.max_plays, config.max_plays_per_dest);
        Self { config, limits }
    }

    /// The Play caps (shared with the playback tasks).
    const fn limits(&self) -> &PlayLimits {
        &self.limits
    }

    /// Checks one Play request: kind, destination policy and delay bound.
    ///
    /// NIST 800-53 Rev5: SI-10
    fn validate(
        &self,
        req: &PlayAnnouncementRequest,
        call_id: &str,
    ) -> Result<(AnnouncementType, SocketAddr, u32), Status> {
        let kind = match req.kind() {
            AnnouncementKind::NumberNotInService => AnnouncementType::NumberNotInService,
            AnnouncementKind::AllCircuitsBusy => AnnouncementType::AllCircuitsBusy,
            AnnouncementKind::Silence => AnnouncementType::Silence,
            AnnouncementKind::Unspecified => {
                return Err(Status::invalid_argument("announcement kind is required"));
            }
        };

        let destination: SocketAddr = req
            .rtp_destination
            .parse()
            .map_err(|_| Status::invalid_argument("rtp_destination is not an IP:port"))?;

        // NIST 800-53 Rev5: SC-7, SI-10 -- refuse special address classes
        // and destinations outside the configured media networks. The
        // refusal names the class only, never the address.
        // POAM: POA&M-434 refusals go to the pod log only (no audit sink).
        if let Err(refusal) = self.config.dest_policy.check(destination) {
            warn!(call_id = %call_id, reason = %refusal, "Announcement destination refused");
            return Err(Status::invalid_argument(format!(
                "rtp_destination refused: {refusal}"
            )));
        }

        // The RTP socket is bound on SBC_ANN_BIND_IP (IPv4 any when unset):
        // an IPv6 destination on an IPv4 socket can never be sent to.
        let local = SocketAddr::new(
            self.config
                .bind_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            0,
        );
        if let Err(refusal) = sbc_announcement::destination_for_socket(local, destination) {
            warn!(call_id = %call_id, reason = %refusal, "Announcement destination refused");
            return Err(Status::invalid_argument(format!(
                "rtp_destination refused: {refusal}"
            )));
        }

        let delay_ms = match req.initial_delay_ms {
            0 => self.config.default_delay_ms,
            d if d > MAX_INITIAL_DELAY_MS => {
                return Err(Status::invalid_argument(format!(
                    "initial_delay_ms must be at most {MAX_INITIAL_DELAY_MS}"
                )));
            }
            d => d,
        };
        Ok((kind, destination, delay_ms))
    }

    /// Binds an RTP socket: random ports within the configured range
    /// (with a few retries for collisions), or a kernel-assigned
    /// ephemeral port when no range is configured.
    async fn bind_rtp(&self) -> Result<(tokio::net::UdpSocket, u16), String> {
        if let Some((min, max)) = self.config.rtp_port_range {
            let span = u32::from(max - min) + 1;
            let mut last_err = String::new();
            for _ in 0..16 {
                #[allow(clippy::cast_possible_truncation)]
                let offset = (rand::random::<u32>() % span) as u16;
                let port = min.saturating_add(offset).min(max);
                match Engine::bind_socket(port, self.config.bind_ip).await {
                    Ok(ok) => return Ok(ok),
                    Err(e) => last_err = e,
                }
            }
            Err(format!(
                "no free RTP port in {min}-{max} after 16 attempts: {last_err}"
            ))
        } else {
            Engine::bind_socket(0, self.config.bind_ip).await
        }
    }
}

#[tonic::async_trait]
impl AnnouncementService for AnnouncementServiceImpl {
    type PlayStream =
        Pin<Box<dyn Stream<Item = Result<PlayAnnouncementEvent, Status>> + Send + 'static>>;

    async fn play(
        &self,
        request: Request<PlayAnnouncementRequest>,
    ) -> Result<Response<Self::PlayStream>, Status> {
        let req = request.into_inner();
        let call_id = log_call_id(&req.call_id).to_string();

        let (kind, destination, delay_ms) = self.validate(&req, &call_id)?;

        // NIST 800-53 Rev5: SC-5 -- both caps before any socket is bound;
        // the guard is released when the playback task ends.
        // POAM: POA&M-434 cap refusals go to the pod log only (no audit sink).
        let guard = self
            .limits()
            .try_acquire_detailed(destination.ip())
            .map_err(|(refusal, counts)| {
                warn!(
                    call_id = %call_id,
                    reason = %refusal,
                    active = counts.active,
                    active_for_destination = counts.active_for_destination,
                    destinations = counts.destinations,
                    "Announcement refused"
                );
                Status::resource_exhausted(refusal.to_string())
            })?;

        // NIST 800-53 Rev5: SI-11 -- fixed status text; the OS error and the
        // port range stay in the log.
        let (socket, rtp_port) = self.bind_rtp().await.map_err(|e| {
            warn!(call_id = %call_id, error = %e, "Announcement RTP bind failed");
            Status::resource_exhausted("no RTP port available")
        })?;

        info!(
            call_id = %call_id,
            kind = ?kind,
            destination = %destination,
            rtp_port,
            delay_ms,
            "Announcement requested"
        );

        let advertised_ip = self.config.advertised_ip.to_string();
        let ssrc = req.ssrc;
        let max_play = self.config.max_play;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<PlayAnnouncementEvent, Status>>(4);

        tokio::spawn(async move {
            // Held for the task's lifetime: dropped on every exit.
            let _guard = guard;
            let bound = PlayAnnouncementEvent {
                event: Some(Event::Bound(AnnouncementBound {
                    advertised_ip,
                    rtp_port: u32::from(rtp_port),
                })),
            };
            if tx.send(Ok(bound)).await.is_err() {
                // Daemon went away before we even reported the port.
                return;
            }

            let playback = async {
                // Let the caller process the 200 OK / send ACK before audio.
                tokio::time::sleep(Duration::from_millis(u64::from(delay_ms))).await;
                Engine::play_on_socket(kind, socket, destination, ssrc).await
            };

            // Stop when the daemon drops the stream (or its connection dies)
            // and at the duration bound, initial delay included. The select
            // drops the playback future as soon as either fires.
            let outcome = tokio::select! {
                () = tx.closed() => {
                    debug!(call_id = %call_id, "Announcement stream dropped; playback stopped");
                    return;
                }
                r = tokio::time::timeout(max_play, playback) => r,
            };

            let event = match outcome {
                Ok(Ok(packets_sent)) => {
                    info!(call_id = %call_id, packets_sent, "Announcement playback complete");
                    Ok(PlayAnnouncementEvent {
                        event: Some(Event::Completed(AnnouncementCompleted { packets_sent })),
                    })
                }
                Ok(Err(e)) => {
                    warn!(call_id = %call_id, error = %e, "Announcement playback failed");
                    Err(Status::internal("announcement playback failed"))
                }
                Err(_) => {
                    warn!(call_id = %call_id, "Announcement exceeded the maximum play time");
                    Err(Status::deadline_exceeded(
                        "announcement exceeded the maximum play time",
                    ))
                }
            };
            let _ = tx.send(event).await;
        });

        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// The gRPC server: mTLS when configured (with a TLS handshake timeout),
/// and keepalives so plays on a dead connection stop.
///
/// The Play caps are the play bound, not HTTP/2 limits: the daemon shares
/// one connection for all its plays, so `max_concurrent_streams` sits
/// [`STREAM_HEADROOM`] above the cap and over-cap Plays get
/// `RESOURCE_EXHAUSTED` from the cap check. A refused Play over a new
/// connection still costs one TLS handshake.
///
/// NIST 800-53 Rev5: IA-3, SC-8, AC-3 -- mTLS with a client SAN allow-list
/// on every RPC (`Config` refuses a listener off loopback without both);
/// SC-5 -- handshake timeout and stream limit.
///
/// Also returns the fingerprint of the certificate files as loaded, for the
/// renewal watcher.
fn server_builder(config: &Config) -> Result<(Server, Option<TlsFingerprint>), String> {
    let mut builder = Server::builder();
    let mut loaded = None;
    if let Some(tls) = &config.grpc_tls {
        let (tls_config, fingerprint) = load_server_tls_fingerprinted(tls)?;
        loaded = Some(fingerprint);
        builder = builder.tls_config(tls_config).map_err(|e| e.to_string())?;
    }
    let streams =
        u32::try_from(config.max_plays.saturating_add(STREAM_HEADROOM)).unwrap_or(u32::MAX);
    let builder = builder
        .max_concurrent_streams(Some(streams))
        .http2_keepalive_interval(Some(H2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(H2_KEEPALIVE_TIMEOUT))
        .tcp_keepalive(Some(TCP_KEEPALIVE));
    Ok((builder, loaded))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    // Select the process-level rustls CryptoProvider before any TLS config
    // is built (tonic's listener uses it): the CNSA 2.0 subset of aws-lc,
    // TLS 1.3 AES-256-GCM-SHA384 with ML-KEM-1024 / P-384 only.
    // NIST 800-53 Rev5: SC-13 (CNSA 2.0 on this listener)
    if cnsa_provider().install_default().is_err() {
        eprintln!("rustls CryptoProvider was already installed");
    }
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_announcement_server=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-announcement-server starting"
    );

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    if config.dest_policy.allow_loopback {
        warn!("SBC_ANN_ALLOW_LOOPBACK_DEST=true: loopback RTP destinations admitted (lab only)");
    }

    info!(
        listen = %config.grpc_listen,
        mtls = config.grpc_tls.is_some(),
        allowed_client_names = config.allowed_client_names.len(),
        advertised_ip = %config.advertised_ip,
        bind_ip = ?config.bind_ip,
        rtp_port_range = ?config.rtp_port_range,
        max_plays = config.max_plays,
        max_plays_per_dest = config.max_plays_per_dest,
        max_play_secs = config.max_play.as_secs(),
        allowed_dest_cidrs = config.dest_policy.allowed.len(),
        "Configuration loaded"
    );

    let (mut builder, loaded) = match server_builder(&config) {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "AnnouncementService TLS configuration");
            return ExitCode::from(2);
        }
    };
    let gate = ClientNameGate::new(
        config.grpc_tls.is_some(),
        &config.allowed_client_names,
        "AnnouncementService",
    );

    let listen = config.grpc_listen;
    let service = AnnouncementServiceImpl::new(config);

    // NIST 800-53 Rev5: IA-3, SC-12 -- the certificate is read once at
    // start; exit on renewal so the orchestrator restarts the pod with it.
    let tls_files = service.config.grpc_tls.clone().zip(loaded);
    let (changed_tx, mut changed_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        tokio::select! {
            () = shutdown_signal() => {}
            () = tls_changed(tls_files) => {
                warn!("exiting to reload the listener certificate");
                let _ = changed_tx.send(());
            }
        }
    };

    // Only the name-checked AnnouncementService is served (no Health: the
    // probes are TCP checks). NIST 800-53 Rev5: CM-7
    let result = builder
        .add_service(AnnouncementServiceServer::with_interceptor(service, gate))
        .serve_with_shutdown(listen, shutdown)
        .await;

    if let Err(e) = result {
        error!(error = %e, "gRPC server failed");
        return ExitCode::FAILURE;
    }
    if changed_rx.try_recv().is_ok() {
        return ExitCode::from(EXIT_TLS_CHANGED);
    }
    ExitCode::SUCCESS
}

/// SIGTERM or Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to install SIGTERM handler");
                    let _ = ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    info!("shutdown signal received");
}

/// Resolves when the listener's TLS files change; never without TLS.
/// Resolves when the listener's TLS files differ from what was loaded, after
/// a random [`restart_jitter`] so replicas that see the same renewal do not
/// restart together; never without TLS. A shutdown signal during the jitter
/// still wins (the caller selects on both).
async fn tls_changed(tls: Option<(ServerTls, TlsFingerprint)>) {
    let Some((tls, loaded)) = tls else {
        return std::future::pending().await;
    };
    wait_for_tls_change(&tls, loaded, TLS_CHANGE_CHECK).await;
    let jitter = restart_jitter();
    warn!(
        delay_ms = u64::try_from(jitter.as_millis()).unwrap_or(u64::MAX),
        "listener certificate files changed; restarting after a random delay"
    );
    tokio::time::sleep(jitter).await;
}

/// Longest random delay before a certificate-renewal restart.
const MAX_RESTART_JITTER_MS: u64 = 10_000;

/// A uniform random delay in 0..=10 s.
fn restart_jitter() -> Duration {
    use rand::Rng;
    Duration::from_millis(rand::thread_rng().gen_range(0..=MAX_RESTART_JITTER_MS))
}
