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
//! Configuration (env):
//! - `SBC_ANN_GRPC_LISTEN` — gRPC listen address (default `0.0.0.0:9095`)
//! - `SBC_ANN_ADVERTISED_IP` — IP placed in the Bound event for the
//!   daemon's SDP `c=` line (the pod's externally reachable media IP).
//!   Falls back to `SBC_ANN_BIND_IP`; startup fails when neither is set.
//! - `SBC_ANN_BIND_IP` — local IP to bind RTP sockets to (default any)
//! - `SBC_ANN_RTP_PORT_MIN` / `SBC_ANN_RTP_PORT_MAX` — inclusive UDP port
//!   range for RTP sockets (default: kernel-assigned ephemeral ports).
//!   Set this when the pod's exposed UDP port range is constrained.
//! - `SBC_ANN_DEFAULT_DELAY_MS` — Bound→first-RTP-packet delay when the
//!   request leaves `initial_delay_ms` at 0 (default 200ms, matching the
//!   daemon's historical ACK-settle sleep).

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;

use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use sbc_grpc_api::health::health_check_response::ServingStatus;
use sbc_grpc_api::health::health_server::{Health, HealthServer};
use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse};
use sbc_grpc_api::sbc::announcement_service_server::{
    AnnouncementService, AnnouncementServiceServer,
};
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{
    AnnouncementBound, AnnouncementCompleted, AnnouncementKind, PlayAnnouncementEvent,
    PlayAnnouncementRequest,
};

use sbc_announcement::{AnnouncementServer as Engine, AnnouncementType};

/// Pod configuration, parsed from env at startup.
#[derive(Debug, Clone)]
struct Config {
    grpc_listen: SocketAddr,
    advertised_ip: IpAddr,
    bind_ip: Option<IpAddr>,
    rtp_port_range: Option<(u16, u16)>,
    default_delay_ms: u32,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let grpc_listen: SocketAddr = std::env::var("SBC_ANN_GRPC_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:9095".to_string())
            .parse()
            .map_err(|e| format!("SBC_ANN_GRPC_LISTEN invalid: {e}"))?;

        let bind_ip = match std::env::var("SBC_ANN_BIND_IP") {
            Ok(v) => Some(
                v.parse::<IpAddr>()
                    .map_err(|e| format!("SBC_ANN_BIND_IP invalid: {e}"))?,
            ),
            Err(_) => None,
        };

        let advertised_ip = match std::env::var("SBC_ANN_ADVERTISED_IP") {
            Ok(v) => v
                .parse::<IpAddr>()
                .map_err(|e| format!("SBC_ANN_ADVERTISED_IP invalid: {e}"))?,
            Err(_) => bind_ip.filter(|ip| !ip.is_unspecified()).ok_or_else(|| {
                "SBC_ANN_ADVERTISED_IP is required (no usable SBC_ANN_BIND_IP fallback): \
                 it is the media IP placed in the announcement SDP"
                    .to_string()
            })?,
        };

        let rtp_port_range = match (
            std::env::var("SBC_ANN_RTP_PORT_MIN"),
            std::env::var("SBC_ANN_RTP_PORT_MAX"),
        ) {
            (Ok(min), Ok(max)) => {
                let min: u16 = min
                    .parse()
                    .map_err(|e| format!("SBC_ANN_RTP_PORT_MIN invalid: {e}"))?;
                let max: u16 = max
                    .parse()
                    .map_err(|e| format!("SBC_ANN_RTP_PORT_MAX invalid: {e}"))?;
                if min == 0 || min > max {
                    return Err(format!("invalid RTP port range {min}-{max}"));
                }
                Some((min, max))
            }
            (Err(_), Err(_)) => None,
            _ => {
                return Err(
                    "SBC_ANN_RTP_PORT_MIN and SBC_ANN_RTP_PORT_MAX must be set together"
                        .to_string(),
                );
            }
        };

        let default_delay_ms = std::env::var("SBC_ANN_DEFAULT_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);

        Ok(Self {
            grpc_listen,
            advertised_ip,
            bind_ip,
            rtp_port_range,
            default_delay_ms,
        })
    }
}

/// gRPC `AnnouncementService` implementation backed by the shared
/// `sbc-announcement` playback engine.
#[derive(Debug)]
struct AnnouncementServiceImpl {
    config: Config,
}

impl AnnouncementServiceImpl {
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
            .map_err(|e| Status::invalid_argument(format!("rtp_destination invalid: {e}")))?;

        let (socket, rtp_port) = self
            .bind_rtp()
            .await
            .map_err(|e| Status::resource_exhausted(format!("RTP bind failed: {e}")))?;

        let delay_ms = if req.initial_delay_ms == 0 {
            self.config.default_delay_ms
        } else {
            req.initial_delay_ms
        };

        info!(
            call_id = %req.call_id,
            kind = ?kind,
            destination = %destination,
            rtp_port,
            delay_ms,
            "Announcement requested"
        );

        let advertised_ip = self.config.advertised_ip.to_string();
        let ssrc = req.ssrc;
        let call_id = req.call_id;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<PlayAnnouncementEvent, Status>>(4);

        tokio::spawn(async move {
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

            // Let the caller process the 200 OK / send ACK before audio.
            tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay_ms))).await;

            match Engine::play_on_socket(kind, socket, destination, ssrc).await {
                Ok(packets_sent) => {
                    info!(call_id = %call_id, packets_sent, "Announcement playback complete");
                    let done = PlayAnnouncementEvent {
                        event: Some(Event::Completed(AnnouncementCompleted { packets_sent })),
                    };
                    let _ = tx.send(Ok(done)).await;
                }
                Err(e) => {
                    warn!(call_id = %call_id, error = %e, "Announcement playback failed");
                    let _ = tx.send(Err(Status::internal(e))).await;
                }
            }
        });

        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// Minimal always-serving gRPC health implementation for k8s probes.
#[derive(Debug, Default)]
struct AlwaysServing;

#[tonic::async_trait]
impl Health for AlwaysServing {
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        }))
    }

    type WatchStream =
        Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send + 'static>>;

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let stream = tokio_stream::once(Ok(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        }));
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
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

    info!(
        listen = %config.grpc_listen,
        advertised_ip = %config.advertised_ip,
        bind_ip = ?config.bind_ip,
        rtp_port_range = ?config.rtp_port_range,
        "Configuration loaded"
    );

    let listen = config.grpc_listen;
    let service = AnnouncementServiceImpl { config };

    let shutdown = async {
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
    };

    let result = Server::builder()
        .add_service(AnnouncementServiceServer::new(service))
        .add_service(HealthServer::new(AlwaysServing))
        .serve_with_shutdown(listen, shutdown)
        .await;

    if let Err(e) = result {
        error!(error = %e, "gRPC server failed");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
