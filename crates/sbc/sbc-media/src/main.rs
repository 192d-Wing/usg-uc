//! sbc-media — the SBC media plane pod.
//!
//! Hosts the gRPC `MediaControllerService` (see
//! `sbc-grpc-api/proto/media_controller.proto`) over a
//! [`sbc_media_core::media_pipeline::MediaPipeline`]. The SIP daemon keeps all
//! signaling and dialog state and drives this pod per call — allocate ports,
//! set remote addresses, start/stop the relay, terminate DTLS-SRTP — so this
//! pod owns only the media sockets and (in terminate mode) the DTLS sidecar.
//! That keeps the media plane independently scalable and crash-isolated from
//! signaling (Phase 2 of the signaling↔media split).
//!
//! Configuration (env), mirroring the daemon's `[media]` section so the pod
//! relays identically to the in-process path:
//! - `SBC_MEDIA_GRPC_LISTEN` — gRPC listen address (default `0.0.0.0:9096`).
//! - `SBC_MEDIA_RTP_PORT_MIN` / `SBC_MEDIA_RTP_PORT_MAX` — inclusive RTP port
//!   range (defaults 16384 / 32768, the pipeline defaults).
//! - `SBC_MEDIA_DEFAULT_MODE` — `relay` (default) or `pass-through`.
//! - `SBC_MEDIA_SRTP_REQUIRED` — `true` (default) / `false`.
//! - `SBC_MEDIA_ADVERTISED_IP` — this node's media IP, returned per session so
//!   the signaling daemon steers SDP to it (standalone media-node pool). Unset
//!   in the co-located deployment (signaling advertises the shared pod IP).
//! - `SBC_MEDIA_TERMINATE_DTLS` — `true` to terminate DTLS-SRTP. When set, both
//!   of the following are REQUIRED (fail-closed, matching the daemon):
//!   - `SBC_MEDIA_DTLS_SIDECAR_SOCKET` — the DTLS terminator sidecar's UDS path.
//!   - `SBC_MEDIA_DTLS_FINGERPRINT_FILE` — the file the sidecar publishes its
//!     SHA-384 fingerprint to; served to signaling over `GetDtlsFingerprint`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use sbc_grpc_api::health::health_check_response::ServingStatus;
use sbc_grpc_api::health::health_server::{Health, HealthServer};
use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse};
use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerServiceServer;

use sbc_media_core::dtls_identity::DtlsFingerprintSource;
use sbc_media_core::grpc_media_server::MediaControllerServer;
use sbc_media_core::media_pipeline::{MediaPipeline, MediaPipelineConfig};
use uc_media_engine::MediaMode;

/// Pod configuration, parsed from env at startup.
#[derive(Debug, Clone)]
struct Config {
    grpc_listen: SocketAddr,
    rtp_port_min: u16,
    rtp_port_max: u16,
    default_mode: MediaMode,
    srtp_required: bool,
    terminate_dtls: bool,
    dtls_sidecar_socket: Option<PathBuf>,
    dtls_fingerprint_file: Option<PathBuf>,
    /// This node's advertised media IP, returned per session so signaling steers
    /// SDP to it (Phase 3 media-node pool). Unset in the co-located deployment,
    /// where signaling advertises the shared pod IP from its own zone config.
    advertised_media_ip: Option<IpAddr>,
}

fn env_bool(key: &str, default: bool) -> Result<bool, String> {
    let Ok(v) = std::env::var(key) else {
        return Ok(default);
    };
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("{key} invalid boolean: {other:?}")),
    }
}

fn env_port(key: &str, default: u16) -> Result<u16, String> {
    std::env::var(key).ok().map_or(Ok(default), |v| {
        v.parse().map_err(|e| format!("{key} invalid: {e}"))
    })
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let grpc_listen: SocketAddr = std::env::var("SBC_MEDIA_GRPC_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:9096".to_string())
            .parse()
            .map_err(|e| format!("SBC_MEDIA_GRPC_LISTEN invalid: {e}"))?;

        let default_mode = match std::env::var("SBC_MEDIA_DEFAULT_MODE")
            .unwrap_or_else(|_| "relay".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "relay" => MediaMode::Relay,
            "pass-through" | "passthrough" => MediaMode::PassThrough,
            other => return Err(format!("SBC_MEDIA_DEFAULT_MODE invalid: {other:?}")),
        };

        let terminate_dtls = env_bool("SBC_MEDIA_TERMINATE_DTLS", false)?;
        let dtls_sidecar_socket = std::env::var("SBC_MEDIA_DTLS_SIDECAR_SOCKET")
            .ok()
            .map(PathBuf::from);
        let dtls_fingerprint_file = std::env::var("SBC_MEDIA_DTLS_FINGERPRINT_FILE")
            .ok()
            .map(PathBuf::from);

        // Fail-closed, identical to the daemon: terminating DTLS needs both the
        // sidecar socket and the sidecar-published fingerprint file, or the pod
        // would advertise an identity it can't back and black-hole secured calls.
        if terminate_dtls && (dtls_sidecar_socket.is_none() || dtls_fingerprint_file.is_none()) {
            return Err(
                "SBC_MEDIA_TERMINATE_DTLS requires SBC_MEDIA_DTLS_SIDECAR_SOCKET and \
                        SBC_MEDIA_DTLS_FINGERPRINT_FILE"
                    .to_string(),
            );
        }

        let advertised_media_ip = std::env::var("SBC_MEDIA_ADVERTISED_IP")
            .ok()
            .map(|s| s.parse::<IpAddr>())
            .transpose()
            .map_err(|e| format!("SBC_MEDIA_ADVERTISED_IP invalid: {e}"))?;

        Ok(Self {
            grpc_listen,
            rtp_port_min: env_port("SBC_MEDIA_RTP_PORT_MIN", 16_384)?,
            rtp_port_max: env_port("SBC_MEDIA_RTP_PORT_MAX", 32_768)?,
            default_mode,
            srtp_required: env_bool("SBC_MEDIA_SRTP_REQUIRED", true)?,
            terminate_dtls,
            dtls_sidecar_socket,
            dtls_fingerprint_file,
            advertised_media_ip,
        })
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

/// Builds the `MediaControllerServer` from config: the pipeline, the DTLS
/// identity (terminate mode), and the media-failure event bridge.
///
/// Returns an error string if the fingerprint file can't be read in terminate
/// mode (fail-closed — see [`Config::from_env`]).
fn build_server(config: &Config) -> Result<MediaControllerServer, String> {
    // `from_env` guarantees the fingerprint file is present whenever terminate
    // mode is on, so the `(true, None)` case is unreachable and maps to no source.
    let fingerprint = match (config.terminate_dtls, config.dtls_fingerprint_file.as_ref()) {
        (true, Some(path)) => {
            let source = DtlsFingerprintSource::from_file(path)
                .map_err(|e| format!("reading DTLS fingerprint file {}: {e}", path.display()))?;
            info!(fingerprint = %source.current(), "DTLS-SRTP termination enabled");
            Some(Arc::new(source))
        }
        _ => None,
    };

    // The pipeline signals a failed call's id here; the server bridges it to
    // WatchMediaEvents subscribers (the signaling process).
    let (media_failure_tx, media_failure_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    let media_config = MediaPipelineConfig {
        default_mode: config.default_mode,
        srtp_required: config.srtp_required,
        advertised_media_ip: config.advertised_media_ip,
        rtp_port_min: config.rtp_port_min,
        rtp_port_max: config.rtp_port_max,
        terminate_dtls: config.terminate_dtls,
        dtls_sidecar_socket: config.dtls_sidecar_socket.clone(),
        dtls_fingerprint: fingerprint.clone(),
        media_failure_tx: Some(media_failure_tx),
        ..Default::default()
    };
    let pipeline = Arc::new(MediaPipeline::new(media_config));
    Ok(MediaControllerServer::new(
        pipeline,
        fingerprint,
        media_failure_rx,
    ))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_media=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "sbc-media starting");

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    // TODO: gRPC authentication (mTLS or token) on MediaControllerService.
    // Any peer that can reach this port can allocate ports / drive relays;
    // restrict access via NetworkPolicy until gRPC auth is implemented.
    warn!(
        "MediaControllerService gRPC is unauthenticated — restrict access via \
         NetworkPolicy until gRPC auth is implemented"
    );

    info!(
        listen = %config.grpc_listen,
        rtp_port_range = ?(config.rtp_port_min, config.rtp_port_max),
        default_mode = ?config.default_mode,
        terminate_dtls = config.terminate_dtls,
        "Configuration loaded"
    );

    let service = match build_server(&config) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to build media server");
            return ExitCode::from(2);
        }
    };

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

    info!(listen = %config.grpc_listen, "MediaControllerService listening");
    let result = Server::builder()
        .add_service(MediaControllerServiceServer::new(service))
        .add_service(HealthServer::new(AlwaysServing))
        .serve_with_shutdown(config.grpc_listen, shutdown)
        .await;

    match result {
        Ok(()) => {
            info!("sbc-media stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "gRPC server error");
            ExitCode::FAILURE
        }
    }
}
