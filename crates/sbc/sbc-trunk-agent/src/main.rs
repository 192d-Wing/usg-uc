//! sbc-trunk-agent — trunk maintenance pod.
//!
//! Runs the two outbound trunk loops from `sbc-trunk-services` outside
//! the daemon:
//!
//! - SIP OPTIONS health monitoring per trunk
//! - outbound carrier REGISTER (digest auth) with re-registration
//!
//! Trunk configuration is read from Postgres (the same `trunk_groups`
//! table sbc-api writes) and re-polled on an interval; per-trunk loops
//! start, restart, and stop as the configuration changes. Status
//! snapshots are pushed to the daemon's gRPC `TrunkStatusPublishService`
//! so `TrunkHealthService` reads (sbc-api, dashboard) keep working
//! unchanged.
//!
//! Run the daemon with `SBC_TRUNK_SERVICES=external` so it does not also
//! run these loops, and deploy exactly ONE agent replica — two agents
//! would double-REGISTER to carriers and double-count OPTIONS pings.
//!
//! Configuration (env):
//! - `SBC_POSTGRES_URL` — trunk-group configuration source (required)
//! - `SBC_DAEMON_GRPC_URL` — daemon gRPC endpoint to publish status to,
//!   e.g. `http://sbc-daemon:9091` (required)
//! - `SBC_AGENT_GRPC_LISTEN` — health-probe gRPC listen address
//!   (default `0.0.0.0:9096`)
//! - `SBC_INSTANCE_NAME` — local SIP domain for From/Call-ID in OPTIONS
//!   and REGISTER (default `sbc-trunk-agent`)
//! - `SBC_TRUNK_POLL_SECS` — Postgres config re-poll interval (default 30)
//! - `SBC_PUBLISH_INTERVAL_SECS` — status push interval (default 10)
//! - `SBC_TRUNK_BIND_IP` — local IP to bind SIP sockets to (optional)
//! - `SBC_SIP_CONTACT_IP` — IP written into REGISTER Contact headers.
//!   This must be the DAEMON's externally reachable SIP address (port
//!   5060), not this pod's: carriers route inbound INVITEs to the
//!   registered Contact, and inbound calls must land on the daemon.
//!   Carriers that route inbound to the REGISTER's source address
//!   instead of the Contact cannot use an external agent — keep those
//!   deployments on in-daemon trunk services.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use sbc_grpc_api::health::health_check_response::ServingStatus;
use sbc_grpc_api::health::health_server::{Health, HealthServer};
use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse};
use sbc_grpc_api::sbc::trunk_status_publish_service_client::TrunkStatusPublishServiceClient;
use sbc_grpc_api::sbc::{PublishTrunkStatusRequest, TrunkHealthInfo, TrunkRegistrationInfo};

use sbc_trunk_services::monitor::{MonitoredTrunk, TrunkMonitor};
use sbc_trunk_services::registrar::{TrunkRegConfig, TrunkRegistrar};

/// Agent configuration, parsed from env at startup.
#[derive(Debug, Clone)]
struct Config {
    postgres_url: String,
    daemon_grpc_url: String,
    grpc_listen: std::net::SocketAddr,
    instance_name: String,
    poll_interval: Duration,
    publish_interval: Duration,
    bind_ip: Option<IpAddr>,
    contact_ip: Option<IpAddr>,
    agent_id: String,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let postgres_url =
            std::env::var("SBC_POSTGRES_URL").map_err(|_| "SBC_POSTGRES_URL is required")?;
        let daemon_grpc_url =
            std::env::var("SBC_DAEMON_GRPC_URL").map_err(|_| "SBC_DAEMON_GRPC_URL is required")?;
        let grpc_listen = std::env::var("SBC_AGENT_GRPC_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:9096".to_string())
            .parse()
            .map_err(|e| format!("SBC_AGENT_GRPC_LISTEN invalid: {e}"))?;
        let instance_name =
            std::env::var("SBC_INSTANCE_NAME").unwrap_or_else(|_| "sbc-trunk-agent".to_string());
        let poll_interval = Duration::from_secs(
            std::env::var("SBC_TRUNK_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
                .max(5),
        );
        let publish_interval = Duration::from_secs(
            std::env::var("SBC_PUBLISH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10)
                .max(1),
        );
        let bind_ip = match std::env::var("SBC_TRUNK_BIND_IP") {
            Ok(v) => Some(
                v.parse::<IpAddr>()
                    .map_err(|e| format!("SBC_TRUNK_BIND_IP invalid: {e}"))?,
            ),
            Err(_) => None,
        };
        let contact_ip = match std::env::var("SBC_SIP_CONTACT_IP") {
            Ok(v) => Some(
                v.parse::<IpAddr>()
                    .map_err(|e| format!("SBC_SIP_CONTACT_IP invalid: {e}"))?,
            ),
            Err(_) => None,
        };
        let agent_id = std::env::var("HOSTNAME").unwrap_or_else(|_| instance_name.clone());

        Ok(Self {
            postgres_url,
            daemon_grpc_url,
            grpc_listen,
            instance_name,
            poll_interval,
            publish_interval,
            bind_ip,
            contact_ip,
            agent_id,
        })
    }
}

/// Reconciles desired trunk configuration (from Postgres) against the
/// running monitor/registrar loops: starts new ones, replaces changed
/// ones, stops removed ones.
async fn reconcile_trunks(
    config: &Config,
    monitor: &TrunkMonitor,
    registrar: &TrunkRegistrar,
    last_seen: &mut HashMap<String, serde_json::Value>,
    groups: &[serde_json::Value],
) {
    let mut desired: HashMap<String, serde_json::Value> = HashMap::new();
    for group in groups {
        if let Some(trunks) = group.get("trunks").and_then(|v| v.as_array()) {
            for trunk in trunks {
                if let Some(id) = trunk.get("id").and_then(|v| v.as_str())
                    && !id.is_empty()
                {
                    desired.insert(id.to_string(), trunk.clone());
                }
            }
        }
    }

    // Stop loops for trunks that disappeared from configuration.
    let removed: Vec<String> = last_seen
        .keys()
        .filter(|id| !desired.contains_key(*id))
        .cloned()
        .collect();
    for id in removed {
        info!(trunk_id = %id, "Trunk removed from configuration; stopping services");
        monitor.stop_trunk(&id).await;
        registrar.stop_trunk(&id).await;
        last_seen.remove(&id);
    }

    // Start or replace loops for new/changed trunks. monitor_trunk and
    // register_trunk replace any existing loop for the trunk id, so a
    // changed config does not leak the old loop — but we only call them
    // on actual change to avoid re-REGISTERing every poll.
    for (id, trunk) in &desired {
        if last_seen.get(id) == Some(trunk) {
            continue;
        }
        start_trunk_services(config, monitor, registrar, trunk).await;
        last_seen.insert(id.clone(), trunk.clone());
    }
}

/// Starts (or replaces) the OPTIONS monitor and registration loop for one
/// trunk, mirroring the daemon's `start_trunk_services` field handling.
/// Unlike the daemon there is no zone registry here: bind and Contact IPs
/// come from the agent's env (`SBC_TRUNK_BIND_IP`, `SBC_SIP_CONTACT_IP`).
async fn start_trunk_services(
    config: &Config,
    monitor: &TrunkMonitor,
    registrar: &TrunkRegistrar,
    trunk: &serde_json::Value,
) {
    let trunk_id = trunk.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let host = trunk
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let port = trunk
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(5060) as u16;
    if trunk_id.is_empty() || host.is_empty() {
        return;
    }

    let ping_enabled = trunk
        .get("options_ping_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if ping_enabled {
        let interval = trunk
            .get("options_ping_interval")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30) as u32;
        monitor.monitor_trunk(MonitoredTrunk {
            trunk_id: trunk_id.to_string(),
            host: host.to_string(),
            port,
            interval_secs: interval,
            bind_ip: config.bind_ip,
        });
        info!(trunk_id, host, "Started OPTIONS health monitor");
    } else {
        // Config may have just turned monitoring off for a known trunk.
        monitor.stop_trunk(trunk_id).await;
    }

    let register_enabled = trunk
        .get("register_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if register_enabled {
        let username = trunk
            .get("sip_username")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let password = trunk
            .get("sip_password")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if username.is_empty() || password.is_empty() {
            warn!(trunk_id, "register_enabled but credentials missing");
            return;
        }
        let domain = trunk
            .get("sip_domain")
            .and_then(|v| v.as_str())
            .unwrap_or(host);
        let expires = trunk
            .get("register_expires")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(25) as u32;
        registrar.register_trunk(TrunkRegConfig {
            trunk_id: trunk_id.to_string(),
            host: host.to_string(),
            port,
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            expires,
            bind_ip: config.bind_ip,
            external_ip: config.contact_ip,
        });
        info!(trunk_id, host, "Started carrier registration");
    } else {
        registrar.stop_trunk(trunk_id).await;
    }
}

/// Builds the publish request from current monitor/registrar snapshots.
async fn build_snapshot(
    config: &Config,
    monitor: &TrunkMonitor,
    registrar: &TrunkRegistrar,
) -> PublishTrunkStatusRequest {
    let health = monitor
        .get_all_status()
        .await
        .into_iter()
        .map(|s| TrunkHealthInfo {
            trunk_id: s.trunk_id,
            reachable: s.reachable,
            last_response_ms: s.last_response_ms.unwrap_or(0) as i64,
            last_success_epoch: s.last_success.unwrap_or(0),
            last_failure_epoch: s.last_failure.unwrap_or(0),
            consecutive_success: s.consecutive_success,
            consecutive_failures: s.consecutive_failures,
            total_pings: s.total_pings,
            total_success: s.total_success,
            uptime_pct: s.uptime_pct,
            in_service_since_epoch: s.in_service_since.unwrap_or(0),
        })
        .collect();
    let registrations = registrar
        .get_all_status()
        .await
        .into_iter()
        .map(|s| TrunkRegistrationInfo {
            trunk_id: s.trunk_id,
            registered: s.registered,
            state: s.state,
            registrar: s.registrar,
            username: s.username,
            last_registered_epoch: s.last_registered.unwrap_or(0),
            last_error: s.last_error.unwrap_or_default(),
            expires_secs: s.expires,
            attempts: s.attempts,
            successes: s.successes,
        })
        .collect();
    PublishTrunkStatusRequest {
        agent_id: config.agent_id.clone(),
        health,
        registrations,
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
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_trunk_agent=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-trunk-agent starting"
    );

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };
    info!(
        daemon = %config.daemon_grpc_url,
        poll_secs = config.poll_interval.as_secs(),
        publish_secs = config.publish_interval.as_secs(),
        bind_ip = ?config.bind_ip,
        contact_ip = ?config.contact_ip,
        "Configuration loaded"
    );
    if config.contact_ip.is_none() {
        warn!(
            "SBC_SIP_CONTACT_IP not set — REGISTER Contact headers will use this pod's IP, \
             so carriers will route inbound calls here instead of to the daemon"
        );
    }

    // Trunk config source. Retry like the daemon does: a fresh helm
    // install can take ~30s before Postgres accepts connections.
    let store = {
        let mut attempt = 0u32;
        loop {
            match sbc_config_store::PostgresTrunkGroupStore::new(&config.postgres_url).await {
                Ok(s) => break s,
                Err(e) => {
                    attempt += 1;
                    if attempt >= 10 {
                        error!(error = %e, "Postgres unreachable after 10 attempts");
                        return ExitCode::FAILURE;
                    }
                    let wait = Duration::from_secs(u64::from(attempt.min(6)) * 5);
                    warn!(error = %e, attempt, wait_secs = wait.as_secs(), "Postgres connect failed; retrying");
                    tokio::time::sleep(wait).await;
                }
            }
        }
    };
    info!("Trunk group store connected (PostgreSQL)");

    let monitor = Arc::new(TrunkMonitor::new(&config.instance_name));
    let registrar = Arc::new(TrunkRegistrar::new(&config.instance_name));

    // Health-probe gRPC server.
    let health_listen = config.grpc_listen;
    tokio::spawn(async move {
        if let Err(e) = Server::builder()
            .add_service(HealthServer::new(AlwaysServing))
            .serve(health_listen)
            .await
        {
            error!(error = %e, "health gRPC server failed");
        }
    });

    // Config reconcile loop.
    {
        let config = config.clone();
        let monitor = Arc::clone(&monitor);
        let registrar = Arc::clone(&registrar);
        tokio::spawn(async move {
            let mut last_seen: HashMap<String, serde_json::Value> = HashMap::new();
            let mut ticker = tokio::time::interval(config.poll_interval);
            loop {
                ticker.tick().await;
                match store.list().await {
                    Ok(groups) => {
                        reconcile_trunks(&config, &monitor, &registrar, &mut last_seen, &groups)
                            .await;
                    }
                    Err(e) => warn!(error = %e, "Failed to load trunk groups from Postgres"),
                }
            }
        });
    }

    // Status publish loop with reconnect-on-failure, until shutdown.
    let mut client: Option<TrunkStatusPublishServiceClient<tonic::transport::Channel>> = None;
    let mut ticker = tokio::time::interval(config.publish_interval);
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to install SIGTERM handler");
            return ExitCode::FAILURE;
        }
    };

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
        }

        if client.is_none() {
            match TrunkStatusPublishServiceClient::connect(config.daemon_grpc_url.clone()).await {
                Ok(c) => {
                    info!(daemon = %config.daemon_grpc_url, "Connected to daemon gRPC");
                    client = Some(c);
                }
                Err(e) => {
                    warn!(error = %e, "Cannot reach daemon gRPC; will retry");
                    continue;
                }
            }
        }

        let snapshot = build_snapshot(&config, &monitor, &registrar).await;
        let trunk_count = snapshot.health.len().max(snapshot.registrations.len());
        if let Some(ref mut c) = client {
            match c.publish_trunk_status(snapshot).await {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    if resp.accepted {
                        debug!(trunk_count, "Published trunk status");
                    } else {
                        warn!(message = %resp.message, "Daemon rejected trunk status publish");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Publish failed; dropping connection for retry");
                    client = None;
                }
            }
        }
    }

    info!("shutdown signal received; stopping trunk loops");
    monitor.stop_all();
    registrar.stop_all();
    ExitCode::SUCCESS
}
