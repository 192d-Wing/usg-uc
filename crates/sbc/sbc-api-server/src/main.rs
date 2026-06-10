//! sbc-api-server — stand-alone REST API pod for the USG SBC.
//!
//! Owns the config-entity surface (phones, DIDs, trunk groups, dial
//! plans) directly out of Postgres, and reverse-proxies everything else
//! to the sbc-daemon's REST endpoint. After a write that needs SIP-
//! router invalidation, sbc-api calls the daemon's `TrunkSync` /
//! `DialPlanSync` / `DidMappingSync` gRPC services to push the change.
//!
//! Runs independently of the daemon so dashboard/config releases roll
//! without touching the SIP-serving process. The daemon is on the
//! upgrade-blast-radius side that drops calls when it restarts; sbc-api
//! is the side that takes operator pressure.

use std::process::ExitCode;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod config;
mod handlers;
mod state;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    // Tracing first so init failures get logged.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_api_server=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-api-server starting"
    );

    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    let app_state = match state::AppState::build(&cfg).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "state init failed");
            return ExitCode::from(3);
        }
    };

    let router = handlers::router(app_state);

    let listener = match tokio::net::TcpListener::bind(cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %cfg.listen_addr, error = %e, "bind failed");
            return ExitCode::from(4);
        }
    };
    info!(addr = %cfg.listen_addr, "listening");

    // Shutdown on SIGTERM / SIGINT — same shape Kubernetes expects for
    // graceful pod termination during a rolling update.
    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let term = async {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut s) = signal(SignalKind::terminate()) {
                s.recv().await;
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! {
            () = ctrl_c => info!("SIGINT received, shutting down"),
            () = term => info!("SIGTERM received, shutting down"),
        }
    };

    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
    {
        error!(error = %e, "server error");
        return ExitCode::from(5);
    }
    info!("clean shutdown");
    ExitCode::SUCCESS
}
