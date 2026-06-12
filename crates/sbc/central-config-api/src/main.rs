//! central-config-api — the fleet-facing HTTP service for the central
//! configuration database (Phase 1 of `docs/CENTRAL-CONFIG-PLAN.md`).
//!
//! Serves the site-scoped sync surface (`/v1/sync/{site}/epoch|delta|
//! snapshot`) the per-site `sbc-config-sync` agent pulls, authorized by
//! per-site OIDC service-account tokens whose `site_code` claim must
//! match the path. It writes nothing to sites and never talks to the SIP
//! daemons: sites pull and apply on their own.

use std::process::ExitCode;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod handlers;
mod state;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,central_config_api=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).json().init();

    info!(version = env!("CARGO_PKG_VERSION"), "central-config-api starting");

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

    if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
        error!(error = %e, "server error");
        return ExitCode::from(5);
    }
    info!("clean shutdown");
    ExitCode::SUCCESS
}
