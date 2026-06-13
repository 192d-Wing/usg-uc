//! sbc-config-sync — per-site config sync agent.
//!
//! Polls `central-config-api` for this site's shard and applies deltas /
//! snapshots into the local Postgres on an interval, surviving WAN
//! outages by serving the last-applied state until the link returns.

use std::process::ExitCode;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use sbc_config_sync::{
    Auth, AuthConfig, CentralClient, Config, Outcome, SyncStatus, TokenProvider, reconcile, status,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_config_sync=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).json().init();

    info!(version = env!("CARGO_PKG_VERSION"), "sbc-config-sync starting");

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    // The local pool. We don't migrate here — the SBC stack owns the
    // site-local schema; the agent only reads/writes existing tables.
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&cfg.local_database_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "local database connect failed");
            return ExitCode::from(3);
        }
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let auth = match &cfg.auth {
        AuthConfig::Static(token) => Auth::Static(token.clone()),
        AuthConfig::Oidc { token_url, client_id, client_secret, scope } => Auth::Oidc(
            TokenProvider::new(http.clone(), token_url, client_id, client_secret, scope),
        ),
    };
    let client = CentralClient::new(http, cfg.central_url.clone(), auth);

    // Metrics/health server, sharing status with the reconcile loop.
    let sync_status = SyncStatus::new(&cfg.site_code);
    match tokio::net::TcpListener::bind(cfg.metrics_addr).await {
        Ok(listener) => {
            let router = status::router(sync_status.clone());
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    error!(error = %e, "metrics server exited");
                }
            });
            info!(addr = %cfg.metrics_addr, "metrics server listening");
        }
        Err(e) => {
            // Non-fatal: keep syncing even if the metrics port is taken.
            warn!(addr = %cfg.metrics_addr, error = %e, "metrics bind failed; continuing without it");
        }
    }

    let tick = cfg.jittered_interval();
    info!(site = %cfg.site_code, interval_secs = tick.as_secs(), "entering sync loop");
    let mut ticker = interval(tick);
    // If a cycle runs long (big snapshot), don't then fire a burst of
    // catch-up ticks — just resume the cadence.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!("shutdown signal received, exiting sync loop");
                return ExitCode::SUCCESS;
            }
            _ = ticker.tick() => {
                match reconcile(&pool, &client, &cfg.site_code).await {
                    Ok(outcome) => {
                        match &outcome {
                            Outcome::UpToDate { epoch } =>
                                info!(site = %cfg.site_code, epoch = *epoch, "up to date"),
                            Outcome::DeltaApplied { from, to, changes } =>
                                info!(site = %cfg.site_code, from = *from, to = *to, changes = *changes, "delta applied"),
                            Outcome::Snapshotted { epoch, rows } =>
                                info!(site = %cfg.site_code, epoch = *epoch, rows = *rows, "snapshot applied"),
                        }
                        sync_status.record_success(&outcome);
                    }
                    Err(e) => {
                        // Transient (WAN down, central restarting): keep the
                        // last-applied state and retry next tick.
                        warn!(site = %cfg.site_code, error = %e, "reconcile failed; will retry");
                        sync_status.record_error();
                    }
                }
            }
        }
    }
}

async fn shutdown_signal() {
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
        () = ctrl_c => {},
        () = term => {},
    }
}
