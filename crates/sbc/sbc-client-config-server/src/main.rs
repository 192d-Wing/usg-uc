//! sbc-client-config-server — soft-client discovery + provisioning pod.
//!
//! Implements the provisioning service from docs/CLIENT-PROVISIONING-OIDC.md:
//!
//! - `GET /.well-known/sip-client-config` — unauthenticated discovery
//!   document (OIDC issuer/client id, this POP's config endpoint). Served
//!   behind the anycast VIP; this is the soft client's first contact after
//!   the user types the service domain.
//! - `GET /v1/client-config` — per-user SIP configuration (DN, SIP URI,
//!   POP-scoped registrar domain for RFC 3263 NAPTR/SRV resolution).
//!   Authorized by an OIDC bearer token (Keycloak) validated against the
//!   `IdP`'s JWKS: signature, `iss`, `aud`, `exp`, `sip` scope, `dn` claim.
//!
//! Stateless by design — user identity comes from token claims, policy
//! from env — so the pod scales horizontally per POP and needs no
//! database. Runs as its own pod so soft-client sign-in rolls and
//! recovers independently of the SIP-serving daemon.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod handlers;
mod jwks;
mod token;

use config::Config;
use handlers::AppState;
use jwks::JwksCache;
use token::Verifier;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_client_config_server=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-client-config-server starting"
    );

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    let http = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "http client build failed");
            return ExitCode::from(3);
        }
    };

    let jwks = Arc::new(JwksCache::new(http, cfg.oidc_issuer.clone()));
    // Warm the key cache so the first client request doesn't pay the IdP
    // round trip. Not fatal when the IdP is down — readiness gates traffic
    // until keys arrive.
    if let Err(e) = jwks.refresh().await {
        warn!(issuer = %cfg.oidc_issuer, error = %e, "JWKS prefetch failed; pod stays not-ready until the IdP is reachable");
    }

    let verifier = Arc::new(Verifier::new(
        Arc::clone(&jwks),
        cfg.oidc_issuer.clone(),
        cfg.oidc_audience.clone(),
    ));
    info!(
        issuer = %cfg.oidc_issuer,
        audience = %cfg.oidc_audience,
        pop = %cfg.pop_id,
        registrar = %cfg.registrar_domain,
        "verifier ready"
    );

    let listen_addr = cfg.listen_addr;
    let app = handlers::router(AppState {
        cfg: Arc::new(cfg),
        verifier,
        start_time: std::time::Instant::now(),
    });

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %listen_addr, error = %e, "bind failed");
            return ExitCode::from(4);
        }
    };
    info!(addr = %listen_addr, "listening");

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

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        error!(error = %e, "server error");
        return ExitCode::from(5);
    }
    info!("clean shutdown");
    ExitCode::SUCCESS
}
