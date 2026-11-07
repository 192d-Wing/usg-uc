//! sbc-provision-server — stand-alone phone provisioning HTTP pod.
//!
//! Serves `/provision/<MAC>.{cfg,xml}` (and the legacy bare-root path
//! `/<MAC>.{cfg,xml}` that some TEO firmwares hit pre-discovery) by
//! reading the phone record from Postgres and rendering the vendor-
//! specific config via `uc_phone_mgmt::ProvisioningServer`.
//!
//! Runs as its own pod so phone provisioning rolls and recovers
//! independently of the SIP-serving daemon. The daemon's old
//! `serve_phone_config` code path stays in place for now (PR6 doesn't
//! remove it) but stops being on the request path once the chart's
//! nginx routes `/provision/*` here.

use std::process::ExitCode;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sbc_config_store::PostgresPhoneStore;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uc_phone_mgmt::provisioning::ProvisioningServer;

mod config;
mod token;

use config::Config;
use token::ProvisionSecret;

#[derive(Clone)]
struct AppState {
    phones: Arc<PostgresPhoneStore>,
    provisioning: Arc<ProvisioningServer>,
    start_time: std::time::Instant,
    /// Shared secret for HMAC device auth. `None` = unauthenticated.
    provision_secret: Option<ProvisionSecret>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    // `--mint-token <MAC>`: print the device token for a MAC and exit.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--mint-token") {
        return mint_token_cli(args.get(1).map(String::as_str));
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_provision_server=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-provision-server starting"
    );

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    let phones = match PostgresPhoneStore::new(&cfg.database_url).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            error!(error = %e, "PostgresPhoneStore init failed");
            return ExitCode::from(3);
        }
    };

    let provisioning = Arc::new(ProvisioningServer::new(
        &cfg.provision_host,
        cfg.provision_port,
    ));
    info!(host = %cfg.provision_host, port = cfg.provision_port, "ProvisioningServer ready");

    if cfg.provision_secret.is_none() {
        warn!(
            "SBC_PROVISION_SECRET not set — phone provisioning is unauthenticated; \
               any host that can reach this endpoint can fetch phone configs"
        );
    }

    let state = AppState {
        phones,
        provisioning,
        start_time: std::time::Instant::now(),
        provision_secret: cfg.provision_secret.clone(),
    };

    let restriction = source_restriction(&cfg);

    let app = Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/system/version", get(version))
        // Canonical path used by phones after first boot (URL from the
        // rendered config's update_server field).
        .route("/provision/{*path}", get(serve_phone_config))
        // TEO global-config probe — daemon used to return 404 with a
        // specific body; same thing here so phones don't fall through
        // to nginx's SPA fallback.
        .route("/TCS7000A.xml", get(serve_teo_global))
        .layer(axum::middleware::from_fn_with_state(
            restriction,
            restrict_source,
        ))
        .with_state(state)
        // NIST 800-53 Rev5: IA-5 (protect authenticator) -- record only the path in the request
        // span; the query string carries the device token (POA&M-120).
        .layer(TraceLayer::new_for_http().make_span_with(http_span));

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

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    {
        error!(error = %e, "server error");
        return ExitCode::from(5);
    }
    info!("clean shutdown");
    ExitCode::SUCCESS
}

/// Middleware state for [`restrict_source`]: the source allowlist plus
/// the trusted-proxy networks used to decide when `X-Real-IP` is
/// trustworthy.
#[derive(Clone)]
struct SourceRestriction {
    allowed: Arc<Vec<ipnet::IpNet>>,
    trusted_proxies: Arc<Vec<ipnet::IpNet>>,
}

/// Rejects provisioning requests whose originating client IP is outside
/// the allowed source networks. A no-op when no CIDRs are configured.
///
/// The client IP comes from nginx's `X-Real-IP` header, but only when
/// the request's TCP peer is a configured trusted proxy — otherwise a
/// caller reaching this pod directly could forge an allowed source IP.
/// When no trusted proxies are configured the header is trusted
/// unconditionally (a startup warning is logged) and the check falls
/// back to the direct peer only when the header is absent.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
async fn restrict_source(
    axum::extract::State(cfg): axum::extract::State<SourceRestriction>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if cfg.allowed.is_empty() {
        return next.run(req).await;
    }
    // Probes (kubelet) and version come from the node, not the phone
    // subnet — exempt them.
    let path = req.uri().path();
    if matches!(path, "/healthz" | "/readyz" | "/system/version") {
        return next.run(req).await;
    }

    // Fail closed if the connection has no peer info (should never happen
    // with into_make_service_with_connect_info, but don't allowlist a
    // request whose source we can't establish).
    let Some(peer) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
    else {
        warn!("provisioning request with no connection info; denying");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "source network not permitted"})),
        )
            .into_response();
    };

    let client_ip = sbc_http_util::resolve_client_ip(req.headers(), peer, &cfg.trusted_proxies);
    if cfg.allowed.iter().any(|net| net.contains(&client_ip)) {
        return next.run(req).await;
    }

    warn!(
        %client_ip,
        "provisioning request from disallowed source network"
    );
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": "source network not permitted"})),
    )
        .into_response()
}

async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    match state.phones.is_empty().await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "error": e.to_string()})),
        ),
    }
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "sbc-provision-server",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.start_time.elapsed().as_secs(),
    }))
}

async fn serve_teo_global() -> impl IntoResponse {
    // TEO spec p.19 — phones probe for a fleet-wide global file before
    // their per-MAC file. We don't ship a global; respond 404 with a
    // body distinct from the upstream proxy's "no such file" so phones
    // don't fall back to a cached config thinking the server's broken.
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(axum::body::Body::from(
            "No global Teo config served; per-MAC files only",
        ))
        .unwrap_or_default()
}

/// Query parameters for provisioning requests.
#[derive(Debug, serde::Deserialize)]
struct ProvisionQuery {
    /// HMAC-SHA-384 token (96 hex chars) for device authentication.
    #[serde(default)]
    token: Option<String>,
}

/// Request span without the query string (which carries `?token=`).
fn http_span<B>(req: &axum::http::Request<B>) -> tracing::Span {
    tracing::info_span!("http", method = %req.method(), path = %span_path(req.uri()))
}

/// The URI component recorded in request spans: path only, never query.
fn span_path(uri: &axum::http::Uri) -> &str {
    uri.path()
}

/// Serve a per-MAC phone provisioning config.
///
/// Logic is a faithful port of the daemon's old `serve_phone_config`
/// (`api_server.rs` in commits up to 0852812): extract MAC from filename,
/// normalize, look up phone by normalized MAC, render via vendor
/// generator, return with the right Content-Type per extension.
async fn serve_phone_config(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(query): Query<ProvisionQuery>,
) -> Response {
    // Filename forms across vendors:
    //   <mac>.cfg           Polycom VVX/Edge
    //   <mac>.xml           Cisco MPP/9800
    //   <mac>-edge.cfg      Polycom Edge variant
    //   <MAC>.xml           Teo (uppercase mandated by spec)
    let filename = path.rsplit('/').next().unwrap_or(&path);
    let stem = filename.split('.').next().unwrap_or(filename);
    let mac_token = stem.split('-').next().unwrap_or(stem);
    let mac_key = token::normalize_mac(mac_token);

    // Verify HMAC device token when a provision secret is configured.
    // POAM: POA&M-120 -- the token is a static HMAC(secret, mac) in the
    // query string: it never expires, cannot be revoked per device, and
    // reaches proxy access logs (it is kept out of this service's spans by
    // `http_span`). Planned v2: `v2.<key_id>.<device_epoch>.<hmac>` with a
    // per-phone `provision_epoch` for revocation, keyed rotation, and the
    // token carried in the generated resync URLs (IA-3, IA-5(1), AC-2(3)).
    if let Some(ref secret) = state.provision_secret {
        // NIST 800-53 Rev5: SC-13 — HMAC-SHA-384 (CNSA 2.0); legacy
        // HMAC-SHA-256 tokens are rejected (re-mint with --mint-token).
        let valid = query
            .token
            .as_deref()
            .is_some_and(|t| token::verify_device_token(secret, &mac_key, t));
        if !valid {
            warn!(mac = %mac_key, "provisioning request with invalid or missing device token");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("invalid device token"))
                .unwrap_or_default();
        }
    }

    let phone = match state.phones.get_by_mac(&mac_key).await {
        Ok(p) => p,
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from(format!(
                    "No phone record for MAC {mac_key}"
                )))
                .unwrap_or_default();
        }
        Err(e) => {
            warn!(mac = %mac_key, error = %e, "phone lookup failed");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("internal server error"))
                .unwrap_or_default();
        }
    };

    match state.provisioning.generate_config(&phone) {
        Ok(config_text) => {
            let ct = if filename.to_ascii_lowercase().ends_with(".xml") {
                "application/xml"
            } else {
                "text/plain"
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ct)
                .body(axum::body::Body::from(config_text))
                .unwrap_or_default()
        }
        Err(e) => {
            warn!(mac = %mac_key, error = %e, "config generation failed");
            Response::builder()
                .status(StatusCode::UNPROCESSABLE_ENTITY)
                .body(axum::body::Body::from("internal server error"))
                .unwrap_or_default()
        }
    }
}

/// Build the source-network restriction and log its effective posture.
fn source_restriction(cfg: &Config) -> SourceRestriction {
    // Source-network restriction (defense in depth behind the Cilium
    // NetworkPolicy). Health/version probes come from the node, not the
    // phone subnet, so they bypass the check.
    let restriction = SourceRestriction {
        allowed: Arc::new(cfg.allowed_cidrs.clone()),
        trusted_proxies: Arc::new(cfg.trusted_proxies.clone()),
    };
    if restriction.allowed.is_empty() {
        info!(
            "SBC_PROVISION_ALLOWED_CIDRS unset — app-layer source restriction disabled (NetworkPolicy only)"
        );
    } else {
        info!(cidrs = ?restriction.allowed, "provisioning restricted to source networks");
        if restriction.trusted_proxies.is_empty() {
            warn!(
                "SBC_TRUSTED_PROXIES unset — X-Real-IP is trusted unconditionally; a caller \
                 reaching this pod directly (bypassing nginx) can forge an allowed source IP and \
                 defeat the source-network check. Set it to the frontend nginx pod network."
            );
        } else {
            info!(trusted_proxies = ?restriction.trusted_proxies, "X-Real-IP trusted only from these networks");
        }
    }
    restriction
}

/// Output of `--mint-token`: the token, or an error message (never the
/// secret).
fn mint_token_output(secret: Option<String>, mac: Option<&str>) -> Result<String, String> {
    let mac = mac
        .map(token::normalize_mac)
        .filter(|m| m.len() == 12 && m.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| "usage: sbc-provision-server --mint-token <MAC>".to_string())?;
    let secret = config::parse_provision_secret(secret)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "SBC_PROVISION_SECRET is not set".to_string())?;
    Ok(token::mint_device_token(&secret, &mac))
}

/// `--mint-token <MAC>` CLI: reads `SBC_PROVISION_SECRET` from env, prints
/// the hex token for `?token=` and exits.
fn mint_token_cli(mac: Option<&str>) -> ExitCode {
    match mint_token_output(std::env::var("SBC_PROVISION_SECRET").ok(), mac) {
        Ok(t) => {
            println!("{t}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod span_tests {
    use super::*;

    #[test]
    fn span_path_drops_query_token() {
        let uri: axum::http::Uri = "/provision/aabbccddeeff.cfg?token=deadbeef"
            .parse()
            .unwrap();
        assert_eq!(span_path(&uri), "/provision/aabbccddeeff.cfg");
        let req = axum::http::Request::get(uri).body(()).unwrap();
        let _span = http_span(&req);
    }

    #[test]
    fn mint_token_cli_matches_verifier() {
        let secret = "5a".repeat(48);
        let t = mint_token_output(Some(secret.clone()), Some("AA:BB:CC:DD:EE:FF")).unwrap();
        let s = ProvisionSecret::new(secret.clone()).unwrap();
        assert!(token::verify_device_token(&s, "aabbccddeeff", &t));
        assert!(mint_token_output(Some(secret), Some("not-a-mac")).is_err());
        assert!(mint_token_output(None, Some("aabbccddeeff")).is_err());
        assert!(mint_token_output(Some("short".into()), Some("aabbccddeeff")).is_err());
    }

    #[test]
    fn mint_token_cli_rejects_bad_mac_and_secret_boundaries() {
        let secret = "5a".repeat(32);
        // Exactly the secret floor (32 decoded bytes) is accepted.
        assert!(mint_token_output(Some(secret.clone()), Some("aabbccddeeff")).is_ok());
        assert!(mint_token_output(Some("5a".repeat(31)), Some("aabbccddeeff")).is_err());
        // Non-hex secret of sufficient length is rejected.
        assert!(mint_token_output(Some("s".repeat(64)), Some("aabbccddeeff")).is_err());
        assert!(mint_token_output(Some(String::new()), Some("aabbccddeeff")).is_err());
        // MAC argument missing, wrong length, or non-hex.
        assert!(mint_token_output(Some(secret.clone()), None).is_err());
        assert!(mint_token_output(Some(secret.clone()), Some("")).is_err());
        assert!(mint_token_output(Some(secret.clone()), Some("aabbccddeef")).is_err());
        assert!(mint_token_output(Some(secret.clone()), Some("aabbccddeeff0")).is_err());
        assert!(mint_token_output(Some(secret), Some("gghhiijjkkll")).is_err());
        // Error text never echoes the secret.
        let err =
            mint_token_output(Some("hunter2hunter2".into()), Some("aabbccddeeff")).unwrap_err();
        assert!(!err.contains("hunter2"));
        let err = mint_token_output(Some("5a".repeat(20)), Some("aabbccddeeff")).unwrap_err();
        assert!(!err.contains("5a5a"));
    }
}
