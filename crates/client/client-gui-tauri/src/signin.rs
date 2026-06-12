//! OIDC sign-in / auto-provisioning commands and session management.
//!
//! Implements the desktop half of docs/CLIENT-PROVISIONING-OIDC.md on top of
//! `client-provisioning`: the user enters one value (the service domain), the
//! flow discovers the POP, authenticates in the **system browser**
//! (Authorization Code + PKCE via a loopback redirect, RFC 8252), fetches the
//! per-user SIP config, maps it onto the default [`SipAccount`], and
//! registers. The refresh token is persisted in the OS keychain for silent
//! resume; the access token is refreshed at ~half-life by a background task.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use client_core::{ClientApp, ProvisioningSettings, SettingsManager};
use client_provisioning::{
    generate_pkce, id_token_nonce, random_token, start_loopback, verify_issuer_pinned, CaTrust,
    ClientConfig, DiscoveryDoc, OidcMetadata, ProvisionedSession, ProvisioningClient, SessionState,
    TokenResponse,
};
use client_types::TransportPreference;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_shell::ShellExt;
use tokio::sync::{oneshot, Mutex, RwLock};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::TauriAppState;

/// How long we wait for the browser redirect before giving up.
const SIGNIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Refresh-loop tick interval.
const REFRESH_TICK: Duration = Duration::from_secs(30);

/// Session state snapshot for the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct SessionStateDto {
    /// Lifecycle state (`needs_domain` … `registered` / `error`).
    pub state: String,
    /// Service domain (current or persisted).
    pub service_domain: String,
    /// Display name from the provisioned config, when available.
    pub display_name: Option<String>,
    /// Last error message, when `state == "error"`.
    pub error: Option<String>,
    /// Whether a persisted session exists for silent resume.
    pub can_silent_resume: bool,
}

/// Arc-cloned slices of [`TauriAppState`] the spawned flows need.
#[derive(Clone)]
struct SigninCtx {
    settings_manager: Arc<RwLock<SettingsManager>>,
    client: Arc<Mutex<Option<ClientApp>>>,
    session: Arc<RwLock<ProvisionedSession>>,
}

impl SigninCtx {
    fn from_state(state: &State<'_, TauriAppState>) -> Self {
        Self {
            settings_manager: state.settings_manager.clone(),
            client: state.client.clone(),
            session: state.session.clone(),
        }
    }
}

const fn state_str(state: SessionState) -> &'static str {
    match state {
        SessionState::NeedsDomain => "needs_domain",
        SessionState::Discovering => "discovering",
        SessionState::Authenticating => "authenticating",
        SessionState::Provisioning => "provisioning",
        SessionState::Registered => "registered",
        SessionState::Refreshing => "refreshing",
        SessionState::Error => "error",
    }
}

/// Emits an event via the Tauri event API plus the `__tauriEventFallback`
/// eval path (mirrors `poll_events` — listener registration can race app
/// startup).
fn emit_event(app: &AppHandle, name: &str, payload: serde_json::Value) {
    let payload_str = payload.to_string();
    if let Err(e) = app.emit(name, payload) {
        warn!("Failed to emit event {name}: {e}");
    }
    if let Some(window) = app.webview_windows().values().next() {
        let js = format!(
            "if (window.__tauriEventFallback) {{ window.__tauriEventFallback('{name}', {payload_str}); }}"
        );
        if let Err(e) = window.eval(&js) {
            warn!("Failed to eval event {name}: {e}");
        }
    }
}

fn emit_progress(app: &AppHandle, step: &str, message: &str) {
    emit_event(
        app,
        "signin-progress",
        serde_json::json!({ "step": step, "message": message }),
    );
}

async fn emit_session_changed(app: &AppHandle, ctx: &SigninCtx) {
    let payload = {
        let s = ctx.session.read().await;
        serde_json::json!({
            "state": state_str(s.state),
            "service_domain": s.service_domain,
            "display_name": s.config.as_ref()
                .and_then(|c| c.user.as_ref())
                .map(|u| u.display_name.clone()),
            "error": s.error,
        })
    };
    emit_event(app, "session-state-changed", payload);
}

async fn set_session_state(app: &AppHandle, ctx: &SigninCtx, state: SessionState) {
    {
        let mut s = ctx.session.write().await;
        s.state = state;
        if state != SessionState::Error {
            s.error = None;
        }
    }
    emit_session_changed(app, ctx).await;
}

async fn set_session_error(app: &AppHandle, ctx: &SigninCtx, message: String) {
    warn!(error = %message, "sign-in flow failed");
    {
        let mut s = ctx.session.write().await;
        s.state = SessionState::Error;
        s.error = Some(message);
    }
    emit_session_changed(app, ctx).await;
}

/// CA trust for provisioning HTTP, from the persisted extra-CA path.
async fn ca_trust(ctx: &SigninCtx) -> CaTrust {
    let sm = ctx.settings_manager.read().await;
    sm.settings()
        .provisioning
        .as_ref()
        .and_then(|p| p.extra_ca_cert_file.clone())
        .filter(|p| !p.trim().is_empty())
        .map_or(CaTrust::System, |p| CaTrust::ExtraPem(p.into()))
}

/// Cancels a pending browser sign-in, if any.
async fn cancel_inflight(cancel: &Arc<Mutex<Option<oneshot::Sender<()>>>>) {
    if let Some(tx) = cancel.lock().await.take() {
        let _ = tx.send(());
    }
}

// ---------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------

/// Returns the current sign-in session state (drives the frontend gate).
#[tauri::command]
pub async fn get_session_state(state: State<'_, TauriAppState>) -> Result<SessionStateDto, String> {
    let session = state.session.read().await;
    let sm = state.settings_manager.read().await;
    let persisted = sm.settings().provisioning.clone();
    let can_silent_resume = persisted
        .as_ref()
        .is_some_and(|p| p.refresh_token_persisted && !p.service_domain.is_empty());
    let service_domain = if session.service_domain.is_empty() {
        persisted.map(|p| p.service_domain).unwrap_or_default()
    } else {
        session.service_domain.clone()
    };
    Ok(SessionStateDto {
        state: state_str(session.state).to_string(),
        service_domain,
        display_name: session
            .config
            .as_ref()
            .and_then(|c| c.user.as_ref())
            .map(|u| u.display_name.clone()),
        error: session.error.clone(),
        can_silent_resume,
    })
}

/// Starts the browser sign-in flow for `domain`. Progress is reported via
/// `signin-progress` / `session-state-changed` events; the command returns
/// as soon as the flow is spawned.
#[tauri::command]
pub async fn start_signin(
    domain: String,
    extra_ca_path: Option<String>,
    app: AppHandle,
    state: State<'_, TauriAppState>,
) -> Result<(), String> {
    let domain = domain.trim().to_string();
    if domain.is_empty() {
        return Err("Enter the service domain (e.g. sbc.oopl.dev.mil)".to_string());
    }

    // Persist the domain + optional extra CA up front so the HTTP client
    // builder and a later silent resume can find them.
    {
        let mut sm = state.settings_manager.write().await;
        let prev_ca = sm
            .settings()
            .provisioning
            .as_ref()
            .and_then(|p| p.extra_ca_cert_file.clone());
        sm.settings_mut().provisioning = Some(ProvisioningSettings {
            service_domain: domain.clone(),
            refresh_token_persisted: false,
            extra_ca_cert_file: extra_ca_path.filter(|p| !p.trim().is_empty()).or(prev_ca),
        });
        if let Err(e) = sm.save() {
            warn!(error = %e, "failed to persist provisioning settings");
        }
    }

    cancel_inflight(&state.signin_cancel).await;
    let (cancel_tx, cancel_rx) = oneshot::channel();
    *state.signin_cancel.lock().await = Some(cancel_tx);

    let ctx = SigninCtx::from_state(&state);
    tauri::async_runtime::spawn(async move {
        if let Err(message) = run_signin_flow(&app, &ctx, &domain, cancel_rx).await {
            if message == "cancelled" {
                {
                    let mut s = ctx.session.write().await;
                    *s = ProvisionedSession::default();
                }
                emit_session_changed(&app, &ctx).await;
            } else {
                set_session_error(&app, &ctx, message).await;
            }
        }
    });
    Ok(())
}

/// Cancels an in-flight browser sign-in and returns to the domain prompt.
#[tauri::command]
pub async fn cancel_signin(app: AppHandle, state: State<'_, TauriAppState>) -> Result<(), String> {
    cancel_inflight(&state.signin_cancel).await;
    let ctx = SigninCtx::from_state(&state);
    {
        let mut s = ctx.session.write().await;
        *s = ProvisionedSession::default();
    }
    emit_session_changed(&app, &ctx).await;
    Ok(())
}

/// Signs out: best-effort token revocation + unregister, wipes the keychain
/// refresh token and the persisted session, and returns to the domain prompt.
#[tauri::command]
pub async fn sign_out(app: AppHandle, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Signing out of OIDC session");
    cancel_inflight(&state.signin_cancel).await;
    let ctx = SigninCtx::from_state(&state);

    // Best-effort revocation at the IdP (design doc: logout revokes the
    // refresh token), using the cached metadata + in-memory refresh token.
    let revoke = {
        let s = ctx.session.read().await;
        match (&s.oidc_meta, &s.discovery, &s.refresh_token) {
            (Some(meta), Some(disc), Some(rt)) => Some((
                meta.clone(),
                disc.oidc.client_id.clone(),
                rt.as_str().to_string(),
            )),
            _ => None,
        }
    };
    if let Some((meta, client_id, refresh)) = revoke {
        let trust = ca_trust(&ctx).await;
        if let Ok(pc) = ProvisioningClient::new(&trust) {
            if let Err(e) = pc.revoke_refresh_token(&meta, &client_id, &refresh).await {
                warn!(error = %e, "refresh-token revocation failed (continuing sign-out)");
            }
        }
    }

    // Best-effort unregister.
    {
        let mut guard = ctx.client.lock().await;
        if let Some(client) = guard.as_mut() {
            if let Err(e) = client.unregister().await {
                warn!(error = %e, "unregister during sign-out failed");
            }
        }
    }

    // Wipe keychain + persisted session.
    {
        let mut sm = ctx.settings_manager.write().await;
        let domain = sm
            .settings()
            .provisioning
            .as_ref()
            .map(|p| p.service_domain.clone())
            .unwrap_or_default();
        if !domain.is_empty() {
            if let Err(e) = sm.delete_refresh_token(&domain) {
                warn!(error = %e, "failed to delete refresh token from keychain");
            }
        }
        sm.settings_mut().provisioning = None;
        if let Err(e) = sm.save() {
            warn!(error = %e, "failed to persist sign-out");
        }
    }

    {
        let mut s = ctx.session.write().await;
        *s = ProvisionedSession::default();
    }
    emit_session_changed(&app, &ctx).await;
    Ok(())
}

/// Attempts a silent resume from the persisted session (refresh token in the
/// keychain). Returns `true` when the session is restored — no browser.
#[tauri::command]
pub async fn try_silent_resume(
    app: AppHandle,
    state: State<'_, TauriAppState>,
) -> Result<bool, String> {
    let ctx = SigninCtx::from_state(&state);
    let (domain, refresh) = {
        let mut sm = state.settings_manager.write().await;
        let Some(p) = sm.settings().provisioning.clone() else {
            return Ok(false);
        };
        if p.service_domain.is_empty() || !p.refresh_token_persisted {
            return Ok(false);
        }
        let refresh = sm.get_refresh_token(&p.service_domain).ok().flatten();
        (p.service_domain, refresh)
    };
    let Some(refresh) = refresh else {
        return Ok(false);
    };

    set_session_state(&app, &ctx, SessionState::Refreshing).await;
    match silent_refresh(&app, &ctx, &domain, &refresh).await {
        Ok(()) => Ok(true),
        Err(e) => {
            info!(error = %e, "silent resume failed; falling back to sign-in");
            {
                let mut s = ctx.session.write().await;
                *s = ProvisionedSession::default();
            }
            emit_session_changed(&app, &ctx).await;
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------
// Flow internals
// ---------------------------------------------------------------------

/// The full first-run browser sign-in flow.
async fn run_signin_flow(
    app: &AppHandle,
    ctx: &SigninCtx,
    domain: &str,
    mut cancel_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    // 1. Discovery + issuer pinning (the trust bootstrap — before any browser).
    set_session_state(app, ctx, SessionState::Discovering).await;
    {
        let mut s = ctx.session.write().await;
        s.service_domain = domain.to_string();
    }
    emit_progress(app, "discovering", "Contacting service…");
    let trust = ca_trust(ctx).await;
    let pc = ProvisioningClient::new(&trust).map_err(|e| e.to_string())?;
    let discovery = pc
        .fetch_discovery(domain)
        .await
        .map_err(|e| e.to_string())?;
    verify_issuer_pinned(domain, &discovery.oidc.issuer).map_err(|e| e.to_string())?;
    let meta = pc
        .fetch_oidc_metadata(&discovery.oidc.issuer)
        .await
        .map_err(|e| e.to_string())?;

    // 2. PKCE + state/nonce + loopback redirect.
    let pkce = generate_pkce().ok_or("secure RNG unavailable")?;
    let oauth_state = random_token(16).ok_or("secure RNG unavailable")?;
    let nonce = random_token(16).ok_or("secure RNG unavailable")?;
    let loopback = start_loopback().await.map_err(|e| e.to_string())?;
    let redirect_uri = loopback.redirect_uri.clone();
    let auth_url = ProvisioningClient::build_authorization_url(
        &meta,
        &discovery.oidc,
        &redirect_uri,
        &pkce.challenge,
        &oauth_state,
        &nonce,
    );

    // 3. System browser (RFC 8252 — never an embedded webview).
    set_session_state(app, ctx, SessionState::Authenticating).await;
    emit_progress(app, "opening-browser", "Opening your browser to sign in…");
    // tauri-plugin-shell's open is deprecated in favor of tauri-plugin-opener,
    // but shell is the plugin this app already registers; migrate alongside
    // the rest of the app's plugin usage.
    #[allow(deprecated)]
    app.shell()
        .open(&auth_url, None)
        .map_err(|e| format!("failed to open the system browser: {e}"))?;
    emit_progress(app, "waiting", "Complete sign-in in your browser…");

    // 4. Await the redirect (cancellable).
    let callback = tokio::select! {
        cb = loopback.wait_for_code(SIGNIN_TIMEOUT) => cb.map_err(|e| e.to_string())?,
        _ = &mut cancel_rx => return Err("cancelled".to_string()),
    };
    if let Some(err) = callback.error {
        return Err(format!("sign-in was not completed: {err}"));
    }
    let code = callback.code.ok_or("no authorization code returned")?;
    if callback.state.as_deref() != Some(oauth_state.as_str()) {
        return Err("OAuth state mismatch — possible interception; aborting".to_string());
    }

    // 5. Code → tokens; bind via the id_token nonce.
    emit_progress(app, "exchanging", "Completing sign-in…");
    let tokens = pc
        .exchange_code(
            &meta,
            &discovery.oidc.client_id,
            &redirect_uri,
            &code,
            &pkce.verifier,
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(id_token) = tokens.id_token.as_deref() {
        if id_token_nonce(id_token).as_deref() != Some(nonce.as_str()) {
            return Err("ID token nonce mismatch — aborting".to_string());
        }
    }

    // 6. Tokens → per-user SIP config → account + register.
    set_session_state(app, ctx, SessionState::Provisioning).await;
    emit_progress(app, "provisioning", "Fetching your phone configuration…");
    let cfg = pc
        .fetch_client_config(
            &discovery.provisioning.config_endpoint,
            &tokens.access_token,
        )
        .await
        .map_err(|e| e.to_string())?;

    finish_provisioning(app, ctx, domain, discovery, meta, tokens, cfg).await
}

/// Silent token refresh + config re-fetch (no browser). Used by silent
/// resume, the half-life refresh loop, and `token-refresh-required`.
async fn silent_refresh(
    app: &AppHandle,
    ctx: &SigninCtx,
    domain: &str,
    refresh_token: &str,
) -> Result<(), String> {
    let trust = ca_trust(ctx).await;
    let pc = ProvisioningClient::new(&trust).map_err(|e| e.to_string())?;
    let discovery = pc
        .fetch_discovery(domain)
        .await
        .map_err(|e| e.to_string())?;
    verify_issuer_pinned(domain, &discovery.oidc.issuer).map_err(|e| e.to_string())?;
    let meta = pc
        .fetch_oidc_metadata(&discovery.oidc.issuer)
        .await
        .map_err(|e| e.to_string())?;
    let tokens = pc
        .refresh_token(&meta, &discovery.oidc.client_id, refresh_token)
        .await
        .map_err(|e| e.to_string())?;
    let cfg = pc
        .fetch_client_config(
            &discovery.provisioning.config_endpoint,
            &tokens.access_token,
        )
        .await
        .map_err(|e| e.to_string())?;
    finish_provisioning(app, ctx, domain, discovery, meta, tokens, cfg).await
}

/// Maps the provisioned config onto the default account, persists everything
/// (settings + keychain), updates the session, and (re-)registers.
async fn finish_provisioning(
    app: &AppHandle,
    ctx: &SigninCtx,
    domain: &str,
    discovery: DiscoveryDoc,
    meta: OidcMetadata,
    tokens: TokenResponse,
    cfg: ClientConfig,
) -> Result<(), String> {
    let account = client_provisioning::mapping::to_sip_account(
        &cfg,
        &tokens.access_token,
        TransportPreference::TlsOnly,
    );

    // Persist: account, default-account pointer, refresh token (keychain),
    // and the non-secret session slice.
    {
        let mut sm = ctx.settings_manager.write().await;
        sm.set_account(account.clone());
        sm.set_default_account(Some(account.id.clone()));
        let mut persisted_flag = sm
            .settings()
            .provisioning
            .as_ref()
            .is_some_and(|p| p.refresh_token_persisted);
        if let Some(rt) = tokens.refresh_token.as_deref() {
            // Keycloak rotates refresh tokens — always store the newest.
            match sm.store_refresh_token(domain, rt) {
                Ok(stored) => persisted_flag = stored,
                Err(e) => warn!(error = %e, "failed to store refresh token"),
            }
        }
        let extra_ca = sm
            .settings()
            .provisioning
            .as_ref()
            .and_then(|p| p.extra_ca_cert_file.clone());
        sm.settings_mut().provisioning = Some(ProvisioningSettings {
            service_domain: domain.to_string(),
            refresh_token_persisted: persisted_flag,
            extra_ca_cert_file: extra_ca,
        });
        sm.save()
            .map_err(|e| format!("failed to save settings: {e}"))?;
    }

    // Update the in-memory session.
    {
        let mut s = ctx.session.write().await;
        s.state = SessionState::Registered;
        s.service_domain = domain.to_string();
        s.discovery = Some(discovery);
        s.oidc_meta = Some(meta);
        s.access_token = Some(Zeroizing::new(tokens.access_token.clone()));
        if let Some(rt) = tokens.refresh_token.clone() {
            s.refresh_token = Some(Zeroizing::new(rt));
        }
        s.access_lifetime_secs = tokens.expires_in;
        s.access_expires_at = tokens
            .expires_in
            .and_then(|secs| i64::try_from(secs).ok())
            .map(|secs| Utc::now() + chrono::Duration::seconds(secs));
        s.config = Some(cfg);
        s.config_fetched_at = Some(Utc::now());
        s.error = None;
    }

    // Register with the fresh bearer token (best effort — the client may not
    // be initialized yet on first run; the frontend registers after init).
    {
        let extra_ca = {
            let sm = ctx.settings_manager.read().await;
            sm.settings()
                .provisioning
                .as_ref()
                .and_then(|p| p.extra_ca_cert_file.clone())
                .filter(|p| !p.trim().is_empty())
        };
        let mut guard = ctx.client.lock().await;
        if let Some(client) = guard.as_mut() {
            // The extra CA may have been entered with this sign-in, after
            // the client initialized — trust it for SIP TLS before
            // registering over TLS.
            if let Some(path) = extra_ca {
                if let Err(e) = client
                    .set_trusted_ca_certs_from_pem_file(std::path::Path::new(&path))
                    .await
                {
                    warn!(path = %path, error = %e, "failed to load extra CA for SIP TLS");
                }
            }
            if let Err(e) = client.register_account(&account).await {
                warn!(error = %e, "registration after provisioning failed");
            }
        } else {
            info!("client not yet initialized; registration deferred to frontend");
        }
    }

    emit_session_changed(app, ctx).await;
    info!(domain = %domain, dn = ?account.caller_id, "provisioning complete");
    Ok(())
}

// ---------------------------------------------------------------------
// Background refresh
// ---------------------------------------------------------------------

/// Half-life token refresh + config-TTL re-fetch loop. Spawned once at app
/// setup; on refresh failure the session drops to `Authenticating` and the
/// frontend re-shows the sign-in gate (active calls are not torn down).
pub async fn refresh_loop(app: AppHandle) {
    loop {
        tokio::time::sleep(REFRESH_TICK).await;
        let state = app.state::<TauriAppState>();
        let ctx = SigninCtx {
            settings_manager: state.settings_manager.clone(),
            client: state.client.clone(),
            session: state.session.clone(),
        };

        let (due, domain, refresh) = {
            let s = ctx.session.read().await;
            let now = Utc::now();
            let due = s.state == SessionState::Registered
                && (s.needs_refresh(now, s.refresh_skew_secs()) || s.config_expired(now));
            (
                due,
                s.service_domain.clone(),
                s.refresh_token.as_ref().map(|t| t.as_str().to_string()),
            )
        };
        if !due || domain.is_empty() {
            continue;
        }

        // In-memory token first; keychain as fallback.
        let refresh = if refresh.is_some() {
            refresh
        } else {
            let mut sm = ctx.settings_manager.write().await;
            sm.get_refresh_token(&domain)
                .ok()
                .flatten()
                .map(|t| t.as_str().to_string())
        };
        let Some(refresh) = refresh else {
            continue;
        };

        {
            let mut s = ctx.session.write().await;
            s.state = SessionState::Refreshing;
        }
        if let Err(e) = silent_refresh(&app, &ctx, &domain, &refresh).await {
            warn!(error = %e, "token refresh failed; re-authentication required");
            {
                let mut s = ctx.session.write().await;
                s.state = SessionState::Authenticating;
                s.error = Some("Your session expired — please sign in again.".to_string());
                s.access_token = None;
                s.refresh_token = None;
            }
            emit_session_changed(&app, &ctx).await;
        }
    }
}
