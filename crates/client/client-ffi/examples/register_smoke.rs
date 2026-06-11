//! Headless registration smoke test against a real SIP provider, driven
//! entirely through the FFI surface (the same path the native shells use).
//!
//! Requires the `digest-auth` feature. Credentials come from the environment
//! so they never land in the repo:
//!
//! ```sh
//! SIP_USERNAME=user SIP_PASSWORD=pass \
//!     cargo run -p client-ffi --features digest-auth --example register_smoke
//! ```
//!
//! Optional: `SIP_URI`, `SIP_REGISTRAR`, `SIP_CALLER_ID` update the default
//! account before registering; `SIP_DIAL` places a test call after
//! registration succeeds.

use client_ffi::{AppEvent, ClientConfig, EventListener, RegistrationState, SipClient};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

struct Printer(mpsc::Sender<AppEvent>);

impl EventListener for Printer {
    fn on_event(&self, event: AppEvent) {
        println!("event: {event:?}");
        let _ = self.0.send(event);
    }
}

fn update_account(username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut settings = client_core::SettingsManager::new()?;
    let mut account = settings
        .default_account()
        .cloned()
        .ok_or("no default account in settings.toml — configure one first")?;

    if let Ok(uri) = std::env::var("SIP_URI") {
        account.sip_uri = uri;
    }
    if let Ok(registrar) = std::env::var("SIP_REGISTRAR") {
        account.registrar_uri = registrar;
    }
    if let Ok(caller_id) = std::env::var("SIP_CALLER_ID") {
        account.caller_id = Some(caller_id);
    }

    let mut creds = client_types::DigestAuthCredentials::new(username, password);
    creds.password_persisted = true;
    account.digest_credentials = Some(creds);

    let account_id = account.id.clone();
    settings.set_account(account);
    let stored = settings.store_digest_password(&account_id, password)?;
    println!("credentials updated for '{account_id}' (secure storage: {stored})");
    settings.save_if_dirty()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "client_core=info,client_sip_ua=info".into()),
        )
        .init();

    let username = std::env::var("SIP_USERNAME").map_err(|_| "SIP_USERNAME not set")?;
    let password = std::env::var("SIP_PASSWORD").map_err(|_| "SIP_PASSWORD not set")?;
    update_account(&username, &password)?;

    let (tx, rx) = mpsc::channel();
    let client = SipClient::new(ClientConfig {
        sip_listen_addr: "0.0.0.0:5060".into(),
        media_addr: "0.0.0.0:16384".into(),
        config_dir: None,
        data_dir: None,
        prefer_ipv6: false,
    })?;
    client.set_event_listener(Arc::new(Printer(tx)))?;
    client.initialize()?;
    println!("initialized; waiting for registration...");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut registered = false;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(AppEvent::RegistrationStateChanged { state, .. }) => match state {
                RegistrationState::Registered => {
                    registered = true;
                    break;
                }
                RegistrationState::Failed | RegistrationState::CertificateInvalid => {
                    eprintln!("REGISTRATION FAILED: {state:?}");
                    client.shutdown()?;
                    std::process::exit(1);
                }
                other => println!("registration: {other:?}"),
            },
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if !registered {
        eprintln!("TIMED OUT waiting for registration");
        client.shutdown()?;
        std::process::exit(1);
    }
    println!("REGISTERED OK");

    if let Ok(dial) = std::env::var("SIP_DIAL") {
        println!("dialing {dial}...");
        let call_id = client.make_call(dial)?;
        println!("call started: {call_id}");
        // Watch the call for up to 20 seconds, then hang up.
        let call_deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < call_deadline {
            if let Ok(AppEvent::CallStateChanged { state, .. }) =
                rx.recv_timeout(Duration::from_millis(500))
            {
                println!("call: {state:?}");
            }
        }
        let _ = client.hangup();
    }

    client.shutdown()?;
    println!("done");
    Ok(())
}
