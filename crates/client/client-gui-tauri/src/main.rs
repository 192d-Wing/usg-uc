//! USG SIP Soft Client - Modern Tauri GUI Application.
//!
//! A CNSA 2.0 compliant SIP soft client for enterprise/government use.
//! Authentication is via smart card (CAC/PIV/SIPR token) only.
//!
//! This crate uses Tauri to provide a modern web-based desktop UI.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use client_audio::DeviceManager;
use client_core::{
    AppEvent, AppState as CoreAppState, CertificateStore, ClientApp, ContactManager,
    SettingsManager, run_udp_receive_loop,
};
use client_types::{CallHistoryEntry, CertificateInfo, Contact, SipAccount, SmartCardPin};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{error, info, warn};

/// Application state holding the SIP client core.
struct TauriAppState {
    /// SIP client core application.
    client: Arc<Mutex<Option<ClientApp>>>,
    /// Audio device manager for device enumeration.
    device_manager: Arc<RwLock<DeviceManager>>,
    /// Settings manager for persistence.
    settings_manager: Arc<RwLock<SettingsManager>>,
    /// Contact manager for persistence.
    contact_manager: Arc<RwLock<ContactManager>>,
    /// Certificate store for smart card access.
    cert_store: Arc<RwLock<CertificateStore>>,
    /// Selected certificate thumbprint.
    selected_cert_thumbprint: Arc<RwLock<Option<String>>>,
    /// Event receiver for app events.
    event_rx: Arc<Mutex<Option<mpsc::Receiver<AppEvent>>>>,
}

/// Audio device information for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioDeviceInfo {
    /// Device name (identifier).
    pub name: String,
    /// Display name for UI.
    pub display_name: String,
    /// Whether this is the default device.
    pub is_default: bool,
    /// Device type: "input" or "output".
    pub device_type: String,
}

/// SIP registration settings for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipSettings {
    /// Display name.
    pub display_name: String,
    /// SIP username/AOR.
    pub username: String,
    /// SIP domain.
    pub domain: String,
    /// Registrar/proxy address.
    pub registrar: String,
    /// SIP port.
    pub port: u16,
    /// Transport protocol: "udp", "tcp", or "tls".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Whether auto-registration is enabled.
    pub auto_register: bool,
    /// Caller ID / DN (Directory Number) for outgoing calls.
    /// Used in the From header as the calling party number.
    #[serde(default)]
    pub caller_id: Option<String>,
    /// Authentication username (for digest auth testing).
    #[serde(default)]
    pub auth_username: Option<String>,
    /// Authentication password (for digest auth testing).
    #[serde(default)]
    pub auth_password: Option<String>,
}

fn default_transport() -> String {
    "tls".to_string()
}

/// Classification configuration for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationConfig {
    /// Classification level.
    pub level: String,
    /// SCI caveats (e.g., SI, TK, G, HCS).
    pub caveats: Vec<String>,
    /// Dissemination controls (e.g., NOFORN, RELTO).
    pub dissem: Vec<String>,
}

/// Registration state for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStatus {
    /// Current state: "unregistered", "registering", "registered", "failed".
    pub state: String,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Call state for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStatus {
    /// Call ID.
    pub call_id: Option<String>,
    /// Current state: "idle", "dialing", "ringing", "connected", "on_hold", "terminated".
    pub state: String,
    /// Remote party URI.
    pub remote_uri: Option<String>,
    /// Remote party display name.
    pub remote_display_name: Option<String>,
    /// Call duration in seconds (if connected).
    pub duration_secs: Option<u64>,
    /// Whether muted.
    pub is_muted: bool,
    /// Whether on hold.
    pub is_on_hold: bool,
}

/// Check if digest authentication feature is enabled.
///
/// This allows the UI to conditionally show username/password fields
/// for testing with commercial VoIP providers like BulkVS.
#[tauri::command]
fn is_digest_auth_enabled() -> bool {
    cfg!(feature = "digest-auth")
}

/// Initialize the SIP client core.
#[tauri::command]
async fn initialize_client(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Initializing SIP client core");

    let mut client_guard = state.client.lock().await;
    if client_guard.is_some() {
        return Ok(()); // Already initialized
    }

    // Create event channel for GUI updates
    let (event_tx, event_rx) = mpsc::channel(64);

    // Use default addresses - these will be configured by the transport layer
    let local_sip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let local_media_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    // Create the client application
    let mut client = ClientApp::new(local_sip_addr, local_media_addr, event_tx)
        .map_err(|e| format!("Failed to create client: {e}"))?;

    // Get UDP socket and event sender for the receive loop BEFORE initialize
    // This ensures the receive loop is running before any registration sends
    if let Some((udp_socket, transport_event_tx)) = client.get_udp_socket_for_receive().await {
        info!("Spawning UDP receive loop using Tauri async runtime");
        tauri::async_runtime::spawn(async move {
            run_udp_receive_loop(udp_socket, transport_event_tx).await;
        });
        // Give the receive loop a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    } else {
        warn!("Could not get UDP socket for receive loop");
    }

    // Initialize the client (this triggers auto-registration)
    client
        .initialize()
        .await
        .map_err(|e| format!("Failed to initialize client: {e}"))?;
    info!("Client initialized successfully, storing in state");

    *client_guard = Some(client);
    drop(client_guard);

    // Store the event receiver for polling
    let mut rx_guard = state.event_rx.lock().await;
    *rx_guard = Some(event_rx);
    drop(rx_guard);

    // Spawn background task to poll for SIP events
    info!("About to spawn SIP event polling loop");
    let client_arc = state.client.clone();
    tauri::async_runtime::spawn(async move {
        info!("Starting SIP event polling loop");
        loop {
            // Use try_lock to avoid blocking other commands (like end_call)
            // If the lock is held by a command, we'll just skip this poll cycle
            match client_arc.try_lock() {
                Ok(mut guard) => {
                    if let Some(ref mut client) = *guard {
                        // Use tokio::select with a timeout to ensure we don't hold
                        // the lock for too long, allowing other commands to proceed
                        let poll_result = tokio::time::timeout(
                            tokio::time::Duration::from_millis(20),
                            client.poll_events()
                        ).await;

                        match poll_result {
                            Ok(Ok(())) => {} // Success
                            Ok(Err(e)) => error!(error = %e, "Error polling SIP events"),
                            Err(_) => {} // Timeout - this is fine, we'll poll again
                        }
                    }
                    // Explicitly drop the guard to release the lock quickly
                    drop(guard);
                }
                Err(_) => {
                    // Lock is held by another task (e.g., end_call command)
                    // This is expected and fine - we'll poll on next iteration
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        }
    });

    info!("SIP client core initialized");
    Ok(())
}

/// Make a SIP call.
#[tauri::command]
async fn make_call(target: String, state: State<'_, TauriAppState>) -> Result<String, String> {
    info!("Making call to: {}", target);

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    let call_id = client
        .make_call(&target)
        .await
        .map_err(|e| format!("Failed to make call: {e}"))?;

    // Poll events immediately to send the INVITE request
    // (call_agent.make_call() queues the SendRequest event which needs to be processed)
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after make_call");
    }

    Ok(call_id)
}

/// End the current call.
#[tauri::command]
async fn end_call(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("end_call command invoked, acquiring client lock...");

    // Use timeout to avoid indefinite blocking
    let mut client_guard = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        state.client.lock()
    )
    .await
    .map_err(|_| {
        error!("end_call: Timeout acquiring client lock");
        "Timeout acquiring client lock".to_string()
    })?;
    info!("end_call: client lock acquired");
    let client = client_guard
        .as_mut()
        .ok_or_else(|| {
            error!("end_call: Client not initialized");
            "Client not initialized".to_string()
        })?;

    info!("end_call: calling client.hangup()");
    match client.hangup().await {
        Ok(()) => {
            info!("end_call: hangup() succeeded");
        }
        Err(e) => {
            error!(error = %e, "end_call: hangup() failed");
            return Err(format!("Failed to end call: {e}"));
        }
    }

    // Poll events to send BYE/CANCEL request
    info!("end_call: polling events to send BYE/CANCEL");
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after end_call");
    }

    info!("end_call: completed successfully");
    Ok(())
}

/// Accept an incoming call.
#[tauri::command]
async fn accept_call(call_id: String, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Accepting call: {}", call_id);

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    client
        .accept_incoming_call(&call_id)
        .await
        .map_err(|e| format!("Failed to accept call: {e}"))?;

    // Poll events to send 200 OK response
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after accept_call");
    }

    Ok(())
}

/// Reject an incoming call.
#[tauri::command]
async fn reject_call(call_id: String, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Rejecting call: {}", call_id);

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    client
        .reject_incoming_call(&call_id)
        .await
        .map_err(|e| format!("Failed to reject call: {e}"))?;

    // Poll events to send 486/603 response
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after reject_call");
    }

    Ok(())
}

/// Mute/unmute the microphone.
#[tauri::command]
async fn toggle_mute(state: State<'_, TauriAppState>) -> Result<bool, String> {
    info!("Toggling mute");

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    let is_muted = client.toggle_mute();
    Ok(is_muted)
}

/// Hold/unhold the call.
#[tauri::command]
async fn toggle_hold(state: State<'_, TauriAppState>) -> Result<bool, String> {
    info!("Toggling hold");

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    let is_on_hold = client
        .toggle_hold()
        .await
        .map_err(|e| format!("Failed to toggle hold: {e}"))?;

    // Poll events to send re-INVITE request
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after toggle_hold");
    }

    Ok(is_on_hold)
}

/// Transfer the current call.
#[tauri::command]
async fn transfer_call(target: String, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Transferring call to: {}", target);

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    client
        .transfer_call(&target)
        .await
        .map_err(|e| format!("Failed to transfer call: {e}"))?;

    // Poll events to send REFER request
    if let Err(e) = client.poll_events().await {
        warn!(error = %e, "Error polling events after transfer_call");
    }

    Ok(())
}

/// Send a DTMF digit.
#[tauri::command]
async fn send_dtmf(digit: String, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Sending DTMF: {}", digit);

    let dtmf_digit = match digit.chars().next() {
        Some('0') => client_types::DtmfDigit::Zero,
        Some('1') => client_types::DtmfDigit::One,
        Some('2') => client_types::DtmfDigit::Two,
        Some('3') => client_types::DtmfDigit::Three,
        Some('4') => client_types::DtmfDigit::Four,
        Some('5') => client_types::DtmfDigit::Five,
        Some('6') => client_types::DtmfDigit::Six,
        Some('7') => client_types::DtmfDigit::Seven,
        Some('8') => client_types::DtmfDigit::Eight,
        Some('9') => client_types::DtmfDigit::Nine,
        Some('*') => client_types::DtmfDigit::Star,
        Some('#') => client_types::DtmfDigit::Pound,
        Some('A') | Some('a') => client_types::DtmfDigit::A,
        Some('B') | Some('b') => client_types::DtmfDigit::B,
        Some('C') | Some('c') => client_types::DtmfDigit::C,
        Some('D') | Some('d') => client_types::DtmfDigit::D,
        _ => return Err(format!("Invalid DTMF digit: {digit}")),
    };

    let client_guard = state.client.lock().await;
    let client = client_guard
        .as_ref()
        .ok_or_else(|| "Client not initialized".to_string())?;

    client
        .send_dtmf(dtmf_digit)
        .await
        .map_err(|e| format!("Failed to send DTMF: {e}"))?;

    Ok(())
}

/// Get list of contacts.
#[tauri::command]
async fn get_contacts(state: State<'_, TauriAppState>) -> Result<Vec<Contact>, String> {
    info!("Fetching contacts");

    let manager = state.contact_manager.read().await;
    let contacts: Vec<Contact> = manager.contacts_sorted().into_iter().cloned().collect();

    Ok(contacts)
}

/// Add a new contact.
#[tauri::command]
async fn add_contact(contact: Contact, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Adding contact: {:?}", contact.name);

    let mut manager = state.contact_manager.write().await;
    manager.set_contact(contact);
    manager
        .save_if_dirty()
        .map_err(|e| format!("Failed to save contact: {e}"))?;

    Ok(())
}

/// Update an existing contact.
#[tauri::command]
async fn update_contact(contact: Contact, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Updating contact: {:?}", contact.name);

    let mut manager = state.contact_manager.write().await;
    manager.set_contact(contact);
    manager
        .save_if_dirty()
        .map_err(|e| format!("Failed to save contact: {e}"))?;

    Ok(())
}

/// Delete a contact.
#[tauri::command]
async fn delete_contact(id: String, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Deleting contact: {}", id);

    let mut manager = state.contact_manager.write().await;
    manager.remove_contact(&id);
    manager
        .save_if_dirty()
        .map_err(|e| format!("Failed to save contact: {e}"))?;

    Ok(())
}

/// Search contacts.
#[tauri::command]
async fn search_contacts(query: String, state: State<'_, TauriAppState>) -> Result<Vec<Contact>, String> {
    info!("Searching contacts: {}", query);

    let manager = state.contact_manager.read().await;
    let contacts: Vec<Contact> = manager.search_contacts(&query).into_iter().cloned().collect();

    Ok(contacts)
}

/// Get call history.
#[tauri::command]
async fn get_call_history(state: State<'_, TauriAppState>) -> Result<Vec<CallHistoryEntry>, String> {
    info!("Fetching call history");

    let manager = state.contact_manager.read().await;
    let history: Vec<CallHistoryEntry> = manager.call_history().into_iter().cloned().collect();

    Ok(history)
}

/// Get SIP registration settings.
#[tauri::command]
async fn get_sip_settings(state: State<'_, TauriAppState>) -> Result<SipSettings, String> {
    info!("Fetching SIP settings");

    let manager = state.settings_manager.read().await;
    let account = manager.default_account();

    match account {
        Some(acc) => {
            // Extract username from sip_uri (e.g., "sips:user@domain.com" -> "user")
            let username = acc.user().unwrap_or_default().to_string();
            // Extract domain from sip_uri
            let domain = acc.domain().unwrap_or_default().to_string();

            // Extract digest auth credentials if feature enabled
            #[cfg(feature = "digest-auth")]
            let (auth_username, auth_password) = acc
                .digest_credentials
                .as_ref()
                .map(|c| (Some(c.username.clone()), None)) // Never return password
                .unwrap_or((None, None));
            #[cfg(not(feature = "digest-auth"))]
            let (auth_username, auth_password): (Option<String>, Option<String>) = (None, None);

            // Get transport preference
            let transport = match acc.transport {
                client_types::TransportPreference::TlsOnly => "tls",
                client_types::TransportPreference::Tcp => "tcp",
                client_types::TransportPreference::Udp => "udp",
            };

            // Default port based on transport
            let default_port = match transport {
                "tls" => 5061,
                _ => 5060,
            };

            Ok(SipSettings {
                display_name: acc.display_name.clone(),
                username,
                domain,
                registrar: acc.registrar_uri.clone(),
                port: default_port,
                transport: transport.to_string(),
                auto_register: acc.enabled,
                caller_id: acc.caller_id.clone(),
                auth_username,
                auth_password,
            })
        }
        None => Ok(SipSettings {
            display_name: String::new(),
            username: String::new(),
            domain: String::new(),
            registrar: String::new(),
            port: 5061,
            transport: "tls".to_string(),
            auto_register: false,
            caller_id: None,
            auth_username: None,
            auth_password: None,
        }),
    }
}

/// Update SIP registration settings.
#[tauri::command]
async fn update_sip_settings(settings: SipSettings, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Updating SIP settings");

    let mut manager = state.settings_manager.write().await;

    // Parse transport preference
    let transport_pref = match settings.transport.as_str() {
        "udp" => client_types::TransportPreference::Udp,
        "tcp" => client_types::TransportPreference::Tcp,
        _ => client_types::TransportPreference::TlsOnly,
    };

    // Use appropriate URI scheme based on transport
    let uri_scheme = match transport_pref {
        client_types::TransportPreference::TlsOnly => "sips",
        client_types::TransportPreference::Udp | client_types::TransportPreference::Tcp => "sip",
    };

    // Build SIP URI from username and domain
    let sip_uri = format!("{}:{}@{}", uri_scheme, settings.username, settings.domain);

    // Registrar URI - append port if not default for the transport
    // Strip any existing sip: or sips: prefix from the registrar
    let registrar_host = settings.registrar
        .strip_prefix("sips:")
        .or_else(|| settings.registrar.strip_prefix("sip:"))
        .unwrap_or(&settings.registrar);

    let default_port = transport_pref.default_port();
    let registrar_uri = if registrar_host.is_empty() {
        format!("{}:{}", uri_scheme, settings.domain)
    } else if settings.port != default_port {
        format!("{}:{}:{}", uri_scheme, registrar_host, settings.port)
    } else {
        format!("{}:{}", uri_scheme, registrar_host)
    };

    // Create account from settings
    let mut account = SipAccount::new(
        "default",
        &settings.display_name,
        &sip_uri,
        &registrar_uri,
    );
    account.enabled = settings.auto_register;
    account.transport = transport_pref;

    // Set caller ID if provided
    account.caller_id = settings.caller_id.filter(|s| !s.is_empty());
    if let Some(ref cid) = account.caller_id {
        info!(caller_id = %cid, "Caller ID configured");
    }

    // Set digest auth credentials if provided (only when feature enabled)
    #[cfg(feature = "digest-auth")]
    {
        if let (Some(auth_user), Some(auth_pass)) = (&settings.auth_username, &settings.auth_password) {
            if !auth_user.is_empty() && !auth_pass.is_empty() {
                info!(
                    auth_user = %auth_user,
                    password_len = auth_pass.len(),
                    "Digest auth credentials received from GUI"
                );
                account.digest_credentials = Some(client_types::DigestAuthCredentials::new(
                    auth_user.clone(),
                    auth_pass.clone(),
                ));
                info!("Digest auth credentials configured for testing");
            } else {
                info!(
                    auth_user_empty = auth_user.is_empty(),
                    auth_pass_empty = auth_pass.is_empty(),
                    "Digest auth credentials incomplete"
                );
            }
        } else {
            info!(
                has_auth_user = settings.auth_username.is_some(),
                has_auth_pass = settings.auth_password.is_some(),
                "Digest auth credentials not provided"
            );
        }
    }

    manager.set_account(account);
    manager.set_default_account(Some("default".to_string()));

    // Persist digest credentials to secure storage (keychain)
    #[cfg(feature = "digest-auth")]
    {
        if let Err(e) = manager.persist_account_passwords() {
            warn!("Failed to persist passwords to secure storage: {}", e);
        } else {
            info!("Digest credentials persisted to secure storage");
        }
    }

    manager
        .save()
        .map_err(|e| format!("Failed to persist settings: {e}"))?;

    Ok(())
}

/// Save SIP settings (alias for update_sip_settings for frontend compatibility).
#[tauri::command]
async fn save_sip_settings(settings: SipSettings, state: State<'_, TauriAppState>) -> Result<(), String> {
    update_sip_settings(settings, state).await
}

/// Register with SIP server.
#[tauri::command]
async fn register_sip(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Registering with SIP server");

    // Get the account from settings
    let settings_mgr = state.settings_manager.read().await;
    let account = settings_mgr
        .default_account()
        .cloned()
        .ok_or_else(|| "No account configured".to_string())?;
    drop(settings_mgr);

    // Log digest credentials status
    #[cfg(feature = "digest-auth")]
    {
        if let Some(ref creds) = account.digest_credentials {
            info!(
                username = %creds.username,
                password_len = creds.password.len(),
                "Digest credentials found in account for registration"
            );
        } else {
            info!("No digest credentials in account");
        }
    }

    // Check if a certificate is selected for mTLS authentication
    let selected_thumbprint = state.selected_cert_thumbprint.read().await.clone();

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    // If a certificate is selected, configure it for mTLS before registering
    if let Some(thumbprint) = selected_thumbprint {
        info!(thumbprint = %thumbprint, "Configuring client certificate for mTLS");

        // Get the certificate chain from the store
        let cert_store = state.cert_store.read().await;
        let cert_chain = cert_store
            .get_certificate_chain(&thumbprint)
            .map_err(|e| format!("Failed to get certificate chain: {e}"))?;
        drop(cert_store);

        // Set the client certificate for mTLS authentication
        client.set_client_certificate(cert_chain, &thumbprint);
    } else {
        warn!("No client certificate selected - mTLS may fail if server requires client auth");
    }

    client
        .register_account(&account)
        .await
        .map_err(|e| format!("Registration failed: {e}"))?;

    Ok(())
}

/// Unregister from SIP server.
#[tauri::command]
async fn unregister_sip(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Unregistering from SIP server");

    let mut client_guard = state.client.lock().await;
    let client = client_guard
        .as_mut()
        .ok_or_else(|| "Client not initialized".to_string())?;

    client
        .unregister()
        .await
        .map_err(|e| format!("Unregistration failed: {e}"))?;

    Ok(())
}

/// Get registration status.
#[tauri::command]
async fn get_registration_status(state: State<'_, TauriAppState>) -> Result<RegistrationStatus, String> {
    let client_guard = state.client.lock().await;

    match client_guard.as_ref() {
        Some(client) => {
            let state_str = match client.state() {
                CoreAppState::Starting | CoreAppState::Ready => "unregistered",
                CoreAppState::Registering => "registering",
                CoreAppState::Registered | CoreAppState::InCall => "registered",
                CoreAppState::ShuttingDown => "unregistered",
            };

            Ok(RegistrationStatus {
                state: state_str.to_string(),
                error: None,
            })
        }
        None => Ok(RegistrationStatus {
            state: "unregistered".to_string(),
            error: None,
        }),
    }
}

/// Get current call status.
#[tauri::command]
async fn get_call_status(state: State<'_, TauriAppState>) -> Result<CallStatus, String> {
    let client_guard = state.client.lock().await;

    match client_guard.as_ref() {
        Some(client) => {
            let calls = client.all_call_info();

            if let Some(call) = calls.first() {
                let state_str = match call.state {
                    client_types::CallState::Idle => "idle",
                    client_types::CallState::Dialing => "dialing",
                    client_types::CallState::Ringing => "ringing",
                    client_types::CallState::EarlyMedia => "early_media",
                    client_types::CallState::Connecting => "connecting",
                    client_types::CallState::Connected => "connected",
                    client_types::CallState::OnHold => "on_hold",
                    client_types::CallState::Transferring => "transferring",
                    client_types::CallState::Terminating => "terminating",
                    client_types::CallState::Terminated => "terminated",
                };

                Ok(CallStatus {
                    call_id: Some(call.id.clone()),
                    state: state_str.to_string(),
                    remote_uri: Some(call.remote_uri.clone()),
                    remote_display_name: call.remote_display_name.clone(),
                    duration_secs: call.duration().map(|d| d.as_secs()),
                    is_muted: client.is_muted(),
                    is_on_hold: call.state == client_types::CallState::OnHold,
                })
            } else {
                Ok(CallStatus {
                    call_id: None,
                    state: "idle".to_string(),
                    remote_uri: None,
                    remote_display_name: None,
                    duration_secs: None,
                    is_muted: false,
                    is_on_hold: false,
                })
            }
        }
        None => Ok(CallStatus {
            call_id: None,
            state: "idle".to_string(),
            remote_uri: None,
            remote_display_name: None,
            duration_secs: None,
            is_muted: false,
            is_on_hold: false,
        }),
    }
}

/// Get available input (microphone) devices.
#[tauri::command]
async fn get_input_devices(state: State<'_, TauriAppState>) -> Result<Vec<AudioDeviceInfo>, String> {
    info!("Fetching input devices");

    let manager = state.device_manager.read().await;
    let devices = manager
        .list_input_devices()
        .map_err(|e| format!("Failed to enumerate input devices: {e}"))?;

    let result: Vec<AudioDeviceInfo> = devices
        .into_iter()
        .map(|d| AudioDeviceInfo {
            name: d.name,
            display_name: d.display_name,
            is_default: d.is_default,
            device_type: "input".to_string(),
        })
        .collect();

    Ok(result)
}

/// Get available output (speaker) devices.
#[tauri::command]
async fn get_output_devices(state: State<'_, TauriAppState>) -> Result<Vec<AudioDeviceInfo>, String> {
    info!("Fetching output devices");

    let manager = state.device_manager.read().await;
    let devices = manager
        .list_output_devices()
        .map_err(|e| format!("Failed to enumerate output devices: {e}"))?;

    let result: Vec<AudioDeviceInfo> = devices
        .into_iter()
        .map(|d| AudioDeviceInfo {
            name: d.name,
            display_name: d.display_name,
            is_default: d.is_default,
            device_type: "output".to_string(),
        })
        .collect();

    Ok(result)
}

/// Set the input device.
#[tauri::command]
async fn set_input_device(device_name: Option<String>, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Setting input device: {:?}", device_name);

    let client_guard = state.client.lock().await;
    if let Some(client) = client_guard.as_ref() {
        client
            .switch_input_device(device_name)
            .await
            .map_err(|e| format!("Failed to switch input device: {e}"))?;
    }

    Ok(())
}

/// Set the output device.
#[tauri::command]
async fn set_output_device(device_name: Option<String>, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Setting output device: {:?}", device_name);

    let client_guard = state.client.lock().await;
    if let Some(client) = client_guard.as_ref() {
        client
            .switch_output_device(device_name)
            .await
            .map_err(|e| format!("Failed to switch output device: {e}"))?;
    }

    Ok(())
}

/// Audio settings for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioSettings {
    /// Preferred codec for calls.
    pub preferred_codec: String,
    /// Echo cancellation enabled.
    pub echo_cancellation: bool,
    /// Noise suppression enabled.
    pub noise_suppression: bool,
    /// Jitter buffer minimum depth in milliseconds.
    pub jitter_buffer_min_ms: u32,
    /// Jitter buffer maximum depth in milliseconds.
    pub jitter_buffer_max_ms: u32,
}

/// Get audio settings.
#[tauri::command]
async fn get_audio_settings(state: State<'_, TauriAppState>) -> Result<AudioSettings, String> {
    info!("Fetching audio settings");

    let manager = state.settings_manager.read().await;
    let audio = &manager.settings().audio;

    let codec_str = match audio.preferred_codec {
        client_types::CodecPreference::Opus => "opus",
        client_types::CodecPreference::G722 => "g722",
        client_types::CodecPreference::G711Ulaw => "g711_ulaw",
        client_types::CodecPreference::G711Alaw => "g711_alaw",
    };

    Ok(AudioSettings {
        preferred_codec: codec_str.to_string(),
        echo_cancellation: audio.echo_cancellation,
        noise_suppression: audio.noise_suppression,
        jitter_buffer_min_ms: audio.jitter_buffer_min_ms,
        jitter_buffer_max_ms: audio.jitter_buffer_max_ms,
    })
}

/// Save audio settings.
#[tauri::command]
async fn save_audio_settings(settings: AudioSettings, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Saving audio settings: codec={}", settings.preferred_codec);

    let mut manager = state.settings_manager.write().await;

    // Parse codec preference
    let codec = match settings.preferred_codec.as_str() {
        "opus" => client_types::CodecPreference::Opus,
        "g722" => client_types::CodecPreference::G722,
        "g711_ulaw" => client_types::CodecPreference::G711Ulaw,
        "g711_alaw" => client_types::CodecPreference::G711Alaw,
        _ => client_types::CodecPreference::Opus, // Default to Opus
    };

    {
        let audio = &mut manager.settings_mut().audio;
        audio.preferred_codec = codec;
        audio.echo_cancellation = settings.echo_cancellation;
        audio.noise_suppression = settings.noise_suppression;
        audio.jitter_buffer_min_ms = settings.jitter_buffer_min_ms;
        audio.jitter_buffer_max_ms = settings.jitter_buffer_max_ms;
    }

    manager
        .save()
        .map_err(|e| format!("Failed to save audio settings: {e}"))?;

    info!("Audio settings saved");
    Ok(())
}

// ============================================================================
// Smart Card / Certificate Commands
// ============================================================================

/// Get available certificates from the certificate store.
///
/// Returns certificates filtered by the configured certificate filter settings:
/// - Only DOD CA issuers (if configured)
/// - Only certificates with Smart Card Logon EKU
/// - Only certificates with Client Authentication EKU
/// - Hides expired certificates
#[tauri::command]
async fn get_certificates(state: State<'_, TauriAppState>) -> Result<Vec<CertificateInfo>, String> {
    info!("Fetching filtered certificates from store");

    // Get certificate filter settings
    let settings_mgr = state.settings_manager.read().await;
    let filter = settings_mgr.settings().certificates.clone();
    drop(settings_mgr);

    info!(
        "Certificate filter: trusted_issuers={}, require_smart_card_logon={}, require_client_auth={}",
        filter.trusted_issuers.len(),
        filter.require_smart_card_logon_eku,
        filter.require_client_auth_eku
    );

    let store = state.cert_store.read().await;
    let certs = store
        .list_certificates_filtered(&filter)
        .map_err(|e| format!("Failed to list certificates: {e}"))?;

    info!("Found {} certificates after filtering", certs.len());
    for cert in &certs {
        info!(
            "  Certificate: {} (issuer: {}, smart_card_logon: {})",
            cert.subject_cn, cert.issuer_cn, cert.has_smart_card_logon
        );
    }

    Ok(certs)
}

/// Get the currently selected certificate thumbprint.
#[tauri::command]
async fn get_selected_certificate(state: State<'_, TauriAppState>) -> Result<Option<String>, String> {
    let selected = state.selected_cert_thumbprint.read().await;
    Ok(selected.clone())
}

/// Select a certificate by thumbprint for TLS authentication.
#[tauri::command]
async fn select_certificate(thumbprint: String, state: State<'_, TauriAppState>) -> Result<CertificateInfo, String> {
    info!("Selecting certificate: {}", thumbprint);

    let store = state.cert_store.read().await;

    // Verify the certificate exists and is valid
    let cert = store
        .find_by_thumbprint(&thumbprint)
        .map_err(|e| format!("Certificate not found: {e}"))?;

    if !cert.is_valid {
        return Err("Selected certificate is expired or not yet valid".to_string());
    }

    // Store the selected thumbprint
    {
        let mut selected = state.selected_cert_thumbprint.write().await;
        *selected = Some(thumbprint);
    }

    info!("Certificate selected: {}", cert.subject_cn);
    Ok(cert)
}

/// Clear the selected certificate.
#[tauri::command]
async fn clear_selected_certificate(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Clearing selected certificate");

    let mut selected = state.selected_cert_thumbprint.write().await;
    *selected = None;

    Ok(())
}

/// Verify a smart card PIN for the selected certificate.
#[tauri::command]
async fn verify_pin(thumbprint: String, pin: String, state: State<'_, TauriAppState>) -> Result<bool, String> {
    info!("Verifying PIN for certificate: {}", thumbprint);

    let store = state.cert_store.read().await;
    let smart_card_pin = SmartCardPin::new(&pin);

    store
        .verify_pin(&thumbprint, &smart_card_pin)
        .map_err(|e| match e {
            client_core::CertStoreError::PinIncorrect => "PIN incorrect".to_string(),
            client_core::CertStoreError::SmartCardNotPresent => {
                "Smart card not present - please insert your CAC/PIV card".to_string()
            }
            _ => format!("PIN verification failed: {e}"),
        })
}

/// Check if a certificate has an associated private key (smart card present).
#[tauri::command]
async fn check_private_key(thumbprint: String, state: State<'_, TauriAppState>) -> Result<bool, String> {
    info!("Checking private key for certificate: {}", thumbprint);

    let store = state.cert_store.read().await;
    store
        .has_private_key(&thumbprint)
        .map_err(|e| format!("Failed to check private key: {e}"))
}

/// Refresh the certificate list from the store.
///
/// Refreshes and returns certificates filtered by the configured settings.
#[tauri::command]
async fn refresh_certificates(state: State<'_, TauriAppState>) -> Result<Vec<CertificateInfo>, String> {
    info!("Refreshing certificate list");

    // Get certificate filter settings
    let settings_mgr = state.settings_manager.read().await;
    let filter = settings_mgr.settings().certificates.clone();
    drop(settings_mgr);

    let mut store = state.cert_store.write().await;
    store
        .refresh()
        .map_err(|e| format!("Failed to refresh certificates: {e}"))?;

    let certs = store
        .list_certificates_filtered(&filter)
        .map_err(|e| format!("Failed to list certificates: {e}"))?;

    info!("Refreshed {} certificates after filtering", certs.len());
    Ok(certs)
}

/// Get certificate details by thumbprint.
#[tauri::command]
async fn get_certificate_details(thumbprint: String, state: State<'_, TauriAppState>) -> Result<CertificateInfo, String> {
    info!("Getting certificate details: {}", thumbprint);

    let store = state.cert_store.read().await;
    store
        .find_by_thumbprint(&thumbprint)
        .map_err(|e| format!("Certificate not found: {e}"))
}

// ============================================================================
// Classification Config Commands
// ============================================================================

/// Get the classification configuration.
#[tauri::command]
async fn get_classification_config(state: State<'_, TauriAppState>) -> Result<ClassificationConfig, String> {
    info!("Fetching classification config");

    let manager = state.settings_manager.read().await;
    let ui = &manager.settings().ui;

    Ok(ClassificationConfig {
        level: ui.classification_level.clone(),
        caveats: ui.classification_caveats.clone(),
        dissem: ui.classification_dissem.clone(),
    })
}

/// Save the classification configuration.
#[tauri::command]
async fn save_classification_config(config: ClassificationConfig, state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Saving classification config: level={}, caveats={:?}, dissem={:?}",
        config.level, config.caveats, config.dissem);

    let mut manager = state.settings_manager.write().await;
    {
        let ui = &mut manager.settings_mut().ui;
        ui.classification_level = config.level;
        ui.classification_caveats = config.caveats;
        ui.classification_dissem = config.dissem;
    }

    manager
        .save()
        .map_err(|e| format!("Failed to save classification config: {e}"))?;

    info!("Classification config saved");
    Ok(())
}

/// Open the config file in the system's default editor.
#[tauri::command]
async fn open_config_file(state: State<'_, TauriAppState>) -> Result<(), String> {
    info!("Opening config file");

    let manager = state.settings_manager.read().await;
    let config_path = manager.path();

    info!("Config path: {:?}", config_path);

    // Use the shell opener to open the file
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("-t") // Open with default text editor
            .arg(&config_path)
            .spawn()
            .map_err(|e| format!("Failed to open config file: {e}"))?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "notepad"])
            .arg(&config_path)
            .spawn()
            .map_err(|e| format!("Failed to open config file: {e}"))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&config_path)
            .spawn()
            .map_err(|e| format!("Failed to open config file: {e}"))?;
    }

    Ok(())
}

/// Poll for application events and emit them to the frontend.
async fn poll_events(app_handle: AppHandle, event_rx: Arc<Mutex<Option<mpsc::Receiver<AppEvent>>>>) {
    loop {
        let event = {
            let mut rx_guard = event_rx.lock().await;
            if let Some(ref mut rx) = *rx_guard {
                rx.recv().await
            } else {
                // No receiver yet, wait a bit
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        if let Some(event) = event {
            // Emit event to frontend
            let event_name = match &event {
                AppEvent::RegistrationStateChanged { .. } => "registration-state-changed",
                AppEvent::CallStateChanged { .. } => "call-state-changed",
                AppEvent::IncomingCall { .. } => "incoming-call",
                AppEvent::CallEnded { .. } => "call-ended",
                AppEvent::Error { .. } => "error",
                AppEvent::SettingsChanged => "settings-changed",
                AppEvent::ContactsChanged => "contacts-changed",
                AppEvent::PinRequired { .. } => "pin-required",
                AppEvent::PinCompleted { .. } => "pin-completed",
                AppEvent::TransferProgress { .. } => "transfer-progress",
            };

            // Serialize event payload
            let payload = match &event {
                AppEvent::RegistrationStateChanged { account_id, state } => {
                    serde_json::json!({
                        "account_id": account_id,
                        "state": format!("{:?}", state)
                    })
                }
                AppEvent::CallStateChanged { call_id, state, info } => {
                    serde_json::json!({
                        "call_id": call_id,
                        "state": format!("{:?}", state),
                        "remote_uri": info.remote_uri,
                        "remote_display_name": info.remote_display_name
                    })
                }
                AppEvent::IncomingCall {
                    call_id,
                    remote_uri,
                    remote_display_name,
                } => {
                    serde_json::json!({
                        "call_id": call_id,
                        "remote_uri": remote_uri,
                        "remote_display_name": remote_display_name
                    })
                }
                AppEvent::CallEnded {
                    call_id,
                    duration_secs,
                } => {
                    serde_json::json!({
                        "call_id": call_id,
                        "duration_secs": duration_secs
                    })
                }
                AppEvent::Error { message } => {
                    serde_json::json!({
                        "message": message
                    })
                }
                AppEvent::SettingsChanged => serde_json::json!({}),
                AppEvent::ContactsChanged => serde_json::json!({}),
                AppEvent::PinRequired {
                    operation,
                    thumbprint,
                } => {
                    serde_json::json!({
                        "operation": format!("{:?}", operation),
                        "thumbprint": thumbprint
                    })
                }
                AppEvent::PinCompleted { success, error } => {
                    serde_json::json!({
                        "success": success,
                        "error": error
                    })
                }
                AppEvent::TransferProgress {
                    call_id,
                    target_uri,
                    status_code,
                    is_success,
                    is_final,
                } => {
                    serde_json::json!({
                        "call_id": call_id,
                        "target_uri": target_uri,
                        "status_code": status_code,
                        "is_success": is_success,
                        "is_final": is_final
                    })
                }
            };

            if let Err(e) = app_handle.emit(event_name, payload) {
                warn!("Failed to emit event {}: {}", event_name, e);
            }
        }
    }
}

fn main() {
    // Initialize logging - use RUST_LOG env var if set, otherwise default to INFO
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("USG SIP Soft Client (Tauri) starting...");

    // Create settings manager
    #[allow(unused_mut)] // mut only needed with digest-auth feature
    let settings_manager = match SettingsManager::new() {
        Ok(mut m) => {
            // Load any persisted passwords from secure storage (keychain)
            #[cfg(feature = "digest-auth")]
            {
                if let Err(e) = m.load_persisted_passwords() {
                    warn!("Failed to load persisted passwords: {}", e);
                } else {
                    info!("Persisted passwords loaded from secure storage");
                }
            }
            Arc::new(RwLock::new(m))
        }
        Err(e) => {
            error!("Failed to create settings manager: {}", e);
            return;
        }
    };

    // Create contact manager
    let contact_manager = match ContactManager::new() {
        Ok(m) => Arc::new(RwLock::new(m)),
        Err(e) => {
            error!("Failed to create contact manager: {}", e);
            return;
        }
    };

    // Create device manager
    let device_manager = Arc::new(RwLock::new(DeviceManager::new()));

    // Create certificate store for smart card access
    let cert_store = Arc::new(RwLock::new(CertificateStore::open_personal()));
    info!("Certificate store initialized");

    // Create event receiver placeholder
    let event_rx = Arc::new(Mutex::new(None));

    let app_state = TauriAppState {
        client: Arc::new(Mutex::new(None)),
        device_manager,
        settings_manager,
        contact_manager,
        cert_store,
        selected_cert_thumbprint: Arc::new(RwLock::new(None)),
        event_rx: event_rx.clone(),
    };

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            is_digest_auth_enabled,
            initialize_client,
            make_call,
            end_call,
            accept_call,
            reject_call,
            toggle_mute,
            toggle_hold,
            transfer_call,
            send_dtmf,
            get_contacts,
            add_contact,
            update_contact,
            delete_contact,
            search_contacts,
            get_call_history,
            get_sip_settings,
            update_sip_settings,
            save_sip_settings,
            register_sip,
            unregister_sip,
            get_registration_status,
            get_call_status,
            get_input_devices,
            get_output_devices,
            set_input_device,
            set_output_device,
            // Audio settings commands
            get_audio_settings,
            save_audio_settings,
            // Smart card / certificate commands
            get_certificates,
            get_selected_certificate,
            select_certificate,
            clear_selected_certificate,
            verify_pin,
            check_private_key,
            refresh_certificates,
            get_certificate_details,
            // Classification config commands
            get_classification_config,
            save_classification_config,
            // Config file command
            open_config_file,
        ])
        .setup(move |app| {
            // Start event polling task
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                poll_events(app_handle, event_rx).await;
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!("Error running Tauri application: {}", e);
        });

    info!("Application shutting down");
}
