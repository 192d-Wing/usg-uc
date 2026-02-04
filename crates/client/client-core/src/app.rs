//! Application coordinator for the SIP Soft Client.
//!
//! The `ClientApp` is the central coordinator that manages:
//! - Account registration
//! - Call lifecycle
//! - Settings and contacts persistence
//! - Event broadcasting to the GUI

use crate::call_manager::{CallManager, CallManagerEvent};
use crate::contact_manager::ContactManager;
use crate::settings::SettingsManager;
use crate::sip_transport::{SipTransport, TransportEvent};
use crate::{AppError, AppResult};
use client_sip_ua::{RegistrationAgent, RegistrationEvent};
use client_types::{CallInfo, CallState, RegistrationState, SipAccount};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

/// Application events broadcast to the GUI.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Registration state changed.
    RegistrationStateChanged {
        /// Account ID.
        account_id: String,
        /// New state.
        state: RegistrationState,
    },
    /// Call state changed.
    CallStateChanged {
        /// Call ID.
        call_id: String,
        /// New state.
        state: CallState,
        /// Call info.
        info: CallInfo,
    },
    /// Incoming call.
    IncomingCall {
        /// Call ID.
        call_id: String,
        /// Remote party URI.
        remote_uri: String,
        /// Remote party display name.
        remote_display_name: Option<String>,
    },
    /// Call ended.
    CallEnded {
        /// Call ID.
        call_id: String,
        /// Duration in seconds (if connected).
        duration_secs: Option<u64>,
    },
    /// Error occurred.
    Error {
        /// Error message.
        message: String,
    },
    /// Settings changed.
    SettingsChanged,
    /// Contacts changed.
    ContactsChanged,
    /// PIN required for smart card operation.
    PinRequired {
        /// Operation that requires PIN.
        operation: PinOperationType,
        /// Certificate thumbprint (if applicable).
        thumbprint: Option<String>,
    },
    /// PIN entry completed.
    PinCompleted {
        /// Whether the PIN was successful.
        success: bool,
        /// Error message if failed.
        error: Option<String>,
    },
}

/// Type of operation requiring a PIN.
#[derive(Debug, Clone)]
pub enum PinOperationType {
    /// Certificate selection for authentication.
    CertificateSelection,
    /// SIP registration.
    Registration,
    /// Call establishment (DTLS signing).
    CallEstablishment,
}

/// Application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is starting up.
    Starting,
    /// Application is ready but not registered.
    Ready,
    /// Application is registering.
    Registering,
    /// Application is registered and ready for calls.
    Registered,
    /// Application is in a call.
    InCall,
    /// Application is shutting down.
    ShuttingDown,
}

/// Main application coordinator.
pub struct ClientApp {
    /// Application state.
    state: AppState,
    /// Settings manager.
    settings_manager: SettingsManager,
    /// Contact manager.
    contact_manager: Arc<RwLock<ContactManager>>,
    /// Registration agent.
    registration_agent: RegistrationAgent,
    /// Call manager.
    call_manager: CallManager,
    /// SIP transport layer.
    sip_transport: Option<SipTransport>,
    /// Event sender for application events.
    app_event_tx: mpsc::Sender<AppEvent>,
    /// Registration event receiver.
    reg_event_rx: mpsc::Receiver<RegistrationEvent>,
    /// Call manager event receiver.
    #[allow(dead_code)]
    call_event_rx: mpsc::Receiver<CallManagerEvent>,
    /// Transport event receiver.
    transport_event_rx: Option<mpsc::Receiver<TransportEvent>>,
    /// Current account ID.
    current_account_id: Option<String>,
    /// Client certificate chain (DER-encoded) for mTLS authentication.
    client_cert_chain: Option<Vec<Vec<u8>>>,
    /// Client certificate thumbprint.
    client_cert_thumbprint: Option<String>,
}

impl ClientApp {
    /// Creates a new client application.
    ///
    /// # Arguments
    /// * `local_sip_addr` - Local address for SIP signaling
    /// * `local_media_addr` - Local address for RTP media
    /// * `app_event_tx` - Channel for application events to GUI
    pub fn new(
        local_sip_addr: SocketAddr,
        local_media_addr: SocketAddr,
        app_event_tx: mpsc::Sender<AppEvent>,
    ) -> AppResult<Self> {
        info!(
            sip_addr = %local_sip_addr,
            media_addr = %local_media_addr,
            "Initializing client application"
        );

        // Load settings
        let settings_manager = SettingsManager::new()?;

        // Load contacts
        let contact_manager = Arc::new(RwLock::new(ContactManager::new()?));

        // Create registration agent channel
        let (reg_event_tx, reg_event_rx) = mpsc::channel(32);
        let registration_agent = RegistrationAgent::new(local_sip_addr, reg_event_tx);

        // Create call manager channel
        let (call_event_tx, call_event_rx) = mpsc::channel(32);
        let mut call_manager = CallManager::new(local_sip_addr, local_media_addr, call_event_tx);
        call_manager.set_contact_manager(contact_manager.clone());

        // Create SIP transport
        let (transport_event_tx, transport_event_rx) = mpsc::channel(32);
        let sip_transport = SipTransport::new(transport_event_tx)
            .map_err(|e| AppError::Sip(format!("Failed to create SIP transport: {e}")))?;

        Ok(Self {
            state: AppState::Starting,
            settings_manager,
            contact_manager,
            registration_agent,
            call_manager,
            sip_transport: Some(sip_transport),
            app_event_tx,
            reg_event_rx,
            call_event_rx,
            transport_event_rx: Some(transport_event_rx),
            current_account_id: None,
            client_cert_chain: None,
            client_cert_thumbprint: None,
        })
    }

    /// Initializes the application.
    ///
    /// This loads settings and prepares for registration.
    pub async fn initialize(&mut self) -> AppResult<()> {
        info!("Initializing application");

        // Set state to ready
        self.state = AppState::Ready;

        // Auto-register default account if configured
        if let Some(account) = self.settings_manager.default_account()
            && account.enabled
        {
            info!(account_id = %account.id, "Auto-registering default account");
            let account = account.clone();
            self.register_account(&account).await?;
        }

        Ok(())
    }

    /// Sets the client certificate for mTLS authentication.
    ///
    /// The certificate chain should be DER-encoded, with the end-entity
    /// certificate first, followed by any intermediate certificates.
    pub fn set_client_certificate(&mut self, cert_chain: Vec<Vec<u8>>, thumbprint: &str) {
        info!(
            thumbprint = %thumbprint,
            chain_length = cert_chain.len(),
            "Setting client certificate for authentication"
        );

        self.client_cert_chain = Some(cert_chain.clone());
        self.client_cert_thumbprint = Some(thumbprint.to_string());

        // Configure the call manager with the DTLS credentials
        // For smart card certificates, the private key stays on the card
        // and signing operations are performed by the Windows CryptoAPI
        self.call_manager.set_dtls_credentials(cert_chain, Vec::new());

        info!("Client certificate configured");
    }

    /// Returns the configured client certificate thumbprint.
    pub fn client_certificate_thumbprint(&self) -> Option<&str> {
        self.client_cert_thumbprint.as_deref()
    }

    /// Returns whether a client certificate is configured.
    pub fn has_client_certificate(&self) -> bool {
        self.client_cert_chain.is_some()
    }

    /// Registers a SIP account.
    pub async fn register_account(&mut self, account: &SipAccount) -> AppResult<()> {
        info!(account_id = %account.id, "Registering account");

        self.state = AppState::Registering;
        self.current_account_id = Some(account.id.clone());

        // Configure call manager with account
        self.call_manager.configure_account(account);

        // Start registration
        self.registration_agent
            .register(account)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        Ok(())
    }

    /// Unregisters the current account.
    pub async fn unregister(&mut self) -> AppResult<()> {
        let account_id = self
            .current_account_id
            .as_ref()
            .ok_or_else(|| AppError::Sip("No account registered".to_string()))?
            .clone();

        info!(account_id = %account_id, "Unregistering account");

        self.registration_agent
            .unregister(&account_id)
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        self.state = AppState::Ready;
        self.current_account_id = None;

        Ok(())
    }

    /// Makes an outbound call.
    pub async fn make_call(&mut self, remote_uri: &str) -> AppResult<String> {
        // Verify we're registered
        if self.state != AppState::Registered {
            return Err(AppError::Sip("Not registered".to_string()));
        }

        info!(remote_uri = %remote_uri, "Making call");

        self.state = AppState::InCall;
        self.call_manager.make_call(remote_uri).await
    }

    /// Hangs up the current call.
    pub async fn hangup(&mut self) -> AppResult<()> {
        self.call_manager.hangup().await?;
        self.state = AppState::Registered;
        Ok(())
    }

    /// Toggles mute state.
    pub fn toggle_mute(&mut self) -> bool {
        self.call_manager.toggle_mute()
    }

    /// Returns whether currently muted.
    pub fn is_muted(&self) -> bool {
        self.call_manager.is_muted()
    }

    /// Returns the current application state.
    pub fn state(&self) -> AppState {
        self.state
    }

    /// Returns the registration state for the current account.
    pub fn registration_state(&self) -> Option<RegistrationState> {
        self.current_account_id
            .as_ref()
            .and_then(|id| self.registration_agent.get_state(id))
    }

    /// Returns the active call info.
    pub fn active_call_info(&self) -> Option<CallInfo> {
        self.call_manager.active_call_info()
    }

    /// Returns the settings manager.
    pub fn settings(&self) -> &SettingsManager {
        &self.settings_manager
    }

    /// Returns mutable reference to settings manager.
    pub fn settings_mut(&mut self) -> &mut SettingsManager {
        &mut self.settings_manager
    }

    /// Returns the contact manager.
    pub fn contacts(&self) -> &Arc<RwLock<ContactManager>> {
        &self.contact_manager
    }

    /// Handles a registration event.
    pub async fn handle_registration_event(&mut self, event: RegistrationEvent) -> AppResult<()> {
        match event {
            RegistrationEvent::StateChanged { account_id, state } => {
                debug!(account_id = %account_id, state = ?state, "Registration state changed");

                // Update app state based on registration
                match state {
                    RegistrationState::Registered => {
                        if self.state == AppState::Registering {
                            self.state = AppState::Registered;
                        }
                    }
                    RegistrationState::Failed | RegistrationState::CertificateInvalid => {
                        if self.state == AppState::Registering {
                            self.state = AppState::Ready;
                        }
                    }
                    RegistrationState::Unregistered => {
                        if self.state == AppState::Registered {
                            self.state = AppState::Ready;
                        }
                    }
                    _ => {}
                }

                // Notify GUI
                let _ = self
                    .app_event_tx
                    .send(AppEvent::RegistrationStateChanged { account_id, state })
                    .await;
            }
            RegistrationEvent::Expiring {
                account_id,
                expires_in_secs,
            } => {
                debug!(
                    account_id = %account_id,
                    expires_in_secs = expires_in_secs,
                    "Registration expiring"
                );

                // Auto-refresh registration
                if let Some(account) = self.settings_manager.get_account(&account_id) {
                    let account = account.clone();
                    if let Err(e) = self.registration_agent.register(&account).await {
                        warn!(error = %e, "Failed to refresh registration");
                    }
                }
            }
            RegistrationEvent::SendRequest { request, destination } => {
                // Send via SIP transport
                if let Some(ref transport) = self.sip_transport {
                    if let Err(e) = transport.send_request(&request, destination).await {
                        error!(error = %e, "Failed to send SIP request");
                        let _ = self
                            .app_event_tx
                            .send(AppEvent::Error {
                                message: format!("Failed to send registration: {}", e),
                            })
                            .await;
                    }
                } else {
                    warn!("SIP transport not initialized");
                }
            }
        }

        Ok(())
    }

    /// Handles a call manager event.
    pub async fn handle_call_event(&mut self, event: CallManagerEvent) -> AppResult<()> {
        match event {
            CallManagerEvent::CallStateChanged {
                call_id,
                state,
                info,
            } => {
                debug!(call_id = %call_id, state = ?state, "Call state changed");

                // Update app state
                match state {
                    CallState::Terminated => {
                        if self.state == AppState::InCall {
                            self.state = AppState::Registered;
                        }
                    }
                    _ if state.is_active() => {
                        self.state = AppState::InCall;
                    }
                    _ => {}
                }

                // Notify GUI
                let _ = self
                    .app_event_tx
                    .send(AppEvent::CallStateChanged {
                        call_id,
                        state,
                        info,
                    })
                    .await;
            }
            CallManagerEvent::IncomingCall {
                call_id,
                remote_uri,
                remote_display_name,
            } => {
                info!(call_id = %call_id, remote_uri = %remote_uri, "Incoming call");

                let _ = self
                    .app_event_tx
                    .send(AppEvent::IncomingCall {
                        call_id,
                        remote_uri,
                        remote_display_name,
                    })
                    .await;
            }
            CallManagerEvent::CallEnded {
                call_id,
                reason: _,
                duration_secs,
            } => {
                info!(call_id = %call_id, "Call ended");

                if self.state == AppState::InCall {
                    self.state = AppState::Registered;
                }

                let _ = self
                    .app_event_tx
                    .send(AppEvent::CallEnded {
                        call_id,
                        duration_secs,
                    })
                    .await;
            }
            CallManagerEvent::CallConnected { .. } => {
                // Already handled via state change
            }
            CallManagerEvent::MediaStateChanged { .. } => {
                // Internal event, not forwarded to GUI
            }
            CallManagerEvent::Error { call_id, message } => {
                error!(call_id = ?call_id, message = %message, "Call error");

                let _ = self.app_event_tx.send(AppEvent::Error { message }).await;
            }
        }

        Ok(())
    }

    /// Handles a transport event.
    pub async fn handle_transport_event(&mut self, event: TransportEvent) -> AppResult<()> {
        match event {
            TransportEvent::ResponseReceived { response, source } => {
                debug!(
                    source = %source,
                    status = response.status.code(),
                    "Received SIP response"
                );

                // Route response to registration agent if it's a REGISTER response
                // The Via header and Call-ID can be used to correlate with the request
                if let Some(ref account_id) = self.current_account_id {
                    if let Err(e) = self
                        .registration_agent
                        .handle_response(&response, account_id)
                        .await
                    {
                        warn!(error = %e, "Failed to handle registration response");
                    }
                }
            }
            TransportEvent::RequestReceived { request, source } => {
                info!(
                    source = %source,
                    method = %request.method,
                    "Received incoming SIP request"
                );

                // TODO: Handle incoming calls (INVITE), etc.
                // For now, just log it
            }
            TransportEvent::Connected { peer } => {
                info!(peer = %peer, "Connected to SIP peer");
            }
            TransportEvent::Disconnected { peer, reason } => {
                warn!(peer = %peer, reason = %reason, "Disconnected from SIP peer");

                // If we were registered, update state
                if self.state == AppState::Registered {
                    self.state = AppState::Ready;
                    if let Some(ref account_id) = self.current_account_id {
                        let _ = self
                            .app_event_tx
                            .send(AppEvent::RegistrationStateChanged {
                                account_id: account_id.clone(),
                                state: RegistrationState::Failed,
                            })
                            .await;
                    }
                }
            }
            TransportEvent::Error { message } => {
                error!(message = %message, "Transport error");
                let _ = self.app_event_tx.send(AppEvent::Error { message }).await;
            }
        }

        Ok(())
    }

    /// Polls for pending events from all sources.
    ///
    /// Call this periodically from the main event loop.
    pub async fn poll_events(&mut self) -> AppResult<()> {
        // Collect registration events first, then process them
        // (avoids borrow checker issues with async methods)
        let reg_events: Vec<_> = std::iter::from_fn(|| self.reg_event_rx.try_recv().ok()).collect();
        for event in reg_events {
            self.handle_registration_event(event).await?;
        }

        // Collect transport events first, then process them
        let transport_events: Vec<_> = if let Some(ref mut rx) = self.transport_event_rx {
            std::iter::from_fn(|| rx.try_recv().ok()).collect()
        } else {
            vec![]
        };
        for event in transport_events {
            self.handle_transport_event(event).await?;
        }

        Ok(())
    }

    /// Saves all dirty state.
    pub async fn save_all(&mut self) -> AppResult<()> {
        // Save settings
        self.settings_manager.save_if_dirty()?;

        // Save contacts
        let mut contacts = self.contact_manager.write().await;
        contacts.save_if_dirty()?;

        Ok(())
    }

    /// Shuts down the application gracefully.
    pub async fn shutdown(&mut self) -> AppResult<()> {
        info!("Shutting down application");

        self.state = AppState::ShuttingDown;

        // Hangup any active call
        if self.call_manager.active_call_id().is_some() {
            let _ = self.call_manager.hangup().await;
        }

        // Unregister
        if self.current_account_id.is_some() {
            let _ = self.unregister().await;
        }

        // Save state
        self.save_all().await?;

        info!("Application shutdown complete");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_state_default() {
        let (tx, _rx) = mpsc::channel(10);
        let sip_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let media_addr: SocketAddr = "127.0.0.1:16384".parse().unwrap();

        // This will fail if config directories don't exist, which is fine for tests
        let result = ClientApp::new(sip_addr, media_addr, tx);
        // Just verify it doesn't panic during construction
        let _ = result;
    }
}
