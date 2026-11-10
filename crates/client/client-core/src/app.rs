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
use crate::sip_transport::{CertVerificationMode, SipTransport, SipTransportKind, TransportEvent};
use crate::{AppError, AppResult};
use client_sip_ua::{RegistrationAgent, RegistrationEvent};
use client_types::audio::CodecPreference;
use client_types::{
    CallInfo, CallQualityMetrics, CallState, DtmfDigit, RegistrationState, SipAccount,
};
#[cfg(feature = "insecure-transports")]
use proto_sip::header::HeaderName;
use proto_sip::message::SipRequest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, trace, warn};

/// Most transport events handled in one [`ClientApp::poll_events`] pass.
///
/// The receive tasks refill the transport queue while the pump drains it, so
/// without a bound a sustained inbound burst would keep one pass (and the
/// client lock its caller holds) running indefinitely. Events beyond the
/// bound stay queued for the next pass.
const MAX_TRANSPORT_EVENTS_PER_POLL: usize = 64;

/// Port advertised in Via and Contact when the shell supplies none.
///
/// A TLS-only client has no SIP listening socket (responses and in-dialog
/// requests use the connection it opened to the registrar), so the port is
/// nominal. Port 0 is not a valid SIP port and a registrar rejects it;
/// 5061 is the SIP-over-TLS default (RFC 3261 §19.1.1, §18.1.1), i.e. what a URI
/// with no port means.
const DEFAULT_SIP_TLS_PORT: u16 = 5061;

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
    /// The registrar rejected our OIDC Bearer token (RFC 8898); the
    /// provisioning session should refresh the token and re-register.
    TokenRefreshRequired {
        /// Account ID whose token needs refreshing.
        account_id: String,
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
    /// Incoming call cancelled by remote party before answer.
    IncomingCallCancelled {
        /// Call ID.
        call_id: String,
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
    /// Transfer progress update (RFC 3515 REFER NOTIFY).
    TransferProgress {
        /// Call ID being transferred.
        call_id: String,
        /// Transfer target URI.
        target_uri: String,
        /// SIP status code (100=Trying, 180=Ringing, 200=Success, etc.).
        status_code: u16,
        /// Whether the transfer succeeded.
        is_success: bool,
        /// Whether this is the final status.
        is_final: bool,
    },
    /// DTMF digit received via SIP INFO.
    DtmfReceived {
        /// Call ID.
        call_id: String,
        /// DTMF digit character (0-9, *, #, A-D).
        digit: char,
        /// Duration in timestamp units.
        duration: u16,
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

/// Filesystem locations for persisted client state.
///
/// Desktop builds resolve these automatically via the `directories` crate
/// (see [`ClientApp::new`]). Mobile shells must pass their app-sandbox
/// container paths via [`ClientApp::with_paths`] instead, since mobile
/// platforms have no XDG/Known Folders equivalent visible to this process.
#[derive(Debug, Clone)]
pub struct StoragePaths {
    /// Directory for configuration (`settings.toml`).
    pub config_dir: std::path::PathBuf,
    /// Directory for application data (`contacts.json`, call history).
    pub data_dir: std::path::PathBuf,
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
        let settings_manager = SettingsManager::new()?;
        let contact_manager = ContactManager::new()?;
        Self::from_parts(
            local_sip_addr,
            local_media_addr,
            app_event_tx,
            settings_manager,
            contact_manager,
        )
    }

    /// Creates a new client application with explicit storage locations.
    ///
    /// Mobile shells (iOS/Android) must use this constructor and pass their
    /// app-sandbox container paths; the default [`ClientApp::new`] resolves
    /// desktop config directories that don't exist on mobile platforms.
    /// The directories are created if missing.
    pub fn with_paths(
        local_sip_addr: SocketAddr,
        local_media_addr: SocketAddr,
        app_event_tx: mpsc::Sender<AppEvent>,
        paths: &StoragePaths,
    ) -> AppResult<Self> {
        std::fs::create_dir_all(&paths.config_dir)?;
        std::fs::create_dir_all(&paths.data_dir)?;
        let settings_manager = SettingsManager::with_path(paths.config_dir.join("settings.toml"))?;
        let contact_manager = ContactManager::with_path(paths.data_dir.join("contacts.json"))?;
        Self::from_parts(
            local_sip_addr,
            local_media_addr,
            app_event_tx,
            settings_manager,
            contact_manager,
        )
    }

    /// Shared constructor body: wires agents, channels, and transport around
    /// already-loaded settings and contacts.
    fn from_parts(
        local_sip_addr: SocketAddr,
        local_media_addr: SocketAddr,
        app_event_tx: mpsc::Sender<AppEvent>,
        settings_manager: SettingsManager,
        contact_manager: ContactManager,
    ) -> AppResult<Self> {
        info!(
            sip_addr = %local_sip_addr,
            media_addr = %local_media_addr,
            "Initializing client application"
        );

        #[allow(unused_mut)] // mut only needed with digest-auth feature
        let mut settings_manager = settings_manager;

        // Load any persisted passwords from secure storage (keychain)
        #[cfg(feature = "digest-auth")]
        {
            if let Err(e) = settings_manager.load_persisted_passwords() {
                warn!("Failed to load persisted passwords: {e}");
            } else {
                info!("Persisted passwords loaded from secure storage");
            }
        }

        let contact_manager = Arc::new(RwLock::new(contact_manager));

        // Without a UDP SIP socket nothing replaces an unset port with a
        // bound one, so make sure Via/Contact never carry `:0`.
        let local_sip_addr = advertised_sip_addr(local_sip_addr);

        // Create registration agent channel
        let (reg_event_tx, reg_event_rx) = mpsc::channel(32);
        let registration_agent = RegistrationAgent::new(local_sip_addr, reg_event_tx);

        // Create call manager channel
        let (call_event_tx, call_event_rx) = mpsc::channel(32);
        let mut call_manager = CallManager::new(local_sip_addr, local_media_addr, call_event_tx);
        call_manager.set_contact_manager(contact_manager.clone());

        // Restore saved device preferences from settings
        let audio = &settings_manager.settings().audio;
        if audio.input_device.is_some() || audio.output_device.is_some() {
            info!(
                input = ?audio.input_device,
                output = ?audio.output_device,
                "Restoring saved audio device preferences"
            );
        }
        call_manager.set_preferred_devices(audio.input_device.clone(), audio.output_device.clone());

        // ICE: STUN servers and nomination mode come from [network] settings.
        // TURN needs a password the settings schema does not carry yet, so
        // relay candidates stay unconfigured.
        call_manager.set_ice_config(ice_config_from_settings(
            &settings_manager.settings().network,
        ));

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
            info!(account_id = %account.id, "Auto-registration started successfully");
        }

        info!("Application initialization complete");
        Ok(())
    }

    /// Sets the client certificate for mTLS authentication.
    ///
    /// The certificate chain should be DER-encoded, with the end-entity
    /// certificate first, followed by any intermediate certificates.
    ///
    /// This configures:
    /// - SIP transport for mTLS with the registrar
    /// - Call manager for DTLS-SRTP with media endpoints
    #[allow(clippy::needless_pass_by_value)] // cert_chain is consumed by set_dtls_credentials
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
        self.call_manager
            .set_dtls_credentials(cert_chain, Vec::new());

        // Note: For smart card mTLS, we pass the cert chain without private key.
        // The Windows TLS stack handles smart card signing natively.
        // For software keys, pass the private key via set_client_certificate_with_key().
        info!("Client certificate configured for DTLS");
    }

    /// Sets the client certificate with private key for mTLS authentication.
    ///
    /// Use this for software-based certificates where the private key is available.
    /// For smart card certificates, use `set_client_certificate()` instead.
    pub async fn set_client_certificate_with_key(
        &mut self,
        cert_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        thumbprint: &str,
    ) -> AppResult<()> {
        info!(
            thumbprint = %thumbprint,
            chain_length = cert_chain.len(),
            "Setting client certificate with private key for mTLS"
        );

        self.client_cert_chain = Some(cert_chain.clone());
        self.client_cert_thumbprint = Some(thumbprint.to_string());

        // Configure the SIP transport for mTLS
        if let Some(ref transport) = self.sip_transport {
            transport
                .set_client_certificate(cert_chain.clone(), Some(private_key.clone()))
                .await?;
            info!("SIP transport configured for mTLS");
        }

        // Configure the call manager with the DTLS credentials
        self.call_manager
            .set_dtls_credentials(cert_chain, private_key);

        info!("Client certificate configured for mTLS and DTLS");
        Ok(())
    }

    /// Sets the certificate verification mode for the SIP transport.
    ///
    /// # Arguments
    /// * `mode` - The verification mode to use:
    ///   - `Insecure` - Accept all certificates (development only)
    ///   - `System` - Use platform's trusted CA store
    ///   - `Custom` - Use custom CA certificates
    pub async fn set_verification_mode(&mut self, mode: CertVerificationMode) -> AppResult<()> {
        info!(mode = ?mode, "Setting certificate verification mode");

        if let Some(ref transport) = self.sip_transport {
            transport.set_verification_mode(mode).await?;
        }

        Ok(())
    }

    /// Sets custom trusted CA certificates for server verification.
    ///
    /// Use this for environments with private CAs (e.g., government networks).
    pub async fn set_trusted_ca_certs(&mut self, trusted_certs: Vec<Vec<u8>>) -> AppResult<()> {
        info!(
            cert_count = trusted_certs.len(),
            "Setting custom trusted CA certificates"
        );

        let mode = CertVerificationMode::Custom { trusted_certs };
        self.set_verification_mode(mode).await
    }

    /// Loads PEM-encoded CA certificate(s) from `path` and trusts them for
    /// SIP TLS server verification (private-CA environments; same file as
    /// the provisioning extra-CA setting).
    pub async fn set_trusted_ca_certs_from_pem_file(
        &mut self,
        path: &std::path::Path,
    ) -> AppResult<()> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        let certs: Vec<Vec<u8>> = CertificateDer::pem_file_iter(path)
            .map_err(|e| {
                AppError::Settings(format!("Failed to read CA file {}: {e}", path.display()))
            })?
            .filter_map(Result::ok)
            .map(|cert| cert.to_vec())
            .collect();

        if certs.is_empty() {
            return Err(AppError::Settings(format!(
                "No certificates found in {}",
                path.display()
            )));
        }

        self.set_trusted_ca_certs(certs).await
    }

    /// Returns the configured client certificate thumbprint.
    pub fn client_certificate_thumbprint(&self) -> Option<&str> {
        self.client_cert_thumbprint.as_deref()
    }

    /// Returns whether a client certificate is configured.
    pub const fn has_client_certificate(&self) -> bool {
        self.client_cert_chain.is_some()
    }

    /// Gets the UDP socket and event sender for external UDP receive loop management.
    ///
    /// In Tauri context, `tokio::spawn` doesn't work correctly, so the UDP receive
    /// loop needs to be spawned using `tauri::async_runtime::spawn`. This method
    /// provides the necessary components for that.
    ///
    /// **Important**: This also updates the registration agent's local address
    /// to use the actual bound UDP port for correct Via/Contact headers.
    ///
    /// Returns `None` if the transport is not initialized.
    ///
    /// Only in `insecure-transports` builds: a TLS-only build never binds a
    /// UDP SIP socket.
    // NIST 800-53 Rev5: SC-8, CM-7 (no cleartext SIP listener by default).
    #[cfg(feature = "insecure-transports")]
    pub async fn get_udp_socket_for_receive(
        &mut self,
        use_ipv6: bool,
    ) -> Option<(
        std::sync::Arc<tokio::net::UdpSocket>,
        tokio::sync::mpsc::Sender<TransportEvent>,
    )> {
        if let Some(ref transport) = self.sip_transport {
            match transport.get_or_create_udp_socket(use_ipv6).await {
                Ok((socket, _is_new)) => {
                    // Update the registration agent's local address with the actual bound address
                    // This ensures Via/Contact headers have the correct port
                    if let Ok(local_addr) = socket.local_addr() {
                        info!(local_addr = %local_addr, "Updating registration agent with actual UDP socket address");
                        self.registration_agent.set_local_addr(local_addr);
                    }
                    Some((socket, transport.event_sender()))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get UDP socket for receive loop");
                    None
                }
            }
        } else {
            None
        }
    }

    /// Registers a SIP account.
    pub async fn register_account(&mut self, account: &SipAccount) -> AppResult<()> {
        info!(account_id = %account.id, "Registering account");

        // Default builds are TLS-only (CNSA 2.0). UDP/TCP exist for lab
        // and commercial-provider testing and require an explicit
        // `insecure-transports` build feature.
        #[cfg(not(feature = "insecure-transports"))]
        if account.transport != client_types::TransportPreference::TlsOnly {
            error!(
                account_id = %account.id,
                transport = %account.transport,
                "Non-TLS SIP transport rejected (TLS-only build)"
            );
            return Err(AppError::Settings(format!(
                "{} SIP transport is disabled in this build — TLS only. \
                 Rebuild with --features insecure-transports for lab testing.",
                account.transport
            )));
        }

        self.state = AppState::Registering;
        self.current_account_id = Some(account.id.clone());

        // TLS connections are made to resolved socket addresses, so tell the
        // transport which DNS name to present as SNI and verify the server
        // certificate against (IP-literal registrars keep the IP fallback).
        // RFC 3263 §4.4 / RFC 5922 §4: this is the SIP domain from the AoR's
        // registrar URI, never the NAPTR/SRV target (resolution returns only a
        // socket address), so spoofed SRV cannot redirect identity checks.
        if let Some(ref transport) = self.sip_transport {
            let host = account
                .registrar_uri
                .parse::<proto_sip::uri::SipUri>()
                .ok()
                .map(|uri| uri.host)
                .filter(|host| host.parse::<std::net::IpAddr>().is_err());
            transport.set_tls_server_name(host).await;
        }

        // Configure call manager with account
        self.call_manager.configure_account(account);

        // Start registration
        if let Err(e) = self.registration_agent.register(account).await {
            error!(account_id = %account.id, error = %e, "Registration failed");
            return Err(AppError::Sip(e.to_string()));
        }

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
            warn!(
                current_state = ?self.state,
                "Cannot make call: not registered"
            );
            let state = self.state;
            return Err(AppError::Sip(format!(
                "Cannot make call: not registered (current state: {state:?})"
            )));
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

    /// Accepts an incoming call.
    ///
    /// Sends a 200 OK response with SDP answer.
    pub async fn accept_incoming_call(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Accepting incoming call");
        self.call_manager.accept_incoming_call(call_id).await?;
        self.state = AppState::InCall;
        Ok(())
    }

    /// Rejects an incoming call.
    ///
    /// Sends a 486 Busy Here or 603 Decline response.
    pub async fn reject_incoming_call(&mut self, call_id: &str) -> AppResult<()> {
        info!(call_id = %call_id, "Rejecting incoming call");
        self.call_manager.reject_incoming_call(call_id, false).await
    }

    /// Toggles mute state.
    pub fn toggle_mute(&mut self) -> bool {
        self.call_manager.toggle_mute()
    }

    /// Returns whether currently muted.
    pub const fn is_muted(&self) -> bool {
        self.call_manager.is_muted()
    }

    /// Sends a DTMF digit on the active call.
    ///
    /// Uses RFC 4733 telephone-event when available, falling back to SIP INFO
    /// plus in-band tones when telephone-event is not negotiated.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send (0-9, *, #, A-D)
    pub async fn send_dtmf(&mut self, digit: DtmfDigit) -> AppResult<()> {
        // Use standard DTMF duration of 100ms
        const DTMF_DURATION_MS: u32 = 100;
        self.call_manager.send_dtmf(digit, DTMF_DURATION_MS).await
    }

    /// Transfers the active call to another party (blind transfer).
    ///
    /// Sends a REFER request per RFC 3515 to transfer the call to the
    /// specified target URI.
    ///
    /// # Arguments
    /// * `transfer_target` - SIP URI of the transfer destination (e.g., "sips:bob@example.com")
    pub async fn transfer_call(&mut self, transfer_target: &str) -> AppResult<()> {
        self.call_manager.transfer_call(transfer_target).await
    }

    /// Switches the input (microphone) device during an active call.
    ///
    /// This allows changing the microphone mid-call without disconnecting.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new input device, or None for default
    pub fn switch_input_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        self.call_manager.switch_input_device(device_name)
    }

    /// Switches the output (speaker) device during an active call.
    ///
    /// This allows changing the speaker mid-call without disconnecting.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new output device, or None for default
    pub fn switch_output_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        self.call_manager.switch_output_device(device_name)
    }

    /// Returns the current input device name for the active call.
    pub fn current_input_device(&self) -> Option<String> {
        self.call_manager.current_input_device()
    }

    /// Returns the current output device name for the active call.
    pub fn current_output_device(&self) -> Option<String> {
        self.call_manager.current_output_device()
    }

    /// Toggles hold state for the active call.
    ///
    /// Returns `true` if call is now on hold, `false` if resumed.
    pub async fn toggle_hold(&mut self) -> AppResult<bool> {
        self.call_manager.toggle_hold().await
    }

    /// Changes the codec for an active call via SIP re-INVITE.
    ///
    /// The call must be in Connected state. The audio session will be
    /// automatically restarted with the new codec when the remote accepts.
    pub async fn change_codec(&mut self, call_id: &str, codec: CodecPreference) -> AppResult<()> {
        self.call_manager.change_codec(call_id, codec).await
    }

    /// Switches focus to a different call.
    ///
    /// The current focused call will be put on hold if it's connected,
    /// and the target call will be resumed if it's on hold.
    pub async fn switch_to_call(&mut self, call_id: &str) -> AppResult<()> {
        self.call_manager.switch_to_call(call_id).await
    }

    /// Returns info for all active calls (including held).
    pub fn all_call_info(&self) -> Vec<CallInfo> {
        self.call_manager.all_call_info()
    }

    /// Returns the current application state.
    pub const fn state(&self) -> AppState {
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

    /// Returns call quality metrics for the active call.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn call_quality_metrics(&self) -> Option<CallQualityMetrics> {
        let stats = self.call_manager.audio_stats()?;
        let packets_lost = stats.jitter_stats.packets_lost;
        let packets_received = stats.rx_stats.packets_received;
        let packet_loss_rate = if packets_received > 0 {
            packets_lost as f64 / (packets_received + packets_lost) as f64
        } else {
            0.0
        };

        Some(CallQualityMetrics::from_stats(
            stats.tx_stats.packets_sent,
            packets_received,
            packets_lost,
            packet_loss_rate,
            stats.jitter_stats.average_jitter_ms,
            stats.jitter_stats.current_depth_ms,
            stats.capture_underruns,
            stats.playback_underruns,
            stats.rx_stats.srtp_errors,
            stats.rtt_ms,
            stats.codec_name,
        ))
    }

    /// Returns the settings manager.
    pub const fn settings(&self) -> &SettingsManager {
        &self.settings_manager
    }

    /// Returns mutable reference to settings manager.
    pub const fn settings_mut(&mut self) -> &mut SettingsManager {
        &mut self.settings_manager
    }

    /// Returns the contact manager.
    pub const fn contacts(&self) -> &Arc<RwLock<ContactManager>> {
        &self.contact_manager
    }

    /// Handles a registration event.
    pub async fn handle_registration_event(&mut self, event: RegistrationEvent) -> AppResult<()> {
        match event {
            RegistrationEvent::StateChanged { account_id, state } => {
                debug!(account_id = %account_id, state = ?state, "Registration state changed");

                // Update app state based on registration
                match state {
                    RegistrationState::Registered if self.state == AppState::Registering => {
                        self.state = AppState::Registered;
                    }
                    RegistrationState::Failed | RegistrationState::CertificateInvalid
                        if self.state == AppState::Registering =>
                    {
                        self.state = AppState::Ready;
                    }
                    RegistrationState::Unregistered if self.state == AppState::Registered => {
                        self.state = AppState::Ready;
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
            RegistrationEvent::SendRequest {
                request,
                destination,
            } => {
                debug!(
                    method = %request.method,
                    destination = %destination,
                    "Processing SendRequest event"
                );

                // Send via SIP transport
                if let Some(ref transport) = self.sip_transport {
                    let result =
                        send_request_on_account_transport(transport, &request, destination).await;

                    if let Err(e) = result {
                        error!(error = %e, "Failed to send SIP request");
                        let _ = self
                            .app_event_tx
                            .send(AppEvent::Error {
                                message: format!("Failed to send registration: {e}"),
                            })
                            .await;
                    }
                } else {
                    warn!("SIP transport not initialized");
                }
            }
            RegistrationEvent::TokenRefreshRequired { account_id } => {
                debug!(account_id = %account_id, "Bearer token refresh requested by registrar");
                // Forward to the GUI/provisioning session, which owns the
                // OIDC refresh + re-register.
                let _ = self
                    .app_event_tx
                    .send(AppEvent::TokenRefreshRequired { account_id })
                    .await;
            }
        }

        Ok(())
    }

    /// Handles a call manager event.
    #[allow(clippy::too_many_lines)]
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
                    CallState::Terminated if self.state == AppState::InCall => {
                        self.state = AppState::Registered;
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
            CallManagerEvent::IncomingCallCancelled { call_id } => {
                info!(call_id = %call_id, "Incoming call cancelled by remote party");

                let _ = self
                    .app_event_tx
                    .send(AppEvent::IncomingCallCancelled { call_id })
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
            CallManagerEvent::CallConnected { .. } | CallManagerEvent::MediaStateChanged { .. } => {
                // Already handled via state change / internal event, not forwarded to GUI
            }
            CallManagerEvent::Error { call_id, message } => {
                error!(call_id = ?call_id, message = %message, "Call error");

                let _ = self.app_event_tx.send(AppEvent::Error { message }).await;
            }
            CallManagerEvent::SendResponse {
                response,
                destination,
                transport: received_on,
            } => {
                // Forward response to transport layer on the transport the
                // request arrived on (RFC 3261 §18.2.2). The Via text is
                // peer-controlled and is never used to pick the transport: a
                // request received over TLS is answered over TLS only.
                // NIST 800-53 Rev5: SC-8, SC-8(1); SC-23 (response bound to the
                // receiving connection only; REGISTER responses are not yet
                // matched to their transaction).
                info!(
                    status = response.status.code(),
                    destination = %destination,
                    transport = ?received_on,
                    "Sending SIP response"
                );

                if let Some(transport) = &self.sip_transport {
                    let result = match received_on {
                        SipTransportKind::Tls => {
                            transport.send_response(&response, destination).await
                        }
                        #[cfg(feature = "insecure-transports")]
                        SipTransportKind::Udp => {
                            transport.send_response_udp(&response, destination).await
                        }
                    };

                    match &result {
                        Ok(()) => info!(
                            status = response.status.code(),
                            destination = %destination,
                            "SIP response sent successfully"
                        ),
                        Err(e) => error!(error = %e, "Failed to send SIP response"),
                    }
                } else {
                    warn!("No SIP transport configured, cannot send response");
                }
            }
            CallManagerEvent::TransferProgress {
                call_id,
                target_uri,
                status_code,
                is_success,
                is_final,
            } => {
                info!(
                    call_id = %call_id,
                    target = %target_uri,
                    status_code = status_code,
                    is_success = is_success,
                    is_final = is_final,
                    "Transfer progress event"
                );

                // Forward to GUI
                let _ = self
                    .app_event_tx
                    .send(AppEvent::TransferProgress {
                        call_id,
                        target_uri,
                        status_code,
                        is_success,
                        is_final,
                    })
                    .await;
            }
            CallManagerEvent::DtmfReceived {
                call_id,
                digit,
                duration,
            } => {
                info!(call_id = %call_id, digit = %digit, duration = duration, "DTMF received via SIP INFO");

                let _ = self
                    .app_event_tx
                    .send(AppEvent::DtmfReceived {
                        call_id,
                        digit,
                        duration,
                    })
                    .await;
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

                // Route response to appropriate agent based on CSeq method
                // For REGISTER responses, route to registration agent
                // For INVITE/BYE/CANCEL responses, route to call manager
                let cseq_value = response
                    .headers
                    .get_value(&proto_sip::header::HeaderName::CSeq);
                let is_register_response =
                    cseq_value.is_some_and(|v| v.to_uppercase().contains("REGISTER"));

                if is_register_response {
                    if let Some(ref account_id) = self.current_account_id
                        && let Err(e) = self
                            .registration_agent
                            .handle_response(&response, account_id)
                            .await
                    {
                        warn!(error = %e, "Failed to handle registration response");
                    }
                } else {
                    // Route to call manager for call-related responses
                    if let Err(e) = self.call_manager.handle_sip_response(&response).await {
                        warn!(error = %e, "Failed to handle call response");
                    }
                }
            }
            TransportEvent::RequestReceived {
                request,
                source,
                transport,
            } => {
                info!(
                    source = %source,
                    method = %request.method,
                    "Received incoming SIP request"
                );

                // Route to call manager for handling (INVITE, BYE, CANCEL, etc.)
                if let Err(e) = self
                    .call_manager
                    .handle_sip_request_from(&request, source, transport)
                    .await
                {
                    warn!(error = %e, "Failed to handle incoming SIP request");
                }
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
        trace!("poll_events called");

        // Events queued since the last pass (UI commands, timers).
        self.drain_internal_events().await?;

        // Transport events, one at a time, bounded per pass. The receiver
        // stays in `self` for the whole pass (the borrow ends when
        // `try_recv` returns), so no error, early return or unwind in a
        // handler can lose it and silence inbound SIP.
        // NIST 800-53 Rev5: SC-5 (at most MAX_TRANSPORT_EVENTS_PER_POLL
        // transport events per pass; receiver retained across errors and
        // cancellation). The pump still awaits the shell event channel.
        // POAM: POA&M-314 — awaited app_event_tx sends park the pump while the shell does
        // not drain its event channel.
        for _ in 0..MAX_TRANSPORT_EVENTS_PER_POLL {
            let Some(event) = self.next_transport_event() else {
                break;
            };
            self.handle_transport_event(event).await?;
            // Everything this event produced is sent (requests, responses)
            // or forwarded before the next one is taken: see
            // `drain_internal_events`.
            self.drain_internal_events().await?;
        }

        // Drive call-agent timers (491 glare re-INVITE retry, RFC 3261 §14.1)
        self.call_manager.process_timers().await?;

        // Check for expiring registrations and trigger refresh
        self.registration_agent
            .check_expiring()
            .await
            .map_err(|e| AppError::Sip(e.to_string()))?;

        Ok(())
    }

    /// Takes the next queued transport event, if any.
    fn next_transport_event(&mut self) -> Option<TransportEvent> {
        self.transport_event_rx.as_mut()?.try_recv().ok()
    }

    /// Drains the registration, call-agent and call-manager queues.
    ///
    /// These are bounded channels whose only reader is this pump, while
    /// their writers (`RegistrationAgent`, `CallAgent`, `CallManager`) run
    /// inside the pump's own handlers and await capacity. They are therefore
    /// drained after every single input event, and the call-manager queue
    /// after every call-agent event, so the depth of each queue is bounded
    /// by what one event can emit (a handful) and not by how many events
    /// arrive in a pass. Draining only after all transport events had been
    /// handled let 33 queued responses park the pump on its own channel.
    // NIST 800-53 Rev5: SC-5 (bounded queues; no self-deadlock under a burst).
    async fn drain_internal_events(&mut self) -> AppResult<()> {
        // Empty the call-manager queue first: commands may have left it
        // full, and each call-agent event below can add to it with an
        // awaited send (PERF-R1-001).
        // NIST 800-53 Rev5: SC-5 (no self-deadlock on a queue left full by commands).
        self.drain_call_manager_events().await?;

        // Registration events (NLL lets the temporary borrow on
        // reg_event_rx expire before the handler borrows &mut self).
        while let Ok(event) = self.reg_event_rx.try_recv() {
            self.handle_registration_event(event).await?;
        }

        // Call agent events: send requests via transport, track state
        let call_events = self.call_manager.poll_call_events();
        if !call_events.is_empty() {
            info!(count = call_events.len(), "Processing call agent events");
        }
        for event in call_events {
            self.handle_call_agent_event(event).await?;
            self.drain_call_manager_events().await?;
        }

        self.drain_call_manager_events().await
    }

    /// Processes queued call manager events (state changes, responses to send).
    async fn drain_call_manager_events(&mut self) -> AppResult<()> {
        while let Ok(event) = self.call_event_rx.try_recv() {
            self.handle_call_event(event).await?;
        }
        Ok(())
    }

    /// Handles a call agent event.
    #[allow(clippy::too_many_lines)]
    async fn handle_call_agent_event(&mut self, event: client_sip_ua::CallEvent) -> AppResult<()> {
        use client_sip_ua::CallEvent;

        match event {
            CallEvent::SendRequest {
                request,
                destination,
            } => {
                // Send call signaling (INVITE, BYE, CANCEL, ACK) via transport
                info!(
                    method = %request.method,
                    destination = %destination,
                    "Processing call SendRequest event"
                );

                if let Some(ref transport) = self.sip_transport {
                    let result =
                        send_request_on_account_transport(transport, &request, destination).await;

                    match &result {
                        Ok(()) => info!(method = %request.method, "Call request sent successfully"),
                        Err(e) => {
                            error!(error = %e, method = %request.method, "Failed to send call request");
                        }
                    }

                    if let Err(e) = result {
                        let _ = self
                            .app_event_tx
                            .send(AppEvent::Error {
                                message: format!("Failed to send call request: {e}"),
                            })
                            .await;
                    }
                } else {
                    warn!("SIP transport not initialized");
                }
            }
            CallEvent::SendResponse {
                response,
                destination,
            } => {
                // Send response (for incoming calls)
                // Note: Response sending requires adding send_response to SipTransport
                // For now, log that we received a response to send
                debug!(
                    destination = %destination,
                    status = response.status.code(),
                    "Would send SIP response (incoming call responses not yet implemented)"
                );
            }
            CallEvent::StateChanged {
                call_id,
                state,
                info,
            } => {
                // Route to call manager for state tracking
                if let Err(e) = self
                    .call_manager
                    .handle_call_event(CallEvent::StateChanged {
                        call_id,
                        state,
                        info,
                    })
                    .await
                {
                    warn!(error = %e, "Failed to handle call state change");
                }
            }
            CallEvent::SdpOfferReceived { call_id, sdp } => {
                if let Err(e) = self
                    .call_manager
                    .handle_call_event(CallEvent::SdpOfferReceived { call_id, sdp })
                    .await
                {
                    warn!(error = %e, "Failed to handle SDP offer");
                }
            }
            CallEvent::SdpAnswerReceived { call_id, sdp } => {
                if let Err(e) = self
                    .call_manager
                    .handle_call_event(CallEvent::SdpAnswerReceived { call_id, sdp })
                    .await
                {
                    warn!(error = %e, "Failed to handle SDP answer");
                }
            }
            CallEvent::TransferProgress {
                call_id,
                target_uri,
                status,
                is_final,
            } => {
                // Route to call manager for transfer tracking
                if let Err(e) = self
                    .call_manager
                    .handle_call_event(CallEvent::TransferProgress {
                        call_id,
                        target_uri,
                        status,
                        is_final,
                    })
                    .await
                {
                    warn!(error = %e, "Failed to handle transfer progress");
                }
            }
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
        drop(contacts);

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

/// Returns the signaling address to advertise in Via and Contact: the
/// configured one, with [`DEFAULT_SIP_TLS_PORT`] in place of an unset port.
// RFC 3261 §19.1.1, §18.1.1: no port means the transport default. proto-sip
// rejects port 0, so an unset port is never advertised as 0.
const fn advertised_sip_addr(configured: SocketAddr) -> SocketAddr {
    if configured.port() == 0 {
        SocketAddr::new(configured.ip(), DEFAULT_SIP_TLS_PORT)
    } else {
        configured
    }
}

/// Sends a locally built request on the account's signaling transport.
///
/// Default builds are TLS-only: there is no other send path to select. With
/// `insecure-transports`, UDP is used when this client wrote `UDP` into the
/// top Via of the request it built from the account's transport preference;
/// that text is ours, not a peer's.
// NIST 800-53 Rev5: SC-8, SC-8(1) (TLS-only signaling in default builds).
async fn send_request_on_account_transport(
    transport: &SipTransport,
    request: &SipRequest,
    destination: SocketAddr,
) -> AppResult<()> {
    #[cfg(feature = "insecure-transports")]
    if request
        .headers
        .get_value(&HeaderName::Via)
        .is_some_and(|via| via.contains("/UDP"))
    {
        return transport.send_request_udp(request, destination).await;
    }

    transport.send_request(request, destination).await
}

/// Builds the ICE configuration from the persisted network settings.
///
/// `stun_server` accepts `stun:host[:port]` or `host[:port]` (default port
/// 3478) and is resolved once here; an unresolvable server is logged and
/// skipped so a bad setting cannot prevent calls (host candidates still
/// work). `enable_ice = false` yields a configuration with no servers; the
/// media session still falls back to the SDP address when checks cannot run.
fn ice_config_from_settings(network: &crate::settings::NetworkSettings) -> proto_ice::IceConfig {
    use std::net::ToSocketAddrs;
    let mut config = proto_ice::IceConfig {
        aggressive_nomination: network.aggressive_nomination,
        ..proto_ice::IceConfig::default()
    };
    if !network.enable_ice {
        return config;
    }
    if let Some(uri) = network
        .stun_server
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        let host_port = uri.strip_prefix("stun:").unwrap_or(uri);
        let has_port = host_port.matches(':').count() == 1
            && host_port
                .rsplit(':')
                .next()
                .is_some_and(|p| p.parse::<u16>().is_ok());
        let target = if has_port {
            host_port.to_string()
        } else {
            format!("{host_port}:3478")
        };
        match target.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    info!(server = %uri, resolved = %addr, "STUN server configured for ICE");
                    config.stun_servers.push(addr);
                } else {
                    warn!(server = %uri, "STUN server resolved to no addresses; ignored");
                }
            }
            Err(e) => warn!(server = %uri, error = %e, "STUN server did not resolve; ignored"),
        }
    }
    config
}

#[cfg(test)]
mod tests {
    #[test]
    fn ice_config_follows_network_settings() {
        let mut network = crate::settings::NetworkSettings {
            aggressive_nomination: true,
            stun_server: Some("stun:127.0.0.1:3479".to_string()),
            ..Default::default()
        };
        let cfg = super::ice_config_from_settings(&network);
        assert!(cfg.aggressive_nomination);
        assert_eq!(cfg.stun_servers, vec!["127.0.0.1:3479".parse().unwrap()]);

        // Default STUN port, scheme optional.
        network.stun_server = Some("127.0.0.1".to_string());
        assert_eq!(
            super::ice_config_from_settings(&network).stun_servers,
            vec!["127.0.0.1:3478".parse().unwrap()]
        );

        // ICE disabled: no servers regardless of the setting.
        network.enable_ice = false;
        assert_eq!(
            super::ice_config_from_settings(&network).stun_servers,
            Vec::<std::net::SocketAddr>::new()
        );
    }

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

    use proto_sip::message::SipMessage;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A `ClientApp` over `dir` with default settings and no account. It
    /// never reads the user profile or the OS keychain, in any feature set.
    fn hermetic_app(dir: &std::path::Path, app_event_tx: mpsc::Sender<AppEvent>) -> ClientApp {
        let settings = SettingsManager::without_credential_store(dir.join("settings.toml"));
        let contacts = ContactManager::with_path(dir.join("contacts.json")).unwrap();
        ClientApp::from_parts(
            "127.0.0.1:5061".parse().unwrap(),
            "127.0.0.1:16384".parse().unwrap(),
            app_event_tx,
            settings,
            contacts,
        )
        .unwrap()
    }

    fn peer() -> SocketAddr {
        "192.0.2.50:5061".parse().unwrap()
    }

    fn parse_request(text: &str) -> SipRequest {
        match SipMessage::parse(text.as_bytes()).unwrap() {
            SipMessage::Request(request) => request,
            SipMessage::Response(_) => panic!("expected a request"),
        }
    }

    /// A transport event for `text` as received from `source` over TLS.
    fn tls_request(text: &str, source: SocketAddr) -> TransportEvent {
        TransportEvent::RequestReceived {
            request: parse_request(text),
            source,
            transport: SipTransportKind::Tls,
        }
    }

    fn invite(from: &str, call_id: &str) -> String {
        format!(
            "INVITE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS 192.0.2.50:5061;branch=z9hG4bK{call_id}\r\n\
             Max-Forwards: 70\r\n\
             From: {from}\r\n\
             To: <sips:testuser@example.com>\r\n\
             Call-ID: {call_id}@192.0.2.50\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sips:caller@192.0.2.50:5061>\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// An INFO carrying one DTMF digit: the call manager answers it (one
    /// queued response) and reports the digit (one queued event).
    fn dtmf_info(n: usize) -> String {
        let body = "Signal=5\r\nDuration=160\r\n";
        format!(
            "INFO sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS 192.0.2.50:5061;branch=z9hG4bKinfo{n}\r\n\
             Max-Forwards: 70\r\n\
             From: <sips:caller@example.com>;tag=remote\r\n\
             To: <sips:testuser@example.com>;tag=local\r\n\
             Call-ID: burst@192.0.2.50\r\n\
             CSeq: {cseq} INFO\r\n\
             Content-Type: application/dtmf-relay\r\n\
             Content-Length: {len}\r\n\
             \r\n\
             {body}",
            cseq = n + 1,
            len = body.len()
        )
    }

    /// A BYE for a dialog that does not exist (answered with 481) whose Via
    /// names `via_transport` and `via_addr`.
    fn unmatched_bye(via_transport: &str, via_addr: SocketAddr) -> String {
        format!(
            "BYE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/{via_transport} {via_addr};branch=z9hG4bKnodialog\r\n\
             Max-Forwards: 70\r\n\
             From: <sips:caller@example.com>;tag=remote\r\n\
             To: <sips:testuser@example.com>;tag=stale\r\n\
             Call-ID: no-such-dialog@192.0.2.50\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    fn transport_sender(app: &ClientApp) -> mpsc::Sender<TransportEvent> {
        app.sip_transport.as_ref().unwrap().event_sender()
    }

    /// NIST-001 / SEC-S-001: in a TLS-only build a request whose Via says
    /// `UDP` is still answered on the transport it arrived on. Nothing is
    /// sent to the peer over UDP (the old code bound a UDP socket here and
    /// sent the response in cleartext).
    #[cfg(not(feature = "insecure-transports"))]
    #[tokio::test]
    async fn test_tls_only_build_never_answers_over_udp() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let mut app = hermetic_app(dir.path(), app_tx);

        // The "peer": where a cleartext response would land.
        let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observer_addr = observer.local_addr().unwrap();

        transport_sender(&app)
            .send(tls_request(
                &unmatched_bye("UDP", observer_addr),
                observer_addr,
            ))
            .await
            .unwrap();
        app.poll_events().await.unwrap();

        let mut buf = [0u8; 2048];
        let leaked =
            tokio::time::timeout(Duration::from_millis(300), observer.recv_from(&mut buf)).await;
        assert!(
            leaked.is_err(),
            "TLS-only build sent a SIP response over UDP"
        );
    }

    /// With `insecure-transports`, the response goes back on the transport
    /// carried by the event, whatever the request's Via text says.
    #[cfg(feature = "insecure-transports")]
    #[tokio::test]
    async fn test_response_follows_receive_transport_not_via_text() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let mut app = hermetic_app(dir.path(), app_tx);

        let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observer_addr = observer.local_addr().unwrap();
        let mut buf = [0u8; 2048];

        // Received over TLS, Via says UDP: nothing leaves over UDP.
        transport_sender(&app)
            .send(tls_request(
                &unmatched_bye("UDP", observer_addr),
                observer_addr,
            ))
            .await
            .unwrap();
        app.poll_events().await.unwrap();
        let leaked =
            tokio::time::timeout(Duration::from_millis(300), observer.recv_from(&mut buf)).await;
        assert!(
            leaked.is_err(),
            "request received over TLS answered over UDP"
        );

        // Received over UDP, Via says TLS: answered over UDP to the source.
        transport_sender(&app)
            .send(TransportEvent::RequestReceived {
                request: parse_request(&unmatched_bye("TLS", observer_addr)),
                source: observer_addr,
                transport: SipTransportKind::Udp,
            })
            .await
            .unwrap();
        app.poll_events().await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), observer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(buf[..n].starts_with(b"SIP/2.0 481"));
    }

    /// With no UDP SIP socket, nothing supplies a local signaling port. A
    /// shell that passes port 0 (the desktop GUI does) must not make the
    /// REGISTER advertise `:0`, which is not a valid SIP port: the Via and
    /// Contact have to survive the parser a registrar uses.
    #[tokio::test]
    async fn test_register_without_udp_socket_advertises_valid_port() {
        use proto_sip::header_params::{NameAddr, ViaHeader};

        let dir = tempfile::tempdir().unwrap();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let settings = SettingsManager::without_credential_store(dir.path().join("settings.toml"));
        let contacts = ContactManager::with_path(dir.path().join("contacts.json")).unwrap();
        let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut app =
            ClientApp::from_parts(unspecified, unspecified, app_tx, settings, contacts).unwrap();

        let account = SipAccount::new(
            "test-account",
            "Test User",
            "sips:testuser@example.com",
            "sips:192.0.2.1:5061",
        );
        app.register_account(&account).await.unwrap();

        // The REGISTER is queued for the pump; inspect it without sending.
        let register = std::iter::from_fn(|| app.reg_event_rx.try_recv().ok())
            .find_map(|event| match event {
                RegistrationEvent::SendRequest { request, .. } => Some(request),
                _ => None,
            })
            .unwrap();

        let via: ViaHeader = register
            .headers
            .get_value(&proto_sip::header::HeaderName::Via)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(via.port, Some(DEFAULT_SIP_TLS_PORT));

        let contact: NameAddr = register
            .headers
            .get_value(&proto_sip::header::HeaderName::Contact)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(contact.uri.port, Some(DEFAULT_SIP_TLS_PORT));
    }

    /// SEC-S-002 / QA-001: a From with `>` before `<` used to panic inside
    /// the pump with the transport receiver taken out of `self`. The
    /// receiver stays in place across that message, across a handler error
    /// (unparsable From, answered 400), and inbound SIP keeps flowing.
    #[tokio::test]
    async fn test_transport_receiver_survives_handler_error() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);

        for (from, call_id) in [
            (">a<sips:first@example.com>;tag=1", "gtlt"),
            ("Bob <sips:broken@example.com;tag=1", "unclosed"),
            ("<sips:second@example.com>;tag=1", "valid"),
        ] {
            transport_tx
                .send(tls_request(&invite(from, call_id), peer()))
                .await
                .unwrap();
            app.poll_events().await.unwrap();
            assert!(
                app.transport_event_rx.is_some(),
                "receiver lost after {from:?}"
            );
        }

        let mut ringing = Vec::new();
        while let Ok(event) = app_rx.try_recv() {
            if let AppEvent::IncomingCall { remote_uri, .. } = event {
                ringing.push(remote_uri);
            }
        }
        assert_eq!(
            ringing,
            ["sips:first@example.com", "sips:second@example.com"]
        );
    }

    /// The pump can be cancelled mid-handler (a caller-side timeout, a task
    /// abort). The receiver used to live in a local for the duration of the
    /// pass and was dropped with the future; it must stay in `self`.
    #[tokio::test]
    async fn test_transport_receiver_survives_cancelled_pass() {
        let dir = tempfile::tempdir().unwrap();
        // One slot: the second forwarded event parks the handler.
        let (app_tx, mut app_rx) = mpsc::channel(1);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);

        for n in 0..2 {
            transport_tx
                .send(TransportEvent::Error {
                    message: format!("error {n}"),
                })
                .await
                .unwrap();
        }
        let cancelled = tokio::time::timeout(Duration::from_millis(100), app.poll_events()).await;
        assert!(cancelled.is_err(), "the pass should have been parked");
        assert!(
            app.transport_event_rx.is_some(),
            "receiver lost when the pass was cancelled"
        );

        // Inbound SIP still works afterwards.
        while app_rx.try_recv().is_ok() {}
        transport_tx
            .send(tls_request(
                &invite("<sips:caller@example.com>;tag=1", "after-cancel"),
                peer(),
            ))
            .await
            .unwrap();
        app.poll_events().await.unwrap();
        assert!(matches!(
            app_rx.try_recv(),
            Ok(AppEvent::IncomingCall { .. })
        ));
    }

    /// Runs exactly one `poll_events()` pass while `requests` DTMF INFO
    /// requests are fed into the 32-slot transport queue as fast as it
    /// accepts them (the receive task's role). Returns how many had been
    /// fully handled when the pass returned, and how many were left queued.
    async fn handled_in_one_pass(requests: usize) -> (usize, usize) {
        let dir = tempfile::tempdir().unwrap();
        // One slot, drained by another task: the pump yields at every
        // forwarded event, which lets the feeder refill the transport queue
        // while the pass is still running.
        let (app_tx, mut app_rx) = mpsc::channel(1);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);
        let probe = transport_tx.clone();

        let handled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&handled);
        let drainer = tokio::spawn(async move {
            while let Some(event) = app_rx.recv().await {
                if matches!(event, AppEvent::DtmfReceived { .. }) {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let feeder = tokio::spawn(async move {
            for n in 0..requests {
                let event = tls_request(&dtmf_info(n), peer());
                if transport_tx.send(event).await.is_err() {
                    return;
                }
            }
        });

        // Start the pass with the transport queue full.
        while probe.capacity() > 0 && !feeder.is_finished() {
            tokio::task::yield_now().await;
        }

        let pass = tokio::time::timeout(Duration::from_secs(5), app.poll_events()).await;
        assert!(
            pass.is_ok(),
            "poll_events blocked on a queue that only it drains"
        );
        pass.unwrap().unwrap();

        tokio::time::timeout(Duration::from_secs(5), feeder)
            .await
            .unwrap()
            .unwrap();
        // Let the drainer take the last forwarded event.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drainer.abort();

        let left = std::iter::from_fn(|| app.next_transport_event()).count();
        (handled.load(Ordering::SeqCst), left)
    }

    /// PERF-001: more than 32 response-producing requests in one pump pass.
    /// Each INFO queues two call-manager events, so the old order (handle
    /// every transport event, then drain) filled the 32-slot channel at the
    /// 17th request and the pump waited forever for capacity only it frees.
    #[tokio::test]
    async fn test_pump_handles_more_than_32_requests_in_one_pass() {
        const REQUESTS: usize = 40;
        const { assert!(REQUESTS > 32 && REQUESTS <= MAX_TRANSPORT_EVENTS_PER_POLL) };

        let (handled, left) = handled_in_one_pass(REQUESTS).await;
        assert_eq!(handled, REQUESTS, "every request answered in the one pass");
        assert_eq!(left, 0);
    }

    /// A pass is bounded: under a sustained burst it handles
    /// `MAX_TRANSPORT_EVENTS_PER_POLL` events and returns, leaving the rest
    /// queued for the next pass.
    #[tokio::test]
    async fn test_pump_pass_is_bounded() {
        let requests = MAX_TRANSPORT_EVENTS_PER_POLL + 10;

        let (handled, left) = handled_in_one_pass(requests).await;
        assert_eq!(handled, MAX_TRANSPORT_EVENTS_PER_POLL);
        assert_eq!(left, 10);
    }

    // ---- QA round 1 ----

    fn qa_invite(from: &str, contact: &str, call_id: &str) -> String {
        format!(
            "INVITE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS 192.0.2.50:5061;branch=z9hG4bK{call_id}\r\n\
             Max-Forwards: 70\r\n\
             From: {from}\r\n\
             To: <sips:testuser@example.com>\r\n\
             Call-ID: {call_id}@192.0.2.50\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: {contact}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// An INFO whose DTMF duration is `duration`, so deliveries can be told
    /// apart and their order checked.
    fn qa_dtmf_info(n: usize, duration: u16) -> String {
        let body = format!("Signal=7\r\nDuration={duration}\r\n");
        format!(
            "INFO sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS 192.0.2.50:5061;branch=z9hG4bKqainfo{n}\r\n\
             Max-Forwards: 70\r\n\
             From: <sips:caller@example.com>;tag=remote\r\n\
             To: <sips:testuser@example.com>;tag=local\r\n\
             Call-ID: qa-burst@192.0.2.50\r\n\
             CSeq: {cseq} INFO\r\n\
             Content-Type: application/dtmf-relay\r\n\
             Content-Length: {len}\r\n\
             \r\n\
             {body}",
            cseq = n + 1,
            len = body.len()
        )
    }

    /// One pump pass under a timeout: a pass that blocks on a queue only
    /// the pump drains never returns, and the timeout turns that into a
    /// test failure instead of a hung test run.
    async fn qa_poll(app: &mut ClientApp, what: &str) {
        tokio::time::timeout(Duration::from_secs(5), app.poll_events())
            .await
            .unwrap_or_else(|_| panic!("poll_events blocked: {what}"))
            .unwrap_or_else(|e| panic!("poll_events failed: {what}: {e}"));
    }

    /// The application events forwarded so far, in order.
    fn qa_drain_app_events(app_rx: &mut mpsc::Receiver<AppEvent>) -> Vec<AppEvent> {
        std::iter::from_fn(|| app_rx.try_recv().ok()).collect()
    }

    /// B1 / QA-002: a TLS-only build refuses UDP and TCP accounts. Nothing
    /// is queued or sent for them, no datagram reaches the "registrar", the
    /// application state does not move, and a TLS account still registers
    /// afterwards.
    #[cfg(not(feature = "insecure-transports"))]
    #[tokio::test]
    async fn test_qa_tls_only_build_rejects_udp_and_tcp_accounts() {
        use client_types::TransportPreference;

        let dir = tempfile::tempdir().unwrap();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let mut app = hermetic_app(dir.path(), app_tx);
        let state_before = app.state;

        // Where a cleartext REGISTER would land.
        let registrar = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registrar_addr = registrar.local_addr().unwrap();

        for transport in [TransportPreference::Udp, TransportPreference::Tcp] {
            let mut account = SipAccount::new(
                "lab-account",
                "Lab User",
                "sip:lab@example.com",
                format!("sip:{registrar_addr}"),
            );
            account.transport = transport;

            let error = app.register_account(&account).await.unwrap_err();
            assert!(
                matches!(&error, AppError::Settings(message) if message.contains("TLS only")),
                "{transport}: {error}"
            );
            assert!(
                app.reg_event_rx.try_recv().is_err(),
                "{transport}: a REGISTER was queued for a refused account"
            );
            assert_eq!(app.state, state_before, "{transport}");
            assert!(app.current_account_id.is_none(), "{transport}");
            qa_poll(&mut app, "after a refused account").await;
        }

        let mut buf = [0u8; 2048];
        let leaked =
            tokio::time::timeout(Duration::from_millis(300), registrar.recv_from(&mut buf)).await;
        assert!(leaked.is_err(), "a refused account sent SIP over UDP");
        assert!(
            qa_drain_app_events(&mut app_rx).is_empty(),
            "a refused account produced application events"
        );

        // The refusal is not sticky: a TLS account is accepted and its
        // REGISTER is built for TLS.
        let account = SipAccount::new(
            "tls-account",
            "TLS User",
            "sips:testuser@example.com",
            "sips:192.0.2.1:5061",
        );
        assert_eq!(account.transport, TransportPreference::TlsOnly);
        app.register_account(&account).await.unwrap();
        let register = std::iter::from_fn(|| app.reg_event_rx.try_recv().ok())
            .find_map(|event| match event {
                RegistrationEvent::SendRequest { request, .. } => Some(request),
                _ => None,
            })
            .unwrap();
        let via = register
            .headers
            .get_value(&proto_sip::header::HeaderName::Via)
            .unwrap();
        assert!(via.starts_with("SIP/2.0/TLS "), "{via}");
    }

    /// B1, request side, both feature sets: the REGISTER of a TLS account
    /// leaves as a TLS handshake on a TCP connection to the registrar, and
    /// nothing is sent to the registrar's address over UDP. (The coder's
    /// tests cover the response side.)
    #[tokio::test]
    async fn test_qa_tls_account_registers_over_tls_and_never_over_udp() {
        use tokio::io::AsyncReadExt;

        let dir = tempfile::tempdir().unwrap();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let mut app = hermetic_app(dir.path(), app_tx);

        // A "registrar" listening on the same port for TCP and UDP.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registrar_addr = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(registrar_addr).await.unwrap();

        // It reads the first bytes the client sends, then closes, which
        // fails the handshake and lets the pump pass return.
        let first_bytes = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut head = [0u8; 3];
            stream.read_exact(&mut head).await.unwrap();
            head
        });

        let account = SipAccount::new(
            "tls-account",
            "TLS User",
            "sips:testuser@example.com",
            format!("sips:{registrar_addr}"),
        );
        app.register_account(&account).await.unwrap();
        qa_poll(
            &mut app,
            "REGISTER towards a registrar that drops the handshake",
        )
        .await;

        let head = tokio::time::timeout(Duration::from_secs(5), first_bytes)
            .await
            .unwrap_or_else(|_| panic!("the client never connected to the registrar over TCP"))
            .unwrap();
        // TLS record header: handshake (22), legacy record version 3.x.
        assert_eq!(
            head[0], 0x16,
            "first byte on the wire is not a TLS handshake"
        );
        assert_eq!(head[1], 0x03, "not a TLS record: {head:02x?}");

        let mut buf = [0u8; 2048];
        let leaked =
            tokio::time::timeout(Duration::from_millis(300), udp.recv_from(&mut buf)).await;
        assert!(
            leaked.is_err(),
            "the REGISTER (or anything) was sent over UDP"
        );
    }

    /// B5 through the pump: hostile From and Contact values arrive as
    /// transport events, one pass each. No pass panics or errors, the
    /// transport receiver stays in place, unparsable values raise no
    /// incoming call, and a well-formed INVITE sent after each one rings.
    #[tokio::test]
    async fn test_qa_pump_survives_hostile_from_and_contact_values() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, mut app_rx) = mpsc::channel(256);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);

        let good_from = "<sips:caller@example.com>;tag=1";
        let good_contact = "<sips:caller@192.0.2.50:5061>";
        let many_closers = ">".repeat(4000);
        let many_openers = "<".repeat(4000);
        let many_quotes = "\"".repeat(4000);
        // (value, whether an INVITE carrying it rings)
        let values: [(&str, bool); 22] = [
            (">a<sips:x@example.com>", true),
            ("><sips:x@example.com>", true),
            (r#""a\"> x" <sips:x@example.com>"#, true),
            (r#""back\\slash\\" <sips:x@example.com>"#, true),
            ("\u{1f600}>\u{1f600}<sips:x@example.com>\u{1f600}", true),
            ("\"\u{e9}\\\"\" <sips:x@example.com>", true),
            ("<sips:x@example.com>>", true),
            // Round 2 (R2-3): no usable SIP/SIPS URI, so 400 and no call.
            (&many_closers, false),
            ("<", false),
            ("<>", false),
            ("<<<<", false),
            ("<sips:x@example.com", false),
            ("Bob <sips:x@example.com", false),
            ("\"unterminated <sips:x@example.com>", false),
            (r#""escaped closing quote\" <sips:x@example.com>"#, false),
            (r#""trailing escape\"#, false),
            ("\"quoted\" sips:x@example.com", false),
            ("<\u{e9}", false),
            ("\u{1f600}<\u{1f600}", false),
            (&many_openers, false),
            (&many_quotes, false),
            ("", false),
        ];

        let mut n = 0_usize;
        for as_from in [true, false] {
            for (value, rings) in values {
                n += 1;
                let header = if as_from { "From" } else { "Contact" };
                let shown: String = value.chars().take(50).collect();
                let what = format!("{header} {shown:?} ({} bytes)", value.len());
                let (from, contact) = if as_from {
                    (value, good_contact)
                } else {
                    (good_from, value)
                };

                transport_tx
                    .send(tls_request(
                        &qa_invite(from, contact, &format!("hostile{n}")),
                        peer(),
                    ))
                    .await
                    .unwrap();
                qa_poll(&mut app, &what).await;
                assert!(app.transport_event_rx.is_some(), "receiver lost: {what}");
                let incoming = qa_drain_app_events(&mut app_rx)
                    .into_iter()
                    .filter(|event| matches!(event, AppEvent::IncomingCall { .. }))
                    .count();
                assert_eq!(incoming, usize::from(rings), "{what}");

                // The next well-formed INVITE is still processed.
                let valid_from = format!("<sips:valid{n}@example.com>;tag=1");
                transport_tx
                    .send(tls_request(
                        &qa_invite(&valid_from, good_contact, &format!("valid{n}")),
                        peer(),
                    ))
                    .await
                    .unwrap();
                qa_poll(&mut app, &what).await;
                let rang: Vec<String> = qa_drain_app_events(&mut app_rx)
                    .into_iter()
                    .filter_map(|event| match event {
                        AppEvent::IncomingCall { remote_uri, .. } => Some(remote_uri),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    rang,
                    [format!("sips:valid{n}@example.com")],
                    "valid INVITE not processed after {what}"
                );
            }
        }
    }

    /// PERF-R1-001 scenario 2: a command leaves a call-agent `StateChanged`
    /// first in its queue while the call-manager queue is full. The next
    /// pass must empty the call-manager queue before handling it: its
    /// handler adds to that queue with an awaited send.
    #[tokio::test]
    async fn test_pump_drains_full_call_manager_queue_before_call_agent_events() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, _app_rx) = mpsc::channel(256);
        let mut app = hermetic_app(dir.path(), app_tx);
        app.call_manager.configure_account(&SipAccount::new(
            "test-account",
            "Test User",
            "sips:testuser@example.com",
            "sips:192.0.2.1:5061",
        ));
        // INVITE target with no listener: the connect is refused at once.
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };

        // Command with no pass after it: `make_call` queues StateChanged
        // (first) and the INVITE on the call-agent queue. Then the
        // call-manager queue is filled by other commands.
        app.call_manager
            .make_call(&format!("sips:bob@{closed}"))
            .await
            .unwrap();
        let filler = app.call_manager.event_sender_for_test();
        let mut queued = 0;
        while filler
            .try_send(CallManagerEvent::CallEnded {
                call_id: "filler".to_string(),
                reason: client_types::CallEndReason::LocalHangup,
                duration_secs: None,
            })
            .is_ok()
        {
            queued += 1;
        }
        assert!(queued > 0);

        qa_poll(&mut app, "pass after a full call-manager queue").await;
    }

    /// B5 through the application API: the QA-001 Contact reproducer rings,
    /// is answered through `ClientApp::accept_incoming_call` (which used to
    /// panic inside the call manager), the pump keeps running, and a later
    /// call still rings.
    #[tokio::test]
    async fn test_qa_app_accepts_call_with_hostile_contact_and_keeps_pumping() {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, mut app_rx) = mpsc::channel(256);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);
        app.call_manager.configure_account(&SipAccount::new(
            "test-account",
            "Test User",
            "sips:testuser@example.com",
            "sips:192.0.2.1:5061",
        ));

        // The BYE sent at hang-up goes to the Contact address over a new
        // TLS connection. Point it at a loopback port with no listener so
        // the connect is refused at once; an unroutable address would hold
        // the pump for the OS connect timeout (no timeout in `connect()`,
        // outside this round's scope).
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let contacts = [
            format!(">a<sips:caller@{closed}>"),
            format!(r#""a\"> x" <sips:caller@{closed}>"#),
            format!("\u{1f600}>\u{1f600}<sips:caller@{closed}>"),
        ];

        for (n, contact) in contacts.iter().map(String::as_str).enumerate() {
            transport_tx
                .send(tls_request(
                    &qa_invite(
                        "<sips:caller@example.com>;tag=1",
                        contact,
                        &format!("accept{n}"),
                    ),
                    peer(),
                ))
                .await
                .unwrap();
            qa_poll(&mut app, contact).await;
            let call_id = qa_drain_app_events(&mut app_rx)
                .into_iter()
                .find_map(|event| match event {
                    AppEvent::IncomingCall { call_id, .. } => Some(call_id),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{contact:?} did not ring"));

            app.accept_incoming_call(&call_id).await.unwrap();
            qa_poll(&mut app, contact).await;
            assert_eq!(app.state, AppState::InCall, "{contact:?}");
            assert!(app.transport_event_rx.is_some());

            app.hangup().await.unwrap();
            qa_poll(&mut app, contact).await;
            let _ = qa_drain_app_events(&mut app_rx);
        }

        transport_tx
            .send(tls_request(
                &qa_invite(
                    "<sips:later@example.com>;tag=1",
                    "<sips:later@192.0.2.50:5061>",
                    "later",
                ),
                peer(),
            ))
            .await
            .unwrap();
        qa_poll(&mut app, "INVITE after the hostile calls").await;
        assert!(
            qa_drain_app_events(&mut app_rx)
                .iter()
                .any(|event| matches!(event, AppEvent::IncomingCall { .. })),
            "no incoming call after the hostile ones"
        );
    }

    /// Runs pump passes while `requests` are fed into the 32-slot transport
    /// queue by another task (the receive task's role) and the application
    /// events are taken off a one-slot channel by a third (the shell's
    /// role, which also makes the pump yield so the feeder can refill the
    /// queue during a pass). `max_passes` bounds the run. Returns the
    /// application events in delivery order and, per pass, how many
    /// transport events it consumed.
    async fn qa_pump_burst(
        requests: Vec<String>,
        max_passes: usize,
    ) -> (Vec<AppEvent>, Vec<usize>) {
        let dir = tempfile::tempdir().unwrap();
        let (app_tx, mut app_rx) = mpsc::channel(1);
        let mut app = hermetic_app(dir.path(), app_tx);
        let transport_tx = transport_sender(&app);
        let probe = transport_tx.clone();

        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&delivered);
        let drainer = tokio::spawn(async move {
            while let Some(event) = app_rx.recv().await {
                sink.lock().unwrap().push(event);
            }
        });

        let sent = Arc::new(AtomicUsize::new(0));
        let sent_by_feeder = Arc::clone(&sent);
        let feeder = tokio::spawn(async move {
            for text in requests {
                if transport_tx.send(tls_request(&text, peer())).await.is_err() {
                    return;
                }
                sent_by_feeder.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Start with the transport queue full.
        while probe.capacity() > 0 && !feeder.is_finished() {
            tokio::task::yield_now().await;
        }

        let mut per_pass = Vec::new();
        let mut consumed_before = 0_usize;
        for pass in 0..max_passes {
            qa_poll(&mut app, &format!("burst pass {pass}")).await;
            // Let the feeder top the queue up before counting.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            let queued = probe.max_capacity() - probe.capacity();
            let consumed = sent.load(Ordering::SeqCst) - queued;
            per_pass.push(consumed - consumed_before);
            consumed_before = consumed;
            if feeder.is_finished() && queued == 0 {
                break;
            }
        }

        tokio::time::timeout(Duration::from_secs(5), feeder)
            .await
            .unwrap_or_else(|_| panic!("requests were left unfed: the pump stopped draining"))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drainer.abort();
        let events = delivered.lock().unwrap().clone();
        (events, per_pass)
    }

    /// B12: more than three times the per-pass cap of response-producing
    /// requests. No pass blocks, no pass handles more than the cap, and
    /// every request is eventually handled, in the order it arrived.
    #[tokio::test]
    async fn test_qa_pump_delivers_large_burst_across_passes_in_order() {
        const REQUESTS: usize = 3 * MAX_TRANSPORT_EVENTS_PER_POLL + 17;

        let requests = (0..REQUESTS)
            .map(|n| qa_dtmf_info(n, 1000 + u16::try_from(n).unwrap()))
            .collect();
        let (events, per_pass) = qa_pump_burst(requests, 64).await;

        let durations: Vec<u16> = events
            .iter()
            .filter_map(|event| match event {
                AppEvent::DtmfReceived { duration, .. } => Some(*duration),
                _ => None,
            })
            .collect();
        let expected: Vec<u16> = (0..REQUESTS)
            .map(|n| 1000 + u16::try_from(n).unwrap())
            .collect();
        assert_eq!(
            durations, expected,
            "every request handled exactly once, in order"
        );

        assert_eq!(per_pass.iter().sum::<usize>(), REQUESTS, "{per_pass:?}");
        assert!(
            per_pass.iter().all(|n| *n <= MAX_TRANSPORT_EVENTS_PER_POLL),
            "a pass exceeded the per-pass cap: {per_pass:?}"
        );
        assert!(
            per_pass.len() >= REQUESTS.div_ceil(MAX_TRANSPORT_EVENTS_PER_POLL),
            "{per_pass:?}"
        );
    }

    /// B12: 40 INVITEs in one pass. Each queues three call-manager events
    /// (100, 180, incoming call), so the old drain order filled the 32-slot
    /// queue at the 11th INVITE. All 40 ring, in order, in a single pass.
    #[tokio::test]
    async fn test_qa_pump_handles_invite_burst_in_one_pass() {
        const INVITES: usize = 40;
        const { assert!(INVITES > 32 && INVITES <= MAX_TRANSPORT_EVENTS_PER_POLL) };

        let requests = (0..INVITES)
            .map(|n| {
                qa_invite(
                    &format!("<sips:caller{n}@example.com>;tag=1"),
                    "<sips:caller@192.0.2.50:5061>",
                    &format!("burst{n}"),
                )
            })
            .collect();
        let (events, per_pass) = qa_pump_burst(requests, 1).await;

        let ringing: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                AppEvent::IncomingCall { remote_uri, .. } => Some(remote_uri.clone()),
                _ => None,
            })
            .collect();
        let expected: Vec<String> = (0..INVITES)
            .map(|n| format!("sips:caller{n}@example.com"))
            .collect();
        assert_eq!(ringing, expected);
        assert_eq!(per_pass, [INVITES], "handled in a single pass");
    }

    /// B12: a mixed burst (INVITE, INFO, unmatched BYE answered 481, an
    /// INVITE answered 400) longer than the per-pass cap. Requests that
    /// produce only a response and requests that also notify the
    /// application are interleaved; everything is delivered in order.
    #[tokio::test]
    async fn test_qa_pump_delivers_mixed_burst_in_order() {
        const ROUNDS: usize = 30;

        let mut requests = Vec::new();
        let mut expected = Vec::new();
        for n in 0..ROUNDS {
            requests.push(qa_invite(
                &format!("<sips:mixed{n}@example.com>;tag=1"),
                "<sips:caller@192.0.2.50:5061>",
                &format!("mixed{n}"),
            ));
            expected.push(format!("ring sips:mixed{n}@example.com"));
            requests.push(unmatched_bye("TLS", peer()));
            requests.push(qa_dtmf_info(n, 2000 + u16::try_from(n).unwrap()));
            expected.push(format!("dtmf {}", 2000 + n));
            requests.push(qa_invite(
                "Bob <sips:broken@example.com;tag=1",
                "<sips:caller@192.0.2.50:5061>",
                &format!("broken{n}"),
            ));
        }
        let total = requests.len();
        assert!(total > MAX_TRANSPORT_EVENTS_PER_POLL);

        let (events, per_pass) = qa_pump_burst(requests, 64).await;
        let seen: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                AppEvent::IncomingCall { remote_uri, .. } => Some(format!("ring {remote_uri}")),
                AppEvent::DtmfReceived { duration, .. } => Some(format!("dtmf {duration}")),
                _ => None,
            })
            .collect();
        assert_eq!(seen, expected);
        assert_eq!(per_pass.iter().sum::<usize>(), total, "{per_pass:?}");
        assert!(
            per_pass.iter().all(|n| *n <= MAX_TRANSPORT_EVENTS_PER_POLL),
            "{per_pass:?}"
        );
    }
}
