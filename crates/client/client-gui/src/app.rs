//! Main GUI application.
//!
//! Manages the egui window and coordinates between views.

use crate::notifications::NotificationManager;
use crate::tray::TrayAction;
use crate::views::{CallView, ContactsView, DialerView, SettingsView};
use client_core::{AppEvent, ClientApp};
use client_types::{CallInfo, CallState, RegistrationState};
use eframe::egui;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::Receiver as StdReceiver;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Active view in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActiveView {
    /// Dialer (default view).
    #[default]
    Dialer,
    /// Active call view.
    Call,
    /// Contacts list.
    Contacts,
    /// Settings view.
    Settings,
}

/// Main GUI application state.
pub struct SipClientApp {
    /// Active view.
    active_view: ActiveView,
    /// Dialer view state.
    dialer_view: DialerView,
    /// Call view state.
    call_view: CallView,
    /// Contacts view state.
    contacts_view: ContactsView,
    /// Settings view state.
    settings_view: SettingsView,
    /// Application core (wrapped for async).
    client_app: Option<ClientApp>,
    /// Async runtime.
    runtime: Arc<Runtime>,
    /// Event receiver from core.
    event_rx: mpsc::Receiver<AppEvent>,
    /// Tray action receiver.
    tray_action_rx: Option<StdReceiver<TrayAction>>,
    /// Current registration state.
    registration_state: RegistrationState,
    /// Current call info.
    active_call: Option<CallInfo>,
    /// Status message.
    status_message: String,
    /// Error message (if any).
    error_message: Option<String>,
    /// Show error dialog.
    show_error_dialog: bool,
    /// Whether a tray exit was requested.
    exit_requested: bool,
    /// Pending certificate chain (waiting for ClientApp init).
    pending_cert_chain: Option<Vec<Vec<u8>>>,
    /// Pending certificate thumbprint.
    pending_cert_thumbprint: Option<String>,
    /// Notification manager for toast notifications.
    notifications: NotificationManager,
}

impl SipClientApp {
    /// Creates a new application instance.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        tray_action_rx: Option<StdReceiver<TrayAction>>,
    ) -> Self {
        // Set up dark theme
        let mut visuals = egui::Visuals::dark();
        visuals.window_fill = egui::Color32::from_rgb(30, 30, 35);
        visuals.panel_fill = egui::Color32::from_rgb(30, 30, 35);
        cc.egui_ctx.set_visuals(visuals);

        // Create async runtime
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    panic!("Failed to create async runtime: {e}");
                }),
        );

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel(64);

        // Initialize client app
        let local_sip_addr: SocketAddr = "0.0.0.0:5060"
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let local_media_addr: SocketAddr = "0.0.0.0:16384"
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        let client_app = match ClientApp::new(local_sip_addr, local_media_addr, event_tx) {
            Ok(app) => Some(app),
            Err(e) => {
                error!("Failed to initialize client app: {}", e);
                None
            }
        };

        Self {
            active_view: ActiveView::Dialer,
            dialer_view: DialerView::new(),
            call_view: CallView::new(),
            contacts_view: ContactsView::new(),
            settings_view: SettingsView::new(),
            client_app,
            runtime,
            event_rx,
            tray_action_rx,
            registration_state: RegistrationState::Unregistered,
            active_call: None,
            status_message: "Ready".to_string(),
            error_message: None,
            show_error_dialog: false,
            exit_requested: false,
            notifications: NotificationManager::new("USG SIP Client"),
            pending_cert_chain: None,
            pending_cert_thumbprint: None,
        }
    }

    /// Processes pending tray actions.
    fn process_tray_events(&mut self, ctx: &egui::Context) {
        if let Some(ref rx) = self.tray_action_rx {
            while let Ok(action) = rx.try_recv() {
                match action {
                    TrayAction::ShowWindow => {
                        info!("Tray: Show window");
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    TrayAction::HideWindow => {
                        info!("Tray: Hide window");
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                    TrayAction::Exit => {
                        info!("Tray: Exit requested");
                        self.exit_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }
    }

    /// Processes pending events from the core.
    fn process_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::RegistrationStateChanged { account_id, state } => {
                    info!(account_id = %account_id, state = ?state, "Registration state changed");
                    let was_registered = self.registration_state == RegistrationState::Registered;
                    let is_registered = state == RegistrationState::Registered;

                    // Show notification on registration state change
                    if was_registered != is_registered {
                        self.notifications
                            .notify_registration(is_registered, account_id.clone());
                    }

                    self.registration_state = state;
                    self.status_message = format!("Registration: {}", state);
                }
                AppEvent::CallStateChanged {
                    call_id,
                    state,
                    info,
                } => {
                    info!(call_id = %call_id, state = ?state, "Call state changed");
                    self.active_call = Some(info);

                    // Switch to call view when call starts
                    if state.is_active() && self.active_view != ActiveView::Call {
                        self.active_view = ActiveView::Call;
                    }

                    // Switch back to dialer when call ends
                    if state == CallState::Terminated {
                        self.active_call = None;
                        if self.active_view == ActiveView::Call {
                            self.active_view = ActiveView::Dialer;
                        }
                    }
                }
                AppEvent::IncomingCall {
                    call_id,
                    remote_uri,
                    remote_display_name,
                } => {
                    info!(
                        call_id = %call_id,
                        remote_uri = %remote_uri,
                        "Incoming call"
                    );
                    self.status_message = format!(
                        "Incoming call from {}",
                        remote_display_name.as_deref().unwrap_or(&remote_uri)
                    );

                    // Show toast notification for incoming call
                    self.notifications
                        .notify_incoming_call(remote_display_name.clone(), remote_uri.clone());
                }
                AppEvent::CallEnded {
                    call_id: _,
                    duration_secs,
                } => {
                    // Get remote name before clearing active_call
                    let remote_name = self
                        .active_call
                        .as_ref()
                        .and_then(|c| c.remote_display_name.clone());

                    self.active_call = None;
                    if let Some(duration) = duration_secs {
                        self.status_message = format!("Call ended ({duration}s)");
                    } else {
                        self.status_message = "Call ended".to_string();
                    }
                    if self.active_view == ActiveView::Call {
                        self.active_view = ActiveView::Dialer;
                    }

                    // Show notification for call ended
                    self.notifications
                        .notify_call_ended(remote_name, duration_secs);
                }
                AppEvent::Error { message } => {
                    error!(message = %message, "Application error");
                    self.error_message = Some(message.clone());
                    self.show_error_dialog = true;

                    // Show toast notification for error
                    self.notifications.notify_error("Error", &message);
                }
                AppEvent::SettingsChanged => {
                    self.status_message = "Settings saved".to_string();
                }
                AppEvent::ContactsChanged => {
                    self.status_message = "Contacts updated".to_string();
                }
            }
        }
    }

    /// Renders the navigation bar.
    fn render_nav_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.set_height(40.0);
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 0.0);

            let button_size = egui::vec2(80.0, 32.0);

            // Dialer button
            let dialer_selected = self.active_view == ActiveView::Dialer;
            if ui
                .add_sized(
                    button_size,
                    egui::Button::new("Dialer").selected(dialer_selected),
                )
                .clicked()
            {
                self.active_view = ActiveView::Dialer;
            }

            // Call button (only visible during call)
            if self.active_call.is_some() {
                let call_selected = self.active_view == ActiveView::Call;
                if ui
                    .add_sized(
                        button_size,
                        egui::Button::new("Call").selected(call_selected),
                    )
                    .clicked()
                {
                    self.active_view = ActiveView::Call;
                }
            }

            // Contacts button
            let contacts_selected = self.active_view == ActiveView::Contacts;
            if ui
                .add_sized(
                    button_size,
                    egui::Button::new("Contacts").selected(contacts_selected),
                )
                .clicked()
            {
                self.active_view = ActiveView::Contacts;
            }

            // Settings button
            let settings_selected = self.active_view == ActiveView::Settings;
            if ui
                .add_sized(
                    button_size,
                    egui::Button::new("Settings").selected(settings_selected),
                )
                .clicked()
            {
                self.active_view = ActiveView::Settings;
            }

            // Spacer
            ui.add_space(ui.available_width() - 100.0);

            // Registration status indicator
            let (status_color, status_text) = match self.registration_state {
                RegistrationState::Registered => (egui::Color32::GREEN, "Registered"),
                RegistrationState::Registering => (egui::Color32::YELLOW, "Registering..."),
                RegistrationState::Failed => (egui::Color32::RED, "Failed"),
                RegistrationState::CertificateInvalid => (egui::Color32::RED, "Cert Invalid"),
                RegistrationState::SmartCardNotPresent => (egui::Color32::ORANGE, "Insert Card"),
                RegistrationState::WaitingForPin => (egui::Color32::YELLOW, "Enter PIN"),
                _ => (egui::Color32::GRAY, "Unregistered"),
            };

            ui.horizontal(|ui| {
                ui.add(egui::widgets::Spinner::new().color(status_color).size(12.0));
                ui.label(egui::RichText::new(status_text).color(status_color).small());
            });
        });
    }

    /// Renders the status bar.
    fn render_status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.set_height(24.0);
            ui.label(
                egui::RichText::new(&self.status_message)
                    .small()
                    .color(egui::Color32::GRAY),
            );
        });
    }

    /// Renders the error dialog.
    fn render_error_dialog(&mut self, ctx: &egui::Context) {
        if self.show_error_dialog {
            egui::Window::new("Error")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(300.0);

                    if let Some(ref message) = self.error_message {
                        ui.label(egui::RichText::new(message).color(egui::Color32::RED));
                    }

                    ui.add_space(16.0);

                    if ui.button("OK").clicked() {
                        self.show_error_dialog = false;
                        self.error_message = None;
                    }
                });
        }
    }
}

impl eframe::App for SipClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process tray events
        self.process_tray_events(ctx);

        // Process events from core
        self.process_events();

        // Top panel with navigation
        egui::TopBottomPanel::top("nav_bar").show(ctx, |ui| {
            self.render_nav_bar(ui);
        });

        // Bottom panel with status
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            self.render_status_bar(ui);
        });

        // Central panel with active view
        egui::CentralPanel::default().show(ctx, |ui| match self.active_view {
            ActiveView::Dialer => {
                if let Some(action) = self.dialer_view.render(ui) {
                    self.handle_dialer_action(action);
                }
            }
            ActiveView::Call => {
                if let Some(action) = self.call_view.render(ui, self.active_call.as_ref()) {
                    self.handle_call_action(action);
                }
            }
            ActiveView::Contacts => {
                if let Some(action) = self.contacts_view.render(ui) {
                    self.handle_contacts_action(action);
                }
            }
            ActiveView::Settings => {
                if let Some(action) = self.settings_view.render(ui) {
                    self.handle_settings_action(action);
                }
            }
        });

        // Error dialog
        self.render_error_dialog(ctx);

        // Request repaint for animations
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        info!("Application shutting down");

        // Shutdown client app
        if let Some(ref mut app) = self.client_app {
            let _ = self.runtime.block_on(app.shutdown());
        }
    }
}

impl SipClientApp {
    fn handle_dialer_action(&mut self, action: crate::views::DialerAction) {
        match action {
            crate::views::DialerAction::Call(uri) => {
                info!(uri = %uri, "Making call");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    let result = runtime.block_on(app.make_call(&uri));
                    if let Err(e) = result {
                        self.error_message = Some(format!("Call failed: {e}"));
                        self.show_error_dialog = true;
                    }
                }
            }
        }
    }

    fn handle_call_action(&mut self, action: crate::views::CallAction) {
        match action {
            crate::views::CallAction::Hangup => {
                info!("Hanging up call");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    let _ = runtime.block_on(app.hangup());
                }
            }
            crate::views::CallAction::Mute => {
                if let Some(ref mut app) = self.client_app {
                    let muted = app.toggle_mute();
                    self.status_message = if muted { "Muted" } else { "Unmuted" }.to_string();
                }
            }
            crate::views::CallAction::Hold => {
                // TODO: Implement hold
                self.status_message = "Hold not yet implemented".to_string();
            }
        }
    }

    fn handle_contacts_action(&mut self, action: crate::views::ContactsAction) {
        match action {
            crate::views::ContactsAction::Call(uri) => {
                info!(uri = %uri, "Calling contact");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    let result = runtime.block_on(app.make_call(&uri));
                    if let Err(e) = result {
                        self.error_message = Some(format!("Call failed: {e}"));
                        self.show_error_dialog = true;
                    } else {
                        self.active_view = ActiveView::Call;
                    }
                }
            }
            crate::views::ContactsAction::Edit(_contact_id) => {
                // TODO: Open contact editor
            }
            crate::views::ContactsAction::Delete(_contact_id) => {
                // TODO: Delete contact
            }
        }
    }

    fn handle_settings_action(&mut self, action: crate::views::SettingsAction) {
        match action {
            crate::views::SettingsAction::Save => {
                info!("Saving settings");
                // TODO: Save settings
                self.status_message = "Settings saved".to_string();
            }
            crate::views::SettingsAction::Register(account_id) => {
                info!(account_id = %account_id, "Registering account");
                // TODO: Register account
            }
            crate::views::SettingsAction::Unregister => {
                info!("Unregistering");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    let _ = runtime.block_on(app.unregister());
                }
            }
            crate::views::SettingsAction::RefreshCertificates => {
                info!("Refreshing certificates");
                self.settings_view.set_certificates_loading(true);
                self.refresh_certificates();
            }
            crate::views::SettingsAction::SelectCertificate(thumbprint) => {
                info!(thumbprint = %thumbprint, "Selecting certificate");
                self.settings_view.set_selected_certificate(Some(thumbprint));
                self.status_message = "Certificate selected".to_string();
            }
            crate::views::SettingsAction::UseCertificate(thumbprint) => {
                info!(thumbprint = %thumbprint, "Using certificate for authentication");
                self.use_certificate(&thumbprint);
            }
        }
    }

    fn use_certificate(&mut self, thumbprint: &str) {
        use client_core::CertificateStore;

        let cert_store = CertificateStore::open_personal();

        // First verify the certificate has a private key
        match cert_store.has_private_key(thumbprint) {
            Ok(true) => {
                info!(thumbprint = %thumbprint, "Certificate has private key");
            }
            Ok(false) => {
                self.status_message =
                    "Certificate does not have an associated private key".to_string();
                warn!(thumbprint = %thumbprint, "No private key for certificate");
                return;
            }
            Err(e) => {
                self.status_message = format!("Failed to check private key: {e}");
                warn!(error = %e, "Failed to check private key");
                return;
            }
        }

        // Get the certificate chain
        match cert_store.get_certificate_chain(thumbprint) {
            Ok(cert_chain) => {
                info!(
                    thumbprint = %thumbprint,
                    chain_length = cert_chain.len(),
                    "Retrieved certificate chain"
                );

                // Store the certificate chain for use with mTLS
                if let Some(ref mut app) = self.client_app {
                    app.set_client_certificate(cert_chain.clone(), thumbprint.to_string());
                    self.status_message = "Certificate configured for authentication".to_string();
                    info!("Certificate configured in ClientApp");
                } else {
                    // Store for later when ClientApp is initialized
                    self.pending_cert_chain = Some(cert_chain);
                    self.pending_cert_thumbprint = Some(thumbprint.to_string());
                    self.status_message =
                        "Certificate will be used when connecting".to_string();
                }
            }
            Err(e) => {
                self.status_message = format!("Failed to get certificate: {e}");
                warn!(error = %e, "Failed to get certificate chain");
            }
        }
    }

    fn refresh_certificates(&mut self) {
        use client_core::CertificateStore;

        let cert_store = CertificateStore::open_personal();

        // List certificates
        match cert_store.list_certificates() {
            Ok(certs) => {
                info!(count = certs.len(), "Found certificates");
                self.settings_view.set_certificates(certs);
            }
            Err(e) => {
                warn!(error = %e, "Failed to list certificates");
                self.settings_view.set_certificates(Vec::new());
                self.status_message = format!("Failed to load certificates: {e}");
            }
        }

        // List smart card readers
        match cert_store.list_smart_card_readers() {
            Ok(readers) => {
                info!(count = readers.len(), "Found smart card readers");
                self.settings_view.set_smart_card_readers(readers);
            }
            Err(e) => {
                warn!(error = %e, "Failed to list smart card readers");
                self.settings_view.set_smart_card_readers(Vec::new());
            }
        }
    }
}
