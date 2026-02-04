//! Main GUI application.
//!
//! Manages the egui window and coordinates between views.

use crate::notifications::NotificationManager;
use crate::tray::TrayAction;
use crate::views::{CallView, ContactsView, DialerView, SettingsView};
use client_audio::RingtonePlayer;
use client_core::{AppEvent, ClientApp, SettingsManager};
use client_types::{CallInfo, CallState, RegistrationState};
use eframe::egui;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::Receiver as StdReceiver;
use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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

/// Operation that requires PIN entry.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Register and SignCall will be used in future phases
pub enum PinOperation {
    /// Using a certificate for authentication.
    UseCertificate {
        /// Certificate thumbprint.
        thumbprint: String,
    },
    /// Signing during registration.
    Register {
        /// Account ID.
        account_id: String,
    },
    /// Signing during call establishment (DTLS).
    SignCall {
        /// Call ID.
        call_id: String,
    },
}

/// Maximum PIN retry attempts before lockout warning.
const MAX_PIN_ATTEMPTS: u8 = 3;

/// Information about a pending incoming call.
#[derive(Debug, Clone)]
pub struct IncomingCallAlert {
    /// Internal call ID.
    pub call_id: String,
    /// Remote party SIP URI.
    pub remote_uri: String,
    /// Remote party display name (if available).
    pub remote_display_name: Option<String>,
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
    /// Current focused call info.
    active_call: Option<CallInfo>,
    /// All active calls (for multi-call support).
    all_calls: Vec<CallInfo>,
    /// Incoming call alert (ringing).
    incoming_call: Option<IncomingCallAlert>,
    /// Show incoming call dialog.
    show_incoming_call_dialog: bool,
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
    /// Show PIN entry dialog.
    show_pin_dialog: bool,
    /// PIN input field (masked).
    pin_input: String,
    /// PIN dialog error message.
    pin_error: Option<String>,
    /// Operation that requires PIN.
    pin_operation: Option<PinOperation>,
    /// Number of PIN retry attempts.
    pin_attempts: u8,
    /// Ringtone player for incoming calls.
    ringtone_player: RingtonePlayer,
    /// Auto-answer timer (when auto-answer is enabled).
    auto_answer_timer: Option<(String, Instant)>,
    /// Available input (microphone) devices.
    available_inputs: Vec<String>,
    /// Available output (speaker) devices.
    available_outputs: Vec<String>,
    /// Current input device for active call.
    current_input_device: Option<String>,
    /// Current output device for active call.
    current_output_device: Option<String>,
    /// Settings manager for persisting configuration.
    settings_manager: SettingsManager,
    /// Show unsaved settings confirmation dialog.
    show_unsaved_settings_dialog: bool,
    /// Close requested while unsaved settings dialog is shown.
    pending_close: bool,
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

        // Initialize settings manager and load persisted settings
        let settings_manager = match SettingsManager::new() {
            Ok(manager) => manager,
            Err(e) => {
                error!("Failed to load settings: {}, using defaults", e);
                // Create a fallback with default settings
                SettingsManager::new().unwrap_or_else(|_| {
                    // This should not happen, but provide a safe fallback
                    panic!("Failed to create settings manager")
                })
            }
        };

        // Create settings view and populate with persisted settings
        let mut settings_view = SettingsView::new();
        settings_view.load_from_settings(settings_manager.settings());

        Self {
            active_view: ActiveView::Dialer,
            dialer_view: DialerView::new(),
            call_view: CallView::new(),
            contacts_view: ContactsView::new(),
            settings_view,
            client_app,
            runtime,
            event_rx,
            tray_action_rx,
            registration_state: RegistrationState::Unregistered,
            active_call: None,
            all_calls: Vec::new(),
            incoming_call: None,
            show_incoming_call_dialog: false,
            status_message: "Ready".to_string(),
            error_message: None,
            show_error_dialog: false,
            exit_requested: false,
            notifications: NotificationManager::new("USG SIP Client"),
            pending_cert_chain: None,
            pending_cert_thumbprint: None,
            show_pin_dialog: false,
            pin_input: String::new(),
            pin_error: None,
            pin_operation: None,
            pin_attempts: 0,
            ringtone_player: RingtonePlayer::new(),
            auto_answer_timer: None,
            available_inputs: vec!["Default".to_string()],
            available_outputs: vec!["Default".to_string()],
            current_input_device: None,
            current_output_device: None,
            settings_manager,
            show_unsaved_settings_dialog: false,
            pending_close: false,
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
                        if self.settings_view.is_dirty() {
                            // Show confirmation dialog instead of immediate close
                            self.show_unsaved_settings_dialog = true;
                        } else {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
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

                    // Update all_calls from the core
                    if let Some(ref app) = self.client_app {
                        self.all_calls = app.all_call_info();
                    }

                    // Switch to call view when call starts
                    if state.is_active() && self.active_view != ActiveView::Call {
                        self.active_view = ActiveView::Call;
                        self.refresh_audio_devices();
                    }

                    // Switch back to dialer when call ends
                    if state == CallState::Terminated {
                        // Update all_calls - the terminated call should be removed
                        if let Some(ref app) = self.client_app {
                            self.all_calls = app.all_call_info();
                        }

                        // If no more active calls, clear active_call and go back to dialer
                        if self.all_calls.is_empty() {
                            self.active_call = None;
                            if self.active_view == ActiveView::Call {
                                self.active_view = ActiveView::Dialer;
                            }
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

                    // Store incoming call info and show dialog
                    self.incoming_call = Some(IncomingCallAlert {
                        call_id: call_id.clone(),
                        remote_uri: remote_uri.clone(),
                        remote_display_name: remote_display_name.clone(),
                    });
                    self.show_incoming_call_dialog = true;

                    // Start ringtone playback
                    self.start_ringtone();

                    // Check for auto-answer
                    self.check_auto_answer(&call_id);

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

                    // Update all_calls from core
                    if let Some(ref app) = self.client_app {
                        self.all_calls = app.all_call_info();
                    }

                    // Stop ringtone and clear auto-answer timer
                    self.stop_ringtone();
                    self.auto_answer_timer = None;

                    // Clear incoming call dialog
                    self.incoming_call = None;
                    self.show_incoming_call_dialog = false;

                    if let Some(duration) = duration_secs {
                        self.status_message = format!("Call ended ({duration}s)");
                    } else {
                        self.status_message = "Call ended".to_string();
                    }

                    // If no more active calls, clear active_call and go back to dialer
                    if self.all_calls.is_empty() {
                        self.active_call = None;
                        if self.active_view == ActiveView::Call {
                            self.active_view = ActiveView::Dialer;
                        }
                    } else {
                        // Set active_call to the first remaining call
                        self.active_call = self.all_calls.first().cloned();
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
                AppEvent::PinRequired {
                    operation,
                    thumbprint,
                } => {
                    info!(operation = ?operation, thumbprint = ?thumbprint, "PIN required from core");
                    // Map core operation type to GUI operation type
                    if let Some(tp) = thumbprint {
                        self.show_pin_dialog_for(PinOperation::UseCertificate { thumbprint: tp });
                    }
                }
                AppEvent::PinCompleted { success, error } => {
                    if success {
                        info!("PIN operation completed successfully");
                        self.show_pin_dialog = false;
                        self.status_message = "Authentication successful".to_string();
                    } else if let Some(err_msg) = error {
                        warn!(error = %err_msg, "PIN operation failed");
                        self.pin_error = Some(err_msg);
                    }
                }
                AppEvent::TransferProgress {
                    call_id: _,
                    target_uri,
                    status_code,
                    is_success,
                    is_final,
                } => {
                    // Update status message with transfer progress
                    let status_text = match status_code {
                        100 => "Trying",
                        180..=183 => "Ringing",
                        200..=299 => "Success",
                        _ => "Failed",
                    };

                    if is_final {
                        if is_success {
                            self.status_message =
                                format!("Transfer to {target_uri} completed successfully");
                        } else {
                            self.status_message = format!("Transfer to {target_uri} failed");
                        }
                    } else {
                        self.status_message =
                            format!("Transfer to {target_uri}: {status_text}...");
                    }

                    info!(
                        target = %target_uri,
                        status_code = status_code,
                        is_final = is_final,
                        "Transfer progress"
                    );
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

    /// Renders call tabs when multiple calls are active.
    ///
    /// Returns a `SwitchTo` action if user clicks on a non-focused call tab.
    fn render_call_tabs(&mut self, ui: &mut egui::Ui) -> Option<crate::views::CallAction> {
        // Only show tabs if there are multiple calls
        if self.all_calls.len() <= 1 {
            return None;
        }

        let mut action = None;
        let focused_id = self.active_call.as_ref().map(|c| c.id.as_str());

        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Active Calls:")
                    .small()
                    .color(egui::Color32::GRAY),
            );
            ui.add_space(8.0);

            for call in &self.all_calls {
                let is_focused = focused_id == Some(call.id.as_str());

                // Determine tab color based on call state
                let (bg_color, text_color) = if is_focused {
                    (egui::Color32::from_rgb(50, 100, 50), egui::Color32::WHITE)
                } else if call.is_on_hold {
                    (egui::Color32::from_rgb(180, 120, 50), egui::Color32::WHITE)
                } else {
                    (
                        egui::Color32::from_rgb(60, 60, 65),
                        egui::Color32::LIGHT_GRAY,
                    )
                };

                // Display name for the tab
                let display_name = call
                    .remote_display_name
                    .as_deref()
                    .unwrap_or(&call.remote_uri);

                // Truncate if too long
                let tab_label = if display_name.len() > 15 {
                    format!("{}...", &display_name[..12])
                } else {
                    display_name.to_string()
                };

                // Add hold indicator
                let tab_text = if call.is_on_hold {
                    format!("\u{23F8} {}", tab_label)
                } else {
                    tab_label
                };

                let button =
                    egui::Button::new(egui::RichText::new(&tab_text).small().color(text_color))
                        .fill(bg_color)
                        .corner_radius(4.0);

                let response = ui.add(button);

                // Show tooltip with full info
                let tooltip = format!(
                    "{}\n{}\nState: {}",
                    call.remote_display_name.as_deref().unwrap_or("Unknown"),
                    call.remote_uri,
                    call.state
                );
                response.clone().on_hover_text(tooltip);

                // Handle click - switch to this call if not already focused
                if response.clicked() && !is_focused {
                    action = Some(crate::views::CallAction::SwitchTo {
                        call_id: call.id.clone(),
                    });
                }

                ui.add_space(4.0);
            }
        });

        ui.add_space(8.0);
        ui.separator();

        action
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

    /// Renders the unsaved settings confirmation dialog.
    fn render_unsaved_settings_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_unsaved_settings_dialog {
            return;
        }

        egui::Window::new("Unsaved Changes")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(350.0);

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("\u{26A0}").size(40.0).color(egui::Color32::YELLOW));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Unsaved Settings").strong().size(18.0));
                });

                ui.add_space(16.0);

                ui.label("You have unsaved changes to your settings.");
                ui.label("Would you like to save them before exiting?");

                ui.add_space(20.0);

                ui.horizontal(|ui| {
                    if ui.button("Save and Exit").clicked() {
                        self.save_settings();
                        self.show_unsaved_settings_dialog = false;
                        self.pending_close = true;
                    }

                    if ui.button("Discard and Exit").clicked() {
                        self.settings_view.clear_dirty();
                        self.show_unsaved_settings_dialog = false;
                        self.pending_close = true;
                    }

                    if ui.button("Cancel").clicked() {
                        self.show_unsaved_settings_dialog = false;
                        self.pending_close = false;
                    }
                });
            });
    }

    /// Renders the incoming call dialog.
    fn render_incoming_call_dialog(
        &mut self,
        ctx: &egui::Context,
    ) -> Option<crate::views::CallAction> {
        if !self.show_incoming_call_dialog {
            return None;
        }

        let mut action = None;

        if let Some(ref incoming) = self.incoming_call.clone() {
            egui::Window::new("Incoming Call")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);

                    // Phone ringing icon
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("\u{1F4DE}").size(48.0)); // Phone icon
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Incoming Call").strong().size(20.0));
                    });

                    ui.add_space(16.0);

                    // Caller info
                    ui.vertical_centered(|ui| {
                        if let Some(ref name) = incoming.remote_display_name {
                            ui.label(egui::RichText::new(name).size(18.0).strong());
                        }
                        ui.label(
                            egui::RichText::new(&incoming.remote_uri).color(egui::Color32::GRAY),
                        );
                    });

                    ui.add_space(24.0);

                    // Accept/Reject buttons
                    ui.horizontal(|ui| {
                        let button_size = egui::vec2(120.0, 50.0);

                        // Reject button (red)
                        let reject_button = egui::Button::new(
                            egui::RichText::new("\u{1F534} Reject")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(200, 50, 50));

                        if ui.add_sized(button_size, reject_button).clicked() {
                            action = Some(crate::views::CallAction::Reject {
                                call_id: incoming.call_id.clone(),
                            });
                        }

                        ui.add_space(20.0);

                        // Accept button (green)
                        let accept_button = egui::Button::new(
                            egui::RichText::new("\u{1F7E2} Accept")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(50, 180, 50));

                        if ui.add_sized(button_size, accept_button).clicked() {
                            action = Some(crate::views::CallAction::Accept {
                                call_id: incoming.call_id.clone(),
                            });
                        }
                    });
                });
        }

        action
    }

    /// Renders the PIN entry dialog for smart card authentication.
    fn render_pin_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_pin_dialog {
            return;
        }

        let mut submit_pin = false;
        let mut cancel_pin = false;

        egui::Window::new("Smart Card PIN")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(320.0);

                // Icon and title
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("\u{1F512}").size(24.0)); // Lock emoji
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Enter Smart Card PIN")
                                .strong()
                                .size(16.0),
                        );
                        ui.label(
                            egui::RichText::new("Your PIN is required to access the private key")
                                .small()
                                .color(egui::Color32::GRAY),
                        );
                    });
                });

                ui.add_space(16.0);

                // Show which operation requires PIN
                if let Some(ref operation) = self.pin_operation {
                    let op_text = match operation {
                        PinOperation::UseCertificate { thumbprint } => {
                            format!(
                                "Certificate: ...{}",
                                &thumbprint[thumbprint.len().saturating_sub(8)..]
                            )
                        }
                        PinOperation::Register { account_id } => {
                            format!("Registration: {}", account_id)
                        }
                        PinOperation::SignCall { call_id } => {
                            format!("Call: {}", call_id)
                        }
                    };
                    ui.label(
                        egui::RichText::new(op_text)
                            .small()
                            .color(egui::Color32::LIGHT_BLUE),
                    );
                    ui.add_space(8.0);
                }

                // PIN input field (masked)
                ui.label("PIN:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.pin_input)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter PIN"),
                );

                // Focus the input field when dialog opens
                if response.gained_focus() || self.pin_input.is_empty() {
                    response.request_focus();
                }

                // Submit on Enter key
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit_pin = true;
                }

                // Error message
                if let Some(ref error) = self.pin_error {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(error).color(egui::Color32::RED));
                }

                // Attempt counter warning
                if self.pin_attempts > 0 {
                    ui.add_space(4.0);
                    let remaining = MAX_PIN_ATTEMPTS.saturating_sub(self.pin_attempts);
                    let warning_color = if remaining <= 1 {
                        egui::Color32::RED
                    } else {
                        egui::Color32::YELLOW
                    };
                    ui.label(
                        egui::RichText::new(format!("Attempts remaining: {}", remaining))
                            .small()
                            .color(warning_color),
                    );
                }

                ui.add_space(16.0);

                // Buttons
                ui.horizontal(|ui| {
                    // Cancel button
                    if ui.button("Cancel").clicked() {
                        cancel_pin = true;
                    }

                    ui.add_space(ui.available_width() - 60.0);

                    // OK button
                    let ok_enabled = !self.pin_input.is_empty();
                    if ui
                        .add_enabled(ok_enabled, egui::Button::new("OK"))
                        .clicked()
                    {
                        submit_pin = true;
                    }
                });
            });

        // Handle actions after dialog rendering
        if submit_pin {
            self.submit_pin();
        } else if cancel_pin {
            self.cancel_pin();
        }
    }

    /// Shows the PIN dialog for an operation.
    fn show_pin_dialog_for(&mut self, operation: PinOperation) {
        info!(operation = ?operation, "Showing PIN dialog");
        self.pin_operation = Some(operation);
        self.pin_input.clear();
        self.pin_error = None;
        self.pin_attempts = 0;
        self.show_pin_dialog = true;
    }

    /// Handles PIN submission.
    fn submit_pin(&mut self) {
        let pin = self.pin_input.clone();
        self.pin_input.clear(); // Clear immediately for security

        if pin.is_empty() {
            self.pin_error = Some("PIN cannot be empty".to_string());
            return;
        }

        info!("PIN submitted for operation");
        self.pin_attempts += 1;

        // Process the PIN based on operation
        if let Some(operation) = self.pin_operation.take() {
            match operation {
                PinOperation::UseCertificate { thumbprint } => {
                    self.use_certificate_with_pin(&thumbprint, &pin);
                }
                PinOperation::Register { account_id } => {
                    // TODO: Pass PIN to registration agent
                    self.status_message = format!("PIN entered for registration: {}", account_id);
                    self.show_pin_dialog = false;
                }
                PinOperation::SignCall { call_id } => {
                    // TODO: Pass PIN to call signing
                    self.status_message = format!("PIN entered for call: {}", call_id);
                    self.show_pin_dialog = false;
                }
            }
        }
    }

    /// Handles PIN cancellation.
    fn cancel_pin(&mut self) {
        info!("PIN entry cancelled");
        self.pin_input.clear();
        self.pin_error = None;
        self.pin_operation = None;
        self.pin_attempts = 0;
        self.show_pin_dialog = false;
        self.status_message = "PIN entry cancelled".to_string();
    }

    /// Uses certificate with PIN for signing operations.
    ///
    /// This method verifies the PIN against the smart card before configuring
    /// the certificate for use. The PIN is used to acquire the private key
    /// which validates access to the smart card.
    fn use_certificate_with_pin(&mut self, thumbprint: &str, pin: &str) {
        use client_core::{CertStoreError, CertificateStore};
        use client_types::SmartCardPin;

        let cert_store = CertificateStore::open_personal();
        let smart_card_pin = SmartCardPin::new(pin);

        // First verify the PIN is correct by attempting to access the private key
        match cert_store.verify_pin(thumbprint, &smart_card_pin) {
            Ok(true) => {
                info!(thumbprint = %thumbprint, "PIN verified successfully");

                // PIN is correct, now get the certificate chain
                match cert_store.get_certificate_chain(thumbprint) {
                    Ok(cert_chain) => {
                        info!(
                            thumbprint = %thumbprint,
                            chain_length = cert_chain.len(),
                            "Retrieved certificate chain after PIN verification"
                        );

                        if let Some(ref mut app) = self.client_app {
                            app.set_client_certificate(cert_chain.clone(), thumbprint);
                            self.status_message =
                                "Certificate configured for authentication".to_string();
                            info!("Certificate configured in ClientApp");
                        } else {
                            self.pending_cert_chain = Some(cert_chain);
                            self.pending_cert_thumbprint = Some(thumbprint.to_string());
                            self.status_message =
                                "Certificate will be used when connecting".to_string();
                        }

                        self.show_pin_dialog = false;
                        self.pin_error = None;
                    }
                    Err(e) => {
                        self.status_message = format!("Failed to get certificate: {}", e);
                        self.show_pin_dialog = false;
                        warn!(error = %e, "Failed to get certificate chain after PIN verification");
                    }
                }
            }
            Ok(false) => {
                // This shouldn't happen with our implementation, but handle it
                self.pin_error = Some("PIN verification failed".to_string());
                self.pin_operation = Some(PinOperation::UseCertificate {
                    thumbprint: thumbprint.to_string(),
                });
            }
            Err(e) => {
                // Handle specific error types
                match e {
                    CertStoreError::PinIncorrect => {
                        self.pin_error = Some("Incorrect PIN".to_string());
                        self.pin_operation = Some(PinOperation::UseCertificate {
                            thumbprint: thumbprint.to_string(),
                        });

                        if self.pin_attempts >= MAX_PIN_ATTEMPTS {
                            self.pin_error =
                                Some("Too many incorrect attempts. Card may be locked.".to_string());
                            warn!("PIN attempt limit reached");
                        }
                    }
                    CertStoreError::SmartCardNotPresent => {
                        self.pin_error = Some("Smart card not present".to_string());
                        self.status_message = "Please insert your smart card".to_string();
                        // Keep dialog open to retry after card insertion
                        self.pin_operation = Some(PinOperation::UseCertificate {
                            thumbprint: thumbprint.to_string(),
                        });
                    }
                    CertStoreError::PinRequired => {
                        // This means we need to try again with PIN
                        self.pin_error = Some("PIN is required".to_string());
                        self.pin_operation = Some(PinOperation::UseCertificate {
                            thumbprint: thumbprint.to_string(),
                        });
                    }
                    _ => {
                        self.status_message = format!("Certificate error: {}", e);
                        self.show_pin_dialog = false;
                        warn!(error = %e, "Failed to verify PIN");
                    }
                }
            }
        }
    }
}

impl eframe::App for SipClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process tray events
        self.process_tray_events(ctx);

        // Process events from core
        self.process_events();

        // Process ringtone audio frames (for buffer refill)
        self.ringtone_player.process_frame();

        // Process auto-answer timer
        self.process_auto_answer();

        // Handle close request with unsaved settings check
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && !self.pending_close {
            if self.settings_view.is_dirty() {
                // Show confirmation dialog
                self.show_unsaved_settings_dialog = true;
                // Cancel the close - we'll handle it after dialog
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            // If not dirty, let the close proceed normally
        }

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
                // Render call tabs if multiple calls
                if let Some(action) = self.render_call_tabs(ui) {
                    self.handle_call_action(action);
                }
                // Render the call view for the focused call
                if let Some(action) = self.call_view.render(
                    ui,
                    self.active_call.as_ref(),
                    &self.available_inputs,
                    &self.available_outputs,
                    self.current_input_device.as_deref(),
                    self.current_output_device.as_deref(),
                ) {
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

        // Dialogs (rendered last for z-order)
        self.render_error_dialog(ctx);
        self.render_pin_dialog(ctx);

        // Incoming call dialog
        if let Some(action) = self.render_incoming_call_dialog(ctx) {
            self.handle_call_action(action);
        }

        // Insecure mode warning dialog
        if let Some(action) = self.settings_view.render_insecure_warning_dialog(ctx) {
            self.handle_settings_action(action);
        }

        // Unsaved settings confirmation dialog
        self.render_unsaved_settings_dialog(ctx);

        // Handle pending close after dialog confirmation
        if self.pending_close && !self.show_unsaved_settings_dialog {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        // Request repaint for animations
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        info!("Application shutting down");

        // Save settings if dirty before exit
        if self.settings_view.is_dirty() {
            info!("Saving dirty settings on exit");
            self.save_settings();
        }

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
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.toggle_hold()) {
                        Ok(is_on_hold) => {
                            self.status_message = if is_on_hold {
                                "Call on hold".to_string()
                            } else {
                                "Call resumed".to_string()
                            };
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Failed to toggle hold: {e}"));
                            self.show_error_dialog = true;
                        }
                    }
                }
            }
            crate::views::CallAction::Dtmf { digit } => {
                info!(digit = ?digit, "Sending DTMF");
                if let Some(ref app) = self.client_app {
                    let runtime = self.runtime.clone();
                    if let Err(e) = runtime.block_on(app.send_dtmf(digit)) {
                        warn!(error = %e, "Failed to send DTMF");
                    } else {
                        self.status_message = format!("DTMF: {}", digit.to_char());
                    }
                }
            }
            crate::views::CallAction::Accept { call_id } => {
                info!(call_id = %call_id, "Accepting incoming call");
                self.show_incoming_call_dialog = false;
                self.stop_ringtone();
                self.auto_answer_timer = None;

                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.accept_incoming_call(&call_id)) {
                        Ok(()) => {
                            self.status_message = "Call accepted".to_string();
                            self.active_view = ActiveView::Call;
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Failed to accept call: {e}"));
                            self.show_error_dialog = true;
                        }
                    }
                }
                self.incoming_call = None;
            }
            crate::views::CallAction::Reject { call_id } => {
                info!(call_id = %call_id, "Rejecting incoming call");
                self.show_incoming_call_dialog = false;
                self.stop_ringtone();
                self.auto_answer_timer = None;

                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    if let Err(e) = runtime.block_on(app.reject_incoming_call(&call_id)) {
                        warn!(error = %e, "Failed to reject call");
                    }
                }
                self.incoming_call = None;
                self.status_message = "Call rejected".to_string();
            }
            crate::views::CallAction::SwitchTo { call_id } => {
                info!(call_id = %call_id, "Switching to call");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.switch_to_call(&call_id)) {
                        Ok(()) => {
                            self.status_message = "Switched to call".to_string();
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Failed to switch call: {e}"));
                            self.show_error_dialog = true;
                        }
                    }
                }
            }
            crate::views::CallAction::SwitchInputDevice { device_name } => {
                info!(device = ?device_name, "Switching input device");
                if let Some(ref app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.switch_input_device(device_name.clone())) {
                        Ok(()) => {
                            self.current_input_device = device_name;
                            self.status_message = "Microphone changed".to_string();
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to switch input device");
                            self.status_message = format!("Failed to switch microphone: {e}");
                        }
                    }
                }
            }
            crate::views::CallAction::SwitchOutputDevice { device_name } => {
                info!(device = ?device_name, "Switching output device");
                if let Some(ref app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.switch_output_device(device_name.clone())) {
                        Ok(()) => {
                            self.current_output_device = device_name;
                            self.status_message = "Speaker changed".to_string();
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to switch output device");
                            self.status_message = format!("Failed to switch speaker: {e}");
                        }
                    }
                }
            }
            crate::views::CallAction::Transfer { target_uri } => {
                info!(target = %target_uri, "Transferring call");
                if let Some(ref mut app) = self.client_app {
                    let runtime = self.runtime.clone();
                    match runtime.block_on(app.transfer_call(&target_uri)) {
                        Ok(()) => {
                            self.status_message = format!("Transferring to {target_uri}...");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to transfer call");
                            self.status_message = format!("Transfer failed: {e}");
                        }
                    }
                }
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
                self.save_settings();
            }
            crate::views::SettingsAction::Discard => {
                info!("Discarding settings changes");
                self.discard_settings();
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
                self.settings_view
                    .set_selected_certificate(Some(thumbprint));
                self.status_message = "Certificate selected".to_string();
            }
            crate::views::SettingsAction::UseCertificate(thumbprint) => {
                info!(thumbprint = %thumbprint, "Using certificate for authentication");
                self.use_certificate(&thumbprint);
            }
            crate::views::SettingsAction::PinRequired { thumbprint } => {
                info!(thumbprint = %thumbprint, "PIN required for certificate operation");
                self.show_pin_dialog_for(PinOperation::UseCertificate { thumbprint });
            }
            crate::views::SettingsAction::SetVerificationMode(mode) => {
                info!(mode = ?mode, "Setting server certificate verification mode");
                self.set_verification_mode(mode);
            }
            crate::views::SettingsAction::BrowseForCaFile => {
                info!("Browsing for CA file");
                self.browse_for_ca_file();
            }
            crate::views::SettingsAction::ConfirmInsecureMode => {
                info!("User confirmed insecure mode");
                self.apply_insecure_mode();
            }
        }
    }

    fn use_certificate(&mut self, thumbprint: &str) {
        use client_core::{CertStoreError, CertificateStore};

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
            Err(CertStoreError::PinRequired) => {
                // Smart card needs PIN - show dialog
                info!(thumbprint = %thumbprint, "PIN required for certificate");
                self.show_pin_dialog_for(PinOperation::UseCertificate {
                    thumbprint: thumbprint.to_string(),
                });
                return;
            }
            Err(CertStoreError::SmartCardNotPresent) => {
                self.status_message = "Please insert your smart card".to_string();
                self.registration_state = RegistrationState::SmartCardNotPresent;
                warn!("Smart card not present");
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
                    app.set_client_certificate(cert_chain.clone(), thumbprint);
                    self.status_message = "Certificate configured for authentication".to_string();
                    info!("Certificate configured in ClientApp");
                } else {
                    // Store for later when ClientApp is initialized
                    self.pending_cert_chain = Some(cert_chain);
                    self.pending_cert_thumbprint = Some(thumbprint.to_string());
                    self.status_message = "Certificate will be used when connecting".to_string();
                }
            }
            Err(CertStoreError::PinRequired) => {
                // Smart card needs PIN - show dialog
                info!(thumbprint = %thumbprint, "PIN required for certificate chain");
                self.show_pin_dialog_for(PinOperation::UseCertificate {
                    thumbprint: thumbprint.to_string(),
                });
            }
            Err(CertStoreError::PinIncorrect) => {
                self.pin_error = Some("Incorrect PIN".to_string());
                self.show_pin_dialog_for(PinOperation::UseCertificate {
                    thumbprint: thumbprint.to_string(),
                });
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

    fn set_verification_mode(&mut self, mode: client_types::ServerCertVerificationMode) {
        use client_types::ServerCertVerificationMode;

        // Update the settings view
        self.settings_view
            .set_server_cert_verification(mode.clone());

        // Update the custom CA path if in Custom mode
        if let ServerCertVerificationMode::Custom { ref ca_file_path } = mode {
            self.settings_view.set_custom_ca_path(ca_file_path.clone());
        }

        // TODO: Apply to SipTransport when connected
        // For now, just update the UI state
        self.status_message = format!("Verification mode set to: {}", mode.label());
        info!(mode = ?mode, "Server certificate verification mode updated");
    }

    fn browse_for_ca_file(&mut self) {
        // For now, user must type the path manually
        // TODO: Add rfd (native file dialog) dependency for file browsing
        self.status_message = "Enter the CA file path manually in the text field".to_string();
        info!("User requested file browser - must enter path manually for now");
    }

    fn apply_insecure_mode(&mut self) {
        // The warning was already shown and confirmed by the user
        self.set_verification_mode(client_types::ServerCertVerificationMode::Insecure);
        self.status_message =
            "WARNING: Insecure mode enabled - certificates not validated".to_string();
        warn!("User enabled insecure certificate verification mode");
    }

    /// Saves current settings to disk.
    fn save_settings(&mut self) {
        // Collect settings from the view
        let (general, audio, network, ui) = self.settings_view.collect_settings();

        // Update the settings manager
        {
            let settings = self.settings_manager.settings_mut();
            settings.general = general;
            settings.audio = audio;
            settings.network = network;
            settings.ui = ui;
        }

        // Save to disk
        match self.settings_manager.save() {
            Ok(()) => {
                info!("Settings saved successfully");
                self.settings_view.clear_dirty();
                self.status_message = "Settings saved".to_string();
            }
            Err(e) => {
                error!(error = %e, "Failed to save settings");
                self.error_message = Some(format!("Failed to save settings: {e}"));
                self.show_error_dialog = true;
            }
        }

        // Sync with ClientApp if available
        if let Some(ref mut app) = self.client_app {
            let settings = self.settings_manager.settings();
            let app_settings = app.settings_mut();
            *app_settings.settings_mut() = settings.clone();
        }
    }

    /// Discards unsaved settings changes and reloads from disk.
    fn discard_settings(&mut self) {
        // Reload settings from the manager (which has the last saved state)
        self.settings_view.load_from_settings(self.settings_manager.settings());
        self.status_message = "Changes discarded".to_string();
        info!("Settings changes discarded");
    }

    /// Starts ringtone playback for an incoming call.
    fn start_ringtone(&mut self) {
        // Configure ringtone from settings
        if let Some(ref app) = self.client_app {
            let settings = app.settings().settings();

            // Set ring device if configured
            self.ringtone_player
                .set_ring_device(settings.audio.ring_device.clone());

            // Set volume
            self.ringtone_player.set_volume(settings.audio.ring_volume);

            // Load custom ringtone if configured
            if let Some(ref path) = settings.audio.ringtone_file_path {
                if let Err(e) = self.ringtone_player.load(path) {
                    warn!(error = %e, path = %path, "Failed to load ringtone file, using default tone");
                    self.ringtone_player.use_default();
                }
            } else {
                self.ringtone_player.use_default();
            }
        }

        // Start playing
        if let Err(e) = self.ringtone_player.start() {
            warn!(error = %e, "Failed to start ringtone playback");
        } else {
            debug!("Ringtone playback started");
        }
    }

    /// Stops ringtone playback.
    fn stop_ringtone(&mut self) {
        if self.ringtone_player.is_playing() {
            self.ringtone_player.stop();
            debug!("Ringtone playback stopped");
        }
    }

    /// Refreshes the list of available audio devices.
    fn refresh_audio_devices(&mut self) {
        use client_audio::DeviceManager;

        let manager = DeviceManager::new();

        // Get input devices
        match manager.list_input_devices() {
            Ok(devices) => {
                self.available_inputs = vec!["Default".to_string()];
                self.available_inputs
                    .extend(devices.into_iter().map(|d| d.name));
            }
            Err(e) => {
                warn!(error = %e, "Failed to list input devices");
            }
        }

        // Get output devices
        match manager.list_output_devices() {
            Ok(devices) => {
                self.available_outputs = vec!["Default".to_string()];
                self.available_outputs
                    .extend(devices.into_iter().map(|d| d.name));
            }
            Err(e) => {
                warn!(error = %e, "Failed to list output devices");
            }
        }

        debug!(
            inputs = ?self.available_inputs.len(),
            outputs = ?self.available_outputs.len(),
            "Refreshed audio devices"
        );
    }

    /// Checks if auto-answer is enabled and starts the timer if so.
    fn check_auto_answer(&mut self, call_id: &str) {
        if let Some(ref app) = self.client_app {
            let settings = app.settings().settings();

            if settings.general.auto_answer_enabled {
                let delay = settings.general.auto_answer_delay_secs;
                info!(
                    call_id = %call_id,
                    delay_secs = delay,
                    "Auto-answer enabled, starting timer"
                );
                self.auto_answer_timer = Some((call_id.to_string(), Instant::now()));
            }
        }
    }

    /// Processes the auto-answer timer and answers the call if the delay has elapsed.
    fn process_auto_answer(&mut self) {
        let should_answer = if let Some((ref call_id, started_at)) = self.auto_answer_timer {
            if let Some(ref app) = self.client_app {
                let settings = app.settings().settings();
                let delay = std::time::Duration::from_secs(settings.general.auto_answer_delay_secs as u64);

                if started_at.elapsed() >= delay {
                    info!(call_id = %call_id, "Auto-answer timer elapsed, answering call");
                    Some(call_id.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(call_id) = should_answer {
            self.auto_answer_timer = None;
            self.show_incoming_call_dialog = false;
            self.stop_ringtone();

            if let Some(ref mut app) = self.client_app {
                let runtime = self.runtime.clone();
                match runtime.block_on(app.accept_incoming_call(&call_id)) {
                    Ok(()) => {
                        self.status_message = "Call auto-answered".to_string();
                        self.active_view = ActiveView::Call;
                    }
                    Err(e) => {
                        self.error_message = Some(format!("Failed to auto-answer call: {e}"));
                        self.show_error_dialog = true;
                    }
                }
            }
            self.incoming_call = None;
        }
    }
}
