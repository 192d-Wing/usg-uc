//! Main GUI application using native Windows controls.
//!
//! This module provides the main window and coordinates between views
//! using native-windows-gui for true Windows native appearance.

use crate::dialogs::{ContactDialog, ContactDialogResult, DtmfAction, DtmfDialog, PinDialog, PinDialogResult, TransferDialog, TransferDialogResult};
use crate::notifications::NotificationManager;
use crate::tray::{SystemTray, TrayAction};
use crate::views::{CallView, ContactsView, DialerView, SettingsView};
use client_audio::RingtonePlayer;
use client_core::{
    load_certs_from_pem_file, AppEvent, CertVerificationMode, ClientApp, ContactManager,
    SettingsManager,
};
use client_types::{CallInfo, CallState, DtmfDigit, RegistrationState};
use native_windows_gui as nwg;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::mpsc::{Receiver as StdReceiver, TryRecvError};
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Active view in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct IncomingCallAlert {
    /// Internal call ID.
    pub call_id: String,
    /// Remote party SIP URI.
    pub remote_uri: String,
    /// Remote party display name (if available).
    pub remote_display_name: Option<String>,
}

/// Main application window using native Windows controls.
pub struct SipClientApp {
    /// Main window handle.
    window: nwg::Window,
    /// Tab control for navigation.
    tab_control: nwg::TabsContainer,
    /// Status bar.
    #[allow(dead_code)]
    status_bar: nwg::StatusBar,
    /// Timer for event polling.
    #[allow(dead_code)]
    timer: nwg::AnimationTimer,

    // System tray
    /// System tray manager.
    system_tray: RefCell<Option<SystemTray>>,
    /// Tray action receiver.
    #[allow(dead_code)]
    tray_action_rx: RefCell<Option<StdReceiver<TrayAction>>>,

    // View containers (tabs)
    /// Dialer tab.
    #[allow(dead_code)]
    dialer_tab: nwg::Tab,
    /// Call tab.
    #[allow(dead_code)]
    call_tab: nwg::Tab,
    /// Contacts tab.
    #[allow(dead_code)]
    contacts_tab: nwg::Tab,
    /// Settings tab.
    #[allow(dead_code)]
    settings_tab: nwg::Tab,

    // View state
    /// Dialer view.
    dialer_view: RefCell<DialerView>,
    /// Call view.
    call_view: RefCell<CallView>,
    /// Contacts view.
    contacts_view: RefCell<ContactsView>,
    /// Settings view.
    settings_view: RefCell<SettingsView>,

    // Application state (wrapped in RefCell for interior mutability)
    /// Application core.
    client_app: RefCell<Option<ClientApp>>,
    /// Async runtime.
    runtime: Arc<Runtime>,
    /// Event receiver from core.
    #[allow(dead_code)]
    event_rx: RefCell<mpsc::Receiver<AppEvent>>,
    /// Current registration state.
    #[allow(dead_code)]
    registration_state: RefCell<RegistrationState>,
    /// Current focused call info.
    active_call: RefCell<Option<CallInfo>>,
    /// All active calls.
    #[allow(dead_code)]
    all_calls: RefCell<Vec<CallInfo>>,
    /// Incoming call alert.
    incoming_call: RefCell<Option<IncomingCallAlert>>,
    /// Status message.
    status_message: RefCell<String>,
    /// Error message.
    error_message: RefCell<Option<String>>,
    /// Notification manager.
    notifications: RefCell<NotificationManager>,
    /// PIN input state.
    pin_input: RefCell<String>,
    /// PIN error message.
    pin_error: RefCell<Option<String>>,
    /// PIN operation.
    pin_operation: RefCell<Option<PinOperation>>,
    /// PIN attempts.
    pin_attempts: RefCell<u8>,
    /// Ringtone player.
    ringtone_player: RefCell<RingtonePlayer>,
    /// Auto-answer timer.
    auto_answer_timer: RefCell<Option<(String, Instant)>>,
    /// Available input devices.
    available_inputs: RefCell<Vec<String>>,
    /// Available output devices.
    available_outputs: RefCell<Vec<String>>,
    /// Current input device.
    #[allow(dead_code)]
    current_input_device: RefCell<Option<String>>,
    /// Current output device.
    #[allow(dead_code)]
    current_output_device: RefCell<Option<String>>,
    /// Settings manager.
    settings_manager: RefCell<SettingsManager>,
    /// Contact manager.
    contact_manager: RefCell<ContactManager>,
    /// Whether window is closing.
    is_closing: RefCell<bool>,
}

impl SipClientApp {
    /// Builds and displays the application window.
    pub fn build() -> Result<Rc<Self>, nwg::NwgError> {
        // Create async runtime
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| {
                    nwg::NwgError::resource_create(format!("Failed to create async runtime: {}", e))
                })?,
        );

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel(64);

        // Initialize client app
        let local_sip_addr: SocketAddr = "0.0.0.0:5060"
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().map_err(|_| ()).ok().unwrap_or_else(|| {
                // This is a fallback that shouldn't happen
                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
            }));
        let local_media_addr: SocketAddr = "0.0.0.0:16384"
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().map_err(|_| ()).ok().unwrap_or_else(|| {
                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
            }));

        let client_app = match ClientApp::new(local_sip_addr, local_media_addr, event_tx) {
            Ok(app) => Some(app),
            Err(e) => {
                error!("Failed to initialize client app: {}", e);
                None
            }
        };

        // Initialize settings manager
        let settings_manager = SettingsManager::new().map_err(|e| {
            nwg::NwgError::resource_create(format!("Failed to create settings manager: {}", e))
        })?;

        // Initialize contact manager
        let contact_manager = ContactManager::new().map_err(|e| {
            nwg::NwgError::resource_create(format!("Failed to create contact manager: {}", e))
        })?;

        // Create the main window - larger, modern sizing with colorful title
        let mut window = Default::default();
        nwg::Window::builder()
            .size((500, 720))
            .position((300, 100))
            .title("📞 USG SIP Soft Client - CNSA 2.0 🔒")
            .flags(
                nwg::WindowFlags::WINDOW
                    | nwg::WindowFlags::VISIBLE
                    | nwg::WindowFlags::MINIMIZE_BOX,
            )
            .build(&mut window)?;

        // Create tab control for navigation
        let mut tab_control = Default::default();
        nwg::TabsContainer::builder()
            .parent(&window)
            .position((10, 10))
            .size((480, 660))
            .build(&mut tab_control)?;

        // Create status bar
        let mut status_bar = Default::default();
        nwg::StatusBar::builder()
            .parent(&window)
            .text("Ready")
            .build(&mut status_bar)?;

        // Create timer for event polling (100ms interval)
        let mut timer = Default::default();
        nwg::AnimationTimer::builder()
            .parent(&window)
            .interval(std::time::Duration::from_millis(100))
            .build(&mut timer)?;

        // Create tabs
        let mut dialer_tab = Default::default();
        nwg::Tab::builder()
            .text("Dialer")
            .parent(&tab_control)
            .build(&mut dialer_tab)?;

        let mut call_tab = Default::default();
        nwg::Tab::builder()
            .text("Call")
            .parent(&tab_control)
            .build(&mut call_tab)?;

        let mut contacts_tab = Default::default();
        nwg::Tab::builder()
            .text("Contacts")
            .parent(&tab_control)
            .build(&mut contacts_tab)?;

        let mut settings_tab = Default::default();
        nwg::Tab::builder()
            .text("Settings")
            .parent(&tab_control)
            .build(&mut settings_tab)?;

        // Create views
        let dialer_view = DialerView::build(&dialer_tab)?;
        let call_view = CallView::build(&call_tab)?;
        let contacts_view = ContactsView::build(&contacts_tab)?;
        let mut settings_view = SettingsView::build(&settings_tab)?;

        // Load settings into view
        settings_view.load_from_settings(settings_manager.settings());

        // Load contacts into view
        let mut contacts_view = contacts_view;
        contacts_view.set_contacts(contact_manager.contacts().cloned());

        // Create system tray (requires window to be built first)
        let (system_tray, tray_action_rx) = match SystemTray::new(&window) {
            Ok((tray, rx)) => {
                info!("System tray initialized");
                (Some(tray), Some(rx))
            }
            Err(e) => {
                warn!(error = %e, "Failed to create system tray");
                (None, None)
            }
        };

        // Build the app
        let app = Rc::new(Self {
            window,
            tab_control,
            status_bar,
            timer,
            system_tray: RefCell::new(system_tray),
            tray_action_rx: RefCell::new(tray_action_rx),
            dialer_tab,
            call_tab,
            contacts_tab,
            settings_tab,
            dialer_view: RefCell::new(dialer_view),
            call_view: RefCell::new(call_view),
            contacts_view: RefCell::new(contacts_view),
            settings_view: RefCell::new(settings_view),
            client_app: RefCell::new(client_app),
            runtime,
            event_rx: RefCell::new(event_rx),
            registration_state: RefCell::new(RegistrationState::Unregistered),
            active_call: RefCell::new(None),
            all_calls: RefCell::new(Vec::new()),
            incoming_call: RefCell::new(None),
            status_message: RefCell::new("Ready".to_string()),
            error_message: RefCell::new(None),
            notifications: RefCell::new(NotificationManager::new("USG SIP Client")),
            pin_input: RefCell::new(String::new()),
            pin_error: RefCell::new(None),
            pin_operation: RefCell::new(None),
            pin_attempts: RefCell::new(0),
            ringtone_player: RefCell::new(RingtonePlayer::new()),
            auto_answer_timer: RefCell::new(None),
            available_inputs: RefCell::new(vec!["Default".to_string()]),
            available_outputs: RefCell::new(vec!["Default".to_string()]),
            current_input_device: RefCell::new(None),
            current_output_device: RefCell::new(None),
            settings_manager: RefCell::new(settings_manager),
            contact_manager: RefCell::new(contact_manager),
            is_closing: RefCell::new(false),
        });

        // Bind events
        Self::bind_events(&app);

        // Start the timer
        app.timer.start();

        Ok(app)
    }

    /// Binds window events to handlers.
    fn bind_events(app: &Rc<Self>) {
        let app_weak = Rc::downgrade(app);

        // Window close event
        let app_close = app_weak.clone();
        nwg::bind_event_handler(
            &app.window.handle,
            &app.window.handle,
            move |evt, _evt_data, _handle| {
                if let Some(app) = app_close.upgrade() {
                    match evt {
                        nwg::Event::OnWindowClose => {
                            app.on_close();
                        }
                        _ => {}
                    }
                }
            },
        );

        // Note: AnimationTimer events are not bound via bind_event_handler.
        // We handle them in the on_timer method which is called from the event loop polling.

        // Tab selection change
        let app_tab = app_weak.clone();
        nwg::bind_event_handler(
            &app.tab_control.handle,
            &app.window.handle,
            move |evt, _evt_data, _handle| {
                if let Some(app) = app_tab.upgrade() {
                    if evt == nwg::Event::TabsContainerChanged {
                        app.on_tab_change();
                    }
                }
            },
        );

        // Bind view-specific events
        app.dialer_view.borrow().bind_events(app);
        app.call_view.borrow().bind_events(app);
        app.contacts_view.borrow().bind_events(app);
        app.settings_view.borrow().bind_events(app);

        // TODO: Bind tray events - currently disabled due to handle type incompatibility
        // Need to investigate proper NWG TrayNotification event binding
        #[allow(unused_variables)]
        if let Some(ref tray) = *app.system_tray.borrow() {
            // Temporarily disabled tray event binding
            /*
            let app_tray_icon = app_weak.clone();
            nwg::bind_event_handler(
                &tray.tray_icon().handle,
                &app.window().handle,
                move |evt, _evt_data, _handle| {
                    if let Some(app) = app_tray_icon.upgrade() {
                        if evt == nwg::Event::OnContextMenu {
                            app.on_tray_context_menu();
                        } else if evt == nwg::Event::OnMousePress(nwg::MousePressEvent::MousePressLeftDown) {
                            app.on_tray_click();
                        }
                    }
                },
            );

            // Show menu item click
            let app_show = app_weak.clone();
            nwg::bind_event_handler(
                &tray.show_item().handle,
                &app.window().handle,
                move |evt, _evt_data, _handle| {
                    if let Some(app) = app_show.upgrade() {
                        if evt == nwg::Event::OnMenuItemSelected {
                            app.on_tray_show();
                        }
                    }
                },
            );

            // Hide menu item click
            let app_hide = app_weak.clone();
            nwg::bind_event_handler(
                &tray.hide_item().handle,
                &app.window().handle,
                move |evt, _evt_data, _handle| {
                    if let Some(app) = app_hide.upgrade() {
                        if evt == nwg::Event::OnMenuItemSelected {
                            app.on_tray_hide();
                        }
                    }
                },
            );

            // Exit menu item click
            let app_exit = app_weak.clone();
            nwg::bind_event_handler(
                &tray.exit_item().handle,
                &app.window().handle,
                move |evt, _evt_data, _handle| {
                    if let Some(app) = app_exit.upgrade() {
                        if evt == nwg::Event::OnMenuItemSelected {
                            app.on_tray_exit();
                        }
                    }
                },
            );
            */
        }
    }

    /// Called when the window is closing.
    fn on_close(&self) {
        *self.is_closing.borrow_mut() = true;

        // Stop timer
        self.timer.stop();

        // Save settings if dirty
        if self.settings_view.borrow().is_dirty() {
            info!("Saving dirty settings on exit");
            self.save_settings();
        }

        // Shutdown client app
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            let _ = self.runtime.block_on(app.shutdown());
        }

        nwg::stop_thread_dispatch();
    }

    /// Called on timer tick - processes events and updates UI.
    #[allow(dead_code)]
    fn on_timer(&self) {
        self.process_events();
        self.process_tray_events();
        self.process_auto_answer();

        // Update ringtone
        self.ringtone_player.borrow_mut().process_frame();

        // Update status bar
        self.status_bar
            .set_text(0, &self.status_message.borrow());
    }

    /// Called when tab selection changes.
    fn on_tab_change(&self) {
        let selected = self.tab_control.selected_tab();
        debug!("Tab changed to: {}", selected);

        // Refresh audio devices when entering call tab
        if selected == 1 {
            self.refresh_audio_devices();
        }
    }

    /// Processes pending events from the core.
    fn process_events(&self) {
        let mut event_rx = self.event_rx.borrow_mut();

        while let Ok(event) = event_rx.try_recv() {
            match event {
                AppEvent::RegistrationStateChanged { account_id, state } => {
                    info!(
                        account_id = %account_id,
                        state = ?state,
                        "Registration state changed"
                    );

                    let was_registered =
                        *self.registration_state.borrow() == RegistrationState::Registered;
                    let is_registered = state == RegistrationState::Registered;

                    // Clear registration in progress when we get a final state
                    if state == RegistrationState::Registered
                        || state == RegistrationState::Unregistered
                        || state == RegistrationState::Failed
                    {
                        self.settings_view
                            .borrow_mut()
                            .set_registration_in_progress(false);
                    }

                    // Show notification on registration state change
                    if was_registered != is_registered {
                        self.notifications
                            .borrow()
                            .notify_registration(is_registered, account_id.clone());
                    }

                    *self.registration_state.borrow_mut() = state.clone();
                    *self.status_message.borrow_mut() = format!("Registration: {}", state);
                }
                AppEvent::CallStateChanged {
                    call_id,
                    state,
                    info,
                } => {
                    info!(call_id = %call_id, state = ?state, "Call state changed");
                    *self.active_call.borrow_mut() = Some(info);

                    // Update all_calls from the core
                    if let Some(ref app) = *self.client_app.borrow() {
                        *self.all_calls.borrow_mut() = app.all_call_info();
                    }

                    // Switch to call tab when call starts
                    if state.is_active() {
                        self.tab_control.set_selected_tab(1);
                        self.refresh_audio_devices();
                    }

                    // Switch back to dialer when call ends
                    if state == CallState::Terminated {
                        if let Some(ref app) = *self.client_app.borrow() {
                            *self.all_calls.borrow_mut() = app.all_call_info();
                        }

                        if self.all_calls.borrow().is_empty() {
                            *self.active_call.borrow_mut() = None;
                            self.tab_control.set_selected_tab(0);
                        }
                    }

                    // Update call view
                    self.call_view
                        .borrow_mut()
                        .update_call_info(self.active_call.borrow().as_ref());
                }
                AppEvent::IncomingCall {
                    call_id,
                    remote_uri,
                    remote_display_name,
                } => {
                    info!(call_id = %call_id, remote_uri = %remote_uri, "Incoming call");

                    *self.status_message.borrow_mut() = format!(
                        "Incoming call from {}",
                        remote_display_name.as_deref().unwrap_or(&remote_uri)
                    );

                    *self.incoming_call.borrow_mut() = Some(IncomingCallAlert {
                        call_id: call_id.clone(),
                        remote_uri: remote_uri.clone(),
                        remote_display_name: remote_display_name.clone(),
                    });

                    // Start ringtone
                    self.start_ringtone();

                    // Check auto-answer
                    self.check_auto_answer(&call_id);

                    // Show notification
                    self.notifications
                        .borrow()
                        .notify_incoming_call(remote_display_name.clone(), remote_uri.clone());

                    // Show incoming call dialog
                    self.show_incoming_call_dialog();
                }
                AppEvent::CallEnded {
                    call_id: _,
                    duration_secs,
                } => {
                    let remote_name = self
                        .active_call
                        .borrow()
                        .as_ref()
                        .and_then(|c| c.remote_display_name.clone());

                    if let Some(ref app) = *self.client_app.borrow() {
                        *self.all_calls.borrow_mut() = app.all_call_info();
                    }

                    self.stop_ringtone();
                    *self.auto_answer_timer.borrow_mut() = None;
                    *self.incoming_call.borrow_mut() = None;

                    if let Some(duration) = duration_secs {
                        *self.status_message.borrow_mut() = format!("Call ended ({duration}s)");
                    } else {
                        *self.status_message.borrow_mut() = "Call ended".to_string();
                    }

                    if self.all_calls.borrow().is_empty() {
                        *self.active_call.borrow_mut() = None;
                        self.tab_control.set_selected_tab(0);
                    } else {
                        *self.active_call.borrow_mut() = self.all_calls.borrow().first().cloned();
                    }

                    self.notifications
                        .borrow()
                        .notify_call_ended(remote_name, duration_secs);
                }
                AppEvent::Error { message } => {
                    error!(message = %message, "Application error");
                    *self.error_message.borrow_mut() = Some(message.clone());
                    self.notifications.borrow().notify_error("Error", &message);
                    self.show_error_dialog(&message);
                }
                AppEvent::SettingsChanged => {
                    *self.status_message.borrow_mut() = "Settings saved".to_string();
                }
                AppEvent::ContactsChanged => {
                    *self.status_message.borrow_mut() = "Contacts updated".to_string();
                }
                AppEvent::PinRequired {
                    operation,
                    thumbprint,
                } => {
                    info!(operation = ?operation, thumbprint = ?thumbprint, "PIN required");
                    if let Some(tp) = thumbprint {
                        self.show_pin_dialog_for(PinOperation::UseCertificate { thumbprint: tp });
                    }
                }
                AppEvent::PinCompleted { success, error } => {
                    if success {
                        info!("PIN operation completed successfully");
                        *self.status_message.borrow_mut() = "Authentication successful".to_string();
                    } else if let Some(err_msg) = error {
                        warn!(error = %err_msg, "PIN operation failed");
                        *self.pin_error.borrow_mut() = Some(err_msg);
                    }
                }
                AppEvent::TransferProgress {
                    call_id: _,
                    target_uri,
                    status_code,
                    is_success,
                    is_final,
                } => {
                    let status_text = match status_code {
                        100 => "Trying",
                        180..=183 => "Ringing",
                        200..=299 => "Success",
                        _ => "Failed",
                    };

                    if is_final {
                        if is_success {
                            *self.status_message.borrow_mut() =
                                format!("Transfer to {target_uri} completed successfully");
                        } else {
                            *self.status_message.borrow_mut() =
                                format!("Transfer to {target_uri} failed");
                        }
                    } else {
                        *self.status_message.borrow_mut() =
                            format!("Transfer to {target_uri}: {status_text}...");
                    }
                }
            }
        }
    }

    /// Processes pending tray actions from the channel.
    fn process_tray_events(&self) {
        if let Some(ref rx) = *self.tray_action_rx.borrow() {
            loop {
                match rx.try_recv() {
                    Ok(action) => match action {
                        TrayAction::ShowWindow => {
                            info!("Tray: Show window");
                            self.window.set_visible(true);
                            nwg::Window::set_focus(&self.window);
                        }
                        TrayAction::HideWindow => {
                            info!("Tray: Hide window");
                            self.window.set_visible(false);
                        }
                        TrayAction::Exit => {
                            info!("Tray: Exit requested");
                            self.on_close();
                        }
                    },
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        warn!("Tray action channel disconnected");
                        break;
                    }
                }
            }
        }
    }

    /// Called when tray icon is right-clicked (context menu).
    #[allow(dead_code)]
    fn on_tray_context_menu(&self) {
        if let Some(ref tray) = *self.system_tray.borrow() {
            tray.show_menu();
        }
    }

    /// Called when tray icon is left-clicked.
    #[allow(dead_code)]
    fn on_tray_click(&self) {
        // Show the window on tray click
        self.window.set_visible(true);
        nwg::Window::set_focus(&self.window);
    }

    /// Called when "Show" menu item is clicked.
    #[allow(dead_code)]
    fn on_tray_show(&self) {
        info!("Tray: Show window");
        self.window.set_visible(true);
        nwg::Window::set_focus(&self.window);
    }

    /// Called when "Hide" menu item is clicked.
    #[allow(dead_code)]
    fn on_tray_hide(&self) {
        info!("Tray: Hide window");
        self.window.set_visible(false);
    }

    /// Called when "Exit" menu item is clicked.
    #[allow(dead_code)]
    fn on_tray_exit(&self) {
        info!("Tray: Exit requested");
        self.on_close();
    }

    /// Shows an error dialog.
    fn show_error_dialog(&self, message: &str) {
        nwg::modal_error_message(&self.window, "Error", message);
    }

    /// Shows the incoming call dialog.
    fn show_incoming_call_dialog(&self) {
        let incoming = self.incoming_call.borrow();
        if let Some(ref call) = *incoming {
            let caller = call
                .remote_display_name
                .as_deref()
                .unwrap_or(&call.remote_uri);
            let message = format!("Incoming call from:\n{}", caller);

            // Use nwg message box with Yes/No for Accept/Reject
            let params = nwg::MessageParams {
                title: "Incoming Call",
                content: &message,
                buttons: nwg::MessageButtons::YesNo,
                icons: nwg::MessageIcons::Question,
            };

            let result = nwg::modal_message(&self.window, &params);

            drop(incoming); // Release borrow before handling

            match result {
                nwg::MessageChoice::Yes => {
                    self.accept_incoming_call();
                }
                nwg::MessageChoice::No => {
                    self.reject_incoming_call();
                }
                _ => {}
            }
        }
    }

    /// Shows the PIN entry dialog.
    fn show_pin_dialog_for(&self, operation: PinOperation) {
        info!(operation = ?operation, "Showing PIN dialog");

        let message = match &operation {
            PinOperation::UseCertificate { thumbprint } => {
                format!("Enter PIN for certificate:\n{}", &thumbprint[..8.min(thumbprint.len())])
            }
            PinOperation::Register { account_id } => {
                format!("Enter PIN to register account:\n{}", account_id)
            }
            PinOperation::SignCall { call_id } => {
                format!("Enter PIN to authenticate call:\n{}", call_id)
            }
        };

        let error = self.pin_error.borrow().clone();

        match PinDialog::show(&self.window, &message, error.as_deref()) {
            PinDialogResult::Entered(pin) => {
                *self.pin_input.borrow_mut() = pin;
                *self.pin_operation.borrow_mut() = Some(operation);
                self.submit_pin();
            }
            PinDialogResult::Cancelled => {
                self.cancel_pin();
            }
        }
    }

    /// Submits the PIN for verification.
    fn submit_pin(&self) {
        let pin = self.pin_input.borrow().clone();
        self.pin_input.borrow_mut().clear();

        if pin.is_empty() {
            *self.pin_error.borrow_mut() = Some("PIN cannot be empty".to_string());
            return;
        }

        info!("PIN submitted for operation");
        *self.pin_attempts.borrow_mut() += 1;

        if let Some(operation) = self.pin_operation.borrow_mut().take() {
            match operation {
                PinOperation::UseCertificate { thumbprint } => {
                    self.use_certificate_with_pin(&thumbprint, &pin);
                }
                PinOperation::Register { account_id } => {
                    *self.status_message.borrow_mut() =
                        format!("PIN entered for registration: {}", account_id);
                }
                PinOperation::SignCall { call_id } => {
                    *self.status_message.borrow_mut() =
                        format!("PIN entered for call: {}", call_id);
                }
            }
        }
    }

    /// Cancels PIN entry.
    fn cancel_pin(&self) {
        info!("PIN entry cancelled");
        self.pin_input.borrow_mut().clear();
        *self.pin_error.borrow_mut() = None;
        *self.pin_operation.borrow_mut() = None;
        *self.pin_attempts.borrow_mut() = 0;
        *self.status_message.borrow_mut() = "PIN entry cancelled".to_string();
    }

    /// Uses certificate with PIN for signing operations.
    fn use_certificate_with_pin(&self, thumbprint: &str, pin: &str) {
        use client_core::{CertStoreError, CertificateStore};
        use client_types::SmartCardPin;

        let cert_store = CertificateStore::open_personal();
        let smart_card_pin = SmartCardPin::new(pin);

        match cert_store.verify_pin(thumbprint, &smart_card_pin) {
            Ok(true) => {
                info!(thumbprint = %thumbprint, "PIN verified successfully");

                match cert_store.get_certificate_chain(thumbprint) {
                    Ok(cert_chain) => {
                        info!(
                            thumbprint = %thumbprint,
                            chain_length = cert_chain.len(),
                            "Retrieved certificate chain"
                        );

                        if let Some(ref mut app) = *self.client_app.borrow_mut() {
                            app.set_client_certificate(cert_chain.clone(), thumbprint);
                            *self.status_message.borrow_mut() =
                                "Certificate configured for authentication".to_string();
                        }
                    }
                    Err(e) => {
                        *self.status_message.borrow_mut() =
                            format!("Failed to get certificate: {}", e);
                        warn!(error = %e, "Failed to get certificate chain");
                    }
                }
            }
            Ok(false) => {
                *self.pin_error.borrow_mut() = Some("PIN verification failed".to_string());
                *self.pin_operation.borrow_mut() = Some(PinOperation::UseCertificate {
                    thumbprint: thumbprint.to_string(),
                });
            }
            Err(e) => match e {
                CertStoreError::PinIncorrect => {
                    *self.pin_error.borrow_mut() = Some("Incorrect PIN".to_string());
                    *self.pin_operation.borrow_mut() = Some(PinOperation::UseCertificate {
                        thumbprint: thumbprint.to_string(),
                    });

                    if *self.pin_attempts.borrow() >= MAX_PIN_ATTEMPTS {
                        *self.pin_error.borrow_mut() =
                            Some("Too many incorrect attempts. Card may be locked.".to_string());
                    }
                }
                CertStoreError::SmartCardNotPresent => {
                    *self.pin_error.borrow_mut() = Some("Smart card not present".to_string());
                    *self.status_message.borrow_mut() = "Please insert your smart card".to_string();
                    *self.pin_operation.borrow_mut() = Some(PinOperation::UseCertificate {
                        thumbprint: thumbprint.to_string(),
                    });
                }
                _ => {
                    *self.status_message.borrow_mut() = format!("Certificate error: {}", e);
                    warn!(error = %e, "Failed to verify PIN");
                }
            },
        }
    }

    // =========================================================================
    // Dialer Event Handlers
    // =========================================================================

    /// Called when a digit button is clicked on the dialer.
    pub fn on_dialer_digit(&self, digit: &str) {
        self.dialer_view.borrow().on_digit_click(digit);
    }

    /// Called when the call button is clicked on the dialer.
    pub fn on_dialer_call(&self) {
        if let Some(uri) = self.dialer_view.borrow().on_call() {
            self.make_call(&uri);
        }
    }

    /// Called when the clear button is clicked on the dialer.
    pub fn on_dialer_clear(&self) {
        self.dialer_view.borrow().on_clear();
    }

    /// Called when the backspace button is clicked on the dialer.
    pub fn on_dialer_backspace(&self) {
        self.dialer_view.borrow().on_backspace();
    }

    // =========================================================================
    // Call View Event Handlers
    // =========================================================================

    /// Called when the mute button is clicked.
    pub fn on_call_mute(&self) {
        self.toggle_mute();
    }

    /// Called when the hold button is clicked.
    pub fn on_call_hold(&self) {
        self.toggle_hold();
    }

    /// Called when the transfer button is clicked.
    pub fn on_call_transfer(&self) {
        self.show_transfer_dialog();
    }

    /// Called when the hangup button is clicked.
    pub fn on_call_hangup(&self) {
        self.hangup_call();
    }

    /// Called when the keypad button is clicked.
    pub fn on_call_keypad(&self) {
        self.show_dtmf_dialog();
    }

    /// Called when the input device selection changes.
    pub fn on_input_device_changed(&self) {
        if let Some(device) = self.call_view.borrow().selected_input_device() {
            info!(device = %device, "Input device changed");
            if let Some(ref app) = *self.client_app.borrow() {
                let device_clone = Some(device.clone());
                if let Err(e) = self.runtime.block_on(app.switch_input_device(device_clone)) {
                    warn!(error = %e, "Failed to switch input device");
                }
            }
        }
    }

    /// Called when the output device selection changes.
    pub fn on_output_device_changed(&self) {
        if let Some(device) = self.call_view.borrow().selected_output_device() {
            info!(device = %device, "Output device changed");
            if let Some(ref app) = *self.client_app.borrow() {
                let device_clone = Some(device.clone());
                if let Err(e) = self.runtime.block_on(app.switch_output_device(device_clone)) {
                    warn!(error = %e, "Failed to switch output device");
                }
            }
        }
    }

    /// Shows the transfer dialog.
    fn show_transfer_dialog(&self) {
        match TransferDialog::show(&self.window) {
            TransferDialogResult::Transfer(target_uri) => {
                info!(target_uri = %target_uri, "Initiating call transfer");
                self.transfer_call(&target_uri);
            }
            TransferDialogResult::Cancelled => {
                debug!("Transfer cancelled by user");
            }
        }
    }

    /// Transfers the current call to the specified URI.
    fn transfer_call(&self, target_uri: &str) {
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self.runtime.block_on(app.transfer_call(target_uri)) {
                Ok(()) => {
                    *self.status_message.borrow_mut() = format!("Transferring to {}...", target_uri);
                }
                Err(e) => {
                    self.show_error_dialog(&format!("Transfer failed: {}", e));
                }
            }
        }
    }

    /// Shows the DTMF dialpad dialog.
    fn show_dtmf_dialog(&self) {
        // Check if there's an active call
        if self.active_call.borrow().is_none() {
            *self.status_message.borrow_mut() = "No active call for DTMF".to_string();
            return;
        }

        let (_dialog, action_rx) = DtmfDialog::show(&self.window);

        // Process DTMF actions from the dialog
        // Since NWG is single-threaded, we process actions in a loop
        // The dialog runs non-modally so we need to check for actions
        loop {
            match action_rx.try_recv() {
                Ok(DtmfAction::SendDigit(digit_char)) => {
                    if let Some(digit) = DtmfDigit::from_char(digit_char) {
                        self.send_dtmf(digit);
                    }
                }
                Ok(DtmfAction::Close) => {
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Process window events to keep the dialog responsive
                    nwg::dispatch_thread_events_with_callback(|| {});
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
    }

    /// Sends a DTMF digit during an active call.
    fn send_dtmf(&self, digit: DtmfDigit) {
        info!(digit = %digit, "Sending DTMF");
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self.runtime.block_on(app.send_dtmf(digit)) {
                Ok(()) => {
                    *self.status_message.borrow_mut() = format!("Sent DTMF: {}", digit);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to send DTMF");
                    *self.status_message.borrow_mut() = format!("DTMF failed: {}", e);
                }
            }
        }
    }

    // =========================================================================
    // Contacts View Event Handlers
    // =========================================================================

    /// Called when the add contact button is clicked.
    pub fn on_contact_add(&self) {
        match ContactDialog::show_add(&self.window) {
            ContactDialogResult::Saved(contact) => {
                info!(contact_id = %contact.id, name = %contact.name, "Adding new contact");
                self.save_contact(contact);
            }
            ContactDialogResult::Cancelled => {
                debug!("Add contact cancelled by user");
            }
        }
    }

    /// Called when the call contact button is clicked.
    pub fn on_contact_call(&self) {
        if let Some(contact) = self.contacts_view.borrow().selected_contact() {
            info!(contact = %contact.name, uri = %contact.sip_uri, "Calling contact");
            self.make_call(&contact.sip_uri);
            // Switch to dialer tab
            self.tab_control.set_selected_tab(0);
        } else {
            *self.status_message.borrow_mut() = "No contact selected".to_string();
        }
    }

    /// Called when the edit contact button is clicked.
    pub fn on_contact_edit(&self) {
        if let Some(contact) = self.contacts_view.borrow().selected_contact() {
            match ContactDialog::show_edit(&self.window, &contact) {
                ContactDialogResult::Saved(updated_contact) => {
                    info!(contact_id = %updated_contact.id, name = %updated_contact.name, "Updating contact");
                    self.save_contact(updated_contact);
                }
                ContactDialogResult::Cancelled => {
                    debug!("Edit contact cancelled by user");
                }
            }
        } else {
            *self.status_message.borrow_mut() = "No contact selected".to_string();
        }
    }

    /// Called when the favorite contact button is clicked.
    pub fn on_contact_favorite(&self) {
        if let Some(contact) = self.contacts_view.borrow().selected_contact() {
            self.toggle_favorite(&contact.id);
        } else {
            *self.status_message.borrow_mut() = "No contact selected".to_string();
        }
    }

    /// Called when the delete contact button is clicked.
    pub fn on_contact_delete(&self) {
        if let Some(contact) = self.contacts_view.borrow().selected_contact() {
            // Confirm deletion
            let params = nwg::MessageParams {
                title: "Delete Contact",
                content: &format!("Are you sure you want to delete '{}'?", contact.name),
                buttons: nwg::MessageButtons::YesNo,
                icons: nwg::MessageIcons::Warning,
            };

            if nwg::modal_message(&self.window, &params) == nwg::MessageChoice::Yes {
                self.delete_contact(&contact.id);
            }
        } else {
            *self.status_message.borrow_mut() = "No contact selected".to_string();
        }
    }

    /// Called when the search text changes.
    pub fn on_contact_search(&self) {
        self.contacts_view.borrow().refresh_filter();
    }

    // =========================================================================
    // Call Handling
    // =========================================================================

    /// Makes a call to the given URI.
    pub fn make_call(&self, uri: &str) {
        info!(uri = %uri, "Making call");
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            let result = self.runtime.block_on(app.make_call(uri));
            if let Err(e) = result {
                self.show_error_dialog(&format!("Call failed: {}", e));
            }
        }
    }

    /// Hangs up the current call.
    pub fn hangup_call(&self) {
        info!("Hanging up call");
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            let _ = self.runtime.block_on(app.hangup());
        }
    }

    /// Toggles mute on the current call.
    pub fn toggle_mute(&self) {
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            let muted = app.toggle_mute();
            *self.status_message.borrow_mut() = if muted { "Muted" } else { "Unmuted" }.to_string();
        }
    }

    /// Toggles hold on the current call.
    pub fn toggle_hold(&self) {
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self.runtime.block_on(app.toggle_hold()) {
                Ok(is_on_hold) => {
                    *self.status_message.borrow_mut() = if is_on_hold {
                        "Call on hold".to_string()
                    } else {
                        "Call resumed".to_string()
                    };
                }
                Err(e) => {
                    self.show_error_dialog(&format!("Failed to toggle hold: {}", e));
                }
            }
        }
    }

    /// Accepts the incoming call.
    fn accept_incoming_call(&self) {
        let call_id = self
            .incoming_call
            .borrow()
            .as_ref()
            .map(|c| c.call_id.clone());

        if let Some(call_id) = call_id {
            info!(call_id = %call_id, "Accepting incoming call");
            self.stop_ringtone();
            *self.auto_answer_timer.borrow_mut() = None;

            if let Some(ref mut app) = *self.client_app.borrow_mut() {
                match self.runtime.block_on(app.accept_incoming_call(&call_id)) {
                    Ok(()) => {
                        *self.status_message.borrow_mut() = "Call accepted".to_string();
                        self.tab_control.set_selected_tab(1);
                    }
                    Err(e) => {
                        self.show_error_dialog(&format!("Failed to accept call: {}", e));
                    }
                }
            }

            *self.incoming_call.borrow_mut() = None;
        }
    }

    /// Rejects the incoming call.
    fn reject_incoming_call(&self) {
        let call_id = self
            .incoming_call
            .borrow()
            .as_ref()
            .map(|c| c.call_id.clone());

        if let Some(call_id) = call_id {
            info!(call_id = %call_id, "Rejecting incoming call");
            self.stop_ringtone();
            *self.auto_answer_timer.borrow_mut() = None;

            if let Some(ref mut app) = *self.client_app.borrow_mut() {
                let _ = self.runtime.block_on(app.reject_incoming_call(&call_id));
            }

            *self.incoming_call.borrow_mut() = None;
            *self.status_message.borrow_mut() = "Call rejected".to_string();
        }
    }

    // =========================================================================
    // Audio
    // =========================================================================

    /// Starts ringtone playback.
    fn start_ringtone(&self) {
        if let Some(ref app) = *self.client_app.borrow() {
            let settings = app.settings().settings();

            self.ringtone_player
                .borrow_mut()
                .set_ring_device(settings.audio.ring_device.clone());
            self.ringtone_player
                .borrow_mut()
                .set_volume(settings.audio.ring_volume);

            if let Some(ref path) = settings.audio.ringtone_file_path {
                if let Err(e) = self.ringtone_player.borrow_mut().load(path) {
                    warn!(error = %e, "Failed to load ringtone file");
                    self.ringtone_player.borrow_mut().use_default();
                }
            } else {
                self.ringtone_player.borrow_mut().use_default();
            }
        }

        if let Err(e) = self.ringtone_player.borrow_mut().start() {
            warn!(error = %e, "Failed to start ringtone");
        } else {
            debug!("Ringtone started");
        }
    }

    /// Stops ringtone playback.
    fn stop_ringtone(&self) {
        if self.ringtone_player.borrow().is_playing() {
            self.ringtone_player.borrow_mut().stop();
            debug!("Ringtone stopped");
        }
    }

    /// Refreshes available audio devices.
    fn refresh_audio_devices(&self) {
        use client_audio::DeviceManager;

        let manager = DeviceManager::new();

        match manager.list_input_devices() {
            Ok(devices) => {
                let mut inputs = vec!["Default".to_string()];
                inputs.extend(devices.into_iter().map(|d| d.name));
                *self.available_inputs.borrow_mut() = inputs;
            }
            Err(e) => {
                warn!(error = %e, "Failed to list input devices");
            }
        }

        match manager.list_output_devices() {
            Ok(devices) => {
                let mut outputs = vec!["Default".to_string()];
                outputs.extend(devices.into_iter().map(|d| d.name));
                *self.available_outputs.borrow_mut() = outputs;
            }
            Err(e) => {
                warn!(error = %e, "Failed to list output devices");
            }
        }

        // Update call view with device lists
        self.call_view.borrow_mut().set_audio_devices(
            self.available_inputs.borrow().clone(),
            self.available_outputs.borrow().clone(),
        );
    }

    // =========================================================================
    // Auto-Answer
    // =========================================================================

    /// Checks if auto-answer is enabled and starts timer.
    fn check_auto_answer(&self, call_id: &str) {
        if let Some(ref app) = *self.client_app.borrow() {
            let settings = app.settings().settings();

            if settings.general.auto_answer_enabled {
                let delay = settings.general.auto_answer_delay_secs;
                info!(call_id = %call_id, delay = delay, "Auto-answer enabled");
                *self.auto_answer_timer.borrow_mut() = Some((call_id.to_string(), Instant::now()));
            }
        }
    }

    /// Processes auto-answer timer.
    fn process_auto_answer(&self) {
        let should_answer = {
            let timer = self.auto_answer_timer.borrow();
            if let Some((ref call_id, started_at)) = *timer {
                if let Some(ref app) = *self.client_app.borrow() {
                    let settings = app.settings().settings();
                    let delay = std::time::Duration::from_secs(
                        settings.general.auto_answer_delay_secs as u64,
                    );

                    if started_at.elapsed() >= delay {
                        Some(call_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(call_id) = should_answer {
            info!(call_id = %call_id, "Auto-answering call");
            *self.auto_answer_timer.borrow_mut() = None;
            self.stop_ringtone();

            if let Some(ref mut app) = *self.client_app.borrow_mut() {
                match self.runtime.block_on(app.accept_incoming_call(&call_id)) {
                    Ok(()) => {
                        *self.status_message.borrow_mut() = "Call auto-answered".to_string();
                        self.tab_control.set_selected_tab(1);
                    }
                    Err(e) => {
                        self.show_error_dialog(&format!("Failed to auto-answer: {}", e));
                    }
                }
            }

            *self.incoming_call.borrow_mut() = None;
        }
    }

    // =========================================================================
    // Settings
    // =========================================================================

    /// Saves current settings to disk.
    pub fn save_settings(&self) {
        let (general, audio, network, ui) = self.settings_view.borrow().collect_settings();

        {
            let mut manager = self.settings_manager.borrow_mut();
            let settings = manager.settings_mut();
            settings.general = general;
            settings.audio = audio;
            settings.network = network;
            settings.ui = ui;
        }

        match self.settings_manager.borrow_mut().save() {
            Ok(()) => {
                info!("Settings saved successfully");
                self.settings_view.borrow_mut().clear_dirty();
                *self.status_message.borrow_mut() = "Settings saved".to_string();
            }
            Err(e) => {
                error!(error = %e, "Failed to save settings");
                self.show_error_dialog(&format!("Failed to save settings: {}", e));
            }
        }

        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            let settings_mgr = self.settings_manager.borrow();
            let settings = settings_mgr.settings();
            let app_settings = app.settings_mut();
            *app_settings.settings_mut() = settings.clone();
        }
    }

    /// Discards unsaved settings.
    pub fn discard_settings(&self) {
        self.settings_view
            .borrow_mut()
            .load_from_settings(self.settings_manager.borrow().settings());
        *self.status_message.borrow_mut() = "Changes discarded".to_string();
    }

    /// Registers the account.
    pub fn register_account(&self) {
        let account = match self.settings_view.borrow().build_account() {
            Some(account) => account,
            None => {
                self.show_error_dialog("Please enter SIP URI and Registrar");
                return;
            }
        };

        self.settings_view
            .borrow_mut()
            .set_registration_in_progress(true);
        *self.status_message.borrow_mut() = "Registering...".to_string();

        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self.runtime.block_on(app.register_account(&account)) {
                Ok(()) => {
                    info!(account_id = %account.id, "Registration initiated");
                }
                Err(e) => {
                    error!(error = %e, "Registration failed");
                    self.settings_view
                        .borrow_mut()
                        .set_registration_in_progress(false);
                    self.show_error_dialog(&format!("Registration failed: {}", e));
                }
            }
        } else {
            self.settings_view
                .borrow_mut()
                .set_registration_in_progress(false);
            self.show_error_dialog("Client not initialized");
        }
    }

    /// Unregisters from the server.
    pub fn unregister_account(&self) {
        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self.runtime.block_on(app.unregister()) {
                Ok(()) => {
                    info!("Unregistration initiated");
                    *self.status_message.borrow_mut() = "Unregistering...".to_string();
                }
                Err(e) => {
                    warn!(error = %e, "Unregistration failed");
                    *self.status_message.borrow_mut() = format!("Unregister failed: {}", e);
                }
            }
        }
    }

    /// Refreshes the certificate list.
    pub fn refresh_certificates(&self) {
        use client_core::CertificateStore;

        let cert_store = CertificateStore::open_personal();

        match cert_store.list_certificates() {
            Ok(certs) => {
                info!(count = certs.len(), "Found certificates");
                self.settings_view.borrow_mut().set_certificates(certs);
            }
            Err(e) => {
                warn!(error = %e, "Failed to list certificates");
                self.settings_view.borrow_mut().set_certificates(Vec::new());
                *self.status_message.borrow_mut() = format!("Failed to load certificates: {}", e);
            }
        }

        match cert_store.list_smart_card_readers() {
            Ok(readers) => {
                info!(count = readers.len(), "Found smart card readers");
                self.settings_view
                    .borrow_mut()
                    .set_smart_card_readers(readers);
            }
            Err(e) => {
                warn!(error = %e, "Failed to list smart card readers");
                self.settings_view
                    .borrow_mut()
                    .set_smart_card_readers(Vec::new());
            }
        }
    }

    /// Sets server certificate verification mode.
    #[allow(dead_code)]
    pub fn set_verification_mode(&self, mode: client_types::ServerCertVerificationMode) {
        use client_types::ServerCertVerificationMode;

        self.settings_view
            .borrow_mut()
            .set_server_cert_verification(mode.clone());

        if let ServerCertVerificationMode::Custom { ref ca_file_path } = mode {
            self.settings_view
                .borrow_mut()
                .set_custom_ca_path(ca_file_path.clone());
        } else {
            self.settings_view.borrow_mut().set_custom_ca_cert_count(0);
        }

        let transport_mode = match &mode {
            ServerCertVerificationMode::Insecure => CertVerificationMode::Insecure,
            ServerCertVerificationMode::System => CertVerificationMode::System,
            ServerCertVerificationMode::Custom { ca_file_path } => {
                let path = std::path::Path::new(ca_file_path);
                match load_certs_from_pem_file(path) {
                    Ok(certs) => {
                        let cert_count = certs.len();
                        info!(path = %ca_file_path, cert_count, "Loaded CA certificates");
                        self.settings_view
                            .borrow_mut()
                            .set_custom_ca_cert_count(cert_count);
                        CertVerificationMode::Custom {
                            trusted_certs: certs,
                        }
                    }
                    Err(e) => {
                        error!(error = %e, path = %ca_file_path, "Failed to load CA file");
                        self.settings_view.borrow_mut().set_custom_ca_cert_count(0);
                        self.show_error_dialog(&format!("Failed to load CA file: {}", e));
                        return;
                    }
                }
            }
        };

        if let Some(ref mut app) = *self.client_app.borrow_mut() {
            match self
                .runtime
                .block_on(app.set_verification_mode(transport_mode))
            {
                Ok(()) => {
                    *self.status_message.borrow_mut() =
                        format!("Verification mode set to: {}", mode.label());
                    info!(mode = ?mode, "Verification mode applied");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to apply verification mode");
                }
            }
        }
    }

    /// Browses for a CA certificate file.
    #[allow(dead_code)]
    pub fn browse_for_ca_file(&self) {
        use rfd::FileDialog;

        let file = FileDialog::new()
            .add_filter("Certificate Files", &["pem", "crt", "cer", "der"])
            .add_filter("All Files", &["*"])
            .set_title("Select CA Certificate File")
            .pick_file();

        if let Some(path) = file {
            let path_str = path.to_string_lossy().to_string();
            info!(path = %path_str, "User selected CA file");

            match load_certs_from_pem_file(&path) {
                Ok(certs) => {
                    info!(cert_count = certs.len(), "Validated CA certificate file");
                    self.set_verification_mode(client_types::ServerCertVerificationMode::Custom {
                        ca_file_path: path_str,
                    });
                }
                Err(e) => {
                    error!(error = %e, "Invalid CA certificate file");
                    self.show_error_dialog(&format!("Invalid CA file: {}", e));
                }
            }
        }
    }

    // =========================================================================
    // Contacts
    // =========================================================================

    /// Saves a contact.
    pub fn save_contact(&self, contact: client_types::Contact) {
        info!(contact_id = %contact.id, name = %contact.name, "Saving contact");
        self.contact_manager.borrow_mut().set_contact(contact);
        self.contacts_view
            .borrow_mut()
            .set_contacts(self.contact_manager.borrow().contacts().cloned());

        if let Err(e) = self.contact_manager.borrow_mut().save() {
            warn!(error = %e, "Failed to save contacts");
        }

        *self.status_message.borrow_mut() = "Contact saved".to_string();
    }

    /// Deletes a contact.
    pub fn delete_contact(&self, contact_id: &str) {
        info!(contact_id = %contact_id, "Deleting contact");
        if self
            .contact_manager
            .borrow_mut()
            .remove_contact(contact_id)
            .is_some()
        {
            self.contacts_view
                .borrow_mut()
                .set_contacts(self.contact_manager.borrow().contacts().cloned());

            if let Err(e) = self.contact_manager.borrow_mut().save() {
                warn!(error = %e, "Failed to save contacts");
            }

            *self.status_message.borrow_mut() = "Contact deleted".to_string();
        }
    }

    /// Toggles a contact's favorite status.
    pub fn toggle_favorite(&self, contact_id: &str) {
        if let Some(contact) = self.contact_manager.borrow().get_contact(contact_id) {
            let mut updated = contact.clone();
            updated.favorite = !updated.favorite;
            self.contact_manager.borrow_mut().set_contact(updated);
            self.contacts_view
                .borrow_mut()
                .set_contacts(self.contact_manager.borrow().contacts().cloned());

            if let Err(e) = self.contact_manager.borrow_mut().save() {
                warn!(error = %e, "Failed to save contacts");
            }
        }
    }

    // =========================================================================
    // Settings View Event Handlers
    // =========================================================================

    /// Called when the register button is clicked.
    pub fn on_settings_register(&self) {
        self.register_account();
    }

    /// Called when the unregister button is clicked.
    pub fn on_settings_unregister(&self) {
        self.unregister_account();
    }

    /// Called when the refresh certificates button is clicked.
    pub fn on_settings_refresh_certs(&self) {
        self.refresh_certificates();
    }

    /// Called when the use certificate button is clicked.
    pub fn on_settings_use_cert(&self) {
        if let Some(thumbprint) = self.settings_view.borrow().get_selected_certificate() {
            info!(thumbprint = %thumbprint, "Using selected certificate");
            self.show_pin_dialog_for(PinOperation::UseCertificate { thumbprint });
        } else {
            *self.status_message.borrow_mut() = "No certificate selected".to_string();
        }
    }

    /// Called when the save button is clicked.
    pub fn on_settings_save(&self) {
        self.save_settings();
    }

    /// Called when the discard button is clicked.
    pub fn on_settings_discard(&self) {
        self.discard_settings();
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns a reference to the main window.
    pub fn window(&self) -> &nwg::Window {
        &self.window
    }
}
