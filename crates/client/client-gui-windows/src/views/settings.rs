//! Settings view using native Windows controls.
//!
//! Provides account configuration, security, audio, and general settings.

use crate::app::SipClientApp;
use client_core::{GeneralSettings, NetworkSettings, Settings, UiSettings};
use client_types::{
    AudioConfig, CertificateConfig, CertificateInfo, ServerCertVerificationMode, SipAccount,
    TransportPreference,
};
use native_windows_gui as nwg;
use std::cell::RefCell;
use std::rc::Rc;

/// Settings view state with native Windows controls.
pub struct SettingsView {
    /// Display name input.
    display_name_input: nwg::TextInput,
    /// SIP URI input.
    sip_uri_input: nwg::TextInput,
    /// Registrar URI input.
    registrar_input: nwg::TextInput,
    /// Register button.
    register_button: nwg::Button,
    /// Unregister button.
    unregister_button: nwg::Button,
    /// Certificate list.
    cert_list: nwg::ListBox<String>,
    /// Refresh certificates button.
    refresh_certs_button: nwg::Button,
    /// Use certificate button.
    use_cert_button: nwg::Button,
    /// Save button.
    save_button: nwg::Button,
    /// Discard button.
    discard_button: nwg::Button,

    // State fields
    /// Available certificates.
    available_certificates: RefCell<Vec<CertificateInfo>>,
    /// Selected certificate index.
    #[allow(dead_code)]
    selected_certificate: RefCell<Option<String>>,
    /// Smart card readers.
    smart_card_readers: RefCell<Vec<String>>,
    /// Certificates loading.
    certificates_loading: RefCell<bool>,
    /// Server cert verification mode.
    server_cert_verification: RefCell<ServerCertVerificationMode>,
    /// Custom CA path.
    custom_ca_path: RefCell<String>,
    /// Custom CA cert count.
    custom_ca_cert_count: RefCell<usize>,
    /// Auto-answer enabled.
    auto_answer_enabled: RefCell<bool>,
    /// Auto-answer delay.
    auto_answer_delay: RefCell<u32>,
    /// Has unsaved changes.
    is_dirty: RefCell<bool>,
    /// Registration in progress.
    registration_in_progress: RefCell<bool>,
    /// Input device.
    input_device: RefCell<String>,
    /// Output device.
    output_device: RefCell<String>,
    /// Ring device.
    ring_device: RefCell<String>,
    /// Ring volume.
    ring_volume: RefCell<f32>,
    /// Echo cancellation.
    echo_cancellation: RefCell<bool>,
    /// Noise suppression.
    noise_suppression: RefCell<bool>,
    /// Ringtone path.
    ringtone_path: RefCell<String>,
    /// Start minimized.
    start_minimized: RefCell<bool>,
    /// Minimize to tray.
    minimize_to_tray: RefCell<bool>,
    /// Dark mode.
    dark_mode: RefCell<bool>,
}

impl SettingsView {
    /// Builds the settings view within the given parent tab.
    pub fn build(parent: &nwg::Tab) -> Result<Self, nwg::NwgError> {
        // Account section label - larger, modern header
        let mut _account_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("📱 SIP Account Settings")
            .position((20, 20))
            .size((440, 30))
            .build(&mut _account_label)?;

        // Display name - better spacing
        let mut _name_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("Display Name:")
            .position((30, 60))
            .size((120, 25))
            .build(&mut _name_label)?;

        let mut display_name_input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((160, 58))
            .size((300, 30))
            .build(&mut display_name_input)?;

        // SIP URI - larger inputs
        let mut _uri_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("SIP URI:")
            .position((30, 100))
            .size((120, 25))
            .build(&mut _uri_label)?;

        let mut sip_uri_input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((160, 98))
            .size((300, 30))
            .placeholder_text(Some("sips:user@domain.com"))
            .build(&mut sip_uri_input)?;

        // Registrar
        let mut _reg_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("Registrar:")
            .position((30, 140))
            .size((120, 25))
            .build(&mut _reg_label)?;

        let mut registrar_input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((160, 138))
            .size((300, 30))
            .placeholder_text(Some("sips:registrar.domain.com"))
            .build(&mut registrar_input)?;

        // Register/Unregister buttons - larger, modern
        let mut register_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("✅ Register")
            .position((160, 180))
            .size((140, 40))
            .build(&mut register_button)?;

        let mut unregister_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("⛔ Unregister")
            .position((310, 180))
            .size((150, 40))
            .build(&mut unregister_button)?;

        // Certificate section - modern header
        let mut _cert_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("🔐 Client Certificates (CAC/PIV/SIPR)")
            .position((20, 240))
            .size((440, 30))
            .build(&mut _cert_label)?;

        let mut cert_list = Default::default();
        nwg::ListBox::builder()
            .parent(parent)
            .position((20, 280))
            .size((440, 200))
            .collection(Vec::new())
            .build(&mut cert_list)?;

        // Certificate buttons - larger and modern
        let mut refresh_certs_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("🔄 Refresh")
            .position((20, 490))
            .size((110, 40))
            .build(&mut refresh_certs_button)?;

        let mut use_cert_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("🔑 Use Selected")
            .position((140, 490))
            .size((150, 40))
            .build(&mut use_cert_button)?;

        // Save/Discard buttons at bottom - prominent
        let mut save_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("💾 Save Settings")
            .position((200, 560))
            .size((130, 45))
            .build(&mut save_button)?;

        let mut discard_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("❌ Discard")
            .position((340, 560))
            .size((120, 45))
            .build(&mut discard_button)?;

        Ok(Self {
            display_name_input,
            sip_uri_input,
            registrar_input,
            register_button,
            unregister_button,
            cert_list,
            refresh_certs_button,
            use_cert_button,
            save_button,
            discard_button,
            available_certificates: RefCell::new(Vec::new()),
            selected_certificate: RefCell::new(None),
            smart_card_readers: RefCell::new(Vec::new()),
            certificates_loading: RefCell::new(false),
            server_cert_verification: RefCell::new(ServerCertVerificationMode::default()),
            custom_ca_path: RefCell::new(String::new()),
            custom_ca_cert_count: RefCell::new(0),
            auto_answer_enabled: RefCell::new(false),
            auto_answer_delay: RefCell::new(3),
            is_dirty: RefCell::new(false),
            registration_in_progress: RefCell::new(false),
            input_device: RefCell::new("Default".to_string()),
            output_device: RefCell::new("Default".to_string()),
            ring_device: RefCell::new("Default".to_string()),
            ring_volume: RefCell::new(1.0),
            echo_cancellation: RefCell::new(true),
            noise_suppression: RefCell::new(true),
            ringtone_path: RefCell::new(String::new()),
            start_minimized: RefCell::new(false),
            minimize_to_tray: RefCell::new(true),
            dark_mode: RefCell::new(true),
        })
    }

    /// Binds events to the settings view controls.
    pub fn bind_events(&self, app: &Rc<SipClientApp>) {
        let app_weak = Rc::downgrade(app);

        // Bind register button
        let app_register = app_weak.clone();
        nwg::bind_event_handler(
            &self.register_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_register.upgrade() {
                        app.on_settings_register();
                    }
                }
            },
        );

        // Bind unregister button
        let app_unregister = app_weak.clone();
        nwg::bind_event_handler(
            &self.unregister_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_unregister.upgrade() {
                        app.on_settings_unregister();
                    }
                }
            },
        );

        // Bind refresh certificates button
        let app_refresh = app_weak.clone();
        nwg::bind_event_handler(
            &self.refresh_certs_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_refresh.upgrade() {
                        app.on_settings_refresh_certs();
                    }
                }
            },
        );

        // Bind use certificate button
        let app_use_cert = app_weak.clone();
        nwg::bind_event_handler(
            &self.use_cert_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_use_cert.upgrade() {
                        app.on_settings_use_cert();
                    }
                }
            },
        );

        // Bind save button
        let app_save = app_weak.clone();
        nwg::bind_event_handler(
            &self.save_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_save.upgrade() {
                        app.on_settings_save();
                    }
                }
            },
        );

        // Bind discard button
        let app_discard = app_weak.clone();
        nwg::bind_event_handler(
            &self.discard_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_discard.upgrade() {
                        app.on_settings_discard();
                    }
                }
            },
        );
    }

    /// Updates the available certificates.
    pub fn set_certificates(&mut self, certs: Vec<CertificateInfo>) {
        // Update display list
        let display_items: Vec<String> = certs
            .iter()
            .map(|c| {
                let algo = if c.key_algorithm.contains("P-384") {
                    "[P-384]"
                } else if c.key_algorithm.contains("P-256") {
                    "[P-256]"
                } else {
                    "[RSA]"
                };
                let valid = if c.is_valid { "" } else { " (EXPIRED)" };
                format!("{} {} {}{}", algo, c.subject_cn, c.issuer_cn, valid)
            })
            .collect();

        self.cert_list.set_collection(display_items);
        *self.available_certificates.borrow_mut() = certs;
        *self.certificates_loading.borrow_mut() = false;
    }

    /// Updates the smart card readers.
    pub fn set_smart_card_readers(&mut self, readers: Vec<String>) {
        *self.smart_card_readers.borrow_mut() = readers;
    }

    /// Sets the selected certificate thumbprint.
    #[allow(dead_code)]
    pub fn set_selected_certificate(&mut self, thumbprint: Option<String>) {
        *self.selected_certificate.borrow_mut() = thumbprint;
    }

    /// Sets the certificate loading state.
    #[allow(dead_code)]
    pub fn set_certificates_loading(&mut self, loading: bool) {
        *self.certificates_loading.borrow_mut() = loading;
    }

    /// Sets the server certificate verification mode.
    pub fn set_server_cert_verification(&mut self, mode: ServerCertVerificationMode) {
        if let ServerCertVerificationMode::Custom { ca_file_path } = &mode {
            *self.custom_ca_path.borrow_mut() = ca_file_path.clone();
        }
        *self.server_cert_verification.borrow_mut() = mode;
    }

    /// Sets the custom CA file path.
    pub fn set_custom_ca_path(&mut self, path: String) {
        *self.custom_ca_path.borrow_mut() = path;
    }

    /// Sets the number of certificates loaded from the custom CA file.
    pub fn set_custom_ca_cert_count(&mut self, count: usize) {
        *self.custom_ca_cert_count.borrow_mut() = count;
    }

    /// Sets whether registration is in progress.
    pub fn set_registration_in_progress(&mut self, in_progress: bool) {
        *self.registration_in_progress.borrow_mut() = in_progress;
        self.register_button.set_enabled(!in_progress);
    }

    /// Builds a SipAccount from the current view state.
    pub fn build_account(&self) -> Option<SipAccount> {
        let sip_uri = self.sip_uri_input.text();
        let registrar_uri = self.registrar_input.text();

        if sip_uri.is_empty() || registrar_uri.is_empty() {
            return None;
        }

        Some(SipAccount {
            id: "default".to_string(),
            display_name: self.display_name_input.text(),
            sip_uri,
            registrar_uri,
            outbound_proxy: None,
            transport: TransportPreference::TlsOnly,
            register_expiry: 3600,
            stun_server: None,
            turn_config: None,
            enabled: true,
            certificate_config: CertificateConfig::default(),
        })
    }

    /// Loads settings from a Settings struct into the view.
    pub fn load_from_settings(&mut self, settings: &Settings) {
        // General settings
        *self.start_minimized.borrow_mut() = settings.general.start_minimized;
        *self.minimize_to_tray.borrow_mut() = settings.general.minimize_to_tray;
        *self.dark_mode.borrow_mut() = settings.ui.dark_mode;
        *self.auto_answer_enabled.borrow_mut() = settings.general.auto_answer_enabled;
        *self.auto_answer_delay.borrow_mut() = settings.general.auto_answer_delay_secs;

        // Audio settings
        *self.input_device.borrow_mut() = settings
            .audio
            .input_device
            .clone()
            .unwrap_or_else(|| "Default".to_string());
        *self.output_device.borrow_mut() = settings
            .audio
            .output_device
            .clone()
            .unwrap_or_else(|| "Default".to_string());
        *self.ring_device.borrow_mut() = settings
            .audio
            .ring_device
            .clone()
            .unwrap_or_else(|| "Default".to_string());
        *self.ring_volume.borrow_mut() = settings.audio.ring_volume;
        *self.echo_cancellation.borrow_mut() = settings.audio.echo_cancellation;
        *self.noise_suppression.borrow_mut() = settings.audio.noise_suppression;
        if let Some(ref path) = settings.audio.ringtone_file_path {
            *self.ringtone_path.borrow_mut() = path.clone();
        } else {
            self.ringtone_path.borrow_mut().clear();
        }

        // Network/Security settings
        *self.server_cert_verification.borrow_mut() =
            settings.network.server_cert_verification.clone();
        if let ServerCertVerificationMode::Custom { ca_file_path } =
            &settings.network.server_cert_verification
        {
            *self.custom_ca_path.borrow_mut() = ca_file_path.clone();
        }

        // Account settings (use first account if available)
        if let Some(account) = settings.accounts.values().next() {
            self.display_name_input.set_text(&account.display_name);
            self.sip_uri_input.set_text(&account.sip_uri);
            self.registrar_input.set_text(&account.registrar_uri);
        }

        // Clear dirty flag after loading
        *self.is_dirty.borrow_mut() = false;
    }

    /// Collects current view state into Settings components.
    pub fn collect_settings(&self) -> (GeneralSettings, AudioConfig, NetworkSettings, UiSettings) {
        let input_device = self.input_device.borrow();
        let output_device = self.output_device.borrow();
        let ring_device = self.ring_device.borrow();
        let ringtone_path = self.ringtone_path.borrow();

        let general = GeneralSettings {
            start_minimized: *self.start_minimized.borrow(),
            minimize_to_tray: *self.minimize_to_tray.borrow(),
            auto_answer_enabled: *self.auto_answer_enabled.borrow(),
            auto_answer_delay_secs: *self.auto_answer_delay.borrow(),
            ..Default::default()
        };

        let audio = AudioConfig {
            input_device: if *input_device == "Default" {
                None
            } else {
                Some(input_device.clone())
            },
            output_device: if *output_device == "Default" {
                None
            } else {
                Some(output_device.clone())
            },
            ring_device: if *ring_device == "Default" {
                None
            } else {
                Some(ring_device.clone())
            },
            ring_volume: *self.ring_volume.borrow(),
            echo_cancellation: *self.echo_cancellation.borrow(),
            noise_suppression: *self.noise_suppression.borrow(),
            ringtone_file_path: if ringtone_path.is_empty() {
                None
            } else {
                Some(ringtone_path.clone())
            },
            ..Default::default()
        };

        let network = NetworkSettings {
            server_cert_verification: self.server_cert_verification.borrow().clone(),
            ..Default::default()
        };

        let ui = UiSettings {
            dark_mode: *self.dark_mode.borrow(),
            ..Default::default()
        };

        (general, audio, network, ui)
    }

    /// Returns whether the view has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        *self.is_dirty.borrow()
    }

    /// Clears the dirty flag (after saving).
    pub fn clear_dirty(&mut self) {
        *self.is_dirty.borrow_mut() = false;
    }

    /// Returns a reference to the register button.
    #[allow(dead_code)]
    pub fn register_button(&self) -> &nwg::Button {
        &self.register_button
    }

    /// Returns a reference to the unregister button.
    #[allow(dead_code)]
    pub fn unregister_button(&self) -> &nwg::Button {
        &self.unregister_button
    }

    /// Returns a reference to the refresh certificates button.
    #[allow(dead_code)]
    pub fn refresh_certs_button(&self) -> &nwg::Button {
        &self.refresh_certs_button
    }

    /// Returns a reference to the use certificate button.
    #[allow(dead_code)]
    pub fn use_cert_button(&self) -> &nwg::Button {
        &self.use_cert_button
    }

    /// Returns a reference to the save button.
    #[allow(dead_code)]
    pub fn save_button(&self) -> &nwg::Button {
        &self.save_button
    }

    /// Returns a reference to the discard button.
    #[allow(dead_code)]
    pub fn discard_button(&self) -> &nwg::Button {
        &self.discard_button
    }

    /// Returns a reference to the certificate list.
    #[allow(dead_code)]
    pub fn cert_list(&self) -> &nwg::ListBox<String> {
        &self.cert_list
    }

    /// Gets the selected certificate thumbprint.
    pub fn get_selected_certificate(&self) -> Option<String> {
        let selection = self.cert_list.selection()?;
        let certs = self.available_certificates.borrow();
        certs.get(selection).map(|c| c.thumbprint.clone())
    }

    /// Triggers certificate refresh request.
    #[allow(dead_code)]
    pub fn refresh_certificates(&mut self) {
        *self.certificates_loading.borrow_mut() = true;
    }
}
