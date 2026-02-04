//! Settings view.

use client_types::{CertificateInfo, ServerCertVerificationMode};
use eframe::egui;

/// Actions from the settings view.
#[derive(Debug, Clone)]
#[allow(dead_code)] // PinRequired will be used when CertStoreError::PinRequired is returned
pub enum SettingsAction {
    /// Save settings.
    Save,
    /// Register the specified account.
    Register(String),
    /// Unregister.
    Unregister,
    /// Refresh certificate list.
    RefreshCertificates,
    /// Select a certificate by thumbprint.
    SelectCertificate(String),
    /// Use the selected certificate for authentication.
    UseCertificate(String),
    /// PIN is required for certificate operation.
    PinRequired {
        /// Certificate thumbprint that needs PIN.
        thumbprint: String,
    },
    /// Change server certificate verification mode.
    SetVerificationMode(ServerCertVerificationMode),
    /// Browse for custom CA file.
    BrowseForCaFile,
    /// Confirm insecure mode (user acknowledged the warning).
    ConfirmInsecureMode,
}

/// Settings view state.
pub struct SettingsView {
    /// Active settings tab.
    active_tab: SettingsTab,
    /// Account display name.
    display_name: String,
    /// SIP URI.
    sip_uri: String,
    /// Registrar URI.
    registrar_uri: String,
    /// Input device name.
    input_device: String,
    /// Output device name.
    output_device: String,
    /// Echo cancellation enabled.
    echo_cancellation: bool,
    /// Noise suppression enabled.
    noise_suppression: bool,
    /// Start minimized.
    start_minimized: bool,
    /// Minimize to tray.
    minimize_to_tray: bool,
    /// Dark mode.
    dark_mode: bool,
    /// Available input devices.
    available_inputs: Vec<String>,
    /// Available output devices.
    available_outputs: Vec<String>,
    /// Has unsaved changes.
    is_dirty: bool,
    /// Available certificates from certificate store.
    available_certificates: Vec<CertificateInfo>,
    /// Selected certificate thumbprint.
    selected_certificate: Option<String>,
    /// Whether auto-select mode is enabled.
    auto_select_certificate: bool,
    /// Smart card readers detected.
    smart_card_readers: Vec<String>,
    /// Certificate loading state.
    certificates_loading: bool,
    /// Server certificate verification mode.
    server_cert_verification: ServerCertVerificationMode,
    /// Custom CA file path (when using Custom verification mode).
    custom_ca_path: String,
    /// Whether to show the insecure mode warning dialog.
    show_insecure_warning: bool,
    /// Pending verification mode change (awaiting insecure confirmation).
    pending_verification_mode: Option<ServerCertVerificationMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SettingsTab {
    #[default]
    Account,
    Security,
    Audio,
    General,
    About,
}

impl SettingsView {
    /// Creates a new settings view.
    pub fn new() -> Self {
        Self {
            active_tab: SettingsTab::Account,
            display_name: String::new(),
            sip_uri: String::new(),
            registrar_uri: String::new(),
            input_device: "Default".to_string(),
            output_device: "Default".to_string(),
            echo_cancellation: true,
            noise_suppression: true,
            start_minimized: false,
            minimize_to_tray: true,
            dark_mode: true,
            available_inputs: vec!["Default".to_string(), "Microphone (USB)".to_string()],
            available_outputs: vec![
                "Default".to_string(),
                "Speakers".to_string(),
                "Headphones".to_string(),
            ],
            is_dirty: false,
            available_certificates: Vec::new(),
            selected_certificate: None,
            auto_select_certificate: true,
            smart_card_readers: Vec::new(),
            certificates_loading: false,
            server_cert_verification: ServerCertVerificationMode::default(),
            custom_ca_path: String::new(),
            show_insecure_warning: false,
            pending_verification_mode: None,
        }
    }

    /// Updates the available certificates.
    pub fn set_certificates(&mut self, certs: Vec<CertificateInfo>) {
        self.available_certificates = certs;
        self.certificates_loading = false;
    }

    /// Updates the smart card readers.
    pub fn set_smart_card_readers(&mut self, readers: Vec<String>) {
        self.smart_card_readers = readers;
    }

    /// Sets the selected certificate thumbprint.
    pub fn set_selected_certificate(&mut self, thumbprint: Option<String>) {
        self.selected_certificate = thumbprint;
    }

    /// Sets the certificate loading state.
    pub fn set_certificates_loading(&mut self, loading: bool) {
        self.certificates_loading = loading;
    }

    /// Sets the server certificate verification mode.
    pub fn set_server_cert_verification(&mut self, mode: ServerCertVerificationMode) {
        if let ServerCertVerificationMode::Custom { ca_file_path } = &mode {
            self.custom_ca_path = ca_file_path.clone();
        }
        self.server_cert_verification = mode;
    }

    /// Sets the custom CA file path.
    pub fn set_custom_ca_path(&mut self, path: String) {
        self.custom_ca_path = path;
    }

    /// Shows or hides the insecure mode warning dialog.
    #[allow(dead_code)] // Will be used when applying verification mode from settings persistence
    pub fn set_show_insecure_warning(&mut self, show: bool) {
        self.show_insecure_warning = show;
    }

    /// Confirms the pending insecure mode change.
    pub fn confirm_insecure_mode(&mut self) {
        if let Some(mode) = self.pending_verification_mode.take() {
            self.server_cert_verification = mode;
            self.is_dirty = true;
        }
        self.show_insecure_warning = false;
    }

    /// Cancels the pending insecure mode change.
    pub fn cancel_insecure_mode(&mut self) {
        self.pending_verification_mode = None;
        self.show_insecure_warning = false;
    }

    /// Renders the settings view.
    pub fn render(&mut self, ui: &mut egui::Ui) -> Option<SettingsAction> {
        let mut action = None;

        ui.vertical(|ui| {
            ui.add_space(10.0);

            ui.heading("Settings");

            ui.add_space(10.0);

            // Tab bar
            ui.horizontal(|ui| {
                let tabs = [
                    (SettingsTab::Account, "Account"),
                    (SettingsTab::Security, "Security"),
                    (SettingsTab::Audio, "Audio"),
                    (SettingsTab::General, "General"),
                    (SettingsTab::About, "About"),
                ];

                for (tab, label) in tabs {
                    if ui.selectable_label(self.active_tab == tab, label).clicked() {
                        self.active_tab = tab;
                    }
                }
            });

            ui.separator();

            // Tab content
            egui::ScrollArea::vertical().show(ui, |ui| match self.active_tab {
                SettingsTab::Account => {
                    if let Some(a) = self.render_account_settings(ui) {
                        action = Some(a);
                    }
                }
                SettingsTab::Security => {
                    if let Some(a) = self.render_security_settings(ui) {
                        action = Some(a);
                    }
                }
                SettingsTab::Audio => {
                    self.render_audio_settings(ui);
                }
                SettingsTab::General => {
                    self.render_general_settings(ui);
                }
                SettingsTab::About => {
                    self.render_about(ui);
                }
            });

            // Save button (if dirty)
            if self.is_dirty {
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Save Changes").clicked() {
                            action = Some(SettingsAction::Save);
                            self.is_dirty = false;
                        }
                        if ui.button("Discard").clicked() {
                            self.is_dirty = false;
                            // TODO: Reload settings
                        }
                    });
                });
            }
        });

        action
    }

    fn render_account_settings(&mut self, ui: &mut egui::Ui) -> Option<SettingsAction> {
        let mut action = None;

        ui.add_space(10.0);
        ui.label(egui::RichText::new("SIP Account").strong());
        ui.add_space(10.0);

        egui::Grid::new("account_settings_grid")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                // Display name
                ui.label("Display Name:");
                if ui.text_edit_singleline(&mut self.display_name).changed() {
                    self.is_dirty = true;
                }
                ui.end_row();

                // SIP URI
                ui.label("SIP URI:");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.sip_uri)
                            .hint_text("sips:user@domain.com"),
                    )
                    .changed()
                {
                    self.is_dirty = true;
                }
                ui.end_row();

                // Registrar URI
                ui.label("Registrar:");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.registrar_uri)
                            .hint_text("sips:registrar.domain.com"),
                    )
                    .changed()
                {
                    self.is_dirty = true;
                }
                ui.end_row();
            });

        ui.add_space(20.0);

        // Smart card info section
        ui.label(egui::RichText::new("Authentication").strong());
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("\u{1F4B3} Smart Card:");
            ui.label(egui::RichText::new("CAC/PIV Required").color(egui::Color32::YELLOW));
        });

        ui.label(
            egui::RichText::new("Authentication uses mutual TLS with client certificates from your smart card (CAC/PIV/SIPR token). Password-based authentication is not supported for CNSA 2.0 compliance.")
                .small()
                .color(egui::Color32::GRAY),
        );

        ui.add_space(20.0);

        // Registration buttons
        ui.horizontal(|ui| {
            if ui.button("Register").clicked() {
                action = Some(SettingsAction::Register("default".to_string()));
            }
            if ui.button("Unregister").clicked() {
                action = Some(SettingsAction::Unregister);
            }
        });

        action
    }

    fn render_security_settings(&mut self, ui: &mut egui::Ui) -> Option<SettingsAction> {
        let mut action = None;

        ui.add_space(10.0);
        ui.label(egui::RichText::new("Smart Card Readers").strong());
        ui.add_space(10.0);

        if self.smart_card_readers.is_empty() {
            ui.horizontal(|ui| {
                ui.label("\u{26A0}"); // Warning sign
                ui.label(
                    egui::RichText::new("No smart card readers detected")
                        .color(egui::Color32::YELLOW),
                );
            });
        } else {
            for reader in &self.smart_card_readers {
                ui.horizontal(|ui| {
                    ui.label("\u{2705}"); // Check mark
                    ui.label(reader);
                });
            }
        }

        ui.add_space(20.0);
        ui.label(egui::RichText::new("Client Certificates").strong());
        ui.add_space(10.0);

        // Refresh button
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.certificates_loading,
                    egui::Button::new("\u{1F504} Refresh"),
                )
                .clicked()
            {
                action = Some(SettingsAction::RefreshCertificates);
            }

            if self.certificates_loading {
                ui.spinner();
                ui.label("Loading certificates...");
            }
        });

        ui.add_space(10.0);

        // Auto-select toggle
        ui.horizontal(|ui| {
            if ui
                .checkbox(
                    &mut self.auto_select_certificate,
                    "Auto-select best certificate",
                )
                .changed()
            {
                self.is_dirty = true;
            }
            ui.label(
                egui::RichText::new("(Prefers ECDSA P-384 for CNSA 2.0)")
                    .small()
                    .color(egui::Color32::GRAY),
            );
        });

        ui.add_space(10.0);

        // Certificate list
        if self.available_certificates.is_empty() && !self.certificates_loading {
            ui.label(
                egui::RichText::new(
                    "No valid client certificates found. Insert your CAC/PIV card.",
                )
                .color(egui::Color32::LIGHT_RED),
            );
        } else {
            egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for cert in &self.available_certificates {
                            let is_selected =
                                self.selected_certificate.as_ref() == Some(&cert.thumbprint);

                            let mut frame = egui::Frame::new()
                                .inner_margin(8.0)
                                .outer_margin(2.0)
                                .corner_radius(4.0);

                            if is_selected {
                                frame = frame.fill(egui::Color32::from_rgb(40, 60, 80));
                            }

                            frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    // Selection radio
                                    let response = ui.selectable_label(is_selected, "");

                                    if response.clicked() && !self.auto_select_certificate {
                                        action = Some(SettingsAction::SelectCertificate(
                                            cert.thumbprint.clone(),
                                        ));
                                    }

                                    ui.vertical(|ui| {
                                        // Subject CN with key algorithm badge
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(&cert.subject_cn).strong(),
                                            );

                                            // Key algorithm badge
                                            let (badge_color, badge_text) =
                                                if cert.key_algorithm.contains("P-384") {
                                                    (egui::Color32::GREEN, "P-384")
                                                } else if cert.key_algorithm.contains("P-256") {
                                                    (egui::Color32::YELLOW, "P-256")
                                                } else if cert.key_algorithm.contains("RSA") {
                                                    (egui::Color32::LIGHT_RED, "RSA")
                                                } else {
                                                    (egui::Color32::GRAY, "?")
                                                };

                                            ui.label(
                                                egui::RichText::new(badge_text)
                                                    .small()
                                                    .color(badge_color)
                                                    .background_color(egui::Color32::from_gray(40)),
                                            );

                                            // Smart card indicator
                                            if cert.reader_name.is_some() {
                                                ui.label(egui::RichText::new("\u{1F4B3}").small());
                                            }

                                            // Validity indicator
                                            if cert.is_valid {
                                                ui.label(egui::RichText::new("\u{2705}").small());
                                            } else {
                                                ui.label(
                                                    egui::RichText::new("\u{274C} Expired")
                                                        .small()
                                                        .color(egui::Color32::LIGHT_RED),
                                                );
                                            }
                                        });

                                        // Issuer
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "Issued by: {}",
                                                cert.issuer_cn
                                            ))
                                            .small()
                                            .color(egui::Color32::GRAY),
                                        );

                                        // Validity period
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "Valid: {} to {}",
                                                cert.not_before, cert.not_after
                                            ))
                                            .small()
                                            .color(egui::Color32::GRAY),
                                        );

                                        // Reader name if from smart card
                                        if let Some(reader) = &cert.reader_name {
                                            ui.label(
                                                egui::RichText::new(format!("Reader: {}", reader))
                                                    .small()
                                                    .color(egui::Color32::LIGHT_BLUE),
                                            );
                                        }
                                    });
                                });
                            });

                            ui.add_space(2.0);
                        }
                    });
            });
        }

        ui.add_space(20.0);

        // Use certificate button
        if let Some(thumbprint) = &self.selected_certificate.clone() {
            ui.horizontal(|ui| {
                if ui
                    .button("\u{1F512} Use Selected Certificate")
                    .on_hover_text(
                        "Configure the application to use this certificate for authentication",
                    )
                    .clicked()
                {
                    action = Some(SettingsAction::UseCertificate(thumbprint.clone()));
                }
            });

            ui.add_space(10.0);
        }

        // CNSA 2.0 compliance info
        ui.label(egui::RichText::new("CNSA 2.0 Compliance").strong());
        ui.add_space(5.0);

        ui.label(
            egui::RichText::new(
                "For CNSA 2.0 compliance, P-384 ECDSA certificates are preferred. \
                RSA certificates are supported but not recommended for government use.",
            )
            .small()
            .color(egui::Color32::GRAY),
        );

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);

        // Server Certificate Verification section
        ui.label(egui::RichText::new("Server Certificate Verification").strong());
        ui.add_space(10.0);

        ui.label(
            egui::RichText::new(
                "Controls how the client verifies TLS server certificates. \
                For production use, 'System CA Store' or 'Custom CA File' should always be used.",
            )
            .small()
            .color(egui::Color32::GRAY),
        );

        ui.add_space(10.0);

        // Verification mode dropdown
        egui::Grid::new("cert_verification_grid")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                ui.label("Verification Mode:");

                let current_label = self.server_cert_verification.label();
                egui::ComboBox::from_id_salt("cert_verification_mode")
                    .selected_text(current_label)
                    .show_ui(ui, |ui| {
                        // System mode
                        if ui
                            .selectable_label(
                                matches!(
                                    self.server_cert_verification,
                                    ServerCertVerificationMode::System
                                ),
                                "System CA Store",
                            )
                            .on_hover_text("Use the operating system's trusted CA store")
                            .clicked()
                        {
                            action = Some(SettingsAction::SetVerificationMode(
                                ServerCertVerificationMode::System,
                            ));
                        }

                        // Custom mode
                        if ui
                            .selectable_label(
                                matches!(
                                    self.server_cert_verification,
                                    ServerCertVerificationMode::Custom { .. }
                                ),
                                "Custom CA File",
                            )
                            .on_hover_text("Use a custom CA certificate file (PEM format)")
                            .clicked()
                        {
                            // If already in custom mode, keep current path
                            let path = self
                                .server_cert_verification
                                .custom_ca_path()
                                .map(String::from)
                                .unwrap_or_else(|| self.custom_ca_path.clone());
                            action = Some(SettingsAction::SetVerificationMode(
                                ServerCertVerificationMode::Custom { ca_file_path: path },
                            ));
                        }

                        ui.separator();

                        // Insecure mode (with warning)
                        if ui
                            .selectable_label(
                                matches!(
                                    self.server_cert_verification,
                                    ServerCertVerificationMode::Insecure
                                ),
                                egui::RichText::new("Insecure (Dev Only)")
                                    .color(egui::Color32::LIGHT_RED),
                            )
                            .on_hover_text(
                                "DEVELOPMENT ONLY: Accepts all certificates without validation",
                            )
                            .clicked()
                        {
                            // Show warning dialog before enabling
                            self.pending_verification_mode =
                                Some(ServerCertVerificationMode::Insecure);
                            self.show_insecure_warning = true;
                        }
                    });
                ui.end_row();

                // Show custom CA file path field when in Custom mode
                if matches!(
                    self.server_cert_verification,
                    ServerCertVerificationMode::Custom { .. }
                ) {
                    ui.label("CA File:");
                    ui.horizontal(|ui| {
                        let path_response = ui.add(
                            egui::TextEdit::singleline(&mut self.custom_ca_path)
                                .hint_text("/path/to/ca-bundle.pem")
                                .desired_width(200.0),
                        );
                        if path_response.changed() {
                            self.is_dirty = true;
                        }

                        if ui.button("Browse...").clicked() {
                            action = Some(SettingsAction::BrowseForCaFile);
                        }
                    });
                    ui.end_row();
                }
            });

        // Warning for insecure mode
        if self.server_cert_verification.is_insecure() {
            ui.add_space(10.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(80, 40, 40))
                .inner_margin(10.0)
                .corner_radius(4.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("\u{26A0}").size(20.0)); // Warning sign
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new("INSECURE MODE ACTIVE")
                                    .strong()
                                    .color(egui::Color32::LIGHT_RED),
                            );
                            ui.label(
                                egui::RichText::new(
                                    "Server certificates are NOT being validated. \
                                    This should ONLY be used for local development \
                                    with self-signed certificates.",
                                )
                                .small()
                                .color(egui::Color32::LIGHT_YELLOW),
                            );
                        });
                    });
                });
        }

        action
    }

    /// Renders the insecure mode warning dialog.
    ///
    /// Returns Some(action) if the user confirms or cancels.
    pub fn render_insecure_warning_dialog(
        &mut self,
        ctx: &egui::Context,
    ) -> Option<SettingsAction> {
        let mut action = None;

        if self.show_insecure_warning {
            egui::Window::new("Security Warning")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("\u{26A0}")
                                .size(48.0)
                                .color(egui::Color32::YELLOW),
                        );
                        ui.add_space(10.0);

                        ui.heading("Enable Insecure Mode?");
                        ui.add_space(10.0);

                        ui.label(
                            "You are about to disable server certificate validation.\n\n\
                            This means the client will accept ANY certificate from servers,\n\
                            including invalid, expired, or malicious certificates.\n\n\
                            This should ONLY be used for local development with\n\
                            self-signed certificates.",
                        );

                        ui.add_space(20.0);

                        ui.label(
                            egui::RichText::new("NEVER use this mode in production!")
                                .strong()
                                .color(egui::Color32::LIGHT_RED),
                        );

                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            if ui
                                .button(egui::RichText::new("Cancel").color(egui::Color32::WHITE))
                                .clicked()
                            {
                                self.cancel_insecure_mode();
                            }

                            ui.add_space(20.0);

                            if ui
                                .button(
                                    egui::RichText::new("I Understand, Enable Anyway")
                                        .color(egui::Color32::LIGHT_RED),
                                )
                                .clicked()
                            {
                                self.confirm_insecure_mode();
                                action = Some(SettingsAction::ConfirmInsecureMode);
                            }
                        });

                        ui.add_space(10.0);
                    });
                });
        }

        action
    }

    fn render_audio_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Audio Devices").strong());
        ui.add_space(10.0);

        egui::Grid::new("audio_settings_grid")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                // Input device
                ui.label("Input (Microphone):");
                egui::ComboBox::from_id_salt("input_device")
                    .selected_text(&self.input_device)
                    .show_ui(ui, |ui| {
                        for device in &self.available_inputs {
                            if ui
                                .selectable_label(self.input_device == *device, device)
                                .clicked()
                            {
                                self.input_device = device.clone();
                                self.is_dirty = true;
                            }
                        }
                    });
                ui.end_row();

                // Output device
                ui.label("Output (Speakers):");
                egui::ComboBox::from_id_salt("output_device")
                    .selected_text(&self.output_device)
                    .show_ui(ui, |ui| {
                        for device in &self.available_outputs {
                            if ui
                                .selectable_label(self.output_device == *device, device)
                                .clicked()
                            {
                                self.output_device = device.clone();
                                self.is_dirty = true;
                            }
                        }
                    });
                ui.end_row();
            });

        ui.add_space(20.0);
        ui.label(egui::RichText::new("Audio Processing").strong());
        ui.add_space(10.0);

        if ui
            .checkbox(&mut self.echo_cancellation, "Echo Cancellation")
            .changed()
        {
            self.is_dirty = true;
        }
        if ui
            .checkbox(&mut self.noise_suppression, "Noise Suppression")
            .changed()
        {
            self.is_dirty = true;
        }

        ui.add_space(20.0);

        // Test audio button
        if ui.button("\u{1F50A} Test Audio").clicked() {
            // TODO: Play test tone
        }
    }

    fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Startup").strong());
        ui.add_space(10.0);

        if ui
            .checkbox(&mut self.start_minimized, "Start minimized to system tray")
            .changed()
        {
            self.is_dirty = true;
        }
        if ui
            .checkbox(
                &mut self.minimize_to_tray,
                "Minimize to tray instead of taskbar",
            )
            .changed()
        {
            self.is_dirty = true;
        }

        ui.add_space(20.0);
        ui.label(egui::RichText::new("Appearance").strong());
        ui.add_space(10.0);

        if ui.checkbox(&mut self.dark_mode, "Dark mode").changed() {
            self.is_dirty = true;
        }
    }

    fn render_about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);

        ui.vertical_centered(|ui| {
            ui.heading("USG SIP Soft Client");
            ui.add_space(10.0);

            ui.label(egui::RichText::new("Version 0.1.0").color(egui::Color32::GRAY));
            ui.add_space(20.0);

            ui.label("A CNSA 2.0 compliant SIP soft client");
            ui.label("for enterprise and government use.");

            ui.add_space(20.0);

            ui.label(egui::RichText::new("Security Features:").strong());
            ui.label("- TLS 1.3 only (CNSA 2.0)");
            ui.label("- AES-256-GCM encryption");
            ui.label("- P-384 ECDHE/ECDSA");
            ui.label("- Smart card authentication (CAC/PIV)");
            ui.label("- No password-based authentication");

            ui.add_space(30.0);

            ui.label(
                egui::RichText::new("Built with Rust and egui")
                    .small()
                    .color(egui::Color32::GRAY),
            );
        });
    }
}

impl Default for SettingsView {
    fn default() -> Self {
        Self::new()
    }
}
