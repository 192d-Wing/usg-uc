//! Settings view.

use eframe::egui;

/// Actions from the settings view.
#[derive(Debug, Clone)]
pub enum SettingsAction {
    /// Save settings.
    Save,
    /// Register the specified account.
    Register(String),
    /// Unregister.
    Unregister,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SettingsTab {
    #[default]
    Account,
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
            available_outputs: vec!["Default".to_string(), "Speakers".to_string(), "Headphones".to_string()],
            is_dirty: false,
        }
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
                    (SettingsTab::Audio, "Audio"),
                    (SettingsTab::General, "General"),
                    (SettingsTab::About, "About"),
                ];

                for (tab, label) in tabs {
                    if ui
                        .selectable_label(self.active_tab == tab, label)
                        .clicked()
                    {
                        self.active_tab = tab;
                    }
                }
            });

            ui.separator();

            // Tab content
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    SettingsTab::Account => {
                        if let Some(a) = self.render_account_settings(ui) {
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
                if ui
                    .text_edit_singleline(&mut self.display_name)
                    .changed()
                {
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
            ui.label(
                egui::RichText::new("CAC/PIV Required")
                    .color(egui::Color32::YELLOW),
            );
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
            .checkbox(&mut self.minimize_to_tray, "Minimize to tray instead of taskbar")
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
