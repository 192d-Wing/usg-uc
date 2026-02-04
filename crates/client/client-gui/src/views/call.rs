//! Active call view.

use client_types::{CallInfo, CallState, DtmfDigit};
use eframe::egui;

/// Actions from the call view.
#[derive(Debug, Clone)]
pub enum CallAction {
    /// Hang up the call.
    Hangup,
    /// Toggle mute.
    Mute,
    /// Toggle hold.
    Hold,
    /// Send DTMF digit.
    Dtmf {
        /// DTMF digit to send.
        digit: DtmfDigit,
    },
    /// Accept incoming call.
    Accept {
        /// Call ID to accept.
        call_id: String,
    },
    /// Reject incoming call.
    Reject {
        /// Call ID to reject.
        call_id: String,
    },
    /// Switch focus to a different call (multi-call mode).
    SwitchTo {
        /// Call ID to switch to.
        call_id: String,
    },
    /// Switch input (microphone) device.
    SwitchInputDevice {
        /// Device name, or None for default.
        device_name: Option<String>,
    },
    /// Switch output (speaker) device.
    SwitchOutputDevice {
        /// Device name, or None for default.
        device_name: Option<String>,
    },
}

/// Call view state.
pub struct CallView {
    /// Whether local audio is muted.
    is_muted: bool,
    /// Whether call is on hold.
    is_on_hold: bool,
    /// Whether to show the DTMF dialpad.
    show_dialpad: bool,
    /// Whether to show the audio device menu.
    show_audio_menu: bool,
}

impl CallView {
    /// Creates a new call view.
    pub fn new() -> Self {
        Self {
            is_muted: false,
            is_on_hold: false,
            show_dialpad: false,
            show_audio_menu: false,
        }
    }

    /// Renders the call view.
    ///
    /// # Arguments
    /// * `ui` - The egui UI context
    /// * `call_info` - Current call information
    /// * `available_inputs` - List of available input (microphone) devices
    /// * `available_outputs` - List of available output (speaker) devices
    /// * `current_input` - Currently selected input device name
    /// * `current_output` - Currently selected output device name
    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        call_info: Option<&CallInfo>,
        available_inputs: &[String],
        available_outputs: &[String],
        current_input: Option<&str>,
        current_output: Option<&str>,
    ) -> Option<CallAction> {
        let mut action = None;

        ui.vertical_centered(|ui| {
            ui.add_space(40.0);

            // Call state and remote party info
            if let Some(info) = call_info {
                // Remote party display
                let display_name = info
                    .remote_display_name
                    .as_deref()
                    .unwrap_or(&info.remote_uri);

                ui.heading(display_name);
                ui.label(
                    egui::RichText::new(&info.remote_uri)
                        .small()
                        .color(egui::Color32::GRAY),
                );

                ui.add_space(20.0);

                // Call state
                let state_color = match info.state {
                    CallState::Connected => egui::Color32::GREEN,
                    CallState::Ringing | CallState::EarlyMedia => egui::Color32::YELLOW,
                    CallState::Dialing | CallState::Connecting => egui::Color32::LIGHT_BLUE,
                    CallState::OnHold => egui::Color32::ORANGE,
                    CallState::Terminating | CallState::Terminated => egui::Color32::RED,
                    _ => egui::Color32::GRAY,
                };

                ui.label(
                    egui::RichText::new(info.state.to_string())
                        .color(state_color)
                        .size(18.0),
                );

                ui.add_space(10.0);

                // Duration timer - styled orange when on hold
                let duration = info.duration_string();
                let duration_style = if info.is_on_hold {
                    egui::RichText::new(duration)
                        .size(32.0)
                        .strong()
                        .color(egui::Color32::ORANGE)
                } else {
                    egui::RichText::new(duration).size(32.0).strong()
                };
                ui.label(duration_style);

                // Hold banner - prominent visual indicator when call is on hold
                if info.is_on_hold {
                    ui.add_space(16.0);

                    egui::Frame::new()
                        .fill(egui::Color32::from_rgba_unmultiplied(255, 165, 0, 200))
                        .corner_radius(8.0)
                        .inner_margin(20.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Pause icon
                                ui.label(
                                    egui::RichText::new("\u{23F8}")
                                        .size(20.0)
                                        .color(egui::Color32::WHITE),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new("CALL ON HOLD")
                                        .color(egui::Color32::WHITE)
                                        .strong()
                                        .size(16.0),
                                );
                            });
                        });
                }

                // Update local state from call info
                self.is_muted = info.is_muted;
                self.is_on_hold = info.is_on_hold;
            } else {
                ui.heading("No Active Call");
            }

            ui.add_space(40.0);

            // Call control buttons
            if call_info.is_some() {
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 3.0 * 80.0 - 16.0) / 2.0);

                    let button_size = egui::vec2(70.0, 70.0);

                    // Mute button
                    let mute_color = if self.is_muted {
                        egui::Color32::RED
                    } else {
                        egui::Color32::from_rgb(60, 60, 65)
                    };
                    let mute_text = if self.is_muted {
                        "\u{1F507}"
                    } else {
                        "\u{1F508}"
                    };

                    if ui
                        .add_sized(
                            button_size,
                            egui::Button::new(egui::RichText::new(mute_text).size(24.0))
                                .fill(mute_color),
                        )
                        .on_hover_text(if self.is_muted { "Unmute" } else { "Mute" })
                        .clicked()
                    {
                        action = Some(CallAction::Mute);
                    }

                    // Hold button
                    let hold_color = if self.is_on_hold {
                        egui::Color32::ORANGE
                    } else {
                        egui::Color32::from_rgb(60, 60, 65)
                    };

                    if ui
                        .add_sized(
                            button_size,
                            egui::Button::new(egui::RichText::new("\u{23F8}").size(24.0))
                                .fill(hold_color),
                        )
                        .on_hover_text(if self.is_on_hold { "Resume" } else { "Hold" })
                        .clicked()
                    {
                        action = Some(CallAction::Hold);
                    }

                    // Hangup button
                    let hangup_button = egui::Button::new(
                        egui::RichText::new("\u{1F4F5}")
                            .size(24.0)
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(200, 50, 50));

                    if ui
                        .add_sized(button_size, hangup_button)
                        .on_hover_text("Hang up")
                        .clicked()
                    {
                        action = Some(CallAction::Hangup);
                    }
                });

                ui.add_space(20.0);

                // Button labels
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 3.0 * 80.0 - 16.0) / 2.0);
                    ui.label(egui::RichText::new("Mute").small());
                    ui.add_space(40.0);
                    ui.label(egui::RichText::new("Hold").small());
                    ui.add_space(35.0);
                    ui.label(egui::RichText::new("End").small());
                });

                ui.add_space(20.0);

                // Dialpad and Audio toggle buttons
                ui.horizontal(|ui| {
                    let dialpad_label = if self.show_dialpad {
                        "Hide Keypad"
                    } else {
                        "Show Keypad"
                    };
                    if ui.button(dialpad_label).clicked() {
                        self.show_dialpad = !self.show_dialpad;
                        if self.show_dialpad {
                            self.show_audio_menu = false;
                        }
                    }

                    let audio_label = if self.show_audio_menu {
                        "Hide Audio"
                    } else {
                        "Audio Devices"
                    };
                    if ui.button(audio_label).clicked() {
                        self.show_audio_menu = !self.show_audio_menu;
                        if self.show_audio_menu {
                            self.show_dialpad = false;
                        }
                    }
                });

                // DTMF Dialpad (when visible)
                if self.show_dialpad {
                    ui.add_space(20.0);
                    if let Some(dtmf_action) = self.render_dialpad(ui) {
                        action = Some(dtmf_action);
                    }
                }

                // Audio device menu (when visible)
                if self.show_audio_menu {
                    ui.add_space(20.0);
                    if let Some(audio_action) = self.render_audio_menu(
                        ui,
                        available_inputs,
                        available_outputs,
                        current_input,
                        current_output,
                    ) {
                        action = Some(audio_action);
                    }
                }
            }
        });

        action
    }

    /// Renders the audio device selection menu.
    fn render_audio_menu(
        &self,
        ui: &mut egui::Ui,
        available_inputs: &[String],
        available_outputs: &[String],
        current_input: Option<&str>,
        current_output: Option<&str>,
    ) -> Option<CallAction> {
        let mut action = None;

        egui::Frame::new()
            .fill(egui::Color32::from_rgb(40, 40, 45))
            .corner_radius(8.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Audio Devices").strong());
                ui.add_space(10.0);

                // Microphone selection
                ui.label("Microphone:");
                let current_input_display = current_input.unwrap_or("Default");
                egui::ComboBox::from_id_salt("call_input_device")
                    .selected_text(current_input_display)
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        // Default option
                        if ui
                            .selectable_label(current_input.is_none(), "Default")
                            .clicked()
                        {
                            action = Some(CallAction::SwitchInputDevice { device_name: None });
                        }
                        // Available devices
                        for device in available_inputs {
                            if device != "Default" {
                                let is_selected = current_input == Some(device.as_str());
                                if ui.selectable_label(is_selected, device).clicked() {
                                    action = Some(CallAction::SwitchInputDevice {
                                        device_name: Some(device.clone()),
                                    });
                                }
                            }
                        }
                    });

                ui.add_space(10.0);

                // Speaker selection
                ui.label("Speaker:");
                let current_output_display = current_output.unwrap_or("Default");
                egui::ComboBox::from_id_salt("call_output_device")
                    .selected_text(current_output_display)
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        // Default option
                        if ui
                            .selectable_label(current_output.is_none(), "Default")
                            .clicked()
                        {
                            action = Some(CallAction::SwitchOutputDevice { device_name: None });
                        }
                        // Available devices
                        for device in available_outputs {
                            if device != "Default" {
                                let is_selected = current_output == Some(device.as_str());
                                if ui.selectable_label(is_selected, device).clicked() {
                                    action = Some(CallAction::SwitchOutputDevice {
                                        device_name: Some(device.clone()),
                                    });
                                }
                            }
                        }
                    });
            });

        action
    }

    /// Renders the DTMF dialpad.
    fn render_dialpad(&self, ui: &mut egui::Ui) -> Option<CallAction> {
        let mut action = None;

        egui::Frame::new()
            .fill(egui::Color32::from_rgb(40, 40, 45))
            .corner_radius(8.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                let button_size = egui::vec2(60.0, 50.0);
                let button_style = egui::Color32::from_rgb(60, 60, 65);

                // Row 1: 1, 2, 3
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(button_size, egui::Button::new("1").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::One,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("2\nABC").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Two,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("3\nDEF").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Three,
                        });
                    }
                });

                // Row 2: 4, 5, 6
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(button_size, egui::Button::new("4\nGHI").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Four,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("5\nJKL").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Five,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("6\nMNO").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Six,
                        });
                    }
                });

                // Row 3: 7, 8, 9
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(button_size, egui::Button::new("7\nPQRS").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Seven,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("8\nTUV").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Eight,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("9\nWXYZ").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Nine,
                        });
                    }
                });

                // Row 4: *, 0, #
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(button_size, egui::Button::new("*").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Star,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("0\n+").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Zero,
                        });
                    }
                    if ui
                        .add_sized(button_size, egui::Button::new("#").fill(button_style))
                        .clicked()
                    {
                        action = Some(CallAction::Dtmf {
                            digit: DtmfDigit::Pound,
                        });
                    }
                });
            });

        action
    }
}

impl Default for CallView {
    fn default() -> Self {
        Self::new()
    }
}
