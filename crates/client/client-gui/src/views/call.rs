//! Active call view.

use client_types::{CallInfo, CallState};
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
}

/// Call view state.
pub struct CallView {
    /// Whether local audio is muted.
    is_muted: bool,
    /// Whether call is on hold.
    is_on_hold: bool,
}

impl CallView {
    /// Creates a new call view.
    pub fn new() -> Self {
        Self {
            is_muted: false,
            is_on_hold: false,
        }
    }

    /// Renders the call view.
    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        call_info: Option<&CallInfo>,
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

                // Duration timer
                let duration = info.duration_string();
                ui.label(egui::RichText::new(duration).size(32.0).strong());

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
            }
        });

        action
    }
}

impl Default for CallView {
    fn default() -> Self {
        Self::new()
    }
}
