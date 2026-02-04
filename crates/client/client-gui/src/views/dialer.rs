//! Dialer view with number pad.

use eframe::egui;

/// Actions from the dialer view.
#[derive(Debug, Clone)]
pub enum DialerAction {
    /// Make a call to the given URI.
    Call(String),
}

/// Dialer view state.
pub struct DialerView {
    /// Current input (number or SIP URI).
    input: String,
}

impl DialerView {
    /// Creates a new dialer view.
    pub fn new() -> Self {
        Self {
            input: String::new(),
        }
    }

    /// Renders the dialer view.
    pub fn render(&mut self, ui: &mut egui::Ui) -> Option<DialerAction> {
        let mut action = None;

        ui.vertical_centered(|ui| {
            ui.add_space(20.0);

            // Title
            ui.heading("Dialer");

            ui.add_space(20.0);

            // Input field
            let input_width = 250.0;
            ui.allocate_ui(egui::vec2(input_width, 40.0), |ui| {
                let text_edit = egui::TextEdit::singleline(&mut self.input)
                    .font(egui::TextStyle::Heading)
                    .hint_text("Enter number or SIP URI")
                    .horizontal_align(egui::Align::Center);

                let response = ui.add_sized([input_width, 36.0], text_edit);

                // Handle Enter key
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if !self.input.is_empty() {
                        action = Some(DialerAction::Call(self.format_uri()));
                        self.input.clear();
                    }
                }
            });

            ui.add_space(20.0);

            // Number pad
            let button_size = egui::vec2(60.0, 50.0);
            let pad_buttons = [
                ["1", "2", "3"],
                ["4", "5", "6"],
                ["7", "8", "9"],
                ["*", "0", "#"],
            ];

            for row in &pad_buttons {
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 3.0 * button_size.x - 16.0) / 2.0);
                    for &digit in row {
                        if ui
                            .add_sized(
                                button_size,
                                egui::Button::new(egui::RichText::new(digit).size(24.0)),
                            )
                            .clicked()
                        {
                            self.input.push_str(digit);
                        }
                    }
                });
                ui.add_space(4.0);
            }

            ui.add_space(20.0);

            // Call and backspace buttons
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 2.0 * 100.0 - 8.0) / 2.0);

                // Backspace button
                if ui
                    .add_sized(
                        egui::vec2(100.0, 50.0),
                        egui::Button::new(egui::RichText::new("\u{232B}").size(24.0)),
                    )
                    .clicked()
                {
                    self.input.pop();
                }

                // Call button
                let call_button = egui::Button::new(
                    egui::RichText::new("\u{1F4DE} Call")
                        .size(18.0)
                        .color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(0, 150, 0));

                if ui.add_sized(egui::vec2(100.0, 50.0), call_button).clicked() {
                    if !self.input.is_empty() {
                        action = Some(DialerAction::Call(self.format_uri()));
                        self.input.clear();
                    }
                }
            });

            ui.add_space(10.0);

            // Clear button
            if !self.input.is_empty() {
                if ui.small_button("Clear").clicked() {
                    self.input.clear();
                }
            }
        });

        action
    }

    /// Formats the input as a SIP URI if needed.
    fn format_uri(&self) -> String {
        let input = self.input.trim();

        // Already a SIP URI
        if input.starts_with("sip:") || input.starts_with("sips:") {
            return input.to_string();
        }

        // Looks like a phone number - wrap in sips: URI
        // In production, you'd need the domain from account settings
        if input
            .chars()
            .all(|c| c.is_ascii_digit() || c == '+' || c == '-' || c == '*' || c == '#')
        {
            return format!("sips:{input}@example.com");
        }

        // Assume it's user@domain format
        if input.contains('@') {
            return format!("sips:{input}");
        }

        // Default: treat as phone number
        format!("sips:{input}@example.com")
    }
}

impl Default for DialerView {
    fn default() -> Self {
        Self::new()
    }
}
