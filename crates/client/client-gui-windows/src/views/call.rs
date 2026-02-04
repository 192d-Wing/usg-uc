//! Call view with call controls using native Windows controls.
//!
//! Displays active call information and provides control buttons.

use crate::app::SipClientApp;
use client_types::CallInfo;
use native_windows_gui as nwg;
use std::cell::RefCell;
use std::rc::Rc;

/// Call view state with native Windows controls.
pub struct CallView {
    /// Caller info label.
    caller_label: nwg::Label,
    /// Call status label.
    status_label: nwg::Label,
    /// Call duration label.
    duration_label: nwg::Label,
    /// Mute button.
    mute_button: nwg::Button,
    /// Hold button.
    hold_button: nwg::Button,
    /// Hangup button.
    hangup_button: nwg::Button,
    /// Transfer button.
    transfer_button: nwg::Button,
    /// Input device combo box.
    input_device_combo: nwg::ComboBox<String>,
    /// Output device combo box.
    output_device_combo: nwg::ComboBox<String>,
    /// Input device label.
    _input_label: nwg::Label,
    /// Output device label.
    _output_label: nwg::Label,
    /// Available input devices.
    input_devices: RefCell<Vec<String>>,
    /// Available output devices.
    output_devices: RefCell<Vec<String>>,
    /// Current mute state.
    is_muted: RefCell<bool>,
    /// Current hold state.
    is_on_hold: RefCell<bool>,
}

impl CallView {
    /// Builds the call view within the given parent tab.
    pub fn build(parent: &nwg::Tab) -> Result<Self, nwg::NwgError> {
        // Caller info label (large, centered)
        let mut caller_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("No active call")
            .position((10, 30))
            .size((380, 30))
            .h_align(nwg::HTextAlign::Center)
            .build(&mut caller_label)?;

        // Status label
        let mut status_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("")
            .position((10, 70))
            .size((380, 25))
            .h_align(nwg::HTextAlign::Center)
            .build(&mut status_label)?;

        // Duration label (large timer)
        let mut duration_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("00:00")
            .position((10, 110))
            .size((380, 40))
            .h_align(nwg::HTextAlign::Center)
            .build(&mut duration_label)?;

        // Control buttons row
        let button_width = 90;
        let button_height = 45;
        let button_y = 180;
        let spacing = 10;
        let start_x = 25;

        let mut mute_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Mute")
            .position((start_x, button_y))
            .size((button_width, button_height))
            .build(&mut mute_button)?;

        let mut hold_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Hold")
            .position((start_x + button_width as i32 + spacing, button_y))
            .size((button_width, button_height))
            .build(&mut hold_button)?;

        let mut transfer_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Transfer")
            .position((start_x + 2 * (button_width as i32 + spacing), button_y))
            .size((button_width, button_height))
            .build(&mut transfer_button)?;

        let mut hangup_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Hangup")
            .position((start_x + 3 * (button_width as i32 + spacing), button_y))
            .size((button_width, button_height))
            .build(&mut hangup_button)?;

        // Audio device selection
        let device_y = 260;

        let mut input_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("Microphone:")
            .position((10, device_y))
            .size((100, 25))
            .build(&mut input_label)?;

        let mut input_device_combo = Default::default();
        nwg::ComboBox::builder()
            .parent(parent)
            .position((120, device_y))
            .size((270, 25))
            .collection(vec!["Default".to_string()])
            .build(&mut input_device_combo)?;

        let mut output_label = Default::default();
        nwg::Label::builder()
            .parent(parent)
            .text("Speaker:")
            .position((10, device_y + 35))
            .size((100, 25))
            .build(&mut output_label)?;

        let mut output_device_combo = Default::default();
        nwg::ComboBox::builder()
            .parent(parent)
            .position((120, device_y + 35))
            .size((270, 25))
            .collection(vec!["Default".to_string()])
            .build(&mut output_device_combo)?;

        Ok(Self {
            caller_label,
            status_label,
            duration_label,
            mute_button,
            hold_button,
            hangup_button,
            transfer_button,
            input_device_combo,
            output_device_combo,
            _input_label: input_label,
            _output_label: output_label,
            input_devices: RefCell::new(vec!["Default".to_string()]),
            output_devices: RefCell::new(vec!["Default".to_string()]),
            is_muted: RefCell::new(false),
            is_on_hold: RefCell::new(false),
        })
    }

    /// Binds events to the call view controls.
    pub fn bind_events(&self, app: &Rc<SipClientApp>) {
        let _ = app; // Events handled through the main app's event loop
    }

    /// Updates the view with call information.
    pub fn update_call_info(&mut self, call: Option<&CallInfo>) {
        match call {
            Some(info) => {
                // Update caller info
                let caller_text = info
                    .remote_display_name
                    .as_deref()
                    .unwrap_or(&info.remote_uri);
                self.caller_label.set_text(caller_text);

                // Update status
                self.status_label.set_text(&info.state.to_string());

                // Update duration
                let duration_text = format_duration(info.duration_secs);
                self.duration_label.set_text(&duration_text);

                // Update button states
                *self.is_muted.borrow_mut() = info.is_muted;
                *self.is_on_hold.borrow_mut() = info.is_on_hold;

                self.mute_button
                    .set_text(if info.is_muted { "Unmute" } else { "Mute" });
                self.hold_button
                    .set_text(if info.is_on_hold { "Resume" } else { "Hold" });
            }
            None => {
                self.caller_label.set_text("No active call");
                self.status_label.set_text("");
                self.duration_label.set_text("00:00");
                self.mute_button.set_text("Mute");
                self.hold_button.set_text("Hold");
            }
        }
    }

    /// Sets the available audio devices.
    pub fn set_audio_devices(&mut self, inputs: Vec<String>, outputs: Vec<String>) {
        *self.input_devices.borrow_mut() = inputs.clone();
        *self.output_devices.borrow_mut() = outputs.clone();

        // Update combo boxes
        self.input_device_combo.set_collection(inputs);
        self.output_device_combo.set_collection(outputs);

        // Select first item
        self.input_device_combo.set_selection(Some(0));
        self.output_device_combo.set_selection(Some(0));
    }

    /// Returns a reference to the mute button.
    pub fn mute_button(&self) -> &nwg::Button {
        &self.mute_button
    }

    /// Returns a reference to the hold button.
    pub fn hold_button(&self) -> &nwg::Button {
        &self.hold_button
    }

    /// Returns a reference to the hangup button.
    pub fn hangup_button(&self) -> &nwg::Button {
        &self.hangup_button
    }

    /// Returns a reference to the transfer button.
    pub fn transfer_button(&self) -> &nwg::Button {
        &self.transfer_button
    }

    /// Returns a reference to the input device combo.
    pub fn input_device_combo(&self) -> &nwg::ComboBox<String> {
        &self.input_device_combo
    }

    /// Returns a reference to the output device combo.
    pub fn output_device_combo(&self) -> &nwg::ComboBox<String> {
        &self.output_device_combo
    }

    /// Gets the currently selected input device.
    pub fn selected_input_device(&self) -> Option<String> {
        self.input_device_combo
            .selection()
            .and_then(|i| self.input_devices.borrow().get(i).cloned())
    }

    /// Gets the currently selected output device.
    pub fn selected_output_device(&self) -> Option<String> {
        self.output_device_combo
            .selection()
            .and_then(|i| self.output_devices.borrow().get(i).cloned())
    }
}

/// Formats a duration in seconds as MM:SS or HH:MM:SS.
fn format_duration(seconds: u32) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, secs)
    } else {
        format!("{:02}:{:02}", minutes, secs)
    }
}
