//! Dialer view with number pad using native Windows controls.
//!
//! Provides a phone-style dialpad for entering SIP URIs or phone numbers.

use crate::app::SipClientApp;
use native_windows_gui as nwg;
use std::cell::RefCell;
use std::rc::Rc;

/// Dialer view state with native Windows controls.
pub struct DialerView {
    /// Input field for number/SIP URI.
    input: nwg::TextInput,
    /// Dial buttons (0-9, *, #).
    buttons: Vec<nwg::Button>,
    /// Call button.
    call_button: nwg::Button,
    /// Clear button.
    clear_button: nwg::Button,
    /// Backspace button.
    backspace_button: nwg::Button,
    /// Default domain for phone numbers.
    default_domain: RefCell<Option<String>>,
}

impl DialerView {
    /// Builds the dialer view within the given parent tab.
    pub fn build(parent: &nwg::Tab) -> Result<Self, nwg::NwgError> {
        // Input field
        let mut input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((10, 20))
            .size((380, 30))
            .placeholder_text(Some("Enter number or SIP URI"))
            .build(&mut input)?;

        // Create dialpad buttons (4 rows x 3 columns)
        let button_labels = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];
        let button_width = 80i32;
        let button_height = 60i32;
        let start_x = 90i32;
        let start_y = 70i32;
        let spacing = 10i32;

        let mut buttons = Vec::with_capacity(12);
        for (i, label) in button_labels.iter().enumerate() {
            let row = (i / 3) as i32;
            let col = (i % 3) as i32;
            let x = start_x + col * (button_width + spacing);
            let y = start_y + row * (button_height + spacing);

            let mut button = Default::default();
            nwg::Button::builder()
                .parent(parent)
                .text(label)
                .position((x, y))
                .size((button_width as u32, button_height as u32))
                .build(&mut button)?;
            buttons.push(button);
        }

        // Action buttons row
        let action_y = start_y + 4 * (button_height + spacing);

        let mut backspace_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("<-") // Backspace symbol
            .position((start_x, action_y))
            .size((80, 50))
            .build(&mut backspace_button)?;

        let mut call_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Call")
            .position((start_x + 90, action_y))
            .size((170, 50))
            .build(&mut call_button)?;

        let mut clear_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Clear")
            .position((start_x + 180, action_y + 60))
            .size((80, 30))
            .build(&mut clear_button)?;

        Ok(Self {
            input,
            buttons,
            call_button,
            clear_button,
            backspace_button,
            default_domain: RefCell::new(None),
        })
    }

    /// Binds events to the dialer controls.
    pub fn bind_events(&self, app: &Rc<SipClientApp>) {
        // Note: In NWG, we typically use derive macros for event binding.
        // For this manual approach, we'll handle events through the app's timer polling.
        // The app will call our action methods directly based on button states.

        // For a proper implementation, we would use the nwg_ui! macro or NativeUi derive.
        // However, to keep things simple and avoid macros, we'll use a different approach:
        // The main app will poll for button clicks using the timer.

        let _ = app; // Silence unused warning - events handled through polling
    }

    /// Processes a digit button click.
    pub fn on_digit_click(&self, digit: &str) {
        let current = self.input.text();
        self.input.set_text(&format!("{}{}", current, digit));
    }

    /// Processes backspace button click.
    pub fn on_backspace(&self) {
        let mut text = self.input.text();
        if !text.is_empty() {
            text.pop();
            self.input.set_text(&text);
        }
    }

    /// Processes clear button click.
    pub fn on_clear(&self) {
        self.input.set_text("");
    }

    /// Processes call button click. Returns the formatted URI if input is non-empty.
    pub fn on_call(&self) -> Option<String> {
        let text = self.input.text();
        if text.is_empty() {
            return None;
        }

        let uri = self.format_uri(&text);
        self.input.set_text("");
        Some(uri)
    }

    /// Sets the default domain for phone number URIs.
    pub fn set_default_domain(&self, domain: Option<String>) {
        *self.default_domain.borrow_mut() = domain;
    }

    /// Gets the current input text.
    pub fn input_text(&self) -> String {
        self.input.text()
    }

    /// Sets the input text.
    pub fn set_input_text(&self, text: &str) {
        self.input.set_text(text);
    }

    /// Returns references to the digit buttons for event handling.
    pub fn digit_buttons(&self) -> &[nwg::Button] {
        &self.buttons
    }

    /// Returns a reference to the call button.
    pub fn call_button(&self) -> &nwg::Button {
        &self.call_button
    }

    /// Returns a reference to the clear button.
    pub fn clear_button(&self) -> &nwg::Button {
        &self.clear_button
    }

    /// Returns a reference to the backspace button.
    pub fn backspace_button(&self) -> &nwg::Button {
        &self.backspace_button
    }

    /// Formats the input as a SIP URI if needed.
    fn format_uri(&self, input: &str) -> String {
        let input = input.trim();
        let default_domain = self.default_domain.borrow();

        // Already a SIP URI - use as-is
        if input.starts_with("sip:") || input.starts_with("sips:") {
            return input.to_string();
        }

        // Get domain from settings, or leave it off for server to fill in
        let domain = default_domain.as_deref().filter(|d| !d.is_empty());

        // Looks like a phone number - wrap in sips: URI
        if input
            .chars()
            .all(|c| c.is_ascii_digit() || c == '+' || c == '-' || c == '*' || c == '#')
        {
            return match domain {
                Some(d) => format!("sips:{input}@{d}"),
                None => format!("sips:{input}"),
            };
        }

        // Already has @ - assume it's user@domain format
        if input.contains('@') {
            return format!("sips:{input}");
        }

        // Default: treat as username, add domain if available
        match domain {
            Some(d) => format!("sips:{input}@{d}"),
            None => format!("sips:{input}"),
        }
    }
}
