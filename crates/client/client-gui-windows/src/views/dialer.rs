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
        // Input field - larger and more modern
        let mut input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((20, 30))
            .size((440, 40))
            .placeholder_text(Some("Enter number or SIP URI"))
            .build(&mut input)?;

        // Create dialpad buttons (4 rows x 3 columns) - larger, more touch-friendly
        let button_labels = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];
        let button_width = 100i32;
        let button_height = 70i32;
        let start_x = 90i32;
        let start_y = 100i32;
        let spacing = 15i32;

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
                .size((button_width, button_height))
                .build(&mut button)?;
            buttons.push(button);
        }

        // Action buttons row - larger, more modern
        let action_y = start_y + 4 * (button_height + spacing) + 20;

        let mut backspace_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("⌫") // Backspace symbol
            .position((start_x, action_y))
            .size((100, 60))
            .build(&mut backspace_button)?;

        let mut call_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("📞 Call")
            .position((start_x + 115, action_y))
            .size((215, 60))
            .build(&mut call_button)?;

        let mut clear_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Clear")
            .position((start_x + 220, action_y + 70))
            .size((110, 40))
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
        let app_weak = Rc::downgrade(app);

        // Bind digit button events (0-9, *, #)
        let digit_labels = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];
        for (i, button) in self.buttons.iter().enumerate() {
            let app_digit = app_weak.clone();
            let digit = digit_labels[i].to_string();
            nwg::bind_event_handler(
                &button.handle,
                &app.window().handle,
                move |evt, _evt_data, _handle| {
                    if evt == nwg::Event::OnButtonClick {
                        if let Some(app) = app_digit.upgrade() {
                            app.on_dialer_digit(&digit);
                        }
                    }
                },
            );
        }

        // Bind call button
        let app_call = app_weak.clone();
        nwg::bind_event_handler(
            &self.call_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_call.upgrade() {
                        app.on_dialer_call();
                    }
                }
            },
        );

        // Bind clear button
        let app_clear = app_weak.clone();
        nwg::bind_event_handler(
            &self.clear_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_clear.upgrade() {
                        app.on_dialer_clear();
                    }
                }
            },
        );

        // Bind backspace button
        let app_backspace = app_weak.clone();
        nwg::bind_event_handler(
            &self.backspace_button.handle,
            &app.window().handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    if let Some(app) = app_backspace.upgrade() {
                        app.on_dialer_backspace();
                    }
                }
            },
        );
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
    #[allow(dead_code)]
    pub fn set_default_domain(&self, domain: Option<String>) {
        *self.default_domain.borrow_mut() = domain;
    }

    /// Gets the current input text.
    #[allow(dead_code)]
    pub fn input_text(&self) -> String {
        self.input.text()
    }

    /// Sets the input text.
    #[allow(dead_code)]
    pub fn set_input_text(&self, text: &str) {
        self.input.set_text(text);
    }

    /// Returns references to the digit buttons for event handling.
    #[allow(dead_code)]
    pub fn digit_buttons(&self) -> &[nwg::Button] {
        &self.buttons
    }

    /// Returns a reference to the call button.
    #[allow(dead_code)]
    pub fn call_button(&self) -> &nwg::Button {
        &self.call_button
    }

    /// Returns a reference to the clear button.
    #[allow(dead_code)]
    pub fn clear_button(&self) -> &nwg::Button {
        &self.clear_button
    }

    /// Returns a reference to the backspace button.
    #[allow(dead_code)]
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
