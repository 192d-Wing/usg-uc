//! PIN entry dialog for smart card authentication.
//!
//! Provides a secure PIN entry dialog with masked input.

use native_windows_gui as nwg;
use std::cell::RefCell;

/// Result of the PIN dialog.
#[derive(Debug, Clone)]
pub enum PinDialogResult {
    /// User entered a PIN.
    Entered(String),
    /// User cancelled the dialog.
    Cancelled,
}

/// PIN entry dialog window.
pub struct PinDialog {
    /// Dialog window.
    window: nwg::Window,
    /// Message label.
    _message_label: nwg::Label,
    /// PIN input field.
    pin_input: nwg::TextInput,
    /// Error label (for showing PIN errors).
    error_label: nwg::Label,
    /// OK button.
    ok_button: nwg::Button,
    /// Cancel button.
    cancel_button: nwg::Button,
    /// Dialog result.
    result: RefCell<PinDialogResult>,
}

impl PinDialog {
    /// Shows the PIN dialog and returns the result.
    ///
    /// # Arguments
    /// * `parent` - Parent window for the dialog
    /// * `message` - Message to display (e.g., "Enter PIN for certificate X")
    /// * `error` - Optional error message from previous attempt
    pub fn show(parent: &nwg::Window, message: &str, error: Option<&str>) -> PinDialogResult {
        // Build the dialog
        let dialog = match Self::build(parent, message, error) {
            Ok(d) => d,
            Err(e) => {
                nwg::modal_error_message(parent, "Error", &format!("Failed to create dialog: {}", e));
                return PinDialogResult::Cancelled;
            }
        };

        // Set up event handlers
        dialog.bind_events();

        // Show modal and run event loop
        dialog.window.set_visible(true);
        nwg::Modal::new(&dialog.window).run_modal(&dialog.ok_button, &dialog.cancel_button);

        // Return result
        dialog.result.borrow().clone()
    }

    /// Builds the PIN dialog.
    fn build(parent: &nwg::Window, message: &str, error: Option<&str>) -> Result<Self, nwg::NwgError> {
        let height = if error.is_some() { 180 } else { 150 };

        let mut window = Default::default();
        nwg::Window::builder()
            .size((350, height))
            .position((
                parent.position().0 + 50,
                parent.position().1 + 100,
            ))
            .title("Smart Card PIN")
            .flags(
                nwg::WindowFlags::WINDOW
                    | nwg::WindowFlags::VISIBLE
                    | nwg::WindowFlags::POPUP,
            )
            .build(&mut window)?;

        // Message label
        let mut message_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text(message)
            .position((15, 15))
            .size((320, 40))
            .build(&mut message_label)?;

        // PIN input (password style)
        let mut pin_input = Default::default();
        nwg::TextInput::builder()
            .parent(&window)
            .position((15, 60))
            .size((320, 25))
            .password(Some('*'))
            .build(&mut pin_input)?;

        // Error label (only visible if there's an error)
        let error_y = 95;
        let mut error_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text(error.unwrap_or(""))
            .position((15, error_y))
            .size((320, 20))
            .build(&mut error_label)?;

        // Buttons
        let button_y = if error.is_some() { 125 } else { 100 };

        let mut ok_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("OK")
            .position((130, button_y))
            .size((100, 30))
            .build(&mut ok_button)?;

        let mut cancel_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Cancel")
            .position((235, button_y))
            .size((100, 30))
            .build(&mut cancel_button)?;

        // Focus the PIN field
        nwg::Window::set_focus(&pin_input);

        Ok(Self {
            window,
            _message_label: message_label,
            pin_input,
            error_label,
            ok_button,
            cancel_button,
            result: RefCell::new(PinDialogResult::Cancelled),
        })
    }

    /// Binds event handlers to the dialog controls.
    fn bind_events(&self) {
        // OK button click
        let result_ok = self.result.clone();
        let pin_input = self.pin_input.handle.clone();
        let window_ok = self.window.handle.clone();
        nwg::bind_event_handler(
            &self.ok_button.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let pin = nwg::TextInput::from(&pin_input).text();
                    if !pin.is_empty() {
                        *result_ok.borrow_mut() = PinDialogResult::Entered(pin);
                    }
                    nwg::Window::from(&window_ok).close();
                }
            },
        );

        // Cancel button click
        let window_cancel = self.window.handle.clone();
        nwg::bind_event_handler(
            &self.cancel_button.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    nwg::Window::from(&window_cancel).close();
                }
            },
        );

        // Enter key in PIN field submits
        let result_enter = self.result.clone();
        let pin_input_enter = self.pin_input.handle.clone();
        let window_enter = self.window.handle.clone();
        nwg::bind_event_handler(
            &self.pin_input.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnKeyEnter {
                    let pin = nwg::TextInput::from(&pin_input_enter).text();
                    if !pin.is_empty() {
                        *result_enter.borrow_mut() = PinDialogResult::Entered(pin);
                    }
                    nwg::Window::from(&window_enter).close();
                }
            },
        );

        // Window close (X button)
        nwg::bind_event_handler(
            &self.window.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnWindowClose {
                    nwg::stop_thread_dispatch();
                }
            },
        );
    }

    /// Sets the error message on the dialog.
    pub fn set_error(&self, error: &str) {
        self.error_label.set_text(error);
    }
}
