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
    #[allow(dead_code)]
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

        // Simple modal loop - wait for window to close
        while dialog.window.visible() {
            nwg::dispatch_thread_events();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

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
        pin_input.set_focus();

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
    #[allow(unsafe_code)]
    fn bind_events(&self) {
        use std::mem;

        // SAFETY: Creating a static reference for modal dialog event handlers.
        // Safe because the dialog is short-lived and bind_events is called only once.
        let this: &'static Self = unsafe { mem::transmute(self) };

        // OK button click
        nwg::bind_event_handler(
            &self.ok_button.handle,
            &self.window.handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let pin = this.pin_input.text();
                    if !pin.is_empty() {
                        *this.result.borrow_mut() = PinDialogResult::Entered(pin);
                    }
                    this.window.close();
                }
            },
        );

        // Cancel button click
        nwg::bind_event_handler(
            &self.cancel_button.handle,
            &self.window.handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    this.window.close();
                }
            },
        );

        // Enter key in PIN field submits
        nwg::bind_event_handler(
            &self.pin_input.handle,
            &self.window.handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnKeyEnter {
                    let pin = this.pin_input.text();
                    if !pin.is_empty() {
                        *this.result.borrow_mut() = PinDialogResult::Entered(pin);
                    }
                    this.window.close();
                }
            },
        );

        // Window close (X button)
        nwg::bind_event_handler(
            &self.window.handle,
            &self.window.handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnWindowClose {
                    nwg::stop_thread_dispatch();
                }
            },
        );
    }

    /// Sets the error message on the dialog.
    #[allow(dead_code)]
    pub fn set_error(&self, error: &str) {
        self.error_label.set_text(error);
    }
}
