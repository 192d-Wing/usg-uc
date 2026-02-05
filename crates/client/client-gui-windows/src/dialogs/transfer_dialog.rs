//! Transfer dialog for call transfers.
//!
//! Allows the user to enter a SIP URI to transfer the current call.

use native_windows_gui as nwg;

/// Result of the transfer dialog.
#[derive(Debug, Clone)]
pub enum TransferDialogResult {
    /// User confirmed transfer to the given URI.
    Transfer(String),
    /// User cancelled the dialog.
    Cancelled,
}

/// Transfer dialog window.
pub struct TransferDialog {
    /// Dialog window.
    window: nwg::Window,
    /// URI input field.
    uri_input: nwg::TextInput,
    /// Transfer button.
    transfer_button: nwg::Button,
    /// Cancel button.
    cancel_button: nwg::Button,
    /// URI label.
    _uri_label: nwg::Label,
    /// Dialog result.
    result: std::cell::RefCell<TransferDialogResult>,
}

impl TransferDialog {
    /// Shows the transfer dialog and returns the result.
    pub fn show(parent: &nwg::Window) -> TransferDialogResult {
        // Build the dialog
        let dialog = match Self::build(parent) {
            Ok(d) => d,
            Err(e) => {
                nwg::modal_error_message(parent, "Error", &format!("Failed to create dialog: {}", e));
                return TransferDialogResult::Cancelled;
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

    /// Builds the transfer dialog.
    fn build(parent: &nwg::Window) -> Result<Self, nwg::NwgError> {
        let mut window = Default::default();
        nwg::Window::builder()
            .size((350, 140))
            .position((
                parent.position().0 + 50,
                parent.position().1 + 100,
            ))
            .title("Transfer Call")
            .flags(
                nwg::WindowFlags::WINDOW
                    | nwg::WindowFlags::VISIBLE
                    | nwg::WindowFlags::POPUP,
            )
            .build(&mut window)?;

        // URI label
        let mut uri_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text("Transfer to (SIP URI):")
            .position((15, 20))
            .size((320, 20))
            .build(&mut uri_label)?;

        // URI input
        let mut uri_input = Default::default();
        nwg::TextInput::builder()
            .parent(&window)
            .position((15, 45))
            .size((320, 25))
            .placeholder_text(Some("sip:user@domain.com"))
            .build(&mut uri_input)?;

        // Buttons
        let mut transfer_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Transfer")
            .position((130, 90))
            .size((100, 30))
            .build(&mut transfer_button)?;

        let mut cancel_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Cancel")
            .position((235, 90))
            .size((100, 30))
            .build(&mut cancel_button)?;

        // Focus the input field
        uri_input.set_focus();

        Ok(Self {
            window,
            uri_input,
            transfer_button,
            cancel_button,
            _uri_label: uri_label,
            result: std::cell::RefCell::new(TransferDialogResult::Cancelled),
        })
    }

    /// Binds event handlers to the dialog controls.
    #[allow(unsafe_code)]
    fn bind_events(&self) {
        use std::mem;

        // SAFETY: Creating a static reference for modal dialog event handlers.
        // Safe because the dialog is short-lived and bind_events is called only once.
        let this: &'static Self = unsafe { mem::transmute(self) };

        // Transfer button click
        nwg::bind_event_handler(
            &self.transfer_button.handle,
            &self.window.handle,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let uri = this.uri_input.text();
                    if !uri.is_empty() {
                        *this.result.borrow_mut() = TransferDialogResult::Transfer(uri);
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

        // Window close (X button or escape)
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

    /// Gets the entered URI.
    #[allow(dead_code)]
    pub fn uri(&self) -> String {
        self.uri_input.text()
    }
}
