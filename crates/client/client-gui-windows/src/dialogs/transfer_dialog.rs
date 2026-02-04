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
        nwg::Modal::new(&dialog.window).run_modal(&dialog.transfer_button, &dialog.cancel_button);

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
        nwg::Window::set_focus(&uri_input);

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
    fn bind_events(&self) {
        // Transfer button click
        let result_transfer = self.result.clone();
        let uri_input_transfer = self.uri_input.handle.clone();
        let window_transfer = self.window.handle.clone();
        nwg::bind_event_handler(
            &self.transfer_button.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let uri = nwg::TextInput::from(&uri_input_transfer).text();
                    if !uri.is_empty() {
                        *result_transfer.borrow_mut() = TransferDialogResult::Transfer(uri);
                    }
                    nwg::Window::from(&window_transfer).close();
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

        // Window close (X button or escape)
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

    /// Gets the entered URI.
    pub fn uri(&self) -> String {
        self.uri_input.text()
    }
}
