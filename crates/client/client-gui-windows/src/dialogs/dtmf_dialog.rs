//! DTMF dialpad dialog for in-call digit entry.
//!
//! Provides a dialpad for sending DTMF tones during an active call.

use native_windows_gui as nwg;
use std::cell::RefCell;
use std::sync::mpsc;

/// DTMF digit sent from the dialog.
#[derive(Debug, Clone)]
pub enum DtmfAction {
    /// Send a DTMF digit.
    SendDigit(char),
    /// Close the dialog.
    Close,
}

/// DTMF dialpad dialog window.
pub struct DtmfDialog {
    /// Dialog window.
    window: nwg::Window,
    /// Dialpad buttons (0-9, *, #).
    buttons: Vec<nwg::Button>,
    /// Close button.
    close_button: nwg::Button,
    /// Display showing sent digits.
    display_label: nwg::Label,
    /// Sent digits.
    sent_digits: RefCell<String>,
    /// Action sender.
    action_tx: mpsc::Sender<DtmfAction>,
}

impl DtmfDialog {
    /// Creates and shows the DTMF dialog.
    ///
    /// Returns a receiver for DTMF actions. The dialog remains open until
    /// the user closes it. Actions are sent as digits are pressed.
    pub fn show(parent: &nwg::Window) -> (Self, mpsc::Receiver<DtmfAction>) {
        let (action_tx, action_rx) = mpsc::channel();

        let dialog = match Self::build(parent, action_tx.clone()) {
            Ok(d) => d,
            Err(e) => {
                nwg::modal_error_message(parent, "Error", &format!("Failed to create dialog: {}", e));
                // Return a dummy dialog that immediately sends Close
                let (tx, rx) = mpsc::channel();
                let _ = tx.send(DtmfAction::Close);
                return (Self::dummy(tx), rx);
            }
        };

        // Bind events
        dialog.bind_events();

        // Show window (non-modal)
        dialog.window.set_visible(true);

        (dialog, action_rx)
    }

    /// Creates a dummy dialog for error cases.
    fn dummy(action_tx: mpsc::Sender<DtmfAction>) -> Self {
        Self {
            window: Default::default(),
            buttons: Vec::new(),
            close_button: Default::default(),
            display_label: Default::default(),
            sent_digits: RefCell::new(String::new()),
            action_tx,
        }
    }

    /// Builds the DTMF dialog.
    fn build(parent: &nwg::Window, action_tx: mpsc::Sender<DtmfAction>) -> Result<Self, nwg::NwgError> {
        let mut window = Default::default();
        nwg::Window::builder()
            .size((220, 320))
            .position((
                parent.position().0 + parent.size().0 as i32 + 10,
                parent.position().1,
            ))
            .title("DTMF Keypad")
            .flags(
                nwg::WindowFlags::WINDOW
                    | nwg::WindowFlags::VISIBLE,
            )
            .build(&mut window)?;

        // Display label for sent digits
        let mut display_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text("")
            .position((10, 10))
            .size((200, 30))
            .h_align(nwg::HTextAlign::Center)
            .build(&mut display_label)?;

        // Dialpad buttons
        let button_size = 55;
        let spacing = 10;
        let start_x = 15;
        let start_y = 50;

        let digit_labels = [
            ["1", "2", "3"],
            ["4", "5", "6"],
            ["7", "8", "9"],
            ["*", "0", "#"],
        ];

        let mut buttons = Vec::with_capacity(12);

        for (row, row_labels) in digit_labels.iter().enumerate() {
            for (col, label) in row_labels.iter().enumerate() {
                let mut button = Default::default();
                let x = start_x + col as i32 * (button_size + spacing);
                let y = start_y + row as i32 * (button_size + spacing);

                nwg::Button::builder()
                    .parent(&window)
                    .text(label)
                    .position((x, y))
                    .size((button_size as u32, button_size as u32))
                    .build(&mut button)?;

                buttons.push(button);
            }
        }

        // Close button
        let mut close_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Close")
            .position((60, 270))
            .size((100, 30))
            .build(&mut close_button)?;

        Ok(Self {
            window,
            buttons,
            close_button,
            display_label,
            sent_digits: RefCell::new(String::new()),
            action_tx,
        })
    }

    /// Binds event handlers to the dialog controls.
    fn bind_events(&self) {
        let digit_labels = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];

        // Bind each dialpad button
        for (i, button) in self.buttons.iter().enumerate() {
            let digit = digit_labels[i].chars().next().unwrap_or('0');
            let action_tx = self.action_tx.clone();
            let display_handle = self.display_label.handle.clone();
            let sent_digits = self.sent_digits.clone();

            nwg::bind_event_handler(
                &button.handle,
                &self.window,
                move |evt, _evt_data, _handle| {
                    if evt == nwg::Event::OnButtonClick {
                        // Send digit action
                        let _ = action_tx.send(DtmfAction::SendDigit(digit));

                        // Update display
                        let mut digits = sent_digits.borrow_mut();
                        digits.push(digit);
                        // Keep last 20 digits
                        if digits.len() > 20 {
                            *digits = digits.chars().skip(digits.len() - 20).collect();
                        }
                        nwg::Label::from(&display_handle).set_text(&digits);
                    }
                },
            );
        }

        // Bind close button
        let window_close = self.window.handle.clone();
        let action_tx_close = self.action_tx.clone();
        nwg::bind_event_handler(
            &self.close_button.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let _ = action_tx_close.send(DtmfAction::Close);
                    nwg::Window::from(&window_close).close();
                }
            },
        );

        // Bind window close (X button)
        let action_tx_window = self.action_tx.clone();
        nwg::bind_event_handler(
            &self.window.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnWindowClose {
                    let _ = action_tx_window.send(DtmfAction::Close);
                }
            },
        );
    }

    /// Closes the dialog.
    pub fn close(&self) {
        self.window.close();
    }

    /// Returns true if the window is still visible.
    pub fn is_visible(&self) -> bool {
        self.window.visible()
    }
}
