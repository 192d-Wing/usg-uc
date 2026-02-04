//! Contact add/edit dialog.
//!
//! Allows the user to add a new contact or edit an existing one.

use client_types::Contact;
use native_windows_gui as nwg;
use std::cell::RefCell;

/// Result of the contact dialog.
#[derive(Debug, Clone)]
pub enum ContactDialogResult {
    /// User saved the contact.
    Saved(Contact),
    /// User cancelled the dialog.
    Cancelled,
}

/// Contact add/edit dialog window.
pub struct ContactDialog {
    /// Dialog window.
    window: nwg::Window,
    /// Name input field.
    name_input: nwg::TextInput,
    /// SIP URI input field.
    uri_input: nwg::TextInput,
    /// Favorite checkbox.
    favorite_checkbox: nwg::CheckBox,
    /// Save button.
    save_button: nwg::Button,
    /// Cancel button.
    cancel_button: nwg::Button,
    /// Labels (kept for ownership).
    _name_label: nwg::Label,
    _uri_label: nwg::Label,
    /// Contact ID (for editing existing contacts).
    contact_id: RefCell<Option<String>>,
    /// Dialog result.
    result: RefCell<ContactDialogResult>,
}

impl ContactDialog {
    /// Shows the dialog for adding a new contact.
    pub fn show_add(parent: &nwg::Window) -> ContactDialogResult {
        Self::show_internal(parent, None)
    }

    /// Shows the dialog for editing an existing contact.
    pub fn show_edit(parent: &nwg::Window, contact: &Contact) -> ContactDialogResult {
        Self::show_internal(parent, Some(contact))
    }

    /// Internal show method.
    fn show_internal(parent: &nwg::Window, existing: Option<&Contact>) -> ContactDialogResult {
        let title = if existing.is_some() { "Edit Contact" } else { "Add Contact" };

        // Build the dialog
        let dialog = match Self::build(parent, title) {
            Ok(d) => d,
            Err(e) => {
                nwg::modal_error_message(parent, "Error", &format!("Failed to create dialog: {}", e));
                return ContactDialogResult::Cancelled;
            }
        };

        // Populate fields if editing
        if let Some(contact) = existing {
            dialog.name_input.set_text(&contact.name);
            dialog.uri_input.set_text(&contact.sip_uri);
            dialog.favorite_checkbox.set_check_state(if contact.favorite {
                nwg::CheckBoxState::Checked
            } else {
                nwg::CheckBoxState::Unchecked
            });
            *dialog.contact_id.borrow_mut() = Some(contact.id.clone());
        }

        // Set up event handlers
        dialog.bind_events();

        // Show modal and run event loop
        dialog.window.set_visible(true);
        nwg::Modal::new(&dialog.window).run_modal(&dialog.save_button, &dialog.cancel_button);

        // Return result
        dialog.result.borrow().clone()
    }

    /// Builds the contact dialog.
    fn build(parent: &nwg::Window, title: &str) -> Result<Self, nwg::NwgError> {
        let mut window = Default::default();
        nwg::Window::builder()
            .size((350, 200))
            .position((
                parent.position().0 + 50,
                parent.position().1 + 100,
            ))
            .title(title)
            .flags(
                nwg::WindowFlags::WINDOW
                    | nwg::WindowFlags::VISIBLE
                    | nwg::WindowFlags::POPUP,
            )
            .build(&mut window)?;

        // Name label and input
        let mut name_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text("Name:")
            .position((15, 15))
            .size((80, 20))
            .build(&mut name_label)?;

        let mut name_input = Default::default();
        nwg::TextInput::builder()
            .parent(&window)
            .position((100, 12))
            .size((235, 25))
            .build(&mut name_input)?;

        // SIP URI label and input
        let mut uri_label = Default::default();
        nwg::Label::builder()
            .parent(&window)
            .text("SIP URI:")
            .position((15, 50))
            .size((80, 20))
            .build(&mut uri_label)?;

        let mut uri_input = Default::default();
        nwg::TextInput::builder()
            .parent(&window)
            .position((100, 47))
            .size((235, 25))
            .placeholder_text(Some("sip:user@domain.com"))
            .build(&mut uri_input)?;

        // Favorite checkbox
        let mut favorite_checkbox = Default::default();
        nwg::CheckBox::builder()
            .parent(&window)
            .text("Favorite")
            .position((100, 85))
            .size((100, 25))
            .build(&mut favorite_checkbox)?;

        // Buttons
        let mut save_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Save")
            .position((130, 130))
            .size((100, 30))
            .build(&mut save_button)?;

        let mut cancel_button = Default::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Cancel")
            .position((235, 130))
            .size((100, 30))
            .build(&mut cancel_button)?;

        // Focus the name field
        nwg::Window::set_focus(&name_input);

        Ok(Self {
            window,
            name_input,
            uri_input,
            favorite_checkbox,
            save_button,
            cancel_button,
            _name_label: name_label,
            _uri_label: uri_label,
            contact_id: RefCell::new(None),
            result: RefCell::new(ContactDialogResult::Cancelled),
        })
    }

    /// Binds event handlers to the dialog controls.
    fn bind_events(&self) {
        // Save button click
        let result_save = self.result.clone();
        let contact_id = self.contact_id.clone();
        let name_input = self.name_input.handle.clone();
        let uri_input = self.uri_input.handle.clone();
        let favorite_checkbox = self.favorite_checkbox.handle.clone();
        let window_save = self.window.handle.clone();
        nwg::bind_event_handler(
            &self.save_button.handle,
            &self.window,
            move |evt, _evt_data, _handle| {
                if evt == nwg::Event::OnButtonClick {
                    let name = nwg::TextInput::from(&name_input).text();
                    let uri = nwg::TextInput::from(&uri_input).text();
                    let favorite = nwg::CheckBox::from(&favorite_checkbox).check_state()
                        == nwg::CheckBoxState::Checked;

                    if name.is_empty() || uri.is_empty() {
                        nwg::modal_error_message(
                            &nwg::Window::from(&window_save),
                            "Validation Error",
                            "Name and SIP URI are required.",
                        );
                        return;
                    }

                    // Generate ID for new contacts or use existing
                    let id = contact_id
                        .borrow()
                        .clone()
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                    let contact = Contact {
                        id,
                        name,
                        sip_uri: uri,
                        favorite,
                    };

                    *result_save.borrow_mut() = ContactDialogResult::Saved(contact);
                    nwg::Window::from(&window_save).close();
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
}
