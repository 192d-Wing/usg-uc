//! Contacts list view using native Windows controls.
//!
//! Displays a list of contacts with call and management functionality.

use crate::app::SipClientApp;
use client_types::Contact;
use native_windows_gui as nwg;
use std::cell::RefCell;
use std::rc::Rc;

/// Contacts view state with native Windows controls.
pub struct ContactsView {
    /// Search input.
    search_input: nwg::TextInput,
    /// Contacts list box.
    contacts_list: nwg::ListBox<String>,
    /// Add contact button.
    add_button: nwg::Button,
    /// Call button.
    call_button: nwg::Button,
    /// Edit button.
    edit_button: nwg::Button,
    /// Delete button.
    delete_button: nwg::Button,
    /// Favorite toggle button.
    favorite_button: nwg::Button,
    /// Stored contacts.
    contacts: RefCell<Vec<Contact>>,
    /// Filtered contact indices (maps list index to contact index).
    filtered_indices: RefCell<Vec<usize>>,
}

impl ContactsView {
    /// Builds the contacts view within the given parent tab.
    pub fn build(parent: &nwg::Tab) -> Result<Self, nwg::NwgError> {
        // Search input
        let mut search_input = Default::default();
        nwg::TextInput::builder()
            .parent(parent)
            .position((10, 10))
            .size((280, 25))
            .placeholder_text(Some("Search contacts..."))
            .build(&mut search_input)?;

        // Add contact button
        let mut add_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Add")
            .position((300, 10))
            .size((90, 25))
            .build(&mut add_button)?;

        // Contacts list
        let mut contacts_list = Default::default();
        nwg::ListBox::builder()
            .parent(parent)
            .position((10, 45))
            .size((380, 380))
            .collection(Vec::new())
            .build(&mut contacts_list)?;

        // Action buttons
        let button_y = 435;
        let button_width = 85;
        let spacing = 10;

        let mut call_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Call")
            .position((10, button_y))
            .size((button_width, 30))
            .build(&mut call_button)?;

        let mut edit_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Edit")
            .position((10 + button_width as i32 + spacing, button_y))
            .size((button_width, 30))
            .build(&mut edit_button)?;

        let mut favorite_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Favorite")
            .position((10 + 2 * (button_width as i32 + spacing), button_y))
            .size((button_width, 30))
            .build(&mut favorite_button)?;

        let mut delete_button = Default::default();
        nwg::Button::builder()
            .parent(parent)
            .text("Delete")
            .position((10 + 3 * (button_width as i32 + spacing), button_y))
            .size((button_width, 30))
            .build(&mut delete_button)?;

        Ok(Self {
            search_input,
            contacts_list,
            add_button,
            call_button,
            edit_button,
            delete_button,
            favorite_button,
            contacts: RefCell::new(Vec::new()),
            filtered_indices: RefCell::new(Vec::new()),
        })
    }

    /// Binds events to the contacts view controls.
    pub fn bind_events(&self, app: &Rc<SipClientApp>) {
        let _ = app; // Events handled through the main app's event loop
    }

    /// Updates the contacts list from an iterator.
    pub fn set_contacts(&mut self, contacts: impl Iterator<Item = Contact>) {
        let mut contact_list: Vec<Contact> = contacts.collect();
        // Sort alphabetically by name
        contact_list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        *self.contacts.borrow_mut() = contact_list;
        self.update_list_display();
    }

    /// Updates the list display based on current search filter.
    fn update_list_display(&self) {
        let query = self.search_input.text().to_lowercase();
        let contacts = self.contacts.borrow();

        let mut display_items: Vec<String> = Vec::new();
        let mut filtered_indices: Vec<usize> = Vec::new();

        for (i, contact) in contacts.iter().enumerate() {
            if query.is_empty()
                || contact.name.to_lowercase().contains(&query)
                || contact.sip_uri.to_lowercase().contains(&query)
            {
                let fav_marker = if contact.favorite { "*" } else { "" };
                display_items.push(format!("{}{} - {}", fav_marker, contact.name, contact.sip_uri));
                filtered_indices.push(i);
            }
        }

        self.contacts_list.set_collection(display_items);
        *self.filtered_indices.borrow_mut() = filtered_indices;
    }

    /// Gets the currently selected contact.
    pub fn selected_contact(&self) -> Option<Contact> {
        let selection = self.contacts_list.selection()?;
        let filtered = self.filtered_indices.borrow();
        let contact_idx = *filtered.get(selection)?;
        self.contacts.borrow().get(contact_idx).cloned()
    }

    /// Returns a reference to the add button.
    pub fn add_button(&self) -> &nwg::Button {
        &self.add_button
    }

    /// Returns a reference to the call button.
    pub fn call_button(&self) -> &nwg::Button {
        &self.call_button
    }

    /// Returns a reference to the edit button.
    pub fn edit_button(&self) -> &nwg::Button {
        &self.edit_button
    }

    /// Returns a reference to the delete button.
    pub fn delete_button(&self) -> &nwg::Button {
        &self.delete_button
    }

    /// Returns a reference to the favorite button.
    pub fn favorite_button(&self) -> &nwg::Button {
        &self.favorite_button
    }

    /// Returns a reference to the search input.
    pub fn search_input(&self) -> &nwg::TextInput {
        &self.search_input
    }

    /// Returns a reference to the contacts list.
    pub fn contacts_list(&self) -> &nwg::ListBox<String> {
        &self.contacts_list
    }

    /// Gets all stored contacts.
    pub fn contacts(&self) -> std::cell::Ref<Vec<Contact>> {
        self.contacts.borrow()
    }
}
