//! Contacts list view.

use client_types::Contact;
use eframe::egui;

/// Actions from the contacts view.
#[derive(Debug, Clone)]
pub enum ContactsAction {
    /// Call the contact at the given URI.
    Call(String),
    /// Open add contact dialog.
    Add,
    /// Edit the contact with the given ID.
    Edit(String),
    /// Delete the contact with the given ID.
    Delete(String),
    /// Toggle favorite status for the contact.
    ToggleFavorite(String),
    /// Save a new or edited contact.
    SaveContact(Contact),
    /// Confirm deletion of a contact.
    ConfirmDelete(String),
}

/// Contact dialog mode.
#[derive(Debug, Clone, PartialEq)]
enum ContactDialogMode {
    /// Adding a new contact.
    Add,
    /// Editing an existing contact.
    Edit(String),
}

/// Contacts view state.
pub struct ContactsView {
    /// Search query.
    search_query: String,
    /// Contacts loaded from ContactManager.
    contacts: Vec<Contact>,
    /// Selected contact ID.
    selected_contact: Option<String>,
    /// Whether the add/edit dialog is open.
    show_contact_dialog: bool,
    /// Dialog mode (add or edit).
    dialog_mode: ContactDialogMode,
    /// Dialog fields.
    dialog_name: String,
    dialog_sip_uri: String,
    dialog_organization: String,
    dialog_notes: String,
    dialog_favorite: bool,
    /// Validation error message.
    dialog_error: Option<String>,
    /// Whether the delete confirmation dialog is open.
    show_delete_dialog: bool,
    /// Contact ID pending deletion.
    delete_contact_id: Option<String>,
    /// Name of contact pending deletion (for display).
    delete_contact_name: String,
}

impl ContactsView {
    /// Creates a new contacts view.
    pub fn new() -> Self {
        Self {
            search_query: String::new(),
            contacts: Vec::new(),
            selected_contact: None,
            show_contact_dialog: false,
            dialog_mode: ContactDialogMode::Add,
            dialog_name: String::new(),
            dialog_sip_uri: String::new(),
            dialog_organization: String::new(),
            dialog_notes: String::new(),
            dialog_favorite: false,
            dialog_error: None,
            show_delete_dialog: false,
            delete_contact_id: None,
            delete_contact_name: String::new(),
        }
    }

    /// Updates the contacts list from an iterator.
    pub fn set_contacts(&mut self, contacts: impl Iterator<Item = Contact>) {
        self.contacts = contacts.collect();
        // Sort alphabetically by name
        self.contacts
            .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    }

    /// Opens the add contact dialog.
    pub fn open_add_dialog(&mut self) {
        self.dialog_mode = ContactDialogMode::Add;
        self.dialog_name.clear();
        self.dialog_sip_uri.clear();
        self.dialog_organization.clear();
        self.dialog_notes.clear();
        self.dialog_favorite = false;
        self.dialog_error = None;
        self.show_contact_dialog = true;
    }

    /// Opens the edit contact dialog for the given contact.
    pub fn open_edit_dialog(&mut self, contact: &Contact) {
        self.dialog_mode = ContactDialogMode::Edit(contact.id.clone());
        self.dialog_name = contact.name.clone();
        self.dialog_sip_uri = contact.sip_uri.clone();
        self.dialog_organization = contact.organization.clone().unwrap_or_default();
        self.dialog_notes = contact.notes.clone().unwrap_or_default();
        self.dialog_favorite = contact.favorite;
        self.dialog_error = None;
        self.show_contact_dialog = true;
    }

    /// Opens the delete confirmation dialog.
    pub fn open_delete_dialog(&mut self, contact_id: &str, contact_name: &str) {
        self.delete_contact_id = Some(contact_id.to_string());
        self.delete_contact_name = contact_name.to_string();
        self.show_delete_dialog = true;
    }

    /// Closes the contact dialog.
    #[allow(dead_code)]
    pub fn close_contact_dialog(&mut self) {
        self.show_contact_dialog = false;
    }

    /// Closes the delete confirmation dialog.
    #[allow(dead_code)]
    pub fn close_delete_dialog(&mut self) {
        self.show_delete_dialog = false;
        self.delete_contact_id = None;
    }

    /// Renders the contacts view.
    pub fn render(&mut self, ui: &mut egui::Ui) -> Option<ContactsAction> {
        let mut action = None;

        ui.vertical(|ui| {
            ui.add_space(10.0);

            // Header with search
            ui.horizontal(|ui| {
                ui.heading("Contacts");
                ui.add_space(20.0);

                // Search box
                let search_edit = egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("\u{1F50D} Search...")
                    .desired_width(200.0);
                ui.add(search_edit);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("\u{2795} Add").clicked() {
                        action = Some(ContactsAction::Add);
                    }
                });
            });

            ui.separator();

            // Filter contacts by search query - clone to avoid borrow conflict
            let query_lower = self.search_query.to_lowercase();
            let filtered_contacts: Vec<Contact> = self
                .contacts
                .iter()
                .filter(|c| {
                    query_lower.is_empty()
                        || c.name.to_lowercase().contains(&query_lower)
                        || c.sip_uri.to_lowercase().contains(&query_lower)
                })
                .cloned()
                .collect();

            // Separate favorites - also cloned
            let favorites: Vec<Contact> = filtered_contacts
                .iter()
                .filter(|c| c.favorite)
                .cloned()
                .collect();
            let has_favorites = !favorites.is_empty();
            let is_empty = filtered_contacts.is_empty();

            // Contacts list
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Favorites section
                if has_favorites {
                    ui.label(
                        egui::RichText::new("Favorites")
                            .small()
                            .color(egui::Color32::GOLD),
                    );
                    ui.add_space(4.0);

                    for contact in &favorites {
                        if let Some(a) = self.render_contact_row(ui, contact) {
                            action = Some(a);
                        }
                    }

                    ui.add_space(12.0);
                }

                // All contacts section
                ui.label(
                    egui::RichText::new("All Contacts")
                        .small()
                        .color(egui::Color32::GRAY),
                );
                ui.add_space(4.0);

                for contact in &filtered_contacts {
                    if let Some(a) = self.render_contact_row(ui, contact) {
                        action = Some(a);
                    }
                }

                // Empty state
                if is_empty {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("No contacts found")
                                .color(egui::Color32::GRAY)
                                .size(16.0),
                        );
                    });
                }
            });
        });

        action
    }

    /// Renders the add/edit contact dialog.
    pub fn render_contact_dialog(&mut self, ctx: &egui::Context) -> Option<ContactsAction> {
        let mut action = None;

        if !self.show_contact_dialog {
            return None;
        }

        let title = match &self.dialog_mode {
            ContactDialogMode::Add => "Add Contact",
            ContactDialogMode::Edit(_) => "Edit Contact",
        };

        let mut open = true;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(300.0);

                // Name field
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.add_space(40.0);
                    ui.text_edit_singleline(&mut self.dialog_name);
                });

                ui.add_space(8.0);

                // SIP URI field
                ui.horizontal(|ui| {
                    ui.label("SIP URI:");
                    ui.add_space(24.0);
                    ui.text_edit_singleline(&mut self.dialog_sip_uri);
                });

                ui.add_space(8.0);

                // Organization field
                ui.horizontal(|ui| {
                    ui.label("Organization:");
                    ui.text_edit_singleline(&mut self.dialog_organization);
                });

                ui.add_space(8.0);

                // Notes field
                ui.horizontal(|ui| {
                    ui.label("Notes:");
                    ui.add_space(32.0);
                    ui.text_edit_singleline(&mut self.dialog_notes);
                });

                ui.add_space(8.0);

                // Favorite checkbox
                ui.checkbox(&mut self.dialog_favorite, "Favorite");

                // Error message
                if let Some(ref error) = self.dialog_error {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(error).color(egui::Color32::RED));
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.show_contact_dialog = false;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let save_enabled =
                            !self.dialog_name.is_empty() && !self.dialog_sip_uri.is_empty();

                        if ui
                            .add_enabled(save_enabled, egui::Button::new("Save"))
                            .clicked()
                        {
                            // Validate SIP URI format
                            if !self.dialog_sip_uri.starts_with("sip:")
                                && !self.dialog_sip_uri.starts_with("sips:")
                            {
                                self.dialog_error =
                                    Some("SIP URI must start with sip: or sips:".to_string());
                            } else {
                                // Build contact
                                let contact = Contact {
                                    id: match &self.dialog_mode {
                                        ContactDialogMode::Add => generate_contact_id(),
                                        ContactDialogMode::Edit(id) => id.clone(),
                                    },
                                    name: self.dialog_name.clone(),
                                    sip_uri: self.dialog_sip_uri.clone(),
                                    phone_numbers: Vec::new(),
                                    favorite: self.dialog_favorite,
                                    avatar_path: None,
                                    organization: if self.dialog_organization.is_empty() {
                                        None
                                    } else {
                                        Some(self.dialog_organization.clone())
                                    },
                                    notes: if self.dialog_notes.is_empty() {
                                        None
                                    } else {
                                        Some(self.dialog_notes.clone())
                                    },
                                };
                                action = Some(ContactsAction::SaveContact(contact));
                                self.show_contact_dialog = false;
                            }
                        }
                    });
                });
            });

        if !open {
            self.show_contact_dialog = false;
        }

        action
    }

    /// Renders the delete confirmation dialog.
    pub fn render_delete_dialog(&mut self, ctx: &egui::Context) -> Option<ContactsAction> {
        let mut action = None;

        if !self.show_delete_dialog {
            return None;
        }

        let mut open = true;
        egui::Window::new("Delete Contact")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(280.0);

                ui.label(format!(
                    "Are you sure you want to delete \"{}\"?",
                    self.delete_contact_name
                ));
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("This action cannot be undone.")
                        .small()
                        .color(egui::Color32::GRAY),
                );

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.show_delete_dialog = false;
                        self.delete_contact_id = None;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let delete_button = egui::Button::new(
                            egui::RichText::new("Delete").color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(200, 50, 50));

                        if ui.add(delete_button).clicked() {
                            if let Some(ref id) = self.delete_contact_id {
                                action = Some(ContactsAction::ConfirmDelete(id.clone()));
                            }
                            self.show_delete_dialog = false;
                            self.delete_contact_id = None;
                        }
                    });
                });
            });

        if !open {
            self.show_delete_dialog = false;
            self.delete_contact_id = None;
        }

        action
    }

    /// Renders a single contact row.
    fn render_contact_row(&mut self, ui: &mut egui::Ui, contact: &Contact) -> Option<ContactsAction> {
        let mut action = None;

        let is_selected = self.selected_contact.as_ref() == Some(&contact.id);

        let response = ui
            .horizontal(|ui| {
                ui.set_min_height(48.0);

                // Avatar placeholder (initials)
                let initials = contact.initials();

                let avatar_rect = ui.allocate_space(egui::vec2(36.0, 36.0)).1;
                ui.painter().circle_filled(
                    avatar_rect.center(),
                    18.0,
                    egui::Color32::from_rgb(70, 70, 80),
                );
                ui.painter().text(
                    avatar_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    &initials,
                    egui::FontId::proportional(14.0),
                    egui::Color32::WHITE,
                );

                // Contact info
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&contact.name).strong());
                        if contact.favorite {
                            ui.label(egui::RichText::new("\u{2B50}").small());
                        }
                    });
                    ui.label(
                        egui::RichText::new(&contact.sip_uri)
                            .small()
                            .color(egui::Color32::GRAY),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Call button
                    let call_button = egui::Button::new(
                        egui::RichText::new("\u{1F4DE}")
                            .size(16.0)
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0, 150, 0))
                    .min_size(egui::vec2(36.0, 36.0));

                    if ui.add(call_button).on_hover_text("Call").clicked() {
                        action = Some(ContactsAction::Call(contact.sip_uri.clone()));
                    }

                    // Favorite toggle button
                    let fav_text = if contact.favorite { "\u{2B50}" } else { "\u{2606}" };
                    let fav_button = egui::Button::new(egui::RichText::new(fav_text).size(14.0))
                        .min_size(egui::vec2(28.0, 28.0));
                    if ui
                        .add(fav_button)
                        .on_hover_text(if contact.favorite {
                            "Remove from favorites"
                        } else {
                            "Add to favorites"
                        })
                        .clicked()
                    {
                        action = Some(ContactsAction::ToggleFavorite(contact.id.clone()));
                    }

                    // More options (context menu trigger)
                    if ui.small_button("\u{22EE}").clicked() {
                        self.selected_contact = Some(contact.id.clone());
                    }
                });
            })
            .response;

        // Handle selection
        if response.clicked() {
            self.selected_contact = if is_selected {
                None
            } else {
                Some(contact.id.clone())
            };
        }

        // Context menu
        response.context_menu(|ui| {
            if ui.button("Call").clicked() {
                action = Some(ContactsAction::Call(contact.sip_uri.clone()));
                ui.close();
            }
            if ui.button("Edit").clicked() {
                action = Some(ContactsAction::Edit(contact.id.clone()));
                ui.close();
            }
            let fav_label = if contact.favorite {
                "Remove from Favorites"
            } else {
                "Add to Favorites"
            };
            if ui.button(fav_label).clicked() {
                action = Some(ContactsAction::ToggleFavorite(contact.id.clone()));
                ui.close();
            }
            ui.separator();
            if ui.button("Delete").clicked() {
                action = Some(ContactsAction::Delete(contact.id.clone()));
                ui.close();
            }
        });

        // Visual feedback for selected item
        if is_selected {
            ui.painter().rect_stroke(
                response.rect,
                4.0,
                egui::Stroke::new(1.0, egui::Color32::from_rgb(100, 100, 200)),
                egui::StrokeKind::Outside,
            );
        }

        ui.add_space(4.0);

        action
    }
}

/// Generates a unique contact ID.
fn generate_contact_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("contact-{timestamp:x}")
}

impl Default for ContactsView {
    fn default() -> Self {
        Self::new()
    }
}
