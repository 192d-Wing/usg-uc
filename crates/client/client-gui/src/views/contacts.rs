//! Contacts list view.

use eframe::egui;

/// Actions from the contacts view.
#[derive(Debug, Clone)]
pub enum ContactsAction {
    /// Call the contact at the given URI.
    Call(String),
    /// Edit the contact with the given ID.
    Edit(String),
    /// Delete the contact with the given ID.
    Delete(String),
}

/// A contact entry for display.
#[derive(Debug, Clone)]
struct ContactEntry {
    /// Contact ID.
    id: String,
    /// Display name.
    name: String,
    /// SIP URI.
    sip_uri: String,
    /// Whether this is a favorite.
    favorite: bool,
}

/// Contacts view state.
pub struct ContactsView {
    /// Search query.
    search_query: String,
    /// Sample contacts (in production, these come from ContactManager).
    contacts: Vec<ContactEntry>,
    /// Selected contact ID.
    selected_contact: Option<String>,
}

impl ContactsView {
    /// Creates a new contacts view.
    pub fn new() -> Self {
        // Sample contacts for demonstration
        let contacts = vec![
            ContactEntry {
                id: "1".to_string(),
                name: "Alice Smith".to_string(),
                sip_uri: "sips:alice@example.com".to_string(),
                favorite: true,
            },
            ContactEntry {
                id: "2".to_string(),
                name: "Bob Johnson".to_string(),
                sip_uri: "sips:bob@example.com".to_string(),
                favorite: false,
            },
            ContactEntry {
                id: "3".to_string(),
                name: "Carol White".to_string(),
                sip_uri: "sips:carol@example.com".to_string(),
                favorite: true,
            },
        ];

        Self {
            search_query: String::new(),
            contacts,
            selected_contact: None,
        }
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
                        // TODO: Open add contact dialog
                    }
                });
            });

            ui.separator();

            // Filter contacts by search query - clone to avoid borrow conflict
            let query_lower = self.search_query.to_lowercase();
            let filtered_contacts: Vec<ContactEntry> = self
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
            let favorites: Vec<ContactEntry> = filtered_contacts
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

    /// Renders a single contact row.
    fn render_contact_row(&mut self, ui: &mut egui::Ui, contact: &ContactEntry) -> Option<ContactsAction> {
        let mut action = None;

        let is_selected = self.selected_contact.as_ref() == Some(&contact.id);

        let response = ui
            .horizontal(|ui| {
                ui.set_min_height(48.0);

                // Avatar placeholder (initials)
                let initials: String = contact
                    .name
                    .split_whitespace()
                    .filter_map(|w| w.chars().next())
                    .take(2)
                    .collect::<String>()
                    .to_uppercase();

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

impl Default for ContactsView {
    fn default() -> Self {
        Self::new()
    }
}
