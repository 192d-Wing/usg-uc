//! Contact management for the SIP soft client.
//!
//! Stores contacts and call history in JSON format.

use crate::{AppError, AppResult};
use client_types::{CallHistoryEntry, Contact, PhoneNumber};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

/// Contact storage with call history.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContactStore {
    /// Contacts by ID.
    pub contacts: HashMap<String, Contact>,
    /// Call history (most recent first).
    pub call_history: Vec<CallHistoryEntry>,
}

/// Contact manager for storing and retrieving contacts and call history.
pub struct ContactManager {
    /// Contact store.
    store: ContactStore,
    /// Path to contacts file.
    contacts_path: PathBuf,
    /// Maximum call history entries to keep.
    max_history_entries: usize,
    /// Whether store has been modified since last save.
    dirty: bool,
}

impl ContactManager {
    /// Creates a new contact manager, loading from disk if available.
    pub fn new() -> AppResult<Self> {
        let contacts_path = Self::contacts_file_path()?;

        let store = if contacts_path.exists() {
            Self::load_from_file(&contacts_path)?
        } else {
            info!("No contacts file found, starting fresh");
            ContactStore::default()
        };

        Ok(Self {
            store,
            contacts_path,
            max_history_entries: 1000,
            dirty: false,
        })
    }

    /// Creates a contact manager with a custom path (for testing).
    pub fn with_path(path: PathBuf) -> AppResult<Self> {
        let store = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            ContactStore::default()
        };

        Ok(Self {
            store,
            contacts_path: path,
            max_history_entries: 1000,
            dirty: false,
        })
    }

    /// Gets the platform-specific contacts file path.
    fn contacts_file_path() -> AppResult<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "usg", "sip-client").ok_or_else(|| {
            AppError::Contact("Could not determine config directory".to_string())
        })?;

        let data_dir = proj_dirs.data_dir();

        // Create directory if it doesn't exist
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)?;
            debug!(path = ?data_dir, "Created data directory");
        }

        Ok(data_dir.join("contacts.json"))
    }

    /// Loads contacts from a JSON file.
    fn load_from_file(path: &PathBuf) -> AppResult<ContactStore> {
        let content = fs::read_to_string(path)?;
        let store: ContactStore = serde_json::from_str(&content)
            .map_err(|e| AppError::Serialization(format!("Failed to parse contacts: {e}")))?;

        info!(
            path = ?path,
            contacts = store.contacts.len(),
            history = store.call_history.len(),
            "Loaded contacts"
        );
        Ok(store)
    }

    /// Saves contacts to disk.
    pub fn save(&mut self) -> AppResult<()> {
        let content = serde_json::to_string_pretty(&self.store)
            .map_err(|e| AppError::Serialization(format!("Failed to serialize contacts: {e}")))?;

        // Write to temp file first, then rename (atomic)
        let temp_path = self.contacts_path.with_extension("json.tmp");
        fs::write(&temp_path, &content)?;
        fs::rename(&temp_path, &self.contacts_path)?;

        self.dirty = false;
        info!(path = ?self.contacts_path, "Saved contacts");
        Ok(())
    }

    /// Saves contacts if modified.
    pub fn save_if_dirty(&mut self) -> AppResult<()> {
        if self.dirty {
            self.save()
        } else {
            Ok(())
        }
    }

    /// Returns whether contacts have unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    // --- Contact Management ---

    /// Adds or updates a contact.
    pub fn set_contact(&mut self, contact: Contact) {
        self.dirty = true;
        self.store.contacts.insert(contact.id.clone(), contact);
    }

    /// Removes a contact.
    pub fn remove_contact(&mut self, contact_id: &str) -> Option<Contact> {
        self.dirty = true;
        self.store.contacts.remove(contact_id)
    }

    /// Gets a contact by ID.
    pub fn get_contact(&self, contact_id: &str) -> Option<&Contact> {
        self.store.contacts.get(contact_id)
    }

    /// Gets all contacts.
    pub fn contacts(&self) -> impl Iterator<Item = &Contact> {
        self.store.contacts.values()
    }

    /// Gets contacts sorted alphabetically by display name.
    pub fn contacts_sorted(&self) -> Vec<&Contact> {
        let mut contacts: Vec<_> = self.store.contacts.values().collect();
        contacts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        contacts
    }

    /// Searches contacts by name or number.
    pub fn search_contacts(&self, query: &str) -> Vec<&Contact> {
        let query_lower = query.to_lowercase();
        self.store
            .contacts
            .values()
            .filter(|c| {
                c.name.to_lowercase().contains(&query_lower)
                    || c.phone_numbers
                        .iter()
                        .any(|p| p.number.contains(&query_lower))
                    || c.sip_uri.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Finds a contact by phone number or SIP URI.
    ///
    /// Supports partial matching - the normalized query can match
    /// as a suffix of the contact's phone number.
    pub fn find_by_number(&self, number: &str) -> Option<&Contact> {
        let normalized = normalize_number(number);
        self.store.contacts.values().find(|c| {
            c.phone_numbers.iter().any(|p| {
                let contact_num = normalize_number(&p.number);
                // Exact match or suffix match (for searches without country code)
                contact_num == normalized || contact_num.ends_with(&normalized)
            }) || c.sip_uri.contains(number)
        })
    }

    /// Gets the total number of contacts.
    pub fn contact_count(&self) -> usize {
        self.store.contacts.len()
    }

    // --- Call History Management ---

    /// Adds a call history entry.
    pub fn add_call_history(&mut self, entry: CallHistoryEntry) {
        self.dirty = true;

        // Add to front (most recent first)
        self.store.call_history.insert(0, entry);

        // Trim if over limit
        if self.store.call_history.len() > self.max_history_entries {
            self.store.call_history.truncate(self.max_history_entries);
        }
    }

    /// Gets call history entries.
    pub fn call_history(&self) -> &[CallHistoryEntry] {
        &self.store.call_history
    }

    /// Gets recent call history (limited count).
    pub fn recent_calls(&self, limit: usize) -> &[CallHistoryEntry] {
        let end = limit.min(self.store.call_history.len());
        &self.store.call_history[..end]
    }

    /// Gets call history for a specific contact or number.
    pub fn call_history_for(&self, remote_uri: &str) -> Vec<&CallHistoryEntry> {
        self.store
            .call_history
            .iter()
            .filter(|e| e.remote_uri == remote_uri)
            .collect()
    }

    /// Clears all call history.
    pub fn clear_call_history(&mut self) {
        self.dirty = true;
        self.store.call_history.clear();
    }

    /// Removes a specific call history entry by ID.
    pub fn remove_call_history(&mut self, entry_id: &str) -> bool {
        let initial_len = self.store.call_history.len();
        self.store.call_history.retain(|e| e.id != entry_id);
        let removed = self.store.call_history.len() < initial_len;
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Gets the total number of call history entries.
    pub fn call_history_count(&self) -> usize {
        self.store.call_history.len()
    }

    /// Sets the maximum number of call history entries to keep.
    pub fn set_max_history_entries(&mut self, max: usize) {
        self.max_history_entries = max;
        if self.store.call_history.len() > max {
            self.dirty = true;
            self.store.call_history.truncate(max);
        }
    }
}

/// Normalizes a phone number for comparison (removes non-digits).
fn normalize_number(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Creates a new contact with a generated ID.
pub fn create_contact(name: String, sip_uri: String, phone_numbers: Vec<PhoneNumber>) -> Contact {
    Contact {
        id: generate_contact_id(),
        name,
        sip_uri,
        phone_numbers,
        favorite: false,
        avatar_path: None,
        organization: None,
        notes: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use client_types::{CallDirection, CallEndReason, PhoneNumberType};
    use tempfile::tempdir;

    fn test_contact() -> Contact {
        Contact {
            id: "test-1".to_string(),
            name: "John Doe".to_string(),
            sip_uri: "sip:john@example.com".to_string(),
            phone_numbers: vec![PhoneNumber {
                number: "+1-555-1234".to_string(),
                number_type: PhoneNumberType::Work,
                label: None,
            }],
            favorite: false,
            avatar_path: None,
            organization: Some("Example Corp".to_string()),
            notes: None,
        }
    }

    fn test_history_entry() -> CallHistoryEntry {
        use chrono::Utc;

        CallHistoryEntry {
            id: "call-123".to_string(),
            remote_uri: "sip:bob@example.com".to_string(),
            remote_display_name: Some("Bob Smith".to_string()),
            direction: CallDirection::Outbound,
            start_time: Utc::now(),
            connect_time: Some(Utc::now()),
            end_time: Utc::now(),
            end_reason: CallEndReason::LocalHangup,
            duration_secs: Some(120),
        }
    }

    #[test]
    fn test_contact_manager_new() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");

        let manager = ContactManager::with_path(path).unwrap();
        assert_eq!(manager.contact_count(), 0);
        assert_eq!(manager.call_history_count(), 0);
    }

    #[test]
    fn test_contact_crud() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let mut manager = ContactManager::with_path(path).unwrap();

        // Create
        manager.set_contact(test_contact());
        assert_eq!(manager.contact_count(), 1);
        assert!(manager.is_dirty());

        // Read
        let contact = manager.get_contact("test-1").unwrap();
        assert_eq!(contact.name, "John Doe");

        // Update
        let mut updated = test_contact();
        updated.name = "Jane Doe".to_string();
        manager.set_contact(updated);
        assert_eq!(manager.get_contact("test-1").unwrap().name, "Jane Doe");

        // Delete
        let removed = manager.remove_contact("test-1");
        assert!(removed.is_some());
        assert_eq!(manager.contact_count(), 0);
    }

    #[test]
    fn test_contact_search() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let mut manager = ContactManager::with_path(path).unwrap();

        manager.set_contact(test_contact());

        // Search by name
        let results = manager.search_contacts("john");
        assert_eq!(results.len(), 1);

        // Search by number
        let results = manager.search_contacts("555");
        assert_eq!(results.len(), 1);

        // Search by SIP URI
        let results = manager.search_contacts("example.com");
        assert_eq!(results.len(), 1);

        // No match
        let results = manager.search_contacts("xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_call_history() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let mut manager = ContactManager::with_path(path).unwrap();

        // Add entries
        manager.add_call_history(test_history_entry());
        assert_eq!(manager.call_history_count(), 1);

        // Most recent first
        let mut entry2 = test_history_entry();
        entry2.id = "call-456".to_string();
        manager.add_call_history(entry2);

        assert_eq!(manager.call_history()[0].id, "call-456");

        // Remove by ID
        assert!(manager.remove_call_history("call-123"));
        assert_eq!(manager.call_history_count(), 1);

        // Clear all
        manager.clear_call_history();
        assert_eq!(manager.call_history_count(), 0);
    }

    #[test]
    fn test_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");

        // Save
        {
            let mut manager = ContactManager::with_path(path.clone()).unwrap();
            manager.set_contact(test_contact());
            manager.add_call_history(test_history_entry());
            manager.save().unwrap();
        }

        // Load
        {
            let manager = ContactManager::with_path(path).unwrap();
            assert_eq!(manager.contact_count(), 1);
            assert_eq!(manager.call_history_count(), 1);
        }
    }

    #[test]
    fn test_find_by_number() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let mut manager = ContactManager::with_path(path).unwrap();

        manager.set_contact(test_contact());

        // Find with different formats
        assert!(manager.find_by_number("5551234").is_some());
        assert!(manager.find_by_number("+1-555-1234").is_some());
        assert!(manager.find_by_number("9999999").is_none());
    }

    #[test]
    fn test_normalize_number() {
        assert_eq!(normalize_number("+1-555-1234"), "15551234");
        assert_eq!(normalize_number("(555) 123-4567"), "5551234567");
        assert_eq!(normalize_number("555.123.4567"), "5551234567");
    }
}
