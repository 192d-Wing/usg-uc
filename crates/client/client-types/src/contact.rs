//! Contact management types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Contact entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Unique identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Primary SIP URI.
    pub sip_uri: String,
    /// Additional phone numbers.
    pub phone_numbers: Vec<PhoneNumber>,
    /// Whether this is a favorite contact.
    pub favorite: bool,
    /// Path to avatar image (optional).
    pub avatar_path: Option<PathBuf>,
    /// Organization/company name.
    pub organization: Option<String>,
    /// Notes about the contact.
    pub notes: Option<String>,
}

impl Contact {
    /// Creates a new contact with required fields.
    pub fn new(id: impl Into<String>, name: impl Into<String>, sip_uri: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            sip_uri: sip_uri.into(),
            phone_numbers: Vec::new(),
            favorite: false,
            avatar_path: None,
            organization: None,
            notes: None,
        }
    }

    /// Adds a phone number to the contact.
    pub fn with_phone_number(mut self, number: PhoneNumber) -> Self {
        self.phone_numbers.push(number);
        self
    }

    /// Sets the contact as a favorite.
    pub fn with_favorite(mut self, favorite: bool) -> Self {
        self.favorite = favorite;
        self
    }

    /// Sets the organization.
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Returns the display label for the contact.
    pub fn display_label(&self) -> &str {
        &self.name
    }

    /// Returns initials for avatar placeholder.
    pub fn initials(&self) -> String {
        self.name
            .split_whitespace()
            .filter_map(|word| word.chars().next())
            .take(2)
            .collect::<String>()
            .to_uppercase()
    }
}

/// Phone number with type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneNumber {
    /// The phone number (E.164 format preferred).
    pub number: String,
    /// Type of phone number.
    pub number_type: PhoneNumberType,
    /// Label (custom type name).
    pub label: Option<String>,
}

impl PhoneNumber {
    /// Creates a new phone number.
    pub fn new(number: impl Into<String>, number_type: PhoneNumberType) -> Self {
        Self {
            number: number.into(),
            number_type,
            label: None,
        }
    }

    /// Creates a work phone number.
    pub fn work(number: impl Into<String>) -> Self {
        Self::new(number, PhoneNumberType::Work)
    }

    /// Creates a mobile phone number.
    pub fn mobile(number: impl Into<String>) -> Self {
        Self::new(number, PhoneNumberType::Mobile)
    }

    /// Creates a home phone number.
    pub fn home(number: impl Into<String>) -> Self {
        Self::new(number, PhoneNumberType::Home)
    }

    /// Sets a custom label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Returns the display type string.
    pub fn type_label(&self) -> &str {
        self.label
            .as_deref()
            .unwrap_or_else(|| match self.number_type {
                PhoneNumberType::Work => "Work",
                PhoneNumberType::Mobile => "Mobile",
                PhoneNumberType::Home => "Home",
                PhoneNumberType::Fax => "Fax",
                PhoneNumberType::Other => "Other",
            })
    }
}

/// Phone number type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PhoneNumberType {
    /// Work phone.
    #[default]
    Work,
    /// Mobile phone.
    Mobile,
    /// Home phone.
    Home,
    /// Fax number.
    Fax,
    /// Other type.
    Other,
}

impl std::fmt::Display for PhoneNumberType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Work => write!(f, "Work"),
            Self::Mobile => write!(f, "Mobile"),
            Self::Home => write!(f, "Home"),
            Self::Fax => write!(f, "Fax"),
            Self::Other => write!(f, "Other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_creation() {
        let contact = Contact::new("1", "John Doe", "sips:john@example.com")
            .with_phone_number(PhoneNumber::work("+1-555-1234"))
            .with_favorite(true)
            .with_organization("ACME Corp");

        assert_eq!(contact.name, "John Doe");
        assert!(contact.favorite);
        assert_eq!(contact.phone_numbers.len(), 1);
        assert_eq!(contact.organization, Some("ACME Corp".to_string()));
    }

    #[test]
    fn test_contact_initials() {
        let contact = Contact::new("1", "John Doe", "sips:john@example.com");
        assert_eq!(contact.initials(), "JD");

        let contact2 = Contact::new("2", "Alice", "sips:alice@example.com");
        assert_eq!(contact2.initials(), "A");

        let contact3 = Contact::new("3", "John Paul Smith", "sips:jps@example.com");
        assert_eq!(contact3.initials(), "JP");
    }

    #[test]
    fn test_phone_number_type_label() {
        let work = PhoneNumber::work("+1-555-1234");
        assert_eq!(work.type_label(), "Work");

        let custom = PhoneNumber::new("+1-555-5678", PhoneNumberType::Other).with_label("Desk");
        assert_eq!(custom.type_label(), "Desk");
    }
}
