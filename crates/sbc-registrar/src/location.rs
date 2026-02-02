//! Location service for endpoint discovery.
//!
//! The location service maintains a database of registered endpoints
//! and provides lookup functionality for call routing.

use crate::binding::{Binding, BindingState};
use crate::error::{RegistrarError, RegistrarResult};
use crate::MAX_CONTACTS_PER_AOR;
use std::collections::HashMap;

/// Location service.
///
/// Manages bindings for all registered AORs.
#[derive(Debug, Default)]
pub struct LocationService {
    /// Bindings organized by AOR.
    bindings: HashMap<String, Vec<Binding>>,
    /// Maximum contacts per AOR.
    max_contacts_per_aor: usize,
}

impl LocationService {
    /// Creates a new location service.
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            max_contacts_per_aor: MAX_CONTACTS_PER_AOR,
        }
    }

    /// Creates a location service with custom limits.
    pub fn with_max_contacts(max_contacts: usize) -> Self {
        Self {
            bindings: HashMap::new(),
            max_contacts_per_aor: max_contacts,
        }
    }

    /// Adds or updates a binding.
    pub fn add_binding(&mut self, binding: Binding) -> RegistrarResult<()> {
        let aor = binding.aor().to_string();
        let bindings = self.bindings.entry(aor).or_default();

        // Look for existing binding with same key
        let binding_key = binding.binding_key();
        if let Some(pos) = bindings.iter().position(|b| b.binding_key() == binding_key) {
            // Update existing binding
            bindings[pos] = binding;
        } else {
            // Check limit
            if bindings.len() >= self.max_contacts_per_aor {
                return Err(RegistrarError::TooManyContacts {
                    max: self.max_contacts_per_aor,
                });
            }
            bindings.push(binding);
        }

        Ok(())
    }

    /// Removes a binding.
    pub fn remove_binding(&mut self, aor: &str, contact_uri: &str) -> RegistrarResult<()> {
        let bindings = self
            .bindings
            .get_mut(aor)
            .ok_or_else(|| RegistrarError::AorNotFound { aor: aor.to_string() })?;

        let pos = bindings
            .iter()
            .position(|b| b.contact_uri() == contact_uri)
            .ok_or_else(|| RegistrarError::BindingNotFound {
                contact: contact_uri.to_string(),
            })?;

        bindings.remove(pos);

        // Remove AOR if no more bindings
        if bindings.is_empty() {
            self.bindings.remove(aor);
        }

        Ok(())
    }

    /// Removes all bindings for an AOR.
    pub fn remove_all_bindings(&mut self, aor: &str) -> RegistrarResult<usize> {
        let bindings = self
            .bindings
            .remove(aor)
            .ok_or_else(|| RegistrarError::AorNotFound { aor: aor.to_string() })?;

        Ok(bindings.len())
    }

    /// Looks up bindings for an AOR.
    ///
    /// Returns bindings sorted by q-value (highest first).
    pub fn lookup(&self, aor: &str) -> Vec<&Binding> {
        let mut result: Vec<&Binding> = self
            .bindings
            .get(aor)
            .map(|bindings| {
                bindings
                    .iter()
                    .filter(|b| b.state() == BindingState::Active && !b.is_expired())
                    .collect()
            })
            .unwrap_or_default();

        // Sort by q-value (highest first)
        result.sort_by(|a, b| {
            b.q_value()
                .partial_cmp(&a.q_value())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }

    /// Gets all bindings for an AOR (including expired).
    pub fn get_bindings(&self, aor: &str) -> Option<&[Binding]> {
        self.bindings.get(aor).map(|v| v.as_slice())
    }

    /// Gets a specific binding.
    pub fn get_binding(&self, aor: &str, contact_uri: &str) -> Option<&Binding> {
        self.bindings.get(aor).and_then(|bindings| {
            bindings.iter().find(|b| b.contact_uri() == contact_uri)
        })
    }

    /// Gets a mutable reference to a binding.
    pub fn get_binding_mut(&mut self, aor: &str, contact_uri: &str) -> Option<&mut Binding> {
        self.bindings.get_mut(aor).and_then(|bindings| {
            bindings.iter_mut().find(|b| b.contact_uri() == contact_uri)
        })
    }

    /// Checks if an AOR has any bindings.
    pub fn has_bindings(&self, aor: &str) -> bool {
        self.bindings
            .get(aor)
            .map(|bindings| !bindings.is_empty())
            .unwrap_or(false)
    }

    /// Returns the number of bindings for an AOR.
    pub fn binding_count(&self, aor: &str) -> usize {
        self.bindings.get(aor).map(|b| b.len()).unwrap_or(0)
    }

    /// Returns the total number of bindings.
    pub fn total_bindings(&self) -> usize {
        self.bindings.values().map(|b| b.len()).sum()
    }

    /// Returns the number of registered AORs.
    pub fn aor_count(&self) -> usize {
        self.bindings.len()
    }

    /// Returns all registered AORs.
    pub fn aors(&self) -> impl Iterator<Item = &str> {
        self.bindings.keys().map(|s| s.as_str())
    }

    /// Removes expired bindings.
    ///
    /// Returns the number of removed bindings.
    pub fn cleanup_expired(&mut self) -> usize {
        let mut removed = 0;
        let mut empty_aors = Vec::new();

        for (aor, bindings) in self.bindings.iter_mut() {
            let before = bindings.len();
            bindings.retain(|b| !b.is_expired());
            removed += before - bindings.len();

            if bindings.is_empty() {
                empty_aors.push(aor.clone());
            }
        }

        // Remove empty AORs
        for aor in empty_aors {
            self.bindings.remove(&aor);
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_binding(aor: &str, contact: &str) -> Binding {
        Binding::new(aor, contact, "call-123@client", 1)
    }

    #[test]
    fn test_location_service_creation() {
        let service = LocationService::new();
        assert_eq!(service.total_bindings(), 0);
        assert_eq!(service.aor_count(), 0);
    }

    #[test]
    fn test_add_binding() {
        let mut service = LocationService::new();
        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");

        service.add_binding(binding).unwrap();

        assert_eq!(service.total_bindings(), 1);
        assert_eq!(service.aor_count(), 1);
        assert!(service.has_bindings("sip:alice@example.com"));
    }

    #[test]
    fn test_multiple_bindings_per_aor() {
        let mut service = LocationService::new();

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");

        service.add_binding(binding1).unwrap();
        service.add_binding(binding2).unwrap();

        assert_eq!(service.binding_count("sip:alice@example.com"), 2);
    }

    #[test]
    fn test_update_binding() {
        let mut service = LocationService::new();

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding1).unwrap();

        // Add same contact again - should update, not add
        let mut binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        binding2.set_q_value(0.5);
        service.add_binding(binding2).unwrap();

        assert_eq!(service.binding_count("sip:alice@example.com"), 1);

        let binding = service
            .get_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .unwrap();
        assert!((binding.q_value() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_max_contacts_limit() {
        let mut service = LocationService::with_max_contacts(2);

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.1:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.2:5060");
        let binding3 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.3:5060");

        service.add_binding(binding1).unwrap();
        service.add_binding(binding2).unwrap();

        // Third binding should fail
        assert!(matches!(
            service.add_binding(binding3),
            Err(RegistrarError::TooManyContacts { max: 2 })
        ));
    }

    #[test]
    fn test_lookup() {
        let mut service = LocationService::new();

        let mut binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        binding1.set_q_value(0.5);

        let mut binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");
        binding2.set_q_value(1.0);

        service.add_binding(binding1).unwrap();
        service.add_binding(binding2).unwrap();

        let results = service.lookup("sip:alice@example.com");
        assert_eq!(results.len(), 2);

        // Higher q-value should be first
        assert!((results[0].q_value() - 1.0).abs() < f32::EPSILON);
        assert!((results[1].q_value() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_remove_binding() {
        let mut service = LocationService::new();

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).unwrap();

        service
            .remove_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .unwrap();

        assert_eq!(service.total_bindings(), 0);
        assert!(!service.has_bindings("sip:alice@example.com"));
    }

    #[test]
    fn test_remove_all_bindings() {
        let mut service = LocationService::new();

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");

        service.add_binding(binding1).unwrap();
        service.add_binding(binding2).unwrap();

        let removed = service.remove_all_bindings("sip:alice@example.com").unwrap();
        assert_eq!(removed, 2);
        assert!(!service.has_bindings("sip:alice@example.com"));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut service = LocationService::new();

        let mut binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");

        // Mark first binding as removed (expires = 0)
        binding1.remove();

        service.add_binding(binding1).unwrap();
        service.add_binding(binding2).unwrap();

        let removed = service.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(service.binding_count("sip:alice@example.com"), 1);
    }

    #[test]
    fn test_aors_iterator() {
        let mut service = LocationService::new();

        service
            .add_binding(test_binding(
                "sip:alice@example.com",
                "sip:alice@192.168.1.100:5060",
            ))
            .unwrap();
        service
            .add_binding(test_binding(
                "sip:bob@example.com",
                "sip:bob@192.168.1.200:5060",
            ))
            .unwrap();

        let aors: Vec<&str> = service.aors().collect();
        assert_eq!(aors.len(), 2);
        assert!(aors.contains(&"sip:alice@example.com"));
        assert!(aors.contains(&"sip:bob@example.com"));
    }

    #[test]
    fn test_get_binding_mut() {
        let mut service = LocationService::new();

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).unwrap();

        // Modify binding through mutable reference
        let binding = service
            .get_binding_mut("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .unwrap();
        binding.set_q_value(0.5);

        // Verify modification
        let binding = service
            .get_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .unwrap();
        assert!((binding.q_value() - 0.5).abs() < f32::EPSILON);
    }
}
