//! Async location service with pluggable storage backends.
//!
//! This module provides an async wrapper around `LocationService` that supports
//! external storage backends (Redis, PostgreSQL) via the `uc-storage` crate.
//!
//! ## Architecture
//!
//! Uses a cache-aside pattern:
//! 1. In-memory `LocationService` serves as a fast cache
//! 2. External storage (via `StorageManager`) provides persistence
//! 3. Writes update both cache and storage
//! 4. Reads check cache first, fall back to storage on miss
//!
//! ## Example
//!
//! ```ignore
//! use proto_registrar::{AsyncLocationService, Binding};
//! use uc_storage::{StorageConfig, StorageManager};
//! use std::sync::Arc;
//!
//! let config = StorageConfig::in_memory();
//! let storage = StorageManager::new(config).await?;
//! let location = AsyncLocationService::new(Arc::new(storage));
//!
//! let binding = Binding::new("sip:alice@example.com", "sip:alice@192.168.1.100", "call-123", 1);
//! location.add_binding(binding).await?;
//! ```

// Note: The #[cfg(feature = "storage")] is applied at the module level in lib.rs

// Allow significant_drop_tightening: The RwLock patterns here are intentional
// and provide clearer ownership semantics for the cache operations.
#![allow(clippy::significant_drop_tightening)]

use crate::MAX_CONTACTS_PER_AOR;
use crate::binding::{Binding, StorableBinding};
use crate::error::{RegistrarError, RegistrarResult};
use crate::location::LocationService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};
use uc_storage::StorageManager;

/// Key prefix for bindings in storage.
const BINDING_PREFIX: &str = "sip:binding:";

/// Default TTL buffer added to binding expires for storage.
const DEFAULT_TTL_BUFFER_SECS: u32 = 60;

/// Async location service with storage backend support.
///
/// Wraps the synchronous `LocationService` with an async interface and
/// optional persistence to external storage backends.
pub struct AsyncLocationService {
    /// In-memory cache (fast path).
    cache: RwLock<LocationService>,
    /// Storage backend for persistence.
    storage: Arc<StorageManager>,
    /// TTL buffer (adds extra time to storage TTL for safety).
    ttl_buffer_secs: u32,
    /// Maximum contacts per AOR.
    max_contacts_per_aor: usize,
}

impl AsyncLocationService {
    /// Creates a new async location service with the given storage backend.
    #[must_use]
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self {
            cache: RwLock::new(LocationService::new()),
            storage,
            ttl_buffer_secs: DEFAULT_TTL_BUFFER_SECS,
            max_contacts_per_aor: MAX_CONTACTS_PER_AOR,
        }
    }

    /// Creates a new async location service with custom max contacts per AOR.
    #[must_use]
    pub fn with_max_contacts(storage: Arc<StorageManager>, max_contacts: usize) -> Self {
        Self {
            cache: RwLock::new(LocationService::with_max_contacts(max_contacts)),
            storage,
            ttl_buffer_secs: DEFAULT_TTL_BUFFER_SECS,
            max_contacts_per_aor: max_contacts,
        }
    }

    /// Sets the TTL buffer for storage operations.
    ///
    /// The buffer is added to the binding's expires value when storing,
    /// to account for clock skew and ensure bindings don't expire prematurely
    /// in storage.
    #[must_use]
    pub const fn with_ttl_buffer(mut self, buffer_secs: u32) -> Self {
        self.ttl_buffer_secs = buffer_secs;
        self
    }

    /// Generates a storage key for a binding.
    fn storage_key(aor: &str, binding_key: &str) -> String {
        format!("{BINDING_PREFIX}{aor}:{binding_key}")
    }

    /// Generates a pattern for all bindings of an AOR.
    fn aor_pattern(aor: &str) -> String {
        format!("{BINDING_PREFIX}{aor}:*")
    }

    /// Adds or updates a binding.
    ///
    /// The binding is stored in both the in-memory cache and the external
    /// storage backend. The storage TTL is set to `expires + ttl_buffer`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The AOR has too many contacts
    /// - Storage operation fails
    /// - Serialization fails
    pub async fn add_binding(&self, binding: Binding) -> RegistrarResult<()> {
        let storable = StorableBinding::from_binding(&binding);
        let key = Self::storage_key(binding.aor(), &storable.binding_key());

        // Calculate TTL for storage (expires + buffer)
        let ttl = Duration::from_secs((binding.expires() + self.ttl_buffer_secs) as u64);

        // Serialize and store
        let json = serde_json::to_vec(&storable).map_err(|e| RegistrarError::Internal {
            message: format!("Serialization error: {e}"),
        })?;

        self.storage
            .set(&key, &json, Some(ttl))
            .await
            .map_err(|e| RegistrarError::Internal {
                message: format!("Storage error: {e}"),
            })?;

        trace!(
            aor = %binding.aor(),
            contact = %binding.contact_uri(),
            expires = binding.expires(),
            "Binding stored in backend"
        );

        // Update cache
        let mut cache = self.cache.write().await;
        cache.add_binding(binding)?;

        Ok(())
    }

    /// Removes a binding by contact URI.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The AOR or binding doesn't exist
    /// - Storage operation fails
    pub async fn remove_binding(&self, aor: &str, contact_uri: &str) -> RegistrarResult<()> {
        // First, get the binding key from cache to find the storage key
        let binding_key = {
            let cache = self.cache.read().await;
            cache
                .get_binding(aor, contact_uri)
                .map(Binding::binding_key)
                .ok_or_else(|| RegistrarError::BindingNotFound {
                    contact: contact_uri.to_string(),
                })?
        };

        let key = Self::storage_key(aor, &binding_key);

        // Remove from storage
        self.storage
            .delete(&key)
            .await
            .map_err(|e| RegistrarError::Internal {
                message: format!("Storage error: {e}"),
            })?;

        debug!(aor = %aor, contact = %contact_uri, "Binding removed from backend");

        // Update cache
        let mut cache = self.cache.write().await;
        cache.remove_binding(aor, contact_uri)
    }

    /// Removes a binding by its binding key (for RFC 5626 outbound).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The AOR or binding doesn't exist
    /// - Storage operation fails
    pub async fn remove_binding_by_key(&self, aor: &str, binding_key: &str) -> RegistrarResult<()> {
        let key = Self::storage_key(aor, binding_key);

        // Remove from storage
        self.storage
            .delete(&key)
            .await
            .map_err(|e| RegistrarError::Internal {
                message: format!("Storage error: {e}"),
            })?;

        debug!(aor = %aor, binding_key = %binding_key, "Binding removed from backend by key");

        // Update cache
        let mut cache = self.cache.write().await;
        cache.remove_binding_by_key(aor, binding_key)
    }

    /// Removes all bindings for an AOR.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage operation fails
    pub async fn remove_all_bindings(&self, aor: &str) -> RegistrarResult<usize> {
        let pattern = Self::aor_pattern(aor);

        // Get all keys matching the pattern
        let keys = self
            .storage
            .keys(&pattern)
            .await
            .map_err(|e| RegistrarError::Internal {
                message: format!("Storage error: {e}"),
            })?;

        let count = keys.len();

        // Delete all matching keys
        for key in keys {
            if let Err(e) = self.storage.delete(&key).await {
                warn!(key = %key, error = %e, "Failed to delete binding from storage");
            }
        }

        debug!(aor = %aor, count = count, "All bindings removed from backend");

        // Update cache
        let mut cache = self.cache.write().await;
        let _ = cache.remove_all_bindings(aor);

        Ok(count)
    }

    /// Looks up bindings for an AOR.
    ///
    /// Uses cache-first lookup: checks the in-memory cache first,
    /// falls back to storage on cache miss.
    ///
    /// Returns bindings sorted by q-value (highest first).
    pub async fn lookup(&self, aor: &str) -> Vec<Binding> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            let cached = cache.lookup(aor);
            if !cached.is_empty() {
                trace!(aor = %aor, count = cached.len(), "Cache hit");
                return cached.into_iter().cloned().collect();
            }
        }

        // Cache miss - load from storage
        trace!(aor = %aor, "Cache miss, loading from storage");
        match self.load_from_storage(aor).await {
            Ok(bindings) => {
                // Populate cache
                if !bindings.is_empty() {
                    let mut cache = self.cache.write().await;
                    for binding in &bindings {
                        let _ = cache.add_binding(binding.clone());
                    }
                }
                bindings
            }
            Err(e) => {
                warn!(aor = %aor, error = %e, "Failed to load bindings from storage");
                Vec::new()
            }
        }
    }

    /// Loads bindings from storage backend.
    async fn load_from_storage(&self, aor: &str) -> RegistrarResult<Vec<Binding>> {
        let pattern = Self::aor_pattern(aor);

        let keys = self
            .storage
            .keys(&pattern)
            .await
            .map_err(|e| RegistrarError::Internal {
                message: format!("Storage error: {e}"),
            })?;

        let mut bindings = Vec::new();
        for key in keys {
            if let Some(data) =
                self.storage
                    .get(&key)
                    .await
                    .map_err(|e| RegistrarError::Internal {
                        message: format!("Storage error: {e}"),
                    })?
            {
                match serde_json::from_slice::<StorableBinding>(&data) {
                    Ok(storable) => {
                        if !storable.is_expired() {
                            bindings.push(storable.to_binding());
                        }
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "Failed to deserialize binding");
                    }
                }
            }
        }

        // Sort by q-value (highest first)
        bindings.sort_by(|a, b| {
            b.q_value()
                .partial_cmp(&a.q_value())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(bindings)
    }

    /// Gets a specific binding.
    ///
    /// Uses cache-first lookup.
    pub async fn get_binding(&self, aor: &str, contact_uri: &str) -> Option<Binding> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            if let Some(binding) = cache.get_binding(aor, contact_uri) {
                return Some(binding.clone());
            }
        }

        // Try to load all bindings for this AOR from storage
        if let Ok(bindings) = self.load_from_storage(aor).await {
            // Populate cache
            let mut cache = self.cache.write().await;
            for binding in &bindings {
                let _ = cache.add_binding(binding.clone());
            }
            drop(cache);

            // Find the specific binding
            bindings
                .into_iter()
                .find(|b| b.contact_uri() == contact_uri)
        } else {
            None
        }
    }

    /// Gets all bindings for a specific instance-id (RFC 5626).
    ///
    /// Returns bindings sorted by reg-id.
    pub async fn get_bindings_by_instance(&self, aor: &str, instance_id: &str) -> Vec<Binding> {
        // Ensure cache is populated
        let _ = self.lookup(aor).await;

        // Now query from cache
        let cache = self.cache.read().await;
        cache
            .get_bindings_by_instance(aor, instance_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Checks if an AOR has any bindings.
    pub async fn has_bindings(&self, aor: &str) -> bool {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if cache.has_bindings(aor) {
                return true;
            }
        }

        // Check storage
        let pattern = Self::aor_pattern(aor);
        self.storage
            .keys(&pattern)
            .await
            .is_ok_and(|keys| !keys.is_empty())
    }

    /// Returns the number of bindings for an AOR.
    pub async fn binding_count(&self, aor: &str) -> usize {
        // Ensure cache is populated
        let _ = self.lookup(aor).await;

        let cache = self.cache.read().await;
        cache.binding_count(aor)
    }

    /// Returns the total number of bindings in the cache.
    pub async fn total_bindings(&self) -> usize {
        self.cache.read().await.total_bindings()
    }

    /// Returns the number of registered AORs in the cache.
    pub async fn aor_count(&self) -> usize {
        self.cache.read().await.aor_count()
    }

    /// Synchronizes the cache by cleaning up expired bindings.
    ///
    /// Returns the number of bindings removed from the cache.
    pub async fn sync_cache(&self) -> usize {
        let mut cache = self.cache.write().await;
        cache.cleanup_expired()
    }

    /// Clears the in-memory cache without affecting storage.
    ///
    /// Useful for forcing a reload from storage.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = LocationService::with_max_contacts(self.max_contacts_per_aor);
    }

    /// Checks if the storage backend is healthy.
    pub async fn health_check(&self) -> bool {
        self.storage.health_check().await
    }

    /// Returns statistics about the location service.
    #[must_use]
    pub async fn stats(&self) -> AsyncLocationStats {
        let cache = self.cache.read().await;
        AsyncLocationStats {
            cached_bindings: cache.total_bindings(),
            cached_aors: cache.aor_count(),
            storage_healthy: self.storage.health_check().await,
        }
    }
}

/// Statistics about the async location service.
#[derive(Debug, Clone)]
pub struct AsyncLocationStats {
    /// Number of bindings in cache.
    pub cached_bindings: usize,
    /// Number of AORs in cache.
    pub cached_aors: usize,
    /// Whether storage backend is healthy.
    pub storage_healthy: bool,
}

impl std::fmt::Debug for AsyncLocationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncLocationService")
            .field("ttl_buffer_secs", &self.ttl_buffer_secs)
            .field("max_contacts_per_aor", &self.max_contacts_per_aor)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use uc_storage::StorageConfig;

    async fn test_service() -> AsyncLocationService {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();
        AsyncLocationService::new(Arc::new(storage))
    }

    fn test_binding(aor: &str, contact: &str) -> Binding {
        Binding::new(aor, contact, "call-123@client", 1)
    }

    #[tokio::test]
    async fn test_add_and_lookup() {
        let service = test_service().await;

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).await.unwrap();

        let results = service.lookup("sip:alice@example.com").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].contact_uri(), "sip:alice@192.168.1.100:5060");
    }

    #[tokio::test]
    async fn test_multiple_bindings() {
        let service = test_service().await;

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");

        service.add_binding(binding1).await.unwrap();
        service.add_binding(binding2).await.unwrap();

        assert_eq!(service.binding_count("sip:alice@example.com").await, 2);
    }

    #[tokio::test]
    async fn test_remove_binding() {
        let service = test_service().await;

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).await.unwrap();

        service
            .remove_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .await
            .unwrap();

        assert!(!service.has_bindings("sip:alice@example.com").await);
    }

    #[tokio::test]
    async fn test_remove_all_bindings() {
        let service = test_service().await;

        let binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        let binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");

        service.add_binding(binding1).await.unwrap();
        service.add_binding(binding2).await.unwrap();

        let removed = service
            .remove_all_bindings("sip:alice@example.com")
            .await
            .unwrap();
        assert_eq!(removed, 2);
        assert!(!service.has_bindings("sip:alice@example.com").await);
    }

    #[tokio::test]
    async fn test_cache_miss_loads_from_storage() {
        let service = test_service().await;

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).await.unwrap();

        // Clear cache
        service.clear_cache().await;
        assert_eq!(service.total_bindings().await, 0);

        // Lookup should reload from storage
        let results = service.lookup("sip:alice@example.com").await;
        assert_eq!(results.len(), 1);
        assert_eq!(service.total_bindings().await, 1);
    }

    #[tokio::test]
    async fn test_get_binding() {
        let service = test_service().await;

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).await.unwrap();

        let result = service
            .get_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060")
            .await;
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().contact_uri(),
            "sip:alice@192.168.1.100:5060"
        );

        // Non-existent binding
        let result = service
            .get_binding("sip:alice@example.com", "sip:nonexistent@example.com")
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_q_value_ordering() {
        let service = test_service().await;

        let mut binding1 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        binding1.set_q_value(0.5);

        let mut binding2 = test_binding("sip:alice@example.com", "sip:alice@192.168.1.200:5060");
        binding2.set_q_value(1.0);

        service.add_binding(binding1).await.unwrap();
        service.add_binding(binding2).await.unwrap();

        let results = service.lookup("sip:alice@example.com").await;
        assert_eq!(results.len(), 2);
        // Higher q-value should be first
        assert!((results[0].q_value() - 1.0).abs() < f32::EPSILON);
        assert!((results[1].q_value() - 0.5).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_outbound_binding() {
        let service = test_service().await;

        let mut binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        binding.set_instance_id("<urn:uuid:test-123>");
        binding.set_reg_id(1);

        service.add_binding(binding).await.unwrap();

        let results = service
            .get_bindings_by_instance("sip:alice@example.com", "<urn:uuid:test-123>")
            .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].reg_id(), Some(1));
    }

    #[tokio::test]
    async fn test_stats() {
        let service = test_service().await;

        let binding = test_binding("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        service.add_binding(binding).await.unwrap();

        let stats = service.stats().await;
        assert_eq!(stats.cached_bindings, 1);
        assert_eq!(stats.cached_aors, 1);
        assert!(stats.storage_healthy);
    }

    #[tokio::test]
    async fn test_health_check() {
        let service = test_service().await;
        assert!(service.health_check().await);
    }
}
