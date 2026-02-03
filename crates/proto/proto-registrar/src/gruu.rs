//! GRUU (Globally Routable UA URI) support per RFC 5627.
//!
//! GRUUs allow a request to be routed to a specific UA instance,
//! ensuring that the request reaches a particular device even if
//! the user is registered from multiple locations.
//!
//! ## Types of GRUUs
//!
//! - **Public GRUU (pub-gruu)**: Can be safely shared with other parties
//! - **Temporary GRUU (temp-gruu)**: Hides the AOR for privacy
//!
//! ## Proxy GRUU Routing (RFC 5627 §5.1)
//!
//! When a proxy receives a request with a GRUU in the Request-URI,
//! it must route the request to the specific UA instance identified
//! by the GRUU. The `GruuRouter` provides this functionality.

use crate::binding::Binding;
use crate::error::{RegistrarError, RegistrarResult};
use crate::location::LocationService;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// GRUU generator trait.
///
/// Allows pluggable GRUU generation strategies.
pub trait GruuGenerator {
    /// Generates a public GRUU for the given AOR and instance-id.
    fn generate_pub_gruu(&self, aor: &str, instance_id: &str) -> String;

    /// Generates a temporary GRUU for the given AOR and instance-id.
    fn generate_temp_gruu(&self, aor: &str, instance_id: &str) -> String;

    /// Extracts the AOR from a GRUU (if possible).
    fn extract_aor(&self, gruu: &str) -> Option<String>;

    /// Extracts the instance-id from a GRUU (if possible).
    fn extract_instance_id(&self, gruu: &str) -> Option<String>;
}

/// GRUU entry stored for a binding.
#[derive(Debug, Clone)]
pub struct GruuEntry {
    /// The public GRUU.
    pub_gruu: String,
    /// The temporary GRUU.
    temp_gruu: String,
    /// Associated AOR.
    aor: String,
    /// Associated instance-id.
    instance_id: String,
    /// When this entry was created.
    created_at: Instant,
    /// When the temp-gruu expires (should match registration expiry).
    expires_at: Instant,
}

impl GruuEntry {
    /// Creates a new GRUU entry.
    pub fn new(
        pub_gruu: impl Into<String>,
        temp_gruu: impl Into<String>,
        aor: impl Into<String>,
        instance_id: impl Into<String>,
        expires: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            pub_gruu: pub_gruu.into(),
            temp_gruu: temp_gruu.into(),
            aor: aor.into(),
            instance_id: instance_id.into(),
            created_at: now,
            expires_at: now + expires,
        }
    }

    /// Returns the public GRUU.
    pub fn pub_gruu(&self) -> &str {
        &self.pub_gruu
    }

    /// Returns the temporary GRUU.
    pub fn temp_gruu(&self) -> &str {
        &self.temp_gruu
    }

    /// Returns the AOR.
    pub fn aor(&self) -> &str {
        &self.aor
    }

    /// Returns the instance-id.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Checks if the GRUU entry is expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Refreshes the expiration.
    pub fn refresh(&mut self, expires: Duration) {
        self.expires_at = Instant::now() + expires;
    }

    /// Returns when this entry was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }
}

/// GRUU service for managing GRUUs.
///
/// The service maintains a mapping from GRUUs to bindings and
/// generates new GRUUs when registrations include instance-ids.
#[derive(Debug)]
pub struct GruuService {
    /// Mapping from pub-gruu to entry.
    pub_gruu_map: HashMap<String, GruuEntry>,
    /// Mapping from temp-gruu to entry.
    temp_gruu_map: HashMap<String, GruuEntry>,
    /// Mapping from (AOR, instance-id) to entry.
    binding_map: HashMap<(String, String), GruuEntry>,
    /// Domain for GRUU generation.
    domain: String,
}

impl GruuService {
    /// Creates a new GRUU service.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            pub_gruu_map: HashMap::new(),
            temp_gruu_map: HashMap::new(),
            binding_map: HashMap::new(),
            domain: domain.into(),
        }
    }

    /// Creates or updates a GRUU for a registration.
    ///
    /// Returns the GRUU entry.
    pub fn create_or_update_gruu(
        &mut self,
        aor: &str,
        instance_id: &str,
        expires: Duration,
    ) -> RegistrarResult<&GruuEntry> {
        let key = (aor.to_string(), instance_id.to_string());

        // Check if we already have a GRUU for this binding
        if self.binding_map.contains_key(&key) {
            // Generate new temp-gruu first (before mutable borrow)
            let new_temp_gruu = self.generate_temp_gruu(aor, instance_id);

            // Now get mutable access and update
            let entry =
                self.binding_map
                    .get_mut(&key)
                    .ok_or_else(|| RegistrarError::BindingNotFound {
                        contact: instance_id.to_string(),
                    })?;

            // Remove old temp-gruu mapping
            let old_temp_gruu = entry.temp_gruu.clone();
            self.temp_gruu_map.remove(&old_temp_gruu);

            // Update entry
            entry.refresh(expires);
            entry.temp_gruu = new_temp_gruu.clone();

            // Add new temp-gruu mapping
            let updated_entry = entry.clone();
            self.temp_gruu_map.insert(new_temp_gruu, updated_entry);

            return self
                .binding_map
                .get(&key)
                .ok_or_else(|| RegistrarError::BindingNotFound {
                    contact: instance_id.to_string(),
                });
        }

        // Generate new GRUUs
        let pub_gruu = self.generate_pub_gruu(aor, instance_id);
        let temp_gruu = self.generate_temp_gruu(aor, instance_id);

        let entry = GruuEntry::new(&pub_gruu, &temp_gruu, aor, instance_id, expires);

        // Store in all maps
        self.pub_gruu_map.insert(pub_gruu, entry.clone());
        self.temp_gruu_map.insert(temp_gruu, entry.clone());
        self.binding_map.insert(key.clone(), entry);

        self.binding_map
            .get(&key)
            .ok_or_else(|| RegistrarError::BindingNotFound {
                contact: instance_id.to_string(),
            })
    }

    /// Looks up a GRUU (either public or temporary).
    ///
    /// Returns the associated (AOR, instance-id) if found.
    pub fn lookup_gruu(&self, gruu: &str) -> Option<(&str, &str)> {
        // Try public GRUU first
        if let Some(entry) = self.pub_gruu_map.get(gruu) {
            if !entry.is_expired() {
                return Some((entry.aor(), entry.instance_id()));
            }
        }

        // Try temporary GRUU
        if let Some(entry) = self.temp_gruu_map.get(gruu) {
            if !entry.is_expired() {
                return Some((entry.aor(), entry.instance_id()));
            }
        }

        None
    }

    /// Gets the GRUU entry for a binding.
    pub fn get_gruu_for_binding(&self, aor: &str, instance_id: &str) -> Option<&GruuEntry> {
        let key = (aor.to_string(), instance_id.to_string());
        self.binding_map.get(&key).filter(|e| !e.is_expired())
    }

    /// Removes a GRUU for a binding.
    pub fn remove_gruu(&mut self, aor: &str, instance_id: &str) -> bool {
        let key = (aor.to_string(), instance_id.to_string());

        if let Some(entry) = self.binding_map.remove(&key) {
            self.pub_gruu_map.remove(&entry.pub_gruu);
            self.temp_gruu_map.remove(&entry.temp_gruu);
            true
        } else {
            false
        }
    }

    /// Removes all GRUUs for an AOR.
    pub fn remove_all_gruus(&mut self, aor: &str) -> usize {
        let keys_to_remove: Vec<_> = self
            .binding_map
            .keys()
            .filter(|(a, _)| a == aor)
            .cloned()
            .collect();

        let count = keys_to_remove.len();

        for key in keys_to_remove {
            if let Some(entry) = self.binding_map.remove(&key) {
                self.pub_gruu_map.remove(&entry.pub_gruu);
                self.temp_gruu_map.remove(&entry.temp_gruu);
            }
        }

        count
    }

    /// Cleans up expired GRUU entries.
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_keys: Vec<_> = self
            .binding_map
            .iter()
            .filter(|(_, v)| v.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired_keys.len();

        for key in expired_keys {
            if let Some(entry) = self.binding_map.remove(&key) {
                self.pub_gruu_map.remove(&entry.pub_gruu);
                self.temp_gruu_map.remove(&entry.temp_gruu);
            }
        }

        count
    }

    /// Returns the domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Generates a public GRUU.
    ///
    /// Per RFC 5627, the public GRUU should be stable across registrations
    /// and should allow determination of the AOR (for logging/billing).
    ///
    /// Format: `sip:<user>@<domain>;gr=<instance-id-hash>`
    fn generate_pub_gruu(&self, aor: &str, instance_id: &str) -> String {
        // Extract user part from AOR
        let user = extract_user_from_aor(aor).unwrap_or("unknown");

        // Hash the instance-id for the gr parameter
        let instance_hash = simple_hash(instance_id);

        format!("sip:{}@{};gr={}", user, self.domain, instance_hash)
    }

    /// Generates a temporary GRUU.
    ///
    /// Per RFC 5627, the temporary GRUU should not reveal the AOR
    /// and should change with each registration.
    ///
    /// Format: `sip:<random>@<domain>;gr`
    fn generate_temp_gruu(&self, _aor: &str, instance_id: &str) -> String {
        // Generate a random-looking identifier that encodes the instance
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let random_part = simple_hash(&format!("{}{}", instance_id, timestamp));

        format!("sip:{}@{};gr", random_part, self.domain)
    }
}

/// Extracts the user part from a SIP AOR.
fn extract_user_from_aor(aor: &str) -> Option<&str> {
    let aor = aor
        .strip_prefix("sip:")
        .or_else(|| aor.strip_prefix("sips:"))?;
    aor.split('@').next()
}

/// Simple hash function for generating GRUU components.
/// In production, use a proper cryptographic hash.
fn simple_hash(input: &str) -> String {
    let mut hash: u64 = 0x811c9dc5;
    for byte in input.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x01000193);
    }
    format!("{:016x}", hash)
}

/// Parses the "gr" parameter from a GRUU URI.
pub fn parse_gr_parameter(uri: &str) -> Option<String> {
    // Look for ;gr= or ;gr at the end
    if let Some(pos) = uri.find(";gr=") {
        let rest = &uri[pos + 4..];
        // Extract until next ; or end
        let value = rest.split(';').next()?;
        return Some(value.to_string());
    }

    // Check for just ;gr (temporary GRUU marker)
    if uri.contains(";gr") {
        return Some(String::new());
    }

    None
}

/// Checks if a URI is a GRUU.
pub fn is_gruu(uri: &str) -> bool {
    uri.contains(";gr")
}

/// Result of GRUU routing per RFC 5627 §5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GruuRoutingResult {
    /// Successfully resolved to a routing target.
    Resolved {
        /// The contact URI to route to.
        contact_uri: String,
        /// The AOR associated with this GRUU.
        aor: String,
        /// The instance-id of the target UA.
        instance_id: String,
        /// Optional Path headers to prepend to Route (RFC 3327).
        path: Vec<String>,
    },
    /// The GRUU is valid but the registration has expired.
    RegistrationExpired {
        /// The AOR associated with this GRUU.
        aor: String,
        /// The instance-id of the target UA.
        instance_id: String,
    },
    /// The GRUU was not found (invalid or never registered).
    NotFound,
    /// The URI is not a GRUU.
    NotAGruu,
}

/// GRUU Router per RFC 5627 §5.1.
///
/// The router is responsible for resolving GRUU URIs to routing targets.
/// When a proxy receives a request with a GRUU in the Request-URI, it uses
/// this router to determine where to forward the request.
///
/// ## RFC 5627 §5.1 Requirements
///
/// - The proxy MUST locate the binding for the GRUU
/// - If the binding exists, route to that specific contact
/// - If multiple flows exist for the instance, use the one with lowest reg-id
/// - If no binding exists, return 480 Temporarily Unavailable
/// - Path headers from registration MUST be included in routing
#[derive(Debug)]
pub struct GruuRouter<'a> {
    /// Reference to the GRUU service.
    gruu_service: &'a GruuService,
    /// Reference to the location service.
    location_service: &'a LocationService,
}

impl<'a> GruuRouter<'a> {
    /// Creates a new GRUU router.
    pub fn new(gruu_service: &'a GruuService, location_service: &'a LocationService) -> Self {
        Self {
            gruu_service,
            location_service,
        }
    }

    /// Routes a request based on a GRUU URI.
    ///
    /// Per RFC 5627 §5.1, when a proxy receives a request where the
    /// Request-URI contains a GRUU, it:
    ///
    /// 1. Extracts the AOR and instance-id from the GRUU
    /// 2. Looks up the binding for that instance-id
    /// 3. If found, returns the contact URI and path
    /// 4. If not found or expired, returns appropriate status
    ///
    /// # Arguments
    ///
    /// * `gruu_uri` - The GRUU URI from the Request-URI
    ///
    /// # Returns
    ///
    /// A `GruuRoutingResult` indicating the routing decision.
    pub fn route(&self, gruu_uri: &str) -> GruuRoutingResult {
        // Check if this is actually a GRUU
        if !is_gruu(gruu_uri) {
            return GruuRoutingResult::NotAGruu;
        }

        // Look up the GRUU to get AOR and instance-id
        let (aor, instance_id) = match self.gruu_service.lookup_gruu(gruu_uri) {
            Some((aor, instance_id)) => (aor.to_string(), instance_id.to_string()),
            None => return GruuRoutingResult::NotFound,
        };

        // Find bindings for this AOR and instance-id
        // Per RFC 5627 §5.1, if multiple flows exist, use lowest reg-id
        let bindings = self
            .location_service
            .get_bindings_by_instance(&aor, &instance_id);

        // Filter to active, non-expired bindings and find lowest reg-id
        let active_binding = bindings
            .into_iter()
            .filter(|b| !b.is_expired())
            .min_by_key(|b| b.reg_id().unwrap_or(u32::MAX));

        match active_binding {
            Some(binding) => GruuRoutingResult::Resolved {
                contact_uri: binding.contact_uri().to_string(),
                aor,
                instance_id,
                path: binding.path().to_vec(),
            },
            None => GruuRoutingResult::RegistrationExpired { aor, instance_id },
        }
    }

    /// Routes a request and returns the binding if found.
    ///
    /// This is useful when you need the full binding information,
    /// not just the routing result.
    pub fn route_to_binding(&self, gruu_uri: &str) -> Option<&'a Binding> {
        if !is_gruu(gruu_uri) {
            return None;
        }

        let (aor, instance_id) = self.gruu_service.lookup_gruu(gruu_uri)?;

        // Find bindings for this instance
        let bindings = self
            .location_service
            .get_bindings_by_instance(aor, instance_id);

        // Return first active binding with lowest reg-id
        bindings
            .into_iter()
            .filter(|b| !b.is_expired())
            .min_by_key(|b| b.reg_id().unwrap_or(u32::MAX))
    }

    /// Checks if a GRUU is valid and has an active registration.
    pub fn is_gruu_active(&self, gruu_uri: &str) -> bool {
        matches!(self.route(gruu_uri), GruuRoutingResult::Resolved { .. })
    }

    /// Gets the AOR for a GRUU without full routing.
    ///
    /// Useful for authorization checks where you need to know
    /// the identity but don't need the routing target.
    pub fn get_aor_for_gruu(&self, gruu_uri: &str) -> Option<String> {
        if !is_gruu(gruu_uri) {
            return None;
        }

        self.gruu_service
            .lookup_gruu(gruu_uri)
            .map(|(aor, _)| aor.to_string())
    }
}

/// Extracts GRUU routing information from a Request-URI.
///
/// This is a standalone function for quick GRUU detection and parsing
/// without requiring full service access.
///
/// # Returns
///
/// - `Some((gr_value, is_temp))` if the URI is a GRUU
///   - `gr_value` is the value of the gr parameter (empty for temp-gruu)
///   - `is_temp` is true if this is a temporary GRUU
/// - `None` if the URI is not a GRUU
pub fn extract_gruu_info(uri: &str) -> Option<(String, bool)> {
    if !is_gruu(uri) {
        return None;
    }

    // Check for public GRUU (;gr=value)
    if let Some(gr_value) = parse_gr_parameter(uri) {
        if gr_value.is_empty() {
            // Temporary GRUU: ;gr (no value)
            Some((String::new(), true))
        } else {
            // Public GRUU: ;gr=value
            Some((gr_value, false))
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gruu_entry_creation() {
        let entry = GruuEntry::new(
            "sip:alice@example.com;gr=abc123",
            "sip:xyz789@example.com;gr",
            "sip:alice@example.com",
            "<urn:uuid:test-instance>",
            Duration::from_secs(3600),
        );

        assert_eq!(entry.pub_gruu(), "sip:alice@example.com;gr=abc123");
        assert_eq!(entry.temp_gruu(), "sip:xyz789@example.com;gr");
        assert_eq!(entry.aor(), "sip:alice@example.com");
        assert_eq!(entry.instance_id(), "<urn:uuid:test-instance>");
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_gruu_service_creation() {
        let service = GruuService::new("example.com");
        assert_eq!(service.domain(), "example.com");
    }

    #[test]
    fn test_create_gruu() {
        let mut service = GruuService::new("example.com");

        let entry = service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        assert!(entry.pub_gruu().contains("example.com"));
        assert!(entry.pub_gruu().contains(";gr="));
        assert!(entry.temp_gruu().contains(";gr"));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_lookup_gruu() {
        let mut service = GruuService::new("example.com");

        let entry = service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        let pub_gruu = entry.pub_gruu().to_string();
        let temp_gruu = entry.temp_gruu().to_string();

        // Lookup by pub-gruu
        let (aor, instance_id) = service.lookup_gruu(&pub_gruu).unwrap();
        assert_eq!(aor, "sip:alice@example.com");
        assert_eq!(instance_id, "<urn:uuid:test-instance>");

        // Lookup by temp-gruu
        let (aor, instance_id) = service.lookup_gruu(&temp_gruu).unwrap();
        assert_eq!(aor, "sip:alice@example.com");
        assert_eq!(instance_id, "<urn:uuid:test-instance>");
    }

    #[test]
    fn test_get_gruu_for_binding() {
        let mut service = GruuService::new("example.com");

        service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        let entry = service
            .get_gruu_for_binding("sip:alice@example.com", "<urn:uuid:test-instance>")
            .unwrap();

        assert!(entry.pub_gruu().contains("alice"));
    }

    #[test]
    fn test_remove_gruu() {
        let mut service = GruuService::new("example.com");

        service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        assert!(service.remove_gruu("sip:alice@example.com", "<urn:uuid:test-instance>"));
        assert!(
            service
                .get_gruu_for_binding("sip:alice@example.com", "<urn:uuid:test-instance>")
                .is_none()
        );
    }

    #[test]
    fn test_remove_all_gruus() {
        let mut service = GruuService::new("example.com");

        service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:instance-1>",
                Duration::from_secs(3600),
            )
            .unwrap();
        service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:instance-2>",
                Duration::from_secs(3600),
            )
            .unwrap();
        service
            .create_or_update_gruu(
                "sip:bob@example.com",
                "<urn:uuid:instance-3>",
                Duration::from_secs(3600),
            )
            .unwrap();

        let removed = service.remove_all_gruus("sip:alice@example.com");
        assert_eq!(removed, 2);

        assert!(
            service
                .get_gruu_for_binding("sip:bob@example.com", "<urn:uuid:instance-3>")
                .is_some()
        );
    }

    #[test]
    fn test_parse_gr_parameter() {
        assert_eq!(
            parse_gr_parameter("sip:alice@example.com;gr=abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            parse_gr_parameter("sip:xyz@example.com;gr"),
            Some(String::new())
        );
        assert_eq!(parse_gr_parameter("sip:alice@example.com"), None);
    }

    #[test]
    fn test_is_gruu() {
        assert!(is_gruu("sip:alice@example.com;gr=abc123"));
        assert!(is_gruu("sip:xyz@example.com;gr"));
        assert!(!is_gruu("sip:alice@example.com"));
    }

    #[test]
    fn test_extract_user_from_aor() {
        assert_eq!(
            extract_user_from_aor("sip:alice@example.com"),
            Some("alice")
        );
        assert_eq!(extract_user_from_aor("sips:bob@test.com"), Some("bob"));
        assert_eq!(extract_user_from_aor("invalid"), None);
    }

    #[test]
    fn test_gruu_update_regenerates_temp() {
        let mut service = GruuService::new("example.com");

        let entry1 = service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        let pub_gruu1 = entry1.pub_gruu().to_string();
        let temp_gruu1 = entry1.temp_gruu().to_string();

        // Small delay to ensure different timestamp
        std::thread::sleep(Duration::from_millis(10));

        let entry2 = service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();

        // Public GRUU should remain stable
        assert_eq!(entry2.pub_gruu(), pub_gruu1);

        // Temporary GRUU should change
        assert_ne!(entry2.temp_gruu(), temp_gruu1);
    }

    // ========================================================================
    // RFC 5627 §5.1 Proxy GRUU Routing Tests
    // ========================================================================

    #[test]
    fn test_gruu_router_route_not_a_gruu() {
        let gruu_service = GruuService::new("example.com");
        let location_service = LocationService::new();
        let router = GruuRouter::new(&gruu_service, &location_service);

        // Non-GRUU URI
        let result = router.route("sip:alice@example.com");
        assert_eq!(result, GruuRoutingResult::NotAGruu);
    }

    #[test]
    fn test_gruu_router_route_not_found() {
        let gruu_service = GruuService::new("example.com");
        let location_service = LocationService::new();
        let router = GruuRouter::new(&gruu_service, &location_service);

        // Unknown GRUU
        let result = router.route("sip:unknown@example.com;gr=abc123");
        assert_eq!(result, GruuRoutingResult::NotFound);
    }

    #[test]
    fn test_gruu_router_route_success() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        // Create a binding with matching instance-id
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        location_service.add_binding(binding).unwrap();

        // Route using the GRUU
        let router = GruuRouter::new(&gruu_service, &location_service);
        let result = router.route(&pub_gruu);

        match result {
            GruuRoutingResult::Resolved {
                contact_uri,
                aor,
                instance_id,
                ..
            } => {
                assert_eq!(contact_uri, "sip:alice@192.168.1.100:5060");
                assert_eq!(aor, "sip:alice@example.com");
                assert_eq!(instance_id, "<urn:uuid:test-instance>");
            }
            _ => panic!("Expected Resolved, got {:?}", result),
        }
    }

    #[test]
    fn test_gruu_router_route_with_path() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        // Create a binding with path headers
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        binding.set_path(vec![
            "<sip:edge.example.com;lr>".to_string(),
            "<sip:proxy.example.com;lr>".to_string(),
        ]);
        location_service.add_binding(binding).unwrap();

        // Route using the GRUU
        let router = GruuRouter::new(&gruu_service, &location_service);
        let result = router.route(&pub_gruu);

        match result {
            GruuRoutingResult::Resolved { path, .. } => {
                assert_eq!(path.len(), 2);
                assert_eq!(path[0], "<sip:edge.example.com;lr>");
                assert_eq!(path[1], "<sip:proxy.example.com;lr>");
            }
            _ => panic!("Expected Resolved, got {:?}", result),
        }
    }

    #[test]
    fn test_gruu_router_route_multiple_flows_lowest_regid() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        // Create multiple bindings with different reg-ids
        // Per RFC 5627 §5.1, should pick lowest reg-id
        let mut binding1 = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding1.set_instance_id("<urn:uuid:test-instance>");
        binding1.set_reg_id(3); // Higher reg-id

        let mut binding2 = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.200:5060",
            "call-456",
            1,
        );
        binding2.set_instance_id("<urn:uuid:test-instance>");
        binding2.set_reg_id(1); // Lowest reg-id - should be selected

        let mut binding3 = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.300:5060",
            "call-789",
            1,
        );
        binding3.set_instance_id("<urn:uuid:test-instance>");
        binding3.set_reg_id(2);

        location_service.add_binding(binding1).unwrap();
        location_service.add_binding(binding2).unwrap();
        location_service.add_binding(binding3).unwrap();

        // Route should pick binding with lowest reg-id
        let router = GruuRouter::new(&gruu_service, &location_service);
        let result = router.route(&pub_gruu);

        match result {
            GruuRoutingResult::Resolved { contact_uri, .. } => {
                assert_eq!(contact_uri, "sip:alice@192.168.1.200:5060");
            }
            _ => panic!("Expected Resolved, got {:?}", result),
        }
    }

    #[test]
    fn test_gruu_router_route_expired_registration() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        // Create a binding but mark it as removed/expired
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        binding.remove(); // Mark as expired
        location_service.add_binding(binding).unwrap();

        // Route should indicate expired
        let router = GruuRouter::new(&gruu_service, &location_service);
        let result = router.route(&pub_gruu);

        match result {
            GruuRoutingResult::RegistrationExpired { aor, instance_id } => {
                assert_eq!(aor, "sip:alice@example.com");
                assert_eq!(instance_id, "<urn:uuid:test-instance>");
            }
            _ => panic!("Expected RegistrationExpired, got {:?}", result),
        }
    }

    #[test]
    fn test_gruu_router_route_temp_gruu() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let temp_gruu = entry.temp_gruu().to_string();

        // Create a binding
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        location_service.add_binding(binding).unwrap();

        // Route using the temporary GRUU
        let router = GruuRouter::new(&gruu_service, &location_service);
        let result = router.route(&temp_gruu);

        match result {
            GruuRoutingResult::Resolved { contact_uri, .. } => {
                assert_eq!(contact_uri, "sip:alice@192.168.1.100:5060");
            }
            _ => panic!("Expected Resolved, got {:?}", result),
        }
    }

    #[test]
    fn test_gruu_router_route_to_binding() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        // Create a binding
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        binding.set_user_agent("TestPhone/1.0");
        location_service.add_binding(binding).unwrap();

        // Get full binding
        let router = GruuRouter::new(&gruu_service, &location_service);
        let binding = router.route_to_binding(&pub_gruu).unwrap();

        assert_eq!(binding.contact_uri(), "sip:alice@192.168.1.100:5060");
        assert_eq!(binding.user_agent(), Some("TestPhone/1.0"));
    }

    #[test]
    fn test_gruu_router_is_gruu_active() {
        let mut gruu_service = GruuService::new("example.com");
        let mut location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        let router = GruuRouter::new(&gruu_service, &location_service);

        // Not active yet (no binding)
        assert!(!router.is_gruu_active(&pub_gruu));

        // Add binding
        let mut binding = crate::binding::Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123",
            1,
        );
        binding.set_instance_id("<urn:uuid:test-instance>");
        binding.set_reg_id(1);
        location_service.add_binding(binding).unwrap();

        // Need to recreate router with updated location service
        let router = GruuRouter::new(&gruu_service, &location_service);
        assert!(router.is_gruu_active(&pub_gruu));
    }

    #[test]
    fn test_gruu_router_get_aor_for_gruu() {
        let mut gruu_service = GruuService::new("example.com");
        let location_service = LocationService::new();

        // Create a GRUU
        let entry = gruu_service
            .create_or_update_gruu(
                "sip:alice@example.com",
                "<urn:uuid:test-instance>",
                Duration::from_secs(3600),
            )
            .unwrap();
        let pub_gruu = entry.pub_gruu().to_string();

        let router = GruuRouter::new(&gruu_service, &location_service);

        // Get AOR without routing
        let aor = router.get_aor_for_gruu(&pub_gruu).unwrap();
        assert_eq!(aor, "sip:alice@example.com");

        // Non-GRUU returns None
        assert!(router.get_aor_for_gruu("sip:bob@example.com").is_none());
    }

    #[test]
    fn test_extract_gruu_info() {
        // Public GRUU
        let (value, is_temp) = extract_gruu_info("sip:alice@example.com;gr=abc123").unwrap();
        assert_eq!(value, "abc123");
        assert!(!is_temp);

        // Temporary GRUU
        let (value, is_temp) = extract_gruu_info("sip:xyz@example.com;gr").unwrap();
        assert!(value.is_empty());
        assert!(is_temp);

        // Not a GRUU
        assert!(extract_gruu_info("sip:alice@example.com").is_none());
    }
}
