//! Topology hiding for SIP messages.
//!
//! This module provides mechanisms to hide internal network topology from
//! external entities per RFC 3323 (Privacy Mechanism) and related security
//! best practices.
//!
//! ## Features
//!
//! - Via header stripping and anonymization
//! - Contact header anonymization
//! - Record-Route manipulation
//! - Call-ID obfuscation
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Core (§16.6 - Request Forwarding)
//! - **RFC 3323**: A Privacy Mechanism for SIP
//! - **RFC 3325**: Private Extensions to SIP for Asserted Identity
//!
//! ## Security Benefits
//!
//! - Prevents internal IP address disclosure
//! - Hides network topology from external parties
//! - Protects against targeted attacks on internal infrastructure

use crate::error::{SipError, SipResult};
use crate::header::{Header, HeaderName, Headers};
use crate::header_params::{NameAddr, ViaHeader};
use crate::uri::{SipUri, UriScheme};
use std::collections::HashMap;
use std::fmt;

/// Topology hiding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TopologyHidingMode {
    /// No topology hiding (pass-through).
    None,
    /// Basic hiding - replace internal addresses with external address.
    #[default]
    Basic,
    /// Aggressive hiding - anonymize all possible information.
    Aggressive,
}

impl fmt::Display for TopologyHidingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Basic => write!(f, "basic"),
            Self::Aggressive => write!(f, "aggressive"),
        }
    }
}

/// Configuration for topology hiding.
#[derive(Debug, Clone)]
pub struct TopologyHidingConfig {
    /// Hiding mode.
    pub mode: TopologyHidingMode,
    /// External/public hostname to use for anonymization.
    pub external_host: String,
    /// External port (None means use default port).
    pub external_port: Option<u16>,
    /// Domain to use for anonymized URIs.
    pub anonymization_domain: String,
    /// Whether to obfuscate Call-ID.
    pub obfuscate_call_id: bool,
    /// Whether to hide Via received/rport parameters.
    pub hide_via_params: bool,
    /// Internal network prefixes (CIDR-like patterns).
    pub internal_networks: Vec<String>,
}

impl Default for TopologyHidingConfig {
    fn default() -> Self {
        Self {
            mode: TopologyHidingMode::Basic,
            external_host: "proxy.example.com".to_string(),
            external_port: None,
            anonymization_domain: "anonymous.invalid".to_string(),
            obfuscate_call_id: true,
            hide_via_params: true,
            internal_networks: vec![
                "10.".to_string(),
                "172.16.".to_string(),
                "172.17.".to_string(),
                "172.18.".to_string(),
                "172.19.".to_string(),
                "172.20.".to_string(),
                "172.21.".to_string(),
                "172.22.".to_string(),
                "172.23.".to_string(),
                "172.24.".to_string(),
                "172.25.".to_string(),
                "172.26.".to_string(),
                "172.27.".to_string(),
                "172.28.".to_string(),
                "172.29.".to_string(),
                "172.30.".to_string(),
                "172.31.".to_string(),
                "192.168.".to_string(),
            ],
        }
    }
}

impl TopologyHidingConfig {
    /// Creates a new configuration with the given external host.
    #[must_use]
    pub fn new(external_host: impl Into<String>) -> Self {
        Self {
            external_host: external_host.into(),
            ..Default::default()
        }
    }

    /// Sets the hiding mode.
    #[must_use]
    pub fn with_mode(mut self, mode: TopologyHidingMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the external port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.external_port = Some(port);
        self
    }

    /// Sets the anonymization domain.
    #[must_use]
    pub fn with_anonymization_domain(mut self, domain: impl Into<String>) -> Self {
        self.anonymization_domain = domain.into();
        self
    }

    /// Sets Call-ID obfuscation.
    #[must_use]
    pub fn with_call_id_obfuscation(mut self, enabled: bool) -> Self {
        self.obfuscate_call_id = enabled;
        self
    }

    /// Adds an internal network prefix.
    #[must_use]
    pub fn with_internal_network(mut self, prefix: impl Into<String>) -> Self {
        self.internal_networks.push(prefix.into());
        self
    }

    /// Checks if an address is considered internal.
    #[must_use]
    pub fn is_internal_address(&self, host: &str) -> bool {
        for prefix in &self.internal_networks {
            if host.starts_with(prefix) {
                return true;
            }
        }
        false
    }
}

/// Topology hider for SIP messages.
///
/// Provides methods to anonymize and hide internal topology information
/// from SIP messages before forwarding to external parties.
#[derive(Debug, Clone)]
pub struct TopologyHider {
    /// Configuration.
    config: TopologyHidingConfig,
    /// Call-ID mapping (original -> obfuscated).
    call_id_map: HashMap<String, String>,
    /// Reverse Call-ID mapping (obfuscated -> original).
    reverse_call_id_map: HashMap<String, String>,
}

impl TopologyHider {
    /// Creates a new topology hider with the given configuration.
    #[must_use]
    pub fn new(config: TopologyHidingConfig) -> Self {
        Self {
            config,
            call_id_map: HashMap::new(),
            reverse_call_id_map: HashMap::new(),
        }
    }

    /// Creates a topology hider with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TopologyHidingConfig::default())
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &TopologyHidingConfig {
        &self.config
    }

    // =========================================================================
    // Via Header Manipulation
    // =========================================================================

    /// Strips internal Via headers from a list, keeping only the topmost.
    ///
    /// This is used for topology hiding when forwarding responses back to
    /// internal clients.
    ///
    /// # RFC 3261 §16.6
    ///
    /// The proxy MUST strip its own Via header from the response. For topology
    /// hiding, we additionally strip Via headers that reveal internal addresses.
    #[must_use]
    pub fn strip_internal_vias(&self, vias: &[ViaHeader]) -> Vec<ViaHeader> {
        if self.config.mode == TopologyHidingMode::None {
            return vias.to_vec();
        }

        vias.iter()
            .filter(|via| !self.config.is_internal_address(&via.host))
            .cloned()
            .collect()
    }

    /// Anonymizes a Via header by replacing internal addresses.
    ///
    /// Returns None if the Via should be stripped entirely.
    #[must_use]
    pub fn anonymize_via(&self, via: &ViaHeader) -> Option<ViaHeader> {
        if self.config.mode == TopologyHidingMode::None {
            return Some(via.clone());
        }

        let mut anonymized = via.clone();

        // Replace internal host with external host
        if self.config.is_internal_address(&via.host) {
            if self.config.mode == TopologyHidingMode::Aggressive {
                // In aggressive mode, strip internal Vias entirely
                return None;
            }
            anonymized.host.clone_from(&self.config.external_host);
            anonymized.port = self.config.external_port;
        }

        // Hide received/rport if configured
        if self.config.hide_via_params {
            if anonymized
                .received
                .as_ref()
                .is_some_and(|r| self.config.is_internal_address(r))
            {
                anonymized.received = None;
            }
            // Always hide rport for internal addresses since it can reveal port allocation
            if self.config.is_internal_address(&via.host) {
                anonymized.rport = None;
            }
        }

        Some(anonymized)
    }

    /// Rewrites Via headers in a header collection for outbound requests.
    ///
    /// This adds the proxy's Via and optionally hides internal Via headers.
    pub fn rewrite_vias_for_outbound(&self, headers: &mut Headers, proxy_via: &ViaHeader) {
        if self.config.mode == TopologyHidingMode::None {
            // Just add proxy Via without hiding - insert at beginning
            let existing_vias = headers.via_all_parsed();
            headers.remove(&HeaderName::Via);
            headers.add(Header::new(HeaderName::Via, proxy_via.to_string()));
            for via in &existing_vias {
                headers.add(Header::new(HeaderName::Via, via.to_string()));
            }
            return;
        }

        // Collect existing Vias
        let existing_vias = headers.via_all_parsed();

        // Remove all Via headers
        headers.remove(&HeaderName::Via);

        // Add proxy's Via first
        headers.add(Header::new(HeaderName::Via, proxy_via.to_string()));

        // Add anonymized internal Vias (or skip them in aggressive mode)
        for via in &existing_vias {
            if let Some(anonymized) = self.anonymize_via(via) {
                headers.add(Header::new(HeaderName::Via, anonymized.to_string()));
            }
        }
    }

    /// Rewrites Via headers in a header collection for inbound responses.
    ///
    /// This removes the topmost Via (proxy's own) and optionally hides
    /// remaining internal Vias.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn rewrite_vias_for_inbound(&self, headers: &mut Headers) -> SipResult<ViaHeader> {
        // Parse all Vias
        let vias = headers.via_all_parsed();

        if vias.is_empty() {
            return Err(SipError::ParseError {
                reason: "no Via headers in response".to_string(),
            });
        }

        // Remove all Via headers
        headers.remove(&HeaderName::Via);

        // The topmost Via is the proxy's own - save it for return
        let proxy_via = vias[0].clone();

        // Re-add remaining Vias (anonymized if needed)
        for via in vias.iter().skip(1) {
            if self.config.mode == TopologyHidingMode::None {
                headers.add(Header::new(HeaderName::Via, via.to_string()));
            } else if let Some(anonymized) = self.anonymize_via(via) {
                headers.add(Header::new(HeaderName::Via, anonymized.to_string()));
            }
        }

        Ok(proxy_via)
    }

    // =========================================================================
    // Contact Header Anonymization
    // =========================================================================

    /// Anonymizes a Contact header by replacing the URI.
    ///
    /// Returns an anonymized `NameAddr` that hides the actual contact address.
    #[must_use]
    pub fn anonymize_contact(&self, contact: &NameAddr) -> NameAddr {
        if self.config.mode == TopologyHidingMode::None {
            return contact.clone();
        }

        let mut anonymized = contact.clone();

        // Check if the contact URI reveals internal topology
        if self.config.is_internal_address(&contact.uri.host) {
            // Create anonymized URI
            let mut anon_uri = SipUri::new(&self.config.external_host);
            anon_uri.scheme = contact.uri.scheme;
            if let Some(ref user) = contact.uri.user {
                // Keep the user part but change the host
                anon_uri.user = Some(user.clone());
            }
            if let Some(port) = self.config.external_port {
                anon_uri.port = Some(port);
            }

            anonymized.uri = anon_uri;
        }

        // In aggressive mode, also remove the display name
        if self.config.mode == TopologyHidingMode::Aggressive {
            anonymized.display_name = None;
        }

        anonymized
    }

    /// Rewrites Contact headers in a header collection.
    pub fn rewrite_contacts(&self, headers: &mut Headers) {
        if self.config.mode == TopologyHidingMode::None {
            return;
        }

        // Parse existing Contact header
        if let Some(contact) = headers.contact_parsed() {
            let anonymized = self.anonymize_contact(&contact);
            headers.set(HeaderName::Contact, anonymized.to_string());
        }
    }

    // =========================================================================
    // Record-Route Manipulation
    // =========================================================================

    /// Creates an anonymized Record-Route header value.
    ///
    /// Returns a Record-Route URI that uses the external address.
    #[must_use]
    pub fn create_anonymized_record_route(&self, transport: Option<&str>) -> String {
        let mut uri = SipUri::new(&self.config.external_host);
        uri.scheme = UriScheme::Sip;
        if let Some(port) = self.config.external_port {
            uri.port = Some(port);
        }
        // Add lr parameter for loose routing per RFC 3261
        uri.params.push(("lr".to_string(), None));

        if let Some(t) = transport {
            uri.params
                .push(("transport".to_string(), Some(t.to_string())));
        }

        format!("<{uri}>")
    }

    /// Rewrites Record-Route headers to hide internal addresses.
    pub fn rewrite_record_routes(&self, headers: &mut Headers, transport: Option<&str>) {
        if self.config.mode == TopologyHidingMode::None {
            return;
        }

        // Get existing Record-Route headers
        let routes: Vec<String> = headers
            .get_all(&HeaderName::RecordRoute)
            .iter()
            .map(|h| h.value.clone())
            .collect();

        if routes.is_empty() {
            return;
        }

        // Remove all Record-Route headers
        headers.remove(&HeaderName::RecordRoute);

        // Re-add with anonymization
        for route in &routes {
            // Parse the route to check if it's internal
            if let Ok(name_addr) = route.parse::<NameAddr>() {
                if self.config.is_internal_address(&name_addr.uri.host) {
                    // Replace with anonymized route
                    headers.add(Header::new(
                        HeaderName::RecordRoute,
                        self.create_anonymized_record_route(transport),
                    ));
                } else {
                    // Keep external routes as-is
                    headers.add(Header::new(HeaderName::RecordRoute, route.clone()));
                }
            } else {
                // If we can't parse it, keep it as-is
                headers.add(Header::new(HeaderName::RecordRoute, route.clone()));
            }
        }
    }

    // =========================================================================
    // Call-ID Obfuscation
    // =========================================================================

    /// Generates an obfuscated Call-ID.
    fn generate_obfuscated_call_id(&self, original: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        original.hash(&mut hasher);
        let hash = hasher.finish();

        format!("{:016x}@{}", hash, self.config.anonymization_domain)
    }

    /// Obfuscates a Call-ID.
    ///
    /// Returns the obfuscated version and stores the mapping for reverse lookup.
    pub fn obfuscate_call_id(&mut self, original: &str) -> String {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return original.to_string();
        }

        // Check if we already have a mapping
        if let Some(obfuscated) = self.call_id_map.get(original) {
            return obfuscated.clone();
        }

        // Generate new obfuscated Call-ID
        let obfuscated = self.generate_obfuscated_call_id(original);

        // Store both mappings
        self.call_id_map
            .insert(original.to_string(), obfuscated.clone());
        self.reverse_call_id_map
            .insert(obfuscated.clone(), original.to_string());

        obfuscated
    }

    /// Restores an original Call-ID from an obfuscated one.
    ///
    /// Returns None if the Call-ID was not previously obfuscated by this hider.
    #[must_use]
    pub fn restore_call_id(&self, obfuscated: &str) -> Option<String> {
        self.reverse_call_id_map.get(obfuscated).cloned()
    }

    /// Rewrites the Call-ID header in a header collection.
    pub fn rewrite_call_id(&mut self, headers: &mut Headers) {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return;
        }

        if let Some(call_id) = headers.get(&HeaderName::CallId) {
            let obfuscated = self.obfuscate_call_id(&call_id.value);
            headers.set(HeaderName::CallId, obfuscated);
        }
    }

    /// Restores the original Call-ID header in a header collection.
    pub fn restore_call_id_header(&self, headers: &mut Headers) {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return;
        }

        if let Some(call_id) = headers.get(&HeaderName::CallId)
            && let Some(original) = self.restore_call_id(&call_id.value)
        {
            headers.set(HeaderName::CallId, original);
        }
    }

    // =========================================================================
    // Complete Message Processing
    // =========================================================================

    /// Applies all topology hiding transformations to outbound request headers.
    pub fn hide_outbound_request(&mut self, headers: &mut Headers, proxy_via: ViaHeader) {
        if self.config.mode == TopologyHidingMode::None {
            // Just add proxy Via at the beginning
            let existing_vias = headers.via_all_parsed();
            headers.remove(&HeaderName::Via);
            headers.add(Header::new(HeaderName::Via, proxy_via.to_string()));
            for via in &existing_vias {
                headers.add(Header::new(HeaderName::Via, via.to_string()));
            }
            return;
        }

        self.rewrite_vias_for_outbound(headers, &proxy_via);
        self.rewrite_contacts(headers);
        self.rewrite_call_id(headers);
        // Note: Record-Route is typically added by the proxy, not rewritten here
    }

    /// Applies all topology hiding transformations to inbound response headers.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn hide_inbound_response(&mut self, headers: &mut Headers) -> SipResult<ViaHeader> {
        let proxy_via = self.rewrite_vias_for_inbound(headers)?;

        if self.config.mode != TopologyHidingMode::None {
            self.rewrite_contacts(headers);
            // Don't rewrite Call-ID on responses - use restore instead
            self.restore_call_id_header(headers);
        }

        Ok(proxy_via)
    }

    /// Returns the number of stored Call-ID mappings.
    #[must_use]
    pub fn call_id_mapping_count(&self) -> usize {
        self.call_id_map.len()
    }

    /// Clears all Call-ID mappings.
    pub fn clear_call_id_mappings(&mut self) {
        self.call_id_map.clear();
        self.reverse_call_id_map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_hiding_mode_display() {
        assert_eq!(TopologyHidingMode::None.to_string(), "none");
        assert_eq!(TopologyHidingMode::Basic.to_string(), "basic");
        assert_eq!(TopologyHidingMode::Aggressive.to_string(), "aggressive");
    }

    #[test]
    fn test_config_internal_address_detection() {
        let config = TopologyHidingConfig::default();

        // RFC 1918 private addresses should be detected
        assert!(config.is_internal_address("10.0.0.1"));
        assert!(config.is_internal_address("10.255.255.255"));
        assert!(config.is_internal_address("172.16.0.1"));
        assert!(config.is_internal_address("172.31.255.255"));
        assert!(config.is_internal_address("192.168.1.100"));
        assert!(config.is_internal_address("192.168.0.1"));

        // Public addresses should not be detected
        assert!(!config.is_internal_address("8.8.8.8"));
        assert!(!config.is_internal_address("203.0.113.1"));
        assert!(!config.is_internal_address("proxy.example.com"));
    }

    #[test]
    fn test_config_builder() {
        let config = TopologyHidingConfig::new("edge.example.com")
            .with_mode(TopologyHidingMode::Aggressive)
            .with_port(5060)
            .with_call_id_obfuscation(false)
            .with_internal_network("100.64.");

        assert_eq!(config.external_host, "edge.example.com");
        assert_eq!(config.mode, TopologyHidingMode::Aggressive);
        assert_eq!(config.external_port, Some(5060));
        assert!(!config.obfuscate_call_id);
        assert!(config.is_internal_address("100.64.0.1"));
    }

    #[test]
    fn test_via_anonymization_basic() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100")
            .with_port(5060)
            .with_branch("z9hG4bK123456".to_string());

        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_some());
        let anon = anonymized.unwrap();
        assert_eq!(anon.host, "proxy.example.com");
        assert_eq!(anon.branch, Some("z9hG4bK123456".to_string()));
    }

    #[test]
    fn test_via_anonymization_aggressive() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_mode(TopologyHidingMode::Aggressive);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100").with_port(5060);

        // Internal Via should be stripped entirely in aggressive mode
        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_none());

        // External Via should pass through
        let external_via = ViaHeader::new("UDP", "203.0.113.1");
        let anonymized = hider.anonymize_via(&external_via);
        assert!(anonymized.is_some());
    }

    #[test]
    fn test_via_no_hiding() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::None);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100");

        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_some());
        let anon = anonymized.unwrap();
        assert_eq!(anon.host, "192.168.1.100"); // Should remain unchanged
    }

    #[test]
    fn test_strip_internal_vias() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let vias = vec![
            ViaHeader::new("UDP", "192.168.1.100"), // Internal
            ViaHeader::new("UDP", "10.0.0.1"),      // Internal
            ViaHeader::new("UDP", "203.0.113.1"),   // External
        ];

        let stripped = hider.strip_internal_vias(&vias);
        assert_eq!(stripped.len(), 1);
        assert_eq!(stripped[0].host, "203.0.113.1");
    }

    #[test]
    fn test_contact_anonymization() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let uri = SipUri::new("192.168.1.100");
        let contact = NameAddr::new(uri.clone()).with_display_name("Alice");

        let anonymized = hider.anonymize_contact(&contact);
        assert_eq!(anonymized.uri.host, "proxy.example.com");
        assert_eq!(anonymized.display_name, Some("Alice".to_string())); // Preserved in basic mode
    }

    #[test]
    fn test_contact_anonymization_aggressive() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_mode(TopologyHidingMode::Aggressive);
        let hider = TopologyHider::new(config);

        let uri = SipUri::new("192.168.1.100");
        let contact = NameAddr::new(uri).with_display_name("Alice");

        let anonymized = hider.anonymize_contact(&contact);
        assert_eq!(anonymized.uri.host, "proxy.example.com");
        assert!(anonymized.display_name.is_none()); // Removed in aggressive mode
    }

    #[test]
    fn test_call_id_obfuscation() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let mut hider = TopologyHider::new(config);

        let original = "abc123@192.168.1.100";
        let obfuscated = hider.obfuscate_call_id(original);

        // Should be different from original
        assert_ne!(obfuscated, original);
        // Should end with anonymization domain
        assert!(obfuscated.ends_with("@anonymous.invalid"));

        // Same input should give same output
        let obfuscated2 = hider.obfuscate_call_id(original);
        assert_eq!(obfuscated, obfuscated2);

        // Should be able to restore
        let restored = hider.restore_call_id(&obfuscated);
        assert_eq!(restored, Some(original.to_string()));
    }

    #[test]
    fn test_call_id_no_obfuscation() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::None);
        let mut hider = TopologyHider::new(config);

        let original = "abc123@192.168.1.100";
        let result = hider.obfuscate_call_id(original);
        assert_eq!(result, original); // Should remain unchanged
    }

    #[test]
    fn test_record_route_creation() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_port(5060)
            .with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let rr = hider.create_anonymized_record_route(Some("tcp"));
        assert!(rr.contains("proxy.example.com"));
        assert!(rr.contains(";lr"));
        assert!(rr.contains("transport=tcp"));
    }

    #[test]
    fn test_hider_creation() {
        let hider = TopologyHider::with_defaults();
        assert_eq!(hider.config().mode, TopologyHidingMode::Basic);
        assert_eq!(hider.call_id_mapping_count(), 0);
    }

    #[test]
    fn test_clear_call_id_mappings() {
        let config = TopologyHidingConfig::default();
        let mut hider = TopologyHider::new(config);

        hider.obfuscate_call_id("call1@example.com");
        hider.obfuscate_call_id("call2@example.com");
        assert_eq!(hider.call_id_mapping_count(), 2);

        hider.clear_call_id_mappings();
        assert_eq!(hider.call_id_mapping_count(), 0);
    }
}
