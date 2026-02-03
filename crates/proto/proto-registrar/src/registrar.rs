//! SIP registrar implementation.
//!
//! Handles REGISTER requests and manages the location service.

use crate::authentication::{AuthChallenge, AuthCredentials, AuthResult, Authenticator};
use crate::binding::Binding;
use crate::error::RegistrarResult;
use crate::location::LocationService;
use crate::{DEFAULT_EXPIRES, MAX_CONTACTS_PER_AOR, MAX_EXPIRES, MIN_EXPIRES};

/// Registrar operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistrarMode {
    /// B2BUA registrar mode.
    ///
    /// Terminates registrations locally and maintains bindings.
    #[default]
    B2bua,

    /// Proxy mode.
    ///
    /// Forwards registrations to upstream registrar.
    Proxy,

    /// Stateless proxy mode.
    ///
    /// Forwards registrations without maintaining state.
    StatelessProxy,
}

impl std::fmt::Display for RegistrarMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::B2bua => write!(f, "b2bua"),
            Self::Proxy => write!(f, "proxy"),
            Self::StatelessProxy => write!(f, "stateless-proxy"),
        }
    }
}

/// Registrar configuration.
#[derive(Debug, Clone)]
pub struct RegistrarConfig {
    /// Operation mode.
    pub mode: RegistrarMode,
    /// Default expiration time in seconds.
    pub default_expires: u32,
    /// Minimum expiration time in seconds.
    pub min_expires: u32,
    /// Maximum expiration time in seconds.
    pub max_expires: u32,
    /// Maximum contacts per AOR.
    pub max_contacts: usize,
    /// Realm for authentication.
    pub realm: String,
    /// Whether authentication is required.
    pub require_auth: bool,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            mode: RegistrarMode::B2bua,
            default_expires: DEFAULT_EXPIRES,
            min_expires: MIN_EXPIRES,
            max_expires: MAX_EXPIRES,
            max_contacts: MAX_CONTACTS_PER_AOR,
            realm: "sip".to_string(),
            require_auth: false,
        }
    }
}

impl RegistrarConfig {
    /// Creates a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the operation mode.
    pub fn with_mode(mut self, mode: RegistrarMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the default expiration.
    pub fn with_default_expires(mut self, expires: u32) -> Self {
        self.default_expires = expires;
        self
    }

    /// Sets the realm.
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Enables authentication requirement.
    pub fn with_auth_required(mut self, required: bool) -> Self {
        self.require_auth = required;
        self
    }
}

/// Registration request.
#[derive(Debug, Clone)]
pub struct RegisterRequest {
    /// Address of record.
    pub aor: String,
    /// Contact URIs with expiration.
    pub contacts: Vec<ContactInfo>,
    /// Call-ID header.
    pub call_id: String,
    /// CSeq number.
    pub cseq: u32,
    /// Expires header value (if present).
    pub expires: Option<u32>,
    /// Path headers from the request (RFC 3327).
    pub path: Vec<String>,
    /// Source address of the request (for outbound connection tracking).
    pub source_address: Option<String>,
    /// Authorization header value (for digest authentication).
    pub authorization: Option<String>,
    /// Request method (typically REGISTER).
    pub method: String,
}

impl RegisterRequest {
    /// Creates a new register request with the given AOR.
    pub fn new(aor: impl Into<String>) -> Self {
        Self {
            aor: aor.into(),
            contacts: Vec::new(),
            call_id: String::new(),
            cseq: 1,
            expires: None,
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        }
    }

    /// Sets the contacts.
    pub fn with_contacts(mut self, contacts: Vec<ContactInfo>) -> Self {
        self.contacts = contacts;
        self
    }

    /// Sets the Call-ID.
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = call_id.into();
        self
    }

    /// Sets the CSeq.
    pub fn with_cseq(mut self, cseq: u32) -> Self {
        self.cseq = cseq;
        self
    }

    /// Sets the Authorization header.
    pub fn with_authorization(mut self, auth: impl Into<String>) -> Self {
        self.authorization = Some(auth.into());
        self
    }

    /// Parses authorization credentials if present.
    pub fn credentials(&self) -> Option<AuthCredentials> {
        self.authorization
            .as_ref()
            .and_then(|a| AuthCredentials::parse(a))
    }
}

/// Contact information from a REGISTER request.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    /// Contact URI.
    pub uri: String,
    /// Expires parameter (overrides header).
    pub expires: Option<u32>,
    /// Q-value.
    pub q_value: Option<f32>,
    /// Instance ID (RFC 5626).
    pub instance_id: Option<String>,
    /// Reg-ID (RFC 5626).
    pub reg_id: Option<u32>,
}

impl ContactInfo {
    /// Creates a new contact info.
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            expires: None,
            q_value: None,
            instance_id: None,
            reg_id: None,
        }
    }

    /// Sets the expires value.
    pub fn with_expires(mut self, expires: u32) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets the q-value.
    pub fn with_q_value(mut self, q: f32) -> Self {
        self.q_value = Some(q);
        self
    }
}

/// Registration response.
///
/// Per RFC 3261 Section 10.3, a 200 OK response to REGISTER MUST contain:
/// - All current bindings for the AOR in Contact headers
/// - Each Contact with its expiry time
/// - Service-Route headers if applicable (RFC 3608)
/// - Path headers if stored during registration (RFC 3327)
#[derive(Debug)]
pub struct RegisterResponse {
    /// Whether registration succeeded.
    pub success: bool,
    /// Status code.
    pub status_code: u16,
    /// Reason phrase.
    pub reason: String,
    /// Current bindings (for 200 OK).
    pub contacts: Vec<Binding>,
    /// Minimum expires (for 423 response).
    pub min_expires: Option<u32>,
    /// Path headers to include (RFC 3327).
    pub path: Vec<String>,
    /// Service-Route headers (RFC 3608).
    pub service_route: Vec<String>,
    /// WWW-Authenticate header (for 401 response).
    pub www_authenticate: Option<String>,
    /// Authentication-Info header (for successful auth).
    pub authentication_info: Option<String>,
}

impl RegisterResponse {
    /// Creates a success response.
    pub fn ok(contacts: Vec<Binding>) -> Self {
        Self {
            success: true,
            status_code: 200,
            reason: "OK".to_string(),
            contacts,
            min_expires: None,
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: None,
            authentication_info: None,
        }
    }

    /// Creates a success response with Path headers.
    pub fn ok_with_path(contacts: Vec<Binding>, path: Vec<String>) -> Self {
        Self {
            success: true,
            status_code: 200,
            reason: "OK".to_string(),
            contacts,
            min_expires: None,
            path,
            service_route: Vec::new(),
            www_authenticate: None,
            authentication_info: None,
        }
    }

    /// Creates an interval too brief response.
    pub fn interval_too_brief(min_expires: u32) -> Self {
        Self {
            success: false,
            status_code: 423,
            reason: "Interval Too Brief".to_string(),
            contacts: Vec::new(),
            min_expires: Some(min_expires),
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: None,
            authentication_info: None,
        }
    }

    /// Creates an error response.
    pub fn error(status_code: u16, reason: impl Into<String>) -> Self {
        Self {
            success: false,
            status_code,
            reason: reason.into(),
            contacts: Vec::new(),
            min_expires: None,
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: None,
            authentication_info: None,
        }
    }

    /// Creates a 401 Unauthorized response with authentication challenge.
    pub fn unauthorized(challenge: &AuthChallenge) -> Self {
        Self {
            success: false,
            status_code: 401,
            reason: "Unauthorized".to_string(),
            contacts: Vec::new(),
            min_expires: None,
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: Some(challenge.to_header_value()),
            authentication_info: None,
        }
    }

    /// Sets authentication info for successful auth response.
    pub fn with_authentication_info(mut self, info: impl Into<String>) -> Self {
        self.authentication_info = Some(info.into());
        self
    }

    /// Adds Service-Route headers.
    pub fn with_service_route(mut self, routes: Vec<String>) -> Self {
        self.service_route = routes;
        self
    }

    /// Formats Contact headers for the response per RFC 3261 Section 10.3.
    ///
    /// Each contact is formatted with its remaining expiry time.
    /// Format: `<uri>;expires=<seconds>`
    pub fn format_contacts(&self) -> Vec<String> {
        self.contacts
            .iter()
            .map(|binding| {
                let remaining = binding.remaining_seconds();
                let mut contact = format!("<{}>", binding.contact_uri());

                // Add expires parameter
                contact.push_str(&format!(";expires={}", remaining));

                // Add q-value if not default (1.0)
                let q = binding.q_value();
                if (q - 1.0).abs() > f32::EPSILON {
                    contact.push_str(&format!(";q={:.1}", q));
                }

                // Add instance-id if present (RFC 5626)
                if let Some(instance) = binding.instance_id() {
                    contact.push_str(&format!(";+sip.instance=\"{}\"", instance));
                }

                // Add reg-id if present (RFC 5626)
                if let Some(reg_id) = binding.reg_id() {
                    contact.push_str(&format!(";reg-id={}", reg_id));
                }

                contact
            })
            .collect()
    }

    /// Formats the Date header value (RFC 3261 recommends including Date).
    pub fn format_date(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // RFC 1123 date format (simplified)
        // In production, use a proper date formatting library
        format!("SIP-Date: {}", now)
    }
}

/// SIP registrar.
#[derive(Debug)]
pub struct Registrar {
    /// Configuration.
    config: RegistrarConfig,
    /// Location service.
    location: LocationService,
}

impl Registrar {
    /// Creates a new registrar.
    pub fn new(config: RegistrarConfig) -> Self {
        Self {
            location: LocationService::with_max_contacts(config.max_contacts),
            config,
        }
    }

    /// Creates a registrar with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RegistrarConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &RegistrarConfig {
        &self.config
    }

    /// Returns the location service.
    pub fn location(&self) -> &LocationService {
        &self.location
    }

    /// Returns a mutable reference to the location service.
    pub fn location_mut(&mut self) -> &mut LocationService {
        &mut self.location
    }

    /// Processes a REGISTER request.
    pub fn process_register(
        &mut self,
        request: RegisterRequest,
    ) -> RegistrarResult<RegisterResponse> {
        // Check if this is a fetch (no contacts)
        if request.contacts.is_empty() {
            return self.fetch_bindings(&request.aor);
        }

        // Check for wildcard removal (Contact: *)
        if request.contacts.len() == 1 && request.contacts[0].uri == "*" {
            return self.remove_all_bindings(&request);
        }

        // Process each contact
        for contact in &request.contacts {
            let expires = self.calculate_expires(contact.expires, request.expires);

            // Check for interval too brief
            if expires > 0 && expires < self.config.min_expires {
                return Ok(RegisterResponse::interval_too_brief(
                    self.config.min_expires,
                ));
            }

            if expires == 0 {
                // Remove binding
                let _ = self.location.remove_binding(&request.aor, &contact.uri);
            } else {
                // Add or update binding
                self.add_or_update_binding(&request, contact, expires)?;
            }
        }

        // Return current bindings
        self.fetch_bindings(&request.aor)
    }

    /// Fetches current bindings for an AOR.
    fn fetch_bindings(&self, aor: &str) -> RegistrarResult<RegisterResponse> {
        let bindings: Vec<Binding> = self.location.lookup(aor).into_iter().cloned().collect();

        Ok(RegisterResponse::ok(bindings))
    }

    /// Removes all bindings for an AOR.
    fn remove_all_bindings(
        &mut self,
        request: &RegisterRequest,
    ) -> RegistrarResult<RegisterResponse> {
        // Wildcard removal requires expires=0
        if request.expires != Some(0) {
            return Ok(RegisterResponse::error(400, "Bad Request"));
        }

        let _ = self.location.remove_all_bindings(&request.aor);
        Ok(RegisterResponse::ok(Vec::new()))
    }

    /// Adds or updates a binding.
    fn add_or_update_binding(
        &mut self,
        request: &RegisterRequest,
        contact: &ContactInfo,
        expires: u32,
    ) -> RegistrarResult<()> {
        // Check if binding exists
        if let Some(existing) = self.location.get_binding_mut(&request.aor, &contact.uri) {
            // Update existing binding
            existing.refresh(&request.call_id, request.cseq, expires)?;

            if let Some(q) = contact.q_value {
                existing.set_q_value(q);
            }
        } else {
            // Create new binding
            let mut binding =
                Binding::new(&request.aor, &contact.uri, &request.call_id, request.cseq);
            binding.set_expires(expires)?;

            if let Some(q) = contact.q_value {
                binding.set_q_value(q);
            }
            if let Some(ref instance_id) = contact.instance_id {
                binding.set_instance_id(instance_id);
            }
            if let Some(reg_id) = contact.reg_id {
                binding.set_reg_id(reg_id);
            }

            self.location.add_binding(binding)?;
        }

        Ok(())
    }

    /// Calculates the effective expires value.
    fn calculate_expires(&self, contact_expires: Option<u32>, header_expires: Option<u32>) -> u32 {
        // Contact parameter takes precedence over header
        let expires = contact_expires
            .or(header_expires)
            .unwrap_or(self.config.default_expires);

        // Cap at maximum
        expires.min(self.config.max_expires)
    }

    /// Removes expired bindings.
    pub fn cleanup_expired(&mut self) -> usize {
        self.location.cleanup_expired()
    }

    /// Returns the total number of bindings.
    pub fn total_bindings(&self) -> usize {
        self.location.total_bindings()
    }

    /// Returns the number of registered AORs.
    pub fn aor_count(&self) -> usize {
        self.location.aor_count()
    }
}

impl Default for Registrar {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Registrar with integrated authentication support.
///
/// Combines the basic registrar with an authenticator for RFC 3261 §22
/// digest authentication.
pub struct AuthenticatedRegistrar {
    /// Inner registrar.
    registrar: Registrar,
    /// Authenticator for digest auth.
    authenticator: Authenticator,
}

impl std::fmt::Debug for AuthenticatedRegistrar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedRegistrar")
            .field("registrar", &self.registrar)
            .field("authenticator", &self.authenticator)
            .finish()
    }
}

impl AuthenticatedRegistrar {
    /// Creates a new authenticated registrar.
    pub fn new(config: RegistrarConfig) -> Self {
        Self {
            registrar: Registrar::new(config),
            authenticator: Authenticator::new(),
        }
    }

    /// Sets the password lookup function.
    pub fn with_password_lookup<F>(mut self, lookup: F) -> Self
    where
        F: Fn(&str, &str) -> Option<String> + Send + Sync + 'static,
    {
        self.authenticator = self.authenticator.with_password_lookup(lookup);
        self
    }

    /// Returns the configuration.
    pub fn config(&self) -> &RegistrarConfig {
        self.registrar.config()
    }

    /// Returns the location service.
    pub fn location(&self) -> &LocationService {
        self.registrar.location()
    }

    /// Processes a REGISTER request with authentication.
    ///
    /// If authentication is required and credentials are missing or invalid,
    /// returns a 401 Unauthorized response with a challenge.
    pub fn process_register(
        &mut self,
        request: RegisterRequest,
    ) -> RegistrarResult<RegisterResponse> {
        let config = self.registrar.config();

        // Check if authentication is required
        if config.require_auth {
            let credentials = request.credentials();
            let auth_result = self.authenticator.authenticate(
                credentials.as_ref(),
                &config.realm,
                &request.method,
                None, // No entity body for REGISTER
            );

            match auth_result {
                AuthResult::Success { .. } => {
                    // Authentication successful, proceed with registration
                }
                AuthResult::ChallengeRequired { challenge } => {
                    return Ok(RegisterResponse::unauthorized(&challenge));
                }
                AuthResult::StaleNonce { challenge } => {
                    return Ok(RegisterResponse::unauthorized(&challenge));
                }
                AuthResult::Failed { reason } => {
                    return Ok(RegisterResponse::error(
                        403,
                        format!("Forbidden: {}", reason),
                    ));
                }
            }
        }

        // Process the registration
        self.registrar.process_register(request)
    }

    /// Removes expired bindings and nonces.
    pub fn cleanup_expired(&mut self) -> usize {
        let bindings_removed = self.registrar.cleanup_expired();
        let nonces_removed = self.authenticator.cleanup_expired();
        bindings_removed + nonces_removed
    }

    /// Returns the total number of bindings.
    pub fn total_bindings(&self) -> usize {
        self.registrar.total_bindings()
    }

    /// Returns the number of registered AORs.
    pub fn aor_count(&self) -> usize {
        self.registrar.aor_count()
    }

    /// Returns the inner registrar.
    pub fn registrar(&self) -> &Registrar {
        &self.registrar
    }

    /// Returns a mutable reference to the inner registrar.
    pub fn registrar_mut(&mut self) -> &mut Registrar {
        &mut self.registrar
    }

    /// Returns the authenticator.
    pub fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    /// Returns a mutable reference to the authenticator.
    pub fn authenticator_mut(&mut self) -> &mut Authenticator {
        &mut self.authenticator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_register_request(aor: &str, contact: &str) -> RegisterRequest {
        RegisterRequest {
            aor: aor.to_string(),
            contacts: vec![ContactInfo::new(contact)],
            call_id: "call-123@client".to_string(),
            cseq: 1,
            expires: Some(3600),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        }
    }

    #[test]
    fn test_registrar_creation() {
        let registrar = Registrar::with_defaults();
        assert_eq!(registrar.config().mode, RegistrarMode::B2bua);
        assert_eq!(registrar.total_bindings(), 0);
    }

    #[test]
    fn test_registrar_mode_display() {
        assert_eq!(RegistrarMode::B2bua.to_string(), "b2bua");
        assert_eq!(RegistrarMode::Proxy.to_string(), "proxy");
    }

    #[test]
    fn test_config_builder() {
        let config = RegistrarConfig::new()
            .with_mode(RegistrarMode::Proxy)
            .with_realm("example.com")
            .with_auth_required(true);

        assert_eq!(config.mode, RegistrarMode::Proxy);
        assert_eq!(config.realm, "example.com");
        assert!(config.require_auth);
    }

    #[test]
    fn test_process_register() {
        let mut registrar = Registrar::with_defaults();

        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");

        let response = registrar.process_register(request).unwrap();
        assert!(response.success);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.contacts.len(), 1);
    }

    #[test]
    fn test_register_multiple_contacts() {
        let mut registrar = Registrar::with_defaults();

        let request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![
                ContactInfo::new("sip:alice@192.168.1.100:5060"),
                ContactInfo::new("sip:alice@192.168.1.200:5060"),
            ],
            call_id: "call-123@client".to_string(),
            cseq: 1,
            expires: Some(3600),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(request).unwrap();
        assert!(response.success);
        assert_eq!(response.contacts.len(), 2);
    }

    #[test]
    fn test_register_fetch() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(request).unwrap();

        // Then fetch (no contacts)
        let fetch_request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: Vec::new(),
            call_id: "call-456@client".to_string(),
            cseq: 1,
            expires: None,
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(fetch_request).unwrap();
        assert!(response.success);
        assert_eq!(response.contacts.len(), 1);
    }

    #[test]
    fn test_register_remove() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(request).unwrap();

        // Then remove with expires=0
        let remove_request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![ContactInfo::new("sip:alice@192.168.1.100:5060").with_expires(0)],
            call_id: "call-123@client".to_string(),
            cseq: 2,
            expires: None,
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(remove_request).unwrap();
        assert!(response.success);
        assert!(response.contacts.is_empty());
    }

    #[test]
    fn test_register_wildcard_removal() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(request).unwrap();

        // Remove all with wildcard
        let remove_request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![ContactInfo::new("*")],
            call_id: "call-123@client".to_string(),
            cseq: 2,
            expires: Some(0),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(remove_request).unwrap();
        assert!(response.success);
        assert!(response.contacts.is_empty());
    }

    #[test]
    fn test_interval_too_brief() {
        let mut registrar = Registrar::with_defaults();

        // Request with expires below minimum
        let request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![ContactInfo::new("sip:alice@192.168.1.100:5060").with_expires(30)],
            call_id: "call-123@client".to_string(),
            cseq: 1,
            expires: None,
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(request).unwrap();
        assert!(!response.success);
        assert_eq!(response.status_code, 423);
        assert!(response.min_expires.is_some());
    }

    #[test]
    fn test_register_update() {
        let mut registrar = Registrar::with_defaults();

        // Initial register
        let request1 = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![ContactInfo::new("sip:alice@192.168.1.100:5060")],
            call_id: "call-123@client".to_string(),
            cseq: 1,
            expires: Some(3600),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };
        registrar.process_register(request1).unwrap();

        // Update with higher CSeq
        let request2 = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![ContactInfo::new("sip:alice@192.168.1.100:5060").with_q_value(0.5)],
            call_id: "call-123@client".to_string(),
            cseq: 2,
            expires: Some(7200),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };
        let response = registrar.process_register(request2).unwrap();

        assert!(response.success);
        assert_eq!(response.contacts.len(), 1);
        // Q-value should be updated
        let q = response.contacts[0].q_value();
        assert!((q - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_contact_info_builder() {
        let contact = ContactInfo::new("sip:alice@example.com")
            .with_expires(1800)
            .with_q_value(0.5);

        assert_eq!(contact.expires, Some(1800));
        assert!((contact.q_value.unwrap() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_register_response_helpers() {
        let ok_response = RegisterResponse::ok(Vec::new());
        assert!(ok_response.success);
        assert_eq!(ok_response.status_code, 200);

        let brief_response = RegisterResponse::interval_too_brief(60);
        assert!(!brief_response.success);
        assert_eq!(brief_response.status_code, 423);

        let error_response = RegisterResponse::error(500, "Server Error");
        assert!(!error_response.success);
        assert_eq!(error_response.status_code, 500);
    }

    #[test]
    fn test_format_contacts_rfc3261() {
        let mut registrar = Registrar::with_defaults();

        // Register with instance-id and reg-id (RFC 5626)
        let mut contact = ContactInfo::new("sip:alice@192.168.1.100:5060");
        contact.instance_id = Some("<urn:uuid:abc123>".to_string());
        contact.reg_id = Some(1);
        contact.q_value = Some(0.8);

        let request = RegisterRequest {
            aor: "sip:alice@example.com".to_string(),
            contacts: vec![contact],
            call_id: "call-123@client".to_string(),
            cseq: 1,
            expires: Some(3600),
            path: Vec::new(),
            source_address: None,
            authorization: None,
            method: "REGISTER".to_string(),
        };

        let response = registrar.process_register(request).unwrap();
        assert!(response.success);

        // Format contacts per RFC 3261 §10.3
        let formatted = response.format_contacts();
        assert_eq!(formatted.len(), 1);

        let contact_str = &formatted[0];
        assert!(contact_str.contains("<sip:alice@192.168.1.100:5060>"));
        assert!(contact_str.contains(";expires="));
        assert!(contact_str.contains(";q=0.8"));
        assert!(contact_str.contains(";+sip.instance=\"<urn:uuid:abc123>\""));
        assert!(contact_str.contains(";reg-id=1"));
    }

    #[test]
    fn test_response_with_path() {
        let bindings = Vec::new();
        let path = vec![
            "<sip:proxy1.example.com;lr>".to_string(),
            "<sip:proxy2.example.com;lr>".to_string(),
        ];

        let response = RegisterResponse::ok_with_path(bindings, path.clone());
        assert!(response.success);
        assert_eq!(response.path.len(), 2);
        assert_eq!(response.path, path);
    }

    #[test]
    fn test_response_with_service_route() {
        let response = RegisterResponse::ok(Vec::new())
            .with_service_route(vec!["<sip:edge.example.com;lr>".to_string()]);

        assert_eq!(response.service_route.len(), 1);
    }
}
