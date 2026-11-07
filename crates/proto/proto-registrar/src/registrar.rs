//! SIP registrar implementation.
//!
//! Handles REGISTER requests and manages the location service.

use crate::authentication::{AuthChallenge, AuthCredentials, AuthResult, Authenticator};
use crate::binding::Binding;
use crate::error::{RegistrarError, RegistrarResult};
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
    #[must_use]
    pub fn with_mode(mut self, mode: RegistrarMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the default expiration.
    #[must_use]
    pub fn with_default_expires(mut self, expires: u32) -> Self {
        self.default_expires = expires;
        self
    }

    /// Sets the realm.
    #[must_use]
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Enables authentication requirement.
    #[must_use]
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
    #[must_use]
    pub fn with_contacts(mut self, contacts: Vec<ContactInfo>) -> Self {
        self.contacts = contacts;
        self
    }

    /// Sets the Call-ID.
    #[must_use]
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = call_id.into();
        self
    }

    /// Sets the CSeq.
    #[must_use]
    pub fn with_cseq(mut self, cseq: u32) -> Self {
        self.cseq = cseq;
        self
    }

    /// Sets the Authorization header.
    #[must_use]
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
    #[must_use]
    pub fn with_expires(mut self, expires: u32) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets the q-value.
    #[must_use]
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

    /// Creates a 401 Unauthorized response with a Bearer challenge
    /// (RFC 8898 / RFC 6750). `challenge` is the `WWW-Authenticate` value,
    /// e.g. from [`crate::bearer::BearerAuthenticator::challenge_header`].
    pub fn unauthorized_bearer(challenge: impl Into<String>) -> Self {
        Self {
            success: false,
            status_code: 401,
            reason: "Unauthorized".to_string(),
            contacts: Vec::new(),
            min_expires: None,
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: Some(challenge.into()),
            authentication_info: None,
        }
    }

    /// Creates a 403 Forbidden response — the request authenticated but is
    /// not authorized (e.g. a Bearer token whose `dn` does not own the AOR).
    /// No challenge is included; re-authenticating would not help.
    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            status_code: 403,
            reason: reason.into(),
            contacts: Vec::new(),
            min_expires: None,
            path: Vec::new(),
            service_route: Vec::new(),
            www_authenticate: None,
            authentication_info: None,
        }
    }

    /// Sets authentication info for successful auth response.
    #[must_use]
    pub fn with_authentication_info(mut self, info: impl Into<String>) -> Self {
        self.authentication_info = Some(info.into());
        self
    }

    /// Adds Service-Route headers.
    #[must_use]
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
                contact.push_str(";expires=");
                contact.push_str(&remaining.to_string());

                // Add q-value if not default (1.0)
                let q = binding.q_value();
                if (q - 1.0).abs() > f32::EPSILON {
                    use std::fmt::Write;
                    let _ = write!(contact, ";q={q:.1}");
                }

                // Add instance-id if present (RFC 5626)
                if let Some(instance) = binding.instance_id() {
                    contact.push_str(";+sip.instance=\"");
                    contact.push_str(instance);
                    contact.push('"');
                }

                // Add reg-id if present (RFC 5626)
                if let Some(reg_id) = binding.reg_id() {
                    contact.push_str(";reg-id=");
                    contact.push_str(&reg_id.to_string());
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
            .map_or(0, |d| d.as_secs());

        // RFC 1123 date format (simplified)
        // In production, use a proper date formatting library
        format!("SIP-Date: {now}")
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

/// Binding key a contact will be stored under; mirrors
/// [`Binding::binding_key`] (instance-id + reg-id for RFC 5626 outbound,
/// otherwise the contact URI).
fn contact_binding_key(contact: &ContactInfo) -> String {
    match (&contact.instance_id, contact.reg_id) {
        (Some(instance_id), Some(reg_id)) => format!("{instance_id}:{reg_id}"),
        _ => contact.uri.clone(),
    }
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
        request: &RegisterRequest,
    ) -> RegistrarResult<RegisterResponse> {
        // Check if this is a fetch (no contacts)
        if request.contacts.is_empty() {
            return Ok(self.fetch_bindings(&request.aor));
        }

        // Check for wildcard removal (Contact: *)
        if request.contacts.len() == 1 && request.contacts[0].uri == "*" {
            return Ok(self.remove_all_bindings(request));
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
                // Remove by binding key, the same key add/refresh/count use:
                // an RFC 5626 outbound binding (instance:reg-id) and a plain
                // binding (URI) may share a contact URI, so removing by URI
                // could delete the wrong one.
                let key = contact_binding_key(contact);
                let _ = self.location.remove_binding_by_key(&request.aor, &key);
            } else {
                // Add or update binding
                self.add_or_update_binding(request, contact, expires)?;
            }
        }

        // Return current bindings
        Ok(self.fetch_bindings(&request.aor))
    }

    /// Number of bindings `request` would add to the location service,
    /// using the same de-duplication `process_register` applies.
    ///
    /// A contact is an update, not an addition, exactly when the AOR
    /// already has a binding with the same binding key: the
    /// `+sip.instance` / reg-id pair for RFC 5626 outbound contacts,
    /// otherwise the contact URI (RFC 3261 §10.3 step 7: a rebooted UA
    /// replaces its binding, whatever its Call-ID). This is the predicate
    /// the write path (`add_or_update_binding` / `LocationService::add_binding`)
    /// uses, so a contact counted 0 never creates a stored binding. Contacts
    /// sharing a key within the request count once. Contacts whose effective
    /// expiry is 0, a query (no Contact) and `Contact: *` add nothing.
    /// Removals in the same request are not netted off, so the count may
    /// over-state but never under-states the bindings actually added.
    pub fn new_binding_count(&self, request: &RegisterRequest) -> usize {
        if request.contacts.is_empty()
            || (request.contacts.len() == 1 && request.contacts[0].uri == "*")
        {
            return 0;
        }
        let existing = self.location.get_bindings(&request.aor).unwrap_or(&[]);
        let mut seen: Vec<String> = Vec::with_capacity(request.contacts.len());
        let mut added = 0;
        for contact in &request.contacts {
            if self.calculate_expires(contact.expires, request.expires) == 0 {
                continue;
            }
            let key = contact_binding_key(contact);
            let bound = existing.iter().any(|b| b.binding_key() == key);
            if bound || seen.contains(&key) {
                continue;
            }
            seen.push(key);
            added += 1;
        }
        added
    }

    /// Fetches current bindings for an AOR.
    fn fetch_bindings(&self, aor: &str) -> RegisterResponse {
        let bindings: Vec<Binding> = self.location.lookup(aor).into_iter().cloned().collect();

        RegisterResponse::ok(bindings)
    }

    /// Removes all bindings for an AOR.
    fn remove_all_bindings(&mut self, request: &RegisterRequest) -> RegisterResponse {
        // Wildcard removal requires expires=0
        if request.expires != Some(0) {
            return RegisterResponse::error(400, "Bad Request");
        }

        let _ = self.location.remove_all_bindings(&request.aor);
        RegisterResponse::ok(Vec::new())
    }

    /// Adds or updates a binding.
    fn add_or_update_binding(
        &mut self,
        request: &RegisterRequest,
        contact: &ContactInfo,
        expires: u32,
    ) -> RegistrarResult<()> {
        // Same predicate as `LocationService::add_binding` and
        // `new_binding_count`: match on the binding key. A key match with a
        // different contact URI (RFC 5626 flow moved) is replaced whole by
        // `add_binding` below so the stored URI follows the new Contact.
        let key = contact_binding_key(contact);
        // RFC 3261 §10.3 step 7: on a key match with a moved URI, apply the
        // same Call-ID/CSeq ordering `Binding::refresh` enforces before the
        // whole-binding replacement, so a stale/replayed REGISTER cannot
        // overwrite a newer flow.
        if let Some(existing) = self.location.get_binding_by_key_mut(&request.aor, &key)
            && existing.contact_uri() != contact.uri
            && existing.call_id() == request.call_id
            && request.cseq <= existing.cseq()
        {
            return Err(RegistrarError::InvalidContact {
                contact: contact.uri.clone(),
                reason: format!("CSeq {} not higher than {}", request.cseq, existing.cseq()),
            });
        }
        if let Some(existing) = self
            .location
            .get_binding_by_key_mut(&request.aor, &key)
            .filter(|b| b.contact_uri() == contact.uri)
        {
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
    #[must_use]
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
        request: &RegisterRequest,
    ) -> RegistrarResult<RegisterResponse> {
        if let Some(denied) = self.authenticate(request) {
            return Ok(denied);
        }

        // Process the registration
        self.registrar.process_register(request)
    }

    /// Like [`Self::process_register`], but after authentication succeeds
    /// and before any binding changes, calls `admit(total_bindings,
    /// new_bindings)`. When it returns `false` nothing is stored and
    /// `Ok(None)` is returned, so the caller can answer (e.g. 503) knowing
    /// the identity was authenticated.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    pub fn process_register_with_admission<F>(
        &mut self,
        request: &RegisterRequest,
        admit: F,
    ) -> RegistrarResult<Option<RegisterResponse>>
    where
        F: FnOnce(usize, usize) -> bool,
    {
        if let Some(denied) = self.authenticate(request) {
            return Ok(Some(denied));
        }
        let new = self.registrar.new_binding_count(request);
        if new > 0 && !admit(self.registrar.total_bindings(), new) {
            return Ok(None);
        }
        self.registrar.process_register(request).map(Some)
    }

    /// Runs digest authentication; `Some(response)` is the 401/403 to send.
    fn authenticate(&mut self, request: &RegisterRequest) -> Option<RegisterResponse> {
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
                AuthResult::Success { username, .. } => {
                    // RFC 3261 §10.3 step 4: the authenticated identity must
                    // be authorised for this AOR. Users may register only
                    // their own address-of-record (user part is case-sensitive,
                    // §19.1.4).
                    if aor_user(&request.aor) != Some(username.as_str()) {
                        return Some(RegisterResponse::error(
                            403,
                            "Forbidden: credentials do not match address-of-record",
                        ));
                    }
                }
                AuthResult::ChallengeRequired { challenge } => {
                    return Some(RegisterResponse::unauthorized(&challenge));
                }
                AuthResult::StaleNonce { challenge } => {
                    return Some(RegisterResponse::unauthorized(&challenge));
                }
                AuthResult::Failed { reason } => {
                    return Some(RegisterResponse::error(403, format!("Forbidden: {reason}")));
                }
            }
        }

        None
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

/// Returns the user part of an address-of-record (`sip:user@host` → `user`),
/// or `None` when it has no user part.
fn aor_user(aor: &str) -> Option<&str> {
    let without_scheme = aor
        .strip_prefix("sips:")
        .or_else(|| aor.strip_prefix("sip:"))
        .unwrap_or(aor);
    without_scheme.split_once('@').map(|(user, _)| user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{AuthAlgorithm, AuthQop};

    #[test]
    fn aor_user_extracts_user_part() {
        assert_eq!(aor_user("sip:alice@example.com"), Some("alice"));
        assert_eq!(aor_user("sips:alice@example.com:5061"), Some("alice"));
        assert_eq!(aor_user("sip:example.com"), None);
    }

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

    /// Builds a valid Digest Authorization header for `username` against the
    /// nonce in `challenge`, the way a real UA would.
    fn digest_authorization(challenge: &str, username: &str, password: &str) -> String {
        let field = |name: &str| {
            let key = format!("{name}=\"");
            let start = challenge.find(&key).unwrap() + key.len();
            challenge[start..].split('"').next().unwrap().to_string()
        };
        let (realm, nonce) = (field("realm"), field("nonce"));
        let response =
            crate::authentication::compute_digest_response(&crate::authentication::DigestParams {
                username,
                realm: &realm,
                password,
                method: "REGISTER",
                uri: "sip:example.com",
                nonce: &nonce,
                algorithm: AuthAlgorithm::Sha256,
                qop: Some(AuthQop::Auth),
                nc: Some(1),
                cnonce: Some("cnonce1"),
                entity_body: None,
            });
        format!(
            "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", \
             uri=\"sip:example.com\", response=\"{response}\", algorithm=SHA-256, \
             qop=auth, nc=00000001, cnonce=\"cnonce1\""
        )
    }

    /// RFC 3261 §10.3 step 4: the authenticated user may only register their
    /// own address-of-record.
    #[test]
    fn authenticated_user_cannot_register_another_aor() {
        let config = RegistrarConfig::new()
            .with_realm("example.com")
            .with_auth_required(true);
        let mut registrar = AuthenticatedRegistrar::new(config)
            .with_password_lookup(|u, _| (u == "alice").then(|| "secret".to_string()));

        for (aor, expected) in [("sip:bob@example.com", 403), ("sip:alice@example.com", 200)] {
            let challenge = registrar
                .process_register(&test_register_request(aor, "sip:x@10.0.0.5:5060"))
                .unwrap();
            assert_eq!(challenge.status_code, 401);
            let www = challenge.www_authenticate.clone().unwrap();

            let mut request = test_register_request(aor, "sip:x@10.0.0.5:5060");
            request.authorization = Some(digest_authorization(&www, "alice", "secret"));
            let response = registrar.process_register(&request).unwrap();
            assert_eq!(response.status_code, expected, "aor {aor}: {response:?}");
        }
        assert!(registrar.location().has_bindings("sip:alice@example.com"));
        assert!(!registrar.location().has_bindings("sip:bob@example.com"));
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

        let response = registrar.process_register(&request).unwrap();
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

        let response = registrar.process_register(&request).unwrap();
        assert!(response.success);
        assert_eq!(response.contacts.len(), 2);
    }

    #[test]
    fn test_register_fetch() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(&request).unwrap();

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

        let response = registrar.process_register(&fetch_request).unwrap();
        assert!(response.success);
        assert_eq!(response.contacts.len(), 1);
    }

    #[test]
    fn test_register_remove() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(&request).unwrap();

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

        let response = registrar.process_register(&remove_request).unwrap();
        assert!(response.success);
        assert!(response.contacts.is_empty());
    }

    #[test]
    fn test_register_wildcard_removal() {
        let mut registrar = Registrar::with_defaults();

        // First register
        let request =
            test_register_request("sip:alice@example.com", "sip:alice@192.168.1.100:5060");
        registrar.process_register(&request).unwrap();

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

        let response = registrar.process_register(&remove_request).unwrap();
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

        let response = registrar.process_register(&request).unwrap();
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
        registrar.process_register(&request1).unwrap();

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
        let response = registrar.process_register(&request2).unwrap();

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

        let response = registrar.process_register(&request).unwrap();
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

    #[test]
    fn test_new_binding_count_uses_registrar_dedup() {
        let mut registrar = Registrar::with_defaults();
        let aor = "sip:alice@example.com";
        registrar
            .process_register(&test_register_request(aor, "sip:alice@10.0.0.1"))
            .unwrap();
        // Same contact, new Call-ID (reboot): an update.
        let mut reboot = test_register_request(aor, "sip:alice@10.0.0.1");
        reboot.call_id = "call-456@client".to_string();
        assert_eq!(registrar.new_binding_count(&reboot), 0);
        // One bound + one new contact, the new one listed twice.
        let mut mixed = test_register_request(aor, "sip:alice@10.0.0.1");
        mixed.contacts.push(ContactInfo::new("sip:alice@10.0.0.2"));
        mixed.contacts.push(ContactInfo::new("sip:alice@10.0.0.2"));
        assert_eq!(registrar.new_binding_count(&mixed), 1);
        // expires=0, wildcard and query add nothing.
        let mut off = test_register_request(aor, "sip:alice@10.0.0.3");
        off.contacts[0] = ContactInfo::new("sip:alice@10.0.0.3").with_expires(0);
        assert_eq!(registrar.new_binding_count(&off), 0);
        assert_eq!(
            registrar.new_binding_count(&test_register_request(aor, "*")),
            0
        );
        let mut query = test_register_request(aor, "x");
        query.contacts.clear();
        assert_eq!(registrar.new_binding_count(&query), 0);
    }

    #[test]
    fn test_admission_runs_after_auth_and_stores_nothing_when_refused() {
        let mut registrar = AuthenticatedRegistrar::new(RegistrarConfig::default());
        let req = test_register_request("sip:alice@example.com", "sip:alice@10.0.0.1");
        let refused = registrar
            .process_register_with_admission(&req, |_, _| false)
            .unwrap();
        assert!(refused.is_none());
        assert_eq!(registrar.total_bindings(), 0);
        let ok = registrar
            .process_register_with_admission(&req, |total, new| total + new <= 1)
            .unwrap();
        assert_eq!(ok.map(|r| r.status_code), Some(200));
        assert_eq!(registrar.total_bindings(), 1);
    }

    fn outbound_request(aor: &str, uri: &str, instance: &str, cseq: u32) -> RegisterRequest {
        let mut req = test_register_request(aor, uri);
        req.cseq = cseq;
        req.contacts[0].instance_id = Some(instance.to_string());
        req.contacts[0].reg_id = Some(1);
        req
    }

    // NIST 800-53 Rev5: SC-5 -- counting must match what is stored, else a
    // contact counted 0 can push the total past the cap.
    #[test]
    fn test_admission_same_uri_new_instance_at_cap_is_refused() {
        let mut registrar = AuthenticatedRegistrar::new(RegistrarConfig::default());
        let aor = "sip:alice@example.com";
        let cap = |total: usize, new: usize| total + new <= 1;
        let first = outbound_request(aor, "sip:alice@10.0.0.1", "<urn:uuid:a>", 1);
        assert!(
            registrar
                .process_register_with_admission(&first, cap)
                .unwrap()
                .is_some()
        );
        let second = outbound_request(aor, "sip:alice@10.0.0.1", "<urn:uuid:b>", 2);
        assert_eq!(registrar.registrar.new_binding_count(&second), 1);
        // Refused (caller answers 503) and nothing stored.
        assert!(
            registrar
                .process_register_with_admission(&second, cap)
                .unwrap()
                .is_none()
        );
        assert_eq!(registrar.total_bindings(), 1);
        // Without the cap it really is stored as a second binding.
        registrar
            .process_register_with_admission(&second, |_, _| true)
            .unwrap();
        assert_eq!(registrar.total_bindings(), 2);
    }

    #[test]
    fn test_admission_same_instance_new_uri_at_cap_is_accepted() {
        let mut registrar = AuthenticatedRegistrar::new(RegistrarConfig::default());
        let aor = "sip:alice@example.com";
        let cap = |total: usize, new: usize| total + new <= 1;
        let first = outbound_request(aor, "sip:alice@10.0.0.1", "<urn:uuid:a>", 1);
        registrar
            .process_register_with_admission(&first, cap)
            .unwrap();
        let moved = outbound_request(aor, "sip:alice@10.0.0.2", "<urn:uuid:a>", 2);
        assert_eq!(registrar.registrar.new_binding_count(&moved), 0);
        let ok = registrar
            .process_register_with_admission(&moved, cap)
            .unwrap();
        assert_eq!(ok.map(|r| r.status_code), Some(200));
        assert_eq!(registrar.total_bindings(), 1);
        let stored = registrar.registrar.location().get_bindings(aor).unwrap();
        assert_eq!(stored[0].contact_uri(), "sip:alice@10.0.0.2");
    }

    fn outbound_contact(uri: &str) -> ContactInfo {
        let mut c = ContactInfo::new(uri);
        c.instance_id = Some("<urn:uuid:00000000-0000-0000-0000-000000000001>".to_string());
        c.reg_id = Some(1);
        c
    }

    /// Registers an outbound and a plain binding sharing one URI.
    fn shared_uri_registrar(aor: &str, uri: &str) -> Registrar {
        let mut registrar = Registrar::with_defaults();
        let mut req = test_register_request(aor, uri);
        req.contacts = vec![outbound_contact(uri), ContactInfo::new(uri)];
        registrar.process_register(&req).unwrap();
        assert_eq!(registrar.total_bindings(), 2);
        registrar
    }

    // RFC 5626 §6 / RFC 3261 §10.3: expires=0 removes by binding key, so
    // deregistering the outbound flow leaves the plain binding at the same URI.
    #[test]
    fn expires_zero_outbound_removes_only_outbound() {
        let (aor, uri) = ("sip:alice@example.com", "sip:alice@10.0.0.1");
        let mut registrar = shared_uri_registrar(aor, uri);
        let mut req = test_register_request(aor, uri);
        req.cseq = 2;
        req.expires = Some(0);
        req.contacts = vec![outbound_contact(uri)];
        registrar.process_register(&req).unwrap();
        assert_eq!(registrar.total_bindings(), 1);
        let stored = registrar.location().get_bindings(aor).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].binding_key(), uri);
    }

    #[test]
    fn expires_zero_plain_removes_only_plain() {
        let (aor, uri) = ("sip:alice@example.com", "sip:alice@10.0.0.1");
        let mut registrar = shared_uri_registrar(aor, uri);
        let mut req = test_register_request(aor, uri);
        req.cseq = 2;
        req.expires = Some(0);
        registrar.process_register(&req).unwrap();
        assert_eq!(registrar.total_bindings(), 1);
        let stored = registrar.location().get_bindings(aor).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].binding_key(),
            "<urn:uuid:00000000-0000-0000-0000-000000000001>:1"
        );
    }

    #[test]
    fn wildcard_removes_shared_uri_bindings() {
        let (aor, uri) = ("sip:alice@example.com", "sip:alice@10.0.0.1");
        let mut registrar = shared_uri_registrar(aor, uri);
        let mut req = test_register_request(aor, "*");
        req.cseq = 2;
        req.expires = Some(0);
        registrar.process_register(&req).unwrap();
        assert_eq!(registrar.total_bindings(), 0);
        assert!(registrar.location().get_bindings(aor).is_none());
    }

    // RFC 3261 §10.3 step 7: a moved outbound flow with a stale CSeq on the
    // same Call-ID must not replace the stored binding.
    #[test]
    fn moved_flow_with_stale_cseq_is_rejected() {
        let aor = "sip:alice@example.com";
        let mut registrar = Registrar::with_defaults();
        let mut req = test_register_request(aor, "sip:alice@10.0.0.1");
        req.cseq = 5;
        req.contacts = vec![outbound_contact("sip:alice@10.0.0.1")];
        registrar.process_register(&req).unwrap();

        req.cseq = 5;
        req.contacts = vec![outbound_contact("sip:alice@10.0.0.2")];
        assert!(registrar.process_register(&req).is_err());
        let stored = registrar.location().get_bindings(aor).unwrap();
        assert_eq!(stored[0].contact_uri(), "sip:alice@10.0.0.1");

        req.cseq = 6;
        registrar.process_register(&req).unwrap();
        let stored = registrar.location().get_bindings(aor).unwrap();
        assert_eq!(stored[0].contact_uri(), "sip:alice@10.0.0.2");
        assert_eq!(registrar.total_bindings(), 1);
    }
}
