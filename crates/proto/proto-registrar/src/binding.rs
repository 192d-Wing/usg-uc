//! Contact binding management.
//!
//! A binding associates a contact URI with an address of record (AOR).

use crate::error::{RegistrarError, RegistrarResult};
use crate::{DEFAULT_EXPIRES, MAX_EXPIRES, MIN_EXPIRES};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Binding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    /// Binding is active.
    Active,
    /// Binding is refreshing.
    Refreshing,
    /// Binding has expired.
    Expired,
    /// Binding was removed.
    Removed,
}

impl std::fmt::Display for BindingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Refreshing => write!(f, "refreshing"),
            Self::Expired => write!(f, "expired"),
            Self::Removed => write!(f, "removed"),
        }
    }
}

/// Contact binding.
///
/// Represents a registration binding between a contact URI and an AOR.
#[derive(Debug, Clone)]
pub struct Binding {
    /// Address of record (canonical URI).
    aor: String,
    /// Contact URI.
    contact_uri: String,
    /// Call-ID from REGISTER request.
    call_id: String,
    /// CSeq from REGISTER request.
    cseq: u32,
    /// Expiration time in seconds.
    expires: u32,
    /// When the binding was created.
    created_at: Instant,
    /// When the binding was last updated.
    updated_at: Instant,
    /// Current state.
    state: BindingState,
    /// Q-value (priority) 0-1.
    q_value: f32,
    /// Source address of the registration.
    source_addr: Option<SocketAddr>,
    /// Instance ID (RFC 5626).
    instance_id: Option<String>,
    /// Reg-ID (RFC 5626).
    reg_id: Option<u32>,
    /// User-Agent header.
    user_agent: Option<String>,
    /// Path header (RFC 3327).
    path: Vec<String>,
}

impl Binding {
    /// Creates a new binding.
    pub fn new(
        aor: impl Into<String>,
        contact_uri: impl Into<String>,
        call_id: impl Into<String>,
        cseq: u32,
    ) -> Self {
        let now = Instant::now();
        Self {
            aor: aor.into(),
            contact_uri: contact_uri.into(),
            call_id: call_id.into(),
            cseq,
            expires: DEFAULT_EXPIRES,
            created_at: now,
            updated_at: now,
            state: BindingState::Active,
            q_value: 1.0,
            source_addr: None,
            instance_id: None,
            reg_id: None,
            user_agent: None,
            path: Vec::new(),
        }
    }

    /// Returns the AOR.
    pub fn aor(&self) -> &str {
        &self.aor
    }

    /// Returns the contact URI.
    pub fn contact_uri(&self) -> &str {
        &self.contact_uri
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the CSeq.
    pub fn cseq(&self) -> u32 {
        self.cseq
    }

    /// Returns the expiration time in seconds.
    pub fn expires(&self) -> u32 {
        self.expires
    }

    /// Returns when the binding was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when the binding was last updated.
    pub fn updated_at(&self) -> Instant {
        self.updated_at
    }

    /// Returns the current state.
    pub fn state(&self) -> BindingState {
        self.state
    }

    /// Returns the Q-value.
    pub fn q_value(&self) -> f32 {
        self.q_value
    }

    /// Returns the source address.
    pub fn source_addr(&self) -> Option<SocketAddr> {
        self.source_addr
    }

    /// Returns the instance ID.
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    /// Returns the reg-ID.
    pub fn reg_id(&self) -> Option<u32> {
        self.reg_id
    }

    /// Returns the User-Agent.
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Returns the path.
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// Sets the expiration time.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn set_expires(&mut self, expires: u32) -> RegistrarResult<()> {
        if expires > 0 && expires < MIN_EXPIRES {
            return Err(RegistrarError::InvalidExpires {
                requested: expires,
                min: MIN_EXPIRES,
            });
        }
        self.expires = expires.min(MAX_EXPIRES);
        Ok(())
    }

    /// Sets the Q-value.
    pub fn set_q_value(&mut self, q: f32) {
        self.q_value = q.clamp(0.0, 1.0);
    }

    /// Sets the source address.
    pub fn set_source_addr(&mut self, addr: SocketAddr) {
        self.source_addr = Some(addr);
    }

    /// Sets the instance ID.
    pub fn set_instance_id(&mut self, id: impl Into<String>) {
        self.instance_id = Some(id.into());
    }

    /// Sets the reg-ID.
    pub fn set_reg_id(&mut self, reg_id: u32) {
        self.reg_id = Some(reg_id);
    }

    /// Sets the User-Agent.
    pub fn set_user_agent(&mut self, ua: impl Into<String>) {
        self.user_agent = Some(ua.into());
    }

    /// Sets the path.
    pub fn set_path(&mut self, path: Vec<String>) {
        self.path = path;
    }

    /// Refreshes the binding.
    ///
    /// Updates the binding if the Call-ID matches and CSeq is higher,
    /// or if the Call-ID is different.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn refresh(&mut self, call_id: &str, cseq: u32, expires: u32) -> RegistrarResult<()> {
        // Check if this is a valid refresh
        if call_id == self.call_id && cseq <= self.cseq {
            return Err(RegistrarError::InvalidContact {
                contact: self.contact_uri.clone(),
                reason: format!("CSeq {} not higher than {}", cseq, self.cseq),
            });
        }

        self.call_id = call_id.to_string();
        self.cseq = cseq;
        self.set_expires(expires)?;
        self.updated_at = Instant::now();
        self.state = BindingState::Active;

        Ok(())
    }

    /// Checks if the binding has expired.
    pub fn is_expired(&self) -> bool {
        if self.state == BindingState::Removed {
            return true;
        }
        if self.expires == 0 {
            return true;
        }
        self.time_until_expiry() == Duration::ZERO
    }

    /// Returns time until expiry.
    pub fn time_until_expiry(&self) -> Duration {
        let expires = Duration::from_secs(self.expires as u64);
        let elapsed = self.updated_at.elapsed();

        if elapsed >= expires {
            Duration::ZERO
        } else {
            // Safe because we checked elapsed < expires above
            expires.saturating_sub(elapsed)
        }
    }

    /// Returns remaining seconds until expiry (for RFC 3261 §10.3 response).
    pub fn remaining_seconds(&self) -> u32 {
        self.time_until_expiry().as_secs() as u32
    }

    /// Returns time since last update.
    pub fn time_since_update(&self) -> Duration {
        self.updated_at.elapsed()
    }

    /// Marks the binding as expired.
    pub fn expire(&mut self) {
        self.state = BindingState::Expired;
    }

    /// Removes the binding (sets expires to 0).
    pub fn remove(&mut self) {
        self.expires = 0;
        self.state = BindingState::Removed;
    }

    /// Returns whether this is an outbound binding (RFC 5626).
    pub fn is_outbound(&self) -> bool {
        self.instance_id.is_some() && self.reg_id.is_some()
    }

    /// Returns a unique key for this binding.
    ///
    /// For outbound bindings, uses instance-id + reg-id.
    /// Otherwise, uses the contact URI.
    pub fn binding_key(&self) -> String {
        if let (Some(instance_id), Some(reg_id)) = (&self.instance_id, self.reg_id) {
            format!("{instance_id}:{reg_id}")
        } else {
            self.contact_uri.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_binding() -> Binding {
        Binding::new(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "call-123@client",
            1,
        )
    }

    #[test]
    fn test_binding_creation() {
        let binding = test_binding();
        assert_eq!(binding.aor(), "sip:alice@example.com");
        assert_eq!(binding.contact_uri(), "sip:alice@192.168.1.100:5060");
        assert_eq!(binding.call_id(), "call-123@client");
        assert_eq!(binding.cseq(), 1);
        assert_eq!(binding.expires(), DEFAULT_EXPIRES);
        assert_eq!(binding.state(), BindingState::Active);
    }

    #[test]
    fn test_binding_state_display() {
        assert_eq!(BindingState::Active.to_string(), "active");
        assert_eq!(BindingState::Expired.to_string(), "expired");
    }

    #[test]
    fn test_set_expires() {
        let mut binding = test_binding();

        // Valid expires
        binding.set_expires(1800).unwrap();
        assert_eq!(binding.expires(), 1800);

        // Capped at max
        binding.set_expires(100000).unwrap();
        assert_eq!(binding.expires(), MAX_EXPIRES);

        // Too low (non-zero)
        assert!(binding.set_expires(30).is_err());

        // Zero is allowed (removal)
        binding.set_expires(0).unwrap();
        assert_eq!(binding.expires(), 0);
    }

    #[test]
    fn test_q_value() {
        let mut binding = test_binding();
        assert!((binding.q_value() - 1.0).abs() < f32::EPSILON);

        binding.set_q_value(0.5);
        assert!((binding.q_value() - 0.5).abs() < f32::EPSILON);

        // Clamped to valid range
        binding.set_q_value(-0.5);
        assert!((binding.q_value() - 0.0).abs() < f32::EPSILON);

        binding.set_q_value(1.5);
        assert!((binding.q_value() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_refresh() {
        let mut binding = test_binding();

        // Refresh with higher CSeq, same Call-ID
        binding.refresh("call-123@client", 2, 1800).unwrap();
        assert_eq!(binding.cseq(), 2);
        assert_eq!(binding.expires(), 1800);

        // Refresh with different Call-ID
        binding.refresh("call-456@client", 1, 3600).unwrap();
        assert_eq!(binding.call_id(), "call-456@client");

        // Should fail: same Call-ID, lower CSeq
        assert!(binding.refresh("call-456@client", 1, 3600).is_err());
    }

    #[test]
    fn test_expiration() {
        let mut binding = test_binding();

        // Not expired initially
        assert!(!binding.is_expired());
        assert!(binding.time_until_expiry() > Duration::ZERO);

        // Remove makes it expired
        binding.remove();
        assert!(binding.is_expired());
        assert_eq!(binding.state(), BindingState::Removed);
    }

    #[test]
    fn test_outbound_binding() {
        let mut binding = test_binding();
        assert!(!binding.is_outbound());

        binding.set_instance_id("<urn:uuid:12345678-1234-1234-1234-123456789abc>");
        assert!(!binding.is_outbound()); // Need both

        binding.set_reg_id(1);
        assert!(binding.is_outbound());
    }

    #[test]
    fn test_binding_key() {
        let mut binding = test_binding();

        // Without outbound params, key is contact URI
        assert_eq!(binding.binding_key(), "sip:alice@192.168.1.100:5060");

        // With outbound params, key is instance-id:reg-id
        binding.set_instance_id("<urn:uuid:test>");
        binding.set_reg_id(1);
        assert_eq!(binding.binding_key(), "<urn:uuid:test>:1");
    }

    #[test]
    fn test_source_addr() {
        let mut binding = test_binding();
        assert!(binding.source_addr().is_none());

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        binding.set_source_addr(addr);
        assert_eq!(binding.source_addr(), Some(addr));
    }

    #[test]
    fn test_path() {
        let mut binding = test_binding();
        assert!(binding.path().is_empty());

        let path = vec![
            "<sip:edge.example.com;lr>".to_string(),
            "<sip:proxy.example.com;lr>".to_string(),
        ];
        binding.set_path(path.clone());
        assert_eq!(binding.path(), &path);
    }

    #[test]
    fn test_user_agent() {
        let mut binding = test_binding();
        assert!(binding.user_agent().is_none());

        binding.set_user_agent("TestPhone/1.0");
        assert_eq!(binding.user_agent(), Some("TestPhone/1.0"));
    }
}
