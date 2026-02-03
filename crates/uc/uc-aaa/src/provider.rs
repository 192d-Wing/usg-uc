//! AAA provider trait and types.

use crate::error::AaaResult;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// Authentication request.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Username.
    pub username: String,
    /// Password or credential.
    pub password: String,
    /// Source IP address.
    pub source_ip: Option<IpAddr>,
    /// Called station ID (dialed number).
    pub called_station_id: Option<String>,
    /// Calling station ID (caller number).
    pub calling_station_id: Option<String>,
    /// Service type requested.
    pub service_type: ServiceType,
}

impl AuthRequest {
    /// Creates a new authentication request.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            source_ip: None,
            called_station_id: None,
            calling_station_id: None,
            service_type: ServiceType::SipSession,
        }
    }

    /// Sets the source IP.
    #[must_use]
    pub const fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the called station ID.
    #[must_use]
    pub fn with_called_station_id(mut self, id: impl Into<String>) -> Self {
        self.called_station_id = Some(id.into());
        self
    }

    /// Sets the calling station ID.
    #[must_use]
    pub fn with_calling_station_id(mut self, id: impl Into<String>) -> Self {
        self.calling_station_id = Some(id.into());
        self
    }
}

/// Authentication response.
#[derive(Debug, Clone)]
pub struct AuthResponse {
    /// Whether authentication succeeded.
    pub success: bool,
    /// Session timeout in seconds (if authorized).
    pub session_timeout: Option<u32>,
    /// Attributes returned by the server.
    pub attributes: Vec<AuthAttribute>,
    /// Reject reason (if rejected).
    pub reject_reason: Option<String>,
}

impl AuthResponse {
    /// Creates a successful response.
    #[must_use]
    pub fn accept() -> Self {
        Self {
            success: true,
            session_timeout: None,
            attributes: Vec::new(),
            reject_reason: None,
        }
    }

    /// Creates a rejection response.
    #[must_use]
    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            session_timeout: None,
            attributes: Vec::new(),
            reject_reason: Some(reason.into()),
        }
    }

    /// Sets the session timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: u32) -> Self {
        self.session_timeout = Some(timeout);
        self
    }
}

/// Authentication attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAttribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value.
    pub value: String,
}

/// Service type for authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// SIP session.
    #[default]
    SipSession,
    /// SIP registration.
    Registration,
    /// Outbound call.
    OutboundCall,
    /// Administrative access.
    Administrative,
}

/// Accounting record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountingRecord {
    /// Record type.
    pub record_type: AccountingRecordType,
    /// Session ID.
    pub session_id: String,
    /// Username.
    pub username: String,
    /// Source IP.
    pub source_ip: Option<IpAddr>,
    /// Call duration in seconds (for stop records).
    pub duration_secs: Option<u32>,
    /// Bytes sent.
    pub bytes_sent: Option<u64>,
    /// Bytes received.
    pub bytes_received: Option<u64>,
    /// Termination cause.
    pub termination_cause: Option<String>,
    /// Additional attributes.
    pub attributes: Vec<AuthAttribute>,
}

impl AccountingRecord {
    /// Creates a start record.
    #[must_use]
    pub fn start(session_id: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            record_type: AccountingRecordType::Start,
            session_id: session_id.into(),
            username: username.into(),
            source_ip: None,
            duration_secs: None,
            bytes_sent: None,
            bytes_received: None,
            termination_cause: None,
            attributes: Vec::new(),
        }
    }

    /// Creates a stop record.
    #[must_use]
    pub fn stop(session_id: impl Into<String>, username: impl Into<String>, duration: u32) -> Self {
        Self {
            record_type: AccountingRecordType::Stop,
            session_id: session_id.into(),
            username: username.into(),
            source_ip: None,
            duration_secs: Some(duration),
            bytes_sent: None,
            bytes_received: None,
            termination_cause: None,
            attributes: Vec::new(),
        }
    }

    /// Creates an interim record.
    #[must_use]
    pub fn interim(session_id: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            record_type: AccountingRecordType::Interim,
            session_id: session_id.into(),
            username: username.into(),
            source_ip: None,
            duration_secs: None,
            bytes_sent: None,
            bytes_received: None,
            termination_cause: None,
            attributes: Vec::new(),
        }
    }
}

/// Accounting record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingRecordType {
    /// Session start.
    Start,
    /// Session stop.
    Stop,
    /// Interim update.
    Interim,
}

/// AAA provider trait.
pub trait AaaProvider: Send + Sync + 'static {
    /// Authenticates a user.
    fn authenticate(
        &self,
        request: AuthRequest,
    ) -> Pin<Box<dyn Future<Output = AaaResult<AuthResponse>> + Send + '_>>;

    /// Sends an accounting record.
    fn account(
        &self,
        record: AccountingRecord,
    ) -> Pin<Box<dyn Future<Output = AaaResult<()>> + Send + '_>>;

    /// Returns the provider name.
    fn provider_name(&self) -> &'static str;

    /// Checks if the provider is healthy.
    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_request() {
        let request = AuthRequest::new("user", "pass")
            .with_called_station_id("5551234")
            .with_calling_station_id("5559999");

        assert_eq!(request.username, "user");
        assert_eq!(request.password, "pass");
        assert_eq!(request.called_station_id, Some("5551234".to_string()));
    }

    #[test]
    fn test_auth_response() {
        let accept = AuthResponse::accept().with_timeout(3600);
        assert!(accept.success);
        assert_eq!(accept.session_timeout, Some(3600));

        let reject = AuthResponse::reject("bad password");
        assert!(!reject.success);
        assert_eq!(reject.reject_reason, Some("bad password".to_string()));
    }

    #[test]
    fn test_accounting_records() {
        let start = AccountingRecord::start("sess-001", "user1");
        assert!(matches!(start.record_type, AccountingRecordType::Start));

        let stop = AccountingRecord::stop("sess-001", "user1", 300);
        assert!(matches!(stop.record_type, AccountingRecordType::Stop));
        assert_eq!(stop.duration_secs, Some(300));
    }
}
