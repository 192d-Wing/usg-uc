//! Audit event types per NIST 800-53 Rev5 AU-2.
//!
//! ## NIST 800-53 Rev5: AU-2 (Event Logging)
//!
//! The organization determines that the information system is capable of
//! auditing the following events:
//!
//! - Authentication attempts (success/failure)
//! - Authorization decisions
//! - System configuration changes
//! - Cryptographic key operations
//! - Call establishment and termination
//! - Security-relevant events

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uc_types::attestation::AttestationLevel;
use uc_types::identifier::CallId;

/// Audit event category.
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Call-related events.
    Call,
    /// Authentication events.
    Authentication,
    /// Authorization events.
    Authorization,
    /// Configuration changes.
    Configuration,
    /// Cryptographic operations.
    Cryptographic,
    /// Security alerts and violations.
    Security,
    /// System lifecycle events.
    System,
}

/// Auditable event.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
///
/// Each event contains:
/// - Type of event
/// - When the event occurred (added by [`AuditRecord`](crate::record::AuditRecord))
/// - Where the event occurred (source)
/// - Source of the event (identity)
/// - Outcome of the event (success/failure)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Call attempt initiated.
    CallAttempt(CallAttempt),

    /// Call successfully established.
    CallEstablished(CallEstablished),

    /// Call terminated.
    CallTerminated(CallTerminated),

    /// Authentication attempt.
    AuthenticationAttempt(AuthenticationAttempt),

    /// Authorization decision.
    AuthorizationDecision(AuthorizationDecision),

    /// Configuration change.
    ConfigurationChange(ConfigurationChange),

    /// Cryptographic key operation.
    CryptoKeyOperation(CryptoKeyOperation),

    /// Denial of Service detected.
    DosDetected(DosDetected),

    /// STIR/SHAKEN verification result.
    StirShakenVerification(StirShakenVerification),

    /// Rate limit triggered.
    RateLimitTriggered(RateLimitTriggered),

    /// System startup.
    SystemStartup(SystemStartup),

    /// System shutdown.
    SystemShutdown(SystemShutdown),
}

impl AuditEvent {
    /// Returns the event type category.
    #[must_use]
    pub const fn event_type(&self) -> AuditEventType {
        match self {
            Self::CallAttempt(_) | Self::CallEstablished(_) | Self::CallTerminated(_) => {
                AuditEventType::Call
            }
            Self::AuthenticationAttempt(_) => AuditEventType::Authentication,
            Self::AuthorizationDecision(_) => AuditEventType::Authorization,
            Self::ConfigurationChange(_) => AuditEventType::Configuration,
            Self::CryptoKeyOperation(_) => AuditEventType::Cryptographic,
            Self::DosDetected(_)
            | Self::StirShakenVerification(_)
            | Self::RateLimitTriggered(_) => AuditEventType::Security,
            Self::SystemStartup(_) | Self::SystemShutdown(_) => AuditEventType::System,
        }
    }
}

/// Call attempt event.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallAttempt {
    /// Call identifier.
    pub call_id: CallId,
    /// Calling party URI.
    pub from_uri: String,
    /// Called party URI.
    pub to_uri: String,
    /// Source IP address.
    pub source_ip: IpAddr,
    /// STIR/SHAKEN attestation level, if present.
    pub attestation: Option<AttestationLevel>,
}

/// Call established event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEstablished {
    /// Call identifier.
    pub call_id: CallId,
    /// Time call was established.
    pub established_at: DateTime<Utc>,
}

/// Call termination reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// Normal hangup by caller.
    CallerHangup,
    /// Normal hangup by callee.
    CalleeHangup,
    /// Call rejected by callee.
    Rejected,
    /// Call canceled before answer.
    Canceled,
    /// Call failed (network error, etc.).
    Failed,
    /// Call timed out.
    Timeout,
    /// Terminated by policy.
    PolicyTerminated,
}

/// Call terminated event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTerminated {
    /// Call identifier.
    pub call_id: CallId,
    /// Call duration in seconds.
    pub duration_secs: u64,
    /// Termination reason.
    pub reason: TerminationReason,
}

/// Authentication attempt event.
///
/// ## NIST 800-53 Rev5: IA-2 (Identification and Authentication)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationAttempt {
    /// Username or identity attempting authentication.
    pub identity: String,
    /// Source IP address.
    pub source_ip: IpAddr,
    /// Whether authentication succeeded.
    pub success: bool,
    /// Failure reason if unsuccessful.
    pub failure_reason: Option<String>,
    /// Authentication method used.
    pub method: AuthMethod,
}

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// SIP Digest authentication.
    Digest,
    /// TLS client certificate.
    TlsCertificate,
    /// API key.
    ApiKey,
    /// JWT token.
    Jwt,
}

/// Authorization decision event.
///
/// ## NIST 800-53 Rev5: AC-3 (Access Enforcement)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Identity making the request.
    pub identity: String,
    /// Resource being accessed.
    pub resource: String,
    /// Action being performed.
    pub action: String,
    /// Whether access was granted.
    pub granted: bool,
    /// Policy that made the decision.
    pub policy: String,
}

/// Configuration change type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigChangeType {
    /// Configuration loaded.
    Loaded,
    /// Configuration reloaded.
    Reloaded,
    /// Configuration modified.
    Modified,
}

/// Configuration change event.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationChange {
    /// Administrator who made the change.
    pub admin: String,
    /// Type of change.
    pub change_type: ConfigChangeType,
    /// Description of what changed.
    pub description: String,
}

/// Cryptographic key operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOperationType {
    /// Key generated.
    Generated,
    /// Key loaded.
    Loaded,
    /// Key rotated.
    Rotated,
    /// Key destroyed.
    Destroyed,
}

/// Cryptographic key operation event.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKeyOperation {
    /// Key identifier.
    pub key_id: String,
    /// Type of operation.
    pub operation: KeyOperationType,
    /// Algorithm associated with the key.
    pub algorithm: String,
}

/// `DoS` attack type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DosType {
    /// Global rate limit exceeded.
    GlobalRateExceeded,
    /// Per-IP rate limit exceeded.
    IpRateExceeded,
    /// Malformed message flood.
    MalformedFlood,
    /// SYN flood detected.
    SynFlood,
}

/// Denial of Service detected event.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosDetected {
    /// Source IP address.
    pub source_ip: IpAddr,
    /// Type of attack detected.
    pub attack_type: DosType,
    /// Additional details.
    pub details: String,
}

/// STIR/SHAKEN verification result event.
///
/// ## NIST 800-53 Rev5: IA-9 (Service Identification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirShakenVerification {
    /// Call identifier.
    pub call_id: CallId,
    /// Whether verification succeeded.
    pub success: bool,
    /// Attestation level if successful.
    pub attestation: Option<AttestationLevel>,
    /// Failure reason if unsuccessful.
    pub failure_reason: Option<String>,
}

/// Rate limit triggered event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitTriggered {
    /// Source IP address.
    pub source_ip: IpAddr,
    /// Rate limit that was exceeded.
    pub limit_name: String,
    /// Current request count.
    pub request_count: u64,
    /// Limit threshold.
    pub threshold: u64,
}

/// System startup event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStartup {
    /// Version of the SBC.
    pub version: String,
    /// Configuration file path.
    pub config_path: String,
}

/// System shutdown event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemShutdown {
    /// Shutdown reason.
    pub reason: String,
    /// Whether shutdown was graceful.
    pub graceful: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_categorization() {
        let call_event = AuditEvent::CallAttempt(CallAttempt {
            call_id: CallId::new("test"),
            from_uri: "sip:a@example.com".to_string(),
            to_uri: "sip:b@example.com".to_string(),
            source_ip: "::1".parse().expect("valid loopback"),
            attestation: None,
        });

        assert_eq!(call_event.event_type(), AuditEventType::Call);
    }

    #[test]
    fn test_event_serialization() {
        let event = AuditEvent::AuthenticationAttempt(AuthenticationAttempt {
            identity: "alice".to_string(),
            source_ip: "::1".parse().expect("valid loopback"),
            success: true,
            failure_reason: None,
            method: AuthMethod::Digest,
        });

        let json = serde_json::to_string(&event).expect("serialize event");
        assert!(json.contains("authentication_attempt"));
        assert!(json.contains("alice"));
    }
}
