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

    /// A call failed over from one trunk to the next.
    TrunkFailover(TrunkFailover),

    /// A trunk became reachable or unreachable.
    TrunkReachabilityChanged(TrunkReachabilityChanged),

    /// The CDR pipeline failed to write or is dropping records.
    CdrSinkFailure(CdrSinkFailure),

    /// A CDR file was closed and its digest sidecar written.
    CdrFileRotated(CdrFileRotated),

    /// CDRs were read in bulk through the management plane.
    CdrExport(CdrExport),

    /// Outbound `PASSporT` signing failed (call continues unsigned).
    StirSignFailure(StirSignFailure),

    /// Inbound Identity verification failed (aggregated per trunk + reason).
    StirVerifyFailure(StirVerifyFailure),

    /// STI-CR trust anchors (re)loaded.
    StirTrustAnchorsReloaded(StirTrustAnchorsReloaded),

    /// STI-CR trust-anchor reload failed; the previous set stays active.
    StirTrustAnchorReloadFailed(StirTrustAnchorReloadFailed),

    /// The STIR signing key and certificate were loaded and self-checked.
    StirKeyLoaded(StirKeyLoaded),

    /// STIR failure audit events were dropped because an aggregation table
    /// was full (AU-5 capacity alert).
    StirAuditEventsDropped(StirAuditEventsDropped),

    /// A managed user account was created, modified or removed (or the
    /// attempt failed).
    AccountManagement(AccountManagement),

    /// Audit records were lost (queue full, sink write failure) or a torn
    /// tail was found at startup. Chained by the writer so the loss is
    /// visible inside the trail itself.
    AuditRecordsDropped(AuditRecordsDropped),
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
            Self::AuthorizationDecision(_) | Self::CdrExport(_) => AuditEventType::Authorization,
            Self::CryptoKeyOperation(_) | Self::StirSignFailure(_) | Self::StirKeyLoaded(_) => {
                AuditEventType::Cryptographic
            }
            Self::DosDetected(_)
            | Self::StirShakenVerification(_)
            | Self::RateLimitTriggered(_)
            | Self::StirVerifyFailure(_)
            | Self::StirAuditEventsDropped(_)
            | Self::AuditRecordsDropped(_) => AuditEventType::Security,
            Self::ConfigurationChange(_)
            | Self::StirTrustAnchorsReloaded(_)
            | Self::StirTrustAnchorReloadFailed(_)
            | Self::AccountManagement(_) => AuditEventType::Configuration,
            Self::SystemStartup(_)
            | Self::SystemShutdown(_)
            | Self::TrunkFailover(_)
            | Self::TrunkReachabilityChanged(_)
            | Self::CdrSinkFailure(_)
            | Self::CdrFileRotated(_) => AuditEventType::System,
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
    /// Source IP address of the request, when known (additive; absent in
    /// records written before it existed).
    ///
    /// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
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
    /// Outcome of the operation. Omitted from the serialized form on
    /// success so records written before this field existed re-serialize
    /// byte-identically (canonical form, see `record::parse_canonical`).
    ///
    /// NIST 800-53 Rev5: AU-3 (outcome of the event)
    #[serde(default, skip_serializing_if = "KeyOperationOutcome::is_success")]
    pub outcome: KeyOperationOutcome,
    /// Failure reason (sanitized: no CR/LF, bounded length). Must never
    /// contain key material or full file paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Maximum length (bytes) of [`CryptoKeyOperation::reason`].
pub const MAX_KEY_OPERATION_REASON_LEN: usize = 256;

impl CryptoKeyOperation {
    /// Successful key operation.
    #[must_use]
    pub fn success(
        key_id: impl Into<String>,
        operation: KeyOperationType,
        algorithm: impl Into<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            operation,
            algorithm: algorithm.into(),
            outcome: KeyOperationOutcome::Success,
            reason: None,
        }
    }

    /// Failed key operation. `reason` is sanitized: control characters
    /// (including CR/LF) are replaced and it is truncated to
    /// [`MAX_KEY_OPERATION_REASON_LEN`] bytes on a char boundary.
    ///
    /// NIST 800-53 Rev5: AU-3, SI-10 (no log injection via reason)
    #[must_use]
    pub fn failure(
        key_id: impl Into<String>,
        operation: KeyOperationType,
        algorithm: impl Into<String>,
        reason: &str,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            operation,
            algorithm: algorithm.into(),
            outcome: KeyOperationOutcome::Failure,
            reason: Some(sanitize_reason(reason)),
        }
    }
}

fn sanitize_reason(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len().min(MAX_KEY_OPERATION_REASON_LEN));
    for c in reason.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > MAX_KEY_OPERATION_REASON_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// Outcome of a [`CryptoKeyOperation`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOperationOutcome {
    /// Operation succeeded.
    #[default]
    Success,
    /// Operation failed.
    Failure,
}

impl KeyOperationOutcome {
    /// `true` for [`KeyOperationOutcome::Success`].
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
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

/// Why a call failed over to the next trunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverReason {
    /// The trunk answered with a failover status (408/5xx).
    Status(u16),
    /// No response before Timer B (RFC 3261 §17.1.1.2).
    Timeout,
    /// The INVITE could not be sent (RFC 3261 §8.1.3.1).
    TransportError,
}

/// Trunk failover event.
///
/// ## NIST 800-53 Rev5: CP-8 (Telecommunications Services), AU-2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkFailover {
    /// Call identifier (A-leg Call-ID).
    pub call_id: CallId,
    /// Trunk group of the failed trunk.
    pub group_id: String,
    /// Trunk that failed.
    pub failed_trunk_id: String,
    /// Why the trunk failed.
    pub reason: FailoverReason,
    /// Trunk tried next.
    pub next_trunk_id: String,
}

/// Where a trunk reachability change was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilitySource {
    /// Local SIP OPTIONS health probe.
    Options,
    /// Trunk-services agent status publish.
    Agent,
}

/// Trunk reachability change event.
///
/// ## NIST 800-53 Rev5: CP-8 (Telecommunications Services), AU-2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkReachabilityChanged {
    /// Trunk identifier.
    pub trunk_id: String,
    /// New reachability.
    pub reachable: bool,
    /// Detector of the change.
    pub source: ReachabilitySource,
}

/// CDR pipeline failure.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrSinkFailure {
    /// `"write_error"`, `"queue_full"` or `"writer_dead"`.
    pub reason: String,
    /// Error text or drop count; never record content.
    pub detail: String,
}

/// CDR file rotation.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AU-11
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrFileRotated {
    /// Closed file path.
    pub file: String,
    /// Hex SHA-384 of the closed file.
    pub sha384: String,
}

/// Account-management action.
///
/// ## NIST 800-53 Rev5: AC-2 (Account Management)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAction {
    /// Account created.
    Create,
    /// Account modified (attributes, credential or enabled flag).
    Update,
    /// Account removed.
    Delete,
}

/// A management-plane change to a managed (SIP) user account.
///
/// Never carries the password, HA1 or any other authenticator.
///
/// ## NIST 800-53 Rev5: AC-2 (Account Management), AC-2(4) (Automated Audit
/// Actions), AU-3 (Content of Audit Records)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountManagement {
    /// Authenticated principal that requested the change.
    pub actor: String,
    /// Issuer that authenticated `actor` (OIDC `iss`), when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_issuer: Option<String>,
    /// Target account identifier (empty when not yet assigned/unknown).
    pub target_user_id: String,
    /// Target account username, when known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_username: String,
    /// What was attempted.
    pub action: AccountAction,
    /// Whether the change was applied.
    pub success: bool,
    /// Fixed failure token (`not_found`, `already_exists`, `invalid`,
    /// `storage`); `None` on success. Never contains backend error text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Source IP address of the request, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// Which attribute groups an update touched (`password`, `enabled`,
    /// `username`, `profile`), so credential resets and enable/disable are
    /// distinguishable from edits. Names only, never values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<String>,
}

/// Bulk CDR read (export) by a management user. CDRs carry PII.
///
/// ## NIST 800-53 Rev5: AU-2, AC-3, SI-12
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrExport {
    /// Authenticated principal: the REST user in sbc-api; in the daemon the
    /// gRPC client certificate name (`cert:<name>`), or `unauthenticated`
    /// on a loopback listener without mTLS.
    pub user: String,
    /// End user the authenticated principal says it acts for (gRPC
    /// `x-sbc-user`). Caller-asserted, never the principal. Additive.
    ///
    /// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on_behalf_of: String,
    /// Filter as given (query string form).
    pub filter: String,
    /// Records returned.
    pub count: u64,
    /// Export format.
    pub format: String,
    /// Outcome: `success`, `truncated`, `failed`, `busy` or `denied`.
    ///
    /// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
    #[serde(default)]
    pub outcome: String,
}

/// Outbound STIR signing failure.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, SC-13
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirSignFailure {
    /// Hex SHA-384 prefix of the A-leg Call-ID (no raw Call-ID).
    pub call_id_hash: String,
    /// Egress trunk.
    pub trunk: String,
    /// Fixed reason token: `key-unusable`, `cert-expired`, `no-attestation`,
    /// `bad-number`.
    pub reason: String,
    /// Failures folded into this event (>= 1); one event is emitted per
    /// (`trunk`, `reason`) per aggregation window.
    pub count: u64,
}

/// Inbound STIR verification failures, aggregated.
///
/// One event is emitted per (`source_trunk`, `reason`) per aggregation window
/// so an attacker sending bad Identity headers cannot flood the audit log.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, IA-9, SI-10
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirVerifyFailure {
    /// Hex SHA-384 prefix of the first Call-ID in the window.
    pub call_id_hash: String,
    /// Ingress trunk.
    pub source_trunk: String,
    /// Source IP of the first failure in the window.
    pub source_ip: Option<IpAddr>,
    /// Host of the `x5u` URL (no path), if known.
    pub x5u_host: Option<String>,
    /// Fixed failure reason token (see `proto_stir_shaken::FailureReason`).
    pub reason: String,
    /// Action taken: `pass`, `mark` or `reject`.
    pub action: String,
    /// Failures folded into this event (>= 1).
    pub count: u64,
}

/// Trust-anchor set loaded.
///
/// ## NIST 800-53 Rev5: SC-17 (PKI Certificates), CM-6
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirTrustAnchorsReloaded {
    /// Anchors loaded.
    pub count: u64,
    /// Hex SHA-384 over the concatenated anchor DER.
    pub sha384: String,
}

/// Trust-anchor reload failure.
///
/// ## NIST 800-53 Rev5: SC-17, AU-5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirTrustAnchorReloadFailed {
    /// Error text (path / parse error; never key material).
    pub reason: String,
}

/// STIR failure events dropped since the previous report because an
/// aggregation table was full of live keys.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirAuditEventsDropped {
    /// Events dropped since the previous report (>= 1).
    pub count: u64,
    /// Total dropped since startup.
    pub total: u64,
}

/// Audit records lost since the previous marker of the same reason.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures), AU-9
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecordsDropped {
    /// Records lost since the previous marker of this reason (0 for a torn
    /// tail whose fragment was not a whole record).
    pub count: u64,
    /// Total lost for this reason since startup.
    pub total: u64,
    /// Why the records were lost.
    pub reason: AuditDropReason,
}

/// Cause of an [`AuditRecordsDropped`] marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDropReason {
    /// The bounded writer queue was full.
    QueueFull,
    /// The sink failed to persist the record (e.g. ENOSPC).
    SinkWriteFailed,
    /// The audit file ended in an unterminated or unreadable tail at open
    /// (crash-torn write or tamper); the chain resumes after the last good
    /// record.
    TornTail,
}

/// Signing key loaded.
///
/// ## NIST 800-53 Rev5: SC-12, SC-17
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StirKeyLoaded {
    /// Hex SHA-384 fingerprint of the signing certificate.
    pub cert_fingerprint_sha384: String,
    /// Certificate `notAfter` (Unix seconds).
    pub not_after: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn stir_events_serialize_and_categorize() {
        let e = AuditEvent::StirVerifyFailure(StirVerifyFailure {
            call_id_hash: "ab".into(),
            source_trunk: "carrier".into(),
            source_ip: None,
            x5u_host: Some("cert.example.invalid".into()),
            reason: "bad-signature".into(),
            action: "mark".into(),
            count: 3,
        });
        assert_eq!(e.event_type(), AuditEventType::Security);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""type":"stir_verify_failure""#), "{json}");
        let k = AuditEvent::StirKeyLoaded(StirKeyLoaded {
            cert_fingerprint_sha384: "00".into(),
            not_after: 1,
        });
        assert_eq!(k.event_type(), AuditEventType::Cryptographic);
        let d = AuditEvent::StirAuditEventsDropped(StirAuditEventsDropped { count: 2, total: 5 });
        assert_eq!(d.event_type(), AuditEventType::Security);
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            json.contains(r#""type":"stir_audit_events_dropped""#),
            "{json}"
        );
    }

    use super::*;

    #[test]
    fn crypto_key_operation_success_is_byte_compatible() {
        // Golden: pre-outcome-field serialization must be unchanged.
        let e = AuditEvent::CryptoKeyOperation(CryptoKeyOperation::success(
            "k",
            KeyOperationType::Loaded,
            "ECDSA-P384",
        ));
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(
            json,
            r#"{"type":"crypto_key_operation","key_id":"k","operation":"Loaded","algorithm":"ECDSA-P384"}"#
        );
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        let op = match back {
            AuditEvent::CryptoKeyOperation(op) => Some(op),
            _ => None,
        }
        .unwrap();
        assert_eq!(op.outcome, KeyOperationOutcome::Success);
        assert!(op.reason.is_none());
    }

    #[test]
    fn crypto_key_operation_failure_round_trips_and_sanitizes() {
        let long = format!("bad\r\nINJECT {}", "x".repeat(400));
        let op = CryptoKeyOperation::failure("k", KeyOperationType::Loaded, "ECDSA-P384", &long);
        let r = op.reason.clone().unwrap();
        assert!(!r.contains('\n') && !r.contains('\r'));
        assert!(r.len() <= MAX_KEY_OPERATION_REASON_LEN);
        let e = AuditEvent::CryptoKeyOperation(op);
        assert_eq!(e.event_type(), AuditEventType::Cryptographic);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""outcome":"failure""#), "{json}");
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        let op = match back {
            AuditEvent::CryptoKeyOperation(op) => Some(op),
            _ => None,
        }
        .unwrap();
        assert_eq!(op.outcome, KeyOperationOutcome::Failure);
    }

    #[test]
    fn audit_records_dropped_serializes_snake_case_and_is_security() {
        let d = AuditEvent::AuditRecordsDropped(AuditRecordsDropped {
            count: 3,
            total: 7,
            reason: AuditDropReason::QueueFull,
        });
        assert_eq!(d.event_type(), AuditEventType::Security);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(
            json,
            r#"{"type":"audit_records_dropped","count":3,"total":7,"reason":"queue_full"}"#
        );
        let json = serde_json::to_string(&AuditDropReason::SinkWriteFailed).unwrap();
        assert_eq!(json, r#""sink_write_failed""#);
        let json = serde_json::to_string(&AuditDropReason::TornTail).unwrap();
        assert_eq!(json, r#""torn_tail""#);
    }

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

    fn as_authz(event: AuditEvent) -> Option<AuthorizationDecision> {
        match event {
            AuditEvent::AuthorizationDecision(d) => Some(d),
            _ => None,
        }
    }

    #[test]
    fn authorization_decision_source_ip_is_additive() {
        let old = r#"{"type":"authorization_decision","identity":"a","resource":"sip:911@x","action":"INVITE","granted":false,"policy":"vps"}"#;
        let d = as_authz(serde_json::from_str(old).unwrap()).unwrap();
        assert_eq!(d.source_ip, None);
        let none = serde_json::to_string(&AuditEvent::AuthorizationDecision(d.clone())).unwrap();
        assert!(!none.contains("source_ip"));

        let with = AuditEvent::AuthorizationDecision(AuthorizationDecision {
            source_ip: Some("192.0.2.7".parse().unwrap()),
            ..d
        });
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.contains(r#""source_ip":"192.0.2.7""#));
        let back = as_authz(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(back.source_ip, Some("192.0.2.7".parse().unwrap()));
    }

    #[test]
    fn cdr_export_is_authorization_and_outcome_is_additive() {
        let old = r#"{"user":"op1","filter":"","count":2,"format":"csv"}"#;
        let e: CdrExport = serde_json::from_str(old).unwrap();
        assert_eq!(e.outcome, "");
        assert_eq!(e.on_behalf_of, "");
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("on_behalf_of"), "{json}");
        assert_eq!(
            AuditEvent::CdrExport(e).event_type(),
            AuditEventType::Authorization
        );
    }

    #[test]
    fn trunk_events_serialize_and_categorize() {
        let failover = AuditEvent::TrunkFailover(TrunkFailover {
            call_id: CallId::new("c\"1"),
            group_id: "g".to_string(),
            failed_trunk_id: "t1".to_string(),
            reason: FailoverReason::Status(503),
            next_trunk_id: "t2".to_string(),
        });
        assert_eq!(failover.event_type(), AuditEventType::System);
        let json = serde_json::to_string(&failover).unwrap();
        assert!(json.contains(r#""type":"trunk_failover""#));
        assert!(json.contains(r#""reason":{"status":503}"#));
        assert!(json.contains(r#"c\"1"#), "call_id JSON-escaped: {json}");
        let t = serde_json::to_string(&FailoverReason::TransportError).unwrap();
        assert_eq!(t, r#""transport_error""#);

        let reach = AuditEvent::TrunkReachabilityChanged(TrunkReachabilityChanged {
            trunk_id: "t1".to_string(),
            reachable: false,
            source: ReachabilitySource::Options,
        });
        assert_eq!(reach.event_type(), AuditEventType::System);
        let json = serde_json::to_string(&reach).unwrap();
        assert!(json.contains(r#""type":"trunk_reachability_changed""#));
        assert!(json.contains(r#""source":"options""#));
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AuditEvent::TrunkReachabilityChanged(r) if !r.reachable));
    }

    #[test]
    fn account_management_serializes_without_secrets() {
        let ev = AuditEvent::AccountManagement(AccountManagement {
            actor: "op1".to_string(),
            actor_issuer: Some("https://idp.example.invalid".to_string()),
            target_user_id: "u-1".to_string(),
            target_username: "alice".to_string(),
            action: AccountAction::Create,
            success: false,
            failure_reason: Some("already_exists".to_string()),
            source_ip: None,
            changed: vec!["password".to_string()],
        });
        assert_eq!(ev.event_type(), AuditEventType::Configuration);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""type":"account_management""#), "{json}");
        assert!(json.contains(r#""action":"create""#), "{json}");
        assert!(!json.contains("source_ip"), "{json}");
        assert!(json.contains(r#""changed":["password"]"#), "{json}");
        assert!(json.contains(r#""actor_issuer""#), "{json}");
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AuditEvent::AccountManagement(a) if !a.success));
    }

    /// QA (POA&M-166, SI-10): every control char is replaced, the cap is
    /// exact, and truncation never splits a multi-byte char.
    #[test]
    fn qa_key_operation_reason_sanitization_edges() {
        let f = |r: &str| {
            CryptoKeyOperation::failure("k", KeyOperationType::Loaded, "ECDSA-P384", r)
                .reason
                .unwrap()
        };
        let r = f("a\tb\0c\x1bd\x7fe\u{85}f");
        assert!(!r.chars().any(char::is_control), "{r:?}");
        assert_eq!(r, "a b c d e f");
        let exact = "x".repeat(MAX_KEY_OPERATION_REASON_LEN);
        assert_eq!(f(&exact), exact);
        let r = f(&format!(
            "{}\u{20ac}",
            "x".repeat(MAX_KEY_OPERATION_REASON_LEN - 1)
        ));
        assert_eq!(r.len(), MAX_KEY_OPERATION_REASON_LEN - 1);
        let r = f(&"\u{20ac}".repeat(200));
        assert!(r.len() <= MAX_KEY_OPERATION_REASON_LEN);
        assert_eq!(r.len() % 3, 0);
        assert_eq!(f(""), "");
    }
}
