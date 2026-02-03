//! Call detail record types.

use std::collections::HashMap;
use std::time::Duration;

/// Call status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum CallStatus {
    /// Call is in progress.
    #[default]
    InProgress,
    /// Call completed successfully.
    Completed,
    /// Call failed.
    Failed,
    /// Call was cancelled.
    Cancelled,
    /// Call was busy.
    Busy,
    /// No answer.
    NoAnswer,
    /// Call was rejected.
    Rejected,
}

impl CallStatus {
    /// Returns whether the call connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::InProgress | Self::Completed)
    }

    /// Returns a string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Busy => "busy",
            Self::NoAnswer => "no_answer",
            Self::Rejected => "rejected",
        }
    }
}


impl std::fmt::Display for CallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Disconnect cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum DisconnectCause {
    /// Normal clearing.
    NormalClearing,
    /// User busy.
    UserBusy,
    /// No answer.
    NoAnswer,
    /// Call rejected.
    CallRejected,
    /// Destination unreachable.
    DestinationUnreachable,
    /// Service unavailable.
    ServiceUnavailable,
    /// Network error.
    NetworkError,
    /// Invalid number.
    InvalidNumber,
    /// Timeout.
    Timeout,
    /// Unknown.
    #[default]
    Unknown,
}

impl DisconnectCause {
    /// Returns a string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NormalClearing => "normal_clearing",
            Self::UserBusy => "user_busy",
            Self::NoAnswer => "no_answer",
            Self::CallRejected => "call_rejected",
            Self::DestinationUnreachable => "destination_unreachable",
            Self::ServiceUnavailable => "service_unavailable",
            Self::NetworkError => "network_error",
            Self::InvalidNumber => "invalid_number",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the SIP status code.
    pub fn sip_code(&self) -> u16 {
        match self {
            Self::NormalClearing => 200,
            Self::UserBusy => 486,
            Self::NoAnswer => 480,
            Self::CallRejected => 603,
            Self::DestinationUnreachable => 404,
            Self::ServiceUnavailable => 503,
            Self::NetworkError => 500,
            Self::InvalidNumber => 404,
            Self::Timeout => 408,
            Self::Unknown => 500,
        }
    }

    /// Creates from a SIP status code.
    pub fn from_sip_code(code: u16) -> Self {
        match code {
            200 => Self::NormalClearing,
            486 | 600 => Self::UserBusy,
            480 | 408 => Self::NoAnswer,
            603 | 403 | 401 => Self::CallRejected,
            404 => Self::DestinationUnreachable,
            501..=503 => Self::ServiceUnavailable,
            500 => Self::NetworkError,
            _ => Self::Unknown,
        }
    }
}


impl std::fmt::Display for DisconnectCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Direction of the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum CallDirection {
    /// Inbound call.
    #[default]
    Inbound,
    /// Outbound call.
    Outbound,
}

impl CallDirection {
    /// Returns a string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}


impl std::fmt::Display for CallDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Call detail record.
#[derive(Debug, Clone)]
pub struct CallRecord {
    /// Unique call ID.
    pub call_id: String,
    /// Correlation ID (for linking related CDRs).
    pub correlation_id: Option<String>,
    /// Call direction.
    pub direction: CallDirection,
    /// Caller number (From).
    pub caller: String,
    /// Callee number (To).
    pub callee: String,
    /// Original callee (before translation).
    pub original_callee: Option<String>,
    /// Source IP address.
    pub source_ip: String,
    /// Destination IP address.
    pub dest_ip: String,
    /// Trunk ID.
    pub trunk_id: Option<String>,
    /// Call status.
    pub status: CallStatus,
    /// Disconnect cause.
    pub disconnect_cause: DisconnectCause,
    /// Start time (Unix timestamp in milliseconds).
    pub start_time_ms: u64,
    /// Connect time (Unix timestamp in milliseconds).
    pub connect_time_ms: Option<u64>,
    /// End time (Unix timestamp in milliseconds).
    pub end_time_ms: Option<u64>,
    /// Setup duration in milliseconds.
    pub setup_duration_ms: Option<u64>,
    /// Call duration in seconds.
    pub duration_secs: Option<u64>,
    /// Codec used.
    pub codec: Option<String>,
    /// Media type.
    pub media_type: Option<String>,
    /// Custom fields.
    pub custom_fields: HashMap<String, String>,
}

impl CallRecord {
    /// Creates a new call record.
    pub fn new(
        call_identifier: impl Into<String>,
        from_number: impl Into<String>,
        to_number: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_identifier.into(),
            correlation_id: None,
            direction: CallDirection::default(),
            caller: from_number.into(),
            callee: to_number.into(),
            original_callee: None,
            source_ip: String::new(),
            dest_ip: String::new(),
            trunk_id: None,
            status: CallStatus::default(),
            disconnect_cause: DisconnectCause::default(),
            start_time_ms: 0,
            connect_time_ms: None,
            end_time_ms: None,
            setup_duration_ms: None,
            duration_secs: None,
            codec: None,
            media_type: None,
            custom_fields: HashMap::new(),
        }
    }

    /// Sets the direction.
    #[must_use]
    pub fn with_direction(mut self, direction: CallDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Sets the source IP.
    #[must_use]
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = ip.into();
        self
    }

    /// Sets the destination IP.
    #[must_use]
    pub fn with_dest_ip(mut self, ip: impl Into<String>) -> Self {
        self.dest_ip = ip.into();
        self
    }

    /// Sets the trunk ID.
    #[must_use]
    pub fn with_trunk(mut self, trunk_id: impl Into<String>) -> Self {
        self.trunk_id = Some(trunk_id.into());
        self
    }

    /// Sets the start time.
    #[must_use]
    pub fn with_start_time(mut self, start_ms: u64) -> Self {
        self.start_time_ms = start_ms;
        self
    }

    /// Sets a custom field.
    #[must_use]
    pub fn with_custom_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_fields.insert(key.into(), value.into());
        self
    }

    /// Marks the call as connected.
    pub fn connect(&mut self, connect_time_ms: u64) {
        self.connect_time_ms = Some(connect_time_ms);
        self.setup_duration_ms = Some(connect_time_ms.saturating_sub(self.start_time_ms));
    }

    /// Marks the call as completed.
    pub fn complete(&mut self, end_time_ms: u64, cause: DisconnectCause) {
        self.end_time_ms = Some(end_time_ms);
        self.disconnect_cause = cause;
        self.status = CallStatus::Completed;

        // Calculate duration if we have connect time
        if let Some(connect_ms) = self.connect_time_ms {
            self.duration_secs = Some(end_time_ms.saturating_sub(connect_ms) / 1000);
        }
    }

    /// Marks the call as failed.
    pub fn fail(&mut self, end_time_ms: u64, cause: DisconnectCause) {
        self.end_time_ms = Some(end_time_ms);
        self.disconnect_cause = cause;
        self.status = CallStatus::Failed;
    }

    /// Returns the total duration from start to end.
    pub fn total_duration(&self) -> Option<Duration> {
        self.end_time_ms
            .map(|end| Duration::from_millis(end.saturating_sub(self.start_time_ms)))
    }

    /// Returns the billable duration.
    pub fn billable_duration(&self) -> Option<Duration> {
        self.duration_secs.map(Duration::from_secs)
    }

    /// Returns whether the call connected.
    pub fn is_connected(&self) -> bool {
        self.connect_time_ms.is_some()
    }

    /// Returns whether the call is complete.
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            CallStatus::Completed | CallStatus::Failed | CallStatus::Cancelled
        )
    }
}

impl Default for CallRecord {
    fn default() -> Self {
        Self::new("", "", "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_status() {
        assert!(CallStatus::Completed.is_connected());
        assert!(!CallStatus::Failed.is_connected());
        assert_eq!(CallStatus::Completed.as_str(), "completed");
    }

    #[test]
    fn test_disconnect_cause() {
        assert_eq!(DisconnectCause::NormalClearing.sip_code(), 200);
        assert_eq!(DisconnectCause::UserBusy.sip_code(), 486);
    }

    #[test]
    fn test_disconnect_cause_from_sip() {
        assert_eq!(
            DisconnectCause::from_sip_code(200),
            DisconnectCause::NormalClearing
        );
        assert_eq!(
            DisconnectCause::from_sip_code(486),
            DisconnectCause::UserBusy
        );
        assert_eq!(
            DisconnectCause::from_sip_code(999),
            DisconnectCause::Unknown
        );
    }

    #[test]
    fn test_call_direction() {
        assert_eq!(CallDirection::Inbound.as_str(), "inbound");
        assert_eq!(CallDirection::Outbound.as_str(), "outbound");
    }

    #[test]
    fn test_call_record_creation() {
        let record = CallRecord::new("call-123", "+15551234567", "+15559876543")
            .with_direction(CallDirection::Outbound)
            .with_source_ip("192.168.1.100")
            .with_dest_ip("10.0.0.1")
            .with_trunk("trunk-1")
            .with_start_time(1704067200000);

        assert_eq!(record.call_id, "call-123");
        assert_eq!(record.caller, "+15551234567");
        assert_eq!(record.callee, "+15559876543");
        assert_eq!(record.direction, CallDirection::Outbound);
    }

    #[test]
    fn test_call_record_connect() {
        let mut record = CallRecord::new("call-123", "alice", "bob").with_start_time(1000);

        record.connect(1500);

        assert!(record.is_connected());
        assert_eq!(record.setup_duration_ms, Some(500));
    }

    #[test]
    fn test_call_record_complete() {
        let mut record = CallRecord::new("call-123", "alice", "bob").with_start_time(1000);

        record.connect(1500);
        record.complete(61500, DisconnectCause::NormalClearing);

        assert!(record.is_complete());
        assert_eq!(record.duration_secs, Some(60)); // 60 seconds
        assert_eq!(record.disconnect_cause, DisconnectCause::NormalClearing);
    }

    #[test]
    fn test_call_record_fail() {
        let mut record = CallRecord::new("call-123", "alice", "bob").with_start_time(1000);

        record.fail(5000, DisconnectCause::UserBusy);

        assert!(record.is_complete());
        assert_eq!(record.status, CallStatus::Failed);
        assert_eq!(record.disconnect_cause, DisconnectCause::UserBusy);
    }

    #[test]
    fn test_call_record_duration() {
        let mut record = CallRecord::new("call-123", "alice", "bob").with_start_time(0);

        record.connect(1000);
        record.complete(61000, DisconnectCause::NormalClearing);

        let total = record.total_duration().unwrap();
        assert_eq!(total.as_millis(), 61000);

        let billable = record.billable_duration().unwrap();
        assert_eq!(billable.as_secs(), 60);
    }

    #[test]
    fn test_call_record_custom_fields() {
        let record = CallRecord::new("call-123", "alice", "bob")
            .with_custom_field("tenant_id", "tenant-1")
            .with_custom_field("account_code", "12345");

        assert_eq!(
            record.custom_fields.get("tenant_id"),
            Some(&"tenant-1".to_string())
        );
        assert_eq!(
            record.custom_fields.get("account_code"),
            Some(&"12345".to_string())
        );
    }
}
