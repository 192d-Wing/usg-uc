//! Call detail record schema v1.
//!
//! One [`CallRecord`] is written per call attempt that reaches admission.
//! Field order in the struct is the canonical JSON field order: the hash
//! chain is computed over that serialization, so reordering fields is a
//! schema change.
//!
//! ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), AU-3(1)

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Current record schema version. Bumping it is breaking for parsers.
pub const SCHEMA_VERSION: u16 = 1;

/// Longest stored string field, in bytes. Longer values (attacker-controlled
/// From/To users, Call-IDs) are truncated at a UTF-8 boundary.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), SI-10
pub const MAX_FIELD_LEN: usize = 256;

/// Most entries kept in `b_call_ids` / `trunks_tried`.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
pub const MAX_ATTEMPTS: usize = 32;

/// Call direction relative to the SBC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From a trunk/peer toward internal endpoints.
    #[default]
    Inbound,
    /// From internal endpoints toward a trunk.
    Outbound,
    /// Between internal endpoints.
    Internal,
}

/// Signaling transport of the A-leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// UDP.
    #[default]
    Udp,
    /// TCP.
    Tcp,
    /// TLS over TCP.
    Tls,
    /// WebSocket.
    Ws,
    /// Secure WebSocket.
    Wss,
}

/// Call outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// 2xx was sent to the A-leg.
    Answered,
    /// Failed for a reason not covered below.
    #[default]
    Failed,
    /// CANCELled by the caller before answer.
    Cancelled,
    /// Rejected by the SBC (admission, policy, no route).
    Rejected,
    /// 486/600 from the callee side.
    Busy,
    /// 408/480 or no final answer from the callee side.
    NoAnswer,
    /// Torn down because the media path failed.
    MediaFailure,
    /// Terminated by an operator through the management API.
    OperatorTerminated,
}

impl Disposition {
    /// Schema string for this value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
            Self::NoAnswer => "no_answer",
            Self::MediaFailure => "media_failure",
            Self::OperatorTerminated => "operator_terminated",
        }
    }

    /// Parses a schema string.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "answered" => Self::Answered,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "rejected" => Self::Rejected,
            "busy" => Self::Busy,
            "no_answer" => Self::NoAnswer,
            "media_failure" => Self::MediaFailure,
            "operator_terminated" => Self::OperatorTerminated,
            _ => return None,
        })
    }
}

/// Which side ended the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSide {
    /// The A-leg (BYE/CANCEL from the caller).
    Caller,
    /// The B-leg (BYE or final error from the callee/trunk).
    Callee,
    /// The SBC itself (timers, admission, media failure, operator, shutdown).
    #[default]
    Sbc,
}

impl ReleaseSide {
    /// Schema string for this value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::Callee => "callee",
            Self::Sbc => "sbc",
        }
    }
}

/// Why the call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCause {
    /// Normal clearing (BYE).
    #[default]
    Normal,
    /// CANCEL before answer (RFC 3261 §9).
    Cancel,
    /// INVITE client transaction timeout (RFC 3261 §17.1.1.2).
    TimerB,
    /// Transport failure toward the next hop.
    TransportError,
    /// Final error response from the trunk/callee.
    TrunkError,
    /// Admission refused: `max_calls` reached.
    AdmissionMaxCalls,
    /// Admission refused: node draining.
    Draining,
    /// Refused by policy (403).
    PolicyDenied,
    /// No route to the callee.
    NoRoute,
    /// Media path failure.
    MediaFailure,
    /// Operator termination.
    Operator,
    /// SBC shutdown.
    Shutdown,
}

impl ReleaseCause {
    /// Schema string for this value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Cancel => "cancel",
            Self::TimerB => "timer_b",
            Self::TransportError => "transport_error",
            Self::TrunkError => "trunk_error",
            Self::AdmissionMaxCalls => "admission_max_calls",
            Self::Draining => "draining",
            Self::PolicyDenied => "policy_denied",
            Self::NoRoute => "no_route",
            Self::MediaFailure => "media_failure",
            Self::Operator => "operator",
            Self::Shutdown => "shutdown",
        }
    }
}

impl Direction {
    /// Schema string for this value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Internal => "internal",
        }
    }
}

impl Transport {
    /// Schema string for this value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

/// How one B-leg attempt ended. Serialized as the SIP status number, or
/// the strings `"timeout"` / `"transport_error"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrunkOutcome {
    /// Final SIP response status.
    Status(u16),
    /// No final response before Timer B.
    Timeout,
    /// The request could not be sent.
    TransportError,
}

impl TrunkOutcome {
    /// Schema string (`"status"`, `"timeout"`, `"transport_error"`).
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Status(_) => "status",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
        }
    }
}

impl Serialize for TrunkOutcome {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Status(code) => s.serialize_u16(*code),
            Self::Timeout => s.serialize_str("timeout"),
            Self::TransportError => s.serialize_str("transport_error"),
        }
    }
}

impl<'de> Deserialize<'de> for TrunkOutcome {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = TrunkOutcome;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a SIP status, \"timeout\" or \"transport_error\"")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<TrunkOutcome, E> {
                u16::try_from(v)
                    .map(TrunkOutcome::Status)
                    .map_err(|_| E::custom("status out of range"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<TrunkOutcome, E> {
                match v {
                    "timeout" => Ok(TrunkOutcome::Timeout),
                    "transport_error" => Ok(TrunkOutcome::TransportError),
                    _ => Err(E::custom("unknown trunk outcome")),
                }
            }
        }
        d.deserialize_any(V)
    }
}

/// One B-leg attempt toward a trunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrunkAttempt {
    /// Trunk identifier.
    pub trunk_id: String,
    /// Outcome.
    pub status: TrunkOutcome,
    /// Epoch ms (UTC) the attempt ended.
    pub at_ms: u64,
}

/// STIR/SHAKEN attestation level (RFC 8588). Placeholder in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attestation {
    /// Full attestation.
    A,
    /// Partial attestation.
    B,
    /// Gateway attestation.
    C,
}

/// A Call Detail Record, schema v1.
///
/// Producers fill the call facts; `schema_version`, `record_id`, `node_id`,
/// `sequence`, `prev_hash` and `hash` are assigned by the writer and any
/// values set by the producer are overwritten.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), AU-8 (Time Stamps)
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecord {
    /// Schema version ([`SCHEMA_VERSION`]).
    pub schema_version: u16,
    /// `"{node_id}-{sequence}"`.
    pub record_id: String,
    /// Node that produced the record.
    pub node_id: String,
    /// Per-node monotonic sequence, continued across restarts.
    pub sequence: u64,
    /// A-leg SIP Call-ID.
    pub a_call_id: String,
    /// One Call-ID per B-leg attempt.
    pub b_call_ids: Vec<String>,
    /// SBC-internal call identifier.
    pub internal_call_id: String,
    /// Direction.
    pub direction: Direction,
    /// From user as received.
    pub caller: String,
    /// Request-URI user as received.
    pub callee_dialed: String,
    /// Callee after dial-plan transform.
    pub callee_translated: Option<String>,
    /// Caller after From manipulation.
    pub caller_translated: Option<String>,
    /// A-leg source IP.
    pub source_ip: String,
    /// A-leg source port.
    pub source_port: u16,
    /// A-leg transport.
    pub transport: Transport,
    /// Ingress zone.
    pub ingress_zone: Option<String>,
    /// Egress zone.
    pub egress_zone: Option<String>,
    /// Trunk group selected by routing.
    pub trunk_group: Option<String>,
    /// B-leg attempts, in order.
    pub trunks_tried: Vec<TrunkAttempt>,
    /// Trunk of the final attempt.
    pub final_trunk: Option<String>,
    /// Number of failovers after the first attempt.
    pub failover_count: u32,
    /// Epoch ms the INVITE was received.
    pub setup_ms: u64,
    /// Epoch ms of the first 18x.
    pub ring_ms: Option<u64>,
    /// Epoch ms of the 2xx.
    pub answer_ms: Option<u64>,
    /// Epoch ms the call ended.
    pub end_ms: u64,
    /// `end_ms - answer_ms`, 0 when unanswered.
    pub duration_ms: u64,
    /// Post-dial delay: setup to first 18x/2xx.
    pub pdd_ms: Option<u64>,
    /// Outcome.
    pub disposition: Disposition,
    /// Final status sent to the A-leg (200 when answered).
    pub final_sip_status: u16,
    /// Side that released.
    pub release_side: ReleaseSide,
    /// Release cause.
    pub release_cause: ReleaseCause,
    /// Q.850 cause from a Reason header (RFC 3326), if present.
    pub q850_cause: Option<u8>,
    /// Media node that anchored the call.
    pub media_node: Option<String>,
    /// Whether media was anchored on the SBC.
    pub media_anchored: bool,
    /// Negotiated codec.
    pub codec: Option<String>,
    /// SRTP crypto suite.
    pub srtp: Option<String>,
    /// Emergency call.
    pub emergency: bool,
    /// STIR/SHAKEN attestation. Always `None` in v1.
    pub stir_attestation: Option<Attestation>,
    /// This node took the dialog over from a failed peer; timing is partial.
    pub failover_takeover: bool,
    /// Hex SHA-384 of the previous record (empty when chaining is off).
    pub prev_hash: String,
    /// Hex SHA-384 of this record (empty when chaining is off).
    pub hash: String,
}

impl CallRecord {
    /// Derives `duration_ms` and `pdd_ms` from the timestamps.
    pub fn compute_durations(&mut self) {
        self.duration_ms = self.answer_ms.map_or(0, |a| self.end_ms.saturating_sub(a));
        let first = match (self.ring_ms, self.answer_ms) {
            (Some(r), Some(a)) => Some(r.min(a)),
            (r, a) => r.or(a),
        };
        self.pdd_ms = first.map(|t| t.saturating_sub(self.setup_ms));
    }

    /// Caps every string at [`MAX_FIELD_LEN`] bytes and every list at
    /// [`MAX_ATTEMPTS`] entries. Truncates in place; never allocates.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), SI-10
    pub fn sanitize(&mut self) {
        for s in [
            &mut self.a_call_id,
            &mut self.internal_call_id,
            &mut self.caller,
            &mut self.callee_dialed,
            &mut self.source_ip,
        ] {
            truncate_str(s, MAX_FIELD_LEN);
        }
        for s in [
            &mut self.callee_translated,
            &mut self.caller_translated,
            &mut self.ingress_zone,
            &mut self.egress_zone,
            &mut self.trunk_group,
            &mut self.final_trunk,
            &mut self.media_node,
            &mut self.codec,
            &mut self.srtp,
        ]
        .into_iter()
        .flatten()
        {
            truncate_str(s, MAX_FIELD_LEN);
        }
        self.b_call_ids.truncate(MAX_ATTEMPTS);
        for id in &mut self.b_call_ids {
            truncate_str(id, MAX_FIELD_LEN);
        }
        self.trunks_tried.truncate(MAX_ATTEMPTS);
        for t in &mut self.trunks_tried {
            truncate_str(&mut t.trunk_id, MAX_FIELD_LEN);
        }
    }
}

/// Truncates `s` to at most `max` bytes on a char boundary.
pub(crate) fn truncate_str(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

/// First line of every JSONL CDR file.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHeader {
    /// Schema version.
    pub schema_version: u16,
    /// Always `"header"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Node that wrote the file.
    pub node_id: String,
    /// Epoch ms the file was opened.
    pub created_ms: u64,
    /// Hex hash the first record chains from (empty when chaining is off).
    pub chain_start: String,
    /// Sequence of the first record in the file.
    pub first_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        let mut r = CallRecord {
            setup_ms: 1000,
            ring_ms: Some(1500),
            answer_ms: Some(3000),
            end_ms: 63000,
            ..Default::default()
        };
        r.compute_durations();
        assert_eq!(r.duration_ms, 60000);
        assert_eq!(r.pdd_ms, Some(500));

        let mut r = CallRecord {
            setup_ms: 1000,
            end_ms: 2000,
            ..Default::default()
        };
        r.compute_durations();
        assert_eq!(r.duration_ms, 0);
        assert_eq!(r.pdd_ms, None);
    }

    #[test]
    fn sanitize_caps_strings_on_char_boundary() {
        let mut r = CallRecord {
            caller: "é".repeat(200), // 400 bytes
            callee_translated: Some("x".repeat(10_000)),
            b_call_ids: vec!["id".to_string(); 100],
            ..Default::default()
        };
        r.sanitize();
        assert!(r.caller.len() <= MAX_FIELD_LEN);
        assert_eq!(r.caller.chars().count(), 128);
        assert_eq!(r.callee_translated.as_deref().map(str::len), Some(256));
        assert_eq!(r.b_call_ids.len(), MAX_ATTEMPTS);
    }

    #[test]
    fn trunk_outcome_serde() {
        let a = vec![
            TrunkAttempt {
                trunk_id: "t1".into(),
                status: TrunkOutcome::Status(503),
                at_ms: 1,
            },
            TrunkAttempt {
                trunk_id: "t2".into(),
                status: TrunkOutcome::Timeout,
                at_ms: 2,
            },
            TrunkAttempt {
                trunk_id: "t3".into(),
                status: TrunkOutcome::TransportError,
                at_ms: 3,
            },
        ];
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"status\":503"));
        assert!(s.contains("\"status\":\"timeout\""));
        let back: Vec<TrunkAttempt> = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        assert!(serde_json::from_str::<TrunkOutcome>("\"bogus\"").is_err());
        assert!(serde_json::from_str::<TrunkOutcome>("70000").is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        let mut v = serde_json::to_value(CallRecord::default()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<CallRecord>(v).is_err());
    }

    #[test]
    fn disposition_parse_roundtrip() {
        for d in [
            Disposition::Answered,
            Disposition::Failed,
            Disposition::Cancelled,
            Disposition::Rejected,
            Disposition::Busy,
            Disposition::NoAnswer,
            Disposition::MediaFailure,
            Disposition::OperatorTerminated,
        ] {
            assert_eq!(Disposition::parse(d.as_str()), Some(d));
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{}\"", d.as_str())
            );
        }
    }
}
