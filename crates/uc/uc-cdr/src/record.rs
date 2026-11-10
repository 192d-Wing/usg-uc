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
///
/// v2 (STIR/SHAKEN) adds `stir_verstat`, `stir_verify_reason`,
/// `stir_inbound_attestation` and `stir_x5u_host`. They are omitted from JSON
/// when unset, so a v1 record re-serialises byte-identically and its chain
/// hash still verifies.
///
/// v3 (T.38 fax, POA&M-294) adds `media_kinds`, also omitted when empty so
/// v1/v2 records keep verifying.
///
/// v4 (SIPREC recording, POA&M-306) adds `recording` and
/// `recording_session_id`, omitted when unset so v1..v3 records keep
/// verifying, and the `recording_failure` disposition / release cause.
pub const SCHEMA_VERSION: u16 = 4;

/// Oldest schema version readers accept.
pub const MIN_READ_SCHEMA_VERSION: u16 = 1;

/// True if `v` is a schema version this crate can read.
#[must_use]
pub const fn is_readable_schema(v: u16) -> bool {
    v >= MIN_READ_SCHEMA_VERSION && v <= SCHEMA_VERSION
}

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
    /// Refused or torn down because the call had to be recorded and could
    /// not be (`recording.on_failure = reject`) (v4).
    RecordingFailure,
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
            Self::RecordingFailure => "recording_failure",
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
            "recording_failure" => Self::RecordingFailure,
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
    /// Recording failure under `recording.on_failure = reject` (v4).
    RecordingFailure,
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
            Self::RecordingFailure => "recording_failure",
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

/// STIR/SHAKEN attestation level (RFC 8588).
///
/// Kept separate from `uc_types::AttestationLevel` so the CDR wire form
/// (`"A"`/`"B"`/`"C"`) is pinned by this crate's schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attestation {
    /// Full attestation.
    A,
    /// Partial attestation.
    B,
    /// Gateway attestation.
    C,
}

impl Attestation {
    /// `"A"`, `"B"` or `"C"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

/// STIR verification status (ATIS-1000074 verstat), schema v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verstat {
    /// `TN-Validation-Passed`.
    TnValidationPassed,
    /// `TN-Validation-Failed`.
    TnValidationFailed,
    /// `No-TN-Validation`.
    NoTnValidation,
}

impl Verstat {
    /// Lower-case token, as serialised.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TnValidationPassed => "tn-validation-passed",
            Self::TnValidationFailed => "tn-validation-failed",
            Self::NoTnValidation => "no-tn-validation",
        }
    }
}

/// Media kind a call used (schema v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaKindTag {
    /// RTP audio.
    Audio,
    /// `m=image` (T.38 fax over UDPTL).
    Image,
}

impl MediaKindTag {
    /// Lower-case token, as serialised.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Image => "image",
        }
    }

    /// Parses a token produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "audio" => Some(Self::Audio),
            "image" => Some(Self::Image),
            _ => None,
        }
    }
}

/// Recording outcome of a call that matched the recording trigger
/// (schema v4, RFC 7866 SRC).
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), AU-14
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingTag {
    /// The recording session was active until the call ended (no failure
    /// signalled by the SRS; excludes the setup window after answer).
    Recorded,
    /// The recording session ended before the call did
    /// (`on_failure = continue`).
    Partial,
    /// The recording session could not be set up.
    Failed,
    /// The SBC could not read the call's media, or had no recording slot.
    NotRecordable,
    /// A participant opted out (`a=recordpref:off`, honoured by policy).
    OptOut,
}

impl RecordingTag {
    /// Snake-case token, as serialised.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::NotRecordable => "not_recordable",
            Self::OptOut => "opt_out",
        }
    }

    /// Parses a token produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "recorded" => Some(Self::Recorded),
            "partial" => Some(Self::Partial),
            "failed" => Some(Self::Failed),
            "not_recordable" => Some(Self::NotRecordable),
            "opt_out" => Some(Self::OptOut),
            _ => None,
        }
    }
}

/// Upper bound on `CallRecord::media_kinds` (one entry per [`MediaKindTag`]).
pub const MAX_MEDIA_KINDS: usize = 2;

/// Adds `kind` to a set-like media-kind list (ordered by first use, no
/// duplicates, at most [`MAX_MEDIA_KINDS`] entries).
pub fn note_media_kind(kinds: &mut Vec<MediaKindTag>, kind: MediaKindTag) {
    if !kinds.contains(&kind) && kinds.len() < MAX_MEDIA_KINDS {
        kinds.push(kind);
    }
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
    /// STIR/SHAKEN attestation this SBC signed the B-leg INVITE with.
    pub stir_attestation: Option<Attestation>,
    /// Verification outcome of the inbound Identity (v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stir_verstat: Option<Verstat>,
    /// Fixed failure-reason token when verification failed (v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stir_verify_reason: Option<String>,
    /// Attestation carried by the verified inbound PASSporT (v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stir_inbound_attestation: Option<Attestation>,
    /// Host part of the inbound `x5u` (no path: limits PII/cardinality) (v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stir_x5u_host: Option<String>,
    /// Media kinds the call used, ordered by first use, no duplicates (v3).
    /// An audio call that switched to T.38 and back is `["audio","image"]`.
    // NIST 800-53 Rev5: AU-3 (Content of Audit Records) - fax calls are
    // distinguishable in the record (POA&M-294).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media_kinds: Vec<MediaKindTag>,
    /// Recording outcome (v4). Unset when the call did not match the
    /// recording trigger (and in v1..v3 records).
    // NIST 800-53 Rev5: AU-3, AU-14 - whether a call was recorded is part
    // of its record and inside the hash chain (POA&M-306).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording: Option<RecordingTag>,
    /// RFC 7865 recording session identifier (SBC-generated UUID; not the
    /// RS Call-ID) (v4). Correlates the record with the SRS and with the
    /// `recording_*` audit events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_session_id: Option<String>,
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
            &mut self.stir_verify_reason,
            &mut self.stir_x5u_host,
            &mut self.recording_session_id,
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
        let (mut seen_audio, mut seen_image) = (false, false);
        self.media_kinds.retain(|k| {
            let seen = match k {
                MediaKindTag::Audio => &mut seen_audio,
                MediaKindTag::Image => &mut seen_image,
            };
            !std::mem::replace(seen, true)
        });
        // Unreachable today (dedup + two MediaKindTag variants); defence in
        // depth. Raise MAX_MEDIA_KINDS when adding a variant, or it is dropped.
        self.media_kinds.truncate(MAX_MEDIA_KINDS);
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
    fn media_kinds_set_semantics_and_serde() {
        let mut kinds = Vec::new();
        for k in [
            MediaKindTag::Audio,
            MediaKindTag::Image,
            MediaKindTag::Audio,
            MediaKindTag::Image,
        ] {
            note_media_kind(&mut kinds, k);
        }
        assert_eq!(kinds, vec![MediaKindTag::Audio, MediaKindTag::Image]);

        let r = CallRecord {
            media_kinds: kinds,
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains(r#""media_kinds":["audio","image"]"#),
            "{json}"
        );
        let back: CallRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);

        // Empty set is omitted, so v1/v2 records re-serialise identically.
        let json = serde_json::to_string(&CallRecord::default()).unwrap();
        assert!(!json.contains("media_kinds"));

        let mut dup = CallRecord {
            media_kinds: vec![
                MediaKindTag::Image,
                MediaKindTag::Image,
                MediaKindTag::Audio,
            ],
            ..Default::default()
        };
        dup.sanitize();
        assert_eq!(
            dup.media_kinds,
            vec![MediaKindTag::Image, MediaKindTag::Audio]
        );

        assert!(is_readable_schema(3));
        assert!(serde_json::from_str::<MediaKindTag>(r#""video""#).is_err());
        assert_eq!(MediaKindTag::parse("image"), Some(MediaKindTag::Image));
        assert_eq!(MediaKindTag::parse("x"), None);
    }

    #[test]
    fn recording_fields_serde_and_omission() {
        assert_eq!(SCHEMA_VERSION, 4);
        assert_eq!(MIN_READ_SCHEMA_VERSION, 1);
        assert!((1..=4).all(is_readable_schema));
        assert!(!is_readable_schema(0) && !is_readable_schema(5));

        // Unset: both keys are omitted, so v1..v3 records re-serialise
        // byte-identically.
        let json = serde_json::to_string(&CallRecord::default()).unwrap();
        assert!(!json.contains("recording"), "{json}");

        let r = CallRecord {
            recording: Some(RecordingTag::NotRecordable),
            recording_session_id: Some("0b0e7f8c-6c0c-4d53-9f0a-2a1d2c3b4e5f".into()),
            disposition: Disposition::RecordingFailure,
            release_cause: ReleaseCause::RecordingFailure,
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap();
        for needle in [
            r#""recording":"not_recordable""#,
            r#""recording_session_id":"0b0e7f8c-6c0c-4d53-9f0a-2a1d2c3b4e5f""#,
            r#""disposition":"recording_failure""#,
            r#""release_cause":"recording_failure""#,
        ] {
            assert!(json.contains(needle), "{json}");
        }
        // Canonical order: after media_kinds' slot, before failover_takeover.
        assert!(json.find("\"recording\"").unwrap() < json.find("failover_takeover").unwrap());
        let back: CallRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);

        for t in [
            RecordingTag::Recorded,
            RecordingTag::Partial,
            RecordingTag::Failed,
            RecordingTag::NotRecordable,
            RecordingTag::OptOut,
        ] {
            assert_eq!(RecordingTag::parse(t.as_str()), Some(t));
            assert_eq!(
                serde_json::to_string(&t).unwrap(),
                format!("\"{}\"", t.as_str())
            );
        }
        assert_eq!(RecordingTag::parse("yes"), None);
        assert!(serde_json::from_str::<RecordingTag>(r#""yes""#).is_err());
        assert_eq!(ReleaseCause::RecordingFailure.as_str(), "recording_failure");

        let mut long = CallRecord {
            recording_session_id: Some("x".repeat(10_000)),
            ..Default::default()
        };
        long.sanitize();
        assert_eq!(
            long.recording_session_id.as_deref().map(str::len),
            Some(MAX_FIELD_LEN)
        );
    }

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
            Disposition::RecordingFailure,
        ] {
            assert_eq!(Disposition::parse(d.as_str()), Some(d));
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{}\"", d.as_str())
            );
        }
    }
}
