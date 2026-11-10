//! Conversion between `uc_cdr::CallRecord` (schema v1) and the
//! `CdrRecord` proto.
//!
//! [`from_proto`] treats the proto as untrusted input: enum strings and
//! trunk outcomes are validated through the record's serde schema
//! (`deny_unknown_fields`, exact enum names), so a malformed record is an
//! error, never a panic.
//!
//! ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), SI-10

use crate::sbc::{CdrRecord, TrunkAttempt};
use uc_cdr::{CallRecord, TrunkOutcome};

/// Converts a schema v1 record to its proto form.
#[must_use]
pub fn to_proto(r: &CallRecord) -> CdrRecord {
    CdrRecord {
        schema_version: u32::from(r.schema_version),
        record_id: r.record_id.clone(),
        node_id: r.node_id.clone(),
        sequence: r.sequence,
        a_call_id: r.a_call_id.clone(),
        b_call_ids: r.b_call_ids.clone(),
        internal_call_id: r.internal_call_id.clone(),
        direction: r.direction.as_str().to_string(),
        caller: r.caller.clone(),
        callee_dialed: r.callee_dialed.clone(),
        callee_translated: r.callee_translated.clone(),
        caller_translated: r.caller_translated.clone(),
        source_ip: r.source_ip.clone(),
        source_port: u32::from(r.source_port),
        transport: r.transport.as_str().to_string(),
        ingress_zone: r.ingress_zone.clone(),
        egress_zone: r.egress_zone.clone(),
        trunk_group: r.trunk_group.clone(),
        trunks_tried: r
            .trunks_tried
            .iter()
            .map(|t| TrunkAttempt {
                trunk_id: t.trunk_id.clone(),
                status: match t.status {
                    TrunkOutcome::Status(c) => u32::from(c),
                    _ => 0,
                },
                outcome: t.status.kind().to_string(),
                at_ms: t.at_ms,
            })
            .collect(),
        final_trunk: r.final_trunk.clone(),
        failover_count: r.failover_count,
        setup_ms: r.setup_ms,
        ring_ms: r.ring_ms,
        answer_ms: r.answer_ms,
        end_ms: r.end_ms,
        duration_ms: r.duration_ms,
        pdd_ms: r.pdd_ms,
        disposition: r.disposition.as_str().to_string(),
        final_sip_status: u32::from(r.final_sip_status),
        release_side: r.release_side.as_str().to_string(),
        release_cause: r.release_cause.as_str().to_string(),
        q850_cause: r.q850_cause.map(u32::from),
        media_node: r.media_node.clone(),
        media_anchored: r.media_anchored,
        codec: r.codec.clone(),
        srtp: r.srtp.clone(),
        emergency: r.emergency,
        stir_attestation: r.stir_attestation.map(|a| a.as_str().to_string()),
        stir_verstat: r.stir_verstat.map(|v| v.as_str().to_string()),
        stir_verify_reason: r.stir_verify_reason.clone(),
        stir_inbound_attestation: r.stir_inbound_attestation.map(|a| a.as_str().to_string()),
        stir_x5u_host: r.stir_x5u_host.clone(),
        media_kinds: r
            .media_kinds
            .iter()
            .map(|k| k.as_str().to_string())
            .collect(),
        // Schema v4: empty string = unset.
        recording: r
            .recording
            .map(|t| t.as_str().to_string())
            .unwrap_or_default(),
        recording_session_id: r.recording_session_id.clone().unwrap_or_default(),
        failover_takeover: r.failover_takeover,
        prev_hash: r.prev_hash.clone(),
        hash: r.hash.clone(),
    }
}

/// Converts a proto record back to schema v1, validating every enum string.
///
/// # Errors
///
/// Returns a description of the first invalid field.
pub fn from_proto(p: &CdrRecord) -> Result<CallRecord, String> {
    let attempts: Vec<serde_json::Value> = p
        .trunks_tried
        .iter()
        .map(|t| {
            let status = match t.outcome.as_str() {
                "status" => u16::try_from(t.status)
                    .map(serde_json::Value::from)
                    .map_err(|_| format!("trunk status {} out of range", t.status)),
                "timeout" | "transport_error" => Ok(serde_json::Value::from(t.outcome.clone())),
                other => Err(format!("unknown trunk outcome {other:?}")),
            }?;
            Ok(serde_json::json!({
                "trunk_id": t.trunk_id,
                "status": status,
                "at_ms": t.at_ms,
            }))
        })
        .collect::<Result<_, String>>()?;
    let mut v = serde_json::json!({
        "schema_version": p.schema_version,
        "record_id": p.record_id,
        "node_id": p.node_id,
        "sequence": p.sequence,
        "a_call_id": p.a_call_id,
        "b_call_ids": p.b_call_ids,
        "internal_call_id": p.internal_call_id,
        "direction": p.direction,
        "caller": p.caller,
        "callee_dialed": p.callee_dialed,
        "callee_translated": p.callee_translated,
        "caller_translated": p.caller_translated,
        "source_ip": p.source_ip,
        "source_port": p.source_port,
        "transport": p.transport,
        "ingress_zone": p.ingress_zone,
        "egress_zone": p.egress_zone,
        "trunk_group": p.trunk_group,
        "trunks_tried": attempts,
        "final_trunk": p.final_trunk,
        "failover_count": p.failover_count,
        "setup_ms": p.setup_ms,
        "ring_ms": p.ring_ms,
        "answer_ms": p.answer_ms,
        "end_ms": p.end_ms,
        "duration_ms": p.duration_ms,
        "pdd_ms": p.pdd_ms,
        "disposition": p.disposition,
        "final_sip_status": p.final_sip_status,
        "release_side": p.release_side,
        "release_cause": p.release_cause,
        "q850_cause": p.q850_cause,
        "media_node": p.media_node,
        "media_anchored": p.media_anchored,
        "codec": p.codec,
        "srtp": p.srtp,
        "emergency": p.emergency,
        "stir_attestation": p.stir_attestation,
        "failover_takeover": p.failover_takeover,
        "prev_hash": p.prev_hash,
        "hash": p.hash,
    });
    // Schema v2 fields, added separately to stay under json!'s macro
    // recursion limit.
    if let Some(obj) = v.as_object_mut() {
        obj.insert("stir_verstat".into(), serde_json::json!(p.stir_verstat));
        obj.insert(
            "stir_verify_reason".into(),
            serde_json::json!(p.stir_verify_reason),
        );
        obj.insert(
            "stir_inbound_attestation".into(),
            serde_json::json!(p.stir_inbound_attestation),
        );
        obj.insert("stir_x5u_host".into(), serde_json::json!(p.stir_x5u_host));
        // Schema v3. Bounded and set-like; unknown tokens are rejected by
        // the MediaKindTag deserializer below.
        // NIST 800-53 Rev5: SI-10 (Information Input Validation)
        if p.media_kinds.len() > uc_cdr::MAX_MEDIA_KINDS {
            return Err(format!(
                "invalid CDR record: more than {} media_kinds",
                uc_cdr::MAX_MEDIA_KINDS
            ));
        }
        obj.insert("media_kinds".into(), serde_json::json!(p.media_kinds));
        // Schema v4. Empty = unset (key omitted, as the writer does, so the
        // record's chain hash is reproducible). An unknown token is rejected
        // by the RecordingTag deserializer below; the session ID is bounded
        // like every stored string.
        // NIST 800-53 Rev5: SI-10 (Information Input Validation), SC-5
        if !p.recording.is_empty() {
            obj.insert("recording".into(), serde_json::json!(p.recording));
        }
        if p.recording_session_id.len() > uc_cdr::record::MAX_FIELD_LEN {
            return Err("invalid CDR record: recording_session_id too long".to_string());
        }
        if !p.recording_session_id.is_empty() {
            obj.insert(
                "recording_session_id".into(),
                serde_json::json!(p.recording_session_id),
            );
        }
    }
    serde_json::from_value(v).map_err(|e| format!("invalid CDR record: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use uc_cdr::{Attestation, Disposition, ReleaseCause, TrunkAttempt as Attempt};

    #[test]
    fn round_trip() {
        let r = CallRecord {
            schema_version: 1,
            record_id: "n-1".into(),
            caller: "alice".into(),
            trunks_tried: vec![
                Attempt {
                    trunk_id: "t1".into(),
                    status: TrunkOutcome::Status(503),
                    at_ms: 5,
                },
                Attempt {
                    trunk_id: "t2".into(),
                    status: TrunkOutcome::Timeout,
                    at_ms: 6,
                },
            ],
            disposition: Disposition::NoAnswer,
            release_cause: ReleaseCause::TimerB,
            q850_cause: Some(16),
            stir_attestation: Some(Attestation::B),
            stir_verstat: Some(uc_cdr::Verstat::TnValidationPassed),
            stir_inbound_attestation: Some(Attestation::A),
            stir_x5u_host: Some("cert.example.invalid".into()),
            media_kinds: vec![uc_cdr::MediaKindTag::Audio, uc_cdr::MediaKindTag::Image],
            ..Default::default()
        };
        let p = to_proto(&r);
        assert_eq!(
            p.media_kinds,
            vec!["audio".to_string(), "image".to_string()]
        );
        assert_eq!(p.stir_attestation.as_deref(), Some("B"));
        assert_eq!(p.stir_verstat.as_deref(), Some("tn-validation-passed"));
        assert_eq!(from_proto(&p).unwrap(), r);
    }

    /// Schema v4: the recording fields survive the proto round trip, unset
    /// maps to empty strings and back, and the hash chain value computed
    /// from the converted record is unchanged.
    #[test]
    fn recording_fields_round_trip() {
        let mut r = CallRecord {
            schema_version: uc_cdr::SCHEMA_VERSION,
            record_id: "n-2".into(),
            node_id: "n".into(),
            disposition: Disposition::RecordingFailure,
            release_cause: ReleaseCause::RecordingFailure,
            final_sip_status: 503,
            recording: Some(uc_cdr::RecordingTag::Failed),
            recording_session_id: Some("7d0c8a52-1f0e-4a43-9c58-0f3a5b6c7d8e".into()),
            ..Default::default()
        };
        uc_cdr::chain::seal(&mut r, &uc_cdr::chain::GENESIS).unwrap();
        let p = to_proto(&r);
        assert_eq!(p.recording, "failed");
        assert_eq!(
            p.recording_session_id,
            "7d0c8a52-1f0e-4a43-9c58-0f3a5b6c7d8e"
        );
        assert_eq!(p.disposition, "recording_failure");
        assert_eq!(p.release_cause, "recording_failure");
        let back = from_proto(&p).unwrap();
        assert_eq!(back, r);
        let h = uc_cdr::chain::compute_hash(&uc_cdr::chain::GENESIS, &back).unwrap();
        assert_eq!(uc_cdr::chain::to_hex(&h), r.hash);

        for tag in [
            uc_cdr::RecordingTag::Recorded,
            uc_cdr::RecordingTag::Partial,
            uc_cdr::RecordingTag::Failed,
            uc_cdr::RecordingTag::NotRecordable,
            uc_cdr::RecordingTag::OptOut,
        ] {
            let r = CallRecord {
                recording: Some(tag),
                ..Default::default()
            };
            let p = to_proto(&r);
            assert_eq!(p.recording, tag.as_str());
            assert_eq!(p.recording_session_id, "");
            assert_eq!(from_proto(&p).unwrap(), r);
        }

        // Not applicable: empty on the wire, None in the record.
        let p = to_proto(&CallRecord::default());
        assert_eq!(
            (p.recording.as_str(), p.recording_session_id.as_str()),
            ("", "")
        );
        let back = from_proto(&p).unwrap();
        assert_eq!((back.recording, back.recording_session_id), (None, None));
    }

    #[test]
    fn rejects_bad_enums() {
        let mut p = to_proto(&CallRecord::default());
        p.disposition = "exploded".into();
        assert!(from_proto(&p).is_err());
        let mut p = to_proto(&CallRecord::default());
        p.q850_cause = Some(999);
        assert!(from_proto(&p).is_err());
        let mut p = to_proto(&CallRecord::default());
        p.trunks_tried.push(TrunkAttempt {
            outcome: "nope".into(),
            ..Default::default()
        });
        assert!(from_proto(&p).is_err());
        let mut p = to_proto(&CallRecord::default());
        p.media_kinds = vec!["video".into()];
        assert!(from_proto(&p).is_err());
        let mut p = to_proto(&CallRecord::default());
        p.media_kinds = vec!["audio".into(), "image".into(), "audio".into()];
        assert!(from_proto(&p).is_err());
        for bad in ["yes", "Recorded", "recorded ", "true"] {
            let mut p = to_proto(&CallRecord::default());
            p.recording = bad.into();
            assert!(from_proto(&p).is_err(), "{bad:?}");
        }
        let mut p = to_proto(&CallRecord::default());
        p.recording_session_id = "x".repeat(uc_cdr::record::MAX_FIELD_LEN + 1);
        assert!(from_proto(&p).is_err());
        p.recording_session_id = "x".repeat(uc_cdr::record::MAX_FIELD_LEN);
        assert!(from_proto(&p).is_ok());
    }
}
