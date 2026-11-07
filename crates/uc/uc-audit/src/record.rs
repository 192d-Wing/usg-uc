//! Audit record with integrity protection.
//!
//! ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
//!
//! Audit records include a cryptographic hash chain for tamper detection.

use crate::event::AuditEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit record with integrity protection.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
///
/// Contains:
/// - Sequence number for ordering
/// - Timestamp for when the event occurred
/// - The audit event itself
/// - Hash chain for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number.
    pub sequence: u64,

    /// When the writer thread chained this record (time recorded, not time
    /// queued). Taken when the sequence number is assigned, so timestamps are
    /// non-decreasing in sequence order unless the wall clock steps; a step
    /// is kept as-is, not clamped.
    ///
    /// ## NIST 800-53 Rev5: AU-8 (Time Stamps)
    pub timestamp: DateTime<Utc>,

    /// The audit event.
    pub event: AuditEvent,

    /// Hash chain linking this record to the previous one.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
    ///
    /// SHA-384 hash of: `previous_hash` || sequence || timestamp || `event_json`
    #[serde(with = "hex_array")]
    pub hash_chain: [u8; 48],
}

impl AuditRecord {
    /// Creates a new audit record with hash chain.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
    #[must_use]
    pub fn new(
        sequence: u64,
        event: AuditEvent,
        timestamp: DateTime<Utc>,
        previous_hash: [u8; 48],
    ) -> Self {
        let hash_chain = compute_hash_chain(&previous_hash, sequence, &timestamp, &event);

        Self {
            sequence,
            timestamp,
            event,
            hash_chain,
        }
    }

    /// Verifies the hash chain is correct given the previous record's hash.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
    #[must_use]
    pub fn verify(&self, previous_hash: &[u8; 48]) -> bool {
        let expected =
            compute_hash_chain(previous_hash, self.sequence, &self.timestamp, &self.event);
        self.hash_chain == expected
    }
}

/// Parses one on-disk audit line (without its newline) and requires it to
/// be the exact canonical serialization of the parsed record.
///
/// ## NIST 800-53 Rev5: AU-9, SI-7 (Software, Firmware, and Information Integrity)
///
/// The hash covers the re-serialized record, not the raw bytes, so any byte
/// serde would discard or normalize (an extra key, reordered keys,
/// whitespace, an alternate timestamp offset, an escaped form of the same
/// string) would otherwise go unauthenticated. Such lines are rejected.
///
/// # Errors
/// Returns a description (never echoing line content) when the line does
/// not parse or is not byte-for-byte canonical.
pub fn parse_canonical(line: &[u8]) -> Result<AuditRecord, String> {
    let record: AuditRecord =
        serde_json::from_slice(line).map_err(|e| format!("bad record: {e}"))?;
    let canonical = serde_json::to_vec(&record).map_err(|e| format!("bad record: {e}"))?;
    if canonical != line {
        return Err("record is not in canonical form (bytes not covered by the hash)".to_string());
    }
    Ok(record)
}

/// Computes the hash chain value for a record.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
// POAM: POA&M-130 -- the chain is unkeyed SHA-384 (tamper-evident only);
// anyone who can write the file can recompute it. Key it (HMAC-SHA-384) or
// sign checkpoints (ML-DSA-87) for AU-9(3) / AU-10.
fn compute_hash_chain(
    previous_hash: &[u8; 48],
    sequence: u64,
    timestamp: &DateTime<Utc>,
    event: &AuditEvent,
) -> [u8; 48] {
    use uc_crypto::hash::Sha384;

    let mut hasher = Sha384::new();

    // Include previous hash
    hasher.update(previous_hash);

    // Include sequence number
    hasher.update(&sequence.to_be_bytes());

    // Include timestamp
    let ts_string = timestamp.to_rfc3339();
    hasher.update(ts_string.as_bytes());

    // Include event JSON
    if let Ok(event_json) = serde_json::to_vec(event) {
        hasher.update(&event_json);
    }

    hasher.finish()
}

/// Serde helper for hex encoding/decoding fixed-size arrays.
///
/// ## NIST 800-53 Rev5: AU-9, SI-10 (Information Input Validation)
///
/// Audit files are read back by the resume path and the verifier, so the
/// hash field is untrusted input: odd-length, non-hex, multibyte or
/// wrong-length values are a serde error (reported as tamper), never a panic.
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the hash as lowercase hex.
    ///
    /// # Errors
    /// Returns the serializer's error.
    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Parses a 96-character hex string into a 48-byte hash.
    ///
    /// # Errors
    /// Returns an error for non-hex, odd-length or wrong-length input.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid hash length"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::event::{AuthMethod, AuthenticationAttempt};

    fn sample_event() -> AuditEvent {
        AuditEvent::AuthenticationAttempt(AuthenticationAttempt {
            identity: "test".to_string(),
            source_ip: "::1".parse().expect("valid loopback"),
            success: true,
            failure_reason: None,
            method: AuthMethod::Digest,
        })
    }

    #[test]
    fn test_record_creation() {
        let event = sample_event();
        let timestamp = Utc::now();
        let previous_hash = [0u8; 48];

        let record = AuditRecord::new(1, event, timestamp, previous_hash);

        assert_eq!(record.sequence, 1);
        assert_ne!(record.hash_chain, [0u8; 48]);
    }

    #[test]
    fn test_record_verification() {
        let event = sample_event();
        let timestamp = Utc::now();
        let previous_hash = [0u8; 48];

        let record = AuditRecord::new(1, event, timestamp, previous_hash);

        assert!(record.verify(&previous_hash));
        assert!(!record.verify(&[1u8; 48]));
    }

    #[test]
    fn test_hash_chain_linkage() {
        let event1 = sample_event();
        let event2 = sample_event();
        let timestamp = Utc::now();
        let initial_hash = [0u8; 48];

        let record1 = AuditRecord::new(1, event1, timestamp, initial_hash);
        let record2 = AuditRecord::new(2, event2, timestamp, record1.hash_chain);

        // Record 1 verifies against initial hash
        assert!(record1.verify(&initial_hash));

        // Record 2 verifies against record 1's hash
        assert!(record2.verify(&record1.hash_chain));

        // Record 2 does NOT verify against initial hash (chain broken)
        assert!(!record2.verify(&initial_hash));
    }

    #[test]
    fn test_record_serialization() {
        let event = sample_event();
        let timestamp = Utc::now();
        let record = AuditRecord::new(1, event, timestamp, [0u8; 48]);

        let json = serde_json::to_string(&record).expect("serialize record");
        let deserialized: AuditRecord = serde_json::from_str(&json).expect("deserialize record");

        assert_eq!(record.sequence, deserialized.sequence);
        assert_eq!(record.hash_chain, deserialized.hash_chain);
    }

    fn record_json_with_hash(hash: &str) -> String {
        let record = AuditRecord::new(1, sample_event(), Utc::now(), [0u8; 48]);
        let mut v = serde_json::to_value(&record).unwrap();
        v["hash_chain"] = serde_json::Value::String(hash.to_string());
        v.to_string()
    }

    #[test]
    fn hex_odd_length_errors() {
        let json = record_json_with_hash(&"a".repeat(95));
        assert!(serde_json::from_str::<AuditRecord>(&json).is_err());
    }

    #[test]
    fn hex_multibyte_errors() {
        // 48 two-byte chars: even byte length, but slicing at byte offsets
        // would split a char (the old decoder panicked here).
        let json = record_json_with_hash(&"\u{e9}".repeat(48));
        assert!(serde_json::from_str::<AuditRecord>(&json).is_err());
        let json = record_json_with_hash(&format!("{}\u{e9}", "a".repeat(95)));
        assert!(serde_json::from_str::<AuditRecord>(&json).is_err());
    }

    #[test]
    fn hex_wrong_length_errors() {
        for s in [
            "",
            "00",
            &"ab".repeat(47),
            &"ab".repeat(49),
            &"zz".repeat(48),
        ] {
            let json = record_json_with_hash(s);
            assert!(serde_json::from_str::<AuditRecord>(&json).is_err(), "{s}");
        }
    }

    #[test]
    fn hex_roundtrip() {
        for seed in 0u8..=255 {
            let mut hash = [0u8; 48];
            for (i, b) in hash.iter_mut().enumerate() {
                *b = seed.wrapping_mul(31).wrapping_add(u8::try_from(i).unwrap());
            }
            let mut record = AuditRecord::new(1, sample_event(), Utc::now(), [0u8; 48]);
            record.hash_chain = hash;
            let json = serde_json::to_string(&record).unwrap();
            let back: AuditRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(back.hash_chain, hash);
        }
    }
}
