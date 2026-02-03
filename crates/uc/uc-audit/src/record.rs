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
pub struct AuditRecord {
    /// Monotonically increasing sequence number.
    pub sequence: u64,

    /// When this record was created.
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

/// Computes the hash chain value for a record.
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
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = bytes.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        serializer.serialize_str(&hex)
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde::de::Error::custom)?;

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
}
