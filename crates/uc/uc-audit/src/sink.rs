//! Audit log output sinks.
//!
//! ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity)
//!
//! Sinks handle the actual output of audit records.

use crate::record::AuditRecord;

/// Trait for audit log output destinations.
///
/// ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity)
pub trait AuditSink: Send + Sync {
    /// Writes an audit record to the sink.
    fn write(&self, record: &AuditRecord);

    /// Flushes any buffered records.
    fn flush(&self) {}
}

/// Sink that outputs to the tracing framework.
///
/// This integrates audit logs with the standard logging infrastructure.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn write(&self, record: &AuditRecord) {
        // Use structured logging via tracing
        tracing::info!(
            target: "audit",
            sequence = record.sequence,
            timestamp = %record.timestamp,
            event_type = ?record.event.event_type(),
            hash = %hex_encode(&record.hash_chain),
            event = %serde_json::to_string(&record.event).unwrap_or_default(),
            "audit event"
        );
    }
}

/// Sink that collects records in memory (for testing).
#[cfg(test)]
pub struct MemorySink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

#[cfg(test)]
impl MemorySink {
    /// Creates a new memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns collected records.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
    }
}

/// Helper to encode bytes as hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, AuthMethod, AuthenticationAttempt};
    use chrono::Utc;

    #[test]
    fn test_memory_sink() {
        let sink = MemorySink::new();

        let event = AuditEvent::AuthenticationAttempt(AuthenticationAttempt {
            identity: "test".to_string(),
            source_ip: "::1".parse().unwrap(),
            success: true,
            failure_reason: None,
            method: AuthMethod::Digest,
        });

        let record = AuditRecord::new(1, event, Utc::now(), [0u8; 48]);
        sink.write(&record);

        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 1);
    }
}
