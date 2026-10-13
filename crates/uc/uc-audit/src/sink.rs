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

/// Sink that appends one JSON record per line to a file.
///
/// Records carry the sequence number and SHA-384 hash chain, so the file can
/// be verified for gaps and tampering with [`crate::AuditRecord::verify`].
/// Each write is flushed so a crash loses at most the record being written.
///
/// ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity), AU-9
pub struct FileSink {
    file: std::sync::Mutex<std::fs::File>,
    path: std::path::PathBuf,
}

impl FileSink {
    /// Opens (creating or appending to) the audit log at `path`.
    ///
    /// # Errors
    /// Returns the I/O error when the file cannot be opened for appending.
    pub fn open(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            file: std::sync::Mutex::new(file),
            path,
        })
    }

    /// The file this sink appends to.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl AuditSink for FileSink {
    fn write(&self, record: &AuditRecord) {
        use std::io::Write as _;
        let Ok(mut line) = serde_json::to_vec(record) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut file) = self.file.lock()
            && let Err(e) = file.write_all(&line).and_then(|()| file.flush())
        {
            tracing::error!(path = %self.path.display(), error = %e, "audit record not written");
        }
    }

    fn flush(&self) {
        use std::io::Write as _;
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

/// Sink that collects records in memory (for testing).
#[cfg(test)]
pub struct MemorySink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

#[cfg(test)]
impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
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
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn file_sink_appends_one_json_record_per_line() {
        let path = std::env::temp_dir().join(format!(
            "uc-audit-sink-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sink = FileSink::open(&path).unwrap();
        assert_eq!(sink.path(), path.as_path());
        for seq in 0..2 {
            let event = crate::AuditEvent::SystemStartup(crate::event::SystemStartup {
                version: "test".to_string(),
                config_path: "/dev/null".to_string(),
            });
            let record = AuditRecord::new(seq, event, chrono::Utc::now(), [0u8; 48]);
            sink.write(&record);
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        for (i, line) in lines.iter().enumerate() {
            let parsed: AuditRecord = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.sequence, i as u64);
        }
        let _ = std::fs::remove_file(&path);
    }
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
