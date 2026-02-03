//! Snapshot management for bulk state transfer.

use crate::error::{StateSyncError, StateSyncResult};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// State snapshot for bulk transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot version.
    pub version: u64,
    /// Creation timestamp (Unix epoch milliseconds).
    pub created_at: i64,
    /// Source node ID.
    pub source_node: String,
    /// Snapshot entries.
    pub entries: Vec<SnapshotEntry>,
    /// Metadata.
    pub metadata: HashMap<String, String>,
}

impl StateSnapshot {
    /// Creates a new empty snapshot.
    #[must_use]
    pub fn new(version: u64, source_node: impl Into<String>) -> Self {
        Self {
            version,
            created_at: chrono::Utc::now().timestamp_millis(),
            source_node: source_node.into(),
            entries: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Adds an entry to the snapshot.
    pub fn add_entry(&mut self, key: impl Into<String>, value: Bytes, entry_type: EntryType) {
        self.entries.push(SnapshotEntry {
            key: key.into(),
            value,
            entry_type,
        });
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if the snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds metadata.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Serializes the snapshot to bytes.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> StateSyncResult<Bytes> {
        let json = serde_json::to_vec(self)?;
        Ok(Bytes::from(json))
    }

    /// Deserializes a snapshot from bytes.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn from_bytes(data: &[u8]) -> StateSyncResult<Self> {
        serde_json::from_slice(data).map_err(|e| StateSyncError::DeserializationError {
            reason: e.to_string(),
        })
    }
}

/// Snapshot entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Entry key.
    pub key: String,
    /// Entry value.
    pub value: Bytes,
    /// Entry type.
    pub entry_type: EntryType,
}

/// Types of snapshot entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    /// Key-value data.
    KeyValue,
    /// Registration data.
    Registration,
    /// Call state.
    CallState,
    /// CRDT state.
    Crdt,
    /// Configuration.
    Config,
}

/// Snapshot writer for creating snapshots.
pub struct SnapshotWriter {
    snapshot: StateSnapshot,
    chunk_size: usize,
}

impl SnapshotWriter {
    /// Creates a new snapshot writer.
    #[must_use]
    pub fn new(version: u64, source_node: impl Into<String>, chunk_size: usize) -> Self {
        Self {
            snapshot: StateSnapshot::new(version, source_node),
            chunk_size,
        }
    }

    /// Adds an entry to the snapshot.
    pub fn write(&mut self, key: impl Into<String>, value: Bytes, entry_type: EntryType) {
        self.snapshot.add_entry(key, value, entry_type);
    }

    /// Adds metadata.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.snapshot.add_metadata(key, value);
    }

    /// Returns the number of entries written.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.snapshot.len()
    }

    /// Finalizes the snapshot.
    #[must_use]
    pub fn finalize(self) -> StateSnapshot {
        info!(
            version = self.snapshot.version,
            entries = self.snapshot.len(),
            "Finalized snapshot"
        );
        self.snapshot
    }

    /// Converts to chunked bytes for transmission.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_chunks(&self) -> StateSyncResult<Vec<Bytes>> {
        let data = self.snapshot.to_bytes()?;
        let mut chunks = Vec::new();

        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + self.chunk_size).min(data.len());
            chunks.push(data.slice(offset..end));
            offset = end;
        }

        debug!(
            total_size = data.len(),
            chunk_count = chunks.len(),
            "Split snapshot into chunks"
        );

        Ok(chunks)
    }
}

/// Snapshot reader for processing incoming snapshots.
pub struct SnapshotReader {
    /// Chunks received.
    chunks: Vec<(u32, Bytes)>,
    /// Total expected chunks.
    total_chunks: Option<u32>,
    /// Version being received.
    version: u64,
}

impl SnapshotReader {
    /// Creates a new snapshot reader.
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self {
            chunks: Vec::new(),
            total_chunks: None,
            version,
        }
    }

    /// Adds a chunk.
    pub fn add_chunk(&mut self, index: u32, total: u32, data: Bytes) {
        if self.total_chunks.is_none() {
            self.total_chunks = Some(total);
        }
        self.chunks.push((index, data));
    }

    /// Checks if all chunks have been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total_chunks
            .map_or(false, |total| self.chunks.len() == total as usize)
    }

    /// Returns the progress as a fraction.
    #[must_use]
    pub fn progress(&self) -> f64 {
        self.total_chunks.map_or(0.0, |total| {
            if total == 0 {
                1.0
            } else {
                self.chunks.len() as f64 / total as f64
            }
        })
    }

    /// Assembles the snapshot from chunks.
    ///
    /// # Errors
    /// Returns an error if the snapshot is incomplete or invalid.
    pub fn assemble(&self) -> StateSyncResult<StateSnapshot> {
        if !self.is_complete() {
            return Err(StateSyncError::SnapshotApplicationFailed {
                reason: "Snapshot incomplete".to_string(),
            });
        }

        // Sort chunks by index and concatenate
        let mut sorted: Vec<_> = self.chunks.iter().collect();
        sorted.sort_by_key(|(idx, _)| *idx);

        let mut data = BytesMut::new();
        for (_, chunk) in sorted {
            data.extend_from_slice(chunk);
        }

        StateSnapshot::from_bytes(&data)
    }

    /// Returns the version being received.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_creation() {
        let mut snapshot = StateSnapshot::new(1, "node1");

        snapshot.add_entry("key1", Bytes::from("value1"), EntryType::KeyValue);
        snapshot.add_entry("key2", Bytes::from("value2"), EntryType::Registration);
        snapshot.add_metadata("created_by", "test");

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot.metadata.get("created_by"),
            Some(&"test".to_string())
        );
    }

    #[test]
    fn test_snapshot_serialization() {
        let mut snapshot = StateSnapshot::new(1, "node1");
        snapshot.add_entry("key", Bytes::from("value"), EntryType::KeyValue);

        let bytes = snapshot.to_bytes().unwrap();
        let restored = StateSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, 1);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.entries[0].key, "key");
    }

    #[test]
    fn test_snapshot_writer() {
        let mut writer = SnapshotWriter::new(1, "node1", 1024);

        writer.write("key1", Bytes::from("value1"), EntryType::KeyValue);
        writer.write("key2", Bytes::from("value2"), EntryType::CallState);
        writer.add_metadata("test", "metadata");

        assert_eq!(writer.entry_count(), 2);

        let snapshot = writer.finalize();
        assert_eq!(snapshot.len(), 2);
    }

    #[test]
    fn test_snapshot_chunking() {
        let mut writer = SnapshotWriter::new(1, "node1", 50); // Small chunks

        for i in 0..10 {
            writer.write(
                format!("key{i}"),
                Bytes::from(format!("value{i}")),
                EntryType::KeyValue,
            );
        }

        let chunks = writer.to_chunks().unwrap();
        assert!(chunks.len() > 1); // Should be split into multiple chunks
    }

    #[test]
    fn test_snapshot_reader() {
        // Create a snapshot
        let mut writer = SnapshotWriter::new(1, "node1", 100);
        writer.write("key", Bytes::from("value"), EntryType::KeyValue);
        let chunks = writer.to_chunks().unwrap();

        // Read it back
        let mut reader = SnapshotReader::new(1);
        let total = chunks.len() as u32;

        for (idx, chunk) in chunks.into_iter().enumerate() {
            reader.add_chunk(idx as u32, total, chunk);
        }

        assert!(reader.is_complete());
        assert_eq!(reader.progress(), 1.0);

        let snapshot = reader.assemble().unwrap();
        assert_eq!(snapshot.len(), 1);
    }

    #[test]
    fn test_incomplete_reader() {
        let reader = SnapshotReader::new(1);
        assert!(!reader.is_complete());

        let result = reader.assemble();
        assert!(result.is_err());
    }
}
