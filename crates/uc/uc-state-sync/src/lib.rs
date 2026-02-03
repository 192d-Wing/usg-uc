//! # State Replication Engine for USG SBC Clustering
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::unused_async)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::use_self)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::option_if_let_else)]
#![allow(dead_code)]
//!
//! This crate provides state replication mechanisms for the USG Session Border Controller
//! clustering layer, enabling:
//!
//! - **State Replication**: Synchronize state across cluster nodes
//! - **CRDT Support**: Conflict-free replicated data types for eventual consistency
//! - **Snapshot Sync**: Bulk state transfer for new nodes
//!
//! ## Consistency Models
//!
//! - **Registrations**: Strongly consistent (Raft-based)
//! - **Call State**: Eventually consistent (async + CRDT)
//! - **Rate Limits**: Eventually consistent (PNCounter)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CP-9**: System Backup
//! - **CP-10**: System Recovery and Reconstitution
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    State Sync Manager                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Replicator   │     CRDTs      │    Snapshot    │  Protocol │
//! │  (Async)      │  (G/PN Counter)│    Engine      │  Messages │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod crdt;
pub mod error;
pub mod protocol;
pub mod replicator;
pub mod snapshot;

pub use config::{ReplicationMode, StateSyncConfig};
pub use crdt::{GCounter, LWWRegister, PNCounter};
pub use error::{StateSyncError, StateSyncResult};
pub use protocol::{ReplicationMessage, ReplicationPayload};
pub use replicator::{Replicable, StateReplicator};
pub use snapshot::{SnapshotReader, SnapshotWriter, StateSnapshot};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        // Verify all public types are accessible
        let _ = StateSyncConfig::default();
        let _ = GCounter::new("test");
        let _ = PNCounter::new("test");
    }
}
