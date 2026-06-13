//! Persistence layer for SBC management entities.
//!
//! The SBC's REST API today persists phones, directory numbers, and trunk
//! groups as JSON files on a per-pod PVC. That model only works while one
//! pod owns both the API and the SIP path. Splitting the API into its own
//! pod (so dashboard/API releases stop interrupting SIP) requires the two
//! pods to share configuration state.
//!
//! This crate is that shared state. PR1 covers `DirectoryNumber` only;
//! phones, trunk groups, and dial plans follow the same shape in
//! subsequent PRs.
//!
//! Backends:
//! - [`PostgresDirectoryNumberStore`] — the production backend. Used when
//!   the daemon's `[storage.postgres]` section is configured.
//! - The legacy JSON-on-disk path remains in `sbc-daemon::MemStore` and is
//!   chosen at runtime when no DSN is configured, so existing single-pod
//!   deploys keep working unchanged.

pub mod dial_plans;
pub mod directory;
pub mod error;
pub mod migration;
pub mod model;
pub mod phones;
pub mod sbc;
pub mod schema;
pub mod trunk_groups;

pub use dial_plans::PostgresDialPlanStore;
pub use directory::PostgresDirectoryNumberStore;
pub use error::{ConfigStoreError, ConfigStoreResult};
pub use migration::{
    migrate_directory_json_to_postgres, migrate_phones_json_to_postgres,
    migrate_trunk_groups_json_to_postgres,
};
pub use model::DirectoryNumber;
pub use phones::PostgresPhoneStore;
pub use sbc::{
    PostgresCallingSearchSpaceStore, PostgresPartitionStore, PostgresRouteListStore,
    PostgresRoutePatternStore,
};
pub use schema::ensure_schema;
pub use trunk_groups::PostgresTrunkGroupStore;
