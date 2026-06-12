//! Partition-aware persistence for the fleet-wide central config
//! database (Phase 1 of `docs/CENTRAL-CONFIG-PLAN.md`).
//!
//! This crate is the write-and-sync half of the central stack. It owns
//! the central schema (embedded migrations), creates per-site partitions
//! as bases are onboarded, performs every config write as one
//! transaction (epoch bump + revision stamp + journal append), enforces
//! fleet-wide DID uniqueness, and serves the three sync reads the per-site
//! `sbc-config-sync` agent pulls: [`epoch`], [`delta`], [`snapshot`].
//!
//! It deliberately does not depend on the SIP daemon or its gRPC surface:
//! the central API only writes Postgres; sites pull and apply on their own.
//!
//! [`epoch`]: CentralConfigStore::epoch
//! [`delta`]: CentralConfigStore::delta
//! [`snapshot`]: CentralConfigStore::snapshot

pub mod error;
pub mod model;
pub mod schema;
pub mod store;

pub use error::{CentralError, CentralResult};
pub use model::{Change, ChangeOp, ConfigTable, DeltaResult, Snapshot, TableRows};
pub use schema::ensure_schema;
pub use store::CentralConfigStore;
