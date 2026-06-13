//! Per-site config sync agent (Phase 2 of `docs/CENTRAL-CONFIG-PLAN.md`).
//!
//! Runs as one pod per base. Each cycle it pulls its shard's changes from
//! `central-config-api` and applies them transactionally into the
//! site-local Postgres the SBC daemon and provision/api servers already
//! read — making that local database a synced replica of the site's
//! central shard. The agent is the *only* writer of central-origin rows
//! locally; local break-glass writes (`updated_by = 'local'`) are left
//! alone.
//!
//! - [`apply`] — the transactional snapshot/delta apply engine.
//! - [`source`] — the [`ConfigSource`] reads + the [`reconcile`] policy +
//!   the HTTP [`CentralClient`].
//! - [`config`] — env configuration.
//!
//! [`ConfigSource`]: source::ConfigSource
//! [`reconcile`]: source::reconcile
//! [`CentralClient`]: source::CentralClient

pub mod apply;
pub mod config;
pub mod error;
pub mod source;
pub mod status;
pub mod token;

pub use config::{AuthConfig, Config};
pub use error::{SyncError, SyncResult};
pub use source::{CentralClient, ConfigSource, Outcome, reconcile};
pub use status::SyncStatus;
pub use token::{Auth, TokenProvider};
