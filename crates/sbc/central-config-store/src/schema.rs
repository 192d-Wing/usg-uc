//! Embedded migrations for the central config database.
//!
//! The central DDL is the single source of truth in
//! `deploy/central-db/migrations`; this module embeds those same files so
//! the service migrates itself on startup (no `psql -f` bootstrap), and
//! `deploy/central-db/README.md`'s "Phase 1 wraps these in an embedded
//! migrator" is satisfied. One copy, two consumers (this migrator and the
//! schema-drift test in `sbc-config-store`).
//!
//! Note the migrations create only the *parent* partitioned tables;
//! per-site partitions are created by
//! [`CentralConfigStore::register_site`] as sites are onboarded.
//!
//! [`CentralConfigStore::register_site`]: crate::CentralConfigStore::register_site

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::error::CentralResult;

static MIGRATOR: Migrator = sqlx::migrate!("../../../deploy/central-db/migrations");

/// Run any pending central migrations.
///
/// # Errors
/// [`crate::error::CentralError::Storage`] if a migration fails or the
/// recorded history conflicts with the embedded files.
pub async fn ensure_schema(pool: &PgPool) -> CentralResult<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}
