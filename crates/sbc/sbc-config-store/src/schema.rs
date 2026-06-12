//! Embedded sqlx migrations for the site-local config database.
//!
//! Replaces the per-store inline `CREATE TABLE IF NOT EXISTS` bootstrap.
//! Migration files live in this crate's `migrations/` directory and are
//! compiled into the binary, so a pod needs no filesystem access to
//! migrate. `0001_baseline.sql` recreates exactly what the old inline
//! DDL built (everything IF NOT EXISTS, so databases bootstrapped by
//! older builds adopt the migration history cleanly); later migrations
//! evolve the schema from there.
//!
//! Every store constructor calls [`ensure_schema`]. sqlx records applied
//! migrations in `_sqlx_migrations` and serializes concurrent runners
//! behind a Postgres advisory lock, so repeated calls — from multiple
//! stores sharing a pool, or from multiple pods racing at startup — are
//! cheap no-ops.

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::error::ConfigStoreResult;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Run any pending migrations against the given pool.
///
/// # Errors
/// Returns `ConfigStoreError::Storage` if a migration fails to apply or
/// the recorded history conflicts with the embedded files (e.g. an
/// edited past migration — fix the file mismatch, never edit applied
/// migrations).
pub async fn ensure_schema(pool: &PgPool) -> ConfigStoreResult<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}
