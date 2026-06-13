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
//! Every store constructor calls [`ensure_schema`]. The first call per
//! database runs the migrator (sqlx records history in
//! `_sqlx_migrations` and serializes concurrent runners behind a
//! Postgres advisory lock, so racing pods are safe); subsequent calls
//! from the same process — the daemon and api-server construct 8–9
//! stores at startup — short-circuit on an in-process cache keyed by
//! server identity, costing one round trip instead of a full
//! lock-and-history pass.
//!
//! Privileges: unlike the old bootstrap (a no-op on existing tables),
//! the migrator needs `CREATE` on the schema (for `_sqlx_migrations` /
//! `sync_state`) and ownership of the config tables (for `ALTER TABLE`
//! in 0002+). The in-cluster Postgres chart satisfies this (the app
//! role bootstraps the database); external/managed databases must grant
//! the same or pre-apply the migrations out of band.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex, PoisonError};

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::error::ConfigStoreResult;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Databases this process has already migrated, keyed by server
/// identity + database name. Lets every store constructor call
/// [`ensure_schema`] unconditionally without re-paying the migrator's
/// advisory-lock and history round trips 8–9× per startup.
static MIGRATED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// `inet_server_addr()`/`port()` are NULL on unix-socket connections;
/// the database name alone still disambiguates the common multi-DB case
/// (integration tests against one local server).
const IDENTITY_SQL: &str = "SELECT current_database()::text
    || ':' || COALESCE(inet_server_addr()::text, 'local')
    || ':' || COALESCE(inet_server_port()::text, '0')";

/// Run any pending migrations against the given pool (once per database
/// per process; later calls are a single round-trip no-op).
///
/// # Errors
/// Returns `ConfigStoreError::Storage` if a migration fails to apply or
/// the recorded history conflicts with the embedded files (e.g. an
/// edited past migration — fix the file mismatch, never edit applied
/// migrations).
pub async fn ensure_schema(pool: &PgPool) -> ConfigStoreResult<()> {
    let identity: String = sqlx::query_scalar(IDENTITY_SQL).fetch_one(pool).await?;
    {
        let cache = MIGRATED.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.contains(&identity) {
            return Ok(());
        }
    }
    MIGRATOR.run(pool).await?;
    MIGRATED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(identity);
    Ok(())
}
