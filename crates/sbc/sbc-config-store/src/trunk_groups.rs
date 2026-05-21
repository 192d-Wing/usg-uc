//! Postgres-backed store for trunk groups.
//!
//! Unlike DIDs (typed model) and phones (reuse uc_phone_mgmt::Phone), the
//! trunk-group body is currently passed through as `serde_json::Value`
//! end-to-end. `sync_trunk_group_to_router` in the daemon pulls per-trunk
//! config (priority, weight, cooldown, options-ping, register creds,
//! etc.) directly out of the JSON; the dashboard sends bodies of varying
//! shape across vendors. A typed wrapper would either be incomplete (and
//! then everyone has to fall back to `extra`-style JSON anyway) or a
//! sprawling enum.
//!
//! So the store is a JSONB pass-through keyed by `id`. The daemon's
//! existing `sync_trunk_group_to_router` keeps reading from the same
//! `serde_json::Value` shape it already understands.

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use tracing::debug;

use crate::error::{ConfigStoreError, ConfigStoreResult};

/// Pooled Postgres backend for trunk groups.
#[derive(Clone)]
pub struct PostgresTrunkGroupStore {
    pool: PgPool,
}

impl PostgresTrunkGroupStore {
    /// Connect with a fresh pool and ensure the table exists.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` on pool/schema failure.
    pub async fn new(database_url: &str) -> ConfigStoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        let store = Self { pool };
        store.create_tables().await?;
        Ok(store)
    }

    /// Construct from an existing pool.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` on schema bootstrap failure.
    pub async fn from_pool(pool: PgPool) -> ConfigStoreResult<Self> {
        let store = Self { pool };
        store.create_tables().await?;
        Ok(store)
    }

    /// Expose the underlying pool for cross-store reuse.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn create_tables(&self) -> ConfigStoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS trunk_groups (
                id TEXT PRIMARY KEY,
                data JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await?;
        debug!("trunk_groups table ready");
        Ok(())
    }

    /// Upsert a trunk group's full JSON body.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn upsert(&self, id: &str, data: &serde_json::Value) -> ConfigStoreResult<()> {
        sqlx::query(
            "INSERT INTO trunk_groups (id, data)
             VALUES ($1, $2)
             ON CONFLICT (id) DO UPDATE SET
                 data       = EXCLUDED.data,
                 updated_at = NOW()",
        )
        .bind(id)
        .bind(data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a trunk group by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no row matched, or
    /// `ConfigStoreError::Storage` for other DB errors.
    pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
        let result = sqlx::query("DELETE FROM trunk_groups WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(ConfigStoreError::NotFound);
        }
        Ok(())
    }

    /// Fetch a trunk group's JSON body by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if absent.
    pub async fn get(&self, id: &str) -> ConfigStoreResult<serde_json::Value> {
        let row = sqlx::query("SELECT data FROM trunk_groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_data(&row)
    }

    /// List every trunk group's JSON body, ordered by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn list(&self) -> ConfigStoreResult<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT data FROM trunk_groups ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(Self::row_to_data(row)?);
        }
        Ok(out)
    }

    /// `true` when there are no trunk groups; used by the migration helper.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn is_empty(&self) -> ConfigStoreResult<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS count FROM trunk_groups")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count == 0)
    }

    fn row_to_data(row: &PgRow) -> ConfigStoreResult<serde_json::Value> {
        let data: serde_json::Value = row.try_get("data")?;
        Ok(data)
    }
}
