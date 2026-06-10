//! Postgres-backed store for dial plans.
//!
//! Dial plans were genuinely ephemeral before this PR: the daemon held
//! them in `CucmRouter` only, and a restart lost every plan unless the
//! operator re-POSTed them or had them in the ConfigMap seed. With a
//! Postgres store wired in, dial plans persist across daemon restarts
//! and (once `sbc-api` lands in PR5) become writeable from a separate
//! pod without going through the daemon.
//!
//! Schema is JSONB-pass-through like trunk groups — the dial-plan body
//! is a mix of vendor-shape fields and the daemon's existing
//! `sync_dial_plan_to_router` already understands the JSON shape.
//! Adding columns would just mean another schema migration each time
//! we taught the dashboard a new dial-plan toggle.

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use tracing::debug;

use crate::error::{ConfigStoreError, ConfigStoreResult};

/// Pooled Postgres backend for dial plans.
#[derive(Clone)]
pub struct PostgresDialPlanStore {
    pool: PgPool,
}

impl PostgresDialPlanStore {
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
            "CREATE TABLE IF NOT EXISTS dial_plans (
                id TEXT PRIMARY KEY,
                data JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await?;
        debug!("dial_plans table ready");
        Ok(())
    }

    /// Upsert a dial plan's full JSON body.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn upsert(&self, id: &str, data: &serde_json::Value) -> ConfigStoreResult<()> {
        sqlx::query(
            "INSERT INTO dial_plans (id, data)
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

    /// Delete a dial plan by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no row matched, or
    /// `ConfigStoreError::Storage` for other DB errors.
    pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
        let result = sqlx::query("DELETE FROM dial_plans WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(ConfigStoreError::NotFound);
        }
        Ok(())
    }

    /// Fetch a dial plan's JSON body by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if absent.
    pub async fn get(&self, id: &str) -> ConfigStoreResult<serde_json::Value> {
        let row = sqlx::query("SELECT data FROM dial_plans WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_data(&row)
    }

    /// List every dial plan's JSON body, ordered by ID. Used on startup
    /// to replay plans into the `CucmRouter` (so SIP routing decisions
    /// don't fall back to the empty default after a restart).
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn list(&self) -> ConfigStoreResult<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT data FROM dial_plans ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(Self::row_to_data(row)?);
        }
        Ok(out)
    }

    fn row_to_data(row: &PgRow) -> ConfigStoreResult<serde_json::Value> {
        let data: serde_json::Value = row.try_get("data")?;
        Ok(data)
    }
}
