//! Postgres-backed store for phones.
//!
//! The typed model lives in `uc_phone_mgmt::model::Phone` — a 30-field
//! struct with six nested config sub-structs. Mapping every field to its
//! own column would mean tedious schema migrations every time the
//! dashboard learns a new toggle, so the table stores the full struct as
//! JSONB in a `data` column and lifts only what's queryable to first-
//! class columns: `id` (PK) and a normalized MAC for the provisioning
//! lookup. `serve_phone_config` is the hot path — it hits this table once
//! per phone boot — so the MAC lookup must be index-backed.

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use tracing::debug;

use uc_phone_mgmt::model::Phone;

use crate::error::{ConfigStoreError, ConfigStoreResult};

/// Pooled Postgres backend for phones.
#[derive(Clone)]
pub struct PostgresPhoneStore {
    pool: PgPool,
}

impl PostgresPhoneStore {
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

    /// Construct from a pre-existing pool. Lets the daemon share one pool
    /// across all entity stores once we consolidate pooling (planned for
    /// when the third or fourth store lands — currently each store opens
    /// its own pool, which is fine at this size).
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

    /// Normalize a MAC for indexed lookup: strip `:` and `-`, lowercase.
    /// Matches the comparison used today in `serve_phone_config`
    /// (api_server.rs); store + lookup must agree.
    #[must_use]
    pub fn normalize_mac(mac: &str) -> String {
        mac.replace([':', '-'], "").to_lowercase()
    }

    async fn create_tables(&self) -> ConfigStoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS phones (
                id TEXT PRIMARY KEY,
                mac_normalized TEXT NOT NULL,
                data JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await?;
        // Unique on normalized MAC: two phone records sharing a MAC is a
        // provisioning ambiguity (which config wins?), so we surface it
        // at write time instead of silently picking one at lookup time.
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_phones_mac_normalized
             ON phones (mac_normalized)",
        )
        .execute(&self.pool)
        .await?;
        debug!("phones table ready");
        Ok(())
    }

    /// Insert or replace a phone. The MAC is normalized on the way in so
    /// `get_by_mac` can compare against the same canonical form.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors (including the
    /// unique-MAC violation when another phone already owns this MAC) or
    /// `ConfigStoreError::Serialization` if the `Phone` cannot be
    /// JSON-encoded.
    pub async fn upsert(&self, phone: &Phone) -> ConfigStoreResult<()> {
        let mac_normalized = Self::normalize_mac(&phone.mac_address);
        let data = serde_json::to_value(phone)?;
        sqlx::query(
            "INSERT INTO phones (id, mac_normalized, data)
             VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET
                 mac_normalized = EXCLUDED.mac_normalized,
                 data           = EXCLUDED.data,
                 updated_at     = NOW()",
        )
        .bind(&phone.id)
        .bind(&mac_normalized)
        .bind(&data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a phone by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no row matched, or
    /// `ConfigStoreError::Storage` for other DB errors.
    pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
        let result = sqlx::query("DELETE FROM phones WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(ConfigStoreError::NotFound);
        }
        Ok(())
    }

    /// Fetch a phone by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if absent, or
    /// `ConfigStoreError::Storage`/`Serialization` for other failures.
    pub async fn get(&self, id: &str) -> ConfigStoreResult<Phone> {
        let row = sqlx::query("SELECT data FROM phones WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_phone(&row)
    }

    /// Fetch a phone by MAC. Normalizes the caller's input before lookup
    /// — accepts `aa:bb:cc:dd:ee:ff`, `AA-BB-...`, `aabbccddeeff`, etc.
    /// This is the provisioning hot path; see the comment above the
    /// `mac_normalized` index.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no phone owns this MAC.
    pub async fn get_by_mac(&self, mac: &str) -> ConfigStoreResult<Phone> {
        let normalized = Self::normalize_mac(mac);
        let row = sqlx::query("SELECT data FROM phones WHERE mac_normalized = $1")
            .bind(&normalized)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_phone(&row)
    }

    /// Return every phone, ordered by `id`.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors,
    /// `ConfigStoreError::Serialization` if any row's `data` is malformed.
    pub async fn list(&self) -> ConfigStoreResult<Vec<Phone>> {
        let rows = sqlx::query("SELECT data FROM phones ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(Self::row_to_phone(row)?);
        }
        Ok(out)
    }

    /// `true` when there are no phones; used by the migration helper.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn is_empty(&self) -> ConfigStoreResult<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS count FROM phones")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count == 0)
    }

    fn row_to_phone(row: &PgRow) -> ConfigStoreResult<Phone> {
        let data: serde_json::Value = row.try_get("data")?;
        let phone: Phone = serde_json::from_value(data)?;
        Ok(phone)
    }
}
