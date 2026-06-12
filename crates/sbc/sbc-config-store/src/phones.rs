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

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};

use uc_phone_mgmt::model::Phone;

use crate::error::{ConfigStoreError, ConfigStoreResult};
use crate::schema;

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
        schema::ensure_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// Construct from a pre-existing pool. Lets the daemon share one pool
    /// across all entity stores once we consolidate pooling (planned for
    /// when the third or fourth store lands — currently each store opens
    /// its own pool, which is fine at this size).
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` on schema bootstrap failure.
    pub async fn from_pool(pool: PgPool) -> ConfigStoreResult<Self> {
        schema::ensure_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// Expose the underlying pool for cross-store reuse.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Normalize a MAC for indexed lookup: strip `:` and `-`, lowercase.
    /// Matches the comparison used today in `serve_phone_config`
    /// (`api_server.rs`); store + lookup must agree.
    #[must_use]
    pub fn normalize_mac(mac: &str) -> String {
        mac.replace([':', '-'], "").to_lowercase()
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
                 deleted        = FALSE,
                 revision       = 0,
                 updated_by     = 'local',
                 updated_at     = NOW()",
        )
        .bind(&phone.id)
        .bind(&mac_normalized)
        .bind(&data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a phone by ID. Writes a tombstone (`deleted = TRUE`)
    /// rather than removing the row, so central sync can distinguish
    /// "deleted here" from "never existed" and never resurrects it.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no live row matched, or
    /// `ConfigStoreError::Storage` for other DB errors.
    pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
        let result = sqlx::query(
            "UPDATE phones
             SET deleted = TRUE, revision = 0, updated_by = 'local', updated_at = NOW()
             WHERE id = $1 AND NOT deleted",
        )
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
        let row = sqlx::query("SELECT data FROM phones WHERE id = $1 AND NOT deleted")
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
        let row = sqlx::query("SELECT data FROM phones WHERE mac_normalized = $1 AND NOT deleted")
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
        let rows = sqlx::query("SELECT data FROM phones WHERE NOT deleted ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(Self::row_to_phone(row)?);
        }
        Ok(out)
    }

    /// `true` when there are no phones at all — tombstones included.
    /// This gates the one-shot legacy JSON import: "the table has ever
    /// been written" is the signal, so an all-tombstoned table must NOT
    /// read as empty (a stale JSON re-import would resurrect rows).
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
