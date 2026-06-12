//! Postgres-backed store for [`DirectoryNumber`].
//!
//! Schema mirrors the typed model (one column per first-class field) plus a
//! JSONB `extra` column for forward-compatible fields the schema hasn't
//! caught up with yet. Indices are intentionally minimal — DID volume per
//! site is in the thousands, not millions; pg can table-scan happily.

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};

use crate::error::{ConfigStoreError, ConfigStoreResult};
use crate::model::DirectoryNumber;
use crate::schema;

/// Pooled Postgres backend for directory numbers.
#[derive(Clone)]
pub struct PostgresDirectoryNumberStore {
    pool: PgPool,
}

impl PostgresDirectoryNumberStore {
    /// Connect with a fresh pool and ensure the table exists.
    ///
    /// `max_connections` should be small (default 5) — DID writes are
    /// low-volume operator actions, not on the SIP hot path.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` if the pool cannot be created
    /// or the schema bootstrap fails.
    pub async fn new(database_url: &str) -> ConfigStoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        schema::ensure_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// Construct from a pre-existing pool (lets multiple stores share one
    /// pool once we add phones/trunks/dial-plans in later PRs).
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` if schema bootstrap fails.
    pub async fn from_pool(pool: PgPool) -> ConfigStoreResult<Self> {
        schema::ensure_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// Expose the underlying pool so future stores in this crate (phones,
    /// trunks, dial-plans) can share it.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Insert a DID, or replace the existing row if `did` already exists.
    /// Used by both the POST handler (operator add) and the PUT handler
    /// (operator update) — the SBC's REST surface today treats these as
    /// upserts, so we match.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for any DB error or
    /// `ConfigStoreError::Serialization` if the `extra` map cannot be
    /// JSON-encoded.
    pub async fn upsert(&self, dn: &DirectoryNumber) -> ConfigStoreResult<()> {
        let extra_json = serde_json::to_value(&dn.extra)?;
        sqlx::query(
            "INSERT INTO directory_numbers (did, sip_user, partition, description, extra)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (did) DO UPDATE SET
                 sip_user    = EXCLUDED.sip_user,
                 partition   = EXCLUDED.partition,
                 description = EXCLUDED.description,
                 extra       = EXCLUDED.extra,
                 deleted     = FALSE,
                 updated_at  = NOW()",
        )
        .bind(&dn.did)
        .bind(&dn.user)
        .bind(&dn.partition)
        .bind(&dn.description)
        .bind(&extra_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a DID. Returns `NotFound` if the DID didn't exist.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors, or
    /// `ConfigStoreError::NotFound` if the DID didn't exist.
    pub async fn delete(&self, did: &str) -> ConfigStoreResult<()> {
        let result = sqlx::query("DELETE FROM directory_numbers WHERE did = $1")
            .bind(did)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(ConfigStoreError::NotFound);
        }
        Ok(())
    }

    /// Fetch one DID. Returns `NotFound` if absent.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors or
    /// `ConfigStoreError::NotFound` if the DID isn't present.
    pub async fn get(&self, did: &str) -> ConfigStoreResult<DirectoryNumber> {
        let row = sqlx::query(
            "SELECT did, sip_user, partition, description, extra
             FROM directory_numbers WHERE did = $1 AND NOT deleted",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_dn(&row)
    }

    /// Return every DID, ordered by `did`. The SBC's `/directory` endpoint
    /// has no pagination today; volume is bounded and operator-scale.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn list(&self) -> ConfigStoreResult<Vec<DirectoryNumber>> {
        let rows = sqlx::query(
            "SELECT did, sip_user, partition, description, extra
             FROM directory_numbers WHERE NOT deleted ORDER BY did",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(Self::row_to_dn(row)?);
        }
        Ok(out)
    }

    /// `true` when there are no DIDs in the table. Used by the JSON
    /// migration helper to decide whether backfill is needed.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn is_empty(&self) -> ConfigStoreResult<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS count FROM directory_numbers WHERE NOT deleted")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("count")?;
        Ok(count == 0)
    }

    fn row_to_dn(row: &PgRow) -> ConfigStoreResult<DirectoryNumber> {
        let extra_json: serde_json::Value = row.try_get("extra")?;
        let extra: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_value(extra_json)?;
        Ok(DirectoryNumber {
            did: row.try_get("did")?,
            user: row.try_get("sip_user")?,
            partition: row.try_get("partition")?,
            description: row.try_get("description")?,
            extra,
        })
    }
}
