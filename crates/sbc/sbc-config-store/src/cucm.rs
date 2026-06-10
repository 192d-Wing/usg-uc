//! Postgres-backed stores for the four CUCM-routing entities the SBC
//! exposes via REST: partitions, calling search spaces, route patterns,
//! and route lists.
//!
//! All four share the same shape — id PK + JSONB body — and pre-PR11
//! lived in-memory only inside [`uc_routing::CucmRouter`], so a daemon
//! restart wiped them. This module is the persistence half of the move;
//! the daemon's startup loop now replays these tables back into the
//! router on boot.
//!
//! The shape mirrors [`super::trunk_groups::PostgresTrunkGroupStore`]:
//! the dashboard sends JSON bodies of varying shape across entity
//! types, so the store stays a pass-through and the daemon's
//! `sync_*_to_router` helpers do the typed conversion when applying.

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use tracing::debug;

use crate::error::{ConfigStoreError, ConfigStoreResult};

/// Generic JSONB-by-id store. One physical table per CUCM entity type,
/// one [`CucmJsonStore`] instance per table.
#[derive(Clone)]
pub struct CucmJsonStore {
    pool: PgPool,
    table: &'static str,
}

impl CucmJsonStore {
    /// Connect with a fresh pool and ensure the table exists.
    ///
    /// `table` must be a static identifier — it's interpolated into DDL
    /// directly (no sqlx bind-params possible for identifiers).
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` on pool/schema failure.
    pub async fn new(database_url: &str, table: &'static str) -> ConfigStoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        let store = Self { pool, table };
        store.create_tables().await?;
        Ok(store)
    }

    /// Construct from an existing pool (no extra connections).
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` on schema bootstrap failure.
    pub async fn from_pool(pool: PgPool, table: &'static str) -> ConfigStoreResult<Self> {
        let store = Self { pool, table };
        store.create_tables().await?;
        Ok(store)
    }

    /// Expose the underlying pool for cross-store reuse.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn create_tables(&self) -> ConfigStoreResult<()> {
        let ddl = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id TEXT PRIMARY KEY,
                data JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            self.table
        );
        sqlx::query(&ddl).execute(&self.pool).await?;
        debug!(table = self.table, "cucm table ready");
        Ok(())
    }

    /// Upsert a row's JSON body. Updates `updated_at` on conflict.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn upsert(&self, id: &str, data: &serde_json::Value) -> ConfigStoreResult<()> {
        let sql = format!(
            "INSERT INTO {} (id, data)
             VALUES ($1, $2)
             ON CONFLICT (id) DO UPDATE SET
                 data       = EXCLUDED.data,
                 updated_at = NOW()",
            self.table
        );
        sqlx::query(&sql)
            .bind(id)
            .bind(data)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a row by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if no row matched.
    pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
        let sql = format!("DELETE FROM {} WHERE id = $1", self.table);
        let result = sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(ConfigStoreError::NotFound);
        }
        Ok(())
    }

    /// Fetch a row's JSON body by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::NotFound` if absent.
    pub async fn get(&self, id: &str) -> ConfigStoreResult<serde_json::Value> {
        let sql = format!("SELECT data FROM {} WHERE id = $1", self.table);
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ConfigStoreError::NotFound)?;
        Self::row_to_data(&row)
    }

    /// List every row's JSON body, ordered by ID.
    ///
    /// # Errors
    /// Returns `ConfigStoreError::Storage` for DB errors.
    pub async fn list(&self) -> ConfigStoreResult<Vec<serde_json::Value>> {
        let sql = format!("SELECT data FROM {} ORDER BY id", self.table);
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
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

/// Newtype wrappers so handler code can ask for one specific entity's
/// store without accidentally getting another. They're zero-cost and
/// make `AppState` field types descriptive.
macro_rules! cucm_store {
    ($name:ident, $table:literal) => {
        /// Postgres-backed store for the named CUCM entity. JSONB
        /// pass-through over [`CucmJsonStore`].
        #[derive(Clone)]
        pub struct $name(CucmJsonStore);

        impl $name {
            /// Open with a fresh pool.
            ///
            /// # Errors
            /// See [`CucmJsonStore::new`].
            pub async fn new(database_url: &str) -> ConfigStoreResult<Self> {
                Ok(Self(CucmJsonStore::new(database_url, $table).await?))
            }

            /// Open from an existing pool.
            ///
            /// # Errors
            /// See [`CucmJsonStore::from_pool`].
            pub async fn from_pool(pool: PgPool) -> ConfigStoreResult<Self> {
                Ok(Self(CucmJsonStore::from_pool(pool, $table).await?))
            }

            /// Expose the underlying pool.
            #[must_use]
            pub fn pool(&self) -> &PgPool {
                self.0.pool()
            }

            /// Upsert by ID.
            ///
            /// # Errors
            /// See [`CucmJsonStore::upsert`].
            pub async fn upsert(
                &self,
                id: &str,
                data: &serde_json::Value,
            ) -> ConfigStoreResult<()> {
                self.0.upsert(id, data).await
            }

            /// Delete by ID.
            ///
            /// # Errors
            /// See [`CucmJsonStore::delete`].
            pub async fn delete(&self, id: &str) -> ConfigStoreResult<()> {
                self.0.delete(id).await
            }

            /// Fetch JSON body by ID.
            ///
            /// # Errors
            /// See [`CucmJsonStore::get`].
            pub async fn get(&self, id: &str) -> ConfigStoreResult<serde_json::Value> {
                self.0.get(id).await
            }

            /// List all rows' bodies, ordered by ID.
            ///
            /// # Errors
            /// See [`CucmJsonStore::list`].
            pub async fn list(&self) -> ConfigStoreResult<Vec<serde_json::Value>> {
                self.0.list().await
            }
        }
    };
}

cucm_store!(PostgresPartitionStore, "cucm_partitions");
cucm_store!(
    PostgresCallingSearchSpaceStore,
    "cucm_calling_search_spaces"
);
cucm_store!(PostgresRoutePatternStore, "cucm_route_patterns");
cucm_store!(PostgresRouteListStore, "cucm_route_lists");
