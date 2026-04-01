//! PostgreSQL storage backend for user management.
//!
//! Uses `sqlx::PgPool` for async, pooled connections suitable for
//! HA deployments where multiple SBC nodes share a single database.

use std::collections::HashMap;

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tracing::debug;

use crate::error::UserMgmtError;
use crate::model::{AuthType, User, UserFilter};
use crate::store::{Result, UserStore};

/// PostgreSQL-backed user store.
///
/// Uses a connection pool for concurrent access across async tasks.
pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    /// Connect to a PostgreSQL database and initialize the schema.
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::StorageError` if the connection pool cannot be
    /// created or the schema migration fails.
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let store = Self { pool };
        store.create_tables().await?;
        Ok(store)
    }

    /// Create a store from an existing connection pool.
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::StorageError` if schema migration fails.
    pub async fn from_pool(pool: PgPool) -> Result<Self> {
        let store = Self { pool };
        store.create_tables().await?;
        Ok(store)
    }

    async fn create_tables(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL,
                sip_uri TEXT NOT NULL,
                auth_type TEXT NOT NULL,
                digest_ha1 TEXT,
                certificate_dn TEXT,
                certificate_san TEXT,
                calling_search_space TEXT,
                device_ids JSONB NOT NULL DEFAULT '[]',
                partition TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                last_login BIGINT,
                metadata JSONB NOT NULL DEFAULT '{}'
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_users_certificate_dn ON users (certificate_dn)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        debug!("PostgreSQL user tables initialized");
        Ok(())
    }

    fn row_to_user(row: &sqlx::postgres::PgRow) -> std::result::Result<User, sqlx::Error> {
        let auth_type_str: String = row.try_get("auth_type")?;
        let auth_type = match auth_type_str.as_str() {
            "Digest" => AuthType::Digest,
            "MtlsPki" => AuthType::MtlsPki,
            "Both" => AuthType::Both,
            _ => AuthType::Digest,
        };

        let device_ids_json: serde_json::Value = row.try_get("device_ids")?;
        let device_ids: Vec<String> =
            serde_json::from_value(device_ids_json).unwrap_or_default();

        let metadata_json: serde_json::Value = row.try_get("metadata")?;
        let metadata: HashMap<String, String> =
            serde_json::from_value(metadata_json).unwrap_or_default();

        Ok(User {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            display_name: row.try_get("display_name")?,
            email: row.try_get("email")?,
            sip_uri: row.try_get("sip_uri")?,
            auth_type,
            digest_ha1: row.try_get("digest_ha1")?,
            certificate_dn: row.try_get("certificate_dn")?,
            certificate_san: row.try_get("certificate_san")?,
            calling_search_space: row.try_get("calling_search_space")?,
            device_ids,
            partition: row.try_get("partition")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_login: row.try_get("last_login")?,
            metadata,
        })
    }
}

impl UserStore for PostgresUserStore {
    async fn create_user(&self, user: User) -> Result<User> {
        let auth_type_str = match user.auth_type {
            AuthType::Digest => "Digest",
            AuthType::MtlsPki => "MtlsPki",
            AuthType::Both => "Both",
        };

        let device_ids_json = serde_json::to_value(&user.device_ids)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let metadata_json = serde_json::to_value(&user.metadata)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        sqlx::query(
            "INSERT INTO users (id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&user.sip_uri)
        .bind(auth_type_str)
        .bind(&user.digest_ha1)
        .bind(&user.certificate_dn)
        .bind(&user.certificate_san)
        .bind(&user.calling_search_space)
        .bind(&device_ids_json)
        .bind(&user.partition)
        .bind(user.enabled)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.last_login)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|de| de.code().as_deref() == Some("23505"))
            {
                UserMgmtError::UserAlreadyExists
            } else {
                UserMgmtError::StorageError(e.to_string())
            }
        })?;

        Ok(user)
    }

    async fn get_user(&self, id: &str) -> Result<User> {
        let row = sqlx::query(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?
        .ok_or(UserMgmtError::UserNotFound)?;

        Self::row_to_user(&row).map_err(|e| UserMgmtError::StorageError(e.to_string()))
    }

    async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let row = sqlx::query(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?
        .ok_or(UserMgmtError::UserNotFound)?;

        Self::row_to_user(&row).map_err(|e| UserMgmtError::StorageError(e.to_string()))
    }

    async fn get_user_by_certificate_dn(&self, dn: &str) -> Result<User> {
        let row = sqlx::query(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE certificate_dn = $1",
        )
        .bind(dn)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?
        .ok_or(UserMgmtError::UserNotFound)?;

        Self::row_to_user(&row).map_err(|e| UserMgmtError::StorageError(e.to_string()))
    }

    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>> {
        let mut sql = String::from(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE TRUE",
        );

        // We build the query dynamically but bind parameters safely.
        // sqlx doesn't support dynamic bind indices easily, so we collect
        // values and use a manual approach with format + bind.
        let mut binds: Vec<String> = Vec::new();
        let mut bind_idx = 1u32;

        if let Some(ref username) = filter.username_contains {
            sql.push_str(&format!(" AND username ILIKE ${bind_idx}"));
            binds.push(format!("%{username}%"));
            bind_idx += 1;
        }

        if let Some(ref auth_type) = filter.auth_type {
            let type_str = match auth_type {
                AuthType::Digest => "Digest",
                AuthType::MtlsPki => "MtlsPki",
                AuthType::Both => "Both",
            };
            sql.push_str(&format!(" AND auth_type = ${bind_idx}"));
            binds.push(type_str.to_owned());
            bind_idx += 1;
        }

        if let Some(ref css) = filter.css_id {
            sql.push_str(&format!(" AND calling_search_space = ${bind_idx}"));
            binds.push(css.clone());
            bind_idx += 1;
        }

        if let Some(enabled) = filter.enabled {
            sql.push_str(&format!(
                " AND enabled = {}",
                if enabled { "TRUE" } else { "FALSE" }
            ));
        }

        sql.push_str(" ORDER BY username");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT ${bind_idx}"));
            binds.push(limit.to_string());
            bind_idx += 1;
        }

        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET ${bind_idx}"));
            binds.push(offset.to_string());
        }

        let mut query = sqlx::query(&sql);
        for val in &binds {
            query = query.bind(val);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let mut users = Vec::with_capacity(rows.len());
        for row in &rows {
            users.push(
                Self::row_to_user(row)
                    .map_err(|e| UserMgmtError::StorageError(e.to_string()))?,
            );
        }
        Ok(users)
    }

    async fn update_user(&self, user: User) -> Result<User> {
        let auth_type_str = match user.auth_type {
            AuthType::Digest => "Digest",
            AuthType::MtlsPki => "MtlsPki",
            AuthType::Both => "Both",
        };

        let device_ids_json = serde_json::to_value(&user.device_ids)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let metadata_json = serde_json::to_value(&user.metadata)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE users SET username = $2, display_name = $3, email = $4, sip_uri = $5,
             auth_type = $6, digest_ha1 = $7, certificate_dn = $8, certificate_san = $9,
             calling_search_space = $10, device_ids = $11, partition = $12, enabled = $13,
             updated_at = $14, last_login = $15, metadata = $16
             WHERE id = $1",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&user.sip_uri)
        .bind(auth_type_str)
        .bind(&user.digest_ha1)
        .bind(&user.certificate_dn)
        .bind(&user.certificate_san)
        .bind(&user.calling_search_space)
        .bind(&device_ids_json)
        .bind(&user.partition)
        .bind(user.enabled)
        .bind(user.updated_at)
        .bind(user.last_login)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(UserMgmtError::UserNotFound);
        }

        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(UserMgmtError::UserNotFound);
        }

        Ok(())
    }

    async fn authenticate_digest(
        &self,
        username: &str,
        _realm: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT digest_ha1 FROM users WHERE username = $1 AND enabled = TRUE
             AND auth_type IN ('Digest', 'Both')",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        match row {
            Some(row) => {
                let ha1: Option<String> = row
                    .try_get("digest_ha1")
                    .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
                Ok(ha1)
            }
            None => Ok(None),
        }
    }

    async fn authenticate_certificate(
        &self,
        dn: &str,
        san: &str,
    ) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE certificate_dn = $1 AND certificate_san = $2
             AND enabled = TRUE AND auth_type IN ('MtlsPki', 'Both')",
        )
        .bind(dn)
        .bind(san)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        match row {
            Some(row) => {
                let user = Self::row_to_user(&row)
                    .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn count_users(&self) -> Result<usize> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let count: i64 = row
            .try_get("count")
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        Ok(count as usize)
    }
}
