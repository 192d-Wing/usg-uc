//! SQLite storage backend for user management.

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use tracing::debug;

use crate::error::UserMgmtError;
use crate::model::{AuthType, User, UserFilter};
use crate::store::{Result, UserStore};

/// SQLite-backed user store.
///
/// Uses a `Mutex<Connection>` for thread-safe access.
pub struct SqliteUserStore {
    conn: Mutex<Connection>,
}

impl SqliteUserStore {
    /// Open or create a SQLite database at the given path.
    ///
    /// Creates the users table if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::StorageError` if the database cannot be opened
    /// or the schema migration fails.
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.create_tables()?;
        Ok(store)
    }

    /// Create an in-memory SQLite database (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns `UserMgmtError::StorageError` if table creation fails.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.create_tables()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        conn.execute_batch(
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
                device_ids TEXT NOT NULL DEFAULT '[]',
                partition TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login INTEGER,
                metadata TEXT NOT NULL DEFAULT '{}'
            );",
        )
        .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        debug!("SQLite user tables initialized");
        Ok(())
    }

    fn row_to_user(
        row: &rusqlite::Row<'_>,
    ) -> std::result::Result<User, rusqlite::Error> {
        let auth_type_str: String = row.get(5)?;
        let auth_type = match auth_type_str.as_str() {
            "Digest" => AuthType::Digest,
            "MtlsPki" => AuthType::MtlsPki,
            "Both" => AuthType::Both,
            _ => AuthType::Digest,
        };

        let device_ids_json: String = row.get(10)?;
        let device_ids: Vec<String> =
            serde_json::from_str(&device_ids_json).unwrap_or_default();

        let metadata_json: String = row.get(16)?;
        let metadata: HashMap<String, String> =
            serde_json::from_str(&metadata_json).unwrap_or_default();

        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            display_name: row.get(2)?,
            email: row.get(3)?,
            sip_uri: row.get(4)?,
            auth_type,
            digest_ha1: row.get(6)?,
            certificate_dn: row.get(7)?,
            certificate_san: row.get(8)?,
            calling_search_space: row.get(9)?,
            device_ids,
            partition: row.get(11)?,
            enabled: row.get::<_, i32>(12)? != 0,
            created_at: row.get(13)?,
            updated_at: row.get(14)?,
            last_login: row.get(15)?,
            metadata,
        })
    }
}

impl UserStore for SqliteUserStore {
    async fn create_user(&self, user: User) -> Result<User> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let auth_type_str = match user.auth_type {
            AuthType::Digest => "Digest",
            AuthType::MtlsPki => "MtlsPki",
            AuthType::Both => "Both",
        };

        let device_ids_json = serde_json::to_string(&user.device_ids)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let metadata_json = serde_json::to_string(&user.metadata)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        conn.execute(
            "INSERT INTO users (id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                user.id,
                user.username,
                user.display_name,
                user.email,
                user.sip_uri,
                auth_type_str,
                user.digest_ha1,
                user.certificate_dn,
                user.certificate_san,
                user.calling_search_space,
                device_ids_json,
                user.partition,
                i32::from(user.enabled),
                user.created_at,
                user.updated_at,
                user.last_login,
                metadata_json,
            ],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                UserMgmtError::UserAlreadyExists
            } else {
                UserMgmtError::StorageError(e.to_string())
            }
        })?;

        Ok(user)
    }

    async fn get_user(&self, id: &str) -> Result<User> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        conn.query_row(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE id = ?1",
            params![id],
            Self::row_to_user,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => UserMgmtError::UserNotFound,
            _ => UserMgmtError::StorageError(e.to_string()),
        })
    }

    async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        conn.query_row(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE username = ?1",
            params![username],
            Self::row_to_user,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => UserMgmtError::UserNotFound,
            _ => UserMgmtError::StorageError(e.to_string()),
        })
    }

    async fn get_user_by_certificate_dn(&self, dn: &str) -> Result<User> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        conn.query_row(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE certificate_dn = ?1",
            params![dn],
            Self::row_to_user,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => UserMgmtError::UserNotFound,
            _ => UserMgmtError::StorageError(e.to_string()),
        })
    }

    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let mut sql = String::from(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE 1=1",
        );

        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut param_idx = 1u32;

        if let Some(ref username) = filter.username_contains {
            sql.push_str(&format!(" AND username LIKE ?{param_idx}"));
            param_values
                .push(Box::new(format!("%{username}%")));
            param_idx += 1;
        }

        if let Some(ref auth_type) = filter.auth_type {
            let type_str = match auth_type {
                AuthType::Digest => "Digest",
                AuthType::MtlsPki => "MtlsPki",
                AuthType::Both => "Both",
            };
            sql.push_str(&format!(" AND auth_type = ?{param_idx}"));
            param_values.push(Box::new(type_str.to_owned()));
            param_idx += 1;
        }

        if let Some(ref css) = filter.css_id {
            sql.push_str(&format!(" AND calling_search_space = ?{param_idx}"));
            param_values.push(Box::new(css.clone()));
            param_idx += 1;
        }

        if let Some(enabled) = filter.enabled {
            sql.push_str(&format!(" AND enabled = ?{param_idx}"));
            param_values.push(Box::new(i32::from(enabled)));
            param_idx += 1;
        }

        sql.push_str(" ORDER BY username");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT ?{param_idx}"));
            param_values.push(Box::new(limit));
            param_idx += 1;
        }

        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET ?{param_idx}"));
            param_values.push(Box::new(offset));
            // param_idx not needed after this point
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), Self::row_to_user)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let mut users = Vec::new();
        for row in rows {
            users.push(
                row.map_err(|e| UserMgmtError::StorageError(e.to_string()))?,
            );
        }
        Ok(users)
    }

    async fn update_user(&self, user: User) -> Result<User> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let auth_type_str = match user.auth_type {
            AuthType::Digest => "Digest",
            AuthType::MtlsPki => "MtlsPki",
            AuthType::Both => "Both",
        };

        let device_ids_json = serde_json::to_string(&user.device_ids)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;
        let metadata_json = serde_json::to_string(&user.metadata)
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let rows_affected = conn
            .execute(
                "UPDATE users SET username = ?2, display_name = ?3, email = ?4, sip_uri = ?5,
                 auth_type = ?6, digest_ha1 = ?7, certificate_dn = ?8, certificate_san = ?9,
                 calling_search_space = ?10, device_ids = ?11, partition = ?12, enabled = ?13,
                 updated_at = ?14, last_login = ?15, metadata = ?16
                 WHERE id = ?1",
                params![
                    user.id,
                    user.username,
                    user.display_name,
                    user.email,
                    user.sip_uri,
                    auth_type_str,
                    user.digest_ha1,
                    user.certificate_dn,
                    user.certificate_san,
                    user.calling_search_space,
                    device_ids_json,
                    user.partition,
                    i32::from(user.enabled),
                    user.updated_at,
                    user.last_login,
                    metadata_json,
                ],
            )
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        if rows_affected == 0 {
            return Err(UserMgmtError::UserNotFound);
        }

        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let rows_affected = conn
            .execute("DELETE FROM users WHERE id = ?1", params![id])
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        if rows_affected == 0 {
            return Err(UserMgmtError::UserNotFound);
        }

        Ok(())
    }

    async fn authenticate_digest(
        &self,
        username: &str,
        _realm: &str,
    ) -> Result<Option<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let result: std::result::Result<Option<String>, _> = conn.query_row(
            "SELECT digest_ha1 FROM users WHERE username = ?1 AND enabled = 1
             AND auth_type IN ('Digest', 'Both')",
            params![username],
            |row| row.get(0),
        );

        match result {
            Ok(ha1) => Ok(ha1),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(UserMgmtError::StorageError(e.to_string())),
        }
    }

    async fn authenticate_certificate(
        &self,
        dn: &str,
        san: &str,
    ) -> Result<Option<User>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let result = conn.query_row(
            "SELECT id, username, display_name, email, sip_uri, auth_type,
             digest_ha1, certificate_dn, certificate_san, calling_search_space,
             device_ids, partition, enabled, created_at, updated_at, last_login, metadata
             FROM users WHERE certificate_dn = ?1 AND certificate_san = ?2
             AND enabled = 1 AND auth_type IN ('MtlsPki', 'Both')",
            params![dn, san],
            Self::row_to_user,
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(UserMgmtError::StorageError(e.to_string())),
        }
    }

    async fn count_users(&self) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| UserMgmtError::StorageError(e.to_string()))?;

        Ok(count as usize)
    }
}
