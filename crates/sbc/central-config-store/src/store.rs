//! The central config store: transactional writes and sync reads against
//! the fleet-wide, `site_code`-partitioned database.
//!
//! Every write is one transaction that (1) bumps the site's
//! `config_epoch` — which also row-locks the site, serializing concurrent
//! writers so epochs stay monotonic and gap-free — (2) writes the row
//! stamping `revision = epoch`, and (3) appends a `config_journal` entry.
//! The journal is the delta source for [`CentralConfigStore::delta`] and
//! the audit log; because all three steps share the transaction, a reader
//! never sees a row whose change isn't journaled, or vice versa.

use serde_json::{Map, Value};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};

use crate::error::{CentralError, CentralResult};
use crate::model::{Change, ChangeOp, ConfigTable, DeltaResult, Snapshot, SnapshotRow, TableRows};

/// Tables that are LIST-partitioned by `site_code`; [`register_site`]
/// creates one partition of each per site. Mirrors the array in
/// `deploy/central-db/scripts/sync-site-partitions.sql` (the config
/// tables plus the journal).
///
/// [`register_site`]: CentralConfigStore::register_site
const PARTITIONED_TABLES: &[&str] = &[
    "phones",
    "directory_numbers",
    "trunk_groups",
    "dial_plans",
    "sbc_partitions",
    "sbc_calling_search_spaces",
    "sbc_route_patterns",
    "sbc_route_lists",
    "site_telephony_config",
    "config_journal",
];

/// Pooled handle to the central config database.
#[derive(Clone)]
pub struct CentralConfigStore {
    pool: PgPool,
}

impl CentralConfigStore {
    /// Connect with a fresh pool and run pending migrations.
    ///
    /// # Errors
    /// [`CentralError::Storage`] on pool or migration failure.
    pub async fn connect(database_url: &str) -> CentralResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        Self::from_pool(pool).await
    }

    /// Build from an existing pool, running pending migrations.
    ///
    /// # Errors
    /// [`CentralError::Storage`] on migration failure.
    pub async fn from_pool(pool: PgPool) -> CentralResult<Self> {
        crate::schema::ensure_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// The underlying pool (for shared construction).
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cheap round-trip to confirm the database is reachable (for
    /// readiness probes).
    ///
    /// # Errors
    /// [`CentralError::Storage`] if the query fails.
    pub async fn ping(&self) -> CentralResult<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------- registry

    /// Register a site and create its partition in every sharded table.
    /// Idempotent on the partitions (IF NOT EXISTS); the `sites` insert
    /// is `ON CONFLICT DO NOTHING`, so re-registering an existing site is
    /// a no-op that still backfills any missing partitions.
    ///
    /// # Errors
    /// [`CentralError::InvalidSiteCode`] if `site_code` isn't canonical,
    /// or [`CentralError::Storage`] on DB failure.
    pub async fn register_site(
        &self,
        site_code: &str,
        display_name: &str,
        fqdn_base: &str,
        timezone: &str,
        status: &str,
    ) -> CentralResult<()> {
        validate_site_code(site_code)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO sites (site_code, display_name, fqdn_base, timezone, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (site_code) DO NOTHING",
        )
        .bind(site_code)
        .bind(display_name)
        .bind(fqdn_base)
        .bind(timezone)
        .bind(status)
        .execute(&mut *tx)
        .await?;

        // Partition name: <table>_p_<site lowercased, '-' → '_'>. site_code
        // is validated to [A-Z0-9-] only, so the interpolation is
        // injection-safe (no quotes/whitespace possible).
        let suffix = site_code.to_lowercase().replace('-', "_");
        for table in PARTITIONED_TABLES {
            let part = format!("{table}_p_{suffix}");
            let ddl = format!(
                "CREATE TABLE IF NOT EXISTS {part} PARTITION OF {table} FOR VALUES IN ('{site_code}')"
            );
            sqlx::query(&ddl).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------ writes

    /// Upsert a phone. `data` is the canonical Phone JSON; `mac_normalized`
    /// is lifted out for the per-site live-MAC unique index. Returns the
    /// new shard epoch.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`] if the site isn't registered,
    /// [`CentralError::Conflict`] if another live phone owns the MAC, or
    /// [`CentralError::Storage`].
    pub async fn upsert_phone(
        &self,
        site_code: &str,
        id: &str,
        mac_normalized: &str,
        data: &Value,
        actor: &str,
    ) -> CentralResult<i64> {
        let mut tx = self.pool.begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;
        let res = sqlx::query(
            "INSERT INTO phones
                 (site_code, id, mac_normalized, data, revision, deleted, updated_by)
             VALUES ($1, $2, $3, $4, $5, FALSE, $6)
             ON CONFLICT (site_code, id) DO UPDATE SET
                 mac_normalized = EXCLUDED.mac_normalized,
                 data           = EXCLUDED.data,
                 revision       = EXCLUDED.revision,
                 deleted        = FALSE,
                 updated_by     = EXCLUDED.updated_by,
                 updated_at     = NOW()",
        )
        .bind(site_code)
        .bind(id)
        .bind(mac_normalized)
        .bind(data)
        .bind(epoch)
        .bind(actor)
        .execute(&mut *tx)
        .await;
        if let Err(e) = res {
            return Err(map_phone_error(e));
        }
        journal(
            &mut tx,
            site_code,
            epoch,
            ConfigTable::Phones,
            id,
            ChangeOp::Upsert,
            Some(data),
            actor,
        )
        .await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Upsert a directory number, maintaining fleet-wide DID ownership in
    /// `did_registry`. `extra` carries forward-compatible fields. Returns
    /// the new shard epoch.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`], [`CentralError::DidConflict`] if the
    /// DID belongs to another site, or [`CentralError::Storage`].
    #[allow(clippy::too_many_arguments)] // DID columns + identity; cohesive
    pub async fn upsert_did(
        &self,
        site_code: &str,
        did: &str,
        sip_user: Option<&str>,
        partition: Option<&str>,
        description: Option<&str>,
        extra: &Map<String, Value>,
        actor: &str,
    ) -> CentralResult<i64> {
        let mut tx = self.pool.begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;

        // Claim the DID fleet-wide. FOR UPDATE locks any existing row so
        // two sites can't race to claim the same number.
        let owner: Option<String> =
            sqlx::query_scalar("SELECT site_code FROM did_registry WHERE did = $1 FOR UPDATE")
                .bind(did)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(owner) = owner {
            if owner != site_code {
                return Err(CentralError::DidConflict {
                    did: did.to_string(),
                    owner,
                });
            }
        } else {
            sqlx::query("INSERT INTO did_registry (did, site_code) VALUES ($1, $2)")
                .bind(did)
                .bind(site_code)
                .execute(&mut *tx)
                .await?;
        }

        let extra_json = Value::Object(extra.clone());
        sqlx::query(
            "INSERT INTO directory_numbers
                 (site_code, did, sip_user, partition, description, extra,
                  revision, deleted, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
             ON CONFLICT (site_code, did) DO UPDATE SET
                 sip_user    = EXCLUDED.sip_user,
                 partition   = EXCLUDED.partition,
                 description = EXCLUDED.description,
                 extra       = EXCLUDED.extra,
                 revision    = EXCLUDED.revision,
                 deleted     = FALSE,
                 updated_by  = EXCLUDED.updated_by,
                 updated_at  = NOW()",
        )
        .bind(site_code)
        .bind(did)
        .bind(sip_user)
        .bind(partition)
        .bind(description)
        .bind(&extra_json)
        .bind(epoch)
        .bind(actor)
        .execute(&mut *tx)
        .await?;

        let payload = did_payload(did, sip_user, partition, description, extra);
        journal(
            &mut tx,
            site_code,
            epoch,
            ConfigTable::DirectoryNumbers,
            did,
            ChangeOp::Upsert,
            Some(&payload),
            actor,
        )
        .await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Upsert a JSONB pass-through entity (trunk groups, dial plans, the
    /// SBC tables, site telephony config). Returns the new shard epoch.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`] or [`CentralError::Storage`]. Passing
    /// [`ConfigTable::Phones`] or [`ConfigTable::DirectoryNumbers`] is a
    /// programming error — use [`upsert_phone`]/[`upsert_did`] for those.
    ///
    /// [`upsert_phone`]: Self::upsert_phone
    /// [`upsert_did`]: Self::upsert_did
    pub async fn upsert_json(
        &self,
        table: ConfigTable,
        site_code: &str,
        id: &str,
        data: &Value,
        actor: &str,
    ) -> CentralResult<i64> {
        debug_assert!(
            is_json_table(table),
            "upsert_json called for typed table {}",
            table.name()
        );
        let mut tx = self.pool.begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;
        let sql = format!(
            "INSERT INTO {table} (site_code, id, data, revision, deleted, updated_by)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (site_code, id) DO UPDATE SET
                 data       = EXCLUDED.data,
                 revision   = EXCLUDED.revision,
                 deleted    = FALSE,
                 updated_by = EXCLUDED.updated_by,
                 updated_at = NOW()",
            table = table.name()
        );
        sqlx::query(&sql)
            .bind(site_code)
            .bind(id)
            .bind(data)
            .bind(epoch)
            .bind(actor)
            .execute(&mut *tx)
            .await?;
        journal(
            &mut tx,
            site_code,
            epoch,
            table,
            id,
            ChangeOp::Upsert,
            Some(data),
            actor,
        )
        .await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Tombstone a row in any config table (the directory path also frees
    /// the DID in `did_registry`). Returns the new shard epoch.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`], [`CentralError::NotFound`] if no live
    /// row matched (the epoch bump is rolled back), or
    /// [`CentralError::Storage`].
    pub async fn delete(
        &self,
        table: ConfigTable,
        site_code: &str,
        row_id: &str,
        actor: &str,
    ) -> CentralResult<i64> {
        let id_col = if table == ConfigTable::DirectoryNumbers {
            "did"
        } else {
            "id"
        };
        let mut tx = self.pool.begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;
        let sql = format!(
            "UPDATE {table} SET deleted = TRUE, revision = $1, updated_by = $2, updated_at = NOW()
             WHERE site_code = $3 AND {id_col} = $4 AND NOT deleted",
            table = table.name()
        );
        let affected = sqlx::query(&sql)
            .bind(epoch)
            .bind(actor)
            .bind(site_code)
            .bind(row_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            // Roll back the epoch bump: nothing was deleted.
            return Err(CentralError::NotFound);
        }
        if table == ConfigTable::DirectoryNumbers {
            sqlx::query("DELETE FROM did_registry WHERE did = $1 AND site_code = $2")
                .bind(row_id)
                .bind(site_code)
                .execute(&mut *tx)
                .await?;
        }
        journal(
            &mut tx,
            site_code,
            epoch,
            table,
            row_id,
            ChangeOp::Delete,
            None,
            actor,
        )
        .await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Apply one change to a site's shard, dispatching by table and op.
    /// Used by the site-upload path (DDIL reconcile): a delete tombstones;
    /// an upsert is routed to the typed phone/DID writers (extracting the
    /// MAC / DID columns from the payload) or the generic JSON writer.
    /// Returns the new shard epoch.
    ///
    /// # Errors
    /// [`CentralError::Serialization`] if an upsert payload is missing or
    /// malformed for its table, plus the usual write errors.
    pub async fn apply_change(
        &self,
        site_code: &str,
        table: ConfigTable,
        op: ChangeOp,
        id: &str,
        payload: Option<&Value>,
        actor: &str,
    ) -> CentralResult<i64> {
        if op == ChangeOp::Delete {
            return self.delete(table, site_code, id, actor).await;
        }
        let payload = payload.ok_or_else(|| {
            CentralError::Serialization(format!("upsert for {}/{id} has no payload", table.name()))
        })?;
        match table {
            ConfigTable::Phones => {
                let mac = payload
                    .get("mac_address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        CentralError::Serialization(format!(
                            "phone {id} payload missing mac_address"
                        ))
                    })?;
                self.upsert_phone(site_code, id, &normalize_mac(mac), payload, actor)
                    .await
            }
            ConfigTable::DirectoryNumbers => {
                let obj = payload.as_object().ok_or_else(|| {
                    CentralError::Serialization(format!("DID {id} payload is not an object"))
                })?;
                let field = |k: &str| obj.get(k).and_then(Value::as_str);
                let mut extra = obj.clone();
                for k in ["did", "user", "partition", "description"] {
                    extra.remove(k);
                }
                self.upsert_did(
                    site_code,
                    id,
                    field("user"),
                    field("partition"),
                    field("description"),
                    &extra,
                    actor,
                )
                .await
            }
            json_table => {
                self.upsert_json(json_table, site_code, id, payload, actor)
                    .await
            }
        }
    }

    // ------------------------------------------------------- sync reads

    /// The site's current shard epoch — the cheap staleness probe.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`] or [`CentralError::Storage`].
    pub async fn epoch(&self, site_code: &str) -> CentralResult<i64> {
        let epoch: Option<i64> =
            sqlx::query_scalar("SELECT config_epoch FROM sites WHERE site_code = $1")
                .bind(site_code)
                .fetch_optional(&self.pool)
                .await?;
        epoch.ok_or_else(|| CentralError::UnknownSite(site_code.to_string()))
    }

    /// Changes for `site_code` with `epoch > since`, ascending. If `since`
    /// is ahead of the current epoch (the client's local DB regressed),
    /// returns [`DeltaResult::MustSnapshot`]. The journal is retained
    /// indefinitely, so there is no lower pruning horizon to fall off.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`] or [`CentralError::Storage`].
    pub async fn delta(&self, site_code: &str, since: i64) -> CentralResult<DeltaResult> {
        let current = self.epoch(site_code).await?;
        if since > current {
            return Ok(DeltaResult::MustSnapshot { current });
        }
        let rows = sqlx::query(
            "SELECT epoch, table_name, row_id, op, payload
             FROM config_journal
             WHERE site_code = $1 AND epoch > $2
             ORDER BY epoch, table_name, row_id",
        )
        .bind(site_code)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut changes = Vec::with_capacity(rows.len());
        for row in &rows {
            let table_name: String = row.try_get("table_name")?;
            let op_str: String = row.try_get("op")?;
            let table = parse_table(&table_name)?;
            let op = ChangeOp::from_str(&op_str)
                .ok_or_else(|| CentralError::Storage(format!("bad journal op: {op_str}")))?;
            changes.push(Change {
                epoch: row.try_get("epoch")?,
                table,
                row_id: row.try_get("row_id")?,
                op,
                payload: row.try_get("payload")?,
            });
        }
        Ok(DeltaResult::Delta {
            from: since,
            to: current,
            changes,
        })
    }

    /// A full materialized snapshot: every live row, grouped by table, at
    /// the site's current epoch. The client loads this then resumes deltas
    /// from `epoch`. Read in a repeatable-read transaction so `epoch` and
    /// the rows are mutually consistent under concurrent writes.
    ///
    /// # Errors
    /// [`CentralError::UnknownSite`] or [`CentralError::Storage`].
    pub async fn snapshot(&self, site_code: &str) -> CentralResult<Snapshot> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        let epoch: Option<i64> =
            sqlx::query_scalar("SELECT config_epoch FROM sites WHERE site_code = $1")
                .bind(site_code)
                .fetch_optional(&mut *tx)
                .await?;
        let epoch = epoch.ok_or_else(|| CentralError::UnknownSite(site_code.to_string()))?;

        let mut tables = Vec::with_capacity(ConfigTable::ALL.len());
        for &table in &ConfigTable::ALL {
            let rows = snapshot_table(&mut tx, table, site_code).await?;
            tables.push(TableRows { table, rows });
        }
        tx.commit().await?;
        Ok(Snapshot { epoch, tables })
    }

    // --------------------------------------------------- operator reads

    /// List all registered sites (for the operator/dashboard selector),
    /// ordered by site code.
    ///
    /// # Errors
    /// [`CentralError::Storage`] on DB failure.
    pub async fn list_sites(&self) -> CentralResult<Vec<crate::model::SiteInfo>> {
        let rows = sqlx::query(
            "SELECT site_code, display_name, status, config_epoch FROM sites ORDER BY site_code",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(crate::model::SiteInfo {
                site_code: row.try_get("site_code")?,
                display_name: row.try_get("display_name")?,
                status: row.try_get("status")?,
                config_epoch: row.try_get("config_epoch")?,
            });
        }
        Ok(out)
    }

    /// List a table's live rows for a site (id + canonical payload).
    ///
    /// # Errors
    /// [`CentralError::Storage`] on DB failure.
    pub async fn list_rows(
        &self,
        table: ConfigTable,
        site_code: &str,
    ) -> CentralResult<Vec<SnapshotRow>> {
        let mut tx = self.pool.begin().await?;
        let rows = snapshot_table(&mut tx, table, site_code).await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Fetch one live row's canonical payload by id, or `None` if absent
    /// (or tombstoned).
    ///
    /// # Errors
    /// [`CentralError::Storage`] on DB failure.
    pub async fn get_row(
        &self,
        table: ConfigTable,
        site_code: &str,
        row_id: &str,
    ) -> CentralResult<Option<Value>> {
        if table == ConfigTable::DirectoryNumbers {
            let row = sqlx::query(
                "SELECT did, sip_user, partition, description, extra
                 FROM directory_numbers WHERE site_code = $1 AND did = $2 AND NOT deleted",
            )
            .bind(site_code)
            .bind(row_id)
            .fetch_optional(&self.pool)
            .await?;
            let Some(row) = row else { return Ok(None) };
            let extra: Value = row.try_get("extra")?;
            let extra_map = extra.as_object().cloned().unwrap_or_default();
            Ok(Some(did_payload(
                row.try_get::<String, _>("did")?.as_str(),
                row.try_get::<Option<String>, _>("sip_user")?.as_deref(),
                row.try_get::<Option<String>, _>("partition")?.as_deref(),
                row.try_get::<Option<String>, _>("description")?.as_deref(),
                &extra_map,
            )))
        } else {
            let sql = format!(
                "SELECT data FROM {} WHERE site_code = $1 AND id = $2 AND NOT deleted",
                table.name()
            );
            let row = sqlx::query(&sql)
                .bind(site_code)
                .bind(row_id)
                .fetch_optional(&self.pool)
                .await?;
            row.map(|r| r.try_get::<Value, _>("data"))
                .transpose()
                .map_err(CentralError::from)
        }
    }
}

// ----------------------------------------------------------- tx helpers

/// Bump and return the site's epoch. The `UPDATE ... RETURNING` locks the
/// `sites` row for the rest of the transaction, serializing concurrent
/// writers to this site. Absent row → [`CentralError::UnknownSite`].
pub(crate) async fn bump_epoch(
    tx: &mut Transaction<'_, Postgres>,
    site_code: &str,
) -> CentralResult<i64> {
    let epoch: Option<i64> = sqlx::query_scalar(
        "UPDATE sites SET config_epoch = config_epoch + 1, updated_at = NOW()
         WHERE site_code = $1
         RETURNING config_epoch",
    )
    .bind(site_code)
    .fetch_optional(&mut **tx)
    .await?;
    epoch.ok_or_else(|| CentralError::UnknownSite(site_code.to_string()))
}

/// Append one journal entry within the write transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn journal(
    tx: &mut Transaction<'_, Postgres>,
    site_code: &str,
    epoch: i64,
    table: ConfigTable,
    row_id: &str,
    op: ChangeOp,
    payload: Option<&Value>,
    actor: &str,
) -> CentralResult<()> {
    sqlx::query(
        "INSERT INTO config_journal
             (site_code, epoch, table_name, row_id, op, payload, actor)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(site_code)
    .bind(epoch)
    .bind(table.name())
    .bind(row_id)
    .bind(op.as_str())
    .bind(payload)
    .bind(actor)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Read one table's live rows for a site as id + canonical JSON payload.
async fn snapshot_table(
    tx: &mut Transaction<'_, Postgres>,
    table: ConfigTable,
    site_code: &str,
) -> CentralResult<Vec<SnapshotRow>> {
    if table == ConfigTable::DirectoryNumbers {
        let rows = sqlx::query(
            "SELECT did, sip_user, partition, description, extra
             FROM directory_numbers
             WHERE site_code = $1 AND NOT deleted
             ORDER BY did",
        )
        .bind(site_code)
        .fetch_all(&mut **tx)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let did: String = row.try_get("did")?;
            let extra: Value = row.try_get("extra")?;
            let extra_map = extra.as_object().cloned().unwrap_or_default();
            let payload = did_payload(
                &did,
                row.try_get::<Option<String>, _>("sip_user")?.as_deref(),
                row.try_get::<Option<String>, _>("partition")?.as_deref(),
                row.try_get::<Option<String>, _>("description")?.as_deref(),
                &extra_map,
            );
            out.push(SnapshotRow { id: did, payload });
        }
        Ok(out)
    } else {
        // phones + JSONB tables all expose `id` + `data`.
        let sql = format!(
            "SELECT id, data FROM {} WHERE site_code = $1 AND NOT deleted ORDER BY id",
            table.name()
        );
        let rows = sqlx::query(&sql)
            .bind(site_code)
            .fetch_all(&mut **tx)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(SnapshotRow {
                id: row.try_get::<String, _>("id")?,
                payload: row.try_get::<Value, _>("data")?,
            });
        }
        Ok(out)
    }
}

// --------------------------------------------------------- pure helpers

/// Reconstruct the canonical `DirectoryNumber` JSON (`{ did, user?,
/// partition?, description?, ...extra }`) — the shape the site store's
/// `DirectoryNumber::from_json` consumes. Null optionals are omitted to
/// match the model's `skip_serializing_if`.
fn did_payload(
    did: &str,
    sip_user: Option<&str>,
    partition: Option<&str>,
    description: Option<&str>,
    extra: &Map<String, Value>,
) -> Value {
    let mut obj = Map::new();
    obj.insert("did".to_string(), Value::String(did.to_string()));
    if let Some(u) = sip_user {
        obj.insert("user".to_string(), Value::String(u.to_string()));
    }
    if let Some(p) = partition {
        obj.insert("partition".to_string(), Value::String(p.to_string()));
    }
    if let Some(d) = description {
        obj.insert("description".to_string(), Value::String(d.to_string()));
    }
    for (k, v) in extra {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// Normalize a MAC the same way the phone store and sync agent do: strip
/// `:`/`-`, lowercase.
fn normalize_mac(mac: &str) -> String {
    mac.replace([':', '-'], "").to_lowercase()
}

/// `true` for the JSONB pass-through tables (everything except the two
/// typed tables).
const fn is_json_table(table: ConfigTable) -> bool {
    !matches!(table, ConfigTable::Phones | ConfigTable::DirectoryNumbers)
}

fn parse_table(name: &str) -> CentralResult<ConfigTable> {
    ConfigTable::ALL
        .into_iter()
        .find(|t| t.name() == name)
        .ok_or_else(|| CentralError::Storage(format!("unknown journal table: {name}")))
}

/// Map a phones-insert error: a unique violation is the live-MAC
/// collision (partial index `idx_phones_site_mac_live`).
fn map_phone_error(err: sqlx::Error) -> CentralError {
    if err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
        == Some("23505")
    {
        CentralError::Conflict("a live phone already owns this MAC at this site".to_string())
    } else {
        CentralError::from(err)
    }
}

/// Canonical site-code check: uppercase, starts with a letter, ends with
/// a letter or digit, A–Z/0–9/hyphen, 2–16 chars. Mirrors the `sites`
/// CHECK constraint so we fail with a clear error (and a safe partition
/// name) before touching the DB.
fn validate_site_code(code: &str) -> CentralResult<()> {
    let bytes = code.as_bytes();
    let first_ok = bytes.first().is_some_and(u8::is_ascii_uppercase);
    let last_ok = bytes
        .last()
        .is_some_and(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let body_ok = bytes
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
    if (2..=16).contains(&code.len()) && first_ok && last_ok && body_ok {
        Ok(())
    } else {
        Err(CentralError::InvalidSiteCode(code.to_string()))
    }
}
