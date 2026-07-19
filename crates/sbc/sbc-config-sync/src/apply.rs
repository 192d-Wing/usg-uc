//! Apply engine: write central changes into the site-local Postgres.
//!
//! Two entry points, both atomic (one transaction each, so the site never
//! exposes a half-applied state and `sync_state.applied_epoch` only
//! advances when the rows it claims are durably present):
//!
//! - [`apply_snapshot`] replaces the local shard wholesale with a
//!   materialized snapshot (used on first sync and after a regression).
//! - [`apply_delta`] applies an ordered batch of changes incrementally.
//!
//! Applied rows are stamped with the central `revision` (the epoch at
//! which the change committed) and `updated_by = 'central'`, which is
//! what distinguishes a synced row from a local break-glass write
//! (`updated_by = 'local'`, `revision = 0`). Deletes are tombstones.

use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

use central_config_store::{Change, ChangeOp, ConfigTable, Snapshot, UploadChange};
use sbc_config_store::{DirectoryNumber, PostgresPhoneStore};

use serde_json::{Map, json};

use crate::error::{SyncError, SyncResult};

/// Marker written to `updated_by` for every synced row, so local code and
/// the future reconcile path can tell central-origin rows from local
/// break-glass writes.
const CENTRAL_ORIGIN: &str = "central";

/// The current applied epoch for `site_code`, or `None` if this site has
/// never been synced (→ caller must fetch a full snapshot).
///
/// # Errors
/// [`SyncError::Local`] on query failure.
pub async fn applied_epoch(pool: &sqlx::PgPool, site_code: &str) -> SyncResult<Option<i64>> {
    let epoch =
        sqlx::query_scalar::<_, i64>("SELECT applied_epoch FROM sync_state WHERE site_code = $1")
            .bind(site_code)
            .fetch_optional(pool)
            .await?;
    Ok(epoch)
}

/// Replace the local shard with `snapshot` and set the applied epoch.
/// Every config table is cleared and reloaded inside one transaction, so
/// a crash mid-apply leaves the prior state intact.
///
/// # Errors
/// [`SyncError`] on a malformed payload or DB failure.
pub async fn apply_snapshot(
    pool: &sqlx::PgPool,
    site_code: &str,
    snapshot: &Snapshot,
) -> SyncResult<()> {
    let mut tx = pool.begin().await?;
    for table in &snapshot.tables {
        // Replace the central-origin rows only; local-origin rows (edits
        // made while partitioned, updated_by = 'local') are preserved so
        // DDIL autonomy survives a snapshot reload. They'll be uploaded
        // back to central separately.
        let sql = format!(
            "DELETE FROM {} WHERE updated_by <> 'local'",
            table.table.name()
        );
        sqlx::query(&sql).execute(&mut *tx).await?;
        for row in &table.rows {
            upsert_local(
                &mut tx,
                table.table,
                site_code,
                &row.id,
                &row.payload,
                snapshot.epoch,
            )
            .await?;
        }
    }
    set_applied_epoch(&mut tx, site_code, snapshot.epoch).await?;
    tx.commit().await?;
    Ok(())
}

/// Apply `changes` (ascending epoch order) and advance the applied epoch
/// to `to_epoch`, all in one transaction.
///
/// # Errors
/// [`SyncError`] on a malformed payload or DB failure.
pub async fn apply_delta(
    pool: &sqlx::PgPool,
    site_code: &str,
    changes: &[Change],
    to_epoch: i64,
) -> SyncResult<()> {
    let mut tx = pool.begin().await?;
    for change in changes {
        match change.op {
            ChangeOp::Upsert => {
                let payload = change.payload.as_ref().ok_or_else(|| SyncError::Payload {
                    table: change.table.name().to_string(),
                    row_id: change.row_id.clone(),
                    reason: "upsert change has no payload".to_string(),
                })?;
                upsert_local(
                    &mut tx,
                    change.table,
                    site_code,
                    &change.row_id,
                    payload,
                    change.epoch,
                )
                .await?;
            }
            ChangeOp::Delete => {
                tombstone_local(
                    &mut tx,
                    change.table,
                    site_code,
                    &change.row_id,
                    change.epoch,
                )
                .await?;
            }
        }
    }
    set_applied_epoch(&mut tx, site_code, to_epoch).await?;
    tx.commit().await?;
    Ok(())
}

/// Upsert one row into its local table from a central payload.
async fn upsert_local(
    tx: &mut Transaction<'_, Postgres>,
    table: ConfigTable,
    site_code: &str,
    id: &str,
    payload: &Value,
    revision: i64,
) -> SyncResult<()> {
    match table {
        ConfigTable::Phones => {
            let mac = payload
                .get("mac_address")
                .and_then(Value::as_str)
                .ok_or_else(|| SyncError::Payload {
                    table: "phones".to_string(),
                    row_id: id.to_string(),
                    reason: "missing mac_address".to_string(),
                })?;
            let mac_normalized = PostgresPhoneStore::normalize_mac(mac);
            sqlx::query(
                "INSERT INTO phones
                     (id, mac_normalized, data, revision, deleted, updated_by, site_code)
                 VALUES ($1, $2, $3, $4, FALSE, $5, $6)
                 ON CONFLICT (id) DO UPDATE SET
                     mac_normalized = EXCLUDED.mac_normalized,
                     data           = EXCLUDED.data,
                     revision       = EXCLUDED.revision,
                     deleted        = FALSE,
                     updated_by     = EXCLUDED.updated_by,
                     site_code      = EXCLUDED.site_code,
                     updated_at     = NOW()
                 WHERE phones.updated_by <> 'local'",
            )
            .bind(id)
            .bind(&mac_normalized)
            .bind(payload)
            .bind(revision)
            .bind(CENTRAL_ORIGIN)
            .bind(site_code)
            .execute(&mut **tx)
            .await?;
        }
        ConfigTable::DirectoryNumbers => {
            let dn =
                DirectoryNumber::from_json(payload.clone()).map_err(|e| SyncError::Payload {
                    table: "directory_numbers".to_string(),
                    row_id: id.to_string(),
                    reason: e.to_string(),
                })?;
            let extra = serde_json::to_value(&dn.extra).unwrap_or(Value::Null);
            sqlx::query(
                "INSERT INTO directory_numbers
                     (did, sip_user, partition, description, extra,
                      revision, deleted, updated_by, site_code)
                 VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, $8)
                 ON CONFLICT (did) DO UPDATE SET
                     sip_user    = EXCLUDED.sip_user,
                     partition   = EXCLUDED.partition,
                     description = EXCLUDED.description,
                     extra       = EXCLUDED.extra,
                     revision    = EXCLUDED.revision,
                     deleted     = FALSE,
                     updated_by  = EXCLUDED.updated_by,
                     site_code   = EXCLUDED.site_code,
                     updated_at  = NOW()
                 WHERE directory_numbers.updated_by <> 'local'",
            )
            .bind(&dn.did)
            .bind(&dn.user)
            .bind(&dn.partition)
            .bind(&dn.description)
            .bind(&extra)
            .bind(revision)
            .bind(CENTRAL_ORIGIN)
            .bind(site_code)
            .execute(&mut **tx)
            .await?;
        }
        json_table => {
            let sql = format!(
                "INSERT INTO {tbl} (id, data, revision, deleted, updated_by, site_code)
                 VALUES ($1, $2, $3, FALSE, $4, $5)
                 ON CONFLICT (id) DO UPDATE SET
                     data       = EXCLUDED.data,
                     revision   = EXCLUDED.revision,
                     deleted    = FALSE,
                     updated_by = EXCLUDED.updated_by,
                     site_code  = EXCLUDED.site_code,
                     updated_at = NOW()
                 WHERE {tbl}.updated_by <> 'local'",
                tbl = json_table.name(),
            );
            sqlx::query(&sql)
                .bind(id)
                .bind(payload)
                .bind(revision)
                .bind(CENTRAL_ORIGIN)
                .bind(site_code)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(())
}

/// Tombstone one row (idempotent; a no-op if the row never reached this
/// site). The id column is `did` for directory numbers, `id` elsewhere.
async fn tombstone_local(
    tx: &mut Transaction<'_, Postgres>,
    table: ConfigTable,
    site_code: &str,
    id: &str,
    revision: i64,
) -> SyncResult<()> {
    let id_col = if table == ConfigTable::DirectoryNumbers {
        "did"
    } else {
        "id"
    };
    // `updated_by <> 'local'` preserves a local edit: central must not
    // tombstone a row the site changed while partitioned.
    let sql = format!(
        "UPDATE {} SET deleted = TRUE, revision = $1, updated_by = $2, site_code = $3, updated_at = NOW()
         WHERE {} = $4 AND updated_by <> 'local'",
        table.name(),
        id_col
    );
    sqlx::query(&sql)
        .bind(revision)
        .bind(CENTRAL_ORIGIN)
        .bind(site_code)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Collect the site's pending local edits as upload changes.
///
/// These are rows written locally while partitioned
/// (`updated_by = 'local'`), pushed to central on reconnect. Live rows
/// become upserts; tombstones become deletes.
///
/// # Errors
/// [`SyncError::Local`] on query failure.
pub async fn collect_local_changes(
    pool: &sqlx::PgPool,
    _site_code: &str,
) -> SyncResult<Vec<UploadChange>> {
    let mut out = Vec::new();

    // Phones: payload is the stored Phone JSON (`data`).
    for row in sqlx::query("SELECT id, data, deleted FROM phones WHERE updated_by = 'local'")
        .fetch_all(pool)
        .await?
    {
        let id: String = row.try_get("id")?;
        let deleted: bool = row.try_get("deleted")?;
        out.push(if deleted {
            UploadChange {
                table: ConfigTable::Phones,
                id,
                op: ChangeOp::Delete,
                payload: None,
            }
        } else {
            UploadChange {
                table: ConfigTable::Phones,
                id,
                op: ChangeOp::Upsert,
                payload: Some(row.try_get::<Value, _>("data")?),
            }
        });
    }

    // Directory numbers: reconstruct the canonical { did, user?, … } payload.
    for row in sqlx::query(
        "SELECT did, sip_user, partition, description, extra, deleted
         FROM directory_numbers WHERE updated_by = 'local'",
    )
    .fetch_all(pool)
    .await?
    {
        let did: String = row.try_get("did")?;
        let deleted: bool = row.try_get("deleted")?;
        if deleted {
            out.push(UploadChange {
                table: ConfigTable::DirectoryNumbers,
                id: did,
                op: ChangeOp::Delete,
                payload: None,
            });
            continue;
        }
        let mut obj = Map::new();
        obj.insert("did".into(), json!(did));
        for (col, key) in [
            ("sip_user", "user"),
            ("partition", "partition"),
            ("description", "description"),
        ] {
            if let Some(v) = row.try_get::<Option<String>, _>(col)? {
                obj.insert(key.into(), json!(v));
            }
        }
        if let Some(extra) = row.try_get::<Value, _>("extra")?.as_object() {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        out.push(UploadChange {
            table: ConfigTable::DirectoryNumbers,
            id: did,
            op: ChangeOp::Upsert,
            payload: Some(Value::Object(obj)),
        });
    }

    // JSONB pass-through tables.
    for table in [
        ConfigTable::TrunkGroups,
        ConfigTable::DialPlans,
        ConfigTable::SbcPartitions,
        ConfigTable::SbcCallingSearchSpaces,
        ConfigTable::SbcRoutePatterns,
        ConfigTable::SbcRouteLists,
        ConfigTable::SiteTelephonyConfig,
    ] {
        let sql = format!(
            "SELECT id, data, deleted FROM {} WHERE updated_by = 'local'",
            table.name()
        );
        for row in sqlx::query(&sql).fetch_all(pool).await? {
            let id: String = row.try_get("id")?;
            let deleted: bool = row.try_get("deleted")?;
            out.push(if deleted {
                UploadChange {
                    table,
                    id,
                    op: ChangeOp::Delete,
                    payload: None,
                }
            } else {
                UploadChange {
                    table,
                    id,
                    op: ChangeOp::Upsert,
                    payload: Some(row.try_get::<Value, _>("data")?),
                }
            });
        }
    }

    Ok(out)
}

/// Clear the `'local'` marker on rows central has just adopted.
///
/// Re-stamps them `'central'` (with the central `epoch` as revision) so
/// they converge and aren't re-uploaded next cycle. Only flips rows still
/// marked local, so a fresh edit made during the upload is preserved.
///
/// # Errors
/// [`SyncError::Local`] on query failure.
pub async fn restamp_uploaded(
    pool: &sqlx::PgPool,
    changes: &[UploadChange],
    epoch: i64,
    collected_at: chrono::DateTime<chrono::Utc>,
) -> SyncResult<()> {
    let mut tx = pool.begin().await?;
    for change in changes {
        let id_col = if change.table == ConfigTable::DirectoryNumbers {
            "did"
        } else {
            "id"
        };
        // Only restamp rows whose updated_at predates the collection snapshot;
        // rows edited after the collect keep updated_by = 'local' so the next
        // cycle picks them up again instead of silently clobbering them.
        let sql = format!(
            "UPDATE {} SET updated_by = $1, revision = $2
             WHERE {} = $3 AND updated_by = 'local' AND updated_at <= $4",
            change.table.name(),
            id_col
        );
        sqlx::query(&sql)
            .bind(CENTRAL_ORIGIN)
            .bind(epoch)
            .bind(&change.id)
            .bind(collected_at)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Upsert the site's applied-epoch watermark within the apply transaction.
async fn set_applied_epoch(
    tx: &mut Transaction<'_, Postgres>,
    site_code: &str,
    epoch: i64,
) -> SyncResult<()> {
    sqlx::query(
        "INSERT INTO sync_state (site_code, applied_epoch, last_success_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (site_code) DO UPDATE SET
             applied_epoch   = EXCLUDED.applied_epoch,
             last_success_at = NOW(),
             updated_at      = NOW()",
    )
    .bind(site_code)
    .bind(epoch)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
