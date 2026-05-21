//! One-shot JSON → Postgres migration for directory_numbers.
//!
//! Called by the daemon at startup when Postgres is configured. Backfills
//! the legacy `/var/lib/sbc/directory_numbers.json` file if (and only if)
//! the destination table is empty — so a daemon that's already been
//! migrated and has live DB writes won't get its newer rows overwritten by
//! a stale JSON file.
//!
//! On success, the JSON file is renamed to `*.migrated.bak` so a future
//! restart skips this branch and so operators have a clear trail of what
//! happened. On failure, the JSON file is left in place.

use std::collections::HashMap;
use std::path::Path;

use tracing::{info, warn};

use crate::directory::PostgresDirectoryNumberStore;
use crate::error::{ConfigStoreError, ConfigStoreResult};
use crate::model::DirectoryNumber;

/// Migrate `directory_numbers.json` into the Postgres store.
///
/// Returns the number of rows imported. `Ok(0)` is the steady-state happy
/// path (no JSON file present, or Postgres already populated).
///
/// # Errors
/// Returns `ConfigStoreError` if reading the JSON, parsing it, writing to
/// the database, or renaming the file fails. The caller (the daemon's
/// startup path) should log and continue — DIDs can be re-added via the
/// API if migration fails.
pub async fn migrate_directory_json_to_postgres(
    json_path: &Path,
    store: &PostgresDirectoryNumberStore,
) -> ConfigStoreResult<usize> {
    if !json_path.exists() {
        return Ok(0);
    }
    if !store.is_empty().await? {
        info!(
            path = %json_path.display(),
            "directory_numbers table not empty; skipping JSON migration"
        );
        return Ok(0);
    }

    let raw = tokio::fs::read_to_string(json_path).await?;
    // Legacy on-disk shape: HashMap<did, object>. We tolerate fields the
    // typed model doesn't know about by funneling them into `extra` via
    // `DirectoryNumber::from_json`'s `#[serde(flatten)]`.
    let map: HashMap<String, serde_json::Value> = serde_json::from_str(&raw)?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for (key, mut value) in map {
        // Ensure the value carries its `did` (legacy code persisted it
        // both as the map key and inside the object; tolerate either).
        if value.get("did").is_none() {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("did".to_string(), serde_json::Value::String(key.clone()));
            }
        }
        match DirectoryNumber::from_json(value) {
            Ok(dn) => {
                store.upsert(&dn).await?;
                imported += 1;
            }
            Err(e) => {
                warn!(did = %key, error = %e, "Skipping malformed DID during migration");
                skipped += 1;
            }
        }
    }

    let backup_path = json_path.with_extension("json.migrated.bak");
    tokio::fs::rename(json_path, &backup_path).await?;

    info!(
        imported,
        skipped,
        backup = %backup_path.display(),
        "Migrated directory_numbers.json into Postgres"
    );
    Ok(imported)
}
