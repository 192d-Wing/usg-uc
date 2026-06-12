//! One-shot import of a site-local config database into its central shard.
//!
//! Onboarding a base means copying the config it already serves from its
//! local Postgres (the `sbc-config-store` schema) into that site's shard of
//! the central database, after which the `sbc-config-sync` agent keeps the
//! local copy in step with central. This crate is that copy step.
//!
//! Each row is written through [`CentralConfigStore`]'s normal
//! transactional write path, so the shard ends up journaled and
//! epoch-stamped exactly as if an operator had entered it — the sync agent
//! can immediately serve deltas from it. Tombstoned local rows are not
//! imported (only live config is carried over).

use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use thiserror::Error;

use central_config_store::{CentralConfigStore, CentralError, ConfigTable};

/// Import failures.
#[derive(Debug, Error)]
pub enum ImportError {
    /// Reading the site-local database failed.
    #[error("source database: {0}")]
    Source(String),
    /// Writing the central shard failed (e.g. a cross-site DID collision).
    #[error("central store: {0}")]
    Central(#[from] CentralError),
}

impl From<sqlx::Error> for ImportError {
    fn from(e: sqlx::Error) -> Self {
        Self::Source(e.to_string())
    }
}

/// Per-table counts of rows imported.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImportReport {
    /// Phones imported.
    pub phones: usize,
    /// Directory numbers imported.
    pub directory_numbers: usize,
    /// Trunk groups imported.
    pub trunk_groups: usize,
    /// Dial plans imported.
    pub dial_plans: usize,
    /// CUCM routing entities imported (all four tables).
    pub cucm: usize,
    /// Site telephony config documents imported (0 or 1).
    pub site_config: usize,
}

/// The JSONB-pass-through tables imported generically by (id, data).
const JSON_TABLES: &[ConfigTable] = &[
    ConfigTable::TrunkGroups,
    ConfigTable::DialPlans,
    ConfigTable::CucmPartitions,
    ConfigTable::CucmCallingSearchSpaces,
    ConfigTable::CucmRoutePatterns,
    ConfigTable::CucmRouteLists,
    ConfigTable::SiteTelephonyConfig,
];

/// Import every live row from `source` (a site-local config DB) into
/// `central`'s shard for `site_code`.
///
/// The site must already be registered centrally (so its partitions
/// exist); `actor` is recorded as the writer. Idempotent: re-running
/// upserts the same rows. A DID already owned by a different site aborts
/// the import with [`ImportError::Central`].
///
/// # Errors
/// [`ImportError`] on a source read or central write failure.
pub async fn import_site(
    source: &PgPool,
    central: &CentralConfigStore,
    site_code: &str,
    actor: &str,
) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport::default();

    // Phones.
    let rows = sqlx::query("SELECT id, mac_normalized, data FROM phones WHERE NOT deleted")
        .fetch_all(source)
        .await?;
    for row in &rows {
        let id: String = row.try_get("id")?;
        let mac: String = row.try_get("mac_normalized")?;
        let data: Value = row.try_get("data")?;
        central.upsert_phone(site_code, &id, &mac, &data, actor).await?;
        report.phones += 1;
    }

    // Directory numbers.
    let rows =
        sqlx::query("SELECT did, sip_user, partition, description, extra FROM directory_numbers WHERE NOT deleted")
            .fetch_all(source)
            .await?;
    for row in &rows {
        let did: String = row.try_get("did")?;
        let sip_user: Option<String> = row.try_get("sip_user")?;
        let partition: Option<String> = row.try_get("partition")?;
        let description: Option<String> = row.try_get("description")?;
        let extra: Value = row.try_get("extra")?;
        let extra_map: Map<String, Value> = extra.as_object().cloned().unwrap_or_default();
        central
            .upsert_did(
                site_code,
                &did,
                sip_user.as_deref(),
                partition.as_deref(),
                description.as_deref(),
                &extra_map,
                actor,
            )
            .await?;
        report.directory_numbers += 1;
    }

    // JSONB pass-through tables. Some (CUCM, site config) may not exist in
    // an older site schema — a missing relation is treated as "nothing to
    // import", not an error.
    for &table in JSON_TABLES {
        let sql = format!("SELECT id, data FROM {} WHERE NOT deleted", table.name());
        let rows = match sqlx::query(&sql).fetch_all(source).await {
            Ok(r) => r,
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P01") => continue,
            Err(e) => return Err(ImportError::from(e)),
        };
        for row in &rows {
            let id: String = row.try_get("id")?;
            let data: Value = row.try_get("data")?;
            central.upsert_json(table, site_code, &id, &data, actor).await?;
            match table {
                ConfigTable::TrunkGroups => report.trunk_groups += 1,
                ConfigTable::DialPlans => report.dial_plans += 1,
                ConfigTable::SiteTelephonyConfig => report.site_config += 1,
                _ => report.cucm += 1,
            }
        }
    }

    Ok(report)
}
