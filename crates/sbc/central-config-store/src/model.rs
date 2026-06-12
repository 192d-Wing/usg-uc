//! Types for the central config store's public API.

use serde::{Deserialize, Serialize};

/// The sharded config tables. Each is LIST-partitioned by `site_code`;
/// one partition per registered site. The order here is the order
/// [`ConfigTable::ALL`] returns and the order a snapshot emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigTable {
    /// `phones` — provisioning records keyed by id, MAC-unique per site.
    Phones,
    /// `directory_numbers` — DIDs; fleet-wide unique via `did_registry`.
    DirectoryNumbers,
    /// `trunk_groups` — JSONB pass-through.
    TrunkGroups,
    /// `dial_plans` — JSONB pass-through.
    DialPlans,
    /// `cucm_partitions` — JSONB pass-through.
    CucmPartitions,
    /// `cucm_calling_search_spaces` — JSONB pass-through.
    CucmCallingSearchSpaces,
    /// `cucm_route_patterns` — JSONB pass-through.
    CucmRoutePatterns,
    /// `cucm_route_lists` — JSONB pass-through.
    CucmRouteLists,
    /// `site_telephony_config` — per-site scalar settings.
    SiteTelephonyConfig,
}

impl ConfigTable {
    /// Every config table, in snapshot order.
    pub const ALL: [Self; 9] = [
        Self::Phones,
        Self::DirectoryNumbers,
        Self::TrunkGroups,
        Self::DialPlans,
        Self::CucmPartitions,
        Self::CucmCallingSearchSpaces,
        Self::CucmRoutePatterns,
        Self::CucmRouteLists,
        Self::SiteTelephonyConfig,
    ];

    /// The physical table name (also the `config_journal.table_name`
    /// value and the partition-name stem).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Phones => "phones",
            Self::DirectoryNumbers => "directory_numbers",
            Self::TrunkGroups => "trunk_groups",
            Self::DialPlans => "dial_plans",
            Self::CucmPartitions => "cucm_partitions",
            Self::CucmCallingSearchSpaces => "cucm_calling_search_spaces",
            Self::CucmRoutePatterns => "cucm_route_patterns",
            Self::CucmRouteLists => "cucm_route_lists",
            Self::SiteTelephonyConfig => "site_telephony_config",
        }
    }
}

/// A single change in the journal, as served by [`delta`]. The site sync
/// agent applies these in `epoch` order to converge its local shard.
///
/// [`delta`]: crate::CentralConfigStore::delta
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// The shard epoch at which this change committed. Multiple changes
    /// in one transaction share an epoch.
    pub epoch: i64,
    /// Which table the row lives in.
    pub table: ConfigTable,
    /// The row's identifier within its table (`id`, or `did` for
    /// directory numbers).
    pub row_id: String,
    /// `"upsert"` or `"delete"`.
    pub op: ChangeOp,
    /// For an upsert, the row's canonical JSON payload (what the site
    /// store's `upsert` consumes). `None` for a delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// The kind of change a [`Change`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeOp {
    /// Row created or updated.
    Upsert,
    /// Row deleted (tombstoned at the site).
    Delete,
}

impl ChangeOp {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "upsert" => Some(Self::Upsert),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// The result of a delta request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeltaResult {
    /// The journal covered the requested range; apply `changes` to move
    /// from epoch `from` to epoch `to`.
    Delta {
        /// The `since` epoch the client asked from.
        from: i64,
        /// The site's current epoch after applying `changes`.
        to: i64,
        /// Changes with `epoch > from`, ascending.
        changes: Vec<Change>,
    },
    /// The client's `since` is ahead of the site's current epoch (its
    /// local DB was restored to an earlier point, or it desynced). It
    /// must discard local state and fetch a fresh snapshot.
    MustSnapshot {
        /// The site's current epoch.
        current: i64,
    },
}

/// A full materialized shard: every live row, grouped by table, at a
/// single consistent `epoch`. The site loads this then resumes deltas
/// from `epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The epoch this snapshot was taken at.
    pub epoch: i64,
    /// Live rows per table, in [`ConfigTable::ALL`] order. Each inner
    /// value is the row's canonical JSON payload.
    pub tables: Vec<TableRows>,
}

/// The live rows of one table within a [`Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRows {
    /// Which table these rows belong to.
    pub table: ConfigTable,
    /// The rows' canonical JSON payloads.
    pub rows: Vec<serde_json::Value>,
}
