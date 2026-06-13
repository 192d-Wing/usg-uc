//! The config source abstraction and the reconcile cycle.
//!
//! [`ConfigSource`] is the three sync reads the agent needs. The
//! production implementation, [`CentralClient`], is HTTP against
//! `central-config-api`; tests implement it in-process over the real
//! `CentralConfigStore`, so [`reconcile`] is exercised end-to-end without
//! a network. [`reconcile`] itself is the convergence policy: snapshot
//! when we've never synced or have regressed, otherwise apply a delta.

use central_config_store::{DeltaResult, Snapshot, UploadBatch, UploadChange};
use reqwest::StatusCode;

use crate::token::Auth;

use crate::apply::{
    applied_epoch, apply_delta, apply_snapshot, collect_local_changes, restamp_uploaded,
};
use crate::error::{SyncError, SyncResult};
use crate::refresh::{RefreshItem, Refresher};

/// The reads the agent pulls from central, plus the upload it pushes.
pub trait ConfigSource {
    /// The site's current shard epoch.
    fn epoch(&self, site_code: &str) -> impl Future<Output = SyncResult<i64>> + Send;
    /// Changes since `since` (or a directive to re-snapshot).
    fn delta(
        &self,
        site_code: &str,
        since: i64,
    ) -> impl Future<Output = SyncResult<DeltaResult>> + Send;
    /// The full live shard at the current epoch.
    fn snapshot(&self, site_code: &str) -> impl Future<Output = SyncResult<Snapshot>> + Send;
    /// Upload local edits (made while partitioned) for central to adopt;
    /// returns the resulting epoch.
    fn upload(
        &self,
        site_code: &str,
        changes: &[UploadChange],
    ) -> impl Future<Output = SyncResult<i64>> + Send;
}

/// What a reconcile cycle did — for logging and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Local already at the central epoch; nothing fetched or applied.
    UpToDate {
        /// The shared epoch.
        epoch: i64,
    },
    /// A delta was applied, advancing the local epoch.
    DeltaApplied {
        /// Epoch advanced from.
        from: i64,
        /// Epoch advanced to.
        to: i64,
        /// Number of changes applied.
        changes: usize,
    },
    /// A full snapshot was loaded (first sync or after a regression).
    Snapshotted {
        /// The snapshot's epoch.
        epoch: i64,
        /// Number of rows loaded.
        rows: usize,
    },
}

/// Run one reconcile cycle for `site_code` against `source`, applying the
/// result into the local `pool`.
///
/// Policy:
/// - never synced, or local epoch ahead of central (a regression — central
///   restored to an earlier point, or our `sync_state` is corrupt), or the
///   delta endpoint says so → full snapshot.
/// - local == central → up to date.
/// - local behind central → apply the delta.
///
/// # Errors
/// [`SyncError`] if a read or the apply transaction fails.
pub async fn reconcile<S: ConfigSource + Sync, R: Refresher + Sync>(
    pool: &sqlx::PgPool,
    source: &S,
    refresher: &R,
    site_code: &str,
) -> SyncResult<Outcome> {
    // DDIL reconcile: push any local edits made while partitioned up to
    // central first (local wins), then re-stamp them central-origin so they
    // converge and aren't re-uploaded. Only after they're adopted do we pull
    // — so a delta/snapshot can't clobber an edit central hasn't seen yet.
    let pending = collect_local_changes(pool, site_code).await?;
    if !pending.is_empty() {
        let epoch = source.upload(site_code, &pending).await?;
        restamp_uploaded(pool, &pending, epoch).await?;
    }

    let local = applied_epoch(pool, site_code).await?;
    let central = source.epoch(site_code).await?;

    match local {
        Some(a) if a == central => Ok(Outcome::UpToDate { epoch: central }),
        Some(a) if a < central => match source.delta(site_code, a).await? {
            DeltaResult::Delta { from, to, changes } => {
                let n = changes.len();
                // Best-effort daemon refresh for the entities that changed.
                let items: Vec<RefreshItem> = changes
                    .iter()
                    .map(|c| RefreshItem {
                        table: c.table,
                        id: c.row_id.clone(),
                        op: c.op,
                    })
                    .collect();
                apply_delta(pool, site_code, &changes, to).await?;
                refresher.refresh(&items).await;
                Ok(Outcome::DeltaApplied {
                    from,
                    to,
                    changes: n,
                })
            }
            DeltaResult::MustSnapshot { .. } => {
                snapshot_path(pool, source, refresher, site_code).await
            }
        },
        // None (never synced) or local ahead of central (regressed).
        _ => snapshot_path(pool, source, refresher, site_code).await,
    }
}

async fn snapshot_path<S: ConfigSource + Sync, R: Refresher + Sync>(
    pool: &sqlx::PgPool,
    source: &S,
    refresher: &R,
    site_code: &str,
) -> SyncResult<Outcome> {
    let snap = source.snapshot(site_code).await?;
    let rows = snap.tables.iter().map(|t| t.rows.len()).sum();
    // Refresh every live row the snapshot loaded (best-effort upserts).
    let items: Vec<RefreshItem> = snap
        .tables
        .iter()
        .flat_map(|t| {
            t.rows.iter().map(move |r| RefreshItem {
                table: t.table,
                id: r.id.clone(),
                op: central_config_store::ChangeOp::Upsert,
            })
        })
        .collect();
    apply_snapshot(pool, site_code, &snap).await?;
    refresher.refresh(&items).await;
    Ok(Outcome::Snapshotted {
        epoch: snap.epoch,
        rows,
    })
}

/// HTTP implementation of [`ConfigSource`] against `central-config-api`.
pub struct CentralClient {
    http: reqwest::Client,
    base_url: String,
    auth: Auth,
}

impl CentralClient {
    /// Build a client. `base_url` is the API root (no trailing slash);
    /// `auth` supplies (and refreshes) the site's bearer token.
    #[must_use]
    pub fn new(http: reqwest::Client, base_url: impl Into<String>, auth: Auth) -> Self {
        Self {
            http,
            base_url: base_url.into(),
            auth,
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> SyncResult<T> {
        let token = self.auth.bearer().await?;
        let resp = self.http.get(url).bearer_auth(token).send().await?;
        let status = resp.status();
        if status != StatusCode::OK {
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::Central(format!("{status} from {url}: {body}")));
        }
        resp.json::<T>().await.map_err(SyncError::from)
    }
}

/// `{ "epoch": N }` from the epoch endpoint.
#[derive(serde::Deserialize)]
struct EpochResp {
    epoch: i64,
}

impl ConfigSource for CentralClient {
    async fn epoch(&self, site_code: &str) -> SyncResult<i64> {
        let url = format!("{}/v1/sync/{site_code}/epoch", self.base_url);
        let r: EpochResp = self.get_json(&url).await?;
        Ok(r.epoch)
    }

    async fn delta(&self, site_code: &str, since: i64) -> SyncResult<DeltaResult> {
        let url = format!("{}/v1/sync/{site_code}/delta?since={since}", self.base_url);
        self.get_json(&url).await
    }

    async fn snapshot(&self, site_code: &str) -> SyncResult<Snapshot> {
        let url = format!("{}/v1/sync/{site_code}/snapshot", self.base_url);
        self.get_json(&url).await
    }

    async fn upload(&self, site_code: &str, changes: &[UploadChange]) -> SyncResult<i64> {
        let url = format!("{}/v1/sync/{site_code}/upload", self.base_url);
        let batch = UploadBatch {
            changes: changes.to_vec(),
        };
        let token = self.auth.bearer().await?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&batch)
            .send()
            .await?;
        let status = resp.status();
        if status != StatusCode::OK {
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::Central(format!("{status} from {url}: {body}")));
        }
        let r: EpochResp = resp.json().await?;
        Ok(r.epoch)
    }
}
