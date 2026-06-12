//! End-to-end convergence tests: a local site database, driven by the
//! reconcile loop against the *real* `CentralConfigStore` (wrapped as an
//! in-process [`ConfigSource`], so no HTTP), must converge to central
//! state through snapshots and deltas — including tombstones, the
//! never-synced bootstrap, and the regression→snapshot path.
//!
//! Skipped unless `CENTRAL_STORE_TEST_DSN` (CREATE DATABASE rights) is
//! set:
//!
//! ```sh
//! CENTRAL_STORE_TEST_DSN=postgres://postgres@127.0.0.1:5432/postgres \
//!     cargo test -p sbc-config-sync --test convergence
//! ```

#![allow(clippy::expect_used)]

use std::str::FromStr;

use serde_json::{Map, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use central_config_store::{CentralConfigStore, ConfigTable, DeltaResult, Snapshot};
use sbc_config_sync::{ConfigSource, Outcome, SyncResult, reconcile};

const SITE: &str = "MUHJ";

/// Wrap the central store as a `ConfigSource` so reconcile runs in-process
/// against the genuine read paths (epoch/delta/snapshot).
struct DirectSource(CentralConfigStore);

impl ConfigSource for DirectSource {
    async fn epoch(&self, site: &str) -> SyncResult<i64> {
        self.0.epoch(site).await.map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
    async fn delta(&self, site: &str, since: i64) -> SyncResult<DeltaResult> {
        self.0.delta(site, since).await.map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
    async fn snapshot(&self, site: &str) -> SyncResult<Snapshot> {
        self.0.snapshot(site).await.map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
}

async fn admin_pool(admin: &str) -> PgPool {
    let opts = PgConnectOptions::from_str(admin).expect("parse dsn");
    PgPoolOptions::new().max_connections(1).connect_with(opts).await.expect("admin connect")
}

async fn make_db(admin: &str, name: &str) -> PgPool {
    let pool = admin_pool(admin).await;
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .execute(&pool)
        .await
        .expect("drop");
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&pool).await.expect("create");
    let opts = PgConnectOptions::from_str(admin).expect("dsn").database(name);
    PgPoolOptions::new().max_connections(5).connect_with(opts).await.expect("connect")
}

fn no_extra() -> Map<String, serde_json::Value> {
    Map::new()
}

/// Live (non-tombstoned) phone ids in the local DB.
async fn local_phone_ids(pool: &PgPool) -> Vec<String> {
    sqlx::query("SELECT id FROM phones WHERE NOT deleted ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("phones")
        .iter()
        .map(|r| r.get::<String, _>("id"))
        .collect()
}

async fn local_applied_epoch(pool: &PgPool) -> Option<i64> {
    sqlx::query_scalar::<_, i64>("SELECT applied_epoch FROM sync_state WHERE site_code = $1")
        .bind(SITE)
        .fetch_optional(pool)
        .await
        .expect("sync_state")
}

#[tokio::test]
async fn converges_via_snapshot_then_deltas() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else { return };

    // Central, seeded with a couple of rows before the site ever syncs.
    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_central").await)
        .await
        .expect("central migrate");
    central.register_site(SITE, "MUHJ", "muhj.x", "UTC", "active").await.expect("register");
    central
        .upsert_phone(SITE, "p1", "aaaaaaaaaaaa", &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}), "op")
        .await
        .expect("p1");
    central
        .upsert_did(SITE, "5551112222", Some("jdoe"), None, None, &no_extra(), "op")
        .await
        .expect("did");
    central
        .upsert_json(ConfigTable::DialPlans, SITE, "main", &json!({"id": "main", "entries": []}), "op")
        .await
        .expect("dialplan");
    let source = DirectSource(central);

    // Local site DB with the SBC schema but no data.
    let local = make_db(&admin, "scs_local").await;
    sbc_config_store::ensure_schema(&local).await.expect("local schema");

    // First reconcile: never synced → full snapshot.
    let outcome = reconcile(&local, &source, SITE).await.expect("first reconcile");
    assert!(matches!(outcome, Outcome::Snapshotted { rows: 3, .. }), "got {outcome:?}");
    assert_eq!(local_phone_ids(&local).await, vec!["p1"]);
    assert_eq!(local_applied_epoch(&local).await, Some(3));

    // Idempotent: nothing changed centrally → up to date, no work.
    let outcome = reconcile(&local, &source, SITE).await.expect("noop reconcile");
    assert!(matches!(outcome, Outcome::UpToDate { epoch: 3 }), "got {outcome:?}");

    // Central mutates: add a phone, delete the DID, update p1.
    source
        .0
        .upsert_phone(SITE, "p2", "bbbbbbbbbbbb", &json!({"id": "p2", "mac_address": "bb:bb:bb:bb:bb:bb"}), "op")
        .await
        .expect("p2");
    source.0.delete(ConfigTable::DirectoryNumbers, SITE, "5551112222", "op").await.expect("del did");
    source
        .0
        .upsert_phone(SITE, "p1", "aaaaaaaaaaaa", &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa", "label": "front desk"}), "op")
        .await
        .expect("p1 update");

    // Next reconcile: delta path applies all three.
    let outcome = reconcile(&local, &source, SITE).await.expect("delta reconcile");
    assert!(matches!(outcome, Outcome::DeltaApplied { from: 3, to: 6, changes: 3 }), "got {outcome:?}");
    assert_eq!(local_phone_ids(&local).await, vec!["p1", "p2"]);

    // The DID is tombstoned locally (not live), and p1 carries the update.
    let live_dids: i64 = sqlx::query_scalar("SELECT count(*) FROM directory_numbers WHERE NOT deleted")
        .fetch_one(&local)
        .await
        .expect("did count");
    assert_eq!(live_dids, 0, "DID tombstoned");
    let p1_label: serde_json::Value =
        sqlx::query_scalar("SELECT data -> 'label' FROM phones WHERE id = 'p1'")
            .fetch_one(&local)
            .await
            .expect("p1 label");
    assert_eq!(p1_label, json!("front desk"));

    // Synced rows are stamped central-origin, not local.
    let p2_origin: String =
        sqlx::query_scalar("SELECT updated_by FROM phones WHERE id = 'p2'")
            .fetch_one(&local)
            .await
            .expect("p2 origin");
    assert_eq!(p2_origin, "central");
}

#[tokio::test]
async fn regressed_local_recovers_via_snapshot() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else { return };

    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_regress_central").await)
        .await
        .expect("central migrate");
    central.register_site(SITE, "MUHJ", "muhj.x", "UTC", "active").await.expect("register");
    central
        .upsert_phone(SITE, "p1", "aaaaaaaaaaaa", &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}), "op")
        .await
        .expect("p1");
    let source = DirectSource(central);

    let local = make_db(&admin, "scs_regress_local").await;
    sbc_config_store::ensure_schema(&local).await.expect("local schema");
    reconcile(&local, &source, SITE).await.expect("initial");
    assert_eq!(local_applied_epoch(&local).await, Some(1));

    // Simulate a regression: local sync_state claims a future epoch (e.g.
    // central was restored from an older backup, or local state is stale
    // ahead). reconcile must fall back to a snapshot, not request a delta
    // from a since the central can't honor.
    sqlx::query("UPDATE sync_state SET applied_epoch = 999 WHERE site_code = $1")
        .bind(SITE)
        .execute(&local)
        .await
        .expect("bump local epoch");

    let outcome = reconcile(&local, &source, SITE).await.expect("regress reconcile");
    assert!(matches!(outcome, Outcome::Snapshotted { epoch: 1, rows: 1 }), "got {outcome:?}");
    assert_eq!(local_applied_epoch(&local).await, Some(1), "epoch corrected back down");
    assert_eq!(local_phone_ids(&local).await, vec!["p1"]);
}
