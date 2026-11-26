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

#![allow(clippy::expect_used, clippy::significant_drop_tightening)]

use std::str::FromStr;

use serde_json::{Map, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use central_config_store::{CentralConfigStore, ConfigTable, DeltaResult, Snapshot};
use sbc_config_sync::{
    ConfigSource, NoopRefresher, Outcome, RefreshItem, Refresher, SyncResult, reconcile,
};

/// Records the items reconcile asks the daemon to refresh.
#[derive(Default)]
struct RecordingRefresher {
    seen: std::sync::Mutex<Vec<(String, String)>>, // (table, id)
}

impl Refresher for RecordingRefresher {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "async signature kept for callers; body has no await yet"
    )]
    async fn refresh(&self, items: &[RefreshItem]) {
        let mut g = self.seen.lock().expect("lock");
        for i in items {
            g.push((i.table.name().to_string(), i.id.clone()));
        }
    }
}

const SITE: &str = "MUHJ";

/// Wrap the central store as a `ConfigSource` so reconcile runs in-process
/// against the genuine read paths (epoch/delta/snapshot).
struct DirectSource(CentralConfigStore);

impl ConfigSource for DirectSource {
    async fn epoch(&self, site: &str) -> SyncResult<i64> {
        self.0
            .epoch(site)
            .await
            .map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
    async fn delta(&self, site: &str, since: i64) -> SyncResult<DeltaResult> {
        self.0
            .delta(site, since)
            .await
            .map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
    async fn snapshot(&self, site: &str) -> SyncResult<Snapshot> {
        self.0
            .snapshot(site)
            .await
            .map_err(|e| sbc_config_sync::SyncError::Central(e.to_string()))
    }
    async fn upload(
        &self,
        site: &str,
        changes: &[central_config_store::UploadChange],
    ) -> SyncResult<i64> {
        // Mirror the central API's upload handler: apply each change to
        // the shard (local wins), idempotent on NotFound deletes.
        let mut last = self.0.epoch(site).await.unwrap_or(0);
        for c in changes {
            match self
                .0
                .apply_change(site, c.table, c.op, &c.id, c.payload.as_ref(), "site:test")
                .await
            {
                Ok(e) => last = e,
                Err(central_config_store::CentralError::NotFound) => {}
                Err(e) => return Err(sbc_config_sync::SyncError::Central(e.to_string())),
            }
        }
        Ok(last)
    }
}

async fn admin_pool(admin: &str) -> PgPool {
    let opts = PgConnectOptions::from_str(admin).expect("parse dsn");
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("admin connect")
}

async fn make_db(admin: &str, name: &str) -> PgPool {
    let pool = admin_pool(admin).await;
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .execute(&pool)
        .await
        .expect("drop");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&pool)
        .await
        .expect("create");
    let opts = PgConnectOptions::from_str(admin)
        .expect("dsn")
        .database(name);
    PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect")
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
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };

    // Central, seeded with a couple of rows before the site ever syncs.
    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_central").await)
        .await
        .expect("central migrate");
    central
        .register_site(SITE, "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    central
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}),
            "op",
        )
        .await
        .expect("p1");
    central
        .upsert_did(
            SITE,
            "5551112222",
            Some("jdoe"),
            None,
            None,
            &no_extra(),
            "op",
        )
        .await
        .expect("did");
    central
        .upsert_json(
            ConfigTable::DialPlans,
            SITE,
            "main",
            &json!({"id": "main", "entries": []}),
            "op",
        )
        .await
        .expect("dialplan");
    let source = DirectSource(central);

    // Local site DB with the SBC schema but no data.
    let local = make_db(&admin, "scs_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");

    // First reconcile: never synced → full snapshot.
    let outcome = reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("first reconcile");
    assert!(
        matches!(outcome, Outcome::Snapshotted { rows: 3, .. }),
        "got {outcome:?}"
    );
    assert_eq!(local_phone_ids(&local).await, vec!["p1"]);
    assert_eq!(local_applied_epoch(&local).await, Some(3));

    // Idempotent: nothing changed centrally → up to date, no work.
    let outcome = reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("noop reconcile");
    assert!(
        matches!(outcome, Outcome::UpToDate { epoch: 3 }),
        "got {outcome:?}"
    );

    // Central mutates: add a phone, delete the DID, update p1.
    source
        .0
        .upsert_phone(
            SITE,
            "p2",
            "bbbbbbbbbbbb",
            &json!({"id": "p2", "mac_address": "bb:bb:bb:bb:bb:bb"}),
            "op",
        )
        .await
        .expect("p2");
    source
        .0
        .delete(ConfigTable::DirectoryNumbers, SITE, "5551112222", "op")
        .await
        .expect("del did");
    source
        .0
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa", "label": "front desk"}),
            "op",
        )
        .await
        .expect("p1 update");

    // Next reconcile: delta path applies all three.
    let outcome = reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("delta reconcile");
    assert!(
        matches!(
            outcome,
            Outcome::DeltaApplied {
                from: 3,
                to: 6,
                changes: 3
            }
        ),
        "got {outcome:?}"
    );
    assert_eq!(local_phone_ids(&local).await, vec!["p1", "p2"]);

    // The DID is tombstoned locally (not live), and p1 carries the update.
    let live_dids: i64 =
        sqlx::query_scalar("SELECT count(*) FROM directory_numbers WHERE NOT deleted")
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
    let p2_origin: String = sqlx::query_scalar("SELECT updated_by FROM phones WHERE id = 'p2'")
        .fetch_one(&local)
        .await
        .expect("p2 origin");
    assert_eq!(p2_origin, "central");
}

#[tokio::test]
async fn ddil_local_edit_survives_and_syncs_up() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };

    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_ddil_central").await)
        .await
        .expect("central migrate");
    central
        .register_site(SITE, "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    central
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}),
            "op",
        )
        .await
        .expect("central p1");
    let source = DirectSource(central);

    let local = make_db(&admin, "scs_ddil_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("initial sync"); // pulls p1

    // --- link goes down; the site makes local edits ---
    // A new phone the field operator added, and an edit to p1 — both
    // stamped updated_by='local' as the site-local API would.
    sqlx::query(
        "INSERT INTO phones (id, mac_normalized, data, updated_by) VALUES ($1,$2,$3,'local')",
    )
    .bind("p-field")
    .bind("bbbbbbbbbbbb")
    .bind(json!({"id":"p-field","mac_address":"bb:bb:bb:bb:bb:bb","label":"forward TOC"}))
    .execute(&local)
    .await
    .expect("local add");
    sqlx::query("UPDATE phones SET data = $1, updated_by='local', revision=0 WHERE id='p1'")
        .bind(json!({"id":"p1","mac_address":"aa:aa:aa:aa:aa:aa","label":"edited at edge"}))
        .execute(&local)
        .await
        .expect("local edit");

    // Meanwhile central changes something unrelated (another phone).
    source
        .0
        .upsert_phone(
            SITE,
            "p-hq",
            "cccccccccccc",
            &json!({"id":"p-hq","mac_address":"cc:cc:cc:cc:cc:cc"}),
            "op",
        )
        .await
        .expect("central p-hq");

    // --- link returns: reconcile pushes local edits up, then pulls ---
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("reconnect reconcile");

    // The local edits propagated to central (local wins).
    let snap = source.0.snapshot(SITE).await.expect("central snapshot");
    let phones: std::collections::HashMap<String, serde_json::Value> = snap
        .tables
        .iter()
        .find(|t| t.table == ConfigTable::Phones)
        .expect("phones")
        .rows
        .iter()
        .map(|r| (r.id.clone(), r.payload.clone()))
        .collect();
    assert!(
        phones.contains_key("p-field"),
        "new local phone reached central"
    );
    assert_eq!(
        phones["p1"]["label"], "edited at edge",
        "local edit of p1 won at central"
    );
    assert!(
        phones.contains_key("p-hq"),
        "central's own change still present"
    );

    // Locally everything converged and nothing is left marked 'local'.
    let still_local: i64 =
        sqlx::query_scalar("SELECT count(*) FROM phones WHERE updated_by='local'")
            .fetch_one(&local)
            .await
            .expect("count local");
    assert_eq!(still_local, 0, "uploaded edits re-stamped central-origin");
    assert_eq!(local_phone_ids(&local).await, vec!["p-field", "p-hq", "p1"]);
    // The central change pulled down too.
    let hq: i64 = sqlx::query_scalar("SELECT count(*) FROM phones WHERE id='p-hq' AND NOT deleted")
        .fetch_one(&local)
        .await
        .expect("hq");
    assert_eq!(hq, 1);
}

#[tokio::test]
async fn regressed_local_recovers_via_snapshot() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };

    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_regress_central").await)
        .await
        .expect("central migrate");
    central
        .register_site(SITE, "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    central
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}),
            "op",
        )
        .await
        .expect("p1");
    let source = DirectSource(central);

    let local = make_db(&admin, "scs_regress_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("initial");
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

    let outcome = reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("regress reconcile");
    assert!(
        matches!(outcome, Outcome::Snapshotted { epoch: 1, rows: 1 }),
        "got {outcome:?}"
    );
    assert_eq!(
        local_applied_epoch(&local).await,
        Some(1),
        "epoch corrected back down"
    );
    assert_eq!(local_phone_ids(&local).await, vec!["p1"]);
}

#[tokio::test]
async fn reconcile_refreshes_changed_entities() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };

    let central = CentralConfigStore::from_pool(make_db(&admin, "scs_refresh_central").await)
        .await
        .expect("central migrate");
    central
        .register_site(SITE, "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    central
        .upsert_json(
            ConfigTable::DialPlans,
            SITE,
            "main",
            &json!({"id": "main", "entries": []}),
            "op",
        )
        .await
        .expect("dialplan");
    central
        .upsert_json(
            ConfigTable::TrunkGroups,
            SITE,
            "us",
            &json!({"id": "us"}),
            "op",
        )
        .await
        .expect("tg");
    let source = DirectSource(central);

    let local = make_db(&admin, "scs_refresh_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    let rec = RecordingRefresher::default();

    // Snapshot bootstrap refreshes the two live routing/trunk rows.
    reconcile(&local, &source, &rec, SITE)
        .await
        .expect("snapshot");
    {
        let seen = rec.seen.lock().expect("lock");
        assert!(
            seen.contains(&("dial_plans".into(), "main".into())),
            "snapshot refresh: {seen:?}"
        );
        assert!(seen.contains(&("trunk_groups".into(), "us".into())));
    }
    rec.seen.lock().expect("lock").clear();

    // A delta refreshes exactly what changed: one trunk-group delete.
    source
        .0
        .delete(ConfigTable::TrunkGroups, SITE, "us", "op")
        .await
        .expect("del tg");
    reconcile(&local, &source, &rec, SITE).await.expect("delta");
    let seen = rec.seen.lock().expect("lock");
    assert_eq!(
        seen.as_slice(),
        &[("trunk_groups".to_string(), "us".to_string())],
        "delta refresh"
    );
}

// ---- SR-40: local rows carry the writer's principal ----------------------
//
// sbc-api now stamps `updated_by = 'local:<actor>'`. Every sync origin test
// must treat both the legacy `'local'` and `'local:%'` as local-origin:
// preserved by snapshot/delta, collected for upload, re-stamped after.
// NIST 800-53 Rev5: AU-3, CM-3, CP-10 (DDIL)

const OIDC_ACTOR: &str = "local:oidc:s-1@https://idp.example/realms/qa";

async fn origin(pool: &PgPool, table: &str, key: &str, id: &str) -> String {
    sqlx::query_scalar(&format!("SELECT updated_by FROM {table} WHERE {key} = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("updated_by")
}

async fn phone_label(pool: &PgPool, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT data FROM phones WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("phone data")
        .get("label")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Central with one site and phone p1 (label "hq"), wrapped as a source.
async fn central_with_p1(admin: &str, name: &str) -> DirectSource {
    let central = CentralConfigStore::from_pool(make_db(admin, name).await)
        .await
        .expect("central migrate");
    central
        .register_site(SITE, "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    central
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa", "label": "hq"}),
            "op",
        )
        .await
        .expect("central p1");
    DirectSource(central)
}

async fn local_edit(pool: &PgPool, id: &str, mac: &str, label: &str, by: &str) {
    sqlx::query(
        "INSERT INTO phones (id, mac_normalized, data, updated_by, revision)
         VALUES ($1, $2, $3, $4, 0)
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data,
             updated_by = EXCLUDED.updated_by, revision = 0, updated_at = NOW()",
    )
    .bind(id)
    .bind(mac.replace(':', ""))
    .bind(json!({"id": id, "mac_address": mac, "label": label}))
    .bind(by)
    .execute(pool)
    .await
    .expect("local edit");
}

#[tokio::test]
async fn local_principal_rows_survive_snapshot_and_upload() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let source = central_with_p1(&admin, "scs_sr40_keep_central").await;
    let local = make_db(&admin, "scs_sr40_keep_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("initial sync");
    assert_eq!(origin(&local, "phones", "id", "p1").await, "central");

    // Partitioned: an operator edits p1 and adds p-field through sbc-api;
    // a DID and a trunk group are tombstoned/edited by an API key.
    local_edit(
        &local,
        "p1",
        "aa:aa:aa:aa:aa:aa",
        "edited at edge",
        OIDC_ACTOR,
    )
    .await;
    local_edit(
        &local,
        "p-field",
        "bb:bb:bb:bb:bb:bb",
        "forward TOC",
        OIDC_ACTOR,
    )
    .await;
    sqlx::query("INSERT INTO trunk_groups (id, data, updated_by) VALUES ('tg-edge', $1, $2)")
        .bind(json!({"id": "tg-edge", "trunks": []}))
        .bind("local:apikey:0123456789abcdef")
        .execute(&local)
        .await
        .expect("local tg");

    // A snapshot reload must not clobber local-principal rows.
    let snap = source.0.snapshot(SITE).await.expect("snapshot");
    sbc_config_sync::apply::apply_snapshot(&local, SITE, &snap)
        .await
        .expect("apply snapshot");
    assert_eq!(
        phone_label(&local, "p1").await.as_deref(),
        Some("edited at edge")
    );
    assert_eq!(origin(&local, "phones", "id", "p1").await, OIDC_ACTOR);
    assert_eq!(origin(&local, "phones", "id", "p-field").await, OIDC_ACTOR);
    assert_eq!(
        origin(&local, "trunk_groups", "id", "tg-edge").await,
        "local:apikey:0123456789abcdef"
    );

    // Nor a same-id central delta (central edits p1 meanwhile).
    source
        .0
        .upsert_phone(
            SITE,
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa", "label": "hq v2"}),
            "op",
        )
        .await
        .expect("central p1 v2");

    // Local-principal rows are collected for upload.
    let pending = sbc_config_sync::apply::collect_local_changes(&local, SITE)
        .await
        .expect("collect");
    let mut ids: Vec<_> = pending.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["p-field", "p1", "tg-edge"], "{pending:?}");

    // Reconnect: local wins at central, nothing is left local-marked.
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("reconnect");
    let snap = source.0.snapshot(SITE).await.expect("snapshot");
    let rows: std::collections::HashMap<String, serde_json::Value> = snap
        .tables
        .iter()
        .find(|t| t.table == ConfigTable::Phones)
        .expect("phones")
        .rows
        .iter()
        .map(|r| (r.id.clone(), r.payload.clone()))
        .collect();
    assert_eq!(rows["p1"]["label"], "edited at edge", "local edit won");
    assert!(rows.contains_key("p-field"));
    assert_eq!(
        phone_label(&local, "p1").await.as_deref(),
        Some("edited at edge")
    );
}

#[tokio::test]
async fn restamp_clears_local_principal_marker() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let local = make_db(&admin, "scs_sr40_restamp").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    local_edit(&local, "p-a", "aa:00:00:00:00:01", "a", OIDC_ACTOR).await;
    local_edit(&local, "p-b", "aa:00:00:00:00:02", "b", "local:admin:admin").await;

    let collected_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&local)
            .await
            .expect("clock");
    let pending = sbc_config_sync::apply::collect_local_changes(&local, SITE)
        .await
        .expect("collect");
    assert_eq!(pending.len(), 2, "{pending:?}");

    // An edit after the collect keeps its marker (TOCTOU guard).
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    local_edit(
        &local,
        "p-b",
        "aa:00:00:00:00:02",
        "b2",
        "local:admin:admin",
    )
    .await;

    sbc_config_sync::apply::restamp_uploaded(&local, &pending, 7, collected_at)
        .await
        .expect("restamp");
    assert_eq!(origin(&local, "phones", "id", "p-a").await, "central");
    let rev: i64 = sqlx::query_scalar("SELECT revision FROM phones WHERE id = 'p-a'")
        .fetch_one(&local)
        .await
        .expect("revision");
    assert_eq!(rev, 7);
    assert_eq!(
        origin(&local, "phones", "id", "p-b").await,
        "local:admin:admin",
        "edited after collect: still local"
    );
    let marked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM phones WHERE updated_by = 'local' OR updated_by LIKE 'local:%'",
    )
    .fetch_one(&local)
    .await
    .expect("count");
    assert_eq!(marked, 1);
}

#[tokio::test]
async fn legacy_local_rows_still_uploaded() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let source = central_with_p1(&admin, "scs_sr40_legacy_central").await;
    let local = make_db(&admin, "scs_sr40_legacy_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("initial sync");

    // A row written before the upgrade, and one after, side by side.
    local_edit(&local, "p-old", "cc:00:00:00:00:01", "legacy", "local").await;
    local_edit(&local, "p-new", "cc:00:00:00:00:02", "new", OIDC_ACTOR).await;
    // A look-alike that is not local-origin must not be uploaded.
    sqlx::query("UPDATE phones SET updated_by = 'localhost' WHERE id = 'p1'")
        .execute(&local)
        .await
        .expect("look-alike");

    let snap = source.0.snapshot(SITE).await.expect("snapshot");
    sbc_config_sync::apply::apply_snapshot(&local, SITE, &snap)
        .await
        .expect("apply snapshot");
    assert_eq!(origin(&local, "phones", "id", "p-old").await, "local");
    assert_eq!(origin(&local, "phones", "id", "p-new").await, OIDC_ACTOR);
    assert_eq!(
        origin(&local, "phones", "id", "p1").await,
        "central",
        "a non-local marker is replaced by the snapshot"
    );

    let pending = sbc_config_sync::apply::collect_local_changes(&local, SITE)
        .await
        .expect("collect");
    let mut ids: Vec<_> = pending.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["p-new", "p-old"]);

    reconcile(&local, &source, &NoopRefresher, SITE)
        .await
        .expect("reconnect");
    let still_local: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM phones WHERE updated_by = 'local' OR updated_by LIKE 'local:%'",
    )
    .fetch_one(&local)
    .await
    .expect("count");
    assert_eq!(still_local, 0, "both re-stamped central-origin");
}

/// SR-40 round 1 (NIST-007): each collected change carries the row's
/// `updated_by`, so central can name the site-local writer.
#[tokio::test]
async fn collected_changes_carry_origin_actor() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let local = make_db(&admin, "scs_sr40_origin_local").await;
    sbc_config_store::ensure_schema(&local)
        .await
        .expect("local schema");
    local_edit(&local, "p-old", "cc:00:00:00:00:11", "legacy", "local").await;
    local_edit(&local, "p-new", "cc:00:00:00:00:12", "new", OIDC_ACTOR).await;
    let mut pending = sbc_config_sync::apply::collect_local_changes(&local, SITE)
        .await
        .expect("collect");
    pending.sort_by(|a, b| a.id.cmp(&b.id));
    let origins: Vec<_> = pending.iter().map(|c| c.origin_actor.as_deref()).collect();
    assert_eq!(origins, [Some(OIDC_ACTOR), Some("local")]);
}
