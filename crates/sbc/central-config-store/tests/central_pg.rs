//! Integration tests for the central config store against a real
//! Postgres. Skipped (pass trivially) unless `CENTRAL_STORE_TEST_DSN` is
//! set to a DSN with CREATE DATABASE rights; each test creates and drops
//! its own scratch database:
//!
//! ```sh
//! CENTRAL_STORE_TEST_DSN=postgres://postgres@127.0.0.1:5432/postgres \
//!     cargo test -p central-config-store --test central_pg
//! ```

#![allow(clippy::expect_used, clippy::panic)] // test harness: fail loudly

use std::str::FromStr;

use serde_json::{Map, Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use central_config_store::{
    CentralConfigStore, ChangeOp, ConfigTable, DeltaResult, SiteMaterialization, StoreConfig,
    TemplateKind,
};

fn admin_dsn() -> Option<String> {
    std::env::var("CENTRAL_STORE_TEST_DSN").ok()
}

/// Drop-if-exists + create a scratch database; return a store on it with
/// migrations applied.
async fn fresh_store(admin: &str, name: &str) -> CentralConfigStore {
    let admin_opts = PgConnectOptions::from_str(admin).expect("parse admin DSN");
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(admin_opts.clone())
        .await
        .expect("connect admin DSN");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .execute(&admin_pool)
        .await
        .expect("drop scratch db");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin_pool)
        .await
        .expect("create scratch db");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(admin_opts.database(name))
        .await
        .expect("connect scratch db");
    CentralConfigStore::from_pool(pool)
        .await
        .expect("migrate central schema")
}

fn no_extra() -> Map<String, Value> {
    Map::new()
}

#[tokio::test]
async fn register_creates_partitions_and_is_idempotent() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_register").await;

    store
        .register_site("OOPL-001", "OOPL lab", "oopl-001.x", "UTC", "active")
        .await
        .expect("register");
    // Re-register: no-op on the row, backfills partitions, no error.
    store
        .register_site("OOPL-001", "OOPL lab", "oopl-001.x", "UTC", "active")
        .await
        .expect("re-register");

    let parts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'phones' AND c.relkind = 'r'",
    )
    .fetch_one(store.pool())
    .await
    .expect("count phone partitions");
    assert_eq!(parts, 1, "exactly one phones partition for the one site");

    assert!(
        store
            .register_site("oopl", "x", "x", "UTC", "active")
            .await
            .is_err(),
        "lowercase site code rejected before DB"
    );
    assert_eq!(store.epoch("OOPL-001").await.expect("epoch"), 0);
    assert!(store.epoch("NOPE").await.is_err(), "unknown site errors");
}

#[tokio::test]
async fn writes_bump_epoch_and_journal_in_lockstep() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_writes").await;
    store
        .register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");

    let e1 = store
        .upsert_phone("MUHJ", "p1", "aabbccddeeff", &json!({"id": "p1"}), "alice")
        .await
        .expect("phone upsert");
    assert_eq!(e1, 1, "first write is epoch 1");

    let e2 = store
        .upsert_json(
            ConfigTable::DialPlans,
            "MUHJ",
            "main",
            &json!({"entries": []}),
            "alice",
        )
        .await
        .expect("dial plan upsert");
    assert_eq!(e2, 2);

    // sites.config_epoch tracks the latest; journal has one row per write.
    assert_eq!(store.epoch("MUHJ").await.expect("epoch"), 2);
    let journal_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM config_journal WHERE site_code = 'MUHJ'")
            .fetch_one(store.pool())
            .await
            .expect("journal count");
    assert_eq!(journal_rows, 2);

    // The phone row carries revision = its write epoch.
    let rev: i64 =
        sqlx::query_scalar("SELECT revision FROM phones WHERE site_code = 'MUHJ' AND id = 'p1'")
            .fetch_one(store.pool())
            .await
            .expect("phone revision");
    assert_eq!(rev, 1);
}

#[tokio::test]
async fn delta_returns_changes_and_snapshot_materializes_live_rows() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_delta").await;
    store
        .register_site("MPLS", "MPLS", "mpls.x", "UTC", "active")
        .await
        .expect("register");

    store
        .upsert_phone(
            "MPLS",
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "v": 1}),
            "a",
        )
        .await
        .expect("p1");
    store
        .upsert_phone("MPLS", "p2", "bbbbbbbbbbbb", &json!({"id": "p2"}), "a")
        .await
        .expect("p2");
    let e_after_update = store
        .upsert_phone(
            "MPLS",
            "p1",
            "aaaaaaaaaaaa",
            &json!({"id": "p1", "v": 2}),
            "a",
        )
        .await
        .expect("p1 update");
    let e_after_delete = store
        .delete(ConfigTable::Phones, "MPLS", "p2", "a")
        .await
        .expect("del p2");
    assert_eq!(e_after_delete, e_after_update + 1);

    // Delta from 0 replays every change in order, last write of p1 wins on
    // apply, and p2 ends in a delete.
    let DeltaResult::Delta { from, to, changes } =
        store.delta("MPLS", 0).await.expect("delta from 0")
    else {
        panic!("expected a delta, not a snapshot directive");
    };
    assert_eq!(from, 0);
    assert_eq!(to, e_after_delete);
    assert_eq!(changes.len(), 4, "p1, p2, p1-update, p2-delete");
    assert!(
        changes.windows(2).all(|w| w[0].epoch <= w[1].epoch),
        "ascending epochs"
    );
    let last = changes.last().expect("a change");
    assert_eq!(last.op, ChangeOp::Delete);
    assert_eq!(last.row_id, "p2");
    assert!(last.payload.is_none(), "delete carries no payload");

    // Incremental delta: only the tail after the second epoch.
    let DeltaResult::Delta { changes: tail, .. } =
        store.delta("MPLS", 2).await.expect("delta from 2")
    else {
        panic!("expected delta");
    };
    assert_eq!(tail.len(), 2, "only the update and the delete");

    // since ahead of current → must snapshot.
    assert!(matches!(
        store.delta("MPLS", 999).await.expect("delta ahead"),
        DeltaResult::MustSnapshot { current } if current == e_after_delete
    ));

    // Snapshot has only the one live phone (p1, v2); the deleted p2 is gone.
    let snap = store.snapshot("MPLS").await.expect("snapshot");
    assert_eq!(snap.epoch, e_after_delete);
    let phones = snap
        .tables
        .iter()
        .find(|t| t.table == ConfigTable::Phones)
        .expect("phones table in snapshot");
    assert_eq!(phones.rows.len(), 1, "only the live phone");
    assert_eq!(phones.rows[0].id, "p1");
    assert_eq!(phones.rows[0].payload, json!({"id": "p1", "v": 2}));
}

#[tokio::test]
async fn did_uniqueness_is_fleet_wide() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_did").await;
    store
        .register_site("AAAA", "A", "a.x", "UTC", "active")
        .await
        .expect("reg A");
    store
        .register_site("BBBB", "B", "b.x", "UTC", "active")
        .await
        .expect("reg B");

    store
        .upsert_did(
            "AAAA",
            "5551234567",
            Some("jdoe"),
            None,
            None,
            &no_extra(),
            "a",
        )
        .await
        .expect("claim DID for A");

    // Same DID at another site is a hard error.
    let err = store
        .upsert_did(
            "BBBB",
            "5551234567",
            Some("other"),
            None,
            None,
            &no_extra(),
            "b",
        )
        .await
        .expect_err("cross-site DID claim must fail");
    assert!(
        matches!(&err, central_config_store::CentralError::DidConflict { owner, .. } if owner == "AAAA"),
        "got {err:?}"
    );

    // Re-claiming at the owning site is fine (update).
    store
        .upsert_did(
            "AAAA",
            "5551234567",
            Some("jdoe2"),
            None,
            None,
            &no_extra(),
            "a",
        )
        .await
        .expect("re-claim at owner");

    // Deleting frees it fleet-wide; another site may then claim it.
    store
        .delete(ConfigTable::DirectoryNumbers, "AAAA", "5551234567", "a")
        .await
        .expect("del");
    let reg_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM did_registry WHERE did = '5551234567'")
            .fetch_one(store.pool())
            .await
            .expect("registry count");
    assert_eq!(reg_rows, 0, "tombstoning the DID frees the registry");
    store
        .upsert_did(
            "BBBB",
            "5551234567",
            Some("nowB"),
            None,
            None,
            &no_extra(),
            "b",
        )
        .await
        .expect("B claims the freed DID");
}

#[tokio::test]
async fn failed_write_rolls_back_epoch() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_rollback").await;
    store
        .register_site("CCCC", "C", "c.x", "UTC", "active")
        .await
        .expect("register");

    store
        .upsert_phone("CCCC", "p1", "aaaaaaaaaaaa", &json!({"id": "p1"}), "a")
        .await
        .expect("p1");
    assert_eq!(store.epoch("CCCC").await.expect("epoch"), 1);

    // A second live phone with the same MAC must fail the partial unique
    // index — and the epoch bump from that attempt must roll back.
    let err = store
        .upsert_phone("CCCC", "p2", "aaaaaaaaaaaa", &json!({"id": "p2"}), "a")
        .await
        .expect_err("duplicate live MAC must conflict");
    assert!(
        matches!(err, central_config_store::CentralError::Conflict(_)),
        "got {err:?}"
    );
    assert_eq!(
        store.epoch("CCCC").await.expect("epoch"),
        1,
        "epoch rolled back"
    );

    // Deleting a missing row is NotFound and also rolls back the epoch.
    let err = store
        .delete(ConfigTable::Phones, "CCCC", "ghost", "a")
        .await
        .expect_err("ghost");
    assert!(
        matches!(err, central_config_store::CentralError::NotFound),
        "got {err:?}"
    );
    assert_eq!(
        store.epoch("CCCC").await.expect("epoch"),
        1,
        "epoch rolled back on NotFound"
    );

    // Writing to an unknown site never advances anything.
    assert!(
        store
            .upsert_phone("ZZZZ", "p", "ffffffffffff", &json!({}), "a")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tombstoned_mac_is_reusable() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_macreuse").await;
    store
        .register_site("DDDD", "D", "d.x", "UTC", "active")
        .await
        .expect("register");

    store
        .upsert_phone("DDDD", "old", "aabbccddeeff", &json!({"id": "old"}), "a")
        .await
        .expect("old phone");
    store
        .delete(ConfigTable::Phones, "DDDD", "old", "a")
        .await
        .expect("tombstone old");

    // A replacement with a new id and the same MAC is provisionable (the
    // unique index is partial over live rows).
    store
        .upsert_phone("DDDD", "new", "aabbccddeeff", &json!({"id": "new"}), "a")
        .await
        .expect("MAC reuse after tombstone");

    let snap = store.snapshot("DDDD").await.expect("snapshot");
    let phones = snap
        .tables
        .iter()
        .find(|t| t.table == ConfigTable::Phones)
        .expect("phones");
    assert_eq!(phones.rows.len(), 1);
    assert_eq!(phones.rows[0].id, "new");
    assert_eq!(phones.rows[0].payload, json!({"id": "new"}));
}

/// Helper: count live rows in a JSON shard table for a site.
async fn live_count(store: &CentralConfigStore, table: &str, site: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE site_code = $1 AND NOT deleted"
    ))
    .bind(site)
    .fetch_one(store.pool())
    .await
    .expect("count")
}

#[tokio::test]
async fn template_materialization_rings_overrides_and_delete() {
    let Some(admin) = admin_dsn() else { return };
    let store = fresh_store(&admin, "cst_templates").await;
    // Ring 0 (canary), ring 1 sites, plus a site that overrides locally.
    for s in ["AAAA", "BBBB", "CCCC"] {
        store
            .register_site(s, s, &format!("{s}.x"), "UTC", "active")
            .await
            .expect("register");
    }

    // Author one trunk-group template, assign to three sites in two rings.
    store
        .upsert_template(
            TemplateKind::TrunkGroup,
            "us-domestic",
            &json!({"id": "us-domestic", "strategy": "priority"}),
            "op",
        )
        .await
        .expect("template");
    store
        .assign_template(TemplateKind::TrunkGroup, "us-domestic", "AAAA", 0)
        .await
        .expect("assign A");
    store
        .assign_template(TemplateKind::TrunkGroup, "us-domestic", "BBBB", 1)
        .await
        .expect("assign B");
    store
        .assign_template(TemplateKind::TrunkGroup, "us-domestic", "CCCC", 1)
        .await
        .expect("assign C");

    // CCCC has a local override of the same id (operator-written).
    store
        .upsert_json(
            ConfigTable::TrunkGroups,
            "CCCC",
            "us-domestic",
            &json!({"id": "us-domestic", "strategy": "round_robin"}),
            "alice@op",
        )
        .await
        .expect("override");

    // Materialize up to ring 0: only AAAA gets it; B/C are ring 1 (skipped).
    let report = store
        .materialize_template(TemplateKind::TrunkGroup, "us-domestic", 0)
        .await
        .expect("materialize r0");
    let applied = report
        .sites
        .iter()
        .filter(|s| matches!(s, SiteMaterialization::Applied { .. }))
        .count();
    assert_eq!(applied, 1, "only canary AAAA");
    assert!(
        report
            .sites
            .iter()
            .any(|s| matches!(s, SiteMaterialization::Applied{site_code,..} if site_code=="AAAA"))
    );
    assert_eq!(live_count(&store, "trunk_groups", "AAAA").await, 1);
    assert_eq!(
        live_count(&store, "trunk_groups", "BBBB").await,
        0,
        "ring 1 not yet"
    );

    // Promote to ring 1: BBBB gets it; CCCC is skipped (override wins).
    let report = store
        .materialize_template(TemplateKind::TrunkGroup, "us-domestic", 1)
        .await
        .expect("materialize r1");
    let overridden = report.sites.iter().any(|s| matches!(s, SiteMaterialization::SkippedOverridden { site_code } if site_code == "CCCC"));
    assert!(overridden, "CCCC override must be skipped: {report:?}");
    assert_eq!(live_count(&store, "trunk_groups", "BBBB").await, 1);

    // CCCC still has its own version, not the template's.
    let ccc: serde_json::Value = sqlx::query_scalar(
        "SELECT data FROM trunk_groups WHERE site_code='CCCC' AND id='us-domestic'",
    )
    .fetch_one(store.pool())
    .await
    .expect("ccc data");
    assert_eq!(ccc["strategy"], "round_robin", "override preserved");

    // Editing the template + re-materializing updates the non-overridden sites.
    store
        .upsert_template(
            TemplateKind::TrunkGroup,
            "us-domestic",
            &json!({"id": "us-domestic", "strategy": "least_connections"}),
            "op",
        )
        .await
        .expect("edit template");
    store
        .materialize_template(TemplateKind::TrunkGroup, "us-domestic", 1)
        .await
        .expect("re-materialize");
    let aaa: serde_json::Value = sqlx::query_scalar(
        "SELECT data FROM trunk_groups WHERE site_code='AAAA' AND id='us-domestic'",
    )
    .fetch_one(store.pool())
    .await
    .expect("aaa data");
    assert_eq!(
        aaa["strategy"], "least_connections",
        "AAAA tracks the template"
    );

    // Delete the template: tombstones template-origin rows (A, B), leaves
    // CCCC's override.
    store
        .delete_template(TemplateKind::TrunkGroup, "us-domestic")
        .await
        .expect("delete template");
    assert_eq!(
        live_count(&store, "trunk_groups", "AAAA").await,
        0,
        "A tombstoned"
    );
    assert_eq!(
        live_count(&store, "trunk_groups", "BBBB").await,
        0,
        "B tombstoned"
    );
    assert_eq!(
        live_count(&store, "trunk_groups", "CCCC").await,
        1,
        "C override survives"
    );

    // Template + assignments are gone (cascade).
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM template_assignments WHERE template_id='us-domestic'",
    )
    .fetch_one(store.pool())
    .await
    .expect("assign count");
    assert_eq!(n, 0);
}

/// Return `dsn` with its database segment replaced by `db` (handles an
/// optional `?query` suffix). Good enough for the simple harness DSNs.
fn with_db(dsn: &str, db: &str) -> String {
    let (base, query) = dsn
        .split_once('?')
        .map_or((dsn, None), |(b, q)| (b, Some(q)));
    let trimmed = base.trim_end_matches('/');
    let cut = trimmed.rfind('/').expect("dsn has a database path segment");
    let mut out = format!("{}/{db}", &trimmed[..cut]);
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
}

/// The read/write split: with a replica DSN configured (here the same node
/// stands in for a replica), writes land via the primary pool and the
/// replica-served `snapshot` still sees them; `ping` checks both pools.
#[tokio::test]
async fn split_pools_serve_reads_and_writes_on_one_node() {
    let Some(admin) = admin_dsn() else { return };
    // Create the scratch DB up front, then connect both pools to it.
    let _ = fresh_store(&admin, "cst_split").await;
    let dsn = with_db(&admin, "cst_split");
    let store = CentralConfigStore::connect_with(StoreConfig {
        primary_url: &dsn,
        replica_url: Some(&dsn),
        max_connections: 5,
        application_name: "central-config-store-test",
    })
    .await
    .expect("connect split pools");

    // Writes go to the primary.
    store
        .register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active")
        .await
        .expect("register");
    store
        .upsert_phone("MUHJ", "p1", "aabbccddeeff", &json!({"id": "p1"}), "op")
        .await
        .expect("upsert phone");

    // epoch/delta are primary-served and authoritative.
    assert_eq!(store.epoch("MUHJ").await.expect("epoch"), 1);

    // snapshot is replica-served and still sees the just-written row
    // (same node here, so no lag).
    let snap = store.snapshot("MUHJ").await.expect("snapshot");
    assert_eq!(snap.epoch, 1);
    let phones = snap
        .tables
        .iter()
        .find(|t| t.table == ConfigTable::Phones)
        .expect("phones table");
    assert_eq!(phones.rows.len(), 1);
    assert_eq!(phones.rows[0].id, "p1");

    // readiness pings both pools.
    store.ping().await.expect("ping both pools");
}
