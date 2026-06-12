//! Import test: seed a site-local config DB (the `sbc-config-store`
//! schema), import it into a central shard, and assert the shard reflects
//! every live row — including DID registry claims and skipped tombstones.
//!
//! Skipped unless `CENTRAL_STORE_TEST_DSN` (CREATE DATABASE rights) is set.

#![allow(clippy::expect_used)]

use std::str::FromStr;

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use central_config_import::import_site;
use central_config_store::{CentralConfigStore, ConfigTable};

async fn make_db(admin: &str, name: &str) -> PgPool {
    let opts = PgConnectOptions::from_str(admin).expect("dsn");
    let admin_pool = PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("admin");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).execute(&admin_pool).await.expect("drop");
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin_pool).await.expect("create");
    PgPoolOptions::new().max_connections(5).connect_with(opts.database(name)).await.expect("connect")
}

#[tokio::test]
async fn imports_live_rows_into_central_shard() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else { return };

    // Site-local DB with the SBC schema + a few rows, including one
    // tombstone that must NOT be imported.
    let site_db = make_db(&admin, "cci_source").await;
    sbc_config_store::ensure_schema(&site_db).await.expect("local schema");
    sqlx::query("INSERT INTO phones (id, mac_normalized, data) VALUES ($1,$2,$3)")
        .bind("p1").bind("aabbccddeeff").bind(json!({"id":"p1","mac_address":"aa:bb:cc:dd:ee:ff"}))
        .execute(&site_db).await.expect("phone");
    sqlx::query("INSERT INTO phones (id, mac_normalized, data, deleted) VALUES ($1,$2,$3,TRUE)")
        .bind("p-dead").bind("ffffffffffff").bind(json!({"id":"p-dead"}))
        .execute(&site_db).await.expect("tombstone phone");
    sqlx::query("INSERT INTO directory_numbers (did, sip_user) VALUES ($1,$2)")
        .bind("5551234567").bind("jdoe")
        .execute(&site_db).await.expect("did");
    sqlx::query("INSERT INTO trunk_groups (id, data) VALUES ($1,$2)")
        .bind("us-domestic").bind(json!({"id":"us-domestic","strategy":"priority"}))
        .execute(&site_db).await.expect("tg");

    // Central DB + a registered site (the importer registers it too, but
    // pre-register here to isolate the import logic).
    let central = CentralConfigStore::from_pool(make_db(&admin, "cci_central").await).await.expect("central");
    central.register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active").await.expect("register");

    let report = import_site(&site_db, &central, "MUHJ", "importer").await.expect("import");
    assert_eq!(report.phones, 1, "tombstoned phone skipped");
    assert_eq!(report.directory_numbers, 1);
    assert_eq!(report.trunk_groups, 1);

    // The central shard now serves these rows.
    let snap = central.snapshot("MUHJ").await.expect("snapshot");
    let count = |t: ConfigTable| snap.tables.iter().find(|x| x.table == t).map_or(0, |x| x.rows.len());
    assert_eq!(count(ConfigTable::Phones), 1);
    assert_eq!(count(ConfigTable::DirectoryNumbers), 1);
    assert_eq!(count(ConfigTable::TrunkGroups), 1);

    // The DID is claimed fleet-wide.
    let owner: Option<String> = sqlx::query_scalar("SELECT site_code FROM did_registry WHERE did='5551234567'")
        .fetch_optional(central.pool()).await.expect("registry");
    assert_eq!(owner.as_deref(), Some("MUHJ"));

    // Idempotent: a second import re-upserts without error.
    let report2 = import_site(&site_db, &central, "MUHJ", "importer").await.expect("re-import");
    assert_eq!(report2.phones, 1);
    assert_eq!(count(ConfigTable::Phones), 1, "still one phone after re-import");
}
