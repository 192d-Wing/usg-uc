//! Integration tests for the embedded sqlx migrator against a real
//! Postgres. Skipped (pass trivially) unless `SBC_CONFIG_STORE_TEST_DSN`
//! is set to a DSN with CREATE DATABASE rights; the test creates and
//! drops its own scratch databases so any throwaway server works:
//!
//! ```sh
//! SBC_CONFIG_STORE_TEST_DSN=postgres://postgres@127.0.0.1:5432/postgres \
//!     cargo test -p sbc-config-store --test schema_pg
//! ```

#![allow(clippy::expect_used)] // test harness: fail loudly with context

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use sbc_config_store::{PostgresPhoneStore, ensure_schema};
use uc_phone_mgmt::model::{Phone, PhoneModel};

fn admin_dsn() -> Option<String> {
    std::env::var("SBC_CONFIG_STORE_TEST_DSN").ok()
}

/// Drop-if-exists + create a scratch database, returning a pool on it.
async fn scratch_db(admin: &str, name: &str) -> PgPool {
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin)
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
    let scratch = replace_dbname(admin, name);
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&scratch)
        .await
        .expect("connect scratch db")
}

/// Swap the database name (path segment) in a postgres:// DSN.
fn replace_dbname(dsn: &str, name: &str) -> String {
    let (base, _) = dsn.rsplit_once('/').expect("DSN has a path");
    format!("{base}/{name}")
}

async fn column_exists(pool: &PgPool, table: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT 1 FROM information_schema.columns
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .expect("information_schema query")
    .is_some()
}

#[tokio::test]
async fn migrates_fresh_database() {
    let Some(admin) = admin_dsn() else { return };
    let pool = scratch_db(&admin, "csmt_fresh").await;

    ensure_schema(&pool).await.expect("fresh migrate");
    // Idempotent: a second run (another store sharing the pool) is a no-op.
    ensure_schema(&pool).await.expect("re-run migrate");

    for table in [
        "directory_numbers",
        "phones",
        "trunk_groups",
        "dial_plans",
        "cucm_partitions",
        "cucm_calling_search_spaces",
        "cucm_route_patterns",
        "cucm_route_lists",
        "sync_state",
    ] {
        assert!(
            column_exists(&pool, table, "updated_at").await,
            "table {table} missing after migration"
        );
    }
    for column in ["revision", "deleted", "updated_by", "site_code"] {
        assert!(
            column_exists(&pool, "phones", column).await,
            "envelope column {column} missing"
        );
    }

    let applied: i64 = sqlx::query("SELECT COUNT(*) AS count FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("migration history")
        .try_get("count")
        .expect("count column");
    assert!(applied >= 2, "expected ≥2 recorded migrations, got {applied}");
}

#[tokio::test]
async fn adopts_legacy_database_and_preserves_rows() {
    let Some(admin) = admin_dsn() else { return };
    let pool = scratch_db(&admin, "csmt_legacy").await;

    // Recreate what the old inline create_tables() bootstrap built, plus
    // a pre-existing row — the state every deployed site DB is in today.
    sqlx::query(
        "CREATE TABLE phones (
            id TEXT PRIMARY KEY,
            mac_normalized TEXT NOT NULL,
            data JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&pool)
    .await
    .expect("legacy phones table");
    sqlx::query(
        "CREATE UNIQUE INDEX idx_phones_mac_normalized ON phones (mac_normalized)",
    )
    .execute(&pool)
    .await
    .expect("legacy mac index");
    let mut seeded = Phone::new("AA:BB:CC:DD:EE:FF", PhoneModel::PolycomVVX150, "legacy");
    seeded.id = "legacy-1".to_string();
    let legacy_phone = serde_json::to_value(&seeded).expect("encode legacy phone");
    sqlx::query("INSERT INTO phones (id, mac_normalized, data) VALUES ($1, $2, $3)")
        .bind("legacy-1")
        .bind("aabbccddeeff")
        .bind(&legacy_phone)
        .execute(&pool)
        .await
        .expect("seed legacy row");

    // Store construction runs the migrator; it must adopt the existing
    // table (baseline is IF NOT EXISTS) and bolt on the envelope.
    let store = PostgresPhoneStore::from_pool(pool.clone())
        .await
        .expect("migrate legacy db");

    let phone = store.get_by_mac("aa-bb-cc-dd-ee-ff").await.expect("legacy row readable");
    assert_eq!(phone.id, "legacy-1");

    // Envelope defaults landed on the pre-existing row.
    let row = sqlx::query("SELECT revision, deleted, updated_by FROM phones WHERE id = 'legacy-1'")
        .fetch_one(&pool)
        .await
        .expect("envelope read");
    assert_eq!(row.try_get::<i64, _>("revision").expect("revision"), 0);
    assert!(!row.try_get::<bool, _>("deleted").expect("deleted"));
    assert_eq!(row.try_get::<String, _>("updated_by").expect("updated_by"), "local");

    // Tombstoned rows disappear from reads; a re-upsert revives them.
    sqlx::query("UPDATE phones SET deleted = TRUE WHERE id = 'legacy-1'")
        .execute(&pool)
        .await
        .expect("tombstone");
    assert!(store.get_by_mac("aabbccddeeff").await.is_err(), "tombstone visible");
    assert!(store.list().await.expect("list").is_empty(), "tombstone listed");
    store.upsert(&phone).await.expect("revive upsert");
    assert_eq!(
        store.get("legacy-1").await.expect("revived row").id,
        "legacy-1"
    );
}
