//! Integration tests for the embedded sqlx migrator against a real
//! Postgres. Skipped (pass trivially) unless `SBC_CONFIG_STORE_TEST_DSN`
//! is set to a DSN with CREATE DATABASE rights; the tests create and
//! drop their own scratch databases so any throwaway server works:
//!
//! ```sh
//! SBC_CONFIG_STORE_TEST_DSN=postgres://postgres@127.0.0.1:5432/postgres \
//!     cargo test -p sbc-config-store --test schema_pg
//! ```

#![allow(clippy::expect_used, clippy::panic)] // test harness: fail loudly with context

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use sbc_config_store::{PostgresPhoneStore, ensure_schema};
use uc_phone_mgmt::model::{Phone, PhoneModel};

fn admin_dsn() -> Option<String> {
    std::env::var("SBC_CONFIG_STORE_TEST_DSN").ok()
}

/// Drop-if-exists + create a scratch database, returning a pool on it.
/// Uses `PgConnectOptions::database()` to swap the database name so DSN
/// query parameters (`?sslmode=require`, etc.) survive.
async fn scratch_db(admin: &str, name: &str) -> PgPool {
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
    PgPoolOptions::new()
        .max_connections(5)
        .connect_with(admin_opts.database(name))
        .await
        .expect("connect scratch db")
}

async fn columns(pool: &PgPool, table: &str) -> BTreeMap<String, String> {
    sqlx::query(
        "SELECT column_name, data_type FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("columns query")
    .iter()
    .map(|r| {
        (
            r.try_get::<String, _>("column_name").expect("name"),
            r.try_get::<String, _>("data_type").expect("type"),
        )
    })
    .collect()
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

    // delete() writes a tombstone: invisible to reads, but the physical
    // row (and the fact a deletion happened) survives.
    store.delete("legacy-1").await.expect("tombstone delete");
    assert!(store.get_by_mac("aabbccddeeff").await.is_err(), "tombstone visible");
    assert!(store.list().await.expect("list").is_empty(), "tombstone listed");
    assert!(
        store.delete("legacy-1").await.is_err(),
        "double delete must be NotFound"
    );
    let row = sqlx::query("SELECT deleted, updated_by FROM phones WHERE id = 'legacy-1'")
        .fetch_one(&pool)
        .await
        .expect("tombstone row gone from table");
    assert!(row.try_get::<bool, _>("deleted").expect("deleted"));
    assert_eq!(row.try_get::<String, _>("updated_by").expect("updated_by"), "local");

    // The legacy-JSON import guard must NOT see an all-tombstoned table
    // as empty — that would re-import a stale file and resurrect rows.
    assert!(!store.is_empty().await.expect("is_empty"), "tombstones must count");

    // A tombstoned phone must not hold its MAC hostage: a replacement
    // phone with a new id and the same MAC is provisionable (partial
    // unique index over live rows only).
    let mut replacement = Phone::new("AA:BB:CC:DD:EE:FF", PhoneModel::PolycomVVX150, "repl");
    replacement.id = "replacement-2".to_string();
    store.upsert(&replacement).await.expect("MAC reuse after tombstone");
    assert_eq!(
        store.get_by_mac("aabbccddeeff").await.expect("live row").id,
        "replacement-2"
    );

    // Re-upserting the tombstoned id revives it with local provenance —
    // but first move its MAC aside so the live-MAC uniqueness holds.
    let mut revived = phone.clone();
    revived.mac_address = "AA:BB:CC:DD:EE:00".to_string();
    store.upsert(&revived).await.expect("revive upsert");
    let row = sqlx::query("SELECT deleted, revision, updated_by FROM phones WHERE id = 'legacy-1'")
        .fetch_one(&pool)
        .await
        .expect("revived row");
    assert!(!row.try_get::<bool, _>("deleted").expect("deleted"));
    assert_eq!(row.try_get::<i64, _>("revision").expect("revision"), 0);
    assert_eq!(row.try_get::<String, _>("updated_by").expect("updated_by"), "local");
}

/// The central database (deploy/central-db, raw SQL applied via psql)
/// and the site-local embedded migrations define the same eight logical
/// config tables. Nothing else mechanically ties them together, so this
/// test applies both schemas to scratch databases and diffs the column
/// name→type maps; the first envelope/payload column added to one side
/// only fails here instead of at a site when the sync agent ships rows.
/// (Nullability and defaults intentionally differ — central is stricter
/// — so only names and types are compared.)
#[tokio::test]
async fn central_and_local_schemas_agree() {
    let Some(admin) = admin_dsn() else { return };

    let local = scratch_db(&admin, "csmt_drift_local").await;
    ensure_schema(&local).await.expect("local migrate");

    let central = scratch_db(&admin, "csmt_drift_central").await;
    let central_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../deploy/central-db/migrations");
    for file in ["0001_sites.sql", "0002_config_tables.sql"] {
        let sql = std::fs::read_to_string(central_dir.join(file))
            .unwrap_or_else(|e| panic!("read central migration {file}: {e}"));
        sqlx::raw_sql(&sql)
            .execute(&central)
            .await
            .unwrap_or_else(|e| panic!("apply central migration {file}: {e}"));
    }

    for table in [
        "phones",
        "directory_numbers",
        "trunk_groups",
        "dial_plans",
        "cucm_partitions",
        "cucm_calling_search_spaces",
        "cucm_route_patterns",
        "cucm_route_lists",
    ] {
        let local_cols = columns(&local, table).await;
        let central_cols = columns(&central, table).await;
        assert!(!local_cols.is_empty(), "{table} missing locally");
        assert_eq!(
            local_cols, central_cols,
            "schema drift between site-local and central definitions of {table}"
        );
    }
}
