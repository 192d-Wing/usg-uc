-- Central config database: sharded config tables + change journal.
-- See docs/CENTRAL-CONFIG-PLAN.md §4.2–4.3.
--
-- Every table is LIST-partitioned by site_code; partitions are created
-- per `sites` row by scripts/gen-site-partitions.sh. Payload columns
-- stay JSONB so the existing `sbc-config` / `uc-phone-mgmt` Rust structs
-- read them unchanged after sync to a site's local Postgres.
--
-- Envelope columns (every config table):
--   revision   — sites.config_epoch at which the row last changed
--   deleted    — tombstone; deletions are upserts so delta sync never
--                diffs row sets
--   updated_by — OIDC subject of the writing operator

-- ---------------------------------------------------------------- phones
CREATE TABLE IF NOT EXISTS phones (
    site_code      text NOT NULL REFERENCES sites(site_code),
    id             text NOT NULL,
    mac_normalized text NOT NULL,
    data           jsonb NOT NULL,
    revision       bigint NOT NULL,
    deleted        boolean NOT NULL DEFAULT false,
    updated_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id),
    -- MAC must be unique within a site (provisioning lookup); the same
    -- MAC may not legitimately appear at two sites either, but partition
    -- constraints can only cover the partition key — fleet-wide MAC
    -- uniqueness is enforced by the central API at write time.
    UNIQUE (site_code, mac_normalized)
) PARTITION BY LIST (site_code);

-- ----------------------------------------------------- directory_numbers
-- Fleet-wide DID uniqueness cannot be a unique index here (a unique
-- constraint on a partitioned table must include the partition key);
-- the central API enforces it at write time via did_registry below.
CREATE TABLE IF NOT EXISTS directory_numbers (
    site_code   text NOT NULL REFERENCES sites(site_code),
    did         text NOT NULL,
    sip_user    text,
    partition   text,
    description text,
    extra       jsonb NOT NULL DEFAULT '{}'::jsonb,
    revision    bigint NOT NULL,
    deleted     boolean NOT NULL DEFAULT false,
    updated_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, did)
) PARTITION BY LIST (site_code);

-- Global DID ownership: one row per live (non-tombstoned) DID across the
-- fleet. Maintained by the central API in the same transaction as the
-- directory_numbers write; the PRIMARY KEY is what makes a DID collision
-- between two sites a hard error.
CREATE TABLE IF NOT EXISTS did_registry (
    did        text PRIMARY KEY,
    site_code  text NOT NULL REFERENCES sites(site_code),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------- JSONB pass-through tables
-- trunk_groups, dial_plans, and the four CUCM routing entities share the
-- same envelope + JSONB body shape as their site-local counterparts.
CREATE TABLE IF NOT EXISTS trunk_groups (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

CREATE TABLE IF NOT EXISTS dial_plans (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

CREATE TABLE IF NOT EXISTS cucm_partitions (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

CREATE TABLE IF NOT EXISTS cucm_calling_search_spaces (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

CREATE TABLE IF NOT EXISTS cucm_route_patterns (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

CREATE TABLE IF NOT EXISTS cucm_route_lists (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL,
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

-- ------------------------------------------------- site telephony config
-- Per-site scalar settings that today live in helm values / config.toml
-- (max_calls, default trunk group, voicemail URI, …). One logical row
-- per site; `id` exists for envelope symmetry and is always 'default'
-- until a second document type needs the table.
CREATE TABLE IF NOT EXISTS site_telephony_config (
    site_code  text NOT NULL REFERENCES sites(site_code),
    id         text NOT NULL DEFAULT 'default',
    data       jsonb NOT NULL,
    revision   bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, id)
) PARTITION BY LIST (site_code);

-- ---------------------------------------------------------- config_journal
-- Append-only change log, one entry per row mutation, written in the
-- same transaction as the mutation and the sites.config_epoch bump.
-- Drives GET /sync/{site}/delta and doubles as the audit log.
CREATE TABLE IF NOT EXISTS config_journal (
    site_code  text NOT NULL REFERENCES sites(site_code),
    epoch      bigint NOT NULL,
    table_name text NOT NULL,
    row_id     text NOT NULL,
    op         text NOT NULL CHECK (op IN ('upsert', 'delete')),
    payload    jsonb,                        -- full row at this epoch (upsert)
    actor      text NOT NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_code, epoch)
) PARTITION BY LIST (site_code);
