-- Site-local mirror of the central `site_telephony_config` table.
--
-- This per-site settings document (max_calls, default trunk group,
-- voicemail URI, …) lives centrally and syncs down like the other config
-- tables, so the site-local schema needs a matching table for the
-- sbc-config-sync apply engine to write into. Same JSONB-pass-through +
-- sync-envelope shape as the other config tables after 0002.
--
-- The central definition (deploy/central-db/migrations/0002_config_tables
-- .sql) is the partitioned parent; this is the single-shard local copy.
-- Columns (names + types) are kept in lockstep — see the
-- central_and_local_schemas_agree test.

CREATE TABLE IF NOT EXISTS site_telephony_config (
    id          TEXT PRIMARY KEY DEFAULT 'default',
    data        JSONB NOT NULL,
    revision    BIGINT NOT NULL DEFAULT 0,
    deleted     BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by  TEXT NOT NULL DEFAULT 'local',
    site_code   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
