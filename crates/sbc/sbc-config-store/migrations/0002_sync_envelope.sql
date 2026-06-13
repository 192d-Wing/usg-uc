-- Sync envelope (docs/CENTRAL-CONFIG-PLAN.md, Phase 0).
--
-- Columns the central-config sync protocol needs on every config table:
--   revision   — shard epoch at which this row last changed; stamped by
--                the sync agent when applying central deltas. 0 = row
--                predates central sync (local-origin).
--   deleted    — tombstone. Central deletions arrive as upserts with
--                deleted = TRUE so delta sync never has to diff row
--                sets; readers filter them out.
--   updated_by — OIDC subject of the operator who made the change
--                centrally; 'local' for rows written by this site's own
--                API (pre-cutover or break-glass).
--   site_code  — which shard this row belongs to. NULL until the site
--                is onboarded to central sync; the sync agent fills it.
--
-- Defaults keep current single-site stacks working unchanged.

ALTER TABLE directory_numbers
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE phones
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE trunk_groups
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE dial_plans
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE sbc_partitions
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE sbc_calling_search_spaces
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE sbc_route_patterns
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

ALTER TABLE sbc_route_lists
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS site_code TEXT;

-- With deletes becoming tombstones, a full unique index would let a
-- tombstoned phone hold its MAC hostage forever (the row is invisible
-- to reads but still occupies the index, and upsert's ON CONFLICT (id)
-- doesn't cover it). Scope uniqueness to live rows so a replacement
-- phone can reuse the MAC of a tombstoned record.
DROP INDEX IF EXISTS idx_phones_mac_normalized;
CREATE UNIQUE INDEX IF NOT EXISTS idx_phones_mac_normalized_live
    ON phones (mac_normalized) WHERE NOT deleted;

-- Tracks the last centrally-applied epoch per shard. One row per site
-- code (in practice one row total — a site DB replicates one shard).
-- Written only by sbc-config-sync; absence of a row means "never
-- synced", which triggers a full snapshot fetch.
CREATE TABLE IF NOT EXISTS sync_state (
    site_code TEXT PRIMARY KEY,
    applied_epoch BIGINT NOT NULL DEFAULT 0,
    last_success_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
