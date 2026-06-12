-- Central config database: site registry.
-- See docs/CENTRAL-CONFIG-PLAN.md §4.1.
--
-- One row per base. This is the shard list: every partitioned config
-- table has exactly one partition per row here, kept in sync by
-- scripts/gen-site-partitions.sh (never hand-written DDL).
--
-- Site-code canon: uppercase A–Z, digits, hyphen; must start with a
-- letter; 2–16 chars total. Examples: MUHJ, MPLS, OOPL-001. Lowercase
-- forms (DNS names, helm site.name, partition table names) are derived
-- by lowercasing; the registry stores only the canonical uppercase form.

CREATE TABLE IF NOT EXISTS sites (
    site_code     text PRIMARY KEY
                  CHECK (site_code ~ '^[A-Z][A-Z0-9-]{1,15}$'),
    display_name  text NOT NULL,
    fqdn_base     text NOT NULL,             -- mirrors helm site.fqdn_base
    timezone      text NOT NULL DEFAULT 'UTC',
    status        text NOT NULL DEFAULT 'planned'
                  CHECK (status IN ('planned', 'active', 'decommissioned')),
    -- Monotonic shard epoch: bumped (in the same transaction) by every
    -- write to any of this site's config rows. Sync clients compare it
    -- against their applied epoch.
    config_epoch  bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
