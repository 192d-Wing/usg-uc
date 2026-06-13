-- Global config templates + per-site assignment (docs/CENTRAL-CONFIG-PLAN
-- .sql §5.4, §8). Trunk groups and dial plans are mostly fleet policy with
-- small per-site deviation: a template is authored once, assigned to many
-- sites (with a rollout ring), and *materialized* into each assigned
-- site's shard — where it becomes an ordinary synced row. A site that has
-- written its own row for the same id (a local override) is skipped by
-- materialization, so overrides win.

-- The fleet-baseline documents. Not sharded; one row per (kind, id).
CREATE TABLE IF NOT EXISTS config_templates (
    kind        text NOT NULL CHECK (kind IN ('trunk_group', 'dial_plan')),
    id          text NOT NULL,
    data        jsonb NOT NULL,
    updated_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, id)
);

-- Which template applies to which site, and in which rollout ring. Ring 0
-- is the canary; materialization is requested "up to ring N", so a change
-- can be proven on ring 0 before promoting to the rest.
CREATE TABLE IF NOT EXISTS template_assignments (
    kind         text NOT NULL,
    template_id  text NOT NULL,
    site_code    text NOT NULL REFERENCES sites(site_code),
    ring         int NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, template_id, site_code),
    FOREIGN KEY (kind, template_id) REFERENCES config_templates (kind, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_template_assignments_site
    ON template_assignments (site_code);
