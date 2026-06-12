# Central config database

Schema and operational scripts for the fleet-wide configuration database
described in [docs/CENTRAL-CONFIG-PLAN.md](../../docs/CENTRAL-CONFIG-PLAN.md).
This database is the source of truth for telephony configuration (phones,
DIDs, trunk groups, dial plans, CUCM routing entities, per-site telephony
settings) across all sites; each site's in-cluster Postgres holds a synced
copy of its own shard.

## Layout

- `migrations/` — ordered SQL applied to the central database, and the
  single source of truth for the central schema. `0001_sites.sql` is the
  site registry (the shard list); `0002` creates the LIST-partitioned
  config tables and the change journal. The `central-config-store` crate
  embeds these same files via `sqlx::migrate!` (relative path) and runs
  them on startup, so a fresh central database needs no `psql -f`
  bootstrap — connecting a store migrates it. Apply manually with
  `psql -f` in filename order only for out-of-band inspection.
- `scripts/gen-site-partitions.sh` — creates missing per-site partitions
  from the `sites` table for the shell/ops path. Idempotent. The same
  per-site partition creation also happens in code via
  `CentralConfigStore::register_site`, so onboarding through the central
  API needs no separate script run.

## Onboarding a site

```sh
psql "$CENTRAL_DB_DSN" -c \
  "INSERT INTO sites (site_code, display_name, fqdn_base, timezone, status)
   VALUES ('MUHJ', 'MUHJ', 'muhj.usg.example.com', 'UTC', 'planned')"
CENTRAL_DB_DSN=... ./scripts/gen-site-partitions.sh
```

Site codes are canonical uppercase (`^[A-Z][A-Z0-9-]{0,14}[A-Z0-9]$` —
must end with a letter or digit so lowercased DNS derivations stay valid);
the CHECK constraint on `sites` rejects anything else. Lowercase
derivations (DNS names, helm `site.name`, partition names) are computed,
never stored.
