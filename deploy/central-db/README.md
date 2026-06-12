# Central config database

Schema and operational scripts for the fleet-wide configuration database
described in [docs/CENTRAL-CONFIG-PLAN.md](../../docs/CENTRAL-CONFIG-PLAN.md).
This database is the source of truth for telephony configuration (phones,
DIDs, trunk groups, dial plans, CUCM routing entities, per-site telephony
settings) across all sites; each site's in-cluster Postgres holds a synced
copy of its own shard.

## Layout

- `migrations/` — ordered SQL applied to the central database.
  `0001_sites.sql` is the site registry (the shard list); `0002` creates
  the LIST-partitioned config tables and the change journal. Phase 1
  wraps these in the `central-config-api` service's embedded migrator;
  until then apply with `psql -f` in filename order.
- `scripts/gen-site-partitions.sh` — creates missing per-site partitions
  for every registered site. Idempotent.

## Onboarding a site

```sh
psql "$CENTRAL_DB_DSN" -c \
  "INSERT INTO sites (site_code, display_name, fqdn_base, timezone, status)
   VALUES ('MUHJ', 'MUHJ', 'muhj.usg.example.com', 'UTC', 'planned')"
CENTRAL_DB_DSN=... ./scripts/gen-site-partitions.sh
```

Site codes are canonical uppercase (`^[A-Z][A-Z0-9-]{1,15}$`); the CHECK
constraint on `sites` rejects anything else. Lowercase derivations (DNS
names, helm `site.name`, partition names) are computed, never stored.
