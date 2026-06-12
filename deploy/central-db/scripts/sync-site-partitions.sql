-- Idempotent partition sync: create the per-site partition of every
-- sharded config table for every non-decommissioned `sites` row that
-- doesn't have one yet. Run via gen-site-partitions.sh after inserting
-- new sites (or any time — existing partitions are skipped).
--
-- Partition naming: <table>_p_<site_code lowercased, '-' → '_'>
-- e.g. phones_p_muhj, dial_plans_p_oopl_001.
--
-- Decommissioned sites keep their partitions (history retention);
-- dropping them is a deliberate manual step, not something this script
-- does implicitly.

DO $$
DECLARE
    sharded_tables constant text[] := ARRAY[
        'phones',
        'directory_numbers',
        'trunk_groups',
        'dial_plans',
        'cucm_partitions',
        'cucm_calling_search_spaces',
        'cucm_route_patterns',
        'cucm_route_lists',
        'site_telephony_config',
        'config_journal'
    ];
    site record;
    tbl text;
    part_name text;
BEGIN
    FOR site IN
        SELECT site_code FROM sites
        WHERE status <> 'decommissioned'
        ORDER BY site_code
    LOOP
        FOREACH tbl IN ARRAY sharded_tables LOOP
            part_name := tbl || '_p_' || replace(lower(site.site_code), '-', '_');
            IF to_regclass(part_name) IS NULL THEN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF %I FOR VALUES IN (%L)',
                    part_name, tbl, site.site_code
                );
                RAISE NOTICE 'created partition %', part_name;
            END IF;
        END LOOP;
    END LOOP;
END
$$;
