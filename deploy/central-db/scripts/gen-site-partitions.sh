#!/usr/bin/env bash
# Create missing per-site partitions on the central config database.
#
# Usage:
#   CENTRAL_DB_DSN='postgres://user:pass@host:5432/usg_config' \
#       ./gen-site-partitions.sh
#
# Idempotent: sites that already have all their partitions are skipped.
# Run after inserting rows into `sites` (onboarding a base) — adding
# base #185 is `INSERT INTO sites ...` followed by this script.
set -euo pipefail

: "${CENTRAL_DB_DSN:?set CENTRAL_DB_DSN to the central config database DSN}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

psql "$CENTRAL_DB_DSN" \
    --set ON_ERROR_STOP=1 \
    --file "$script_dir/sync-site-partitions.sql"
