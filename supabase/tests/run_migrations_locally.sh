#!/usr/bin/env bash
# Usage: PGHOST=/tmp PGPORT=5544 PGUSER=postgres ./run_migrations_locally.sh  (needs a throwaway Postgres server)
set -euo pipefail
cd "$(dirname "$0")"
db=${DB:-aifw_migration_test}
P="psql -q -v ON_ERROR_STOP=1"
$P -d postgres -c "drop database if exists $db" -c "create database $db"
$P -d "$db" -f live_schema_2026-10-26.sql
for f in ../migrations/20261026_lock_down_client_access.sql ../migrations/20261026_align_schema_with_backend.sql; do
  echo "applying $f"; $P -d "$db" -f "$f" 2>&1 | grep -v NOTICE || true
done
echo "re-applying (idempotency)"
for f in ../migrations/20261026_lock_down_client_access.sql ../migrations/20261026_align_schema_with_backend.sql; do $P -d "$db" -f "$f" 2>&1 | grep -v NOTICE || true; done
echo "done: database $db"
