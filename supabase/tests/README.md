# Database access tests (local throwaway Postgres)

`replica_of_live_2026-10-26.sql` is a *reconstruction* of the parts of the live Supabase schema relevant to client
access (tables, RLS policies, grants as read from the catalog on 2026-10-26), with stub `auth` functions.
`client_access_attack.sql` plays a malicious signed-in user and an anonymous user.

    createdb t1 && psql -d t1 -f replica_of_live_2026-10-26.sql
    psql -d t1 -f client_access_attack.sql      # BEFORE the migration: attacker becomes owner of another org
    psql -d t1 -f ../migrations/20261026_lock_down_client_access.sql
    psql -d t1 -f client_access_attack.sql      # AFTER: every attack is denied, frontend reads still work

This is not a test of the real project; re-run the same attack against a staging project before the pilot.

## Baseline migration (F-30)
`live_schema_2026-10-26.sql` is the pre-migration live schema. Run in order, then the checks:

    createdb t2
    psql -d t2 -f live_schema_2026-10-26.sql
    psql -d t2 -f ../migrations/20261026_lock_down_client_access.sql
    psql -d t2 -f ../migrations/20261027_backend_schema_baseline.sql      # run twice: idempotent
    psql -d t2 -f baseline_smoke.sql                                      # mirrors backend writes, RPCs, grants, append-only audit
    python check_code_columns.py -d t2                                    # every table/column the code names exists (30 findings before, 0 after)
