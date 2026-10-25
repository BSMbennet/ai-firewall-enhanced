# Database access tests (local throwaway Postgres)

`replica_of_live_2026-10-26.sql` is a *reconstruction* of the parts of the live Supabase schema relevant to client
access (tables, RLS policies, grants as read from the catalog on 2026-10-26), with stub `auth` functions.
`client_access_attack.sql` plays a malicious signed-in user and an anonymous user.

    createdb t1 && psql -d t1 -f replica_of_live_2026-10-26.sql
    psql -d t1 -f client_access_attack.sql      # BEFORE the migration: attacker becomes owner of another org
    psql -d t1 -f ../migrations/20261026_lock_down_client_access.sql
    psql -d t1 -f client_access_attack.sql      # AFTER: every attack is denied, frontend reads still work

This is not a test of the real project; re-run the same attack against a staging project before the pilot.
