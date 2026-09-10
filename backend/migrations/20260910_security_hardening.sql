-- Security hardening for Supabase/Postgres.
-- This migration is intentionally defensive: it discovers function signatures
-- from pg_proc instead of guessing overloaded argument lists.

begin;

-- SECURITY DEFINER functions must not be callable by anonymous clients unless
-- explicitly designed as public APIs. Remove default/public execution grants.
do $$
declare
  fn record;
begin
  for fn in
    select n.nspname as schema_name,
           p.proname as function_name,
           pg_get_function_identity_arguments(p.oid) as identity_args
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.prosecdef = true
       and p.proname in (
         'enforce_decision_policy',
         'process_event_trigger',
         'user_org_id'
       )
  loop
    execute format(
      'revoke execute on function %I.%I(%s) from anon',
      fn.schema_name, fn.function_name, fn.identity_args
    );
  end loop;
end $$;

-- Make security-sensitive functions resolve names only from trusted schemas.
do $$
declare
  fn record;
begin
  for fn in
    select n.nspname as schema_name,
           p.proname as function_name,
           pg_get_function_identity_arguments(p.oid) as identity_args
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.proname in ('ai_firewall_rate_limit_check', 'assert_org_linkage')
  loop
    execute format(
      'alter function %I.%I(%s) set search_path = pg_catalog, public',
      fn.schema_name, fn.function_name, fn.identity_args
    );
  end loop;
end $$;

-- Explicitly prevent anonymous access to organization settings. Existing
-- authenticated/member policies remain responsible for authorized reads.
revoke all on table public.organization_settings from anon;

commit;
