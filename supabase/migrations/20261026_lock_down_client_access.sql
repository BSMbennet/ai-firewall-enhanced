-- F-29: stop browser clients (anon / authenticated, i.e. anyone holding the public anon key) from writing to, or
-- reading, tables that only the backend (service_role) should touch.
--
-- Why: the API derives a caller's organisation and role from public.profiles, and authenticated had UPDATE on
-- profiles.role / profiles.organization_id (policy profiles_update_own). api_keys / webhooks / notification_settings
-- had "ALL" policies for the row owner, so a user could insert or edit their own API-key rows directly.
--
-- Safe for the application: the backend uses the service-role key (bypasses these grants); the frontend only does
-- SELECT on profiles and organization_settings (frontend/src/contexts/AuthContext.jsx).
-- Idempotent. Review, test on a branch/staging project, take a backup, then apply (owner action).

begin;

-- 1. Policies that allowed client-side writes.
drop policy if exists api_keys_own on public.api_keys;
drop policy if exists webhooks_own on public.webhooks;
drop policy if exists notification_settings_own on public.notification_settings;
drop policy if exists profiles_update_own on public.profiles;

-- 2. No client may write anywhere in public; anon may do nothing at all.
revoke insert, update, delete, truncate, references, trigger on all tables in schema public from anon, authenticated;
revoke all on all tables in schema public from anon;
revoke all on all sequences in schema public from anon, authenticated;

-- 3. Clients may only read what the UI reads (own profile, own organisation's auth settings).
do $$
declare t text;
begin
  for t in select tablename from pg_tables where schemaname = 'public' and tablename not in ('profiles', 'organization_settings')
  loop
    execute format('revoke select on public.%I from authenticated', t);
  end loop;
end $$;

-- 4. Helper used by RLS policies: not callable by anonymous or public callers.
revoke execute on function public.is_org_member(uuid) from public, anon;
grant execute on function public.is_org_member(uuid) to authenticated, service_role;

-- 5. Future tables must not be exposed to clients by default.
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

-- 6. Defence in depth: even if a grant is re-added later, only the service role may change role / organisation.
create or replace function public.guard_profile_privileged_columns() returns trigger
language plpgsql security invoker set search_path = public, pg_temp as $$
begin
  if coalesce(auth.role(), 'service_role') <> 'service_role'
     and (new.role is distinct from old.role or new.organization_id is distinct from old.organization_id or new.id is distinct from old.id) then
    raise exception 'role and organization_id can only be changed by the backend' using errcode = '42501';
  end if;
  return new;
end $$;
drop trigger if exists guard_profile_privileged_columns on public.profiles;
create trigger guard_profile_privileged_columns before update on public.profiles
  for each row execute function public.guard_profile_privileged_columns();

commit;
