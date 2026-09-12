-- Enterprise security hardening migration
-- Apply in Supabase SQL editor or migration runner.

create extension if not exists pgcrypto;

alter table if exists public.api_keys
  add column if not exists scopes jsonb not null default '[]'::jsonb,
  add column if not exists rotated_from uuid references public.api_keys(id),
  add column if not exists revoked_at timestamptz,
  add column if not exists last_used_at timestamptz;

alter table if exists public.profiles
  add column if not exists session_revoked_at timestamptz;

alter table if exists public.organization_members
  add column if not exists suspended_at timestamptz,
  add column if not exists removed_at timestamptz;

alter table if exists public.audit_logs
  add column if not exists organization_id uuid,
  add column if not exists event_type text,
  add column if not exists metadata jsonb not null default '{}'::jsonb;

create index if not exists api_keys_org_active_idx on public.api_keys(organization_id, is_active);
create index if not exists audit_logs_org_created_idx on public.audit_logs(organization_id, created_at desc);
create index if not exists members_org_status_idx on public.organization_members(organization_id, status);

-- Resolve organization from the authenticated profile. Service-role backend calls
-- remain supported; browser clients are constrained by these policies.
create or replace function public.current_org_id()
returns uuid language sql stable security definer set search_path = public as $$
  select organization_id from public.profiles where id = auth.uid()
$$;

create or replace function public.is_org_member(target_org uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = target_org
      and m.user_id = auth.uid()
      and m.status = 'active'
  )
$$;

create or replace function public.has_org_role(target_org uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = target_org
      and m.user_id = auth.uid()
      and m.status = 'active'
      and m.role = any(allowed_roles)
  )
$$;

alter table if exists public.organizations enable row level security;
alter table if exists public.organization_members enable row level security;
alter table if exists public.applications enable row level security;
alter table if exists public.security_policies enable row level security;
alter table if exists public.api_keys enable row level security;
alter table if exists public.audit_logs enable row level security;
alter table if exists public.security_events enable row level security;

-- Drop/recreate only named policies so this migration is repeatable.
drop policy if exists organizations_member_select on public.organizations;
create policy organizations_member_select on public.organizations
  for select using (public.is_org_member(id));

drop policy if exists members_same_org_select on public.organization_members;
create policy members_same_org_select on public.organization_members
  for select using (public.is_org_member(organization_id));

drop policy if exists applications_same_org on public.applications;
create policy applications_same_org on public.applications
  for all using (public.is_org_member(organization_id))
  with check (public.is_org_member(organization_id));

drop policy if exists policies_same_org on public.security_policies;
create policy policies_same_org on public.security_policies
  for all using (public.is_org_member(organization_id))
  with check (public.is_org_member(organization_id));

drop policy if exists api_keys_same_org on public.api_keys;
create policy api_keys_same_org on public.api_keys
  for all using (public.is_org_member(organization_id))
  with check (public.is_org_member(organization_id));

drop policy if exists audit_same_org on public.audit_logs;
create policy audit_same_org on public.audit_logs
  for select using (public.is_org_member(organization_id));

drop policy if exists security_events_same_org on public.security_events;
create policy security_events_same_org on public.security_events
  for select using (public.is_org_member(organization_id));

-- Prevent revoked/suspended identities from continuing to use browser sessions.
create or replace function public.revoke_member_sessions()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.status in ('suspended', 'removed') and old.status is distinct from new.status then
    update public.profiles
       set session_revoked_at = now()
     where id = new.user_id;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_revoke_member_sessions on public.organization_members;
create trigger trg_revoke_member_sessions
after update of status on public.organization_members
for each row execute function public.revoke_member_sessions();

-- Audit export consumers must filter by organization_id and enforce role checks
-- in the API. This view intentionally exposes no key material or raw secrets.
create or replace view public.audit_export_safe as
select id, organization_id, user_id, event_type, action, resource_type,
       resource_id, ip_address, user_agent, metadata, created_at
from public.audit_logs;
