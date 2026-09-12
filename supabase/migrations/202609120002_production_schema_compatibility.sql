begin;

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.organization_members (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  role text not null default 'member' check (role in ('owner','admin','security','developer','member','viewer')),
  status text not null default 'active' check (status in ('active','invited','suspended','removed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, user_id)
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  environment text not null default 'production' check (environment in ('development','staging','production')),
  provider text not null,
  model text not null,
  status text not null default 'active' check (status in ('active','disabled')),
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.security_policies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  pii_protection boolean not null default true,
  prompt_injection_protection boolean not null default true,
  sensitive_content_protection boolean not null default true,
  rate_limit_per_minute integer not null default 60,
  approved_models jsonb not null default '[]'::jsonb,
  allowed_providers jsonb not null default '[]'::jsonb,
  audit_logging boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles add column if not exists organization_id uuid references public.organizations(id);
alter table public.profiles add column if not exists full_name text;
alter table public.api_keys add column if not exists organization_id uuid references public.organizations(id);
alter table public.api_keys add column if not exists application_id uuid references public.applications(id);
alter table public.api_keys add column if not exists employee_id uuid references auth.users(id);
alter table public.api_keys add column if not exists scopes jsonb not null default '["gateway:invoke"]'::jsonb;
alter table public.api_keys add column if not exists rotated_from integer references public.api_keys(id);
alter table public.audit_logs add column if not exists organization_id uuid references public.organizations(id);
alter table public.security_events add column if not exists organization_id uuid references public.organizations(id);

create index if not exists idx_org_members_user on public.organization_members(user_id);
create index if not exists idx_org_members_org on public.organization_members(organization_id);
create index if not exists idx_api_keys_org on public.api_keys(organization_id);
create index if not exists idx_audit_logs_org_timestamp on public.audit_logs(organization_id, timestamp desc);
create index if not exists idx_security_events_org_timestamp on public.security_events(organization_id, timestamp desc);

insert into public.organizations (name, slug)
select coalesce(nullif(trim(p.company), ''), 'Organization ' || left(p.id::text, 8)), 'org-' || replace(left(p.id::text, 18), '-', '')
from public.profiles p
where p.organization_id is null
on conflict (slug) do nothing;

update public.profiles p
set organization_id = o.id
from public.organizations o
where p.organization_id is null
  and o.slug = 'org-' || replace(left(p.id::text, 18), '-', '');

insert into public.organization_members (organization_id, user_id, email, full_name, role, status)
select p.organization_id, p.id, coalesce(p.email, 'user-' || left(p.id::text, 8) || '@local'), p.full_name,
       case when p.role = 'admin' then 'admin' else 'member' end,
       'active'
from public.profiles p
where p.organization_id is not null
on conflict (organization_id, user_id) do nothing;

insert into public.security_policies (organization_id, name)
select o.id, 'Default Enterprise Policy'
from public.organizations o
where not exists (select 1 from public.security_policies sp where sp.organization_id = o.id);

update public.api_keys k set organization_id = p.organization_id
from public.profiles p
where k.organization_id is null and k.user_id = p.id;

update public.audit_logs a set organization_id = p.organization_id
from public.profiles p
where a.organization_id is null and a.user_id = p.id;

update public.security_events s set organization_id = p.organization_id
from public.profiles p
where s.organization_id is null and s.user_id = p.id;

commit;
