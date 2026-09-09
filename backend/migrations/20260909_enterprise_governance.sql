-- Enterprise governance/compliance foundation.
-- This migration is additive and safe to re-run.

create table if not exists public.policy_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  policy_id uuid references public.security_policies(id) on delete cascade,
  version integer not null,
  status text not null default 'draft' check (status in ('draft','published','archived')),
  config jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id),
  published_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  published_at timestamptz,
  unique(policy_id, version)
);

create table if not exists public.compliance_controls (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  framework text not null check (framework in ('soc2','iso27001','nist','custom')),
  control_id text not null,
  title text not null,
  status text not null default 'not_started' check (status in ('not_started','in_progress','implemented','accepted','not_applicable')),
  owner_user_id uuid references auth.users(id),
  evidence jsonb not null default '[]'::jsonb,
  notes text,
  updated_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(organization_id, framework, control_id)
);

create table if not exists public.access_reviews (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  reviewer_user_id uuid not null references auth.users(id),
  period_start timestamptz not null,
  period_end timestamptz not null,
  status text not null default 'open' check (status in ('open','completed','cancelled')),
  decisions jsonb not null default '[]'::jsonb,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.organization_settings (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  retention_days integer not null default 365 check (retention_days between 7 and 3650),
  require_sso boolean not null default false,
  require_mfa boolean not null default false,
  enforce_verified_domains boolean not null default false,
  audit_prompt_content boolean not null default false,
  alert_email_enabled boolean not null default true,
  alert_email_recipients jsonb not null default '[]'::jsonb,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);

create index if not exists policy_versions_org_policy_idx on public.policy_versions(organization_id, policy_id, version desc);
create index if not exists compliance_controls_org_framework_idx on public.compliance_controls(organization_id, framework, status);
create index if not exists access_reviews_org_status_idx on public.access_reviews(organization_id, status, created_at desc);

-- Server-side service role performs writes. Browser access remains disabled unless an
-- explicit least-privilege policy is introduced later.
alter table public.policy_versions enable row level security;
alter table public.compliance_controls enable row level security;
alter table public.access_reviews enable row level security;
alter table public.organization_settings enable row level security;

-- Only allow authenticated users to read settings/control records belonging to their
-- own organization through their profile. Mutations remain backend-only.
drop policy if exists "Users can read own org governance" on public.policy_versions;
create policy "Users can read own org governance" on public.policy_versions
  for select to authenticated
  using (organization_id = (select organization_id from public.profiles where id = (select auth.uid())));

drop policy if exists "Users can read own org compliance" on public.compliance_controls;
create policy "Users can read own org compliance" on public.compliance_controls
  for select to authenticated
  using (organization_id = (select organization_id from public.profiles where id = (select auth.uid())));

drop policy if exists "Users can read own org reviews" on public.access_reviews;
create policy "Users can read own org reviews" on public.access_reviews
  for select to authenticated
  using (organization_id = (select organization_id from public.profiles where id = (select auth.uid())));

drop policy if exists "Users can read own org settings" on public.organization_settings;
create policy "Users can read own org settings" on public.organization_settings
  for select to authenticated
  using (organization_id = (select organization_id from public.profiles where id = (select auth.uid())));
