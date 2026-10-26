-- F-30: bring the live database in line with what the backend actually reads and writes.
-- Derived from: (a) a catalog dump of the live project on 2026-10-26, (b) every table/column the code touches during
-- the test suite (backend/scripts/check_schema.py), (c) the repo's earlier enterprise migrations (which were never
-- applied to this project). Idempotent. Run AFTER 20261026_lock_down_client_access.sql.
--
-- Security model for everything created here: RLS enabled, no policies, no grants to anon/authenticated.
-- Only the backend (service_role) touches these tables; browsers never do.
-- Apply on staging/branch first, take a backup, then production (owner action).

-- ---------------------------------------------------------------------------------------------------------------
-- A. Existing tables: columns the code writes but the live schema lacks
-- ---------------------------------------------------------------------------------------------------------------
-- The legacy `key` column is NOT NULL UNIQUE but the backend stores only a hash (key_hash) and a display prefix.
alter table public.api_keys alter column key drop not null;
alter table public.api_keys
  add column if not exists key_prefix text,
  add column if not exists rotated_at timestamptz,
  add column if not exists rotation_grace_until timestamptz;
alter table public.api_keys alter column scopes set default '["chat"]'::jsonb;
create unique index if not exists api_keys_key_hash_uidx on public.api_keys (key_hash) where key_hash is not null;
create index if not exists api_keys_org_idx on public.api_keys (organization_id);

alter table public.audit_logs
  add column if not exists application_id uuid references public.applications(id) on delete set null,
  add column if not exists employee_id uuid references public.organization_members(id) on delete set null;
create index if not exists audit_logs_org_ts_idx on public.audit_logs (organization_id, "timestamp" desc);
create index if not exists audit_logs_org_employee_ts_idx on public.audit_logs (organization_id, employee_id, "timestamp" desc);
create index if not exists audit_logs_org_application_ts_idx on public.audit_logs (organization_id, application_id, "timestamp" desc);

alter table public.security_events
  add column if not exists application_id uuid references public.applications(id) on delete set null,
  add column if not exists employee_id uuid references public.organization_members(id) on delete set null;
create index if not exists security_events_org_ts_idx on public.security_events (organization_id, "timestamp" desc);

alter table public.organization_settings
  add column if not exists audit_retention_days integer not null default 365 check (audit_retention_days between 7 and 3650),
  add column if not exists alert_email_enabled boolean not null default true,
  add column if not exists alert_email_recipients jsonb not null default '[]'::jsonb,
  add column if not exists enforce_verified_domains boolean not null default false,
  add column if not exists audit_prompt_content boolean not null default false,
  add column if not exists updated_by uuid references auth.users(id);

-- The live `webhooks` / `webhook_deliveries` are an older, per-user design (integer ids, Pascal-case columns, no
-- organisation). Keep them (0 rows at inspection) under legacy_ names so the backend's per-organisation tables can
-- take the names it expects.
do $$
begin
  if exists (select 1 from information_schema.columns where table_schema='public' and table_name='webhook_deliveries' and column_name='Webhook_id') then
    alter table public.webhook_deliveries rename to legacy_webhook_deliveries;
    alter index if exists public.webhook_deliveries_pkey rename to legacy_webhook_deliveries_pkey;
  end if;
  if exists (select 1 from information_schema.columns where table_schema='public' and table_name='webhooks' and column_name='user_id') then
    alter table public.webhooks rename to legacy_webhooks;
    alter index if exists public.webhooks_pkey rename to legacy_webhooks_pkey;
  end if;
end $$;

-- ---------------------------------------------------------------------------------------------------------------
-- B. New tables
-- ---------------------------------------------------------------------------------------------------------------
create table if not exists public.usage_counters (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  period_start date not null,
  request_count bigint not null default 0,
  blocked_count bigint not null default 0,
  tokens_used bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, period_start)
);

-- Administrative audit trail. No foreign key on organization_id so evidence outlives an organisation, and
-- UPDATE/DELETE are rejected by trigger (append-only at the database level, F-20).
create table if not exists public.audit_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid,
  actor_user_id uuid,
  action text not null,
  resource_type text not null,
  resource_id text,
  outcome text not null default 'success',
  request_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists audit_events_org_created_idx on public.audit_events (organization_id, created_at);
create or replace function public.audit_events_append_only() returns trigger
language plpgsql set search_path = public, pg_temp as $$
begin
  raise exception 'audit_events is append-only' using errcode = '42501';
end $$;
drop trigger if exists audit_events_no_update_delete on public.audit_events;
create trigger audit_events_no_update_delete before update or delete on public.audit_events
  for each row execute function public.audit_events_append_only();

create table if not exists public.alert_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  event_type text not null,
  threshold integer not null default 1 check (threshold between 1 and 100000),
  window_minutes integer not null default 15 check (window_minutes between 1 and 1440),
  severity text not null default 'high',
  email_enabled boolean not null default true,
  in_app_enabled boolean not null default true,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists alert_rules_org_event_idx on public.alert_rules (organization_id, event_type) where is_active;

create table if not exists public.security_alerts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  rule_id uuid references public.alert_rules(id) on delete set null,
  event_type text not null,
  severity text not null default 'high',
  title text not null,
  message text,
  metadata jsonb not null default '{}'::jsonb,
  status text not null default 'open' check (status in ('open','acknowledged','resolved')),
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists security_alerts_org_created_idx on public.security_alerts (organization_id, created_at desc);

create table if not exists public.webhook_integrations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  url text not null,
  events text[] not null default '{}',
  secret_encrypted text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists webhook_integrations_org_idx on public.webhook_integrations (organization_id, created_at desc);

create table if not exists public.webhook_deliveries (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  webhook_id uuid not null references public.webhook_integrations(id) on delete cascade,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending',
  attempts integer not null default 0,
  response_code integer,
  last_error text,
  delivered_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists webhook_deliveries_webhook_idx on public.webhook_deliveries (webhook_id, created_at desc);

create table if not exists public.billing_customers (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  stripe_customer_id text not null unique,
  created_at timestamptz not null default now()
);
create table if not exists public.billing_subscriptions (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  stripe_subscription_id text unique,
  stripe_customer_id text,
  plan_key text not null default 'starter',
  status text not null default 'active',
  seat_quantity integer not null default 1,
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists billing_subscriptions_customer_idx on public.billing_subscriptions (stripe_customer_id);
create table if not exists public.billing_events (
  id uuid primary key default gen_random_uuid(),
  stripe_event_id text unique,
  event_type text,
  organization_id uuid references public.organizations(id) on delete set null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.onboarding_progress (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  completed_steps jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

-- From backend/migrations/20260908_enterprise_identity_domains.sql and 20260909_enterprise_governance.sql
create table if not exists public.identity_connections (
  id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null check (provider in ('google','azure','saml','oidc')), name text not null, domain text, client_id text,
  client_secret_hash text, issuer_url text, metadata jsonb not null default '{}'::jsonb, is_active boolean not null default true,
  created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists idx_identity_connections_org_domain_active on public.identity_connections (organization_id, domain, is_active);
create table if not exists public.scim_tokens (
  id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null default 'SCIM token', token_hash text not null unique, last_used_at timestamptz, expires_at timestamptz,
  revoked_at timestamptz, created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.custom_domains (
  id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
  domain text not null unique, status text not null default 'pending' check (status in ('pending','verified','active','failed')),
  verification_type text not null default 'cname', verification_target text, verified_at timestamptz,
  created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.policy_versions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  policy_id uuid references public.security_policies(id) on delete cascade,
  version integer not null,
  status text not null default 'draft' check (status in ('draft','published','archived')),
  config jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id), published_by uuid references auth.users(id),
  created_at timestamptz not null default now(), published_at timestamptz,
  unique (policy_id, version)
);
create table if not exists public.compliance_controls (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  framework text not null check (framework in ('soc2','iso27001','nist','custom')),
  control_id text not null, title text not null,
  status text not null default 'not_started' check (status in ('not_started','in_progress','implemented','accepted','not_applicable')),
  owner_user_id uuid references auth.users(id), evidence jsonb not null default '[]'::jsonb, notes text,
  updated_by uuid references auth.users(id),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (organization_id, framework, control_id)
);
create table if not exists public.access_reviews (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  reviewer_user_id uuid not null references auth.users(id),
  period_start timestamptz not null, period_end timestamptz not null,
  status text not null default 'open' check (status in ('open','completed','cancelled')),
  decisions jsonb not null default '[]'::jsonb, completed_at timestamptz,
  created_at timestamptz not null default now()
);

-- Backend-only access for everything created above.
do $$
declare t text;
begin
  foreach t in array array['usage_counters','audit_events','alert_rules','security_alerts','webhook_integrations','webhook_deliveries',
    'billing_customers','billing_subscriptions','billing_events','onboarding_progress','identity_connections','scim_tokens',
    'custom_domains','policy_versions','compliance_controls','access_reviews']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant all on public.%I to service_role', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------------------------------------------
-- C. Functions the backend calls via RPC (service_role only)
-- ---------------------------------------------------------------------------------------------------------------
create or replace function public.consume_gateway_usage(p_organization_id uuid, p_period_start date, p_limit bigint default null)
returns table(allowed boolean, request_count bigint)
language plpgsql security definer set search_path = public, pg_temp as $$
#variable_conflict use_column
declare current_count bigint;
begin
  insert into public.usage_counters (organization_id, period_start) values (p_organization_id, p_period_start)
  on conflict (organization_id, period_start) do nothing;
  select u.request_count into current_count from public.usage_counters u
   where u.organization_id = p_organization_id and u.period_start = p_period_start for update;
  if p_limit is not null and current_count >= p_limit then
    return query select false, current_count;
    return;
  end if;
  update public.usage_counters u set request_count = u.request_count + 1, updated_at = now()
   where u.organization_id = p_organization_id and u.period_start = p_period_start
  returning u.request_count into current_count;
  return query select true, current_count;
end $$;

create or replace function public.record_gateway_outcome(p_organization_id uuid, p_period_start date, p_blocked boolean default false, p_tokens bigint default 0)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  insert into public.usage_counters (organization_id, period_start, blocked_count, tokens_used)
  values (p_organization_id, p_period_start, case when p_blocked then 1 else 0 end, greatest(coalesce(p_tokens, 0), 0))
  on conflict (organization_id, period_start) do update
    set blocked_count = public.usage_counters.blocked_count + case when p_blocked then 1 else 0 end,
        tokens_used = public.usage_counters.tokens_used + greatest(coalesce(p_tokens, 0), 0),
        updated_at = now();
end $$;

-- Deletes an organisation's request log older than its retention setting (default 365 days). Returns rows deleted.
create or replace function public.cleanup_expired_audit_logs(target_org uuid) returns bigint
language plpgsql security definer set search_path = public, pg_temp as $$
declare days integer; removed bigint;
begin
  select coalesce((select s.audit_retention_days from public.organization_settings s where s.organization_id = target_org), 365) into days;
  delete from public.audit_logs where organization_id = target_org and "timestamp" < now() - make_interval(days => days);
  get diagnostics removed = row_count;
  return removed;
end $$;

revoke all on function public.consume_gateway_usage(uuid, date, bigint) from public, anon, authenticated;
revoke all on function public.record_gateway_outcome(uuid, date, boolean, bigint) from public, anon, authenticated;
revoke all on function public.cleanup_expired_audit_logs(uuid) from public, anon, authenticated;
grant execute on function public.consume_gateway_usage(uuid, date, bigint) to service_role;
grant execute on function public.record_gateway_outcome(uuid, date, boolean, bigint) to service_role;
grant execute on function public.cleanup_expired_audit_logs(uuid) to service_role;
