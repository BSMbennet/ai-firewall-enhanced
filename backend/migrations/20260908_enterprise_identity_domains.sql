-- AI Firewall enterprise identity, provisioning, domains and activity indexes.
-- Applied to the production Supabase project as migration enterprise_identity_domains_activity.
create table if not exists public.identity_connections (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 provider text not null check (provider in ('google','azure','saml','oidc')), name text not null, domain text, client_id text,
 client_secret_hash text, issuer_url text, metadata jsonb not null default '{}'::jsonb, is_active boolean not null default true,
 created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.scim_tokens (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 name text not null default 'SCIM token', token_hash text not null unique, last_used_at timestamptz, expires_at timestamptz,
 revoked_at timestamptz, created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.custom_domains (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 domain text not null unique, status text not null default 'pending' check(status in ('pending','verified','active','failed')),
 verification_type text not null default 'cname', verification_target text, verified_at timestamptz,
 created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists audit_logs_org_employee_timestamp_idx on public.audit_logs(organization_id, employee_id, timestamp desc);
create index if not exists audit_logs_org_application_timestamp_idx on public.audit_logs(organization_id, application_id, timestamp desc);
create index if not exists security_events_org_employee_timestamp_idx on public.security_events(organization_id, employee_id, timestamp desc);
create index if not exists security_events_org_application_timestamp_idx on public.security_events(organization_id, application_id, timestamp desc);
