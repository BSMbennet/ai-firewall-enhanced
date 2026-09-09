-- Enterprise authentication completion: organization SSO/MFA policy state.
-- SSO provider configuration remains in identity_connections and is consumed by
-- Supabase Auth's hosted SAML/OIDC flow. This table stores AI Firewall policy.

alter table public.organization_settings
  add column if not exists require_mfa boolean not null default false,
  add column if not exists require_sso boolean not null default false,
  add column if not exists updated_at timestamptz not null default now();

create index if not exists idx_identity_connections_org_domain_active
  on public.identity_connections (organization_id, domain, is_active);

-- Keep organization settings private to authenticated members of the same org.
-- Existing policies are retained; this policy is additive only when a deployment
-- has no equivalent member-read policy.
