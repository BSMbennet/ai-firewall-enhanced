-- API-key scopes for organization/application access control.
-- Existing keys default to chat access for backwards compatibility.

alter table public.api_keys
  add column if not exists scopes jsonb
  not null default '["chat"]'::jsonb;

update public.api_keys
set scopes = '["chat"]'::jsonb
where scopes is null;

create index if not exists api_keys_scopes_gin_idx
  on public.api_keys using gin (scopes);
