-- Follow-up hardening: remove implicit PUBLIC execution from sensitive helpers.
-- Existing explicit grants are preserved; this migration only removes broad access.
begin;

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
         'user_org_id',
         'ai_firewall_rate_limit_check',
         'assert_org_linkage'
       )
  loop
    execute format(
      'revoke execute on function %I.%I(%s) from public, anon',
      fn.schema_name, fn.function_name, fn.identity_args
    );
  end loop;
end $$;

-- Common organization-scoped access paths used by RLS and enterprise views.
create index if not exists policy_versions_org_idx
  on public.policy_versions (organization_id);
create index if not exists compliance_controls_org_idx
  on public.compliance_controls (organization_id);
create index if not exists access_reviews_org_idx
  on public.access_reviews (organization_id);
create index if not exists organization_settings_org_idx
  on public.organization_settings (organization_id);

commit;
