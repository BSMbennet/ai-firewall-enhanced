-- Keep anonymous clients from discovering organization-scoped data or security helpers.
REVOKE EXECUTE ON FUNCTION public.is_org_member(uuid) FROM anon, authenticated;
REVOKE SELECT ON TABLE public.organizations, public.organization_members, public.applications, public.security_policies, public.organization_settings FROM anon;
REVOKE SELECT ON TABLE public.audit_logs, public.api_keys, public.security_events FROM anon;
