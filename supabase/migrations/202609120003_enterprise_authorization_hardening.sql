-- Enterprise authorization hardening
-- Keeps legacy profiles while supporting organization roles and policy lookups.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.profiles'::regclass
      AND conname = 'profiles_role_check'
  ) THEN
    ALTER TABLE public.profiles DROP CONSTRAINT profiles_role_check;
  END IF;
END $$;

ALTER TABLE public.profiles
  ADD CONSTRAINT profiles_role_check
  CHECK (role IN ('user','admin','owner','security','developer','member','viewer'));

CREATE TABLE IF NOT EXISTS public.organization_settings (
  organization_id uuid PRIMARY KEY REFERENCES public.organizations(id) ON DELETE CASCADE,
  require_mfa boolean NOT NULL DEFAULT false,
  require_sso boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.organization_settings (organization_id)
SELECT id FROM public.organizations
ON CONFLICT (organization_id) DO NOTHING;

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_settings ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.is_org_member(p_org_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members m
    WHERE m.organization_id = p_org_id
      AND m.user_id = auth.uid()
      AND m.status IN ('active','invited')
  );
$$;

DROP POLICY IF EXISTS organizations_member_read ON public.organizations;
CREATE POLICY organizations_member_read ON public.organizations
  FOR SELECT TO authenticated USING (public.is_org_member(id));

DROP POLICY IF EXISTS organization_members_member_read ON public.organization_members;
CREATE POLICY organization_members_member_read ON public.organization_members
  FOR SELECT TO authenticated USING (public.is_org_member(organization_id));

DROP POLICY IF EXISTS applications_member_read ON public.applications;
CREATE POLICY applications_member_read ON public.applications
  FOR SELECT TO authenticated USING (public.is_org_member(organization_id));

DROP POLICY IF EXISTS security_policies_member_read ON public.security_policies;
CREATE POLICY security_policies_member_read ON public.security_policies
  FOR SELECT TO authenticated USING (public.is_org_member(organization_id));

DROP POLICY IF EXISTS organization_settings_member_read ON public.organization_settings;
CREATE POLICY organization_settings_member_read ON public.organization_settings
  FOR SELECT TO authenticated USING (public.is_org_member(organization_id));

COMMENT ON TABLE public.organization_settings IS 'Compatibility and organization authentication policy settings.';
