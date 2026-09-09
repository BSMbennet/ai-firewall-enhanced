-- Authentication/RBAC hardening
-- The backend uses the Supabase service role and therefore continues to bypass RLS.
-- The browser may read only its own profile; role/organization membership must not be client-writable.

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own profile" ON profiles;
CREATE POLICY "Users can view own profile" ON profiles
    FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = id);

DROP POLICY IF EXISTS "Users cannot modify profile from client" ON profiles;
-- No INSERT/UPDATE/DELETE policy is intentionally created for authenticated users.
-- Profile and role changes are performed by the trusted backend.
