-- Run with pgTAP / Supabase database test runner after applying the migration.
-- These tests are intentionally database-level: API-only tests cannot prove RLS.

begin;

select plan(6);

select has_function('public', 'current_org_id', 'current_org_id exists');
select has_function('public', 'is_org_member', 'is_org_member exists');
select has_function('public', 'has_org_role', 'has_org_role exists');
select has_function('public', 'revoke_member_sessions', 'session revocation trigger function exists');
select has_view('public', 'audit_export_safe', 'safe audit export view exists');
select has_column('public', 'api_keys', 'scopes', 'API key scopes exist');

select * from finish();
rollback;

-- Required integration scenarios for the authenticated-role test harness:
-- 1. User A cannot select/update rows belonging to organization B.
-- 2. Suspended/removed member cannot select protected rows.
-- 3. Viewer cannot insert/update members, policies, applications, or keys.
-- 4. Audit export contains only the caller's organization.
-- 5. Rotated/revoked/expired keys cannot authorize a request.
-- 6. Updating membership to suspended/removed advances profiles.session_revoked_at.
