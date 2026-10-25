\set ON_ERROR_STOP off
set role authenticated; set request.jwt.claim.sub='11111111-1111-1111-1111-111111111111'; set request.jwt.claim.role='authenticated';
\echo '--- attacker (viewer of org Mine) tries to become owner of org Victim'
update profiles set role='owner', organization_id='bbbbbbbb-0000-0000-0000-000000000002' where id='11111111-1111-1111-1111-111111111111';
select role, organization_id from profiles where id='11111111-1111-1111-1111-111111111111';
\echo '--- attacker inserts an API key row bound to the victim org'
insert into api_keys(key,user_id,key_hash,organization_id) values ('k','11111111-1111-1111-1111-111111111111','h','bbbbbbbb-0000-0000-0000-000000000002');
select count(*) as attacker_keys from api_keys;
\echo '--- legitimate frontend reads'
select role from profiles where id='11111111-1111-1111-1111-111111111111';
select require_mfa from organization_settings;
reset role; reset request.jwt.claim.sub; set role anon;
\echo '--- anon'
select count(*) from profiles;
