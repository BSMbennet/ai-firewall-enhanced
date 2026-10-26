-- Mirrors what backend/app does against the database; run after live_schema + both migrations. Aborts on first failure.
\set ON_ERROR_STOP on
insert into auth.users values ('11111111-1111-1111-1111-111111111111') on conflict do nothing;
set role service_role;
insert into organizations(id,name,slug) values ('aaaaaaaa-0000-0000-0000-000000000001','Org','org') on conflict do nothing;
insert into organization_members(id,organization_id,user_id,email,role) values ('cccccccc-0000-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','a@x','owner') on conflict do nothing;
insert into applications(id,organization_id,name,provider,model) values ('dddddddd-0000-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001','app','openai','gpt-4o-mini') on conflict do nothing;
-- API key creation (supabase_client.create_api_key): no raw `key`, key_prefix, scopes
insert into api_keys(user_id,organization_id,application_id,employee_id,key_hash,key_prefix,name,is_active,scopes,expires_at)
  values ('11111111-1111-1111-1111-111111111111','aaaaaaaa-0000-0000-0000-000000000001','dddddddd-0000-0000-0000-000000000001','cccccccc-0000-0000-0000-000000000001','h1','afk_abcdefgh','k',true,'["chat"]',now()+interval '30 days');
-- gateway audit + security event rows (main.run_firewall_pipeline)
insert into audit_logs(user_id,organization_id,application_id,employee_id,request_id,action,risk_score,tokens_used,latency_ms,model,cost,metadata)
  values ('11111111-1111-1111-1111-111111111111','aaaaaaaa-0000-0000-0000-000000000001','dddddddd-0000-0000-0000-000000000001','cccccccc-0000-0000-0000-000000000001','r1','ALLOW',3,'{}',0,'gpt-4o-mini',0,'{"gateway":true}');
insert into security_events(user_id,organization_id,application_id,employee_id,event_type,severity,risk_score,details)
  values ('11111111-1111-1111-1111-111111111111','aaaaaaaa-0000-0000-0000-000000000001',null,null,'security_validation','low',3,'{}');
-- admin audit event, then append-only enforcement
insert into audit_events(organization_id,actor_user_id,action,resource_type,resource_id,outcome,request_id,metadata)
  values ('aaaaaaaa-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','api_key.created','api_key','1','success','r1','{"chain":{"prev":"0","hash":"x"}}');
do $$ begin
  begin update audit_events set outcome='denied'; raise exception 'update should have failed'; exception when insufficient_privilege then null; end;
  begin delete from audit_events; raise exception 'delete should have failed'; exception when insufficient_privilege then null; end;
end $$;
-- metering RPCs: atomic count, limit enforced, outcome recorded
select * from consume_gateway_usage('aaaaaaaa-0000-0000-0000-000000000001', date '2026-10-01', 2);
select * from consume_gateway_usage('aaaaaaaa-0000-0000-0000-000000000001', date '2026-10-01', 2);
do $$ declare r record; begin
  select * into r from consume_gateway_usage('aaaaaaaa-0000-0000-0000-000000000001', date '2026-10-01', 2);
  if r.allowed then raise exception 'limit not enforced'; end if;
end $$;
select record_gateway_outcome('aaaaaaaa-0000-0000-0000-000000000001', date '2026-10-01', true, 42);
do $$ declare c record; begin
  select * into c from usage_counters where organization_id='aaaaaaaa-0000-0000-0000-000000000001';
  if c.request_count <> 2 or c.blocked_count <> 1 or c.tokens_used <> 42 then raise exception 'counters wrong: % % %', c.request_count, c.blocked_count, c.tokens_used; end if;
end $$;
-- settings upsert, billing upsert (on_conflict organization_id), onboarding upsert, webhook + delivery
insert into organization_settings(organization_id, audit_retention_days, alert_email_enabled, alert_email_recipients) values ('aaaaaaaa-0000-0000-0000-000000000001', 30, true, '["a@x"]')
  on conflict (organization_id) do update set audit_retention_days = 30;
insert into billing_subscriptions(organization_id, stripe_subscription_id, stripe_customer_id, plan_key, status, seat_quantity) values ('aaaaaaaa-0000-0000-0000-000000000001','sub_1','cus_1','starter','active',3)
  on conflict (organization_id) do update set status='active';
insert into onboarding_progress(organization_id, completed_steps) values ('aaaaaaaa-0000-0000-0000-000000000001','["organization"]') on conflict (organization_id) do update set completed_steps='["organization","policy"]';
insert into webhook_integrations(id,organization_id,name,url,secret_encrypted,events) values ('eeeeeeee-0000-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001','siem','https://x.example','enc','{security.blocked}');
insert into webhook_deliveries(organization_id,webhook_id,event_type,payload,status,attempts) values ('aaaaaaaa-0000-0000-0000-000000000001','eeeeeeee-0000-0000-0000-000000000001','security.blocked','{}','pending',0);
insert into alert_rules(organization_id,name,event_type,threshold,window_minutes,severity) values ('aaaaaaaa-0000-0000-0000-000000000001','r','security.blocked',1,15,'high');
insert into security_alerts(organization_id,event_type,severity,title,message,metadata) values ('aaaaaaaa-0000-0000-0000-000000000001','security.blocked','high','t','m','{}');
-- retention cleanup removes only rows older than the org's retention
insert into audit_logs(organization_id,request_id,action,"timestamp") values ('aaaaaaaa-0000-0000-0000-000000000001','old','ALLOW', now() - interval '90 days');
do $$ declare n int; begin select cleanup_expired_audit_logs('aaaaaaaa-0000-0000-0000-000000000001') into n; if n <> 1 then raise exception 'cleanup removed %', n; end if; end $$;
-- clients cannot reach any of it
reset role; set role authenticated; set request.jwt.claim.sub='11111111-1111-1111-1111-111111111111'; set request.jwt.claim.role='authenticated';
do $$ declare t text; begin
  foreach t in array array['audit_events','usage_counters','billing_subscriptions','webhook_integrations','scim_tokens','api_keys','audit_logs'] loop
    begin execute format('select count(*) from public.%I', t); raise exception 'authenticated could read %', t; exception when insufficient_privilege then null; end;
  end loop;
  begin perform consume_gateway_usage('aaaaaaaa-0000-0000-0000-000000000001', date '2026-10-01', null); raise exception 'authenticated could call RPC'; exception when insufficient_privilege then null; end;
end $$;
reset role;
\echo SMOKE OK
