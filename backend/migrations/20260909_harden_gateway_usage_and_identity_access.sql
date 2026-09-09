-- Atomic gateway metering and least-privilege function execution.
create or replace function public.consume_gateway_usage(
  p_organization_id uuid,
  p_period_start date,
  p_limit bigint default null
)
returns table(allowed boolean, request_count bigint)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  current_count bigint;
begin
  insert into public.usage_counters (organization_id, period_start, request_count, blocked_count, tokens_used)
  values (p_organization_id, p_period_start, 0, 0, 0)
  on conflict (organization_id, period_start) do nothing;

  select u.request_count into current_count
  from public.usage_counters u
  where u.organization_id = p_organization_id
    and u.period_start = p_period_start
  for update;

  if p_limit is not null and current_count >= p_limit then
    return query select false, current_count;
    return;
  end if;

  update public.usage_counters
  set request_count = request_count + 1
  where organization_id = p_organization_id
    and period_start = p_period_start
  returning usage_counters.request_count into current_count;

  return query select true, current_count;
end;
$$;

create or replace function public.record_gateway_outcome(
  p_organization_id uuid,
  p_period_start date,
  p_blocked boolean default false,
  p_tokens bigint default 0
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  insert into public.usage_counters (organization_id, period_start, request_count, blocked_count, tokens_used)
  values (p_organization_id, p_period_start, 0, case when p_blocked then 1 else 0 end, greatest(coalesce(p_tokens, 0), 0))
  on conflict (organization_id, period_start) do update
    set blocked_count = usage_counters.blocked_count + case when p_blocked then 1 else 0 end,
        tokens_used = usage_counters.tokens_used + greatest(coalesce(p_tokens, 0), 0);
end;
$$;

revoke all on function public.consume_gateway_usage(uuid, date, bigint) from public, anon, authenticated;
revoke all on function public.record_gateway_outcome(uuid, date, boolean, bigint) from public, anon, authenticated;
grant execute on function public.consume_gateway_usage(uuid, date, bigint) to service_role;
grant execute on function public.record_gateway_outcome(uuid, date, boolean, bigint) to service_role;

revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.assetflow_same_org(uuid) from public, anon, authenticated;
alter function public.set_settlement_updated_at() set search_path = public, pg_temp;
alter function public.set_governance_review_updated_at() set search_path = public, pg_temp;
