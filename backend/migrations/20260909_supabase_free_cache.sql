create table if not exists public.ai_firewall_cache (
  cache_key text primary key,
  value jsonb not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists ai_firewall_cache_expires_idx on public.ai_firewall_cache (expires_at);
alter table public.ai_firewall_cache enable row level security;
revoke all on public.ai_firewall_cache from anon, authenticated;

create table if not exists public.ai_firewall_rate_limits (
  bucket_key text primary key,
  count integer not null default 0,
  window_started_at timestamptz not null default now()
);
alter table public.ai_firewall_rate_limits enable row level security;
revoke all on public.ai_firewall_rate_limits from anon, authenticated;

create or replace function public.ai_firewall_rate_limit_check(p_bucket_key text, p_limit integer, p_window_seconds integer)
returns boolean
language plpgsql
security invoker
as $$
declare
  v_count integer;
begin
  insert into public.ai_firewall_rate_limits(bucket_key, count, window_started_at)
  values (p_bucket_key, 1, now())
  on conflict (bucket_key) do update
    set count = case
      when now() - public.ai_firewall_rate_limits.window_started_at >= make_interval(secs => p_window_seconds)
        then 1
      else public.ai_firewall_rate_limits.count + 1
    end,
    window_started_at = case
      when now() - public.ai_firewall_rate_limits.window_started_at >= make_interval(secs => p_window_seconds)
        then now()
      else public.ai_firewall_rate_limits.window_started_at
    end
  returning count into v_count;
  return v_count <= p_limit;
end;
$$;
revoke execute on function public.ai_firewall_rate_limit_check(text, integer, integer) from public, anon, authenticated;
