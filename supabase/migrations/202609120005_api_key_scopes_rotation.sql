-- API-key scope validation and atomic rotation support.
-- The API layer must validate requested scopes before calling this function.

create or replace function public.rotate_api_key(
  p_actor_id uuid,
  p_key_id uuid,
  p_new_key_hash text,
  p_name text,
  p_expires_at timestamptz,
  p_scopes jsonb,
  p_grace_until timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_org_id uuid;
  v_old api_keys%rowtype;
  v_new api_keys%rowtype;
begin
  select p.organization_id into v_org_id
  from profiles p
  where p.id = p_actor_id;

  if v_org_id is null then
    raise exception 'organization not found';
  end if;

  if not exists (
    select 1 from organization_members m
    where m.organization_id = v_org_id
      and m.user_id = p_actor_id
      and m.status = 'active'
      and lower(m.role) in ('owner', 'admin', 'security')
  ) then
    raise exception 'not authorized';
  end if;

  select * into v_old
  from api_keys
  where id = p_key_id
    and organization_id = v_org_id
    and is_active = true
    and revoked_at is null
  for update;

  if not found then
    raise exception 'active API key not found';
  end if;

  insert into api_keys (
    user_id, organization_id, application_id, employee_id,
    key_hash, name, scopes, is_active, expires_at,
    rotated_from, rotation_grace_until
  ) values (
    v_old.user_id, v_org_id, v_old.application_id, v_old.employee_id,
    p_new_key_hash, coalesce(nullif(p_name, ''), v_old.name),
    coalesce(p_scopes, v_old.scopes), true, p_expires_at,
    v_old.id, p_grace_until
  ) returning * into v_new;

  update api_keys
  set is_active = case when p_grace_until is null then false else true end,
      revoked_at = case when p_grace_until is null then now() else null end,
      rotation_grace_until = p_grace_until
  where id = v_old.id;

  return jsonb_build_object(
    'id', v_new.id,
    'name', v_new.name,
    'user_id', v_new.user_id,
    'organization_id', v_new.organization_id,
    'application_id', v_new.application_id,
    'employee_id', v_new.employee_id,
    'scopes', v_new.scopes,
    'is_active', v_new.is_active,
    'expires_at', v_new.expires_at,
    'created_at', v_new.created_at,
    'rotated_from', v_new.rotated_from,
    'rotation_grace_until', v_new.rotation_grace_until
  );
end;
$$;

revoke all on function public.rotate_api_key(uuid, uuid, text, text, timestamptz, jsonb, timestamptz) from public, anon, authenticated;
grant execute on function public.rotate_api_key(uuid, uuid, text, text, timestamptz, jsonb, timestamptz) to service_role;
