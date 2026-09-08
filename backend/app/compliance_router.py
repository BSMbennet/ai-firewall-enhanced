from fastapi import APIRouter, Depends, HTTPException, Response
from typing import Any
import csv
import io
from app.auth import AuthManager, get_current_user
from app.supabase_client import SupabaseManager

router = APIRouter(prefix="/v1/enterprise", tags=["compliance"])
supabase = SupabaseManager()
auth = AuthManager()

async def _org(user_id: str):
    if not supabase._initialized:
        await supabase.initialize()
    org = await supabase.get_organization_for_user(user_id)
    return org or await supabase.ensure_organization(user_id)

@router.get("/compliance/overview")
async def compliance_overview(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    oid = org["id"]
    members = supabase.client.table("organization_members").select("id,status,role").eq("organization_id", oid).execute().data or []
    apps = supabase.client.table("applications").select("id,status,environment").eq("organization_id", oid).execute().data or []
    keys = supabase.client.table("api_keys").select("id,is_active,expires_at,revoked_at").eq("organization_id", oid).execute().data or []
    policies = supabase.client.table("security_policies").select("id,is_enabled").eq("organization_id", oid).execute().data or []
    domains = supabase.client.table("custom_domains").select("id,status").eq("organization_id", oid).execute().data or []
    identities = supabase.client.table("identity_connections").select("id,is_active,provider").eq("organization_id", oid).execute().data or []
    scim = supabase.client.table("scim_tokens").select("id,revoked_at,expires_at").eq("organization_id", oid).execute().data or []
    blocked = supabase.client.table("audit_logs").select("id", count="exact").eq("organization_id", oid).eq("action", "BLOCK").execute()
    total = supabase.client.table("audit_logs").select("id", count="exact").eq("organization_id", oid).execute()
    active_members = len([m for m in members if m.get("status") == "active"])
    active_apps = len([a for a in apps if a.get("status", "active") == "active"])
    active_keys = len([k for k in keys if k.get("is_active") and not k.get("revoked_at")])
    enabled_policies = len([p for p in policies if p.get("is_enabled")])
    verified_domains = len([d for d in domains if d.get("status") == "verified"])
    active_identity = len([i for i in identities if i.get("is_active")])
    active_scim = len([s for s in scim if not s.get("revoked_at")])
    checks = {
        "identity_configured": active_identity > 0,
        "scim_configured": active_scim > 0,
        "custom_domain_verified": verified_domains > 0,
        "security_policies_enabled": enabled_policies > 0,
        "applications_protected": active_apps > 0,
        "api_access_configured": active_keys > 0,
        "audit_logging": True,
    }
    score = round(sum(1 for v in checks.values() if v) / len(checks) * 100)
    return {"organization": {"id": oid, "name": org.get("name"), "slug": org.get("slug")}, "score": score, "checks": checks, "metrics": {"active_members": active_members, "active_applications": active_apps, "active_api_keys": active_keys, "enabled_policies": enabled_policies, "verified_domains": verified_domains, "total_requests": total.count or 0, "blocked_requests": blocked.count or 0}}

@router.get("/compliance/audit-export")
async def audit_export(limit: int = 5000, user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    limit = min(max(limit, 1), 10000)
    rows = supabase.client.table("audit_logs").select("*").eq("organization_id", org["id"]).order("timestamp", desc=True).limit(limit).execute().data or []
    output = io.StringIO()
    fields = ["id", "timestamp", "action", "employee_id", "application_id", "model", "risk_score", "latency_ms", "cost", "reason"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k) for k in fields})
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ai-firewall-audit-log.csv"})
