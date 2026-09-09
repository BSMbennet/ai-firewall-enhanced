from fastapi import APIRouter, Depends, HTTPException, Response
from typing import Any, Dict
from datetime import datetime, timezone
import csv
import io
from app.auth import AuthManager, get_current_user
from app.supabase_client import SupabaseManager

router = APIRouter(prefix="/v1/enterprise", tags=["compliance"])
supabase = SupabaseManager()
auth = AuthManager()

async def _org(user_id: str):
    if not supabase._initialized: await supabase.initialize()
    org = await supabase.get_organization_for_user(user_id)
    return org or await supabase.ensure_organization(user_id)

@router.get("/compliance/overview")
async def compliance_overview(user_id: str = Depends(get_current_user)):
    org = await _org(user_id); oid = org["id"]
    members = supabase.client.table("organization_members").select("id,status,role").eq("organization_id", oid).execute().data or []
    apps = supabase.client.table("applications").select("id,status,environment").eq("organization_id", oid).execute().data or []
    keys = supabase.client.table("api_keys").select("id,is_active,expires_at,revoked_at").eq("organization_id", oid).execute().data or []
    policies = supabase.client.table("security_policies").select("id,audit_logging").eq("organization_id", oid).execute().data or []
    domains = supabase.client.table("custom_domains").select("id,status").eq("organization_id", oid).execute().data or []
    identities = supabase.client.table("identity_connections").select("id,is_active,provider").eq("organization_id", oid).execute().data or []
    scim = supabase.client.table("scim_tokens").select("id,revoked_at,expires_at").eq("organization_id", oid).execute().data or []
    controls = supabase.client.table("compliance_controls").select("id,status,framework").eq("organization_id", oid).execute().data or []
    blocked = supabase.client.table("audit_logs").select("id", count="exact").eq("organization_id", oid).eq("action", "BLOCK").execute()
    total = supabase.client.table("audit_logs").select("id", count="exact").eq("organization_id", oid).execute()
    checks = {
        "identity_configured": any(i.get("is_active") for i in identities),
        "scim_configured": any(not s.get("revoked_at") and (not s.get("expires_at") or s.get("expires_at") > datetime.now(timezone.utc).isoformat()) for s in scim),
        "custom_domain_verified": any(d.get("status") in {"verified", "active"} for d in domains),
        "security_policies_enabled": any(p.get("audit_logging") for p in policies),
        "applications_protected": any(a.get("status", "active") == "active" for a in apps),
        "api_access_configured": any(k.get("is_active") and not k.get("revoked_at") for k in keys),
        "audit_logging": any(p.get("audit_logging") for p in policies) if policies else True,
    }
    score = round(sum(1 for v in checks.values() if v) / len(checks) * 100)
    return {
        "organization": {"id": oid, "name": org.get("name"), "slug": org.get("slug")},
        "score": score,
        "checks": checks,
        "metrics": {
            "active_members": sum(m.get("status") == "active" for m in members),
            "active_applications": sum(a.get("status", "active") == "active" for a in apps),
            "active_api_keys": sum(k.get("is_active") and not k.get("revoked_at") for k in keys),
            "enabled_policies": sum(bool(p.get("audit_logging")) for p in policies),
            "verified_domains": sum(d.get("status") in {"verified", "active"} for d in domains),
            "compliance_controls": len(controls),
            "implemented_controls": sum(c.get("status") in {"implemented", "accepted"} for c in controls),
            "total_requests": total.count or 0,
            "blocked_requests": blocked.count or 0,
        },
    }

@router.get("/compliance/audit-export")
async def audit_export(limit: int = 5000, user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    rows = supabase.client.table("audit_logs").select("*").eq("organization_id", org["id"]).order("timestamp", desc=True).limit(min(max(limit, 1), 10000)).execute().data or []
    output = io.StringIO(); fields = ["id", "timestamp", "action", "employee_id", "application_id", "model", "risk_score", "latency_ms", "cost", "reason"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore"); writer.writeheader()
    for row in rows: writer.writerow({k: row.get(k) for k in fields})
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ai-firewall-audit-log.csv"})

@router.get("/governance/controls")
async def list_controls(framework: str | None = None, user_id: str = Depends(get_current_user)):
    org = await _org(user_id); q = supabase.client.table("compliance_controls").select("*").eq("organization_id", org["id"])
    if framework: q = q.eq("framework", framework)
    return {"controls": q.order("framework").order("control_id").execute().data or []}

@router.post("/governance/controls")
async def create_control(payload: Dict[str, Any], user_id: str = Depends(auth.require_admin)):
    org = await _org(user_id); framework = str(payload.get("framework") or "custom").lower(); control_id = str(payload.get("control_id") or "").strip(); title = str(payload.get("title") or "").strip()
    if framework not in {"soc2", "iso27001", "nist", "custom"} or not control_id or not title: raise HTTPException(400, "framework, control_id and title are required")
    owner_user_id = payload.get("owner_user_id")
    if owner_user_id:
        owner = supabase.client.table("organization_members").select("id").eq("organization_id", org["id"]).eq("user_id", owner_user_id).maybe_single().execute().data
        if not owner: raise HTTPException(400, "Control owner must belong to this organization")
    status = str(payload.get("status") or "not_started")
    if status not in {"not_started", "in_progress", "implemented", "accepted", "not_applicable"}: raise HTTPException(400, "Invalid control status")
    row = {"organization_id": org["id"], "framework": framework, "control_id": control_id[:80], "title": title[:240], "status": status, "owner_user_id": owner_user_id, "evidence": payload.get("evidence") or [], "notes": str(payload.get("notes") or "")[:4000], "updated_by": user_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    result = supabase.client.table("compliance_controls").upsert(row, on_conflict="organization_id,framework,control_id").execute()
    return {"control": result.data[0]}

@router.patch("/governance/controls/{control_id}")
async def update_control(control_id: str, payload: Dict[str, Any], user_id: str = Depends(auth.require_admin)):
    org = await _org(user_id); allowed = {"status", "owner_user_id", "evidence", "notes", "title"}; changes = {k: payload[k] for k in allowed if k in payload}
    if "status" in changes and changes["status"] not in {"not_started", "in_progress", "implemented", "accepted", "not_applicable"}: raise HTTPException(400, "Invalid control status")
    if "owner_user_id" in changes and changes["owner_user_id"]:
        owner = supabase.client.table("organization_members").select("id").eq("organization_id", org["id"]).eq("user_id", changes["owner_user_id"]).maybe_single().execute().data
        if not owner: raise HTTPException(400, "Control owner must belong to this organization")
    changes["updated_by"] = user_id; changes["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = supabase.client.table("compliance_controls").update(changes).eq("id", control_id).eq("organization_id", org["id"]).execute()
    if not result.data: raise HTTPException(404, "Compliance control not found")
    return {"control": result.data[0]}

@router.get("/governance/access-reviews")
async def list_access_reviews(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    return {"reviews": supabase.client.table("access_reviews").select("*").eq("organization_id", org["id"]).order("created_at", desc=True).execute().data or []}

@router.post("/governance/access-reviews")
async def create_access_review(payload: Dict[str, Any], user_id: str = Depends(auth.require_admin)):
    org = await _org(user_id); now = datetime.now(timezone.utc); start = str(payload.get("period_start") or now.isoformat()); end = str(payload.get("period_end") or now.isoformat())
    if start > end: raise HTTPException(400, "period_start must be before period_end")
    result = supabase.client.table("access_reviews").insert({"organization_id": org["id"], "reviewer_user_id": user_id, "period_start": start, "period_end": end, "status": "open", "decisions": []}).execute()
    return {"review": result.data[0]}

@router.patch("/governance/access-reviews/{review_id}")
async def update_access_review(review_id: str, payload: Dict[str, Any], user_id: str = Depends(auth.require_admin)):
    org = await _org(user_id); changes = {k: payload[k] for k in ("status", "decisions") if k in payload}
    if "status" in changes and changes["status"] not in {"open", "completed", "cancelled"}: raise HTTPException(400, "Invalid access review status")
    if changes.get("status") == "completed": changes["completed_at"] = datetime.now(timezone.utc).isoformat()
    result = supabase.client.table("access_reviews").update(changes).eq("id", review_id).eq("organization_id", org["id"]).execute()
    if not result.data: raise HTTPException(404, "Access review not found")
    return {"review": result.data[0]}

@router.get("/governance/settings")
async def governance_settings(user_id: str = Depends(get_current_user)):
    org = await _org(user_id); row = supabase.client.table("organization_settings").select("*").eq("organization_id", org["id"]).maybe_single().execute().data
    return {"settings": row or {"organization_id": org["id"], "audit_retention_days": 365, "alert_email_enabled": True, "require_sso": False, "require_mfa": False, "enforce_verified_domains": False, "audit_prompt_content": False}}

@router.patch("/governance/settings")
async def update_governance_settings(payload: Dict[str, Any], user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id); allowed = {"audit_retention_days", "alert_email_enabled", "alert_email_recipients", "require_sso", "require_mfa", "enforce_verified_domains", "audit_prompt_content"}; changes = {k: payload[k] for k in allowed if k in payload}
    if "audit_retention_days" in changes: changes["audit_retention_days"] = min(max(int(changes["audit_retention_days"]), 7), 3650)
    if "alert_email_recipients" in changes:
        if not isinstance(changes["alert_email_recipients"], list) or any("@" not in str(v) for v in changes["alert_email_recipients"]): raise HTTPException(400, "alert_email_recipients must be an array of email addresses")
        changes["alert_email_recipients"] = [str(v).strip().lower() for v in changes["alert_email_recipients"]][:50]
    changes["organization_id"] = org["id"]; changes["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = supabase.client.table("organization_settings").upsert(changes, on_conflict="organization_id").execute()
    return {"settings": result.data[0]}
