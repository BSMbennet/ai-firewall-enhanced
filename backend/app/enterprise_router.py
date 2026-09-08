from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Any, Dict
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import re
import httpx

from app.auth import AuthManager, get_current_user
from app.supabase_client import SupabaseManager

router = APIRouter(prefix="/v1/enterprise", tags=["enterprise"])
supabase = SupabaseManager()
auth = AuthManager()
scim_bearer = HTTPBearer(auto_error=False)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def _org(user_id: str) -> Dict:
    if not supabase._initialized:
        await supabase.initialize()
    org = await supabase.get_organization_for_user(user_id)
    if not org:
        org = await supabase.ensure_organization(user_id)
    return org


@router.get("/identity")
async def identity_connections(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    result = supabase.client.table("identity_connections").select("id,provider,name,domain,issuer_url,metadata,is_active,created_at,updated_at").eq("organization_id", org["id"]).order("created_at").execute()
    return {"connections": result.data or [], "providers": ["google", "azure", "saml", "oidc"]}


@router.post("/identity")
async def create_identity_connection(payload: Dict[str, Any], user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    provider = str(payload.get("provider") or "").lower()
    if provider not in {"google", "azure", "saml", "oidc"}:
        raise HTTPException(400, "Unsupported identity provider")
    name = str(payload.get("name") or provider.title())[:120]
    domain = str(payload.get("domain") or "").strip().lower()[:255] or None
    issuer = str(payload.get("issuer_url") or "").strip()[:500] or None
    client_id = str(payload.get("client_id") or "").strip()[:500] or None
    client_secret = str(payload.get("client_secret") or "").strip()
    record = {"organization_id": org["id"], "provider": provider, "name": name, "domain": domain, "client_id": client_id, "client_secret_hash": _hash(client_secret) if client_secret else None, "issuer_url": issuer, "metadata": payload.get("metadata") or {}, "created_by": user_id, "is_active": True}
    result = supabase.client.table("identity_connections").insert(record).execute()
    if not result.data:
        raise HTTPException(500, "Unable to save identity connection")
    safe = dict(result.data[0]); safe.pop("client_secret_hash", None); safe.pop("client_id", None)
    return {"connection": safe}


@router.patch("/identity/{connection_id}")
async def update_identity_connection(connection_id: str, payload: Dict[str, Any], user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    changes = {}
    for field in ("name", "domain", "issuer_url"):
        if field in payload:
            changes[field] = str(payload[field])[:500] if payload[field] is not None else None
    if "is_active" in payload:
        changes["is_active"] = bool(payload["is_active"])
    if "client_secret" in payload and payload["client_secret"]:
        changes["client_secret_hash"] = _hash(str(payload["client_secret"]))
    changes["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = supabase.client.table("identity_connections").update(changes).eq("id", connection_id).eq("organization_id", org["id"]).execute()
    if not result.data:
        raise HTTPException(404, "Identity connection not found")
    return {"connection": result.data[0]}


@router.post("/scim/tokens")
async def create_scim_token(payload: Dict[str, Any] | None = None, user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    token = "scim_" + secrets.token_urlsafe(36)
    days = max(1, min(int((payload or {}).get("expires_days") or 365), 3650))
    result = supabase.client.table("scim_tokens").insert({"organization_id": org["id"], "name": str((payload or {}).get("name") or "SCIM token")[:120], "token_hash": _hash(token), "expires_at": (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(), "created_by": user_id}).execute()
    if not result.data:
        raise HTTPException(500, "Unable to create SCIM token")
    return {"token": token, "token_id": result.data[0]["id"], "expires_at": result.data[0]["expires_at"]}


@router.get("/scim/tokens")
async def list_scim_tokens(user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    result = supabase.client.table("scim_tokens").select("id,name,last_used_at,expires_at,revoked_at,created_at").eq("organization_id", org["id"]).order("created_at", desc=True).execute()
    return {"tokens": result.data or []}


@router.delete("/scim/tokens/{token_id}")
async def revoke_scim_token(token_id: str, user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    result = supabase.client.table("scim_tokens").update({"revoked_at": datetime.now(timezone.utc).isoformat()}).eq("id", token_id).eq("organization_id", org["id"]).execute()
    if not result.data:
        raise HTTPException(404, "SCIM token not found")
    return {"message": "SCIM token revoked"}


async def _scim_org(request: Request, credentials: HTTPAuthorizationCredentials | None) -> Dict:
    if credentials is None or not credentials.credentials:
        raise HTTPException(401, "SCIM bearer token required")
    if not supabase._initialized:
        await supabase.initialize()
    token_hash = _hash(credentials.credentials)
    result = supabase.client.table("scim_tokens").select("*").eq("token_hash", token_hash).execute()
    if not result.data:
        raise HTTPException(401, "Invalid SCIM token")
    token = result.data[0]
    if token.get("revoked_at") or (token.get("expires_at") and datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)):
        raise HTTPException(401, "Expired or revoked SCIM token")
    supabase.client.table("scim_tokens").update({"last_used_at": datetime.now(timezone.utc).isoformat()}).eq("id", token["id"]).execute()
    return token


async def _scim_member(org_id: str, member_id: str):
    result = supabase.client.table("organization_members").select("*").eq("organization_id", org_id).eq("id", member_id).maybe_single().execute()
    return result.data


@router.get("/scim/{org_slug}/Users")
async def scim_list_users(org_slug: str, request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(scim_bearer)):
    token = await _scim_org(request, credentials)
    org = supabase.client.table("organizations").select("*").eq("id", token["organization_id"]).eq("slug", org_slug).maybe_single().execute().data
    if not org:
        raise HTTPException(404, "Organization not found")
    rows = supabase.client.table("organization_members").select("*").eq("organization_id", org["id"]).neq("status", "removed").execute().data or []
    resources = [{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":m["id"],"userName":m["email"],"active":m["status"] != "suspended","displayName":m.get("full_name") or m["email"],"emails":[{"value":m["email"],"primary":True}]} for m in rows]
    return {"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":len(resources),"startIndex":1,"itemsPerPage":len(resources),"Resources":resources}


@router.post("/scim/{org_slug}/Users")
async def scim_create_user(org_slug: str, payload: Dict[str, Any], request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(scim_bearer)):
    token = await _scim_org(request, credentials)
    org = supabase.client.table("organizations").select("*").eq("id", token["organization_id"]).eq("slug", org_slug).maybe_single().execute().data
    if not org:
        raise HTTPException(404, "Organization not found")
    email = str(payload.get("userName") or ((payload.get("emails") or [{}])[0].get("value") or "")).strip().lower()
    if "@" not in email:
        raise HTTPException(400, "SCIM userName/email is required")
    existing = supabase.client.table("organization_members").select("*").eq("organization_id", org["id"]).eq("email", email).maybe_single().execute().data
    if existing:
        return {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":existing["id"],"userName":email,"active":existing["status"] != "suspended","displayName":existing.get("full_name") or email}
    invite = supabase.client.auth.admin.invite_user_by_email(email)
    invited = getattr(invite, "user", None)
    if invited is None:
        raise HTTPException(502, "Unable to provision user")
    display = str(payload.get("displayName") or ((payload.get("name") or {}).get("formatted") or email))[:120]
    member = supabase.client.table("organization_members").insert({"organization_id":org["id"],"user_id":str(invited.id),"email":email,"full_name":display,"role":"member","status":"active"}).execute().data[0]
    supabase.client.table("profiles").update({"organization_id":org["id"],"role":"member","full_name":display}).eq("id",str(invited.id)).execute()
    return {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":member["id"],"userName":email,"active":True,"displayName":display}


@router.patch("/scim/{org_slug}/Users/{member_id}")
async def scim_update_user(org_slug: str, member_id: str, payload: Dict[str, Any], request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(scim_bearer)):
    token = await _scim_org(request, credentials)
    org = supabase.client.table("organizations").select("*").eq("id", token["organization_id"]).eq("slug", org_slug).maybe_single().execute().data
    if not org:
        raise HTTPException(404, "Organization not found")
    member = await _scim_member(org["id"], member_id)
    if not member:
        raise HTTPException(404, "SCIM user not found")
    active = payload.get("active")
    if active is None:
        for op in payload.get("Operations", []):
            if str(op.get("path","")).lower() == "active": active = op.get("value")
    changes = {}
    if active is not None: changes["status"] = "active" if bool(active) else "suspended"
    if payload.get("displayName"): changes["full_name"] = str(payload["displayName"])[:120]
    if not changes: return {"id":member_id,"message":"No changes"}
    result = supabase.client.table("organization_members").update(changes).eq("id",member_id).eq("organization_id",org["id"]).execute()
    return {"id":member_id,"userName":member["email"],"active":result.data[0]["status"] != "suspended"}


@router.get("/activity/employees/{member_id}")
async def employee_activity(member_id: str, limit: int = 100, user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    member = await _scim_member(org["id"], member_id)
    if not member: raise HTTPException(404, "Employee not found")
    limit = min(max(limit,1),500)
    logs = supabase.client.table("audit_logs").select("*").eq("organization_id",org["id"]).eq("employee_id",member_id).order("timestamp",desc=True).limit(limit).execute().data or []
    events = supabase.client.table("security_events").select("*").eq("organization_id",org["id"]).eq("employee_id",member_id).order("timestamp",desc=True).limit(limit).execute().data or []
    return {"employee":member,"requests":logs,"security_events":events}


@router.get("/activity/applications/{application_id}")
async def application_activity(application_id: str, limit: int = 100, user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    app = supabase.client.table("applications").select("*").eq("organization_id",org["id"]).eq("id",application_id).maybe_single().execute().data
    if not app: raise HTTPException(404, "Application not found")
    limit = min(max(limit,1),500)
    logs = supabase.client.table("audit_logs").select("*").eq("organization_id",org["id"]).eq("application_id",application_id).order("timestamp",desc=True).limit(limit).execute().data or []
    events = supabase.client.table("security_events").select("*").eq("organization_id",org["id"]).eq("application_id",application_id).order("timestamp",desc=True).limit(limit).execute().data or []
    return {"application":app,"requests":logs,"security_events":events}


@router.get("/domains")
async def list_domains(user_id: str = Depends(get_current_user)):
    org = await _org(user_id)
    result = supabase.client.table("custom_domains").select("*").eq("organization_id",org["id"]).order("created_at",desc=True).execute()
    return {"domains":result.data or [],"tls": "managed by Vercel after domain is attached"}


@router.post("/domains")
async def add_domain(payload: Dict[str,Any], user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    domain = str(payload.get("domain") or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",domain):
        raise HTTPException(400,"Enter a valid hostname")
    result = supabase.client.table("custom_domains").upsert({"organization_id":org["id"],"domain":domain,"verification_type":"cname","verification_target":os.getenv("CUSTOM_DOMAIN_TARGET","cname.vercel-dns.com"),"created_by":user_id,"status":"pending"},on_conflict="domain").execute()
    return {"domain":result.data[0],"instructions":{"record_type":"CNAME","target":result.data[0]["verification_target"],"note":"Attach this domain to the Vercel project, then verify DNS here. Vercel provisions TLS automatically after the domain is correctly configured."}}


@router.post("/domains/{domain_id}/verify")
async def verify_domain(domain_id: str, user_id: str = Depends(auth.require_owner_or_admin)):
    org = await _org(user_id)
    row = supabase.client.table("custom_domains").select("*").eq("id",domain_id).eq("organization_id",org["id"]).maybe_single().execute().data
    if not row: raise HTTPException(404,"Domain not found")
    name = row["domain"]
    target = row["verification_target"] or "cname.vercel-dns.com"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get("https://cloudflare-dns.com/dns-query",params={"name":name,"type":"CNAME"},headers={"accept":"application/dns-json"})
            data = response.json()
        answers = [str(a.get("data","")).rstrip(".").lower() for a in data.get("Answer",[])]
        verified = target.rstrip(".").lower() in answers or name == target.rstrip(".").lower()
    except Exception:
        verified = False
    status = "verified" if verified else "pending"
    patch={"status":status,"verified_at":datetime.now(timezone.utc).isoformat() if verified else None,"updated_at":datetime.now(timezone.utc).isoformat()}
    result=supabase.client.table("custom_domains").update(patch).eq("id",domain_id).eq("organization_id",org["id"]).execute()
    return {"domain":result.data[0],"verified":verified,"target":target}
