from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from typing import Any, Dict
from datetime import datetime, timezone, timedelta
import base64, hashlib, hmac, json, os, secrets
import httpx
from cryptography.fernet import Fernet
from app.auth import AuthManager, get_current_user
from app.supabase_client import SupabaseManager

router = APIRouter(prefix="/v1/enterprise", tags=["enterprise-operations"])
supabase = SupabaseManager()
auth = AuthManager()

def _key_cipher():
    seed = os.getenv("WEBHOOK_ENCRYPTION_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY") or ""
    if not seed:
        raise RuntimeError("Webhook encryption key is not configured")
    key = base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest())
    return Fernet(key)

def _encrypt(value: str) -> str:
    return _key_cipher().encrypt(value.encode()).decode()

def _decrypt(value: str) -> str:
    return _key_cipher().decrypt(value.encode()).decode()

async def _org(user_id: str):
    if not supabase._initialized: await supabase.initialize()
    org = await supabase.get_organization_for_user(user_id)
    return org or await supabase.ensure_organization(user_id)

async def _is_admin(user_id: str):
    role = await supabase.get_member_role(user_id)
    if role not in {"owner", "admin", "security"}: raise HTTPException(403, "Administrator or security role required")

async def _email_alert(org_id: str, title: str, message: str):
    if os.getenv("ALERT_EMAIL_ENABLED", "true").lower() != "true": return
    api_key = os.getenv("RESEND_API_KEY")
    if not api_key: return
    settings = supabase.client.table("organization_settings").select("alert_email_enabled,alert_email_recipients").eq("organization_id", org_id).maybe_single().execute().data or {}
    if not settings.get("alert_email_enabled", True): return
    recipients = settings.get("alert_email_recipients") or []
    if not recipients:
        members = supabase.client.table("organization_members").select("email").eq("organization_id", org_id).in_("role", ["owner", "admin", "security"]).eq("status", "active").execute().data or []
        recipients = [m["email"] for m in members if m.get("email")]
    if not recipients: return
    sender = os.getenv("ALERT_EMAIL_FROM", "AI Firewall <alerts@your-domain.example>")
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post("https://api.resend.com/emails", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json={"from": sender, "to": recipients, "subject": f"AI Firewall alert: {title}", "text": message})

async def emit_security_alert(org_id: str, event_type: str, title: str, message: str, severity: str = "high", metadata: Dict[str, Any] | None = None):
    if not supabase._initialized: await supabase.initialize()
    metadata = metadata or {}
    rules = supabase.client.table("alert_rules").select("*").eq("organization_id", org_id).eq("event_type", event_type).eq("is_active", True).execute().data or []
    if not rules:
        rules = supabase.client.table("alert_rules").select("*").eq("organization_id", org_id).eq("event_type", "*").eq("is_active", True).execute().data or []
    if not rules and event_type not in {"security.blocked", "security.high_risk", "security.pii"}: return
    rule = rules[0] if rules else None
    alert = supabase.client.table("security_alerts").insert({"organization_id":org_id,"rule_id":rule.get("id") if rule else None,"event_type":event_type,"severity":severity,"title":title[:200],"message":message[:2000],"metadata":metadata}).execute().data
    await _email_alert(org_id, title, message)
    await dispatch_webhook_event(org_id, event_type, {"title":title,"message":message,"severity":severity,"metadata":metadata})
    return alert[0] if alert else None

async def dispatch_webhook_event(org_id: str, event_type: str, payload: Dict[str, Any]):
    if not supabase._initialized: await supabase.initialize()
    hooks = supabase.client.table("webhook_integrations").select("*").eq("organization_id", org_id).eq("is_active", True).execute().data or []
    body = {"id":str(secrets.token_hex(16)),"type":event_type,"created_at":datetime.now(timezone.utc).isoformat(),"organization_id":org_id,"data":payload}
    for hook in hooks:
        events = hook.get("events") or []
        if events and event_type not in events and "*" not in events: continue
        delivery = supabase.client.table("webhook_deliveries").insert({"organization_id":org_id,"webhook_id":hook["id"],"event_type":event_type,"payload":body,"status":"pending","attempts":0}).execute().data
        try:
            secret = _decrypt(hook["secret_encrypted"]); raw = json.dumps(body,separators=(",",":"),ensure_ascii=False); signature = hmac.new(secret.encode(),raw.encode(),hashlib.sha256).hexdigest()
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(hook["url"],content=raw,headers={"Content-Type":"application/json","X-AI-Firewall-Event":event_type,"X-AI-Firewall-Signature":f"sha256={signature}"})
            patch={"attempts":1,"response_code":r.status_code,"status":"delivered" if 200<=r.status_code<300 else "failed","delivered_at":datetime.now(timezone.utc).isoformat() if 200<=r.status_code<300 else None,"last_error":None if 200<=r.status_code<300 else r.text[:500]}
        except Exception as exc:
            patch={"attempts":1,"status":"failed","last_error":str(exc)[:500]}
        if delivery: supabase.client.table("webhook_deliveries").update(patch).eq("id",delivery[0]["id"]).execute()

@router.get("/alerts")
async def list_alerts(status:str|None=None, limit:int=100, user_id:str=Depends(get_current_user)):
    org=await _org(user_id); q=supabase.client.table("security_alerts").select("*").eq("organization_id",org["id"]).order("created_at",desc=True).limit(min(max(limit,1),500));
    if status in {"open","acknowledged","resolved"}: q=q.eq("status",status)
    return {"alerts":q.execute().data or []}

@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id:str,payload:Dict[str,Any],user_id:str=Depends(get_current_user)):
    org=await _org(user_id); status=payload.get("status")
    if status not in {"open","acknowledged","resolved"}: raise HTTPException(400,"Invalid alert status")
    now=datetime.now(timezone.utc).isoformat(); changes={"status":status}
    if status=="acknowledged": changes["acknowledged_at"]=now
    if status=="resolved": changes["resolved_at"]=now
    r=supabase.client.table("security_alerts").update(changes).eq("id",alert_id).eq("organization_id",org["id"]).execute()
    if not r.data: raise HTTPException(404,"Alert not found")
    return {"alert":r.data[0]}

@router.get("/alert-rules")
async def list_alert_rules(user_id:str=Depends(get_current_user)):
    org=await _org(user_id); return {"rules":supabase.client.table("alert_rules").select("*").eq("organization_id",org["id"]).order("created_at").execute().data or []}

@router.post("/alert-rules")
async def create_alert_rule(payload:Dict[str,Any],user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); event=str(payload.get("event_type") or "security.blocked");
    if event not in {"security.blocked","security.high_risk","security.pii","security.suspicious","*"}: raise HTTPException(400,"Unsupported alert event")
    data={"organization_id":org["id"],"name":str(payload.get("name") or event)[:120],"event_type":event,"threshold":max(1,min(int(payload.get("threshold") or 1),100000)),"window_minutes":max(1,min(int(payload.get("window_minutes") or 15),1440)),"severity":str(payload.get("severity") or "high")[:20],"email_enabled":bool(payload.get("email_enabled",True)),"in_app_enabled":bool(payload.get("in_app_enabled",True)),"is_active":bool(payload.get("is_active",True))}; r=supabase.client.table("alert_rules").insert(data).execute(); return {"rule":r.data[0]}

@router.get("/webhooks")
async def list_webhooks(user_id:str=Depends(get_current_user)):
    org=await _org(user_id); rows=supabase.client.table("webhook_integrations").select("id,name,url,events,is_active,created_at,updated_at").eq("organization_id",org["id"]).order("created_at",desc=True).execute().data or []; return {"webhooks":rows}

@router.post("/webhooks")
async def create_webhook(payload:Dict[str,Any],user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); url=str(payload.get("url") or "").strip();
    if not url.startswith("https://"): raise HTTPException(400,"Webhook URL must use HTTPS")
    secret=str(payload.get("secret") or "").strip() or "whsec_"+secrets.token_urlsafe(32); events=payload.get("events") or ["*"]
    r=supabase.client.table("webhook_integrations").insert({"organization_id":org["id"],"name":str(payload.get("name") or "Security webhook")[:120],"url":url[:1000],"secret_encrypted":_encrypt(secret),"events":events,"is_active":True}).execute()
    if not r.data: raise HTTPException(500,"Unable to create webhook")
    return {"webhook":{k:v for k,v in r.data[0].items() if k!="secret_encrypted"},"secret":secret}

@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id:str,user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); r=supabase.client.table("webhook_integrations").delete().eq("id",webhook_id).eq("organization_id",org["id"]).execute();
    if not r.data: raise HTTPException(404,"Webhook not found")
    return {"message":"Webhook deleted"}

@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id:str,user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); hook=supabase.client.table("webhook_integrations").select("*").eq("id",webhook_id).eq("organization_id",org["id"]).maybe_single().execute().data
    if not hook: raise HTTPException(404,"Webhook not found")
    await dispatch_webhook_event(org["id"],"test.ping",{"message":"AI Firewall webhook test"}); return {"message":"Test delivery queued"}

@router.get("/analytics")
async def analytics(start:str|None=None,end:str|None=None,employee_id:str|None=None,application_id:str|None=None,action:str|None=None,search:str|None=None,limit:int=500,user_id:str=Depends(get_current_user)):
    org=await _org(user_id); q=supabase.client.table("audit_logs").select("*").eq("organization_id",org["id"]).order("timestamp",desc=True).limit(min(max(limit,1),2000))
    if start: q=q.gte("timestamp",start)
    if end: q=q.lte("timestamp",end)
    if employee_id: q=q.eq("employee_id",employee_id)
    if application_id: q=q.eq("application_id",application_id)
    if action in {"ALLOW","BLOCK"}: q=q.eq("action",action)
    rows=q.execute().data or []
    if search:
        needle=search.lower(); rows=[r for r in rows if needle in json.dumps(r,default=str).lower()]
    total=len(rows); blocked=sum(1 for r in rows if r.get("action")=="BLOCK"); costs=sum(float(r.get("cost") or 0) for r in rows); lat=[float(r["latency_ms"]) for r in rows if r.get("latency_ms") is not None]
    by_day={}
    for r in rows:
        day=str(r.get("timestamp","") or "")[:10]; by_day.setdefault(day,{"requests":0,"blocked":0,"cost":0}); by_day[day]["requests"]+=1; by_day[day]["blocked"]+=1 if r.get("action")=="BLOCK" else 0; by_day[day]["cost"]+=float(r.get("cost") or 0)
    return {"summary":{"total_requests":total,"blocked_requests":blocked,"block_rate":blocked/total*100 if total else 0,"total_cost":costs,"avg_latency_ms":sum(lat)/len(lat) if lat else 0},"timeline":[{"date":k,**v} for k,v in sorted(by_day.items())],"requests":rows}

@router.get("/audit/search")
async def audit_search(q:str|None=None,start:str|None=None,end:str|None=None,employee_id:str|None=None,application_id:str|None=None,action:str|None=None,limit:int=200,user_id:str=Depends(get_current_user)):
    data=await analytics(start,end,employee_id,application_id,action,q,limit,user_id); return {"results":data["requests"],"summary":data["summary"]}

@router.get("/audit/export")
async def audit_export(start:str|None=None,end:str|None=None,employee_id:str|None=None,application_id:str|None=None,action:str|None=None,search:str|None=None,user_id:str=Depends(get_current_user)):
    data=await analytics(start,end,employee_id,application_id,action,search,2000,user_id); rows=data["requests"]
    if not rows: return Response(content="timestamp,action,risk_score,model,cost,latency_ms,reason\n",media_type="text/csv")
    headers=["timestamp","action","risk_score","model","cost","latency_ms","reason"]; lines=[",".join(headers)]
    for r in rows:
        lines.append(",".join(json.dumps(r.get(h) if r.get(h) is not None else "",ensure_ascii=False) for h in headers))
    return Response(content="\n".join(lines),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=ai-firewall-filtered-audit.csv"})

@router.get("/retention")
async def get_retention(user_id:str=Depends(get_current_user)):
    org=await _org(user_id); row=supabase.client.table("organization_settings").select("audit_retention_days,alert_email_enabled,alert_email_recipients,updated_at").eq("organization_id",org["id"]).maybe_single().execute().data; return {"settings":row or {"audit_retention_days":365,"alert_email_enabled":True,"alert_email_recipients":[]}}

@router.patch("/retention")
async def update_retention(payload:Dict[str,Any],user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); days=max(7,min(int(payload.get("audit_retention_days") or 365),3650)); recipients=[str(x).strip().lower() for x in (payload.get("alert_email_recipients") or []) if "@" in str(x)]; r=supabase.client.table("organization_settings").upsert({"organization_id":org["id"],"audit_retention_days":days,"alert_email_enabled":bool(payload.get("alert_email_enabled",True)),"alert_email_recipients":recipients,"updated_at":datetime.now(timezone.utc).isoformat()},on_conflict="organization_id").execute(); return {"settings":r.data[0]}

@router.post("/retention/cleanup")
async def cleanup_retention(user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); result=supabase.client.rpc("cleanup_expired_audit_logs",{"target_org":org["id"]}).execute(); return {"deleted":result.data or 0}

@router.post("/api-keys/{key_id}/rotate")
async def rotate_api_key(key_id:str,payload:Dict[str,Any]|None=None,user_id:str=Depends(auth.require_owner_or_admin)):
    org=await _org(user_id); old=supabase.client.table("api_keys").select("*").eq("id",key_id).eq("organization_id",org["id"]).maybe_single().execute().data
    if not old: raise HTTPException(404,"API key not found")
    payload=payload or {}; days=max(1,min(int(payload.get("expires_days") or 30),3650)); grace=max(0,min(int(payload.get("grace_minutes") or 0),10080));
    from app.supabase_client import SupabaseManager as SM
    raw="aifw_"+secrets.token_urlsafe(32); expires=datetime.now(timezone.utc)+timedelta(days=days); grace_until=datetime.now(timezone.utc)+timedelta(minutes=grace) if grace else datetime.now(timezone.utc)
    new=supabase.client.table("api_keys").insert({"user_id":user_id,"organization_id":org["id"],"application_id":old.get("application_id"),"employee_id":old.get("employee_id"),"key_hash":SM._hash_api_key(raw),"name":(old.get("name") or "API key")+" (rotated)","is_active":True,"expires_at":expires.isoformat(),"rotated_from":old["id"],"rotation_grace_until":grace_until.isoformat(),"key_prefix":raw[:12]}).execute().data
    if not new: raise HTTPException(500,"Unable to rotate API key")
    if grace==0: supabase.client.table("api_keys").update({"is_active":False,"revoked_at":datetime.now(timezone.utc).isoformat()}).eq("id",old["id"]).execute()
    return {"key":raw,"id":new[0]["id"],"expires_at":new[0]["expires_at"],"old_key_id":old["id"],"old_key_grace_until":grace_until.isoformat() if grace else None}

@router.get("/onboarding")
async def onboarding(user_id:str=Depends(get_current_user)):
    org=await _org(user_id); p=supabase.client.table("onboarding_progress").select("*").eq("organization_id",org["id"]).maybe_single().execute().data or {"completed_steps":[]}; steps=p.get("completed_steps") or []
    checks={"organization":bool(org.get("name")),"identity":bool((supabase.client.table("identity_connections").select("id").eq("organization_id",org["id"]).limit(1).execute().data or [])),"application":bool((supabase.client.table("applications").select("id").eq("organization_id",org["id"]).limit(1).execute().data or [])),"policy":bool((supabase.client.table("security_policies").select("id").eq("organization_id",org["id"]).limit(1).execute().data or [])),"api_key":bool((supabase.client.table("api_keys").select("id").eq("organization_id",org["id"]).eq("is_active",True).limit(1).execute().data or [])),"alerts":bool((supabase.client.table("alert_rules").select("id").eq("organization_id",org["id"]).limit(1).execute().data or []))};
    done=list(dict.fromkeys(steps+[k for k,v in checks.items() if v])); return {"steps":checks,"completed_steps":done,"progress":round(sum(checks.values())/len(checks)*100)}

@router.post("/onboarding/steps/{step}")
async def complete_onboarding_step(step:str,user_id:str=Depends(get_current_user)):
    allowed={"organization","identity","application","policy","api_key","alerts"}
    if step not in allowed: raise HTTPException(400,"Unknown onboarding step")
    org=await _org(user_id); current=supabase.client.table("onboarding_progress").select("completed_steps").eq("organization_id",org["id"]).maybe_single().execute().data or {"completed_steps":[]}; steps=list(dict.fromkeys((current.get("completed_steps") or [])+[step])); r=supabase.client.table("onboarding_progress").upsert({"organization_id":org["id"],"completed_steps":steps,"updated_at":datetime.now(timezone.utc).isoformat()},on_conflict="organization_id").execute(); return {"completed_steps":steps}
