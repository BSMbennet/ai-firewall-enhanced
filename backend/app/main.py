from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Any
from datetime import datetime
import uuid, time, asyncio, os
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

from app.auth import AuthManager, get_current_user, APIKeyManager
from app.orchestrator import SecurityOrchestrator
from app.llm_router import LLMRouter
from app.supabase_client import SupabaseManager
from app.upstash_cache import UpstashCache
from app.r2_storage import CloudflareR2
from app.monitoring import BetterStackMonitor, MetricsCollector
from app.models import SecurityRequest, SecurityResponse, AuditLogResponse, HealthResponse
from app.enterprise_router import router as enterprise_router
from app.compliance_router import router as compliance_router
from app.operations_router import router as operations_router, emit_security_alert, dispatch_webhook_event

supabase_manager = SupabaseManager()
auth_manager = AuthManager()
api_key_manager = APIKeyManager()
orchestrator = SecurityOrchestrator()
llm_router = LLMRouter()
upstash_cache = UpstashCache()
r2_storage = CloudflareR2()
monitor = BetterStackMonitor()
metrics = MetricsCollector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting AI Firewall...")
    await supabase_manager.initialize()
    await upstash_cache.initialize()
    await r2_storage.initialize()
    await monitor.initialize()
    yield
    await supabase_manager.close()
    await upstash_cache.close()

app = FastAPI(title="AI Firewall Enterprise API", version="3.3.0", lifespan=lifespan)
app.include_router(enterprise_router)
app.include_router(compliance_router)
app.include_router(operations_router)

frontend_urls = os.getenv("FRONTEND_URL", "http://localhost:5173")
allowed_origins = [origin.strip().rstrip("/") for origin in frontend_urls.split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", timestamp=datetime.utcnow(), version="3.3.0", services={
        "supabase": await supabase_manager.health_check(),
        "upstash": await upstash_cache.health_check(),
        "r2": await r2_storage.health_check(),
        "llm": await llm_router.health_check(),
    })

@app.get("/ready")
async def readiness_check():
    return {"status": "ready", "version": "3.3.0"}

@app.get("/v1/organization")
async def get_organization(current_user: str = Depends(get_current_user)):
    org = await supabase_manager.get_organization_for_user(current_user)
    if not org: org = await supabase_manager.ensure_organization(current_user)
    return org

@app.get("/v1/organization/members")
async def get_members(current_user: str = Depends(auth_manager.require_admin)):
    return {"members": await supabase_manager.list_members(current_user)}

@app.post("/v1/organization/members")
async def invite_member(payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    try:
        member = await supabase_manager.invite_member(current_user, str(payload.get("email") or ""), str(payload.get("full_name") or ""), str(payload.get("role") or "member"))
        return {"member": member, "message": "Employee invitation sent"}
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        print(f"Employee invitation failed: {exc}"); raise HTTPException(status_code=502, detail="Unable to invite employee")

@app.patch("/v1/organization/members/{member_id}")
async def update_member(member_id: str, payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    member = await supabase_manager.update_member(current_user, member_id, payload.get("status"), payload.get("role"))
    if not member: raise HTTPException(status_code=404, detail="Employee not found")
    return {"member": member}

@app.get("/v1/organization/applications")
async def get_applications(current_user: str = Depends(get_current_user)):
    return {"applications": await supabase_manager.list_applications(current_user)}

@app.post("/v1/organization/applications")
async def create_application(payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    name = str(payload.get("name") or "New AI Application").strip()
    if not name: raise HTTPException(status_code=400, detail="Application name is required")
    return {"application": await supabase_manager.create_application(current_user, name, str(payload.get("environment") or "production"), str(payload.get("provider") or "openai"), str(payload.get("model") or "gpt-4o-mini"))}

@app.patch("/v1/organization/applications/{application_id}")
async def update_application(application_id: str, payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    application = await supabase_manager.update_application(current_user, application_id, payload.get("status"), payload.get("model"))
    if not application: raise HTTPException(status_code=404, detail="Application not found")
    return {"application": application}

@app.get("/v1/organization/policies")
async def get_policies(current_user: str = Depends(get_current_user)):
    return {"policies": await supabase_manager.list_policies(current_user)}

@app.patch("/v1/organization/policies/{policy_id}")
async def update_policy(policy_id: str, payload: Dict[str, Any], current_user: str = Depends(get_current_user)):
    policy = await supabase_manager.update_policy(current_user, policy_id, payload)
    if not policy: raise HTTPException(status_code=404, detail="Policy not found")
    return {"policy": policy}

@app.get("/v1/organization/stats")
async def get_org_stats(current_user: str = Depends(get_current_user)):
    return await supabase_manager.get_org_stats(current_user)

@app.get("/v1/organization/activity")
async def get_org_activity(limit: int = 50, current_user: str = Depends(get_current_user)):
    return {"activity": await supabase_manager.get_org_activity(current_user, min(max(limit, 1), 200))}

@app.post("/v1/api-keys")
async def create_api_key(payload: Dict[str, Any] | None = None, current_user: str = Depends(auth_manager.require_admin)):
    payload = payload or {}; name = str(payload.get("name") or "Default Key")[:100]; expires_days = max(1, min(int(payload.get("expires_days") or 30), 3650)); application_id = payload.get("application_id") or None; employee_id = payload.get("employee_id") or None
    api_key = await api_key_manager.create_api_key(current_user, name=name, expires_days=expires_days, application_id=application_id, employee_id=employee_id)
    if not api_key: raise HTTPException(status_code=500, detail="Failed to create API key")
    return {"key": api_key["key"], "id": api_key["id"], "name": api_key.get("name"), "user_id": current_user, "application_id": api_key.get("application_id"), "employee_id": api_key.get("employee_id"), "is_active": api_key.get("is_active", True), "expires_at": api_key.get("expires_at"), "created_at": api_key.get("created_at")}

@app.get("/v1/api-keys")
async def list_api_keys(current_user: str = Depends(get_current_user)):
    return {"keys": await api_key_manager.list_keys(current_user)}

@app.delete("/v1/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: str = Depends(auth_manager.require_admin)):
    await api_key_manager.revoke_key(key_id, current_user); return {"message": "API key revoked"}

async def run_firewall_pipeline(prompt: str, model: str, max_tokens: int, temperature: float, user_id: str, request_id: str, gateway_context: Dict[str, Any] | None = None):
    start_time = time.time(); gateway_context = gateway_context or {}
    if not prompt or not prompt.strip(): raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    if len(prompt) > 4000: raise HTTPException(status_code=400, detail="Prompt exceeds the 4000 character limit")
    input_validation = await orchestrator.validate_input(prompt=prompt, max_length=4000, allowed_languages=["en"])
    if not input_validation["valid"]: raise HTTPException(status_code=400, detail=input_validation["error"])
    security_result = await orchestrator.validate_request_parallel(prompt=prompt, context={}, user_id=user_id, request_id=request_id)
    org_id = gateway_context.get("organization_id"); app_id = gateway_context.get("application_id"); employee_id = gateway_context.get("employee_id"); event_base = {"user_id": user_id, "organization_id": org_id, "application_id": app_id, "employee_id": employee_id}
    await supabase_manager.log_security_event({**event_base, "event_type": "security_validation", "severity": "high" if security_result.decision == "BLOCK" else "low", "risk_score": security_result.risk_score, "details": {"reason": security_result.reason, "request_id": request_id}})
    if org_id:
        event_type = "security.blocked" if security_result.decision == "BLOCK" else ("security.pii" if security_result.pii_detected else ("security.high_risk" if security_result.risk_score >= 70 else "security.allowed"))
        await dispatch_webhook_event(org_id, event_type, {"request_id":request_id,"user_id":user_id,"application_id":app_id,"employee_id":employee_id,"risk_score":security_result.risk_score,"reason":security_result.reason,"pii_detected":security_result.pii_detected,"model":model})
        if event_type in {"security.blocked","security.high_risk","security.pii"}:
            title = "AI request blocked" if event_type == "security.blocked" else ("High-risk AI request detected" if event_type == "security.high_risk" else "PII detected in AI request")
            await emit_security_alert(org_id, event_type, title, f"Request {request_id} triggered {event_type}. Risk score: {security_result.risk_score}. {security_result.reason or ''}", "critical" if event_type == "security.blocked" else "high", {"request_id":request_id,"application_id":app_id,"employee_id":employee_id,"risk_score":security_result.risk_score})
    if security_result.decision == "BLOCK":
        latency_ms = (time.time() - start_time) * 1000
        await supabase_manager.log_audit({**event_base, "request_id": request_id, "action": "BLOCK", "risk_score": security_result.risk_score, "tokens_used": {}, "latency_ms": latency_ms, "model": model, "cost": 0, "reason": security_result.reason, "metadata": {"gateway": True}})
        return {"blocked": True, "response": None, "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}, "risk_score": security_result.risk_score, "reason": security_result.reason}
    sanitized_prompt = await orchestrator.sanitize_prompt(prompt, redact_pii=security_result.pii_detected); guarded_prompt = await orchestrator.apply_prompt_guard(sanitized_prompt, context={}); llm_response = await llm_router.route(prompt=guarded_prompt, model=model, max_tokens=max_tokens, temperature=temperature, request_id=request_id)
    if llm_response.get("error"): raise HTTPException(status_code=502, detail="AI provider unavailable")
    filtered_response = await orchestrator.filter_response(llm_response=llm_response, prevent_data_leakage=True, block_harmful_content=True); latency_ms = (time.time() - start_time) * 1000
    await supabase_manager.log_audit({**event_base, "request_id": request_id, "action": "ALLOW", "risk_score": security_result.risk_score, "tokens_used": llm_response.get("usage", {}), "latency_ms": latency_ms, "model": model, "cost": llm_response.get("cost", 0), "metadata": {"gateway": True, "sanitized": security_result.pii_redacted, "guard_applied": True}})
    return {"blocked": False, "response": filtered_response["content"], "usage": llm_response.get("usage", {}), "risk_score": security_result.risk_score, "reason": security_result.reason}

@app.post("/v1/chat/completions")
async def chat_completions(payload: Dict[str, Any], key_data: Dict = Depends(api_key_manager.verify_api_key_context)):
    if key_data.get("organization_id") and key_data.get("application_id"):
        app_row = await supabase_manager.client.table("applications").select("status,model").eq("id", key_data["application_id"]).eq("organization_id", key_data["organization_id"]).maybe_single().execute()
        if not app_row.data or app_row.data.get("status") != "active": raise HTTPException(status_code=403, detail="Application is disabled")
    messages = payload.get("messages") or []
    if not isinstance(messages, list) or not messages: raise HTTPException(status_code=400, detail="messages must be a non-empty array")
    user_messages = [str(message.get("content", "")) for message in messages if isinstance(message, dict) and message.get("role") == "user"]; prompt = "\n".join(message for message in user_messages if message.strip())
    if not prompt: raise HTTPException(status_code=400, detail="At least one user message is required")
    model = str(payload.get("model") or "gpt-4o-mini"); max_tokens = max(1, min(int(payload.get("max_tokens") or 1000), 4000)); temperature = float(payload.get("temperature") if payload.get("temperature") is not None else 0.7); temperature = max(0, min(temperature, 2)); request_id = str(uuid.uuid4())
    result = await run_firewall_pipeline(prompt, model, max_tokens, temperature, key_data["user_id"], request_id, key_data)
    if result["blocked"]: return JSONResponse(status_code=403, content={"error":{"message":"Request blocked by AI Firewall security policy","type":"firewall_blocked","code":"security_policy","risk_score":result["risk_score"],"reason":result["reason"]},"request_id":request_id})
    return {"id":request_id,"object":"chat.completion","created":int(time.time()),"model":model,"choices":[{"index":0,"message":{"role":"assistant","content":result["response"]},"finish_reason":"stop"}],"usage":result["usage"],"firewall":{"risk_score":result["risk_score"]}}

@app.post("/v1/secure-ai/query", response_model=SecurityResponse)
async def secure_query(request: SecurityRequest, background_tasks: BackgroundTasks, current_user: str = Depends(get_current_user), http_request: Request = None):
    request_id = str(uuid.uuid4()); result = await run_firewall_pipeline(request.prompt, request.model.value if hasattr(request.model,"value") else str(request.model), request.max_tokens or 1000, request.temperature if request.temperature is not None else 0.7, current_user, request_id)
    if result["blocked"]: return SecurityResponse(request_id=request_id, allowed=False, blocked=True, message="Request blocked by security policy", risk_score=result["risk_score"], reason=result["reason"], timestamp=datetime.utcnow())
    return SecurityResponse(request_id=request_id, allowed=True, blocked=False, response=result["response"], usage=result["usage"], risk_score=result["risk_score"], security_metadata={"gateway":True}, timestamp=datetime.utcnow())

@app.post("/v1/secure-ai/batch")
async def batch_secure_query(requests: List[SecurityRequest], current_user: str = Depends(get_current_user)):
    tasks=[secure_query(req,BackgroundTasks(),current_user,None) for req in requests]; return {"results":await asyncio.gather(*tasks,return_exceptions=True)}

@app.get("/v1/dashboard/stats")
async def get_dashboard_stats(current_user: str = Depends(get_current_user)): return await supabase_manager.get_org_stats(current_user)
@app.get("/v1/dashboard/recent-requests")
async def get_recent_requests(limit:int=50,current_user:str=Depends(get_current_user)): return {"requests":await supabase_manager.get_org_activity(current_user,limit)}
@app.get("/v1/dashboard/threat-timeline")
async def get_threat_timeline(days:int=7,current_user:str=Depends(get_current_user)): return {"timeline":await supabase_manager.get_threat_timeline(current_user,days)}
@app.get("/v1/admin/logs",response_model=List[AuditLogResponse])
async def get_audit_logs(limit:int=100,offset:int=0,user_id:str=None,current_user:str=Depends(get_current_user),is_admin:bool=Depends(auth_manager.require_admin)): return await supabase_manager.get_logs(limit,offset,user_id)
@app.exception_handler(HTTPException)
async def http_exception_handler(request,exc): return JSONResponse(status_code=exc.status_code,content={"error":exc.detail,"timestamp":datetime.utcnow().isoformat()})
