from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Any, Dict, List
from datetime import datetime
import logging, uuid, time, os
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

from app.audit import record_event, verify_chain
from app.auth import AuthManager, get_current_user, APIKeyManager
from app.gateway import GatewayError, effective_rate_limit, enforce_model_policy, parse_chat_payload
from app.limits import IPRateLimitMiddleware, UpstashStore, env_int, lifecycle_limit, rate_limiter
from app.orchestrator import InspectionUnavailable, SecurityOrchestrator
from app.llm_router import LLMRouter, ProviderError
from app.policy import effective_protections
from app.supabase_client import SupabaseManager
from app.upstash_cache import UpstashCache
from app.r2_storage import CloudflareR2
from app.monitoring import BetterStackMonitor, MetricsCollector
from app.models import SecurityRequest, SecurityResponse, AuditLogResponse, HealthResponse
from app.enterprise_router import router as enterprise_router
from app.compliance_router import router as compliance_router
from app.operations_router import router as operations_router, emit_security_alert, dispatch_webhook_event
from app.email_service import email_service
from app.observability import RequestContextMiddleware, configure_logging, current_request_id, enforce_startup_config, validate_environment

configure_logging()
logger = logging.getLogger("aifirewall.main")

supabase_manager = SupabaseManager()
auth_manager = AuthManager()
api_key_manager = APIKeyManager()
orchestrator = SecurityOrchestrator()
llm_router = LLMRouter()
upstash_cache = UpstashCache()
r2_storage = CloudflareR2()
monitor = BetterStackMonitor()
metrics = MetricsCollector()
rate_limiter.primary = UpstashStore(lambda: upstash_cache.client)

@asynccontextmanager
async def lifespan(app: FastAPI):
    enforce_startup_config(logger=logger)
    logger.info("Starting AI Firewall")
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

# ---------------------------------------------------------
# Secure CORS configuration
# ---------------------------------------------------------

frontend_urls = os.getenv(
    "FRONTEND_URL",
    "http://localhost:5173",
)

allowed_origins = [
    origin.strip().rstrip("/")
    for origin in frontend_urls.split(",")
    if origin.strip()
]

cors_kwargs = {
    "allow_origins": allowed_origins,
    "allow_credentials": True,
    "allow_methods": [
        "GET",
        "POST",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    "allow_headers": [
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-API-Key",
        "X-Request-ID",
    ],
    "expose_headers": ["X-Request-ID"],
}

# Optional regex support.
# Keep FRONTEND_ORIGIN_REGEX empty in production unless required.
frontend_origin_regex = os.getenv(
    "FRONTEND_ORIGIN_REGEX",
    "",
).strip()

if frontend_origin_regex:
    cors_kwargs["allow_origin_regex"] = frontend_origin_regex

# Innermost of the three: runs after CORS (so browsers can read a 429) and before authentication or any database work.
app.add_middleware(IPRateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    **cors_kwargs,
)
# Added last so it is the outermost layer: every response (including CORS pre-flights and errors) carries X-Request-ID.
app.add_middleware(RequestContextMiddleware)

@app.get("/")
async def root(): return {"service": "AI Firewall Enterprise API", "status": "online", "docs": "/docs"}

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Liveness plus dependency state. Never performs a billable provider call."""
    database_ok = await supabase_manager.health_check()
    services = {"supabase": database_ok, "upstash": await upstash_cache.health_check(), "r2": await r2_storage.health_check(),
                "llm": llm_router.provider_status()}
    return HealthResponse(status="healthy" if database_ok else "degraded", timestamp=datetime.utcnow(), version="3.3.0", services=services)

@app.get("/ready")
async def readiness_check():
    """Readiness for traffic. Reports only check names and booleans - never configuration values."""
    checks = {"database": await supabase_manager.health_check(), "config": validate_environment().ok}
    if not all(checks.values()):
        return JSONResponse(status_code=503, content={"status": "not_ready", "version": "3.3.0", "checks": checks})
    return {"status": "ready", "version": "3.3.0", "checks": checks}

@app.get("/v1/organization")
async def get_organization(current_user: str = Depends(get_current_user)):
    org = await supabase_manager.get_organization_for_user(current_user)
    if not org: org = await supabase_manager.ensure_organization(current_user)
    return org

@app.get("/v1/organization/members")
async def get_members(current_user: str = Depends(auth_manager.require_admin)):
    return {"members": await supabase_manager.list_members(current_user)}

async def _org_id_for(user_id: str) -> str | None:
    org = await supabase_manager.get_organization_for_user(user_id)
    return org["id"] if org else None

@app.post("/v1/organization/members", dependencies=[Depends(lifecycle_limit("member_invite", 20, 600))])
async def invite_member(payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    email = str(payload.get("email") or "").strip().lower(); full_name = str(payload.get("full_name") or "").strip(); role = str(payload.get("role") or "member")
    try:
        member = await supabase_manager.invite_member(current_user, email, full_name, role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        logger.error("employee_invitation_failed", exc_info=True)
        raise HTTPException(status_code=502, detail="Unable to invite employee")
    org = await supabase_manager.get_organization_for_user(current_user) or {}
    await record_event(supabase_manager, organization_id=org.get("id"), actor_user_id=current_user, action="member.invited", resource_type="member", resource_id=member.get("id") or member.get("user_id"), metadata={"role": role})
    try:
        email_result = await email_service.send_employee_invitation(email=email, full_name=full_name, organization_name=org.get("name") or "your organization", role=role)
    except Exception:
        logger.error("employee_invitation_email_failed", exc_info=True)
        email_result = {"sent": False, "error": "Invitation email could not be sent"}
    return {"member": member, "message": "Employee invitation created", "email": email_result}

@app.patch("/v1/organization/members/{member_id}")
async def update_member(member_id: str, payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    try:
        member = await supabase_manager.update_member(current_user, member_id, payload.get("status"), payload.get("role"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not member: raise HTTPException(status_code=404, detail="Employee not found")
    await record_event(supabase_manager, organization_id=member.get("organization_id"), actor_user_id=current_user, action="member.updated", resource_type="member", resource_id=member_id, outcome="success" if member.get("auth_sync") != "failed" else "partial", metadata={"status": payload.get("status"), "role": payload.get("role"), "auth_sync": member.get("auth_sync")})
    return {"member": member}

@app.get("/v1/organization/applications")
async def get_applications(current_user: str = Depends(get_current_user)):
    return {"applications": await supabase_manager.list_applications(current_user)}

@app.post("/v1/organization/applications")
async def create_application(payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    name = str(payload.get("name") or "New AI Application").strip()
    if not name: raise HTTPException(status_code=400, detail="Application name is required")
    application = await supabase_manager.create_application(current_user, name, str(payload.get("environment") or "production"), str(payload.get("provider") or "openai"), str(payload.get("model") or "gpt-4o-mini"))
    await record_event(supabase_manager, organization_id=application.get("organization_id"), actor_user_id=current_user, action="application.created", resource_type="application", resource_id=application.get("id"))
    return {"application": application}

@app.patch("/v1/organization/applications/{application_id}")
async def update_application(application_id: str, payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    application = await supabase_manager.update_application(current_user, application_id, payload.get("status"), payload.get("model"))
    if not application: raise HTTPException(status_code=404, detail="Application not found")
    await record_event(supabase_manager, organization_id=application.get("organization_id"), actor_user_id=current_user, action="application.updated", resource_type="application", resource_id=application_id, metadata={"status": payload.get("status"), "model": payload.get("model")})
    return {"application": application}

@app.get("/v1/organization/policies")
async def get_policies(current_user: str = Depends(get_current_user)):
    return {"policies": await supabase_manager.list_policies(current_user)}

@app.patch("/v1/organization/policies/{policy_id}")
async def update_policy(policy_id: str, payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_security)):
    try:
        policy = await supabase_manager.update_policy(current_user, policy_id, payload)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid policy values")
    if not policy: raise HTTPException(status_code=404, detail="Policy not found")
    await record_event(supabase_manager, organization_id=policy.get("organization_id"), actor_user_id=current_user, action="policy.updated", resource_type="security_policy", resource_id=policy_id, metadata={"fields": sorted(k for k in payload if k != "id")})
    return {"policy": policy}

@app.get("/v1/organization/stats")
async def get_org_stats(current_user: str = Depends(get_current_user)):
    return await supabase_manager.get_org_stats(current_user)

@app.get("/v1/organization/activity")
async def get_org_activity(limit: int = 50, current_user: str = Depends(auth_manager.require_audit_reader)):
    return {"activity": await supabase_manager.get_org_activity(current_user, min(max(limit, 1), 200))}

@app.post("/v1/api-keys", dependencies=[Depends(lifecycle_limit("api_key_create", 10, 600))])
async def create_api_key(payload: Dict[str, Any] | None = None, current_user: str = Depends(auth_manager.require_admin)):
    payload = payload or {}; name = str(payload.get("name") or "Default Key")[:100]
    try:
        expires_days = max(1, min(int(payload.get("expires_days") or 30), 3650))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="expires_days must be an integer")
    scopes = payload.get("scopes")
    if scopes is not None and (not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes)):
        raise HTTPException(status_code=400, detail="scopes must be an array of strings")
    application_id = payload.get("application_id") or None; employee_id = payload.get("employee_id") or None
    organization_id = await _org_id_for(current_user)
    # Never trust client-supplied identifiers: bound resources must belong to the caller's organization.
    if organization_id and application_id and not supabase_manager.client.table("applications").select("id").eq("id", application_id).eq("organization_id", organization_id).maybe_single().execute().data:
        raise HTTPException(status_code=404, detail="Application not found")
    if organization_id and employee_id and not supabase_manager.client.table("organization_members").select("id").eq("id", employee_id).eq("organization_id", organization_id).maybe_single().execute().data:
        raise HTTPException(status_code=404, detail="Employee not found")
    try:
        api_key = await api_key_manager.create_api_key(current_user, name=name, expires_days=expires_days, application_id=application_id, employee_id=employee_id, scopes=scopes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not api_key: raise HTTPException(status_code=500, detail="Failed to create API key")
    await record_event(supabase_manager, organization_id=api_key.get("organization_id"), actor_user_id=current_user, action="api_key.created", resource_type="api_key", resource_id=api_key.get("id"), metadata={"scopes": api_key.get("scopes"), "application_id": application_id, "employee_id": employee_id, "expires_at": api_key.get("expires_at")})
    return {"key": api_key["key"], "id": api_key["id"], "name": api_key.get("name"), "user_id": current_user, "application_id": api_key.get("application_id"), "employee_id": api_key.get("employee_id"), "scopes": api_key.get("scopes"), "is_active": api_key.get("is_active", True), "expires_at": api_key.get("expires_at"), "created_at": api_key.get("created_at")}

@app.get("/v1/api-keys")
async def list_api_keys(current_user: str = Depends(get_current_user)):
    return {"keys": await api_key_manager.supabase.list_api_keys(current_user)}

@app.delete("/v1/api-keys/{key_id}", dependencies=[Depends(lifecycle_limit("api_key_revoke", 30, 600))])
async def revoke_api_key(key_id: str, current_user: str = Depends(auth_manager.require_admin)):
    organization_id = await _org_id_for(current_user)
    if not await api_key_manager.revoke_key(key_id, current_user):
        raise HTTPException(status_code=404, detail="API key not found")
    await record_event(supabase_manager, organization_id=organization_id, actor_user_id=current_user, action="api_key.revoked", resource_type="api_key", resource_id=key_id)
    return {"message": "API key revoked"}

# ---------------------------------------------------------------------------
# AI gateway
# ---------------------------------------------------------------------------

async def _safely(label: str, coroutine):
    """Run a non-critical side effect (alerts, webhooks, telemetry); log failures instead of failing the request."""
    try:
        return await coroutine
    except Exception:
        logger.error("%s_failed", label, exc_info=True)
        return None

async def _load_policies(organization_id: str | None) -> list:
    if not organization_id:
        return []
    return supabase_manager.client.table("security_policies").select("*").eq("organization_id", organization_id).execute().data or []

async def run_firewall_pipeline(prompt: str, model: str, max_tokens: int, temperature: float, user_id: str, request_id: str, gateway_context: Dict[str, Any] | None = None, messages: list | None = None, policies: list | None = None):
    """Inspect -> decide -> (audit) -> forward -> filter -> record.

    Returns a dict with ``decision`` of BLOCK, REVIEW or ALLOW. Only ALLOW is ever sent to a provider. If
    inspection or the pre-forward audit write fails the request is refused (fail closed) with a GatewayError.
    """
    start_time = time.time(); ctx = gateway_context or {}
    org_id = ctx.get("organization_id"); app_id = ctx.get("application_id"); employee_id = ctx.get("employee_id")
    event_base = {"user_id": user_id, "organization_id": org_id, "application_id": app_id, "employee_id": employee_id}
    elapsed = lambda: (time.time() - start_time) * 1000
    protections = effective_protections(policies or [])
    messages = messages or [{"role": "user", "content": prompt}]

    try:
        security_result = await orchestrator.validate_request_parallel(prompt=prompt, context={}, user_id=user_id, request_id=request_id, protections=protections)
    except InspectionUnavailable:
        await _safely("audit_log", supabase_manager.log_audit({**event_base, "request_id": request_id, "action": "BLOCK", "risk_score": None, "tokens_used": {}, "latency_ms": elapsed(), "model": model, "cost": 0, "reason": "inspection_unavailable", "metadata": {"gateway": True, "fail_closed": True}}))
        await api_key_manager.record_gateway_outcome(ctx, blocked=True)
        raise GatewayError(503, "inspection_unavailable", "Security inspection is temporarily unavailable. The request was not forwarded.", "service_unavailable")

    decision = security_result.decision
    await _safely("security_event_log", supabase_manager.log_security_event({**event_base, "event_type": "security_validation", "severity": "high" if decision == "BLOCK" else "low", "risk_score": security_result.risk_score, "details": {"reason": security_result.reason, "request_id": request_id, "decision": decision}}))
    if org_id:
        event_type = "security.blocked" if decision == "BLOCK" else ("security.pii" if security_result.pii_detected else ("security.high_risk" if security_result.risk_score >= 70 or decision == "REVIEW" else "security.allowed"))
        await _safely("webhook_dispatch", dispatch_webhook_event(org_id, event_type, {"request_id": request_id, "user_id": user_id, "application_id": app_id, "employee_id": employee_id, "risk_score": security_result.risk_score, "reason": security_result.reason, "pii_detected": security_result.pii_detected, "model": model, "decision": decision}))
        if event_type in {"security.blocked", "security.high_risk", "security.pii"}:
            title = "AI request blocked" if event_type == "security.blocked" else ("High-risk AI request detected" if event_type == "security.high_risk" else "PII detected in AI request")
            await _safely("security_alert", emit_security_alert(org_id, event_type, title, f"Request {request_id} triggered {event_type}. Risk score: {security_result.risk_score}. {security_result.reason or ''}", "critical" if event_type == "security.blocked" else "high", {"request_id": request_id, "application_id": app_id, "employee_id": employee_id, "risk_score": security_result.risk_score}))

    if decision in {"BLOCK", "REVIEW"}:
        await _safely("audit_log", supabase_manager.log_audit({**event_base, "request_id": request_id, "action": decision, "risk_score": security_result.risk_score, "tokens_used": {}, "latency_ms": elapsed(), "model": model, "cost": 0, "reason": security_result.reason, "metadata": {"gateway": True}}))
        await api_key_manager.record_gateway_outcome(ctx, blocked=True)
        return {"decision": decision, "response": None, "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}, "risk_score": security_result.risk_score, "reason": security_result.reason}

    # ALLOW: the decision is recorded *before* anything leaves the platform. If it cannot be recorded the
    # request is refused, so no traffic is ever forwarded without an audit record.
    try:
        audit_row = await supabase_manager.log_audit({**event_base, "request_id": request_id, "action": "ALLOW", "risk_score": security_result.risk_score, "tokens_used": {}, "latency_ms": 0, "model": model, "cost": 0, "metadata": {"gateway": True, "sanitized": security_result.pii_detected, "guard_applied": True}})
        if not audit_row: raise RuntimeError("audit row was not created")
    except Exception:
        logger.error("audit_precommit_failed request_id=%s", request_id, exc_info=True)
        raise GatewayError(503, "audit_unavailable", "The request could not be recorded and was not forwarded.", "service_unavailable")

    async def finalize(patch: Dict[str, Any]):
        await _safely("audit_update", _update_audit(audit_row["id"], patch))

    outbound = orchestrator.build_messages(messages, redact_pii=protections.pii and security_result.pii_detected)
    try:
        llm_response = await llm_router.route(prompt=outbound[-1]["content"], messages=outbound, model=model, max_tokens=max_tokens, temperature=temperature, request_id=request_id)
        filtered_response = await orchestrator.filter_response(llm_response=llm_response, prevent_data_leakage=protections.sensitive_content, block_harmful_content=protections.sensitive_content)
        content = filtered_response["choices"][0]["message"]["content"]
    except ProviderError as exc:
        logger.error("provider_call_failed request_id=%s model=%s provider=%s code=%s", request_id, model, exc.provider, exc.code)
        await finalize({"latency_ms": elapsed(), "reason": f"provider_{exc.code}", "metadata": {"gateway": True, "provider_error": True, "provider_code": exc.code, "provider_status": exc.status}})
        raise _provider_gateway_error(exc)
    except Exception:
        logger.error("provider_call_failed request_id=%s model=%s", request_id, model, exc_info=True)
        await finalize({"latency_ms": elapsed(), "reason": "provider_error", "metadata": {"gateway": True, "provider_error": True}})
        raise GatewayError(502, "provider_unavailable", "The AI provider is unavailable", "provider_error")
    usage = llm_response.get("usage", {})
    await finalize({"latency_ms": elapsed(), "tokens_used": usage, "cost": llm_response.get("cost") or 0})
    await api_key_manager.record_gateway_outcome(ctx, blocked=False, tokens=usage.get("total_tokens", 0))
    return {"decision": "ALLOW", "response": content, "usage": usage, "risk_score": security_result.risk_score, "reason": security_result.reason}

def _provider_gateway_error(exc: ProviderError) -> GatewayError:
    if exc.code == "timeout":
        return GatewayError(504, "provider_timeout", "The AI provider did not respond in time", "provider_error")
    if exc.code == "rate_limited":
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        return GatewayError(429, "provider_rate_limited", "The AI provider is rate limiting requests. Retry later.", "rate_limit_error", headers=headers)
    if exc.code == "not_configured":
        return GatewayError(503, "provider_not_configured", "The requested provider is not configured on this gateway", "service_unavailable")
    return GatewayError(502, "provider_unavailable", "The AI provider is unavailable", "provider_error")

async def _update_audit(audit_id: str, patch: Dict[str, Any]):
    supabase_manager.client.table("audit_logs").update(patch).eq("id", audit_id).execute()

async def _enforce_rate_limits(ctx: Dict[str, Any], policies: list, request_id: str, principal_id: str):
    """Per-principal then per-organisation limits. Runs before quota metering so rejected requests are not billed.

    Returns the principal's Decision (used for X-RateLimit-* headers) or raises GatewayError(429)."""
    org_id = ctx.get("organization_id")
    checks = [("gw_principal", principal_id, effective_rate_limit(policies, env_int("GATEWAY_RATE_LIMIT_PER_MINUTE", 60)))]
    if org_id:
        checks.append(("gw_org", str(org_id), env_int("GATEWAY_ORG_RATE_LIMIT_PER_MINUTE", 600)))
    first = None
    for scope, identifier, limit in checks:
        decision = await rate_limiter.check(scope, identifier, limit, 60)
        first = first or decision
        if not decision.allowed:
            if decision.first_rejection:  # one audit event per window, so a flood cannot also flood the audit table
                await _safely("rate_limit_audit", record_event(supabase_manager, organization_id=org_id, actor_user_id=ctx.get("user_id"), action="rate_limit.exceeded", resource_type=scope, resource_id=identifier, outcome="denied", request_id=request_id, metadata={"limit": limit, "window_seconds": 60}))
            raise GatewayError(429, "rate_limit_exceeded", "Rate limit exceeded. Retry after the interval in the Retry-After header.", "rate_limit_error", headers=decision.headers())
    return first

@app.post("/v1/chat/completions")
async def chat_completions(payload: Dict[str, Any], response: Response, key_data: Dict = Depends(api_key_manager.verify_api_key_context)):
    request_id = current_request_id() or str(uuid.uuid4())
    try:
        policies = await _load_policies(key_data.get("organization_id"))
        # Rate limiting precedes payload parsing so malformed floods are throttled too, and quota metering so
        # throttled requests are never counted against the monthly allowance.
        decision = await _enforce_rate_limits(key_data, policies, request_id, str(key_data.get("id") or key_data["user_id"]))
        chat_request = parse_chat_payload(payload)
        enforce_model_policy(chat_request.model, policies)
        await api_key_manager.enforce_usage(key_data)  # count the request only once it is valid and permitted
        result = await run_firewall_pipeline(chat_request.prompt, chat_request.model, chat_request.max_tokens, chat_request.temperature, key_data["user_id"], request_id, key_data, messages=list(chat_request.messages), policies=policies)
    except GatewayError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.body(request_id), headers=exc.headers)
    if decision:
        response.headers.update({k: v for k, v in decision.headers().items() if k.startswith("X-RateLimit")})
    if result["decision"] == "BLOCK":
        return JSONResponse(status_code=403, content={"error": {"message": "Request blocked by AI Firewall security policy", "type": "firewall_blocked", "code": "security_policy", "risk_score": result["risk_score"], "reason": result["reason"]}, "request_id": request_id})
    if result["decision"] == "REVIEW":
        return JSONResponse(status_code=403, content={"error": {"message": "Request held for security review and was not forwarded", "type": "firewall_review", "code": "review_required", "risk_score": result["risk_score"]}, "request_id": request_id})
    return {"id": request_id, "object": "chat.completion", "created": int(time.time()), "model": chat_request.model, "choices": [{"index": 0, "message": {"role": "assistant", "content": result["response"]}, "finish_reason": "stop"}], "usage": result["usage"], "firewall": {"risk_score": result["risk_score"]}}

@app.post("/v1/secure-ai/query", response_model=SecurityResponse)
async def secure_query(request: SecurityRequest, current_user: str = Depends(auth_manager.require_ai_user)):
    """Interactive query with a user session. Subject to the same policy, quota and audit controls as the gateway."""
    request_id = current_request_id() or str(uuid.uuid4()); model = request.model.value if hasattr(request.model, "value") else str(request.model)
    org = await supabase_manager.get_organization_for_user(current_user)
    if not org: raise HTTPException(status_code=404, detail="Organization not found")
    member = supabase_manager.client.table("organization_members").select("id").eq("organization_id", org["id"]).eq("user_id", current_user).maybe_single().execute().data
    context = {"user_id": current_user, "organization_id": org["id"], "application_id": None, "employee_id": (member or {}).get("id")}
    try:
        policies = await _load_policies(org["id"])
        await _enforce_rate_limits(context, policies, request_id, current_user)
        enforce_model_policy(model, policies)
        await api_key_manager.enforce_usage(context)
        result = await run_firewall_pipeline(request.prompt, model, request.max_tokens or 1000, request.temperature if request.temperature is not None else 0.7, current_user, request_id, context, policies=policies)
    except GatewayError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message, headers=exc.headers)
    if result["decision"] == "BLOCK": return SecurityResponse(request_id=request_id, allowed=False, blocked=True, message="Request blocked by security policy", risk_score=result["risk_score"], reason=result["reason"], timestamp=datetime.utcnow())
    if result["decision"] == "REVIEW": return SecurityResponse(request_id=request_id, allowed=False, blocked=False, message="Request held for security review", risk_score=result["risk_score"], reason=result["reason"], timestamp=datetime.utcnow())
    return SecurityResponse(request_id=request_id, allowed=True, blocked=False, response=result["response"], usage=result["usage"], risk_score=result["risk_score"], security_metadata={"gateway": True}, timestamp=datetime.utcnow())

@app.get("/v1/audit/verify")
async def verify_audit_chain(current_user: str = Depends(auth_manager.require_audit_reader)):
    """Re-computes the organisation's audit hash chain. ok=false means an event was edited, removed or reordered."""
    org = await supabase_manager.get_organization_for_user(current_user)
    if not org: raise HTTPException(status_code=404, detail="Organization not found")
    rows = supabase_manager.client.table("audit_events").select("*").eq("organization_id", org["id"]).order("created_at").limit(5000).execute().data or []
    return {**verify_chain(rows), "events_examined": len(rows), "truncated": len(rows) >= 5000}

@app.get("/v1/email/status")
async def email_status(current_user: str = Depends(auth_manager.require_admin)):
    return {"configured": email_service.enabled, "from": email_service.from_email, "provider": "resend"}

@app.post("/v1/email/test")
async def send_test_email(payload: Dict[str, Any], current_user: str = Depends(auth_manager.require_admin)):
    recipient = str(payload.get("to") or "").strip().lower()
    if not recipient or "@" not in recipient: raise HTTPException(status_code=400, detail="A valid recipient email is required")
    result = await email_service.send(to=recipient, subject="AI Firewall email integration test", html="<h2>AI Firewall + Resend is connected.</h2><p>This is a test email from your AI Firewall backend.</p>", text="AI Firewall + Resend is connected. This is a test email from your AI Firewall backend.")
    if not result.get("sent") and not result.get("skipped"): raise HTTPException(status_code=502, detail=result.get("error") or "Email could not be sent")
    return result

@app.get("/v1/dashboard/stats")
async def get_dashboard_stats(current_user: str = Depends(get_current_user)): return await supabase_manager.get_org_stats(current_user)
@app.get("/v1/dashboard/recent-requests")
async def get_recent_requests(limit:int=50,current_user:str=Depends(auth_manager.require_audit_reader)): return {"requests":await supabase_manager.get_org_activity(current_user,min(max(limit,1),200))}
@app.get("/v1/dashboard/threat-timeline")
async def get_threat_timeline(days:int=7,current_user:str=Depends(get_current_user)): return {"timeline":await supabase_manager.get_threat_timeline(current_user,min(max(days,1),90))}

@app.get("/v1/admin/logs",response_model=List[AuditLogResponse])
async def get_audit_logs(limit:int=100,offset:int=0,user_id:str=None,current_user:str=Depends(auth_manager.require_admin)):
    org = await supabase_manager.get_organization_for_user(current_user)
    if not org: raise HTTPException(status_code=404, detail="Organization not found")
    query = supabase_manager.client.table("audit_logs").select("*").eq("organization_id", org["id"])
    if user_id: query = query.eq("user_id", user_id)
    return query.order("timestamp", desc=True).limit(min(max(limit,1),500)).offset(max(offset,0)).execute().data or []

# ---------------------------------------------------------
# Error handlers
# ---------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "request_id": current_request_id(),
            "timestamp": datetime.utcnow().isoformat(),
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    # Log the full technical error server-side only.
    # Never expose provider/database/internal details to clients.
    logger.error("unhandled_exception %s %s", request.method, request.url.path, exc_info=exc)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "Internal server error",
                "type": "internal_error",
            },
            "request_id": current_request_id(),
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
