from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List
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
from app.models import SecurityRequest, SecurityResponse, APIKeyResponse, AuditLogResponse, HealthResponse

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

app = FastAPI(title="AI Firewall API", version="2.0.0", lifespan=lifespan)

frontend_urls = os.getenv("FRONTEND_URL", "http://localhost:5173")
allowed_origins = [origin.strip().rstrip("/") for origin in frontend_urls.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version="2.0.0",
        services={
            "supabase": await supabase_manager.health_check(),
            "upstash": await upstash_cache.health_check(),
            "r2": await r2_storage.health_check(),
            "llm": await llm_router.health_check(),
        },
    )

@app.get("/ready")
async def readiness_check():
    return {"status": "ready"}

# Authentication is handled directly by Supabase Auth in the frontend.
# The backend only accepts and validates Supabase bearer tokens.

@app.post("/v1/api-keys")
async def create_api_key(current_user: str = Depends(get_current_user)):
    api_key = await api_key_manager.create_api_key(current_user)
    return APIKeyResponse(api_key=api_key["key"], user_id=current_user)

@app.get("/v1/api-keys")
async def list_api_keys(current_user: str = Depends(get_current_user)):
    return {"keys": await api_key_manager.list_keys(current_user)}

@app.delete("/v1/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: str = Depends(get_current_user)):
    await api_key_manager.revoke_key(key_id, current_user)
    return {"message": "API key revoked"}

@app.post("/v1/secure-ai/query", response_model=SecurityResponse)
async def secure_query(
    request: SecurityRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user),
    http_request: Request = None,
):
    request_id = str(uuid.uuid4())
    start_time = time.time()

    if not await upstash_cache.check_rate_limit(current_user):
        metrics.track_metric("rate_limit_exceeded", 1)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        cached_response = await upstash_cache.get_cached_response(request.prompt)
        if cached_response:
            return SecurityResponse(request_id=request_id, allowed=True, blocked=False,
                response=cached_response["content"], cached=True, risk_score=0,
                timestamp=datetime.utcnow())

        input_validation = await orchestrator.validate_input(
            prompt=request.prompt, max_length=4000, allowed_languages=["en"])
        if not input_validation["valid"]:
            raise HTTPException(status_code=400, detail=input_validation["error"])

        security_result = await orchestrator.validate_request_parallel(
            prompt=request.prompt, context=request.context or {},
            user_id=current_user, request_id=request_id)

        await supabase_manager.log_security_event({
            "user_id": current_user, "event_type": "security_validation",
            "severity": "high" if security_result.decision == "BLOCK" else "low",
            "risk_score": security_result.risk_score,
            "details": {"reason": security_result.reason, "request_id": request_id},
        })

        if security_result.decision == "BLOCK":
            return SecurityResponse(request_id=request_id, allowed=False, blocked=True,
                message="Request blocked by security policy", risk_score=security_result.risk_score,
                reason=security_result.reason, timestamp=datetime.utcnow())

        sanitized_prompt = await orchestrator.sanitize_prompt(
            request.prompt, redact_pii=security_result.pii_detected)
        guarded_prompt = await orchestrator.apply_prompt_guard(
            sanitized_prompt, context=request.context)
        llm_response = await llm_router.route(
            prompt=guarded_prompt, model=request.model or "gpt-4",
            max_tokens=request.max_tokens or 1000,
            temperature=request.temperature or 0.7, request_id=request_id)
        filtered_response = await orchestrator.filter_response(
            llm_response=llm_response, prevent_data_leakage=True, block_harmful_content=True)

        await upstash_cache.cache_response(request.prompt, filtered_response, ttl=3600)
        latency_ms = (time.time() - start_time) * 1000
        await supabase_manager.log_audit({
            "user_id": current_user, "request_id": request_id, "action": "ALLOW",
            "risk_score": security_result.risk_score,
            "tokens_used": llm_response.get("usage", {}), "latency_ms": latency_ms,
            "model": request.model or "gpt-4", "cost": llm_response.get("cost", 0),
            "metadata": {"sanitized": security_result.pii_redacted, "guard_applied": True},
        })

        return SecurityResponse(
            request_id=request_id, allowed=True, blocked=False,
            response=filtered_response["content"], usage=llm_response.get("usage"),
            risk_score=security_result.risk_score,
            security_metadata={"sanitized": security_result.pii_redacted, "guard_applied": True},
            timestamp=datetime.utcnow())
    except HTTPException:
        raise
    except Exception as e:
        monitor.log_error({"request_id": request_id, "error": str(e), "user_id": current_user})
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/v1/secure-ai/batch")
async def batch_secure_query(requests: List[SecurityRequest], current_user: str = Depends(get_current_user)):
    tasks = [secure_query(req, BackgroundTasks(), current_user, None) for req in requests]
    return {"results": await asyncio.gather(*tasks, return_exceptions=True)}

@app.get("/v1/dashboard/stats")
async def get_dashboard_stats(current_user: str = Depends(get_current_user)):
    return await supabase_manager.get_user_stats(current_user)

@app.get("/v1/dashboard/recent-requests")
async def get_recent_requests(limit: int = 50, current_user: str = Depends(get_current_user)):
    return {"requests": await supabase_manager.get_user_requests(current_user, limit)}

@app.get("/v1/dashboard/threat-timeline")
async def get_threat_timeline(days: int = 7, current_user: str = Depends(get_current_user)):
    return {"timeline": await supabase_manager.get_threat_timeline(current_user, days)}

@app.get("/v1/admin/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(limit: int = 100, offset: int = 0, user_id: str = None,
                         current_user: str = Depends(get_current_user),
                         is_admin: bool = Depends(auth_manager.require_admin)):
    return await supabase_manager.get_logs(limit, offset, user_id)

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code,
        content={"error": exc.detail, "timestamp": datetime.utcnow().isoformat()})
