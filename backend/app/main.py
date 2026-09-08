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

app = FastAPI(title="AI Firewall API", version="2.1.0", lifespan=lifespan)

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
        version="2.1.0",
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

# Dashboard authentication uses the user's Supabase session.
# Customer application traffic uses an AI Firewall API key instead.

@app.post("/v1/api-keys")
async def create_api_key(
    payload: Dict[str, Any] | None = None,
    current_user: str = Depends(get_current_user),
):
    payload = payload or {}
    name = str(payload.get("name") or "Default Key")[:100]
    expires_days = int(payload.get("expires_days") or 30)
    expires_days = max(1, min(expires_days, 365))
    api_key = await api_key_manager.create_api_key(current_user, name=name, expires_days=expires_days)
    if not api_key:
        raise HTTPException(status_code=500, detail="Failed to create API key")
    return {
        "key": api_key["key"],
        "id": api_key["id"],
        "name": api_key.get("name"),
        "user_id": current_user,
        "is_active": api_key.get("is_active", True),
        "expires_at": api_key.get("expires_at"),
        "created_at": api_key.get("created_at"),
    }

@app.get("/v1/api-keys")
async def list_api_keys(current_user: str = Depends(get_current_user)):
    return {"keys": await api_key_manager.list_keys(current_user)}

@app.delete("/v1/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: str = Depends(get_current_user)):
    await api_key_manager.revoke_key(key_id, current_user)
    return {"message": "API key revoked"}

async def run_firewall_pipeline(
    prompt: str,
    model: str,
    max_tokens: int,
    temperature: float,
    user_id: str,
    request_id: str,
):
    start_time = time.time()
    if not prompt or not prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    if len(prompt) > 4000:
        raise HTTPException(status_code=400, detail="Prompt exceeds the 4000 character limit")

    input_validation = await orchestrator.validate_input(
        prompt=prompt, max_length=4000, allowed_languages=["en"]
    )
    if not input_validation["valid"]:
        raise HTTPException(status_code=400, detail=input_validation["error"])

    security_result = await orchestrator.validate_request_parallel(
        prompt=prompt, context={}, user_id=user_id, request_id=request_id
    )

    await supabase_manager.log_security_event({
        "user_id": user_id,
        "event_type": "security_validation",
        "severity": "high" if security_result.decision == "BLOCK" else "low",
        "risk_score": security_result.risk_score,
        "details": {"reason": security_result.reason, "request_id": request_id},
    })

    if security_result.decision == "BLOCK":
        latency_ms = (time.time() - start_time) * 1000
        await supabase_manager.log_audit({
            "user_id": user_id,
            "request_id": request_id,
            "action": "BLOCK",
            "risk_score": security_result.risk_score,
            "tokens_used": {},
            "latency_ms": latency_ms,
            "model": model,
            "cost": 0,
            "reason": security_result.reason,
            "metadata": {"gateway": True},
        })
        return {
            "blocked": True,
            "response": None,
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "risk_score": security_result.risk_score,
            "reason": security_result.reason,
        }

    sanitized_prompt = await orchestrator.sanitize_prompt(
        prompt, redact_pii=security_result.pii_detected
    )
    guarded_prompt = await orchestrator.apply_prompt_guard(sanitized_prompt, context={})
    llm_response = await llm_router.route(
        prompt=guarded_prompt,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        request_id=request_id,
    )
    if llm_response.get("error"):
        raise HTTPException(status_code=502, detail="AI provider unavailable")

    filtered_response = await orchestrator.filter_response(
        llm_response=llm_response,
        prevent_data_leakage=True,
        block_harmful_content=True,
    )
    latency_ms = (time.time() - start_time) * 1000
    await supabase_manager.log_audit({
        "user_id": user_id,
        "request_id": request_id,
        "action": "ALLOW",
        "risk_score": security_result.risk_score,
        "tokens_used": llm_response.get("usage", {}),
        "latency_ms": latency_ms,
        "model": model,
        "cost": llm_response.get("cost", 0),
        "metadata": {"gateway": True, "sanitized": security_result.pii_redacted, "guard_applied": True},
    })
    return {
        "blocked": False,
        "response": filtered_response["content"],
        "usage": llm_response.get("usage", {}),
        "risk_score": security_result.risk_score,
        "reason": security_result.reason,
    }

@app.post("/v1/chat/completions")
async def chat_completions(
    payload: Dict[str, Any],
    current_user: str = Depends(api_key_manager.verify_api_key),
):
    """OpenAI-compatible gateway. Customers authenticate with their AI Firewall API key."""
    messages = payload.get("messages") or []
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages must be a non-empty array")

    user_messages = [
        str(message.get("content", ""))
        for message in messages
        if isinstance(message, dict) and message.get("role") == "user"
    ]
    prompt = "\n".join(message for message in user_messages if message.strip())
    if not prompt:
        raise HTTPException(status_code=400, detail="At least one user message is required")

    model = str(payload.get("model") or "gpt-4o-mini")
    max_tokens = max(1, min(int(payload.get("max_tokens") or 1000), 4000))
    temperature = float(payload.get("temperature") if payload.get("temperature") is not None else 0.7)
    temperature = max(0, min(temperature, 2))
    request_id = str(uuid.uuid4())

    result = await run_firewall_pipeline(
        prompt, model, max_tokens, temperature, current_user, request_id
    )
    if result["blocked"]:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by AI Firewall security policy",
                    "type": "firewall_blocked",
                    "code": "security_policy",
                    "risk_score": result["risk_score"],
                    "reason": result["reason"],
                },
                "request_id": request_id,
            },
        )

    return {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": result["response"]},
            "finish_reason": "stop",
        }],
        "usage": result["usage"],
        "firewall": {"risk_score": result["risk_score"]},
    }

@app.post("/v1/secure-ai/query", response_model=SecurityResponse)
async def secure_query(
    request: SecurityRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user),
    http_request: Request = None,
):
    request_id = str(uuid.uuid4())
    result = await run_firewall_pipeline(
        request.prompt,
        request.model.value if hasattr(request.model, "value") else str(request.model),
        request.max_tokens or 1000,
        request.temperature if request.temperature is not None else 0.7,
        current_user,
        request_id,
    )
    if result["blocked"]:
        return SecurityResponse(
            request_id=request_id,
            allowed=False,
            blocked=True,
            message="Request blocked by security policy",
            risk_score=result["risk_score"],
            reason=result["reason"],
            timestamp=datetime.utcnow(),
        )
    return SecurityResponse(
        request_id=request_id,
        allowed=True,
        blocked=False,
        response=result["response"],
        usage=result["usage"],
        risk_score=result["risk_score"],
        security_metadata={"gateway": True},
        timestamp=datetime.utcnow(),
    )

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
