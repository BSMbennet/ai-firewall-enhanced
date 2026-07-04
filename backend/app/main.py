from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import uuid
import time
import asyncio
import os
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
from app.models import (
    SecurityRequest, SecurityResponse,
    APIKeyCreate, APIKeyResponse,
    AuditLogResponse, MetricsResponse,
    HealthResponse
)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting AI Firewall...")
    await supabase_manager.initialize()
    await upstash_cache.initialize()
    await r2_storage.initialize()
    await monitor.initialize()
    print("✅ All services initialized")
    yield
    # Shutdown
    print("🛑 Shutting down AI Firewall...")
    await supabase_manager.close()
    await upstash_cache.close()

# Initialize app
app = FastAPI(
    title="AI Firewall API",
    version="2.0.0",
    description="Enterprise-grade AI Security Layer with FREE Services",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# Initialize services
auth_manager = AuthManager()
api_key_manager = APIKeyManager()
orchestrator = SecurityOrchestrator()
llm_router = LLMRouter()
supabase_manager = SupabaseManager()
upstash_cache = UpstashCache()
r2_storage = CloudflareR2()
monitor = BetterStackMonitor()
metrics = MetricsCollector()

# ==================== HEALTH ENDPOINTS ====================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version="2.0.0",
        services={
            "supabase": await supabase_manager.health_check(),
            "upstash": await upstash_cache.health_check(),
            "r2": await r2_storage.health_check(),
            "llm": await llm_router.health_check()
        }
    )

@app.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe"""
    return {"status": "ready"}

# ==================== AUTH ENDPOINTS ====================

@app.post("/v1/auth/register")
async def register_user(email: str, password: str, company: str = None):
    """Register new user"""
    try:
        user = await supabase_manager.create_user(email, password, company)
        api_key = await api_key_manager.create_api_key(user['id'])
        return {
            "user_id": user['id'],
            "api_key": api_key,
            "message": "User registered successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/v1/auth/login")
async def login(email: str, password: str):
    """Login and get JWT token"""
    token = await auth_manager.authenticate(email, password)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/v1/api-keys")
async def create_api_key(current_user: str = Depends(get_current_user)):
    """Create new API key"""
    api_key = await api_key_manager.create_api_key(current_user)
    return APIKeyResponse(api_key=api_key['key'], user_id=current_user)

@app.get("/v1/api-keys")
async def list_api_keys(current_user: str = Depends(get_current_user)):
    """List all API keys for user"""
    keys = await api_key_manager.list_keys(current_user)
    return {"keys": keys}

@app.delete("/v1/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: str = Depends(get_current_user)):
    """Revoke API key"""
    await api_key_manager.revoke_key(key_id, current_user)
    return {"message": "API key revoked"}

# ==================== CORE SECURITY ENDPOINT ====================

@app.post("/v1/secure-ai/query", response_model=SecurityResponse)
async def secure_query(
    request: SecurityRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(api_key_manager.verify_api_key),
    http_request: Request = None
):
    """
    Main endpoint for secure LLM queries with comprehensive protection.
    """
    request_id = str(uuid.uuid4())
    start_time = time.time()

    # Rate limiting check
    if not await upstash_cache.check_rate_limit(api_key):
        metrics.track_metric("rate_limit_exceeded", 1)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        # Check cache
        cached_response = await upstash_cache.get_cached_response(request.prompt)
        if cached_response:
            metrics.track_metric("cache_hit", 1)
            return SecurityResponse(
                request_id=request_id,
                allowed=True,
                blocked=False,
                response=cached_response['content'],
                cached=True,
                risk_score=0,
                timestamp=datetime.utcnow()
            )

        # STEP 1: Input validation
        input_validation = await orchestrator.validate_input(
            prompt=request.prompt,
            max_length=4000,
            allowed_languages=["en"]
        )
        if not input_validation["valid"]:
            raise HTTPException(status_code=400, detail=input_validation["error"])

        # STEP 2: Security validation (parallel)
        security_result = await orchestrator.validate_request_parallel(
            prompt=request.prompt,
            context=request.context or {},
            user_id=api_key,
            request_id=request_id
        )

        # Log security event
        await supabase_manager.log_security_event({
            "user_id": api_key,
            "event_type": "security_validation",
            "severity": "high" if security_result.decision == "BLOCK" else "low",
            "risk_score": security_result.risk_score,
            "details": {
                "reason": security_result.reason,
                "request_id": request_id
            }
        })

        # BLOCK decision
        if security_result.decision == "BLOCK":
            metrics.track_metric("request_blocked", 1)
            monitor.log_security_event({
                "type": "prompt_injection",
                "request_id": request_id,
                "risk_score": security_result.risk_score,
                "reason": security_result.reason
            })

            # Store threat signature
            await upstash_cache.store_threat_signature(
                request.prompt[:100],
                {
                    "type": "prompt_injection",
                    "risk_score": security_result.risk_score,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

            return SecurityResponse(
                request_id=request_id,
                allowed=False,
                blocked=True,
                message="Request blocked by security policy",
                risk_score=security_result.risk_score,
                reason=security_result.reason,
                timestamp=datetime.utcnow()
            )

        # STEP 3: Sanitize prompt
        sanitized_prompt = await orchestrator.sanitize_prompt(
            request.prompt,
            redact_pii=security_result.pii_detected
        )

        # STEP 4: Apply prompt guard
        guarded_prompt = await orchestrator.apply_prompt_guard(
            sanitized_prompt,
            context=request.context
        )

        # STEP 5: Route to LLM
        llm_response = await llm_router.route(
            prompt=guarded_prompt,
            model=request.model or "gpt-4",
            max_tokens=request.max_tokens or 1000,
            temperature=request.temperature or 0.7,
            request_id=request_id
        )

        # Track LLM cost
        cost = llm_response.get("cost", 0)
        metrics.track_metric("llm_cost", cost)
        metrics.track_metric("tokens_used", llm_response.get("usage", {}).get("total_tokens", 0))

        # STEP 6: Filter response
        filtered_response = await orchestrator.filter_response(
            llm_response=llm_response,
            prevent_data_leakage=True,
            block_harmful_content=True
        )

        # Cache response
        await upstash_cache.cache_response(
            request.prompt,
            filtered_response,
            ttl=3600
        )

        # STEP 7: Audit logging
        latency_ms = (time.time() - start_time) * 1000
        await supabase_manager.log_audit({
            "user_id": api_key,
            "request_id": request_id,
            "action": "ALLOW",
            "risk_score": security_result.risk_score,
            "tokens_used": llm_response.get("usage", {}),
            "latency_ms": latency_ms,
            "model": request.model or "gpt-4",
            "cost": cost,
            "metadata": {
                "sanitized": security_result.pii_redacted,
                "guard_applied": True
            }
        })

        # Update metrics
        metrics.track_metric("request_latency", latency_ms)
        metrics.track_metric("request_success", 1)

        return SecurityResponse(
            request_id=request_id,
            allowed=True,
            blocked=False,
            response=filtered_response["content"],
            usage=llm_response.get("usage"),
            risk_score=security_result.risk_score,
            security_metadata={
                "sanitized": security_result.pii_redacted,
                "guard_applied": True
            },
            timestamp=datetime.utcnow()
        )

    except Exception as e:
        # Log error
        error_msg = str(e)
        monitor.log_error({
            "request_id": request_id,
            "error": error_msg,
            "user_id": api_key
        })
        metrics.track_metric("request_error", 1)
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")

# ==================== BATCH PROCESSING ====================

@app.post("/v1/secure-ai/batch")
async def batch_secure_query(
    requests: List[SecurityRequest],
    api_key: str = Depends(api_key_manager.verify_api_key)
):
    """Process multiple requests in batch"""
    tasks = [
        secure_query(req, BackgroundTasks(), api_key, None)
        for req in requests
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {"results": results}

# ==================== ADMIN ENDPOINTS ====================

@app.get("/v1/admin/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    user_id: str = None,
    current_user: str = Depends(get_current_user),
    is_admin: bool = Depends(auth_manager.require_admin)
):
    """Get audit logs (admin only)"""
    logs = await supabase_manager.get_logs(limit, offset, user_id)
    return logs

@app.get("/v1/admin/metrics")
async def get_metrics(
    time_range: str = "24h",
    current_user: str = Depends(get_current_user),
    is_admin: bool = Depends(auth_manager.require_admin)
):
    """Get system metrics (admin only)"""
    metrics_data = await metrics.get_metrics(time_range)
    return metrics_data

@app.get("/v1/admin/threats")
async def get_threats(
    current_user: str = Depends(get_current_user),
    is_admin: bool = Depends(auth_manager.require_admin)
):
    """Get global threat intelligence"""
    threats = await upstash_cache.get_threat_signatures()
    return {"threats": threats}

# ==================== USER DASHBOARD ENDPOINTS ====================

@app.get("/v1/dashboard/stats")
async def get_dashboard_stats(
    api_key: str = Depends(api_key_manager.verify_api_key)
):
    """Get user dashboard statistics"""
    stats = await supabase_manager.get_user_stats(api_key)
    return stats

@app.get("/v1/dashboard/recent-requests")
async def get_recent_requests(
    limit: int = 50,
    api_key: str = Depends(api_key_manager.verify_api_key)
):
    """Get recent requests for user"""
    requests_data = await supabase_manager.get_user_requests(api_key, limit)
    return {"requests": requests_data}

@app.get("/v1/dashboard/threat-timeline")
async def get_threat_timeline(
    days: int = 7,
    api_key: str = Depends(api_key_manager.verify_api_key)
):
    """Get threat timeline for dashboard"""
    timeline = await supabase_manager.get_threat_timeline(api_key, days)
    return {"timeline": timeline}

# ==================== WEBHOOK CONFIGURATION ====================

@app.post("/v1/webhooks/configure")
async def configure_webhook(
    url: str,
    events: List[str],
    api_key: str = Depends(api_key_manager.verify_api_key)
):
    """Configure webhook for alerts"""
    await supabase_manager.save_webhook_config(api_key, url, events)
    return {"message": "Webhook configured"}

# ==================== ERROR HANDLERS ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )