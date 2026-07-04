from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class ModelType(str, Enum):
    GPT4 = "gpt-4"
    GPT35 = "gpt-3.5-turbo"
    CLAUDE = "claude-3-opus"
    LLAMA = "llama-2"

class SecurityRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    context: Optional[Dict[str, Any]] = None
    model: Optional[ModelType] = ModelType.GPT4
    max_tokens: Optional[int] = Field(1000, ge=1, le=4000)
    temperature: Optional[float] = Field(0.7, ge=0, le=2.0)
    user_metadata: Optional[Dict[str, Any]] = None

    @validator('prompt')
    def validate_prompt(cls, v):
        if not v.strip():
            raise ValueError('Prompt cannot be empty')
        if len([c for c in v if not c.isalnum() and not c.isspace()]) > len(v) * 0.3:
            raise ValueError('Prompt contains too many special characters')
        return v

class SecurityResponse(BaseModel):
    request_id: str
    allowed: bool
    blocked: bool = False
    response: Optional[str] = None
    cached: bool = False
    usage: Optional[Dict[str, int]] = None
    risk_score: float
    reason: Optional[str] = None
    message: Optional[str] = None
    security_metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class APIKeyCreate(BaseModel):
    name: str
    permissions: List[str] = ["query"]
    expires_days: Optional[int] = 30

class APIKeyResponse(BaseModel):
    api_key: str
    user_id: str
    created_at: datetime
    expires_at: datetime

class AuditLogResponse(BaseModel):
    id: str
    user_id: str
    action: str
    risk_score: float
    latency_ms: float
    tokens_used: Dict[str, int]
    timestamp: datetime

class MetricsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    avg_latency_ms: float
    p95_latency_ms: float
    total_cost: float
    threat_rate: float
    time_range: str

class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    services: Dict[str, bool]