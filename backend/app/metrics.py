# app/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from typing import Dict
import time

class MetricsCollector:
    """Prometheus metrics collection"""
    
    # Define metrics
    requests_total = Counter('ai_firewall_requests_total', 'Total requests', ['action', 'model'])
    request_duration = Histogram('ai_firewall_request_duration_seconds', 'Request latency', buckets=[0.1, 0.5, 1.0, 2.0, 5.0])
    threats_blocked = Counter('ai_firewall_threats_blocked_total', 'Blocked threats', ['type'])
    llm_cost = Counter('ai_firewall_llm_cost_dollars', 'LLM API cost', ['model'])
    active_requests = Gauge('ai_firewall_active_requests', 'Active requests')
    risk_scores = Histogram('ai_firewall_risk_scores', 'Risk score distribution', buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    
    @classmethod
    async def initialize(cls):
        """Initialize metrics collector"""
        # Register all metrics
        pass
    
    @classmethod
    async def record_request(cls, latency_ms: float, success: bool, tokens: int):
        """Record request metrics"""
        action = "success" if success else "error"
        cls.requests_total.labels(action=action, model="unknown").inc()
        cls.request_duration.observe(latency_ms / 1000)
    
    @classmethod
    async def record_blocked_request(cls, risk_score: float):
        """Record blocked request"""
        cls.threats_blocked.labels(type="injection").inc()
        cls.risk_scores.observe(risk_score)
    
    @classmethod
    async def record_llm_cost(cls, model: str, tokens: int):
        """Record LLM cost"""
        # Approximate cost: $0.03 per 1K tokens for GPT-4
        cost = (tokens / 1000) * 0.03
        cls.llm_cost.labels(model=model).inc(cost)
    
    @classmethod
    async def record_error(cls):
        """Record error"""
        cls.requests_total.labels(action="error", model="unknown").inc()
    
    @classmethod
    async def get_metrics(cls, time_range: str = "24h") -> Dict:
        """Get current metrics"""
        # In production, query Prometheus API
        return {
            "total_requests": 12345,
            "blocked_requests": 123,
            "avg_latency_ms": 450,
            "p95_latency_ms": 850,
            "total_cost": 12.50,
            "threat_rate": 1.0,
            "time_range": time_range
        }