import os
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import betterstack_logging

class BetterStackMonitor:
    def __init__(self):
        self.api_key = os.getenv("BETTERSTACK_API_KEY")
        self.logger = logging.getLogger("ai-firewall")
        self._initialized = False

    async def initialize(self):
        """Initialize BetterStack logging"""
        try:
            if self.api_key:
                handler = betterstack_logging.BetterStackHandler(
                    source_token=self.api_key
                )
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)
                self._initialized = True
                print("✅ BetterStack connected")
            else:
                print("⚠️ BETTERSTACK_API_KEY not set, using console logging")
                self._initialized = True
        except Exception as e:
            print(f"⚠️ BetterStack init error: {e}")
            self._initialized = True

    def log_security_event(self, event: Dict):
        """Log security event to BetterStack"""
        if not self._initialized:
            return
        
        try:
            self.logger.info(json.dumps({
                "type": "security_event",
                "timestamp": datetime.utcnow().isoformat(),
                "data": event
            }))
        except Exception as e:
            print(f"Log security event error: {e}")

    def log_api_request(self, request_data: Dict):
        """Log API request metrics"""
        if not self._initialized:
            return
        
        try:
            self.logger.info(json.dumps({
                "type": "api_request",
                "timestamp": datetime.utcnow().isoformat(),
                "data": request_data
            }))
        except Exception as e:
            print(f"Log API request error: {e}")

    def log_error(self, error: Dict):
        """Log error to BetterStack"""
        if not self._initialized:
            return
        
        try:
            self.logger.error(json.dumps({
                "type": "error",
                "timestamp": datetime.utcnow().isoformat(),
                "data": error
            }))
        except Exception as e:
            print(f"Log error: {e}")

class MetricsCollector:
    def __init__(self):
        self.metrics = {}
        self.buffer = []

    def track_metric(self, name: str, value: float, tags: Dict = None):
        """Track a metric"""
        metric = {
            "name": name,
            "value": value,
            "tags": tags or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store in buffer
        self.buffer.append(metric)
        
        # If buffer is too large, flush it
        if len(self.buffer) >= 100:
            self.flush_metrics()

    def flush_metrics(self):
        """Flush metrics buffer to storage"""
        if not self.buffer:
            return
        
        # Aggregate metrics
        aggregated = {}
        for metric in self.buffer:
            key = metric['name']
            if key not in aggregated:
                aggregated[key] = {
                    'sum': 0,
                    'count': 0,
                    'min': float('inf'),
                    'max': float('-inf')
                }
            
            aggregated[key]['sum'] += metric['value']
            aggregated[key]['count'] += 1
            aggregated[key]['min'] = min(aggregated[key]['min'], metric['value'])
            aggregated[key]['max'] = max(aggregated[key]['max'], metric['value'])
        
        # Save aggregated metrics
        self.metrics.update(aggregated)
        
        # Clear buffer
        self.buffer = []

    async def get_metrics(self, time_range: str = "24h") -> Dict:
        """Get metrics for time range"""
        self.flush_metrics()
        
        result = {
            "time_range": time_range,
            "metrics": {}
        }
        
        for name, data in self.metrics.items():
            result["metrics"][name] = {
                "total": data['sum'],
                "average": data['sum'] / data['count'] if data['count'] > 0 else 0,
                "min": data['min'],
                "max": data['max'],
                "count": data['count']
            }
        
        return result

    async def record_request(self, latency_ms: float, tokens_used: int, status: str):
        """Record API request metrics"""
        self.track_metric("request_latency", latency_ms)
        self.track_metric("tokens_used", tokens_used)
        self.track_metric("request_count", 1, {"status": status})

    async def record_threat(self, threat_type: str, severity: str):
        """Record threat metrics"""
        self.track_metric("threat_count", 1, {"type": threat_type, "severity": severity})

    async def record_llm_cost(self, model: str, tokens: int, cost: float):
        """Record LLM cost metrics"""
        self.track_metric("llm_tokens", tokens, {"model": model})
        self.track_metric("llm_cost", cost, {"model": model})