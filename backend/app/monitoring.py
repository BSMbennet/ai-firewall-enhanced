import os
import logging
import json
from datetime import datetime
from typing import Dict

try:
    import betterstack_logging
except ImportError:
    betterstack_logging = None


class BetterStackMonitor:
    def __init__(self):
        self.api_key = os.getenv("BETTERSTACK_API_KEY")
        self.logger = logging.getLogger("ai-firewall")
        self._initialized = False

    async def initialize(self):
        """Initialize BetterStack logging when the optional SDK is available."""
        try:
            if self.api_key and betterstack_logging is not None:
                handler = betterstack_logging.BetterStackHandler(source_token=self.api_key)
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)
                print("BetterStack connected")
            elif self.api_key:
                print("BetterStack SDK unavailable; using console logging")
            else:
                print("BETTERSTACK_API_KEY not set; using console logging")
        except Exception as e:
            print(f"BetterStack init error: {e}")
        finally:
            self._initialized = True

    def _log(self, level: str, event_type: str, data: Dict):
        if self._initialized:
            getattr(self.logger, level)(json.dumps({
                "type": event_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data
            }))

    def log_security_event(self, event: Dict):
        self._log("info", "security_event", event)

    def log_api_request(self, request_data: Dict):
        self._log("info", "api_request", request_data)

    def log_error(self, error: Dict):
        self._log("error", "error", error)


class MetricsCollector:
    def __init__(self):
        self.metrics = {}
        self.buffer = []

    def track_metric(self, name: str, value: float, tags: Dict = None):
        self.buffer.append({"name": name, "value": value, "tags": tags or {}, "timestamp": datetime.utcnow().isoformat()})
        if len(self.buffer) >= 100:
            self.flush_metrics()

    def flush_metrics(self):
        if not self.buffer:
            return
        aggregated = {}
        for metric in self.buffer:
            key = metric["name"]
            aggregated.setdefault(key, {"sum": 0, "count": 0, "min": float("inf"), "max": float("-inf")})
            aggregated[key]["sum"] += metric["value"]
            aggregated[key]["count"] += 1
            aggregated[key]["min"] = min(aggregated[key]["min"], metric["value"])
            aggregated[key]["max"] = max(aggregated[key]["max"], metric["value"])
        self.metrics.update(aggregated)
        self.buffer = []

    async def get_metrics(self, time_range: str = "24h") -> Dict:
        self.flush_metrics()
        return {"time_range": time_range, "metrics": {name: {"total": data["sum"], "average": data["sum"] / data["count"] if data["count"] else 0, "min": data["min"], "max": data["max"], "count": data["count"]} for name, data in self.metrics.items()}}

    async def record_request(self, latency_ms: float, tokens_used: int, status: str):
        self.track_metric("request_latency", latency_ms)
        self.track_metric("tokens_used", tokens_used)
        self.track_metric("request_count", 1, {"status": status})

    async def record_threat(self, threat_type: str, severity: str):
        self.track_metric("threat_count", 1, {"type": threat_type, "severity": severity})

    async def record_llm_cost(self, model: str, tokens: int, cost: float):
        self.track_metric("llm_tokens", tokens, {"model": model})
        self.track_metric("llm_cost", cost, {"model": model})
