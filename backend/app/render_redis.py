import os
import json
import hashlib
from typing import Optional, Dict
import redis.asyncio as redis


class RenderRedisCache:
    """Redis cache for Render Key Value. Render can inject REDIS_URL/REDIS_PASSWORD."""

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL") or os.getenv("RENDER_REDIS_URL")
        self.redis_password = os.getenv("REDIS_PASSWORD") or os.getenv("RENDER_REDIS_PASSWORD")
        self.client = None
        self._initialized = False

    async def initialize(self):
        if not self.redis_url:
            if os.getenv("ENVIRONMENT", "development").lower() == "production":
                raise RuntimeError("REDIS_URL is required in production. Connect a Render Key Value instance to this service.")
            self._initialized = True
            return
        try:
            self.client = redis.from_url(self.redis_url, password=self.redis_password, decode_responses=True)
            await self.client.ping()
            self._initialized = True
            print("Redis cache connected")
        except Exception as exc:
            self.client = None
            raise RuntimeError(f"Render Redis connection failed: {exc}") from exc

    async def close(self):
        if self.client:
            await self.client.aclose()
            self.client = None

    async def health_check(self) -> bool:
        if not self.client:
            return False
        try:
            await self.client.ping()
            return True
        except Exception:
            return False

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    async def get_cached_response(self, prompt: str) -> Optional[Dict]:
        if not self.client:
            return None
        cached = await self.client.get(f"cache:{self._hash(prompt)}")
        return json.loads(cached) if cached else None

    async def cache_response(self, prompt: str, response: Dict, ttl: int = 3600):
        if self.client:
            await self.client.setex(f"cache:{self._hash(prompt)}", ttl, json.dumps(response))

    async def check_rate_limit(self, api_key: str, limit: int = 100, window: int = 60) -> bool:
        if not self.client:
            return False if os.getenv("ENVIRONMENT", "development").lower() == "production" else True
        key = f"rate_limit:{self._hash(api_key)}"
        current = await self.client.incr(key)
        if current == 1:
            await self.client.expire(key, window)
        return current <= limit

    async def get_rate_limit(self, api_key: str) -> int:
        if not self.client:
            return 0
        value = await self.client.get(f"rate_limit:{self._hash(api_key)}")
        return int(value) if value else 0

    async def store_threat_signature(self, signature: str, details: Dict):
        if self.client:
            await self.client.setex(f"threat:{self._hash(signature)}", 86400, json.dumps(details))

    async def get_threat_signatures(self) -> list:
        if not self.client:
            return []
        keys = []
        async for key in self.client.scan_iter(match="threat:*"):
            keys.append(key)
        values = await self.client.mget(keys) if keys else []
        return [json.loads(value) for value in values if value]

    async def increment_metric(self, metric_name: str, value: int = 1):
        if self.client:
            await self.client.incrby(f"metric:{self._hash(metric_name)}", value)

    async def get_metric(self, metric_name: str) -> int:
        if not self.client:
            return 0
        value = await self.client.get(f"metric:{self._hash(metric_name)}")
        return int(value) if value else 0
