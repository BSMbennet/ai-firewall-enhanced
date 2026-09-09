import hashlib
import json
import os
from typing import Dict, Optional

from upstash_redis.asyncio import Redis


class UpstashCache:
    """Upstash Redis cache, rate-limit, threat-signature, and metric backend."""

    def __init__(self):
        self.url = os.getenv("UPSTASH_REDIS_REST_URL")
        self.token = os.getenv("UPSTASH_REDIS_REST_TOKEN")
        self.client: Optional[Redis] = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.url or not self.token:
            if os.getenv("ENVIRONMENT", "development").lower() == "production":
                raise RuntimeError("UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required in production")
            self._initialized = True
            return
        self.client = Redis(url=self.url, token=self.token)
        try:
            await self.client.ping()
        except Exception as exc:
            self.client = None
            raise RuntimeError(f"Upstash Redis connection failed: {exc}") from exc
        self._initialized = True
        print("Upstash Redis connected")

    async def close(self):
        self.client = None
        self._initialized = False

    async def health_check(self) -> bool:
        if not self.client:
            return False
        try:
            return bool(await self.client.ping())
        except Exception:
            return False

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    async def get_cached_response(self, prompt: str) -> Optional[Dict]:
        if not self.client:
            return None
        cached = await self.client.get(f"cache:{self._hash(prompt)}")
        if not cached:
            return None
        return json.loads(cached) if isinstance(cached, str) else cached

    async def cache_response(self, prompt: str, response: Dict, ttl: int = 3600):
        if self.client:
            await self.client.set(f"cache:{self._hash(prompt)}", json.dumps(response), ex=max(1, ttl))

    async def check_rate_limit(self, api_key: str, limit: int = 100, window: int = 60) -> bool:
        if not self.client:
            return False if os.getenv("ENVIRONMENT", "development").lower() == "production" else True
        key = f"rate_limit:{self._hash(api_key)}"
        current = await self.client.incr(key)
        if int(current) == 1:
            await self.client.expire(key, max(1, window))
        return int(current) <= max(1, limit)

    async def get_rate_limit(self, api_key: str) -> int:
        if not self.client:
            return 0
        value = await self.client.get(f"rate_limit:{self._hash(api_key)}")
        return int(value or 0)

    async def store_threat_signature(self, signature: str, details: Dict):
        if self.client:
            await self.client.set(f"threat:{self._hash(signature)}", json.dumps(details), ex=86400)

    async def get_threat_signatures(self) -> list:
        if not self.client:
            return []
        keys = await self.client.keys("threat:*")
        if not keys:
            return []
        values = await self.client.mget(*keys)
        return [json.loads(value) if isinstance(value, str) else value for value in values if value]

    async def increment_metric(self, metric_name: str, value: int = 1):
        if self.client:
            await self.client.incrby(f"metric:{self._hash(metric_name)}", value)

    async def get_metric(self, metric_name: str) -> int:
        if not self.client:
            return 0
        value = await self.client.get(f"metric:{self._hash(metric_name)}")
        return int(value or 0)
