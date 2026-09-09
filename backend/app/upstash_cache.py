import os
import json
import hashlib
from typing import Optional, Dict, Any
import redis.asyncio as redis

class UpstashCache:
    def __init__(self):
        self.redis_url = os.getenv("UPSTASH_REDIS_URL")
        self.redis_token = os.getenv("UPSTASH_REDIS_TOKEN")
        self.client = None
        self._initialized = False

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Accept either a native Redis URL or an Upstash REST-style hostname."""
        value = (url or "").strip()
        if value.startswith(("redis://", "rediss://", "unix://")):
            return value
        if value.startswith("https://"):
            return "rediss://" + value[len("https://"):].rstrip("/") + ":6379"
        if value.startswith("http://"):
            return "redis://" + value[len("http://"):].rstrip("/") + ":6379"
        return value

    async def initialize(self):
        """Initialize Redis connection."""
        if not self.redis_url:
            print("⚠️ UPSTASH_REDIS_URL not set, using mock cache")
            self._initialized = True
            return

        try:
            self.client = redis.from_url(
                self._normalize_url(self.redis_url),
                password=self.redis_token,
                decode_responses=True,
            )
            await self.client.ping()
            self._initialized = True
            print("✅ Upstash Redis connected")
        except Exception as e:
            print(f"⚠️ Failed to connect to Upstash Redis: {e}")
            self.client = None
            self._initialized = True

    async def close(self):
        """Close Redis connection."""
        if self.client:
            await self.client.close()

    async def health_check(self) -> bool:
        """Check if Redis is healthy."""
        try:
            if not self.client:
                return False
            await self.client.ping()
            return True
        except Exception:
            return False

    async def get_cached_response(self, prompt: str) -> Optional[Dict]:
        if not self.client:
            return None
        try:
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            cached = await self.client.get(f"cache:{prompt_hash}")
            return json.loads(cached) if cached else None
        except Exception as e:
            print(f"Cache get error: {e}")
            return None

    async def cache_response(self, prompt: str, response: Dict, ttl: int = 3600):
        if not self.client:
            return
        try:
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            await self.client.setex(f"cache:{prompt_hash}", ttl, json.dumps(response))
        except Exception as e:
            print(f"Cache set error: {e}")

    async def check_rate_limit(self, api_key: str, limit: int = 100, window: int = 60) -> bool:
        if not self.client:
            return True
        try:
            key = f"rate_limit:{api_key}"
            current = await self.client.get(key)
            if current is None:
                await self.client.setex(key, window, 1)
                return True
            count = int(current)
            if count >= limit:
                return False
            await self.client.incr(key)
            return True
        except Exception as e:
            print(f"Rate limit error: {e}")
            return True

    async def get_rate_limit(self, api_key: str) -> int:
        if not self.client:
            return 0
        try:
            count = await self.client.get(f"rate_limit:{api_key}")
            return int(count) if count else 0
        except Exception:
            return 0

    async def store_threat_signature(self, signature: str, details: Dict):
        if not self.client:
            return
        try:
            key = f"threat:{hashlib.md5(signature.encode()).hexdigest()}"
            await self.client.setex(key, 86400, json.dumps(details))
        except Exception as e:
            print(f"Store threat error: {e}")

    async def get_threat_signatures(self) -> list:
        if not self.client:
            return []
        try:
            keys = await self.client.keys("threat:*")
            signatures = []
            for key in keys:
                data = await self.client.get(key)
                if data:
                    signatures.append(json.loads(data))
            return signatures
        except Exception as e:
            print(f"Get threats error: {e}")
            return []

    async def increment_metric(self, metric_name: str, value: int = 1):
        if not self.client:
            return
        try:
            await self.client.incrby(f"metric:{metric_name}", value)
        except Exception as e:
            print(f"Metric increment error: {e}")

    async def get_metric(self, metric_name: str) -> int:
        if not self.client:
            return 0
        try:
            value = await self.client.get(f"metric:{metric_name}")
            return int(value) if value else 0
        except Exception:
            return 0
