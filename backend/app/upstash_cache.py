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

    async def initialize(self):
        """Initialize Redis connection"""
        if not self.redis_url:
            print("⚠️ UPSTASH_REDIS_URL not set, using mock cache")
            self._initialized = True
            return
        
        try:
            self.client = await redis.from_url(
                self.redis_url,
                password=self.redis_token,
                decode_responses=True
            )
            self._initialized = True
            print("✅ Upstash Redis connected")
        except Exception as e:
            print(f"⚠️ Failed to connect to Upstash Redis: {e}")
            self._initialized = True  # Continue with mock

    async def close(self):
        """Close Redis connection"""
        if self.client:
            await self.client.close()

    async def health_check(self) -> bool:
        """Check if Redis is healthy"""
        try:
            if not self.client:
                return False
            await self.client.ping()
            return True
        except:
            return False

    async def get_cached_response(self, prompt: str) -> Optional[Dict]:
        """Get cached response using hash of prompt"""
        if not self.client:
            return None
        
        try:
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            key = f"cache:{prompt_hash}"
            
            cached = await self.client.get(key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            print(f"Cache get error: {e}")
        return None

    async def cache_response(self, prompt: str, response: Dict, ttl: int = 3600):
        """Cache response with TTL"""
        if not self.client:
            return
        
        try:
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            key = f"cache:{prompt_hash}"
            
            await self.client.setex(key, ttl, json.dumps(response))
        except Exception as e:
            print(f"Cache set error: {e}")

    async def check_rate_limit(self, api_key: str, limit: int = 100, window: int = 60) -> bool:
        """Check if request is within rate limit"""
        if not self.client:
            return True  # Allow if cache is down
        
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
            return True  # Allow on error

    async def get_rate_limit(self, api_key: str) -> int:
        """Get current rate limit count"""
        if not self.client:
            return 0
        
        try:
            key = f"rate_limit:{api_key}"
            count = await self.client.get(key)
            return int(count) if count else 0
        except:
            return 0

    async def store_threat_signature(self, signature: str, details: Dict):
        """Store threat signatures for global detection"""
        if not self.client:
            return
        
        try:
            key = f"threat:{hashlib.md5(signature.encode()).hexdigest()}"
            await self.client.setex(key, 86400, json.dumps(details))
        except Exception as e:
            print(f"Store threat error: {e}")

    async def get_threat_signatures(self) -> list:
        """Get all threat signatures"""
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
        """Increment a metric counter"""
        if not self.client:
            return
        
        try:
            key = f"metric:{metric_name}"
            await self.client.incrby(key, value)
        except Exception as e:
            print(f"Metric increment error: {e}")

    async def get_metric(self, metric_name: str) -> int:
        """Get a metric value"""
        if not self.client:
            return 0
        
        try:
            key = f"metric:{metric_name}"
            value = await self.client.get(key)
            return int(value) if value else 0
        except:
            return 0