# app/cache.py - CORRECTED VERSION
import os
import json
from typing import Optional, Any

# Simple in-memory cache when Redis is not available
class SimpleCache:
    def __init__(self):
        self._cache = {}
    
    async def get(self, key: str) -> Optional[Any]:
        return self._cache.get(key)
    
    async def set(self, key: str, value: Any, ttl: int = 3600):
        self._cache[key] = value
    
    async def delete(self, key: str):
        self._cache.pop(key, None)
    
    async def clear(self):
        self._cache.clear()

# Try Redis, fallback to simple cache
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

class CacheManager:
    redis_client = None
    _use_redis = False
    _simple_cache = SimpleCache()
    
    @classmethod
    async def initialize(cls):
        """Initialize cache (Redis or fallback)"""
        redis_url = os.getenv("REDIS_URL")
        
        if REDIS_AVAILABLE and redis_url:
            try:
                cls.redis_client = await redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_timeout=5
                )
                await cls.redis_client.ping()
                cls._use_redis = True
                print("✅ Redis cache connected")
                return
            except Exception as e:
                print(f"⚠️ Redis connection failed: {e}")
        
        cls._use_redis = False
        print("📦 Using in-memory cache (no Redis)")
    
    @classmethod
    async def get(cls, key: str) -> Optional[Any]:
        if cls._use_redis and cls.redis_client:
            try:
                value = await cls.redis_client.get(key)
                return json.loads(value) if value else None
            except:
                return None
        else:
            return await cls._simple_cache.get(key)
    
    @classmethod
    async def set(cls, key: str, value: Any, ttl: int = 3600) -> bool:
        if cls._use_redis and cls.redis_client:
            try:
                await cls.redis_client.setex(key, ttl, json.dumps(value))
                return True
            except:
                return False
        else:
            await cls._simple_cache.set(key, value, ttl)
            return True
    
    @classmethod
    async def delete(cls, key: str) -> bool:
        if cls._use_redis and cls.redis_client:
            try:
                await cls.redis_client.delete(key)
                return True
            except:
                return False
        else:
            await cls._simple_cache.delete(key)
            return True
    
    @classmethod
    async def close(cls):
        if cls._use_redis and cls.redis_client:
            await cls.redis_client.close()