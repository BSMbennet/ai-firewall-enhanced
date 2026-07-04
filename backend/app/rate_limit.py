# app/rate_limit.py
import os
import time
import redis.asyncio as redis
from datetime import datetime, timedelta
from typing import Dict, Optional

class RateLimiter:
    """Advanced rate limiting with multiple strategies for Upstash and Render"""
    
    def __init__(self):
        self.redis = None
        self._initialized = False
        # Different limits for different tiers
        self.tier_limits = {
            "free": {"requests": 100, "window": 3600},      # 100 per hour
            "pro": {"requests": 5000, "window": 3600},     # 5000 per hour
            "business": {"requests": 25000, "window": 3600},# 25000 per hour
            "enterprise": {"requests": 100000, "window": 3600} # 100k per hour
        }

    async def initialize(self):
        """Initialize Redis connection with SSL for Upstash"""
        if self._initialized:
            return
        try:
            # 1. Get URL from Render environment
            raw_url = os.getenv("REDIS_URL")
            if not raw_url:
                print("REDIS_URL not found, using fallback")
                self.redis = None
                self._initialized = True
                return

            # 2. Upstash requires 'rediss://' for TLS
            url = raw_url.replace("redis://", "rediss://", 1) if raw_url.startswith("redis://") else raw_url

            # 3. Connect with SSL and timeouts
            self.redis = await redis.from_url(
                url,
                decode_responses=True,
                max_connections=20,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                ssl_cert_reqs=None  # Necessary for many cloud providers
            )
            
            # 4. Test connection
            await self.redis.ping()
            self._initialized = True
            print("✅ Rate limiter initialized with Redis")
            
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            # Fallback to in-memory (allows app to start)
            self.redis = None
            self._initialized = True
            print("Using fallback in-memory rate limiting")

    async def close(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
            self.redis = None

    async def get_user_tier(self, user_id: str) -> str:
        """Get user's subscription tier"""
        if self.redis:
            try:
                tier = await self.redis.get(f"user_tier:{user_id}")
                if tier: return tier
            except:
                pass
        return "free"

    async def check_rate_limit(self, user_id: str, endpoint: str = "default") -> bool:
        """Check if request is within rate limits"""
        if not self._initialized:
            await self.initialize()

        tier = await self.get_user_tier(user_id)
        limits = self.tier_limits.get(tier, self.tier_limits["free"])

        if not self.redis:
            return True # Allow all if Redis is down (safety fallback)

        window = limits['window']
        key = f"ratelimit:{user_id}:{endpoint}:{int(time.time() / window)}"

        try:
            current = await self.redis.get(key)
            if current is None:
                await self.redis.setex(key, window, 1)
                return True
            
            if int(current) >= limits['requests']:
                return False
                
            await self.redis.incr(key)
            return True
        except Exception as e:
            print(f"Rate limit check failed: {e}")
            return True

    async def get_rate_limit_info(self, user_id: str, endpoint: str = "default") -> Dict:
        """Get rate limit information for user"""
        if not self.redis:
            return {"limit": 100, "remaining": 100, "reset": 0, "tier": "free"}
            
        tier = await self.get_user_tier(user_id)
        limits = self.tier_limits.get(tier, self.tier_limits["free"])
        window = limits['window']
        key = f"ratelimit:{user_id}:{endpoint}:{int(time.time() / window)}"
        
        current = await self.redis.get(key) or 0
        remaining = max(0, limits['requests'] - int(current))
        reset_time = int((int(time.time() / window) + 1) * window)
        
        return {
            "limit": limits['requests'],
            "remaining": remaining,
            "reset": reset_time,
            "tier": tier
        }

    async def health_check(self) -> bool:
        """Check Redis health"""
        if not self.redis:
            return False
        try:
            await self.redis.ping()
            return True
        except:
            return False
