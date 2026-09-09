import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from supabase import create_client, Client


class SupabaseCache:
    """Free cache/rate-limit backend using the existing Supabase project."""

    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.client: Optional[Client] = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.url or not self.key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
        self.client = create_client(self.url, self.key)
        self._initialized = True

    async def close(self):
        self.client = None
        self._initialized = False

    async def health_check(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.table("ai_firewall_rate_limits").select("bucket_key").limit(1).execute()
            return True
        except Exception:
            return False

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    async def get_cached_response(self, prompt: str) -> Optional[Dict]:
        if not self.client:
            return None
        key = self._hash(prompt)
        result = self.client.table("ai_firewall_cache").select("value,expires_at").eq("cache_key", key).maybe_single().execute()
        row = result.data
        if not row:
            return None
        expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if expires <= datetime.now(timezone.utc):
            self.client.table("ai_firewall_cache").delete().eq("cache_key", key).execute()
            return None
        return row.get("value")

    async def cache_response(self, prompt: str, response: Dict, ttl: int = 3600):
        if not self.client:
            return
        expires = datetime.now(timezone.utc) + timedelta(seconds=max(1, ttl))
        self.client.table("ai_firewall_cache").upsert({
            "cache_key": self._hash(prompt),
            "value": response,
            "expires_at": expires.isoformat(),
        }).execute()

    async def check_rate_limit(self, api_key: str, limit: int = 100, window: int = 60) -> bool:
        if not self.client:
            return False if os.getenv("ENVIRONMENT", "development").lower() == "production" else True
        result = self.client.rpc("ai_firewall_rate_limit_check", {
            "p_bucket_key": self._hash(api_key),
            "p_limit": max(1, limit),
            "p_window_seconds": max(1, window),
        }).execute()
        return bool(result.data)

    async def get_rate_limit(self, api_key: str) -> int:
        if not self.client:
            return 0
        result = self.client.table("ai_firewall_rate_limits").select("count").eq("bucket_key", self._hash(api_key)).maybe_single().execute()
        return int((result.data or {}).get("count") or 0)

    async def store_threat_signature(self, signature: str, details: Dict):
        if not self.client:
            return
        expires = datetime.now(timezone.utc) + timedelta(days=1)
        self.client.table("ai_firewall_cache").upsert({
            "cache_key": f"threat:{self._hash(signature)}",
            "value": details,
            "expires_at": expires.isoformat(),
        }).execute()

    async def get_threat_signatures(self) -> list:
        if not self.client:
            return []
        now = datetime.now(timezone.utc).isoformat()
        result = self.client.table("ai_firewall_cache").select("value,cache_key").like("cache_key", "threat:%").gt("expires_at", now).limit(1000).execute()
        return [row["value"] for row in (result.data or []) if row.get("cache_key", "").startswith("threat:")]

    async def increment_metric(self, metric_name: str, value: int = 1):
        return None

    async def get_metric(self, metric_name: str) -> int:
        return 0
