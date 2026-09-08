from supabase import create_client, Client
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets


class SupabaseManager:
    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_ANON_KEY")
        self.client: Optional[Client] = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_ANON_KEY must be set")
        self.client = create_client(self.supabase_url, self.supabase_key)
        self._initialized = True

    async def health_check(self) -> bool:
        try:
            if not self._initialized:
                await self.initialize()
            self.client.auth.get_session()
            return True
        except Exception as e:
            print(f"Supabase health check failed: {e}")
            return False

    async def close(self):
        self._initialized = False

    async def create_api_key(
        self, user_id: str, name: str = None, expires_days: int = 30
    ) -> Dict:
        if not self._initialized:
            await self.initialize()

        api_key = f"aifw_{secrets.token_urlsafe(32)}"
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        data = {
            "user_id": user_id,
            "key": api_key,
            "name": name,
            "expires_at": expires_at.isoformat(),
        }
        result = self.client.table("api_keys").insert(data).execute()
        return result.data[0] if result.data else None

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        if not self._initialized:
            await self.initialize()
        result = (
            self.client.table("api_keys")
            .select("id,name,is_active,expires_at,created_at,revoked_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    async def verify_api_key(self, api_key: str) -> Optional[Dict]:
        if not self._initialized:
            await self.initialize()
        result = self.client.table("api_keys").select("*").eq("key", api_key).execute()
        if not result.data:
            return None

        key_data = result.data[0]
        if not key_data.get("is_active"):
            return None

        expires_at_value = key_data.get("expires_at")
        if expires_at_value:
            expires_at = datetime.fromisoformat(
                expires_at_value.replace("Z", "+00:00")
            ).replace(tzinfo=None)
            if expires_at < datetime.utcnow():
                return None

        return key_data

    async def revoke_key(self, key_id: str, user_id: str):
        if not self._initialized:
            await self.initialize()
        (
            self.client.table("api_keys")
            .update({"is_active": False, "revoked_at": datetime.utcnow().isoformat()})
            .eq("id", key_id)
            .eq("user_id", user_id)
            .execute()
        )

    async def log_audit(self, log_data: Dict[str, Any]):
        result = self.client.table("audit_logs").insert(log_data).execute()
        return result.data[0] if result.data else None

    async def log_security_event(self, event_data: Dict[str, Any]):
        result = self.client.table("security_events").insert(event_data).execute()
        return result.data[0] if result.data else None

    async def get_user_stats(self, user_id: str) -> Dict:
        total_result = self.client.table("audit_logs").select("count", count="exact").eq("user_id", user_id).execute()
        blocked_result = self.client.table("audit_logs").select("count", count="exact").eq("user_id", user_id).eq("action", "BLOCK").execute()
        latency_result = self.client.table("audit_logs").select("latency_ms").eq("user_id", user_id).execute()
        cost_result = self.client.table("audit_logs").select("cost").eq("user_id", user_id).execute()

        latencies = [row["latency_ms"] for row in (latency_result.data or []) if row.get("latency_ms") is not None]
        total_cost = sum(row.get("cost") or 0 for row in (cost_result.data or []))
        total = total_result.count or 0
        blocked = blocked_result.count or 0

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0,
            "total_cost": total_cost,
            "threat_rate": (blocked / total * 100) if total else 0,
        }

    async def get_user_requests(self, user_id: str, limit: int = 50) -> List[Dict]:
        result = self.client.table("audit_logs").select("*").eq("user_id", user_id).order("timestamp", desc=True).limit(limit).execute()
        return result.data or []

    async def get_threat_timeline(self, user_id: str, days: int = 7) -> List[Dict]:
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        result = self.client.table("security_events").select("*").eq("user_id", user_id).gte("timestamp", start_date).order("timestamp", desc=True).execute()
        return result.data or []

    async def get_logs(self, limit: int = 100, offset: int = 0, user_id: str = None) -> List[Dict]:
        query = self.client.table("audit_logs").select("*")
        if user_id:
            query = query.eq("user_id", user_id)
        return query.order("timestamp", desc=True).limit(limit).offset(offset).execute().data or []

    async def save_webhook_config(self, user_id: str, url: str, events: List[str]):
        data = {"user_id": user_id, "url": url, "events": events, "created_at": datetime.utcnow().isoformat()}
        result = self.client.table("webhook_configs").upsert(data).execute()
        return result.data[0] if result.data else None
