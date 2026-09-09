from supabase import create_client, Client
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import re


class SupabaseManager:
    """Server-side Supabase access.

    The backend uses the Supabase secret/service-role credential only on the server.
    It is never exposed to the browser.
    """

    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.client: Optional[Client] = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set on the backend")
        self.client = create_client(self.supabase_url, self.supabase_key)
        self._initialized = True

    async def health_check(self) -> bool:
        try:
            if not self._initialized:
                await self.initialize()
            self.client.table("profiles").select("id").limit(1).execute()
            return True
        except Exception as e:
            print(f"Supabase health check failed: {e}")
            return False

    async def close(self):
        self._initialized = False

    async def get_profile(self, user_id: str) -> Optional[Dict]:
        if not self._initialized:
            await self.initialize()
        result = self.client.table("profiles").select("*").eq("id", user_id).maybe_single().execute()
        return result.data

    async def ensure_organization(self, user_id: str, name: str = "My Organization") -> Dict:
        if not self._initialized:
            await self.initialize()
        profile = await self.get_profile(user_id)
        if profile and profile.get("organization_id"):
            org = self.client.table("organizations").select("*").eq("id", profile["organization_id"]).maybe_single().execute().data
            if org:
                return org

        safe_slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "organization"
        safe_slug = f"{safe_slug}-{secrets.token_hex(3)}"
        org_result = self.client.table("organizations").insert({"name": name[:120], "slug": safe_slug}).execute()
        if not org_result.data:
            raise RuntimeError("Failed to create organization")
        org = org_result.data[0]

        user = self.client.auth.admin.get_user_by_id(user_id)
        email = getattr(user.user, "email", None) if getattr(user, "user", None) else None
        full_name = (profile or {}).get("full_name") or "Organization owner"
        self.client.table("profiles").update({
            "organization_id": org["id"],
            "role": "owner",
            "full_name": full_name,
        }).eq("id", user_id).execute()
        self.client.table("organization_members").upsert({
            "organization_id": org["id"],
            "user_id": user_id,
            "email": email or f"user-{user_id[:8]}@local",
            "full_name": full_name,
            "role": "owner",
            "status": "active",
        }, on_conflict="organization_id,user_id").execute()
        self.client.table("security_policies").insert({
            "organization_id": org["id"],
            "name": "Default Enterprise Policy",
        }).execute()
        return org

    async def get_organization_for_user(self, user_id: str) -> Optional[Dict]:
        if not self._initialized:
            await self.initialize()
        profile = await self.get_profile(user_id)
        if not profile or not profile.get("organization_id"):
            return None
        return self.client.table("organizations").select("*").eq("id", profile["organization_id"]).maybe_single().execute().data

    async def get_member_role(self, user_id: str) -> Optional[str]:
        profile = await self.get_profile(user_id)
        return profile.get("role") if profile else None

    async def list_members(self, user_id: str) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        result = self.client.table("organization_members").select("*").eq("organization_id", org["id"]).neq("status", "removed").order("created_at", desc=True).execute()
        return result.data or []

    async def invite_member(self, actor_id: str, email: str, full_name: str = "", role: str = "member") -> Dict:
        org = await self.get_organization_for_user(actor_id)
        if not org:
            org = await self.ensure_organization(actor_id)
        allowed_roles = {"admin", "security", "developer", "member", "viewer"}
        if role not in allowed_roles:
            role = "member"
        email = email.strip().lower()
        if not email or "@" not in email:
            raise ValueError("A valid employee email is required")
        invite = self.client.auth.admin.invite_user_by_email(email)
        invited_user = getattr(invite, "user", None)
        if invited_user is None:
            raise RuntimeError("Unable to create employee invitation")
        member = self.client.table("organization_members").upsert({
            "organization_id": org["id"],
            "user_id": str(invited_user.id),
            "email": email,
            "full_name": full_name[:120],
            "role": role,
            "status": "invited",
        }, on_conflict="organization_id,user_id").execute()
        self.client.table("profiles").update({
            "organization_id": org["id"],
            "role": role,
            "full_name": full_name[:120],
        }).eq("id", str(invited_user.id)).execute()
        return member.data[0] if member.data else {"user_id": str(invited_user.id), "email": email, "role": role, "status": "invited"}

    async def update_member(self, actor_id: str, member_id: str, status: Optional[str] = None, role: Optional[str] = None) -> Optional[Dict]:
        org = await self.get_organization_for_user(actor_id)
        if not org:
            return None
        changes = {}
        if status in {"active", "suspended", "removed", "invited"}:
            changes["status"] = status
        if role in {"admin", "security", "developer", "member", "viewer"}:
            changes["role"] = role
        if not changes:
            return None
        changes["updated_at"] = datetime.now(timezone.utc).isoformat()
        result = self.client.table("organization_members").update(changes).eq("id", member_id).eq("organization_id", org["id"]).execute()
        if not result.data:
            return None
        member = result.data[0]
        self.client.table("profiles").update({"role": member["role"]}).eq("id", member["user_id"]).execute()
        if status in {"suspended", "removed"}:
            try:
                self.client.auth.admin.update_user_by_id(member["user_id"], {"ban_duration": "876000h"})
            except Exception:
                pass
        return member

    async def list_applications(self, user_id: str) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        result = self.client.table("applications").select("*").eq("organization_id", org["id"]).order("created_at", desc=True).execute()
        return result.data or []

    async def create_application(self, user_id: str, name: str, environment: str, provider: str, model: str) -> Dict:
        org = await self.get_organization_for_user(user_id)
        if not org:
            org = await self.ensure_organization(user_id)
        result = self.client.table("applications").insert({
            "organization_id": org["id"],
            "name": name[:120],
            "environment": environment if environment in {"development", "staging", "production"} else "production",
            "provider": provider[:80],
            "model": model[:120],
            "created_by": user_id,
        }).execute()
        return result.data[0]

    async def update_application(self, user_id: str, app_id: str, status: Optional[str] = None, model: Optional[str] = None) -> Optional[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return None
        changes = {}
        if status in {"active", "disabled"}:
            changes["status"] = status
        if model:
            changes["model"] = model[:120]
        if not changes:
            return None
        result = self.client.table("applications").update(changes).eq("id", app_id).eq("organization_id", org["id"]).execute()
        return result.data[0] if result.data else None

    async def list_policies(self, user_id: str) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        result = self.client.table("security_policies").select("*").eq("organization_id", org["id"]).order("created_at").execute()
        return result.data or []

    async def update_policy(self, user_id: str, policy_id: str, values: Dict[str, Any]) -> Optional[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return None
        allowed = {"name", "pii_protection", "prompt_injection_protection", "sensitive_content_protection", "rate_limit_per_minute", "approved_models", "allowed_providers", "audit_logging"}
        changes = {k: v for k, v in values.items() if k in allowed}
        if "rate_limit_per_minute" in changes:
            changes["rate_limit_per_minute"] = max(1, min(int(changes["rate_limit_per_minute"]), 10000))
        if not changes:
            return None
        result = self.client.table("security_policies").update(changes).eq("id", policy_id).eq("organization_id", org["id"]).execute()
        return result.data[0] if result.data else None

    @staticmethod
    def _hash_api_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    async def create_api_key(self, user_id: str, name: str = None, expires_days: int = 30, application_id: str = None, employee_id: str = None) -> Dict:
        if not self._initialized:
            await self.initialize()
        org = await self.get_organization_for_user(user_id)
        if not org:
            org = await self.ensure_organization(user_id)
        api_key = f"aifw_{secrets.token_urlsafe(32)}"
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        data = {
            "user_id": user_id,
            "organization_id": org["id"],
            "application_id": application_id,
            "employee_id": employee_id,
            "key_hash": self._hash_api_key(api_key),
            "name": name,
            "is_active": True,
            "expires_at": expires_at.isoformat(),
        }
        result = self.client.table("api_keys").insert(data).execute()
        if not result.data:
            return None
        record = dict(result.data[0])
        record["key"] = api_key
        return record

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        if not self._initialized:
            await self.initialize()
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        result = self.client.table("api_keys").select("id,name,is_active,expires_at,created_at,revoked_at,last_used_at,application_id,employee_id").eq("organization_id", org["id"]).order("created_at", desc=True).execute()
        return result.data or []

    async def verify_api_key(self, api_key: str) -> Optional[Dict]:
        if not self._initialized:
            await self.initialize()
        key_hash = self._hash_api_key(api_key)
        result = self.client.table("api_keys").select("*").eq("key_hash", key_hash).execute()
        if not result.data:
            return None
        key_data = result.data[0]
        if not key_data.get("is_active") or key_data.get("revoked_at"):
            return None
        expires_at_value = key_data.get("expires_at")
        if expires_at_value:
            expires_at = datetime.fromisoformat(expires_at_value.replace("Z", "+00:00"))
            if expires_at <= datetime.now(timezone.utc):
                return None
        self.client.table("api_keys").update({"last_used_at": datetime.now(timezone.utc).isoformat()}).eq("id", key_data["id"]).execute()
        return key_data

    async def revoke_key(self, key_id: str, user_id: str):
        if not self._initialized:
            await self.initialize()
        org = await self.get_organization_for_user(user_id)
        if not org:
            return
        self.client.table("api_keys").update({"is_active": False, "revoked_at": datetime.now(timezone.utc).isoformat()}).eq("id", key_id).eq("organization_id", org["id"]).execute()

    async def log_audit(self, log_data: Dict[str, Any]):
        if not self._initialized:
            await self.initialize()
        result = self.client.table("audit_logs").insert(log_data).execute()
        return result.data[0] if result.data else None

    async def log_security_event(self, event_data: Dict[str, Any]):
        if not self._initialized:
            await self.initialize()
        result = self.client.table("security_events").insert(event_data).execute()
        return result.data[0] if result.data else None

    async def get_user_stats(self, user_id: str) -> Dict:
        if not self._initialized:
            await self.initialize()
        total_result = self.client.table("audit_logs").select("count", count="exact").eq("user_id", user_id).execute()
        blocked_result = self.client.table("audit_logs").select("count", count="exact").eq("user_id", user_id).eq("action", "BLOCK").execute()
        latency_result = self.client.table("audit_logs").select("latency_ms").eq("user_id", user_id).execute()
        cost_result = self.client.table("audit_logs").select("cost").eq("user_id", user_id).execute()
        latencies = [row["latency_ms"] for row in (latency_result.data or []) if row.get("latency_ms") is not None]
        total_cost = sum(row.get("cost") or 0 for row in (cost_result.data or []))
        total = total_result.count or 0
        blocked = blocked_result.count or 0
        return {"total_requests": total, "blocked_requests": blocked, "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0, "total_cost": total_cost, "threat_rate": (blocked / total * 100) if total else 0}

    async def get_org_stats(self, user_id: str) -> Dict:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return {"total_requests": 0, "blocked_requests": 0, "avg_latency_ms": 0, "total_cost": 0, "threat_rate": 0, "employees": 0, "applications": 0}
        base = self.client.table("audit_logs").select("latency_ms,cost,action").eq("organization_id", org["id"]).execute().data or []
        total = len(base)
        blocked = sum(1 for row in base if row.get("action") == "BLOCK")
        latencies = [row.get("latency_ms") for row in base if row.get("latency_ms") is not None]
        members = self.client.table("organization_members").select("id", count="exact").eq("organization_id", org["id"]).neq("status", "removed").execute()
        apps = self.client.table("applications").select("id", count="exact").eq("organization_id", org["id"]).execute()
        return {"total_requests": total, "blocked_requests": blocked, "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0, "total_cost": sum(row.get("cost") or 0 for row in base), "threat_rate": (blocked / total * 100) if total else 0, "employees": members.count or 0, "applications": apps.count or 0}

    async def get_org_activity(self, user_id: str, limit: int = 50) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        result = self.client.table("audit_logs").select("*").eq("organization_id", org["id"]).order("timestamp", desc=True).limit(limit).execute()
        return result.data or []

    async def get_user_requests(self, user_id: str, limit: int = 50) -> List[Dict]:
        if not self._initialized:
            await self.initialize()
        result = self.client.table("audit_logs").select("*").eq("user_id", user_id).order("timestamp", desc=True).limit(limit).execute()
        return result.data or []

    async def get_threat_timeline(self, user_id: str, days: int = 7) -> List[Dict]:
        if not self._initialized:
            await self.initialize()
        start_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        result = self.client.table("security_events").select("*").eq("user_id", user_id).gte("timestamp", start_date).order("timestamp", desc=True).execute()
        return result.data or []

    async def get_logs(self, limit: int = 100, offset: int = 0, user_id: str = None) -> List[Dict]:
        if not self._initialized:
            await self.initialize()
        query = self.client.table("audit_logs").select("*")
        if user_id:
            query = query.eq("user_id", user_id)
        return query.order("timestamp", desc=True).limit(limit).offset(offset).execute().data or []

    async def save_webhook_config(self, user_id: str, url: str, events: List[str]):
        if not self._initialized:
            await self.initialize()
        data = {"user_id": user_id, "url": url, "events": events, "created_at": datetime.now(timezone.utc).isoformat()}
        result = self.client.table("webhook_configs").upsert(data).execute()
        return result.data[0] if result.data else None
