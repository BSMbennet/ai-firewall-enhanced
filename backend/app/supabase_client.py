import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

from supabase import create_client, Client


class SupabaseManager:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.client: Client | None = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        if not self.url or not self.service_key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
        self.client = create_client(self.url, self.service_key)
        self._initialized = True

    async def close(self):
        self._initialized = False
        self.client = None

    async def health_check(self) -> bool:
        try:
            if not self._initialized:
                await self.initialize()
            self.client.table("organizations").select("id").limit(1).execute()
            return True
        except Exception:
            return False

    async def get_member_role(self, user_id: str) -> Optional[str]:
        if not self._initialized:
            await self.initialize()
        row = self.client.table("organization_members").select("role,status").eq("user_id", user_id).maybe_single().execute().data
        if not row or row.get("status") in {"suspended", "removed"}:
            return None
        return row.get("role")

    async def get_organization_for_user(self, user_id: str) -> Optional[Dict]:
        if not self._initialized:
            await self.initialize()
        profile = self.client.table("profiles").select("organization_id").eq("id", user_id).maybe_single().execute().data
        if not profile or not profile.get("organization_id"):
            return None
        return self.client.table("organizations").select("*").eq("id", profile["organization_id"]).maybe_single().execute().data

    async def ensure_organization(self, user_id: str) -> Dict:
        org = await self.get_organization_for_user(user_id)
        if org:
            return org
        profile = self.client.table("profiles").select("full_name").eq("id", user_id).maybe_single().execute().data or {}
        org = self.client.table("organizations").insert({"name": f"{profile.get('full_name') or 'My'} Organization"}).execute().data[0]
        self.client.table("profiles").update({"organization_id": org["id"], "role": "owner"}).eq("id", user_id).execute()
        self.client.table("organization_members").upsert({"organization_id": org["id"], "user_id": user_id, "full_name": profile.get("full_name"), "role": "owner", "status": "active"}, on_conflict="organization_id,user_id").execute()
        return org

    async def list_members(self, user_id: str) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        return self.client.table("organization_members").select("*").eq("organization_id", org["id"]).order("created_at", desc=True).execute().data or []

    async def invite_member(self, user_id: str, email: str, full_name: str, role: str = "member") -> Dict:
        org = await self.get_organization_for_user(user_id)
        if not org:
            raise ValueError("Organization not found")
        allowed_roles = {"admin", "security", "developer", "member", "viewer"}
        if role not in allowed_roles:
            raise ValueError("Invalid employee role")
        if not email or "@" not in email:
            raise ValueError("Valid employee email is required")
        existing = self.client.table("organization_members").select("id,status").eq("organization_id", org["id"]).eq("email", email).maybe_single().execute().data
        if existing and existing.get("status") != "removed":
            raise ValueError("An employee with this email already exists")
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
        actor = self.client.table("organization_members").select("role").eq("organization_id", org["id"]).eq("user_id", actor_id).maybe_single().execute().data or {}
        target = self.client.table("organization_members").select("*").eq("id", member_id).eq("organization_id", org["id"]).maybe_single().execute().data
        if not target:
            return None
        actor_role = actor.get("role")
        if target.get("role") == "owner" or role == "owner":
            raise ValueError("Owner membership can only be changed through an ownership transfer")
        if actor_role != "owner" and role == "admin":
            raise ValueError("Only the owner can grant administrator role")
        if actor_role != "owner" and status == "removed" and target.get("user_id") == actor_id:
            raise ValueError("Administrators cannot remove themselves")
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
        elif status == "active":
            try:
                self.client.auth.admin.update_user_by_id(member["user_id"], {"ban_duration": "none"})
            except Exception:
                pass
        return member

    async def list_applications(self, user_id: str) -> List[Dict]:
        org = await self.get_organization_for_user(user_id)
        if not org:
            return []
        return self.client.table("applications").select("*").eq("organization_id", org["id"]).order("created_at", desc=True).execute().data or []

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
        return self.client.table("security_policies").select("*").eq("organization_id", org["id"]).order("created_at").execute().data or []

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
        if application_id:
            app = self.client.table("applications").select("id,status").eq("id", application_id).eq("organization_id", org["id"]).maybe_single().execute().data
            if not app:
                raise ValueError("Application does not belong to this organization")
            if app.get("status") != "active":
                raise ValueError("Application is disabled")
        if employee_id:
            employee = self.client.table("organization_members").select("id,status").eq("id", employee_id).eq("organization_id", org["id"]).maybe_single().execute().data
            if not employee:
                raise ValueError("Employee does not belong to this organization")
            if employee.get("status") != "active":
                raise ValueError("API keys cannot be assigned to inactive employees")
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
        result = self.client.table("api_keys").select("*").eq("key_hash", key_hash).maybe_single().execute()
        key_data = result.data
        if not key_data:
            return None
        if not key_data.get("is_active") or key_data.get("revoked_at"):
            return None
        expires_at_value = key_data.get("expires_at")
        if expires_at_value:
            expires_at = datetime.fromisoformat(expires_at_value.replace("Z", "+00:00"))
            if expires_at <= datetime.now(timezone.utc):
                return None
        if key_data.get("organization_id"):
            member = self.client.table("organization_members").select("status,role").eq("organization_id", key_data["organization_id"]).eq("user_id", key_data["user_id"]).maybe_single().execute().data
            if not member or member.get("status") in {"suspended", "removed"}:
                return None
            if key_data.get("employee_id"):
                employee = self.client.table("organization_members").select("status").eq("id", key_data["employee_id"]).eq("organization_id", key_data["organization_id"]).maybe_single().execute().data
                if not employee or employee.get("status") in {"suspended", "removed"}:
                    return None
        self.client.table("api_keys").update({"last_used_at": datetime.now(timezone.utc).isoformat()}).eq("id", key_data["id"]).execute()
        return key_data

    async def revoke_key(self, key_id: str, user_id: str):
        org = await self.get_organization_for_user(user_id)
        if not org:
            return
        self.client.table("api_keys").update({"is_active": False, "revoked_at": datetime.now(timezone.utc).isoformat()}).eq("id", key_id).eq("organization_id", org["id"]).execute()
