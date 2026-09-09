from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict
from datetime import datetime, timezone
import os

from app.supabase_client import SupabaseManager

security = HTTPBearer(auto_error=False)
supabase = SupabaseManager()


def unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def get_current_user(token: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    """Validate a Supabase Auth access token and return the authenticated user id."""
    if token is None or not token.credentials:
        raise unauthorized("Missing bearer token")
    try:
        if not supabase._initialized:
            await supabase.initialize()
        response = supabase.client.auth.get_user(token.credentials)
        user = response.user
        if user is None or user.id is None:
            raise unauthorized()
        return str(user.id)
    except HTTPException:
        raise
    except Exception:
        raise unauthorized()


class AuthManager:
    """Organization authorization backed by the server-side profile role."""

    async def _role(self, user_id: str) -> str | None:
        return await supabase.get_member_role(user_id)

    async def require_admin(self, current_user: str = Depends(get_current_user)) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin", "security"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator permission required")
        return current_user

    async def require_security(self, current_user: str = Depends(get_current_user)) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin", "security"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Security administrator permission required")
        return current_user

    async def require_owner_or_admin(self, current_user: str = Depends(get_current_user)) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner or administrator permission required")
        return current_user

    async def require_owner(self, current_user: str = Depends(get_current_user)) -> str:
        role = await self._role(current_user)
        if role != "owner":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization owner permission required")
        return current_user


class APIKeyManager:
    def __init__(self):
        self.supabase = supabase

    async def create_api_key(self, user_id: str, name: str = None, expires_days: int = 30, application_id: str = None, employee_id: str = None) -> Dict:
        return await self.supabase.create_api_key(user_id, name=name, expires_days=expires_days, application_id=application_id, employee_id=employee_id)

    async def _enforce_billing(self, key_data: Dict):
        """Optional server-side quota gate. Disabled by default until Stripe price IDs are configured."""
        if os.getenv("BILLING_ENFORCE", "false").lower() != "true":
            return
        org_id = key_data.get("organization_id")
        if not org_id:
            raise HTTPException(status_code=402, detail="API key is not attached to an organization")
        sub = self.supabase.client.table("billing_subscriptions").select("plan_key,status").eq("organization_id", org_id).maybe_single().execute().data
        if not sub or sub.get("status") not in {"active", "trialing"}:
            raise HTTPException(status_code=402, detail="Organization billing is not active")
        limits = {"starter": 10000, "professional": 100000, "enterprise": None}
        limit = limits.get(sub.get("plan_key"), 0)
        if limit is None:
            return
        period = datetime.now(timezone.utc).date().replace(day=1).isoformat()
        row = self.supabase.client.table("usage_counters").select("request_count").eq("organization_id", org_id).eq("period_start", period).maybe_single().execute().data or {}
        if int(row.get("request_count") or 0) >= limit:
            raise HTTPException(status_code=429, detail="Monthly AI request limit reached")
        current = self.supabase.client.table("usage_counters").select("*").eq("organization_id", org_id).eq("period_start", period).maybe_single().execute().data or {}
        self.supabase.client.table("usage_counters").upsert({"organization_id":org_id,"period_start":period,"request_count":int(current.get("request_count") or 0)+1,"blocked_count":int(current.get("blocked_count") or 0),"tokens_used":int(current.get("tokens_used") or 0)}, on_conflict="organization_id,period_start").execute()

    async def verify_api_key_value(self, api_key: str) -> Dict:
        if not api_key:
            raise unauthorized("Missing API key")
        key_data = await self.supabase.verify_api_key(api_key)
        if not key_data:
            raise unauthorized("Invalid or expired API key")
        await self._enforce_billing(key_data)
        return key_data

    async def verify_api_key(self, token: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
        if token is None or not token.credentials:
            raise unauthorized("Missing API key")
        key_data = await self.verify_api_key_value(token.credentials)
        return key_data["user_id"]

    async def verify_api_key_context(self, token: HTTPAuthorizationCredentials | None = Depends(security)) -> Dict:
        if token is None or not token.credentials:
            raise unauthorized("Missing API key")
        return await self.verify_api_key_value(token.credentials)

    async def revoke_key(self, key_id: str, user_id: str):
        await self.supabase.revoke_key(key_id, user_id)

    async def list_keys(self, user_id: str) -> list:
        return await self.supabase.list_api_keys(user_id)
