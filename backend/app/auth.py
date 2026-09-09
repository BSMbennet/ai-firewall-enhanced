from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict
from datetime import datetime, timezone
from jose import jwt

from app.supabase_client import SupabaseManager

security = HTTPBearer(auto_error=False)
supabase = SupabaseManager()


def unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def enforce_org_auth_policy(user_id: str, user, access_token: str) -> None:
    profile = await supabase.get_profile(user_id)
    org_id = profile.get("organization_id") if profile else None
    if not org_id:
        return
    settings = supabase.client.table("organization_settings").select("require_mfa,require_sso").eq("organization_id", org_id).maybe_single().execute().data or {}
    if settings.get("require_sso"):
        identities = getattr(user, "identities", None) or []
        providers = set()
        for identity in identities:
            provider = getattr(identity, "provider", None)
            if provider is None and isinstance(identity, dict): provider = identity.get("provider")
            if provider: providers.add(str(provider).lower())
        if not providers or providers <= {"email", "password"}:
            raise HTTPException(status_code=403, detail="Organization SSO is required for this account")
    if settings.get("require_mfa"):
        try:
            aal = str(jwt.get_unverified_claims(access_token).get("aal") or "aal1")
        except Exception:
            aal = "aal1"
        if aal != "aal2":
            raise HTTPException(status_code=403, detail="Organization MFA verification is required")


async def get_current_user(token: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    """Validate a Supabase Auth token and enforce organization SSO/MFA policy."""
    if token is None or not token.credentials:
        raise unauthorized("Missing bearer token")
    try:
        if not supabase._initialized:
            await supabase.initialize()
        response = supabase.client.auth.get_user(token.credentials)
        user = response.user
        if user is None or user.id is None:
            raise unauthorized()
        user_id = str(user.id)
        await enforce_org_auth_policy(user_id, user, token.credentials)
        return user_id
    except HTTPException:
        raise
    except Exception:
        raise unauthorized()


class AuthManager:
    """Organization authorization backed by the server-side profile role."""
    async def _role(self, user_id: str) -> str | None:
        return await supabase.get_member_role(user_id)
    async def require_admin(self, current_user: str = Depends(get_current_user)) -> str:
        if await self._role(current_user) not in {"owner", "admin", "security"}: raise HTTPException(403, "Administrator permission required")
        return current_user
    async def require_security(self, current_user: str = Depends(get_current_user)) -> str:
        if await self._role(current_user) not in {"owner", "admin", "security"}: raise HTTPException(403, "Security administrator permission required")
        return current_user
    async def require_owner_or_admin(self, current_user: str = Depends(get_current_user)) -> str:
        if await self._role(current_user) not in {"owner", "admin"}: raise HTTPException(403, "Owner or administrator permission required")
        return current_user
    async def require_owner(self, current_user: str = Depends(get_current_user)) -> str:
        if await self._role(current_user) != "owner": raise HTTPException(403, "Organization owner permission required")
        return current_user


class APIKeyManager:
    def __init__(self): self.supabase = supabase
    async def create_api_key(self, user_id: str, name: str = None, expires_days: int = 30, application_id: str = None, employee_id: str = None) -> Dict:
        return await self.supabase.create_api_key(user_id, name=name, expires_days=expires_days, application_id=application_id, employee_id=employee_id)
    async def _enforce_billing(self, key_data: Dict):
        org_id = key_data.get("organization_id")
        if not org_id: raise HTTPException(status_code=403, detail="API key is not attached to an organization")
        enforce = __import__("os").getenv("BILLING_ENFORCE", "false").lower() == "true"
        limit = None
        if enforce:
            sub = self.supabase.client.table("billing_subscriptions").select("plan_key,status").eq("organization_id", org_id).maybe_single().execute().data
            if not sub or sub.get("status") not in {"active", "trialing"}: raise HTTPException(status_code=402, detail="Organization billing is not active")
            limit = {"starter": 10000, "professional": 100000, "enterprise": None}.get(sub.get("plan_key"), 0)
        period = datetime.now(timezone.utc).date().replace(day=1).isoformat()
        result = self.supabase.client.rpc("consume_gateway_usage", {"p_organization_id": org_id, "p_period_start": period, "p_limit": limit}).execute()
        if not (result.data or [{}])[0].get("allowed", True): raise HTTPException(status_code=429, detail="Monthly AI request limit reached")
    async def record_gateway_outcome(self, key_data: Dict, blocked: bool, tokens: int = 0):
        org_id = key_data.get("organization_id")
        if not org_id: return
        period = datetime.now(timezone.utc).date().replace(day=1).isoformat()
        try: self.supabase.client.rpc("record_gateway_outcome", {"p_organization_id": org_id, "p_period_start": period, "p_blocked": bool(blocked), "p_tokens": max(0, int(tokens or 0))}).execute()
        except Exception as exc: print(f"Gateway outcome metering failed: {exc}")
    async def verify_api_key_value(self, api_key: str) -> Dict:
        if not api_key: raise unauthorized("Missing API key")
        key_data = await self.supabase.verify_api_key(api_key)
        if not key_data: raise unauthorized("Invalid or expired API key")
        await self._enforce_billing(key_data)
        return key_data
    async def verify_api_key(self, token: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
        if token is None or not token.credentials: raise unauthorized("Missing API key")
        return (await self.verify_api_key_value(token.credentials))["user_id"]
    async def verify_api_key_context(self, token: HTTPAuthorizationCredentials | None = Depends(security)) -> Dict:
        if token is None or not token.credentials: raise unauthorized("Missing API key")
        return await self.verify_api_key_value(token.credentials)
    async def revoke_key(self, key_id: str, user_id: str): await self.supabase.revoke_key(key_id, user_id)
    async def list_keys(self, user_id: str) -> list: return await self.supabase.list_api_keys(user_id)
