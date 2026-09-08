from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict

from app.supabase_client import SupabaseManager

security = HTTPBearer(auto_error=False)
supabase = SupabaseManager()


def unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    token: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
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
    """Authorization helpers backed by Supabase Auth."""

    async def require_admin(
        self,
        current_user: str = Depends(get_current_user),
    ) -> bool:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin authorization is not configured",
        )


class APIKeyManager:
    def __init__(self):
        self.supabase = supabase

    async def create_api_key(self, user_id: str, name: str = None, expires_days: int = 30) -> Dict:
        return await self.supabase.create_api_key(
            user_id,
            name=name,
            expires_days=expires_days,
        )

    async def verify_api_key_value(self, api_key: str) -> str:
        if not api_key:
            raise unauthorized("Missing API key")
        key_data = await self.supabase.verify_api_key(api_key)
        if not key_data:
            raise unauthorized("Invalid or expired API key")
        return key_data["user_id"]

    async def verify_api_key(
        self,
        token: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> str:
        if token is None or not token.credentials:
            raise unauthorized("Missing API key")
        return await self.verify_api_key_value(token.credentials)

    async def revoke_key(self, key_id: str, user_id: str):
        await self.supabase.revoke_key(key_id, user_id)

    async def list_keys(self, user_id: str) -> list:
        return await self.supabase.list_api_keys(user_id)
