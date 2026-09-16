from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt

from app.supabase_client import SupabaseManager


security = HTTPBearer(auto_error=False)
supabase = SupabaseManager()


# ---------------------------------------------------------------------------
# Common HTTP errors
# ---------------------------------------------------------------------------

def unauthorized(
    detail: str = "Could not validate credentials",
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def forbidden(detail: str = "Insufficient permissions") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Supabase organization authentication policies
# ---------------------------------------------------------------------------

async def enforce_org_auth_policy(
    user_id: str,
    user: Any,
    access_token: str,
) -> None:
    """
    Enforce organization-level SSO and MFA requirements.

    These policies are read from organization_settings and are applied
    after Supabase validates the access token.
    """
    profile = await supabase.get_profile(user_id)
    organization_id = profile.get("organization_id") if profile else None

    if not organization_id:
        return

    settings_response = (
        supabase.client
        .table("organization_settings")
        .select("require_mfa,require_sso")
        .eq("organization_id", organization_id)
        .maybe_single()
        .execute()
    )

    settings = settings_response.data or {}

    if settings.get("require_sso"):
        identities = getattr(user, "identities", None) or []
        providers: set[str] = set()

        for identity in identities:
            provider = getattr(identity, "provider", None)

            if provider is None and isinstance(identity, dict):
                provider = identity.get("provider")

            if provider:
                providers.add(str(provider).lower())

        if not providers or providers <= {"email", "password"}:
            raise forbidden(
                "Organization SSO is required for this account"
            )

    if settings.get("require_mfa"):
        try:
            claims = jwt.get_unverified_claims(access_token)
            assurance_level = str(claims.get("aal") or "aal1")
        except Exception:
            assurance_level = "aal1"

        if assurance_level != "aal2":
            raise forbidden(
                "Organization MFA verification is required"
            )


async def get_current_user(
    token: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
    """Validate a Supabase Auth bearer token and enforce organization policies."""
    if token is None or not token.credentials:
        raise unauthorized("Missing bearer token")

    try:
        if not supabase._initialized:
            await supabase.initialize()

        response = supabase.client.auth.get_user(token.credentials)
        user = response.user

        if user is None or not getattr(user, "id", None):
            raise unauthorized()

        user_id = str(user.id)

        await enforce_org_auth_policy(
            user_id=user_id,
            user=user,
            access_token=token.credentials,
        )

        return user_id

    except HTTPException:
        raise

    except Exception:
        raise unauthorized()


# ---------------------------------------------------------------------------
# Organization role authorization
# ---------------------------------------------------------------------------

class AuthManager:
    """Organization authorization backed by the server-side member role."""

    async def _role(self, user_id: str) -> str | None:
        """Resolve the effective organization role for a user.

        Prefer the server-side membership helper, then recover from the
        organization_members table when an older account has a missing or
        unsynchronized profile role.
        """
        role = await supabase.get_member_role(user_id)
        if role:
            return str(role).strip().lower()

        try:
            profile = await supabase.get_profile(user_id)
            organization_id = (profile or {}).get("organization_id")

            if organization_id:
                result = (
                    supabase.client
                    .table("organization_members")
                    .select("role,status")
                    .eq("organization_id", organization_id)
                    .eq("user_id", user_id)
                    .maybe_single()
                    .execute()
                )
                member = result.data or {}
                member_role = member.get("role")
                member_status = str(member.get("status") or "active").lower()

                if member_role and member_status != "removed":
                    recovered_role = str(member_role).strip().lower()
                    (
                        supabase.client
                        .table("profiles")
                        .update({"role": recovered_role})
                        .eq("id", user_id)
                        .execute()
                    )
                    return recovered_role
        except Exception as exc:
            print(f"Role recovery failed for {user_id}: {exc}")

        return None

    async def require_admin(
        self,
        current_user: str = Depends(get_current_user),
    ) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin", "security"}:
            raise forbidden("Administrator permission required")
        return current_user

    async def require_security(
        self,
        current_user: str = Depends(get_current_user),
    ) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin", "security"}:
            raise forbidden("Security administrator permission required")
        return current_user

    async def require_owner_or_admin(
        self,
        current_user: str = Depends(get_current_user),
    ) -> str:
        role = await self._role(current_user)
        if role not in {"owner", "admin"}:
            raise forbidden("Owner or administrator permission required")
        return current_user

    async def require_owner(
        self,
        current_user: str = Depends(get_current_user),
    ) -> str:
        role = await self._role(current_user)
        if role != "owner":
            raise forbidden("Organization owner permission required")
        return current_user


# ---------------------------------------------------------------------------
# API-key authorization
# ---------------------------------------------------------------------------

class APIKeyManager:
    """API-key validation, scope enforcement, billing metering, and revocation."""

    DEFAULT_CHAT_SCOPES = {
        "chat",
        "chat:read",
        "chat:write",
        "ai:request",
        "*",
    }

    def __init__(self) -> None:
        self.supabase = supabase

    async def create_api_key(
        self,
        user_id: str,
        name: str | None = None,
        expires_days: int = 30,
        application_id: str | None = None,
        employee_id: str | None = None,
        scopes: Iterable[str] | None = None,
    ) -> Dict[str, Any]:
        safe_name = str(name or "Default Key")[:100]
        try:
            safe_expires_days = max(1, min(int(expires_days or 30), 3650))
        except (TypeError, ValueError):
            safe_expires_days = 30

        normalized_scopes = self.normalize_scopes(scopes)
        result = await self.supabase.create_api_key(
            user_id,
            name=safe_name,
            expires_days=safe_expires_days,
            application_id=application_id,
            employee_id=employee_id,
        )

        if not result:
            return result
        if isinstance(result, dict):
            result.setdefault("scopes", sorted(normalized_scopes))
        return result

    @staticmethod
    def normalize_scopes(scopes: Iterable[str] | None) -> set[str]:
        if not scopes:
            return set()
        normalized: set[str] = set()
        for scope in scopes:
            value = str(scope).strip().lower()
            if value:
                normalized.add(value)
        return normalized

    @classmethod
    def extract_scopes(cls, key_data: Dict[str, Any]) -> set[str]:
        raw_scopes = key_data.get("scopes")
        if raw_scopes is None:
            return set()
        if isinstance(raw_scopes, dict):
            return cls.normalize_scopes(
                scope for scope, enabled in raw_scopes.items() if enabled
            )
        if isinstance(raw_scopes, str):
            raw_scopes = raw_scopes.replace(",", " ").split()
        if isinstance(raw_scopes, (list, tuple, set)):
            return cls.normalize_scopes(raw_scopes)
        return set()

    @classmethod
    def has_scope(cls, key_data: Dict[str, Any], required_scope: str) -> bool:
        required = str(required_scope).strip().lower()
        if not required:
            return True
        scopes = cls.extract_scopes(key_data)
        if not scopes:
            return required in cls.DEFAULT_CHAT_SCOPES
        return "*" in scopes or required in scopes

    @classmethod
    def require_scope(cls, key_data: Dict[str, Any], required_scope: str) -> None:
        if not cls.has_scope(key_data, required_scope):
            raise forbidden(
                f"API key does not have the required scope: {required_scope}"
            )

    @staticmethod
    def _is_expired(key_data: Dict[str, Any]) -> bool:
        expires_at = key_data.get("expires_at")
        if not expires_at:
            return False
        try:
            if isinstance(expires_at, datetime):
                expiry = expires_at
            else:
                value = str(expires_at).replace("Z", "+00:00")
                expiry = datetime.fromisoformat(value)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return expiry <= datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return True

    @classmethod
    def validate_key_status(cls, key_data: Dict[str, Any]) -> None:
        if key_data.get("is_active") is False:
            raise unauthorized("API key has been revoked")
        if cls._is_expired(key_data):
            raise unauthorized("Invalid or expired API key")

    async def _enforce_billing(self, key_data: Dict[str, Any]) -> None:
        organization_id = key_data.get("organization_id")
        if not organization_id:
            raise forbidden("API key is not attached to an organization")

        billing_enforce = os.getenv("BILLING_ENFORCE", "false").lower() == "true"
        limit: int | None = None

        if billing_enforce:
            subscription = (
                self.supabase.client.table("billing_subscriptions")
                .select("plan_key,status")
                .eq("organization_id", organization_id)
                .maybe_single()
                .execute().data
            )
            if not subscription or subscription.get("status") not in {"active", "trialing"}:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail="Organization billing is not active",
                )
            limit = {
                "starter": 10_000,
                "professional": 100_000,
                "enterprise": None,
            }.get(subscription.get("plan_key"), 0)

        period_start = datetime.now(timezone.utc).date().replace(day=1).isoformat()
        result = self.supabase.client.rpc(
            "consume_gateway_usage",
            {
                "p_organization_id": organization_id,
                "p_period_start": period_start,
                "p_limit": limit,
            },
        ).execute()
        rows = result.data or [{}]
        first_row = rows[0] if isinstance(rows, list) else rows
        if not first_row.get("allowed", True):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Monthly AI request limit reached",
            )

    async def record_gateway_outcome(
        self,
        key_data: Dict[str, Any],
        blocked: bool,
        tokens: int = 0,
    ) -> None:
        organization_id = key_data.get("organization_id")
        if not organization_id:
            return
        period_start = datetime.now(timezone.utc).date().replace(day=1).isoformat()
        try:
            self.supabase.client.rpc(
                "record_gateway_outcome",
                {
                    "p_organization_id": organization_id,
                    "p_period_start": period_start,
                    "p_blocked": bool(blocked),
                    "p_tokens": max(0, int(tokens or 0)),
                },
            ).execute()
        except Exception as exc:
            print(f"Gateway outcome metering failed: {exc}")

    async def verify_api_key_value(self, api_key: str) -> Dict[str, Any]:
        if not api_key:
            raise unauthorized("Missing API key")
        key_data = await self.supabase.verify_api_key(api_key)
        if not key_data:
            raise unauthorized("Invalid or expired API key")
        self.validate_key_status(key_data)
        await self._enforce_billing(key_data)
        return key_data

    async def verify_api_key(
        self,
        token: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> str:
        if token is None or not token.credentials:
            raise unauthorized("Missing API key")
        key_data = await self.verify_api_key_value(token.credentials)
        return str(key_data["user_id"])

    async def verify_api_key_context(
        self,
        token: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> Dict[str, Any]:
        if token is None or not token.credentials:
            raise unauthorized("Missing API key")
        return await self.verify_api_key_value(token.credentials)

    async def revoke_key(self, key_id: str, user_id: str) -> Any:
        return await self.supabase.revoke_key(key_id, user_id)

    async def list_keys(self, user_id: str) -> list:
        return await self.supabase.list_api_keys(user_id)
