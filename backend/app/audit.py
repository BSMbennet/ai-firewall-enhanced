"""Append-only audit trail for administrative and security-relevant actions.

Events never contain secrets: any metadata key that looks like a credential is dropped before
the event is written. Writing is best-effort for admin actions (a failure is logged loudly but
does not undo the change); see docs/KNOWN_LIMITATIONS.md for the transactional-audit follow-up.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("aifirewall.audit")

_SENSITIVE_MARKERS = ("secret", "token", "password", "key", "authorization", "credential")
_ALLOWED_KEY_NAMES = {"key_id", "key_prefix", "api_key_id", "old_key_id", "new_key_id", "scopes"}


def sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    clean: Dict[str, Any] = {}
    for name, value in (metadata or {}).items():
        lowered = str(name).lower()
        if lowered not in _ALLOWED_KEY_NAMES and any(marker in lowered for marker in _SENSITIVE_MARKERS):
            continue
        clean[str(name)] = value
    return clean


async def record_event(supabase, *, organization_id: Optional[str], actor_user_id: Optional[str], action: str,
                       resource_type: str, resource_id: Optional[str] = None, outcome: str = "success",
                       request_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
    """Persist one audit event. Returns False (after logging) if it could not be stored."""
    row = {
        "organization_id": organization_id,
        "actor_user_id": actor_user_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "outcome": outcome,
        "request_id": request_id,
        "metadata": sanitize_metadata(metadata),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if not supabase._initialized:
            await supabase.initialize()
        supabase.client.table("audit_events").insert(row).execute()
        return True
    except Exception:
        logger.error("audit_event_write_failed action=%s resource=%s/%s org=%s", action, resource_type,
                     resource_id, organization_id, exc_info=True)
        return False
