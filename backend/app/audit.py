"""Append-only audit trail for administrative and security-relevant actions.

Events never contain secrets: any metadata key that looks like a credential is dropped before
the event is written. Writing is best-effort for admin actions (a failure is logged loudly but
does not undo the change); see docs/KNOWN_LIMITATIONS.md for the transactional-audit follow-up.
"""
from __future__ import annotations

import hashlib
import json
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


GENESIS = "0" * 64
_HASHED_FIELDS = ("organization_id", "actor_user_id", "action", "resource_type", "resource_id", "outcome", "request_id", "created_at")


def compute_event_hash(row: Dict[str, Any], prev_hash: str) -> str:
    body = {k: row.get(k) for k in _HASHED_FIELDS}
    body["metadata"] = {k: v for k, v in (row.get("metadata") or {}).items() if k != "chain"}
    return hashlib.sha256((prev_hash + json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))).encode()).hexdigest()


def verify_chain(rows: list) -> Dict[str, Any]:
    """Check events (oldest first, one organisation). Detects edited, deleted or reordered rows and forks.

    Tamper-*evidence* only: someone holding the service-role key can rewrite and re-hash the whole chain, so the latest
    hash should be anchored outside the database (see docs/KNOWN_LIMITATIONS.md). Rows written before chaining are skipped."""
    prev, checked = None, 0
    for index, row in enumerate(rows):
        chain = (row.get("metadata") or {}).get("chain")
        if not chain:
            continue
        expected_prev = prev if prev is not None else chain.get("prev")
        if chain.get("prev") != expected_prev or chain.get("hash") != compute_event_hash(row, chain.get("prev", "")):
            return {"ok": False, "checked": checked, "broken_at": index, "event_id": row.get("id")}
        prev, checked = chain["hash"], checked + 1
    return {"ok": True, "checked": checked, "head": prev}


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
        prev = GENESIS
        if organization_id:
            last = supabase.client.table("audit_events").select("metadata").eq("organization_id", organization_id).order("created_at", desc=True).limit(1).execute().data
            prev = ((last[0].get("metadata") or {}).get("chain") or {}).get("hash", GENESIS) if last else GENESIS
        row["metadata"]["chain"] = {"prev": prev, "hash": compute_event_hash(row, prev)}
        supabase.client.table("audit_events").insert(row).execute()
        return True
    except Exception:
        logger.error("audit_event_write_failed action=%s resource=%s/%s org=%s", action, resource_type,
                     resource_id, organization_id, exc_info=True)
        return False
