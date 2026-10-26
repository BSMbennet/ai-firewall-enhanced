"""Monthly token budget per organisation (hard stop).

``MONTHLY_TOKEN_BUDGET`` (env, integer, unset = no budget) is the number of provider tokens an organisation may use per
calendar month (UTC), counted from ``usage_counters.tokens_used`` which the gateway updates after every forwarded call.

Semantics, stated plainly:
* Hard stop: once recorded usage has reached the budget, new requests are refused with 429 ``token_budget_exceeded``
  before anything is forwarded.
* It is a *check-then-act* control on usage that is recorded after each call, so concurrent in-flight requests can
  overshoot by up to (concurrency x max_tokens cap). It is a spend ceiling, not an exact meter.
* Fail closed: if a budget is configured and usage cannot be read, the request is refused (503) rather than allowed
  unmetered.
* The budget is global (environment). Per-organisation budgets need a schema change and are not implemented.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Optional

from app.gateway import GatewayError

logger = logging.getLogger("aifirewall.budget")


def monthly_token_budget() -> Optional[int]:
    raw = os.getenv("MONTHLY_TOKEN_BUDGET", "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        logger.error("MONTHLY_TOKEN_BUDGET is not an integer; failing closed (0 tokens allowed)")
        return 0
    return max(0, value)


async def enforce_token_budget(supabase_client: Any, organization_id: Optional[str],
                               on_exceeded: Optional[Callable[[int, int], Awaitable[None]]] = None) -> None:
    budget = monthly_token_budget()
    if budget is None or not organization_id:
        return
    period_start = datetime.now(timezone.utc).date().replace(day=1).isoformat()
    try:
        rows = (supabase_client.table("usage_counters").select("tokens_used")
                .eq("organization_id", organization_id).eq("period_start", period_start).limit(1).execute().data) or []
    except Exception:
        logger.error("token_budget_read_failed org=%s", organization_id, exc_info=True)
        raise GatewayError(503, "budget_unavailable", "Usage could not be verified, so the request was not forwarded.", "service_unavailable")
    used = int(rows[0].get("tokens_used") or 0) if rows else 0
    if used >= budget:
        if on_exceeded:
            await on_exceeded(used, budget)
        raise GatewayError(429, "token_budget_exceeded", "The organization's monthly token budget has been reached.", "rate_limit_error")
