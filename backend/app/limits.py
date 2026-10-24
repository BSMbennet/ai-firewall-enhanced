"""Rate limiting for the gateway and for credential-lifecycle operations.

Algorithm: fixed window per (scope, identifier). The window starts at the first hit and the counter is incremented
atomically on the store, so concurrent requests - including across several application instances sharing Upstash -
cannot both observe the same count. A fixed window permits at most 2x ``limit`` across a window boundary; that is an
accepted, documented trade-off for simplicity and a single round trip.

Store failure policy (documented in docs/SECURITY_CONTROLS.md): if the shared store is unconfigured, slow or failing,
limits keep being enforced by an in-process counter. Limits are then per instance (so the effective ceiling is
``limit x instances``), the decision is flagged ``degraded`` and logged - but traffic is never allowed unmetered, and
a store outage does not become a service outage.
"""
from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional, Tuple

from fastapi import Depends, HTTPException

logger = logging.getLogger("aifirewall.limits")

STORE_TIMEOUT_SECONDS = 1.0
MAX_IN_PROCESS_KEYS = 50_000
_DEGRADED_LOG_INTERVAL_SECONDS = 60.0

# Atomic on the server: increment, start the window on first hit, and repair a key that somehow lost its TTL
# (which would otherwise lock the caller out forever).
_LUA_HIT = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {c, ttl}
"""


class StoreUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int  # seconds until the window resets
    first_rejection: bool = False  # True only for the first denied hit in a window (used to bound audit volume)
    degraded: bool = False

    def headers(self) -> Dict[str, str]:
        headers = {"X-RateLimit-Limit": str(self.limit), "X-RateLimit-Remaining": str(self.remaining),
                   "X-RateLimit-Reset": str(self.retry_after)}
        if not self.allowed:
            headers["Retry-After"] = str(max(1, self.retry_after))
        return headers


class InProcessStore:
    """Per-process counters. Single event loop, no awaits inside ``hit`` -> the read-modify-write is atomic."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = MAX_IN_PROCESS_KEYS):
        self._clock = clock
        self._max_keys = max_keys
        self._windows: Dict[str, Tuple[float, int]] = {}

    async def hit(self, key: str, window_ms: int) -> Tuple[int, int]:
        now = self._clock() * 1000
        started, count = self._windows.get(key, (now, 0))
        if now - started >= window_ms:
            started, count = now, 0
        count += 1
        self._windows[key] = (started, count)
        if len(self._windows) > self._max_keys:
            self._evict(now, window_ms)
        return count, max(1, int(window_ms - (now - started)))

    def _evict(self, now: float, window_ms: int) -> None:
        expired = [k for k, (s, _) in self._windows.items() if now - s >= window_ms]
        for k in expired:
            del self._windows[k]
        while len(self._windows) > self._max_keys:  # still over: drop the oldest windows
            del self._windows[min(self._windows, key=lambda k: self._windows[k][0])]


class UpstashStore:
    def __init__(self, client_provider: Callable[[], object]):
        self._client_provider = client_provider

    async def hit(self, key: str, window_ms: int) -> Tuple[int, int]:
        client = self._client_provider()
        if client is None:
            raise StoreUnavailable("rate-limit store is not configured")
        try:
            count, ttl = await asyncio.wait_for(client.eval(_LUA_HIT, keys=[key], args=[str(window_ms)]), STORE_TIMEOUT_SECONDS)
            return int(count), int(ttl)
        except Exception as exc:
            raise StoreUnavailable(type(exc).__name__) from exc


class RateLimiter:
    def __init__(self, primary=None, fallback: Optional[InProcessStore] = None, clock: Callable[[], float] = time.monotonic):
        self.primary = primary
        self.fallback = fallback or InProcessStore(clock)
        self._last_degraded_log = -1e9
        self._clock = clock

    async def check(self, scope: str, identifier: str, limit: int, window_seconds: int) -> Decision:
        limit = max(1, int(limit))
        window_ms = max(1, int(window_seconds)) * 1000
        key = f"rl:{scope}:{identifier}"
        degraded = False
        try:
            if self.primary is None:
                raise StoreUnavailable("no shared store")
            count, ttl_ms = await self.primary.hit(key, window_ms)
        except StoreUnavailable as exc:
            degraded = True
            self._log_degraded(str(exc))
            count, ttl_ms = await self.fallback.hit(key, window_ms)
        allowed = count <= limit
        return Decision(allowed=allowed, limit=limit, remaining=max(0, limit - count),
                        retry_after=max(1, math.ceil(ttl_ms / 1000)), first_rejection=(count == limit + 1), degraded=degraded)

    def _log_degraded(self, reason: str) -> None:
        now = self._clock()
        if now - self._last_degraded_log >= _DEGRADED_LOG_INTERVAL_SECONDS:
            self._last_degraded_log = now
            logger.warning("rate_limit_store_unavailable reason=%s: enforcing per-instance limits", reason)


# Shared instance. app.main attaches the Upstash-backed primary store at import time.
rate_limiter = RateLimiter()


def env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


def lifecycle_limit(action: str, limit: int, window_seconds: int) -> Callable[..., Awaitable[None]]:
    """FastAPI dependency: throttle a sensitive operation per *verified* user.

    Counts every attempt by an authenticated user (including ones later refused with 403), so a compromised low-privilege
    account cannot be used to hammer credential endpoints either.
    """
    from app.auth import get_current_user  # local import: auth imports the Supabase client

    async def dependency(user_id: str = Depends(get_current_user)) -> None:
        decision = await rate_limiter.check(f"lifecycle:{action}", user_id, limit, window_seconds)
        if not decision.allowed:
            logger.warning("lifecycle_rate_limited action=%s", action)
            raise HTTPException(status_code=429, detail=f"Too many {action} requests. Try again later.", headers=decision.headers())

    return dependency
