"""Pre-authentication per-IP throttle: client IP derivation (spoof resistance), enforcement, exemptions."""
import asyncio

import pytest

import app.limits as limits


def run(coro):
    return asyncio.run(coro)


def scope(xff=None, peer="10.0.0.9", path="/v1/x", method="GET"):
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return {"type": "http", "client": (peer, 1234), "headers": headers, "path": path, "method": method}


# --- client_ip -----------------------------------------------------------------------------------

def test_one_trusted_hop_uses_the_entry_the_proxy_appended_not_the_spoofed_left_side():
    assert limits.client_ip(scope("6.6.6.6, 203.0.113.5"), 1) == "203.0.113.5"

def test_two_trusted_hops_count_from_the_right():
    assert limits.client_ip(scope("6.6.6.6, 203.0.113.5, 172.16.0.1"), 2) == "203.0.113.5"

def test_zero_hops_ignores_the_header_entirely():
    assert limits.client_ip(scope("203.0.113.5"), 0) == "10.0.0.9"

def test_missing_header_or_too_few_entries_fall_back_to_the_socket_peer():
    assert limits.client_ip(scope(None), 1) == "10.0.0.9"
    assert limits.client_ip(scope("203.0.113.5"), 2) == "10.0.0.9"

def test_garbage_entry_falls_back_and_ipv6_is_normalised():
    assert limits.client_ip(scope("not-an-ip"), 1) == "10.0.0.9"
    assert limits.client_ip(scope("2001:DB8:0:0:0:0:0:1"), 1) == "2001:db8::1"


# --- middleware ----------------------------------------------------------------------------------

async def _drive(mw, sc):
    sent = []
    async def send(m): sent.append(m)
    async def receive(): return {"type": "http.request"}
    await mw(sc, receive, send)
    return sent

def make(limit):
    calls = []
    async def app(sc, receive, send):
        calls.append(sc.get("path"))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    limiter = limits.RateLimiter()
    return limits.IPRateLimitMiddleware(app, limiter=limiter, limit=limit), calls

def status(sent):
    return sent[0]["status"]

def test_requests_over_the_limit_get_429_with_retry_after_and_never_reach_the_app():
    mw, calls = make(2)
    codes = [status(run(_drive(mw, scope("203.0.113.5")))) for _ in range(4)]
    assert codes == [200, 200, 429, 429] and len(calls) == 2
    sent = run(_drive(mw, scope("203.0.113.5")))
    headers = dict(sent[0]["headers"])
    assert int(headers[b"retry-after"]) >= 1 and b"ip_rate_limit_exceeded" in sent[1]["body"]

def test_different_clients_have_independent_budgets_and_spoofed_left_entries_do_not_help():
    mw, _ = make(1)
    assert status(run(_drive(mw, scope("1.1.1.1, 203.0.113.5")))) == 200
    assert status(run(_drive(mw, scope("2.2.2.2, 203.0.113.5")))) == 429   # same real client, rotating spoofed value
    assert status(run(_drive(mw, scope("1.1.1.1, 203.0.113.6")))) == 200   # different real client

def test_health_ready_options_and_non_http_scopes_are_exempt():
    mw, calls = make(1)
    for _ in range(3):
        assert status(run(_drive(mw, scope("203.0.113.5", path="/health")))) == 200
        assert status(run(_drive(mw, scope("203.0.113.5", path="/ready")))) == 200
        assert status(run(_drive(mw, scope("203.0.113.5", method="OPTIONS")))) == 200
    run(_drive(mw, {"type": "lifespan"}))
    assert len(calls) == 10 and calls[-1] is None  # the lifespan scope is passed straight through

def test_default_limit_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("IP_RATE_LIMIT_PER_MINUTE", "1")
    async def app(sc, r, s):
        await s({"type": "http.response.start", "status": 200, "headers": []})
        await s({"type": "http.response.body", "body": b""})
    mw = limits.IPRateLimitMiddleware(app, limiter=limits.RateLimiter())
    assert [status(run(_drive(mw, scope("203.0.113.5")))) for _ in range(2)] == [200, 429]


def test_through_the_real_app_a_flood_is_throttled_before_authentication(client, monkeypatch):
    monkeypatch.setenv("IP_RATE_LIMIT_PER_MINUTE", "3")
    codes = [client.get("/v1/dashboard/stats").status_code for _ in range(5)]   # unauthenticated
    assert codes[:3] == [401, 401, 401] or all(c in (401, 403) for c in codes[:3])
    assert codes[3:] == [429, 429]
    assert client.get("/health").status_code == 200   # probes keep working during a flood
