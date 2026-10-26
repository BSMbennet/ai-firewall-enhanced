"""Rate limiting: algorithm, atomicity (incl. against a real Redis), store-failure policy, and API behaviour."""
import asyncio
import os
import shutil
import socket
import subprocess
import time

import pytest

import app.limits as limits
from app.gateway import effective_rate_limit
from conftest import chat, make_key


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --- algorithm --------------------------------------------------------------------------------

def test_allows_up_to_the_limit_then_denies_with_retry_after_and_resets_after_the_window():
    clock = Clock()
    limiter = limits.RateLimiter(fallback=limits.InProcessStore(clock), clock=clock)
    results = [run(limiter.check("s", "id", 3, 60)) for _ in range(5)]
    assert [r.allowed for r in results] == [True, True, True, False, False]
    assert [r.remaining for r in results] == [2, 1, 0, 0, 0]
    denied = results[3]
    assert denied.retry_after == 60 and denied.headers()["Retry-After"] == "60"
    clock.t += 61
    assert run(limiter.check("s", "id", 3, 60)).allowed


def test_first_rejection_is_flagged_exactly_once_per_window():
    limiter = limits.RateLimiter()
    results = [run(limiter.check("s", "id", 2, 60)) for _ in range(6)]
    assert [r.first_rejection for r in results] == [False, False, True, False, False, False]


def test_identifiers_and_scopes_are_independent():
    limiter = limits.RateLimiter()
    assert run(limiter.check("s", "a", 1, 60)).allowed
    assert not run(limiter.check("s", "a", 1, 60)).allowed
    assert run(limiter.check("s", "b", 1, 60)).allowed
    assert run(limiter.check("other", "a", 1, 60)).allowed


def test_limit_below_one_is_treated_as_one_never_as_unlimited():
    limiter = limits.RateLimiter()
    assert run(limiter.check("s", "id", 0, 60)).allowed
    assert not run(limiter.check("s", "id", -5, 60)).allowed


def test_in_process_concurrency_admits_exactly_the_limit():
    async def scenario():
        limiter = limits.RateLimiter()
        return await asyncio.gather(*[limiter.check("s", "id", 50, 60) for _ in range(500)])
    assert sum(d.allowed for d in run(scenario())) == 50


def test_in_process_store_is_bounded():
    store = limits.InProcessStore(max_keys=100)
    async def scenario():
        for i in range(1000):
            await store.hit(f"k{i}", 60_000)
    run(scenario())
    assert len(store._windows) <= 100


@pytest.mark.parametrize("policies, expected", [
    ([], 60), ([{"rate_limit_per_minute": 10}], 10), ([{"rate_limit_per_minute": 10}, {"rate_limit_per_minute": 5}], 5),
    ([{"rate_limit_per_minute": 0}], 60), ([{"rate_limit_per_minute": -3}], 60), ([{"rate_limit_per_minute": "abc"}], 60),
    ([{"rate_limit_per_minute": True}], 60), ([{"rate_limit_per_minute": None}], 60), ([{"rate_limit_per_minute": "25"}], 25),
])
def test_effective_rate_limit_is_the_most_restrictive_valid_policy(policies, expected):
    assert effective_rate_limit(policies, 60) == expected


# --- store failure policy -----------------------------------------------------------------------

class BrokenStore:
    async def hit(self, key, window_ms):
        raise limits.StoreUnavailable("down")


def test_store_outage_degrades_to_per_instance_limits_and_never_to_unlimited(caplog):
    limiter = limits.RateLimiter(primary=BrokenStore())
    results = [run(limiter.check("s", "id", 2, 60)) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, False, False]
    assert all(r.degraded for r in results)


def test_degradation_is_logged_but_rate_limited_in_log_volume(caplog):
    limiter = limits.RateLimiter(primary=BrokenStore())
    with caplog.at_level("WARNING", logger="aifirewall.limits"):
        for _ in range(20):
            run(limiter.check("s", "id", 100, 60))
    assert len([r for r in caplog.records if "rate_limit_store_unavailable" in r.getMessage()]) == 1


def test_unconfigured_shared_store_is_handled_as_degraded():
    store = limits.UpstashStore(lambda: None)
    limiter = limits.RateLimiter(primary=store)
    assert run(limiter.check("s", "id", 5, 60)).degraded


def test_hanging_store_times_out_and_falls_back(monkeypatch):
    monkeypatch.setattr(limits, "STORE_TIMEOUT_SECONDS", 0.05)

    class Hanging:
        async def eval(self, *_a, **_k):
            await asyncio.sleep(5)

    limiter = limits.RateLimiter(primary=limits.UpstashStore(lambda: Hanging()))
    started = time.monotonic()
    decision = run(limiter.check("s", "id", 5, 60))
    assert decision.allowed and decision.degraded and time.monotonic() - started < 1


# --- the Lua script against a real Redis ----------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def redis_url():
    if not shutil.which("redis-server"):
        if os.getenv("REQUIRE_REDIS"):  # CI sets this so the Lua script can never go unverified by a silent skip
            pytest.fail("redis-server is required (REQUIRE_REDIS is set) but is not installed")
        pytest.skip("redis-server not installed")
    port = _free_port()
    proc = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--appendonly", "no", "--bind", "127.0.0.1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import redis
    for _ in range(50):
        try:
            redis.Redis(port=port).ping()
            break
        except Exception:
            time.sleep(0.1)
    yield f"redis://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=5)


class UpstashStyleClient:
    """Adapts redis-py to the (script, keys=, args=) call shape of the Upstash client, over a real Redis server."""

    def __init__(self, client):
        self.client = client

    async def eval(self, script, keys=None, args=None):
        return await self.client.eval(script, len(keys or []), *(keys or []), *(args or []))


def test_lua_hit_is_atomic_under_concurrency_on_a_real_redis(redis_url):
    import redis.asyncio as aioredis

    async def scenario():
        client = aioredis.from_url(redis_url, max_connections=500)
        try:
            limiter = limits.RateLimiter(primary=limits.UpstashStore(lambda: UpstashStyleClient(client)))
            decisions = await asyncio.gather(*[limiter.check("s", "id", 50, 60) for _ in range(400)])
            ttl = await client.pttl("rl:s:id")
            return decisions, ttl
        finally:
            await client.aclose()

    decisions, ttl = run(scenario())
    assert sum(d.allowed for d in decisions) == 50
    assert not any(d.degraded for d in decisions)
    assert 0 < ttl <= 60_000
    assert sum(d.first_rejection for d in decisions) == 1


def test_lua_window_expires_and_a_key_that_lost_its_ttl_is_repaired(redis_url):
    import redis.asyncio as aioredis

    async def scenario():
        client = aioredis.from_url(redis_url, max_connections=500)
        try:
            store = limits.UpstashStore(lambda: UpstashStyleClient(client))
            assert (await store.hit("k1", 300))[0] == 1
            assert (await store.hit("k1", 300))[0] == 2
            await asyncio.sleep(0.45)
            assert (await store.hit("k1", 300))[0] == 1          # new window
            await client.set("k2", 41)                            # a counter with NO ttl (e.g. crash between INCR and EXPIRE)
            count, ttl = await store.hit("k2", 5_000)
            assert count == 42 and 0 < ttl <= 5_000
            assert await client.pttl("k2") > 0                    # repaired: it can no longer lock the caller out forever
        finally:
            await client.aclose()

    run(scenario())


# --- gateway behaviour ------------------------------------------------------------------------------

@pytest.fixture
def small_limits(monkeypatch):
    monkeypatch.setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "3")
    monkeypatch.setenv("GATEWAY_ORG_RATE_LIMIT_PER_MINUTE", "100")


def test_gateway_returns_429_with_headers_and_never_reaches_the_provider_when_limited(client, db, world, provider, small_limits):
    key = make_key(client, db, world["admin"])["key"]
    ok = [chat(client, key) for _ in range(3)]
    assert [r.status_code for r in ok] == [200, 200, 200]
    assert ok[0].headers["x-ratelimit-limit"] == "3" and ok[0].headers["x-ratelimit-remaining"] == "2"
    limited = chat(client, key)
    assert limited.status_code == 429
    body = limited.json()
    assert body["error"]["code"] == "rate_limit_exceeded" and body["request_id"] == limited.headers["x-request-id"]
    assert int(limited.headers["retry-after"]) >= 1
    assert len(provider.calls) == 3


def test_malformed_requests_are_throttled_too(client, db, world, small_limits):
    key = make_key(client, db, world["admin"])["key"]
    for _ in range(3):
        assert client.post("/v1/chat/completions", json={"messages": "nope"}, headers={"Authorization": f"Bearer {key}"}).status_code == 400
    assert chat(client, key).status_code == 429


def test_rate_limited_requests_do_not_consume_the_monthly_quota(client, db, world, small_limits):
    key = make_key(client, db, world["admin"])["key"]
    for _ in range(8):
        chat(client, key)
    counted = sum(r["request_count"] for r in db.rows("usage_counters", organization_id=world["org_a"]))
    assert counted == 3


def test_org_policy_rate_limit_overrides_the_default(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "60")
    db.tables["security_policies"][0]["rate_limit_per_minute"] = 2
    key = make_key(client, db, world["admin"])["key"]
    assert [chat(client, key).status_code for _ in range(3)] == [200, 200, 429]


def test_keys_have_independent_limits_but_share_the_organisation_ceiling(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "3")
    monkeypatch.setenv("GATEWAY_ORG_RATE_LIMIT_PER_MINUTE", "4")
    k1 = make_key(client, db, world["admin"])["key"]
    k2 = make_key(client, db, world["admin"])["key"]
    statuses = [chat(client, k1).status_code for _ in range(3)] + [chat(client, k2).status_code for _ in range(3)]
    assert statuses == [200, 200, 200, 200, 429, 429]  # org ceiling (4) hit although k2 is within its own limit (3)


def test_one_organisation_exhausting_its_limit_does_not_affect_another(client, db, world, provider, small_limits):
    key_a = make_key(client, db, world["admin"])["key"]
    key_b = make_key(client, db, world["owner_b"])["key"]
    for _ in range(5):
        chat(client, key_a)
    assert chat(client, key_a).status_code == 429
    assert chat(client, key_b).status_code == 200


def test_enforcement_continues_when_the_shared_store_is_down(client, db, world, provider, small_limits, isolated_rate_limiter):
    isolated_rate_limiter.primary = BrokenStore()
    key = make_key(client, db, world["admin"])["key"]
    assert [chat(client, key).status_code for _ in range(4)] == [200, 200, 200, 429]


def test_only_one_audit_event_is_written_per_window_however_many_requests_are_rejected(client, db, world, small_limits):
    key = make_key(client, db, world["admin"])["key"]
    for _ in range(25):
        chat(client, key)
    events = [e for e in db.rows("audit_events", organization_id=world["org_a"]) if e["action"] == "rate_limit.exceeded"]
    assert len(events) == 1 and events[0]["outcome"] == "denied" and events[0]["metadata"]["limit"] == 3


def test_interactive_endpoint_is_limited_per_user(client, db, world, provider, small_limits):
    body = {"prompt": "What is the capital of France?", "model": "meta/llama-3.1-8b-instruct"}
    statuses = [client.post("/v1/secure-ai/query", json=body, headers=db.token(world["developer"])).status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]


# --- lifecycle endpoints ------------------------------------------------------------------------------

def test_api_key_creation_is_throttled_per_user(client, db, world):
    codes = [client.post("/v1/api-keys", json={}, headers=db.token(world["admin"])) for _ in range(11)]
    assert [r.status_code for r in codes[:10]] == [200] * 10
    assert codes[10].status_code == 429 and "retry-after" in codes[10].headers
    assert client.post("/v1/api-keys", json={}, headers=db.token(world["owner"])).status_code == 200  # other users unaffected


def test_unauthorised_attempts_also_count_so_a_low_privilege_account_cannot_hammer_the_endpoint(client, db, world):
    codes = [client.post("/v1/api-keys", json={}, headers=db.token(world["developer"])).status_code for _ in range(11)]
    assert codes[:10] == [403] * 10 and codes[10] == 429


def test_unauthenticated_requests_do_not_touch_the_per_user_limiter(client):
    assert [client.post("/v1/api-keys", json={}).status_code for _ in range(12)] == [401] * 12


@pytest.mark.parametrize("method, url, body, status, limit", [
    ("post", "/v1/enterprise/webhooks", {"url": "http://insecure.example.com"}, 400, 10),
    ("post", "/v1/organization/members", {"email": "not-an-email"}, 400, 20),
    ("delete", "/v1/api-keys/does-not-exist", None, 404, 30),
    ("post", "/v1/enterprise/api-keys/does-not-exist/rotate", {}, 404, 10),
    ("post", "/v1/enterprise/scim/tokens", {}, None, 10),
])
def test_credential_lifecycle_endpoints_are_throttled(client, db, world, method, url, body, status, limit):
    headers = db.token(world["owner"])
    send = lambda: getattr(client, method)(url, headers=headers, **({"json": body} if body is not None else {}))
    codes = [send().status_code for _ in range(limit)]
    if status is not None:
        assert set(codes) == {status}
    assert send().status_code == 429
