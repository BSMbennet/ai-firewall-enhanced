import asyncio

from app.billing_router import PLANS
from app.upstash_cache import UpstashCache


def test_billing_plan_limits_are_defined():
    assert PLANS["starter"]["requests_month"] == 10_000
    assert PLANS["professional"]["requests_month"] == 100_000
    assert PLANS["enterprise"]["requests_month"] is None


def test_upstash_url_normalization():
    assert UpstashCache._normalize_url("rediss://example.upstash.io") == "rediss://example.upstash.io"
    assert UpstashCache._normalize_url("https://example.upstash.io") == "rediss://example.upstash.io:6379"
    assert UpstashCache._normalize_url("http://example.upstash.io/") == "redis://example.upstash.io:6379"


def test_upstash_missing_url_initializes_without_network():
    cache = UpstashCache()
    cache.redis_url = None
    asyncio.run(cache.initialize())
    assert cache._initialized is True
    assert cache.client is None
