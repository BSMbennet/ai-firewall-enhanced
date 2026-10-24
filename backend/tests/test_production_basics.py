import asyncio

import pytest

from app.billing_router import PLANS
from app.upstash_cache import UpstashCache


def _unconfigured_cache() -> UpstashCache:
    cache = UpstashCache()
    cache.url = None
    cache.token = None
    return cache


def test_billing_plan_limits_are_defined():
    assert PLANS["starter"]["requests_month"] == 10_000
    assert PLANS["professional"]["requests_month"] == 100_000
    assert PLANS["enterprise"]["requests_month"] is None


def test_upstash_unconfigured_initializes_without_network_in_development(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    cache = _unconfigured_cache()
    asyncio.run(cache.initialize())
    assert cache._initialized is True
    assert cache.client is None


def test_upstash_unconfigured_is_refused_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    cache = _unconfigured_cache()
    with pytest.raises(RuntimeError, match="required in production"):
        asyncio.run(cache.initialize())


def test_rate_limit_store_unavailable_fails_closed_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert asyncio.run(_unconfigured_cache().check_rate_limit("key")) is False


def test_rate_limit_store_unavailable_is_permissive_only_in_development(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert asyncio.run(_unconfigured_cache().check_rate_limit("key")) is True
