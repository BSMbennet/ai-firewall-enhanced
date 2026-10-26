"""Shared fixtures.

Every test runs against an in-memory Supabase fake (tests/fakes.py) and a recording
fake LLM provider. No network access and no real credentials are used anywhere.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

import pytest

# Dummy, non-secret placeholders. The application refuses to build a Supabase client
# without these, but the fake replaces the client before any call is made.
os.environ.setdefault("SUPABASE_URL", "http://supabase.invalid")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-not-a-real-key")
os.environ.setdefault("ENVIRONMENT", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import FakeDB  # noqa: E402


class RecordingProvider:
    """Replaces LLMRouter.route. Records every call so tests can prove what did (not) reach the provider."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.fail = False
        self.content = "Hello from the controlled test provider."

    async def route(self, prompt: str, model: str = "gpt-4o-mini", max_tokens: int = 1000,
                    temperature: float = 0.7, request_id: str | None = None,
                    messages: List[Dict[str, str]] | None = None) -> Dict[str, Any]:
        messages = messages or [{"role": "user", "content": prompt}]
        self.calls.append({"prompt": "\n".join(m["content"] for m in messages), "messages": messages,
                           "model": model, "request_id": request_id})
        if self.fail:
            from app.llm_router import ProviderError
            raise ProviderError("openai", "upstream_error", retryable=True, status=502)
        return {"choices": [{"message": {"content": self.content}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
                "model": model, "cost": 0}


@pytest.fixture(autouse=True)
def isolated_rate_limiter(monkeypatch):
    """The limiter is process-wide state; every test starts with empty counters and no shared store."""
    import app.limits as limits

    fresh = limits.RateLimiter()
    for name in ("primary", "fallback", "_last_degraded_log"):
        monkeypatch.setattr(limits.rate_limiter, name, getattr(fresh, name), raising=True)
    yield limits.rate_limiter


@pytest.fixture
def db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def provider(monkeypatch) -> RecordingProvider:
    import app.main as main

    fake = RecordingProvider()
    monkeypatch.setattr(main.llm_router, "route", fake.route)
    return fake


@pytest.fixture
def client(db, provider, monkeypatch):
    """FastAPI TestClient wired to the fake database."""
    from fastapi.testclient import TestClient

    import app.auth as auth_mod
    import app.billing_router as billing_mod
    import app.compliance_router as compliance_mod
    import app.enterprise_router as enterprise_mod
    import app.main as main
    import app.operations_router as operations_mod
    from app.supabase_client import SupabaseManager

    managers = [auth_mod.supabase, main.supabase_manager, enterprise_mod.supabase,
                operations_mod.supabase, compliance_mod.supabase, billing_mod.supabase]
    for manager in managers:
        manager.client = db.client
        manager._initialized = True

    async def fake_initialize(self):
        self.client = db.client
        self._initialized = True

    monkeypatch.setattr(SupabaseManager, "initialize", fake_initialize)

    async def noop(*_a, **_k):
        return True

    # Storage/cache backends are external services; they are out of scope for these tests.
    monkeypatch.setattr(main.r2_storage, "initialize", noop)
    monkeypatch.setattr(main.r2_storage, "health_check", noop)
    monkeypatch.delenv("BILLING_ENFORCE", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)

    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def world(db):
    """Two organisations with one user per role in A, and an owner in B."""
    org_a, org_b = db.add_org("Org A"), db.add_org("Org B")
    w = {"org_a": org_a, "org_b": org_b}
    for role in ("owner", "admin", "security", "developer", "member", "viewer"):
        w[role] = db.add_member(org_a, role)
    w["owner_b"] = db.add_member(org_b, "owner")
    db.tables.setdefault("security_policies", []).append({"id": "pol-a", "organization_id": org_a, "name": "A"})
    db.tables["security_policies"].append({"id": "pol-b", "organization_id": org_b, "name": "B"})
    return w


def make_key(client, db, user_id: str, **payload) -> Dict[str, Any]:
    """Create an API key through the real endpoint and return the response body."""
    response = client.post("/v1/api-keys", json=payload, headers=db.token(user_id))
    assert response.status_code == 200, response.text
    return response.json()


def chat(client, key: str, content: str = "What is the capital of France?", **extra):
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}], **extra}
    return client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {key}"})


def pytest_sessionfinish(session, exitstatus):
    """With RECORD_DB_USAGE=<path>, write every table/column the code touched during the run (see scripts/check_schema.py)."""
    import json, os
    path = os.getenv("RECORD_DB_USAGE")
    if path:
        from fakes import USAGE
        with open(path, "w") as fh:
            json.dump({t: {k: sorted(v) for k, v in e.items()} for t, e in USAGE.items()}, fh, indent=1, sort_keys=True)
