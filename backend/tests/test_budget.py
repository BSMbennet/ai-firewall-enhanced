"""Monthly token budget: hard stop, fail closed, tenant isolation, audit bounding, request-count independence."""
from datetime import datetime, timezone

from conftest import chat, make_key

PERIOD = datetime.now(timezone.utc).date().replace(day=1).isoformat()


def set_usage(db, org, tokens):
    rows = db.tables.setdefault("usage_counters", [])
    rows[:] = [r for r in rows if not (r["organization_id"] == org and r["period_start"] == PERIOD)]
    rows.append({"id": f"u-{org}", "organization_id": org, "period_start": PERIOD, "request_count": 0, "blocked_count": 0, "tokens_used": tokens})


def test_no_budget_configured_means_no_token_limit(client, db, world, provider, monkeypatch):
    monkeypatch.delenv("MONTHLY_TOKEN_BUDGET", raising=False)
    set_usage(db, world["org_a"], 10**12)
    key = make_key(client, db, world["owner"])
    assert chat(client, key["key"]).status_code == 200


def test_under_budget_is_allowed_and_at_budget_is_refused_before_forwarding(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    key = make_key(client, db, world["owner"])
    set_usage(db, world["org_a"], 999)
    assert chat(client, key["key"]).status_code == 200
    calls = len(provider.calls)
    set_usage(db, world["org_a"], 1000)
    refused = chat(client, key["key"])
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "token_budget_exceeded"
    assert len(provider.calls) == calls                     # nothing forwarded


def test_budget_is_per_organisation(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    set_usage(db, world["org_a"], 5000)
    set_usage(db, world["org_b"], 10)
    key_b = make_key(client, db, world["owner_b"])
    assert chat(client, key_b["key"]).status_code == 200


def test_refused_requests_are_not_counted_as_requests(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    key = make_key(client, db, world["owner"])
    set_usage(db, world["org_a"], 5000)
    before = db.rows("usage_counters", organization_id=world["org_a"])[0]["request_count"]
    chat(client, key["key"])
    assert db.rows("usage_counters", organization_id=world["org_a"])[0]["request_count"] == before


def test_exceeded_budget_is_audited_once_per_hour_not_per_request(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    key = make_key(client, db, world["owner"])
    set_usage(db, world["org_a"], 5000)
    for _ in range(5):
        assert chat(client, key["key"]).status_code == 429
    events = [e for e in db.tables.get("audit_events", []) if e.get("action") == "token_budget.exceeded"]
    assert len(events) == 1 and events[0]["metadata"]["budget"] == 1000


def test_invalid_budget_setting_fails_closed(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "lots")
    key = make_key(client, db, world["owner"])
    assert chat(client, key["key"]).status_code == 429


def test_unreadable_usage_fails_closed_with_503(client, db, world, provider, monkeypatch):
    import app.main as main
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    key = make_key(client, db, world["owner"])
    real = main.supabase_manager.client.table

    def broken(name):
        if name == "usage_counters":
            raise RuntimeError("db down")
        return real(name)

    monkeypatch.setattr(main.supabase_manager.client, "table", broken)
    response = chat(client, key["key"])
    assert response.status_code == 503 and response.json()["error"]["code"] == "budget_unavailable"
    assert provider.calls == []


def test_interactive_endpoint_is_budgeted_too(client, db, world, provider, monkeypatch):
    monkeypatch.setenv("MONTHLY_TOKEN_BUDGET", "1000")
    set_usage(db, world["org_a"], 5000)
    r = client.post("/v1/secure-ai/query", json={"prompt": "Say hello"}, headers=db.token(world["member"]))
    assert r.status_code == 429 and provider.calls == []
