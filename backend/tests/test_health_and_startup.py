import os
import subprocess
import sys


def test_app_imports_without_provider_or_database_credentials():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NVIDIA", "ANTHROPIC", "SUPABASE"))}
    result = subprocess.run([sys.executable, "-c", "import app.main"], cwd=os.path.join(os.path.dirname(__file__), ".."),
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]


def test_health_makes_no_billable_provider_call(client, provider, monkeypatch):
    import app.main as main

    async def explode(*_a, **_k):
        raise AssertionError("health check must not call the provider")

    monkeypatch.setattr(main.llm_router, "route", explode)
    monkeypatch.setenv("NVIDIA_API_KEY", "configured-for-test")
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["services"]["llm"] == {"nvidia": True, "anthropic": False} or body["services"]["llm"] is True
    assert provider.calls == []


def test_readiness_reflects_database_availability(client, monkeypatch):
    import app.main as main
    assert client.get("/ready").status_code == 200

    async def down():
        return False

    monkeypatch.setattr(main.supabase_manager, "health_check", down)
    assert client.get("/ready").status_code == 503
