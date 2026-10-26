"""Provider adapters against fake transports: no network, no real keys."""
import asyncio
import json

import httpx
import pytest

from app.llm_router import ANTHROPIC_MESSAGES_URL, NVIDIA_CHAT_URL, LLMRouter, ProviderError

MSGS = [{"role": "system", "content": "guard"}, {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"}, {"role": "user", "content": "again"}]


def router_with(handler, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    r = LLMRouter()
    r._http_client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    r._sleep = lambda _s: asyncio.sleep(0)
    return r


def run(coro):
    return asyncio.run(coro)


def ok_body(text="done", model="claude-3-5-sonnet-latest"):
    return {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 3, "output_tokens": 4}, "model": model}


def test_anthropic_uses_requested_model_and_separates_system(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"], seen["body"], seen["key"] = str(request.url), json.loads(request.content), request.headers["x-api-key"]
        return httpx.Response(200, json=ok_body())

    result = run(router_with(handler, monkeypatch).route(messages=MSGS, model="claude-3-haiku-20240307", max_tokens=50, temperature=0.2))
    assert seen["url"] == ANTHROPIC_MESSAGES_URL
    assert seen["body"]["model"] == "claude-3-haiku-20240307"
    assert seen["body"]["system"] == "guard"
    assert [m["role"] for m in seen["body"]["messages"]] == ["user", "assistant", "user"]
    assert result["choices"][0]["message"]["content"] == "done"
    assert result["usage"]["total_tokens"] == 7
    assert result["cost"] is None  # never invented


def test_anthropic_merges_consecutive_roles(monkeypatch):
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok_body())

    run(router_with(handler, monkeypatch).route(messages=[{"role": "user", "content": "a"}, {"role": "user", "content": "b"}], model="claude-x"))
    assert seen["body"]["messages"] == [{"role": "user", "content": "a\n\nb"}]


@pytest.mark.parametrize("status,code,retryable", [(400, "bad_request", False), (401, "auth", False), (403, "auth", False),
                                                    (429, "rate_limited", True), (500, "upstream_error", True), (529, "upstream_error", True)])
def test_anthropic_http_errors_are_normalised(monkeypatch, status, code, retryable):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(status, json={"error": {"message": "secret prompt echo"}}, headers={"retry-after": "7"})

    with pytest.raises(ProviderError) as info:
        run(router_with(handler, monkeypatch).route(messages=MSGS, model="claude-x"))
    assert (info.value.code, info.value.retryable, info.value.status) == (code, retryable, status)
    assert "secret prompt echo" not in str(info.value)
    assert len(calls) == (2 if retryable else 1)  # bounded retry, transient only


def test_retry_succeeds_after_transient_failure(monkeypatch):
    responses = [httpx.Response(503), httpx.Response(200, json=ok_body("second"))]
    result = run(router_with(lambda req: responses.pop(0), monkeypatch).route(messages=MSGS, model="claude-x"))
    assert result["choices"][0]["message"]["content"] == "second"


def test_timeout_and_connection_errors(monkeypatch):
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request):
        raise httpx.ConnectError("no", request=request)

    with pytest.raises(ProviderError) as t:
        run(router_with(timeout, monkeypatch).route(messages=MSGS, model="claude-x"))
    assert t.value.code == "timeout"
    with pytest.raises(ProviderError) as c:
        run(router_with(refused, monkeypatch).route(messages=MSGS, model="claude-x"))
    assert c.value.code == "connection"


def test_malformed_success_body_is_bad_response(monkeypatch):
    with pytest.raises(ProviderError) as info:
        run(router_with(lambda r: httpx.Response(200, content=b"<html>"), monkeypatch).route(messages=MSGS, model="claude-x"))
    assert info.value.code == "bad_response"


def test_missing_credentials_and_unsupported_model(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    r = LLMRouter()
    for model, provider in (("claude-x", "anthropic"), ("meta/llama-3.1-8b-instruct", "nvidia")):
        with pytest.raises(ProviderError) as info:
            run(r.route(messages=MSGS, model=model))
        assert (info.value.code, info.value.provider) == ("not_configured", provider)
    with pytest.raises(ProviderError) as info:
        run(r.route(messages=MSGS, model="gpt-4o"))
    assert info.value.code == "unsupported_model"  # no silent re-route to another provider


def test_provider_status_makes_no_network_call(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "x")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert LLMRouter().provider_status() == {"nvidia": True, "anthropic": False}


NIM_MODEL = "meta/llama-3.1-8b-instruct"


def nim_router(handler, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-key")
    r = LLMRouter()
    r._http_client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    r._sleep = lambda _s: asyncio.sleep(0)
    return r


def nim_ok(text="hey", model=NIM_MODEL):
    return {"choices": [{"message": {"role": "assistant", "content": text}}], "model": model,
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}


def test_nvidia_uses_fixed_endpoint_bearer_auth_exact_model_and_roles(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"], seen["body"], seen["auth"] = str(request.url), json.loads(request.content), request.headers["authorization"]
        return httpx.Response(200, json=nim_ok())

    result = run(nim_router(handler, monkeypatch).route(messages=MSGS, model=NIM_MODEL, max_tokens=9, temperature=0.1))
    assert seen["url"] == NVIDIA_CHAT_URL == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert seen["auth"] == "Bearer nvapi-test-key"
    assert seen["body"]["model"] == NIM_MODEL and seen["body"]["messages"] == MSGS and seen["body"]["stream"] is False
    assert result["usage"]["total_tokens"] == 5 and result["cost"] is None
    assert result["choices"][0]["message"]["content"] == "hey"


def test_nvidia_alias_key_name_is_accepted(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("NVIDIA_NIM_API_KEY", "nvapi-alias")
    assert LLMRouter().provider_status()["nvidia"] is True


@pytest.mark.parametrize("status,code,retryable", [(400, "bad_request", False), (404, "bad_request", False), (401, "auth", False),
                                                    (403, "auth", False), (429, "rate_limited", True), (500, "upstream_error", True), (503, "upstream_error", True)])
def test_nvidia_http_errors_are_normalised_and_retries_bounded(monkeypatch, status, code, retryable):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(status, json={"detail": "secret prompt echo"}, headers={"retry-after": "3"})

    with pytest.raises(ProviderError) as info:
        run(nim_router(handler, monkeypatch).route(messages=MSGS, model=NIM_MODEL))
    assert (info.value.code, info.value.retryable, info.value.status) == (code, retryable, status)
    assert "secret prompt echo" not in str(info.value)
    assert len(calls) == (2 if retryable else 1)
    if status == 429:
        assert info.value.retry_after == 3


def test_nvidia_timeout_connection_and_malformed_bodies(monkeypatch):
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request):
        raise httpx.ConnectError("no", request=request)

    for handler, code in ((timeout, "timeout"), (refused, "connection")):
        with pytest.raises(ProviderError) as info:
            run(nim_router(handler, monkeypatch).route(messages=MSGS, model=NIM_MODEL))
        assert info.value.code == code
    for body in (b"<html>", json.dumps({"choices": []}).encode(), json.dumps({"choices": [{"message": {"content": 5}}]}).encode()):
        with pytest.raises(ProviderError) as info:
            run(nim_router(lambda r, b=body: httpx.Response(200, content=b), monkeypatch).route(messages=MSGS, model=NIM_MODEL))
        assert info.value.code == "bad_response"


def test_nvidia_retry_succeeds_after_transient_failure(monkeypatch):
    responses = [httpx.Response(503), httpx.Response(200, json=nim_ok("second"))]
    assert run(nim_router(lambda req: responses.pop(0), monkeypatch).route(messages=MSGS, model=NIM_MODEL))["choices"][0]["message"]["content"] == "second"


def test_cost_is_computed_only_from_a_dated_operator_price_table(monkeypatch):
    monkeypatch.setenv("MODEL_PRICES_JSON", json.dumps({NIM_MODEL: {"input_per_1k": 1.0, "output_per_1k": 2.0, "as_of": "2026-10-01"}}))
    result = run(nim_router(lambda r: httpx.Response(200, json=nim_ok()), monkeypatch).route(messages=MSGS, model=NIM_MODEL))
    assert result["cost"] == round((2 * 1.0 + 3 * 2.0) / 1000, 6)
    for bad in ({NIM_MODEL: {"input_per_1k": 1.0, "output_per_1k": 2.0}},                       # no as_of
                {NIM_MODEL: {"input_per_1k": -1, "output_per_1k": 2.0, "as_of": "2026-10-01"}},  # negative
                {NIM_MODEL: {"input_per_1k": 1, "output_per_1k": 2.0, "as_of": "yesterday"}}):   # not a date
        monkeypatch.setenv("MODEL_PRICES_JSON", json.dumps(bad))
        assert run(nim_router(lambda r: httpx.Response(200, json=nim_ok()), monkeypatch).route(messages=MSGS, model=NIM_MODEL))["cost"] is None
    monkeypatch.setenv("MODEL_PRICES_JSON", "not json")
    assert run(nim_router(lambda r: httpx.Response(200, json=nim_ok()), monkeypatch).route(messages=MSGS, model=NIM_MODEL))["cost"] is None
