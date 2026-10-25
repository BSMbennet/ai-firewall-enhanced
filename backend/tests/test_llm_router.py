"""Provider adapters against fake transports: no network, no real keys."""
import asyncio
import json

import httpx
import openai
import pytest

from app.llm_router import ANTHROPIC_MESSAGES_URL, LLMRouter, ProviderError

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
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    r = LLMRouter()
    for model, provider in (("claude-x", "anthropic"), ("gpt-4o", "openai")):
        with pytest.raises(ProviderError) as info:
            run(r.route(messages=MSGS, model=model))
        assert (info.value.code, info.value.provider) == ("not_configured", provider)
    with pytest.raises(ProviderError) as info:
        run(r.route(messages=MSGS, model="llama-3"))
    assert info.value.code == "unsupported_model"  # no silent re-route to another provider


def test_provider_status_makes_no_network_call(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert LLMRouter().provider_status() == {"openai": True, "anthropic": False}


class FakeCompletions:
    def __init__(self, outcomes):
        self.outcomes, self.calls = outcomes, []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def openai_router(outcomes, monkeypatch):
    r = LLMRouter()
    completions = FakeCompletions(outcomes)

    class Client:
        chat = type("C", (), {"completions": completions})()

    r._openai_client = Client()
    r._sleep = lambda _s: asyncio.sleep(0)
    return r, completions


def test_openai_passes_messages_and_exact_model(monkeypatch):
    from types import SimpleNamespace as NS
    resp = NS(choices=[NS(message=NS(content="hey"))], usage=NS(prompt_tokens=2, completion_tokens=3, total_tokens=5), model="gpt-4o-2024")
    r, comps = openai_router([resp], monkeypatch)
    result = run(r.route(messages=MSGS, model="gpt-4o", max_tokens=9, temperature=0.1))
    assert comps.calls[0]["model"] == "gpt-4o" and comps.calls[0]["messages"] == MSGS
    assert result["usage"]["total_tokens"] == 5 and result["cost"] is None


def _status_error(cls, status):
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    return cls("boom", response=httpx.Response(status, request=req, headers={"retry-after": "3"}), body=None)


def test_openai_errors_are_normalised_and_retries_bounded(monkeypatch):
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    cases = [(openai.APITimeoutError(request=req), "timeout", 2), (openai.APIConnectionError(request=req), "connection", 2),
             (_status_error(openai.RateLimitError, 429), "rate_limited", 2), (_status_error(openai.InternalServerError, 500), "upstream_error", 2),
             (_status_error(openai.AuthenticationError, 401), "auth", 1), (_status_error(openai.BadRequestError, 400), "bad_request", 1)]
    for error, code, attempts in cases:
        r, comps = openai_router([error, error], monkeypatch)
        with pytest.raises(ProviderError) as info:
            run(r.route(messages=MSGS, model="gpt-4o"))
        assert info.value.code == code and len(comps.calls) == attempts, code
    r, _ = openai_router([_status_error(openai.RateLimitError, 429)] * 2, monkeypatch)
    with pytest.raises(ProviderError) as info:
        run(r.route(messages=MSGS, model="gpt-4o"))
    assert info.value.retry_after == 3
