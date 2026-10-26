"""Provider adapters for the AI gateway (NVIDIA NIM chat completions, Anthropic messages).

Guarantees (each covered by tests/test_llm_router.py):
* The model that is called is exactly the model that was requested (and approved by policy) - no substitution.
* Requests only ever go to the fixed provider endpoints below; no URL is taken from a request or from configuration.
* Failures are normalised to ``ProviderError`` (provider, code, retryable, upstream status); nothing is silently
  replaced by placeholder text and no cross-provider fallback is attempted.
* Retries are bounded (2 attempts) and only for transient failures: timeouts, connection errors, 429 and 5xx.
* Error messages and logs never contain prompt text, response bodies or credentials.
* Cost is not invented: ``cost`` is None unless an operator-supplied, dated price table covers the model (app/pricing.py).
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx
from app.gateway import provider_for_model
from app.pricing import estimate_cost

logger = logging.getLogger("aifirewall.llm")

NVIDIA_CHAT_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_ATTEMPTS = 2
BACKOFF_SECONDS = 0.5


class ProviderError(Exception):
    """A normalised upstream failure. ``str(error)`` is safe to log: it contains no content or credentials."""

    def __init__(self, provider: str, code: str, retryable: bool, status: Optional[int] = None, retry_after: Optional[int] = None):
        super().__init__(f"{provider}:{code}" + (f":{status}" if status else ""))
        self.provider = provider
        self.code = code  # timeout | connection | rate_limited | upstream_error | auth | bad_request | bad_response | not_configured | unsupported_model | unexpected
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after


def _retry_after(headers: Any) -> Optional[int]:
    try:
        value = headers.get("retry-after") if headers is not None else None
        return max(1, min(int(float(value)), 300)) if value is not None else None
    except (TypeError, ValueError):
        return None


class LLMRouter:
    def __init__(self):
        # Clients are created on first use so the application can be imported (tests, tooling, health checks)
        # without provider credentials configured.
        self._http_client_factory: Callable[[], httpx.AsyncClient] = lambda: httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    @property
    def anthropic_key(self) -> Optional[str]:
        return os.getenv("ANTHROPIC_API_KEY")

    @property
    def nvidia_key(self) -> Optional[str]:
        return os.getenv("NVIDIA_API_KEY") or os.getenv("NVIDIA_NIM_API_KEY")

    def provider_status(self) -> Dict[str, bool]:
        """Report which providers are *configured*. Makes no network or billable call."""
        return {"nvidia": bool(self.nvidia_key), "anthropic": bool(self.anthropic_key)}

    # ------------------------------------------------------------------------------------------------
    async def route(self, prompt: Optional[str] = None, model: str = "gpt-4o-mini", max_tokens: int = 1000,
                    temperature: float = 0.7, request_id: Optional[str] = None,
                    messages: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Call the provider that owns ``model``. Raises ProviderError; never returns placeholder output."""
        if messages is None:
            if prompt is None:
                raise ProviderError("gateway", "bad_request", retryable=False)
            messages = [{"role": "user", "content": prompt}]
        provider = provider_for_model(model)
        if provider is None:
            raise ProviderError("gateway", "unsupported_model", retryable=False)
        call = self._call_nvidia if provider == "nvidia" else self._call_anthropic

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return await call(messages, model, max_tokens, temperature)
            except ProviderError as error:
                logger.warning("provider_call_failed provider=%s code=%s status=%s attempt=%s request_id=%s",
                               error.provider, error.code, error.status, attempt, request_id)
                if not error.retryable or attempt == MAX_ATTEMPTS:
                    raise
                await self._sleep(BACKOFF_SECONDS * attempt)
        raise ProviderError(provider, "unexpected", retryable=False)  # unreachable; keeps the return type honest

    # ------------------------------------------------------------------------------------------------
    async def _call_nvidia(self, messages, model, max_tokens, temperature) -> Dict[str, Any]:
        """NVIDIA NIM hosted API (OpenAI-compatible chat completions) at a fixed endpoint."""
        key = self.nvidia_key
        if not key:
            raise ProviderError("nvidia", "not_configured", retryable=False)
        body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature, "stream": False}
        try:
            async with self._http_client_factory() as client:
                response = await client.post(NVIDIA_CHAT_URL, json=body, headers={
                    "Authorization": f"Bearer {key}", "Accept": "application/json", "Content-Type": "application/json"})
        except httpx.TimeoutException:
            raise ProviderError("nvidia", "timeout", retryable=True, status=504)
        except httpx.TransportError:
            raise ProviderError("nvidia", "connection", retryable=True)
        status = response.status_code
        if status == 429:
            raise ProviderError("nvidia", "rate_limited", retryable=True, status=429, retry_after=_retry_after(response.headers))
        if status >= 500:
            raise ProviderError("nvidia", "upstream_error", retryable=True, status=status)
        if status >= 400:
            raise ProviderError("nvidia", "auth" if status in (401, 403) else "bad_request", retryable=False, status=status)
        try:
            data = response.json()
            content = data["choices"][0]["message"].get("content") or ""
            if not isinstance(content, str):
                raise TypeError("content is not text")
            usage = data.get("usage") or {}
            prompt_tokens, completion_tokens = int(usage.get("prompt_tokens", 0) or 0), int(usage.get("completion_tokens", 0) or 0)
            total = int(usage.get("total_tokens", 0) or 0) or prompt_tokens + completion_tokens
            return {
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": total},
                "model": data.get("model") or model,
                "cost": estimate_cost(model, prompt_tokens, completion_tokens),
            }
        except (ValueError, KeyError, IndexError, AttributeError, TypeError):
            raise ProviderError("nvidia", "bad_response", retryable=False, status=status)

    async def _call_anthropic(self, messages, model, max_tokens, temperature) -> Dict[str, Any]:
        key = self.anthropic_key
        if not key:
            raise ProviderError("anthropic", "not_configured", retryable=False)
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        turns: List[Dict[str, str]] = []
        for m in messages:
            if m["role"] == "system":
                continue
            if turns and turns[-1]["role"] == m["role"]:  # the Messages API requires alternating roles
                turns[-1]["content"] += "\n\n" + m["content"]
            else:
                turns.append({"role": m["role"], "content": m["content"]})
        body: Dict[str, Any] = {"model": model, "max_tokens": max_tokens, "temperature": min(float(temperature), 1.0), "messages": turns}
        if system:
            body["system"] = system
        try:
            async with self._http_client_factory() as client:
                response = await client.post(ANTHROPIC_MESSAGES_URL, json=body, headers={
                    "x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json"})
        except httpx.TimeoutException:
            raise ProviderError("anthropic", "timeout", retryable=True, status=504)
        except httpx.TransportError:
            raise ProviderError("anthropic", "connection", retryable=True)
        status = response.status_code
        if status == 429:
            raise ProviderError("anthropic", "rate_limited", retryable=True, status=429, retry_after=_retry_after(response.headers))
        if status >= 500 or status == 529:
            raise ProviderError("anthropic", "upstream_error", retryable=True, status=status)
        if status >= 400:
            raise ProviderError("anthropic", "auth" if status in (401, 403) else "bad_request", retryable=False, status=status)
        try:
            data = response.json()
            text = "".join(block.get("text", "") for block in data.get("content", []) if isinstance(block, dict) and block.get("type") == "text")
            usage = data.get("usage") or {}
            prompt_tokens, completion_tokens = int(usage.get("input_tokens", 0) or 0), int(usage.get("output_tokens", 0) or 0)
            return {
                "choices": [{"message": {"content": text}}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens},
                "model": data.get("model") or model,
                "cost": estimate_cost(model, prompt_tokens, completion_tokens),
            }
        except (ValueError, AttributeError, TypeError):
            raise ProviderError("anthropic", "bad_response", retryable=False, status=status)
