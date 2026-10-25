"""Provider adapters for the AI gateway (OpenAI chat completions, Anthropic messages).

Guarantees (each covered by tests/test_llm_router.py):
* The model that is called is exactly the model that was requested (and approved by policy) - no substitution.
* Requests only ever go to the fixed provider endpoints below; no URL is taken from a request or from configuration.
* Failures are normalised to ``ProviderError`` (provider, code, retryable, upstream status); nothing is silently
  replaced by placeholder text and no cross-provider fallback is attempted.
* Retries are bounded (2 attempts) and only for transient failures: timeouts, connection errors, 429 and 5xx.
* Error messages and logs never contain prompt text, response bodies or credentials.
* Cost is not invented: ``cost`` is None unless a dated price table is configured (not implemented yet - F-16).
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx
import openai

from app.gateway import provider_for_model

logger = logging.getLogger("aifirewall.llm")

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
        self._openai_client = None
        self._http_client_factory: Callable[[], httpx.AsyncClient] = lambda: httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    @property
    def anthropic_key(self) -> Optional[str]:
        return os.getenv("ANTHROPIC_API_KEY")

    @property
    def openai_client(self):
        if self._openai_client is None:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ProviderError("openai", "not_configured", retryable=False)
            # max_retries=0: retries are decided here, not hidden inside the SDK.
            self._openai_client = openai.AsyncOpenAI(api_key=api_key, timeout=REQUEST_TIMEOUT_SECONDS, max_retries=0)
        return self._openai_client

    def provider_status(self) -> Dict[str, bool]:
        """Report which providers are *configured*. Makes no network or billable call."""
        return {"openai": bool(os.getenv("OPENAI_API_KEY")), "anthropic": bool(self.anthropic_key)}

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
        call = self._call_openai if provider == "openai" else self._call_anthropic

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
    async def _call_openai(self, messages, model, max_tokens, temperature) -> Dict[str, Any]:
        client = self.openai_client
        try:
            response = await client.chat.completions.create(model=model, messages=messages, max_tokens=max_tokens, temperature=temperature)
        except openai.APITimeoutError:
            raise ProviderError("openai", "timeout", retryable=True, status=504)
        except openai.APIConnectionError:
            raise ProviderError("openai", "connection", retryable=True)
        except openai.RateLimitError as exc:
            raise ProviderError("openai", "rate_limited", retryable=True, status=429, retry_after=_retry_after(getattr(exc.response, "headers", None)))
        except openai.APIStatusError as exc:
            status = exc.status_code
            if status >= 500:
                raise ProviderError("openai", "upstream_error", retryable=True, status=status)
            code = "auth" if status in (401, 403) else "bad_request"
            raise ProviderError("openai", code, retryable=False, status=status)
        except ProviderError:
            raise
        except Exception:
            logger.error("provider_unexpected_error provider=openai", exc_info=True)
            raise ProviderError("openai", "unexpected", retryable=False)
        try:
            content = response.choices[0].message.content or ""
            usage = response.usage
            return {
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                          "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
                          "total_tokens": int(getattr(usage, "total_tokens", 0) or 0)},
                "model": getattr(response, "model", model) or model,
                "cost": None,
            }
        except (AttributeError, IndexError, TypeError, ValueError):
            raise ProviderError("openai", "bad_response", retryable=False)

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
                "cost": None,
            }
        except (ValueError, AttributeError, TypeError):
            raise ProviderError("anthropic", "bad_response", retryable=False, status=status)
