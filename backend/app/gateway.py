"""Pure request-parsing and policy helpers for the AI gateway (no network, no database)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set

MAX_PROMPT_CHARS = 4000
MAX_MESSAGES = 50
MAX_TOKENS_CAP = 4000

# Provider adapters that actually exist in app/llm_router.py. A model is only routable if its
# name maps to one of these; arbitrary names are rejected rather than silently re-routed.
MODEL_PROVIDERS = (("gpt-", "openai"), ("claude-", "anthropic"))


class GatewayError(Exception):
    def __init__(self, status_code: int, code: str, message: str, error_type: str = "invalid_request_error"):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.error_type = error_type

    def body(self, request_id: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"error": {"message": self.message, "type": self.error_type, "code": self.code}}
        if request_id:
            payload["request_id"] = request_id
        return payload


@dataclass(frozen=True)
class ChatRequest:
    model: str
    prompt: str
    max_tokens: int
    temperature: float


def provider_for_model(model: str) -> Optional[str]:
    lowered = str(model or "").strip().lower()
    for prefix, provider in MODEL_PROVIDERS:
        if lowered.startswith(prefix):
            return provider
    return None


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # OpenAI content parts; only text parts are inspected/forwarded
        return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict) and part.get("type") == "text")
    return ""


def _number(value: Any, name: str, *, integer: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (integer and isinstance(value, float) and not value.is_integer()):
        raise GatewayError(400, "invalid_parameter", f"{name} must be a number")
    return value


def parse_chat_payload(payload: Any) -> ChatRequest:
    if not isinstance(payload, dict):
        raise GatewayError(400, "invalid_request", "Request body must be a JSON object")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise GatewayError(400, "invalid_request", "messages must be a non-empty array")
    if len(messages) > MAX_MESSAGES:
        raise GatewayError(400, "invalid_request", f"messages may contain at most {MAX_MESSAGES} entries")
    user_text = [_content_text(m.get("content")) for m in messages if isinstance(m, dict) and m.get("role") == "user"]
    prompt = "\n".join(t for t in user_text if t.strip())
    if not prompt:
        raise GatewayError(400, "invalid_request", "At least one user message is required")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise GatewayError(400, "prompt_too_long", f"Prompt exceeds the {MAX_PROMPT_CHARS} character limit")

    model = payload.get("model") or "gpt-4o-mini"
    if not isinstance(model, str) or len(model) > 100:
        raise GatewayError(400, "invalid_parameter", "model must be a string")
    max_tokens = payload.get("max_tokens")
    temperature = payload.get("temperature")
    tokens = int(_number(max_tokens, "max_tokens", integer=True)) if max_tokens is not None else 1000
    temp = float(_number(temperature, "temperature", integer=False)) if temperature is not None else 0.7
    return ChatRequest(model=model.strip(), prompt=prompt, max_tokens=max(1, min(tokens, MAX_TOKENS_CAP)),
                       temperature=max(0.0, min(temp, 2.0)))


def _as_set(value: Any) -> Optional[Set[str]]:
    """Normalise a policy list column (list, JSON string, or empty) to a lowercase set; None = unrestricted."""
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = [v for v in value.replace(",", " ").split() if v]
    if not isinstance(value, (list, tuple, set)):
        return None
    items = {str(v).strip().lower() for v in value if str(v).strip()}
    return items or None


def effective_allowlists(policies: Iterable[Dict[str, Any]]) -> Dict[str, Optional[Set[str]]]:
    """Combine an organisation's policies using the most restrictive rule (intersection of non-empty lists)."""
    result: Dict[str, Optional[Set[str]]] = {"models": None, "providers": None}
    for policy in policies:
        for key, column in (("models", "approved_models"), ("providers", "allowed_providers")):
            current = _as_set(policy.get(column))
            if current is None:
                continue
            result[key] = current if result[key] is None else (result[key] & current)
    return result


def enforce_model_policy(model: str, policies: List[Dict[str, Any]]) -> str:
    """Return the provider for ``model`` or raise GatewayError(400, 'model_not_allowed')."""
    provider = provider_for_model(model)
    if provider is None:
        raise GatewayError(400, "model_not_allowed", "The requested model is not supported by this gateway")
    allow = effective_allowlists(policies)
    if allow["providers"] is not None and provider not in allow["providers"]:
        raise GatewayError(400, "model_not_allowed", "The requested provider is not approved for this organization")
    if allow["models"] is not None and model.strip().lower() not in allow["models"]:
        raise GatewayError(400, "model_not_allowed", "The requested model is not approved for this organization")
    return provider
