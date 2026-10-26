"""Request correlation, structured logging with secret redaction, and startup configuration validation."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

# Only well-formed ids are echoed back. Anything else (control characters, log-injection payloads, huge values)
# is discarded and replaced with a server-generated id.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")

access_logger = logging.getLogger("aifirewall.access")


def current_request_id() -> Optional[str]:
    return request_id_var.get()


def new_request_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------------------

_REDACTIONS = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}"), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:aifw|scim|whsec|sk|rk|pk)_[A-Za-z0-9_-]{8,}"), "[REDACTED_KEY]"),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"),
    # Authorization header: the credentials may follow a scheme word ("Basic <creds>").
    (re.compile(r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?)(?:[A-Za-z]+\s+)?[^\s\"',;}&]+"), r"\1[REDACTED]"),
    # name=value / "name": "value" where the name ends in a credential word (SUPABASE_SERVICE_ROLE_KEY, client_secret, ...)
    (re.compile(r"(?i)([A-Za-z0-9_-]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|role[_-]?key)"
                r"[\"']?\s*[:=]\s*[\"']?)[^\s\"',;}&]+"), r"\1[REDACTED]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class RedactingJsonFormatter(logging.Formatter):
    """One JSON object per line. Messages and tracebacks are passed through :func:`redact`."""

    def format(self, record: logging.LogRecord) -> str:
        entry: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            entry["request_id"] = request_id
        for field_name in ("method", "path", "status", "duration_ms"):
            if hasattr(record, field_name):
                entry[field_name] = getattr(record, field_name)
        if record.exc_info:
            entry["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: Optional[str] = None) -> None:
    """Idempotent: installs one JSON stdout handler on the root logger."""
    root = logging.getLogger()
    if any(getattr(h, "_aifw_handler", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(RedactingJsonFormatter())
    handler._aifw_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(getattr(logging, (level or os.getenv("LOG_LEVEL", "INFO")).upper(), logging.INFO))


# --------------------------------------------------------------------------------------------------
# Request context middleware (pure ASGI: does not buffer or wrap streaming bodies)
# --------------------------------------------------------------------------------------------------

class RequestContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        inbound = ""
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                inbound = value.decode("latin-1")
                break
        request_id = inbound if _VALID_REQUEST_ID.match(inbound) else new_request_id()
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status = {"code": 500}

        async def send_with_request_id(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            path = scope.get("path", "")
            # The query string is deliberately never logged: it can carry tokens.
            access_logger.log(
                logging.DEBUG if path in {"/health", "/ready"} else logging.INFO,
                "request",
                extra={"method": scope.get("method"), "path": path, "status": status["code"],
                       "duration_ms": round((time.perf_counter() - started) * 1000, 1)},
            )
            request_id_var.reset(token)


# --------------------------------------------------------------------------------------------------
# Startup configuration validation
# --------------------------------------------------------------------------------------------------

@dataclass
class ConfigReport:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_environment(env: Optional[Mapping[str, str]] = None) -> ConfigReport:
    """Check configuration for the current ENVIRONMENT.

    Only conditions that make the service unusable or unsafe to start are *errors* (and only in production).
    Everything else is a warning so that a deployment is not taken down by an optional integration;
    ``CONFIG_STRICT=true`` promotes warnings to errors for environments that want that.
    """
    env = os.environ if env is None else env
    report = ConfigReport()
    if (env.get("ENVIRONMENT") or "development").lower() != "production":
        return report

    for name in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"):
        if not env.get(name):
            report.errors.append(f"{name} is required in production")

    frontend = env.get("FRONTEND_URL", "")
    if not frontend or "localhost" in frontend or "your-app" in frontend:
        report.warnings.append("FRONTEND_URL is unset or a placeholder; browser CORS will not match the real frontend")
    regex = (env.get("FRONTEND_ORIGIN_REGEX") or "").strip()
    if regex in {".*", ".+", "^.*$"}:
        report.errors.append("FRONTEND_ORIGIN_REGEX matches every origin; with credentialed CORS this is unsafe")
    elif regex:
        report.warnings.append("FRONTEND_ORIGIN_REGEX widens CORS beyond FRONTEND_URL; keep it as narrow as possible")
    if not env.get("WEBHOOK_ENCRYPTION_KEY"):
        report.warnings.append("WEBHOOK_ENCRYPTION_KEY is unset; webhook secrets use a key derived from the service-role key")
    if not (env.get("NVIDIA_API_KEY") or env.get("NVIDIA_NIM_API_KEY") or env.get("ANTHROPIC_API_KEY")):
        report.warnings.append("No AI provider key is configured; the gateway cannot serve requests")
    if not (env.get("UPSTASH_REDIS_REST_URL") and env.get("UPSTASH_REDIS_REST_TOKEN")):
        report.warnings.append("Upstash is not configured")

    if (env.get("CONFIG_STRICT") or "").lower() == "true":
        report.errors.extend(report.warnings)
        report.warnings = []
    return report


def enforce_startup_config(env: Optional[Mapping[str, str]] = None, logger: Optional[logging.Logger] = None) -> ConfigReport:
    """Log warnings; raise RuntimeError listing every error (never values) so a misconfigured deploy fails fast."""
    logger = logger or logging.getLogger("aifirewall.config")
    report = validate_environment(env)
    for warning in report.warnings:
        logger.warning("config_warning: %s", warning)
    if report.errors:
        raise RuntimeError("Invalid production configuration: " + "; ".join(report.errors))
    return report
