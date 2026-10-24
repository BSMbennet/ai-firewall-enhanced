"""Outbound webhook safety: SSRF guard, timestamped signatures and bounded retries.

Threat addressed: an organisation administrator (or an attacker holding one admin session) registers a webhook
URL that points at infrastructure the platform can reach but the customer must not - cloud metadata endpoints,
loopback, private networks, the database. The guard therefore:

* accepts only ``https`` URLs without embedded credentials,
* rejects hostnames that resolve to any non-public address (checked at registration *and* again at delivery,
  because DNS can change between the two - "DNS rebinding"),
* connects to the address it validated (pinned) instead of resolving a second time,
* never follows redirects.

Limits that remain (documented in docs/KNOWN_LIMITATIONS.md): the check cannot stop a public host that the
customer controls from receiving the event data - that is the purpose of a webhook.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("aifirewall.webhooks")

MAX_URL_LENGTH = 1000
SIGNATURE_TOLERANCE_SECONDS = 300
DELIVERY_TIMEOUT_SECONDS = 10.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS: Sequence[float] = (1.0, 5.0)
MAX_RESPONSE_BYTES_RECORDED = 500
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp")


class UnsafeWebhookURL(ValueError):
    """Raised when a webhook target is not a safe, public HTTPS endpoint."""


@dataclass(frozen=True)
class ResolvedTarget:
    url: str
    hostname: str
    port: int
    path_and_query: str
    addresses: tuple[str, ...]


def is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if getattr(address, "ipv4_mapped", None):
        address = address.ipv4_mapped
    return address.is_global and not (address.is_multicast or address.is_reserved or address.is_loopback or address.is_link_local)


def parse_webhook_url(url: str) -> tuple[str, int, str]:
    """Syntactic validation only. Returns (hostname, port, path_and_query)."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeWebhookURL("Webhook URL is missing or too long")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise UnsafeWebhookURL("Webhook URL contains invalid characters")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeWebhookURL("Webhook URL must use HTTPS")
    if parts.username or parts.password:
        raise UnsafeWebhookURL("Webhook URL must not contain credentials")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeWebhookURL("Webhook URL has no host")
    try:
        port = parts.port or 443
    except ValueError:
        raise UnsafeWebhookURL("Webhook URL has an invalid port")
    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeWebhookURL("Webhook host is not a public internet host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # a DNS name; resolved and checked below
    else:
        if not is_public_address(host):
            raise UnsafeWebhookURL("Webhook host is not a public internet address")
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return host, port, path


async def _resolve(host: str, port: int) -> List[str]:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeWebhookURL("Webhook host could not be resolved")
    return sorted({info[4][0] for info in infos})


async def resolve_public_target(url: str, resolver: Optional[Callable[[str, int], Awaitable[Iterable[str]]]] = None) -> ResolvedTarget:
    """Validate ``url`` and resolve it. Every resolved address must be public, otherwise the target is refused."""
    host, port, path = parse_webhook_url(url)
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        addresses = list(await (resolver or _resolve)(host, port))
    if not addresses:
        raise UnsafeWebhookURL("Webhook host could not be resolved")
    if not all(is_public_address(a) for a in addresses):
        raise UnsafeWebhookURL("Webhook host resolves to a non-public address")
    return ResolvedTarget(url=url, hostname=host, port=port, path_and_query=path, addresses=tuple(addresses))


def sign(secret: str, body: bytes, timestamp: int) -> str:
    """``t=<unix>,v1=<hex hmac-sha256 of "<t>.<body>">`` - the timestamp is signed, so replays can be rejected."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify_signature(secret: str, body: bytes, header: str, now: Optional[float] = None,
                     tolerance: int = SIGNATURE_TOLERANCE_SECONDS) -> bool:
    """Reference verifier for receivers (and our tests): constant-time compare plus replay window."""
    try:
        fields = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(fields["t"])
        provided = fields["v1"]
    except (KeyError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - timestamp) > tolerance:
        return False
    expected = sign(secret, body, timestamp).split("v1=", 1)[1]
    return hmac.compare_digest(expected, provided)


@dataclass
class DeliveryResult:
    status: str  # delivered | failed
    attempts: int
    response_code: Optional[int] = None
    error: Optional[str] = None


Sender = Callable[[ResolvedTarget, bytes, dict], Awaitable[httpx.Response]]


async def send_pinned(target: ResolvedTarget, body: bytes, headers: dict) -> httpx.Response:
    """POST to the validated address with the original Host/SNI, no redirects, bounded time."""
    address = target.addresses[0]
    netloc = f"[{address}]" if ":" in address else address
    url = f"https://{netloc}:{target.port}{target.path_and_query}"
    request_headers = {**headers, "Host": target.hostname if target.port == 443 else f"{target.hostname}:{target.port}"}
    async with httpx.AsyncClient(timeout=DELIVERY_TIMEOUT_SECONDS, follow_redirects=False) as client:
        return await client.post(url, content=body, headers=request_headers, extensions={"sni_hostname": target.hostname})


def _retryable(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


async def deliver_with_retries(
    url: str,
    secret: str,
    event_id: str,
    event_type: str,
    body: bytes,
    *,
    sender: Optional[Sender] = None,
    resolver: Optional[Callable[[str, int], Awaitable[Iterable[str]]]] = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.time,
) -> DeliveryResult:
    """Deliver one event with bounded retries.

    Retries only network errors, HTTP 429 and 5xx (never other 4xx, which indicate a receiver-side rejection).
    The target is re-validated on every attempt. The event id is identical across attempts so receivers can
    de-duplicate; the signature timestamp is refreshed per attempt so a slow retry is not outside the replay window.
    """
    last_error: Optional[str] = None
    last_code: Optional[int] = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            target = await resolve_public_target(url, resolver)
        except UnsafeWebhookURL as exc:
            # Not retryable: the destination itself is unacceptable.
            return DeliveryResult("failed", attempt, None, f"blocked: {exc}")
        timestamp = int(clock())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AI-Firewall-Webhook/1",
            "X-AI-Firewall-Event": event_type,
            "X-AI-Firewall-Event-Id": event_id,
            "X-AI-Firewall-Delivery-Attempt": str(attempt),
            "X-AI-Firewall-Signature-V2": sign(secret, body, timestamp),
            # Legacy header kept for existing receivers; it is not replay-protected - receivers should migrate to V2.
            "X-AI-Firewall-Signature": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(),
        }
        try:
            response = await (sender or send_pinned)(target, body, headers)
            last_code = response.status_code
            if 200 <= response.status_code < 300:
                return DeliveryResult("delivered", attempt, response.status_code)
            last_error = f"HTTP {response.status_code}"
            if not _retryable(response.status_code):
                return DeliveryResult("failed", attempt, last_code, last_error)
        except Exception as exc:  # network/TLS/timeout; the message is recorded, never the secret
            last_error = f"{type(exc).__name__}"
            logger.warning("webhook_delivery_attempt_failed attempt=%s error=%s", attempt, last_error)
        if attempt < MAX_ATTEMPTS:
            await sleep(RETRY_BACKOFF_SECONDS[min(attempt - 1, len(RETRY_BACKOFF_SECONDS) - 1)])
    return DeliveryResult("failed", MAX_ATTEMPTS, last_code, last_error)
