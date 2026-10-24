"""Webhook safety: SSRF guard, signatures/replay, bounded retries, API behaviour. No network is used."""
import asyncio

import httpx
import pytest

import app.operations_router as ops
import app.webhook_security as ws

PUBLIC = "93.184.216.34"


async def public_resolver(host, port):
    return [PUBLIC]


def run(coro):
    return asyncio.run(coro)


# --- SSRF guard ----------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://example.com/hook",                      # not HTTPS
    "https://user:pass@example.com/hook",           # embedded credentials
    "https://localhost/hook",
    "https://127.0.0.1/hook",
    "https://[::1]/hook",
    "https://169.254.169.254/latest/meta-data/",    # cloud metadata
    "https://10.0.0.5/hook",
    "https://192.168.1.10/hook",
    "https://172.16.0.1/hook",
    "https://[::ffff:127.0.0.1]/hook",              # IPv4-mapped loopback
    "https://0.0.0.0/hook",
    "https://db.internal/hook",
    "https://printer.local/hook",
    "https://example.com:notaport/hook",
    "https://exa mple.com/hook",
    "",
    "https://example.com/" + "a" * 1100,
])
def test_unsafe_urls_are_rejected_syntactically(url):
    with pytest.raises(ws.UnsafeWebhookURL):
        run(ws.resolve_public_target(url, public_resolver))


def test_public_host_is_accepted_and_pinned_to_the_resolved_address():
    target = run(ws.resolve_public_target("https://hooks.example.com/in?x=1", public_resolver))
    assert target.addresses == (PUBLIC,) and target.port == 443 and target.path_and_query == "/in?x=1"


def test_dns_name_resolving_to_a_private_address_is_rejected():
    async def private(host, port):
        return ["10.1.2.3"]
    with pytest.raises(ws.UnsafeWebhookURL):
        run(ws.resolve_public_target("https://evil.example.com/hook", private))


def test_mixed_public_and_private_answers_are_rejected():
    async def mixed(host, port):
        return [PUBLIC, "127.0.0.1"]
    with pytest.raises(ws.UnsafeWebhookURL):
        run(ws.resolve_public_target("https://evil.example.com/hook", mixed))


def test_unresolvable_host_is_rejected():
    async def none(host, port):
        return []
    with pytest.raises(ws.UnsafeWebhookURL):
        run(ws.resolve_public_target("https://nope.example.com/hook", none))


# --- signatures & replay --------------------------------------------------------------

def test_signature_roundtrip_and_tamper_detection():
    header = ws.sign("s3cret", b'{"a":1}', 1_000)
    assert ws.verify_signature("s3cret", b'{"a":1}', header, now=1_010)
    assert not ws.verify_signature("s3cret", b'{"a":2}', header, now=1_010)
    assert not ws.verify_signature("other", b'{"a":1}', header, now=1_010)
    assert not ws.verify_signature("s3cret", b'{"a":1}', "garbage", now=1_010)


def test_old_signature_is_rejected_as_a_replay():
    header = ws.sign("s3cret", b"{}", 1_000)
    assert not ws.verify_signature("s3cret", b"{}", header, now=1_000 + ws.SIGNATURE_TOLERANCE_SECONDS + 1)


def test_timestamp_cannot_be_changed_without_invalidating_the_signature():
    header = ws.sign("s3cret", b"{}", 1_000)
    forged = header.replace("t=1000", "t=5000")
    assert not ws.verify_signature("s3cret", b"{}", forged, now=5_000)


# --- delivery & retries -----------------------------------------------------------------

class Recorder:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), []

    async def __call__(self, target, body, headers):
        self.calls.append((target, body, headers))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome)


async def no_sleep(_):
    return None


def deliver(sender, url="https://hooks.example.com/in", resolver=public_resolver, now=lambda: 1_000.0):
    return run(ws.deliver_with_retries(url, "whsec_x", "evt1", "security.blocked", b'{"ok":true}',
                                       sender=sender, resolver=resolver, sleep=no_sleep, clock=now))


def test_success_on_first_attempt_sends_signed_headers():
    sender = Recorder([200])
    result = deliver(sender)
    assert (result.status, result.attempts, result.response_code) == ("delivered", 1, 200)
    headers = sender.calls[0][2]
    assert headers["X-AI-Firewall-Event-Id"] == "evt1"
    assert ws.verify_signature("whsec_x", b'{"ok":true}', headers["X-AI-Firewall-Signature-V2"], now=1_000)
    assert headers["X-AI-Firewall-Signature"].startswith("sha256=")  # legacy header preserved


def test_server_errors_are_retried_with_the_same_event_id_then_succeed():
    sender = Recorder([503, 502, 200])
    result = deliver(sender)
    assert (result.status, result.attempts) == ("delivered", 3)
    assert {c[2]["X-AI-Firewall-Event-Id"] for c in sender.calls} == {"evt1"}
    assert [c[2]["X-AI-Firewall-Delivery-Attempt"] for c in sender.calls] == ["1", "2", "3"]


def test_client_errors_are_not_retried():
    sender = Recorder([400, 200])
    result = deliver(sender)
    assert (result.status, result.attempts, result.response_code) == ("failed", 1, 400)
    assert len(sender.calls) == 1


def test_retries_are_bounded_and_failure_is_reported():
    sender = Recorder([httpx.ConnectTimeout("t")] * 10)
    result = deliver(sender)
    assert (result.status, result.attempts) == ("failed", ws.MAX_ATTEMPTS)
    assert len(sender.calls) == ws.MAX_ATTEMPTS
    assert result.error == "ConnectTimeout"


def test_destination_is_revalidated_at_delivery_and_never_contacted_if_it_became_private():
    async def rebinding(host, port):
        return ["169.254.169.254"]
    sender = Recorder([200])
    result = deliver(sender, resolver=rebinding)
    assert result.status == "failed" and result.error.startswith("blocked")
    assert sender.calls == []


def test_signature_timestamp_is_refreshed_per_attempt():
    times = iter([1_000.0, 1_100.0])
    sender = Recorder([500, 200])
    deliver(sender, now=lambda: next(times))
    stamps = [c[2]["X-AI-Firewall-Signature-V2"].split(",")[0] for c in sender.calls]
    assert stamps == ["t=1000", "t=1100"]


# --- API behaviour ------------------------------------------------------------------------

@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(ws, "_resolve", public_resolver)


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "https://169.254.169.254/x", "https://127.0.0.1/x",
                                 "https://10.0.0.1/x", "https://localhost/x"])
def test_registering_an_unsafe_webhook_is_refused_and_nothing_is_stored(client, db, world, public_dns, url):
    response = client.post("/v1/enterprise/webhooks", json={"url": url}, headers=db.token(world["admin"]))
    assert response.status_code == 400
    assert db.rows("webhook_integrations") == []


def test_registering_a_public_webhook_returns_the_secret_once_and_never_lists_it(client, db, world, public_dns):
    response = client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/x", "events": ["security.blocked"]},
                           headers=db.token(world["admin"]))
    assert response.status_code == 200, response.text
    secret = response.json()["secret"]
    assert secret.startswith("whsec_")
    stored = db.rows("webhook_integrations")[0]
    assert secret not in str(stored)  # only the encrypted form is stored
    listing = client.get("/v1/enterprise/webhooks", headers=db.token(world["admin"]))
    assert secret not in listing.text and "secret_encrypted" not in listing.text
    assert any(e["action"] == "webhook.created" for e in db.rows("audit_events", organization_id=world["org_a"]))


@pytest.mark.parametrize("role", ["developer", "member", "viewer", "security"])
def test_only_owner_or_admin_can_register_webhooks(client, db, world, public_dns, role):
    response = client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/x"}, headers=db.token(world[role]))
    assert response.status_code == 403
    assert db.rows("webhook_integrations") == []


def test_events_must_be_a_list_of_strings(client, db, world, public_dns):
    response = client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/x", "events": "all"},
                           headers=db.token(world["admin"]))
    assert response.status_code == 400


def test_dispatch_returns_before_delivery_and_records_the_outcome(client, db, world, public_dns, monkeypatch):
    client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/x"}, headers=db.token(world["admin"]))
    gate = asyncio.Event()
    seen = {}

    async def slow_delivery(url, secret, event_id, event_type, body, **_):
        seen.update(url=url, secret=secret, event_id=event_id)
        await gate.wait()
        return ws.DeliveryResult("delivered", 2, 200)

    monkeypatch.setattr(ops, "deliver_with_retries", slow_delivery)

    async def scenario():
        await ops.dispatch_webhook_event(world["org_a"], "security.blocked", {"request_id": "r1"})
        # dispatch has returned while delivery is still blocked: it is off the request path
        assert db.rows("webhook_deliveries")[0]["status"] == "pending"
        gate.set()
        await asyncio.gather(*list(ops._background_tasks))

    asyncio.run(scenario())
    row = db.rows("webhook_deliveries")[0]
    assert (row["status"], row["attempts"], row["response_code"]) == ("delivered", 2, 200)
    assert seen["secret"].startswith("whsec_")  # decrypted server-side for signing only
    assert row["organization_id"] == world["org_a"]


def test_dispatch_only_targets_the_events_own_organisation(client, db, world, public_dns, monkeypatch):
    client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/a"}, headers=db.token(world["admin"]))
    client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/b"}, headers=db.token(world["owner_b"]))
    urls = []

    async def capture(url, *_a, **_k):
        urls.append(url)
        return ws.DeliveryResult("delivered", 1, 200)

    monkeypatch.setattr(ops, "deliver_with_retries", capture)

    async def scenario():
        await ops.dispatch_webhook_event(world["org_a"], "security.blocked", {})
        await asyncio.gather(*list(ops._background_tasks))

    asyncio.run(scenario())
    assert urls == ["https://hooks.example.com/a"]


def test_failed_delivery_is_recorded_without_leaking_the_secret(client, db, world, public_dns, monkeypatch):
    secret = client.post("/v1/enterprise/webhooks", json={"url": "https://hooks.example.com/x"},
                         headers=db.token(world["admin"])).json()["secret"]

    async def failing(*_a, **_k):
        return ws.DeliveryResult("failed", 3, 503, "HTTP 503")

    monkeypatch.setattr(ops, "deliver_with_retries", failing)

    async def scenario():
        await ops.dispatch_webhook_event(world["org_a"], "security.blocked", {})
        await asyncio.gather(*list(ops._background_tasks))

    asyncio.run(scenario())
    row = db.rows("webhook_deliveries")[0]
    assert (row["status"], row["attempts"]) == ("failed", 3)
    assert secret not in str(row)


def test_legacy_encrypted_secret_still_decrypts_after_a_dedicated_key_is_set(monkeypatch):
    monkeypatch.delenv("WEBHOOK_ENCRYPTION_KEY", raising=False)
    token = ops._encrypt("whsec_legacy")                       # encrypted under the service-role-derived key
    monkeypatch.setenv("WEBHOOK_ENCRYPTION_KEY", "a-dedicated-key")
    assert ops._decrypt(token) == "whsec_legacy"               # legacy secrets remain usable
    fresh = ops._encrypt("whsec_new")
    monkeypatch.delenv("WEBHOOK_ENCRYPTION_KEY")
    with pytest.raises(Exception):
        ops._decrypt(fresh)                                    # new secrets require the dedicated key


# --- pinned transport ---------------------------------------------------------------------

def test_send_pinned_connects_to_the_validated_ip_keeps_host_and_sni_and_does_not_follow_redirects(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(ip=request.url.host, port=request.url.port or 443, path=request.url.raw_path.decode(), host=request.headers["host"], sni=request.extensions.get("sni_hostname"))
        return httpx.Response(302, headers={"location": "https://169.254.169.254/latest/meta-data/"})

    real_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        captured["follow_redirects"] = kwargs.get("follow_redirects")
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(ws.httpx, "AsyncClient", client_factory)
    target = ws.ResolvedTarget("https://hooks.example.com/in", "hooks.example.com", 443, "/in?a=1", (PUBLIC,))
    response = run(ws.send_pinned(target, b"{}", {"Content-Type": "application/json"}))
    assert (captured["ip"], captured["port"], captured["path"]) == (PUBLIC, 443, "/in?a=1")  # the validated address
    assert captured["host"] == "hooks.example.com"                # virtual host preserved
    assert captured["sni"] == "hooks.example.com"                 # TLS name check against the real hostname
    assert captured["follow_redirects"] is False
    assert response.status_code == 302                            # redirect is returned, not followed -> treated as failure
