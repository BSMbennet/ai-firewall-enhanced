# Security controls (what exists today)

Only controls that are implemented **and covered by an automated test** are listed as such. "Verified" here means
exercised by the test suite against fakes or a local Redis, **not** against production Supabase, Render, Vercel,
Upstash or a real AI provider. This document is not a compliance claim (no POPIA, ISO 27001 or SOC 2 attestation).

| Control | Behaviour | Evidence |
|---|---|---|
| Server-side authorization | Every protected route derives the actor from a verified Supabase JWT or API key and checks the member's role from the database; suspended/removed members are denied on every request | `tests/test_authz.py` |
| Tenant scoping | Organisation-scoped queries are constrained by the caller's organisation; client-supplied organisation ids are ignored | `tests/test_authz.py` (application level only - no RLS test yet, see KNOWN_LIMITATIONS) |
| API keys | 256-bit random secret shown once, stored as SHA-256 digest, scopes enforced, expiry/revocation honoured | `tests/test_api_keys.py` |
| Gateway fail-closed | Inspection failure, audit-write failure and `REVIEW`/`BLOCK` decisions never reach a provider | `tests/test_gateway.py` |
| Rate limits - gateway | Per API key (default 60/min, or the lowest `rate_limit_per_minute` among the organisation's policies) and per organisation (default 600/min). Applied before payload parsing and before monthly quota metering. 429 with `Retry-After` and `X-RateLimit-*` | `tests/test_limits.py` |
| Rate limits - lifecycle | Per verified user, per 10 minutes: API-key create 10, revoke 30, rotate 10; webhook create 10; member invite 20; SCIM token create 10. Unauthorised attempts count | `tests/test_limits.py` |
| Rate-limit store failure | Shared store (Upstash) unavailable, slow (>1 s) or unconfigured -> per-instance in-process limits keep being enforced and the decision is flagged degraded and logged once a minute. Traffic is never allowed unmetered | `tests/test_limits.py` |
| Rate-limit atomicity | Increment + window start + TTL repair happen in one server-side Lua call; 400 concurrent checks admit exactly the limit | `tests/test_limits.py` against a real Redis 7.0 |
| Webhook SSRF guard | HTTPS only, no credentials, all resolved addresses must be public, re-checked at delivery, connection pinned to the validated IP with original Host/SNI, redirects never followed | `tests/test_webhooks.py` |
| Webhook signatures | `X-AI-Firewall-Signature-V2: t=<unix>,v1=<hmac>` over `"<t>.<body>"`; receivers should reject timestamps outside 5 minutes. Legacy header kept for existing receivers (not replay-protected) | `tests/test_webhooks.py` |
| Webhook secrets | Encrypted at rest (Fernet); returned once at creation; never listed or logged. `WEBHOOK_ENCRYPTION_KEY` for new secrets, legacy service-role-derived key accepted for decryption only | `tests/test_webhooks.py` |
| Request inspection | Rule table (instruction override, role-marker injection, prompt exfiltration, jailbreak), Unicode/homoglyph/zero-width normalisation; ids and categories only in decisions, never matched text. Severity >= 0.8 blocks, >= 0.5 holds for review | `tests/test_detection.py`, `tests/test_detection_eval.py`; limits in `docs/DETECTION_EVALUATION.md` |
| PII / secret handling | Validated SA ID, SA phone, card (Luhn), email, provider/cloud keys, JWT, password; redacted before forwarding and in model output; private keys blocked outright | `tests/test_detection.py` |
| Inspection DoS bound | 17 adversarial 20k-character shapes inspected in < 0.5 s (about 50 ms measured) | `tests/test_detection.py` |
| Request correlation | `X-Request-ID` on every response (well-formed inbound ids propagated, others replaced), shared with gateway body, audit rows and error bodies | `tests/test_observability.py` |
| Log hygiene | JSON logs; bearer tokens, JWTs, API/SCIM/webhook/provider key shapes and `name=value` secrets redacted; query strings never logged | `tests/test_observability.py` |
| Startup validation | In production only missing Supabase credentials or a match-everything CORS regex stop startup; other gaps warn (`CONFIG_STRICT=true` promotes warnings) | `tests/test_observability.py` |

## Rate-limit configuration

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | 60 | Per API key (and per user for `/v1/secure-ai/query`) when no organisation policy sets a lower value |
| `GATEWAY_ORG_RATE_LIMIT_PER_MINUTE` | 600 | Per organisation across all keys |
| `WEBHOOK_MAX_CONCURRENT_DELIVERIES` | 20 | Concurrent background webhook deliveries per instance |

An organisation policy's `rate_limit_per_minute` is interpreted as **per API key** and can only *lower* the limit below
the default if it is smaller; invalid, zero or negative values are ignored and never mean "unlimited".
