# Architecture (as implemented)

Describes what exists in this repository. Items marked *unverified* have never run against the live service.

## Components
| Component | Technology | Notes |
|---|---|---|
| API | FastAPI 0.104, Python 3.11 (`backend/.python-version`) | `backend/app/main.py` plus routers (`enterprise_router`, `operations_router`, `compliance_router`, `billing_router`). Hosted on Render (free plan) - *unverified* |
| Database / auth | Supabase Postgres + GoTrue | The API uses the **service-role key** and enforces tenancy and roles in application code; RLS is not relied on and is untested (F-14) |
| Shared limiter state | Upstash Redis (REST) | Lua script for atomic fixed-window counters; per-process fallback if the store is unreachable (never unmetered). Real-Upstash behaviour *unverified* |
| Frontend | React 18 + Vite 5 on Vercel | Display only; every authorisation decision is server-side |
| Providers | OpenAI chat completions, Anthropic messages | Fixed endpoints; models selected by prefix (`gpt-`, `claude-`) |

## Gateway request flow (`POST /v1/chat/completions`)
1. Request ID assigned (middleware) and bound to all logs.
2. API key authenticated (hash lookup, status, expiry, scope `chat`, owning member active).
3. Organisation policies loaded; per-key and per-organisation rate limits applied (429 + `Retry-After`).
4. Payload parsed: roles `system|user|assistant`, text only, size/message caps. Anything else -> 400.
5. Model/provider allow-lists enforced -> 400 `model_not_allowed`.
6. Monthly usage metered (only for valid, permitted requests).
7. Inspection (`detection.py` via `orchestrator.py`): injection rules, PII/secret detectors. Toggles from `policy.py`.
   Inspection error -> 503, **nothing forwarded**. BLOCK/REVIEW -> 403, nothing forwarded.
8. Audit row (`audit_logs`) written **before** forwarding; failure -> 503, nothing forwarded.
9. Messages built: trusted guard system message first, caller roles preserved, PII redacted if enabled.
10. Provider call (`llm_router.py`): requested model verbatim, 30 s timeout, one retry for transient errors only.
    Failures -> 504/429/503/502. No fallback text, no cross-provider fallback.
11. Response filtered (secret/PII redaction, harmful-content pattern filter) if `sensitive_content_protection`.
12. Audit row finalised (tokens, latency). Response returned.

## Tenancy and roles
Every row is scoped by `organization_id`; handlers derive the organisation from the authenticated principal, never from
the request body. Roles: owner > admin > security > developer > member > viewer (`auth.py` dependencies). Negative
cross-tenant and privilege tests live in `backend/tests/test_authz.py`.

## Outbound webhooks
`webhook_security.py`: https only, public-address check at create and at send time, DNS answers pinned, no redirects,
HMAC-SHA256 signature over timestamp + body, bounded retries off the request path. Secrets encrypted with MultiFernet.

## Observability
JSON logs with redaction (`observability.py`), `X-Request-ID` on every response, `/health` (liveness + integrations),
`/ready` (database + config checks), startup config validation that fails a production deploy with missing core settings.
