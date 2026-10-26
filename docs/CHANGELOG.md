# Changelog (branch `production-readiness`)

## Unreleased
### Added
- Request IDs, redacting JSON logging, startup config validation, `/ready` checks.
- Atomic rate limiting (Redis Lua) with documented fail-safe fallback; lifecycle-endpoint limits.
- Webhook SSRF protection, signed deliveries (timestamped HMAC V2), bounded retries.
- Deterministic detection engine with evaluation harness and blind held-out set (`docs/DETECTION_EVALUATION.md`).
- Policy engine: model/provider allow-lists, PII / injection / sensitive-content toggles (`app/policy.py`).
- Role-preserving message handling with a separate trusted guard message.
- Hash-chained audit events, `GET /v1/audit/verify`, SCIM token audit events.
- Pre-authentication per-client-IP rate limit (`IPRateLimitMiddleware`, `IP_RATE_LIMIT_PER_MINUTE`, `TRUSTED_PROXY_HOPS`).
- NVIDIA NIM provider adapter (fixed endpoint, normalised errors, bounded retries); `MONTHLY_TOKEN_BUDGET` hard stop; optional dated price table (`MODEL_PRICES_JSON`).
- 474 tests; CI runs them (with real Redis) before deploy.

### Changed
- Dependencies: runtime set trimmed to what the API imports and upgraded (pip-audit clean); frontend react-router 7; CI audits dependencies.
- Frontend: Tailwind installed (styling was largely missing), fabricated metrics removed, dashboard uses live API data only.
- Provider adapters rewritten: requested model verbatim, status checks, bounded retries, normalised errors (504/429/503/502).
- Gateway fails closed on inspection or audit failure.

### Removed
- OpenAI provider and the `openai` dependency (replaced by NVIDIA NIM). Breaking: `gpt-*` model names are now rejected; default model is `meta/llama-3.1-8b-instruct`; `OPENAI_API_KEY` is no longer read.
- Fabricated provider cost figures; silent fallback responses; billable provider health check.

### Known open items
See `docs/KNOWN_LIMITATIONS.md`.
