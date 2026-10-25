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
- 446 tests; CI runs them (with real Redis) before deploy.

### Changed
- Provider adapters rewritten: requested model verbatim, status checks, bounded retries, normalised errors (504/429/503/502).
- Gateway fails closed on inspection or audit failure.

### Removed
- Fabricated provider cost figures; silent fallback responses; billable provider health check.

### Known open items
See `docs/KNOWN_LIMITATIONS.md`.
