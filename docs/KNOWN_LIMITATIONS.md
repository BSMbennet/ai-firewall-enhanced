# Known limitations and open risks

Honest list of what is **not** done or **not verified**. Items are removed only when evidence is recorded in
`PRODUCTION_READINESS_PLAN.md`. Independent security review and penetration testing are still required before any
high-risk enterprise or government deployment.

## Verification gaps
- Nothing has been run against a live Supabase project, Render, Vercel, Upstash or a real AI provider. All tests use an
  in-memory Supabase fake, a recording provider and (for rate limiting) a local Redis 7.0.
- **Upstash REST `EVAL`** is assumed to behave like Redis `EVAL` for the rate-limit script. The script is verified on
  Redis 7.0 only. Verify on the real Upstash database before relying on shared limits in production.
- Row Level Security and database constraints are untested: the base schema is not in version control (F-14).
- GitHub-hosted CI has not yet been observed running the rewritten workflows.

## Security gaps
- **Prompt-injection detection is rule-based and incomplete (F-18, F-27).** Measured in `docs/DETECTION_EVALUATION.md`:
  85.7% on the author-written tuning set but **35% on the first blind held-out set** (n=20). Not detected: other
  languages (Spanish/French/Afrikaans overrides are allowed), encodings, leetspeak, paraphrases, role-play framing,
  indirect injection from retrieved documents. No ML signal and no human-reviewed real-traffic evaluation. Known false
  positives exist (held requests such as "disable the content filter in Chrome"). Do not describe the firewall as
  comprehensive or as preventing prompt injection.
- PII coverage: SA ID numbers, SA/international phones, cards, emails, common key shapes, JWTs, passwords and private keys.
  Not covered: passport numbers, bank accounts, names, addresses, health data, digit-by-digit spaced identifiers.
- Trusted/untrusted separation: the security rules are a separate first system message and roles are preserved; this
  reduces but does not eliminate injection risk (the model may still follow untrusted text). Only text content is
  supported; tool/function messages and images are rejected.
- **No limiting of unauthenticated traffic.** Invalid-API-key floods are not throttled per client IP, because trustworthy
  client-IP extraction depends on the proxy topology (Render/Vercel) that has not been confirmed.
- No token-based quotas or cost budgets; only request-count limits. Fixed-window counting allows up to 2x the limit
  across a window boundary.
- Enterprise SSO (OIDC/SAML) is not functional (F-13): identity-connection secrets are stored hashed.
- Audit: `audit_events` carry a per-organisation hash chain (`GET /v1/audit/verify`), which is tamper-*evident* only: a
  service-role holder can re-hash it, concurrent writes can fork it, the head is not anchored outside the database, and the
  gateway request log (`audit_logs`) is not chained. Admin-action audit writes are best-effort. Failed API-key
  authentications are logged, not stored (unauthenticated callers must not be able to grow tables).
- Webhook retries run in-process: a restart loses in-flight retries (the delivery row stays `pending`). No secret
  rotation endpoint. The SSRF guard cannot stop a public host the customer controls from receiving event data.
- Streaming responses are not supported by the gateway, so output filtering before release is whole-response only.

## Operational gaps
- About 25 `print()` calls in legacy modules still bypass the redacting JSON logger.
- Render free plan (cold starts, no SLA); no staging environment; no backup-restore drill; no load testing.
- Synchronous Supabase client calls inside async handlers limit throughput (F-21).
- Cost is not computed (F-16): fabricated prices were removed; there is no dated price table yet, so cost is recorded as 0.
- Backend dependencies were upgraded and audit clean on 2026-10-25 (`pip-audit`); **new versions were not run against live Supabase/OpenAI/Upstash** (fastapi 0.104->0.162, starlette 0.27->1.10, openai 1.6->3.37, supabase 2.3->2.33). Frontend: 5 build/dev-tooling advisories remain (vite/esbuild, tailwind chain); fixes require major upgrades. Legacy modules importing removed packages (`app/validators`, `self_learning_model.py`, `metrics.py`, `database.py`, `cache.py`, `rate_limit.py`, `render_redis.py`) are unused and would fail to import.
