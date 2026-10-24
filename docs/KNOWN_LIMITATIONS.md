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
- **Prompt-injection detection is weak (F-18, F-26).** Regex rules only; `Ignore all previous instructions...` is
  allowed (strict xfail in `tests/test_detection_gaps.py`). No evaluation dataset. No South African ID/phone/card
  detection. Do not describe the firewall as comprehensive.
- **No limiting of unauthenticated traffic.** Invalid-API-key floods are not throttled per client IP, because trustworthy
  client-IP extraction depends on the proxy topology (Render/Vercel) that has not been confirmed.
- No token-based quotas or cost budgets; only request-count limits. Fixed-window counting allows up to 2x the limit
  across a window boundary.
- Enterprise SSO (OIDC/SAML) is not functional (F-13): identity-connection secrets are stored hashed.
- Audit log is mutable service-role data without a hash chain (F-20); admin-action audit writes are best-effort.
- Webhook retries run in-process: a restart loses in-flight retries (the delivery row stays `pending`). No secret
  rotation endpoint. The SSRF guard cannot stop a public host the customer controls from receiving event data.
- Streaming responses are not supported by the gateway, so output filtering before release is whole-response only.

## Operational gaps
- About 25 `print()` calls in legacy modules still bypass the redacting JSON logger.
- Render free plan (cold starts, no SLA); no staging environment; no backup-restore drill; no load testing.
- Synchronous Supabase client calls inside async handlers limit throughput (F-21).
- Cost figures are not reliable (F-16): provider pricing is hard-coded.
- Dependencies have known vulnerabilities (B7); upgrades are pending.
