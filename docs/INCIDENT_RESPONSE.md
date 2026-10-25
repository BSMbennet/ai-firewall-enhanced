# Incident response (initial runbook)

Not exercised in a drill. Owner: the platform owner. Record every incident with timeline, impact and actions.

## Severity
- **SEV1** suspected data exposure across tenants, leaked service-role key, gateway forwarding without inspection/audit.
- **SEV2** provider outage, sustained 5xx, rate-limiter failure, webhook abuse.
- **SEV3** degraded detection quality, single-tenant misconfiguration.

## First 30 minutes
1. Declare severity; note the time; keep a log. Use `X-Request-ID` to correlate (every response carries one).
2. Contain (see below). 3. Preserve evidence (Render logs, Supabase logs, `audit_events`, `audit_logs`); run `GET /v1/audit/verify`.
4. Communicate: affected organisations promptly; for personal-information compromise, see POPIA below.

## Playbooks
- **Leaked customer API key:** revoke (`DELETE /v1/api-keys/{id}`) or rotate; review `audit_logs` for the key's usage.
- **Leaked service-role / provider / Upstash key:** rotate at the provider, update Render env (owner action), redeploy,
  review Supabase logs for the exposure window. Rotating the service-role key invalidates the running API until redeployed.
- **Suspected cross-tenant exposure:** disable the affected endpoint or deployment, identify the handler from logs, add a
  failing regression test in `test_authz.py` before fixing.
- **Provider outage:** gateway returns 502/503/504 by design; no failover is configured. Communicate; do not enable
  unreviewed fallback providers.
- **Abusive tenant:** revoke keys / suspend member; lower `rate_limit_per_minute` in the policy.
- **Malicious webhook target:** delete the webhook (`DELETE /v1/enterprise/webhooks/{id}`).

## POPIA
A security compromise involving personal information must be notified to the Information Regulator and affected data
subjects as soon as reasonably possible (POPIA s22). Obtain legal advice for the exact obligations; this runbook is not
legal advice. The platform stores prompts only as redacted audit metadata where implemented - verify per deployment.
