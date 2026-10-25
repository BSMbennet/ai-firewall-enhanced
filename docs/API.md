# API reference (summary)

Generated from the registered FastAPI routes; interactive schema at `/docs` when the service is running. Errors from
the gateway use `{"error": {"message","type","code"}, "request_id"}`.

**Auth:** `Bearer <Supabase JWT>` for the admin plane; `Bearer <API key>` for the gateway. "any member" endpoints may
still apply role checks inside the handler (e.g. creating API keys requires owner/admin; tested).

## Gateway
`POST /v1/chat/completions` - API key (scope `chat`). Body: `model`, `messages[{role: system|user|assistant, content: string | [{type:"text",text}]}]`,
optional `max_tokens` (capped 4000), `temperature` (0-2). No streaming.

| Status | code | Meaning |
|---|---|---|
| 400 | `invalid_request`, `unsupported_role`, `unsupported_content`, `prompt_too_long`, `model_not_allowed`, `invalid_parameter` | Rejected before inspection or forwarding |
| 401/403 | - | Missing/invalid/revoked key, wrong scope, suspended member; 403 `security_policy` / `review_required` for blocked or held requests |
| 429 | `rate_limit_exceeded`, `provider_rate_limited` | Includes `Retry-After`; successful responses carry `X-RateLimit-*` |
| 502/503/504 | `provider_unavailable`, `provider_not_configured`, `inspection_unavailable`, `audit_unavailable`, `provider_timeout` | Nothing was returned from a provider |

`POST /v1/secure-ai/query` - interactive equivalent using a user session.

## Admin plane (JWT)
- Organisation: `GET /v1/organization`, `/members` (GET/POST/PATCH), `/applications`, `/policies` (GET, PATCH `{id}`), `/activity`, `/stats`.
- API keys: `POST/GET /v1/api-keys`, `DELETE /v1/api-keys/{id}`, `POST /v1/enterprise/api-keys/{id}/rotate`.
- Audit: `GET /v1/audit/verify`, `/v1/enterprise/audit/search`, `/audit/export`, `/v1/admin/logs`, `/v1/dashboard/*`.
- Alerts/webhooks: `/v1/enterprise/alert-rules`, `/alerts`, `/webhooks` (+ `/{id}/test`).
- Identity/governance: `/v1/enterprise/identity` (SSO is not functional, F-13), `/domains`, `/auth/policy`, `/governance/*`, `/retention`, `/compliance/*`, `/onboarding`.
- SCIM: token management under `/v1/enterprise/scim/tokens`; provisioning at `/v1/enterprise/scim/{org_slug}/Users` (SCIM bearer token).
- Billing: `/v1/enterprise/billing/*`, `/billing/*`.

## Operations
`GET /health`, `GET /ready` (200 only if database and configuration checks pass), `GET /` .

## Webhook signature (outgoing)
Header `X-AI-Firewall-Signature-V2: t=<unix>,v1=<hex>` where `v1 = HMAC-SHA256(secret, "<t>." + raw body)`. Other
headers: `X-AI-Firewall-Event`, `-Event-Id`, `-Delivery-Attempt`. Receivers must reject timestamps outside the replay
window and compare in constant time (reference verifier: `webhook_security.verify_signature`).
