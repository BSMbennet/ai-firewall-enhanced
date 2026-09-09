# AI Firewall Enterprise Implementation Roadmap

This roadmap turns AI Firewall into an enterprise/government-ready AI security gateway. The target architecture is: customer application -> AI Firewall gateway -> security/policy engine -> approved LLM provider -> response controls -> immutable telemetry/audit.

## Phase 0 — Production foundation
**Status:** in progress / existing
- Vercel frontend, Render API, Supabase Auth/Postgres, Upstash cache, R2 storage, Better Stack monitoring.
- Environment separation and secret management.
- Health/readiness endpoints.
- CI build checks and deployment verification.
- CORS allow-listing and secure bearer authentication.

**Exit criteria:** production build passes; health/readiness are green; secrets are server-only; no service-role credential reaches the browser.

## Phase 1 — Identity and session security
**Status:** implemented
- Supabase Auth login/signup/OAuth.
- Protected frontend routes.
- Server-side JWT validation.
- Logout.
- Role-aware inactivity timeout and warning.
- Profile RLS so clients cannot change their own role/organization.

**Exit criteria:** expired/invalid sessions fail closed; role changes are enforced server-side.

## Phase 2 — Organizations and RBAC
**Status:** implemented, hardening ongoing
- Organization creation and ownership.
- Employees/members and invitations.
- Roles: owner, admin, security, developer, member, viewer.
- Application/environment management.
- Organization policies.
- API keys with expiry, revocation and hashed storage.
- Employee/application activity views.

**Exit criteria:** every organization-scoped query is constrained by the authenticated user's organization; privileged mutations use backend role checks.

## Phase 3 — AI security gateway
**Status:** implemented
- OpenAI-compatible `/v1/chat/completions` gateway.
- API-key authentication.
- Prompt validation.
- Prompt-injection/risk scoring.
- PII detection/redaction.
- Prompt guard.
- Provider routing/fallback.
- Response filtering.
- Block/allow decisions with request IDs.

**Exit criteria:** an integration can switch its base URL/key and receive a compatible response without exposing provider credentials.

## Phase 4 — Policy engine and controls
**Status:** existing; expand
- Organization-level policies.
- Approved providers/models.
- PII protection.
- Prompt-injection protection.
- Sensitive-content controls.
- Per-application controls.
- Rate limits and quotas.
- Policy versioning and change audit trail.
- Fail-closed behavior for invalid policy configuration.

**Exit criteria:** security administrators can define, publish, test and roll back policy versions.

## Phase 5 — Observability and security operations
**Status:** existing; expand
- Audit logs.
- Security events.
- Threat timeline.
- Employee/application activity.
- Usage, latency, token and cost analytics.
- Alerts for blocked/high-risk/PII events.
- Webhooks.
- Exportable audit evidence.

**Exit criteria:** security teams can answer who, what, when, application, decision, risk and policy for every gateway request.

## Phase 6 — Enterprise integrations
**Status:** existing foundation
- Custom domain onboarding.
- Managed TLS through the deployment platform.
- Webhook integrations.
- Identity connection configuration for Google, Microsoft/Azure, SAML and OIDC.
- SCIM token management and provisioning endpoints.
- Integration health/status.

**Exit criteria:** an organization's ICT team can connect identity, provision employees and route traffic without manual database access.

## Phase 7 — Enterprise identity lifecycle
**Status:** foundation exists; production completion required
- SAML/OIDC SSO initiation and callback flow.
- Domain discovery and verified-domain enforcement.
- SCIM create/update/deactivate lifecycle.
- Session revocation after suspension/removal.
- MFA enforcement policy at the organization level using the identity provider/Supabase Auth capabilities.
- Break-glass owner recovery procedure.

**Exit criteria:** enterprise users can authenticate through their IdP and employee lifecycle changes propagate automatically.

## Phase 8 — Compliance and governance
**Status:** existing foundation; expand
- Audit export.
- Retention policy.
- Data minimization.
- Security policy evidence.
- Access reviews.
- Administrative action logging.
- Compliance dashboards for SOC 2 / ISO 27001 / NIST-style control mapping.
- Evidence packages without storing unnecessary prompt content.

**Exit criteria:** security/compliance staff can export a defensible evidence package and demonstrate access control, monitoring and change history.

## Phase 9 — Billing and commercial controls
**Status:** infrastructure available; complete product flow
- Stripe products/prices.
- Organization subscription state.
- Usage metering.
- Plan limits and enforcement.
- Customer portal.
- Invoice/subscription webhook reconciliation.
- Enterprise contract/seat handling.

**Exit criteria:** billing state is authoritative, idempotent and cannot be bypassed by client-side fields.

## Phase 10 — Government/regulated deployment profile
**Status:** planned
- Strict tenant isolation.
- Region/data-residency configuration.
- Default-deny integrations.
- Stronger retention controls.
- Administrative separation of duties.
- Export controls and evidence workflows.
- Private networking/deployment options where required.
- Security documentation and incident-response runbooks.

**Exit criteria:** deployment profile can be configured for regulated customers without weakening the standard security model.

## Phase 11 — Production acceptance
- End-to-end signup -> organization -> employee -> application -> API key -> gateway -> firewall -> provider -> audit -> dashboard test.
- RBAC matrix tests for every role.
- API-key expiry/revocation tests.
- Cross-tenant access tests.
- SSO/SCIM integration tests.
- Load and rate-limit tests.
- Failure/timeout/fallback tests.
- Dependency and secret scanning.
- Vercel/Render deployment smoke tests.

## Role model

| Role | Dashboard | Employees | Apps | Policies | API keys | Identity/SCIM | Compliance |
|---|---|---|---|---|---|---|---|
| owner | yes | manage | manage | manage | manage | manage | manage |
| admin | yes | manage | manage | manage | manage | manage | manage |
| security | yes | manage | manage | manage | manage | read | manage |
| developer | yes | read | manage | read | use/create where allowed | no | read |
| member | yes | no | assigned | read | assigned | no | own/read |
| viewer | yes | read | read | read | read | no | read |

## Non-negotiable security rules

1. The browser never receives Supabase service-role credentials or provider secrets.
2. Frontend role checks are UX only; backend authorization is the security boundary.
3. Every organization-scoped database query must constrain on the authenticated organization.
4. Raw API keys, SCIM tokens and webhook secrets are shown only at creation time and stored as hashes/encrypted values as appropriate.
5. Audit events must not contain unnecessary secrets or full sensitive prompts.
6. Employee suspension/removal must invalidate access to organization resources.
7. Billing, quotas and policy enforcement are server-side.
8. Production deployments must pass build, smoke and cross-tenant authorization tests before release.
