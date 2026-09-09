# Production acceptance matrix

## Authentication
- [ ] Signup creates a Supabase Auth user and organization owner profile.
- [ ] Login restores a valid session.
- [ ] Logout revokes the browser session.
- [ ] Inactivity timeout logs out according to role policy.
- [ ] Invalid/expired JWT returns 401.

## Tenant isolation
- [ ] User A cannot read User B's organization.
- [ ] User A cannot read User B's employees.
- [ ] User A cannot read User B's applications.
- [ ] User A cannot read User B's API keys.
- [ ] User A cannot read User B's audit/security events.
- [ ] User A cannot mutate User B's policies, applications, members or integrations.

## RBAC
- [ ] owner can manage all organization controls.
- [ ] admin can manage employees/apps/policies within the configured admin boundary.
- [ ] security can manage security operations and policy controls.
- [ ] developer cannot manage identity/SCIM.
- [ ] member/viewer cannot perform privileged mutations.
- [ ] Frontend restrictions are backed by server-side checks.

## API gateway
- [ ] API key is shown only at creation.
- [ ] Stored API key is a hash, never plaintext.
- [ ] Expired key is rejected.
- [ ] Revoked key is rejected.
- [ ] Disabled application is rejected.
- [ ] Blocked prompt returns 403 with request ID and safe security metadata.
- [ ] Allowed request reaches configured provider and returns an OpenAI-compatible response.
- [ ] Audit event is created for allow/block.

## Employee lifecycle
- [ ] Admin invitation creates organization membership.
- [ ] Employee role change is persisted server-side.
- [ ] Suspension prevents future access.
- [ ] Removal prevents future organization access.
- [ ] Employee activity is organization-scoped.

## Enterprise identity
- [ ] Identity connection secrets are never returned by read endpoints.
- [ ] SCIM token is shown only at creation.
- [ ] SCIM token is hashed.
- [ ] Expired/revoked SCIM token is rejected.
- [ ] SCIM create/update/deactivate changes organization membership.
- [ ] Verified domains are required when configured.

## Compliance
- [ ] Audit export contains no provider/API/SCIM/webhook secrets.
- [ ] Governance tables are organization-scoped.
- [ ] Retention setting is enforced by a scheduled server-side job.
- [ ] Access reviews can record reviewer decisions.
- [ ] Policy changes are versioned and attributable to an authenticated administrator.

## Reliability
- [ ] `/health` reports dependency state.
- [ ] `/ready` is usable by deployment health checks.
- [ ] Provider failure returns a controlled 502.
- [ ] Cache/storage failures do not expose secrets.
- [ ] Webhook delivery is retryable and idempotent.
- [ ] Deployment build passes before production promotion.
