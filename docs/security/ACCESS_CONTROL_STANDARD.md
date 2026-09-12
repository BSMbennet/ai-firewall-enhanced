# Access Control Standard

## Roles
- Owner: full organization administration and billing.
- Admin: manage members, roles, applications, and keys.
- Security Analyst: view security events, investigate, and export reports.
- Developer: manage assigned applications and non-production keys.
- Viewer: read-only dashboards.

## Rules
- Deny by default.
- Every request must resolve an authenticated user and organization membership.
- Organization ID must come from trusted membership context, never from an untrusted client field.
- Privileged actions require explicit role checks.
- API keys are scoped to an organization and application, shown once, hashed at rest, revocable, and rotated.
- Disabled or removed employees lose access immediately.
- Review privileged access monthly and on role changes.
- Require MFA for privileged users before production rollout.

## Lifecycle
1. Invite employee.
2. Accept invite and verify identity.
3. Assign least-privilege role.
4. Review access periodically.
5. Suspend or remove on departure.
6. Revoke sessions and keys when required.