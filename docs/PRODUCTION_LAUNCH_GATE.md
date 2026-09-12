# Production Launch Gate

## Purpose

This document is the release gate for the AI Firewall investor demo and first controlled production pilot.

## Release modes

### Investor demo

Allowed when:

- Frontend and API health checks pass.
- A test organization can sign in.
- An API key can be created and used.
- Firewall allow/block behavior is demonstrable.
- Dashboard activity is visible.
- No real customer secrets or regulated data are used.
- The environment is explicitly labelled demo/pilot.

### Controlled pilot

Required before onboarding a real institution or company:

- Supabase migrations are applied to the target project.
- Organization IDs are enforced on every read/write query.
- RBAC tests cover every protected endpoint.
- Employee suspension/removal invalidates access and sessions.
- API keys are hashed, scoped, expiring, rotatable and revocable.
- Audit events cover authentication, authorization, employee, key, policy and data-export actions.
- Audit exports are authorized, bounded, rate-limited and free of secrets.
- Tenant-isolation tests pass against a real test database.
- Backups and a restore test are evidenced.
- Incident-response contacts and escalation paths are configured.
- Independent penetration testing is scheduled or completed.

## Pre-demo checklist

- [ ] Set production `FRONTEND_URL` and restrictive CORS origins.
- [ ] Set `SUPABASE_URL` and service-role key only in server-side secrets.
- [ ] Set `RESEND_API_KEY` and verified `RESEND_FROM_EMAIL`.
- [ ] Set provider API keys only in Render secrets.
- [ ] Confirm `/health` and `/ready`.
- [ ] Create a dedicated demo organization.
- [ ] Create separate demo employees for Owner, Admin, Security Analyst and Viewer.
- [ ] Create a demo application and API key.
- [ ] Demonstrate one allowed request and one blocked request.
- [ ] Show employee suspension and key revocation in the dashboard.
- [ ] Do not claim SOC 2 certification, completed penetration testing or completed disaster recovery testing unless independently evidenced.

## Investor-safe positioning

The product should be presented as an enterprise AI security control platform with organization management, employee access controls, API gateway protection, security policy enforcement and audit visibility. SOC 2, ISO 27001 and government procurement readiness are roadmap/evidence objectives until independently assessed.
