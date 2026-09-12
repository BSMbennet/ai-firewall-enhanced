# Backup, Restore and Incident Response Standard

## Scope
This standard applies to production data, authentication, organization membership, API keys, audit logs, security events, and deployment configuration.

## Backup evidence required
- [ ] Supabase automated backup schedule documented.
- [ ] Backup retention and encryption settings recorded.
- [ ] Backup access restricted to named administrators.
- [ ] At least one restore test completed each quarter.
- [ ] Restore test records include date, operator, source backup, restored target, validation results, and issues.
- [ ] Recovery point objective (RPO) and recovery time objective (RTO) approved by management.
- [ ] Disaster recovery runbook reviewed after material architecture changes.

## Restore procedure
1. Declare the recovery event and appoint an incident commander.
2. Identify the last known-good backup and preserve relevant evidence.
3. Restore into an isolated environment first.
4. Validate organization isolation, authentication, memberships, API-key revocation state, and audit-log integrity.
5. Obtain approval before production cutover.
6. Record the result and all deviations.

## Incident response lifecycle
1. Detect and triage.
2. Contain affected credentials, sessions, workloads, or network paths.
3. Preserve logs and evidence.
4. Eradicate the cause and rotate exposed secrets.
5. Recover using the approved restore/deployment procedure.
6. Notify affected stakeholders according to contractual and legal requirements.
7. Complete a post-incident review with corrective actions.

## Evidence register
Maintain restricted evidence for:
- incidents and timelines;
- access and credential revocation;
- backup and restore tests;
- security alerts and investigations;
- post-incident reviews;
- tabletop exercises;
- policy approvals and review dates.

This document is an implementation and evidence standard. It is not proof that backups, restores, or incident exercises have already been performed.
