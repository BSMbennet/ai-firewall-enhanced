# Threat model (initial, pre-pilot)

Scope: the API gateway and admin plane. Method: STRIDE-style walk through trust boundaries. This is the author's
analysis, **not an independent review**. "Control" means implemented in code and covered by a test unless marked otherwise.

| # | Threat | Control | Residual risk |
|---|---|---|---|
| T1 | Cross-tenant data access (IDOR) | Organisation derived from principal; negative tests in `test_authz.py` | RLS absent/untested; a handler bug bypasses isolation because the service-role key is used |
| T2 | Privilege escalation (member -> admin) | Role dependencies; cannot grant role >= own, cannot change own role/status; tests | Roles are coarse; no per-resource permissions |
| T3 | Stolen/leaked API key | Keys stored hashed; revoke, rotate, expiry, scopes; prefix-only display; rate limits | Keys are bearer tokens; no IP allow-listing |
| T4 | Prompt injection / jailbreak | Rule-based detection, guard message, role separation | **Weak**: 35% on blind set; no multilingual coverage (F-27); indirect injection undetected |
| T5 | Sensitive data sent to a provider | PII/secret detection + redaction; private keys always blocked | Limited categories (no names/addresses/health data); toggle can be disabled by org |
| T6 | Sensitive data returned by a provider | Output redaction + harmful-content patterns | Pattern based; no streaming support |
| T7 | Bypass by failure (fail-open) | Inspection or audit failure -> request refused; provider failure -> error, no placeholder | Rate-limiter store failure falls back to per-instance limits |
| T8 | Abuse / cost exhaustion | Atomic rate limits, monthly request quota, token cap | Token budget is global and approximate (no per-org or cost budget); per-IP limit is coarse and its proxy-hop setting is unverified on the live deployment |
| T9 | SSRF through webhooks | Public-address enforcement, DNS pinning, no redirects, https only | A customer-controlled public host still receives event data |
| T10 | Forged/replayed webhook deliveries | Timestamped HMAC V2 signature + replay window | Receivers must verify (documented in API.md) |
| T11 | Audit tampering / repudiation | Hash chain + verify endpoint; append-only usage | Not tamper-proof against service-role holder; head not anchored |
| T12 | Secret leakage via logs/errors | Redacting formatter, no prompt/response bodies in provider errors; tests | ~25 legacy `print()` calls bypass the redactor |
| T13 | ReDoS / oversized input | Bounded regexes, 4000-char prompt cap, timing test (worst 48 ms on 20k chars) | No HTTP-layer body-size cap yet |
| T14 | Dependency vulnerabilities | CI installs pinned requirements | Known vulnerable versions remain (B7) |
| T15 | Compromise of the service-role key | Not stored in repo; startup validation | Key grants full DB access; rotation procedure in INCIDENT_RESPONSE.md; no secret manager |
