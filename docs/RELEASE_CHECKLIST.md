# Release checklist (pilot readiness)

Tick only with recorded evidence in `PRODUCTION_READINESS_PLAN.md`. Unticked = not done.

- [x] Backend test suite green locally with real Redis (446 passed, 1 xfail, 2026-10-25)
- [ ] GitHub-hosted CI observed green on the release commit
- [ ] **BLOCKER** apply `20261026_lock_down_client_access.sql` (F-29) to staging then production, re-run `supabase/tests/client_access_attack.sql` equivalent against it
- [ ] **BLOCKER** reconcile live schema with the code (F-30): baseline migration for all tables/RPCs the backend uses, applied on staging first
- [ ] Enable leaked-password protection in Supabase Auth (dashboard)
- [ ] Real Supabase schema exported to migrations; RLS policies reviewed and tested (F-14)
- [ ] Staging environment created; release rehearsed there
- [ ] Backup restore drill completed
- [ ] Upstash `EVAL` rate limit verified on the real database
- [ ] Real provider smoke test (OpenAI and Anthropic) with a test key
- [x] Backend `pip-audit` clean (2026-10-25); [ ] frontend `npm audit` residual build-tool advisories accepted or upgraded; [ ] upgraded versions smoke-tested against real Supabase/OpenAI/Upstash
- [ ] Detection re-evaluated on a fresh blind set; multilingual gap (F-27) addressed or accepted in writing by the owner
- [ ] Load test at expected pilot volume; p95 latency recorded
- [ ] Independent security review / penetration test of the gateway and admin plane
- [ ] Privacy notice, operator agreement and data-processing terms reviewed by a South African lawyer (POPIA)
- [ ] Incident runbook drill performed
- [ ] `KNOWN_LIMITATIONS.md` shared with pilot customers
