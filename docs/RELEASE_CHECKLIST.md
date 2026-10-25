# Release checklist (pilot readiness)

Tick only with recorded evidence in `PRODUCTION_READINESS_PLAN.md`. Unticked = not done.

- [x] Backend test suite green locally with real Redis (446 passed, 1 xfail, 2026-10-25)
- [ ] GitHub-hosted CI observed green on the release commit
- [ ] Real Supabase schema exported to migrations; RLS policies reviewed and tested (F-14)
- [ ] Staging environment created; release rehearsed there
- [ ] Backup restore drill completed
- [ ] Upstash `EVAL` rate limit verified on the real database
- [ ] Real provider smoke test (OpenAI and Anthropic) with a test key
- [ ] Dependency upgrades and `pip audit` / `npm audit` reviewed (B7)
- [ ] Detection re-evaluated on a fresh blind set; multilingual gap (F-27) addressed or accepted in writing by the owner
- [ ] Load test at expected pilot volume; p95 latency recorded
- [ ] Independent security review / penetration test of the gateway and admin plane
- [ ] Privacy notice, operator agreement and data-processing terms reviewed by a South African lawyer (POPIA)
- [ ] Incident runbook drill performed
- [ ] `KNOWN_LIMITATIONS.md` shared with pilot customers
