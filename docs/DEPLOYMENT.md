# Deployment

**Nothing in this document has been executed against production by the engineering agent.** Changing production
environment variables, running production migrations, deleting resources and DNS changes require explicit owner
authorisation and are performed by the owner.

## Environments
Currently one production-style stack (Render API, Vercel frontend, Supabase, Upstash). **No staging exists** - create a
separate Supabase project and Render service before the pilot and rehearse every release there.

## Required configuration (API)
| Variable | Required | Purpose |
|---|---|---|
| `ENVIRONMENT=production` | yes | Enables strict startup validation |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | yes | Startup fails without them in production |
| `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY` | at least one | Provider access (warning if none) |
| `FRONTEND_URL` | yes | CORS origin; placeholder values warn |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | recommended | Shared rate limits |
| `WEBHOOK_ENCRYPTION_KEY` | recommended | Fernet key(s) for webhook secrets (comma-separated list supports rotation) |
| `GATEWAY_RATE_LIMIT_PER_MINUTE`, `GATEWAY_ORG_RATE_LIMIT_PER_MINUTE` | optional | Defaults 60 / 600 |
| `IP_RATE_LIMIT_PER_MINUTE`, `TRUSTED_PROXY_HOPS` | optional | Defaults 300 / 1. Pre-auth per-IP limit; `/health` and `/ready` exempt. Verify the hop count on the live service before relying on it (`0` ignores `X-Forwarded-For`) |
| `LOG_LEVEL`, `CONFIG_STRICT` | optional | `CONFIG_STRICT=true` turns warnings into startup errors |

Secrets live only in Render/Vercel/Supabase settings, never in the repository.

## Release procedure (proposed)
1. Merge to `main` only after `Production checks` and `tests` workflows pass (backend tests run with a real Redis).
2. Apply database changes first (when migrations exist - the base schema is not yet version-controlled, F-14), on staging,
   then production by the owner, with a backup taken immediately before.
3. `deploy-api` workflow deploys to Render after tests pass (`wait-for-success`). Confirm `GET /ready` returns 200 and
   check logs for `config_warning` lines.
4. Smoke test: create a key, call `/v1/chat/completions` with a harmless prompt, confirm one audit row and
   `X-Request-ID`.
5. Rollback: redeploy the previous Render deploy (dashboard). Database changes must be backward compatible for one
   release so the code rollback is safe.

## Backups
Supabase backup/PITR availability depends on the plan and has **not been checked**. A restore drill is a pilot blocker.
