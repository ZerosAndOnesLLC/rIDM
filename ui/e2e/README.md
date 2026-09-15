# End-to-end tests

Playwright drives the real end-user pages against a running rIDM API, with
[Mailpit](https://mailpit.axllent.org/) catching the emails the flows send.

Prerequisites (the compose `dev` profile provides Postgres, Valkey and Mailpit):

```bash
docker compose -f deploy/docker-compose.yml --profile dev up -d postgres valkey mailpit
# API on :8090 that sends the browser to the dev UI and mail to Mailpit
UI_URL=http://localhost:3110 SMTP_HOST=localhost SMTP_PORT=1025 SMTP_SECURITY=none \
  SMTP_FROM='rIDM <no-reply@ridm.local>' cargo run -p ridm-api
cd ui && npm run e2e            # starts `next dev -p 3110` itself
```

Global setup prepares the `master` tenant directly in the database (password,
magic-link and registration enabled, dynamic client registration open), registers a
client, and creates one user through the registration flow. Settings:

| Variable | Default |
|----------|---------|
| `E2E_API_URL` | `http://localhost:8090` |
| `E2E_UI_PORT` / `E2E_UI_URL` | `3110` / started by Playwright |
| `E2E_MAILPIT_URL` | `http://localhost:8026` |
| `E2E_DATABASE_URL` | `postgres://ridm_migrator:ridm_migrator@localhost:5440/ridm` |
| `E2E_REDIS_URL` | `redis://localhost:6390` (tenant cache is cleared after the settings change) |
| `E2E_TENANT` | `master` |

Every page under test is also checked with axe-core; serious and critical
accessibility violations fail the run.
