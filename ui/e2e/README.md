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
client, creates one user through the registration flow and makes them a global
owner (`ridm:owner` in `master`) so the console specs can sign in as them. Settings:

| Variable | Default |
|----------|---------|
| `E2E_API_URL` | `http://localhost:8090` |
| `E2E_UI_PORT` / `E2E_UI_URL` | `3110` / started by Playwright |
| `E2E_MAILPIT_URL` | `http://localhost:8026` |
| `E2E_DATABASE_URL` | `postgres://ridm_migrator:ridm_migrator@localhost:5440/ridm` |
| `E2E_REDIS_URL` | `redis://localhost:6390` (tenant cache is cleared after the settings change) |
| `E2E_TENANT` | `master` |

## What is covered

| Spec | Journey |
|------|---------|
| `login` | password sign-in (wrong then right), session reuse, `prompt=login` |
| `email-otp` | "Email me a code": wrong code refused, emailed code signs in |
| `magic-link` | sign-in link by email |
| `register` | self-registration, email verification link, first sign-in |
| `invite` | invitation acceptance (password set once, token single-use), then sign-in |
| `recover` | password reset by emailed link, sign-in with the new password |
| `password-change` | forced change at login (mismatch guard, notification email, old password refused) |
| `profile-terms` | profile completion for a newly required attribute; terms re-acceptance |
| `lockout` | account lock after repeated failures; right password refused while locked |
| `consent` | consent denied returns `access_denied` (approval runs inside every sign-in) |
| `logout` | RP-initiated logout with confirmation |
| `console-clients` | wizard creating a confidential client (defaults per type, redirect URI required, reveal-once client ID and secret), detail auto-save surviving a reload and an API-refused change reloading the stored client, secret rotation with grace and revoking the retiring secret, service account, registration token, playground running a real sign-in for a public client (redirect URI added in one click, token response, ID token claims, userinfo, refresh), deletion |
| `console-tenants` | tenants list, slug validation and creation, settings saving as you go (text, switch, number, select and tag fields) and surviving a reload, branding changes reaching the framed login-page preview live and after a reload, tenant deletion with typed confirmation |
| `console` | admin console: sign-in card validation, PKCE sign-in through the tenant login page back to a deep link, session reuse on reload, global search (pages, users, clients), tenant switcher and `t`/`?`/`g o` shortcuts, theme switch persistence, sign-out ending the SSO session, refused stray callback, phone navigation drawer |
| `a11y` | error, device, invite, verify and logout pages, and login without a tenant |
| `openapi-contract` | the live `/openapi.json` equals the committed `api/openapi.json` the typed admin client is generated from; the `openapi-fetch` client reaches the live API and types its 401 problem body |

MFA, passkeys and the device page get their journeys with Phases 7 and 8.

Every page under test is also checked with axe-core; serious and critical
accessibility violations fail the run. Specs that need rows in row-level-secured
tables write them through `tenantSql` (a transaction-local RLS bypass) and call
`clearTenantCache`, which also publishes the API's own invalidation message so
in-process caches drop the stale copy.
