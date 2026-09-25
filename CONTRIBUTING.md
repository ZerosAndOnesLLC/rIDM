# Contributing to rIDM

Thanks for helping build an open, cloud-neutral identity server. This document covers
how to get a development environment running, the conventions the codebase follows, and
what a pull request needs before it can merge.

## Development environment

Requirements: Rust 1.98+ (`rust-toolchain.toml` pins the exact version), Node.js 24 LTS,
Docker with Compose, and `sqlx-cli` (`cargo install sqlx-cli --no-default-features
--features rustls,postgres`).

```bash
cp .env.example .env            # set MASTER_KEY=$(openssl rand -hex 32)
docker compose --env-file .env -f deploy/docker-compose.yml up -d postgres valkey
DATABASE_URL=postgres://ridm_migrator:ridm_migrator@localhost:5432/ridm \
  sqlx migrate run --source api/migrations
cargo run -p ridm-api           # http://localhost:8080/readyz
cd ui && npm install && npm run dev
```

The `Makefile` wraps these (`make setup`, `make api`, `make ui`, `make seed`, `make lint`,
`make test`; `make` lists them all), including seeded tenants to develop against and an
admin token without a browser. Compose reads `deploy/.env` unless told otherwise, hence `--env-file .env`. Migrations
run as the schema owner (`ridm_migrator`); the API connects as the DML-only `ridm_app`
from `.env`, and with `MIGRATE_ON_START=false` it only warns at startup when migrations
are pending. [`GETTING-STARTED.md`](GETTING-STARTED.md) has the fuller local setup (the
API on port 8090, Mailpit, the bootstrap administrator, the examples).

`cargo run -p ridm-api -- migrate` applies migrations too, in place of `sqlx migrate
run`. `make lint` is rustfmt, clippy as CI runs it, and the UI's lint and types;
`make test` the unit tests, `make test-all` the integration tests as well. `make token`
writes a 30-day token to `target/dev/token` (mode `0600`), and `make seed` is
re-runnable; `ACME_USERS=500 make seed` gives `acme` more users to page through (default
120). `make mail` prints Mailpit's address.

The two database roles are deliberate: Postgres superusers bypass row level security
and a table's owner can disable it, so the API must run as neither. The compose stack
creates both and migrates in a one-shot `migrate` service. `MIGRATE_ON_START=true` is
the simpler single-role mode for small installs (pending migrations applied at startup
as `DATABASE_URL`'s role); develop against the two-role setup, which is what production
runs.

Ports are overridable through `RIDM_PG_PORT`, `RIDM_VALKEY_PORT`, `RIDM_HTTP_PORT` and
`RIDM_MAILPIT_UI_PORT` if the defaults collide with something on your machine.

The workspace also builds `ridm`, the administration CLI (`crates/ridm-cli`). Point it at
a local server without writing a profile:

```bash
cargo run -p ridm-cli -- --url http://localhost:8080 --token "$RIDM_TOKEN" whoami
```

Set `RIDM_CONFIG` to a scratch path when a change touches profiles, so a test run never
rewrites your own `~/.config/ridm/config.json`.

**The UI.** The end-user pages are under `ui/src/app` (`/login/`, `/register/`,
`/consent/`, `/mfa/`, `/recover/`, ...); each is driven by query parameters, loads the
tenant's `GET /t/{slug}/branding` document as its theme, and walks the flow API step by
step. The admin console is in `ui/src/app/console/`, `ui/src/components/console/` and
`ui/src/lib/console/` (`auth.ts` is the PKCE sign-in, `session.tsx` the token store the
typed client reads). The `embedded-ui` cargo feature, which compiles `ui/out` into the
binary (`api/src/routes/ui.rs`), is off by default so a Rust-only checkout builds without
Node; a debug build with it reads `ui/out` from disk at run time, so rebuilding the
export needs no recompile. `npm run build` ends with `scripts/csp.mjs`, which writes each
page's `Content-Security-Policy` meta tag (inline scripts allowed by SHA-256 hash); it
has its own tests, `npm run test:scripts`.

## Conventions

**Rust**
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must all pass.
- No `unsafe`. No `SELECT *`. Every tenant-scoped query filters by `tenant_id` and every
  composite index leads with it.
- `mod.rs` files contain only module declarations and re-exports.
- Errors are typed (`thiserror`); handlers return `AppResult<T>` or `Result<T, OAuthError>`.
- Cache first: read through Valkey, invalidate on every write.
- Secrets never appear in logs. Wrap them in `SecretString` / `SecretBytes`.

**Migrations**
- Forward-only, created with `sqlx migrate add --source api/migrations <name>`.
- Never edit a migration once it is on `main`; sqlx refuses a database whose applied
  migration's checksum changed.
- Keep the previous release working (rolling upgrades run it on the new schema): add
  tables, columns with defaults and indexes; drop or rename only what the previous
  release no longer uses, one release after it stopped. The same goes for anything
  stored in Valkey. A migration that cannot keep this goes under **Upgrade notes** in
  `CHANGELOG.md` ([Upgrading](docs/src/deploy/upgrading.md)).
- Nothing may block writes to an existing table for longer than an instant (the
  migrations suite checks every migration from `20260923220219` on):
  - an index on an existing table is created (or dropped) `CONCURRENTLY`, in a
    migration whose first line is `-- no-transaction` and that holds that one
    statement; Postgres refuses `CONCURRENTLY` in a transaction, and several statements
    sent together run in one. A partitioned table cannot be indexed concurrently: its
    migration says why blocking it is acceptable (the word "partitioned" in a comment);
  - a foreign key on an existing table is added `NOT VALID` and validated by the next
    migration (`VALIDATE CONSTRAINT` does not block writes);
  - a new column on an existing table has no volatile default (`gen_random_uuid()`,
    `random()`, `clock_timestamp()`): add it, then backfill;
  - an index a tenant-scoped query uses leads with `tenant_id`; one that serves every
    tenant at once (the cleanup job's, the delivery jobs', key rotation's) is listed in
    `GLOBAL_LOOKUP_INDEXES` with the reason.
- Tested locally with `sqlx migrate run` before committing.
- Tenant-scoped tables call `enable_tenant_rls('table')`, which enables and forces the
  `tenant_isolation` policy. Child tables use composite `(tenant_id, id)` foreign keys.
- The API (and the tests) connect as a non-superuser role; superusers bypass RLS.

**UI**
- Next.js static export; no server components that require a Node runtime.
- `npm run lint` and `npm run typecheck` must pass with no rule disables.
- Forms auto-save; there are no separate "edit" modes.

**Dependencies**
- Exact-pinned in `Cargo.toml` and `package.json`; Renovate proposes updates.
- No pre-release (alpha/beta/rc/dev) versions.
- Nothing cloud-provider-specific in the default build.

## Tests

Tests are part of every change, not a follow-up. See `working-plan.md` §6 for the full
matrix. The short version:

| Kind | Command |
|------|---------|
| Unit | `cargo test --workspace --lib --bins` |
| Integration | `cargo test --workspace --tests` |
| Coverage | `cargo llvm-cov --workspace --all-features --html` |
| UI lint / types / build | `npm run lint && npm run typecheck && npm run build` |
| UI build scripts | `npm run test:scripts` |
| UI end-to-end | `npm run e2e` (Playwright, against a running API and Mailpit; see [`ui/e2e/README.md`](ui/e2e/README.md)) |
| Supply chain | `cargo audit && cargo deny check` |
| Fuzz (nightly) | `api/fuzz/run.sh 60` (one target: `api/fuzz/run.sh 60 authorize_params`) |

Integration tests need Postgres and Valkey (or any Redis-protocol server). Point them at running servers with
`RIDM_TEST_DATABASE_URL` and `RIDM_TEST_REDIS_URL` (for example the docker-compose
stack); without those variables the harness starts reusable containers named
`ridm-test-postgres` and `ridm-test-valkey` through testcontainers and reuses them on
later runs (`docker rm -f ridm-test-postgres ridm-test-valkey` removes them). The LDAP
and SAML interoperability tests start `ridm-test-openldap` and `ridm-test-keycloak`
(Keycloak 26) the same way. Each test
gets its own tenant and its own connection pools, so tests run in parallel. Mock
providers live in `ridm_core::test_support` (feature `test-support`) and capture what
was sent so tests assert on content instead of sleeping.

Every security finding gets a regression test in `api/tests/security/` before the fix
merges.

The admin API has one suite per resource (`api/tests/admin_*.rs`) and three that
cover it as a whole. `admin_matrix.rs` derives every admin operation and the permission
it needs from the route sources (each handler's `#[utoipa::path]` and its first
`admin.require*` call), checks all six built-in roles, the global owner and an anonymous
caller against each one, and calls every tenant-scoped operation across tenants and
across organizations, so a new endpoint is covered the moment it exists.
`admin_pagination.rs` walks listings with inserts in the middle, and `openapi.rs` keeps
`api/openapi.json` current. `api/tests/ridm_auth.rs` runs the `ridm-auth` crate against
tokens this server really issues.

### OpenAPI and the TypeScript client

The admin and account API's OpenAPI document is derived from the routers with utoipa,
so an undocumented route fails the build. Operation ids are the handler names prefixed
with their tag (`users_list`, `clients_create`), unique across the document as
generated clients require. After changing a route, regenerate the committed document
and the UI's typed client (`ui/lib/api/client.ts` on `openapi-fetch`, typed by
`ui/lib/api/openapi.d.ts`):

```bash
make openapi                    # or: cargo run -p ridm-api -- openapi > api/openapi.json
cd ui && npm run gen:api        # writes lib/api/openapi.d.ts
```

`openapi.rs` fails while the committed file differs from what the binary produces, and
the Playwright spec `ui/e2e/openapi-contract.spec.ts` compares the live document with
the committed one and drives the generated client against the live API.

CodeQL runs on every pull request (`.github/workflows/codeql.yml`) over the Rust, the
TypeScript, the Python helpers and the workflows themselves. It does not scan the test
suites (`.github/codeql/codeql-config.yml`): a test is meant to hold the fixed
passwords, fixed signing keys and printed tokens a scanner objects to, and an alert on
one says nothing about what ships. It is not a required check — a finding is triaged in
the Security tab, not by blocking the merge.

### OpenID conformance

The OpenID Foundation conformance suite runs against rIDM from
[`conformance/`](conformance/README.md): the suite's released images behind its own
nginx, rIDM behind a Caddy TLS front as `https://ridm.local` (a private CA the suite
trusts), and a headless Chromium driver that signs in, approves consent and confirms
logout for every browser step the tests leave pending. The `conformance` workflow runs
the configuration, basic (discovery + dynamic registration), RP-initiated, back-channel
and front-channel logout certification plans on every pull request and weekly, fails on
any finding not listed in `conformance/expected-failures.json`, and uploads the suite's
exported logs as an artifact. Running it locally: [`conformance/README.md`](conformance/README.md).

## CI

Every pull request runs the `ci` workflow (`.github/workflows/ci.yml`):

| Job | Checks |
|-----|--------|
| `static` | rustfmt, `cargo check`, clippy with warnings denied (default and optional features), `cargo audit`, `cargo deny`, `cargo package -p ridm-auth`, ESLint, `tsc`, `npm run test:scripts`, `npm audit`, the Helm chart's lint and schema |
| `unit`, `integration` | the Rust tests, integration against Postgres and Valkey |
| `coverage` | `cargo llvm-cov`, with an 80% line floor on each of `services/`, `oidc/` and `middleware/` |
| `ui-build` | the UI's static export |
| `ui-e2e` | the Playwright suite (end-user journeys and every console page, with axe-core checks in light, dark and phone width) against an API built with `embedded-ui` |
| `load-smoke` | a k6 smoke on `/token` with thresholds |
| `fuzz-smoke` | a minute of fuzzing per target |
| `packaging` | the container image boots, migrates and is ready; production compose behind each proxy; an upgrade from the previous release's image |
| `helm-smoke` | the chart on a kind cluster (`deploy/helm/smoke/run.sh`) |
| `examples-smoke` | the example applications signed into in headless Chromium against that image under docker-compose |

The `conformance` workflow runs the OpenID Foundation suite on the same pull request
(and weekly). Off the pull-request path, `weekly` fuzzes each target for four hours and
`release` runs the full 200-VU k6 baseline against a release build when a `v*` tag is
pushed. Fuzz targets, seeds and reproducing a crash: [`api/fuzz/README.md`](api/fuzz/README.md);
load tests: [`perf/README.md`](perf/README.md). Dependencies are exact-pinned and
updated by Renovate (`renovate.json`).

The `docs` workflow builds the GitHub Pages site (`scripts/pages/build.sh`) on every
pull request: the website from `site/` at the root, the documentation from `docs/`
under `/rIDM/docs/`, a redirect stub at each documentation page's old URL, and a
`sitemap.xml` for search engines, each page dated by its last commit. It
checks every link and anchor offline with lychee, plus the OpenAPI document the API
reference loads; on `main` it deploys the site to GitHub Pages. To work on it locally:

```bash
cargo install mdbook --version 0.5.4 --locked
cd docs && mdbook serve --open     # live reload; the API reference page needs ./build.sh
scripts/pages/build.sh             # the whole site in _site/
mkdir -p /tmp/pages && ln -sfn "$PWD/_site" /tmp/pages/rIDM &&
  python3 -m http.server -d /tmp/pages 8000   # http://localhost:8000/rIDM/
```

`site/` is plain HTML, CSS and SVG with no build step; its links are relative, except
in `404.html`, which GitHub Pages serves at any path.

## Pull requests

- Open an issue or discussion first for anything larger than a bug fix.
- Keep PRs focused; one logical change per PR.
- `main` is protected: every required status check must pass and no one can bypass.
  Those checks are `static`, `unit`, `integration`, `coverage`, `ui-build`, `ui-e2e`,
  `load-smoke`, `fuzz-smoke`, `packaging`, `helm-smoke`, `examples-smoke` (all in the `ci`
  workflow) and
  `conformance`.
  Adding a suite means adding it to `working-plan.md` §6 and to branch protection in the
  same pull request. The long runs — four hours a fuzz target (`weekly`) and the 200-VU
  load baseline (`release`) — do not gate a pull request.
- Do not bump versions. Releases bump `Cargo.toml` and `package.json` once, at release time.
- Update `README.md` (and docs) when behaviour or configuration changes.
- Commit messages: imperative subject line, body explains *why*.

## Cutting a release

Releases are built and published by `.github/workflows/release.yml` from a `v*` tag;
nothing is built or uploaded by hand. What a release publishes and how users verify it
is in the docs' *Releases and verification* page.

1. **Bump the version** in one pull request, everywhere it lives (and nowhere else in
   ordinary PRs): `Cargo.toml` (`[workspace.package] version`), `ui/package.json` (and
   `npm install --package-lock-only` for the lockfile), `deploy/helm/ridm/Chart.yaml`
   (`version` and `appVersion`), and the `version` on the `ridm-auth` path dependency in
   `examples/*/Cargo.toml`. Run `cargo check` so `Cargo.lock` follows.
2. **Write the notes**: rename `## [Unreleased]` in `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD`, start a new empty Unreleased section above it, and update
   the link references at the bottom.
3. `scripts/release/check-version.sh vX.Y.Z` must pass, and
   `scripts/release/notes.sh X.Y.Z` must print the notes. Merge the PR.
4. **Tag the merge commit on `main`** and push the tag:
   `git tag -a vX.Y.Z -m "rIDM X.Y.Z" && git push origin vX.Y.Z`. A version with a
   pre-release part (`0.2.0-rc.1`) makes a GitHub pre-release and moves no floating
   image tag.
5. Watch the `release` run. It checks the versions again, builds both architectures
   natively, pushes and signs the image and chart, creates the GitHub release, publishes
   `ridm-auth` to crates.io (only when the `CARGO_REGISTRY_TOKEN` secret is set), and runs
   the load baseline.

The first time an image or chart is pushed, GHCR creates the package as private: make
`ridm` and `charts/ridm` public under the organisation's packages, once.

A pull request that touches the workflow or `scripts/release/` runs every build job
without publishing anything, so the release build is proven before a tag relies on it.

## Reporting security issues

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT License.
