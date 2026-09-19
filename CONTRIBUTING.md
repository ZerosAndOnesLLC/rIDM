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

Ports are overridable through `RIDM_PG_PORT`, `RIDM_VALKEY_PORT`, `RIDM_HTTP_PORT` and
`RIDM_MAILPIT_UI_PORT` if the defaults collide with something on your machine.

The workspace also builds `ridm`, the administration CLI (`crates/ridm-cli`). Point it at
a local server without writing a profile:

```bash
cargo run -p ridm-cli -- --url http://localhost:8080 --token "$RIDM_TOKEN" whoami
```

Set `RIDM_CONFIG` to a scratch path when a change touches profiles, so a test run never
rewrites your own `~/.config/ridm/config.json`.

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
| Supply chain | `cargo audit && cargo deny check` |
| Fuzz (nightly) | `api/fuzz/run.sh 60` (one target: `api/fuzz/run.sh 60 authorize_params`) |

Integration tests need Postgres and Valkey (or any Redis-protocol server). Point them at running servers with
`RIDM_TEST_DATABASE_URL` and `RIDM_TEST_REDIS_URL` (for example the docker-compose
stack); without those variables the harness starts reusable containers named
`ridm-test-postgres` and `ridm-test-valkey` through testcontainers and reuses them on
later runs (`docker rm -f ridm-test-postgres ridm-test-valkey` removes them). Each test
gets its own tenant and its own connection pools, so tests run in parallel. Mock
providers live in `ridm_core::test_support` (feature `test-support`) and capture what
was sent so tests assert on content instead of sleeping.

Every security finding gets a regression test in `api/tests/security/` before the fix
merges.

## Pull requests

- Open an issue or discussion first for anything larger than a bug fix.
- Keep PRs focused; one logical change per PR.
- `main` is protected: every required status check must pass and no one can bypass.
  Those checks are `static`, `unit`, `integration`, `coverage`, `ui-build`, `ui-e2e`,
  `load-smoke`, `fuzz-smoke`, `packaging`, `examples-smoke` (all in the `ci` workflow) and
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
