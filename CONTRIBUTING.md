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
docker compose -f deploy/docker-compose.yml up -d postgres redis
sqlx migrate run --source api/migrations
cargo run -p ridm-api           # http://localhost:8080/readyz
cd ui && npm install && npm run dev
```

Ports are overridable through `RIDM_PG_PORT`, `RIDM_REDIS_PORT`, `RIDM_HTTP_PORT` and
`RIDM_MAILPIT_UI_PORT` if the defaults collide with something on your machine.

## Conventions

**Rust**
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must all pass.
- No `unsafe`. No `SELECT *`. Every tenant-scoped query filters by `tenant_id` and every
  composite index leads with it.
- `mod.rs` files contain only module declarations and re-exports.
- Errors are typed (`thiserror`); handlers return `AppResult<T>` or `Result<T, OAuthError>`.
- Cache first: read through Redis, invalidate on every write.
- Secrets never appear in logs. Wrap them in `SecretString` / `SecretBytes`.

**Migrations**
- Forward-only, created with `sqlx migrate add --source api/migrations <name>`.
- Tested locally with `sqlx migrate run` before committing.
- Tenant-scoped tables enable row level security using `current_tenant_id()`.

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
| Integration (needs Postgres + Redis) | `cargo test --workspace --tests` |
| UI lint / types / build | `npm run lint && npm run typecheck && npm run build` |
| Supply chain | `cargo audit && cargo deny check` |

Every security finding gets a regression test in `api/tests/security/` before the fix
merges.

## Pull requests

- Open an issue or discussion first for anything larger than a bug fix.
- Keep PRs focused; one logical change per PR.
- `main` is protected: every required status check must pass and no one can bypass.
- Do not bump versions. Releases bump `Cargo.toml` and `package.json` once, at release time.
- Update `README.md` (and docs) when behaviour or configuration changes.
- Commit messages: imperative subject line, body explains *why*.

## Reporting security issues

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT License.
