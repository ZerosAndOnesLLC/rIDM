# rIDM

A modern, multi-tenant Identity Management server: OpenID Connect provider, JWT issuer,
user/group/role management, MFA, and identity brokering, with a bundled admin UI and
end-user account console.

- **Stack:** Rust (axum, sqlx, Redis) API in `api/`, Next.js static-export UI in `ui/`.
- **Cloud-agnostic:** runs anywhere a container, Postgres, and Redis run.
- **License:** MIT.

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | `ridm-api` — the identity server |
| `crates/ridm-core/` | shared types, provider traits, event definitions |

## Development

Requirements: Rust 1.98+, Node.js 24 LTS, Postgres 16+, Redis 8+ (or Valkey).

```bash
cargo check
```

See `working-plan.md` for the roadmap and current status.
