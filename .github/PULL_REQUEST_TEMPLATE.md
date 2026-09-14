## Summary

<!-- What does this change and why? Link the issue: Closes #123 -->

## Changes

-

## Tests

<!-- Which suites cover this? New tests added? -->

- [ ] Unit / integration tests added or updated
- [ ] Security-relevant change has a regression test in `api/tests/security/`
- [ ] Migration tested with `sqlx migrate run`

## Checklist

- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass
- [ ] `npm run lint`, `npm run typecheck`, `npm run build` pass (if UI changed)
- [ ] `README.md` / docs updated for behaviour or configuration changes
- [ ] No version bump (releases bump versions separately)
- [ ] Nothing cloud-provider-specific added to the default build
