# Fuzz targets

`cargo-fuzz` (libFuzzer) targets for the parsers that read input rIDM does not
control. Each one runs for 60 seconds per pull request (the required
`fuzz-smoke` check) and for four hours a target in the weekly `fuzz-long`
workflow.

| Target | What it reads | What it asserts beyond "does not panic" |
|--------|---------------|------------------------------------------|
| `authorize_params` | the `/authorize` query string or form body | every parameter is readable or reported as repeated; what the error page echoes carries no `<` or `>` |
| `jwt_decode` | a compact JWT, as a DPoP proof, request object or client assertion arrives | no input verifies against a key it was not signed with; an embedded JWK is turned into a thumbprint and a decoding key |
| `redirect_uri` | a registered list (lines) and a requested URI (after the blank line) | a match outside an exact registration only ever happens for a native client's loopback redirect |
| `pkce` | a `code_verifier` | the grammar check agrees with itself, the transform yields a well-formed challenge, and a verifier verifies against its own challenge and no other |
| `scim_filter` | a SCIM filter string | a parsed filter evaluates over a document (and over an empty one) |

## Running them

Needs a nightly toolchain and cargo-fuzz — the sanitizer and coverage flags
libFuzzer wants are nightly-only. The crate is its own workspace (it lives
inside the `ridm-api` package directory) and is built with its own flags, so
`cargo check --workspace` does not touch it.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

api/fuzz/run.sh                 # every target, 60 s each, seeds copied in
api/fuzz/run.sh 300 pkce        # one target, five minutes
```

`run.sh` runs from `api/` (where `cargo fuzz` expects to find `fuzz/`), copies
`seeds/<target>/` into the working corpus and passes the time budget to
libFuzzer. Committed seeds are inputs worth starting from — a real
authorization request, an RFC 7636 verifier, a DPoP proof header; everything
libFuzzer discovers is written to `corpus/`, which is not committed (the weekly
run uploads it as an artifact).

A crash leaves its input in `artifacts/<target>/`. Reproduce and shrink it:

```bash
cd api
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

Every crash gets a regression test next to the code it found — a unit test in
the module, or `api/tests/security/` when it is a security finding — before the
fix merges.
