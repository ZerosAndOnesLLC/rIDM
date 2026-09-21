# The ridm command line

`ridm` is the command-line administration tool, built from
[`crates/ridm-cli`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/crates/ridm-cli).
Every command except `bootstrap` is a client of the admin API: it resolves a server
URL, a tenant and a bearer token, sends one or two requests, and prints either a
readable summary or the server's JSON. It needs nothing but network access to the
server and a token.

Each release ships a static `ridm` for linux amd64 and arm64
([Releases and verification](../deploy/releases.md)). To build it from the repository:

```bash
cargo build --release -p ridm-cli        # target/release/ridm
cargo run -p ridm-cli -- --help          # while developing
```

`bootstrap` links the server library and talks to the database directly. Build with
`--no-default-features` for a slim, HTTP-only `ridm` without it; bootstrapping is then
left to `ridm-api bootstrap` in the server container.

```bash
cargo build --release -p ridm-cli --no-default-features
```

## A first session

```bash
ridm login --url https://id.example.com             # paste a personal access token
ridm whoami

ridm --tenant acme tenant export -o acme.json        # configuration as code
ridm --tenant acme tenant diff   -f acme.json        # what an import would change
ridm --tenant acme tenant import -f acme.json        # plan, confirm, apply

ridm --tenant acme key rotate
ridm --tenant acme user create alice --email alice@example.com --temporary-password
ridm --tenant acme user reset alice --revoke-sessions
ridm --tenant acme client create --name "Acme SPA" --type spa \
     --redirect-uri https://app.acme.example/callback
ridm master-key status
```

## Global flags

These work with every command, before or after the subcommand.

| Flag | Environment | Default | Meaning |
|------|-------------|---------|---------|
| `--profile NAME` | `RIDM_PROFILE` | the selected profile, else `default` | Stored profile to use |
| `--url URL` | `RIDM_URL` | the profile's | Server origin, such as `https://id.example.com` (a trailing slash is dropped) |
| `--tenant SLUG` | `RIDM_TENANT` | the profile's, else `master` | Tenant the command acts on |
| `--token TOKEN` | `RIDM_TOKEN` | the profile's credential | Bearer token to present; never written to disk |
| `--output text\|json` | — | `text` | `json` prints the API response verbatim, for `jq` |

`ridm --version` prints the version; `ridm help <command>` or `--help` on any command
prints its flags.

The CLI also reads a `.env` file in the working directory at start-up, so `RIDM_URL`
and `RIDM_TOKEN` (and, for `bootstrap`, the server's own variables) may live there.

## Profiles and the config file

`ridm login` writes the server URL, the tenant and the credential to a profile. All
profiles live in one JSON file:

1. `$RIDM_CONFIG`, when set;
2. else `$XDG_CONFIG_HOME/ridm/config.json`;
3. else `~/.config/ridm/config.json`.

The file is written with mode `0600`, because a profile may hold a personal access
token, a refresh token or a client secret. Nothing is written until `ridm login` runs:
`--url` and `--token` (or `RIDM_URL` and `RIDM_TOKEN`) are enough on their own for a
one-off command or a pipeline, and never touch the file.

```json
{
  "current": "prod",
  "profiles": {
    "prod": {
      "url": "https://id.example.com",
      "tenant": "master",
      "credential": { "kind": "token", "token": "rpat_…" }
    }
  }
}
```

The first profile stored becomes the selected one. A profile's `tenant` is the tenant
its credential belongs to and the default target of commands; `--tenant` acts on
another tenant with the same credential, which works only for a global administrator
(see [Administrator access](access.md)).

An OAuth credential (`"kind": "oauth"`) is renewed in place about a minute before the
access token expires: with the refresh token while one lasts, else, for a confidential
client, with the stored secret. The renewed credential is written back so the next
command reuses it.

## Authenticating

An admin token must carry `urn:ridm:admin` in `aud` and belong to a user (or a
machine client's service-account user) holding at least one `ridm:*` permission, so
the CLI always asks for that resource. `ridm login` has three routes:

| Route | Command | Use it for |
|-------|---------|-----------|
| Personal access token (`rpat_…`) | `ridm login --url …` and paste, or `--token-stdin` | Interactive use and CI; nothing to register |
| Client credentials | `ridm login --url … --client-id ID --client-secret-stdin` | Automation acting as a machine client's service account |
| Device authorization grant | `ridm login --url … --client-id ID --device` | An operator approving in a browser; a refresh token keeps the session |

`ridm login` checks the credential against `GET /admin/me` before storing it, and
refuses to store one that does not get through.

- **Personal access token.** Mint one in the account console under Security → personal
  access tokens, choosing the admin permissions it carries (see
  [Personal access tokens](access.md#personal-access-tokens)). In CI, put it in
  `RIDM_TOKEN` and skip `login`.
- **Client credentials.** The client needs the `client_credentials` grant,
  `urn:ridm:admin` in its `allowed_audiences`, and a service account holding admin
  roles. With `--client-id` and neither `--client-secret-stdin` nor `--device`, the
  secret is prompted for.
- **Device grant.** The tenant must offer the device endpoint, and the client must
  allow `urn:ietf:params:oauth:grant-type:device_code` and list `urn:ridm:admin` in its
  audiences. The CLI prints a URL and a code and polls until the code is approved,
  gives up after the code expires or fifteen minutes, whichever is sooner. The
  built-in console clients deliberately do not allow this grant; register a `device`
  client for it.

```bash
# CI: a token from the secret store, no profile file at all
export RIDM_URL=https://id.example.com RIDM_TOKEN="$RIDM_ADMIN_TOKEN"
ridm --tenant acme tenant diff -f acme.json --exit-code

# a stored profile authenticated as a machine client
printf '%s' "$CLIENT_SECRET" | ridm login --url https://id.example.com \
  --name ops --client-id ops-automation --client-secret-stdin
```

## Commands

### login, logout, whoami, profile

| Command | Flags | Does |
|---------|-------|------|
| `ridm login` | `--name NAME` profile to write (default: the selected one, else `default`); `--token-stdin`; `--client-id ID`; `--client-secret-stdin` (needs `--client-id`); `--device` (needs `--client-id`); `--scope SCOPE` (default `openid`, for the device grant) | Obtain a credential, verify it with `GET /admin/me`, store it. `--token-stdin` and `--client-id` are mutually exclusive; a global `--token` is stored as given |
| `ridm logout` | `--all` | Forget the profile's credential; `--all` removes the profile |
| `ridm whoami` | — | `GET /admin/me`: user, tenant, scope (`global` or `tenant`), roles and permissions, and the organization the sign-in acts in when there is one |
| `ridm profile list` | — | Stored profiles, the selected one marked, and the file path |
| `ridm profile use NAME` | — | Select the profile commands use by default |
| `ridm profile show [NAME]` | — | One profile (default: the selected one), credential redacted |

### bootstrap

Creates the first global administrator. See [Bootstrap](#bootstrap) below.

| Flag | Meaning |
|------|---------|
| `--email EMAIL` | Administrator's email (else `BOOTSTRAP_ADMIN_EMAIL`, else prompted) |
| `--username NAME` | Username (else `BOOTSTRAP_ADMIN_USERNAME`, else `admin`) |
| `--password-stdin` | Read the password from stdin (else `BOOTSTRAP_ADMIN_PASSWORD`, else prompted twice) |
| `--no-must-change` | Let the administrator keep this password past the first sign-in |
| `--no-migrate` | Do not apply database migrations first |

### tenant

`[SLUG]` defaults to the tenant from `--tenant` or the profile.

| Command | Flags | API call |
|---------|-------|----------|
| `ridm tenant list` | `--limit N` page size | `GET /admin/tenants` |
| `ridm tenant show [SLUG]` | — | `GET /admin/tenants/{slug}` (always printed as JSON) |
| `ridm tenant create SLUG` | `--name NAME` display name (default: the slug) | `POST /admin/tenants`; needs `ridm:tenants:create`, which only a global owner holds |
| `ridm tenant export [SLUG]` | `-o, --out FILE` (default: stdout) | `GET /admin/tenants/{slug}/export` |
| `ridm tenant import [SLUG]` | `-f, --file FILE` (default `-`, stdin); `--prune`; `-y, --yes` | `POST /admin/tenants/{slug}/import?dry_run=true` for the plan, then without `dry_run` to apply |
| `ridm tenant diff [SLUG]` | `-f, --file FILE` (default `-`); `--prune`; `--exit-code` | `POST /admin/tenants/{slug}/import?dry_run=true` |

`import` shows the plan, with any items the server would refuse (for example a role
granting admin permissions you do not hold yourself), and asks before applying; `--yes`
skips the question and is required when stdin is not a terminal. `--prune` also deletes
configuration the document does not mention. An import that reports per-item errors
exits `1` after printing them; secrets of clients and webhooks it created are printed
once. `diff` prints the plan and fails with exit `1` when the dry run reports items that
would be refused (not with `--output json`, which prints the plan as it arrived);
otherwise `diff --exit-code` exits `3` when the plan is not empty. The document format is described in
[Tenant configuration document](../reference/tenant-document.md), and the workflow in
[Configuration as code](../concepts/config-as-code.md).

### key and master-key

| Command | Flags | API call |
|---------|-------|----------|
| `ridm key list` | `--status pending\|active\|retiring\|revoked` | `GET /admin/tenants/{slug}/keys` |
| `ridm key rotate` | — | `POST /admin/tenants/{slug}/keys/rotate`: a new key with the tenant's default algorithm, active at once |
| `ridm master-key status` | — | `GET /admin/master-key`: current generation and rows still under older ones |
| `ridm master-key rotate` | `-y, --yes` | `POST /admin/master-key/rotate`: re-encrypt every secret at rest under the current generation |

Both master-key commands need a global administrator. See
[Rotating keys](key-rotation.md).

### audit

| Command | Flags | API call |
|---------|-------|----------|
| `ridm audit verify` | `--head HEX` the hash the chain must end on; `--global` the global chain | `GET /admin/tenants/{slug}/audit/verify` (or `/admin/audit/verify`) |
| `ridm audit verify -f FILE` | `--head HEX`; `--after HEX` the hash the first row must follow; `-` reads stdin | none: the file is checked here, trusting nothing else |
| `ridm audit export` | `-o, --out FILE` (default: stdout); `--format json\|csv`; `--from`, `--to` RFC 3339 bounds; `--global` | `GET /admin/tenants/{slug}/audit/export`, streamed to disk |

`verify` prints `Intact: N rows (seq A–B), ending on <hash>` and exits `0`, or names the
first row that doesn't hash or link and exits `1`. Keep the hash: passing it as `--head`
later proves the chain was not cut off or rewritten since. See
[Checking an export yourself](webhooks-audit.md#checking-an-export-yourself).

### user

| Command | Flags | API call |
|---------|-------|----------|
| `ridm user create USERNAME` | `--email`, `--email-verified`, `--phone` (E.164), `--locale TAG`, `--status active\|disabled\|pending`, `--external-id ID`, `--attributes JSON` (an object), `--password-stdin` or `--temporary-password` | `POST /admin/tenants/{slug}/users` |
| `ridm user reset USER` | `--password-stdin`, `--no-must-change`, `--skip-policy`, `--notify`, `--revoke-sessions` | `PUT /admin/tenants/{slug}/users/{id}/password` |

`USER` is a user id, a username or an email address. A name that is not a UUID is
looked up through the user search and must match exactly one account, so a typo never
resets somebody else's password. Without `--password-stdin`, `reset` generates a
temporary password and prints it once; either way the user must change it at the next
sign-in unless `--no-must-change` is given. `create` without a password flag makes an
account with no password (the user can recover one through the reset flow, or sign in
another way the tenant offers).

### client

| Command | Flags | API call |
|---------|-------|----------|
| `ridm client create` | `--name NAME` (required), `--client-id ID`, `--type spa\|web\|native\|machine\|device`, `--redirect-uri URI`, `--post-logout-redirect-uri URI`, `--grant GRANT`, `--scope SCOPE`, `--audience AUDIENCE`, `--cors-origin ORIGIN` (each repeatable), `--auth-method none\|client_secret_basic\|client_secret_post\|private_key_jwt`, `--description TEXT`, `--no-pkce`, `--no-consent` | `POST /admin/tenants/{slug}/clients` |
| `ridm client iat create` | `--description TEXT`, `--expires-in SECS` (default: never), `--max-uses N` (default: no limit) | `POST /admin/tenants/{slug}/dcr/initial-access-tokens`; the token is printed once |
| `ridm client iat list` | — | `GET /admin/tenants/{slug}/dcr/initial-access-tokens`: id, description, uses/limit, expiry, revocation; never the token |
| `ridm client iat revoke ID` | — | `DELETE /admin/tenants/{slug}/dcr/initial-access-tokens/{id}` |

Anything not given takes the server's type-driven defaults; `--grant` and `--scope`
left out mean "the defaults for this type", not "none". A confidential client's secret
is printed once. `private_key_jwt` needs a JWKS, which the CLI cannot set: create the
client in the console or through the API instead.

`client iat` manages the initial access tokens that dynamic client registration demands
when the tenant's `dcr.mode` is `initial_access_token`. See
[Registering clients](clients.md#initial-access-tokens).

## Output

Without `--output json`, results are aligned tables and short sentences on stdout;
prompts, progress and "shown once" notes go to stderr, so `ridm … > file` captures only
the result. With `--output json`, the API's response is printed as it arrived.

Errors from the admin API are printed from their RFC 9457 problem document, with
per-field messages on their own lines:

```text
ridm: POST https://id.example.com/admin/tenants/acme/clients → 400 Bad Request: unknown scope(s): billing
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | The command ran and failed: the API refused it, the network failed, an import reported item errors |
| `2` | The command line or the configuration behind it was wrong: bad flags, no server URL, no credential, a confirmation needed on a pipe without `--yes`. Nothing ran |
| `3` | `ridm tenant diff --exit-code` found changes; the plan has been printed |

## Bootstrap

A new deployment has a `master` tenant and no administrator. `ridm bootstrap` creates
the first global administrator, a user in `master` holding the built-in `ridm:owner`
role. It cannot use the admin API, because no token can exist yet, so it reads the
server's own environment (`DATABASE_URL`, `REDIS_URL`, `MASTER_KEY` and the rest; see
[Server configuration](../reference/configuration.md)) and runs the same code as the
server's own `ridm-api bootstrap` and its start-up bootstrap from
`BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`.

Unlike `ridm-api bootstrap`, which migrates only when `MIGRATE_ON_START=true`,
`ridm bootstrap` applies pending migrations first unless `--no-migrate` is given. That
needs a `DATABASE_URL` whose role owns the schema; against the DML-only app role, run
`ridm-api migrate` as the migrator beforehand and pass `--no-migrate`. It does not
create the `BOOTSTRAP_SAMPLE_CLIENT` sample client; the server does that.

```bash
source .env     # the server's DATABASE_URL, REDIS_URL, MASTER_KEY, PUBLIC_URL, ...
printf '%s' 'a-long-passphrase' | ridm bootstrap --email admin@example.com --password-stdin
```

- It is idempotent: once any live user in `master` holds `ridm:owner`, it changes
  nothing and says so.
- The password must satisfy the `master` tenant's password policy (twelve characters
  by default); a refused password leaves nothing half-created.
- The administrator must change the password at the first sign-in unless
  `--no-must-change` is given.

Then sign in to the admin console through `master`, mint a personal access token in
the account console, and run `ridm login --url <server URL>`.

### A token without a browser

`--issue-token NAME` also mints a personal access token for the administrator named by
`--username` (default `admin`, or `BOOTSTRAP_ADMIN_USERNAME`), carrying every admin
permission that user holds and expiring after `--token-days` (30 by default, and at most
the `master` tenant's `personal_token_max_days`). The token is printed alone on stdout,
everything else goes to stderr, so a script can capture it:

```bash
RIDM_TOKEN=$(ridm bootstrap --no-migrate --issue-token ci-setup --token-days 1)
```

It works on an already-bootstrapped database too — then it creates nothing and needs no
password, only the user to mint for. It is meant for development stacks and automated
setup: anyone who holds `DATABASE_URL` and `MASTER_KEY` already controls every tenant,
so it grants nothing new, but the token is as powerful as the administrator. It is
recorded in the audit log as a token created by the system, and appears in the
administrator's account console where it can be revoked.
