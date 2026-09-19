# Production with docker-compose

[`deploy/production/`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/deploy/production)
runs rIDM on one host for real use: the server behind a TLS-terminating reverse proxy,
Postgres and Valkey on a network with no route out and no published port, and every
secret in a file rather than in the environment. It is a separate file from
[`deploy/docker-compose.yml`](docker-compose.md), which is for evaluation and
development.

Every CI run boots this stack behind each of the three proxies and checks it from the
outside (see [What CI checks](#what-ci-checks)).

## The stack

| Service | Image | Networks | What it does |
|---------|-------|----------|--------------|
| `postgres` | `postgres:18.6-alpine` | `backend` | The database. First initialisation creates the migrator and app roles (`deploy/postgres/init-app-role.sh`) with passwords from secret files |
| `valkey` | `valkey/valkey:9.1.2-alpine3.24` | `backend` | Valkey with a password, append-only persistence and `noeviction` |
| `migrate` | the rIDM image | `backend` | One-shot: `ridm-api migrate` as the schema owner, then exits |
| `ridm` | the rIDM image | `edge`, `backend` | The server, with the embedded UI. Not published on the host |
| `caddy`, `nginx` or `traefik` | see below | `edge` | The proxy, on ports 80 and 443. One of the three, by profile |

`backend` is an `internal` network: nothing on it can reach the internet, and nothing on
the host can reach Postgres or Valkey. `edge` carries the proxy and the server, and the
server's outbound traffic (SMTP, webhooks, upstream identity providers). Its subnet is
fixed (`RIDM_EDGE_SUBNET`, default `172.30.53.0/24`) so the proxy's address
(`RIDM_PROXY_ADDRESS`, default `172.30.53.10`) is known in advance, and that one address
is the server's `TRUSTED_PROXIES`. Trusting the whole subnet would be wrong: with
Docker's userland proxy, a connection from the host arrives at the proxy from the
subnet's gateway, and behind a proxy that appends to `X-Forwarded-For` (nginx) rIDM
would skip that trusted address and record whatever the caller had written further
left. The smoke test below catches exactly that.

Hardening applied to every service: `no-new-privileges`, JSON-file logs capped at five
files of 20 MB, `restart: unless-stopped`. The rIDM containers also run with a read-only
root filesystem, every capability dropped, a 16 MB `/tmp` and a memory limit
(`RIDM_MEMORY_LIMIT`, default `1g`); Caddy and Traefik keep only `NET_BIND_SERVICE`.

## Setting it up

```bash
cd deploy/production
cp .env.example .env     # edit: RIDM_DOMAIN, COMPOSE_PROFILES, RIDM_TLS_MODE, ...
./init.sh                # writes ./secrets once
docker compose up -d
```

`init.sh` writes random passwords for the Postgres superuser, the migrator and app roles
and Valkey; the connection URLs built from them; the master key; a metrics token; an
empty `smtp_password`; and, when `BOOTSTRAP_ADMIN_EMAIL` is set, a one-time password for
the first administrator. It never overwrites a file that has content, so running it
again is safe and rotates nothing. `secrets/` is `0700`; the files in it are `0644`,
because compose bind-mounts them unchanged and the containers read them as their own
non-root users. `secrets/`, `certs/` and `.env` are git-ignored.

**Copy `secrets/master_key` off the host.** It encrypts signing keys, MFA secrets and
provider credentials in the database; a backup restored without it is unreadable. See
[Signing keys and the master key](../concepts/keys.md).

Releases publish the image ([Releases and verification](releases.md)); until the first
one is cut, build it from the checkout, `docker compose build`, or set `RIDM_IMAGE` to
one you built and pushed. Pin a version, or better a digest, rather than `latest`.

### The first administrator

With `BOOTSTRAP_ADMIN_EMAIL` set before `init.sh` runs, the first start creates the
global administrator in `master` (username `admin`) with the password in
`secrets/bootstrap_admin_password`, marked for change at first sign-in. Sign in at
`https://{RIDM_DOMAIN}/console/`. Bootstrap does nothing once an owner exists, so the
setting can stay. To retire it, empty `BOOTSTRAP_ADMIN_EMAIL` and the file together:
the server refuses to start with only one of the two set.

Without it, create one with the server's `bootstrap` command:

```bash
docker compose run --rm -T ridm bootstrap --email admin@example.com --password-stdin
```

### Mail

Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM` and `SMTP_SECURITY` in `.env`
and put the password in `secrets/smtp_password`. This is the fallback for tenants
without SMTP settings of their own; see [Messaging](../admin/messaging.md).

## Choosing a proxy

`COMPOSE_PROFILES` in `.env` picks one: `caddy`, `nginx` or `traefik`. All three are
configured alike: one site for `RIDM_DOMAIN` and every name in `RIDM_CUSTOM_DOMAINS`
(space-separated), everything proxied to rIDM with `Host` passed through, the client's
address in `X-Forwarded-For`, no request-body limit below the 32 MiB bulk import takes,
`/metrics` refused, and no headers of their own: rIDM sends its security headers and
HSTS. What differs is certificates.

| Proxy | Image | Certificates | Configuration |
|-------|-------|--------------|---------------|
| Caddy | `caddy:2.11.4-alpine` | ACME (`RIDM_TLS_MODE=acme`, default) or files | [`deploy/proxy/caddy/Caddyfile`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/caddy/Caddyfile) |
| nginx | `nginx:1.30.5-alpine` | files only | [`deploy/proxy/nginx/templates/default.conf.template`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/nginx/templates/default.conf.template) |
| Traefik | `traefik:v3.7.13` | ACME (default) or files | the `traefik` service's `command:` and [`deploy/proxy/traefik/dynamic/ridm.yml`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/traefik/dynamic/ridm.yml) |

**ACME** (Caddy, Traefik): the proxy obtains and renews Let's Encrypt certificates for
every configured host through the HTTP challenge, so ports 80 and 443 must be reachable
from the internet and each host's DNS must point at this machine first. Certificates
live in the `caddydata` or `traefikacme` volume.

**Files** (`RIDM_TLS_MODE=files`, and always for nginx): put `fullchain.pem` and
`privkey.pem` in `deploy/production/certs/`, one certificate naming every host.
Renewing them is your ACME client's job; afterwards reload the proxy
(`docker compose exec nginx nginx -s reload`, or restart Caddy or Traefik).

Plain http is redirected to https by all three. A host the proxy does not serve is
refused (nginx rejects the TLS handshake and answers `444` on port 80; Caddy has no
certificate for it; Traefik answers `404`).

The same files work outside compose with small changes, described in each file's
header and in [TLS and reverse proxies](tls-and-proxies.md).

## Custom domains

A tenant's [custom domain](../admin/custom-domains.md) is set on the tenant as usual;
this stack also needs the domain in `RIDM_CUSTOM_DOMAINS`, a DNS record pointing at the
host, and (in files mode) the name in the certificate. Then `docker compose up -d`
recreates the proxy with the new site, and an ACME proxy obtains its certificate as it
starts.

## Variables

Read from `.env` next to `compose.yml`
([`.env.example`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/production/.env.example)
has all of them):

| Variable | Default | Used for |
|----------|---------|----------|
| `COMPOSE_PROFILES` | none | The proxy: `caddy`, `nginx` or `traefik` |
| `RIDM_DOMAIN` | required | The public host; `PUBLIC_URL` is `https://{RIDM_DOMAIN}` |
| `RIDM_CUSTOM_DOMAINS` | empty | Tenants' custom domains, space-separated |
| `RIDM_TLS_MODE` | `acme` | `acme` or `files` (nginx always uses files) |
| `BOOTSTRAP_ADMIN_EMAIL` | empty | First administrator, created on first start |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`, `SMTP_SECURITY` | empty, `587`, empty, empty, `starttls` | Server-wide SMTP fallback |
| `RIDM_IMAGE` | `ghcr.io/zerosandonesllc/ridm:latest` | The rIDM image |
| `RIDM_MEMORY_LIMIT` | `1g` | Memory limit of the server container |
| `RIDM_PG_SHARED_BUFFERS` | `512MB` | Postgres `shared_buffers` |
| `RIDM_VALKEY_MAXMEMORY` | `512mb` | Valkey `maxmemory`; with `noeviction`, writes fail when it is reached, so size it with headroom |
| `RIDM_HTTP_PORT`, `RIDM_HTTPS_PORT` | `80`, `443` | Host ports of the proxy |
| `RIDM_EDGE_SUBNET`, `RIDM_PROXY_ADDRESS` | `172.30.53.0/24`, `172.30.53.10` | The proxy network and the proxy's address in it; change both together, and only on a clash |
| `RIDM_SECRETS_DIR`, `RIDM_CERTS_DIR` | `./secrets`, `./certs` | Where the secret files and certificates are |
| `RUST_LOG` | `info` | Log filter |

Other server settings are not passed through. Add them to the `ridm` service's
`environment` in a `compose.override.yml`; the full list is in
[Server configuration](../reference/configuration.md).

## Operating it

- **Metrics.** `/metrics` is refused at the proxy and needs the token in
  `secrets/metrics_token`. Scrape it from a Prometheus attached to the `edge` network:
  `http://ridm:8080/metrics` with that bearer token.
- **Logs.** JSON lines on the server's standard output: `docker compose logs ridm`.
- **Upgrading.** Change `RIDM_IMAGE` and `docker compose up -d`. `migrate` runs first
  and the server starts only if it succeeds. Back up the database before upgrading;
  an upgrade guide is plan item 11.5.
- **Backups.** `docker compose exec -T postgres pg_dump -U ridm -Fc ridm > ridm.dump`,
  kept with a copy of the master key. A backup and restore guide is plan item 11.5.
- **More than one host.** This stack is one node. For several, run the server on each
  host against a shared Postgres and Valkey, or use the [Helm chart](kubernetes.md).

## What CI checks

`deploy/production/smoke/run.sh`, in the `packaging` job, generates a private CA and a
certificate, runs `init.sh`, starts the stack in files mode with the image CI built, and
gives the `master` tenant a custom domain. Then, behind each proxy in turn, it checks
over https that plain http is redirected; discovery names the https issuer and JWKS
answers; `/console/` and `/login/` arrive with rIDM's framing headers and exactly one
HSTS header; `/metrics` is refused; a forged `X-Forwarded-For` is not the address rIDM
records, and neither is the proxy's own (read from rIDM's per-address rate-limit
counters in Valkey); a 20 MiB bulk-import body reaches rIDM whole (an administrator's
token makes rIDM read it all before refusing it as JSON, so a proxy limit or a cut-off
upload fails the check); the custom domain serves the
tenant with its own issuer; and an unknown host gets nothing from rIDM. Once per run it
also checks that Postgres and Valkey publish no port, that no secret's value appears in
`docker inspect`, and that the server is not given the migrator's database URL.

```bash
docker build -f api/Dockerfile -t ridm:smoke .
RIDM_IMAGE=ridm:smoke deploy/production/smoke/run.sh            # all three
RIDM_IMAGE=ridm:smoke deploy/production/smoke/run.sh nginx      # one
```

It binds ports 80 and 443 on the machine running it.
