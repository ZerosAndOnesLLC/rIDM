# TLS and reverse proxies

An identity provider must be reached over https: browsers will not keep rIDM's
`__Host-` cookies otherwise, and relying parties validate the issuer URL, which carries
the scheme. rIDM can terminate TLS itself or sit behind a proxy that does. Either way,
four settings have to agree with how clients actually reach it: `PUBLIC_URL`, `UI_URL`,
`TRUSTED_PROXIES` and `COOKIE_SECURE`.

## PUBLIC_URL and UI_URL

`PUBLIC_URL` is the externally visible base URL, for example `https://id.example.com`.
It is required, must be `http` or `https`, and rIDM derives everything
client-facing from it:

- every tenant's issuer is `{PUBLIC_URL}/t/{slug}` (`https://id.example.com/t/acme`),
  and so are the endpoint URLs in its discovery document;
- `Strict-Transport-Security` is sent only when it is https;
- its origin is admitted for cross-origin calls from the consoles.

rIDM does not look at `X-Forwarded-Proto` or the request's own scheme. If the proxy
terminates TLS and forwards plain http, `PUBLIC_URL` still says `https://`, and that is
what clients see. A `PUBLIC_URL` that does not match what clients type produces tokens
whose `iss` no relying party accepts, so set it before registering any client and treat
changing it as a migration for every relying party.

`UI_URL` is where the sign-in pages and consoles are served. It defaults to
`PUBLIC_URL`, which is right when rIDM serves its embedded UI (the default, and the
layout the snippets below use) or when the proxy serves `ui/out` on the same host. Set
it only when the UI lives elsewhere; see
[Deployment overview](overview.md#where-the-ui-is-served-from).

Every node must have the same `PUBLIC_URL` and `UI_URL`.

## Option 1: TLS at a proxy or load balancer

The usual layout. The proxy holds the certificate, speaks https to clients and plain
http to rIDM on a private network. Leave `TLS_CERT` and `TLS_KEY` unset.

The proxy must:

- pass the original `Host` header (rIDM matches [custom domains](../admin/custom-domains.md)
  by it, or by `X-Forwarded-Host` from a trusted proxy);
- append the client address to `X-Forwarded-For` (or send `Forwarded: for=...`);
- have its address, as rIDM sees it, in `TRUSTED_PROXIES`;
- allow request bodies of 32 MiB on `/admin/`, which is what bulk user import accepts
  (nginx's default is 1 MiB).

## Option 2: native TLS

Set both `TLS_CERT` (a PEM certificate chain) and `TLS_KEY` (the PEM private key) and
the listener on `BIND_ADDR` speaks https only; there is no plain-http listener beside it
and no redirect from http. Setting one without the other is a configuration error. The
files are read once at startup, so a renewed certificate takes a restart (a rolling
restart across nodes is enough).

Native TLS suits a single node or a layer-4 load balancer that passes TCP through.
With no proxy in front, `TRUSTED_PROXIES` stays empty and the TCP peer is the client.
The image's `--healthcheck` probe follows the listener: with `TLS_CERT` set it speaks
https and trusts exactly that certificate (see
[Container image](container.md#health-checks)).

## TRUSTED_PROXIES and the client address

The client address feeds IP rules, every per-address rate limit, login-attempt records,
session metadata and the audit log. rIDM takes it from the TCP peer unless the peer is
listed in `TRUSTED_PROXIES`, a comma-separated list of CIDRs or single addresses:

```bash
TRUSTED_PROXIES=10.0.0.0/8,192.168.10.5
```

When the peer is trusted, rIDM reads `X-Forwarded-For` (or, if that is absent,
`Forwarded`'s `for=` values) **from the right**, skipping every address that is itself in
`TRUSTED_PROXIES`, and takes the first one that is not. Proxies that append (nginx's
`$proxy_add_x_forwarded_for`, AWS load balancers) leave whatever the caller sent at the
left; reading from the right means a caller cannot choose the address rIDM records.
An entry that does not parse as an address ends the walk.

Getting it wrong has a direction:

| Setting | Effect |
|---------|--------|
| Empty behind a proxy | Every request appears to come from the proxy. Per-address rate limits then count all users together and IP rules match the proxy |
| Too wide (for example `0.0.0.0/0`) | Anyone who can reach rIDM directly can forge their address with a header, defeating IP rules and per-address limits |
| Exactly the proxy tier | Correct |

List every hop between the internet and rIDM that you operate: a CDN in front of a load
balancer in front of nginx means all three ranges. `X-Forwarded-Host` is honoured under
the same rule, and only matters for custom domains.

## Cookies

rIDM sets two cookies, both host-only (no `Domain`), `Path=/`, `HttpOnly` and
`SameSite=Lax`. Each carries the tenant's slug in its name, so tenants on one host never
share them; for tenant `acme`:

| `COOKIE_SECURE` | Session cookie | Trusted-device cookie | Attributes |
|-----------------|----------------|-----------------------|------------|
| `true` (default) | `__Host-ridm_session_acme` | `__Host-ridm_device_acme` | `Secure` |
| `false` | `ridm_session_acme` | `ridm_device_acme` | none extra |

The name, not the path, separates tenants because a `__Host-` cookie must have
`Path=/`, and because a [custom domain](../admin/custom-domains.md) serves the tenant
without the `/t/{slug}` prefix. Deployments that ran an earlier build, whose cookies
were named without the slug and scoped to `/t/{slug}`, sign every user out once on
upgrade, and remembered devices are forgotten once.

Browsers accept a `Secure` cookie, and anything named `__Host-`, only from a secure
origin. So with the default `COOKIE_SECURE=true`, sign-in works only when the browser
reaches rIDM over https. `COOKIE_SECURE=false` is for plain-http local development and
nothing else. The compose `dev` profile sets it; the `prod` profile does not.

`SameSite=Lax` also means the cookie is not sent on cross-site `fetch` calls, which is why
the UI belongs on the same origin as the API (or at least the same site).

## Proxy configurations

The repository ships configurations for three proxies in
[`deploy/proxy/`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/deploy/proxy). They
are what the [production compose stack](production-compose.md) runs, and CI boots that
stack behind each one and checks it from outside: the http redirect, the https issuer,
rIDM's headers arriving unchanged, `/metrics` refused, a forged `X-Forwarded-For`
ignored, a 20 MiB bulk-import body arriving whole, and a custom domain served as its tenant.

All three assume the default layout: the UI embedded in the server, so every path goes
to the rIDM nodes. They pass `Host` through, give rIDM the connecting address in
`X-Forwarded-For`, allow the 32 MiB bulk import, refuse `/metrics` and add no security
headers: rIDM sends its own on every response, pages included (framing is refused
everywhere except the login page, which only its own origin may frame, for the console's
branding preview), and HSTS when `PUBLIC_URL` is https. `/docs` is served only if
`DOCS_ENABLED` is on, which production should not do.

### nginx

[`deploy/proxy/nginx/templates/default.conf.template`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/nginx/templates/default.conf.template)
is a template for the official image, which fills in `RIDM_DOMAIN`,
`RIDM_CUSTOM_DOMAINS` and `RIDM_UPSTREAM` at start. Its core, with the values filled in
for nodes outside Docker:

```nginx
upstream ridm {
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
    keepalive 32;
}

server {
    listen 443 ssl;
    http2 on;
    server_name id.example.com;

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    location / {
        proxy_pass http://ridm;
    }
    # Bulk user import accepts up to 32 MiB; nginx's default is 1 MiB.
    location /admin/ {
        client_max_body_size 32m;
        proxy_pass http://ridm;
    }
    # Scrape /metrics on the private network instead.
    location = /metrics { return 404; }
}
```

The file also redirects http to https, refuses the TLS handshake for hosts it does not
serve, and re-resolves the upstream through Docker's DNS (`resolve`, nginx 1.27.3 or
later), which outside Docker becomes your own resolver or a fixed list of addresses.
nginx obtains no certificates: renew them with your ACME client and reload.

`$proxy_add_x_forwarded_for` appends to whatever the caller sent, which is safe because
rIDM reads the list from the right (see above). Setting it to `$remote_addr` instead is
equally correct at the edge but loses the earlier hops when nginx sits behind another
proxy you operate.

### Caddy

[`deploy/proxy/caddy/Caddyfile`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/caddy/Caddyfile)
obtains and renews certificates itself (or reads files with `RIDM_TLS_MODE=files`).
Caddy passes `Host` through and replaces `X-Forwarded-For` with the connecting address by
default, and has no request-body limit, so the whole configuration is short:

```caddy
id.example.com login.acme.com {
	respond /metrics 404
	reverse_proxy 10.0.1.11:8080 10.0.1.12:8080 {
		health_uri /readyz
		health_interval 10s
	}
	header -Server
}
```

### Traefik

Traefik takes its static configuration (entry points, the http-to-https redirect, the
Let's Encrypt resolver) from one source only; the compose stack gives it as the
`traefik` service's `command:`. The routes are the file provider's
[`deploy/proxy/traefik/dynamic/ridm.yml`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/proxy/traefik/dynamic/ridm.yml),
a Go template reading the same `RIDM_` variables: one router for every host, a
`/metrics` router behind an `ipAllowList` that admits nobody, and a load-balanced
service with `/readyz` health checks. Traefik drops a caller's `X-Forwarded-For` unless
the caller is in the entry point's `forwardedHeaders.trustedIPs` (none are configured)
and sets it to the connecting address; it has no request-body limit.

With Traefik's Docker provider instead of a file, the same router is a set of labels on
the rIDM service:

```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.ridm.rule: Host(`id.example.com`)
  traefik.http.routers.ridm.entrypoints: websecure
  traefik.http.routers.ridm.tls.certresolver: letsencrypt
  traefik.http.services.ridm.loadbalancer.server.port: "8080"
  traefik.http.services.ridm.loadbalancer.healthcheck.path: /readyz
```

### Hosting `ui/out` yourself

A binary built without the embedded UI serves only the API, and the proxy serves the
static export. Route the API paths to rIDM and serve the files, adding the headers a
page's `<meta>` policy cannot set. The console frames `/login/` for its branding preview,
so that one page must allow its own origin. This variant is not among the tested
configurations; in nginx:

```nginx
    location ~ ^/(t|admin|scim|\.well-known)/ { proxy_pass http://ridm; ... }
    location ~ ^/(openapi\.json|healthz|readyz)$ { proxy_pass http://ridm; ... }

    root /srv/ridm/ui/out;
    location / {
        try_files $uri $uri/ =404;
        add_header X-Frame-Options "DENY" always;
        add_header Content-Security-Policy "frame-ancestors 'none'" always;
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    location = /login/ {
        try_files /login/index.html =404;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Content-Security-Policy "frame-ancestors 'self'" always;
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    error_page 404 /404.html;
```

The repository's OpenID conformance setup puts Caddy in front of rIDM in this layout,
API paths to the server and the rest to `ui/out`
([`conformance/Caddyfile`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/conformance/Caddyfile)).

## Custom domains behind the proxy

A tenant with a custom domain (say `login.acme.com`) is served on that host without the
`/t/{slug}` prefix, so the proxy must send that host to rIDM with `Host` preserved and
hold a certificate for it: in the shipped configurations, add it to
`RIDM_CUSTOM_DOMAINS`. rIDM compares the whole `Host` value, port included, with the
domain, so serve custom domains on port 443. With the embedded UI the tenant's sign-in pages and account console are served on that
host as well, through the same route. See [Custom domains](../admin/custom-domains.md).
