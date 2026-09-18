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

`UI_URL` is where the static sign-in pages and consoles are served. It defaults to
`PUBLIC_URL`, which is right when the proxy serves `ui/out` on the same host (the
recommended layout, and the one the snippets below use). Set it only when the UI lives
elsewhere; see [Deployment overview](overview.md#where-the-ui-is-served-from-today).

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

## A starting point for nginx

Official reverse-proxy examples are plan item 11.3 and do not exist yet. The two configs
below are starting points, written for this application but not tested in CI: review
them against your environment. Both assume the recommended layout: one host,
`id.example.com`, serving `ui/out` from disk and passing the API paths to rIDM nodes on
port 8080. Set `TRUSTED_PROXIES` on the nodes to the proxy's address.

```nginx
upstream ridm_api {
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name id.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name id.example.com;

    ssl_certificate     /etc/nginx/tls/id.example.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/id.example.com/privkey.pem;

    # The API. /metrics is deliberately not proxied: scrape it on the private network.
    location ~ ^/(t|admin|scim|\.well-known)/ {
        proxy_pass http://ridm_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        client_max_body_size 32m;
    }
    location ~ ^/(openapi\.json|healthz|readyz)$ {
        proxy_pass http://ridm_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # The UI: a static export where every page is a directory with an index.html.
    root /srv/ridm/ui/out;
    location / {
        try_files $uri $uri/ =404;
        add_header X-Frame-Options "DENY" always;
        add_header Content-Security-Policy "frame-ancestors 'none'" always;
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    error_page 404 /404.html;
}
```

Notes on it:

- `Host` is passed through unchanged. That is what rIDM compares against `PUBLIC_URL`'s
  host and against tenants' custom domains.
- The UI location adds framing and HSTS headers because the pages' own
  `Content-Security-Policy` is a `<meta>` tag, which cannot forbid framing. rIDM adds its
  own security headers (and HSTS when `PUBLIC_URL` is https) to API responses, so the
  API locations do not need them.
- Add `/docs` to the API locations only if you turned `DOCS_ENABLED` on, which
  production should not.

## A starting point for Caddy

The same layout. Caddy obtains and renews the certificate itself, sets
`X-Forwarded-For` and passes `Host` through by default, and has no request-body limit
unless you set one.

```caddy
id.example.com {
	@api path /t/* /admin/* /scim/* /.well-known/* /openapi.json /healthz /readyz
	handle @api {
		reverse_proxy 10.0.1.11:8080 10.0.1.12:8080 {
			health_uri /readyz
		}
	}

	handle {
		root * /srv/ridm/ui/out
		try_files {path} {path}/index.html
		file_server
		header {
			X-Frame-Options "DENY"
			Content-Security-Policy "frame-ancestors 'none'"
			Strict-Transport-Security "max-age=63072000"
			X-Content-Type-Options "nosniff"
		}
	}
}
```

The repository's OpenID conformance setup puts Caddy in front of rIDM in the same way
([`conformance/Caddyfile`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/conformance/Caddyfile)),
with its own certificates and both upstreams on the host.

## Custom domains behind the proxy

A tenant with a custom domain (say `login.acme.com`) is served on that host without the
`/t/{slug}` prefix, so the proxy needs a server block (nginx) or site (Caddy) for the
domain that sends everything to rIDM with `Host` preserved, and a certificate for it.
The sign-in pages stay at `UI_URL` until the embedded UI can answer on every host
(plan item 11.1). See [Custom domains](../admin/custom-domains.md).
