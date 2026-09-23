# Mutual TLS

A client can prove who it is with a TLS client certificate instead of a secret or a
signed assertion, and its access tokens can be bound to that certificate so that a
stolen token is useless without the certificate's key. Both come from
[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705):

- **`tls_client_auth`**: the client presents a certificate issued by a certificate
  authority the tenant trusts, carrying a subject registered for the client;
- **`self_signed_tls_client_auth`**: the client presents a certificate it registered
  itself, in its JWK Set;
- **certificate-bound access tokens**: every access token carries the SHA-256
  thumbprint of the client's certificate (`cnf.x5t#S256`), and a resource accepts it
  only over a connection with that certificate.

Machine-to-machine integrations, partner APIs and open-banking deployments use it
where a shared secret is not good enough, and the [FAPI 2.0 profile](ciba-fapi.md)
accepts it in place of `private_key_jwt` and DPoP.

## Getting certificates to rIDM

A client certificate is part of the TLS handshake, so whatever terminates TLS has to
ask for it. There are two ways, and either one turns the feature on (see
[Server configuration](../reference/configuration.md#mutual-tls)).

### rIDM's own mTLS listener

```bash
MTLS_BIND=0.0.0.0:8443
MTLS_CERT=/etc/ridm/tls/mtls-fullchain.pem   # else TLS_CERT
MTLS_KEY=/etc/ridm/tls/mtls-privkey.pem      # else TLS_KEY
MTLS_PUBLIC_URL=https://mtls.id.example.com:8443
```

A second listener serves the same routes and asks every connection for a client
certificate without requiring one. It does not judge the chain (which CA, which
certificate, is decided per client once the request names it), but the handshake does
prove the client holds the certificate's private key. Put it behind a layer-4 load
balancer that passes TCP through, or expose it directly.

### A reverse proxy that forwards the certificate

```bash
CLIENT_CERT_HEADER=X-Client-Cert
TRUSTED_PROXIES=10.0.0.0/8
MTLS_PUBLIC_URL=https://mtls.id.example.com
```

The proxy asks for the certificate (without verifying the chain: rIDM does that per
client), then forwards it in `CLIENT_CERT_HEADER`. rIDM reads the header **only from a
`TRUSTED_PROXIES` peer**, and the proxy must overwrite it on every request, so a
caller can never supply its own. PEM, URL-encoded PEM and base64 DER are all accepted,
leaf first. For example:

```nginx
# nginx: a separate server block for the mTLS host.
server {
    listen 443 ssl;
    server_name mtls.id.example.com;
    ssl_certificate     /etc/nginx/tls/mtls-fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/mtls-privkey.pem;
    ssl_verify_client   optional_no_ca;   # ask, verify possession, leave the CA to rIDM

    location / {
        # Empty without a certificate, and nginx then drops the header: a
        # caller's own X-Client-Cert never reaches rIDM.
        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://ridm;
    }
}
```

```caddyfile
# Caddy
mtls.id.example.com {
	tls {
		client_auth {
			mode request
		}
	}
	reverse_proxy ridm:8080 {
		header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}
	}
}
```

```yaml
# Traefik (dynamic configuration). passTLSClientCert removes any
# X-Forwarded-Tls-Client-Cert the caller sent; set
# CLIENT_CERT_HEADER=X-Forwarded-Tls-Client-Cert.
http:
  routers:
    ridm-mtls:
      rule: "Host(`mtls.id.example.com`)"
      service: ridm
      middlewares: [client-cert]
      tls:
        options: mtls
  middlewares:
    client-cert:
      passTLSClientCert:
        pem: true
tls:
  options:
    mtls:
      clientAuth:
        clientAuthType: RequestClientCert
```

### Kubernetes

The Helm chart's `mtls` values cover both ways. Behind an ingress controller or
gateway that asks for the client certificate without verifying its chain and forwards
it, as the proxies above do, name its header:

```yaml
trustedProxies: 10.0.0.0/8        # the controller's pod network
mtls:
  publicUrl: https://mtls.id.example.com
  clientCertHeader: X-Client-Cert
```

For rIDM's own listener, the chart mounts a `kubernetes.io/tls` Secret, sets
`MTLS_BIND=0.0.0.0:8443` with its certificate, and adds a second Service
(`<release>-mtls`) for it. That Service has to be reached at layer 4 (a
`LoadBalancer`, or an ingress controller's TLS passthrough): an ingress that terminates
TLS would take the client certificate with it.

```yaml
mtls:
  publicUrl: https://mtls.id.example.com
  listener:
    enabled: true
    tlsSecret: ridm-mtls-tls
    service:
      type: LoadBalancer
      annotations:
        service.beta.kubernetes.io/aws-load-balancer-type: nlb
```

The chart refuses `publicUrl` without either, a listener without its Secret, and a
header without `trustedProxies`.

### Endpoint aliases

Asking for a certificate on the host users sign in on makes browsers with a
certificate installed show a picker on the login page. RFC 8705 §5 solves this with a
second host: with `MTLS_PUBLIC_URL` set, discovery lists `mtls_endpoint_aliases` for
the endpoints a client authenticates at (token, PAR, introspection, revocation,
userinfo, device authorization and CIBA), under `{MTLS_PUBLIC_URL}/t/{slug}`. Browsers
keep using the ordinary endpoints; mTLS clients use the aliases. A `private_key_jwt`
assertion sent to the alias token endpoint may name it as its `aud`, and a DPoP proof
may name the alias URL as its `htu`.

## Trusting certificate authorities

`tls_client_auth` clients need at least one of the tenant's certificate authorities:
**Security → Client certificates** in the console, or the admin API:

```bash
curl -X POST "$RIDM/admin/tenants/acme/mtls/trust-anchors" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\": \"Partner CA\", \"certificate_pem\": $(jq -Rs . < partner-ca.pem)}"
```

Each entry is one CA certificate: a root, or an intermediate on its own (a client's
chain only has to reach one of them). rIDM refuses a certificate that is not a CA or
has expired, and lists each with its subject, expiry and SHA-256 thumbprint. A client
certificate passes when it chains to one of them through the intermediates the client
sent, is valid now, and, when it has an extended key usage, allows client
authentication. A tenant trusts at most 50 authorities; they travel in the
[tenant document](../reference/tenant-document.md) as `mtls_trust_anchors`. Adding and
removing one is audited as `mtls_trust_anchor.created` and `.deleted`.

rIDM does not check revocation (CRLs or OCSP). To cut off a certificate, remove its
authority, or change the client's registered subject; keep client certificates
short-lived.

## Registering a client

In the console, pick **Mutual TLS (CA-issued certificate)** or **Mutual TLS
(self-signed certificate)** as the client's authentication; the creation wizard leaves
both to the detail page, where their extra settings are.

**`tls_client_auth`** needs exactly one of these, naming what the certificate must
carry:

| Field | Matched against |
|-------|-----------------|
| `tls_client_auth_subject_dn` | the subject, as an RFC 4514 string with the most specific name first (`CN=billing,O=Acme,C=US`), attribute by attribute; values compare without regard to case or repeated spaces. `openssl x509 -noout -subject -nameopt RFC2253` prints it in this form. |
| `tls_client_auth_san_dns` | a DNS name in the subject alternative names, without regard to case |
| `tls_client_auth_san_uri` | a URI SAN, exactly (a SPIFFE ID, for instance) |
| `tls_client_auth_san_ip` | an IP address SAN |
| `tls_client_auth_san_email` | an email SAN, without regard to case |

**`self_signed_tls_client_auth`** needs the certificate in the client's JWK Set: the
first entry of a key's `x5c`, inline in `jwks` or served at `jwks_uri` (re-fetched once
when an unknown certificate arrives, like a key for `private_key_jwt`). No chain is
checked; the certificate itself is the registration.

At the token endpoint (and PAR, introspection, revocation, device authorization and
CIBA) the client sends `client_id` in the body and nothing else; the certificate is the
credential:

```bash
curl --cert billing.pem --key billing.key \
  https://mtls.id.example.com/t/acme/token \
  -d grant_type=client_credentials -d client_id=billing
```

A missing, untrusted or mismatched certificate is `invalid_client`. Both methods are
also accepted by [dynamic registration](clients.md), with the metadata names above.

## Certificate-bound tokens

Switch on **Certificate-bound access tokens**
(`tls_client_certificate_bound_access_tokens`) and the client's token requests must
come over mutual TLS; every access token then carries

```json
"cnf": { "x5t#S256": "base64url(SHA-256(the certificate's DER))" }
```

This works whatever the client authenticates with, a secret included. The token type
stays `Bearer`: the binding is checked on the connection, not in a header. For a public
client, its refresh tokens are bound to the certificate too; a confidential client's are
bound by its credentials, and each refresh binds the new access token to the
certificate of that request, so certificates can be rolled.

rIDM checks the binding wherever it accepts an access token (userinfo, the account and
admin APIs), and token exchange refuses a certificate-bound subject token unless the
request carries the same certificate and the exchanging client is itself registered for
bound tokens, so the result is bound again.

A resource server built on the [`ridm-auth`](../quickstarts/protect-an-api.md) crate
checks the binding with `Validator::validate_with_certificate`, handing it the
connection's DER certificate; `validate` alone refuses a bound token.

## FAPI 2.0

A [FAPI 2.0](ciba-fapi.md) client may authenticate with `tls_client_auth` or
`self_signed_tls_client_auth` instead of `private_key_jwt`, and be sender-constrained by
its certificate instead of DPoP: a FAPI client registered for certificate-bound tokens
does not need DPoP proofs. It needs at least one of the two.
