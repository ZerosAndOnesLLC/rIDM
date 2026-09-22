# Kerberos desktop sign-in

On a Windows domain, or a Linux or macOS desktop signed in to a Kerberos realm, users
already proved who they are when they logged on. A Kerberos provider lets the browser hand
that proof to rIDM's login page (HTTP Negotiate, "SPNEGO"). The user is signed in without
typing anything, or with one click. The realm is an
[identity provider](../concepts/brokering.md) of kind `kerberos`. rIDM validates the
ticket itself, against the keytab of its service principal. It never talks to the KDC,
and it needs no system Kerberos library.

The released image and binaries include Kerberos. A build of your own needs the
`kerberos` cargo feature (`cargo build -p ridm-api --features embedded-ui,kerberos`).
Without it a Kerberos provider can be configured, which keeps tenant documents portable,
but nobody can sign in with it; the provider page says so.

## The service principal

Browsers ask the KDC for a ticket to `HTTP/<host>`, where `<host>` is the name in the
address bar. That is rIDM's public host, or the tenant's
[custom domain](custom-domains.md). That principal needs a key, and rIDM needs the key in a
keytab file.

- **Use the host's own name.** Browsers resolve a CNAME to its target before building the
  principal name. Give rIDM an A/AAAA record, or register the principal for the name the
  CNAME points to (or turn the lookup off with Chrome's `DisableAuthNegotiateCnameLookup`
  policy). An address typed as an IP never gets Kerberos.
- **AES keys only.** rIDM accepts `aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96`
  tickets. RC4 and DES are refused as broken. The newer RFC 8009 types
  (`aes256-cts-hmac-sha384-192`, `aes128-cts-hmac-sha256-128`, MIT's default since 1.21)
  are not supported yet: give the service principal AES-SHA1 keys only, so the KDC issues
  tickets rIDM can read.

**Active Directory.** Create a service account (a user with a strong random password that
never expires), allow AES on it, register the principal and export the keytab:

```powershell
Set-ADUser svc-ridm -KerberosEncryptionType AES128,AES256
setspn -S HTTP/sso.corp.example CORP\svc-ridm
ktpass -princ HTTP/sso.corp.example@CORP.EXAMPLE -mapuser CORP\svc-ridm `
  -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass * -out ridm.keytab
```

`ktpass` sets the account's password (and so its key). Changing the password afterwards
invalidates the keytab, so export a new one each time.

**MIT Kerberos.**

```sh
kadmin -q "addprinc -randkey -e aes256-cts-hmac-sha1-96:normal HTTP/sso.corp.example"
kadmin -q "ktadd -k ridm.keytab -e aes256-cts-hmac-sha1-96:normal HTTP/sso.corp.example"
```

## Adding the provider

In the console, go to **Identity providers → New provider** and choose
**Kerberos / SPNEGO**. Pick the keytab file. rIDM reads it and shows the services it holds
AES keys for, and the service principal comes from it. Optionally, add the networks where
the login page should try Kerberos on its own. The provider page then has every setting,
saved as you go. The keytab has its own **Replace keytab** control; a new key version
(after a password change) is a new keytab.

Through the API, the keytab is base64:

```http
POST /admin/tenants/{slug}/identity-providers
{
  "alias": "windows",
  "kind": "kerberos",
  "display_name": "Windows sign-in",
  "kerberos": {
    "keytab": "BQIAAABhAAIAD0NPUlAuRVhBTVBMRS…",
    "trusted_networks": ["10.0.0.0/8"]
  }
}
```

`POST …/identity-providers/kerberos-keytab` with `{"keytab": "…"}` reads a keytab without
storing it: its entries (principal, key version, encryption type, never a key) and the
services it can be used for. `PATCH …/identity-providers/{alias}` with
`{"kerberos": {…}}` replaces the settings as a whole. Leave `keytab` out to keep the
stored one, or send `""` to remove it. The keytab is encrypted under the master key and
never returned: the provider shows `kerberos.keytab_set` and `kerberos.keytab_entries`.

| Setting | Default | Meaning |
|---------|---------|---------|
| `keytab` | — | The service's keytab file, base64 (write-only) |
| `service_principal` | from the keytab | `HTTP/<host>@<REALM>`. Required when the keytab holds several services. The keytab must have an AES key for it. One provider per service principal in a tenant |
| `realms` | the service's realm | The client realms whose users may sign in (up to 20). Add a trusted realm only if its user names cannot collide with this realm's (see [Accounts](#accounts)) |
| `name_form` | `local_part` | How a principal names a user: `local_part` (`alice`) or `principal` (`alice@CORP.EXAMPLE`) |
| `ldap_idp_id` | none | An [LDAP provider](ldap.md) that owns these users. See [Accounts](#accounts) |
| `ldap_attribute` | by vendor and name form | The directory attribute holding the name. AD: `sAMAccountName` (local part) or `userPrincipalName` (principal); other directories: `uid` or `krbPrincipalName` |
| `match_username` | on | Without a directory: sign in the local account whose username is the name |
| `create_users` | off | Without a directory: create an account, named by the principal, for one no account matches |
| `trusted_networks` | none | CIDRs (or addresses) from which the login page tries Kerberos on its own (up to 100) |
| `max_skew_seconds` | 300 | Allowed difference between a client's clock and rIDM's (30–900) |

`hidden` removes the login page's button; automatic sign-in from the trusted networks goes
on. `enabled: false` turns the provider off entirely.

## Browsers

A browser answers a Negotiate challenge only for servers its policy trusts:

- **Chrome and Edge** on Windows trust the Local intranet zone. Add rIDM's host to the
  zone (Group Policy: *Site to Zone Assignment List*), or to the `AuthServerAllowlist`
  policy. That policy is also the only way on macOS and Linux.
- **Firefox**: `network.negotiate-auth.trusted-uris`, set to `sso.corp.example` or a
  domain such as `.corp.example`.
- **Safari** on macOS uses the system's tickets for any host in a realm it knows.

A browser outside that policy, or without a ticket, simply does not answer. Chromium-based
browsers may then offer NTLM instead, which rIDM does not accept.

## Signing in

The login page posts to its flow's Kerberos step (`POST /t/{slug}/flows/{id}/kerberos`).

- **On its own:** when the login page opens from one of the provider's
  `trusted_networks`, it asks at once. Unless the client asked for a fresh sign-in
  (`prompt=login` or `max_age=0`, typically to switch accounts), rIDM answers `401` with
  `WWW-Authenticate: Negotiate`. A browser with a ticket sends it back and is signed in.
  One without a ticket gives up quietly, and the page shows its usual form. Elsewhere rIDM
  answers `204` and nothing happens.
- **The button:** "Continue with *display name*" always asks. When nothing comes back, the
  page says that the computer offered no Kerberos ticket.

The trusted networks decide when to ask, not who may sign in: a valid ticket signs its
user in from anywhere. Behind a reverse proxy, set `TRUSTED_PROXIES` so rIDM sees the
client's address. Proxies must pass the `Authorization` and `WWW-Authenticate` headers
through. Kerberos completes in one round trip, so no connection affinity is needed.

rIDM accepts a ticket when:

- it is for the provider's service principal and decrypts under the keytab;
- it is valid now, within the allowed clock skew, and not marked invalid;
- its client comes from one of the provider's `realms`;
- the authenticator decrypts under the ticket's session key, names the same client, and
  was made within the skew of rIDM's clock;
- the authenticator has not been seen before. Accepted authenticators are remembered in
  Valkey for twice the skew, so a captured Negotiate header signs nobody in a second
  time.

When the browser asks for mutual authentication (browsers do), the successful answer
carries rIDM's own token in `WWW-Authenticate`, proving that the server holds the service
key. User-to-user tickets, NTLM and NegoEx are refused.

A Kerberos sign-in is a first factor. The tenant's [MFA policy](mfa-policy.md),
[adaptive authentication](adaptive-auth.md), terms and consent follow as for a password.
The session's `amr` is `["kerberos"]`, and a SAML assertion states the `Kerberos`
authentication context class.

## Accounts

A ticket names a principal and nothing else: no email and no attributes. The name
(`alice`, or `alice@CORP.EXAMPLE` with `name_form: principal`) finds the account.

**With a directory** (`ldap_idp_id`), the name is looked up in that LDAP provider by
`ldap_attribute`, as its service account. One entry imports or refreshes the user exactly
as a password sign-in through the directory does, with email, mapped attributes, groups
and the directory's link policy. The directory decides: a name it does not have signs
nobody in, and an account disabled in Active Directory is refused. This is the usual set-up
for Active Directory, where the same directory is both KDC and LDAP server.

**Without a directory:**

1. a principal linked to an account before signs that account in, even after a rename;
2. with `match_username`, the local account whose username is the name is linked and
   signed in;
3. with `create_users`, a new account is created (username from the name, no email, no
   password) and linked;
4. otherwise nobody is signed in.

Linked principals appear among the user's linked identities. With `name_form: local_part`,
`alice@CORP.EXAMPLE` and `alice@PARTNER.EXAMPLE` are the same name: accept a second realm
only when that is what you mean, or use `principal`.

Deleting a directory the provider names leaves the provider matching local accounts.

## Errors

The Kerberos step answers `403` with one of these `error` codes when a token came back but
signed nobody in:

| `error` | Meaning |
|---------|---------|
| `kerberos_ntlm` | The browser offered NTLM: it had no ticket for this host (principal not registered, a CNAME, a machine off the domain) |
| `kerberos_unsupported` | No Kerberos token, or Kerberos was not the browser's first choice |
| `kerberos_invalid` | The ticket was refused. The server log says why: another service or key version, expired, clock skew, a realm not accepted, an encryption type rIDM does not support |
| `kerberos_replay` | The authenticator was used before |
| `kerberos_no_account` | No account matches the principal |
| `account_disabled` | The account is disabled or locked |

## Configuration as code

Kerberos providers are part of the [tenant configuration document](../concepts/config-as-code.md)
without their keytab: a new provider created by an import reports that its secret is
missing, and the keytab is uploaded afterwards. The directory is named by its alias
(`ldap_provider`), so the document means the same in another tenant.

## Metrics and events

| Metric | Labels | Counts |
|--------|--------|--------|
| `ridm_kerberos_negotiations_total` | `outcome`: `success`, `ntlm`, `unsupported`, `invalid`, `replay`, `no_account`, `disabled` | Negotiate tokens received |

Events: `login.succeeded` (method `kerberos`), `login.brokered`, `identity.linked` for a
principal linked on first sign-in, and those of the directory's import when one owns the
users. Refused principals are recorded as failed login attempts.
