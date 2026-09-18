# Migrating to rIDM

This part of the guide is for moving an existing identity system onto rIDM. rIDM
has no importer written for any particular product. It has two general-purpose
import paths, and the product-specific pages ([From Keycloak](keycloak.md),
[From Auth0](auth0.md)) show how to turn each product's exports into them:

| What moves | How | Where it is described |
|------------|-----|-----------------------|
| Configuration: settings, profile schema, resource servers and permissions, scopes, clients, roles, groups, claim mappers, templates, webhooks, IP rules, identity providers | The tenant configuration document (`ridm.tenant/1`), applied with `ridm tenant import` or `POST /admin/tenants/{slug}/import` | [Configuration as code](../concepts/config-as-code.md), [Tenant configuration document](../reference/tenant-document.md) |
| Users, their role and group memberships, and their password hashes | Bulk user import, `POST /admin/tenants/{slug}/users/import` (JSON or CSV, 10 000 rows per request) | [Users, invitations and bulk import](../admin/users.md#bulk-import) |
| Users kept in step with an HR system or another directory | SCIM 2.0 | [SCIM provisioning](../admin/scim.md) |
| Users who keep signing in through the old system for a while | Identity brokering, with the old system as an upstream OpenID Connect provider | [Identity brokering](../concepts/brokering.md) |

## What carries over and what does not

| Item | Carries over? | Notes |
|------|---------------|-------|
| Client IDs | Yes | A client in the document keeps the `client_id` you give it (1–128 characters of `A-Z a-z 0-9 . _ : -`, starting with a letter or digit) |
| Redirect URIs | Yes, if exact | rIDM compares redirect URIs as exact strings (a `native` client's loopback redirect may use any port). Wildcards are not expanded; list every URI. Plain `http` is refused except for `localhost`, `127.0.0.1` and `[::1]` |
| Client secrets | No | A client created by an import gets a new secret, shown once in the import report. There is no way to set a secret of your choosing, so every confidential client needs its new secret deployed |
| Issuer URL | No | See [Issuer, endpoints and keys](#issuer-endpoints-and-keys) |
| Signing keys | No | The tenant has its own keys; no key material is imported |
| User IDs (`sub`) | No | Imported users get new ids. See [Subject identifiers](#subject-identifiers) |
| Password hashes | Where the format is supported | Verified in the original format at the user's first sign-in, then replaced with argon2id. See [Passwords](#passwords) |
| TOTP secrets, passkeys, recovery codes | No | There is no import path for second factors; users enrol again |
| Sessions, refresh tokens, consents | No | Users sign in again; consent screens are shown again unless the client has `require_consent: false` |
| Linked social or enterprise accounts | Not directly | Links are re-established at the user's next brokered sign-in; see [Brokered users](#brokered-users) |
| Audit history | No | Keep the old system's logs for as long as your retention rules say |

### Issuer, endpoints and keys

A tenant's issuer is `{PUBLIC_URL}/t/{slug}`, for example `https://id.example.com/t/acme`,
or `https://<host>` when the tenant has a [custom domain](../admin/custom-domains.md).
Neither form has a trailing slash and neither can reproduce another product's path
layout (`/realms/acme`, or Auth0's `https://acme.us.auth0.com/` with its trailing slash).
So every relying party must be pointed at the new issuer, and every API that validates
tokens must accept it:

- **Clients** should read the endpoints from discovery,
  `{issuer}/.well-known/openid-configuration`, rather than hard-coding them. SDKs that
  build a product's own URL layout (Keycloak's adapters, Auth0's SDKs) need replacing
  with a generic OpenID Connect library.
- **APIs** must fetch the new JWKS (`jwks_uri` from discovery) and check the new `iss`.
  During a cut-over an API can accept tokens from both issuers by running two
  validators and trying the one whose issuer matches the token's `iss`. With
  [`ridm-auth`](../quickstarts/protect-an-api.md) that is one `Validator` per issuer.
- A custom domain lets you keep a hostname that users recognise (for example moving
  `login.example.com` from the old system to rIDM), which matters for passkeys and for
  users' password managers, even though the issuer string itself still changes.

Tokens are not portable. rIDM cannot validate a refresh token or session cookie issued
by another system, so each user signs in once more after the switch.

### Subject identifiers

An imported user gets a new UUID, and that UUID is the `sub` claim. An application
that stores users by the old `sub` needs a mapping. The usual approach is to carry the
old id into a profile attribute during the import and publish it as a claim:

1. Declare the attribute in the profile schema with `editable_by: none`. Bulk import
   and SCIM may set such an attribute, while neither users nor administrators can
   change it afterwards in the consoles or through the admin API.
2. Put the old id in each import row's `attributes`.
3. Publish it. Listing `id_token`, `userinfo` and `access_token` in the attribute's
   `visible_in` emits it under its own name (`legacy_id`); a claim mapper, as below,
   can emit it under another name.

```json
{
  "profile_schema": {
    "attributes": [
      { "name": "legacy_id", "type": "string", "editable_by": "none" }
    ]
  },
  "claim_mappers": [
    {
      "name": "legacy-sub",
      "config": {
        "type": "user_attribute",
        "attribute": "attributes.legacy_id",
        "claim": "legacy_sub",
        "include_in": ["id", "access", "userinfo"]
      }
    }
  ]
}
```

At the user's first sign-in the application looks the account up by `legacy_sub`,
records the new `sub`, and from then on uses `sub`. Alternatively build the mapping
offline from the user export, which carries both the new id and the attributes:

```bash
curl -s "https://id.example.com/admin/tenants/acme/users/export?format=json" \
  -H "Authorization: Bearer $RIDM_TOKEN" \
  | jq '[.[] | {new_sub: .id, legacy_id: .attributes.legacy_id}]' > sub-map.json
```

### Passwords

A `password_hash` in an import row is stored as given and checked in its own format
the first time the user signs in; after a successful check it is replaced with an
argon2id hash under the server's parameters, and a `user.password_hash_upgraded` event
records the old algorithm. The formats rIDM accepts are listed under
[Legacy password hashes](../admin/users.md#legacy-password-hashes): argon2 (PHC),
bcrypt, PBKDF2-SHA256/SHA512 in passlib's PHC layout or Django's layout, salted and
unsalted SHA-256/SHA-512, and MD5. A row whose hash is in no known format fails with
an error; nothing is guessed.

Most exports need their hashes rewritten into one of those layouts. That is a
mechanical transformation (the product pages give tested scripts), but check it before
importing thousands of users: create one account with a known password in the old
system, export it, convert it, import it into a scratch tenant, and sign in.

Users whose hash cannot be carried over (an unsupported algorithm, or an account that
never had a password) are imported without one. They get in through password
recovery, a [magic link or one-time code](../concepts/mfa.md#first-factors) if the
tenant enables them, a temporary password an administrator sets
([Passwords and credentials](../admin/users.md#passwords-and-credentials)), or a
brokered provider. (Invitations do not help here: they create a new account and are
refused for an address that already has one.)

### Second factors

rIDM has no import for TOTP secrets, passkeys or recovery codes, even where the old
system can export them. Passkeys could not move anyway: they are bound to the relying
party id, which is the host the user saw. Users enrol again. To make that happen at the
first sign-in rather than whenever users notice, set the tenant's
[MFA policy](../admin/mfa-policy.md) to `required` (or `required_for_roles` /
`required_for_admins`): the flow then enrols a second factor before it finishes.

### Brokered users

Users who signed in through a social or enterprise provider in the old system have no
password to move. Import them with their verified email and no password, configure the
same provider in rIDM, and choose a `link_policy` of `verified_email`: at the first
sign-in through the provider, the upstream account is linked to the imported user
because both sides have verified the address. See
[Linking upstream identities to users](../concepts/brokering.md#linking-upstream-identities-to-users).
The provider's client must allow rIDM's callback URL,
`{issuer}/broker/{alias}/callback`.

## Big-bang or gradual

**Big-bang.** Import configuration and users, switch every client and API to the new
issuer in one change window, retire the old system. Simple to reason about; every user
signs in again the same day, and anyone whose hash did not carry over has to recover
their account.

**Gradual, per application.** Import everything, then move applications one at a time.
Each application changes issuer independently; users who use two applications sign in
to each system once. Passwords changed in the old system after the import are not seen
by rIDM, so either freeze password changes in the old system, or import again before
each move. A repeat import does not update existing users (their rows fail as
conflicts), so a changed hash needs the account deleted and imported again, or a
password reset.

**Gradual, through brokering.** Configure the old system as an upstream OpenID Connect
provider of the rIDM tenant (the old system sees rIDM as one more client). Applications
move to rIDM immediately; users who choose "Continue with" the old system are signed in
there and linked to their imported rIDM account. When most users have signed in
directly, remove the provider. This keeps the old system as the source of truth for
passwords during the transition, at the cost of running both. rIDM has no hook that
checks a password against another system at first sign-in (sometimes called lazy or
trickle migration); brokering is the nearest equivalent.

## Checklist

1. Create the tenant: `ridm tenant create acme --name "Acme"` (needs a `master` owner).
2. Write the tenant document from the old system's export (see the product pages),
   including `tenant.settings`. Importing a document replaces the tenant's settings as a
   whole, so anything left out returns to its default.
3. Apply it: `ridm --tenant acme tenant import -f acme.json`. Keep the import report:
   it holds the new client secrets, shown once. Fix any per-item errors and run it
   again; applying the same document twice changes nothing. Roles or groups granting
   admin permissions you do not hold yourself are refused item by item; the plan
   shown before confirmation lists them.
4. Set the secrets the document cannot carry: identity provider client secrets, SMTP,
   SMS and CAPTCHA provider settings.
5. Convert the user export to import rows. Split it into requests of at most 10 000
   rows and 32 MiB, run each with `?dry_run=true`, then for real.
6. Test with a known account: password sign-in, the upgraded hash, second-factor
   enrolment, a brokered sign-in, and the claims your APIs read.
7. Deploy the new client secrets, point clients at the new issuer, and teach APIs the
   new issuer and JWKS.
8. Verify (below), then retire the old system's clients.

Splitting a large import file:

```bash
jq -c 'range(0; length; 10000) as $i | .[$i:$i+10000]' users.json | split -l 1 -d - chunk-
for f in chunk-*; do
  curl -s -X POST "https://id.example.com/admin/tenants/acme/users/import" \
    -H "Authorization: Bearer $RIDM_TOKEN" -H "Content-Type: application/json" \
    --data-binary @"$f" | jq '{total, created, failed, errors}'
done
```

The import needs `ridm:users:write` and `ridm:invitations:write`; a
[personal access token](../admin/access.md#personal-access-tokens) with those
permissions works. Rows are independent: a failed row is reported with its 1-based
position in that request and the rest are still created, so a failed row can be fixed
and sent again on its own. A row that puts a user in a role or group carrying admin
(`ridm:*`) permissions the importing administrator does not hold fails with "cannot
grant permissions you do not hold", in a dry run as well; import administrators with
a token that holds those permissions, or grant them afterwards.

## Verifying the result

Keep the converted tenant document under version control. After the import, and again
after any manual change in the console, compare the tenant with it:

```bash
ridm --tenant acme tenant diff -f acme.json --exit-code
```

`tenant diff` prints the plan an import would carry out, changing nothing. With
`--exit-code` it exits `0` when the tenant matches the document and `3` when it does
not, so it can run in CI; `--prune` also lists configuration that exists in the tenant
but not in the document (for example a client someone created by hand). Other exit
codes are `1` for a failed request, or for a plan with items the import would refuse,
and `2` for a usage error.

For users, compare counts and spot-check: the user export
(`GET /admin/tenants/acme/users/export`) against the source export, and the import
reports' `failed` totals against the rows you expected to fail (for example accounts
without a supported hash).
