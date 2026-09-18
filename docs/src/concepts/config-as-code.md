# Configuration as code

Everything an administrator configures in a tenant can be written down as one
JSON document, kept in version control, reviewed like code, and applied to any
rIDM deployment to produce the same tenant. Applying it is idempotent: applying
the same document twice changes nothing the second time.

This is how you keep `staging` and `production` in step, rebuild a tenant from
scratch, review a change to a client's redirect URIs before it happens, and
avoid configuration that exists only because someone once clicked it into a
console.

## The document

A tenant document has the format tag `ridm.tenant/1` and one section per kind
of configuration:

```json
{
  "format": "ridm.tenant/1",
  "tenant": {
    "slug": "acme",
    "display_name": "Acme Corporation",
    "settings": { "mfa": { "mode": "required_for_admins" } }
  },
  "resource_servers": [
    {
      "identifier": "https://orders.example",
      "name": "Orders API",
      "permissions": [{ "name": "orders:read", "description": "See orders" }]
    }
  ],
  "roles": [
    { "name": "orders-reader", "permissions": ["https://orders.example#orders:read"] }
  ],
  "groups": [
    { "path": ["staff", "support"], "roles": ["orders-reader"] }
  ],
  "clients": [
    {
      "client_id": "acme-spa",
      "name": "Acme SPA",
      "client_type": "spa",
      "redirect_uris": ["https://app.acme.example/callback"],
      "allowed_audiences": ["https://orders.example"]
    }
  ]
}
```

| Section | Contains |
|---------|----------|
| `tenant` | display name and the complete [settings document](tenants.md#tenant-settings) |
| `profile_schema` | the user profile attributes |
| `resource_servers` | APIs and their permissions |
| `scopes` | custom scopes, and changes to the standard ones |
| `clients` | OAuth clients, including whether each has a service account |
| `roles` | roles, their composites and their permission grants |
| `groups` | the group tree and each group's roles |
| `claim_mappers` | tenant-wide and per-client claim mappers |
| `message_templates` | email and SMS template overrides |
| `webhooks` | webhook endpoints and the events they receive |
| `ip_rules` | tenant-wide and per-client IP allow and deny rules |
| `identity_providers` | upstream providers for brokering |

The complete schema is in [Tenant configuration document](../reference/tenant-document.md),
and [`examples/demo-tenant.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/demo-tenant.json)
is a working example.

### Natural keys, not ids

Every object is identified by what it is called, never by a database id: a
client by its `client_id`, a resource server by its `identifier`, a role by its
name (`client_id/name` for a client-scoped role), a group by its path from the
root (`["staff", "support"]`), a permission by
`<resource server identifier>#<permission name>`. That is what makes a document
portable: the same file means the same thing in a tenant where every row has a
different id. The `tenant.slug` in the document is informational; an import
always applies to the tenant named in the request.

### Deterministic export

An export orders everything the same way every time, so exporting an unchanged
tenant twice produces identical files and a `git diff` between two exports
shows exactly what changed.

## What is not in it

The document holds configuration, not data and not secrets:

- **No secrets.** Client secrets, webhook signing secrets and identity provider
  client secrets are never exported. A client or webhook created by an import
  gets a fresh secret, returned once in the import report; an identity
  provider's secret is set after the import, in the console or through the
  admin API.
- **No users**, sessions, tokens, consents or audit history. Users move with
  bulk import and export, or SCIM; see [Users, invitations and bulk import](../admin/users.md).
- **No provider credentials**: SMTP, SMS gateway and CAPTCHA settings contain
  secrets and differ between environments, so they are configured per
  deployment.
- **No signing keys.** Each environment has its own; keys are never copied
  between deployments.
- **No built-ins.** The `ridm:*` roles, the `urn:ridm:admin` and
  `urn:ridm:account` resource servers and the two console clients are managed by
  rIDM itself. Exports leave them out, pruning never deletes them, and an
  import that tries to define a console client is refused.

## Import: plan, then apply

An import first computes a **plan**: which objects would be created, which
updated (with a field-by-field before and after), and, with `prune`, which
existing objects not mentioned in the document would be deleted. Without
`prune`, an import only adds and changes; it never removes anything. The plan
also lists, under `errors`, every change the importer would be refused: a role
or group whose composites, permissions or roles would hand out admin (`ridm:*`)
permissions the importing administrator does not hold themselves ("cannot
grant permissions you do not hold"). A role the same document defines counts
with the permissions it will have once imported.

```bash
ridm --tenant acme tenant export -o acme.json    # current configuration
ridm --tenant acme tenant diff   -f acme.json    # the plan, without applying it
ridm --tenant acme tenant import -f acme.json    # show the plan, confirm, apply
```

`ridm tenant diff --exit-code` exits with status `3` when the plan is not
empty, which lets a pipeline fail when a tenant has drifted from the document
in the repository. `ridm tenant diff` prints the plan's refusals and exits with
status `1` when there are any, whatever `--exit-code` says, since applying
that document would fail in part (with `--output json` it prints the plan,
`errors` included, and leaves the judgement to the caller); `ridm tenant import` shows them with the plan
before asking for confirmation. Over the admin API, the same operations are
`GET /admin/tenants/{slug}/export` (permission `ridm:tenants:export`) and
`POST /admin/tenants/{slug}/import?dry_run=true&prune=false`
(`ridm:tenants:import`, held only by `ridm:owner` among the built-in roles,
because an import can rewrite every client and role in a tenant).

Changes are applied in dependency order (resource servers before the roles that
grant their permissions, roles before the groups that hold them) and
deletions in reverse. Each change is applied on its own: one that fails
(including one refused under the no-escalation rule) is reported with its error
and the rest still apply, so a partly failed import can be fixed and run again.
`ridm tenant import` exits with status `1` when any change failed. The tenant itself must already exist; create it
first with `ridm tenant create` or `POST /admin/tenants`.

A typical GitOps setup keeps one document per tenant in a repository, runs
`tenant diff --exit-code` on every pull request to show reviewers the plan, and
runs `tenant import --yes` from the main branch with a personal access token or
a machine client's credentials. See [The ridm command line](../admin/cli.md).
