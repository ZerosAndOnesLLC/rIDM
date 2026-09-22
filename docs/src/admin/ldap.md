# LDAP and Active Directory

An LDAP directory (Active Directory, OpenLDAP, 389 Directory Server, FreeIPA, …) can be
the home of a tenant's users. They sign in on rIDM's login page with their directory
username or email and their directory password; rIDM checks the password by binding to
the directory as them, so it never holds a copy. The directory is an
[identity provider](../concepts/brokering.md) of kind `ldap`, which gives it account
linking and its `link_policy`, mappers, and the linked identities on a user's page. It
gets no button on the login page: directory users use the ordinary password form.

## Adding a directory

In the console, go to **Identity providers → New provider** and choose
**LDAP / Active Directory**. Pick the server type, then give the URL, the base DN users
are found under, and a service account (its bind DN and password). The provider page then
has every setting, saved as you go. Run **Test connection** to connect, bind as the
service account and list a few users and groups.

Through the API:

```http
POST /admin/tenants/{slug}/identity-providers
{
  "alias": "corp",
  "kind": "ldap",
  "display_name": "Corp directory",
  "ldap": {
    "vendor": "active_directory",
    "url": "ldaps://dc1.corp.example",
    "bind_dn": "CN=ridm,OU=Service Accounts,DC=corp,DC=example",
    "bind_password": "…",
    "users_dn": "OU=Staff,DC=corp,DC=example",
    "groups_dn": "OU=Groups,DC=corp,DC=example"
  }
}
```

`PATCH …/identity-providers/{alias}` with `{"ldap": {…}}` replaces the directory
settings as a whole. Leave `bind_password` out to keep the stored one, or send `""` to
clear it. The password is encrypted under the master key and never returned: the provider
shows `ldap.bind_password_set`. `POST …/{alias}/ldap/test` runs the connection test.

| Setting | Default | Meaning |
|---------|---------|---------|
| `vendor` | `other` | `active_directory`, `openldap` or `other`. It picks the defaults below and how passwords are written |
| `url` | — | `ldaps://host[:636]`, or `ldap://host[:389]` with `starttls`. Plain LDAP is refused unless the host is loopback |
| `starttls` | off | Upgrade an `ldap://` connection to TLS before anything is sent |
| `ca_certificate` | none | PEM certificate(s) the directory's certificate must chain to (an internal CA). None trusts the platform's roots |
| `bind_dn`, `bind_password` | none | The service account that searches (and, when writable, writes). Without one, searches are anonymous |
| `users_dn`, `search_scope` | —, `subtree` | Where users are searched (`one` for direct children only) |
| `user_object_filter` | AD: `(&(objectCategory=person)(objectClass=user))`, else `(objectClass=inetOrgPerson)` | Which entries are users |
| `username_attribute` | AD: `sAMAccountName`, else `uid` | A new account's username |
| `login_attributes` | the username attribute and `mail` | What a typed identifier is matched against (up to five) |
| `uuid_attribute` | AD: `objectGUID`, else `entryUUID` | The attribute that never changes for an entry. The link between entry and account |
| `edit_mode` | `read_only` | See [Write-back](#write-back) |
| `sync_interval_minutes` | 60 | Incremental sync every N minutes (5–10080); 0 turns the periodic sync off |
| `full_sync_interval_hours` | 24 | A full sync every N hours (1–720) |
| `groups_dn` | none | Where groups are searched. None turns group sync off |
| `group_object_filter` | AD: `(objectClass=group)`, else `(objectClass=groupOfNames)` | Which entries are groups |
| `group_name_attribute` | `cn` | A synced group's name |
| `group_membership`, `group_member_attribute` | `dn`, `member` | Whether members are DNs (`groupOfNames`, AD) or usernames (`username`, `memberUid` for `posixGroup`) |
| `group_parent_id` | none | The rIDM group synced groups are created under |
| `timeout_secs` | 10 | For connecting and for each operation (1–60) |

The mappers name directory attributes. The username comes from the username attribute
and the email from `mail`, unless `mappers.username` or `mappers.email` names another.
`mappers.attributes` maps profile attributes to directory attributes, e.g.
`{"given_name": "givenName"}`. A directory says nothing about whether an address is
verified, so addresses count as verified only with `trust_email` on. That is also what
linking an existing account by email (`link_policy: verified_email`) needs.

### Reaching the directory

rIDM connects from the server. Tenant administrators choose the URL, so the connection
follows the same outbound rules as webhooks and upstream endpoints: the host must resolve
to a public address. A directory on a private network, which is where directories live,
needs the operator to open that network with `OUTBOUND_ALLOW_NETWORKS` (for example
`10.20.0.0/16`). The connection goes to the address that check vetted, and TLS verifies
the certificate against the host name in the URL.

## Signing in

A directory user keeps **no local password**. When they sign in, rIDM finds their entry
by its uuid attribute and binds as it with the password typed. A password changed, or an
account disabled, in the directory therefore counts at the next sign-in. Wrong passwords
count toward the tenant's lockout like any other.

An identifier no rIDM account has is looked up in the tenant's enabled directories, in
provider `sort_order`. The first directory with exactly one matching entry decides:
- A bind with the typed password imports the user, following the provider's link policy,
  as a brokered first sign-in does.
- A wrong password fails the sign-in, and no other directory is asked.
- An identifier matching several entries is refused.

Local accounts are never checked against a directory.

Every successful bind refreshes the user's email, username, mapped attributes and groups.
The session then continues like any password sign-in: second step, terms, consent, the
risk policy.

A directory that cannot be reached answers **503**, and sign-in is never allowed to fall
back to anything local. A disabled provider signs its users in no more.

## Sync

The `ldap_sync` job wakes every five minutes and syncs each enabled directory whose
interval has passed. **Sync now** and **Full sync** on the provider page, or
`POST …/{alias}/ldap/sync` with `{"full": true}`, run one at once. One sync per directory
runs at a time; a second one answers 409.

- An **incremental** sync reads the entries modified since the last one
  (`modifyTimestamp`, or `whenChanged` on AD). It imports new users, updates changed
  ones, and disables or re-enables users whose AD account was disabled or enabled.
- A **full** sync reads every entry. It also disables the users whose entries are gone
  (deleted, moved out of the base, or no longer matching the filter), and enables them
  again when they come back. A user an administrator disabled stays disabled. A full
  sync that reads no entries at all disables nobody, because a wrong base DN must not
  lock everyone out.

Deleting a directory user in rIDM is undone by the next sync. Remove them from the
directory, or from the filter, instead.

**Groups.** With `groups_dn` set, every directory group becomes an rIDM group that the
directory owns: the sync creates, renames, fills and deletes it. Its members are kept in
step for directory users only, so members added in rIDM who are not directory users stay.
A group an administrator made with the same name is never taken over; the synced one is
called `{name} ({alias})`. Large AD groups, served in member ranges, are read in full.
Roles given to a synced group apply to its members like any group's.

The outcome of the last sync is on the provider: `last_sync_at`, `last_full_sync_at`,
`last_sync_error` and `last_sync_stats` (read, created, updated, disabled, enabled,
skipped, group and membership changes). Each sync also emits `directory.synced`.

## Write-back

`edit_mode` decides whether rIDM writes to the directory.

- **`read_only`** (the default): the directory is the only source. rIDM refuses to change
  a directory user's password (change, reset, temporary password), email or mapped
  attributes. The message names the directory, where those change. Other fields, such as
  locale and roles, stay editable.
- **`writable`**: rIDM writes the directory first, as the service account, then stores
  what it keeps itself.
  - Passwords are written with the Password Modify operation (RFC 3062), or as
    `unicodePwd` on Active Directory, which accepts that only over TLS. The tenant's
    password policy applies first, and the directory's own policy may still refuse
    (shown as a validation error).
  - A temporary password is written to the directory and flagged locally, so the user
    changes it at the next sign-in.
  - Email and mapped attributes are written as they change.

A writable directory needs a bind DN, and the service account needs write access to those
attributes.

The username always comes from the directory, in both modes.

## Removing a directory

Deleting the provider removes its links. The users keep their accounts but have no
password until one is set (an administrator's reset, or the user's own recovery). The
groups it synced stay as ordinary groups.

## Metrics and events

| Metric | Labels | Counts |
|--------|--------|--------|
| `ridm_ldap_syncs_total` | `outcome`: `success`, `failure` | Sync passes |
| `ridm_ldap_sync_seconds` | — | Their duration |

Events: `directory.synced`, `identity.linked` for each user imported, `user.updated`
when the sync changes, disables or enables a user, and the `group.*` events of synced
groups.
