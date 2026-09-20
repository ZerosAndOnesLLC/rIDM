# Organizations

An organization is a grouping **inside one tenant**: a customer, a business
unit, a team. A tenant that sells to businesses usually has one organization per
customer, with that customer's people as its members.

Organizations are optional. A tenant with none behaves exactly as it did before
they existed, and nothing about them appears in its tokens.

## Organizations are not tenants

The two are easy to confuse, and the difference decides most designs:

| | Tenant | Organization |
|---|---|---|
| Isolation | Complete: separate issuer, users, clients, keys, settings | None: one pool of users, clients and roles, shared settings |
| A user belongs to | exactly one | as many as you put them in |
| Sign-in | its own issuer and login pages | the tenant's, with the organization chosen during the flow |
| Use it for | separate products or deployments, or customers who must never share anything | customers or teams inside one product |

If two groups of people must not see the same users, clients or keys, they are
tenants. If they share an application and differ only in who belongs where, they
are organizations. See [Tenants and issuers](tenants.md).

## Membership

A user may belong to several organizations of their tenant. One of them is their
**primary** organization (`org_id` on the user), which is the first one they
join; later memberships do not move it. Membership comes from three places:

- an administrator adds the user (console or admin API);
- an [invitation](../admin/users.md) that names an organization: accepting it
  makes the new user a member, and that organization their primary one;
- a **verified domain** with auto-join (below).

Deleting an organization leaves its members' accounts alone: they lose the
membership, the roles granted inside it, and, if it was their primary one, they
are simply left without one.

## Choosing one while signing in

A session acts in **one** organization, and the tokens issued through it carry
it as the `org_id` claim. The choice happens during the sign-in flow, after
identity is settled (password, second factor, profile, terms) and before
consent:

- the user belongs to **no** organization: nothing is asked, and no claim is
  minted;
- **one**: it is chosen silently;
- **several**: the login page asks, unless the authorization request named one
  (below);
- a session that already acts in an organization is never asked again; a flow
  resuming it inherits what it chose.

A client can name the organization it wants with an `organization` request
parameter on `/authorize`, holding the organization's slug or its id:

```
GET /t/acme/authorize?...&organization=northwind
```

A member is put there without being asked. If the user does **not** belong to
what the request named, they are asked instead of being put somewhere else
silently.

To act in another organization, the user signs in again — a session's
organization never changes under a token that already names it. The account
console lists what they belong to.

## Roles inside an organization

A role can be granted **within** an organization, to a user or to a group
(`role_assignments.org_id`). Such a grant applies only to sessions acting in
that organization: the same user signing in to another one does not hold it, and
it disappears from `roles` in their tokens there. Grants with no organization
are unscoped and apply everywhere, as they always did.

This is what makes "administrator of Northwind, ordinary member of Contoso"
expressible without one role per customer.

A user must be a member of the organization before a role can be granted to them
inside it, and granting a role there runs the same no-escalation check as
anywhere else: the administrator doing it must already hold every permission the
role carries.

## Email domains and auto-join

An organization can claim email domains. A domain is **verified** by publishing
a TXT record, and a verified domain marked **auto-join** makes every user with a
verified address at that domain a member as they sign in:

```
_ridm-challenge.northwind.example.  IN TXT "ridm-domain-verification=0192f…"
```

Two rules keep this honest: the address must be verified (an unproven email
joins nobody), and the domain must be verified (an unproven domain joins
nobody). A domain belongs to one organization per tenant, so auto-join always
has one answer. Because the check runs at every sign-in, turning auto-join on
for a domain picks up the users a tenant already has, not only new ones.

Auto-join never removes anyone: a member whose address changes keeps the
membership until an administrator removes it.

## What organizations are not, yet

- **Org-scoped administrators** (an org admin who manages their own members and
  nothing else) are the next phase; today, managing organizations needs the
  tenant-level `ridm:orgs:write` permission.
- Organizations carry no settings, branding or policy of their own. Anything of
  that kind is the tenant's.

## Where to look next

- [Organizations (admin guide)](../admin/organizations.md): the console and the
  admin API.
- [Tokens](tokens.md) and the [claims reference](../reference/token-claims.md)
  for `org_id`.
- [Sign-in flows and sessions](flows-and-sessions.md) for the stage the picker
  sits in.
