"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, Briefcase, Plus, UserRoundPlus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextInput } from "@/components/console/form";
import { Picker, type PickerItem } from "@/components/console/picker";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { href } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import {
  challengeRecord,
  type OrganizationDetail,
  type OrganizationDomain,
} from "@/lib/console/organizations";
import { roleName, userHref } from "@/lib/console/users";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";

const P_WRITE = "ridm:orgs:write";

export function OrganizationsPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can, confinedToOrg, org } = useConsole();
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 200);
  // An administrator whose `ridm:orgs:read` comes from a grant inside one
  // organization cannot list the tenant's others; the page opens theirs.
  const confined = confinedToOrg("ridm:orgs:read") && !!org;
  const list = useQuery({
    queryKey: ["organizations", tenant, q],
    enabled: !confined,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations", {
        params: { path: { slug: tenant }, query: q ? { search: q } : {} },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const items = list.data?.items ?? [];

  if (confined) {
    return (
      <>
        <PageHeader
          title={org.display_name}
          sub="The organization you administer. Its members, domains, roles and invitations are yours to manage."
        />
        <OrganizationDetailView key={org.id} tenant={tenant} id={org.id} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Organizations"
        sub="Customers, business units or teams inside this tenant. Members choose one when they sign in."
        actions={
          can(P_WRITE) ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New organization
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Organizations">
            <TextInput
              aria-label="Search organizations"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {list.isPending ? (
              <Spinner label="Loading…" />
            ) : list.isError ? (
              <ErrorLine error={list.error} />
            ) : items.length === 0 ? (
              <p className="mt-3 text-[0.875rem] text-muted">
                {q ? "Nothing matches." : "No organizations yet."}
              </p>
            ) : (
              <ul className="mt-3 flex flex-col">
                {items.map((o) => (
                  <li key={o.id}>
                    <Link
                      href={href("organizations", tenant, { org: o.id })}
                      aria-current={o.id === selected ? "page" : undefined}
                      className={`flex items-center gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${o.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <Briefcase className="size-3.5 shrink-0 text-muted" aria-hidden />
                      <span className="truncate">{o.display_name}</span>
                      {o.status === "disabled" && <Badge>disabled</Badge>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={
          selected ? (
            <OrganizationDetailView key={selected} tenant={tenant} id={selected} />
          ) : (
            <p className="text-[0.9rem] text-muted">Choose an organization.</p>
          )
        }
      />
      <CreateOrganization tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateOrganization({
  tenant,
  open,
  onOpenChange,
}: {
  tenant: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  // The slug follows the name until it is edited by hand.
  const [slugEdited, setSlugEdited] = useState(false);
  const suggested = slugEdited
    ? slug
    : name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 63);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/organizations", {
        params: { path: { slug: tenant } },
        body: { slug: suggested, display_name: name.trim(), description: null, attributes: null },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (o) => {
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
      setName("");
      setSlug("");
      setSlugEdited(false);
      onOpenChange(false);
      router.push(href("organizations", tenant, { org: o.id }));
    },
  });
  return (
    <CreateDialog
      open={open}
      onOpenChange={onOpenChange}
      title="New organization"
      submitLabel="Create organization"
      pending={create.isPending}
      error={create.error?.message ?? null}
      onSubmit={() => name.trim() && suggested && create.mutate()}
    >
      <Field label="Name">
        {(id) => (
          <TextInput
            id={id}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            required
          />
        )}
      </Field>
      <Field label="Slug" hint="Lowercase letters, digits and hyphens. Cannot be changed lightly: it may appear in requests.">
        {(id, by) => (
          <TextInput
            id={id}
            aria-describedby={by}
            value={suggested}
            onChange={(e) => {
              setSlugEdited(true);
              setSlug(e.target.value);
            }}
            required
          />
        )}
      </Field>
    </CreateDialog>
  );
}

function OrganizationDetailView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can, canInOrg, confinedToOrg, org } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  // Inside their own organization an org administrator writes as a tenant
  // administrator does — except for the three things the tenant keeps.
  const ownOrg = org?.id === id;
  const editable = can(P_WRITE) || (ownOrg && canInOrg(P_WRITE));
  const confined = ownOrg && confinedToOrg(P_WRITE);
  const query = useQuery({
    queryKey: ["organization", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<OrganizationDetail | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const save = useCallback(
    async (
      patch: { slug?: string; display_name?: string; description?: string | null; status?: string },
      { keepalive }: SaveOptions,
    ) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
        body: patch as never,
        keepalive,
      });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["organization", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["organization", tenant, id], (old: OrganizationDetail | undefined) =>
        old ? { ...old, ...data } : old,
      );
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save);
  const update = (patch: Partial<OrganizationDetail>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
      router.push(href("organizations", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading organization…" />;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{draft.display_name}</h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section
        id="organization"
        title="Organization"
        description={`${draft.member_count} member${draft.member_count === 1 ? "" : "s"}.`}
      >
        <Field label="Name">
          {(fid) => (
            <TextInput
              id={fid}
              value={draft.display_name}
              disabled={!editable}
              onChange={(e) => update({ display_name: e.target.value })}
            />
          )}
        </Field>
        <Field label="Slug" hint={confined ? "The tenant's administrators change this." : undefined}>
          {(fid, by) => (
            <TextInput
              id={fid}
              aria-describedby={by}
              value={draft.slug}
              disabled={!editable || confined}
              onChange={(e) => update({ slug: e.target.value })}
            />
          )}
        </Field>
        <Field label="Status" hint="A disabled organization takes no new members and cannot be signed in to.">
          {(fid, by) => (
            <SelectInput
              id={fid}
              aria-describedby={by}
              value={draft.status}
              disabled={!editable || confined}
              onChange={(e) => update({ status: e.target.value as OrganizationDetail["status"] })}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Description" wide>
          {(fid) => (
            <TextInput
              id={fid}
              value={draft.description ?? ""}
              disabled={!editable}
              onChange={(e) => update({ description: e.target.value || null })}
            />
          )}
        </Field>
      </Section>
      <OrganizationMembers tenant={tenant} id={id} editable={editable} confined={confined} />
      <OrganizationInvitations tenant={tenant} id={id} />
      <OrganizationDomains
        tenant={tenant}
        id={id}
        domains={draft.domains}
        editable={editable}
        onChanged={() => setResetCount((n) => n + 1)}
      />
      <OrganizationRoles tenant={tenant} id={id} editable={editable} />
      {editable && !confined && (
        <DeleteButton
          what="organization"
          pending={del.isPending}
          error={del.error?.message ?? null}
          onConfirm={() => del.mutate()}
          description="Members keep their accounts but lose this membership, its domains and every role granted inside it."
        />
      )}
    </div>
  );
}

function OrganizationMembers({
  tenant,
  id,
  editable,
  confined,
}: {
  tenant: string;
  id: string;
  editable: boolean;
  /** An organization's own administrator adds members by invitation only. */
  confined: boolean;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 200);
  const members = useQuery({
    queryKey: ["organization", tenant, id, "members"],
    queryFn: async () => {
      const { data, error } = await client.GET(
        "/admin/tenants/{slug}/organizations/{org}/members",
        { params: { path: { slug: tenant, org: id } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const candidates = useQuery({
    queryKey: ["users", tenant, "pick", q],
    enabled: adding && !confined && q.length >= 1,
    queryFn: async () => {
      const { data } = await client.GET("/admin/tenants/{slug}/users", {
        params: { path: { slug: tenant }, query: { search: q, limit: 10 } },
      });
      return data?.items ?? [];
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await client.PUT("/admin/tenants/{slug}/organizations/{org}/members/{user_id}", {
            params: { path: { slug: tenant, org: id, user_id: what.add } },
          })
        : await client.DELETE("/admin/tenants/{slug}/organizations/{org}/members/{user_id}", {
            params: { path: { slug: tenant, org: id, user_id: what.remove! } },
          });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["organization", tenant, id] });
    },
  });
  const have = new Set(members.data?.map((u) => u.id) ?? []);
  const items: PickerItem[] = (candidates.data ?? [])
    .filter((u) => !have.has(u.id))
    .map((u) => ({
      id: u.id,
      group: "Users",
      label: u.username,
      hint: u.email && u.email !== u.username ? u.email : undefined,
      onSelect: () => change.mutate({ add: u.id }),
    }));
  return (
    <Card
      title="Members"
      actions={
        editable && !confined ? (
          <Button className="min-h-8 px-2.5 text-[0.8125rem]" onClick={() => setAdding(true)}>
            <UserRoundPlus className="size-3.5" aria-hidden />
            Add member
          </Button>
        ) : undefined
      }
    >
      {members.isPending ? (
        <Spinner label="Loading members…" />
      ) : members.isError ? (
        <ErrorLine error={members.error} />
      ) : members.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">
          No members. An invitation or a verified auto-join domain adds them.
        </p>
      ) : (
        <ul className="divide-y divide-line">
          {members.data.map((u) => (
            <li key={u.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <Link href={userHref(tenant, u.id)} className="text-ink hover:underline underline-offset-4">
                {u.username}
                {u.org_id === id && <Badge>primary</Badge>}
              </Link>
              {editable && (
                <Button
                  variant="danger"
                  className="min-h-8 px-2.5 text-[0.8125rem]"
                  disabled={change.isPending}
                  onClick={() => change.mutate({ remove: u.id })}
                >
                  Remove
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <ErrorLine error={change.error} />
      <Picker
        open={adding}
        onOpenChange={setAdding}
        title="Add a member"
        query={search}
        onQueryChange={setSearch}
        items={items}
        placeholder="Search users…"
        empty={q.length < 1 ? "Type to search." : "No matching users."}
      />
    </Card>
  );
}

/**
 * Invitations that carry this organization: accepting one creates the account
 * and the membership at once. It is the only way an organization's own
 * administrator adds people who do not arrive through an auto-join domain.
 */
function OrganizationInvitations({ tenant, id }: { tenant: string; id: string }) {
  const { client, can, canInOrg, org } = useConsole();
  const qc = useQueryClient();
  // Org-scoped permissions count only for the organization the sign-in acts
  // in; any other one is judged tenant-wide.
  const ownOrg = org?.id === id;
  const may = (permission: string) => (ownOrg ? canInOrg(permission) : can(permission));
  const mayRead = may("ridm:invitations:read");
  const mayWrite = may("ridm:invitations:write");
  const [email, setEmail] = useState("");
  const list = useQuery({
    queryKey: ["organization", tenant, id, "invitations"],
    enabled: mayRead,
    queryFn: async () => {
      const { data, error } = await client.GET(
        "/admin/tenants/{slug}/organizations/{org}/invitations",
        { params: { path: { slug: tenant, org: id }, query: { open_only: true } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { invite?: string; revoke?: string }) => {
      const r = what.invite
        ? await client.POST("/admin/tenants/{slug}/organizations/{org}/invitations", {
            params: { path: { slug: tenant, org: id } },
            body: { email: what.invite, roles: [], groups: [], org_id: id, expires_days: null },
          })
        : await client.DELETE(
            "/admin/tenants/{slug}/organizations/{org}/invitations/{invitation}",
            { params: { path: { slug: tenant, org: id, invitation: what.revoke! } } },
          );
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: async () => {
      setEmail("");
      await qc.invalidateQueries({ queryKey: ["organization", tenant, id, "invitations"] });
    },
  });
  if (!mayRead) return null;
  const items = list.data?.items ?? [];
  return (
    <Card title="Invitations" actions={<span className="text-[0.8125rem] text-muted">Open invitations</span>}>
      {list.isPending ? (
        <Spinner label="Loading invitations…" />
      ) : list.isError ? (
        <ErrorLine error={list.error} />
      ) : items.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No open invitations.</p>
      ) : (
        <ul className="divide-y divide-line">
          {items.map((i) => (
            <li key={i.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span className="min-w-0 truncate text-ink">
                {i.email}
                <span className="ml-2 text-muted">
                  expires {new Date(i.expires_at).toLocaleDateString()}
                </span>
              </span>
              {mayWrite && (
                <Button
                  variant="danger"
                  className="min-h-8 px-2.5 text-[0.8125rem]"
                  disabled={change.isPending}
                  onClick={() => change.mutate({ revoke: i.id })}
                >
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {mayWrite && (
        <form
          className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (email.trim()) change.mutate({ invite: email.trim() });
          }}
        >
          <TextInput
            type="email"
            aria-label="Email address to invite"
            placeholder="person@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="min-w-56 flex-1"
          />
          <Button type="submit" variant="primary" disabled={!email.trim() || change.isPending}>
            <UserRoundPlus className="size-4" aria-hidden />
            Invite
          </Button>
        </form>
      )}
      <ErrorLine error={change.error} />
    </Card>
  );
}

function OrganizationDomains({
  tenant,
  id,
  domains,
  editable,
  onChanged,
}: {
  tenant: string;
  id: string;
  domains: OrganizationDomain[];
  editable: boolean;
  onChanged: () => void;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const done = async () => {
    setDomain("");
    await qc.invalidateQueries({ queryKey: ["organization", tenant, id] });
    onChanged();
  };
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/organizations/{org}/domains", {
        params: { path: { slug: tenant, org: id } },
        body: { domain: domain.trim(), auto_join: true },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const verify = useMutation({
    mutationFn: async (domainId: string) => {
      const { error } = await client.POST(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}/verify",
        { params: { path: { slug: tenant, org: id, domain_id: domainId } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const toggle = useMutation({
    mutationFn: async (v: { domainId: string; auto_join: boolean }) => {
      const { error } = await client.PATCH(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}",
        {
          params: { path: { slug: tenant, org: id, domain_id: v.domainId } },
          body: { auto_join: v.auto_join },
        },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (domainId: string) => {
      const { error } = await client.DELETE(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}",
        { params: { path: { slug: tenant, org: id, domain_id: domainId } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  return (
    <Card title="Email domains">
      {domains.length === 0 && (
        <p className="text-[0.875rem] text-muted">
          No domains. A verified domain with auto-join makes everyone with a verified address there
          a member.
        </p>
      )}
      <ul className="divide-y divide-line">
        {domains.map((d) => (
          <li key={d.id} className="flex flex-col gap-2 py-3 text-[0.875rem]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-medium text-ink">
                {d.domain}
                {d.verified_at ? (
                  <Badge>
                    <BadgeCheck className="size-3.5" aria-hidden /> verified
                  </Badge>
                ) : (
                  <Badge>unverified</Badge>
                )}
                {d.auto_join && <Badge>auto-join</Badge>}
              </span>
              {editable && (
                <span className="flex gap-2">
                  {!d.verified_at && (
                    <Button
                      className="min-h-8 px-2.5 text-[0.8125rem]"
                      disabled={verify.isPending}
                      onClick={() => verify.mutate(d.id)}
                    >
                      Check record
                    </Button>
                  )}
                  <Button
                    className="min-h-8 px-2.5 text-[0.8125rem]"
                    disabled={toggle.isPending}
                    onClick={() => toggle.mutate({ domainId: d.id, auto_join: !d.auto_join })}
                  >
                    {d.auto_join ? "Turn auto-join off" : "Turn auto-join on"}
                  </Button>
                  <Button
                    variant="danger"
                    className="min-h-8 px-2.5 text-[0.8125rem]"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(d.id)}
                  >
                    Remove
                  </Button>
                </span>
              )}
            </div>
            {!d.verified_at && (
              <p className="text-[0.8125rem] text-muted">
                Publish a TXT record at <code className="text-ink">{challengeRecord(d)}</code> with
                the value <code className="text-ink">{d.verification}</code>, then check it.
              </p>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <form
          className="mt-3 flex gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (domain.trim()) add.mutate();
          }}
        >
          <TextInput
            aria-label="Domain to add"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <Button type="submit" variant="primary" disabled={!domain.trim() || add.isPending}>
            Add
          </Button>
        </form>
      )}
      <ErrorLine error={add.error ?? verify.error ?? toggle.error ?? remove.error} />
    </Card>
  );
}

function OrganizationRoles({
  tenant,
  id,
  editable,
}: {
  tenant: string;
  id: string;
  editable: boolean;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  // The tenant's roles as this caller may grant them here: an organization's
  // own administrator reads them without `ridm:roles:read` tenant-wide, and
  // roles carrying more than they hold come back as not grantable.
  const roles = useQuery({
    queryKey: ["organization", tenant, id, "grantable-roles"],
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET(
        "/admin/tenants/{slug}/organizations/{org}/grantable-roles",
        { params: { path: { slug: tenant, org: id } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [user, setUser] = useState("");
  const [role, setRole] = useState("");
  const grants = useQuery({
    queryKey: ["organization", tenant, id, "roles"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations/{org}/roles", {
        params: { path: { slug: tenant, org: id } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const members = useQuery({
    queryKey: ["organization", tenant, id, "members"],
    queryFn: async () => {
      const { data, error } = await client.GET(
        "/admin/tenants/{slug}/organizations/{org}/members",
        { params: { path: { slug: tenant, org: id } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { userId: string; roleId: string; remove?: boolean }) => {
      const params = {
        path: { slug: tenant, org: id, user_id: what.userId, role_id: what.roleId },
      };
      const r = what.remove
        ? await client.DELETE(
            "/admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}",
            { params },
          )
        : await client.PUT(
            "/admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}",
            { params },
          );
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: async () => {
      setRole("");
      await qc.invalidateQueries({ queryKey: ["organization", tenant, id, "roles"] });
    },
  });
  const nameOf = (roleId: string) => {
    const r = (roles.data ?? []).find((x) => x.id === roleId);
    return r ? roleName(r) : roleId;
  };
  const userName = (userId: string | null | undefined) =>
    (members.data ?? []).find((u) => u.id === userId)?.username ?? userId ?? "—";

  return (
    <Card
      title="Roles inside this organization"
      actions={<span className="text-[0.8125rem] text-muted">Only while acting here</span>}
    >
      {grants.isPending ? (
        <Spinner label="Loading grants…" />
      ) : grants.isError ? (
        <ErrorLine error={grants.error} />
      ) : grants.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No roles granted inside this organization.</p>
      ) : (
        <ul className="divide-y divide-line">
          {grants.data.map((g) => (
            <li key={g.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span className="text-ink">
                {nameOf(g.role_id)} —{" "}
                {g.group_id ? (
                  <span className="text-muted">group grant</span>
                ) : (
                  userName(g.user_id)
                )}
              </span>
              {editable && g.user_id && (
                <Button
                  variant="danger"
                  className="min-h-8 px-2.5 text-[0.8125rem]"
                  disabled={change.isPending}
                  onClick={() =>
                    change.mutate({ userId: g.user_id!, roleId: g.role_id, remove: true })
                  }
                >
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {editable && (
        <form
          className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (user && role) change.mutate({ userId: user, roleId: role });
          }}
        >
          <SelectInput
            aria-label="Member to grant a role to"
            value={user}
            onChange={(e) => setUser(e.target.value)}
          >
            <option value="">Choose a member…</option>
            {(members.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.username}
              </option>
            ))}
          </SelectInput>
          <SelectInput aria-label="Role to grant" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">Choose a role…</option>
            {(roles.data ?? [])
              .filter((r) => r.grantable)
              .map((r) => (
                <option key={r.id} value={r.id}>
                  {roleName(r)}
                </option>
              ))}
          </SelectInput>
          <Button type="submit" variant="primary" disabled={!user || !role || change.isPending}>
            Grant
          </Button>
        </form>
      )}
      <ErrorLine error={change.error} />
    </Card>
  );
}
