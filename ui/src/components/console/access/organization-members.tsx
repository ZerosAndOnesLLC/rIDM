"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserRoundPlus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { TextInput } from "@/components/console/form";
import { Picker, type PickerItem } from "@/components/console/picker";
import { Badge, Button, Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { userHref } from "@/lib/console/users";
import { ErrorLine } from "./common";

export function OrganizationMembers({
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
export function OrganizationInvitations({ tenant, id }: { tenant: string; id: string }) {
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
