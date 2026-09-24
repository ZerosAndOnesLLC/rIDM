"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { SelectInput } from "@/components/console/form";
import { Picker, type PickerItem } from "@/components/console/picker";
import { Button, Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { roleName } from "@/lib/console/users";
import { ErrorLine } from "./common";

export function OrganizationRoles({
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
  const [user, setUser] = useState<{ id: string; username: string } | null>(null);
  const [role, setRole] = useState("");
  const [picking, setPicking] = useState(false);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 200);
  const grants = useInfiniteQuery({
    queryKey: ["organization", tenant, id, "roles"],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations/{org}/roles", {
        params: { path: { slug: tenant, org: id }, query: pageParam ? { cursor: pageParam } : {} },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const granted = grants.data?.pages.flatMap((p) => p.items) ?? [];
  // Members to grant to, searched on the server: an organization may have
  // far more than a list could show.
  const candidates = useQuery({
    queryKey: ["organization", tenant, id, "members", "pick", q],
    enabled: picking && q.length >= 1,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations/{org}/members", {
        params: { path: { slug: tenant, org: id }, query: { search: q, limit: 10 } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data.items;
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
  const items: PickerItem[] = (candidates.data ?? []).map((u) => ({
    id: u.id,
    group: "Members",
    label: u.username,
    hint: u.email && u.email !== u.username ? u.email : undefined,
    onSelect: () => {
      setUser({ id: u.id, username: u.username });
      setPicking(false);
    },
  }));

  return (
    <Card
      title="Roles inside this organization"
      actions={<span className="text-[0.8125rem] text-muted">Only while acting here</span>}
    >
      {grants.isPending ? (
        <Spinner label="Loading grants…" />
      ) : grants.isError ? (
        <ErrorLine error={grants.error} />
      ) : granted.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No roles granted inside this organization.</p>
      ) : (
        <ul className="divide-y divide-line">
          {granted.map((g) => (
            <li key={g.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span className="text-ink">
                {nameOf(g.role_id)} —{" "}
                {g.group_id ? (
                  <span className="text-muted">group grant</span>
                ) : (
                  (g.username ?? g.user_id)
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
      {grants.hasNextPage && (
        <div className="mt-2 text-center">
          <Button onClick={() => void grants.fetchNextPage()} disabled={grants.isFetchingNextPage}>
            {grants.isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
      {editable && (
        <form
          className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (user && role) change.mutate({ userId: user.id, roleId: role });
          }}
        >
          <Button type="button" aria-label="Member to grant a role to" onClick={() => setPicking(true)}>
            {user ? user.username : "Choose a member…"}
          </Button>
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
      <Picker
        open={picking}
        onOpenChange={setPicking}
        title="Choose a member"
        placeholder="Search members by username or email…"
        query={search}
        onQueryChange={setSearch}
        items={items}
        loading={candidates.isFetching}
        empty={q ? "No member matches." : "Type to search."}
      />
    </Card>
  );
}
