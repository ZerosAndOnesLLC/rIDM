"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { SelectInput } from "@/components/console/form";
import { Badge, Button, Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useConsole } from "@/lib/console/session";
import { roleName } from "@/lib/console/users";
import { useRolesAndGroups } from "./invite";

export function RolesTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const { roles: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const mine = useQuery({
    queryKey: ["user", tenant, id, "roles"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/roles", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await api.PUT("/admin/tenants/{slug}/users/{user}/roles/{role_id}", { params: { path: { slug: tenant, user: id, role_id: what.add } } })
        : await api.DELETE("/admin/tenants/{slug}/users/{user}/roles/{role_id}", { params: { path: { slug: tenant, user: id, role_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      void qc.invalidateQueries({ queryKey: ["user", tenant, id] });
    },
  });
  const directIds = new Set(mine.data?.direct.map((r) => r.id) ?? []);
  const options = (all.data ?? []).filter((r) => !directIds.has(r.id));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Assigned directly">
        {mine.isPending ? (
          <Spinner label="Loading…" />
        ) : mine.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {mine.error.message}
          </p>
        ) : (
          <>
            {mine.data.direct.length === 0 && <p className="text-[0.875rem] text-muted">No direct roles.</p>}
            <ul className="divide-y divide-line">
              {mine.data.direct.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                  <span>
                    <span className="font-medium text-ink">{roleName(r)}</span>
                    {r.built_in && <Badge>built-in</Badge>}
                    {r.description && <span className="block text-[0.8125rem] text-muted">{r.description}</span>}
                  </span>
                  {editable && (
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: r.id })}>
                      Remove
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            {editable && (
              <form
                className="mt-4 flex gap-2 border-t border-line pt-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (pick) change.mutate({ add: pick });
                }}
              >
                <SelectInput aria-label="Role to assign" value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Choose a role…</option>
                  {options.map((r) => (
                    <option key={r.id} value={r.id}>
                      {roleName(r)}
                    </option>
                  ))}
                </SelectInput>
                <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
                  Assign
                </Button>
              </form>
            )}
            {change.isError && (
              <p role="alert" className="mt-2 text-[0.875rem] text-danger">
                {change.error.message}
              </p>
            )}
          </>
        )}
      </Card>
      <Card title="Effective roles">
        <p className="mb-2 text-[0.8125rem] text-muted">Direct roles plus those inherited through groups and composites.</p>
        <div className="flex flex-wrap gap-1.5">
          {mine.data?.effective.map((r) => (
            <Badge key={r.id} tone={directIds.has(r.id) ? "accent" : "neutral"}>
              {roleName(r)}
            </Badge>
          ))}
          {mine.data?.effective.length === 0 && <span className="text-[0.875rem] text-muted">None.</span>}
        </div>
      </Card>
    </div>
  );
}

export function GroupsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const { groups: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const mine = useQuery({
    queryKey: ["user", tenant, id, "groups"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/groups", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await api.PUT("/admin/tenants/{slug}/users/{user}/groups/{group_id}", { params: { path: { slug: tenant, user: id, group_id: what.add } } })
        : await api.DELETE("/admin/tenants/{slug}/users/{user}/groups/{group_id}", { params: { path: { slug: tenant, user: id, group_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      void qc.invalidateQueries({ queryKey: ["user", tenant, id] });
    },
  });
  const directIds = new Set(mine.data?.direct.map((g) => g.id) ?? []);
  const byId = new Map((all.data ?? []).map((g) => [g.id, g]));
  const pathOf = (gid: string): string => {
    const g = byId.get(gid);
    if (!g) return gid;
    return g.parent_id ? `${pathOf(g.parent_id)} / ${g.name}` : g.name;
  };
  const options = (all.data ?? []).filter((g) => !directIds.has(g.id)).map((g) => ({ id: g.id, label: pathOf(g.id) })).sort((a, b) => a.label.localeCompare(b.label));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Member of">
        {mine.isPending ? (
          <Spinner label="Loading…" />
        ) : mine.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {mine.error.message}
          </p>
        ) : (
          <>
            {mine.data.direct.length === 0 && <p className="text-[0.875rem] text-muted">No groups.</p>}
            <ul className="divide-y divide-line">
              {mine.data.direct.map((g) => (
                <li key={g.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                  <span className="font-medium text-ink">{pathOf(g.id)}</span>
                  {editable && (
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: g.id })}>
                      Leave
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            {editable && (
              <form
                className="mt-4 flex gap-2 border-t border-line pt-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (pick) change.mutate({ add: pick });
                }}
              >
                <SelectInput aria-label="Group to join" value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Choose a group…</option>
                  {options.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </SelectInput>
                <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
                  Join
                </Button>
              </form>
            )}
            {change.isError && (
              <p role="alert" className="mt-2 text-[0.875rem] text-danger">
                {change.error.message}
              </p>
            )}
          </>
        )}
      </Card>
      <Card title="Effective groups">
        <p className="mb-2 text-[0.8125rem] text-muted">Direct memberships plus their ancestors.</p>
        <div className="flex flex-wrap gap-1.5">
          {mine.data?.effective.map((g) => (
            <Badge key={g.id} tone={directIds.has(g.id) ? "accent" : "neutral"}>
              {pathOf(g.id)}
            </Badge>
          ))}
          {mine.data?.effective.length === 0 && <span className="text-[0.875rem] text-muted">None.</span>}
        </div>
      </Card>
    </div>
  );
}
