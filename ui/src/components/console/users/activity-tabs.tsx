"use client";

import { fmtDateTime } from "@/lib/console/format";
import { Skeleton } from "@/components/base/skeleton";
import { EmptyState } from "@/components/base/empty-state";
import { ListFooter } from "@/components/base/data-table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button, Card } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";

export function ConsentsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const consents = useQuery({
    queryKey: ["user", tenant, id, "consents"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/consents", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const revoke = useMutation({
    mutationFn: async (clientId: string) => {
      const { error } = await api.DELETE("/admin/tenants/{slug}/users/{user}/consents/{client_id}", { params: { path: { slug: tenant, user: id, client_id: clientId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["user", tenant, id, "consents"] }),
  });
  return (
    <Card title="Consented applications">
      {consents.isPending ? (
        <Skeleton shape="lines" count={4} />
      ) : consents.isError ? (
        <p role="alert" className="text-body text-danger">
          {consents.error.message}
        </p>
      ) : consents.data.length === 0 ? (
        <p className="text-body text-muted">No consents recorded.</p>
      ) : (
        <ul className="divide-y divide-line">
          {consents.data.map((c) => (
            <li key={c.client_id} className="flex items-center justify-between gap-3 py-2 text-body">
              <span>
                <span className="font-medium text-ink">{c.client_name} ({c.client})</span>
                <span className="block text-small text-muted">
                  {c.scopes.join(" ")} · granted {fmtDateTime(c.granted_at)}
                  {c.revoked_at ? ` · revoked ${fmtDateTime(c.revoked_at)}` : ""}
                </span>
              </span>
              {editable && !c.revoked_at && (
                <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={revoke.isPending} onClick={() => revoke.mutate(c.client_id)}>
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {revoke.isError && (
        <p role="alert" className="mt-2 text-body text-danger">
          {revoke.error.message}
        </p>
      )}
    </Card>
  );
}

export function AuditTab({ tenant, id }: { tenant: string; id: string }) {
  const { client: api, can } = useConsole();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursors[cursors.length - 1];
  const [open, setOpen] = useState<string | null>(null);
  const page = useQuery({
    queryKey: ["user", tenant, id, "audit", cursor],
    enabled: can("ridm:audit:read"),
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/audit", { params: { path: { slug: tenant, user: id }, query: { cursor, limit: 50 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  if (!can("ridm:audit:read")) return <p className="text-body text-muted">You need audit access to see this.</p>;
  return (
    <Card title="Audit trail">
      {page.isPending ? (
        <Skeleton shape="lines" count={4} />
      ) : page.isError ? (
        <p role="alert" className="text-body text-danger">
          {page.error.message}
        </p>
      ) : page.data.items.length === 0 ? (
        <EmptyState compact title="Nothing recorded yet" />
      ) : (
        <ul className="divide-y divide-line">
          {page.data.items.map((e) => (
            <li key={e.id} className="py-2 text-body">
              <button type="button" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id} className="flex w-full items-center justify-between gap-3 text-start">
                <span>
                  <span className="font-mono text-small font-medium text-ink">{e.name}</span>
                  <span className="ms-2 text-muted">by {e.actor_type}</span>
                </span>
                <span className="shrink-0 text-small text-muted">{fmtDateTime(e.occurred_at)}</span>
              </button>
              {open === e.id && (
                <pre tabIndex={0} aria-label="Event payload" className="mt-2 max-h-64 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-small text-ink">
                  {JSON.stringify({ ip: e.ip, user_agent: e.user_agent, payload: e.payload }, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
      {(cursors.length > 1 || page.data?.next_cursor) && (
        <div className="mt-3">
          <ListFooter
            mode="cursor"
            count={page.data?.items.length ?? 0}
            canNewer={cursors.length > 1}
            canOlder={Boolean(page.data?.next_cursor)}
            loading={page.isFetching}
            onNewer={() => setCursors((c) => c.slice(0, -1))}
            onOlder={() => setCursors((c) => [...c, page.data?.next_cursor ?? undefined])}
          />
        </div>
      )}
    </Card>
  );
}
