"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button, Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
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
        <Spinner label="Loading…" />
      ) : consents.isError ? (
        <p role="alert" className="text-[0.875rem] text-danger">
          {consents.error.message}
        </p>
      ) : consents.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No consents recorded.</p>
      ) : (
        <ul className="divide-y divide-line">
          {consents.data.map((c) => (
            <li key={c.client_id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span>
                <span className="font-medium text-ink">{c.client_name} ({c.client})</span>
                <span className="block text-[0.8125rem] text-muted">
                  {c.scopes.join(" ")} · granted {formatDate("en", c.granted_at)}
                  {c.revoked_at ? ` · revoked ${formatDate("en", c.revoked_at)}` : ""}
                </span>
              </span>
              {editable && !c.revoked_at && (
                <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(c.client_id)}>
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {revoke.isError && (
        <p role="alert" className="mt-2 text-[0.875rem] text-danger">
          {revoke.error.message}
        </p>
      )}
    </Card>
  );
}

export function AuditTab({ tenant, id }: { tenant: string; id: string }) {
  const { client: api, can } = useConsole();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
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
  if (!can("ridm:audit:read")) return <p className="text-[0.875rem] text-muted">You need audit access to see this.</p>;
  return (
    <Card title="Audit trail">
      {page.isPending ? (
        <Spinner label="Loading…" />
      ) : page.isError ? (
        <p role="alert" className="text-[0.875rem] text-danger">
          {page.error.message}
        </p>
      ) : page.data.items.length === 0 ? (
        <p className="text-[0.875rem] text-muted">Nothing recorded yet.</p>
      ) : (
        <ul className="divide-y divide-line">
          {page.data.items.map((e) => (
            <li key={e.id} className="py-2 text-[0.875rem]">
              <button type="button" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id} className="flex w-full items-center justify-between gap-3 text-start">
                <span>
                  <span className="font-mono text-[0.8125rem] font-medium text-ink">{e.name}</span>
                  <span className="ms-2 text-muted">by {e.actor_type}</span>
                </span>
                <span className="shrink-0 text-[0.8125rem] text-muted">{formatDate("en", e.occurred_at)}</span>
              </button>
              {open === e.id && (
                <pre tabIndex={0} aria-label="Event payload" className="mt-2 max-h-64 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.8125rem] text-ink">
                  {JSON.stringify({ ip: e.ip, user_agent: e.user_agent, payload: e.payload }, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
      {page.data?.next_cursor && (
        <div className="mt-3 text-center">
          <Button onClick={() => setCursor(page.data.next_cursor ?? undefined)}>Older events</Button>
        </div>
      )}
    </Card>
  );
}
