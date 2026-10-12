"use client";

import { fmtDateTime } from "@/lib/console/format";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button, Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useConsole } from "@/lib/console/session";
import { describeAgent } from "@/lib/ua";

export function SessionsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const path = { slug: tenant, user: id };
  const sessions = useQuery({
    queryKey: ["user", tenant, id, "sessions"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/sessions", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const devices = useQuery({
    queryKey: ["user", tenant, id, "devices"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/devices", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const revoke = useMutation({
    mutationFn: async (what: { kind: "session" | "device"; id?: string }) => {
      const r =
        what.kind === "session"
          ? what.id
            ? await api.DELETE("/admin/tenants/{slug}/users/{user}/sessions/{session_id}", { params: { path: { ...path, session_id: what.id } } })
            : await api.DELETE("/admin/tenants/{slug}/users/{user}/sessions", { params: { path } })
          : what.id
            ? await api.DELETE("/admin/tenants/{slug}/users/{user}/devices/{device_id}", { params: { path: { ...path, device_id: what.id } } })
            : await api.DELETE("/admin/tenants/{slug}/users/{user}/devices", { params: { path } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["user", tenant, id, "sessions"] });
      void qc.invalidateQueries({ queryKey: ["user", tenant, id, "devices"] });
    },
  });
  return (
    <div className="flex flex-col gap-4">
      {revoke.isError && (
        <p role="alert" className="text-body text-danger">
          {revoke.error.message}
        </p>
      )}
      <Card
        title="Sessions"
        actions={
          editable && (sessions.data?.length ?? 0) > 0 ? (
            <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "session" })}>
              Sign out everywhere
            </Button>
          ) : undefined
        }
      >
        {sessions.isPending ? (
          <Spinner label="Loading…" />
        ) : sessions.isError ? (
          <p role="alert" className="text-body text-danger">
            {sessions.error.message}
          </p>
        ) : sessions.data.length === 0 ? (
          <p className="text-body text-muted">No live sessions.</p>
        ) : (
          <ul className="divide-y divide-line">
            {sessions.data.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-body">
                <span>
                  <span className="font-medium text-ink">{describeAgent(s.user_agent)}</span>
                  <span className="ms-2 text-muted">{s.ip ?? ""}</span>
                  {s.impersonator && (
                    <span className="ms-2">
                      <Badge tone="accent">Impersonated by {s.impersonator.username}</Badge>
                    </span>
                  )}
                  <span className="block text-small text-muted">
                    Signed in {fmtDateTime(s.auth_time)} · {s.amr.join(", ")} · last seen {fmtDateTime(s.last_seen_at)} · ends {fmtDateTime(s.expires_at)}
                  </span>
                </span>
                {editable && (
                  <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "session", id: s.id })}>
                    Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card
        title="Trusted devices"
        actions={
          editable && (devices.data?.length ?? 0) > 0 ? (
            <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "device" })}>
              Forget all
            </Button>
          ) : undefined
        }
      >
        {devices.isPending ? (
          <Spinner label="Loading…" />
        ) : devices.isError ? (
          <p role="alert" className="text-body text-danger">
            {devices.error.message}
          </p>
        ) : devices.data.length === 0 ? (
          <p className="text-body text-muted">No remembered devices.</p>
        ) : (
          <ul className="divide-y divide-line">
            {devices.data.map((d) => (
              <li key={d.id} className="flex items-center justify-between gap-3 py-2 text-body">
                <span>
                  <span className="font-medium text-ink">{d.name ?? describeAgent(d.user_agent)}</span>
                  <span className="ms-2 text-muted">{d.ip ?? ""}</span>
                  <span className="block text-small text-muted">
                    Remembered {fmtDateTime(d.created_at)} · last seen {fmtDateTime(d.last_seen_at)} · until {fmtDateTime(d.expires_at)}
                  </span>
                </span>
                {editable && (
                  <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "device", id: d.id })}>
                    Forget
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
