"use client";

import { useQuery } from "@tanstack/react-query";
import { KeyRound, Search, UserRound } from "lucide-react";
import { useState } from "react";
import { Dashboard } from "@/components/console/dashboard";
import { Badge, Card, Kbd, PageHeader, Row } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";
import { modKey } from "@/lib/console/shortcuts";
import { useConsoleTenant } from "@/lib/console/tenant";
import { formatDate } from "@/i18n";

/** Landing page: who you are, what you can do, and the tenant in view. */
export default function Overview() {
  const { me, client } = useConsole();
  const tenant = useConsoleTenant();
  const [showAll, setShowAll] = useState(false);
  const detail = useQuery({
    queryKey: ["tenant", tenant],
    enabled: Boolean(tenant),
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}", { params: { path: { slug: tenant! } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const permissions = me?.permissions ?? [];
  const shown = showAll ? permissions : permissions.slice(0, 12);

  return (
    <>
      <PageHeader title="Overview" sub={detail.data ? `${detail.data.display_name} · ${detail.data.slug}` : tenant ?? undefined} />
      {tenant && (
        <div className="mb-6">
          <Dashboard tenant={tenant} />
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Signed in as">
          <dl>
            <Row label="User">
              <span className="inline-flex max-w-full items-center gap-1.5">
                <UserRound className="size-4 shrink-0 text-muted" aria-hidden />
                <span className="truncate">{me?.username}</span>
              </span>
            </Row>
            <Row label="Home tenant">{me?.tenant_slug}</Row>
            <Row label="Scope">{me?.scope === "global" ? <Badge tone="accent">Global</Badge> : <Badge>Tenant</Badge>}</Row>
            <Row label="Roles">
              <span className="flex flex-wrap justify-end gap-1">
                {me?.roles.map((r) => (
                  <Badge key={r}>{r}</Badge>
                ))}
              </span>
            </Row>
          </dl>
        </Card>

        <Card title="Tenant">
          {detail.isError ? (
            <p className="text-[0.875rem] text-danger">{detail.error.message}</p>
          ) : detail.data ? (
            <dl>
              <Row label="Name">{detail.data.display_name}</Row>
              <Row label="Slug">{detail.data.slug}</Row>
              <Row label="Status">{detail.data.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">{detail.data.status}</Badge>}</Row>
              <Row label="Created">{formatDate("en", detail.data.created_at, { dateStyle: "medium" })}</Row>
              <Row label="Default locale">{detail.data.settings.locale.default}</Row>
            </dl>
          ) : (
            <p className="text-[0.875rem] text-muted">Loading…</p>
          )}
        </Card>

        <Card
          title="Permissions"
          actions={<span className="text-[0.8125rem] text-muted">{permissions.length}</span>}
        >
          <div className="flex flex-wrap gap-1.5">
            {shown.map((p) => (
              <Badge key={p}>{p}</Badge>
            ))}
          </div>
          {permissions.length > 12 && (
            <button type="button" onClick={() => setShowAll((s) => !s)} className="mt-3 text-[0.8125rem] text-link underline underline-offset-4">
              {showAll ? "Show fewer" : `Show all ${permissions.length}`}
            </button>
          )}
        </Card>

        <Card title="Getting around">
          <ul className="flex flex-col gap-3 text-[0.875rem] text-ink">
            <li className="flex items-center justify-between gap-3">
              <span className="inline-flex items-center gap-2">
                <Search className="size-4 text-muted" aria-hidden />
                Search pages, users and clients
              </span>
              <span className="flex gap-1">
                <Kbd>{modKey()}</Kbd>
                <Kbd>K</Kbd>
              </span>
            </li>
            <li className="flex items-center justify-between gap-3">
              <span className="inline-flex items-center gap-2">
                <KeyRound className="size-4 text-muted" aria-hidden />
                Keyboard shortcuts
              </span>
              <Kbd>?</Kbd>
            </li>
          </ul>
        </Card>
      </div>
    </>
  );
}
