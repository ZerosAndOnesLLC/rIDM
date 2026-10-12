"use client";

import { fmtNumber } from "@/lib/console/format";
import { EmptyState } from "@/components/base/empty-state";
import { DataTable } from "@/components/base/data-table";
import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { useState } from "react";
import { SelectInput } from "@/components/console/form";
import { Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "./access/common";

// Recharts is the console's largest dependency: the charts load in their own
// bundle, after the page, and only where the dashboard is shown.
const SignInsChart = dynamic(() => import("./dashboard-charts").then((m) => m.SignInsChart), { ssr: false, loading: () => <Spinner label="Loading chart…" /> });
const ClientsChart = dynamic(() => import("./dashboard-charts").then((m) => m.ClientsChart), { ssr: false, loading: () => <Spinner label="Loading chart…" /> });

/**
 * Tenant dashboard: sign-ins and failures per day, live sessions, users,
 * second-factor adoption and the most authorized clients. Series colours are
 * the validated dataviz slots (blue, orange) stepped for each theme via CSS
 * variables in globals.css.
 */
export function Dashboard({ tenant }: { tenant: string }) {
  const { client } = useConsole();
  const [days, setDays] = useState(30);
  const stats = useQuery({
    queryKey: ["stats", tenant, days],
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/stats", { params: { path: { slug: tenant }, query: { days } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  if (stats.isPending) return <Spinner label="Loading statistics…" />;
  if (stats.isError) return <ErrorLine error={stats.error} />;
  const s = stats.data;
  const adoption = s.users.active > 0 ? Math.round((s.users.mfa_enrolled / s.users.active) * 100) : 0;
  const series = s.days.map((d) => ({ date: d.date, label: new Date(`${d.date}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" }), "Sign-ins": d.logins, Failed: d.failed }));
  const top = s.top_clients.map((c) => ({ name: c.name, id: c.client_id, Authorizations: c.authorizations }));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid flex-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tile label={`Sign-ins · ${days} days`} value={s.logins_total} />
          <Tile label={`Failed sign-ins · ${days} days`} value={s.failed_total} tone={s.failed_total > 0 && s.failed_total * 5 > s.logins_total ? "warn" : undefined} />
          <Tile label="Live sessions" value={s.active_sessions} />
          <Tile label="Two-step adoption" value={`${adoption}%`} sub={`${fmtNumber(s.users.mfa_enrolled)} of ${fmtNumber(s.users.active)} active users`} />
        </div>
        <label className="flex items-center gap-2 text-small text-muted">
          Window
          <SelectInput aria-label="Window" value={days} onChange={(e) => setDays(Number(e.target.value))} className="min-h-8 w-auto text-small">
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </SelectInput>
        </label>
      </div>

      <Card title="Sign-ins per day">
        <div className="h-64" role="img" aria-label={`Sign-ins and failed sign-ins per day over ${days} days: ${s.logins_total} sign-ins, ${s.failed_total} failed`}>
          <SignInsChart series={series} />
        </div>
        <details className="mt-2 text-small text-muted">
          <summary className="cursor-pointer">Table view</summary>
          <div className="mt-2">
            <DataTable
              label="Sign-ins per day"
              minWidth="16rem"
              columns={[
                { key: "day", header: "Day", width: "minmax(7rem, 1fr)", cell: (d: (typeof s.days)[number]) => <span className="font-mono text-small text-ink">{d.date}</span> },
                { key: "logins", header: "Sign-ins", width: "6rem", align: "end", cell: (d) => <span className="font-mono text-small text-ink">{d.logins}</span> },
                { key: "failed", header: "Failed", width: "6rem", align: "end", cell: (d) => <span className="font-mono text-small text-ink">{d.failed}</span> },
              ]}
              rows={s.days}
              rowKey={(d) => d.date}
              empty={<EmptyState compact title="No days in this window" />}
            />
          </div>
        </details>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Most authorized clients">
          {top.length === 0 ? (
            <p className="text-body text-muted">No authorizations in this window.</p>
          ) : (
            <div className="h-56" role="img" aria-label={`Authorizations per client: ${top.map((c) => `${c.name} ${c.Authorizations}`).join(", ")}`}>
              <ClientsChart top={top} />
            </div>
          )}
        </Card>
        <Card title="Users">
          <dl className="grid grid-cols-3 gap-3 text-center">
            <div>
              <dt className="text-caption uppercase tracking-wide text-muted">Total</dt>
              <dd className="text-2xl font-semibold text-ink">{fmtNumber(s.users.total)}</dd>
            </div>
            <div>
              <dt className="text-caption uppercase tracking-wide text-muted">Active</dt>
              <dd className="text-2xl font-semibold text-ink">{fmtNumber(s.users.active)}</dd>
            </div>
            <div>
              <dt className="text-caption uppercase tracking-wide text-muted">With a second factor</dt>
              <dd className="text-2xl font-semibold text-ink">{fmtNumber(s.users.mfa_enrolled)}</dd>
            </div>
          </dl>
          <div className="mt-4">
            <div className="mb-1 flex justify-between text-small text-muted">
              <span>Two-step adoption</span>
              <span>{adoption}%</span>
            </div>
            <div className="h-2 rounded-full bg-ground" role="progressbar" aria-valuenow={adoption} aria-valuemin={0} aria-valuemax={100} aria-label="Two-step adoption">
              <div className="h-2 rounded-full bg-[var(--series-1)]" style={{ width: `${adoption}%` }} />
            </div>
            <p className="mt-2 text-small text-muted">Active users with a passkey, an authenticator app or another second step enrolled.</p>
          </div>
        </Card>
      </div>
    </div>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: number | string; sub?: string; tone?: "warn" }) {
  return (
    <div className="rounded-[calc(var(--radius)+2px)] border border-line bg-paper px-4 py-3">
      <p className="text-caption uppercase tracking-wide text-muted">{label}</p>
      <p className={`mt-1 text-num font-semibold leading-none ${tone === "warn" ? "text-danger" : "text-ink"}`}>{typeof value === "number" ? fmtNumber(value) : value}</p>
      {sub && <p className="mt-1.5 text-caption text-muted">{sub}</p>}
    </div>
  );
}
