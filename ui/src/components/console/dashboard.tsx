"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SelectInput } from "@/components/console/form";
import { Card } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatNumber } from "@/i18n";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "./access/common";

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
          <Tile label="Two-step adoption" value={`${adoption}%`} sub={`${formatNumber("en", s.users.mfa_enrolled)} of ${formatNumber("en", s.users.active)} active users`} />
        </div>
        <label className="flex items-center gap-2 text-[0.8125rem] text-muted">
          Window
          <SelectInput aria-label="Window" value={days} onChange={(e) => setDays(Number(e.target.value))} className="min-h-8 w-auto text-[0.8125rem]">
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </SelectInput>
        </label>
      </div>

      <Card title="Sign-ins per day">
        <div className="h-64" role="img" aria-label={`Sign-ins and failed sign-ins per day over ${days} days: ${s.logins_total} sign-ins, ${s.failed_total} failed`}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="var(--line)" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 12 }} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={24} />
              <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 12 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--ink)", fontSize: 13 }} labelStyle={{ color: "var(--muted)" }} cursor={{ stroke: "var(--line)" }} />
              <Legend wrapperStyle={{ fontSize: 13, color: "var(--muted)" }} iconType="plainline" />
              <Line type="monotone" dataKey="Sign-ins" stroke="var(--series-1)" strokeWidth={2} dot={false} activeDot={{ r: 5, stroke: "var(--paper)", strokeWidth: 2 }} isAnimationActive={false} />
              <Line type="monotone" dataKey="Failed" stroke="var(--series-2)" strokeWidth={2} dot={false} activeDot={{ r: 5, stroke: "var(--paper)", strokeWidth: 2 }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <details className="mt-2 text-[0.8125rem] text-muted">
          <summary className="cursor-pointer">Table view</summary>
          <table className="mt-2 w-full text-[0.8125rem]">
            <thead>
              <tr className="text-start text-muted">
                <th scope="col" className="py-1 text-start font-medium">Day</th>
                <th scope="col" className="py-1 text-end font-medium">Sign-ins</th>
                <th scope="col" className="py-1 text-end font-medium">Failed</th>
              </tr>
            </thead>
            <tbody>
              {s.days.map((d) => (
                <tr key={d.date} className="border-t border-line">
                  <td className="py-1 text-ink">{d.date}</td>
                  <td className="py-1 text-end text-ink">{d.logins}</td>
                  <td className="py-1 text-end text-ink">{d.failed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Most authorized clients">
          {top.length === 0 ? (
            <p className="text-[0.875rem] text-muted">No authorizations in this window.</p>
          ) : (
            <div className="h-56" role="img" aria-label={`Authorizations per client: ${top.map((c) => `${c.name} ${c.Authorizations}`).join(", ")}`}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={top} layout="vertical" margin={{ top: 4, right: 40, bottom: 0, left: 8 }} barCategoryGap={6}>
                  <CartesianGrid stroke="var(--line)" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 12 }} tickLine={false} axisLine={false} />
                  <YAxis type="category" dataKey="name" width={120} tick={{ fill: "var(--ink)", fontSize: 12 }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--ink)", fontSize: 13 }} cursor={{ fill: "var(--ground)" }} />
                  <Bar dataKey="Authorizations" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false} label={{ position: "right", fill: "var(--muted)", fontSize: 12 }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
        <Card title="Users">
          <dl className="grid grid-cols-3 gap-3 text-center">
            <div>
              <dt className="text-[0.75rem] uppercase tracking-wide text-muted">Total</dt>
              <dd className="text-[1.5rem] font-semibold text-ink">{formatNumber("en", s.users.total)}</dd>
            </div>
            <div>
              <dt className="text-[0.75rem] uppercase tracking-wide text-muted">Active</dt>
              <dd className="text-[1.5rem] font-semibold text-ink">{formatNumber("en", s.users.active)}</dd>
            </div>
            <div>
              <dt className="text-[0.75rem] uppercase tracking-wide text-muted">With a second factor</dt>
              <dd className="text-[1.5rem] font-semibold text-ink">{formatNumber("en", s.users.mfa_enrolled)}</dd>
            </div>
          </dl>
          <div className="mt-4">
            <div className="mb-1 flex justify-between text-[0.8125rem] text-muted">
              <span>Two-step adoption</span>
              <span>{adoption}%</span>
            </div>
            <div className="h-2 rounded-full bg-ground" role="progressbar" aria-valuenow={adoption} aria-valuemin={0} aria-valuemax={100} aria-label="Two-step adoption">
              <div className="h-2 rounded-full bg-[var(--series-1)]" style={{ width: `${adoption}%` }} />
            </div>
            <p className="mt-2 text-[0.8125rem] text-muted">Second factors arrive with Phase 7; adoption stays at zero until then.</p>
          </div>
        </Card>
      </div>
    </div>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: number | string; sub?: string; tone?: "warn" }) {
  return (
    <div className="rounded-[calc(var(--radius)+2px)] border border-line bg-paper px-4 py-3">
      <p className="text-[0.75rem] uppercase tracking-wide text-muted">{label}</p>
      <p className={`mt-1 text-[1.75rem] font-semibold leading-none ${tone === "warn" ? "text-danger" : "text-ink"}`}>{typeof value === "number" ? formatNumber("en", value) : value}</p>
      {sub && <p className="mt-1.5 text-[0.75rem] text-muted">{sub}</p>}
    </div>
  );
}
