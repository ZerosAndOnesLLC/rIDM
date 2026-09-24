"use client";

import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

/** One day of the sign-ins chart. */
export type DaySeries = { date: string; label: string; "Sign-ins": number; Failed: number };
/** One bar of the clients chart. */
export type ClientBar = { name: string; id: string; Authorizations: number };

export function SignInsChart({ series }: { series: DaySeries[] }) {
  return (
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
  );
}

export function ClientsChart({ top }: { top: ClientBar[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={top} layout="vertical" margin={{ top: 4, right: 40, bottom: 0, left: 8 }} barCategoryGap={6}>
        <CartesianGrid stroke="var(--line)" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 12 }} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" width={120} tick={{ fill: "var(--ink)", fontSize: 12 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={{ background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--ink)", fontSize: 13 }} cursor={{ fill: "var(--ground)" }} />
        <Bar dataKey="Authorizations" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false} label={{ position: "right", fill: "var(--muted)", fontSize: 12 }} />
      </BarChart>
    </ResponsiveContainer>
  );
}
