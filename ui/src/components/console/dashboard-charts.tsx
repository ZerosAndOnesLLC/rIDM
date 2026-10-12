"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

/** One day of the sign-ins chart. */
export type DaySeries = { date: string; label: string; "Sign-ins": number; Failed: number };

/** Sign-ins and failures per day as grouped bars on the two series tokens. */
export function SignInsChart({ series }: { series: DaySeries[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={series} margin={{ top: 8, right: 4, bottom: 0, left: -18 }} barCategoryGap={series.length > 31 ? 1 : 4} barGap={1}>
        <CartesianGrid stroke="var(--line)" vertical={false} />
        <XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 11, fontFamily: "var(--font-mono)" }} tickLine={false} axisLine={{ stroke: "var(--line)" }} minTickGap={28} />
        <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11, fontFamily: "var(--font-mono)" }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={{ background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--ink)", fontSize: 13, boxShadow: "var(--shadow-pop)" }} labelStyle={{ color: "var(--muted)" }} cursor={{ fill: "var(--ground)" }} />
        <Bar dataKey="Sign-ins" fill="var(--series-1)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
        <Bar dataKey="Failed" fill="var(--series-2)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}
