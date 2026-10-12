"use client";

import { CheckCircle2, KeyRound, Lock, Mail, Webhook } from "lucide-react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useState, type ReactNode } from "react";
import { DataTable } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { Skeleton } from "@/components/base/skeleton";
import { SelectInput } from "@/components/console/form";
import { Avatar, Badge, Card, Chip } from "@/components/console/ui";
import { useTenantStats, type TenantStats } from "@/lib/console/counts";
import { fmtDate, fmtDistance, fmtNumber, fmtWhen } from "@/lib/console/format";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "./access/common";

// Recharts is the console's largest dependency: the chart loads in its own
// bundle, after the page, and only where the overview is shown.
const SignInsChart = dynamic(() => import("./dashboard-charts").then((m) => m.SignInsChart), { ssr: false, loading: () => <Skeleton shape="block" label="Loading chart…" /> });

/**
 * The overview (design/README.md): a greeting, four stat tiles with
 * sparklines and deltas, sign-ins per day as bars on the two series
 * tokens, what needs attention, the newest events and the most used
 * clients. Everything comes from one cached statistics call.
 */
export function Dashboard({ tenant }: { tenant: string }) {
  const { me } = useConsole();
  const [days, setDays] = useState(30);
  const stats = useTenantStats(tenant, days);
  if (stats.isPending) return <Skeleton shape="rows" count={4} label="Loading statistics…" />;
  if (stats.isError) return <ErrorLine error={stats.error} />;
  const s = stats.data;
  const adoption = s.users.active > 0 ? Math.round((s.users.mfa_enrolled / s.users.active) * 100) : 0;
  const series = s.days.map((d) => ({ date: d.date, label: new Date(`${d.date}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" }), "Sign-ins": d.logins, Failed: d.failed }));
  const failedUp = s.failed_total > 0 && s.failed_total * 5 > s.logins_total;
  const hour = new Date().getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  const today = new Date().toLocaleDateString("en", { weekday: "long", month: "long", day: "numeric" });
  const base = `/console/users/?tenant=${encodeURIComponent(tenant)}`;
  const attention: { icon: typeof Lock; tone?: "warn"; title: string; detail: string; href: string; action: string }[] = [];
  if (s.attention.locked_users > 0) attention.push({ icon: Lock, tone: "warn", title: `${fmtNumber(s.attention.locked_users)} ${s.attention.locked_users === 1 ? "account" : "accounts"} locked`, detail: "Too many failed attempts, or locked by an administrator.", href: base, action: "Review" });
  if (s.attention.open_invitations > 0) attention.push({ icon: Mail, title: `${fmtNumber(s.attention.open_invitations)} ${s.attention.open_invitations === 1 ? "invitation" : "invitations"} waiting`, detail: s.attention.oldest_invitation_at ? `Oldest sent ${fmtWhen(s.attention.oldest_invitation_at).toLowerCase()}.` : "", href: `${base}&view=invitations`, action: "Open" });
  for (const k of s.attention.expiring_keys) attention.push({ icon: KeyRound, title: `Signing key ${k.kid.slice(0, 8)}… stops publishing ${fmtDistance(k.expires_at).toLowerCase()}`, detail: `Until ${fmtDate(k.expires_at)}; rotation is automatic under the key policy.`, href: `/console/keys/?tenant=${encodeURIComponent(tenant)}`, action: "Keys" });
  if (s.attention.dead_deliveries > 0) attention.push({ icon: Webhook, tone: "warn", title: `${fmtNumber(s.attention.dead_deliveries)} webhook ${s.attention.dead_deliveries === 1 ? "delivery" : "deliveries"} given up on`, detail: "In the last 7 days, after every retry.", href: `/console/webhooks/?tenant=${encodeURIComponent(tenant)}`, action: "Webhooks" });
  const topMax = Math.max(1, ...s.top_clients.map((c) => c.authorizations));

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-end justify-between gap-x-4 gap-y-3">
        <div>
          <h1 className="text-2xl font-semibold leading-none text-ink">
            {greeting}, {me?.username ?? "there"}
          </h1>
          <p className="mt-1.5 text-small text-muted">
            {tenant} · {today} · last {days} days
          </p>
        </div>
        <label className="flex items-center gap-2 text-small text-muted">
          Window
          <SelectInput aria-label="Window" value={days} onChange={(e) => setDays(Number(e.target.value))} className="min-h-8 w-auto text-small">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </SelectInput>
        </label>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label={`Sign-ins · ${days} days`} value={s.logins_total} change={delta(s.logins_total, s.previous.logins_total, days, "up")} spark={s.days.map((d) => d.logins)} />
        <Tile label={`Failed sign-ins · ${days} days`} value={s.failed_total} tone={failedUp ? "warn" : undefined} change={delta(s.failed_total, s.previous.failed_total, days, "down")} extra={s.attention.locked_users > 0 ? `${fmtNumber(s.attention.locked_users)} locked` : undefined} spark={s.days.map((d) => d.failed)} sparkColor={failedUp ? "var(--warn)" : "var(--series-2)"} />
        <Tile label="Live sessions" value={s.active_sessions} sub="right now" />
        <Tile label="Two-step adoption" value={`${adoption}%`} sub={`${fmtNumber(s.users.mfa_enrolled)} of ${fmtNumber(s.users.active)} active users`} sparkColor="var(--series-2)" />
      </div>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Card
          title="Sign-ins per day"
          actions={
            <span className="flex gap-3.5 text-caption text-muted" aria-hidden>
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2.5 rounded-[3px] bg-[var(--series-1)]" />
                Succeeded
              </span>
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2.5 rounded-[3px] bg-[var(--series-2)]" />
                Failed
              </span>
            </span>
          }
        >
          <div className="h-52" role="img" aria-label={`Sign-ins and failed sign-ins per day over ${days} days: ${s.logins_total} sign-ins, ${s.failed_total} failed`}>
            <SignInsChart series={series} />
          </div>
          <details className="mt-2 text-small text-muted">
            <summary className="cursor-pointer">Table view</summary>
            <div className="mt-2">
              <DataTable
                label="Sign-ins per day"
                minWidth="16rem"
                columns={[
                  { key: "day", header: "Day", width: "minmax(7rem, 1fr)", cell: (d: TenantStats["days"][number]) => <span className="font-mono text-small text-ink">{d.date}</span> },
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

        <Card id="attention" title="Needs attention" padded={false} actions={attention.length > 0 ? <Badge tone="contrast">{attention.length}</Badge> : undefined}>
          {attention.length === 0 ? (
            <EmptyState compact icon={CheckCircle2} title="Nothing needs attention" description="No locked accounts, open invitations, expiring keys or failed webhook deliveries." />
          ) : (
            <ul className="divide-y divide-line">
              {attention.map((a) => (
                <li key={a.title} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5 text-small">
                  <span aria-hidden className={`flex size-[1.875rem] items-center justify-center rounded-[8px] ${a.tone === "warn" ? "bg-warn-soft text-warn" : "bg-contrast-soft-2 text-contrast-text"}`}>
                    <a.icon className="size-4" />
                  </span>
                  <span className="min-w-0">
                    <span className="block font-semibold text-ink">{a.title}</span>
                    {a.detail && <span className="block text-caption text-muted">{a.detail}</span>}
                  </span>
                  <Link href={a.href} className="inline-flex min-h-7 items-center rounded-[var(--radius)] border border-line-strong bg-paper px-2.5 text-caption font-medium text-ink no-underline hover:bg-ground">
                    {a.action}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Card
          title="Recent activity"
          padded={false}
          actions={
            <Link href={`/console/audit/?tenant=${encodeURIComponent(tenant)}`} className="text-small text-link no-underline hover:underline underline-offset-4">
              Audit log
            </Link>
          }
        >
          {s.recent.length === 0 ? (
            <EmptyState compact title="Nothing recorded yet" description="Sign-ins, changes and administrative actions appear here as they happen." />
          ) : (
            <ul className="divide-y divide-line">
              {s.recent.map((e) => (
                <li key={e.id} className="grid grid-cols-[1.375rem_minmax(0,1fr)_auto] items-start gap-2.5 px-4 py-2.5 text-small">
                  <Avatar name={e.actor ?? e.actor_type} size="sm" />
                  <span className="min-w-0">
                    <span className="font-semibold text-ink">{e.actor ?? e.actor_type}</span> <span className="text-muted">{describeEvent(e.name)}</span>
                    {e.subject && (
                      <>
                        {" "}
                        <Chip>{e.subject}</Chip>
                      </>
                    )}
                  </span>
                  <time dateTime={e.occurred_at} className="whitespace-nowrap font-mono text-caption text-muted">
                    {fmtWhen(e.occurred_at)}
                  </time>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Most authorized clients">
          {s.top_clients.length === 0 ? (
            <EmptyState compact title="No authorizations in this window" />
          ) : (
            <ol className="flex flex-col gap-2.5">
              {s.top_clients.map((c) => (
                <li key={c.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-2.5 gap-y-1 text-small">
                  <Link href={`/console/clients/?tenant=${encodeURIComponent(tenant)}&client=${c.id}`} className="truncate text-ink no-underline hover:underline underline-offset-4">
                    {c.name}
                  </Link>
                  <span className="font-mono text-caption text-muted">{fmtNumber(c.authorizations)}</span>
                  <span className="col-span-2 h-1.5 rounded-full bg-ground" aria-hidden>
                    <span className="block h-1.5 rounded-full bg-[var(--series-1)]" style={{ width: `${(c.authorizations / topMax) * 100}%` }} />
                  </span>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>
    </div>
  );
}

interface Delta {
  text: string;
  tone: "ok" | "danger" | "neutral";
}

/** "▲ 12% vs previous 30 days", with the tone of whether up is good. */
function delta(now: number, before: number, days: number, good: "up" | "down"): Delta | undefined {
  if (before === 0 && now === 0) return undefined;
  if (before === 0) return { text: `new vs previous ${days} days`, tone: "neutral" };
  const pct = Math.round(((now - before) / before) * 100);
  if (pct === 0) return { text: `same as previous ${days} days`, tone: "neutral" };
  const up = pct > 0;
  return { text: `${up ? "▲" : "▼"} ${Math.abs(pct)}% vs previous ${days} days`, tone: (up && good === "up") || (!up && good === "down") ? "ok" : "danger" };
}

function Tile({ label, value, sub, extra, tone, change, spark, sparkColor = "var(--series-1)" }: { label: string; value: number | string; sub?: string; extra?: string; tone?: "warn"; change?: Delta; spark?: number[]; sparkColor?: string }) {
  return (
    <div className={`grid grid-cols-[minmax(0,1fr)_auto] items-end gap-2 overflow-hidden rounded-[var(--radius)] border px-4 pb-3 pt-3.5 ${tone === "warn" ? "border-warn bg-[linear-gradient(180deg,var(--warn-soft),var(--paper))]" : "border-line bg-paper"}`}>
      <div className="min-w-0">
        <p className="text-caption font-medium text-muted">{label}</p>
        <p className="font-display mt-1 text-num font-semibold leading-[1.1] tracking-[-0.03em] text-ink tabular-nums">{typeof value === "number" ? fmtNumber(value) : value}</p>
        {(change || sub || extra) && (
          <p className={`mt-1.5 truncate font-mono text-caption leading-tight ${change?.tone === "ok" ? "text-ok" : change?.tone === "danger" ? "text-danger" : "text-muted"}`}>
            {change?.text ?? sub}
            {extra ? ` · ${extra}` : ""}
          </p>
        )}
      </div>
      {spark && spark.length > 1 && <Sparkline values={spark} color={sparkColor} />}
    </div>
  );
}

/** A small line with a soft fill under it; decoration for a number the tile already states. */
function Sparkline({ values, color }: { values: number[]; color: string }): ReactNode {
  const w = 92;
  const h = 34;
  const max = Math.max(1, ...values);
  const step = w / (values.length - 1);
  const points = values.map((v, i) => `${(i * step).toFixed(1)} ${(h - 3 - (v / max) * (h - 6)).toFixed(1)}`);
  const line = `M${points.join(" L")}`;
  return (
    <svg className="hidden h-[34px] w-[84px] shrink-0 sm:block" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden>
      <path d={`${line} V${h} H0 Z`} fill={color} opacity="0.12" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

const EVENT_WORDS: Record<string, string> = {
  "login.succeeded": "signed in",
  "login.failed": "failed to sign in",
  "login.locked": "was locked after failed attempts",
  "user.created": "created a user",
  "user.updated": "updated a user",
  "user.deleted": "deleted a user",
  "user.unlocked": "unlocked",
  "user.invited": "invited",
  "authorization.granted": "authorized",
  "consent.granted": "granted consent to",
  "client.created": "created a client",
  "client.updated": "updated a client",
  "client.deleted": "deleted a client",
  "client.secret_rotated": "rotated the secret of",
  "signing_key.rotated": "rotated the signing key",
  "tenant.updated": "changed the tenant settings",
  "session.revoked": "ended a session of",
};

/** "user.created" → "created a user", or the name's words when unknown. */
function describeEvent(name: string): string {
  return EVENT_WORDS[name] ?? name.replace(/[._]/g, " ");
}
