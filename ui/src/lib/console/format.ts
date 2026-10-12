import { formatDate, formatNumber } from "@/i18n";

/**
 * The console's date and number formatting in one place. The console is
 * English-only (its strings are not translated), so every call that used to
 * say `formatDate("en", …)` goes through here, and a locale switch later is
 * one change.
 */
const LOCALE = "en";

/** `Oct 10, 2026, 8:02 AM` */
export function fmtDateTime(value: Date | string | number): string {
  return formatDate(LOCALE, value);
}

/** `Oct 10, 2026` */
export function fmtDate(value: Date | string | number): string {
  return formatDate(LOCALE, value, { dateStyle: "medium" });
}

/** `8:02 AM` */
export function fmtTime(value: Date | string | number): string {
  return formatDate(LOCALE, value, { timeStyle: "short" });
}

export function fmtNumber(value: number, opts?: Intl.NumberFormatOptions): string {
  return formatNumber(LOCALE, value, opts);
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * "2 min ago", "Yesterday", "Oct 3": a time as a list row shows it. Within
 * a day it is relative, within a week a weekday word, otherwise a date.
 */
export function fmtWhen(value: Date | string | number, now: number = Date.now()): string {
  const d = value instanceof Date ? value : new Date(value);
  const diff = now - d.getTime();
  if (diff < 0) return fmtDateTime(d);
  if (diff < MINUTE) return "Just now";
  if (diff < HOUR) return `${Math.floor(diff / MINUTE)} min ago`;
  if (diff < DAY && new Date(now).getDate() === d.getDate()) return `Today, ${fmtTime(d)}`;
  if (diff < 2 * DAY) return `Yesterday, ${fmtTime(d)}`;
  if (diff < 7 * DAY) return new Intl.DateTimeFormat(LOCALE, { weekday: "long" }).format(d);
  if (new Date(now).getFullYear() === d.getFullYear()) return new Intl.DateTimeFormat(LOCALE, { month: "short", day: "numeric" }).format(d);
  return fmtDate(d);
}

/** True within the last two days: a list row marks these as fresh. */
export function isFresh(value: Date | string | number | null | undefined, now: number = Date.now()): boolean {
  if (!value) return false;
  const t = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return now - t < 2 * DAY;
}

/** "In 12 days", "3 days ago", "Today": distance to a date, for expiries. */
export function fmtDistance(value: Date | string | number, now: number = Date.now()): string {
  const d = value instanceof Date ? value : new Date(value);
  const days = Math.round((d.getTime() - now) / DAY);
  if (days === 0) return "Today";
  if (days === 1) return "Tomorrow";
  if (days === -1) return "Yesterday";
  return days > 0 ? `In ${days} days` : `${-days} days ago`;
}

/** The letters a name's avatar shows: "ada.lovelace" → "AL", "Acme" → "A". */
export function initials(name: string): string {
  const parts = name.split(/[\s._\-@]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0]!.slice(0, 1).toUpperCase();
  return (parts[0]!.slice(0, 1) + parts[1]!.slice(0, 1)).toUpperCase();
}

/**
 * One of four gradients from the tenant ramps, chosen by the name so the
 * same person always gets the same one.
 */
export function avatarGradient(name: string): string {
  const pairs = [
    ["var(--accent-400)", "var(--accent-700)"],
    ["var(--contrast-500)", "var(--contrast-solid-hover)"],
    ["var(--accent-600)", "var(--accent-900)"],
    ["var(--accent-500)", "var(--contrast-500)"],
  ];
  let h = 0;
  for (const ch of name) h = (h + ch.charCodeAt(0)) % pairs.length;
  const [a, b] = pairs[h]!;
  return `linear-gradient(135deg, ${a}, ${b})`;
}
