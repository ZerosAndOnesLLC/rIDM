// Translation bundles for the end-user pages. English ships; other locales
// are loaded from `./<locale>.json` and fall back to English key by key.
//
// Layout must stay RTL-safe: use logical Tailwind utilities (`ps-`, `pe-`,
// `ms-`, `me-`, `start-`, `end-`, `text-start`) instead of left/right ones,
// and let `dir()` set the document direction.

import en from "./en.json";

export type MessageKey = keyof typeof en;
export type Bundle = Partial<Record<MessageKey, string>>;
export type Params = Record<string, string | number>;

export const DEFAULT_LOCALE = "en";

/** Bundles compiled into the app, keyed by normalized tag. */
export const bundles: Record<string, Bundle> = { en };

/** Languages written right to left (BCP 47 primary subtags). */
const RTL = new Set([
  "ar", "arc", "ckb", "dv", "fa", "he", "iw", "ks", "ku", "pa", "ps", "sd", "ug", "ur", "yi",
]);

/** `pt_BR` / ` PT-br ` → `pt-BR`; `null` for malformed tags. */
export function normalize(tag: string | null | undefined): string | null {
  const raw = (tag ?? "").trim().replace(/_/g, "-");
  if (!raw || raw.length > 35) return null;
  const parts = raw.split("-");
  const out: string[] = [];
  for (const [i, part] of parts.entries()) {
    if (!part || part.length > 8 || !/^[a-z0-9]+$/i.test(part)) return null;
    if (i === 0) out.push(part.toLowerCase());
    else if (part.length === 2) out.push(part.toUpperCase());
    else if (part.length === 4) out.push(part[0]!.toUpperCase() + part.slice(1).toLowerCase());
    else out.push(part.toLowerCase());
  }
  return out.join("-");
}

function language(tag: string): string {
  return tag.split("-")[0]!.toLowerCase();
}

/** Best available locale for one candidate: exact, else same language. */
function resolve(candidate: string, available: readonly string[]): string | null {
  const c = normalize(candidate);
  if (!c) return null;
  const exact = available.find((a) => a.toLowerCase() === c.toLowerCase());
  if (exact) return exact;
  const lang = language(c);
  return available.find((a) => language(a) === lang) ?? null;
}

/**
 * Pick a locale from candidates in preference order (the server's negotiated
 * `locale` first, then `navigator.languages`), constrained to `available`.
 */
export function negotiate(
  requested: readonly (string | null | undefined)[],
  available: readonly string[] = Object.keys(bundles),
): string {
  for (const r of requested) {
    if (!r) continue;
    const hit = resolve(r, available);
    if (hit) return hit;
  }
  return available.includes(DEFAULT_LOCALE) ? DEFAULT_LOCALE : (available[0] ?? DEFAULT_LOCALE);
}

export function isRtl(locale: string): boolean {
  return RTL.has(language(locale));
}

export function dir(locale: string): "ltr" | "rtl" {
  return isRtl(locale) ? "rtl" : "ltr";
}

/** Bundle lookup chain: `de-CH` → `de` → English. */
function chain(locale: string): Bundle[] {
  const out: Bundle[] = [];
  const exact = bundles[locale];
  if (exact) out.push(exact);
  const lang = language(locale);
  if (lang !== locale && bundles[lang]) out.push(bundles[lang]);
  if (lang !== DEFAULT_LOCALE) out.push(bundles[DEFAULT_LOCALE] ?? {});
  return out;
}

function lookup(locale: string, key: string): string | undefined {
  for (const b of chain(locale)) {
    const v = (b as Record<string, string | undefined>)[key];
    if (v !== undefined) return v;
  }
  return undefined;
}

function interpolate(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (m, name: string) =>
    name in params ? String(params[name]) : m,
  );
}

/**
 * Translate `key`, interpolating `{name}` placeholders. When `params.count`
 * is set, `<key>_one` / `<key>_other` (or any CLDR category) is chosen with
 * `Intl.PluralRules`; a missing key returns the key itself so gaps are visible.
 */
export function translate(locale: string, key: MessageKey | string, params?: Params): string {
  let template: string | undefined;
  if (params && typeof params.count === "number") {
    const category = pluralRules(locale).select(params.count);
    template = lookup(locale, `${key}_${category}`) ?? lookup(locale, `${key}_other`);
  }
  template ??= lookup(locale, key);
  return template === undefined ? key : interpolate(template, params);
}

const pluralCache = new Map<string, Intl.PluralRules>();
function pluralRules(locale: string): Intl.PluralRules {
  let r = pluralCache.get(locale);
  if (!r) {
    try {
      r = new Intl.PluralRules(locale);
    } catch {
      r = new Intl.PluralRules(DEFAULT_LOCALE);
    }
    pluralCache.set(locale, r);
  }
  return r;
}

export function formatDate(locale: string, value: Date | string | number, opts?: Intl.DateTimeFormatOptions): string {
  const d = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat(locale, opts ?? { dateStyle: "medium", timeStyle: "short" }).format(d);
}

export function formatNumber(locale: string, value: number, opts?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(locale, opts).format(value);
}

/** Native display name of a locale, for a language switcher. */
export function displayName(locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: "language" }).of(locale) ?? locale;
  } catch {
    return locale;
  }
}
