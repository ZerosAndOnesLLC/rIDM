/**
 * A tenant's appearance, as the public branding document carries it, applied
 * to the page: the colour ramps (src/lib/theme/ramp.ts), the skin attribute,
 * and the light/dark policy the theme provider enforces.
 *
 * The policy lives in a small external store so the provider can combine it
 * with the person's own choice: the person's choice wins only when the tenant
 * allows switching; otherwise the tenant's mode applies, and "system" means
 * no `data-theme` at all (the stylesheet follows the device).
 *
 * The skin and policy are also cached per tenant in localStorage so the root
 * layout's boot script can apply them before the first paint.
 */
import { applyTheme, clearTheme, deriveContrast, isHex, type ThemePair } from "./ramp";

export type Skin = "signal-v2" | "signal" | "vault" | "registry";
export type ThemeMode = "system" | "light" | "dark";
/** What a person may store for themselves. */
export type Theme = ThemeMode;

export const SKINS: readonly { id: Skin; name: string; blurb: string }[] = [
  { id: "signal-v2", name: "Signal v2", blurb: "Dark command bar, tinted ground, the page as a sheet." },
  { id: "signal", name: "Signal", blurb: "Light command bar, dense lists." },
  { id: "vault", name: "Vault", blurb: "Dark navigation rail, quiet ground." },
  { id: "registry", name: "Registry", blurb: "Text-only sidebar, serif titles, hairline tables." },
];

export interface Appearance {
  primary_color: string | null;
  contrast_color: string | null;
  skin: Skin;
  mode: ThemeMode;
  allow_theme_switch: boolean;
}

export interface Policy {
  mode: ThemeMode;
  allowSwitch: boolean;
}

export const DEFAULT_POLICY: Policy = { mode: "system", allowSwitch: true };
export const DEFAULT_SKIN: Skin = "signal-v2";

const CACHE_PREFIX = "ridm.appearance:";

export function isSkin(v: unknown): v is Skin {
  return SKINS.some((s) => s.id === v);
}

// ---- policy store ------------------------------------------------------------------

let policy: Policy = DEFAULT_POLICY;
const listeners = new Set<() => void>();

export function getPolicy(): Policy {
  return policy;
}

export function setPolicy(next: Policy): void {
  if (next.mode === policy.mode && next.allowSwitch === policy.allowSwitch) return;
  policy = next;
  listeners.forEach((l) => l());
}

export function subscribePolicy(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

// ---- skin store ---------------------------------------------------------------------
// The shell reads the skin for its structural switches (chrome variant, icons,
// filters); the stylesheet reads `data-skin` for everything tokens can do.

let skin: Skin = DEFAULT_SKIN;
const skinListeners = new Set<() => void>();

export function getSkin(): Skin {
  return skin;
}

export function setSkin(next: Skin): void {
  if (next === skin) return;
  skin = next;
  skinListeners.forEach((l) => l());
}

export function subscribeSkin(cb: () => void): () => void {
  skinListeners.add(cb);
  return () => {
    skinListeners.delete(cb);
  };
}

/** The `data-theme` value for a person's choice under a policy; null means follow the device. */
export function effectiveTheme(user: Theme, p: Policy): "light" | "dark" | null {
  const chosen = p.allowSwitch && user !== "system" ? user : p.mode;
  return chosen === "system" ? null : chosen;
}

// ---- colours --------------------------------------------------------------------------

/** Accept only CSS colour literals, never arbitrary values. */
export function isCssColor(v: string): boolean {
  return /^(#[0-9a-f]{3,8}|(rgb|hsl|oklch|oklab|color)\([^;{}()<>"'\\]*\))$/i.test(v.trim());
}

/** The theme pair a tenant's colours produce, or null when the primary is not hex. */
export function pairOf(a: Pick<Appearance, "primary_color" | "contrast_color">): ThemePair | null {
  if (!a.primary_color || !isHex(a.primary_color)) return null;
  const primary = a.primary_color.trim();
  const contrast = a.contrast_color && isHex(a.contrast_color) ? a.contrast_color.trim() : deriveContrast(primary);
  return { primary, contrast };
}

// ---- apply ------------------------------------------------------------------------------

/**
 * Applies a tenant's appearance to the root element. `slug` names the tenant
 * to cache it for; leave it out for drafts (the branding preview), which must
 * not overwrite what the boot script will restore.
 */
export function applyAppearance(root: HTMLElement, a: Appearance, slug?: string): void {
  clearTheme(root);
  const pair = pairOf(a);
  if (pair) applyTheme(root, pair);
  else if (a.primary_color && isCssColor(a.primary_color)) root.style.setProperty("--accent", a.primary_color);
  root.dataset.skin = a.skin;
  setSkin(a.skin);
  setPolicy({ mode: a.mode, allowSwitch: a.allow_theme_switch });
  if (slug) {
    try {
      localStorage.setItem(`${CACHE_PREFIX}${slug}`, JSON.stringify({ skin: a.skin, mode: a.mode, allow: a.allow_theme_switch }));
    } catch {
      // Storage blocked: the next load starts from the defaults until the document arrives.
    }
  }
}

/** Back to the stylesheet defaults (leaving a tenant's pages). */
export function resetAppearance(root: HTMLElement): void {
  clearTheme(root);
  root.style.removeProperty("--accent");
  delete root.dataset.skin;
  setSkin(DEFAULT_SKIN);
  setPolicy(DEFAULT_POLICY);
}

/** The cached skin for the tenant named in the page's query string, for the first render. */
export function cachedSkin(): Skin {
  try {
    const slug = new URLSearchParams(window.location.search).get("tenant");
    if (!slug) return DEFAULT_SKIN;
    const raw = localStorage.getItem(`${CACHE_PREFIX}${slug}`);
    if (!raw) return DEFAULT_SKIN;
    const c = JSON.parse(raw) as { skin?: unknown };
    return isSkin(c.skin) ? c.skin : DEFAULT_SKIN;
  } catch {
    return DEFAULT_SKIN;
  }
}

/** The cached policy for the tenant named in the page's query string, for the first render. */
export function cachedPolicy(): Policy {
  try {
    const slug = new URLSearchParams(window.location.search).get("tenant");
    if (!slug) return DEFAULT_POLICY;
    const raw = localStorage.getItem(`${CACHE_PREFIX}${slug}`);
    if (!raw) return DEFAULT_POLICY;
    const c = JSON.parse(raw) as { mode?: ThemeMode; allow?: boolean };
    return { mode: c.mode === "light" || c.mode === "dark" ? c.mode : "system", allowSwitch: c.allow !== false };
  } catch {
    return DEFAULT_POLICY;
  }
}
