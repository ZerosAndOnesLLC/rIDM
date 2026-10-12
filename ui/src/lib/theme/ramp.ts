/**
 * Tenant theme engine.
 *
 * A tenant picks two colours, a primary and a contrast. From each this module
 * derives a ten-step tonal ramp in OKLCH (fixed lightness steps, so every hue
 * lands on the same rhythm; chroma tapers at the ends and is clamped into sRGB)
 * and a set of semantic slots for light and dark mode. The slots are emitted as
 * CSS custom properties whose values are `light-dark(light, dark)`, so the
 * browser resolves the mode through `color-scheme` and nothing here needs to
 * know whether dark mode is on. Plain hex in, plain hex out: no dependency on
 * CSS relative-colour syntax, and the ratios can be checked in a test.
 *
 * `design/README.md` is the reference for the numbers.
 */

export interface Oklch {
  L: number;
  C: number;
  h: number;
}

export type Step = 50 | 100 | 200 | 300 | 400 | 500 | 600 | 700 | 800 | 900;
export type Ramp = Record<Step, string>;

export interface Slots {
  soft: string;
  "soft-2": string;
  border: string;
  ring: string;
  solid: string;
  "solid-hover": string;
  text: string;
  ink: string;
}

export interface ThemePair {
  primary: string;
  contrast: string;
}

export interface Preset extends ThemePair {
  id: string;
  name: string;
}

export const PRESETS: readonly Preset[] = [
  { id: "indigo", name: "Indigo & amber", primary: "#3451b2", contrast: "#b45309" },
  { id: "ocean", name: "Ocean & coral", primary: "#0f766e", contrast: "#c2410c" },
  { id: "forest", name: "Forest & ochre", primary: "#2f6b3a", contrast: "#a16207" },
  { id: "ember", name: "Ember & slate", primary: "#b8431e", contrast: "#334e68" },
  { id: "plum", name: "Plum & lime", primary: "#6d28d9", contrast: "#4d7c0f" },
  { id: "graphite", name: "Graphite & rose", primary: "#3b4252", contrast: "#be123c" },
];

export const DEFAULT_PAIR: ThemePair = { primary: PRESETS[0]!.primary, contrast: PRESETS[0]!.contrast };

// ---- sRGB <-> OKLCH ---------------------------------------------------------

const lin = (c: number): number => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const gam = (c: number): number => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);

const HEX_RE = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;

/** True for `#rgb` and `#rrggbb`; the only input this module accepts. */
export function isHex(v: string): boolean {
  return HEX_RE.test(v.trim());
}

function hexToRgb(hex: string): [number, number, number] {
  let h = hex.trim().replace("#", "");
  if (h.length === 3) h = h.split("").map((x) => x + x).join("");
  const n = parseInt(h, 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

function rgbToHex([r, g, b]: [number, number, number]): string {
  const c = (v: number) => Math.round(Math.min(1, Math.max(0, v)) * 255).toString(16).padStart(2, "0");
  return `#${c(r)}${c(g)}${c(b)}`;
}

function rgbToOklab([r, g, b]: [number, number, number]): [number, number, number] {
  const [R, G, B] = [lin(r), lin(g), lin(b)];
  const l = Math.cbrt(0.4122214708 * R + 0.5363325363 * G + 0.0514459929 * B);
  const m = Math.cbrt(0.2119034982 * R + 0.6806995451 * G + 0.1073969566 * B);
  const s = Math.cbrt(0.0883024619 * R + 0.2817188376 * G + 0.6299787005 * B);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

function oklabToRgb([L, a, b]: [number, number, number]): [number, number, number] {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    gam(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
    gam(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
    gam(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s),
  ];
}

export function hexToOklch(hex: string): Oklch {
  const [L, a, b] = rgbToOklab(hexToRgb(hex));
  return { L, C: Math.hypot(a, b), h: ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360 };
}

/** OKLCH to hex, stepping the chroma down until the colour is inside sRGB. */
export function oklchToHex({ L, C, h }: Oklch): string {
  const rad = (h * Math.PI) / 180;
  for (let c = C; c >= 0; c -= 0.005) {
    const rgb = oklabToRgb([L, c * Math.cos(rad), c * Math.sin(rad)]);
    if (rgb.every((v) => v >= -0.001 && v <= 1.001)) return rgbToHex(rgb);
  }
  return rgbToHex(oklabToRgb([L, 0, 0]));
}

// ---- ramp ---------------------------------------------------------------------

/** [step, lightness, chroma factor] */
const STEPS: readonly [Step, number, number][] = [
  [50, 0.975, 0.25],
  [100, 0.94, 0.4],
  [200, 0.88, 0.6],
  [300, 0.8, 0.8],
  [400, 0.7, 0.95],
  [500, 0.6, 1],
  [600, 0.5, 1],
  [700, 0.43, 0.95],
  [800, 0.36, 0.85],
  [900, 0.28, 0.7],
];

/** A colour's chroma is never taken below this, so greys still make a tinted ramp. */
const MIN_CHROMA = 0.06;

export function ramp(hex: string): Ramp {
  const { C, h } = hexToOklch(hex);
  const chroma = Math.max(C, MIN_CHROMA);
  const out = {} as Ramp;
  for (const [step, L, f] of STEPS) out[step] = oklchToHex({ L, C: chroma * f, h });
  return out;
}

// ---- semantic slots ---------------------------------------------------------------

/** The slots for one mode. Dark "soft" fills are tinted surfaces, not deep shades. */
export function slots(source: string | Ramp, dark: boolean): Slots {
  const r = typeof source === "string" ? ramp(source) : source;
  if (!dark) {
    return { soft: r[50], "soft-2": r[100], border: r[300], ring: r[500], solid: r[600], "solid-hover": r[700], text: r[700], ink: "#ffffff" };
  }
  const { C, h } = hexToOklch(r[500]);
  return {
    soft: oklchToHex({ L: 0.23, C: C * 0.3, h }),
    "soft-2": oklchToHex({ L: 0.3, C: C * 0.4, h }),
    border: r[700],
    ring: r[400],
    solid: r[600],
    "solid-hover": r[500],
    text: r[300],
    ink: "#ffffff",
  };
}

// ---- contrast -----------------------------------------------------------------------

function luminance(hex: string): number {
  const [r, g, b] = hexToRgb(hex).map(lin) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2 contrast ratio between two hex colours. */
export function ratio(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p) as [number, number];
  return (x + 0.05) / (y + 0.05);
}

/** Degrees between two hues, 0–180. */
export function hueDistance(a: string, b: string): number {
  const d = Math.abs(hexToOklch(a).h - hexToOklch(b).h) % 360;
  return d > 180 ? 360 - d : d;
}

/**
 * A contrast colour for tenants that only set a primary: the same lightness
 * and chroma, 150° around the hue circle, which lands indigo on amber, teal on
 * coral and so on.
 */
export function deriveContrast(primary: string): string {
  const { L, C, h } = hexToOklch(primary);
  return oklchToHex({ L: Math.min(Math.max(L, 0.4), 0.6), C: Math.max(C, 0.1), h: (h + 150) % 360 });
}

export interface Check {
  label: string;
  value: number;
  pass: boolean;
  /** "ratio" prints as n:1, "degrees" as n° */
  kind: "ratio" | "degrees";
}

/** The readability checks the Appearance page shows, for one mode's paper. */
export function checks(pair: ThemePair, dark: boolean, paper: string): Check[] {
  const a = slots(pair.primary, dark);
  const c = slots(pair.contrast, dark);
  const r = (label: string, x: string, y: string): Check => {
    const value = ratio(x, y);
    return { label, value, pass: value >= 4.5, kind: "ratio" };
  };
  const apart = hueDistance(pair.primary, pair.contrast);
  return [
    r("Primary text on page", a.text, paper),
    r("White on primary button", a.ink, a.solid),
    r("Contrast text on page", c.text, paper),
    r("Text on selected row", c.text, c.soft),
    { label: "Primary and contrast hues apart", value: apart, pass: apart >= 60, kind: "degrees" },
  ];
}

// ---- CSS -----------------------------------------------------------------------------

const SLOT_NAMES: readonly (keyof Slots)[] = ["soft", "soft-2", "border", "ring", "solid", "solid-hover", "text", "ink"];

/**
 * Every custom property the theme sets, for both colours: the ramp steps
 * (mode-independent) and the slots as `light-dark()` pairs. Keys carry the
 * leading `--`.
 */
export function themeVariables(pair: ThemePair): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, hex] of [
    ["accent", pair.primary],
    ["contrast", pair.contrast],
  ] as const) {
    const r = ramp(hex);
    const light = slots(r, false);
    const dark = slots(r, true);
    out[`--${name}`] = hex.trim().toLowerCase();
    for (const [step, value] of Object.entries(r)) out[`--${name}-${step}`] = value;
    for (const slot of SLOT_NAMES) out[`--${name}-${slot}`] = light[slot] === dark[slot] ? light[slot] : `light-dark(${light[slot]}, ${dark[slot]})`;
  }
  return out;
}

/** Writes the theme onto an element's inline style (the root, in practice). */
export function applyTheme(el: HTMLElement, pair: ThemePair): void {
  for (const [k, v] of Object.entries(themeVariables(pair))) el.style.setProperty(k, v);
}

/** Removes everything `applyTheme` set, so the stylesheet defaults apply again. */
export function clearTheme(el: HTMLElement): void {
  for (const k of Object.keys(themeVariables(DEFAULT_PAIR))) el.style.removeProperty(k);
}
