// Tenant theme engine (mock of what ui/src/lib/tenant.tsx would do at load):
// one primary hex + one contrast hex -> two OKLCH tonal ramps -> semantic CSS
// variables for the current mode. Plain hex output, so it works in any browser
// and the ratios can be checked. No dependency on CSS relative-color syntax.
(function () {
  // ---- sRGB <-> OKLCH -------------------------------------------------------
  const lin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  const gam = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);
  function hexToRgb(h) { h = h.replace("#", ""); if (h.length === 3) h = h.split("").map((x) => x + x).join(""); const n = parseInt(h, 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => v / 255); }
  function rgbToHex([r, g, b]) { return "#" + [r, g, b].map((v) => Math.round(Math.min(1, Math.max(0, v)) * 255).toString(16).padStart(2, "0")).join(""); }
  function rgbToOklab([r, g, b]) {
    const [R, G, B] = [lin(r), lin(g), lin(b)];
    const l = Math.cbrt(0.4122214708 * R + 0.5363325363 * G + 0.0514459929 * B);
    const m = Math.cbrt(0.2119034982 * R + 0.6806995451 * G + 0.1073969566 * B);
    const s = Math.cbrt(0.0883024619 * R + 0.2817188376 * G + 0.6299787005 * B);
    return [0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s, 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s, 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s];
  }
  function oklabToRgb([L, a, b]) {
    const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3, m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3, s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
    return [gam(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s), gam(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s), gam(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s)];
  }
  function hexToOklch(h) { const [L, a, b] = rgbToOklab(hexToRgb(h)); return { L, C: Math.hypot(a, b), h: (Math.atan2(b, a) * 180) / Math.PI }; }
  function oklchToHex({ L, C, h }) {
    // clamp chroma into gamut by stepping down until the rgb is in range
    for (let c = C; c >= 0; c -= 0.005) {
      const rgb = oklabToRgb([L, c * Math.cos((h * Math.PI) / 180), c * Math.sin((h * Math.PI) / 180)]);
      if (rgb.every((v) => v >= -0.001 && v <= 1.001)) return rgbToHex(rgb);
    }
    return rgbToHex(oklabToRgb([L, 0, 0]));
  }
  // ---- ramp -------------------------------------------------------------------
  // 50..900: fixed lightness steps so every hue lands on the same rhythm; chroma
  // tapers toward the ends so pastels and deep shades stay in gamut.
  const STEPS = [[50, 0.975, 0.25], [100, 0.94, 0.4], [200, 0.88, 0.6], [300, 0.80, 0.8], [400, 0.70, 0.95], [500, 0.60, 1], [600, 0.50, 1], [700, 0.43, 0.95], [800, 0.36, 0.85], [900, 0.28, 0.7]];
  function ramp(hex) { const { C, h } = hexToOklch(hex); const Cn = Math.max(C, 0.06); const out = {}; for (const [k, L, f] of STEPS) out[k] = oklchToHex({ L, C: Cn * f, h }); return out; }
  // ---- contrast ----------------------------------------------------------------
  function lum(hex) { const [r, g, b] = hexToRgb(hex).map(lin); return 0.2126 * r + 0.7152 * g + 0.0722 * b; }
  function ratio(a, b) { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); }
  // ---- semantic slots ------------------------------------------------------------
  // Same slot names in both modes; the ramp step behind each one flips.
  function slots(hex, dark) {
    const r = typeof hex === "string" ? ramp(hex) : hex;
    if (!dark) return { soft: r[50], soft2: r[100], border: r[300], ring: r[500], solid: r[600], solidHover: r[700], text: r[700], ink: "#ffffff" };
    // dark: soft fills are tinted surfaces, not deep saturated shades
    const { C, h } = hexToOklch(r[500]);
    return { soft: oklchToHex({ L: 0.23, C: C * 0.3, h }), soft2: oklchToHex({ L: 0.3, C: C * 0.4, h }), border: r[700], ring: r[400], solid: r[600], solidHover: r[500], text: r[300], ink: "#ffffff" };
  }
  function apply(root, { primary, contrast }, dark) {
    for (const [name, hex] of [["accent", primary], ["contrast", contrast]]) {
      const r = ramp(hex), s = slots(r, dark);
      for (const k in r) root.style.setProperty(`--${name}-${k}`, r[k]);
      for (const k in s) root.style.setProperty(`--${name}-${k.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase()).replace(/(\d)$/, "-$1")}`, s[k]);
      root.style.setProperty(`--${name}`, hex);
    }
  }
  const PRESETS = [
    { id: "indigo", name: "Indigo & amber", primary: "#3451b2", contrast: "#b45309" },
    { id: "ocean", name: "Ocean & coral", primary: "#0f766e", contrast: "#c2410c" },
    { id: "forest", name: "Forest & ochre", primary: "#2f6b3a", contrast: "#a16207" },
    { id: "ember", name: "Ember & slate", primary: "#b8431e", contrast: "#334e68" },
    { id: "plum", name: "Plum & lime", primary: "#6d28d9", contrast: "#4d7c0f" },
    { id: "graphite", name: "Graphite & sky", primary: "#3b4252", contrast: "#0369a1" },
  ];
  window.THEME = { ramp, ratio, slots, apply, PRESETS, hexToOklch, oklchToHex };
})();
