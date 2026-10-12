import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_PAIR, PRESETS, checks, deriveContrast, hexToOklch, hueDistance, isHex, oklchToHex, ramp, ratio, slots, themeVariables } from "./ramp.ts";

const LIGHT_PAPER = "#ffffff";
const DARK_PAPER = "#15181f";

test("hex round-trips through OKLCH within one step per channel", () => {
  for (const hex of ["#3451b2", "#b45309", "#0f766e", "#000000", "#ffffff", "#808080"]) {
    const back = oklchToHex(hexToOklch(hex));
    const d = (i: number) => Math.abs(parseInt(hex.slice(i, i + 2), 16) - parseInt(back.slice(i, i + 2), 16));
    assert.ok(d(1) <= 1 && d(3) <= 1 && d(5) <= 1, `${hex} -> ${back}`);
  }
});

test("isHex accepts short and long forms only", () => {
  assert.ok(isHex("#abc") && isHex("#AABBCC") && isHex(" #123456 "));
  assert.ok(!isHex("abc") && !isHex("#abcd") && !isHex("rgb(1,2,3)") && !isHex("#12345g"));
});

test("a ramp gets lighter from 900 to 50 for every preset, and greys still tint", () => {
  for (const p of [...PRESETS.map((p) => p.primary), ...PRESETS.map((p) => p.contrast), "#777777"]) {
    const r = ramp(p);
    const L = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900].map((s) => hexToOklch(r[s as keyof typeof r]).L);
    for (let i = 1; i < L.length; i++) assert.ok(L[i]! < L[i - 1]!, `${p}: step ${i} not darker`);
    assert.ok(hexToOklch(r[500]).C > 0.03, `${p}: no chroma at 500`);
  }
});

test("every preset passes the readability checks in both modes", () => {
  for (const p of PRESETS) {
    for (const [dark, paper] of [
      [false, LIGHT_PAPER],
      [true, DARK_PAPER],
    ] as const) {
      for (const c of checks(p, dark, paper)) assert.ok(c.pass, `${p.id} ${dark ? "dark" : "light"}: ${c.label} = ${c.value.toFixed(2)}`);
    }
  }
});

test("solid buttons keep 4.5:1 with white text whatever the input lightness", () => {
  for (const hex of ["#ffeeaa", "#001133", "#00ff00", "#ff00ff"]) {
    for (const dark of [false, true]) {
      const s = slots(hex, dark);
      assert.ok(ratio(s.ink, s.solid) >= 4.5, `${hex} ${dark}: ${ratio(s.ink, s.solid).toFixed(2)}`);
    }
  }
});

test("deriveContrast lands far enough around the hue circle", () => {
  for (const p of PRESETS) {
    const c = deriveContrast(p.primary);
    assert.ok(hueDistance(p.primary, c) >= 60, `${p.id}: ${hueDistance(p.primary, c)}`);
    assert.ok(isHex(c));
  }
  // indigo's derived partner is in the amber region, like the preset
  const h = hexToOklch(deriveContrast("#3451b2")).h;
  assert.ok(h > 40 && h < 100, `indigo -> ${h}`);
});

test("themeVariables emits both ramps and light-dark() slots", () => {
  const v = themeVariables(DEFAULT_PAIR);
  assert.equal(v["--accent"], "#3451b2");
  assert.equal(v["--contrast"], "#b45309");
  assert.match(v["--accent-500"]!, /^#[0-9a-f]{6}$/);
  assert.match(v["--accent-soft"]!, /^light-dark\(#[0-9a-f]{6}, #[0-9a-f]{6}\)$/);
  assert.match(v["--contrast-text"]!, /^light-dark\(/);
  assert.equal(v["--accent-ink"], "#ffffff");
  assert.equal(Object.keys(v).length, 2 * (1 + 10 + 8));
});
