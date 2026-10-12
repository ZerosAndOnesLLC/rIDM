// Mock controls. Tenant theme (preset or custom pair) + mode policy live in
// localStorage so every open mock and the index iframes follow the same state.
//   mock.theme.preset   indigo|ocean|...|custom
//   mock.theme.primary / mock.theme.contrast  (custom hexes)
//   mock.mode.policy    system|light|dark      (tenant default)
//   mock.mode.user      ""|light|dark          (the person's own switch, if allowed)
//   mock.mode.allow     "1"|"0"
(function () {
  const root = document.documentElement;
  const get = (k, d) => localStorage.getItem("mock." + k) ?? d;
  function tenantTheme() {
    // a page may pin its own tenant (the Acme sign-in); else the shared choice
    if (root.dataset.tenantAccent) return { primary: root.dataset.tenantAccent, contrast: root.dataset.tenantContrast || "#334e68" };
    const id = get("theme.preset", "indigo");
    if (id === "custom") return { primary: get("theme.primary", "#3451b2"), contrast: get("theme.contrast", "#b45309") };
    return THEME.PRESETS.find((p) => p.id === id) || THEME.PRESETS[0];
  }
  function mode() {
    const policy = get("mode.policy", "system"), allow = get("mode.allow", "1") === "1", user = get("mode.user", "");
    const chosen = allow && user ? user : policy;
    if (chosen === "system") return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    return chosen;
  }
  function apply() {
    const m = mode();
    root.dataset.theme = m;
    THEME.apply(root, tenantTheme(), m === "dark");
    document.dispatchEvent(new CustomEvent("mock:theme"));
  }
  apply();
  addEventListener("storage", apply);
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", apply);
  window.MOCKCTL = { get, set: (k, v) => { localStorage.setItem("mock." + k, v); apply(); }, apply, tenantTheme, mode };
  if (new URLSearchParams(location.search).has("bare")) return;
  const bar = document.createElement("div");
  bar.className = "mockbar";
  function draw() {
    const allow = get("mode.allow", "1") === "1";
    bar.innerHTML = `<span>Tenant theme</span>${THEME.PRESETS.map((p) => `<button data-k="theme.preset" data-v="${p.id}" class="${get("theme.preset", "indigo") === p.id ? "on" : ""}"><i style="background:${p.primary}"></i><i style="background:${p.contrast}"></i>${p.name.split(" ")[0]}</button>`).join("")}
      <span>Mode</span>${["system", "light", "dark"].map((v) => `<button data-k="mode.policy" data-v="${v}" class="${get("mode.policy", "system") === v ? "on" : ""}">${v}</button>`).join("")}
      <span>Person</span>${allow ? ["", "light", "dark"].map((v) => `<button data-k="mode.user" data-v="${v}" class="${get("mode.user", "") === v ? "on" : ""}">${v || "default"}</button>`).join("") : "<em>switch off</em>"}
      <a href="../index.html">All mocks</a>`;
  }
  bar.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; MOCKCTL.set(b.dataset.k, b.dataset.v); draw(); });
  document.addEventListener("DOMContentLoaded", () => { draw(); document.body.appendChild(bar); });
})();
