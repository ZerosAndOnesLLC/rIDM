// Signal v2 chrome: injects the command bar + sidebar around the page's <main>,
// renders the nav with counts, and provides avatar gradients + the users rows.
(function () {
  const M = window.MOCK, I = M.icon;
  const COUNTS = { Users: "120", Groups: "9", Clients: "6", Tenants: "3", Webhooks: "2", "Signing keys": "2", "Identity providers": "1" };
  const HOT = { Users: "3 pending" };
  const page = document.body.dataset.page || "Users";
  const crumbs = document.body.dataset.crumbs || "";
  const content = document.querySelector("main");
  const frame = document.createElement("div"); frame.className = "frame";
  frame.innerHTML = `
  <div class="top">
    <div class="brand"><button class="btn icon quiet burger" aria-label="Menu">${I("menu")}</button><i>${I("shield")}</i><span>rIDM</span></div>
    <div class="cmd">
      <button class="tenant" aria-label="Tenant: Acme Corporation"><span class="glyph">A</span><b>Acme Corporation</b><small>acme</small>${I("updown")}</button>
      <button class="search">${I("search")}<span>Search users, clients, pages… or type <b>&gt;</b> for a command</span><kbd>⌘K</kbd></button>
    </div>
    <div class="tools">
      <div class="seg" role="group" aria-label="Theme" id="userSeg"><button data-v="" aria-label="Tenant default">${I("monitor")}</button><button data-v="light" aria-label="Light">${I("sun")}</button><button data-v="dark" aria-label="Dark">${I("moon")}</button></div>
      <button class="bell" aria-label="3 things need attention">${I("warn")}</button>
      <div class="me" title="admin · Global administrator"><span class="av">A</span></div>
    </div>
  </div>
  <aside class="rail"><nav class="nav" aria-label="Console">${M.nav.map((g) => `${g.group ? `<h6>${g.group}</h6>` : ""}${g.items.map(([label, key, icon]) => `<a href="${label === "Users" ? "users" : label === "Overview" ? "overview" : "#"}" ${label === page ? 'aria-current="page"' : ""}>${I(icon)}<span>${label}</span>${HOT[label] ? `<span class="n hot">${HOT[label]}</span>` : COUNTS[label] ? `<span class="n">${COUNTS[label]}</span>` : `<kbd>g ${key}</kbd>`}</a>`).join("")}`).join("")}</nav></aside>
  <div class="content"><div class="sheet">${crumbs ? `<nav class="crumbs" aria-label="Breadcrumb">${crumbs.split(" > ").map((c, i, a) => i < a.length - 1 ? `<a href="#">${c}</a>${I("chev")}` : `<span class="here">${c}</span>`).join("")}</nav>` : ""}</div></div>`;
  frame.querySelector(".sheet").appendChild(content);
  document.body.prepend(frame);
  // person's own mode switch, hidden when the tenant forbids it
  const seg = frame.querySelector("#userSeg"), bs = [...seg.querySelectorAll("button")];
  function d() { seg.hidden = MOCKCTL.get("mode.allow", "1") !== "1"; bs.forEach((b) => b.setAttribute("aria-pressed", b.dataset.v === MOCKCTL.get("mode.user", ""))); }
  bs.forEach((b) => (b.onclick = () => { MOCKCTL.set("mode.user", b.dataset.v); d(); })); d(); document.addEventListener("mock:theme", d);
  // avatar gradients from the tenant ramps
  const G = [["--accent-400", "--accent-700"], ["--contrast-500", "--contrast-solid-hover"], ["--accent-600", "--accent-900"], ["--accent-500", "--contrast-500"]];
  window.avatar = (name, cls = "av") => { const h = [...name].reduce((a, c) => a + c.charCodeAt(0), 0) % G.length; const [a, b] = G[h]; const ini = name.split(/[._-]/).map((p) => p[0]).join("").slice(0, 2).toUpperCase(); return `<span class="${cls}" style="background:linear-gradient(135deg,var(${a}),var(${b}))">${ini}</span>`; };
  window.MFA = ["ada.lovelace", "alan.hopper", "barbara.hamilton", "claude.turing", "ada.dijkstra", "claude.shannon"];
  window.TOTP = ["ada.liskov", "alan.backus", "barbara.diffie", "claude.knuth"];
  document.querySelectorAll("[data-icon]").forEach((el) => { el.innerHTML = I(el.dataset.icon); });
  const rows = document.querySelector("[data-rows]");
  if (rows) rows.innerHTML = M.users.map(([u, e, s, v, last, dept]) => window.ROW(u, e, s, v, last, dept)).join("");
})();
