// Renders the shared console chrome (rail/sidebar, nav) and the users rows into
// each direction's markup. Each page sets data-page and a row template.
(function () {
  const M = window.MOCK;
  const page = document.body.dataset.page || "Users";
  const navEl = document.querySelector("[data-nav]");
  if (navEl) {
    navEl.innerHTML = M.nav.map((g) => `${g.group ? `<h6>${g.group}</h6>` : ""}${g.items.map(([label, key, icon]) => `<a href="#" ${label === page || (page.startsWith("Users") && label === "Users") ? 'aria-current="page"' : ""}>${M.icon(icon)}<span>${label}</span><kbd>g ${key}</kbd></a>`).join("")}`).join("");
  }
  const rows = document.querySelector("[data-rows]");
  if (rows) {
    const tpl = rows.dataset.rows; // "a" | "b" | "c"
    rows.innerHTML = M.users.map(([u, e, s, v, last, dept]) => window.ROW(u, e, s, v, last, dept)).join("");
  }
})();
