// Theme toggle, copy buttons and the hero's issuer line. No dependencies.
(function () {
  var root = document.documentElement;

  // Theme: the stored choice wins, otherwise prefers-color-scheme (pure CSS).
  try {
    var stored = localStorage.getItem("ridm-theme");
    if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);
  } catch (e) {}

  var toggle = document.querySelector("[data-theme-toggle]");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var current = root.getAttribute("data-theme");
      if (!current) {
        current = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      }
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("ridm-theme", next); } catch (e) {}
    });
  }

  // Copy buttons: copy the text of the block named by data-copy.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target || !navigator.clipboard) { btn.hidden = true; return; }
    var label = btn.querySelector("span");
    var original = label ? label.textContent : "";
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent.replace(/^\$ /gm, "").trim()).then(function () {
        if (label) label.textContent = "Copied";
        setTimeout(function () { if (label) label.textContent = original; }, 1600);
      });
    });
  });

  // Issuer line: cycle through a few tenant slugs once, then rest on the first.
  var slug = document.querySelector("[data-slugs]");
  if (slug && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    var slugs = slug.getAttribute("data-slugs").split(",");
    var caret = slug.nextElementSibling;
    var i = 1, delay = 1400;
    function show(n) {
      slug.textContent = slugs[n];
    }
    function step() {
      if (i >= slugs.length) {
        show(0);
        if (caret) caret.remove();
        return;
      }
      show(i);
      i += 1;
      setTimeout(step, delay);
    }
    setTimeout(step, delay);
  } else if (slug) {
    var c = slug.nextElementSibling;
    if (c) c.remove();
  }
})();
