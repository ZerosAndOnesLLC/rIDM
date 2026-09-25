// Copy buttons and the cycling tenant slug. No dependencies.
(function () {
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Copy buttons: copy the commands of the block named by data-copy, without
  // the prompts and comment lines.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target || !navigator.clipboard) { btn.hidden = true; return; }
    var label = btn.querySelector("span");
    var original = label ? label.textContent : "";
    btn.addEventListener("click", function () {
      var text = target.textContent.split("\n")
        .filter(function (line) { return !/^\s*#/.test(line); })
        .map(function (line) { return line.replace(/^\$\s?/, ""); })
        .join("\n").trim();
      navigator.clipboard.writeText(text).then(function () {
        if (label) label.textContent = "Copied";
        setTimeout(function () { if (label) label.textContent = original; }, 1600);
      });
    });
  });

  // The tenant slug in the token card and the issuer line cycle through a few
  // tenants in step, unless the visitor prefers reduced motion.
  var slug = document.querySelector("[data-slugs]");
  var echo = document.querySelector(".slug2");
  if (slug && !reduce) {
    var slugs = slug.getAttribute("data-slugs").split(",");
    var i = 0;
    setInterval(function () {
      i = (i + 1) % slugs.length;
      slug.textContent = slugs[i];
      if (echo) echo.textContent = slugs[i];
    }, 2600);
  }
})();
