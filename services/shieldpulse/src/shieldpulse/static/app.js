// Progressive enhancement only: every page works without this file.
(function () {
  // Theme toggle: cycles to the opposite of what is currently shown and remembers it.
  var toggle = document.querySelector("[data-theme-toggle]");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme") ||
        (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("sp-theme", next); } catch (e) { /* not persisted */ }
      toggle.setAttribute("aria-label", "Switch to " + (next === "dark" ? "light" : "dark") + " theme");
    });
  }

  // Relative times ("5 min ago") next to the absolute UTC time the server rendered.
  var units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]];
  var rtf = window.Intl && Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }) : null;
  function relative(date) {
    var secs = (date.getTime() - Date.now()) / 1000;
    for (var i = 0; i < units.length; i++) {
      if (Math.abs(secs) >= units[i][1]) return rtf.format(Math.round(secs / units[i][1]), units[i][0]);
    }
    return "just now";
  }
  if (rtf) {
    document.querySelectorAll("time[datetime][data-relative]").forEach(function (el) {
      var date = new Date(el.getAttribute("datetime"));
      if (isNaN(date)) return;
      el.title = el.textContent.trim();
      el.textContent = relative(date);
    });
  }

  // Confirm before rejecting: a rejected rollback cannot be re-approved.
  document.querySelectorAll("button[data-confirm]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      if (!window.confirm(button.getAttribute("data-confirm"))) event.preventDefault();
    });
  });
})();
