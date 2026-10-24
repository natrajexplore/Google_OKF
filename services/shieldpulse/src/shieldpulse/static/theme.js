// Loaded synchronously in <head>, so a saved theme applies before first paint (no flash).
// Storage can be unavailable (private mode, blocked site data); the OS setting is the fallback.
(function () {
  try {
    var saved = localStorage.getItem("sp-theme");
    if (saved === "light" || saved === "dark") document.documentElement.setAttribute("data-theme", saved);
  } catch (e) { /* use prefers-color-scheme */ }
})();
