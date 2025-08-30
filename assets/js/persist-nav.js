(function () {
  const KEY = "mkdocs.nav.expanded";
  function loadSet() {
    try { return new Set(JSON.parse(localStorage.getItem(KEY) || "[]")); }
    catch { return new Set(); }
  }
  function saveSet(set) {
    localStorage.setItem(KEY, JSON.stringify([...set]));
  }
  function init() {
    const expanded = loadSet();
    document.querySelectorAll(".md-nav__item--nested > input.md-nav__toggle")
      .forEach((toggle) => {
        const label = toggle.nextElementSibling; // .md-nav__link
        const key = (label?.textContent || "").trim();
        if (!key) return;
        toggle.checked = expanded.has(key);
        toggle.addEventListener("change", () => {
          const s = loadSet();
          if (toggle.checked) s.add(key);
          else s.delete(key);
          saveSet(s);
        });
      });
  }
  if (window.document$) {
    document$.subscribe(init);
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
