/**
 * Shared light/dark theme for ISPCENTRIC.
 * Storage key: ispcentric-theme. Attribute: data-theme on <html>.
 */
(function (global) {
  var KEY = "ispcentric-theme";
  var DARK_META = "#0a1118";
  var LIGHT_META = "#0e7c86";

  function current() {
    return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function apply(theme, btn) {
    var next = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem(KEY, next);
    } catch (e) {}
    var button = btn || document.getElementById("theme-toggle");
    if (button) {
      var label = next === "dark" ? "Switch to light mode" : "Switch to dark mode";
      button.setAttribute("aria-label", label);
      button.title = label;
    }
    try {
      var metas = document.querySelectorAll('meta[name="theme-color"]');
      var color = next === "dark" ? DARK_META : LIGHT_META;
      if (metas.length) {
        metas.forEach(function (m) {
          m.setAttribute("content", color);
        });
      }
    } catch (e) {}
    try {
      document.dispatchEvent(
        new CustomEvent("ispcentric:themechange", { detail: { theme: next } })
      );
    } catch (e) {}
    return next;
  }

  function toggle(btn) {
    return apply(current() === "dark" ? "light" : "dark", btn);
  }

  function bindToggle(btn) {
    var button = btn || document.getElementById("theme-toggle");
    if (!button || button.getAttribute("data-theme-bound") === "1") return button;
    button.setAttribute("data-theme-bound", "1");
    button.addEventListener("click", function () {
      toggle(button);
    });
    apply(current(), button);
    return button;
  }

  /** FOUC-safe bootstrap for standalone pages (call before paint when possible). */
  function bootstrapFromStorage() {
    try {
      var stored = localStorage.getItem(KEY);
      var theme = stored === "light" || stored === "dark" ? stored : "dark";
      document.documentElement.setAttribute("data-theme", theme);
      return theme;
    } catch (e) {
      document.documentElement.setAttribute("data-theme", "dark");
      return "dark";
    }
  }

  global.IspTheme = {
    KEY: KEY,
    DARK_META: DARK_META,
    LIGHT_META: LIGHT_META,
    current: current,
    apply: apply,
    toggle: toggle,
    bindToggle: bindToggle,
    bootstrapFromStorage: bootstrapFromStorage,
  };
})(window);
