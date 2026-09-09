"use strict";

(() => {
  const storageKey = "server-kit-theme";
  const themes = new Set(["dark", "light", "sky"]);
  const themeColors = {
    dark: "#080b12",
    light: "#f4f7fb",
    sky: "#eaf7ff",
  };

  function readTheme() {
    try {
      const saved = window.localStorage.getItem(storageKey);
      return themes.has(saved) ? saved : "dark";
    } catch (_error) {
      return "dark";
    }
  }

  function applyTheme(theme, persist = false) {
    const selected = themes.has(theme) ? theme : "dark";
    document.documentElement.dataset.theme = selected;
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) themeColor.setAttribute("content", themeColors[selected]);
    document.querySelectorAll("[data-theme-value]").forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.themeValue === selected));
    });
    if (persist) {
      try {
        window.localStorage.setItem(storageKey, selected);
      } catch (_error) {
        // 浏览器禁用本地存储时，主题仍对当前页面生效。
      }
    }
  }

  applyTheme(readTheme());

  function bindThemePicker() {
    applyTheme(readTheme());
    document.addEventListener("click", (event) => {
      const button = event.target.closest("[data-theme-value]");
      if (!button) return;
      applyTheme(button.dataset.themeValue, true);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindThemePicker, {once: true});
  } else {
    bindThemePicker();
  }
})();
