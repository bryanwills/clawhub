(function () {
  try {
    var d = document.documentElement;
    var selectionKey = "clawhub-theme-selection";
    var modeKey = "clawhub-theme";
    var nameKey = "clawhub-theme-name";
    var legacyModeKey = "clawdhub-theme";
    var customThemeKey = "clawhub-custom-theme";
    var preferencesKey = "clawhub-preferences";
    var defaults = { theme: "claw", mode: "system" };
    var storageKeys = [
      customThemeKey,
      preferencesKey,
      selectionKey,
      modeKey,
      nameKey,
      legacyModeKey,
    ];
    var cookieKeys = storageKeys;

    function hasCookie(name) {
      if (!document.cookie) return false;
      return document.cookie.split(";").some(function (part) {
        return part.trim().indexOf(name + "=") === 0;
      });
    }

    function clearCookie(name) {
      document.cookie = name + "=; Max-Age=0; path=/";
      document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    }

    function cleanupDom() {
      var style = document.getElementById("clawhub-custom-theme-style");
      if (style) style.remove();
      var fonts = document.getElementById("clawhub-custom-theme-fonts");
      if (fonts) fonts.remove();
      d.classList.remove("theme-custom", "high-contrast", "reduce-motion");
      delete d.dataset.density;
      delete d.dataset.animation;
      d.style.removeProperty("--code-font-size");
    }

    var reset = false;
    try {
      if (localStorage.getItem(customThemeKey) || localStorage.getItem(preferencesKey)) {
        reset = true;
      }
      var raw = localStorage.getItem(selectionKey);
      if (raw) {
        try {
          var parsed = JSON.parse(raw);
          if (parsed && parsed.theme && parsed.theme !== "claw") reset = true;
        } catch (_error) {
          reset = true;
        }
      }
      var storedName = localStorage.getItem(nameKey);
      if (storedName && storedName !== "claw") reset = true;
      var storedMode = localStorage.getItem(modeKey);
      if (storedMode && ["system", "light", "dark"].indexOf(storedMode) < 0) reset = true;
      var legacyMode = localStorage.getItem(legacyModeKey);
      if (legacyMode && ["system", "light", "dark"].indexOf(legacyMode) < 0) reset = true;
    } catch (_error) {}

    if (cookieKeys.some(hasCookie)) reset = true;
    if (reset) {
      try {
        storageKeys.forEach(function (key) {
          localStorage.removeItem(key);
        });
        localStorage.setItem(selectionKey, JSON.stringify(defaults));
        localStorage.setItem(modeKey, defaults.mode);
        localStorage.setItem(nameKey, defaults.theme);
      } catch (_error) {}
      cookieKeys.forEach(clearCookie);
      cleanupDom();
    }

    var selection;
    try {
      var storedSelection = localStorage.getItem(selectionKey);
      if (storedSelection) selection = JSON.parse(storedSelection);
    } catch (_error) {}

    if (!selection) {
      var mode = localStorage.getItem(modeKey);
      var theme = localStorage.getItem(nameKey);
      if (mode || theme) {
        selection = { theme: theme || "claw", mode: mode || "system" };
      } else {
        var legacy = localStorage.getItem(legacyModeKey);
        if (legacy) {
          var legacyModeMap = { dark: "dark", light: "light", system: "system" };
          selection = { theme: "claw", mode: legacyModeMap[legacy] || "system" };
        }
      }
    }

    if (!selection) selection = defaults;
    if (["claw"].indexOf(selection.theme) < 0) selection.theme = "claw";
    if (["system", "light", "dark"].indexOf(selection.mode) < 0) selection.mode = "system";

    var resolved =
      selection.mode === "system"
        ? window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light"
        : selection.mode;
    d.dataset.theme = resolved;
    d.dataset.themeResolved = resolved;
    d.dataset.themeMode = selection.mode;
    d.dataset.themeFamily = selection.theme;
    if (resolved === "dark") d.classList.add("dark");
    else d.classList.remove("dark");
  } catch (_error) {}
})();
